"""
Persistence for scan results (§16).

Maps the in-memory pipeline output onto the relational model. Two rules drive
the design:

* **The database is derived state.** Anything here can be rebuilt by re-running
  a scan, so a write failure must be loud but must never lose the scan result
  the caller is holding.
* **Findings are keyed by fingerprint, not row id.** A finding is a property of
  the code, so tests and patches attach to the fingerprint's row. That keeps
  the audit trail intact across re-runs.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging_config import get_logger
from app.models.entities import (
    AgentExecution,
    FileRecord,
    Finding,
    Patch,
    Project,
    Scan,
    ScanEvent,
    TestCase,
)
from app.models.enums import (
    AgentStatus,
    FindingStatus,
    ProjectStatus,
    ScanStatus,
    TestStatus,
    ValidationStatus,
)
from app.schemas.finding import AgentFinding, GeneratedTest, ProposedPatch
from app.services.orchestrator import ScanOutcome
from app.verification.engine import VerificationResult, VerificationStatus

logger = get_logger(__name__)

#: Sandbox verdict -> the column that records the attempt.
_VALIDATION_BY_STATUS = {
    VerificationStatus.VERIFIED: ValidationStatus.VERIFIED,
    VerificationStatus.FAILED: ValidationStatus.FAILED,
    VerificationStatus.PARTIALLY_VERIFIED: ValidationStatus.PARTIALLY_VERIFIED,
    VerificationStatus.REQUIRES_REVIEW: ValidationStatus.REQUIRES_HUMAN_REVIEW,
    # A skipped verification is not a failure; it stays pending for review.
    VerificationStatus.SKIPPED: ValidationStatus.PENDING,
}


class ScanPersistence:
    """Writes a :class:`ScanOutcome` and its inputs to the database."""

    def __init__(self, session: AsyncSession):
        self.session = session

    # ------------------------------------------------------------------
    # Projects
    # ------------------------------------------------------------------
    async def create_project(
        self,
        name: str,
        *,
        description: str | None = None,
        storage_path: str | None = None,
        original_filename: str | None = None,
    ) -> Project:
        project = Project(
            name=name,
            description=description,
            status=ProjectStatus.ANALYZED.value,
            storage_path=storage_path,
            original_filename=original_filename,
        )
        self.session.add(project)
        await self.session.commit()
        await self.session.refresh(project)
        return project

    async def get_project(self, project_id: str) -> Project | None:
        return await self.session.get(Project, project_id)

    async def list_projects(self, limit: int = 100) -> list[Project]:
        result = await self.session.scalars(
            select(Project).order_by(Project.created_at.desc()).limit(limit)
        )
        return list(result)

    async def sync_files(self, project: Project, snapshot: Any) -> int:
        """Replace the project's file index with the snapshot's contents."""
        await self.session.execute(
            delete(FileRecord).where(FileRecord.project_id == project.id)
        )
        records = [
            FileRecord(
                project_id=project.id,
                path=item.path,
                language=getattr(item, "language", None),
                size_bytes=getattr(item, "size_bytes", 0) or 0,
                line_count=getattr(item, "line_count", 0) or 0,
                is_test=bool(getattr(item, "is_test", False)),
                sha256=getattr(item, "sha256", None),
            )
            for item in getattr(snapshot, "files", [])
        ]
        self.session.add_all(records)
        project.file_count = len(records)
        project.primary_language = snapshot.primary_language
        project.languages = sorted(
            {getattr(f, "language", None) for f in records if getattr(f, "language", None)}
        )
        project.manifest = snapshot.as_manifest()
        project.ingestion_warnings = list(snapshot.warnings)
        await self.session.commit()
        return len(records)

    # ------------------------------------------------------------------
    # Scans
    # ------------------------------------------------------------------
    async def start_scan(self, project: Project, *, ai_provider: str = "mock") -> Scan:
        scan = Scan(
            project_id=project.id,
            status=ScanStatus.RUNNING.value,
            started_at=datetime.now(timezone.utc),
            ai_provider=ai_provider,
        )
        self.session.add(scan)
        await self.session.commit()
        await self.session.refresh(scan)
        return scan

    async def get_scan(self, scan_id: str) -> Scan | None:
        return await self.session.get(Scan, scan_id)

    async def list_scans(self, project_id: str, limit: int = 50) -> list[Scan]:
        result = await self.session.scalars(
            select(Scan)
            .where(Scan.project_id == project_id)
            .order_by(Scan.created_at.desc())
            .limit(limit)
        )
        return list(result)

    async def record_event(
        self,
        scan_id: str,
        event: dict[str, Any],
        *,
        seq: int,
    ) -> ScanEvent:
        row = ScanEvent(
            scan_id=scan_id,
            seq=seq,
            agent_name=event.get("agent"),
            event_type=event.get("phase", "progress"),
            status=event.get("status"),
            progress=event.get("progress"),
            message=event.get("message", ""),
            payload={
                k: v
                for k, v in event.items()
                if k not in {"scan_id", "phase", "message", "progress", "agent", "timestamp"}
            },
        )
        self.session.add(row)
        return row

    # ------------------------------------------------------------------
    # The big one
    # ------------------------------------------------------------------
    async def save_outcome(
        self, scan: Scan, outcome: ScanOutcome, events: list[dict[str, Any]]
    ) -> Scan:
        """
        Persist everything one scan produced.

        Findings go in first because tests and patches reference them.
        """
        snapshot = outcome.snapshot

        scan.status = outcome.status.value
        scan.completed_at = outcome.finished_at or datetime.now(timezone.utc)
        scan.error = "; ".join(outcome.errors)[:4000] or None
        scan.security_score = outcome.summary.security_score
        scan.critical_count = outcome.summary.critical
        scan.high_count = outcome.summary.high
        scan.medium_count = outcome.summary.medium
        scan.low_count = outcome.summary.low
        scan.bugs_detected = outcome.summary.bugs_detected
        scan.tests_generated = outcome.summary.tests_generated
        scan.verified_fixes = outcome.summary.verified_fixes
        scan.duration_seconds = round(outcome.duration_ms / 1000, 3)

        # 1. Findings
        rows: dict[str, Finding] = {}
        for finding in outcome.findings:
            row = Finding(
                scan_id=scan.id,
                fingerprint=finding.fingerprint,
                title=finding.title[:512],
                description=finding.description or "",
                severity=finding.severity.value,
                confidence=finding.confidence,
                category=str(finding.category),
                cwe=finding.cwe,
                owasp=finding.owasp,
                certainty=finding.certainty.value,
                file_path=finding.file_path,
                line_number=finding.line_number,
                line_end=finding.line_end,
                code_snippet=finding.code_snippet,
                evidence=list(finding.evidence or []),
                impact=finding.impact,
                recommendation=finding.recommendation,
                detected_by=list(finding.detected_by or []),
                tools=list(finding.tools or []),
                status=getattr(finding.status, "value", finding.status),
                verified=bool(finding.verified),
                is_bug=bool(finding.is_bug),
            )
            self.session.add(row)
            rows[finding.fingerprint] = row
        await self.session.flush()

        # 2. Tests
        for test in outcome.test_cases:
            self.session.add(
                TestCase(
                    scan_id=scan.id,
                    finding_id=self._row_id(rows, test.finding_id),
                    name=test.name[:512],
                    description=test.description,
                    test_code=test.test_code,
                    # GeneratedTest.test_type is a plain Literal string,
                    # not the TestType enum.
                    test_type=test.test_type,
                    target_file=test.target_file,
                    status=TestStatus.GENERATED.value,
                    is_exploit_test=bool(test.is_exploit_test),
                )
            )

        # 3. Patches, linked to the finding they answer
        verification_by_finding = {v.finding_id: v for v in outcome.verifications}
        for index, patch in enumerate(outcome.patches, start=1):
            finding_id = self._row_id(rows, getattr(patch, "finding_id", None))
            if finding_id is None:
                # A patch with no finding row would violate the FK; skip it
                # rather than lose the scan.
                logger.warning("patch for %s has no finding; not persisted", patch.file_path)
                continue
            result = verification_by_finding.get(getattr(patch, "finding_id", ""))
            self.session.add(
                Patch(
                    scan_id=scan.id,
                    finding_id=finding_id,
                    attempt=index,
                    original_code=patch.original_code,
                    patched_code=patch.patched_code,
                    diff=patch.diff,
                    explanation=getattr(patch, "explanation", None),
                    files_touched=[patch.file_path],
                    validation_status=self._validation_status(result),
                    validation_output=result.message if result else None,
                    verification=self._verification_payload(result),
                    verified=bool(result and result.status is VerificationStatus.VERIFIED),
                    applied=bool(result and result.passed_gates),
                    duration_ms=result.duration_ms if result else None,
                )
            )

        # 4. Agent executions
        for name, message in outcome.agent_messages.items():
            metrics = outcome.agent_metrics.get(name) or {}
            self.session.add(
                AgentExecution(
                    scan_id=scan.id,
                    agent_name=name,
                    # The orchestrator records each agent's own verdict. It
                    # cannot be inferred from ``outcome.errors``, whose entries
                    # are prefixed messages, not bare agent names.
                    status=outcome.agent_statuses.get(
                        name, AgentStatus.COMPLETED.value
                    ),
                    completed_at=datetime.now(timezone.utc),
                    duration_ms=float(metrics.get("duration_ms") or 0.0),
                    message=message,
                    findings_count=int(metrics.get("findings") or 0),
                    metrics=metrics,
                    error=next((e for e in outcome.errors if e.startswith(f"{name}:")), None),
                )
            )

        # 5. Timeline
        for seq, event in enumerate(events, start=1):
            await self.record_event(scan.id, event, seq=seq)

        await self.session.commit()
        await self.session.refresh(scan)
        return scan

    # ------------------------------------------------------------------
    @staticmethod
    def _row_id(rows: dict[str, Finding], fingerprint: str | None) -> str | None:
        if not fingerprint:
            return None
        row = rows.get(fingerprint)
        return row.id if row else None

    @staticmethod
    def _validation_status(result: VerificationResult | None) -> str:
        if result is None:
            return ValidationStatus.PENDING.value
        return _VALIDATION_BY_STATUS.get(result.status, ValidationStatus.PENDING).value

    @staticmethod
    def _verification_payload(result: VerificationResult | None) -> dict[str, Any]:
        if result is None:
            return {}
        return {
            "status": result.status.value,
            "message": result.message,
            "isolated": result.isolated,
            "duration_ms": result.duration_ms,
            "gates": [gate.as_dict() for gate in result.gates],
            "test_output": result.test_output,
        }

    # ------------------------------------------------------------------
    async def findings_for_scan(self, scan_id: str) -> list[Finding]:
        result = await self.session.scalars(
            select(Finding)
            .where(Finding.scan_id == scan_id)
            .order_by(Finding.severity, Finding.file_path)
        )
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        return sorted(result, key=lambda f: (order.get(f.severity, 4), f.file_path or ""))

    async def tests_for_scan(self, scan_id: str) -> list[TestCase]:
        result = await self.session.scalars(
            select(TestCase).where(TestCase.scan_id == scan_id)
        )
        return list(result)

    async def patches_for_scan(self, scan_id: str) -> list[Patch]:
        result = await self.session.scalars(
            select(Patch).where(Patch.scan_id == scan_id)
        )
        return list(result)

    async def events_for_scan(self, scan_id: str) -> list[ScanEvent]:
        result = await self.session.scalars(
            select(ScanEvent)
            .where(ScanEvent.scan_id == scan_id)
            .order_by(ScanEvent.seq)
        )
        return list(result)

    async def agent_executions_for_scan(self, scan_id: str) -> list[AgentExecution]:
        """
        Agent runs in pipeline order, so a reader sees the same sequence the
        orchestrator actually executed rather than database insertion order.
        """
        order = {
            "security_agent": 0,
            "bug_hunter": 1,
            "testing_agent": 2,
            "fix_agent": 3,
        }
        result = await self.session.scalars(
            select(AgentExecution).where(AgentExecution.scan_id == scan_id)
        )
        return sorted(
            result, key=lambda a: (order.get(a.agent_name, 99), a.agent_name)
        )

    async def delete_project(self, project_id: str) -> bool:
        project = await self.get_project(project_id)
        if project is None:
            return False
        await self.session.delete(project)
        await self.session.commit()
        return True

    async def project_stats(self) -> dict[str, Any]:
        projects = await self.session.scalar(select(func.count()).select_from(Project))
        scans = await self.session.scalar(select(func.count()).select_from(Scan))
        findings = await self.session.scalar(select(func.count()).select_from(Finding))
        verified = await self.session.scalar(
            select(func.count()).select_from(Finding).where(Finding.verified.is_(True))
        )
        return {
            "projects": projects or 0,
            "scans": scans or 0,
            "findings": findings or 0,
            "verified_fixes": verified or 0,
        }


__all__ = ["ScanPersistence"]
