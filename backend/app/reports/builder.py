"""
Assemble a :class:`ScanReport` from persisted rows.

The builder is deliberately forgiving about the shapes it is handed: a patch
with no finding, a test with no target file, a verification record written by an
older version. A report is a read model, and a read model that crashes on
missing data is worse than one that degrades -- but it must never *invent*
evidence, so absent gates are reported as absent rather than assumed to have
passed.
"""

from __future__ import annotations

import datetime as dt
from typing import Any, Iterable, Sequence

from app.models.entities import (
    AgentExecution,
    Finding,
    Patch,
    Project,
    Scan,
    ScanEvent,
    TestCase,
)
from app.reports.model import (
    ReportAgent,
    ReportEvent,
    ReportFinding,
    ReportGate,
    ReportPatch,
    ReportSummary,
    ReportTest,
    ScanReport,
    sort_findings,
)

_UNKNOWN = "unknown"


def _text(value: Any) -> str:
    return "" if value is None else str(value)


def _float(value: Any) -> float | None:
    try:
        return None if value is None else float(value)
    except (TypeError, ValueError):
        return None


# ----------------------------------------------------------------------
def _build_gates(verification: dict[str, Any] | None) -> list[ReportGate]:
    raw = (verification or {}).get("gates") or []
    gates: list[ReportGate] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = _text(item.get("gate") or item.get("name"))
        if not name:
            continue
        gates.append(
            ReportGate(
                name=name,
                passed=bool(item.get("passed")),
                detail=_text(item.get("detail") or item.get("message")),
                duration_ms=_float(item.get("duration_ms")),
            )
        )
    return gates


def _build_test(row: TestCase) -> ReportTest:
    return ReportTest(
        name=_text(row.name),
        test_type=_text(row.test_type),
        target_file=row.target_file,
        status=_text(row.status),
        is_exploit_test=bool(row.is_exploit_test),
        finding_id=row.finding_id,
        description=_text(row.description),
        code=_text(row.test_code),
        duration_ms=_float(row.duration_ms),
    )


def _build_patch(row: Patch) -> ReportPatch:
    verification = row.verification or {}
    isolated = verification.get("isolated")
    return ReportPatch(
        finding_id=_text(row.finding_id),
        file_path=_text((row.files_touched or ["(unknown)"])[0]),
        validation_status=_text(row.validation_status),
        verified=bool(row.verified),
        applied=bool(row.applied),
        files_touched=list(row.files_touched or []),
        explanation=_text(row.explanation),
        diff=_text(row.diff),
        isolated=None if isolated is None else bool(isolated),
        reason=_text(verification.get("reason") or row.repair_notes),
        duration_ms=_float(row.duration_ms),
        repair_notes=_text(row.repair_notes),
        gates=_build_gates(verification),
    )


def _build_finding(
    row: Finding,
    *,
    tests_by_finding: dict[str, list[ReportTest]],
    patches_by_finding: dict[str, ReportPatch],
) -> ReportFinding:
    return ReportFinding(
        id=_text(row.id),
        fingerprint=_text(row.fingerprint),
        title=_text(row.title),
        description=_text(row.description),
        severity=_text(row.severity),
        category=_text(row.category),
        status=_text(row.status),
        verified=bool(row.verified),
        is_bug=bool(row.is_bug),
        certainty=_text(row.certainty or _UNKNOWN),
        confidence=_float(row.confidence) or 0.0,
        file_path=row.file_path,
        line_number=row.line_number,
        code_snippet=row.code_snippet,
        impact=_text(row.impact),
        recommendation=_text(row.recommendation),
        cwe=row.cwe,
        owasp=row.owasp,
        detected_by=list(row.detected_by or []),
        tools=list(row.tools or []),
        tests=tests_by_finding.get(_text(row.id), []),
        patch=patches_by_finding.get(_text(row.id)),
    )


def _build_agent(row: AgentExecution) -> ReportAgent:
    return ReportAgent(
        name=_text(row.agent_name),
        status=_text(row.status),
        message=_text(row.message),
        findings_count=int(row.findings_count or 0),
        duration_ms=_float(row.duration_ms),
        metrics=dict(row.metrics or {}),
        error=row.error,
    )


def _build_event(row: ScanEvent) -> ReportEvent:
    progress = _float(row.progress)
    return ReportEvent(
        seq=int(row.seq or 0),
        phase=_text(row.event_type),
        message=_text(row.message),
        progress=progress,
        agent=row.agent_name,
    )


# ----------------------------------------------------------------------
def build_report(
    *,
    scan: Scan,
    project: Project | None,
    findings: Sequence[Finding],
    tests: Iterable[TestCase] = (),
    patches: Iterable[Patch] = (),
    agents: Iterable[AgentExecution] = (),
    events: Iterable[ScanEvent] = (),
    generated_at: dt.datetime | None = None,
) -> ScanReport:
    """
    Assemble one scan into a renderable report.

    ``scan.security_score`` and the severity counts are used as recorded by the
    orchestrator rather than recomputed here, so a report cannot disagree with
    the scan that produced it.
    """
    tests_by_finding: dict[str, list[ReportTest]] = {}
    for row in tests:
        if row.finding_id:
            tests_by_finding.setdefault(_text(row.finding_id), []).append(_build_test(row))

    patches_by_finding: dict[str, ReportPatch] = {}
    for row in sorted(patches, key=lambda p: int(p.attempt or 1)):
        # Later attempts supersede earlier ones for the same finding.
        patches_by_finding[_text(row.finding_id)] = _build_patch(row)

    built = [
        _build_finding(
            row,
            tests_by_finding=tests_by_finding,
            patches_by_finding=patches_by_finding,
        )
        for row in findings
    ]

    # A patch whose finding could not be resolved must not vanish from the
    # report: an unexplained patch is exactly what a reviewer needs to see.
    known_ids = {f.id for f in built}
    orphans = [p for fid, p in patches_by_finding.items() if fid not in known_ids]

    isolated_values = [
        p.isolated for p in patches_by_finding.values() if p.isolated is not None
    ]
    isolated: bool | None = all(isolated_values) if isolated_values else None
    sandbox_backend = "local (unisolated)" if isolated is False else None

    summary = ReportSummary(
        total_findings=len(built),
        critical=int(scan.critical_count or 0),
        high=int(scan.high_count or 0),
        medium=int(scan.medium_count or 0),
        low=int(scan.low_count or 0),
        bugs=int(scan.bugs_detected or 0),
        security_score=int(scan.security_score or 0),
        tests_generated=int(scan.tests_generated or 0),
        verified_fixes=int(scan.verified_fixes or 0),
        failed_fixes=int(scan.failed_fixes or 0),
    )

    return ScanReport(
        scan_id=_text(scan.id),
        project_name=_text(project.name) if project else "(deleted project)",
        project_description=_text(project.description) if project else "",
        scan_status=_text(scan.status),
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        duration_seconds=_float(scan.duration_seconds),
        ai_provider=scan.ai_provider,
        error=scan.error,
        generated_at=generated_at or dt.datetime.now(dt.timezone.utc),
        summary=summary,
        findings=sort_findings(built),
        agents=[_build_agent(a) for a in agents],
        events=sorted((_build_event(e) for e in events), key=lambda e: e.seq),
        ingestion_warnings=list((project.ingestion_warnings if project else None) or []),
        isolated=isolated,
        sandbox_backend=sandbox_backend,
        orphan_patches=orphans,
    )
