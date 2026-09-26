"""
Scan Orchestrator (spec §15).

Runs the full pipeline for one scan and persists the result::

    ingest -> security + bug hunter (concurrently)
           -> correlate
           -> testing agent
           -> fix agent
           -> sandbox verification (per patch, in the sandbox)
           -> summary

Design points that matter:

* **Failure containment.** A scan completes with whatever agents succeeded.
  One crashed agent degrades the result; it never fails the whole scan.
* **Honest verification.** The orchestrator only marks a finding VERIFIED when
  the sandbox ran the exploit, the patch and the rescan. Every other outcome
  is reported as-is.
* **Progress events.** Every transition is published through the event
  callback, which the API forwards to the dashboard over SSE.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from app.agents import AgentContext, BaseAgent, BugHunterAgent, FixAgent, SecurityAgent, TestingAgent
from app.core.config import settings
from app.core.logging_config import get_logger
from app.correlation.correlator import FindingCorrelator
from app.models.enums import AgentStatus, FindingStatus, ScanStatus, Severity
from app.sandbox import SandboxUnavailable, select_executor
from app.schemas.finding import AgentFinding, ScanSummary
from app.services.repository import RepositorySnapshot, build_snapshot
from app.verification.engine import (
    VerificationEngine,
    VerificationResult,
    VerificationStatus,
)

logger = get_logger(__name__)

ProgressHook = Callable[[dict[str, Any]], Awaitable[None] | None]


@dataclass
class ScanOutcome:
    """Everything one scan produced."""

    scan_id: str
    status: ScanStatus = ScanStatus.PENDING
    snapshot: Optional[RepositorySnapshot] = None
    findings: list[AgentFinding] = field(default_factory=list)
    test_cases: list[Any] = field(default_factory=list)
    patches: list[Any] = field(default_factory=list)
    verifications: list[VerificationResult] = field(default_factory=list)
    correlation_stats: dict[str, Any] = field(default_factory=dict)
    agent_messages: dict[str, str] = field(default_factory=dict)
    agent_metrics: dict[str, Any] = field(default_factory=dict)
    #: Each agent's own verdict, recorded verbatim. Persistence must not
    #: have to re-derive this from the error strings.
    agent_statuses: dict[str, str] = field(default_factory=dict)
    summary: ScanSummary = field(default_factory=ScanSummary)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    duration_ms: float = 0.0
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    #: Highest progress published so far; kept monotonic for the UI.
    progress: float = 0.0

    @property
    def verified_findings(self) -> list[AgentFinding]:
        verified_ids = {
            v.finding_id
            for v in self.verifications
            if v.status is VerificationStatus.VERIFIED
        }
        return [f for f in self.findings if f.fingerprint in verified_ids]


class ScanOrchestrator:
    """Executes a complete scan."""

    def __init__(
        self,
        *,
        on_progress: ProgressHook | None = None,
        security_agent: BaseAgent | None = None,
        bug_hunter: BaseAgent | None = None,
        testing_agent: BaseAgent | None = None,
        fix_agent: BaseAgent | None = None,
        verify: bool = True,
    ):
        self.on_progress = on_progress
        self.security_agent = security_agent or SecurityAgent()
        self.bug_hunter = bug_hunter or BugHunterAgent()
        self.testing_agent = testing_agent or TestingAgent()
        self.fix_agent = fix_agent or FixAgent()
        self.correlator = FindingCorrelator()
        self.verify_fixes = verify

    # ------------------------------------------------------------------
    async def run(
        self,
        repository: Path,
        *,
        project_id: str = "",
        scan_id: str | None = None,
        python: str = "python3",
    ) -> ScanOutcome:
        started = time.perf_counter()
        outcome = ScanOutcome(
            scan_id=scan_id or uuid.uuid4().hex,
            started_at=datetime.now(timezone.utc),
            status=ScanStatus.RUNNING,
        )

        # -- 1. Ingest -----------------------------------------------
        await self._emit(outcome, "ingest", "Reading repository", 2)
        try:
            snapshot = build_snapshot(repository)
        except Exception as exc:
            outcome.status = ScanStatus.FAILED
            outcome.errors.append(f"could not read repository: {exc}")
            outcome.duration_ms = (time.perf_counter() - started) * 1000
            await self._emit(outcome, "failed", outcome.errors[0], 100)
            return outcome

        outcome.snapshot = snapshot
        outcome.warnings.extend(snapshot.warnings)
        await self._emit(
            outcome,
            "ingest",
            f"{snapshot.file_count} files, {snapshot.primary_language}, "
            f"frameworks: {', '.join(sorted(snapshot.frameworks)) or 'none'}",
            8,
            manifest=snapshot.as_manifest(),
        )

        # -- 2. Analysis agents, concurrently ------------------------
        await self._emit(outcome, "agents", "Starting security and logic analysis", 12)
        # A context per agent rather than one shared context: the progress
        # hook is bound to a single agent, so a shared context would report
        # every event as coming from whichever agent reported it last.
        def context_for(progress: ProgressHook) -> AgentContext:
            return AgentContext(
                scan_id=outcome.scan_id,
                project_id=project_id or repository.name,
                snapshot=snapshot,
                scan_root=repository,
                on_progress=progress,
            )

        analysis = await asyncio.gather(
            self.security_agent.run(context_for(self._agent_progress(outcome, 12, 35))),
            self.bug_hunter.run(context_for(self._agent_progress(outcome, 12, 35))),
            return_exceptions=True,
        )
        results = []
        for agent, outcome_value in zip(
            (self.security_agent, self.bug_hunter), analysis, strict=True
        ):
            if isinstance(outcome_value, BaseException):
                logger.exception("%s crashed", agent.name, exc_info=outcome_value)
                outcome.errors.append(f"{agent.name} crashed: {outcome_value}")
                outcome.agent_messages[agent.name] = "failed"
                outcome.agent_statuses[agent.name] = AgentStatus.FAILED.value
                continue
            results.append(outcome_value)
            outcome.agent_messages[agent.name] = outcome_value.message
            # Agents report metrics in their own vocabulary, and not one of
            # them used a "findings" key. Publish the count the orchestrator
            # actually holds so persistence and the UI have one contract, and
            # so a self-reported count can never disagree with the results.
            outcome.agent_metrics[agent.name] = {
                **outcome_value.metrics,
                "findings": len(outcome_value.findings),
            }
            outcome.agent_statuses[agent.name] = str(outcome_value.status)
            if outcome_value.status == "FAILED":
                outcome.errors.append(f"{agent.name}: {outcome_value.message}")

        raw_findings = [f for result in results for f in result.findings]
        await self._emit(
            outcome, "agents",
            f"{len(raw_findings)} raw finding(s) from {len(results)} agent(s)", 35,
        )

        # -- 3. Correlate --------------------------------------------
        await self._emit(outcome, "correlate", "Correlating and deduplicating", 40)
        findings, stats = self.correlator.correlate(raw_findings)
        outcome.findings = findings
        outcome.correlation_stats = stats.as_dict()
        await self._emit(
            outcome, "correlate",
            f"{stats.input_count} findings merged into {stats.output_count} "
            f"({stats.cross_agent_confirmed} cross-agent confirmations)", 48,
            stats=stats.as_dict(),
        )

        # -- 4. Tests -------------------------------------------------
        await self._emit(outcome, "tests", "Generating tests", 52)
        test_context = AgentContext(
            scan_id=outcome.scan_id,
            project_id=project_id or repository.name,
            snapshot=snapshot,
            prior_findings=findings,
            on_progress=self._agent_progress(outcome, 52, 58),
        )
        try:
            test_result = await self.testing_agent.run(test_context)
            outcome.test_cases = test_result.test_cases
            outcome.agent_messages[self.testing_agent.name] = test_result.message
            outcome.agent_metrics[self.testing_agent.name] = {
                **test_result.metrics,
                "tests": len(test_result.test_cases),
            }
            outcome.agent_statuses[self.testing_agent.name] = str(test_result.status)
            if test_result.status == "FAILED":
                outcome.errors.append(f"{self.testing_agent.name}: {test_result.message}")
        except Exception as exc:
            logger.exception("testing agent crashed")
            outcome.errors.append(f"test generation failed: {exc}")
            outcome.agent_messages[self.testing_agent.name] = "failed"
            outcome.agent_statuses[self.testing_agent.name] = AgentStatus.FAILED.value
        await self._emit(
            outcome, "tests",
            f"{len(outcome.test_cases)} test(s) generated, "
            f"{sum(1 for t in outcome.test_cases if t.is_exploit_test)} exploit test(s)", 58,
        )

        # -- 5. Patches ----------------------------------------------
        await self._emit(outcome, "fix", "Generating patches", 62)
        fix_context = AgentContext(
            scan_id=outcome.scan_id,
            project_id=project_id or repository.name,
            snapshot=snapshot,
            prior_findings=findings,
            on_progress=self._agent_progress(outcome, 62, 70),
            metadata={"tests": outcome.test_cases},
        )
        try:
            fix_result = await self.fix_agent.run(fix_context)
            outcome.patches = fix_result.patches
            outcome.agent_messages[self.fix_agent.name] = fix_result.message
            outcome.agent_metrics[self.fix_agent.name] = {
                **fix_result.metrics,
                "patches": len(fix_result.patches),
            }
            outcome.agent_statuses[self.fix_agent.name] = str(fix_result.status)
            if fix_result.status == "FAILED":
                outcome.errors.append(f"{self.fix_agent.name}: {fix_result.message}")
        except Exception as exc:
            logger.exception("fix agent crashed")
            outcome.errors.append(f"patch generation failed: {exc}")
            outcome.agent_messages[self.fix_agent.name] = "failed"
            outcome.agent_statuses[self.fix_agent.name] = AgentStatus.FAILED.value
        await self._emit(outcome, "fix", f"{len(outcome.patches)} patch(es) proposed", 70)

        # -- 6. Verification -----------------------------------------
        if self.verify_fixes and outcome.patches:
            await self._emit(outcome, "verify", "Verifying fixes in the sandbox", 74)
            await self._verify(outcome, repository, python)
        else:
            outcome.warnings.append(
                "Fix verification was skipped, so no finding can be marked verified."
            )
            await self._emit(outcome, "verify", "Verification skipped", 95)

        # -- 7. Summarise --------------------------------------------
        outcome.summary = self._summarise(outcome)
        outcome.status = ScanStatus.COMPLETED
        outcome.finished_at = datetime.now(timezone.utc)
        outcome.duration_ms = (time.perf_counter() - started) * 1000
        await self._emit(
            outcome, "complete",
            f"Scan complete: {outcome.summary.total_findings} finding(s), "
            f"{outcome.summary.verified_fixes} verified fix(es), "
            f"score {outcome.summary.security_score}/100", 100,
            summary=outcome.summary.model_dump(),
        )
        return outcome

    # ------------------------------------------------------------------
    async def _verify(self, outcome: ScanOutcome, repository: Path, python: str) -> None:
        """
        Verify each patch in a sandbox, one workspace per patch.

        Each patch starts from a clean copy: applying several patches to one
        workspace would let an earlier patch mask a later one's behaviour.
        """
        try:
            executor, isolation_note = await select_executor()
        except SandboxUnavailable as exc:
            outcome.warnings.append(
                f"No sandbox available ({exc.reason}); fixes were NOT verified."
            )
            outcome.verifications = []
            await self._emit(outcome, "verify", outcome.warnings[-1], 95)
            return

        outcome.warnings.append(isolation_note)
        engine = VerificationEngine(executor, python=python)
        exploit_by_file: dict[str, list[Any]] = {}
        for test in outcome.test_cases:
            if test.is_exploit_test and test.target_file:
                exploit_by_file.setdefault(test.target_file, []).append(test)

        total = len(outcome.patches)
        for index, patch in enumerate(outcome.patches):
            await self._emit(
                outcome, "verify",
                f"Verifying {patch.file_path} ({index + 1}/{total})",
                75 + 18 * index / max(1, total),
                file_path=patch.file_path,
            )
            candidates = exploit_by_file.get(patch.file_path, [])
            finding = self._primary_finding(outcome.findings, patch)
            if finding is None:
                continue

            workspace = None
            try:
                workspace = await executor.prepare(repository)
                # An exploit test per file is enough to demonstrate the class
                # of defect; extra tests for the same file add runtime without
                # adding evidence.
                result = await engine.verify(
                    workspace, finding, patch, candidates[0] if candidates else None
                )
                outcome.verifications.append(result)
            except Exception as exc:
                logger.exception("verification crashed for %s", patch.file_path)
                outcome.errors.append(f"verification failed for {patch.file_path}: {exc}")
            finally:
                if workspace is not None:
                    await executor.cleanup(workspace)

            await self._emit(
                outcome, "verify",
                f"{patch.file_path}: {outcome.verifications[-1].status.value}"
                if outcome.verifications else f"{patch.file_path}: not verified",
                75 + 18 * (index + 1) / max(1, total),
                file_path=patch.file_path,
            )

        self._apply_verification_status(outcome)

    @staticmethod
    def _primary_finding(
        findings: list[AgentFinding], patch: Any
    ) -> AgentFinding | None:
        """The most severe finding in the file this patch targets."""
        in_file = [f for f in findings if f.file_path == patch.file_path]
        if not in_file:
            return None
        return max(in_file, key=lambda f: f.severity.rank)

    @staticmethod
    def _apply_verification_status(outcome: ScanOutcome) -> None:
        """
        Propagate verification verdicts onto the findings.

        Only a VERIFIED result promotes a finding. Everything else maps to a
        status that keeps it visible for review rather than silently closing
        it -- an unverified fix is not a fixed vulnerability.
        """
        by_id = {f.fingerprint: f for f in outcome.findings if f.fingerprint}
        for result in outcome.verifications:
            finding = by_id.get(result.finding_id)
            if finding is None:
                continue
            finding.verified = result.status is VerificationStatus.VERIFIED
            finding.verification_status = result.status.value
            if finding.verified:
                finding.status = FindingStatus.VERIFIED
            elif result.status is VerificationStatus.FAILED:
                finding.status = FindingStatus.FIX_PROPOSED
            elif result.status is VerificationStatus.PARTIALLY_VERIFIED:
                finding.status = FindingStatus.REQUIRES_REVIEW
            else:
                finding.status = FindingStatus.REQUIRES_REVIEW

    # ------------------------------------------------------------------
    def _summarise(self, outcome: ScanOutcome) -> ScanSummary:
        summary = ScanSummary(total_findings=len(outcome.findings))
        for finding in outcome.findings:
            value = finding.severity.value.lower()
            if value in ("critical", "high", "medium", "low"):
                setattr(summary, value, getattr(summary, value) + 1)
            if finding.is_bug:
                summary.bugs_detected += 1

        summary.tests_generated = len(outcome.test_cases)
        for result in outcome.verifications:
            summary.verified_fixes += int(result.status is VerificationStatus.VERIFIED)

        summary.security_score = self._security_score(outcome.findings)
        return summary

    @staticmethod
    def _security_score(findings: list[AgentFinding]) -> int:
        """
        A 0-100 health score that still discriminates between bad repos.

        A linear ``100 - penalty`` bottoms out at zero as soon as a repository
        has a handful of serious findings, which makes the number useless for
        ranking or trending. This uses a saturating curve instead: it is
        monotone, always defined, and keeps resolving differences in the range
        that matters (a repo with one critical finding scores very differently
        from one with twenty).
        """
        weights = {
            Severity.CRITICAL: 25.0,
            Severity.HIGH: 10.0,
            Severity.MEDIUM: 4.0,
            Severity.LOW: 1.0,
        }
        penalty = sum(weights.get(f.severity, 0.0) for f in findings)
        if penalty <= 0:
            return 100
        return max(0, min(100, round(100 / (1 + penalty / 40))))

    # ------------------------------------------------------------------
    def _agent_progress(self, outcome: ScanOutcome, start: float, end: float):
        """
        Bridge an agent's own 0-100 progress into the scan's progress band.

        An agent reports progress relative to itself, so forwarding its number
        unchanged would make the scan's progress bar jump back to zero every
        time an agent starts. Each agent is therefore mapped into the slice of
        the overall timeline it owns, keeping the emitted sequence monotonic.
        """

        async def hook(message: str, progress: float, payload: dict[str, Any]) -> None:
            fraction = min(max(progress, 0.0), 100.0) / 100.0
            await self._emit(
                outcome,
                "agent",
                f"[{payload.get('agent', 'agent')}] {message}",
                start + fraction * (end - start),
                agent=payload.get("agent"),
                # The agent's own number, for a per-agent bar in the UI.
                agent_progress=round(fraction * 100, 2),
                raw=payload,
            )

        return hook

    async def _emit(
        self,
        outcome: ScanOutcome,
        phase: str,
        message: str,
        progress: float,
        **payload: Any,
    ) -> None:
        if self.on_progress is None:
            return
        # Agents run concurrently, so their events interleave and a slower
        # agent can report a lower number after a faster one finished. Clamping
        # to a high-water mark keeps the published progress monotonic, which is
        # what a progress bar has to be to be useful.
        outcome.progress = max(outcome.progress, min(100.0, max(0.0, progress)))
        event = {
            "scan_id": outcome.scan_id,
            "phase": phase,
            "message": message,
            "progress": round(outcome.progress, 2),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **payload,
        }
        try:
            result = self.on_progress(event)
            if asyncio.iscoroutine(result):
                await result
        except Exception:  # progress must never break a scan
            logger.debug("progress hook failed", exc_info=True)


__all__ = ["ScanOrchestrator", "ScanOutcome"]
