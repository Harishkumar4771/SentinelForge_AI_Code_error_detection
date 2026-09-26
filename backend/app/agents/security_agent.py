"""
Security Auditor Agent (spec §9).

Pipeline::

    Repository -> File discovery -> AST analysis -> Semgrep -> Bandit
    -> Gitleaks -> pip-audit -> AI analysis -> Normalized findings

Deterministic tools and LLM reasoning are kept strictly separate. Tool
output is evidence; the LLM may add context but may never overwrite a
tool's severity or invent a file that was not scanned. Everything is
normalized to :class:`AgentFinding` before leaving this module.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from app.agents.base import AgentContext, BaseAgent, severity_sort_key
from app.analyzers.taint import InterproceduralSecurityAnalyzer
from app.analyzers.tools import (
    BanditRunner,
    GitleaksRunner,
    PipAuditRunner,
    SemgrepRunner,
)
from app.core.config import settings
from app.core.logging_config import get_logger
from app.models.enums import AgentName, Certainty, FindingCategory, Severity
from app.providers import AIProvider, ProviderError, get_provider
from app.schemas.finding import AgentFinding, AgentResult, CodeContext

logger = get_logger(__name__)

#: Findings below this severity are dropped from AI review to save tokens.
AI_REVIEW_FLOOR = Severity.LOW


class SecurityAgent(BaseAgent):
    """Combines static tooling, taint analysis and AI review."""

    name = "security_agent"
    agent_enum = AgentName.SECURITY
    description = "Detects vulnerabilities using static analysis, taint tracking and AI review."

    def __init__(
        self,
        *,
        provider: AIProvider | None = None,
        rules_dir: Path | None = None,
        enable_ai: bool = True,
    ):
        self.provider = provider
        self.enable_ai = enable_ai
        self.rules_dir = rules_dir or (settings.base_dir / "security-rules")
        self.bandit = BanditRunner()
        self.semgrep = SemgrepRunner(rules_dir=self.rules_dir)
        self.gitleaks = GitleaksRunner()
        self.pip_audit = PipAuditRunner()

    # ------------------------------------------------------------------
    async def execute(self, context: AgentContext) -> AgentResult:
        snapshot = context.snapshot
        root = snapshot.root
        findings: list[AgentFinding] = []
        metrics: dict[str, int | float | str] = {}

        if snapshot.primary_language != settings.primary_language:
            logger.warning(
                "Primary language is %s; the deterministic pipeline targets %s",
                snapshot.primary_language, settings.primary_language,
            )

        # -- 1. Interprocedural AST taint analysis --------------------
        await context.report("Running AST taint analysis", 0.1)
        taint_engine = InterproceduralSecurityAnalyzer(
            {f.path: f.source or "" for f in snapshot.python_files}
        )
        taint_findings = await asyncio.to_thread(taint_engine.analyze)
        findings.extend(taint_findings)
        metrics["ast_taint_findings"] = len(taint_findings)
        metrics["tainted_parameters"] = len(taint_engine.tainted_parameters())

        # Access control and validation are not injection issues, so the
        # injection analysers above never report them.
        access_findings = await asyncio.to_thread(
            _access_control_findings, snapshot.python_files
        )
        findings.extend(access_findings)
        metrics["access_control_findings"] = len(access_findings)
        await context.report(
            f"AST analysis complete: {len(taint_findings + access_findings)} finding(s)", 0.25
        )

        # -- 2. External tools, concurrently ---------------------------
        await context.report("Running Semgrep, Bandit, Gitleaks and pip-audit", 0.3)
        runners = [
            ("bandit", self.bandit),
            ("semgrep", self.semgrep),
            ("gitleaks", self.gitleaks),
            ("pip-audit", self.pip_audit),
        ]
        results = await asyncio.gather(
            *(runner.run(root) for _, runner in runners),
            return_exceptions=True,
        )

        unavailable: list[str] = []
        tool_counts: dict[str, int] = {}
        for (label, runner), outcome in zip(runners, results):
            if isinstance(outcome, BaseException):
                logger.warning("%s runner raised: %s", label, outcome)
                unavailable.append(label)
                continue
            if not outcome.available:
                unavailable.append(label)
                logger.info("%s unavailable: %s", label, outcome.error)
                continue
            tool_counts[label] = outcome.count
            metrics[f"{label}_ms"] = round(outcome.duration_ms)
            findings.extend(outcome.findings)

        metrics["tool_findings"] = tool_counts
        if unavailable:
            metrics["unavailable_tools"] = unavailable
        await context.report(
            f"Static tools complete: {sum(tool_counts.values())} finding(s)", 0.5
        )

        # -- 3. AI review over a targeted context ---------------------
        ai_findings: list[AgentFinding] = []
        if self.enable_ai:
            await context.report("AI reviewing high-severity code paths", 0.6)
            try:
                ai_findings = await self._ai_review(context, findings, taint_engine)
            except ProviderError as exc:
                # A provider outage degrades the scan, it does not fail it.
                logger.warning("AI review skipped: %s", exc)
                metrics["ai_error"] = str(exc)[:200]
            ai_findings = self._reject_unsupported(ai_findings, snapshot)
            findings.extend(ai_findings)
        metrics["ai_findings"] = len(ai_findings)

        # -- 4. Normalize ---------------------------------------------
        findings = self._dedupe(findings)[: settings.max_findings_per_agent]
        findings.sort(key=severity_sort_key)

        by_severity: dict[str, int] = {}
        for finding in findings:
            by_severity[finding.severity.value] = by_severity.get(finding.severity.value, 0) + 1
        metrics["by_severity"] = by_severity

        await context.report("Security analysis complete", 1.0)
        return AgentResult(
            agent_name=self.name,
            status="COMPLETED",
            findings=findings,
            message=(
                f"{len(findings)} security finding(s) across "
                f"{len(tool_counts)} tool(s) and AST analysis"
            ),
            metrics=metrics,
        )

    # ------------------------------------------------------------------
    async def _ai_review(
        self,
        context: AgentContext,
        existing: list[AgentFinding],
        taint_engine: InterproceduralSecurityAnalyzer,
    ) -> list[AgentFinding]:
        """
        Ask the model to review only the code that already looks risky.

        The context is narrowed to files that deterministic tools flagged, so
        the whole repository is never shipped to the model (spec §24).
        """
        provider = self.provider or get_provider()
        snapshot = context.snapshot

        interesting: list[str] = []
        for finding in existing:
            if finding.severity >= AI_REVIEW_FLOOR and finding.file_path:
                if finding.file_path not in interesting:
                    interesting.append(finding.file_path)

        if not interesting:
            interesting = [f.path for f in snapshot.python_files[:5]]

        code_context = CodeContext(
            project_name=context.project_id,
            primary_language=snapshot.primary_language,
            file_paths=interesting[:12],
            code_snippets={
                path: snapshot.read(path) or "" for path in interesting[:12]
            },
            dependencies=snapshot.dependencies,
            frameworks=sorted(snapshot.frameworks),
            tool_findings=[
                {
                    "tool": tool,
                    "title": f.title,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "cwe": f.cwe,
                }
                for f in existing[:60]
                for tool in (f.tools or ["analysis"])
            ],
        )

        prompt = self._build_prompt(code_context, taint_engine)
        payload = await provider.generate_json(
            request=_security_request(prompt)
        )
        return _coerce_ai_findings(payload)

    def _build_prompt(
        self,
        code_context: CodeContext,
        taint_engine: InterproceduralSecurityAnalyzer,
    ) -> str:
        proven = taint_engine.tainted_parameters()
        taint_note = (
            "\n\nPARAMETERS PROVEN ATTACKER-CONTROLLED BY CROSS-MODULE TAINT ANALYSIS:\n"
            + "\n".join(f"  - {key}: {', '.join(params)}" for key, params in list(proven.items())[:25])
            if proven
            else ""
        )
        return (
            "Review the code below for security vulnerabilities that deterministic "
            "tooling may have missed. Focus on injection, deserialization, path "
            "traversal, broken authentication and authorization.\n"
            "For every finding, cite the exact file and line from the context below."
            f"{taint_note}\n\n{code_context.to_prompt_block()}"
        )

    # ------------------------------------------------------------------
    @staticmethod
    def _reject_unsupported(
        findings: list[AgentFinding], snapshot
    ) -> list[AgentFinding]:
        """
        Drop AI findings that cite code we never showed the model.

        This is the guard that stops a hallucinated file path or line number
        from entering the database (spec §32: never invent evidence).
        """
        known_paths = {f.path for f in snapshot.files}
        kept: list[AgentFinding] = []
        for finding in findings:
            if finding.file_path is None:
                continue
            if finding.file_path not in known_paths:
                logger.info("dropping AI finding with unknown path: %s", finding.file_path)
                continue
            if finding.line_number:
                total = snapshot.get(finding.file_path)
                total_lines = total.line_count if total else 0
                if total_lines and finding.line_number > total_lines + 5:
                    logger.info(
                        "dropping AI finding with out-of-range line %s in %s",
                        finding.line_number, finding.file_path,
                    )
                    continue
            # An AI claim never escalates to confirmed on its own.
            if finding.certainty == Certainty.CONFIRMED and not finding.tools:
                finding.certainty = Certainty.PROBABLE
                finding.confidence = min(finding.confidence, 0.7)
            kept.append(finding)
        return kept

    @staticmethod
    def _dedupe(findings: list[AgentFinding]) -> list[AgentFinding]:
        """Collapse identical (file, line, category, title) reports."""
        seen: dict[tuple, AgentFinding] = {}
        for finding in findings:
            key = (
                finding.file_path,
                finding.line_number,
                finding.category.lower(),
                finding.title.strip().lower()[:80],
            )
            existing = seen.get(key)
            if existing is None:
                seen[key] = finding
            else:
                seen[key] = existing.merge(finding)
        return list(seen.values())


# ----------------------------------------------------------------------
def _access_control_findings(files) -> list[AgentFinding]:
    """
    Run the access-control and validation analysers over every module.

    A crash in one analyser is contained so the rest of the scan survives.
    """
    from app.analyzers.access_control import analyze_access_control, analyze_validation

    results: list[AgentFinding] = []
    for item in files:
        if item.is_test or not item.source:
            continue
        for analyzer in (analyze_access_control, analyze_validation):
            try:
                results.extend(analyzer(item.path, item.source))
            except Exception as exc:
                logger.warning("%s failed on %s: %s", analyzer.__name__, item.path, exc)
    return results


def _security_request(prompt: str):
    from app.providers.base import GenerationRequest

    return GenerationRequest(
        prompt=prompt,
        system="security",
        json_object={"findings": "array of finding objects"},
    )


def _coerce_ai_findings(payload: object) -> list[AgentFinding]:
    """
    Validate model output against the standard finding schema.

    A malformed item is dropped with a log line rather than raising, so one
    bad object cannot lose the whole response.
    """
    if isinstance(payload, dict):
        raw = payload.get("findings", [])
    elif isinstance(payload, list):
        raw = payload
    else:
        logger.warning("AI security response had an unexpected shape: %r", type(payload))
        return []

    if not isinstance(raw, list):
        return []

    results: list[AgentFinding] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        item = dict(item)
        item.pop("id", None)
        try:
            finding = AgentFinding.model_validate(item)
        except Exception as exc:
            logger.info("rejecting malformed AI finding (%s): %s", type(exc).__name__, str(exc)[:160])
            continue
        finding.detected_by = list(dict.fromkeys([*finding.detected_by, "security_agent"]))
        if not finding.tools:
            finding.tools = ["ai"]
        results.append(finding)
    return results


__all__ = ["SecurityAgent", "FindingCategory"]
