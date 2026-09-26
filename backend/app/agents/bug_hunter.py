"""
Bug Hunter Agent (spec §11).

Finds functional and logical defects -- software that behaves incorrectly
even with no conventional vulnerability present. It deliberately does *not*
re-report the Security Agent's injection findings; the correlator merges
duplicates, but the Bug Hunter's job is the complementary set.
"""

from __future__ import annotations

import ast

from app.agents.base import AgentContext, BaseAgent, severity_sort_key
from app.analyzers.ast_analyzer import AstLogicAnalyzer, index_module
from app.core.config import settings
from app.core.logging_config import get_logger
from app.models.enums import AgentName, Severity
from app.providers import AIProvider, ProviderError, get_provider
from app.schemas.finding import AgentFinding, AgentResult, CodeContext

logger = get_logger(__name__)

#: Categories the Security Agent owns; the Bug Hunter stays out of them.
SECURITY_OWNED = {
    "injection",
    "cross-site scripting",
    "path traversal",
    "hardcoded secret",
    "insecure deserialization",
    "insecure cryptography",
    "dangerous import",
    "dependency risk",
    "ssrf",
    "server-side request forgery",
}


class BugHunterAgent(BaseAgent):
    """AST heuristics plus AI review, scoped to correctness."""

    name = "bug_hunter"
    agent_enum = AgentName.BUG_HUNTER
    description = "Detects functional and logical defects in otherwise non-vulnerable code."

    def __init__(self, *, provider: AIProvider | None = None, enable_ai: bool = True):
        self.provider = provider
        self.enable_ai = enable_ai

    async def execute(self, context: AgentContext) -> AgentResult:
        snapshot = context.snapshot
        findings: list[AgentFinding] = []
        metrics: dict[str, int | float] = {}

        # -- 1. AST logic heuristics ------------------------------------
        await context.report("Analysing control flow and arithmetic", 0.2)
        for item in snapshot.python_files:
            if item.is_test:
                continue
            try:
                engine = AstLogicAnalyzer(item.path, item.source or "")
                engine.visit(ast.parse(item.source or "", filename=item.path))
            except (SyntaxError, ValueError, RecursionError):
                continue
            except Exception as exc:  # a heuristic crash must not abort the agent
                logger.debug("logic analyzer error in %s: %s", item.path, exc)
                continue
            findings.extend(engine.findings)

        metrics["ast_findings"] = len(findings)
        await context.report(f"Static logic analysis: {len(findings)} candidate(s)", 0.5)

        # -- 2. AI review ----------------------------------------------
        ai_findings: list[AgentFinding] = []
        if self.enable_ai:
            await context.report("AI reviewing business logic", 0.65)
            try:
                ai_findings = await self._ai_review(context, findings)
            except ProviderError as exc:
                logger.warning("Bug Hunter AI review skipped: %s", exc)
                metrics["ai_error"] = 1
            ai_findings = self._validate(ai_findings, snapshot)
            findings.extend(ai_findings)

        metrics["ai_findings"] = len(ai_findings)
        findings = self._dedupe(findings)
        findings.sort(key=severity_sort_key)
        metrics["total"] = len(findings)

        await context.report("Bug hunt complete", 1.0)
        return AgentResult(
            agent_name=self.name,
            status="COMPLETED",
            findings=findings,
            message=f"{len(findings)} functional/logic defect(s) detected",
            metrics=metrics,
        )

    async def _ai_review(
        self, context: AgentContext, existing: list[AgentFinding]
    ) -> list[AgentFinding]:
        from app.providers.base import GenerationRequest

        provider = self.provider or get_provider()
        snapshot = context.snapshot

        # Prioritise files that already look logic-heavy, then by size.
        candidates = [f for f in snapshot.python_files if not f.is_test]
        candidates.sort(key=lambda f: -f.line_count)
        selected = candidates[:10]

        code_context = CodeContext(
            project_name=context.project_id,
            primary_language=snapshot.primary_language,
            file_paths=[f.path for f in selected],
            code_snippets={f.path: f.source or "" for f in selected},
            ast_summary=self._structure_summary(selected),
        )

        prompt = (
            "Review the code below for FUNCTIONAL and LOGICAL defects -- incorrect "
            "conditions, unreachable branches, wrong arithmetic, sign errors, unhandled "
            "None, broken state transitions, flawed business rules, and inconsistent "
            "error handling. Do NOT report security vulnerabilities; a separate agent "
            "covers those.\n"
            "For each defect, state the concrete wrong behaviour: which input or "
            "sequence of calls produces the incorrect result.\n\n"
            f"{code_context.to_prompt_block(max_chars=40_000)}"
        )

        payload = await provider.generate_json(
            GenerationRequest(
                prompt=prompt,
                system="bug_hunter",
                json_object={"findings": "array of bug objects"},
            )
        )
        return _coerce(payload)

    @staticmethod
    def _structure_summary(files) -> dict[str, dict]:
        """Give the model a map of the code before it reads any of it."""
        summary: dict[str, dict] = {}
        for item in files:
            index = index_module(item.path, item.source or "")
            summary[item.path] = {
                "functions": [
                    {"name": f.name, "args": f.args, "line": f.lineno}
                    for f in index.functions[:40]
                ],
                "classes": index.classes,
                "imports": sorted(index.imports)[:20],
            }
        return summary

    @staticmethod
    def _validate(findings: list[AgentFinding], snapshot) -> list[AgentFinding]:
        """
        Drop unverifiable claims, but keep security observations.

        A security defect noticed during the logic review is not discarded:
        the correlator folds it into the Security Agent's finding and awards
        the cross-agent confidence boost (spec §12). It is simply relabelled
        so it is not double-counted as a functional bug.
        """
        known = {f.path: f.line_count for f in snapshot.files}
        kept: list[AgentFinding] = []
        for finding in findings:
            if finding.file_path and finding.file_path not in known:
                continue
            if finding.file_path and finding.line_number:
                if finding.line_number > known[finding.file_path] + 5:
                    continue
            if finding.category.lower() in SECURITY_OWNED:
                finding.is_bug = False
            else:
                finding.is_bug = True
            if not finding.detected_by:
                finding.detected_by = ["bug_hunter"]
            kept.append(finding)
        return kept

    @staticmethod
    def _dedupe(findings: list[AgentFinding]) -> list[AgentFinding]:
        seen: dict[tuple, AgentFinding] = {}
        for finding in findings:
            key = (
                finding.file_path,
                finding.line_number,
                finding.title.strip().lower()[:80],
            )
            if key in seen:
                seen[key] = seen[key].merge(finding)
            else:
                seen[key] = finding
        return list(seen.values())[: settings.max_findings_per_agent]


def _coerce(payload: object) -> list[AgentFinding]:
    raw = payload.get("findings", []) if isinstance(payload, dict) else payload
    if not isinstance(raw, list):
        return []
    out: list[AgentFinding] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        item = {k: v for k, v in item.items() if k != "id"}
        item.setdefault("is_bug", True)
        item.setdefault("category", "Logic Bug")
        try:
            out.append(AgentFinding.model_validate(item))
        except Exception as exc:
            logger.info("rejecting malformed AI bug (%s): %s", type(exc).__name__, str(exc)[:140])
    return out


__all__ = ["BugHunterAgent", "SECURITY_OWNED", "Severity"]
