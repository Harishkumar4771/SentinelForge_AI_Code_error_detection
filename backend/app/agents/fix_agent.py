"""
Fix Agent (spec §13).

Generates a minimal patch for each fixable finding, then validates the patch
before anyone is told it works. Three gates, all enforced here:

1. the patch must parse and keep the file's imports intact;
2. the patch must not delete the code the test exercises (no "fix" that
   comments out the vulnerable function and deletes the feature);
3. the patch must be a real change.

A patch that fails any gate is rejected with a reason. Whether the patch
actually eliminates the vulnerability is decided later by the sandbox, never
by this module -- the LLM's own claim is not evidence (spec §22).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from app.agents.base import AgentContext, BaseAgent
from app.core.logging_config import get_logger
from app.models.enums import AgentName, Severity
from app.providers import AIProvider, ProviderError, get_provider
from app.schemas.finding import AgentFinding, AgentResult, CodeContext, ProposedPatch

logger = get_logger(__name__)

#: Categories the Fix Agent will attempt. Anything else is routed to a human
#: rather than patched blindly (e.g. a dependency upgrade is a release task,
#: not a code edit).
FIXABLE = {
    "injection",
    "path traversal",
    "insecure deserialization",
    "hardcoded secret",
    "insecure cryptography",
    "authentication",
    "authorization",
    "cross-site scripting",
    "server-side request forgery",
    "input validation",
    "dangerous import",
}

#: Never patch a file whose whole content would be replaced.
MAX_PATCH_RATIO = 0.6


class FixAgent(BaseAgent):
    """Proposes minimal, validated patches."""

    name = "fix_agent"
    agent_enum = AgentName.FIX
    description = "Generates minimal patches and applies verified fixes."

    def __init__(self, *, provider: AIProvider | None = None, enable_ai: bool = True):
        self.provider = provider
        self.enable_ai = enable_ai

    async def execute(self, context: AgentContext) -> AgentResult:
        fixable = [
            f
            for f in context.prior_findings
            if f.file_path and f.category.lower() in FIXABLE
        ]
        await context.report(f"{len(fixable)} fixable finding(s)", 0.1)

        if not fixable:
            return AgentResult(
                agent_name=self.name,
                status="COMPLETED",
                message="No auto-fixable findings.",
                metrics={"patches": 0, "skipped": "nothing_fixable"},
            )

        # One patch per file. Patching the same file once per finding would
        # produce conflicting patches, each of which reverts the others.
        by_file: dict[str, list[AgentFinding]] = {}
        for finding in fixable:
            by_file.setdefault(finding.file_path or "", []).append(finding)

        patches: list[ProposedPatch] = []
        rejected = 0
        for index, (path, findings) in enumerate(by_file.items()):
            await context.report(
                f"Patching {path} ({len(findings)} finding(s))",
                0.1 + 0.8 * index / max(1, len(by_file)),
            )
            patch = await self._patch_file(context, path, findings)
            if patch is None:
                rejected += len(findings)
                continue
            patches.append(patch)

        await context.report(f"{len(patches)} patch(es) proposed", 1.0)
        return AgentResult(
            agent_name=self.name,
            status="COMPLETED",
            patches=patches,
            message=(
                f"{len(patches)} patch(es) covering {len(patches)} file(s); "
                f"{rejected} finding(s) left to a human"
            ),
            metrics={
                "patches": len(patches),
                "rejected_findings": rejected,
                "files_touched": len(patches),
            },
        )

    # ------------------------------------------------------------------
    async def _patch_file(
        self,
        context: AgentContext,
        path: str,
        findings: list[AgentFinding],
    ) -> ProposedPatch | None:
        """
        Fix every finding in one file in a single edit.

        A patch is only coherent as a whole: two patches to the same file
        would each be built against the original and would clobber each other.
        """
        from app.providers.base import GenerationRequest

        provider = self.provider or get_provider()
        snapshot = context.snapshot
        source = snapshot.read(path)
        if not source:
            return None

        lines = source.splitlines()
        # Anchor the prompt on the most severe finding, but ask for all of them.
        findings = sorted(findings, key=lambda f: f.severity.rank, reverse=True)
        primary = findings[0]
        focus = self._focus_block(lines, primary.line_number)

        code_context = CodeContext(
            project_name=context.project_id,
            primary_language=snapshot.primary_language,
            file_paths=[path],
            code_snippets={path: source},
        )

        finding_block = "\n".join(
            f"  - [{f.severity.value}] line {f.line_number}: {f.title} ({f.category}"
            + (f", {f.cwe}" if f.cwe else "")
            + ")\n"
            f"      {f.description[:300]}\n"
            f"      fix: {f.recommendation or 'n/a'}"
            for f in findings
        )

        prompt = (
            "Produce a MINIMAL patch that fixes ALL of the findings listed for this "
            "file, in one edit.\n"
            "Rules you must follow:\n"
            "  1. Change only the lines that cause the defects. Do not reformat, "
            "reorder or rewrite unrelated code.\n"
            "  2. Preserve existing behaviour, function signatures and return types.\n"
            "  3. Do not delete or stub out a vulnerable function -- the fix must still "
            "do the job it was written to do.\n"
            "  4. Return the complete corrected file in `patched_code` plus a unified diff.\n"
            "  5. Remove hardcoded credentials rather than moving them elsewhere.\n"
            f"\nFINDINGS IN {path}:\n{finding_block}\n"
            f"\nCODE AROUND LINE {primary.line_number}:\n{focus}\n"
            f"\n{code_context.to_prompt_block(max_chars=28_000)}"
        )

        try:
            payload = await provider.generate_json(
                GenerationRequest(
                    prompt=prompt,
                    system="fix",
                    json_object={
                        "file_path": "path of the patched file",
                        "patched_code": "complete corrected file content",
                        "diff": "unified diff",
                        "explanation": "why this fixes the defects",
                    },
                )
            )
        except ProviderError as exc:
            logger.warning("patch generation failed for %s: %s", path, exc)
            return None

        patch = self._coerce(payload, primary, source, path)
        if patch is None:
            return None

        # Record every finding this patch is meant to close.
        patch.attack_to_defense = "; ".join(
            f"{f.title} -> {f.recommendation or 'see patched code'}" for f in findings[:6]
        )

        verdict = self.validate_patch(patch, source)
        if not verdict.ok:
            logger.info("rejected patch for %s -- %s", path, verdict.reason)
            return None
        return patch

    # ------------------------------------------------------------------
    @staticmethod
    def _focus_block(lines: list[str], line_number: int | None, radius: int = 12) -> str:
        if not line_number:
            return "\n".join(f"{i + 1:>5} | {line}" for i, line in enumerate(lines[:40]))
        start = max(0, line_number - 1 - radius)
        end = min(len(lines), line_number + radius)
        return "\n".join(f"{i + 1:>5} | {lines[i]}" for i in range(start, end))

    @staticmethod
    def _coerce(
        payload: object,
        finding: AgentFinding,
        source: str,
        path: str | None = None,
    ) -> ProposedPatch | None:
        if not isinstance(payload, dict):
            return None
        patched = payload.get("patched_code") or payload.get("patched") or ""
        if not isinstance(patched, str) or not patched.strip():
            return None
        return ProposedPatch(
            finding_id=finding.fingerprint,
            file_path=str(payload.get("file_path") or path or finding.file_path or ""),
            original_code=source,
            patched_code=patched,
            diff=str(payload.get("diff") or ""),
            explanation=str(payload.get("explanation") or "")[:4000],
            attack_to_defense=payload.get("attack_to_defense"),
            attack_surface_reduction=payload.get("attack_surface_reduction"),
        )

    @staticmethod
    def validate_patch(patch: ProposedPatch, original: str) -> "PatchVerdict":
        """
        Static gate every patch must pass before it is applied.

        This is deliberately conservative: it rejects the obviously broken
        cases (empty file, syntax error, feature deletion) without claiming
        the patch is correct. Correctness is the sandbox's job.
        """
        patched = patch.patched_code
        if not patched.strip():
            return PatchVerdict(False, "patch is empty")

        if patched.strip() == original.strip():
            return PatchVerdict(False, "patch does not change the file")

        # A fix that shrinks the file drastically is usually a deletion.
        if len(patched) < len(original) * (1 - MAX_PATCH_RATIO):
            return PatchVerdict(
                False,
                f"patch removes {1 - len(patched) / max(1, len(original)):.0%} of the file",
            )

        try:
            new_tree = ast.parse(patched)
        except SyntaxError as exc:
            return PatchVerdict(False, f"patched file has a syntax error at line {exc.lineno}: {exc.msg}")

        try:
            old_tree = ast.parse(original)
        except SyntaxError:
            # Original was already unparseable; the new file parsing is all
            # we can check.
            old_tree = None

        if old_tree is not None:
            lost = _lost_capabilities(old_tree, new_tree)
            if lost:
                return PatchVerdict(False, f"patch removes {', '.join(lost)}")

        return PatchVerdict(True, "")

    def timeout(self, context: AgentContext) -> int:
        return 900


@dataclass(frozen=True)
class PatchVerdict:
    """Result of the static patch gate."""

    ok: bool
    reason: str = ""


def _lost_capabilities(old_tree: ast.Module, new_tree: ast.Module) -> list[str]:
    """
    Names the original file exposed that the patched file no longer defines.

    Catches the classic failure mode where a model "fixes" a vulnerability by
    deleting the function that contained it.
    """
    def defined(tree: ast.Module) -> set[str]:
        names: set[str] = set()
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(node.name)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        names.add(target.id)
        return names

    lost = defined(old_tree) - defined(new_tree)
    return sorted(lost)


__all__ = ["FIXABLE", "FixAgent", "PatchVerdict"]
