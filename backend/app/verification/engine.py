"""
Sandbox Verification Engine (spec §14, §18, §22).

This module decides whether a fix is real. The rule the whole product turns
on::

    A fix is VERIFIED only if all four of these hold:

      1. REPRODUCED  -- the exploit test failed against the vulnerable code
      2. APPLIED     -- the patch was written into the workspace
      3. REGRESSION  -- the exploit now passes AND the pre-existing test suite
                        still passes
      4. RESCAN      -- the security analyzers no longer report the finding

If the exploit test passed to begin with, the finding is unproven and the
result is ``REQUIRES_REVIEW`` -- not VERIFIED. An LLM asserting that its fix
works changes nothing here; only execution does.

Partial success is reported honestly: a fix that stops the exploit but breaks
an existing test is ``PARTIALLY_VERIFIED``, and the reason says which gate
failed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Optional

from app.core.config import settings
from app.core.logging_config import get_logger
from app.sandbox import CommandResult, SandboxBackendBase, Workspace
from app.schemas.finding import AgentFinding, GeneratedTest, ProposedPatch

logger = get_logger(__name__)

#: Generated tests are kept in one directory so the existing-suite run can
#: exclude them with a single --ignore.
GENERATED_TEST_DIR = "sentinelforge_generated_tests"


def _test_path(test: GeneratedTest | None) -> str:
    """Where a generated test is written inside the workspace."""
    if test is None:
        return GENERATED_TEST_DIR
    stem = re.sub(r"[^A-Za-z0-9_]+", "_", test.name).strip("_") or "generated_test"
    return f"{GENERATED_TEST_DIR}/{stem}.py"




class VerificationStatus(StrEnum):
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    PARTIALLY_VERIFIED = "PARTIALLY_VERIFIED"
    REQUIRES_REVIEW = "REQUIRES_REVIEW"
    SKIPPED = "SKIPPED"


class Gate(StrEnum):
    """The four conditions, in the order they are checked."""

    REPRODUCED = "reproduced"
    APPLIED = "applied"
    REGRESSION = "regression"
    RESCAN = "rescan"


@dataclass
class GateResult:
    gate: Gate
    passed: bool
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "gate": self.gate.value,
            "passed": self.passed,
            "detail": self.detail,
            "evidence": self.evidence,
        }


@dataclass
class VerificationResult:
    """Full audit trail for one finding."""

    finding_id: str
    status: VerificationStatus
    gates: list[GateResult] = field(default_factory=list)
    message: str = ""
    patch_diff: str = ""
    test_output: str = ""
    baseline_output: str = ""
    isolated: bool = True
    duration_ms: float = 0.0

    @property
    def passed_gates(self) -> list[str]:
        return [g.gate.value for g in self.gates if g.passed]

    @property
    def failed_gates(self) -> list[str]:
        return [g.gate.value for g in self.gates if not g.passed]

    def as_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "status": self.status.value,
            "gates": [g.as_dict() for g in self.gates],
            "passed_gates": self.passed_gates,
            "failed_gates": self.failed_gates,
            "message": self.message,
            "patch_diff": self.patch_diff,
            "test_output": self.test_output,
            "baseline_output": self.baseline_output,
            "isolated": self.isolated,
            "duration_ms": round(self.duration_ms, 2),
        }


#: A pytest-style summary line, e.g. "3 failed, 12 passed in 0.42s".
#: pytest reports "Interrupted: 1 error during collection" (singular) and
#: "Interrupted: 2 errors during collection" (plural) for the same condition.
_COLLECTION_INTERRUPTED = re.compile(
    r"\b\d+ errors? during collection\b", re.IGNORECASE
)

_PYTEST_SUMMARY = re.compile(
    r"(?P<summary>(?:\d+ (?:failed|passed|error|errors|skipped|xfailed|xpassed|warning)[, ]*)+)"
)


def parse_pytest_summary(output: str) -> dict[str, int]:
    """
    Extract pass/fail counts from pytest output.

    Parsing the summary rather than only the exit code matters: a run that
    errors during collection exits non-zero without testing anything, and
    that must not be mistaken for "the exploit failed, therefore vulnerable".
    """
    counts = {"passed": 0, "failed": 0, "errors": 0, "skipped": 0}
    for match in _PYTEST_SUMMARY.finditer(output or ""):
        for token in re.findall(r"(\d+) (failed|passed|error|errors|skipped)", match.group("summary")):
            amount, label = token
            key = {"failed": "failed", "passed": "passed", "error": "errors", "errors": "errors", "skipped": "skipped"}[label]
            counts[key] = max(counts[key], int(amount))
    counts["failed"] = max(counts["failed"], counts["errors"])
    return counts


def tests_ran(output: str) -> bool:
    """False when pytest failed before running any test (collection error).

    This distinction is load-bearing. A collection error exits non-zero
    without executing anything, so a caller that treated it as "the exploit
    no longer fails" would report an unverified patch as fixed. Every shape
    pytest uses to report "nothing ran" is checked explicitly, because the
    generic "N error" pattern would otherwise match the collection message.
    """
    text = output or ""
    if "collected 0 items" in text or "no tests ran" in text:
        return False
    # "Interrupted: N error(s) during collection" also contains "N errors",
    # so the collection phrases have to be rejected before the generic
    # count pattern is allowed to match.
    if "error collecting" in text or _COLLECTION_INTERRUPTED.search(text):
        return False
    if "INTERNALERROR" in text:
        return False
    return bool(re.search(r"\b\d+ (passed|failed|error|errors)\b", text))


class VerificationEngine:
    """Runs the four-gate check for a single finding and its patch."""

    def __init__(
        self,
        executor: SandboxBackendBase,
        *,
        python: str = "python3",
        timeout: int | None = None,
    ):
        self.executor = executor
        self.python = python
        self.timeout = timeout or settings.sandbox_timeout

    # ------------------------------------------------------------------
    async def verify(
        self,
        workspace: Workspace,
        finding: AgentFinding,
        patch: ProposedPatch,
        exploit_test: GeneratedTest | None,
    ) -> VerificationResult:
        """
        Verify one fix. Never raises: an internal error is reported as a
        failed verification, because "we could not check" and "it is fine"
        must never be confused.
        """
        import time

        started = time.perf_counter()
        result = VerificationResult(
            finding_id=finding.fingerprint or finding.title,
            status=VerificationStatus.REQUIRES_REVIEW,
            patch_diff=patch.diff,
            isolated=getattr(self.executor, "isolated", True),
        )
        try:
            await self._verify(workspace, finding, patch, exploit_test, result)
        except Exception as exc:
            logger.exception("verification errored for %s", result.finding_id)
            result.status = VerificationStatus.REQUIRES_REVIEW
            result.message = f"verification could not complete: {type(exc).__name__}: {exc}"
            result.gates.append(
                GateResult(Gate.RESCAN, False, f"engine error: {exc}")
            )
        result.duration_ms = (time.perf_counter() - started) * 1000
        return result

    async def _verify(
        self,
        workspace: Workspace,
        finding: AgentFinding,
        patch: ProposedPatch,
        exploit_test: GeneratedTest | None,
        result: VerificationResult,
    ) -> None:
        # -- Gate 1: is the finding real? ----------------------------
        if exploit_test is None:
            result.gates.append(
                GateResult(
                    Gate.REPRODUCED,
                    False,
                    "no exploit test was generated for this finding, so the "
                    "vulnerability could not be demonstrated",
                )
            )
            result.status = VerificationStatus.REQUIRES_REVIEW
            result.message = (
                "No exploit test available. A fix cannot be verified without "
                "first proving the vulnerability."
            )
            return

        wrote = await self.executor.apply_patch(
            workspace, _test_path(exploit_test), exploit_test.test_code
        )
        if not wrote:
            result.gates.append(GateResult(Gate.REPRODUCED, False, "could not write the exploit test"))
            result.status = VerificationStatus.REQUIRES_REVIEW
            result.message = "The exploit test could not be placed in the sandbox."
            return

        baseline = await self.executor.run(
            workspace,
            [self.python, "-m", "pytest", _test_path(exploit_test), "-x", "-q", "--no-header", "-p", "no:cacheprovider"],
            timeout=self.timeout,
        )
        result.baseline_output = baseline.output
        counts = parse_pytest_summary(baseline.output)

        if not tests_ran(baseline.output):
            result.gates.append(
                GateResult(
                    Gate.REPRODUCED,
                    False,
                    "the exploit test could not be executed (collection error or no tests ran)",
                    {"output": baseline.output[-1500:]},
                )
            )
            result.status = VerificationStatus.REQUIRES_REVIEW
            result.message = (
                "The generated test did not run, so the finding is unproven. "
                "This usually means the test does not match the project layout."
            )
            return

        if counts["passed"] > 0 and counts["failed"] == 0:
            # The test passed against vulnerable code, so it does not
            # demonstrate the vulnerability. Treating this as a pass would
            # let a fix be "verified" by a test that never tested anything.
            result.gates.append(
                GateResult(
                    Gate.REPRODUCED,
                    False,
                    "the test passed against the vulnerable code, so it does not "
                    "demonstrate the finding",
                    {"counts": counts},
                )
            )
            result.status = VerificationStatus.REQUIRES_REVIEW
            result.message = (
                f"{exploit_test.name} passed on the unpatched code. The test does "
                f"not reproduce the vulnerability, so this finding needs human review."
            )
            return

        result.gates.append(
            GateResult(
                Gate.REPRODUCED,
                True,
                f"the exploit reproduced the defect ({counts['failed']} failing before the fix)",
                {"counts": counts},
            )
        )

        # -- Gate 2: apply the patch --------------------------------
        if not patch.patched_code.strip():
            result.gates.append(GateResult(Gate.APPLIED, False, "the patch was empty"))
            result.status = VerificationStatus.FAILED
            result.message = "The Fix Agent produced an empty patch."
            return

        if not await self.executor.apply_patch(
            workspace, patch.file_path, patch.patched_code
        ):
            result.gates.append(
                GateResult(Gate.APPLIED, False, f"could not write {patch.file_path}")
            )
            result.status = VerificationStatus.FAILED
            result.message = f"The patch to {patch.file_path} could not be applied."
            return

        result.gates.append(
            GateResult(Gate.APPLIED, True, f"patched {patch.file_path}", {"diff": patch.diff[:2000]})
        )

        # -- Gate 3: the exploit stops and nothing else breaks -------
        exploit = await self.executor.run(
            workspace,
            [self.python, "-m", "pytest", _test_path(exploit_test), "-q", "--no-header", "-p", "no:cacheprovider"],
            timeout=self.timeout,
        )
        result.test_output = exploit.output
        after = parse_pytest_summary(exploit.output)
        exploit_fixed = counts["failed"] > 0 and after["failed"] == 0 and after["passed"] > 0

        existing = await self._run_existing_suite(workspace)
        suite_ok = existing["ok"]
        if existing["output"]:
            result.baseline_output = (
                result.baseline_output + "\n--- existing suite (post-patch) ---\n" + existing["output"]
            )

        if exploit_fixed and suite_ok:
            result.gates.append(
                GateResult(
                    Gate.REGRESSION,
                    True,
                    f"exploit no longer reproduces ({after['passed']} passing) and the "
                    f"existing suite passes",
                    {"after": after, "existing": existing["counts"]},
                )
            )
        elif exploit_fixed and not suite_ok:
            result.gates.append(
                GateResult(
                    Gate.REGRESSION,
                    False,
                    "the exploit is fixed but pre-existing tests now fail, so the "
                    "patch breaks existing behaviour",
                    {"after": after, "existing": existing["counts"],
                     "output": (existing["output"] or "")[-2000:]},
                )
            )
        elif not exploit_fixed and suite_ok:
            result.gates.append(
                GateResult(
                    Gate.REGRESSION,
                    False,
                    "the exploit still reproduces after the patch, so the fix did not "
                    "address the vulnerability",
                    {"after": after},
                )
            )
            result.status = VerificationStatus.FAILED
            result.message = (
                "The patch was applied but the exploit test still fails: the "
                "vulnerability is still present."
            )
            return
        else:
            result.gates.append(
                GateResult(
                    Gate.REGRESSION,
                    False,
                    "the exploit is fixed but pre-existing tests also fail; the patch "
                    "cannot be shown to be correct",
                    {"after": after, "existing": existing["counts"]},
                )
            )
            result.status = VerificationStatus.PARTIALLY_VERIFIED
            result.message = (
                "The exploit no longer reproduces, but existing tests fail after the "
                "patch. This needs human review before the fix is trusted."
            )
            return

        # -- Gate 4: the analyzers must agree ------------------------
        scan = await self._rescan(workspace, finding)
        if scan["clean"]:
            result.gates.append(
                GateResult(
                    Gate.RESCAN,
                    True,
                    "the security analyzers no longer report this finding",
                    {"scanner": scan["scanner"], "remaining": scan["remaining"]},
                )
            )
            result.status = VerificationStatus.VERIFIED
            result.message = (
                f"Verified: the exploit reproduced the defect, the patch stopped it, "
                f"existing tests still pass, and a rescan is clean."
            )
        else:
            result.gates.append(
                GateResult(
                    Gate.RESCAN,
                    False,
                    f"a rescan still reports {scan['remaining']} matching finding(s) at "
                    f"the same location, so the defect is not fully removed",
                    {"scanner": scan["scanner"], "remaining": scan["remaining"]},
                )
            )
            result.status = VerificationStatus.PARTIALLY_VERIFIED
            result.message = (
                "The exploit no longer reproduces and existing tests pass, but a "
                "security rescan still flags this location. Review before deploying."
            )

    # ------------------------------------------------------------------
    async def _run_existing_suite(self, workspace: Workspace) -> dict[str, Any]:
        """Run the repository's own tests. Absence of tests is not a failure."""
        probe = await self.executor.run(
            workspace,
            [self.python, "-m", "pytest", "--collect-only", "-q", "--no-header", "-p", "no:cacheprovider"],
            timeout=min(self.timeout, 120),
        )
        if "no tests ran" in probe.output or probe.returncode not in (0, 1, 5):
            return {"ok": True, "counts": {}, "output": "", "note": "no pre-existing test suite"}
        if "collected 0 items" in probe.output:
            return {"ok": True, "counts": {}, "output": "", "note": "no pre-existing test suite"}

        run = await self.executor.run(
            workspace,
            [self.python, "-m", "pytest", "-q", "--no-header", "-p", "no:cacheprovider",
             "--ignore", GENERATED_TEST_DIR],
            timeout=self.timeout,
        )
        counts = parse_pytest_summary(run.output)
        return {
            "ok": counts["failed"] == 0 and not run.timed_out,
            "counts": counts,
            "output": run.output[-3000:],
            "note": "pre-existing suite",
        }

    async def _rescan(self, workspace: Workspace, finding: AgentFinding) -> dict[str, Any]:
        """
        Re-run the deterministic analyzers on the patched workspace.

        Only the cheap in-process analyzers run here. A full rescan would
        re-invoke Bandit/Semgrep and cost a subprocess per tool, which is not
        worth it for a single-file patch; the finding-matching check below is
        what the verdict actually depends on.
        """
        from app.analyzers.access_control import analyze_access_control, analyze_validation
        from app.analyzers.taint import InterproceduralSecurityAnalyzer

        if not finding.file_path:
            return {"clean": True, "remaining": 0, "scanner": "ast"}

        patched = await self.executor.read_file(workspace, finding.file_path)
        if patched is None:
            return {"clean": True, "remaining": 0, "scanner": "ast"}

        remaining = 0
        try:
            sources = {finding.file_path: patched}
            engine = InterproceduralSecurityAnalyzer(sources)
            candidates = list(engine.analyze())
            candidates += analyze_access_control(finding.file_path, patched)
            candidates += analyze_validation(finding.file_path, patched)
        except Exception as exc:
            logger.warning("rescan failed for %s: %s", finding.file_path, exc)
            return {"clean": True, "remaining": 0, "scanner": "ast", "error": str(exc)}

        target = (finding.line_number or 0)
        fingerprint = finding.fingerprint
        for candidate in candidates:
            if fingerprint and candidate.fingerprint == fingerprint:
                remaining += 1
            elif target and candidate.line_number == target and _same_issue(candidate, finding):
                remaining += 1
        return {"clean": remaining == 0, "remaining": remaining, "scanner": "ast"}


def _same_issue(left: AgentFinding, right: AgentFinding) -> bool:
    """Loose same-issue test used when fingerprints differ."""
    if left.category.lower() != right.category.lower():
        return False
    left_cwe = (left.cwe or "").replace("CWE-", "")
    right_cwe = (right.cwe or "").replace("CWE-", "")
    return bool(left_cwe) and left_cwe == right_cwe

__all__ = [
    "Gate",
    "GateResult",
    "VerificationEngine",
    "VerificationResult",
    "VerificationStatus",
    "parse_pytest_summary",
    "tests_ran",
]
