"""
Four-gate verification, exercised against a real sandbox.

These tests deliberately include negative controls. A verification harness that
only ever sees good patches proves nothing: the value is entirely in the fact
that it *refuses* to bless a vacuous test, a no-op patch, and a patch that
leaves the vulnerability in place.
"""

from __future__ import annotations

import pathlib
import textwrap

import pytest

from app.models.enums import FindingCategory, Severity
from app.providers.mock_brain import PATCHERS, _generate_tests
from app.sandbox.local import LocalExecutor
from app.schemas.finding import AgentFinding, GeneratedTest, ProposedPatch
from app.verification.engine import (
    Gate,
    VerificationEngine,
    VerificationStatus,
    parse_pytest_summary,
)
from app.verification.engine import tests_ran as _tests_ran  # aliased: pytest would collect it


@pytest.fixture
async def executor():
    async with LocalExecutor() as ex:
        yield ex


def _sql_finding() -> AgentFinding:
    return AgentFinding(
        title="SQL Injection: tainted input reaches a query execution",
        severity=Severity.HIGH,
        confidence=0.95,
        category=FindingCategory.INJECTION,
        cwe="CWE-89",
        file_path="database.py",
        line_number=75,
    )


def _exploit_test() -> GeneratedTest:
    """The genuine exploit for the demo's ``/api/search`` endpoint."""
    prompt = (
        "FINDINGS TO REPRODUCE:\n"
        "  - [HIGH] database.py:75 SQL Injection: tainted input reaches a "
        "query execution (Injection)\n"
    )
    blocks = _generate_tests(prompt, [("database.py", "x = 1\n")])
    exploit = next(t for t in blocks if t["is_exploit_test"])
    return GeneratedTest(
        name="test_sqli",
        test_code=exploit["test_code"],
        is_exploit_test=True,
        test_type="security",
        target_file="database.py",
    )


def _patch(original: str) -> ProposedPatch:
    result = PATCHERS["sql_injection"](original)
    assert result is not None, "the mock produced no SQLi patch"
    patched, explanation = result
    return ProposedPatch(
        file_path="database.py",
        original_code=original,
        patched_code=patched,
        diff="(mock)",
        explanation=explanation,
    )


async def _verify(executor, python, demo_repo, finding, patch, test):
    workspace = await executor.prepare(demo_repo)
    try:
        return await VerificationEngine(executor, python=python).verify(
            workspace, finding, patch, test
        )
    finally:
        await executor.cleanup(workspace)


def _gates(result) -> dict[Gate, bool]:
    return {g.gate: g.passed for g in result.gates}


class TestFourGates:
    async def test_a_real_fix_verifies_end_to_end(
        self, executor, python_executable, demo_repo
    ) -> None:
        original = (demo_repo / "database.py").read_text()
        result = await _verify(
            executor, python_executable, demo_repo, _sql_finding(), _patch(original), _exploit_test()
        )
        assert result.status is VerificationStatus.VERIFIED, result.message
        assert _gates(result) == {
            Gate.REPRODUCED: True,
            Gate.APPLIED: True,
            Gate.REGRESSION: True,
            Gate.RESCAN: True,
        }
        assert result.passed_gates == ["reproduced", "applied", "regression", "rescan"]
        assert result.failed_gates == []

    async def test_local_sandbox_is_reported_as_non_isolated(
        self, executor, python_executable, demo_repo
    ) -> None:
        """A local run must never be able to claim it was isolated."""
        original = (demo_repo / "database.py").read_text()
        result = await _verify(
            executor, python_executable, demo_repo, _sql_finding(), _patch(original), _exploit_test()
        )
        assert result.isolated is False

    async def test_reproduction_is_proven_before_the_patch_is_applied(
        self, executor, python_executable, demo_repo
    ) -> None:
        original = (demo_repo / "database.py").read_text()
        result = await _verify(
            executor, python_executable, demo_repo, _sql_finding(), _patch(original), _exploit_test()
        )
        reproduced = next(g for g in result.gates if g.gate is Gate.REPRODUCED)
        assert "failing before the fix" in reproduced.detail


class TestNegativeControls:
    """The cases a verification harness exists to reject."""

    async def test_unpatched_code_is_not_verified(
        self, executor, python_executable, demo_repo
    ) -> None:
        original = (demo_repo / "database.py").read_text()
        result = await _verify(
            executor, python_executable, demo_repo, _sql_finding(), _patch(original), _exploit_test()
        )
        assert result.status is VerificationStatus.VERIFIED

        # Now re-verify the same finding against a patch that changes nothing.
        noop = ProposedPatch(
            file_path="database.py", original_code=original, patched_code=original
        )
        result = await _verify(
            executor, python_executable, demo_repo, _sql_finding(), noop, _exploit_test()
        )
        assert result.status is VerificationStatus.FAILED
        assert Gate.REGRESSION in _gates(result) and not _gates(result)[Gate.REGRESSION]

    async def test_patch_that_deletes_the_vulnerable_function_is_rejected(
        self, executor, python_executable, demo_repo
    ) -> None:
        original = (demo_repo / "database.py").read_text()
        destructive = ProposedPatch(
            file_path="database.py",
            original_code=original,
            patched_code="def get_connection():\n    return None\n",
        )
        result = await _verify(
            executor, python_executable, demo_repo, _sql_finding(), destructive, _exploit_test()
        )
        assert result.status is not VerificationStatus.VERIFIED

    async def test_vacuous_test_cannot_verify_anything(
        self, executor, python_executable, demo_repo
    ) -> None:
        """
        A test that passes on vulnerable code proves nothing. Accepting it
        would let a broken patch be reported as fixed.
        """
        original = (demo_repo / "database.py").read_text()
        vacuous = GeneratedTest(
            name="test_smoke",
            test_code=textwrap.dedent(
                """
                def test_imports():
                    import database  # noqa: F401
                """
            ),
            is_exploit_test=True,
            test_type="security",
            target_file="database.py",
        )
        result = await _verify(
            executor, python_executable, demo_repo, _sql_finding(), _patch(original), vacuous
        )
        assert result.status is VerificationStatus.REQUIRES_REVIEW
        assert not _gates(result)[Gate.REPRODUCED]

    async def test_missing_exploit_test_is_never_verified(
        self, executor, python_executable, demo_repo
    ) -> None:
        original = (demo_repo / "database.py").read_text()
        result = await _verify(
            executor, python_executable, demo_repo, _sql_finding(), _patch(original), None
        )
        assert result.status is not VerificationStatus.VERIFIED

    async def test_a_test_that_errors_does_not_count_as_reproduction(
        self, executor, python_executable, demo_repo
    ) -> None:
        original = (demo_repo / "database.py").read_text()
        broken = GeneratedTest(
            name="test_broken",
            test_code="def test_x():\n    assert undefined_name\n",
            is_exploit_test=True,
            test_type="security",
            target_file="database.py",
        )
        result = await _verify(
            executor, python_executable, demo_repo, _sql_finding(), _patch(original), broken
        )
        assert result.status is not VerificationStatus.VERIFIED


class TestPytestSummaryParsing:
    @pytest.mark.parametrize(
        "output, expected",
        [
            ("1 failed, 4 passed in 0.12s", {"passed": 4, "failed": 1, "errors": 0}),
            ("2 passed in 0.05s", {"passed": 2, "failed": 0, "errors": 0}),
            ("5 passed, 1 failed, 2 errors in 1.00s", {"passed": 5, "failed": 2, "errors": 2}),
            ("no tests ran in 0.01s", {"passed": 0, "failed": 0, "errors": 0}),
            # A collection error counts as a failure: conservative, never as a pass.
            ("!!!! Interrupted: 1 error during collection !!!!", {"passed": 0, "failed": 1, "errors": 1}),
        ],
    )
    def test_summary_is_extracted(self, output: str, expected: dict) -> None:
        summary = parse_pytest_summary(output)
        for key, value in expected.items():
            assert summary[key] == value, f"{key} in {summary}"

    def test_unparseable_output_yields_zeros_not_a_pass(self) -> None:
        for output in ("Segmentation fault", "", "Killed"):
            summary = parse_pytest_summary(output)
            assert summary == {"passed": 0, "failed": 0, "errors": 0, "skipped": 0}

    def test_a_run_with_no_tests_is_not_a_pass(self) -> None:
        assert parse_pytest_summary("no tests ran in 0.01s")["passed"] == 0
        assert _tests_ran("no tests ran in 0.01s") is False

    def test_collection_errors_are_not_treated_as_test_results(self) -> None:
        """A collection error exits non-zero without running anything."""
        assert _tests_ran("error collecting tests/test_x.py") is False
        assert _tests_ran("!!!! Interrupted: 1 error during collection !!!!") is False
        assert _tests_ran("collected 0 items") is False

    def test_a_real_run_is_recognised(self) -> None:
        assert _tests_ran("1 failed, 4 passed in 0.12s") is True
