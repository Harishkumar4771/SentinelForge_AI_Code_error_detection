"""
End-to-end pipeline tests.

One full scan of the controlled vulnerable repository, with the properties that
must hold no matter which agents happen to succeed:

* the scan completes and produces findings;
* the vulnerable files are found, and the safe one is not;
* verification verdicts are propagated onto findings honestly;
* a failing agent degrades the result instead of failing the scan.
"""

from __future__ import annotations

import pytest
import pytest_asyncio

from app.models.enums import FindingStatus, ScanStatus, Severity
from app.services.orchestrator import ScanOrchestrator
from app.verification.engine import VerificationStatus


# Module-scoped so the (slow) scan runs once for the whole module. An async
# fixture at module scope needs a module-scoped event loop to match.
@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def outcome(demo_repo, python_executable):
    """One real scan, shared by the assertions below."""
    return await ScanOrchestrator().run(
        demo_repo, project_id="demo", python=python_executable
    )


class TestScanCompletes:
    async def test_scan_reaches_completed(self, outcome) -> None:
        assert outcome.status is ScanStatus.COMPLETED
        assert outcome.duration_ms > 0
        assert not outcome.errors, f"scan reported errors: {outcome.errors}"

    async def test_findings_are_correlated_and_deduplicated(self, outcome) -> None:
        stats = outcome.correlation_stats
        assert stats["input_count"] >= stats["output_count"], "correlation grew the finding count"
        assert len(outcome.findings) == stats["output_count"]
        assert len(outcome.findings) < stats["input_count"], (
            "correlation did not merge anything; duplicates should collapse"
        )

    async def test_every_finding_is_usable(self, outcome) -> None:
        for finding in outcome.findings:
            assert finding.title and finding.fingerprint
            assert finding.severity in set(Severity)
            assert 0.0 <= finding.confidence <= 1.0
            assert finding.description, f"{finding.title} has no description"

    async def test_agents_report_their_own_outcome(self, outcome) -> None:
        for name in ("security_agent", "bug_hunter", "testing_agent", "fix_agent"):
            assert name in outcome.agent_messages, f"{name} produced no message"
            assert outcome.agent_messages[name]


class TestSignalQuality:
    async def test_known_vulnerable_files_are_reported(self, outcome) -> None:
        by_file: dict[str, list] = {}
        for finding in outcome.findings:
            by_file.setdefault(finding.file_path, []).append(finding)

        assert any(
            f.category == "Injection" for f in by_file.get("database.py", [])
        ), "the known SQL injection was missed"
        assert any(
            f.category == "Insecure Deserialization" for f in by_file.get("session.py", [])
        ), "the known pickle deserialization was missed"
        assert any(
            f.category == "Path Traversal" for f in by_file.get("files.py", [])
        ), "the known path traversal was missed"

    async def test_parameterized_query_is_not_reported(self, outcome) -> None:
        """The false positive that once hijacked the exploit test."""
        auth_findings = [
            f for f in outcome.findings if f.file_path == "auth.py" and f.category == "Injection"
        ]
        assert auth_findings == [], f"safe parameterized query flagged: {auth_findings}"

    async def test_exploit_tests_exist_for_each_verified_finding(self, outcome) -> None:
        exploit_files = {t.target_file for t in outcome.test_cases if t.is_exploit_test}
        for result in outcome.verifications:
            if result.status is VerificationStatus.VERIFIED:
                finding = next(
                    f for f in outcome.findings if f.fingerprint == result.finding_id
                )
                assert finding.file_path in exploit_files, (
                    f"{finding.file_path} was verified without an exploit test"
                )


class TestHonestVerification:
    async def test_the_three_known_defects_are_verified(self, outcome) -> None:
        verified = {f.file_path for f in outcome.verified_findings}
        assert {"session.py", "database.py", "files.py"} <= verified, (
            f"expected the three fixable defects to verify, got {verified}"
        )

    async def test_only_verified_findings_are_marked_verified(self, outcome) -> None:
        verdicts = {v.finding_id: v.status for v in outcome.verifications}
        for finding in outcome.findings:
            verdict = verdicts.get(finding.fingerprint)
            if verdict is None:
                assert not finding.verified, (
                    f"{finding.title} is marked verified with no verification at all"
                )
            else:
                assert finding.verified is (verdict is VerificationStatus.VERIFIED)

    async def test_unverified_findings_stay_open_for_review(self, outcome) -> None:
        verdicts = {v.finding_id: v.status for v in outcome.verifications}
        for finding in outcome.findings:
            verdict = verdicts.get(finding.fingerprint)
            if verdict is not None and verdict is not VerificationStatus.VERIFIED:
                assert finding.status is not FindingStatus.VERIFIED
                assert finding.status in {
                    FindingStatus.OPEN,
                    FindingStatus.FIX_PROPOSED,
                    FindingStatus.REQUIRES_REVIEW,
                }

    async def test_local_sandbox_results_are_flagged_non_isolated(self, outcome) -> None:
        assert all(result.isolated is False for result in outcome.verifications)
        assert any("UNISOLATED" in w for w in outcome.warnings), (
            "running untrusted code on the host must be surfaced as a warning"
        )

    async def test_more_finding_types_remain_than_are_fixed(self, outcome) -> None:
        """
        Three verified fixes out of dozens of findings is the honest outcome.
        A run that "fixed" everything would mean the gates are too weak.
        """
        assert len(outcome.verified_findings) < len(outcome.findings) / 5


class TestSecurityScore:
    def test_clean_input_scores_full_marks(self) -> None:
        from app.schemas.finding import AgentFinding

        assert ScanOrchestrator._security_score([]) == 100

    def test_score_decreases_with_severity(self) -> None:
        from app.schemas.finding import AgentFinding

        def one(severity):
            return [AgentFinding(title="x" * 60, severity=severity)]

        assert (
            ScanOrchestrator._security_score(one(Severity.LOW))
            > ScanOrchestrator._security_score(one(Severity.MEDIUM))
            > ScanOrchestrator._security_score(one(Severity.HIGH))
            > ScanOrchestrator._security_score(one(Severity.CRITICAL))
        )

    def test_score_stays_in_range_and_discriminates(self) -> None:
        from app.schemas.finding import AgentFinding

        def many(severity, n):
            return [AgentFinding(title="x" * 60, severity=severity) for _ in range(n)]

        assert ScanOrchestrator._security_score(many(Severity.CRITICAL, 10)) > 0
        assert ScanOrchestrator._security_score(many(Severity.CRITICAL, 500)) >= 0
        # The demo repo's shape must not bottom out at zero.
        demo = (
            many(Severity.CRITICAL, 2) + many(Severity.HIGH, 21)
            + many(Severity.MEDIUM, 17) + many(Severity.LOW, 1)
        )
        assert 0 < ScanOrchestrator._security_score(demo) < 100


class TestFailureContainment:
    async def test_a_crashed_agent_does_not_fail_the_scan(
        self, demo_repo, python_executable
    ) -> None:
        class ExplodingBugHunter:
            name = "bug_hunter"

            async def run(self, context):
                raise RuntimeError("agent exploded")

        outcome = await ScanOrchestrator(
            bug_hunter=ExplodingBugHunter(), verify=False
        ).run(demo_repo, project_id="demo", python=python_executable)

        assert outcome.status is ScanStatus.COMPLETED
        assert any("bug_hunter" in e for e in outcome.errors)
        # The security agent's findings still made it through.
        assert outcome.findings

    async def test_verification_can_be_skipped_and_says_so(
        self, demo_repo, python_executable
    ) -> None:
        outcome = await ScanOrchestrator(verify=False).run(
            demo_repo, project_id="demo", python=python_executable
        )
        assert outcome.verifications == []
        assert any("skipped" in w.lower() for w in outcome.warnings)
        assert not any(f.verified for f in outcome.findings)

    async def test_unreadable_repository_fails_cleanly(self, tmp_path) -> None:
        outcome = await ScanOrchestrator().run(tmp_path / "does-not-exist")
        assert outcome.status is ScanStatus.FAILED
        assert outcome.errors
        assert not outcome.findings


class TestProgressReporting:
    async def test_progress_is_monotonic_and_reaches_100(
        self, demo_repo, python_executable
    ) -> None:
        events: list[dict] = []
        await ScanOrchestrator(on_progress=events.append).run(
            demo_repo, project_id="demo", python=python_executable
        )
        assert events
        progresses = [e["progress"] for e in events]
        assert progresses == sorted(progresses), "progress went backwards"
        assert progresses[-1] == 100.0
        assert all(0.0 <= p <= 100.0 for p in progresses)

    async def test_a_broken_progress_hook_does_not_break_the_scan(
        self, demo_repo, python_executable
    ) -> None:
        def explode(event):
            raise RuntimeError("bad hook")

        outcome = await ScanOrchestrator(on_progress=explode, verify=False).run(
            demo_repo, project_id="demo", python=python_executable
        )
        assert outcome.status is ScanStatus.COMPLETED
