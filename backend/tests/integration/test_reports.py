"""
Report tests.

Two things are being checked here, in order of importance:

1. **The report does not overstate.** A verified fix is only called verified
   when all four gates are recorded and passing; failed fixes must still be
   visible; the unisolated-sandbox caveat must survive into every format.
2. **The report cannot be used as an attack.** Findings carry text from an
   untrusted scanned repository, so a report must never emit that text as live
   HTML or let it break out of a Markdown code fence.
"""

from __future__ import annotations

import json
import re

import pytest

from app.models.enums import ProjectStatus, ScanStatus
from app.reports.model import (
    ReportAgent,
    ReportFinding,
    ReportGate,
    ReportPatch,
    ReportSummary,
    ReportTest,
    ScanReport,
    sort_findings,
)
from app.reports.renderers import (
    code_fence,
    render_html,
    render_json,
    render_markdown,
)
from app.services.persistence import ScanPersistence
from app.services.reporting import ReportError, load_report, render_report


# ----------------------------------------------------------------------
# Hand-built reports, so renderer tests do not need a database.
# ----------------------------------------------------------------------
def _gates(*, failing: str | None = None) -> list[ReportGate]:
    names = ("reproduced", "applied", "regression", "rescan")
    return [
        ReportGate(
            name=name,
            passed=name != failing,
            detail=f"{name} detail",
        )
        for name in names
    ]


def _patch(**overrides) -> ReportPatch:
    base = dict(
        finding_id="f-1",
        file_path="session.py",
        validation_status="VERIFIED",
        verified=True,
        applied=True,
        files_touched=["session.py"],
        explanation="Bind the session id instead of trusting the cookie.",
        diff="--- a/session.py\n+++ b/session.py",
        isolated=False,
        reason="",
        gates=_gates(),
    )
    base.update(overrides)
    return ReportPatch(**base)


def _finding(**overrides) -> ReportFinding:
    base = dict(
        id="f-1",
        fingerprint="abc123",
        title="Session fixation via untrusted cookie",
        description="The session id is read straight from the request.",
        severity="HIGH",
        category="Session Management",
        status="VERIFIED",
        verified=True,
        is_bug=False,
        certainty="confirmed",
        confidence=0.95,
        file_path="session.py",
        line_number=42,
        code_snippet="session_id = request.cookies['sid']",
        impact="An attacker fixes a victim's session id.",
        recommendation="Generate a new id on login.",
        cwe="CWE-384",
        detected_by=["ast_taint", "security_agent"],
        tools=["semgrep"],
        tests=[
            ReportTest(
                name="test_exploit_session_fixation",
                test_type="security",
                target_file="session.py",
                status="PASSED",
                is_exploit_test=True,
                finding_id="f-1",
            )
        ],
        patch=_patch(),
    )
    base.update(overrides)
    return ReportFinding(**base)


def _report(findings=None, **overrides) -> ScanReport:
    import datetime as dt

    base = dict(
        scan_id="scan-1234567890abcdef",
        project_name="vulnerable-python-app",
        project_description="demo",
        scan_status="COMPLETED",
        started_at=dt.datetime(2026, 1, 1, 12, 0, tzinfo=dt.timezone.utc),
        completed_at=dt.datetime(2026, 1, 1, 12, 0, 9, tzinfo=dt.timezone.utc),
        duration_seconds=9.4,
        ai_provider="mock",
        error=None,
        generated_at=dt.datetime(2026, 1, 1, 12, 0, 10, tzinfo=dt.timezone.utc),
        summary=ReportSummary(
            total_findings=len(findings if findings is not None else [_finding()]),
            critical=0,
            high=1,
            medium=0,
            low=0,
            bugs=0,
            security_score=42,
            tests_generated=1,
            verified_fixes=1,
            failed_fixes=0,
        ),
        findings=findings if findings is not None else [_finding()],
        agents=[
            ReportAgent(
                name="security_agent",
                status="COMPLETED",
                message="57 finding(s)",
                findings_count=57,
                duration_ms=1200.0,
            )
        ],
        events=[
            type("E", (), {"seq": 1, "phase": "ingest", "message": "Reading", "progress": 2.0, "agent": None})()
        ],
        isolated=False,
        sandbox_backend="local (unisolated)",
    )
    base.update(overrides)
    return ScanReport(**base)


# ----------------------------------------------------------------------
class TestFenceSafety:
    def test_plain_code_uses_three_backticks(self) -> None:
        assert code_fence("x = 1") == "```"

    def test_fence_grows_past_embedded_backticks(self) -> None:
        """A snippet from an untrusted repo must not be able to close its block."""
        hostile = "before\n```\n# not a heading\n```\nafter"
        fence = code_fence(hostile)
        assert len(fence) > 3
        # No run of backticks inside the code can match the fence.
        longest = max(len(run) for run in re.findall(r"`+", hostile))
        assert len(fence) > longest

    def test_empty_and_none(self) -> None:
        assert code_fence("") == "```"
        assert code_fence(None) == "```"


class TestMarkdown:
    def test_includes_headline_caveat(self) -> None:
        md = render_markdown(_report())
        assert "NOT ISOLATED" in md
        assert "do not run this pipeline against code you would not run locally" in md.lower()

    def test_includes_every_finding(self) -> None:
        md = render_markdown(
            _report(
                findings=[
                    _finding(),
                    _finding(
                        id="f-2",
                        title="Hardcoded credential",
                        severity="CRITICAL",
                        file_path="config.py",
                        verified=False,
                        status="OPEN",
                        patch=None,
                    ),
                ]
            )
        )
        assert "Session fixation via untrusted cookie" in md
        assert "Hardcoded credential" in md

    def test_states_that_not_everything_was_fixed(self) -> None:
        md = render_markdown(
            _report(
                findings=[_finding(), _finding(id="f-2", verified=False, status="OPEN", patch=None)],
                summary=ReportSummary(2, 0, 2, 0, 0, 0, 40, 1, 1, 0),
            )
        )
        assert "Not everything was fixed" in md

    def test_failed_fixes_are_still_shown(self) -> None:
        md = render_markdown(
            _report(
                findings=[
                    _finding(
                        status="FAILED",
                        verified=False,
                        patch=_patch(
                            verified=False,
                            validation_status="FAILED",
                            gates=_gates(failing="regression"),
                            reason="regression suite failed after patch",
                        ),
                    )
                ],
                summary=ReportSummary(1, 0, 1, 0, 0, 0, 30, 0, 0, 1),
            )
        )
        assert "**FAIL**" in md, "a failed gate must not be hidden"
        assert "regression suite failed after patch" in md

    def test_all_four_gates_are_listed(self) -> None:
        md = render_markdown(_report())
        for label in (
            "Exploit reproduces on the original code",
            "Patch applies cleanly",
            "Existing tests still pass",
            "Finding is gone after the patch",
        ):
            assert label in md

    def test_missing_gates_are_admitted(self) -> None:
        md = render_markdown(
            _report(
                findings=[_finding(verified=False, patch=_patch(verified=False, gates=[]))],
                summary=ReportSummary(1, 0, 1, 0, 0, 0, 20, 0, 0, 1),
            )
        )
        assert "No verification gates were recorded" in md

    def test_hostile_snippet_cannot_break_out(self) -> None:
        md = render_markdown(_report(findings=[_finding(code_snippet="```\n# injected\n```")]))
        # The injected fence is shorter than the one wrapping the snippet.
        assert md.count("```\n# injected\n```") == 1
        assert "```\n# injected\n```\n" in md

    def test_metadata_rows_are_separate_lines(self) -> None:
        """
        Regression: inline ``{% if %}`` at the end of a Markdown line let the
        template's whitespace trimming glue adjacent rows together, so the whole
        detail block collapsed onto one line.
        """
        md = render_markdown(
            _report(findings=[_finding(cwe="CWE-384", owasp="A07:2021", tools=["semgrep"])])
        )
        assert "- **Severity:** HIGH (CWE-384)\n" in md
        assert "- **Category:** Session Management · OWASP: A07:2021\n" in md
        assert "- **Location:** session.py:42\n" in md
        assert ")- **Category:**" not in md
        assert "execution- **Detected by:**" not in md

    def test_metadata_rows_are_built_in_python(self) -> None:
        rows = dict(_finding().metadata)
        assert rows["Severity"] == "HIGH (CWE-384)"
        assert rows["Category"] == "Session Management"
        assert rows["Status"] == "VERIFIED · fix verified by execution"
        assert "semgrep" in rows["Detected by"]
        # A finding with no CWE/OWASP must not render empty decorations.
        plain = dict(_finding(cwe=None, owasp=None, tools=[]).metadata)
        assert plain["Severity"] == "HIGH"
        assert plain["Category"] == "Session Management"
        assert plain["Detected by"] == "ast_taint, security_agent"

    def test_impact_and_recommendation_are_separate_paragraphs(self) -> None:
        md = render_markdown(_report())
        assert "**Impact.** An attacker fixes" in md
        assert "**Recommendation.** Generate a new id" in md

    def test_empty_report_renders(self) -> None:
        md = render_markdown(
            _report(
                findings=[],
                summary=ReportSummary(0, 0, 0, 0, 0, 0, 100, 0, 0, 0),
            )
        )
        assert "No findings were reported" in md
        assert "100 / 100" in md


class TestHtml:
    def test_escapes_script_tags(self) -> None:
        html = render_html(
            _report(findings=[_finding(title="<script>alert(1)</script> xss")])
        )
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html

    def test_escapes_code_snippets(self) -> None:
        html = render_html(
            _report(findings=[_finding(code_snippet='<img src=x onerror="alert(1)">')])
        )
        assert "onerror=\"alert(1)\"" not in html
        assert "&lt;img" in html

    def test_escapes_attributes(self) -> None:
        html = render_html(
            _report(findings=[_finding(file_path='a" onmouseover="alert(1)')])
        )
        assert 'onmouseover="alert(1)' not in html
        # Jinja emits a numeric entity for the quote; either form is safe.
        assert "&#34;" in html or "&quot;" in html

    def test_keeps_the_isolation_caveat(self) -> None:
        html = render_html(_report())
        assert "NOT ISOLATED" in html

    def test_is_a_complete_document(self) -> None:
        html = render_html(_report())
        assert html.lstrip().startswith("<!DOCTYPE html>")
        assert html.rstrip().endswith("</html>")

    def test_isolated_sandbox_says_so(self) -> None:
        html = render_html(
            _report(isolated=True, sandbox_backend=None, findings=[_finding(patch=_patch(isolated=True))])
        )
        assert "containerised" in html
        assert "NOT ISOLATED" not in html

    def test_unrecorded_isolation_is_not_claimed(self) -> None:
        html = render_html(_report(isolated=None, sandbox_backend=None))
        assert "not recorded" in html.lower()


class TestJson:
    def test_round_trips(self) -> None:
        payload = json.loads(render_json(_report()))
        assert payload["scan_id"] == "scan-1234567890abcdef"
        assert payload["summary"]["verified_fixes"] == 1
        assert len(payload["findings"]) == 1
        assert payload["findings"][0]["location"] == "session.py:42"

    def test_records_isolation_honestly(self) -> None:
        payload = json.loads(render_json(_report()))
        assert payload["assurance"]["isolated"] is False
        assert "host" in payload["assurance"]["note"]

    def test_gates_are_machine_readable(self) -> None:
        payload = json.loads(render_json(_report()))
        gates = payload["findings"][0]["fix"]["gates"]
        assert len(gates) == 4
        assert all(g["passed"] for g in gates)
        assert {g["gate"] for g in gates} == {"reproduced", "applied", "regression", "rescan"}

    def test_orphan_patches_are_listed(self) -> None:
        payload = json.loads(
            render_json(
                _report(
                    findings=[],
                    orphan_patches=[_patch(finding_id="missing")],
                    summary=ReportSummary(0, 0, 0, 0, 0, 0, 100, 0, 0, 0),
                )
            )
        )
        assert payload["orphan_patches"][0]["finding_id"] == "missing"

    def test_is_valid_json_even_with_hostile_text(self) -> None:
        payload = json.loads(
            render_json(_report(findings=[_finding(title='</script><script>x')]))
        )
        assert payload["findings"][0]["title"] == '</script><script>x'


class TestOrdering:
    def test_most_severe_first(self) -> None:
        findings = [
            _finding(id="a", severity="LOW"),
            _finding(id="b", severity="CRITICAL"),
            _finding(id="c", severity="MEDIUM"),
            _finding(id="d", severity="HIGH"),
        ]
        assert [f.severity for f in sort_findings(findings)] == [
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
        ]

    def test_ties_break_on_confidence_then_id(self) -> None:
        findings = [
            _finding(id="z", severity="HIGH", confidence=0.5),
            _finding(id="a", severity="HIGH", confidence=0.9),
        ]
        assert [f.id for f in sort_findings(findings)] == ["a", "z"]


class TestDerivedViews:
    def test_open_findings_exclude_verified(self) -> None:
        report = _report(
            findings=[_finding(), _finding(id="f-2", verified=False, patch=None)]
        )
        assert len(report.verified_findings) == 1
        assert len(report.open_findings) == 1

    def test_tests_are_deduplicated(self) -> None:
        shared = ReportTest(
            name="test_shared",
            test_type="security",
            target_file="a.py",
            status="PASSED",
            is_exploit_test=True,
            finding_id="f-1",
        )
        report = _report(
            findings=[_finding(tests=[shared]), _finding(id="f-2", tests=[shared])]
        )
        assert [t.name for t in report.tests] == ["test_shared"]


# ----------------------------------------------------------------------
class TestService:
    @pytest.fixture
    async def stored(self, db_session, outcome, scan_events, demo_repo):
        store = ScanPersistence(db_session)
        project = await store.create_project(
            "vulnerable-python-app", storage_path=str(demo_repo)
        )
        await store.sync_files(project, outcome.snapshot)
        scan = await store.start_scan(project)
        scan.id = outcome.scan_id
        await db_session.flush()
        await store.save_outcome(scan, outcome, list(scan_events))
        return scan.id

    async def test_renders_from_the_database(self, db_session, stored) -> None:
        result = await render_report(db_session, stored, "md")
        assert "Security & Quality Report" in result.body
        assert result.media_type.startswith("text/markdown")
        assert result.filename.endswith(".md")
        assert stored[:8] in result.filename

    @pytest.mark.parametrize(
        "fmt,extension,mime",
        [
            ("md", ".md", "text/markdown"),
            ("markdown", ".md", "text/markdown"),
            ("html", ".html", "text/html"),
            ("json", ".json", "application/json"),
        ],
    )
    async def test_every_format(self, db_session, stored, fmt, extension, mime) -> None:
        result = await render_report(db_session, stored, fmt)
        assert result.filename.endswith(extension)
        assert result.media_type.startswith(mime)
        assert result.body.strip()

    async def test_json_is_parseable_and_complete(self, db_session, stored) -> None:
        payload = json.loads((await render_report(db_session, stored, "json")).body)
        assert payload["summary"]["total_findings"] == 41
        assert payload["summary"]["verified_fixes"] == 3
        assert len(payload["findings"]) == 41
        assert len(payload["agents"]) == 4
        assert payload["assurance"]["isolated"] is False

    async def test_report_lists_the_verified_fixes(self, db_session, stored) -> None:
        payload = json.loads((await render_report(db_session, stored, "json")).body)
        verified = {
            f["fix"]["file_path"]
            for f in payload["findings"]
            if f.get("fix", {}).get("verified")
        }
        assert verified == {"session.py", "database.py", "files.py"}

    async def test_reports_the_unfixed_majority(self, db_session, stored) -> None:
        """A report that only showed successes would misrepresent the scan."""
        body = (await render_report(db_session, stored, "md")).body
        assert "Not everything was fixed" in body
        payload = json.loads((await render_report(db_session, stored, "json")).body)
        assert payload["summary"]["verified_fixes"] < payload["summary"]["total_findings"]

    async def test_unknown_scan_raises(self, db_session) -> None:
        with pytest.raises(ReportError, match="not found"):
            await render_report(db_session, "no-such-scan", "md")

    async def test_unknown_format_is_rejected(self, db_session, stored) -> None:
        with pytest.raises(ReportError, match="unsupported report format"):
            await render_report(db_session, stored, "pdf")

    async def test_report_structure_from_db(self, db_session, stored) -> None:
        report = await load_report(db_session, stored)
        assert report.scan_status == ScanStatus.COMPLETED.value
        assert report.project_name == "vulnerable-python-app"
        assert report.isolated is False, "the local sandbox must not be reported as isolated"
        assert report.summary.coverage_pct < 10
        # The timeline is the whole scan, and the progress bar never regresses.
        assert len(report.events) > 20
        assert report.events[0].phase == "ingest"
        assert report.events[-1].phase == "complete"
        progresses = [e.progress for e in report.events if e.progress is not None]
        assert progresses == sorted(progresses)
        assert progresses[-1] == 100.0

    async def test_agents_are_in_pipeline_order(self, db_session, stored) -> None:
        report = await load_report(db_session, stored)
        assert [a.name for a in report.agents] == [
            "security_agent",
            "bug_hunter",
            "testing_agent",
            "fix_agent",
        ]
