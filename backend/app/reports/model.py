"""
The report data model.

Reports are built from persisted rows into plain, immutable structures first,
then rendered. Keeping rendering separate from assembly means the JSON, Markdown
and HTML outputs are guaranteed to say the same thing, and it means the report
can be tested without a database or a template engine.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ReportGate:
    """One of the four gates that decide whether a fix is trustworthy."""

    name: str
    passed: bool
    detail: str = ""
    duration_ms: float | None = None

    @property
    def label(self) -> str:
        return _GATE_LABELS.get(self.name, self.name.replace("_", " ").title())


_GATE_LABELS = {
    "reproduced": "Exploit reproduces on the original code",
    "applied": "Patch applies cleanly",
    "regression": "Existing tests still pass",
    "rescan": "Finding is gone after the patch",
}


@dataclass(frozen=True)
class ReportTest:
    name: str
    test_type: str
    target_file: str | None
    status: str
    is_exploit_test: bool
    finding_id: str | None
    description: str = ""
    code: str = ""
    duration_ms: float | None = None


@dataclass(frozen=True)
class ReportPatch:
    """A proposed fix and the evidence for or against trusting it."""

    finding_id: str
    file_path: str
    validation_status: str
    verified: bool
    applied: bool
    files_touched: list[str]
    explanation: str = ""
    diff: str = ""
    isolated: bool | None = None
    reason: str = ""
    duration_ms: float | None = None
    repair_notes: str = ""
    gates: list[ReportGate] = field(default_factory=list)

    @property
    def failed_gates(self) -> list[ReportGate]:
        return [g for g in self.gates if not g.passed]

    @property
    def assurance(self) -> str:
        """A one-line, honest statement of what this patch is worth."""
        if self.verified:
            if self.isolated is False:
                return "Verified on the host (no isolation)"
            return "Verified in an isolated sandbox"
        if not self.gates:
            return "Proposed, not verified"
        failed = ", ".join(g.label for g in self.failed_gates)
        return f"Not verified: {failed}"


@dataclass(frozen=True)
class ReportFinding:
    id: str
    fingerprint: str
    title: str
    description: str
    severity: str
    category: str
    status: str
    verified: bool
    is_bug: bool
    certainty: str
    confidence: float
    file_path: str | None
    line_number: int | None
    code_snippet: str | None
    impact: str = ""
    recommendation: str = ""
    cwe: str | None = None
    owasp: str | None = None
    detected_by: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    tests: list[ReportTest] = field(default_factory=list)
    patch: ReportPatch | None = None

    @property
    def location(self) -> str:
        if not self.file_path:
            return "(no location)"
        if self.line_number:
            return f"{self.file_path}:{self.line_number}"
        return self.file_path

    @property
    def metadata(self) -> list[tuple[str, str]]:
        """
        The per-finding detail rows, as label/value pairs.

        Assembled here rather than with conditionals in the templates: inline
        ``{% if %}`` at the end of a Markdown line interacts badly with
        whitespace trimming and silently glues rows together, which is both
        ugly and easy to miss in review.
        """
        severity = self.severity if not self.cwe else f"{self.severity} ({self.cwe})"
        category = self.category if not self.owasp else f"{self.category} · OWASP: {self.owasp}"
        status = self.status
        if self.verified:
            status += " · fix verified by execution"
        detected_by = ", ".join(self.detected_by) if self.detected_by else "unknown"
        if self.tools:
            detected_by += f" · tools: {', '.join(self.tools)}"
        return [
            ("Severity", severity),
            ("Category", category),
            ("Location", self.location),
            ("Certainty", f"{self.certainty} (confidence {self.confidence:.2f})"),
            ("Status", status),
            ("Detected by", detected_by),
        ]


@dataclass(frozen=True)
class ReportAgent:
    name: str
    status: str
    message: str
    findings_count: int
    duration_ms: float | None
    metrics: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


@dataclass(frozen=True)
class ReportEvent:
    seq: int
    phase: str
    message: str
    progress: float | None
    agent: str | None = None


@dataclass(frozen=True)
class ReportSummary:
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    bugs: int
    security_score: int
    tests_generated: int
    verified_fixes: int
    failed_fixes: int

    @property
    def fixed(self) -> int:
        return self.verified_fixes + self.failed_fixes

    @property
    def coverage_pct(self) -> float:
        """Share of findings that reached a verified fix."""
        if not self.total_findings:
            return 0.0
        return round(100.0 * self.verified_fixes / self.total_findings, 1)

    @property
    def remaining(self) -> int:
        return max(0, self.total_findings - self.verified_fixes)


@dataclass(frozen=True)
class ScanReport:
    """Everything a reader needs to judge one scan."""

    scan_id: str
    project_name: str
    project_description: str
    scan_status: str
    started_at: dt.datetime | None
    completed_at: dt.datetime | None
    duration_seconds: float | None
    ai_provider: str | None
    error: str | None
    generated_at: dt.datetime
    summary: ReportSummary
    findings: list[ReportFinding]
    agents: list[ReportAgent]
    events: list[ReportEvent] = field(default_factory=list)
    ingestion_warnings: list[str] = field(default_factory=list)
    isolated: bool | None = None
    sandbox_backend: str | None = None
    #: Patches whose finding could not be resolved. Surfaced rather than
    #: dropped, because a patch nobody can explain is worth a reviewer's time.
    orphan_patches: list[ReportPatch] = field(default_factory=list)

    # -- derived views ------------------------------------------------
    @property
    def tests(self) -> list[ReportTest]:
        seen: set[str] = set()
        out: list[ReportTest] = []
        for finding in self.findings:
            for test in finding.tests:
                if test.name not in seen:
                    seen.add(test.name)
                    out.append(test)
        return out

    @property
    def patches(self) -> list[ReportPatch]:
        return [f.patch for f in self.findings if f.patch is not None]

    @property
    def verified_findings(self) -> list[ReportFinding]:
        return [f for f in self.findings if f.verified]

    @property
    def open_findings(self) -> list[ReportFinding]:
        return [f for f in self.findings if not f.verified]

    @property
    def by_severity(self) -> dict[str, list[ReportFinding]]:
        grouped: dict[str, list[ReportFinding]] = {}
        for finding in self.findings:
            grouped.setdefault(finding.severity, []).append(finding)
        return grouped

    @property
    def assurance_statement(self) -> str:
        """The single most important caveat in the whole report.

        A local sandbox runs untrusted code on the host. If a reader skims a
        report and sees "3 verified fixes", this is the sentence that stops them
        from over-trusting it.
        """
        if self.isolated is False:
            return (
                "**Sandbox isolation: NOT ISOLATED.** The fixes below were executed "
                "on the host, not inside a container. Results are real but were not "
                "confined; do not run this pipeline against code you would not run "
                "locally."
            )
        if self.isolated is True:
            return "**Sandbox isolation: containerised.** Fixes were verified inside a sandbox."
        return "**Sandbox isolation: not recorded.** Treat the verification results as unconfirmed."

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe structure, used by the JSON renderer and the API."""
        return dataclasses.asdict(self)


SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def sort_findings(findings: list[ReportFinding]) -> list[ReportFinding]:
    """Most severe first, then most confident, then stable by id."""
    rank = {name: i for i, name in enumerate(SEVERITY_ORDER)}
    return sorted(
        findings,
        key=lambda f: (rank.get(f.severity, len(SEVERITY_ORDER)), -f.confidence, f.id),
    )
