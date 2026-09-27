"""
Report renderers.

Three outputs, one source of truth:

* **JSON** for machine consumption and re-import.
* **Markdown** for pull-request comments and CI artifacts.
* **HTML** for humans who should not have to read raw diffs.

Two properties matter more than looks:

1. ``render_html`` autoescapes. Code snippets, finding titles and test output
   all originate in an *untrusted scanned repository*, so a report that injects
   them verbatim into HTML would be a stored-XSS vector in the reviewer's
   browser. Markdown fences are computed, never assumed, so a snippet containing
   ``` cannot break out of its block.
2. The verification evidence is always shown, including for fixes that failed.
   A report that only lists successes is marketing, not an audit trail.
"""

from __future__ import annotations

import datetime as dt
import json
import pathlib
import re
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from app.reports.model import ReportFinding, ReportPatch, ScanReport, sort_findings

TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"

_ENV = Environment(
    loader=FileSystemLoader(str(TEMPLATE_DIR)),
    # Autoescape is on for the HTML output and off for Markdown, where the
    # syntax is not HTML and escaping would corrupt the text.
    autoescape=select_autoescape(default_for_string=False, default=False),
    undefined=StrictUndefined,
    trim_blocks=True,
    lstrip_blocks=True,
    keep_trailing_newline=True,
)


def _html_env() -> Environment:
    env = _ENV.overlay(autoescape=True)
    env.filters["fence"] = code_fence
    return env


def _md_env() -> Environment:
    env = _ENV.overlay(autoescape=False)
    env.filters["fence"] = code_fence
    return env


# ----------------------------------------------------------------------
def code_fence(code: str | None) -> str:
    """
    A backtick run long enough to safely wrap ``code``.

    A snippet from an untrusted repository can contain ``` itself. Using a fixed
    three-backtick fence would let it terminate the block early and inject
    arbitrary Markdown (and, once rendered, arbitrary HTML).
    """
    text = code or ""
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    return "`" * max(3, longest + 1)


def _duration(seconds: float | None) -> str:
    if not seconds:
        return "-"
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 60:
        return f"{seconds:.1f} s"
    minutes, secs = divmod(int(seconds), 60)
    return f"{minutes}m {secs}s"


# ----------------------------------------------------------------------
def render_markdown(report: ScanReport) -> str:
    return _md_env().get_template("report.md.j2").render(
        r=report,
        findings=sort_findings(report.findings),
        duration=_duration,
    )


def render_html(report: ScanReport) -> str:
    return _html_env().get_template("report.html.j2").render(
        r=report,
        findings=sort_findings(report.findings),
        duration=_duration,
    )


def render_json(report: ScanReport) -> str:
    payload: dict[str, Any] = {
        "scan_id": report.scan_id,
        "project": {
            "name": report.project_name,
            "description": report.project_description,
        },
        "scan": {
            "status": report.scan_status,
            "started_at": _iso(report.started_at),
            "completed_at": _iso(report.completed_at),
            "duration_seconds": report.duration_seconds,
            "ai_provider": report.ai_provider,
            "error": report.error,
        },
        "generated_at": _iso(report.generated_at),
        "assurance": {
            # Machine-readable form of the headline caveat.
            "isolated": report.isolated,
            "sandbox_backend": report.sandbox_backend,
            "note": "verified fixes were executed on the host"
            if report.isolated is False
            else "verified fixes ran in an isolated sandbox"
            if report.isolated is True
            else "isolation was not recorded for this scan",
        },
        "summary": {
            "total_findings": report.summary.total_findings,
            "critical": report.summary.critical,
            "high": report.summary.high,
            "medium": report.summary.medium,
            "low": report.summary.low,
            "bugs": report.summary.bugs,
            "security_score": report.summary.security_score,
            "tests_generated": report.summary.tests_generated,
            "verified_fixes": report.summary.verified_fixes,
            "failed_fixes": report.summary.failed_fixes,
            "fix_coverage_pct": report.summary.coverage_pct,
        },
        "findings": [_finding_json(f) for f in sort_findings(report.findings)],
        "orphan_patches": [
            {
                "finding_id": p.finding_id,
                "file_path": p.file_path,
                "validation_status": p.validation_status,
                "verified": p.verified,
            }
            for p in report.orphan_patches
        ],
        "tests": [
            {
                "name": t.name,
                "type": t.test_type,
                "target_file": t.target_file,
                "status": t.status,
                "is_exploit_test": t.is_exploit_test,
                "finding_id": t.finding_id,
            }
            for t in report.tests
        ],
        "agents": [
            {
                "name": a.name,
                "status": a.status,
                "findings_count": a.findings_count,
                "duration_ms": a.duration_ms,
                "message": a.message,
                "error": a.error,
            }
            for a in report.agents
        ],
        "timeline": [
            {
                "seq": e.seq,
                "phase": e.phase,
                "message": e.message,
                "progress": e.progress,
                "agent": e.agent,
            }
            for e in report.events
        ],
    }
    if report.ingestion_warnings:
        payload["ingestion_warnings"] = report.ingestion_warnings
    return json.dumps(payload, indent=2, sort_keys=False, default=str) + "\n"


def _finding_json(f: ReportFinding) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": f.id,
        "fingerprint": f.fingerprint,
        "title": f.title,
        "severity": f.severity,
        "category": f.category,
        "status": f.status,
        "verified": f.verified,
        "is_bug": f.is_bug,
        "certainty": f.certainty,
        "confidence": f.confidence,
        "location": f.location,
        "cwe": f.cwe,
        "owasp": f.owasp,
        "detected_by": f.detected_by,
        "tools": f.tools,
        "description": f.description,
        "impact": f.impact,
        "recommendation": f.recommendation,
        "code_snippet": f.code_snippet,
        "tests": [t.name for t in f.tests],
    }
    if f.patch is not None:
        payload["fix"] = _patch_json(f.patch)
    return payload


def _patch_json(p: ReportPatch) -> dict[str, Any]:
    return {
        "file_path": p.file_path,
        "validation_status": p.validation_status,
        "verified": p.verified,
        "applied": p.applied,
        "assurance": p.assurance,
        "isolated": p.isolated,
        "files_touched": p.files_touched,
        "gates": [
            {"gate": g.name, "passed": g.passed, "detail": g.detail} for g in p.gates
        ],
        "reason": p.reason,
        "explanation": p.explanation,
        "diff": p.diff,
    }


def _iso(value: dt.datetime | None) -> str | None:
    return value.isoformat() if isinstance(value, dt.datetime) else None


RENDERERS = {
    "md": ("text/markdown; charset=utf-8", render_markdown, "md"),
    "markdown": ("text/markdown; charset=utf-8", render_markdown, "md"),
    "html": ("text/html; charset=utf-8", render_html, "html"),
    "json": ("application/json; charset=utf-8", render_json, "json"),
}

EXTENSIONS = {"md": "md", "markdown": "md", "html": "html", "json": "json"}
