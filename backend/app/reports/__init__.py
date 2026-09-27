"""Report generation: one data model, three renderings."""

from app.reports.builder import build_report
from app.reports.model import (
    ReportAgent,
    ReportEvent,
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

__all__ = [
    "build_report",
    "ReportAgent",
    "ReportEvent",
    "ReportFinding",
    "ReportGate",
    "ReportPatch",
    "ReportSummary",
    "ReportTest",
    "ScanReport",
    "sort_findings",
    "code_fence",
    "render_html",
    "render_json",
    "render_markdown",
]
