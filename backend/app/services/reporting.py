"""
Report generation service.

Ties the read model to persistence: load everything belonging to one scan, build
the report structure, render it in the requested format.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from app.reports.builder import build_report
from app.reports.model import ScanReport
from app.reports.renderers import EXTENSIONS, RENDERERS
from app.services.persistence import ScanPersistence


class ReportError(RuntimeError):
    """Raised when a report cannot be produced for the requested scan."""


@dataclass(frozen=True)
class RenderedReport:
    body: str
    media_type: str
    filename: str


async def load_report(
    session: AsyncSession, scan_id: str
) -> ScanReport:
    """Assemble the report for one scan, or raise :class:`ReportError`."""
    store = ScanPersistence(session)
    scan = await store.get_scan(scan_id)
    if scan is None:
        raise ReportError(f"scan not found: {scan_id}")

    project = await store.get_project(scan.project_id)
    return build_report(
        scan=scan,
        project=project,
        findings=await store.findings_for_scan(scan_id),
        tests=await store.tests_for_scan(scan_id),
        patches=await store.patches_for_scan(scan_id),
        agents=await store.agent_executions_for_scan(scan_id),
        events=await store.events_for_scan(scan_id),
    )


async def render_report(
    session: AsyncSession, scan_id: str, fmt: str = "md"
) -> RenderedReport:
    """Render one scan's report. ``fmt`` is one of md, markdown, html, json."""
    try:
        media_type, renderer, _ = RENDERERS[fmt.lower()]
    except KeyError:
        raise ReportError(
            f"unsupported report format {fmt!r}; expected one of: "
            f"{', '.join(sorted(EXTENSIONS))}"
        ) from None

    report = await load_report(session, scan_id)
    # Only allowlisted suffixes reach the filesystem-facing filename, so a
    # caller-supplied format cannot influence the download name.
    extension = EXTENSIONS[fmt.lower()]
    return RenderedReport(
        body=renderer(report),
        media_type=media_type,
        filename=f"sentinelforge-{report.project_name}-{scan_id[:8]}.{extension}",
    )
