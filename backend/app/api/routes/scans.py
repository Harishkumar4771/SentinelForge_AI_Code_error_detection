"""
Scan endpoints: start a scan, poll its result, stream progress, cancel it.

The scan runs in a background task owned by :mod:`app.services.scan_manager`.
The HTTP request returns as soon as the task is scheduled, so a scan never
times out at the proxy; the client follows progress over SSE or polls the scan
resource.
"""

from __future__ import annotations

import asyncio
import json
import pathlib
from collections.abc import AsyncGenerator

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import config
from app.core.database import get_db, session_scope
from app.models.entities import AgentExecution
from app.models.enums import Severity
from app.core.logging_config import get_logger
from app.schemas.api import (
    AgentExecutionOut,
    FindingOut,
    PatchOut,
    ScanAccepted,
    ScanDetail,
    ScanEventOut,
    ScanOut,
    TestCaseOut,
)
from app.services.persistence import ScanPersistence
from app.services import scan_manager
from app.services.scan_manager import _SENTINEL

logger = get_logger(__name__)
router = APIRouter(prefix="/scans", tags=["scans"])

#: How long an idle SSE connection waits before sending a keepalive comment.
SSE_KEEPALIVE_SECONDS = 15.0


@router.post(
    "/projects/{project_id}",
    response_model=ScanAccepted,
    status_code=status.HTTP_202_ACCEPTED,
)
async def start_scan(
    project_id: str,
    verify: bool = Query(True, description="Run sandbox verification on proposed patches"),
    session: AsyncSession = Depends(get_db),
) -> ScanAccepted:
    """Queue a scan for a project and return immediately."""
    store = ScanPersistence(session)
    project = await store.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="project not found")
    if not project.storage_path:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="project has no indexed repository on disk",
        )
    repository = pathlib.Path(project.storage_path)
    if not repository.is_dir():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"repository is no longer on disk: {repository}",
        )
    scan = await store.start_scan(project, ai_provider=config.settings.ai_provider)
    running = scan_manager.manager.register(scan.id, project.id, repository)

    scan_manager.manager.start(running, _make_runner(project.id, scan.id, repository, verify))
    logger.info("scan %s queued for project %s", scan.id, project.id)

    return ScanAccepted(
        scan_id=scan.id,
        project_id=project.id,
        status=scan.status,
        stream_url=f"/api/scans/{scan.id}/stream",
    )


def _make_runner(project_id: str, scan_id: str, repository, verify: bool):
    """Build the coroutine that runs and persists one scan."""

    async def runner(running) -> None:
        from app.models.enums import ScanStatus as _Status
        from app.services.orchestrator import ScanOrchestrator

        orchestrator = ScanOrchestrator(on_progress=running.publish, verify=verify)
        outcome = await orchestrator.run(
            repository,
            project_id=project_id,
            scan_id=scan_id,
            python=_interpreter(),
        )

        async with session_scope() as db_session:
            store = ScanPersistence(db_session)
            scan = await store.get_scan(scan_id)
            if scan is None:
                # The project was deleted mid-scan; there is nothing to attach
                # the result to, but the run still completed.
                logger.warning("scan %s finished with no database row", scan_id)
                return
            await store.save_outcome(scan, outcome, list(running.events))

        running.publish(
            {
                "scan_id": scan_id,
                "phase": "stored",
                "message": "Result persisted",
                "progress": 100.0,
                "summary": outcome.summary.model_dump(),
            }
        )
        return outcome

    return runner


def _interpreter() -> str:
    """
    Interpreter the sandbox should use to run the target's tests.

    An absolute path is required, and it must *not* be resolved: the venv's
    ``bin/python`` is a symlink to the base interpreter, and resolving it drops
    the virtualenv's site-packages from ``sys.path``.
    """
    configured = config.settings.__dict__.get("sandbox_python")
    candidate = pathlib.Path(configured) if configured else pathlib.Path(".venv/bin/python")
    if not candidate.is_absolute():
        candidate = config.settings.base_dir / candidate
    if candidate.exists():
        return str(candidate.absolute())
    import sys

    return sys.executable


@router.get("", response_model=list[ScanOut])
async def list_scans(
    project_id: str | None = None,
    limit: int = 50,
    session: AsyncSession = Depends(get_db),
) -> list[ScanOut]:
    store = ScanPersistence(session)
    if project_id:
        scans = await store.list_scans(project_id, limit)
    else:
        from app.models.entities import Scan

        result = await session.scalars(
            select(Scan).order_by(Scan.created_at.desc()).limit(limit)
        )
        scans = list(result)
    return [ScanOut.model_validate(s) for s in scans]


@router.get("/{scan_id}", response_model=ScanDetail)
async def get_scan(
    scan_id: str,
    session: AsyncSession = Depends(get_db),
) -> ScanDetail:
    """Full scan result: findings, tests, patches and agent runs."""
    store = ScanPersistence(session)
    scan = await store.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")

    agents_result = await session.scalars(
        select(AgentExecution).where(AgentExecution.scan_id == scan_id)
    )
    return ScanDetail(
        scan=ScanOut.model_validate(scan),
        findings=[FindingOut.model_validate(f) for f in await store.findings_for_scan(scan_id)],
        tests=[TestCaseOut.model_validate(t) for t in await store.tests_for_scan(scan_id)],
        patches=[PatchOut.model_validate(p) for p in await store.patches_for_scan(scan_id)],
        agents=[AgentExecutionOut.model_validate(a) for a in agents_result],
    )


@router.get("/{scan_id}/findings", response_model=list[FindingOut])
async def list_findings(
    scan_id: str,
    severity: Severity | None = Query(
        None, description="Filter by severity; an unknown value is rejected, not ignored"
    ),
    verified: bool | None = Query(
        None, description="Filter by whether the fix passed the verification gates"
    ),
    session: AsyncSession = Depends(get_db),
) -> list[FindingOut]:
    store = ScanPersistence(session)
    if await store.get_scan(scan_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    findings = await store.findings_for_scan(scan_id)
    # Filtering is case-insensitive but must be an explicit choice: a typo that
    # silently returned everything would look like a correct answer.
    if severity is not None:
        findings = [f for f in findings if f.severity == severity.value]
    if verified is not None:
        findings = [f for f in findings if f.verified is verified]
    return [FindingOut.model_validate(f) for f in findings]


@router.get("/{scan_id}/patches", response_model=list[PatchOut])
async def list_patches(
    scan_id: str,
    session: AsyncSession = Depends(get_db),
) -> list[PatchOut]:
    store = ScanPersistence(session)
    if await store.get_scan(scan_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    return [PatchOut.model_validate(p) for p in await store.patches_for_scan(scan_id)]


@router.get("/{scan_id}/tests", response_model=list[TestCaseOut])
async def list_tests(
    scan_id: str,
    session: AsyncSession = Depends(get_db),
) -> list[TestCaseOut]:
    store = ScanPersistence(session)
    if await store.get_scan(scan_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    return [TestCaseOut.model_validate(t) for t in await store.tests_for_scan(scan_id)]


@router.get("/{scan_id}/events", response_model=list[ScanEventOut])
async def list_events(
    scan_id: str,
    session: AsyncSession = Depends(get_db),
) -> list[ScanEventOut]:
    """Persisted timeline, for clients that reconnect after a scan ended."""
    store = ScanPersistence(session)
    if await store.get_scan(scan_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    return [ScanEventOut.model_validate(e) for e in await store.events_for_scan(scan_id)]


@router.post("/{scan_id}/cancel", status_code=status.HTTP_202_ACCEPTED)
async def cancel_scan(scan_id: str) -> dict[str, str]:
    if await scan_manager.manager.cancel(scan_id):
        return {"scan_id": scan_id, "status": "CANCELLED"}
    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="scan is not running (it already finished or was never started)",
    )


@router.get("/{scan_id}/stream")
async def stream_scan(scan_id: str) -> StreamingResponse:
    """
    Server-sent events for one scan.

    Implemented on a plain StreamingResponse rather than a SSE library: the
    protocol is three lines of text framing, and avoiding the dependency keeps
    the deployment surface smaller.
    """
    running = scan_manager.manager.get(scan_id)
    if running is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="scan is not in memory; read GET /{scan_id}/events instead",
        )

    async def event_source() -> AsyncGenerator[str, None]:
        queue = await running.subscribe(replay=True)
        try:
            while True:
                try:
                    event = await asyncio.wait_for(
                        queue.get(), timeout=SSE_KEEPALIVE_SECONDS
                    )
                except TimeoutError:
                    # A comment line keeps proxies from closing an idle stream.
                    yield ": keepalive\n\n"
                    continue
                if event is _SENTINEL:
                    break
                yield f"data: {json.dumps(event, default=str)}\n\n"
            # Terminal event so a client can distinguish "done" from "dropped".
            final = running.events[-1] if running.events else {}
            done = {
                "scan_id": scan_id,
                "phase": "closed",
                "status": running.snapshot()["status"],
                "message": final.get("message", ""),
                "progress": final.get("progress", 100.0),
            }
            yield f"data: {json.dumps(done)}\n\n"
        finally:
            running.unsubscribe(queue)

    return StreamingResponse(
        event_source(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
