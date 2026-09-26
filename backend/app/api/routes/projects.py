"""
Project endpoints: create, inspect, list, delete.

Ingestion is intentionally cheap here -- a project is created from a path on
disk. Archive upload lives in ``uploads.py`` because it needs streaming and
size limits, and mixing the two would make both harder to reason about.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import config
from app.core.database import get_db
from app.core.logging_config import get_logger
from app.schemas.api import ProjectCreate, ProjectOut, ScanOut
from app.services.persistence import ScanPersistence
from app.services.repository import build_snapshot

logger = get_logger(__name__)
router = APIRouter(prefix="/projects", tags=["projects"])


@router.post("", response_model=ProjectOut, status_code=status.HTTP_201_CREATED)
async def create_project(
    payload: ProjectCreate,
    session: AsyncSession = Depends(get_db),
) -> ProjectOut:
    """Index a repository that already exists on disk."""
    store = ScanPersistence(session)

    repository: Path | None = None
    if payload.repository_path:
        candidate = Path(payload.repository_path)
        if not candidate.is_absolute():
            candidate = config.settings.base_dir / candidate
        candidate = candidate.resolve()
        if not candidate.is_dir():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"repository_path is not a directory: {payload.repository_path}",
            )
        repository = candidate

    project = await store.create_project(
        payload.name,
        description=payload.description,
        storage_path=str(repository) if repository else None,
        original_filename=repository.name if repository else None,
    )

    if repository is not None:
        try:
            snapshot = build_snapshot(repository)
        except Exception as exc:
            logger.exception("failed to index %s", repository)
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"could not index repository: {exc}",
            ) from exc
        await store.sync_files(project, snapshot)

    return ProjectOut.model_validate(project)


@router.get("", response_model=list[ProjectOut])
async def list_projects(
    limit: int = 100,
    session: AsyncSession = Depends(get_db),
) -> list[ProjectOut]:
    store = ScanPersistence(session)
    return [ProjectOut.model_validate(p) for p in await store.list_projects(limit)]


@router.get("/{project_id}", response_model=ProjectOut)
async def get_project(
    project_id: str,
    session: AsyncSession = Depends(get_db),
) -> ProjectOut:
    store = ScanPersistence(session)
    project = await store.get_project(project_id)
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="project not found")
    return ProjectOut.model_validate(project)


@router.get("/{project_id}/scans", response_model=list[ScanOut])
async def list_project_scans(
    project_id: str,
    limit: int = 50,
    session: AsyncSession = Depends(get_db),
) -> list[ScanOut]:
    store = ScanPersistence(session)
    if await store.get_project(project_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="project not found")
    scans = await store.list_scans(project_id, limit)
    return [ScanOut.model_validate(s) for s in scans]


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
async def delete_project(
    project_id: str,
    session: AsyncSession = Depends(get_db),
) -> Response:
    store = ScanPersistence(session)
    if not await store.delete_project(project_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="project not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)
