"""
Archive upload endpoint.

Two things matter here and both are easy to get wrong:

* **Size is enforced while streaming.** Buffering the whole body and then
  checking its length means a multi-gigabyte upload has already consumed the
  memory by the time you reject it.
* **Extraction is delegated to the hardened helpers.** Path traversal, absolute
  members, symlink escapes, zip bombs and blocked paths are all handled in
  :mod:`app.core.security`; this module only deals with HTTP.
"""

from __future__ import annotations

import shutil
import uuid
from pathlib import Path

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    UploadFile,
    status,
)
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import config
from app.core.database import get_db
from app.core.logging_config import get_logger
from app.schemas.api import ProjectOut
from app.services.persistence import ScanPersistence
from app.services.repository import IngestionError, ingest_archive, workspace_for

logger = get_logger(__name__)
router = APIRouter(prefix="/projects", tags=["uploads"])

#: Chunk size for streaming the upload to disk.
_CHUNK = 1024 * 1024

#: Extensions we will even attempt to extract.
_ALLOWED_SUFFIXES = {".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz"}


def _has_allowed_suffix(name: str) -> bool:
    lowered = name.lower()
    return any(lowered.endswith(suffix) for suffix in _ALLOWED_SUFFIXES)


@router.post(
    "/upload",
    response_model=ProjectOut,
    status_code=status.HTTP_201_CREATED,
)
async def upload_repository(
    file: UploadFile = File(..., description="A .zip or .tar.gz repository archive"),
    name: str | None = Form(None),
    description: str | None = Form(None),
    session: AsyncSession = Depends(get_db),
) -> ProjectOut:
    """Accept a repository archive, extract it safely and index it."""
    original = file.filename or "upload"
    if not _has_allowed_suffix(original):
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Upload a .zip, .tar.gz, .tgz, .tar.bz2 or .tar.xz archive",
        )

    # A per-upload staging area under the data dir: never inside the workspace
    # we are about to scan, so a failed upload cannot be picked up by a scan.
    staging = config.settings.data_dir / "uploads" / uuid.uuid4().hex
    staging.mkdir(parents=True, exist_ok=True)
    archive_path = staging / Path(original).name

    written = 0
    try:
        with archive_path.open("wb") as handle:
            while chunk := await file.read(_CHUNK):
                written += len(chunk)
                if written > config.settings.max_upload_size:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=(
                            f"Archive exceeds the {config.settings.max_upload_size // (1024 * 1024)} MB limit"
                        ),
                    )
                handle.write(chunk)

        if written == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="The uploaded file is empty"
            )

        project_name = (name or Path(original).stem).strip() or "repository"
        project = await ScanPersistence(session).create_project(
            project_name,
            description=description,
            storage_path="",  # filled in below, once the root is known
            original_filename=original,
        )

        workspace = workspace_for(project.id)
        try:
            snapshot = ingest_archive(archive_path, workspace)
        except IngestionError as exc:
            # Do not leave a half-ingested project behind for the user to trip
            # over: the request failed, so the project should not exist.
            await ScanPersistence(session).delete_project(project.id)
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
            ) from exc

        project.storage_path = str(snapshot.root)
        project.total_bytes = written
        store = ScanPersistence(session)
        await store.sync_files(project, snapshot)
        await session.commit()
        await session.refresh(project)

        logger.info(
            "uploaded %s as project %s (%d files)", original, project.id, snapshot.file_count
        )
        return ProjectOut.model_validate(project)

    finally:
        shutil.rmtree(staging, ignore_errors=True)
        await file.close()
