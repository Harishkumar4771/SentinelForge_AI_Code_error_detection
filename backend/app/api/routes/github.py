"""
GitHub clone endpoint.

Accepts a GitHub URL, clones the repository to a workspace directory, indexes
it as a project, and optionally kicks off a scan -- all in one request.

Security notes:
* Only ``https://github.com/`` URLs are accepted to prevent SSRF via
  ``git clone``. Arbitrary hosts (internal IPs, ``file://``, ``ssh://``)
  are rejected.
* The clone runs with ``--depth 1`` so only the latest commit is fetched.
* Timeout guards against hanging on a gigantic repo.
"""

from __future__ import annotations

import asyncio
import re
import shutil
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import config
from app.core.database import get_db
from app.core.logging_config import get_logger
from app.schemas.api import ProjectOut
from app.services.persistence import ScanPersistence
from app.services.repository import build_snapshot

logger = get_logger(__name__)
router = APIRouter(prefix="/projects", tags=["github"])

# Accept github.com HTTPS URLs only.  The pattern deliberately rejects
# ``file://``, ``ssh://`` and internal hosts.
_GITHUB_RE = re.compile(
    r"^https://github\.com/(?P<owner>[A-Za-z0-9_.\-]+)/(?P<repo>[A-Za-z0-9_.\-]+?)(?:\.git)?/?$"
)

#: Hard limit on how long a clone may run before we kill it.
_CLONE_TIMEOUT = 120


class GitHubCloneRequest(BaseModel):
    url: str = Field(
        ...,
        description="HTTPS GitHub URL, e.g. https://github.com/owner/repo",
        min_length=1,
    )
    name: str | None = Field(None, description="Project name override")
    description: str | None = None
    branch: str | None = Field(None, description="Branch to clone (default: HEAD)")


@router.post(
    "/clone",
    response_model=ProjectOut,
    status_code=status.HTTP_201_CREATED,
    summary="Clone a public GitHub repository and create a project",
)
async def clone_github_repository(
    payload: GitHubCloneRequest,
    session: AsyncSession = Depends(get_db),
) -> ProjectOut:
    """Clone a public GitHub repository and index it as a project."""
    match = _GITHUB_RE.match(payload.url.strip())
    if not match:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Only public GitHub HTTPS URLs are accepted. "
                "Example: https://github.com/owner/repo"
            ),
        )

    owner = match.group("owner")
    repo = match.group("repo")
    project_name = payload.name or f"{owner}/{repo}"

    # Clone into a temp staging dir, then move to the workspace.
    staging = config.settings.data_dir / "clone-staging" / uuid.uuid4().hex
    staging.mkdir(parents=True, exist_ok=True)
    clone_target = staging / repo

    cmd = [
        "git", "clone",
        "--depth", "1",
        "--single-branch",
    ]
    if payload.branch:
        cmd += ["--branch", payload.branch]
    cmd += [payload.url.strip(), str(clone_target)]

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            process.communicate(), timeout=_CLONE_TIMEOUT
        )

        if process.returncode != 0:
            error_msg = stderr.decode(errors="replace").strip()
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"git clone failed: {error_msg or 'unknown error'}",
            )
    except TimeoutError:
        process.kill()
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=f"Clone timed out after {_CLONE_TIMEOUT}s. The repository may be too large.",
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Clone failed unexpectedly: {exc}",
        ) from exc

    # Remove the .git directory -- we only care about source files.
    git_dir = clone_target / ".git"
    if git_dir.exists():
        shutil.rmtree(git_dir, ignore_errors=True)

    # Move to workspace.
    workspace_root = config.settings.workspace_path
    workspace_root.mkdir(parents=True, exist_ok=True)
    workspace = workspace_root / uuid.uuid4().hex
    shutil.move(str(clone_target), str(workspace))

    try:
        store = ScanPersistence(session)
        project = await store.create_project(
            project_name,
            description=payload.description or f"Cloned from {payload.url}",
            storage_path=str(workspace),
            original_filename=f"{repo}.git",
        )

        try:
            snapshot = build_snapshot(workspace)
        except Exception as exc:
            await store.delete_project(project.id)
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Could not index cloned repository: {exc}",
            ) from exc

        await store.sync_files(project, snapshot)
        await session.commit()
        await session.refresh(project)

        logger.info(
            "cloned %s/%s as project %s (%d files)",
            owner, repo, project.id, snapshot.file_count,
        )
        return ProjectOut.model_validate(project)

    finally:
        shutil.rmtree(staging, ignore_errors=True)
