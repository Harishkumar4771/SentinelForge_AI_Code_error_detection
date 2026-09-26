"""
Sandbox package (spec §18).

``get_executor()`` returns the configured backend. When Docker is requested
but unavailable, it falls back to the local executor only if the fallback is
explicitly enabled -- and reports that it did, so the scan's audit trail shows
the fix was verified without isolation.
"""

from __future__ import annotations

from app.core.config import settings
from app.core.logging_config import get_logger
from app.sandbox.base import (
    CommandResult,
    SandboxBackend,
    SandboxBackendBase,
    SandboxUnavailable,
    Workspace,
)

logger = get_logger(__name__)


def get_executor() -> SandboxBackendBase:
    """Instantiate the configured sandbox backend."""
    if settings.sandbox_backend == SandboxBackend.DOCKER.value:
        from app.sandbox.docker import DockerExecutor

        return DockerExecutor()

    from app.sandbox.local import LocalExecutor

    return LocalExecutor()


async def select_executor() -> tuple[SandboxBackendBase, str]:
    """
    Return a usable executor and a human-readable note about isolation.

    Docker is preferred regardless of configuration when it actually works,
    because it is the only backend that is a real security boundary.
    """
    from app.sandbox.docker import DockerExecutor
    from app.sandbox.local import LocalExecutor

    docker = DockerExecutor()
    ready, reason = await docker.is_available()
    if ready:
        return docker, "docker container isolation active"

    if settings.sandbox_backend == SandboxBackend.DOCKER.value:
        logger.error("sandbox_backend=docker but Docker is unusable: %s", reason)

    if not settings.sandbox_allow_local_fallback:
        raise SandboxUnavailable(SandboxBackend.DOCKER.value, reason)

    logger.warning("falling back to the unisolated local sandbox: %s", reason)
    return LocalExecutor(), f"UNISOLATED local fallback ({reason})"


__all__ = [
    "CommandResult",
    "SandboxBackend",
    "SandboxBackendBase",
    "SandboxUnavailable",
    "Workspace",
    "get_executor",
    "select_executor",
]
