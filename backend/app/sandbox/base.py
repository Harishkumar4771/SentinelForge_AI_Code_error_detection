"""
Sandbox backends (spec §18).

Two implementations share one interface:

* :class:`~app.sandbox.docker.DockerExecutor` -- the production backend. Each
  run gets a fresh container with no network, a read-only base layer and a
  copy-on-write workspace, so repository code cannot reach the host.
* :class:`~app.sandbox.local.LocalExecutor` -- a development fallback that
  runs on the host. It is **not** isolated and must never be used on
  untrusted input. It exists so the platform is testable where Docker is
  unavailable, and it says so loudly every time it runs.

The interface deliberately returns raw results. Deciding whether a fix worked
is the verification engine's job, not the backend's.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Optional


class SandboxBackend(StrEnum):
    DOCKER = "docker"
    LOCAL = "local"


@dataclass
class CommandResult:
    """Outcome of one command executed inside a sandbox."""

    command: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    duration_ms: float
    timed_out: bool = False
    #: Set when the backend itself could not run the command.
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.error

    @property
    def output(self) -> str:
        """Combined output, clipped -- pytest traces are enormous."""
        combined = (self.stdout or "") + ("\n" + self.stderr if self.stderr else "")
        limit = 60_000
        if len(combined) > limit:
            combined = combined[:limit] + "\n... [output truncated]"
        return combined

    def as_dict(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "returncode": self.returncode,
            "duration_ms": round(self.duration_ms, 2),
            "timed_out": self.timed_out,
            "error": self.error,
        }


@dataclass
class SandboxUnavailable(RuntimeError):
    """Raised when a backend cannot run at all (e.g. no Docker daemon)."""

    backend: str
    reason: str


@dataclass
class Workspace:
    """A prepared copy of the repository that tests run against."""

    root: Path
    backend: SandboxBackend
    #: Identifier the backend uses to find the workspace again (container id,
    #: or the host path for the local backend).
    handle: str
    env: dict[str, str] = field(default_factory=dict)

    def path(self, relative: str) -> Path:
        """Resolve a repo-relative path, refusing to escape the workspace."""
        target = (self.root / relative).resolve()
        if not str(target).startswith(str(self.root.resolve())):
            raise ValueError(f"path escapes workspace: {relative}")
        return target


class SandboxBackendBase(abc.ABC):
    """Interface every sandbox backend implements."""

    name: SandboxBackend

    @abc.abstractmethod
    async def is_available(self) -> tuple[bool, str]:
        """Return (available, reason). Never raises."""

    @abc.abstractmethod
    async def prepare(
        self,
        source: Path,
        *,
        requirements: list[str] | None = None,
        env: dict[str, str] | None = None,
    ) -> Workspace:
        """Create an isolated copy of ``source`` ready to execute."""

    @abc.abstractmethod
    async def run(
        self,
        workspace: Workspace,
        command: list[str],
        *,
        timeout: int = 120,
        cwd: str | None = None,
    ) -> CommandResult:
        """Run one command inside the prepared workspace."""

    @abc.abstractmethod
    async def apply_patch(
        self, workspace: Workspace, relative_path: str, content: str
    ) -> bool:
        """Overwrite a file inside the workspace. Returns success."""

    @abc.abstractmethod
    async def read_file(self, workspace: Workspace, relative_path: str) -> str | None:
        """Read a file from inside the workspace."""

    @abc.abstractmethod
    async def cleanup(self, workspace: Workspace) -> None:
        """Destroy the workspace. Must be safe to call twice."""

    async def __aenter__(self) -> "SandboxBackendBase":
        return self

    async def __aexit__(self, *exc_info) -> None:
        return None


__all__ = [
    "CommandResult",
    "SandboxBackend",
    "SandboxBackendBase",
    "SandboxUnavailable",
    "Workspace",
]
