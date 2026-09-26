"""
Local sandbox backend -- a DEVELOPMENT FALLBACK ONLY.

.. warning::

   This backend runs repository code directly on the host with no isolation
   whatsoever. A malicious repository can read host files, open sockets, fork
   bombs and modify anything the server user can reach. It exists so the
   verification pipeline can be exercised on machines without Docker. Never
   enable it for real user uploads.

What it *does* provide is the parts that are cheap and genuinely useful:

* the repository is copied to a scratch directory, so the original upload is
  never mutated;
* commands run as a subprocess with a wall-clock timeout and no inherited
  privileges, and the process group is killed on timeout so children die too;
* a scrubbed environment, so host credentials are not inherited.

The absence of namespace, capability and network isolation is the whole point
of the warning above. :attr:`LocalExecutor.isolated` is False and the
verification engine records that in the audit trail of every run.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import signal
import sys
import time
import uuid
from pathlib import Path

from app.core.config import settings
from app.core.logging_config import get_logger
from app.sandbox.base import (
    CommandResult,
    SandboxBackend,
    SandboxBackendBase,
    Workspace,
)

logger = get_logger(__name__)

#: Staging root for local workspaces.
LOCAL_ROOT = settings.data_dir / "local-sandbox"

#: Environment variables that must never reach repository code.
_STRIPPED = {
    "AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "GITHUB_TOKEN", "GH_TOKEN",
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "IBM_WATSONX_API_KEY",
    "DATABASE_URL", "IBM_WATSONX_PROJECT_ID",
}


class LocalExecutor(SandboxBackendBase):
    """Runs code on the host. Not a security boundary."""

    name = SandboxBackend.LOCAL
    isolated = False

    def __init__(self, *, allow: bool | None = None):
        # The fallback must be explicitly permitted, so a misconfigured
        # deployment fails loudly instead of silently running untrusted code.
        self.allow = settings.sandbox_allow_local_fallback if allow is None else allow

    async def is_available(self) -> tuple[bool, str]:
        if not self.allow:
            return False, "local fallback disabled (set SANDBOX_ALLOW_LOCAL_FALLBACK=true to enable)"
        if sys.platform == "win32":
            return False, "local fallback is not supported on Windows"
        return True, "host subprocess execution (NOT isolated)"

    # ------------------------------------------------------------------
    async def prepare(
        self,
        source: Path,
        *,
        requirements: list[str] | None = None,
        env: dict[str, str] | None = None,
    ) -> Workspace:
        available, reason = await self.is_available()
        if not available:
            from app.sandbox.base import SandboxUnavailable

            raise SandboxUnavailable(self.name, reason)

        root = LOCAL_ROOT / uuid.uuid4().hex[:12]
        shutil.copytree(source, root, symlinks=False, ignore=shutil.ignore_patterns(
            ".git", "__pycache__", "node_modules", ".venv", "*.pyc"
        ))
        logger.warning(
            "LOCAL SANDBOX: running untrusted code on the host at %s with no isolation", root
        )
        return Workspace(
            root=root,
            backend=self.name,
            handle=str(root),
            env=self._environment(env),
        )

    @staticmethod
    def _environment(extra: dict[str, str] | None) -> dict[str, str]:
        env = {
            key: value
            for key, value in os.environ.items()
            if key not in _STRIPPED and not key.startswith("IBM_")
        }
        env.update(settings.sandbox_env)
        env.update(extra or {})
        env["SENTINELFORGE_SANDBOX"] = "local-unisolated"
        return env

    # ------------------------------------------------------------------
    async def run(
        self,
        workspace: Workspace,
        command: list[str],
        *,
        timeout: int = 120,
        cwd: str | None = None,
    ) -> CommandResult:
        started = time.perf_counter()
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                cwd=cwd or str(workspace.root),
                env=workspace.env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                # Own process group, so a timeout can kill the whole tree.
                start_new_session=True,
            )
        except OSError as exc:
            return CommandResult(
                command, None, "", "", 0.0, error=f"could not start {command[0]}: {exc}"
            )

        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            await self._kill_tree(process)
            return CommandResult(
                command=command,
                returncode=None,
                stdout="",
                stderr=f"timed out after {timeout}s",
                duration_ms=(time.perf_counter() - started) * 1000,
                timed_out=True,
            )

        return CommandResult(
            command=command,
            returncode=process.returncode,
            stdout=(stdout or b"").decode(errors="replace"),
            stderr=(stderr or b"").decode(errors="replace"),
            duration_ms=(time.perf_counter() - started) * 1000,
        )

    @staticmethod
    async def _kill_tree(process: asyncio.subprocess.Process) -> None:
        """SIGKILL the whole process group; a timeout must leave nothing behind."""
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                process.kill()
            except ProcessLookupError:
                pass
        try:
            await asyncio.wait_for(process.wait(), timeout=10)
        except asyncio.TimeoutError:
            logger.error("process %s would not die after SIGKILL", process.pid)

    # ------------------------------------------------------------------
    async def apply_patch(
        self, workspace: Workspace, relative_path: str, content: str
    ) -> bool:
        try:
            target = workspace.path(relative_path)
        except ValueError:
            logger.warning("refused patch to %s: path escapes the workspace", relative_path)
            return False
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            # Atomic write: a half-written file must never be tested.
            temporary = target.with_suffix(target.suffix + ".sentinelforge-tmp")
            temporary.write_text(content, encoding="utf-8")
            temporary.replace(target)
        except OSError as exc:
            logger.warning("could not write %s: %s", relative_path, exc)
            return False
        return True

    async def read_file(self, workspace: Workspace, relative_path: str) -> str | None:
        try:
            target = workspace.path(relative_path)
        except ValueError:
            return None
        try:
            return target.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    async def cleanup(self, workspace: Workspace) -> None:
        shutil.rmtree(workspace.root, ignore_errors=True)


def describe() -> dict[str, object]:
    """Backend description for the API. ``isolated`` is the important field."""
    return {
        "backend": SandboxBackend.LOCAL.value,
        "isolated": False,
        "warning": (
            "Runs untrusted code on the host without isolation. "
            "Development only."
        ),
    }


__all__ = ["LOCAL_ROOT", "LocalExecutor", "describe"]
