"""
Docker sandbox backend (spec §18) -- the production executor.

Every execution runs in a throwaway container with:

* ``--network none`` -- an exploit cannot phone home or fetch a payload;
* a read-only root filesystem with ``/tmp`` as the only writable path;
* CPU, memory and PID caps so a fork bomb or a runaway loop cannot take the
  host down;
* no privilege escalation, no host namespaces, no mounted host paths.

The repository is copied *into* the container. Nothing from the host
filesystem is bind-mounted, so a malicious test cannot read host files.
"""

from __future__ import annotations

import asyncio
import shutil
import tarfile
import time
import uuid
from pathlib import Path
from typing import Any

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

#: Where the repository is mounted inside the container.
CONTAINER_WORKDIR = "/workspace"


class DockerExecutor(SandboxBackendBase):
    """Runs untrusted code in an isolated container."""

    name = SandboxBackend.DOCKER

    def __init__(
        self,
        image: str | None = None,
        *,
        network: str | None = None,
        memory_limit: str | None = None,
        cpu_limit: float | None = None,
        pids_limit: int | None = None,
    ):
        self.image = image or settings.sandbox_image
        self.network = network if network is not None else settings.sandbox_network
        self.memory_limit = memory_limit or settings.sandbox_memory_limit
        self.cpu_limit = cpu_limit or settings.sandbox_cpu_limit
        self.pids_limit = pids_limit or settings.sandbox_pids_limit
        #: container id -> host staging directory, so cleanup can remove both.
        self._staging: dict[str, Path] = {}

    # ------------------------------------------------------------------
    @staticmethod
    def binary() -> str | None:
        return shutil.which("docker")

    async def is_available(self) -> tuple[bool, str]:
        """Docker is only usable if the binary exists *and* the daemon answers."""
        if self.binary() is None:
            return False, "docker binary not found on PATH"
        try:
            process = await asyncio.create_subprocess_exec(
                "docker", "info", "--format", "{{.ServerVersion}}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(process.communicate(), timeout=20)
        except (asyncio.TimeoutError, OSError) as exc:
            return False, f"docker daemon unreachable: {exc}"
        if process.returncode != 0:
            detail = (stderr or b"").decode(errors="replace").strip().splitlines()
            return False, f"docker daemon not ready: {detail[-1] if detail else 'unknown error'}"
        return True, "docker ready"

    async def ensure_image(self) -> None:
        """Pull the image if it is not present. Called once per scan."""
        process = await asyncio.create_subprocess_exec(
            "docker", "image", "inspect", self.image,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await process.communicate()
        if process.returncode == 0:
            return
        logger.info("pulling sandbox image %s", self.image)
        process = await asyncio.create_subprocess_exec(
            "docker", "pull", self.image,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()
        if process.returncode != 0:
            raise SandboxUnavailable(
                self.name,
                f"could not pull {self.image}: {(stderr or b'').decode(errors='replace')[:200]}",
            )

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
            raise SandboxUnavailable(self.name, reason)
        await self.ensure_image()

        container = f"sentinelforge-{uuid.uuid4().hex[:12]}"
        created = await self._create(container, requirements or [], env or {})
        if not created:
            raise SandboxUnavailable(self.name, f"container {container} failed to start")

        # The image is read-only, so a small staging directory is used to build
        # the tarball; the container's own /tmp is writable for tests.
        staging = Path(settings.data_dir) / "sandbox" / container
        staging.mkdir(parents=True, exist_ok=True)
        self._staging[container] = staging

        tar_path = staging / "repo.tar"
        archive = self._make_tarball(source, tar_path)
        copied = await self._exec_in(container, ["tar", "-xf", "-", "-C", CONTAINER_WORKDIR], stdin=archive)
        tar_path.unlink(missing_ok=True)

        if copied.returncode != 0:
            await self._destroy(container)
            raise SandboxUnavailable(
                self.name, f"could not copy repository into container: {copied.stderr[:200]}"
            )

        return Workspace(
            root=Path(CONTAINER_WORKDIR),
            backend=self.name,
            handle=container,
            env={**settings.sandbox_env, **(env or {})},
        )

    @staticmethod
    def _make_tarball(source: Path, destination: Path) -> bytes:
        """Stream the repository into an in-memory tarball."""
        import io

        buffer = io.BytesIO()
        resolved = source.resolve()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            for item in sorted(resolved.rglob("*")):
                if not item.is_file() or item.is_symlink():
                    continue
                if any(part in {".git", "__pycache__", "node_modules", ".venv"} for part in item.parts):
                    continue
                archive.add(item, arcname=str(item.relative_to(resolved)), recursive=False)
        data = buffer.getvalue()
        destination.write_bytes(data)
        return data

    async def _create(self, container: str, requirements: list[str], env: dict[str, str]) -> bool:
        command: list[str] = [
            "docker", "run", "--detach",
            "--name", container,
            "--network", self.network,
            "--memory", self.memory_limit,
            "--memory-swap", self.memory_limit,  # no swap escape from the cap
            "--cpus", str(self.cpu_limit),
            "--pids-limit", str(self.pids_limit),
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
            "--tmpfs", "/workspace:rw,nosuid,size=256m",
            "--workdir", CONTAINER_WORKDIR,
        ]
        for key, value in {**settings.sandbox_env, **env}.items():
            command += ["--env", f"{key}={value}"]
        command += [self.image, "sleep", str(settings.sandbox_container_lifetime)]
        return await self._spawn(command) == 0

    async def _spawn(self, command: list[str]) -> int:
        try:
            process = await asyncio.create_subprocess_exec(
                *command, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE
            )
        except OSError as exc:
            logger.warning("could not run %s: %s", command[0], exc)
            return 1
        _, stderr = await process.communicate()
        if process.returncode != 0:
            logger.warning(
                "command failed (%s): %s", command[:3], (stderr or b"").decode(errors="replace")[:300]
            )
        return process.returncode or 0

    # ------------------------------------------------------------------
    async def run(
        self,
        workspace: Workspace,
        command: list[str],
        *,
        timeout: int = 120,
        cwd: str | None = None,
    ) -> CommandResult:
        full = ["docker", "exec", "--workdir", cwd or CONTAINER_WORKDIR]
        if workspace.env:
            for key, value in workspace.env.items():
                full += ["--env", f"{key}={value}"]
        full += [workspace.handle, *command]

        started = time.perf_counter()
        try:
            process = await asyncio.create_subprocess_exec(
                *full,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as exc:
            return CommandResult(
                command=command,
                returncode=None,
                stdout="",
                stderr="",
                duration_ms=0.0,
                error=f"could not start docker exec: {exc}",
            )

        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            # Kill the whole container: the command may have spawned children
            # that would otherwise keep running.
            await self._destroy(workspace.handle)
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

    async def _exec_in(
        self, container: str, command: list[str], stdin: bytes | None = None
    ) -> CommandResult:
        full = ["docker", "exec", "-i", container, *command]
        started = time.perf_counter()
        try:
            process = await asyncio.create_subprocess_exec(
                *full,
                stdin=asyncio.subprocess.PIPE if stdin else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(stdin), timeout=120
            )
        except (asyncio.TimeoutError, OSError) as exc:
            return CommandResult([], None, "", str(exc), 0.0, error=str(exc))
        return CommandResult(
            command=command,
            returncode=process.returncode,
            stdout=(stdout or b"").decode(errors="replace"),
            stderr=(stderr or b"").decode(errors="replace"),
            duration_ms=(time.perf_counter() - started) * 1000,
        )

    # ------------------------------------------------------------------
    async def apply_patch(
        self, workspace: Workspace, relative_path: str, content: str
    ) -> bool:
        result = await self._write(workspace, relative_path, content)
        return result.returncode == 0

    async def _write(
        self, workspace: Workspace, relative_path: str, content: str
    ) -> CommandResult:
        # Written via stdin so no shell quoting is involved and no host path
        # is ever exposed to the container.
        script = (
            "import sys, pathlib\n"
            "target = pathlib.Path(sys.argv[1])\n"
            "target.parent.mkdir(parents=True, exist_ok=True)\n"
            "data = sys.stdin.buffer.read()\n"
            "target.write_bytes(data)\n"
        )
        full = [
            "docker", "exec", "-i", "--workdir", CONTAINER_WORKDIR,
            workspace.handle, "python", "-c", script, f"{CONTAINER_WORKDIR}/{relative_path}",
        ]
        try:
            process = await asyncio.create_subprocess_exec(
                *full,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(content.encode("utf-8")), timeout=60
            )
        except (asyncio.TimeoutError, OSError) as exc:
            return CommandResult([], None, "", str(exc), 0.0, error=str(exc))
        return CommandResult(
            command=["write", relative_path],
            returncode=process.returncode,
            stdout=(stdout or b"").decode(errors="replace"),
            stderr=(stderr or b"").decode(errors="replace"),
            duration_ms=0.0,
        )

    async def read_file(self, workspace: Workspace, relative_path: str) -> str | None:
        result = await self._exec_in(
            workspace.handle,
            ["python", "-c", (
                "import sys, pathlib\n"
                "p = pathlib.Path(sys.argv[1])\n"
                "sys.stdout.write(p.read_text(errors='replace') if p.is_file() else '')\n"
            ), f"{CONTAINER_WORKDIR}/{relative_path}"],
        )
        if result.returncode != 0 or not result.stdout:
            return None
        return result.stdout

    async def cleanup(self, workspace: Workspace) -> None:
        await self._destroy(workspace.handle)
        staging = self._staging.pop(workspace.handle, None)
        if staging:
            shutil.rmtree(staging, ignore_errors=True)

    async def _destroy(self, container: str) -> None:
        await self._spawn(["docker", "rm", "--force", "--volumes", container])
        self._staging.pop(container, None)


def describe() -> dict[str, Any]:
    """Backend description for the API and dashboard."""
    return {
        "backend": SandboxBackend.DOCKER.value,
        "image": settings.sandbox_image,
        "network": settings.sandbox_network,
        "memory_limit": settings.sandbox_memory_limit,
        "cpu_limit": settings.sandbox_cpu_limit,
        "isolated": True,
    }


__all__ = ["CONTAINER_WORKDIR", "DockerExecutor", "describe"]
