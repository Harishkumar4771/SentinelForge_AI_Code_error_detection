"""
Shared plumbing for deterministic analyzers.

Every external scanner is invoked through :class:`ToolRunner`, which
guarantees a timeout, a size cap on captured output, and a structured
result. A scanner that hangs, explodes or is missing degrades to a
``ToolResult`` with ``available=False`` -- it can never abort a scan
(spec §27: "Never allow one failed agent to crash the entire scan").
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from app.core.config import settings
from app.core.logging_config import get_logger

logger = get_logger(__name__)

# Never buffer more than this from a subprocess; a runaway tool should not
# be able to exhaust host memory.
MAX_CAPTURE = 4_000_000


@dataclass
class ToolResult:
    """Normalized outcome of one external tool invocation."""

    tool: str
    findings: list[Any] = field(default_factory=list)
    available: bool = True
    duration_ms: float = 0.0
    error: str | None = None
    raw_output: str = ""
    version: str | None = None

    @property
    def count(self) -> int:
        return len(self.findings)


@dataclass
class ToolAvailability:
    """Whether a tool is usable, and why not when it is not."""

    name: str
    path: str | None
    reason: str | None = None

    @property
    def ok(self) -> bool:
        return self.path is not None and self.reason is None


class ToolNotAvailable(RuntimeError):
    """Raised internally when a required binary is missing."""


class ToolRunner:
    """
    Base class for subprocess-backed scanners.

    Subclasses implement :meth:`build_command` and :meth:`parse`.
    """

    name: str = "tool"
    #: Output must be JSON for :meth:`parse_json` to work.
    emits_json: bool = True

    def __init__(self, *, executable: str | None = None, timeout: int | None = None):
        self.executable = executable or self.name
        self.timeout = timeout or settings.scanner_timeout
        self._resolved: str | None | bool = False
        self._root: Path | None = None

    # -- discovery -----------------------------------------------------
    def resolve(self) -> str | None:
        """Locate the binary, preferring the virtualenv."""
        if self._resolved is not False:
            return self._resolved

        candidate = shutil.which(self.executable)
        if candidate:
            self._resolved = candidate
            return candidate

        # Fall back to the active virtualenv's bin directory, which is not
        # always on PATH when uvicorn is launched via an absolute path.
        venv_bin = Path(os.sys.prefix) / "bin" / self.executable
        if venv_bin.exists():
            self._resolved = str(venv_bin)
            return self._resolved

        self._resolved = None
        return None

    def availability(self) -> ToolAvailability:
        path = self.resolve()
        if not path:
            return ToolAvailability(self.name, None, f"{self.name} is not installed")
        return ToolAvailability(self.name, path)

    # -- execution -----------------------------------------------------
    def build_command(self, target: Path) -> Sequence[str]:
        raise NotImplementedError

    def env(self) -> dict[str, str]:
        """Child environment: no inherited secrets, no network proxy vars."""
        clean = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", "/tmp"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            # Keep tools offline and non-interactive.
            "NO_COLOR": "1",
            "TERM": "dumb",
            "SEMGREP_SEND_METRICS": "off",
            "SEMGREP_ENABLE_VERSION_CHECK": "0",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        # Proxies are deliberately NOT forwarded: scanners must not phone home.
        return clean

    async def run(self, target: Path) -> ToolResult:
        """Invoke the tool with a hard timeout and capture bounded output."""
        loop = asyncio.get_running_loop()
        start = loop.time()
        self._root = target

        if not self.resolve():
            return ToolResult(
                tool=self.name,
                available=False,
                error=f"{self.name} is not installed",
            )

        command = list(self.build_command(target))
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(target),
                env=self.env(),
            )
        except (OSError, ValueError) as exc:
            return ToolResult(
                tool=self.name, available=False, error=f"could not start {self.name}: {exc}"
            )

        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=self.timeout)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            logger.warning("%s timed out after %ss on %s", self.name, self.timeout, target.name)
            return ToolResult(
                tool=self.name,
                available=True,
                error=f"timed out after {self.timeout}s",
                duration_ms=(loop.time() - start) * 1000,
            )

        duration_ms = (loop.time() - start) * 1000
        out = stdout[:MAX_CAPTURE].decode("utf-8", "replace")
        err = stderr[:MAX_CAPTURE].decode("utf-8", "replace")

        # A non-zero exit is normal for scanners (they signal "found things").
        # Only treat it as a failure when no parsable output came back.
        try:
            findings = self.parse(out, err, process.returncode or 0)
        except Exception as exc:  # a parser bug must not kill the scan
            logger.exception("%s output parsing failed", self.name)
            return ToolResult(
                tool=self.name,
                available=True,
                error=f"parse error: {exc}",
                raw_output=out[:8000],
                duration_ms=duration_ms,
            )

        return ToolResult(
            tool=self.name,
            findings=findings,
            available=True,
            duration_ms=duration_ms,
            raw_output=out[:8000],
            error=err.strip()[:2000] or None,
        )

    # -- parsing -------------------------------------------------------
    def parse(self, stdout: str, stderr: str, returncode: int) -> list[Any]:
        raise NotImplementedError

    @property
    def root(self) -> Path:
        """Directory the tool was pointed at; used to relativize paths."""
        return self._root or Path.cwd()

    def parse_json(self, stdout: str) -> Any:
        """
        Extract JSON from scanner output.

        Returns whatever shape the document has (dict *or* list) so that
        object-shaped payloads such as Bandit's ``{"results": [...]}`` can
        be unwrapped by the caller instead of being hidden inside a list.

        Tools often prefix JSON with progress lines, so fall back to the
        widest decodable bracket-delimited span.
        """
        text = stdout.strip()
        if not text:
            return []
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        best: Any = None
        for opener, closer in (("[", "]"), ("{", "}")):
            start = text.find(opener)
            end = text.rfind(closer)
            if start == -1 or end == -1 or end < start:
                continue
            try:
                candidate = json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                continue
            if best is None:
                best = candidate
            elif isinstance(best, list) and isinstance(candidate, list):
                best.extend(candidate)
            else:
                best = candidate
        return best if best is not None else []


def relative_to_root(path: str, root: Path) -> str:
    """Best-effort conversion of an absolute scan path to repo-relative."""
    if not path:
        return ""
    try:
        return str(Path(path).resolve().relative_to(root.resolve()))
    except (ValueError, OSError):
        text = str(path).replace("\\", "/")
        marker = f"{root.name}/"
        if marker in text:
            return text.split(marker, 1)[1]
        return text
