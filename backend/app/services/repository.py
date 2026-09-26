"""
Repository ingestion (spec §2 "Upload a software repository as a ZIP file").

Turns an uploaded archive into a ``RepositorySnapshot``: an indexed,
analysable view of the code on disk. Nothing here executes repository code.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from app.core.config import settings
from app.core.logging_config import get_logger
from app.core.security import (
    BINARY_EXTENSIONS,
    UnsafeArchiveError,
    is_blocked_path,
    is_text_path,
    safe_extract_any,
    safe_join,
)
from app.models.enums import ProjectStatus

logger = get_logger(__name__)

LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".java": "java",
    ".rb": "ruby",
    ".php": "php",
    ".rs": "rust",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".sql": "sql",
    ".sh": "shell",
    ".bash": "shell",
}

FRAMEWORK_MARKERS = {
    "flask": ("flask",),
    "django": ("django",),
    "fastapi": ("fastapi",),
    "express": ("express",),
    "react": ("react",),
    "next.js": ('"next"',),
    "vue": ("vue",),
    "spring": ("spring-boot", "org.springframework"),
    "rails": ("rails",),
    "gin": ("github.com/gin-gonic/gin",),
    "axios": ("axios",),
    "requests": ("requests",),
}

_DEP_REQUIREMENT = re.compile(r"^\s*([A-Za-z0-9_.\-\[\]]+)\s*(?:[=<>!~]{1,2}\s*([^\s;#]+))?")
_JS_IMPORT = re.compile(r"""(?:from|require\()\s*['"]([^'"]+)['"]""")


class IngestionError(ValueError):
    """Raised when an upload cannot become a usable repository."""


@dataclass
class SourceFile:
    path: str
    absolute: Path
    language: str | None
    size: int
    line_count: int
    is_test: bool
    sha256: str
    source: str | None = None


@dataclass
class RepositorySnapshot:
    """Analysable, in-memory view of an uploaded repository."""

    root: Path
    files: list[SourceFile] = field(default_factory=list)
    languages: dict[str, int] = field(default_factory=dict)
    primary_language: str = "python"
    dependencies: dict[str, list[str]] = field(default_factory=dict)
    entrypoints: list[str] = field(default_factory=list)
    frameworks: set[str] = field(default_factory=set)
    manifest: dict = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    truncated: bool = False

    # -- convenience accessors -----------------------------------------
    @property
    def python_files(self) -> list[SourceFile]:
        return [f for f in self.files if f.language == "python"]

    @property
    def test_files(self) -> list[SourceFile]:
        return [f for f in self.files if f.is_test]

    @property
    def file_count(self) -> int:
        return len(self.files)

    @property
    def total_bytes(self) -> int:
        return sum(f.size for f in self.files)

    def get(self, relative_path: str) -> SourceFile | None:
        target = relative_path.replace("\\", "/").lstrip("/")
        for item in self.files:
            if item.path == target:
                return item
        return None

    def read(self, relative_path: str) -> str | None:
        item = self.get(relative_path)
        return item.source if item else None

    def lines(self, relative_path: str) -> list[str]:
        source = self.read(relative_path)
        return source.splitlines() if source else []

    def snippet(self, relative_path: str, line_number: int, context: int = 2) -> str:
        lines = self.lines(relative_path)
        if not lines or not line_number:
            return ""
        start = max(0, line_number - 1 - context)
        end = min(len(lines), line_number + context)
        return "\n".join(
            f"{idx + 1:>5} | {lines[idx]}" for idx in range(start, end)
        )

    def as_manifest(self) -> dict:
        return {
            "file_count": self.file_count,
            "total_bytes": self.total_bytes,
            "primary_language": self.primary_language,
            "languages": self.languages,
            "dependencies": self.dependencies,
            "entrypoints": self.entrypoints,
            "frameworks": sorted(self.frameworks),
            "test_file_count": len(self.test_files),
            "truncated": self.truncated,
        }


# ----------------------------------------------------------------------
def detect_language(path: Path) -> str | None:
    return LANGUAGE_BY_SUFFIX.get(path.suffix.lower())


def looks_like_test(path: Path) -> bool:
    parts = {p.lower() for p in path.parts}
    name = path.stem.lower()
    return (
        name.startswith("test_")
        or name.endswith("_test")
        or name.endswith("test")
        or "tests" in parts
        or "test" in parts
        or "spec" in parts
        and path.suffix.lower() in {".py", ".js", ".ts"}
    )


def _is_entrypoint(path: Path) -> bool:
    name = path.stem.lower()
    if path.name in {"manage.py", "wsgi.py", "asgi.py", "main.py", "app.py", "server.py", "Procfile"}:
        return True
    if path.suffix.lower() in {".js", ".ts"} and name in {"index", "main", "server", "app"}:
        return True
    return name in {"main", "server", "app"}


def _parse_requirements(path: Path) -> dict[str, str]:
    found: dict[str, str] = {}
    try:
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith(("#", "-")):
                continue
            match = _DEP_REQUIREMENT.match(line)
            if match:
                found[match.group(1).lower()] = (match.group(2) or "*").strip()
    except OSError:
        pass
    return found


def _parse_package_json(path: Path) -> tuple[dict[str, str], set[str]]:
    deps: dict[str, str] = {}
    frameworks: set[str] = set()
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return deps, frameworks
    for section in ("dependencies", "devDependencies"):
        for name, version in (data.get(section) or {}).items():
            deps[str(name).lower()] = str(version)
    return deps, frameworks


def _collect_dependencies(root: Path) -> tuple[dict[str, list[str]], list[str], set[str]]:
    """Read dependency manifests without importing anything."""
    python_deps: dict[str, str] = {}
    js_deps: dict[str, str] = {}
    frameworks: set[str] = set()
    manifest_files: list[str] = []

    for candidate in ("requirements.txt", "requirements-dev.txt", "Pipfile", "pyproject.toml"):
        path = root / candidate
        if not path.is_file():
            continue
        manifest_files.append(candidate)
        if candidate.startswith("requirements"):
            python_deps.update(_parse_requirements(path))
        else:
            text = path.read_text(encoding="utf-8", errors="replace")
            for line in text.splitlines():
                match = re.match(r'\s*"?([A-Za-z0-9_.\-]+)"?\s*=\s*"?([^"\n]+)"?', line)
                if match:
                    python_deps.setdefault(match.group(1).lower(), match.group(2).strip())

    package_json = root / "package.json"
    if package_json.is_file():
        manifest_files.append("package.json")
        parsed, _ = _parse_package_json(package_json)
        js_deps.update(parsed)

    # Framework detection also inspects imports in scanned source.
    for name in (*python_deps, *js_deps):
        for framework, markers in FRAMEWORK_MARKERS.items():
            if any(marker in name for marker in markers):
                frameworks.add(framework)

    dependencies: dict[str, list[str]] = {}
    if python_deps:
        dependencies["python"] = [f"{k}=={v}" if v != "*" else k for k, v in sorted(python_deps.items())]
    if js_deps:
        dependencies["javascript"] = [f"{k}@{v}" for k, v in sorted(js_deps.items())]
    return dependencies, manifest_files, frameworks


# ----------------------------------------------------------------------
def build_snapshot(root: Path, *, result_truncated: bool = False) -> RepositorySnapshot:
    """Index every analysable source file under ``root``."""
    snapshot = RepositorySnapshot(root=root, truncated=result_truncated)
    languages: dict[str, int] = {}
    entrypoints: list[str] = []
    budget = settings.max_uncompressed_size

    for path in sorted(root.rglob("*")):
        if budget <= 0:
            snapshot.truncated = True
            break
        if not path.is_file() or path.is_symlink():
            continue

        relative = path.relative_to(root)
        if is_blocked_path(relative):
            continue
        if path.suffix.lower() in BINARY_EXTENSIONS:
            continue

        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > settings.max_file_size:
            snapshot.warnings.append(f"Skipped oversized file: {relative.as_posix()}")
            continue

        if not is_text_path(path):
            continue

        language = detect_language(path)
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        # A NUL byte in a "text" file means it is really binary.
        if "\x00" in source[:2048]:
            continue

        digest = hashlib.sha256(source.encode("utf-8", "replace")).hexdigest()
        is_test = looks_like_test(path)
        posix = relative.as_posix()

        snapshot.files.append(
            SourceFile(
                path=posix,
                absolute=path,
                language=language,
                size=size,
                line_count=source.count("\n") + 1,
                is_test=is_test,
                sha256=digest,
                source=source,
            )
        )
        budget -= size

        if language:
            languages[language] = languages.get(language, 0) + 1
        if _is_entrypoint(path) and not is_test:
            entrypoints.append(posix)
        if not is_test and len(snapshot.files) <= 400:
            for framework, markers in FRAMEWORK_MARKERS.items():
                lowered = source.lower()
                if any(f"import {m}" in lowered or f"from {m}" in lowered or f'"{m}"' in lowered or f"'{m}'" in lowered for m in markers):
                    snapshot.frameworks.add(framework)

    snapshot.languages = dict(sorted(languages.items(), key=lambda kv: -kv[1]))
    if snapshot.languages:
        # Spec §3: Python first. Fall back to the dominant language only
        # when there is no Python at all.
        snapshot.primary_language = (
            "python" if "python" in snapshot.languages else next(iter(snapshot.languages))
        )

    snapshot.dependencies, manifest_files, dep_frameworks = _collect_dependencies(root)
    snapshot.frameworks |= dep_frameworks
    snapshot.entrypoints = entrypoints[:25]
    snapshot.manifest = {
        **snapshot.as_manifest(),
        "manifest_files": manifest_files,
    }

    if not snapshot.files:
        raise IngestionError(
            "No analysable source files were found. The archive must contain source code "
            "(Python is fully supported; other languages get partial coverage)."
        )
    if snapshot.primary_language != settings.primary_language:
        snapshot.warnings.append(
            f"Primary language is '{snapshot.primary_language}'. "
            f"SentinelForge's analysis pipeline is tuned for "
            f"'{settings.primary_language}'; other languages receive reduced coverage."
        )
    return snapshot


def ingest_archive(archive_path: Path, destination: Path) -> RepositorySnapshot:
    """
    Safely extract an uploaded archive and index it.

    Raises ``IngestionError`` / ``UnsafeArchiveError`` for unusable uploads so
    the API layer can return an actionable message (spec §27).
    """
    if destination.exists():
        shutil.rmtree(destination, ignore_errors=True)
    destination.mkdir(parents=True, exist_ok=True)

    try:
        extraction = safe_extract_any(archive_path, destination)
    except UnsafeArchiveError as exc:
        raise IngestionError(str(exc)) from exc
    except Exception as exc:  # corrupted archive, bad central directory, ...
        raise IngestionError(f"Could not read archive: {exc}") from exc

    if extraction.file_count == 0:
        raise IngestionError("The archive contained no usable files after safety checks.")

    snapshot = build_snapshot(destination, result_truncated=extraction.truncated)
    if extraction.skipped:
        snapshot.warnings.append(
            f"{len(extraction.skipped)} archive entries were skipped by safety checks."
        )
    logger.info(
        "Ingested %s: %d files, %d languages, primary=%s",
        destination.name, snapshot.file_count, len(snapshot.languages), snapshot.primary_language,
    )
    return snapshot


# ----------------------------------------------------------------------
def parse_python_ast(source: str, filename: str = "<unknown>") -> ast.AST | None:
    """Parse Python source, returning ``None`` on syntax errors.

    Used by the analyzers; a repository under test is untrusted and may not
    even be valid Python.
    """
    try:
        return ast.parse(source, filename=filename)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None


def workspace_for(project_id: str, *, base: Path | None = None) -> Path:
    """Return (and create) the on-disk root for a project's extracted code."""
    root = base or settings.workspace_path
    target = safe_join(root, project_id)
    target.mkdir(parents=True, exist_ok=True)
    return target
