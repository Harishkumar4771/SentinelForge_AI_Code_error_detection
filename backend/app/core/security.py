"""
Filesystem and archive safety primitives.

Uploaded repositories are untrusted input. Nothing in this module executes
code; it only validates and normalises paths and archives so that later
stages (sandbox, scanners) can assume a well-formed tree.

Guards implemented here:
  * path traversal ("zip slip") via ``..`` segments and absolute paths
  * symlink / hardlink escapes out of the extraction root
  * zip bombs (uncompressed size, entry count, per-file size)
  * NUL-byte and control-character injection in member names
"""

from __future__ import annotations

import os
import re
import shutil
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from app.core.config import settings

# A single path segment we are willing to write to disk.
_SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9._\-\s]+$")

# Directories that are never useful to scan and often hide payloads.
BLOCKED_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "dist",
    "build",
    ".next",
    ".terraform",
    "vendor",
    "site-packages",
}

# Binary / non-source extensions we never read into an LLM context.
BINARY_EXTENSIONS = {
    ".pyc", ".pyo", ".so", ".dylib", ".dll", ".exe", ".bin", ".o", ".a",
    ".class", ".jar", ".war", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z",
    ".rar", ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".pdf", ".mp3", ".mp4", ".avi", ".mov", ".wav", ".ttf", ".otf", ".woff",
    ".woff2", ".eot", ".db", ".sqlite", ".sqlite3", ".pack", ".idx",
}

TEXT_EXTENSIONS = {
    ".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".json", ".yaml", ".yml",
    ".toml", ".cfg", ".ini", ".txt", ".md", ".sh", ".bash", ".env", ".sql",
    ".html", ".htm", ".css", ".go", ".java", ".rb", ".php", ".rs", ".c",
    ".h", ".cpp", ".hpp", ".cs", ".xml", ".properties", ".conf", ".tf",
}


class UnsafeArchiveError(ValueError):
    """Raised when an archive violates a safety invariant."""


@dataclass
class ExtractionResult:
    """Outcome of a successful safe extraction."""

    root: Path
    file_count: int = 0
    total_bytes: int = 0
    skipped: list[str] = field(default_factory=list)
    truncated: bool = False


# ----------------------------------------------------------------------
# Path safety
# ----------------------------------------------------------------------
def is_blocked_path(relative_path: str | PurePosixPath) -> bool:
    """True when any path segment is a directory we refuse to scan."""
    parts = PurePosixPath(relative_path).parts
    return any(part in BLOCKED_DIR_NAMES for part in parts)


def is_binary_path(path: Path | str) -> bool:
    return Path(path).suffix.lower() in BINARY_EXTENSIONS


def is_text_path(path: Path | str) -> bool:
    suffix = Path(path).suffix.lower()
    if suffix in BINARY_EXTENSIONS:
        return False
    if suffix in TEXT_EXTENSIONS:
        return True
    # Extensionless files that look like config are still worth reading.
    return Path(path).name in {
        "Dockerfile", "Makefile", "Procfile", "requirements.txt", "Pipfile",
    }


def sanitize_member_name(name: str) -> str:
    """Validate a single archive member name and return a safe relative path.

    Raises ``UnsafeArchiveError`` if the name could escape the destination.
    """
    if not name or name in {".", "./"}:
        raise UnsafeArchiveError("Empty archive member name")

    if "\x00" in name:
        raise UnsafeArchiveError(f"NUL byte in archive member name: {name!r}")

    # Normalise Windows separators, then reject anything absolute or climbing.
    normalised = name.replace("\\", "/")
    if normalised.startswith("/") or re.match(r"^[A-Za-z]:", normalised):
        raise UnsafeArchiveError(f"Absolute path in archive: {name!r}")

    parts = [p for p in PurePosixPath(normalised).parts if p not in (".",)]
    if not parts:
        raise UnsafeArchiveError(f"Archive member resolves to root: {name!r}")

    for part in parts:
        if part == "..":
            raise UnsafeArchiveError(f"Path traversal attempt in archive: {name!r}")
        # Control characters can confuse downstream shell/tooling.
        if any(ord(ch) < 32 for ch in part):
            raise UnsafeArchiveError(f"Control character in archive member: {name!r}")

    # Reject hidden dotfiles at the top of member names only when they are
    # absolute-looking; keep normal dotfiles (.env is a real finding target).
    return str(PurePosixPath(*parts))


def safe_join(root: Path, *relative_parts: str) -> Path:
    """Join under ``root`` and guarantee the result stays inside it.

    This is the only sanctioned way to build a path from untrusted input.
    """
    root = root.resolve()
    candidate = root.joinpath(*relative_parts)

    # ``resolve`` collapses ``..`` and follows symlinks, so comparing the
    # resolved candidate against the resolved root catches both traversal
    # and symlink escapes.
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise UnsafeArchiveError(
            f"Resolved path escapes sandbox root: {candidate}"
        ) from exc
    return resolved


# ----------------------------------------------------------------------
# ZIP extraction
# ----------------------------------------------------------------------
def _validate_zip_metadata(zf: zipfile.ZipFile) -> None:
    infos = zf.infolist()
    if len(infos) > settings.max_archive_files:
        raise UnsafeArchiveError(
            f"Archive has {len(infos)} entries, limit is {settings.max_archive_files}"
        )

    total = 0
    for info in infos:
        # 0x1 marks a symlink stored in the unix extra field.
        if (info.external_attr >> 16) & 0o170000 == 0o120000:
            raise UnsafeArchiveError(f"Symlink in archive is not allowed: {info.filename}")
        if info.file_size > settings.max_file_size:
            raise UnsafeArchiveError(
                f"Member {info.filename!r} is {info.file_size} bytes, "
                f"limit is {settings.max_file_size}"
            )
        total += info.file_size

    if total > settings.max_uncompressed_size:
        ratio = total / max(len(infos), 1) / max(settings.max_file_size, 1)
        raise UnsafeArchiveError(
            f"Archive expands to {total} bytes "
            f"(limit {settings.max_uncompressed_size}); possible zip bomb"
        )


def safe_extract_zip(
    archive_path: Path,
    destination: Path,
    *,
    strip_single_root: bool = True,
) -> ExtractionResult:
    """Extract a ZIP into ``destination`` with every safety guard applied.

    ``strip_single_root`` drops a single shared top-level directory, which
    is how users almost always zip a repository on macOS/Windows.
    """
    destination.mkdir(parents=True, exist_ok=True)
    destination = destination.resolve()

    result = ExtractionResult(root=destination)

    with zipfile.ZipFile(archive_path) as zf:
        _validate_zip_metadata(zf)

        members: list[tuple[zipfile.ZipInfo, str]] = []
        for info in zf.infolist():
            try:
                safe_name = sanitize_member_name(info.filename)
            except UnsafeArchiveError:
                result.skipped.append(info.filename)
                continue

            if info.is_dir():
                continue

            if is_blocked_path(safe_name):
                result.skipped.append(safe_name)
                continue

            members.append((info, safe_name))

        if strip_single_root:
            members = _strip_common_root(members, result)

        for info, safe_name in members:
            target = safe_join(destination, safe_name)

            # Defence in depth: a realpath check even after safe_join.
            if not str(target).startswith(str(destination) + os.sep):
                result.skipped.append(safe_name)
                continue

            target.parent.mkdir(parents=True, exist_ok=True)

            written = 0
            with zf.open(info) as src, target.open("wb") as dst:
                while chunk := src.read(65536):
                    written += len(chunk)
                    if written > settings.max_file_size:
                        result.skipped.append(f"{safe_name} (size limit)")
                        break
                    if result.total_bytes + written > settings.max_uncompressed_size:
                        result.truncated = True
                        result.skipped.append(f"{safe_name} (archive budget)")
                        break
                    dst.write(chunk)
                else:
                    result.total_bytes += written
                    result.file_count += 1
                    continue

    return result


def _strip_common_root(
    members: list[tuple[zipfile.ZipInfo, str]],
    result: ExtractionResult,
) -> list[tuple[zipfile.ZipInfo, str]]:
    """Remove a single shared top-level directory if all files share one."""
    if not members:
        return members

    roots = {PurePosixPath(name).parts[0] for _, name in members}
    if len(roots) != 1:
        return members

    root_name = roots.pop()
    # Only strip if the root is itself a directory, never a real source file.
    if any(not PurePosixPath(name).parts[1:] for _, name in members):
        return members

    result.skipped.append(f"<stripped common root: {root_name}/>")
    stripped: list[tuple[zipfile.ZipInfo, str]] = []
    for info, name in members:
        remainder = PurePosixPath(*PurePosixPath(name).parts[1:])
        if str(remainder) == ".":
            continue
        stripped.append((info, str(remainder)))
    return stripped


# ----------------------------------------------------------------------
# tar extraction (used for archives a user may rename to .zip)
# ----------------------------------------------------------------------
def safe_extract_tar(archive_path: Path, destination: Path) -> ExtractionResult:
    destination.mkdir(parents=True, exist_ok=True)
    destination = destination.resolve()
    result = ExtractionResult(root=destination)

    with tarfile.open(archive_path, "r:*") as tf:
        total = 0
        count = 0
        for member in tf:
            if count > settings.max_archive_files:
                result.truncated = True
                break
            if member.issym() or member.islnk():
                result.skipped.append(member.name)
                continue
            if not member.isfile():
                continue
            try:
                safe_name = sanitize_member_name(member.name)
            except UnsafeArchiveError:
                result.skipped.append(member.name)
                continue
            if is_blocked_path(safe_name):
                result.skipped.append(safe_name)
                continue

            target = safe_join(destination, safe_name)
            total += member.size
            if member.size > settings.max_file_size or total > settings.max_uncompressed_size:
                result.skipped.append(f"{safe_name} (size limit)")
                continue

            target.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(member)
            if src is None:
                continue
            with src, target.open("wb") as dst:
                shutil.copyfileobj(src, dst, 65536)
            result.file_count += 1
            result.total_bytes += member.size
            count += 1

    return result


def safe_extract_any(archive_path: Path, destination: Path) -> ExtractionResult:
    """Dispatch to the zip or tar extractor based on real file magic."""
    if zipfile.is_zipfile(archive_path):
        return safe_extract_zip(archive_path, destination)
    if tarfile.is_tarfile(archive_path):
        return safe_extract_tar(archive_path, destination)
    raise UnsafeArchiveError(
        "Unsupported archive format. Upload a .zip (or .tar.gz) repository archive."
    )


# ----------------------------------------------------------------------
# Secret redaction
# ----------------------------------------------------------------------
_REDACT_KEYS = (
    "api_key", "apikey", "secret", "password", "passwd", "token",
    "authorization", "private_key", "access_key", "pwd",
)


def redact(text: str, *, keep_last: int = 4) -> str:
    """Mask anything that looks like a credential before it reaches a log."""
    import re as _re

    pattern = _re.compile(
        r"(?i)\b(" + "|".join(_REDACT_KEYS) + r")\b\s*[:=]\s*[\"']?([^\s\"',;]{3,})"
    )

    def _mask(match: "_re.Match[str]") -> str:
        secret = match.group(2)
        tail = secret[-keep_last:] if len(secret) > keep_last else ""
        return f"{match.group(1)}={'*' * 8}{tail}"

    return pattern.sub(_mask, text)
