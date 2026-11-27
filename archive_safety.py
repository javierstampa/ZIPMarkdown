"""Central path and resource-limit validation for untrusted projects and ZIPs."""
from __future__ import annotations

import stat
import unicodedata
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath


class ArchiveSecurityError(ValueError):
    """Raised when an archive or project entry is unsafe to process."""


@dataclass(frozen=True)
class SecurityLimits:
    max_entries: int = 10_000
    max_file_size: int = 100 * 1024 * 1024
    max_total_size: int = 1024 * 1024 * 1024
    max_markdown_size: int = 1024 * 1024 * 1024
    max_pdf_pages: int = 1_000
    max_compression_ratio: float = 100.0
    max_path_length: int = 240
    max_path_depth: int = 64


DEFAULT_LIMITS = SecurityLimits()
WINDOWS_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}


def canonical_archive_key(name: str) -> str:
    """Return a cross-platform collision key for an already validated path.

    Case-insensitive filesystems and filesystems that normalize Unicode must not
    be allowed to turn two archive entries into one destination file.
    """
    return "/".join(unicodedata.normalize("NFC", part).casefold() for part in PurePosixPath(name).parts)


def validate_archive_name(name: str, *, limits: SecurityLimits = DEFAULT_LIMITS) -> str:
    """Validate a portable relative archive path and return its normalized spelling."""
    if not isinstance(name, str) or not name or "\x00" in name or "\\" in name:
        raise ArchiveSecurityError(f"unsafe archive path: {name!r}")
    posix = PurePosixPath(name)
    windows = PureWindowsPath(name)
    parts = posix.parts
    if (
        posix.is_absolute()
        or windows.is_absolute()
        or bool(windows.drive)
        or name in {".", ".."}
        or any(part in {"", ".", ".."} for part in parts)
        or len(parts) > limits.max_path_depth
        or len(name) > limits.max_path_length
    ):
        raise ArchiveSecurityError(f"unsafe archive path: {name!r}")
    for part in parts:
        if len(part) > 255 or part.endswith((" ", ".")) or ":" in part:
            raise ArchiveSecurityError(f"non-portable archive path: {name!r}")
        stem = part.split(".", 1)[0].upper()
        if stem in WINDOWS_RESERVED:
            raise ArchiveSecurityError(f"Windows-reserved archive path: {name!r}")
    return name


def is_zip_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0xFFFF
    return stat.S_ISLNK(mode)


def validate_zip_infos(infos: list[zipfile.ZipInfo], *, limits: SecurityLimits = DEFAULT_LIMITS) -> None:
    if len(infos) > limits.max_entries:
        raise ArchiveSecurityError(f"ZIP has {len(infos)} entries; limit is {limits.max_entries}")
    seen: set[str] = set()
    total = 0
    for info in infos:
        name = info.filename.rstrip("/") if info.is_dir() else info.filename
        if name:
            validate_archive_name(name, limits=limits)
        folded = canonical_archive_key(name)
        if folded in seen:
            raise ArchiveSecurityError(f"duplicate or canonical path collision in ZIP: {info.filename!r}")
        seen.add(folded)
        if info.flag_bits & 0x1:
            raise ArchiveSecurityError(f"encrypted ZIP entries are not supported: {info.filename!r}")
        if is_zip_symlink(info):
            raise ArchiveSecurityError(f"symbolic links are not supported in ZIPs: {info.filename!r}")
        if info.file_size > limits.max_file_size:
            raise ArchiveSecurityError(f"ZIP entry exceeds the per-file limit: {info.filename!r}")
        total += info.file_size
        if total > limits.max_total_size:
            raise ArchiveSecurityError("ZIP exceeds the total uncompressed-size limit")
        if info.file_size and info.compress_size == 0:
            raise ArchiveSecurityError(f"suspicious compression metadata: {info.filename!r}")
        if info.compress_size:
            ratio = info.file_size / info.compress_size
            if ratio > limits.max_compression_ratio:
                raise ArchiveSecurityError(
                    f"suspicious compression ratio ({ratio:.1f}:1): {info.filename!r}"
                )


def read_zip_entry(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    *,
    limits: SecurityLimits = DEFAULT_LIMITS,
    total_processed: list[int] | None = None,
) -> bytes:
    """Read one entry in chunks while enforcing declared and actual limits."""
    chunks: list[bytes] = []
    actual = 0
    with archive.open(info, "r") as stream:
        while True:
            chunk = stream.read(min(1024 * 1024, limits.max_file_size + 1 - actual))
            if not chunk:
                break
            actual += len(chunk)
            if actual > limits.max_file_size:
                raise ArchiveSecurityError(f"ZIP entry exceeds the per-file limit: {info.filename!r}")
            chunks.append(chunk)
    if actual != info.file_size:
        raise ArchiveSecurityError(f"ZIP entry size changed while reading: {info.filename!r}")
    if total_processed is not None:
        total_processed[0] += actual
        if total_processed[0] > limits.max_total_size:
            raise ArchiveSecurityError("ZIP exceeds the actual total uncompressed-size limit")
    return b"".join(chunks)


def validate_project_file(path: Path, root: Path, *, limits: SecurityLimits = DEFAULT_LIMITS) -> str:
    if path.is_symlink():
        raise ArchiveSecurityError(f"symbolic links are not supported: {path}")
    relative = path.relative_to(root).as_posix()
    validate_archive_name(relative, limits=limits)
    size = path.stat().st_size
    if size > limits.max_file_size:
        raise ArchiveSecurityError(f"file exceeds the per-file limit: {relative!r}")
    return relative
