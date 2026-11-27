"""Small, same-filesystem atomic write helpers used by ZIPMarkdown."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Callable


def atomic_write_bytes(path: Path, data: bytes, *, mode: int | None = None) -> None:
    """Write *data* to *path* without exposing a partially written destination."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if mode is not None:
            os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def atomic_write_text(path: Path, text: str, *, encoding: str = "utf-8") -> None:
    atomic_write_bytes(path, text.encode(encoding))


def atomic_write_pair(
    primary_path: Path,
    primary_data: bytes,
    secondary_path: Path,
    secondary_data: bytes | None,
    *,
    secondary_mode: int | None = None,
) -> None:
    """Commit a Markdown/vault pair with rollback if either replacement fails.

    ``secondary_data=None`` transactionally removes a stale secondary file.  The
    two destinations must share neither identity nor path.  This is not a
    filesystem-wide two-phase commit, but it guarantees that a caught failure
    restores the previously visible pair instead of leaving mixed generations.
    """
    primary_path, secondary_path = Path(primary_path), Path(secondary_path)
    if primary_path.resolve(strict=False) == secondary_path.resolve(strict=False):
        raise ValueError("paired destinations must be distinct")
    primary_path.parent.mkdir(parents=True, exist_ok=True)
    secondary_path.parent.mkdir(parents=True, exist_ok=True)

    def staged(path: Path, data: bytes, mode: int | None = None) -> Path:
        fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        temporary = Path(name)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if mode is not None:
            os.chmod(temporary, mode)
        return temporary

    primary_temp = staged(primary_path, primary_data)
    secondary_temp = staged(secondary_path, secondary_data, secondary_mode) if secondary_data is not None else None
    backups: dict[Path, Path] = {}
    committed: set[Path] = set()
    try:
        for destination in (secondary_path, primary_path):
            if destination.exists():
                fd, backup_name = tempfile.mkstemp(
                    prefix=f".{destination.name}.", suffix=".bak", dir=destination.parent
                )
                os.close(fd)
                backup = Path(backup_name)
                backup.unlink()
                os.replace(destination, backup)
                backups[destination] = backup
        if secondary_temp is not None:
            os.replace(secondary_temp, secondary_path)
            committed.add(secondary_path)
        os.replace(primary_temp, primary_path)
        committed.add(primary_path)
    except BaseException:
        for destination in (primary_path, secondary_path):
            if destination in committed:
                destination.unlink(missing_ok=True)
        for destination in (primary_path, secondary_path):
            backup = backups.get(destination)
            if backup is not None and backup.exists():
                os.replace(backup, destination)
        raise
    finally:
        primary_temp.unlink(missing_ok=True)
        if secondary_temp is not None:
            secondary_temp.unlink(missing_ok=True)
        for backup in backups.values():
            backup.unlink(missing_ok=True)


def atomic_build(path: Path, builder: Callable[[Path], None], validator: Callable[[Path], None] | None = None) -> None:
    """Build a file beside its destination, validate it, then atomically replace it."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    os.close(fd)
    temporary = Path(temporary_name)
    try:
        builder(temporary)
        if validator is not None:
            validator(temporary)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
