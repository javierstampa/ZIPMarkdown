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
