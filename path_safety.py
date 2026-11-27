"""Preflight validation for input, output, vault, and sidecar paths."""
from __future__ import annotations

import unicodedata
from pathlib import Path


def canonical_local_key(path: Path) -> str:
    """Return a conservative cross-platform identity for a local path."""
    resolved = path.expanduser().resolve(strict=False)
    return unicodedata.normalize("NFC", str(resolved)).casefold()


def ensure_distinct_paths(**paths: Path | None) -> None:
    """Reject any pair of paths that could identify the same portable file."""
    seen: dict[str, str] = {}
    for role, path in paths.items():
        if path is None:
            continue
        key = canonical_local_key(path)
        previous = seen.get(key)
        if previous is not None:
            raise ValueError(f"{role} path must differ from {previous} path: {path}")
        seen[key] = role


def require_suffix(path: Path, suffix: str, role: str) -> None:
    if path.suffix.casefold() != suffix.casefold():
        raise ValueError(f"{role} must use the {suffix} extension: {path}")
