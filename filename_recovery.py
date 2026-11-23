"""Recover filename separators when source includes make the intended name clear."""

from __future__ import annotations

import re
from pathlib import PurePosixPath


INCLUDE_RE = re.compile(r'^\s*#\s*include\s*[<"]([^">]+)[">]', re.MULTILINE)


def _normalized_basename(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", PurePosixPath(name).name.casefold())


def recover_names_from_includes(files: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Restore a filename only when a unique quoted/angled include identifies it.

    For example, a file named ``caqgemvv5.cu`` can be restored to
    ``caq_gemv_v5.cu`` when another source file includes that exact basename.
    Ambiguous matches and collisions are left unchanged.
    """
    referenced: dict[str, set[str]] = {}
    for _, content in files:
        for include in INCLUDE_RE.findall(content):
            basename = PurePosixPath(include.replace("\\", "/")).name
            referenced.setdefault(_normalized_basename(basename), set()).add(basename)

    existing_names = {PurePosixPath(name).name for name, _ in files}
    proposed: list[tuple[str, str]] = []
    for name, content in files:
        path = PurePosixPath(name)
        basename = path.name
        candidates = referenced.get(_normalized_basename(basename), set())
        if len(candidates) == 1:
            expected = next(iter(candidates))
            if expected != basename and expected not in existing_names:
                proposed.append((name, str(path.with_name(expected))))
                continue
        proposed.append((name, name))

    destinations = [destination for _, destination in proposed]
    if len(destinations) != len(set(destinations)):
        return files

    renamed = {source: destination for source, destination in proposed if source != destination}
    return [(renamed.get(name, name), content) for name, content in files]
