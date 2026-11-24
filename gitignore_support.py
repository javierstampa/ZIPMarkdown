"""Optional .gitignore matching for ZIPMarkdown folder exports.

Uses pathspec when installed. A documented conservative fallback supports common
rooted, directory, wildcard and negation rules so the safety option remains usable
in constrained/offline environments.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path

try:
    from pathspec.patterns.gitwildmatch import GitWildMatchPattern
except ImportError:  # pragma: no cover - exercised by fallback tests
    GitWildMatchPattern = None  # type: ignore[assignment]


@dataclass(frozen=True)
class IgnoreMatch:
    ignored: bool
    rule: str | None = None


def _fallback_match(rule: str, path: str) -> bool:
    pattern = rule[1:] if rule.startswith("!") else rule
    pattern = pattern.strip()
    normalized = path.lstrip("./")
    directory_rule = pattern.endswith("/")
    pattern = pattern.rstrip("/")
    if pattern.startswith("/"):
        matched = fnmatch.fnmatchcase(normalized.rstrip("/"), pattern[1:])
    elif "/" in pattern:
        matched = fnmatch.fnmatchcase(normalized.rstrip("/"), pattern)
    else:
        matched = any(fnmatch.fnmatchcase(part, pattern) for part in normalized.rstrip("/").split("/"))
    if directory_rule and not path.endswith("/") and f"/{pattern}/" not in f"/{normalized}/":
        return False
    return matched


class GitIgnoreMatcher:
    def __init__(self, root: Path) -> None:
        source = root / ".gitignore"
        self.patterns: list[tuple[str, object | None]] = []
        if source.is_file():
            for raw in source.read_text(encoding="utf-8-sig", errors="replace").splitlines():
                if not raw.strip() or raw.lstrip().startswith("#"):
                    continue
                compiled = GitWildMatchPattern(raw) if GitWildMatchPattern is not None else None
                self.patterns.append((raw, compiled))

    def match(self, relative_path: str) -> IgnoreMatch:
        state: bool | None = None
        rule: str | None = None
        for raw, pattern in self.patterns:
            if pattern is not None:
                matched = pattern.match_file(relative_path)  # type: ignore[attr-defined]
                if matched is None:
                    continue
                state = bool(matched)
            elif _fallback_match(raw, relative_path):
                state = not raw.startswith("!")
            else:
                continue
            rule = raw
        return IgnoreMatch(bool(state), rule if state else None)
