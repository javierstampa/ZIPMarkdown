"""Conservatively apply a local ZIPMarkdown vault to AI-edited Markdown or ZIPs."""
from __future__ import annotations

import base64
import re
import shutil
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from archive_safety import (
    DEFAULT_LIMITS,
    SecurityLimits,
    canonical_archive_key,
    read_zip_entry,
    validate_archive_name,
    validate_zip_infos,
)
from atomic_utils import atomic_build
from local_secrets import VaultBackend, load_secrets
from path_safety import ensure_distinct_paths, require_suffix

TOKEN_RE = re.compile(r"\[\[MDTK_SECRET_([a-f0-9]{32})\]\]")
_PLACEHOLDER_VALUE_RE = re.compile(
    r"(?i)^(?:\[redacted(?: private key)?\]|redacted(?: private key)?|<[^>]+>|\$\{[^}]+\}|"
    r"\{\{[^}]+\}\}|(?:your|example|sample|placeholder|replace|insert|change)[-_ a-z0-9]*"
    r"(?:key|secret|token|password|value)?|changeme|change_me|todo|xxx+)$"
)
_ASSIGNMENT_RE = re.compile(
    r"(?i)(?P<prefix>(?<![A-Za-z0-9])[\"']?(?P<key>[A-Za-z0-9_.-]+)[\"']?\s*[:=]\s*)"
    r"(?P<value>\"[^\"\r\n]*\"|'[^'\r\n]*'|\[[^\]\r\n]*\]|[^\s,;#}\]]+)"
)
_PRIVATE_BLOCK_RE = re.compile(
    r"(?P<begin>-----BEGIN (?P<label>[A-Z0-9 ]*PRIVATE KEY)-----)(?P<body>.*?)(?P<end>-----END (?P=label)-----)", re.S
)
_REDACTED_LINE_RE = re.compile(r"(?m)^(?P<indent>[ \t]*)(?:\[REDACTED(?: PRIVATE KEY)?\]|<[^>]+>)(?P<ending>\r?)$")
_REDACTED_AUTH_RE = re.compile(r"(?i)\b(?P<scheme>Bearer|Basic)\s+(?:\[REDACTED\]|<[^>]+>)")
_REDACTED_URL_PASSWORD_RE = re.compile(r"(?i)(?P<prefix>://[^:/\s]+:)(?:\[REDACTED\]|<[^>]+>)(?P<suffix>@)")


@dataclass(frozen=True)
class RebaseReport:
    values_applied: int = 0
    values_unmatched: int = 0
    sensitive_files_added: int = 0
    files_processed: int = 0
    ambiguous_cases: int = 0
    warnings: tuple[str, ...] = ()
    files_generated: int = 0
    protected_files_added: int = 0


def _path_key(path: str) -> str:
    return canonical_archive_key(path.replace("\\", "/"))


def _basename_key(path: str) -> str:
    return re.sub(r"[^a-z0-9]", "", PurePosixPath(path.replace("\\", "/")).name.casefold())


def _unquote(value: str) -> tuple[str, str]:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'\"', "'"}:
        return value[1:-1], value[0]
    return value, ""


def _is_placeholder(value: str) -> bool:
    inner, _ = _unquote(value.strip())
    return not inner.strip() or bool(_PLACEHOLDER_VALUE_RE.fullmatch(inner.strip()))


def _quote_secret(value: str, quote: str) -> str:
    if not quote:
        return value
    escaped = value.replace("\\", "\\\\").replace(quote, "\\" + quote).replace("\r", "\\r").replace("\n", "\\n")
    return f"{quote}{escaped}{quote}"


def _candidate_indices(source_path: str, files: list[tuple[str, str]]) -> tuple[list[int], str | None]:
    exact = [index for index, (name, _) in enumerate(files) if _path_key(name) == _path_key(source_path)]
    if exact:
        return exact, None
    key = _basename_key(source_path)
    candidates = [index for index, (name, _) in enumerate(files) if _basename_key(name) == key]
    if len(candidates) == 1:
        return candidates, f"Recovered renamed path {source_path!r} as {files[candidates[0]][0]!r}."
    return candidates, None


def rebase_text_files(files: list[tuple[str, str]], payload: dict[str, Any]) -> tuple[list[tuple[str, str]], RebaseReport]:
    redactions, bindings = payload.get("redactions", {}), payload.get("bindings", [])
    if not isinstance(redactions, dict) or not isinstance(bindings, list):
        raise ValueError("vault redaction data is invalid")
    result = list(files)
    restored: set[str] = set()
    applied_count = 0
    warnings: list[str] = []
    ambiguous = 0

    for index, (name, content) in enumerate(result):
        def restore_marker(match: re.Match[str]) -> str:
            nonlocal applied_count
            token = match.group(1)
            if token not in redactions:
                return match.group(0)
            restored.add(token)
            applied_count += 1
            return str(redactions[token])
        result[index] = (name, TOKEN_RE.sub(restore_marker, content))

    unresolved: set[str] = set()
    for binding in bindings:
        if not isinstance(binding, dict):
            continue
        token = binding.get("token")
        if not isinstance(token, str) or token not in redactions or token in restored:
            continue
        source_path, key, kind = binding.get("path", ""), binding.get("key", ""), binding.get("kind", "")
        if not isinstance(source_path, str):
            unresolved.add(token)
            continue
        key = key if isinstance(key, str) else ""
        kind = kind if isinstance(kind, str) else ""
        candidates, recovery_warning = _candidate_indices(source_path, result)
        if recovery_warning:
            warnings.append(recovery_warning)
        if len(candidates) > 1:
            ambiguous += 1
            unresolved.add(token)
            warnings.append(f"Ambiguous path match left unchanged for {source_path!r}.")
            continue
        applied = False
        if key:
            for index in candidates:
                name, content = result[index]
                def replace_assignment(match: re.Match[str]) -> str:
                    nonlocal applied
                    if applied or match.group("key").casefold().replace("-", "_") != key.casefold().replace("-", "_"):
                        return match.group(0)
                    current, quote = _unquote(match.group("value"))
                    if not _is_placeholder(current):
                        return match.group(0)
                    applied = True
                    return f"{match.group('prefix')}{_quote_secret(str(redactions[token]), quote)}"
                content = _ASSIGNMENT_RE.sub(replace_assignment, content)
                result[index] = (name, content)
        if not applied:
            for index in candidates:
                name, content = result[index]
                if kind == "private_key":
                    def restore_line(match: re.Match[str]) -> str:
                        nonlocal applied
                        if applied:
                            return match.group(0)
                        applied = True
                        return f"{match.group('indent')}{redactions[token]}{match.group('ending')}"
                    content = _PRIVATE_BLOCK_RE.sub(
                        lambda match: f"{match.group('begin')}{_REDACTED_LINE_RE.sub(restore_line, match.group('body'))}{match.group('end')}",
                        content,
                    )
                elif kind == "authorization":
                    content, count = _REDACTED_AUTH_RE.subn(lambda match: f"{match.group('scheme')} {redactions[token]}", content, count=1)
                    applied = bool(count)
                elif kind == "url_password":
                    content, count = _REDACTED_URL_PASSWORD_RE.subn(
                        lambda match: f"{match.group('prefix')}{redactions[token]}{match.group('suffix')}", content, count=1
                    )
                    applied = bool(count)
                result[index] = (name, content)
                if applied:
                    break
        if applied:
            restored.add(token)
            applied_count += 1
        else:
            unresolved.add(token)

    existing_paths = {_path_key(name) for name, _ in result}
    protected_paths = {
        _path_key(item.get("name", ""))
        for category in ("sensitive_files", "binary_files")
        for item in (payload.get(category, []) if isinstance(payload.get(category, []), list) else [])
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    restored_with_file = {
        token
        for token in unresolved
        if any(
            isinstance(binding, dict)
            and binding.get("token") == token
            and isinstance(binding.get("path"), str)
            and _path_key(binding["path"]) in protected_paths - existing_paths
            for binding in bindings
        )
    }
    unresolved -= restored_with_file
    applied_count += len(restored_with_file)
    return result, RebaseReport(
        values_applied=applied_count,
        values_unmatched=len(unresolved),
        files_processed=len(result),
        ambiguous_cases=ambiguous,
        warnings=tuple(dict.fromkeys(warnings)),
    )


def _decode_protected_files(payload: dict[str, Any], existing_names: set[str]) -> tuple[list[tuple[str, bytes]], int, int]:
    files: list[tuple[str, bytes]] = []
    sensitive_added = binary_added = 0
    for category in ("sensitive_files", "binary_files"):
        items = payload.get(category, [])
        if not isinstance(items, list):
            raise ValueError(f"vault {category} data is invalid")
        for item in items:
            if not isinstance(item, dict):
                continue
            name, encoded = item.get("name"), item.get("bytes")
            if not isinstance(name, str) or not isinstance(encoded, str):
                continue
            validate_archive_name(name)
            folded = _path_key(name)
            if folded in existing_names:
                continue
            try:
                raw = base64.b64decode(encoded, validate=True)
            except ValueError as error:
                raise ValueError(f"protected content is invalid for {name!r}") from error
            files.append((name, raw))
            existing_names.add(folded)
            if category == "sensitive_files":
                sensitive_added += 1
            else:
                binary_added += 1
    return files, sensitive_added, binary_added


def _validated_zip(path: Path, limits: SecurityLimits) -> None:
    with zipfile.ZipFile(path) as archive:
        validate_zip_infos(archive.infolist(), limits=limits)
        broken = archive.testzip()
        if broken:
            raise zipfile.BadZipFile(f"generated ZIP failed validation at {broken!r}")


def rebase_zip_file(
    input_path: Path,
    output_path: Path,
    secrets_path: Path,
    *,
    vault_backend: VaultBackend | None = None,
    limits: SecurityLimits = DEFAULT_LIMITS,
) -> RebaseReport:
    from zip_a_markdown import decode_text
    require_suffix(input_path, ".zip", "rebase input")
    require_suffix(output_path, ".zip", "rebase output")
    require_suffix(secrets_path, ".secrets", "vault")
    ensure_distinct_paths(input=input_path, output=output_path, vault=secrets_path)
    payload = load_secrets(secrets_path, backend=vault_backend)
    with zipfile.ZipFile(input_path) as source:
        infos = source.infolist()
        validate_zip_infos(infos, limits=limits)
        total = [0]
        text_files: list[tuple[str, str]] = []
        for info in infos:
            if info.is_dir():
                continue
            raw = read_zip_entry(source, info, limits=limits, total_processed=total)
            text = decode_text(raw)
            if text is not None:
                text_files.append((info.filename, text))
    rebased, report = rebase_text_files(text_files, payload)
    rebased_map = {_path_key(name): content for name, content in rebased}
    existing = {_path_key(info.filename) for info in infos if not info.is_dir()}
    protected, sensitive_added, binary_added = _decode_protected_files(payload, existing)

    def build(temporary: Path) -> None:
        with zipfile.ZipFile(input_path) as source, zipfile.ZipFile(temporary, "w") as destination:
            for info in source.infolist():
                if info.is_dir():
                    destination.writestr(info, b"")
                    continue
                replacement = rebased_map.get(_path_key(info.filename))
                if replacement is not None:
                    raw = read_zip_entry(source, info, limits=limits)
                    original = decode_text(raw)
                    destination.writestr(info, raw if original == replacement else replacement.encode("utf-8"))
                else:
                    with source.open(info) as src, destination.open(info, "w") as dst:
                        shutil.copyfileobj(src, dst, length=1024 * 1024)
            for name, raw in protected:
                destination.writestr(name, raw)
    atomic_build(output_path, build, lambda path: _validated_zip(path, limits))
    return RebaseReport(
        report.values_applied, report.values_unmatched, sensitive_added, report.files_processed,
        report.ambiguous_cases, report.warnings, len(infos) + len(protected),
        sensitive_added + binary_added,
    )


def rebase_markdown_file(
    markdown_path: Path,
    output_path: Path,
    secrets_path: Path,
    *,
    vault_backend: VaultBackend | None = None,
    limits: SecurityLimits = DEFAULT_LIMITS,
) -> RebaseReport:
    import markdown_a_zip
    require_suffix(markdown_path, ".md", "Markdown input")
    require_suffix(output_path, ".zip", "rebase output")
    require_suffix(secrets_path, ".secrets", "vault")
    ensure_distinct_paths(input=markdown_path, output=output_path, vault=secrets_path)
    payload = load_secrets(secrets_path, backend=vault_backend)
    files = markdown_a_zip.parse_markdown(markdown_path, limits=limits)
    rebased, report = rebase_text_files(files, payload)
    for name, _ in rebased:
        validate_archive_name(name, limits=limits)
    existing = {_path_key(name) for name, _ in rebased}
    protected, sensitive_added, binary_added = _decode_protected_files(payload, existing)
    backups: dict[str, list[dict[str, Any]]] = {}
    redacted_backups = payload.get("redacted_files", [])
    if isinstance(redacted_backups, list):
        for item in redacted_backups:
            if isinstance(item, dict) and isinstance(item.get("name"), str):
                backups.setdefault(_path_key(item["name"]), []).append(item)

    def build(temporary: Path) -> None:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, content in rebased:
                raw = content.encode("utf-8")
                candidates = backups.get(_path_key(name), [])
                if candidates:
                    backup = candidates.pop(0)
                    original_text, original_bytes = backup.get("text"), backup.get("bytes")
                    if isinstance(original_text, str) and isinstance(original_bytes, str):
                        def normalize(text: str) -> str:
                            return text.replace("\r\n", "\n").replace("\r", "\n")

                        if normalize(content) == normalize(original_text) or name.casefold().endswith(".pdf"):
                            raw = base64.b64decode(original_bytes, validate=True)
                archive.writestr(name, raw)
            for name, raw in protected:
                archive.writestr(name, raw)
    atomic_build(output_path, build, lambda path: _validated_zip(path, limits))
    return RebaseReport(
        report.values_applied, report.values_unmatched, sensitive_added, report.files_processed,
        report.ambiguous_cases, report.warnings, len(rebased) + len(protected),
        sensitive_added + binary_added,
    )
