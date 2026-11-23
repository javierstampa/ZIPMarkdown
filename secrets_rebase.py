"""Apply a local encrypted secret vault to Markdown or ZIP files from an AI."""

from __future__ import annotations

import base64
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from local_secrets import load_secrets


TOKEN_RE = re.compile(r"\[\[MDTK_SECRET_([a-f0-9]{32})\]\]")
_PLACEHOLDER_VALUE_RE = re.compile(
    r"(?i)^(?:\[redacted(?: private key)?\]|redacted(?: private key)?|<[^>]+>|\$\{[^}]+\}|"
    r"\{\{[^}]+\}\}|(?:your|example|sample|placeholder|replace|insert|"
    r"change)[-_ a-z0-9]*(?:key|secret|token|password|value)?|"
    r"changeme|change_me|todo|xxx+)$"
)
_ASSIGNMENT_RE = re.compile(
    r"(?i)(?P<prefix>(?<![A-Za-z0-9])[\"']?(?P<key>[A-Za-z0-9_-]+)"
    r"[\"']?\s*[:=]\s*)(?P<value>\"[^\"\r\n]*\"|'[^'\r\n]*'|"
    r"\[[^\]\r\n]*\]|[^\s,;#}\]]+)"
)
_PRIVATE_BLOCK_RE = re.compile(
    r"(?P<begin>-----BEGIN (?P<label>[A-Z0-9 ]*PRIVATE KEY)-----)"
    r"(?P<body>.*?)"
    r"(?P<end>-----END (?P=label)-----)",
    re.DOTALL,
)
_REDACTED_LINE_RE = re.compile(
    r"(?m)^(?P<indent>[ \t]*)(?:\[REDACTED(?: PRIVATE KEY)?\]|<[^>]+>)(?P<ending>\r?)$"
)
_REDACTED_AUTH_RE = re.compile(r"(?i)\b(?P<scheme>Bearer|Basic)\s+(?:\[REDACTED\]|<[^>]+>)")
_REDACTED_URL_PASSWORD_RE = re.compile(
    r"(?i)(?P<prefix>://[^:/\s]+:)(?:\[REDACTED\]|<[^>]+>)(?P<suffix>@)"
)


@dataclass(frozen=True)
class RebaseReport:
    values_applied: int
    values_unmatched: int
    sensitive_files_added: int


def _path_key(path: str) -> str:
    return path.replace("\\", "/").casefold()


def _unquote(value: str) -> tuple[str, str]:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1], value[0]
    return value, ""


def _is_placeholder(value: str) -> bool:
    inner, _ = _unquote(value.strip())
    return not inner.strip() or bool(_PLACEHOLDER_VALUE_RE.fullmatch(inner.strip()))


def _quote_secret(value: str, quote: str) -> str:
    if not quote:
        return value
    escaped = value.replace("\\", "\\\\").replace(quote, "\\" + quote)
    escaped = escaped.replace("\r", "\\r").replace("\n", "\\n")
    return f"{quote}{escaped}{quote}"


def _safe_archive_name(name: str) -> None:
    posix_path = PurePosixPath(name)
    windows_path = PureWindowsPath(name)
    if (
        not name
        or "\x00" in name
        or "\\" in name
        or posix_path.is_absolute()
        or windows_path.is_absolute()
        or windows_path.drive
        or ".." in posix_path.parts
        or name == "."
    ):
        raise ValueError(f"ruta de archivo no permitida en el vault: {name!r}")


def rebase_text_files(
    files: list[tuple[str, str]], payload: dict[str, Any]
) -> tuple[list[tuple[str, str]], RebaseReport]:
    """Restore explicit markers, then fill placeholder assignments by path/key.

    Unmatched secrets are reported, not treated as a conversion error. Existing
    non-placeholder values are never overwritten.
    """
    redactions = payload.get("redactions", {})
    bindings = payload.get("bindings", [])
    if not isinstance(redactions, dict) or not isinstance(bindings, list):
        raise ValueError("el vault no contiene un mapa de secretos válido")

    restored: set[str] = set()
    result = list(files)
    values_applied = 0
    for index, (name, content) in enumerate(result):
        def restore_marker(match: re.Match[str]) -> str:
            nonlocal values_applied
            token = match.group(1)
            if token not in redactions:
                return match.group(0)
            restored.add(token)
            values_applied += 1
            return str(redactions[token])

        result[index] = (name, TOKEN_RE.sub(restore_marker, content))

    path_indices: dict[str, list[int]] = {}
    for index, (name, _) in enumerate(result):
        path_indices.setdefault(_path_key(name), []).append(index)

    unresolved_tokens: set[str] = set()
    for binding in bindings:
        if not isinstance(binding, dict):
            continue
        token = binding.get("token")
        if not isinstance(token, str) or token not in redactions or token in restored:
            continue
        key = binding.get("key", "")
        source_path = binding.get("path", "")
        if not isinstance(source_path, str):
            unresolved_tokens.add(token)
            continue
        if not isinstance(key, str):
            key = ""
        candidates = path_indices.get(_path_key(source_path), [])
        applied = False
        if key:
            for index in candidates:
                name, content = result[index]

                def replace_assignment(match: re.Match[str]) -> str:
                    nonlocal applied
                    if applied or match.group("key").casefold() != key.casefold():
                        return match.group(0)
                    current, quote = _unquote(match.group("value"))
                    if not _is_placeholder(current):
                        return match.group(0)
                    applied = True
                    return (
                        f"{match.group('prefix')}"
                        f"{_quote_secret(str(redactions[token]), quote)}"
                    )

                content = _ASSIGNMENT_RE.sub(replace_assignment, content)
                result[index] = (name, content)
                if applied:
                    break
        if applied:
            restored.add(token)
            values_applied += 1
        else:
            kind = binding.get("kind", "")
            if not isinstance(kind, str):
                kind = ""
            for index in candidates:
                name, content = result[index]
                if kind == "private_key":
                    def restore_key_line(match: re.Match[str]) -> str:
                        nonlocal applied
                        if applied:
                            return match.group(0)
                        applied = True
                        return (
                            f"{match.group('indent')}{redactions[token]}"
                            f"{match.group('ending')}"
                        )

                    def restore_key_block(match: re.Match[str]) -> str:
                        body = _REDACTED_LINE_RE.sub(restore_key_line, match.group("body"))
                        return f"{match.group('begin')}{body}{match.group('end')}"

                    content = _PRIVATE_BLOCK_RE.sub(restore_key_block, content)
                elif kind == "authorization":
                    content, replacements = _REDACTED_AUTH_RE.subn(
                        lambda match: f"{match.group('scheme')} {redactions[token]}",
                        content,
                        count=1,
                    )
                    applied = replacements > 0
                elif kind == "url_password":
                    content, replacements = _REDACTED_URL_PASSWORD_RE.subn(
                        lambda match: (
                            f"{match.group('prefix')}{redactions[token]}{match.group('suffix')}"
                        ),
                        content,
                        count=1,
                    )
                    applied = replacements > 0
                result[index] = (name, content)
                if applied:
                    break
            if applied:
                restored.add(token)
                values_applied += 1
            else:
                unresolved_tokens.add(token)

    sensitive_files = payload.get("sensitive_files", [])
    if not isinstance(sensitive_files, list):
        raise ValueError("el vault contiene una lista de archivos sensibles inválida")
    existing = {_path_key(name) for name, _ in result}
    added = 0
    restored_sensitive_names: set[str] = set()
    for item in sensitive_files:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        encoded = item.get("bytes")
        if not isinstance(name, str) or not isinstance(encoded, str):
            continue
        _safe_archive_name(name)
        normalized = _path_key(name)
        if normalized in existing:
            continue
        try:
            base64.b64decode(encoded, validate=True)
        except ValueError as error:
            raise ValueError(f"contenido inválido para el archivo protegido {name!r}") from error
        existing.add(normalized)
        restored_sensitive_names.add(normalized)
        added += 1

    # Sensitive files are restored as a whole when absent. Their assignment
    # values therefore count as successfully rebased even without a marker.
    sensitive_restored_tokens = {
        token
        for token in unresolved_tokens
        if any(
            isinstance(binding, dict)
            and binding.get("token") == token
            and isinstance(binding.get("path"), str)
            and _path_key(binding["path"]) in restored_sensitive_names
            for binding in bindings
        )
    }
    unresolved_tokens -= sensitive_restored_tokens
    values_applied += len(sensitive_restored_tokens)
    return result, RebaseReport(values_applied, len(unresolved_tokens), added)


def restore_sensitive_files(payload: dict[str, Any], existing_names: set[str]) -> list[tuple[str, bytes]]:
    files: list[tuple[str, bytes]] = []
    for item in payload.get("sensitive_files", []):
        if not isinstance(item, dict):
            continue
        name, encoded = item.get("name"), item.get("bytes")
        if not isinstance(name, str) or not isinstance(encoded, str):
            continue
        _safe_archive_name(name)
        if _path_key(name) in existing_names:
            continue
        files.append((name, base64.b64decode(encoded, validate=True)))
        existing_names.add(_path_key(name))
    return files


def rebase_zip_file(input_path: Path, output_path: Path, secrets_path: Path) -> RebaseReport:
    """Overlay a local vault onto an AI-provided ZIP while retaining other entries."""
    from zip_a_markdown import decode_text

    if input_path.resolve() == output_path.resolve():
        raise ValueError("el ZIP de salida debe ser distinto del ZIP de entrada")
    payload = load_secrets(secrets_path)
    with zipfile.ZipFile(input_path, "r") as source:
        infos = source.infolist()
        contents = [source.read(info) if not info.is_dir() else b"" for info in infos]

    text_slots: list[int] = []
    text_files: list[tuple[str, str]] = []
    for index, (info, raw) in enumerate(zip(infos, contents)):
        if info.is_dir():
            continue
        text = decode_text(raw)
        if text is not None:
            text_slots.append(index)
            text_files.append((info.filename, text))

    rebased_files, report = rebase_text_files(text_files, payload)
    for index, (name, content) in zip(text_slots, rebased_files):
        original = decode_text(contents[index])
        if original != content:
            contents[index] = content.encode("utf-8")
    existing_names = {_path_key(info.filename) for info in infos if not info.is_dir()}
    sensitive = restore_sensitive_files(payload, existing_names)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_name(output_path.name + ".tmp")
    try:
        with zipfile.ZipFile(temporary, "w") as destination:
            for info, raw in zip(infos, contents):
                destination.writestr(info, raw)
            for name, raw in sensitive:
                destination.writestr(name, raw)
        temporary.replace(output_path)
    finally:
        if temporary.exists():
            temporary.unlink()
    return RebaseReport(report.values_applied, report.values_unmatched, len(sensitive))


def rebase_markdown_file(
    markdown_path: Path,
    output_path: Path,
    secrets_path: Path,
) -> RebaseReport:
    """Reconstruct a ZIP from AI Markdown and overlay the local secret vault."""
    import markdown_a_zip

    if markdown_path.resolve() == output_path.resolve():
        raise ValueError("el ZIP de salida no puede sobrescribir el Markdown")
    payload = load_secrets(secrets_path)
    files = markdown_a_zip.parse_markdown(markdown_path)
    rebased, report = rebase_text_files(files, payload)
    for name, _ in rebased:
        markdown_a_zip.validate_archive_name(name)
    existing = {_path_key(name) for name, _ in rebased}
    sensitive = restore_sensitive_files(payload, existing)

    # Restore original bytes for untouched secret-bearing files. If the AI has
    # changed surrounding code, retain its version and encode the merged text.
    redacted_backups = payload.get("redacted_files", [])
    backups_by_name: dict[str, list[dict[str, Any]]] = {}
    for item in redacted_backups if isinstance(redacted_backups, list) else []:
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            backups_by_name.setdefault(_path_key(item["name"]), []).append(item)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in rebased:
            raw = content.encode("utf-8")
            candidates = backups_by_name.get(_path_key(name), [])
            if candidates:
                backup = candidates.pop(0)
                original_text = backup.get("text")
                original_bytes = backup.get("bytes")
                if isinstance(original_text, str) and isinstance(original_bytes, str):
                    normalize = lambda text: text.replace("\r\n", "\n").replace("\r", "\n")
                    if normalize(content) == normalize(original_text) or name.casefold().endswith(".pdf"):
                        raw = base64.b64decode(original_bytes, validate=True)
            archive.writestr(name, raw)
        for name, raw in sensitive:
            archive.writestr(name, raw)
    return RebaseReport(report.values_applied, report.values_unmatched, len(sensitive))
