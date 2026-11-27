#!/usr/bin/env python3
"""Rebuild a ZIP or project directory from ZIPMarkdown Markdown."""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import tempfile
import zipfile
from pathlib import Path

from archive_safety import (
    DEFAULT_LIMITS,
    SecurityLimits,
    canonical_archive_key,
    validate_archive_name as _validate_archive_name,
    validate_zip_infos,
)
from atomic_utils import atomic_build
from filename_recovery import recover_names_from_includes
from local_secrets import VaultBackend, secrets_path_for
from path_safety import ensure_distinct_paths, require_suffix

DUPLICATE_RE = re.compile(r" \(entrada repetida #\d+\)$", re.I)
HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$")
FENCE_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
INLINE_CODE_RE = re.compile(r"(?<!\\)`([^`\n]+)(?<!\\)`")
FILE_LABEL_RE = re.compile(r"^\s{0,3}(?:[-*+]\s*)?(?:\*\*)?(?:archivo|file|ruta|path)(?:\*\*)?\s*(?:#\d+)?\s*[:：]\s*(.+?)\s*$", re.I)
MANIFEST_RE = re.compile(r"^<!-- ZIPMARKDOWN-MANIFEST (?P<payload>\{.*\}) -->$")
GENERIC_HEADINGS = {
    "índice", "indice", "index", "contenido", "contents", "archivos", "archivos incluidos",
    "files", "files included", "resumen", "summary", "instrucciones", "instructions",
    "ejemplo", "ejemplos", "example", "examples", "uso", "usage", "introducción",
    "introduccion", "introduction", "notas", "notes", "protection report",
}
COMMON_EXTENSIONLESS_NAMES = {"readme", "license", "licence", "dockerfile", "makefile", "gemfile", "procfile", "justfile", "authors", "changelog", "copying"}


def clean_name(value: str) -> str:
    value = value.strip().replace("\\`", "`")
    value = re.sub(r"^\*\*(.*?)\*\*$", r"\1", value).strip()
    value = value.strip(" `\t\r\n\"'")
    value = re.sub(r"\s+—\s*$|\s+-\s*$", "", value).strip()
    return DUPLICATE_RE.sub("", value).strip()


def looks_like_filename(name: str) -> bool:
    return "/" in name or bool(re.search(r"\.[A-Za-z0-9_-]{1,16}$", name)) or name.casefold() in COMMON_EXTENSIONLESS_NAMES


def name_from_heading(heading: str) -> str | None:
    code_names = [clean_name(match) for match in INLINE_CODE_RE.findall(heading)]
    code_names = [name for name in code_names if name]
    starts_with_code = heading.lstrip().startswith("`")
    if code_names and (starts_with_code or any(looks_like_filename(name) for name in code_names)):
        return code_names[0] if starts_with_code else code_names[-1]
    plain = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", heading)
    plain = re.sub(r"[*~]", "", plain).strip()
    explicit = re.match(r"^(?:archivo|file|ruta|path)(?:\s+#?\d+)?\s*[:：—–-]\s*(.+)$", plain, re.I)
    if explicit:
        return clean_name(explicit.group(1)) or None
    name = clean_name(plain)
    return name if name and name.casefold() not in GENERIC_HEADINGS and looks_like_filename(name) else None


def name_from_labels(lines: list[str]) -> str | None:
    for line in reversed(lines):
        match = FILE_LABEL_RE.fullmatch(line)
        if match:
            name = clean_name(match.group(1))
            if name:
                return name
    return None


def _limited_markdown_lines(markdown_path: Path, limits: SecurityLimits):
    size = markdown_path.stat().st_size
    if size > limits.max_markdown_size:
        raise ValueError(
            f"Markdown is {size} bytes; input limit is {limits.max_markdown_size} bytes"
        )
    total = 0
    with markdown_path.open("rb") as stream:
        while True:
            raw = stream.readline(limits.max_file_size + 2)
            if not raw:
                break
            total += len(raw)
            if total > limits.max_markdown_size:
                raise ValueError("Markdown changed or exceeded its configured input-size limit while reading")
            if len(raw) > limits.max_file_size + 1 and not raw.endswith(b"\n"):
                raise ValueError("Markdown contains a line larger than the per-file limit")
            try:
                decoded = raw.decode("utf-8")
                yield decoded[:-1] if decoded.endswith("\n") else decoded
            except UnicodeDecodeError as error:
                raise ValueError("Markdown must be valid UTF-8") from error


def _parse_manifest_line(line: str) -> dict[str, object] | None:
    match = MANIFEST_RE.fullmatch(line.rstrip("\r"))
    if match is None:
        return None
    try:
        manifest = json.loads(match.group("payload"))
    except json.JSONDecodeError as error:
        raise ValueError("ZIPMarkdown snapshot manifest is invalid JSON") from error
    if not isinstance(manifest, dict) or manifest.get("format") != 1:
        raise ValueError("unsupported ZIPMarkdown snapshot manifest")
    entries = manifest.get("entries")
    if not isinstance(entries, int) or isinstance(entries, bool) or entries < 0:
        raise ValueError("ZIPMarkdown snapshot manifest has an invalid entry count")
    export_id, digest = manifest.get("export_id"), manifest.get("markdown_sha256")
    if not isinstance(export_id, str) or re.fullmatch(r"[a-f0-9]{32}", export_id) is None:
        raise ValueError("ZIPMarkdown snapshot manifest has an invalid export ID")
    if not isinstance(digest, str) or re.fullmatch(r"[a-f0-9]{64}", digest) is None:
        raise ValueError("ZIPMarkdown snapshot manifest has an invalid document hash")
    return manifest


def read_snapshot_manifest(markdown_path: Path, *, limits: SecurityLimits = DEFAULT_LIMITS) -> dict[str, object] | None:
    """Read the single export manifest outside fenced content, if present."""
    manifest: dict[str, object] | None = None
    in_fence: re.Pattern[str] | None = None
    for line in _limited_markdown_lines(markdown_path, limits):
        logical = line[:-1] if line.endswith("\r") else line
        if in_fence is not None:
            if in_fence.fullmatch(logical):
                in_fence = None
            continue
        opening = FENCE_RE.fullmatch(logical)
        if opening is not None:
            fence = opening.group(1)
            in_fence = re.compile(rf"^ {{0,3}}{re.escape(fence[0])}{{{len(fence)},}}[ \t]*$")
            continue
        parsed = _parse_manifest_line(logical)
        if parsed is not None:
            if manifest is not None:
                raise ValueError("Markdown contains more than one ZIPMarkdown snapshot manifest")
            manifest = parsed
    return manifest


def parse_markdown(
    markdown_path: Path, *, limits: SecurityLimits = DEFAULT_LIMITS
) -> list[tuple[str, str]]:
    files: list[tuple[str, str]] = []
    current_name: str | None = None
    labels: list[str] = []
    closing_re: re.Pattern[str] | None = None
    block_name: str | None = None
    block_lines: list[str] = []
    block_bytes = total_bytes = 0
    manifest: dict[str, object] | None = None
    for line in _limited_markdown_lines(markdown_path, limits):
        logical_line = line[:-1] if line.endswith("\r") else line
        if closing_re is not None:
            if closing_re.fullmatch(logical_line):
                if block_name:
                    content = "\n".join(block_lines)
                    files.append((DUPLICATE_RE.sub("", block_name), content))
                    if len(files) > limits.max_entries:
                        raise ValueError(
                            f"Markdown has more than {limits.max_entries} file blocks"
                        )
                    total_bytes += len(content.encode("utf-8"))
                    if total_bytes > limits.max_total_size:
                        raise ValueError("Markdown output exceeds the configured total-size limit")
                current_name = block_name = None
                block_lines = []
                block_bytes = 0
                closing_re = None
                labels = []
                continue
            block_bytes += len(line.encode("utf-8")) + (1 if block_lines else 0)
            if block_bytes > limits.max_file_size:
                raise ValueError("Markdown file block exceeds the configured per-file limit")
            block_lines.append(line)
            continue

        heading = HEADING_RE.fullmatch(logical_line)
        if heading:
            current_name = name_from_heading(heading.group(1))
            labels.append(logical_line)
            labels = labels[-200:]
            continue
        opening = FENCE_RE.fullmatch(logical_line)
        if opening is None:
            parsed_manifest = _parse_manifest_line(logical_line)
            if parsed_manifest is not None:
                if manifest is not None:
                    raise ValueError("Markdown contains more than one ZIPMarkdown snapshot manifest")
                manifest = parsed_manifest
            labels.append(logical_line)
            labels = labels[-200:]
            continue
        fence = opening.group(1)
        closing_re = re.compile(rf"^ {{0,3}}{re.escape(fence[0])}{{{len(fence)},}}[ \t]*$")
        block_name = current_name or name_from_labels(labels)
        block_lines = []
        block_bytes = 0
    if closing_re is not None:
        name = block_name or "unnamed block"
        raise ValueError(f"truncated Markdown: unclosed fenced block for {name!r}")
    if manifest is not None and manifest["entries"] != len(files):
        raise ValueError(
            f"ZIPMarkdown snapshot manifest declares {manifest['entries']} entries but {len(files)} were parsed"
        )
    if not files and not (manifest is not None and manifest["entries"] == 0):
        raise ValueError("no named fenced file blocks were found")
    files = recover_names_from_includes(files)
    seen: set[str] = set()
    for name, _ in files:
        validate_archive_name(name)
        folded = canonical_archive_key(name)
        if folded in seen:
            raise ValueError(f"canonical path collision in Markdown: {name!r}")
        seen.add(folded)
    return files


def validate_archive_name(name: str) -> None:
    _validate_archive_name(name)


def _validate_output_zip(path: Path, limits: SecurityLimits) -> None:
    with zipfile.ZipFile(path) as archive:
        validate_zip_infos(archive.infolist(), limits=limits)
        broken = archive.testzip()
        if broken:
            raise zipfile.BadZipFile(f"generated ZIP failed validation at {broken!r}")


def convert(
    markdown_path: Path,
    output_path: Path,
    *,
    secrets_path: Path | None = None,
    vault_backend: VaultBackend | None = None,
    no_vault: bool = False,
    limits: SecurityLimits = DEFAULT_LIMITS,
) -> int:
    selected = secrets_path or secrets_path_for(markdown_path)
    require_suffix(markdown_path, ".md", "Markdown input")
    require_suffix(output_path, ".zip", "rebuild output")
    if secrets_path is not None:
        require_suffix(selected, ".secrets", "vault")
    ensure_distinct_paths(input=markdown_path, output=output_path, vault=selected)
    if not no_vault and selected.is_file():
        from secrets_rebase import rebase_markdown_file
        return rebase_markdown_file(
            markdown_path, output_path, selected, vault_backend=vault_backend, limits=limits
        ).files_generated
    files = parse_markdown(markdown_path, limits=limits)
    if len(files) > limits.max_entries:
        raise ValueError(f"Markdown has {len(files)} files; limit is {limits.max_entries}")
    total = sum(len(content.encode("utf-8")) for _, content in files)
    if total > limits.max_total_size:
        raise ValueError("Markdown output exceeds the configured total-size limit")

    def build(temporary: Path) -> None:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, content in files:
                raw = content.encode("utf-8")
                if len(raw) > limits.max_file_size:
                    raise ValueError(f"file exceeds the configured size limit: {name!r}")
                archive.writestr(name, raw)
    atomic_build(output_path, build, lambda path: _validate_output_zip(path, limits))
    return len(files)


def convert_to_folder(
    markdown_path: Path,
    output_directory: Path,
    *,
    secrets_path: Path | None = None,
    vault_backend: VaultBackend | None = None,
    no_vault: bool = False,
    limits: SecurityLimits = DEFAULT_LIMITS,
) -> int:
    require_suffix(markdown_path, ".md", "Markdown input")
    if output_directory.suffix.casefold() == ".secrets":
        raise ValueError("project directory cannot use the reserved .secrets suffix")
    selected = secrets_path or secrets_path_for(markdown_path)
    if secrets_path is not None:
        require_suffix(selected, ".secrets", "vault")
    ensure_distinct_paths(input=markdown_path, output=output_directory, vault=selected)
    if output_directory.exists():
        raise FileExistsError(f"destination directory already exists: {output_directory}")
    output_directory.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output_directory.parent, prefix=f".{output_directory.name}.") as work:
        work_path = Path(work)
        archive_path = work_path / "rebuilt.zip"
        count = convert(
            markdown_path, archive_path, secrets_path=secrets_path, vault_backend=vault_backend,
            no_vault=no_vault, limits=limits,
        )
        extracted = work_path / "project"
        extracted.mkdir()
        with zipfile.ZipFile(archive_path) as archive:
            infos = archive.infolist()
            validate_zip_infos(infos, limits=limits)
            for info in infos:
                if info.is_dir():
                    continue
                target = extracted / info.filename
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as source, target.open("wb") as destination:
                    shutil.copyfileobj(source, destination, length=1024 * 1024)
        os.replace(extracted, output_directory)
    return count


def main() -> int:
    parser = argparse.ArgumentParser(description="Rebuild a ZIP or project folder from ZIPMarkdown Markdown.")
    parser.add_argument("markdown", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--secrets", type=Path)
    parser.add_argument("--no-vault", action="store_true", help="Do not auto-apply an adjacent vault")
    parser.add_argument("--folder", action="store_true", help="Rebuild a project directory instead of a ZIP")
    args = parser.parse_args()
    if not args.markdown.is_file():
        parser.error(f"file does not exist: {args.markdown}")
    output = args.output or (args.markdown.with_name(args.markdown.stem + "_project") if args.folder else args.markdown.with_suffix(".zip"))
    try:
        count = (
            convert_to_folder(args.markdown, output, secrets_path=args.secrets, no_vault=args.no_vault)
            if args.folder else convert(args.markdown, output, secrets_path=args.secrets, no_vault=args.no_vault)
        )
    except (OSError, UnicodeError, ValueError, zipfile.BadZipFile) as error:
        parser.error(f"rebuild failed: {error}")
    print(f"Created: {output} ({count} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
