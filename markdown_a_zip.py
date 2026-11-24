#!/usr/bin/env python3
"""Rebuild a ZIP or project directory from ZIPMarkdown Markdown."""
from __future__ import annotations

import argparse
import os
import re
import shutil
import tempfile
import zipfile
from pathlib import Path

from archive_safety import DEFAULT_LIMITS, SecurityLimits, validate_archive_name as _validate_archive_name, validate_zip_infos
from atomic_utils import atomic_build
from filename_recovery import recover_names_from_includes
from local_secrets import VaultBackend, secrets_path_for

DUPLICATE_RE = re.compile(r" \(entrada repetida #\d+\)$", re.I)
HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$")
FENCE_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
INLINE_CODE_RE = re.compile(r"(?<!\\)`([^`\n]+)(?<!\\)`")
FILE_LABEL_RE = re.compile(r"^\s{0,3}(?:[-*+]\s*)?(?:\*\*)?(?:archivo|file|ruta|path)(?:\*\*)?\s*(?:#\d+)?\s*[:：]\s*(.+?)\s*$", re.I)
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


def parse_markdown(markdown_path: Path) -> list[tuple[str, str]]:
    with markdown_path.open("r", encoding="utf-8", newline="") as stream:
        lines = stream.read().split("\n")
    files: list[tuple[str, str]] = []
    current_name: str | None = None
    section_start = position = 0
    while position < len(lines):
        heading = HEADING_RE.fullmatch(lines[position])
        if heading:
            current_name = name_from_heading(heading.group(1))
            position += 1
            continue
        opening = FENCE_RE.fullmatch(lines[position])
        if opening is None:
            position += 1
            continue
        fence, closing = opening.group(1), position + 1
        closing_re = re.compile(rf"^ {{0,3}}{re.escape(fence[0])}{{{len(fence)},}}[ \t]*$")
        while closing < len(lines) and not closing_re.fullmatch(lines[closing]):
            closing += 1
        if closing == len(lines):
            position += 1
            continue
        content = "\n".join(lines[position + 1:closing])
        name = current_name or name_from_labels(lines[section_start:position])
        if name:
            files.append((DUPLICATE_RE.sub("", name), content))
        current_name = None
        section_start = position = closing + 1
    if not files:
        raise ValueError("no named fenced file blocks were found")
    files = recover_names_from_includes(files)
    seen: set[str] = set()
    for name, _ in files:
        validate_archive_name(name)
        folded = name.casefold()
        if folded in seen:
            raise ValueError(f"duplicate Markdown file path: {name!r}")
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
    if not no_vault and selected.is_file():
        from secrets_rebase import rebase_markdown_file
        return rebase_markdown_file(
            markdown_path, output_path, selected, vault_backend=vault_backend, limits=limits
        ).files_generated
    files = parse_markdown(markdown_path)
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
