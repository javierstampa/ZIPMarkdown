#!/usr/bin/env python3
"""Convierte los archivos de texto de un ZIP en un único documento Markdown."""

from __future__ import annotations

import argparse
import base64
import os
import zipfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from filename_recovery import recover_names_from_includes
from local_secrets import save_secrets, secrets_path_for
from pdf_extractor import extract_pdf_text
from secret_filter import (
    is_generated_or_dependency_path,
    is_sensitive_path,
    redact_secret_values,
)


LANGUAGES = {
    ".c": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cs": "csharp",
    ".css": "css",
    ".csv": "csv",
    ".dart": "dart",
    ".go": "go",
    ".h": "c",
    ".hpp": "cpp",
    ".html": "html",
    ".ini": "ini",
    ".java": "java",
    ".js": "javascript",
    ".json": "json",
    ".jsx": "jsx",
    ".kt": "kotlin",
    ".lua": "lua",
    ".md": "markdown",
    ".pdf": "text",
    ".php": "php",
    ".py": "python",
    ".rb": "ruby",
    ".rs": "rust",
    ".scss": "scss",
    ".sh": "bash",
    ".sql": "sql",
    ".swift": "swift",
    ".toml": "toml",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".txt": "text",
    ".xml": "xml",
    ".yaml": "yaml",
    ".yml": "yaml",
}


@dataclass
class ProtectionStats:
    sensitive_files_skipped: int = 0
    generated_files_skipped: int = 0
    values_redacted: int = 0


@dataclass(frozen=True)
class ConversionReport:
    included: int
    skipped_binary: int
    sensitive_files_skipped: int
    generated_files_skipped: int
    values_redacted: int
    secrets_file: Path


@dataclass
class SecretCapture:
    redactions: dict[str, str]
    bindings: list[dict[str, str]]
    redacted_files: list[dict[str, str]]
    sensitive_files: list[dict[str, str]]

    @classmethod
    def create(cls) -> SecretCapture:
        return cls({}, [], [], [])

    def payload(self) -> dict[str, Any]:
        return {
            "version": 1,
            "redactions": self.redactions,
            "bindings": self.bindings,
            "redacted_files": self.redacted_files,
            "sensitive_files": self.sensitive_files,
        }


def capture_sensitive_bindings(raw: bytes, name: str, capture: SecretCapture) -> None:
    """Index recognizable assignments inside an omitted sensitive text file."""
    text = decode_text(raw)
    if text is not None:
        redact_secret_values(
            text,
            secret_values=capture.redactions,
            secret_bindings=capture.bindings,
            source_path=name,
        )


def decode_text(data: bytes) -> str | None:
    """Decode common text encodings; return None for data that looks binary."""
    if b"\x00" in data and not data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return None

    encodings = ("utf-8-sig", "utf-16")
    for encoding in encodings:
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, UnicodeError):
            continue

    try:
        text = data.decode("cp1252")
    except UnicodeDecodeError:
        return None
    if any(ord(char) < 32 and char not in "\t\n\r\f" for char in text):
        return None
    return text


def safe_label(name: str) -> str:
    """Keep archive paths on one Markdown heading line."""
    return name.replace("\r", " ").replace("\n", " ").replace("`", "\\`")


def fence_for(content: str) -> str:
    # Count every run, including runs at the start/end of a line.
    longest = 0
    current = 0
    for char in content:
        current = current + 1 if char == "`" else 0
        longest = max(longest, current)
    return "`" * max(3, longest + 1)


def convert(zip_path: Path, output_path: Path) -> ConversionReport:
    protection = ProtectionStats()
    secrets = SecretCapture.create()
    files, skipped_binary = read_zip_text_files(
        zip_path, protection_stats=protection, secret_capture=secrets
    )
    return write_markdown(
        zip_path.name,
        files,
        skipped_binary,
        output_path,
        protection_stats=protection,
        secret_capture=secrets,
    )


def read_zip_text_files(
    zip_path: Path,
    *,
    protection_stats: ProtectionStats | None = None,
    secret_capture: SecretCapture | None = None,
) -> tuple[list[tuple[str, str]], int]:
    files: list[tuple[str, str]] = []
    skipped_binary = 0
    duplicates: Counter[str] = Counter()

    with zipfile.ZipFile(zip_path) as archive:
        entries = sorted(
            (item for item in archive.infolist() if not item.is_dir()),
            key=lambda item: (item.filename.casefold(), item.filename),
        )
        for item in entries:
            if is_generated_or_dependency_path(item.filename):
                if protection_stats is not None:
                    protection_stats.generated_files_skipped += 1
                continue
            if is_sensitive_path(item.filename):
                if secret_capture is not None:
                    raw = archive.read(item)
                    capture_sensitive_bindings(raw, item.filename, secret_capture)
                    secret_capture.sensitive_files.append(
                        {
                            "name": item.filename,
                            "bytes": base64.b64encode(raw).decode("ascii"),
                        }
                    )
                if protection_stats is not None:
                    protection_stats.sensitive_files_skipped += 1
                continue
            raw = archive.read(item)
            if item.filename.casefold().endswith(".pdf"):
                pdf_text = extract_pdf_text(raw)
                if pdf_text is not None:
                    before_redaction = pdf_text
                    text, redacted = redact_secret_values(
                        pdf_text,
                        secret_values=secret_capture.redactions if secret_capture is not None else None,
                        secret_bindings=secret_capture.bindings if secret_capture is not None else None,
                        source_path=item.filename,
                    )
                    if secret_capture is not None:
                        secret_capture.redacted_files.append(
                            {
                                "name": item.filename,
                                "text": before_redaction,
                                "bytes": base64.b64encode(raw).decode("ascii"),
                            }
                        )
                    if protection_stats is not None:
                        protection_stats.values_redacted += redacted
                    duplicates[item.filename] += 1
                    label = item.filename
                    if duplicates[item.filename] > 1:
                        label += f" (entrada repetida #{duplicates[item.filename]})"
                    files.append((label, text))
                    continue
                else:
                    skipped_binary += 1
                    continue

            text = decode_text(raw)
            if text is None:
                skipped_binary += 1
                continue
            before_redaction = text
            text, redacted = redact_secret_values(
                text,
                secret_values=secret_capture.redactions if secret_capture is not None else None,
                secret_bindings=secret_capture.bindings if secret_capture is not None else None,
                source_path=item.filename,
            )
            if redacted and secret_capture is not None:
                secret_capture.redacted_files.append(
                    {
                        "name": item.filename,
                        "text": before_redaction,
                        "bytes": base64.b64encode(raw).decode("ascii"),
                    }
                )
            if protection_stats is not None:
                protection_stats.values_redacted += redacted
            duplicates[item.filename] += 1
            label = item.filename
            if duplicates[item.filename] > 1:
                label += f" (entrada repetida #{duplicates[item.filename]})"
            files.append((label, text))

    files = recover_names_from_includes(files)
    return files, skipped_binary


def read_folder_text_files(
    folder_path: Path,
    *,
    exclude_paths: set[Path] | None = None,
    protection_stats: ProtectionStats | None = None,
    secret_capture: SecretCapture | None = None,
) -> tuple[list[tuple[str, str]], int]:
    """Read text files under a folder, skipping Git metadata and selected outputs."""
    folder_path = folder_path.resolve()
    excluded = {
        os.path.normcase(os.path.abspath(str(path)))
        for path in (exclude_paths or set())
    }
    files: list[tuple[str, str]] = []
    skipped_binary = 0

    entries: list[Path] = []
    for current, directories, filenames in os.walk(folder_path, topdown=True, followlinks=False):
        directories[:] = sorted(
            name
            for name in directories
            if name.casefold() != ".git" and not (Path(current) / name).is_symlink()
        )
        entries.extend(Path(current) / name for name in filenames)
    entries.sort(key=lambda path: (path.as_posix().casefold(), path.as_posix()))
    for path in entries:
        if not path.is_file() or path.is_symlink():
            continue
        try:
            relative = path.relative_to(folder_path)
        except ValueError:
            continue
        if os.path.normcase(os.path.abspath(str(path))) in excluded:
            continue
        if is_generated_or_dependency_path(relative.as_posix()):
            if protection_stats is not None:
                protection_stats.generated_files_skipped += 1
            continue
        if is_sensitive_path(relative.as_posix()):
            if secret_capture is not None:
                try:
                    raw = path.read_bytes()
                except OSError:
                    skipped_binary += 1
                    continue
                capture_sensitive_bindings(raw, relative.as_posix(), secret_capture)
                secret_capture.sensitive_files.append(
                    {
                        "name": relative.as_posix(),
                        "bytes": base64.b64encode(raw).decode("ascii"),
                    }
                )
            if protection_stats is not None:
                protection_stats.sensitive_files_skipped += 1
            continue
        try:
            raw = path.read_bytes()
        except OSError:
            skipped_binary += 1
            continue

        if relative.as_posix().casefold().endswith(".pdf"):
            pdf_text = extract_pdf_text(raw)
            if pdf_text is not None:
                pdf_text = pdf_text.replace("\r\n", "\n").replace("\r", "\n")
                before_redaction = pdf_text
                text, redacted = redact_secret_values(
                    pdf_text,
                    secret_values=secret_capture.redactions if secret_capture is not None else None,
                    secret_bindings=secret_capture.bindings if secret_capture is not None else None,
                    source_path=relative.as_posix(),
                )
                if secret_capture is not None:
                    secret_capture.redacted_files.append(
                        {
                            "name": relative.as_posix(),
                            "text": before_redaction,
                            "bytes": base64.b64encode(raw).decode("ascii"),
                        }
                    )
                if protection_stats is not None:
                    protection_stats.values_redacted += redacted
                files.append((relative.as_posix(), text))
                continue
            else:
                skipped_binary += 1
                continue

        text = decode_text(raw)
        if text is None:
            skipped_binary += 1
            continue
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        before_redaction = text
        text, redacted = redact_secret_values(
            text,
            secret_values=secret_capture.redactions if secret_capture is not None else None,
            secret_bindings=secret_capture.bindings if secret_capture is not None else None,
            source_path=relative.as_posix(),
        )
        if redacted and secret_capture is not None:
            secret_capture.redacted_files.append(
                {
                    "name": relative.as_posix(),
                    "text": before_redaction,
                    "bytes": base64.b64encode(raw).decode("ascii"),
                }
            )
        if protection_stats is not None:
            protection_stats.values_redacted += redacted
        files.append((relative.as_posix(), text))

    return recover_names_from_includes(files), skipped_binary


def convert_folder_to_markdown(
    folder_path: Path,
    output_path: Path,
    *,
    exclude_paths: set[Path] | None = None,
) -> ConversionReport:
    """Create a Markdown snapshot directly from a folder, excluding its .git metadata."""
    if not folder_path.is_dir():
        raise NotADirectoryError(f"no existe la carpeta: {folder_path}")
    protection = ProtectionStats()
    excluded = set(exclude_paths or set())
    # Do not ingest an older export when the destination is inside the source.
    excluded.add(output_path)
    excluded.add(secrets_path_for(output_path))
    secrets = SecretCapture.create()
    files, skipped_binary = read_folder_text_files(
        folder_path,
        exclude_paths=excluded,
        protection_stats=protection,
        secret_capture=secrets,
    )
    return write_markdown(
        folder_path.name,
        files,
        skipped_binary,
        output_path,
        protection_stats=protection,
        secret_capture=secrets,
    )


def write_markdown(
    title: str,
    files: list[tuple[str, str]],
    skipped_binary: int,
    output_path: Path,
    *,
    protection_stats: ProtectionStats | None = None,
    secret_capture: SecretCapture | None = None,
) -> ConversionReport:
    protection = protection_stats or ProtectionStats()
    lines = [
        f"# Contenido de `{safe_label(title)}`",
        "",
        f"Archivos de texto incluidos: **{len(files)}** · "
        f"archivos binarios omitidos: **{skipped_binary}** · "
        f"archivos sensibles omitidos: **{protection.sensitive_files_skipped}** · "
        f"archivos de dependencias/artefactos omitidos: **{protection.generated_files_skipped}** · "
        f"valores potencialmente secretos redactados: **{protection.values_redacted}**.",
        "",
    ]

    if files:
        lines.extend(["## Índice", ""])
        for index, (name, _) in enumerate(files, start=1):
            lines.append(f"- [Archivo {index}](#archivo-{index:04d}) — `{safe_label(name)}`")
        lines.append("")

    for index, (name, content) in enumerate(files, start=1):
        extension = Path(name.split(" (entrada repetida #", 1)[0]).suffix.lower()
        language = LANGUAGES.get(extension, "text")
        fence = fence_for(content)
        lines.extend(
            [
                f'<a id="archivo-{index:04d}"></a>',
                "",
                f"## `{safe_label(name)}`",
                "",
                f"{fence}{language}",
                content,
                fence,
                "",
            ]
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    sidecar_path = secrets_path_for(output_path)
    if secret_capture is not None:
        # Commit the encrypted recovery data first so we never publish a Markdown
        # containing secret markers without its matching local vault.
        save_secrets(sidecar_path, secret_capture.payload())
    output_path.write_text("\n".join(lines), encoding="utf-8", newline="")
    return ConversionReport(
        len(files),
        skipped_binary,
        protection.sensitive_files_skipped,
        protection.generated_files_skipped,
        protection.values_redacted,
        sidecar_path,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Reúne los archivos de texto de un ZIP o carpeta en un único Markdown ordenado."
    )
    parser.add_argument("input", type=Path, help="Archivo ZIP o carpeta de entrada")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Markdown de salida (por defecto, junto al origen y con extensión .md)",
    )
    args = parser.parse_args()

    source = args.input
    if not source.exists() or not (source.is_file() or source.is_dir()):
        parser.error(f"no existe el archivo o carpeta: {source}")
    if source.is_file() and source.suffix.casefold() != ".zip":
        parser.error("el archivo de entrada debe ser un ZIP")
    default_output = (
        source.with_name(source.name + ".md") if source.is_dir() else source.with_suffix(".md")
    )
    output = args.output or default_output
    if output.resolve() == source.resolve():
        parser.error("el archivo de salida no puede sobrescribir el origen")

    try:
        if source.is_dir():
            report = convert_folder_to_markdown(source, output)
        else:
            report = convert(source, output)
    except (OSError, zipfile.BadZipFile, RuntimeError, NotADirectoryError) as error:
        parser.error(f"no se pudo convertir el origen: {error}")

    print(
        f"Creado: {output} ({report.included} archivos de texto; "
        f"{report.skipped_binary} binarios y {report.sensitive_files_skipped} archivos "
        f"sensibles omitidos; {report.generated_files_skipped} archivos de dependencias/artefactos "
        f"omitidos; {report.values_redacted} valores redactados). "
        f"Vault local cifrado: {report.secrets_file}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
