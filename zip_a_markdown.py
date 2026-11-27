#!/usr/bin/env python3
"""Export a folder or ZIP to AI-friendly Markdown with local reversible protection."""
from __future__ import annotations

import argparse
import base64
import os
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from archive_safety import (
    DEFAULT_LIMITS,
    ArchiveSecurityError,
    SecurityLimits,
    canonical_archive_key,
    read_zip_entry,
    validate_archive_name,
    validate_project_file,
    validate_zip_infos,
)
from atomic_utils import atomic_write_text
from filename_recovery import recover_names_from_includes
from gitignore_support import GitIgnoreMatcher
from local_secrets import (
    VaultBackend, VaultUnavailableError, payload_requires_vault, save_secrets, secrets_path_for,
)
from pdf_extractor import extract_pdf_text
from path_safety import ensure_distinct_paths, require_suffix
from secret_filter import FilterReport, is_generated_or_dependency_path, is_sensitive_path, redact_secret_values

LANGUAGES = {
    ".c": "c", ".cc": "cpp", ".cpp": "cpp", ".cs": "csharp", ".css": "css", ".csv": "csv",
    ".dart": "dart", ".go": "go", ".h": "c", ".hpp": "cpp", ".html": "html", ".ini": "ini",
    ".java": "java", ".js": "javascript", ".json": "json", ".jsx": "jsx", ".kt": "kotlin",
    ".lua": "lua", ".md": "markdown", ".pdf": "text", ".php": "php", ".py": "python",
    ".rb": "ruby", ".rs": "rust", ".scss": "scss", ".sh": "bash", ".sql": "sql",
    ".swift": "swift", ".toml": "toml", ".ts": "typescript", ".tsx": "tsx", ".txt": "text",
    ".xml": "xml", ".yaml": "yaml", ".yml": "yaml",
}


@dataclass
class ProtectionStats:
    sensitive_files_skipped: int = 0
    generated_files_skipped: int = 0
    values_redacted: int = 0
    binary_files_preserved: int = 0
    gitignored_files_skipped: int = 0
    filtering: FilterReport = field(default_factory=FilterReport)
    warnings: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ConversionReport:
    included: int
    skipped_binary: int
    sensitive_files_skipped: int
    generated_files_skipped: int
    values_redacted: int
    secrets_file: Path | None
    binary_files_preserved: int = 0
    high_confidence_detections: int = 0
    contextual_detections: int = 0
    files_affected: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    gitignored_files_skipped: int = 0


@dataclass
class SecretCapture:
    redactions: dict[str, str]
    bindings: list[dict[str, str]]
    redacted_files: list[dict[str, str]]
    sensitive_files: list[dict[str, str]]
    binary_files: list[dict[str, str]]

    @classmethod
    def create(cls) -> "SecretCapture":
        return cls({}, [], [], [], [])

    def payload(self) -> dict[str, Any]:
        return {
            "version": 1,
            "redactions": self.redactions,
            "bindings": self.bindings,
            "redacted_files": self.redacted_files,
            "sensitive_files": self.sensitive_files,
            "binary_files": self.binary_files,
        }


def decode_text(data: bytes) -> str | None:
    if b"\x00" in data and not data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return None
    for encoding in ("utf-8-sig", "utf-16"):
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, UnicodeError):
            pass
    try:
        text = data.decode("cp1252")
    except UnicodeDecodeError:
        return None
    return None if any(ord(char) < 32 and char not in "\t\n\r\f" for char in text) else text


def safe_label(name: str) -> str:
    return name.replace("\r", " ").replace("\n", " ").replace("`", "\\`")


def fence_for(content: str) -> str:
    longest = current = 0
    for char in content:
        current = current + 1 if char == "`" else 0
        longest = max(longest, current)
    return "`" * max(3, longest + 1)


def _encoded_file(name: str, raw: bytes) -> dict[str, str]:
    return {"name": name, "bytes": base64.b64encode(raw).decode("ascii")}


def capture_sensitive_bindings(raw: bytes, name: str, capture: SecretCapture, report: FilterReport) -> None:
    text = decode_text(raw)
    if text is not None:
        redact_secret_values(
            text, secret_values=capture.redactions, secret_bindings=capture.bindings,
            source_path=name, report=report,
        )


def _process_file(
    name: str,
    raw: bytes,
    *,
    protection: ProtectionStats,
    capture: SecretCapture,
    limits: SecurityLimits,
) -> tuple[str, str] | None:
    validate_archive_name(name, limits=limits)
    if is_generated_or_dependency_path(name):
        protection.generated_files_skipped += 1
        return None
    if is_sensitive_path(name):
        capture_sensitive_bindings(raw, name, capture, protection.filtering)
        capture.sensitive_files.append(_encoded_file(name, raw))
        protection.sensitive_files_skipped += 1
        return None
    if name.casefold().endswith(".pdf"):
        text = extract_pdf_text(raw, limits=limits)
        if text is None:
            capture.binary_files.append(_encoded_file(name, raw))
            protection.binary_files_preserved += 1
            return None
        original = text
        text, count = redact_secret_values(
            text, secret_values=capture.redactions, secret_bindings=capture.bindings,
            source_path=name, report=protection.filtering,
        )
        capture.redacted_files.append({"name": name, "text": original, "bytes": base64.b64encode(raw).decode("ascii")})
        protection.values_redacted += count
        return name, text
    text = decode_text(raw)
    if text is None:
        capture.binary_files.append(_encoded_file(name, raw))
        protection.binary_files_preserved += 1
        return None
    original = text
    text, count = redact_secret_values(
        text, secret_values=capture.redactions, secret_bindings=capture.bindings,
        source_path=name, report=protection.filtering,
    )
    if count or raw != original.encode("utf-8"):
        capture.redacted_files.append({"name": name, "text": original, "bytes": base64.b64encode(raw).decode("ascii")})
    protection.values_redacted += count
    return name, text


def read_zip_text_files(
    zip_path: Path,
    *,
    protection_stats: ProtectionStats | None = None,
    secret_capture: SecretCapture | None = None,
    limits: SecurityLimits = DEFAULT_LIMITS,
) -> tuple[list[tuple[str, str]], int]:
    protection = protection_stats or ProtectionStats()
    capture = secret_capture or SecretCapture.create()
    files: list[tuple[str, str]] = []
    with zipfile.ZipFile(zip_path) as archive:
        infos = archive.infolist()
        validate_zip_infos(infos, limits=limits)
        total = [0]
        entries = sorted((info for info in infos if not info.is_dir()), key=lambda item: (item.filename.casefold(), item.filename))
        for info in entries:
            raw = read_zip_entry(archive, info, limits=limits, total_processed=total)
            processed = _process_file(info.filename, raw, protection=protection, capture=capture, limits=limits)
            if processed is not None:
                files.append(processed)
    return recover_names_from_includes(files), protection.binary_files_preserved


def _folder_entries(
    root: Path,
    *,
    exclude_paths: set[Path],
    protection: ProtectionStats,
    respect_gitignore: bool,
    verbose: bool,
    limits: SecurityLimits,
) -> Iterable[tuple[str, Path]]:
    excluded = {os.path.normcase(os.path.abspath(str(path))) for path in exclude_paths}
    matcher = GitIgnoreMatcher(root) if respect_gitignore else None
    entries: list[tuple[str, Path]] = []
    for current, directories, filenames in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        kept: list[str] = []
        for directory in sorted(directories):
            path = current_path / directory
            if path.is_symlink():
                raise ArchiveSecurityError(f"symbolic links are not supported: {path}")
            relative = path.relative_to(root).as_posix() + "/"
            if is_generated_or_dependency_path(relative):
                continue
            match = matcher.match(relative) if matcher else None
            if match and match.ignored:
                if verbose:
                    protection.warnings.append(f"Excluded by .gitignore rule {match.rule!r}: {relative}")
                continue
            kept.append(directory)
        directories[:] = kept
        for filename in filenames:
            path = current_path / filename
            if os.path.normcase(os.path.abspath(str(path))) in excluded:
                continue
            relative = validate_project_file(path, root, limits=limits)
            match = matcher.match(relative) if matcher else None
            if match and match.ignored:
                protection.gitignored_files_skipped += 1
                if verbose:
                    protection.warnings.append(f"Excluded by .gitignore rule {match.rule!r}: {relative}")
                continue
            entries.append((relative, path))
    if len(entries) > limits.max_entries:
        raise ArchiveSecurityError(f"project has {len(entries)} files; limit is {limits.max_entries}")
    seen: set[str] = set()
    for relative, _ in entries:
        key = canonical_archive_key(relative)
        if key in seen:
            raise ArchiveSecurityError(f"canonical path collision in project: {relative!r}")
        seen.add(key)
    yield from sorted(entries, key=lambda item: (canonical_archive_key(item[0]), item[0]))


def read_folder_text_files(
    folder_path: Path,
    *,
    exclude_paths: set[Path] | None = None,
    protection_stats: ProtectionStats | None = None,
    secret_capture: SecretCapture | None = None,
    limits: SecurityLimits = DEFAULT_LIMITS,
    respect_gitignore: bool = False,
    verbose: bool = False,
) -> tuple[list[tuple[str, str]], int]:
    root = folder_path.resolve()
    protection = protection_stats or ProtectionStats()
    capture = secret_capture or SecretCapture.create()
    files: list[tuple[str, str]] = []
    total = 0
    for name, path in _folder_entries(
        root, exclude_paths=set(exclude_paths or ()), protection=protection,
        respect_gitignore=respect_gitignore, verbose=verbose, limits=limits,
    ):
        raw = path.read_bytes()
        total += len(raw)
        if total > limits.max_total_size:
            raise ArchiveSecurityError("project exceeds the total size limit")
        processed = _process_file(name, raw, protection=protection, capture=capture, limits=limits)
        if processed is not None:
            files.append(processed)
    return recover_names_from_includes(files), protection.binary_files_preserved


def convert(
    zip_path: Path,
    output_path: Path,
    *,
    vault_backend: VaultBackend | None = None,
    no_vault: bool = False,
    limits: SecurityLimits = DEFAULT_LIMITS,
    strict_secrets: bool = False,
) -> ConversionReport:
    require_suffix(zip_path, ".zip", "input")
    require_suffix(output_path, ".md", "export output")
    ensure_distinct_paths(input=zip_path, output=output_path, vault=secrets_path_for(output_path))
    protection, capture = ProtectionStats(), SecretCapture.create()
    files, skipped_binary = read_zip_text_files(
        zip_path, protection_stats=protection, secret_capture=capture, limits=limits,
    )
    return write_markdown(
        zip_path.name, files, skipped_binary, output_path, protection_stats=protection,
        secret_capture=capture, vault_backend=vault_backend, no_vault=no_vault,
        strict_secrets=strict_secrets,
    )


def convert_folder_to_markdown(
    folder_path: Path,
    output_path: Path,
    *,
    exclude_paths: set[Path] | None = None,
    vault_backend: VaultBackend | None = None,
    no_vault: bool = False,
    limits: SecurityLimits = DEFAULT_LIMITS,
    respect_gitignore: bool = False,
    verbose: bool = False,
    strict_secrets: bool = False,
) -> ConversionReport:
    if not folder_path.is_dir():
        raise NotADirectoryError(f"folder does not exist: {folder_path}")
    require_suffix(output_path, ".md", "export output")
    ensure_distinct_paths(input=folder_path, output=output_path, vault=secrets_path_for(output_path))
    protection, capture = ProtectionStats(), SecretCapture.create()
    excluded = set(exclude_paths or ()) | {output_path, secrets_path_for(output_path)}
    files, skipped_binary = read_folder_text_files(
        folder_path, exclude_paths=excluded, protection_stats=protection, secret_capture=capture,
        limits=limits, respect_gitignore=respect_gitignore, verbose=verbose,
    )
    return write_markdown(
        folder_path.name, files, skipped_binary, output_path, protection_stats=protection,
        secret_capture=capture, vault_backend=vault_backend, no_vault=no_vault,
        strict_secrets=strict_secrets,
    )


def _markdown_document(title: str, files: list[tuple[str, str]], skipped_binary: int, protection: ProtectionStats) -> str:
    lines = [
        f"# Contents of `{safe_label(title)}`", "",
        f"Text files included: **{len(files)}** · binary files protected: **{skipped_binary}** · "
        f"sensitive files protected: **{protection.sensitive_files_skipped}** · "
        f"dependency/generated files excluded: **{protection.generated_files_skipped}** · "
        f"potential secret values redacted: **{protection.values_redacted}**.", "",
        "## Protection report", "",
        f"- Total detections: **{protection.filtering.total_detections}**",
        f"- High confidence: **{protection.filtering.high_confidence}**",
        f"- Contextual confidence: **{protection.filtering.contextual}**",
        f"- Files affected: **{len(protection.filtering.files_affected)}**", "",
    ]
    if files:
        lines.extend(["## Index", ""])
        lines.extend(f"- [File {index}](#file-{index:04d}) — `{safe_label(name)}`" for index, (name, _) in enumerate(files, 1))
        lines.append("")
    for index, (name, content) in enumerate(files, 1):
        extension = Path(name).suffix.lower()
        fence = fence_for(content)
        lines.extend([f'<a id="file-{index:04d}"></a>', "", f"## `{safe_label(name)}`", "", f"{fence}{LANGUAGES.get(extension, 'text')}", content, fence, ""])
    return "\n".join(lines)


def write_markdown(
    title: str,
    files: list[tuple[str, str]],
    skipped_binary: int,
    output_path: Path,
    *,
    protection_stats: ProtectionStats | None = None,
    secret_capture: SecretCapture | None = None,
    vault_backend: VaultBackend | None = None,
    no_vault: bool = False,
    strict_secrets: bool = False,
) -> ConversionReport:
    protection = protection_stats or ProtectionStats()
    capture = secret_capture or SecretCapture.create()
    payload = capture.payload()
    sidecar = secrets_path_for(output_path)
    require_suffix(output_path, ".md", "export output")
    ensure_distinct_paths(output=output_path, vault=sidecar)
    requires_vault = payload_requires_vault(payload)
    if no_vault and requires_vault:
        raise VaultUnavailableError(
            "--no-vault cannot export this project because it requires protected recovery data for secrets, PDFs, sensitive files, or binaries"
        )
    document = _markdown_document(title, files, skipped_binary, protection)
    if strict_secrets:
        if protection.filtering.warnings:
            raise ValueError(
                "strict secret mode rejected ambiguous credential-like assignments; review the source"
            )
        from secret_scanner import scan_markdown_with_gitleaks
        scan_markdown_with_gitleaks(document)
    selected_sidecar: Path | None = None
    if requires_vault:
        save_secrets(sidecar, payload, backend=vault_backend)
        selected_sidecar = sidecar
    elif sidecar.exists():
        sidecar.unlink()
    atomic_write_text(output_path, document)
    warnings = tuple(protection.filtering.warnings + protection.warnings)
    return ConversionReport(
        len(files), skipped_binary, protection.sensitive_files_skipped,
        protection.generated_files_skipped, protection.values_redacted, selected_sidecar,
        protection.binary_files_preserved, protection.filtering.high_confidence,
        protection.filtering.contextual, tuple(sorted(protection.filtering.files_affected)),
        warnings, protection.gitignored_files_skipped,
    )


def _limits_from_args(args: argparse.Namespace) -> SecurityLimits:
    return SecurityLimits(
        max_entries=args.max_entries,
        max_file_size=args.max_file_mb * 1024 * 1024,
        max_total_size=args.max_total_mb * 1024 * 1024,
        max_markdown_size=args.max_markdown_mb * 1024 * 1024,
        max_pdf_pages=args.max_pdf_pages,
        max_compression_ratio=args.max_compression_ratio,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Export a project folder or ZIP to AI-friendly Markdown.")
    parser.add_argument("input", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--no-vault", action="store_true", help="Allow only exports that require no protected recovery data")
    parser.add_argument("--respect-gitignore", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--max-entries", type=int, default=DEFAULT_LIMITS.max_entries)
    parser.add_argument("--max-file-mb", type=int, default=100)
    parser.add_argument("--max-total-mb", type=int, default=1024)
    parser.add_argument("--max-markdown-mb", type=int, default=1024)
    parser.add_argument("--max-pdf-pages", type=int, default=DEFAULT_LIMITS.max_pdf_pages)
    parser.add_argument("--max-compression-ratio", type=float, default=DEFAULT_LIMITS.max_compression_ratio)
    parser.add_argument(
        "--strict-secrets", action="store_true",
        help="Stop on ambiguous findings and require a clean Gitleaks content scan",
    )
    args = parser.parse_args()
    source = args.input
    if not source.exists() or not (source.is_file() or source.is_dir()):
        parser.error(f"input does not exist: {source}")
    if source.is_file() and source.suffix.casefold() != ".zip":
        parser.error("input file must be a ZIP")
    output = args.output or (source.with_name(source.name + ".md") if source.is_dir() else source.with_suffix(".md"))
    if output.resolve() == source.resolve():
        parser.error("output cannot overwrite the input")
    try:
        limits = _limits_from_args(args)
        report = (
            convert_folder_to_markdown(
                source, output, no_vault=args.no_vault, limits=limits,
                respect_gitignore=args.respect_gitignore, verbose=args.verbose,
                strict_secrets=args.strict_secrets,
            )
            if source.is_dir() else convert(
                source, output, no_vault=args.no_vault, limits=limits,
                strict_secrets=args.strict_secrets,
            )
        )
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as error:
        parser.error(f"export failed: {error}")
    vault = str(report.secrets_file) if report.secrets_file else "not required"
    print(f"Created: {output} ({report.included} text files; {report.values_redacted} values redacted; vault: {vault})")
    for warning in report.warnings if args.verbose else ():
        print(f"Warning: {warning}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
