#!/usr/bin/env python3
"""Apply a ZIPMarkdown vault conservatively to AI-edited Markdown or ZIP."""
from __future__ import annotations

import argparse
import zipfile
from pathlib import Path

from archive_safety import DEFAULT_LIMITS, SecurityLimits
from local_secrets import secrets_path_for
from path_safety import ensure_distinct_paths, require_suffix
from secrets_rebase import RebaseReport, rebase_markdown_file, rebase_zip_file


def run_rebase(source: Path, vault: Path, output: Path | None = None, *, limits: SecurityLimits = DEFAULT_LIMITS) -> tuple[RebaseReport, Path]:
    if not source.is_file():
        raise FileNotFoundError(f"input does not exist: {source}")
    if not vault.is_file():
        raise FileNotFoundError(f"vault does not exist: {vault}")
    suffix = source.suffix.casefold()
    if suffix not in {".md", ".zip"}:
        raise ValueError("input must be a .md or .zip file")
    destination = output or source.with_name(source.stem + "_rebased.zip")
    require_suffix(destination, ".zip", "rebase output")
    require_suffix(vault, ".secrets", "vault")
    ensure_distinct_paths(input=source, output=destination, vault=vault)
    report = (
        rebase_markdown_file(source, destination, vault, limits=limits)
        if suffix == ".md" else rebase_zip_file(source, destination, vault, limits=limits)
    )
    return report, destination


def main() -> int:
    parser = argparse.ArgumentParser(description="Conservatively apply a local ZIPMarkdown vault.")
    parser.add_argument("input", type=Path)
    parser.add_argument("--secrets", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()
    vault = args.secrets or secrets_path_for(args.input)
    try:
        report, output = run_rebase(args.input, vault, args.output)
    except (OSError, UnicodeError, ValueError, RuntimeError, zipfile.BadZipFile) as error:
        parser.error(f"rebase failed: {error}")
    print(
        f"Created: {output} · secrets restored: {report.values_applied} · "
        f"unmatched: {report.values_unmatched} · protected files added: {report.protected_files_added}."
    )
    for warning in report.warnings:
        print(f"Warning: {warning}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
