"""Installed command-line interface for ZIPMarkdown."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import markdown_a_zip
import zip_a_markdown
from archive_safety import DEFAULT_LIMITS, SecurityLimits
from rebase_secrets import run_rebase

__version__ = "0.1.0b1"


def _limits(args: argparse.Namespace) -> SecurityLimits:
    return SecurityLimits(
        max_entries=args.max_entries,
        max_file_size=args.max_file_mb * 1024 * 1024,
        max_total_size=args.max_total_mb * 1024 * 1024,
        max_markdown_size=args.max_markdown_mb * 1024 * 1024,
        max_pdf_pages=args.max_pdf_pages,
        max_compression_ratio=args.max_compression_ratio,
    )


def _add_limits(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--max-entries", type=int, default=DEFAULT_LIMITS.max_entries)
    parser.add_argument("--max-file-mb", type=int, default=100)
    parser.add_argument("--max-total-mb", type=int, default=1024)
    parser.add_argument("--max-markdown-mb", type=int, default=1024)
    parser.add_argument("--max-pdf-pages", type=int, default=DEFAULT_LIMITS.max_pdf_pages)
    parser.add_argument("--max-compression-ratio", type=float, default=DEFAULT_LIMITS.max_compression_ratio)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="zipmarkdown", description="Secure project ↔ AI-friendly Markdown round trips.")
    parser.add_argument("--version", action="version", version=f"ZIPMarkdown {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    export = commands.add_parser("export", help="Export a project folder or ZIP to Markdown")
    export.add_argument("source", type=Path)
    export.add_argument("-o", "--output", type=Path)
    export.add_argument("--no-vault", action="store_true")
    export.add_argument("--respect-gitignore", action="store_true")
    export.add_argument("--verbose", action="store_true")
    export.add_argument(
        "--strict-secrets", action="store_true",
        help="Stop on ambiguous findings and require a clean Gitleaks scan of the generated Markdown",
    )
    _add_limits(export)

    rebuild = commands.add_parser("import", help="Rebuild a ZIP or project folder from Markdown")
    rebuild.add_argument("markdown", type=Path)
    rebuild.add_argument("-o", "--output", type=Path)
    rebuild.add_argument("--secrets", type=Path)
    rebuild.add_argument("--no-vault", action="store_true")
    rebuild.add_argument("--folder", action="store_true")
    _add_limits(rebuild)

    rebase = commands.add_parser("rebase", help="Apply a vault conservatively to AI-edited Markdown or ZIP")
    rebase.add_argument("source", type=Path)
    rebase.add_argument("--secrets", type=Path, required=True)
    rebase.add_argument("-o", "--output", type=Path)
    _add_limits(rebase)

    commands.add_parser("gui", help="Start the ZIPMarkdown tray application")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "export":
            if not args.source.exists():
                parser.error(f"source does not exist: {args.source}")
            output = args.output or (args.source.with_name(args.source.name + ".md") if args.source.is_dir() else args.source.with_suffix(".md"))
            report = (
                zip_a_markdown.convert_folder_to_markdown(
                    args.source, output, no_vault=args.no_vault, limits=_limits(args),
                    respect_gitignore=args.respect_gitignore, verbose=args.verbose,
                    strict_secrets=args.strict_secrets,
                )
                if args.source.is_dir() else
                zip_a_markdown.convert(
                    args.source, output, no_vault=args.no_vault, limits=_limits(args),
                    strict_secrets=args.strict_secrets,
                )
            )
            print(f"Created {output}; {report.included} text files; vault: {report.secrets_file or 'not required'}")
            for warning in report.warnings if args.verbose else ():
                print(f"Warning: {warning}", file=sys.stderr)
            return 0
        if args.command == "import":
            output = args.output or (args.markdown.with_name(args.markdown.stem + "_project") if args.folder else args.markdown.with_suffix(".zip"))
            function = markdown_a_zip.convert_to_folder if args.folder else markdown_a_zip.convert
            count = function(args.markdown, output, secrets_path=args.secrets, no_vault=args.no_vault, limits=_limits(args))
            print(f"Created {output}; {count} files")
            return 0
        if args.command == "rebase":
            report, output = run_rebase(args.source, args.secrets, args.output, limits=_limits(args))
            print(f"Created {output}; restored {report.values_applied}; unmatched {report.values_unmatched}; protected files added {report.protected_files_added}")
            return 0
        if args.command == "gui":
            from zip_markdown_app import main as gui_main
            gui_main()
            return 0
    except (OSError, ValueError, RuntimeError) as error:
        parser.error(str(error))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
