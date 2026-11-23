#!/usr/bin/env python3
"""Rebase a local MD Toolkit secrets vault onto an AI-provided Markdown or ZIP."""

from __future__ import annotations

import argparse
import zipfile
from pathlib import Path

from local_secrets import secrets_path_for
from secrets_rebase import rebase_markdown_file, rebase_zip_file


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Aplica de forma conservadora un vault local cifrado a un Markdown o ZIP "
            "entregado por una IA."
        )
    )
    parser.add_argument("input", type=Path, help="Markdown o ZIP nuevo de la IA")
    parser.add_argument(
        "--secrets",
        type=Path,
        help="Archivo .secrets local (por defecto, se busca junto a la entrada)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="ZIP de salida (por defecto, <nombre>_rebased.zip)",
    )
    args = parser.parse_args()

    source = args.input
    if not source.is_file():
        parser.error(f"no existe el archivo: {source}")
    suffix = source.suffix.casefold()
    if suffix not in {".md", ".zip"}:
        parser.error("la entrada debe ser un archivo .md o .zip")
    vault = args.secrets or secrets_path_for(source)
    if not vault.is_file():
        parser.error(f"no se encontró el vault local: {vault} (usa --secrets para seleccionarlo)")
    output = args.output or source.with_name(source.stem + "_rebased.zip")

    try:
        if suffix == ".md":
            report = rebase_markdown_file(source, output, vault)
        else:
            report = rebase_zip_file(source, output, vault)
    except (OSError, UnicodeError, ValueError, RuntimeError, zipfile.BadZipFile) as error:
        parser.error(f"no se pudo rebasar el vault: {error}")

    print(
        f"Creado: {output} · secretos aplicados: {report.values_applied} · "
        f"sin coincidencia segura: {report.values_unmatched} · "
        f"archivos sensibles recuperados: {report.sensitive_files_added}."
    )
    if report.values_unmatched:
        print("Aviso: no se modificaron valores ambiguos; la conversión se completó igualmente.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
