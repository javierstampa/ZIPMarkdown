#!/usr/bin/env python3
"""Reconstruye un ZIP a partir de archivos Markdown con bloques de código."""

from __future__ import annotations

import argparse
import re
import zipfile
from pathlib import Path, PurePosixPath, PureWindowsPath

from filename_recovery import recover_names_from_includes
from local_secrets import secrets_path_for


DUPLICATE_RE = re.compile(r" \(entrada repetida #\d+\)$", re.IGNORECASE)
HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$")
FENCE_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
INLINE_CODE_RE = re.compile(r"(?<!\\)`([^`\n]+)(?<!\\)`")
FILE_LABEL_RE = re.compile(
    r"^\s{0,3}(?:[-*+]\s*)?(?:\*\*)?(?:archivo|file|ruta|path)"
    r"(?:\*\*)?\s*(?:#\d+)?\s*[:：]\s*(.+?)\s*$",
    re.IGNORECASE,
)
GENERIC_HEADINGS = {
    "índice", "indice", "index", "contenido", "contents", "archivos",
    "archivos incluidos", "files", "files included", "resumen", "summary",
    "instrucciones", "instructions", "ejemplo", "ejemplos", "example",
    "examples", "uso", "usage", "introducción", "introduccion",
    "introduction", "notas", "notes",
}
COMMON_EXTENSIONLESS_NAMES = {
    "readme", "license", "licence", "dockerfile", "makefile", "gemfile",
    "procfile", "justfile", "authors", "changelog", "copying",
}


def parse_markdown(markdown_path: Path) -> list[tuple[str, str]]:
    """Extrae bloques cercados y deduce su nombre de los encabezados cercanos."""
    lines = markdown_path.read_text(encoding="utf-8").split("\n")
    files: list[tuple[str, str]] = []

    current_name: str | None = None
    section_start = 0
    position = 0
    while position < len(lines):
        line = lines[position]
        heading = HEADING_RE.fullmatch(line)
        if heading:
            current_name = name_from_heading(heading.group(1))
            position += 1
            continue

        opening = FENCE_RE.fullmatch(line)
        if opening is None:
            position += 1
            continue

        fence = opening.group(1)
        fence_char = fence[0]
        fence_length = len(fence)
        closing_re = re.compile(rf"^ {{0,3}}{re.escape(fence_char)}{{{fence_length},}}[ \t]*$")
        closing = position + 1
        while closing < len(lines) and not closing_re.fullmatch(lines[closing]):
            closing += 1
        if closing == len(lines):
            # Una cerca sin cierre suele ser texto normal o un Markdown incompleto;
            # se ignora en lugar de impedir recuperar los bloques anteriores.
            position += 1
            continue

        content = "\n".join(lines[position + 1 : closing])
        name = current_name or name_from_labels(lines[section_start:position])
        if name:
            name = DUPLICATE_RE.sub("", name)
            files.append((name, content))
        current_name = None
        section_start = closing + 1
        position = closing + 1

    if not files:
        raise ValueError("no se encontraron bloques de código con un nombre de archivo reconocible")
    return recover_names_from_includes(files)


def clean_name(value: str) -> str:
    """Quita etiquetas y formato Markdown alrededor de una ruta/nombre."""
    value = value.strip().replace("\\`", "`")
    value = re.sub(r"^\*\*(.*?)\*\*$", r"\1", value).strip()
    value = value.strip(" `\t\r\n\"'")
    value = re.sub(r"\s+—\s*$|\s+-\s*$", "", value).strip()
    value = DUPLICATE_RE.sub("", value).strip()
    return value


def name_from_heading(heading: str) -> str | None:
    """Obtiene el nombre de archivo de un encabezado, si parece identificable."""
    code_names = [clean_name(match) for match in INLINE_CODE_RE.findall(heading)]
    code_names = [name for name in code_names if name]

    # Un nombre entre backticks al inicio suele ser la forma compacta de indicar
    # un archivo; también aceptamos nombres de archivo dentro de títulos más largos.
    starts_with_code = heading.lstrip().startswith("`")
    if code_names and (starts_with_code or any(looks_like_filename(name) for name in code_names)):
        return code_names[-1] if not starts_with_code else code_names[0]

    plain = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", heading)
    # Los guiones bajos también son caracteres válidos en nombres de archivo
    # (p. ej. `caq_gemv_v5.cu`); no se pueden quitar globalmente como formato.
    # Se conservan y solo se eliminan los marcadores de énfasis más habituales.
    plain = re.sub(r"[*~]", "", plain).strip()
    explicit = re.match(
        r"^(?:archivo|file|ruta|path)(?:\s+#?\d+)?\s*[:：—–-]\s*(.+)$",
        plain,
        flags=re.IGNORECASE,
    )
    if explicit:
        return clean_name(explicit.group(1)) or None

    name = clean_name(plain)
    if not name or name.casefold() in GENERIC_HEADINGS:
        return None
    return name if looks_like_filename(name) else None


def looks_like_filename(name: str) -> bool:
    """Reconoce rutas, extensiones habituales y nombres de archivo conocidos."""
    return (
        "/" in name
        or bool(re.search(r"\.[A-Za-z0-9_-]{1,16}$", name))
        or name.casefold() in COMMON_EXTENSIONLESS_NAMES
    )


def name_from_labels(lines: list[str]) -> str | None:
    """Busca etiquetas explícitas como `Archivo: src/main.py` antes del bloque."""
    for line in reversed(lines):
        match = FILE_LABEL_RE.fullmatch(line)
        if match:
            name = clean_name(match.group(1))
            if name:
                return name
    return None


def validate_archive_name(name: str) -> None:
    """Rechaza rutas absolutas o con traversal antes de incluirlas en el ZIP."""
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
        raise ValueError(f"ruta de archivo no permitida: {name!r}")


def convert(
    markdown_path: Path,
    output_path: Path,
    *,
    secrets_path: Path | None = None,
) -> int:
    selected_secrets = secrets_path or secrets_path_for(markdown_path)
    if selected_secrets.is_file():
        from secrets_rebase import rebase_markdown_file

        report = rebase_markdown_file(markdown_path, output_path, selected_secrets)
        return len(parse_markdown(markdown_path)) + report.sensitive_files_added

    files = parse_markdown(markdown_path)
    for name, _ in files:
        validate_archive_name(name)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in files:
            archive.writestr(name, content.encode("utf-8"))
    return len(files)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Reconstruye un ZIP desde bloques de código Markdown; usa encabezados "
            "cercanos como nombres de archivo."
        )
    )
    parser.add_argument("markdown", type=Path, help="Documento Markdown de entrada")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="ZIP de salida (por defecto, junto al Markdown y con extensión .zip)",
    )
    parser.add_argument(
        "--secrets",
        type=Path,
        help="Vault local opcional; si se omite, busca automáticamente el .secrets adyacente",
    )
    args = parser.parse_args()

    if not args.markdown.is_file():
        parser.error(f"no existe el archivo: {args.markdown}")
    output = args.output or args.markdown.with_suffix(".zip")
    if output.resolve() == args.markdown.resolve():
        parser.error("el archivo de salida no puede sobrescribir el Markdown de entrada")

    try:
        count = convert(args.markdown, output, secrets_path=args.secrets)
    except (OSError, UnicodeError, ValueError, zipfile.BadZipFile) as error:
        parser.error(f"no se pudo reconstruir el ZIP: {error}")

    print(f"Creado: {output} ({count} archivos de texto)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
