#!/usr/bin/env python3
"""Interfaz de escritorio para las herramientas ZIP ↔ Markdown."""

from __future__ import annotations

import sys
import threading
from pathlib import Path
from typing import Callable
import tkinter as tk
from tkinter import filedialog, messagebox

import pystray
from PIL import Image, ImageDraw

import markdown_a_zip
import zip_a_markdown


class MdToolkitApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("MD Toolkit")
        self.root.withdraw()
        self.busy = False
        self.status_var = tk.StringVar(value="Listo para convertir archivos.")
        self.icon = self._create_tray_icon()
        self.icon.run_detached()
        if len(sys.argv) > 1:
            dropped_path = Path(sys.argv[1].strip('"'))
            self.root.after(250, lambda: self._open_dropped_file(dropped_path))

    def _create_tray_icon(self) -> pystray.Icon:
        image = Image.new("RGBA", (64, 64), "#0B1220")
        draw = ImageDraw.Draw(image)
        draw.rounded_rectangle((3, 3, 61, 61), radius=14, fill="#46D7C3")
        draw.line([(15, 46), (15, 19), (26, 34), (37, 19), (37, 46)], fill="#0B1220", width=6)
        draw.line([(43, 19), (43, 46)], fill="#0B1220", width=6)
        draw.arc((40, 19, 55, 46), start=270, end=90, fill="#0B1220", width=6)

        def queue(command: Callable[[], None]) -> Callable[[pystray.Icon, pystray.MenuItem], None]:
            return lambda _icon, _item: self.root.after(0, command)

        menu = pystray.Menu(
            pystray.MenuItem("Markdown → ZIP", queue(self._choose_markdown)),
            pystray.MenuItem("ZIP → Markdown", queue(self._choose_zip)),
            pystray.MenuItem("Carpeta → Markdown", queue(self._choose_folder)),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Salir", queue(self._quit)),
        )
        return pystray.Icon("MD Toolkit", image, "MD Toolkit", menu)

    def _quit(self) -> None:
        self.icon.stop()
        self.root.destroy()

    def _choose_zip(self) -> None:
        source = filedialog.askopenfilename(
            title="Selecciona un archivo ZIP",
            filetypes=[("Archivos ZIP", "*.zip"), ("Todos los archivos", "*.*")],
        )
        if source:
            path = Path(source)
            self._choose_output_and_convert(
                path,
                extension=".md",
                filetypes=[("Markdown", "*.md")],
                converter=zip_a_markdown.convert,
                operation="zip_to_md",
            )

    def _choose_markdown(self) -> None:
        source = filedialog.askopenfilename(
            title="Selecciona un documento Markdown",
            filetypes=[("Markdown", "*.md"), ("Todos los archivos", "*.*")],
        )
        if source:
            path = Path(source)
            self._choose_output_and_convert(
                path,
                extension=".zip",
                filetypes=[("Archivos ZIP", "*.zip")],
                converter=markdown_a_zip.convert,
                operation="md_to_zip",
            )

    def _choose_folder(self) -> None:
        source = filedialog.askdirectory(title="Selecciona una carpeta de proyecto")
        if not source:
            return
        path = Path(source)
        output = filedialog.asksaveasfilename(
            title="Guardar Markdown como",
            initialdir=str(path.parent),
            initialfile=path.name + ".md",
            defaultextension=".md",
            filetypes=[("Markdown", "*.md")],
        )
        if output:
            self._start_conversion(
                path,
                Path(output),
                zip_a_markdown.convert_folder_to_markdown,
                "folder_to_md",
            )
        else:
            self.status_var.set("Operación cancelada.")

    def _open_dropped_file(self, path: Path) -> None:
        if not path.is_file():
            self.status_var.set(f"No se encontró el archivo: {path}")
            return
        suffix = path.suffix.casefold()
        if suffix == ".zip":
            self._choose_output_and_convert(
                path,
                extension=".md",
                filetypes=[("Markdown", "*.md")],
                converter=zip_a_markdown.convert,
                operation="zip_to_md",
            )
        elif suffix == ".md":
            self._choose_output_and_convert(
                path,
                extension=".zip",
                filetypes=[("Archivos ZIP", "*.zip")],
                converter=markdown_a_zip.convert,
                operation="md_to_zip",
            )
        else:
            self.status_var.set("Arrastra un archivo .zip o .md sobre el ejecutable para abrirlo directamente.")

    def _choose_output_and_convert(
        self,
        source: Path,
        *,
        extension: str,
        filetypes: list[tuple[str, str]],
        converter: Callable[[Path, Path], object],
        operation: str,
    ) -> None:
        output = filedialog.asksaveasfilename(
            title="Guardar archivo convertido",
            initialdir=str(source.parent),
            initialfile=source.stem + extension,
            defaultextension=extension,
            filetypes=filetypes,
        )
        if not output:
            self.status_var.set("Operación cancelada.")
            return
        self._start_conversion(source, Path(output), converter, operation)

    def _start_conversion(
        self,
        source: Path,
        output: Path,
        converter: Callable[[Path, Path], object],
        operation: str,
    ) -> None:
        if self.busy:
            return
        self.busy = True
        self.status_var.set(f"Procesando {source.name}…")

        def worker() -> None:
            try:
                result = converter(source, output)
                error: Exception | None = None
            except Exception as caught:  # Surface parser, filesystem, and archive errors in the UI.
                result = None
                error = caught
            self.root.after(0, lambda: self._finish_conversion(source, output, operation, result, error))

        threading.Thread(target=worker, daemon=True).start()

    def _finish_conversion(
        self,
        source: Path,
        output: Path,
        operation: str,
        result: object,
        error: Exception | None,
    ) -> None:
        self.busy = False
        if error is not None:
            self.status_var.set("La conversión no se pudo completar.")
            messagebox.showerror("Error de conversión", str(error), parent=self.root)
            return

        if operation in {"zip_to_md", "folder_to_md"} and isinstance(
            result, zip_a_markdown.ConversionReport
        ):
            detail = (
                f"{result.included} archivos de texto; {result.skipped_binary} binarios y "
                f"{result.sensitive_files_skipped} archivos sensibles omitidos; "
                f"{result.generated_files_skipped} archivos de dependencias/artefactos omitidos; "
                f"{result.values_redacted} valores redactados. "
                "Vault local cifrado creado: "
                f"{result.secrets_file}. Revisa el Markdown antes de compartirlo: "
                "la detección no es infalible"
            )
        else:
            detail = f"{result} archivos reconstruidos"
        self.status_var.set(f"Terminado: {output}")
        messagebox.showinfo(
            "Conversión completada",
            f"Se creó el archivo correctamente.\n\n{output}\n\n{detail}.",
            parent=self.root,
        )

def main() -> None:
    root = tk.Tk()
    MdToolkitApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
