#!/usr/bin/env python3
"""ZIPMarkdown Windows tray application."""
from __future__ import annotations

import os
import subprocess
import sys
import threading
from pathlib import Path
from typing import Callable
try:
    import tkinter as tk
    from tkinter import filedialog, messagebox
except ModuleNotFoundError:  # Allows portable CLI/tests where Tk is not installed.
    tk = None  # type: ignore[assignment]
    filedialog = messagebox = None  # type: ignore[assignment]

try:
    import pystray
except Exception:  # Some Linux backends require a graphical session at import time.
    pystray = None  # type: ignore[assignment]
from PIL import Image, ImageDraw

import markdown_a_zip
import zip_a_markdown
from rebase_secrets import run_rebase


def _resolve_icon_path() -> Path | None:
    """Locate the bundled or repository application icon when present."""
    candidates: list[Path] = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.append(Path(meipass) / "assets" / "zipmarkdown.ico")
    candidates.append(Path(__file__).resolve().parent / "assets" / "zipmarkdown.ico")
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _load_tray_image(icon_path: Path | None) -> Image.Image:
    """Load the 64x64 tray icon image, falling back to a generated badge."""
    if icon_path is not None:
        try:
            with Image.open(icon_path) as ico:
                if (64, 64) in ico.info.get("sizes", ()):
                    ico.size = (64, 64)
                ico.load()
                image = ico.convert("RGBA")
                if image.size != (64, 64):
                    image = image.resize((64, 64), Image.Resampling.LANCZOS)
                return image.copy()
        except (OSError, ValueError):
            pass
    image = Image.new("RGBA", (64, 64), "#0B1220")
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle((3, 3, 61, 61), radius=14, fill="#46D7C3")
    draw.text((12, 20), "ZM", fill="#0B1220")
    return image


class ZIPMarkdownApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("ZIPMarkdown")
        icon_path = _resolve_icon_path()
        if icon_path is not None and tk is not None:
            try:
                self.root.iconbitmap(default=str(icon_path))
            except tk.TclError:
                pass
        self.root.withdraw()
        self.busy = False
        self.last_output: Path | None = None
        self.last_report = "No operation has completed yet."
        self.icon = self._create_tray_icon()
        self.icon.run_detached()
        if len(sys.argv) > 1:
            dropped = Path(sys.argv[1].strip('"'))
            self.root.after(250, lambda: self._open_dropped_path(dropped))

    def _create_tray_icon(self) -> pystray.Icon:
        image = _load_tray_image(_resolve_icon_path())
        def queue(command: Callable[[], None]) -> Callable[[pystray.Icon, pystray.MenuItem], None]:
            return lambda _icon, _item: self.root.after(0, command)
        menu = pystray.Menu(
            pystray.MenuItem("Project or ZIP → Markdown", queue(self._choose_project_or_zip)),
            pystray.MenuItem("Markdown → Project or ZIP", queue(self._choose_markdown)),
            pystray.MenuItem("Apply vault / Rebase secrets", queue(self._choose_rebase)),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Open output folder", queue(self._open_output_folder)),
            pystray.MenuItem("Last operation report", queue(self._show_last_report)),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Exit", queue(self._quit)),
        )
        return pystray.Icon("ZIPMarkdown", image, "ZIPMarkdown", menu)

    def _quit(self) -> None:
        self.icon.stop()
        self.root.destroy()

    def _choose_project_or_zip(self) -> None:
        choice = messagebox.askyesnocancel("ZIPMarkdown", "Select a project folder?\nChoose No to select a ZIP.", parent=self.root)
        if choice is None:
            return
        source = filedialog.askdirectory(title="Select a project folder") if choice else filedialog.askopenfilename(
            title="Select a ZIP", filetypes=[("ZIP files", "*.zip"), ("All files", "*.*")]
        )
        if source:
            self._export_path(Path(source))

    def _export_path(self, source: Path) -> None:
        output = filedialog.asksaveasfilename(
            title="Save AI-friendly Markdown", initialdir=str(source.parent),
            initialfile=(source.name if source.is_dir() else source.stem) + ".md",
            defaultextension=".md", filetypes=[("Markdown", "*.md")],
        )
        if not output:
            return
        converter = zip_a_markdown.convert_folder_to_markdown if source.is_dir() else zip_a_markdown.convert
        self._start(source, Path(output), converter, "export")

    def _choose_markdown(self) -> None:
        source = filedialog.askopenfilename(title="Select modified Markdown", filetypes=[("Markdown", "*.md"), ("All files", "*.*")])
        if not source:
            return
        markdown = Path(source)
        as_folder = messagebox.askyesno("ZIPMarkdown", "Rebuild as a project folder?\nChoose No to create a ZIP.", parent=self.root)
        if as_folder:
            output = filedialog.askdirectory(title="Select the parent folder for the rebuilt project")
            if not output:
                return
            destination = Path(output) / (markdown.stem + "_project")
            converter = markdown_a_zip.convert_to_folder
        else:
            output = filedialog.asksaveasfilename(
                title="Save rebuilt ZIP", initialdir=str(markdown.parent), initialfile=markdown.stem + ".zip",
                defaultextension=".zip", filetypes=[("ZIP files", "*.zip")],
            )
            if not output:
                return
            destination = Path(output)
            converter = markdown_a_zip.convert
        adjacent = markdown.with_suffix(".secrets")
        vault: Path | None = adjacent if adjacent.is_file() else None
        if vault is None and messagebox.askyesno("ZIPMarkdown", "Select a vault manually?", parent=self.root):
            selected = filedialog.askopenfilename(title="Select ZIPMarkdown vault", filetypes=[("ZIPMarkdown vault", "*.secrets"), ("All files", "*.*")])
            vault = Path(selected) if selected else None
        self._start(markdown, destination, lambda src, dst: converter(src, dst, secrets_path=vault), "import")

    def _choose_rebase(self) -> None:
        source = filedialog.askopenfilename(title="Select AI-edited Markdown or ZIP", filetypes=[("Markdown or ZIP", "*.md *.zip"), ("All files", "*.*")])
        if not source:
            return
        vault = filedialog.askopenfilename(title="Select ZIPMarkdown vault", filetypes=[("ZIPMarkdown vault", "*.secrets"), ("All files", "*.*")])
        if not vault:
            return
        source_path = Path(source)
        output = filedialog.asksaveasfilename(
            title="Save rebased ZIP", initialdir=str(source_path.parent), initialfile=source_path.stem + "_rebased.zip",
            defaultextension=".zip", filetypes=[("ZIP files", "*.zip")],
        )
        if output:
            self._start(source_path, Path(output), lambda src, dst: run_rebase(src, Path(vault), dst)[0], "rebase")

    def _open_dropped_path(self, path: Path) -> None:
        if path.is_dir() or (path.is_file() and path.suffix.casefold() == ".zip"):
            self._export_path(path)
        elif path.is_file() and path.suffix.casefold() == ".md":
            # Reuse the normal import flow while preserving the dropped path.
            output = filedialog.asksaveasfilename(
                title="Save rebuilt ZIP", initialdir=str(path.parent), initialfile=path.stem + ".zip",
                defaultextension=".zip", filetypes=[("ZIP files", "*.zip")],
            )
            if output:
                self._start(path, Path(output), markdown_a_zip.convert, "import")
        else:
            messagebox.showerror("ZIPMarkdown", "Drop a project folder, .zip, or .md file.", parent=self.root)

    def _start(self, source: Path, output: Path, converter: Callable[[Path, Path], object], operation: str) -> None:
        if self.busy:
            messagebox.showwarning("ZIPMarkdown", "Another operation is still running.", parent=self.root)
            return
        self.busy = True
        def worker() -> None:
            try:
                result, error = converter(source, output), None
            except Exception as caught:
                result, error = None, caught
            self.root.after(0, lambda: self._finish(output, operation, result, error))
        threading.Thread(target=worker, daemon=True).start()

    def _finish(self, output: Path, operation: str, result: object, error: Exception | None) -> None:
        self.busy = False
        if error is not None:
            self.last_report = f"{operation} failed: {error}"
            messagebox.showerror("ZIPMarkdown", self.last_report, parent=self.root)
            return
        self.last_output = output
        if isinstance(result, zip_a_markdown.ConversionReport):
            vault = result.secrets_file.name if result.secrets_file else "not required"
            detail = (
                f"{result.included} text files; {result.binary_files_preserved} binaries protected; "
                f"{result.values_redacted} values redacted; vault: {vault}."
            )
        else:
            detail = str(result)
        self.last_report = f"{operation} completed. Output: {output}. {detail}"
        messagebox.showinfo("ZIPMarkdown", self.last_report, parent=self.root)

    def _show_last_report(self) -> None:
        messagebox.showinfo("ZIPMarkdown — Last operation", self.last_report, parent=self.root)

    def _open_output_folder(self) -> None:
        folder = self.last_output.parent if self.last_output else Path.cwd()
        try:
            if os.name == "nt":
                os.startfile(folder)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(folder)])
            else:
                subprocess.Popen(["xdg-open", str(folder)])
        except OSError as error:
            messagebox.showerror("ZIPMarkdown", f"Could not open output folder: {error}", parent=self.root)


# Historical import compatibility.
MdToolkitApp = ZIPMarkdownApp


def main() -> None:
    if tk is None or pystray is None:
        raise RuntimeError("ZIPMarkdown GUI requires Tk, pystray, Pillow, and a graphical session")
    root = tk.Tk()
    ZIPMarkdownApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
