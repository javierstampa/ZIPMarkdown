from __future__ import annotations
from pathlib import Path
from zipmarkdown_cli import main


def test_installed_cli_export_and_import_without_vault(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "main.py").write_text("print('ok')\n", encoding="utf-8")
    markdown = tmp_path / "project.md"
    rebuilt = tmp_path / "rebuilt.zip"
    assert main(["export", str(project), "-o", str(markdown), "--no-vault"]) == 0
    assert main(["import", str(markdown), "-o", str(rebuilt), "--no-vault"]) == 0
    assert rebuilt.is_file()
