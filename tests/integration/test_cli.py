from __future__ import annotations
from pathlib import Path
import zipfile

import pytest
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


def _assert_cli_rejects_without_changing(arguments: list[str], protected: Path) -> None:
    before = protected.read_bytes()
    with pytest.raises(SystemExit):
        main(arguments)
    assert protected.read_bytes() == before


def test_import_cannot_replace_its_markdown_input(tmp_path: Path) -> None:
    markdown = tmp_path / "project.md"
    markdown.write_text("## `main.py`\n```python\nprint('ok')\n```\n", encoding="utf-8")
    _assert_cli_rejects_without_changing(
        ["import", str(markdown), "-o", str(markdown), "--no-vault"], markdown
    )


def test_export_cannot_replace_its_zip_input(tmp_path: Path) -> None:
    source = tmp_path / "project.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("main.py", "print('ok')\n")
    _assert_cli_rejects_without_changing(
        ["export", str(source), "-o", str(source), "--no-vault"], source
    )


def test_export_reserves_secrets_extension_for_vaults(tmp_path: Path) -> None:
    source = tmp_path / "project.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("main.py", "print('ok')\n")
    destination = tmp_path / "project.secrets"
    destination.write_bytes(b"existing vault")
    _assert_cli_rejects_without_changing(
        ["export", str(source), "-o", str(destination), "--no-vault"], destination
    )


def test_rebase_cannot_use_vault_as_output(tmp_path: Path) -> None:
    source = tmp_path / "edited.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("main.py", "print('ok')\n")
    vault = tmp_path / "project.secrets"
    vault.write_bytes(b"only recovery copy")
    _assert_cli_rejects_without_changing(
        ["rebase", str(source), "--secrets", str(vault), "-o", str(vault)], vault
    )


def test_cli_export_zip_import_folder_and_strict_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import secret_scanner

    monkeypatch.setattr(secret_scanner, "scan_markdown_with_gitleaks", lambda doc: None)
    source_zip = tmp_path / "app.zip"
    with zipfile.ZipFile(source_zip, "w") as archive:
        archive.writestr("src/app.py", "print('hello')\n")
    markdown = tmp_path / "app.md"
    assert main(["export", str(source_zip), "-o", str(markdown), "--no-vault", "--strict-secrets"]) == 0
    rebuilt_dir = tmp_path / "rebuilt_dir"
    assert main(["import", str(markdown), "--folder", "-o", str(rebuilt_dir), "--no-vault"]) == 0
    assert (rebuilt_dir / "src/app.py").read_text(encoding="utf-8") == "print('hello')\n"

    ambiguous_dir = tmp_path / "ambiguous"
    ambiguous_dir.mkdir()
    (ambiguous_dir / "cfg.py").write_text('token = "abc"\n', encoding="utf-8")
    with pytest.raises(SystemExit):
        main(["export", str(ambiguous_dir), "-o", str(tmp_path / "amb.md"), "--no-vault", "--strict-secrets"])


def test_legacy_entry_points_export_and_import(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import sys
    import markdown_a_zip
    import zip_a_markdown

    project = tmp_path / "proj"
    project.mkdir()
    (project / ".gitignore").write_text("ignored_dir/\n", encoding="utf-8")
    (project / "ignored_dir").mkdir()
    (project / "ignored_dir/skip.txt").write_text("skip", encoding="utf-8")
    (project / "readme.txt").write_text("hi\n", encoding="utf-8")
    md = tmp_path / "proj.md"
    rebuilt = tmp_path / "out.zip"

    monkeypatch.setattr(
        sys, "argv", ["zip_a_markdown.py", str(project), "-o", str(md), "--no-vault", "--respect-gitignore", "--verbose"]
    )
    assert zip_a_markdown.main() == 0
    monkeypatch.setattr(sys, "argv", ["markdown_a_zip.py", str(md), "-o", str(rebuilt), "--no-vault"])
    assert markdown_a_zip.main() == 0
    with zipfile.ZipFile(rebuilt) as archive:
        assert set(archive.namelist()) == {".gitignore", "readme.txt"}
