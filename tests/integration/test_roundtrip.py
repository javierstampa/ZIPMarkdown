from __future__ import annotations
import zipfile
from pathlib import Path
import pytest
import markdown_a_zip
import zip_a_markdown
from local_secrets import TestVaultBackend, VaultUnavailableError
from tests.conftest import simple_pdf


def zip_contents(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path) as archive:
        return {name: archive.read(name) for name in archive.namelist() if not name.endswith("/")}


def test_zip_markdown_zip_exact_content_round_trip(tmp_path: Path, test_vault: TestVaultBackend) -> None:
    source, markdown, rebuilt = tmp_path / "source.zip", tmp_path / "source.md", tmp_path / "rebuilt.zip"
    original = {
        "src/main.py": b"print('ok')\r\n",
        "config/settings.toml": b'api_key = "TEST_ONLY_roundtrip_credential_12345"\n',
        "assets/image.bin": b"\x00\x01\xffbinary",
        "docs/guide.pdf": simple_pdf("Round trip PDF"),
        "unicode/á.txt": "hola".encode(),
        "empty.txt": b"",
    }
    with zipfile.ZipFile(source, "w") as archive:
        for name, raw in original.items():
            archive.writestr(name, raw)
    report = zip_a_markdown.convert(source, markdown, vault_backend=test_vault)
    assert report.secrets_file and report.binary_files_preserved == 1
    markdown_a_zip.convert(markdown, rebuilt, vault_backend=test_vault)
    assert zip_contents(rebuilt) == original


def test_folder_markdown_folder_round_trip(tmp_path: Path, test_vault: TestVaultBackend) -> None:
    source = tmp_path / "project"
    (source / "src").mkdir(parents=True)
    (source / "src/main.py").write_bytes(b"print('ok')\n")
    (source / "asset.bin").write_bytes(b"\x00\x02data")
    markdown = tmp_path / "project.md"
    output = tmp_path / "rebuilt"
    zip_a_markdown.convert_folder_to_markdown(source, markdown, vault_backend=test_vault)
    markdown_a_zip.convert_to_folder(markdown, output, vault_backend=test_vault)
    assert (output / "src/main.py").read_bytes() == b"print('ok')\n"
    assert (output / "asset.bin").read_bytes() == b"\x00\x02data"


def test_simple_project_needs_no_vault_on_non_windows(tmp_path: Path) -> None:
    source = tmp_path / "project"
    source.mkdir()
    (source / "main.py").write_text("print('ok')\n", encoding="utf-8")
    markdown = tmp_path / "project.md"
    report = zip_a_markdown.convert_folder_to_markdown(source, markdown)
    assert report.secrets_file is None
    assert not markdown.with_suffix(".secrets").exists()


def test_no_vault_refuses_data_that_needs_recovery(tmp_path: Path) -> None:
    source = tmp_path / "project"
    source.mkdir()
    (source / "asset.bin").write_bytes(b"\x00binary")
    with pytest.raises(VaultUnavailableError, match="requires protected recovery"):
        zip_a_markdown.convert_folder_to_markdown(source, tmp_path / "project.md", no_vault=True)


def test_optional_gitignore_reports_rule(tmp_path: Path) -> None:
    source = tmp_path / "project"
    source.mkdir()
    (source / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
    (source / "ignored.txt").write_text("ignored", encoding="utf-8")
    (source / "kept.txt").write_text("kept", encoding="utf-8")
    report = zip_a_markdown.convert_folder_to_markdown(
        source, tmp_path / "project.md", respect_gitignore=True, verbose=True
    )
    assert report.gitignored_files_skipped == 1
    assert any("ignored.txt" in warning and "ignored.txt" in warning for warning in report.warnings)
