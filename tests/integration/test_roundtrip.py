from __future__ import annotations
import shutil
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


def test_truncated_final_fence_is_rejected(tmp_path: Path) -> None:
    markdown = tmp_path / "truncated.md"
    markdown.write_text(
        "## `a.txt`\n\n```text\na\n```\n\n## `b.txt`\n\n```text\nb\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="truncated Markdown"):
        markdown_a_zip.parse_markdown(markdown)


def test_empty_project_round_trip_uses_explicit_snapshot_manifest(tmp_path: Path) -> None:
    source = tmp_path / "empty-project"
    source.mkdir()
    markdown = tmp_path / "empty.md"
    rebuilt_zip = tmp_path / "empty.zip"
    rebuilt_folder = tmp_path / "rebuilt-empty"
    report = zip_a_markdown.convert_folder_to_markdown(source, markdown)
    assert report.included == 0
    assert '"entries":0' in markdown.read_text(encoding="utf-8")
    assert markdown_a_zip.convert(markdown, rebuilt_zip) == 0
    with zipfile.ZipFile(rebuilt_zip) as archive:
        assert archive.infolist() == []
    assert markdown_a_zip.convert_to_folder(markdown, rebuilt_folder) == 0
    assert list(rebuilt_folder.iterdir()) == []


def test_markdown_and_vault_from_different_exports_are_rejected(
    tmp_path: Path, test_vault: TestVaultBackend
) -> None:
    vaults: list[Path] = []
    markdowns: list[Path] = []
    for number in (1, 2):
        source = tmp_path / f"project-{number}"
        source.mkdir()
        (source / "config.py").write_text(
            f'API_KEY = "TEST_ONLY_export_secret_{number}_123456"\n', encoding="utf-8"
        )
        markdown = tmp_path / f"project-{number}.md"
        zip_a_markdown.convert_folder_to_markdown(source, markdown, vault_backend=test_vault)
        markdowns.append(markdown)
        vaults.append(markdown.with_suffix(".secrets"))
    shutil.copyfile(vaults[1], vaults[0])
    with pytest.raises(ValueError, match="different ZIPMarkdown exports"):
        markdown_a_zip.convert(markdowns[0], tmp_path / "mismatch.zip", vault_backend=test_vault)


def test_pair_write_rolls_back_when_markdown_replace_fails(
    tmp_path: Path, test_vault: TestVaultBackend, monkeypatch: pytest.MonkeyPatch
) -> None:
    import atomic_utils

    source = tmp_path / "project"
    source.mkdir()
    (source / "config.py").write_text(
        'API_KEY = "TEST_ONLY_rollback_secret_123456"\n', encoding="utf-8"
    )
    markdown = tmp_path / "project.md"
    vault = markdown.with_suffix(".secrets")
    markdown.write_bytes(b"old markdown")
    vault.write_bytes(b"old vault")
    real_replace = atomic_utils.os.replace
    raised = False

    def fail_markdown_once(source_path, destination_path):
        nonlocal raised
        if not raised and Path(destination_path) == markdown and str(source_path).endswith(".tmp"):
            raised = True
            raise OSError("simulated Markdown commit failure")
        return real_replace(source_path, destination_path)

    monkeypatch.setattr(atomic_utils.os, "replace", fail_markdown_once)
    with pytest.raises(OSError, match="simulated Markdown commit failure"):
        zip_a_markdown.convert_folder_to_markdown(source, markdown, vault_backend=test_vault)
    assert markdown.read_bytes() == b"old markdown"
    assert vault.read_bytes() == b"old vault"
