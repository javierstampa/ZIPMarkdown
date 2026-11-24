from __future__ import annotations
import os
import zipfile
from pathlib import Path
import pytest
import zip_a_markdown
from archive_safety import ArchiveSecurityError, SecurityLimits
from zip_markdown_app import ZIPMarkdownApp


def test_actual_zip_slip_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "bad.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("../escape.txt", "bad")
    with pytest.raises(ArchiveSecurityError):
        zip_a_markdown.convert(source, tmp_path / "bad.md", no_vault=True)


def test_actual_duplicate_zip_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "duplicate.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("same.txt", "one")
        archive.writestr("same.txt", "two")
    with pytest.raises(ArchiveSecurityError, match="duplicate"):
        zip_a_markdown.convert(source, tmp_path / "bad.md", no_vault=True)


def test_actual_compression_bomb_ratio_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "bomb.zip"
    with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("zeros.txt", "0" * 100_000)
    with pytest.raises(ArchiveSecurityError, match="compression ratio"):
        zip_a_markdown.convert(source, tmp_path / "bad.md", no_vault=True, limits=SecurityLimits(max_compression_ratio=10))


def test_empty_zip_is_handled_explicitly(tmp_path: Path) -> None:
    source = tmp_path / "empty.zip"
    with zipfile.ZipFile(source, "w"):
        pass
    report = zip_a_markdown.convert(source, tmp_path / "empty.md", no_vault=True)
    assert report.included == report.skipped_binary == 0


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink setup")
def test_folder_symlink_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "project"
    source.mkdir()
    (source / "target.txt").write_text("safe", encoding="utf-8")
    (source / "link.txt").symlink_to(source / "target.txt")
    with pytest.raises(ArchiveSecurityError, match="symbolic"):
        zip_a_markdown.convert_folder_to_markdown(source, tmp_path / "out.md", no_vault=True)


def test_dropped_folder_dispatches_to_export_without_gui(tmp_path: Path) -> None:
    source = tmp_path / "project"
    source.mkdir()
    app = object.__new__(ZIPMarkdownApp)
    seen: list[Path] = []
    app._export_path = seen.append  # type: ignore[method-assign]
    ZIPMarkdownApp._open_dropped_path(app, source)
    assert seen == [source]
