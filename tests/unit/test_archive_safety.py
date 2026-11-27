from __future__ import annotations
import stat
import zipfile
import pytest
from archive_safety import (
    ArchiveSecurityError,
    SecurityLimits,
    canonical_archive_key,
    validate_archive_name,
    validate_zip_infos,
)

@pytest.mark.parametrize("name", [
    "../escape.txt", "../../escape.txt", "/absolute.txt", "C:/drive.txt", "C:\\drive.txt",
    "folder\\file.txt", "CON", "PRN.txt", "AUX/config", "NUL", "COM1.log", "LPT1",
    "trailingspace ", "trailingdot.", "bad:name.txt", "a/../b.txt",
])
def test_hostile_paths_are_rejected(name: str) -> None:
    with pytest.raises(ArchiveSecurityError):
        validate_archive_name(name)

@pytest.mark.parametrize("name", ["src/main.py", "unicode/áéí.txt", "deep/a/b/c/file.json", "empty.txt"])
def test_portable_paths_are_accepted(name: str) -> None:
    assert validate_archive_name(name) == name

def test_duplicate_entries_are_rejected() -> None:
    with pytest.raises(ArchiveSecurityError, match="collision"):
        validate_zip_infos([zipfile.ZipInfo("a.txt"), zipfile.ZipInfo("A.txt")])


def test_unicode_equivalent_entries_are_rejected() -> None:
    composed = "docs/caf\u00e9.md"
    decomposed = "docs/cafe\u0301.md"
    assert canonical_archive_key(composed) == canonical_archive_key(decomposed)
    with pytest.raises(ArchiveSecurityError, match="collision"):
        validate_zip_infos([zipfile.ZipInfo(composed), zipfile.ZipInfo(decomposed)])

def test_encrypted_entry_is_rejected() -> None:
    info = zipfile.ZipInfo("a.txt")
    info.flag_bits = 1
    with pytest.raises(ArchiveSecurityError, match="encrypted"):
        validate_zip_infos([info])

def test_symlink_entry_is_rejected() -> None:
    info = zipfile.ZipInfo("link")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with pytest.raises(ArchiveSecurityError, match="symbolic"):
        validate_zip_infos([info])

def test_entry_and_size_limits() -> None:
    with pytest.raises(ArchiveSecurityError, match="entries"):
        validate_zip_infos([zipfile.ZipInfo("a"), zipfile.ZipInfo("b")], limits=SecurityLimits(max_entries=1))
    info = zipfile.ZipInfo("large.bin")
    info.file_size = 101
    info.compress_size = 101
    with pytest.raises(ArchiveSecurityError, match="per-file"):
        validate_zip_infos([info], limits=SecurityLimits(max_file_size=100))

def test_suspicious_compression_ratio() -> None:
    info = zipfile.ZipInfo("bomb.txt")
    info.file_size = 10_000
    info.compress_size = 10
    with pytest.raises(ArchiveSecurityError, match="compression ratio"):
        validate_zip_infos([info], limits=SecurityLimits(max_compression_ratio=100))

def test_long_and_deep_paths_are_rejected() -> None:
    with pytest.raises(ArchiveSecurityError, match="unsafe"):
        validate_archive_name("a" * 241)
    with pytest.raises(ArchiveSecurityError, match="unsafe"):
        validate_archive_name("/".join(["a"] * 65), limits=SecurityLimits(max_path_depth=64))

def test_empty_file_entry_is_valid() -> None:
    info = zipfile.ZipInfo("empty.txt")
    info.file_size = info.compress_size = 0
    validate_zip_infos([info])
