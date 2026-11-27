from __future__ import annotations

import pytest

import gitignore_support
from archive_safety import ArchiveSecurityError, SecurityLimits
from pdf_extractor import _fallback_extract_pdf_text, extract_pdf_text
from tests.conftest import simple_pdf
from zip_a_markdown import decode_text


def test_gitignore_fallback_handles_directories_rooted_wildcards_and_negation(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / ".gitignore").write_text(
        "# comment\n*.log\n!keep.log\n/root_only.txt\nlogs/\nsub/item.txt\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(gitignore_support, "GitWildMatchPattern", None)
    matcher = gitignore_support.GitIgnoreMatcher(tmp_path)
    assert matcher.match("app.log").ignored
    assert not matcher.match("keep.log").ignored
    assert matcher.match("root_only.txt").ignored
    assert not matcher.match("nested/root_only.txt").ignored
    assert matcher.match("logs/").ignored
    assert matcher.match("logs/out.txt").ignored
    assert not matcher.match("other.txt").ignored
    assert matcher.match("sub/item.txt").ignored


def test_pdf_extractor_limits_and_fallback() -> None:
    pdf = simple_pdf("Fallback check")
    assert "Fallback check" in (extract_pdf_text(pdf) or "")
    assert "Fallback check" in (_fallback_extract_pdf_text(pdf) or "")
    with pytest.raises(ArchiveSecurityError, match="size limit"):
        extract_pdf_text(pdf, limits=SecurityLimits(max_file_size=10))
    with pytest.raises(ArchiveSecurityError, match="0 pages"):
        extract_pdf_text(pdf, limits=SecurityLimits(max_pdf_pages=0))
    with pytest.raises(ArchiveSecurityError, match="more than 0 pages"):
        _fallback_extract_pdf_text(pdf, limits=SecurityLimits(max_pdf_pages=0))
    assert extract_pdf_text(b"not a pdf") is None


def test_decode_text_encodings_and_binary_detection() -> None:
    assert decode_text("hola".encode("utf-16")) == "hola"
    assert decode_text("cafés".encode("cp1252")) == "cafés"
    assert decode_text(b"bin\x00data") is None
