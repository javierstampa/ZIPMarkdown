"""Bounded PDF text extraction for ZIPMarkdown."""
from __future__ import annotations

import io
import re
import zlib

from archive_safety import DEFAULT_LIMITS, ArchiveSecurityError, SecurityLimits


def extract_pdf_text(data: bytes, *, limits: SecurityLimits = DEFAULT_LIMITS) -> str | None:
    if len(data) > limits.max_file_size:
        raise ArchiveSecurityError("PDF exceeds the configured size limit")
    try:
        import pypdf
        reader = pypdf.PdfReader(io.BytesIO(data), strict=False)
        page_count = len(reader.pages)
        if page_count > limits.max_pdf_pages:
            raise ArchiveSecurityError(
                f"PDF has {page_count} pages; limit is {limits.max_pdf_pages}"
            )
        pages_text: list[str] = []
        for index, page in enumerate(reader.pages, start=1):
            text = (page.extract_text() or "").strip()
            if text:
                pages_text.append(f"--- Page {index} ---\n{text}" if page_count > 1 else text)
        return "\n\n".join(pages_text) if pages_text else "[PDF document contains no extractable text]"
    except ArchiveSecurityError:
        raise
    except Exception:
        return _fallback_extract_pdf_text(data, limits=limits)


def _fallback_extract_pdf_text(data: bytes, *, limits: SecurityLimits = DEFAULT_LIMITS) -> str | None:
    # A conservative page-object estimate keeps the dependency-free fallback bounded.
    page_count = len(re.findall(rb"/Type\s*/Page\b", data))
    if page_count > limits.max_pdf_pages:
        raise ArchiveSecurityError(f"PDF has more than {limits.max_pdf_pages} pages")
    try:
        streams = re.findall(rb"stream[\r\n]+(.*?)[\r\n]+endstream", data, re.DOTALL)
        extracted: list[str] = []
        total_decompressed = 0
        for stream in streams:
            try:
                decompressed = zlib.decompress(stream)
            except Exception:
                decompressed = stream if b"BT" in stream and b"ET" in stream else b""
            total_decompressed += len(decompressed)
            if total_decompressed > limits.max_file_size:
                raise ArchiveSecurityError("PDF decompressed content exceeds the configured limit")
            for match in re.findall(rb"\((.*?)\)\s*Tj", decompressed):
                text = match.decode("utf-8", errors="ignore").strip()
                if text:
                    extracted.append(text)
        return "\n".join(extracted) if extracted else None
    except ArchiveSecurityError:
        raise
    except Exception:
        return None
