"""Extractor de texto y utilidades para archivos PDF."""

from __future__ import annotations

import io
import re
import zlib


def extract_pdf_text(data: bytes) -> str | None:
    """Extrae texto legible de un binario PDF. Devuelve None si falla la extracción."""
    # 1. Intentar con pypdf para máxima fidelidad
    try:
        import pypdf

        reader = pypdf.PdfReader(io.BytesIO(data))
        pages_text: list[str] = []
        for idx, page in enumerate(reader.pages, start=1):
            text = (page.extract_text() or "").strip()
            if text:
                if len(reader.pages) > 1:
                    pages_text.append(f"--- Página {idx} ---\n{text}")
                else:
                    pages_text.append(text)
        if pages_text:
            return "\n\n".join(pages_text)
        return "[Documento PDF sin texto extraíble / compuesto por imágenes escaneadas]"
    except Exception:
        pass

    # 2. Fallback sin dependencias externas usando zlib y regex
    return _fallback_extract_pdf_text(data)


def _fallback_extract_pdf_text(data: bytes) -> str | None:
    """Extractor básico sin dependencias para PDFs simples."""
    try:
        streams = re.findall(rb"stream[\r\n]+(.*?)[\r\n]+endstream", data, re.DOTALL)
        extracted: list[str] = []
        for s in streams:
            decompressed = None
            try:
                decompressed = zlib.decompress(s)
            except Exception:
                if b"BT" in s and b"ET" in s:
                    decompressed = s
            if decompressed:
                matches = re.findall(rb"\((.*?)\)\s*Tj", decompressed)
                for m in matches:
                    try:
                        t = m.decode("utf-8", errors="ignore").strip()
                        if t:
                            extracted.append(t)
                    except Exception:
                        pass
        if extracted:
            return "\n".join(extracted)
    except Exception:
        pass
    return None
