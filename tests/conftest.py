from __future__ import annotations
import sys
from pathlib import Path
import pytest
from local_secrets import TestVaultBackend

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

@pytest.fixture
def test_vault() -> TestVaultBackend:
    return TestVaultBackend()


def simple_pdf(text: str = "ZIPMarkdown PDF") -> bytes:
    content = f"BT /F1 12 Tf 72 712 Td ({text}) Tj ET".encode("latin1")
    return (
        b"%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
        b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj\n"
        b"4 0 obj << /Length " + str(len(content)).encode() + b" >>\nstream\n" + content +
        b"\nendstream\nendobj\n5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n"
        b"trailer << /Size 6 /Root 1 0 R >>\n%%EOF\n"
    )
