"""Optional strict content scan backed by the Gitleaks executable."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path


def scan_markdown_with_gitleaks(document: str) -> None:
    """Require Gitleaks and fail without exposing matched secret material."""
    executable = shutil.which("gitleaks")
    if executable is None:
        raise RuntimeError(
            "strict secret mode requires the gitleaks executable; install Gitleaks and retry"
        )
    with tempfile.TemporaryDirectory(prefix="zipmarkdown-gitleaks-") as temporary:
        root = Path(temporary)
        (root / "export.md").write_text(document, encoding="utf-8", newline="\n")
        report = root / "report.json"
        result = subprocess.run(
            [
                executable,
                "detect",
                "--no-git",
                "--source",
                str(root),
                "--report-format",
                "json",
                "--report-path",
                str(report),
                "--redact",
                "--exit-code",
                "1",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if result.returncode == 1:
            raise ValueError("Gitleaks found credential-like material in the generated Markdown")
        if result.returncode != 0:
            raise RuntimeError(f"Gitleaks failed with exit code {result.returncode}")
