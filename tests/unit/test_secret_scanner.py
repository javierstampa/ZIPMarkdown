from __future__ import annotations

from types import SimpleNamespace

import pytest

import secret_scanner


def test_strict_scanner_requires_gitleaks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(secret_scanner.shutil, "which", lambda _: None)
    with pytest.raises(RuntimeError, match="requires the gitleaks executable"):
        secret_scanner.scan_markdown_with_gitleaks("safe")


def test_strict_scanner_rejects_findings_without_leaking_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(secret_scanner.shutil, "which", lambda _: "/usr/bin/gitleaks")
    monkeypatch.setattr(
        secret_scanner.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=1),
    )
    with pytest.raises(ValueError, match="credential-like material"):
        secret_scanner.scan_markdown_with_gitleaks("password = 'TEST_ONLY_secret'")


def test_strict_scanner_passes_clean_and_reports_unexpected_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(secret_scanner.shutil, "which", lambda _: "/usr/bin/gitleaks")
    monkeypatch.setattr(
        secret_scanner.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0),
    )
    secret_scanner.scan_markdown_with_gitleaks("print('clean')\n")

    monkeypatch.setattr(
        secret_scanner.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=2),
    )
    with pytest.raises(RuntimeError, match="exit code 2"):
        secret_scanner.scan_markdown_with_gitleaks("print('error')\n")
