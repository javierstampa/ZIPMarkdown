from __future__ import annotations
from pathlib import Path
import pytest
from local_secrets import TestVaultBackend, load_secrets, payload_requires_vault, save_secrets


def test_injected_backend_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "project.secrets"
    data = {"version": 1, "redactions": {"id": "TEST_ONLY"}, "bindings": [], "redacted_files": [], "sensitive_files": [], "binary_files": []}
    save_secrets(path, data, backend=TestVaultBackend())
    assert b"TEST_ONLY" in path.read_bytes()  # Explicitly non-encrypting test backend.
    assert load_secrets(path, backend=TestVaultBackend()) == data

def test_test_vault_requires_explicit_backend(tmp_path: Path) -> None:
    path = tmp_path / "project.secrets"
    save_secrets(path, {"version": 1}, backend=TestVaultBackend())
    with pytest.raises(ValueError, match="explicitly injected"):
        load_secrets(path)

def test_empty_payload_does_not_require_vault() -> None:
    assert not payload_requires_vault({"redactions": {}, "redacted_files": [], "sensitive_files": [], "binary_files": []})
