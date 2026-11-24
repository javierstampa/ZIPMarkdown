from __future__ import annotations
import os
from pathlib import Path
import pytest
from local_secrets import DPAPIBackend, load_secrets, save_secrets

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI test")

def test_real_dpapi_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "vault.secrets"
    payload = {"version": 1, "redactions": {"token": "TEST_ONLY_DPAPI_VALUE"}, "bindings": [], "redacted_files": [], "sensitive_files": [], "binary_files": []}
    save_secrets(path, payload, backend=DPAPIBackend())
    assert b"TEST_ONLY_DPAPI_VALUE" not in path.read_bytes()
    assert load_secrets(path, backend=DPAPIBackend()) == payload
