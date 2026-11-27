from __future__ import annotations
import pytest
from secrets_rebase import rebase_text_files


def payload(value: str = "TEST_ONLY_original_value_12345", path: str = "src/settings.py") -> dict:
    return {
        "version": 1,
        "redactions": {"a" * 32: value},
        "bindings": [{"token": "a" * 32, "path": path, "key": "api_key", "kind": "assignment"}],
        "redacted_files": [], "sensitive_files": [], "binary_files": [],
    }

@pytest.mark.parametrize("placeholder", ["YOUR_API_KEY", "<token>", "[REDACTED]", "${API_KEY}", "{{ api_key }}", ""])
def test_transformed_placeholders_are_restored(placeholder: str) -> None:
    files, report = rebase_text_files([("src/settings.py", f'API_KEY = "{placeholder}"\n')], payload())
    assert "TEST_ONLY_original" in files[0][1]
    assert report.values_applied == 1 and report.values_unmatched == 0

def test_original_marker_is_restored() -> None:
    token = "a" * 32
    files, report = rebase_text_files([("src/settings.py", f"API_KEY=[[MDTK_SECRET_{token}]]")], payload())
    assert "TEST_ONLY_original" in files[0][1]
    assert report.values_applied == 1

def test_new_real_value_is_never_overwritten() -> None:
    files, report = rebase_text_files([("src/settings.py", 'API_KEY = "TEST_ONLY_new_ai_value_67890"\n')], payload())
    assert "new_ai_value" in files[0][1]
    assert report.values_applied == 0 and report.values_unmatched == 1

def test_unique_renamed_path_can_be_recovered() -> None:
    files, report = rebase_text_files([("renamed/settings.py", 'API_KEY = "YOUR_API_KEY"\n')], payload())
    assert "TEST_ONLY_original" in files[0][1]
    assert any("Recovered renamed path" in warning for warning in report.warnings)

def test_ambiguous_renamed_path_is_left_unchanged() -> None:
    files, report = rebase_text_files([
        ("one/settings.py", 'API_KEY = "YOUR_API_KEY"\n'),
        ("two/settings.py", 'API_KEY = "YOUR_API_KEY"\n'),
    ], payload(path="old/settings.py"))
    assert all("YOUR_API_KEY" in content for _, content in files)
    assert report.ambiguous_cases == 1 and report.values_unmatched == 1


def test_rebase_restores_private_key_auth_and_url_password() -> None:
    vault = {
        "version": 1,
        "redactions": {
            "1" * 32: "TEST_ONLY_KEY_LINE_1",
            "2" * 32: "TEST_ONLY_BEARER_TOKEN_1234",
            "3" * 32: "TEST_ONLY_DB_PASS",
        },
        "bindings": [
            {"token": "1" * 32, "path": "cert.txt", "key": "", "kind": "private_key"},
            {"token": "2" * 32, "path": "req.txt", "key": "", "kind": "authorization"},
            {"token": "3" * 32, "path": "db.txt", "key": "", "kind": "url_password"},
        ],
        "redacted_files": [],
        "sensitive_files": [],
        "binary_files": [],
    }
    files, report = rebase_text_files(
        [
            ("cert.txt", "-----BEGIN PRIVATE KEY-----\n[REDACTED]\n-----END PRIVATE KEY-----\n"),
            ("req.txt", "Authorization: Bearer [REDACTED]\n"),
            ("db.txt", "postgres://admin:[REDACTED]@db.example.com/app\n"),
        ],
        vault,
    )
    assert "TEST_ONLY_KEY_LINE_1" in files[0][1]
    assert "TEST_ONLY_BEARER_TOKEN_1234" in files[1][1]
    assert "TEST_ONLY_DB_PASS" in files[2][1]
    assert report.values_applied == 3 and report.values_unmatched == 0


def test_rebase_zip_and_run_rebase_restore_protected_files(tmp_path) -> None:
    import base64
    import zipfile
    from local_secrets import TestVaultBackend, save_secrets
    from rebase_secrets import run_rebase
    from secrets_rebase import rebase_zip_file

    source_zip = tmp_path / "ai.zip"
    with zipfile.ZipFile(source_zip, "w") as archive:
        archive.writestr("config.py", 'API_KEY = "YOUR_API_KEY"\n')
        archive.writestr("logo.bin", b"\x00\x01bin")
    vault_path = tmp_path / "project.secrets"
    save_secrets(
        vault_path,
        {
            "version": 1,
            "redactions": {"a" * 32: "TEST_ONLY_ZIP_SECRET_123"},
            "bindings": [{"token": "a" * 32, "path": "config.py", "key": "api_key", "kind": "assignment"}],
            "redacted_files": [],
            "sensitive_files": [{"name": ".env", "bytes": base64.b64encode(b"SECRET=1\n").decode("ascii")}],
            "binary_files": [],
        },
        backend=TestVaultBackend(),
    )
    out_zip = tmp_path / "rebased.zip"
    report = rebase_zip_file(source_zip, out_zip, vault_path, vault_backend=TestVaultBackend())
    assert report.values_applied == 1 and report.sensitive_files_added == 1
    with zipfile.ZipFile(out_zip) as archive:
        assert b"TEST_ONLY_ZIP_SECRET_123" in archive.read("config.py")
        assert archive.read(".env") == b"SECRET=1\n"

    with pytest.raises(FileNotFoundError):
        run_rebase(tmp_path / "missing.zip", vault_path)
    with pytest.raises(ValueError, match=".md or .zip"):
        bad = tmp_path / "bad.txt"
        bad.write_text("x", encoding="utf-8")
        run_rebase(bad, vault_path)
