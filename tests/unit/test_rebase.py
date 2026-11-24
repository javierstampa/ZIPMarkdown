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
