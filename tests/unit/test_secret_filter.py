from __future__ import annotations
import pytest
from secret_filter import FilterReport, is_sensitive_path, redact_secret_values

@pytest.mark.parametrize("line", [
    'key = "id"', 'sort_key = "asc"', 'auth = "oauth2"', 'password = None',
    'token = False', 'key = 0', 'secret = null', 'token = ""',
    'token = os.getenv("TOKEN")', 'token = getenv("TOKEN")',
    'token = process.env.TOKEN', 'password = input("Password")',
    'password = getpass.getpass()', 'token = ${TOKEN}',
])
def test_functional_values_are_not_redacted(line: str) -> None:
    redacted, count = redact_secret_values(line)
    assert redacted == line
    assert count == 0

@pytest.mark.parametrize("line", [
    'API_KEY = "TEST_ONLY_credential_value_12345"',
    'client_secret: TEST_ONLY_client_secret_12345',
    'access_token = "TEST_ONLY_access_token_12345"',
    'database_password = "TEST_ONLY_database_password_12345"',
    'password = "TEST_ONLY_password_12345"',
])
def test_high_confidence_names_redact(line: str) -> None:
    report = FilterReport()
    redacted, count = redact_secret_values(line, source_path="config.py", report=report)
    assert "TEST_ONLY" not in redacted
    assert count == report.high_confidence == 1
    assert report.contextual == 0
    assert report.files_affected == {"config.py"}

@pytest.mark.parametrize("line", [
    'token = "TEST_ONLY_contextual_token_12345"',
    'key = "TEST_ONLY_contextual_key_12345"',
])
def test_generic_names_require_credential_like_values(line: str) -> None:
    report = FilterReport()
    redacted, count = redact_secret_values(line, source_path="settings.yaml", report=report)
    assert "TEST_ONLY" not in redacted
    assert count == report.contextual == 1

@pytest.mark.parametrize("path", [".env", ".aws/credentials", "id_rsa", "config/secrets/private.txt"])
def test_sensitive_paths(path: str) -> None:
    assert is_sensitive_path(path)

@pytest.mark.parametrize("path", [".env.example", "src/token_service.py", "auth/password_reset.ts", "docs/token_instructions.pdf"])
def test_non_sensitive_functional_paths(path: str) -> None:
    assert not is_sensitive_path(path)

def test_private_key_preserves_line_count_and_never_reports_material() -> None:
    content = "before\n-----BEGIN PRIVATE KEY-----\nTEST_ONLY_LINE_ONE\nTEST_ONLY_LINE_TWO\n-----END PRIVATE KEY-----\nafter\n"
    report = FilterReport()
    redacted, count = redact_secret_values(content, source_path="key.pem.txt", report=report)
    assert len(redacted.splitlines()) == len(content.splitlines())
    assert "TEST_ONLY_LINE" not in redacted
    assert count == 1
    assert all("TEST_ONLY_LINE" not in warning for warning in report.warnings)

def test_provider_token_is_high_confidence() -> None:
    value = "ghp_" + "A" * 24
    report = FilterReport()
    redacted, count = redact_secret_values(f"value = '{value}'", report=report)
    assert value not in redacted
    assert count == report.high_confidence == 1


@pytest.mark.parametrize("snippet", [
    "Manual Windows GUI startup, basic conversion, rebase dialog",
    "Use Bearer authentication for API access",
    'if kind == "private_key":\n    def restore_line():\n        pass\n',
    'API_KEY = "[[MDTK_SECRET_' + ("a" * 32) + ']]"',
    'API_KEY=[[MDTK_SECRET_{token}]]',
])
def test_prose_multiline_and_markers_are_not_redacted(snippet: str) -> None:
    redacted, count = redact_secret_values(snippet)
    assert redacted == snippet
    assert count == 0


def test_unquoted_assignment_inside_quotes_preserves_closing_quote() -> None:
    snippet = "'client_secret: TEST_ONLY_client_secret_12345',"
    redacted, count = redact_secret_values(snippet, secret_values={}, source_path="sample.py")
    assert count == 1
    assert "TEST_ONLY" not in redacted
    assert redacted.endswith("',")


def test_real_bearer_and_basic_tokens_redact() -> None:
    snippet = "Authorization: Basic dXNlcjpwYXNzd29yZA==\nAuthorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig"
    redacted, count = redact_secret_values(snippet, secret_values={}, source_path="headers.txt")
    assert count == 2
    assert "dXNlcjpwYXNzd29yZA==" not in redacted
    assert "eyJhbGciOiJIUzI1NiJ9" not in redacted


@pytest.mark.parametrize("snippet, leaked", [
    ('password = "Winter26!"', "Winter26!"),
    ("Authorization: Bearer abcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyz"),
])
def test_audit_regression_literals_are_redacted(snippet: str, leaked: str) -> None:
    redacted, count = redact_secret_values(snippet, secret_values={}, source_path="config.txt")
    assert count == 1
    assert leaked not in redacted


def test_ambiguous_url_and_triple_quoted_secrets() -> None:
    report = FilterReport()
    ambiguous_line = 'token = "abc"'
    redacted, count = redact_secret_values(ambiguous_line, secret_values={}, source_path="cfg.py", report=report)
    assert redacted == ambiguous_line and count == 0
    assert any("Ambiguous" in w for w in report.warnings)

    multi = 'api_key = """TEST_ONLY_multiline_secret_value"""\nurl = https://user:TEST_ONLY_url_pass@example.com/db\n'
    redacted_multi, count_multi = redact_secret_values(multi, secret_values={}, source_path="cfg.py", report=report)
    assert count_multi == 2
    assert "TEST_ONLY_multiline_secret_value" not in redacted_multi
    assert "TEST_ONLY_url_pass" not in redacted_multi
