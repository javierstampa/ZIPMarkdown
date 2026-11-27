"""Conservative, reportable secret filtering for ZIPMarkdown exports."""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import PurePosixPath, PureWindowsPath
from uuid import uuid4

SENSITIVE_DIRECTORIES = {".aws", ".docker", ".gnupg", ".kube", ".ssh", "secrets", "secret"}
SENSITIVE_BASENAMES = {
    ".envrc", ".git-credentials", ".netrc", ".npmrc", ".pypirc",
    "application_default_credentials.json", "credentials", "credentials.db",
    "id_dsa", "id_ecdsa", "id_ed25519", "id_rsa", "id_xmss", "secret", "secrets",
    "terraform.tfstate", "terraform.tfstate.backup", "tokens.db",
    "service-account.json", "service_account.json",
}
SENSITIVE_SUFFIXES = {".env", ".key", ".pem", ".p12", ".pfx", ".ppk", ".jks", ".keystore", ".kdbx", ".tfstate", ".tfvars", ".ovpn"}
SAFE_ENV_TEMPLATES = {".env.example", ".env.sample", ".env.template", ".env.dist"}
CODE_OR_DOC_EXTENSIONS = {
    ".c", ".cc", ".cpp", ".cs", ".css", ".dart", ".go", ".h", ".hpp", ".html",
    ".java", ".js", ".jsx", ".kt", ".lua", ".md", ".php", ".py", ".rb", ".rs",
    ".scss", ".sh", ".sql", ".swift", ".ts", ".tsx", ".bat", ".cmd", ".ps1", ".pdf",
}
GENERATED_OR_DEPENDENCY_DIRECTORIES = {
    ".git", ".gradle", ".mypy_cache", ".next", ".nuxt", ".pytest_cache", ".ruff_cache",
    ".tox", ".turbo", ".venv", "__pycache__", "bower_components", "build", "coverage",
    "dist", "node_modules", "pods", "site-packages", "target", "venv", "virtualenv",
}
SENSITIVE_WORDS = re.compile(r"(?:^|[._-])(?:secret|secrets|credential|credentials|password|passwd|token)(?:$|[._-])", re.I)

HIGH_CONFIDENCE_KEYS = {
    "api_key", "apikey", "private_key", "privatekey", "client_secret", "clientsecret",
    "access_token", "accesstoken", "refresh_token", "refreshtoken", "database_password",
    "db_password", "authorization_header", "connection_string", "subscription_key",
    "aws_secret_access_key", "secret_access_key", "password", "passwd",
}
GENERIC_KEYS = {"key", "auth", "authorization", "token", "secret"}
TRIVIAL_VALUES = {"", "none", "null", "true", "false", "0", "1", "oauth2", "bearer", "asc", "desc", "id", "undefined", "nil"}
KNOWN_PREFIXES = ("sk-", "rk-", "github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "AKIA", "AIza", "xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-")

_ASSIGNMENT_RE = re.compile(
    r"(?im)(?P<prefix>(?<![A-Za-z0-9])[\"']?(?P<key>[A-Za-z][A-Za-z0-9_.-]*)[\"']?[ \t]*[:=][ \t]*)"
    r"(?P<value>\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;#}\]\"']+)"
)
_TRIPLE_QUOTED_RE = re.compile(
    r"(?is)(?P<prefix>(?<![A-Za-z0-9])[\"']?(?P<key>[A-Za-z][A-Za-z0-9_.-]*)[\"']?[ \t]*[:=][ \t]*)"
    r"(?P<quote>\"\"\"|''')(?P<value>.*?)(?P=quote)"
)
_BEARER_RE = re.compile(r"(?i)\b(Bearer|Basic)[ \t]+([A-Za-z0-9._~+/=-]{8,})")
_AUTH_HEADER_RE = re.compile(
    r"(?im)(?P<prefix>^[ \t]*Authorization[ \t]*:[ \t]*(?:Bearer|Basic)[ \t]+)"
    r"(?P<token>[A-Za-z0-9._~+/=-]{8,})"
)
_URL_PASSWORD_RE = re.compile(r"(?i)(://[^:/\s]+:)([^@/\s]+)(@)")
_PROVIDER_RES = (
    re.compile(r"\b(?:sk|rk)-(?:live|test)-[A-Za-z0-9]{12,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
)
_PRIVATE_KEY_RE = re.compile(r"(-----BEGIN (?P<label>[A-Z0-9 ]*PRIVATE KEY)-----)(.*?)(-----END (?P=label)-----)", re.S)
_PLACEHOLDER_RE = re.compile(r"(?i)(?:your[_ -]|example|sample|placeholder|redacted|changeme|change[_ -]me|insert[_ -]|replace[_ -]|<[^>]+>|\$\{|\{\{|\[\[MDTK_SECRET_)")
_REFERENCE_RE = re.compile(r"(?i)^(?:\$[A-Za-z_{]|%[A-Za-z_]|\$\{|\{\{|[A-Za-z_][A-Za-z0-9_.]*\s*\(|(?:os\.)?getenv\s*\(|process\.env(?:\.|\[)|input\s*\(|getpass(?:\.getpass)?\s*\()")


@dataclass
class FilterReport:
    total_detections: int = 0
    high_confidence: int = 0
    contextual: int = 0
    files_affected: set[str] = field(default_factory=set)
    warnings: list[str] = field(default_factory=list)

    def record(self, confidence: str, source_path: str | None) -> None:
        self.total_detections += 1
        if confidence == "high":
            self.high_confidence += 1
        else:
            self.contextual += 1
        if source_path:
            self.files_affected.add(source_path)

    def ambiguous(self, key: str, source_path: str | None) -> None:
        location = source_path or "<unknown>"
        message = f"Ambiguous credential-like assignment left unchanged in {location} (key: {key})."
        if message not in self.warnings:
            self.warnings.append(message)


def is_sensitive_path(name: str) -> bool:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    windows_path = PureWindowsPath(name)
    parts = [part.casefold() for part in (*path.parts, *windows_path.parts)]
    basename = parts[-1] if parts else ""
    if any(part in SENSITIVE_DIRECTORIES for part in parts) or basename in SENSITIVE_BASENAMES:
        return True
    if basename.startswith(".env") and basename not in SAFE_ENV_TEMPLATES:
        return True
    if any(basename.endswith(suffix) for suffix in SENSITIVE_SUFFIXES):
        return True
    if path.suffix.casefold() in CODE_OR_DOC_EXTENSIONS:
        return False
    stem = basename.rsplit(".", 1)[0] if "." in basename else basename
    return bool(SENSITIVE_WORDS.search(stem))


def is_generated_or_dependency_path(name: str) -> bool:
    return any(part.casefold() in GENERATED_OR_DEPENDENCY_DIRECTORIES for part in PurePosixPath(name.replace("\\", "/")).parts)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _clean_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", key.casefold()).strip("_")


def _is_nonliteral_or_safe(value: str) -> bool:
    stripped = value.strip()
    inner = stripped[1:-1] if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in {'\"', "'"} else stripped
    candidate = inner.strip()
    return (
        candidate.casefold() in TRIVIAL_VALUES
        or bool(_PLACEHOLDER_RE.search(candidate))
        or bool(_REFERENCE_RE.match(candidate))
    )


def _confidence(key: str, value: str) -> str | None:
    if _is_nonliteral_or_safe(value):
        return None
    inner = value[1:-1] if len(value) >= 2 and value[0] == value[-1] and value[0] in {'\"', "'"} else value
    normalized_key = _clean_key(key)
    if any(inner.startswith(prefix) for prefix in KNOWN_PREFIXES):
        return "high"
    if normalized_key in HIGH_CONFIDENCE_KEYS:
        return "high"
    if normalized_key in GENERIC_KEYS:
        if len(inner) >= 12 and shannon_entropy(inner) >= 3.0 and any(c.isalnum() for c in inner):
            return "contextual"
        return "ambiguous"
    return None


def redact_secret_values(
    content: str,
    *,
    secret_values: dict[str, str] | None = None,
    secret_bindings: list[dict[str, str]] | None = None,
    source_path: str | None = None,
    report: FilterReport | None = None,
) -> tuple[str, int]:
    """Redact only high-confidence or credential-like contextual literals."""
    redacted = 0

    def placeholder(value: str, *, kind: str, key: str = "") -> str:
        if secret_values is None:
            return "[REDACTED]"
        token = uuid4().hex
        secret_values[token] = value
        if secret_bindings is not None and source_path is not None:
            secret_bindings.append({"token": token, "path": source_path, "key": key, "kind": kind})
        return f"[[MDTK_SECRET_{token}]]"

    def note(confidence: str) -> None:
        nonlocal redacted
        redacted += 1
        if report is not None:
            report.record(confidence, source_path)

    def replace_private_key(match: re.Match[str]) -> str:
        note("high")
        body = re.sub(r"[^\r\n]+", lambda line: placeholder(line.group(0), kind="private_key"), match.group(3))
        return f"{match.group(1)}{body}{match.group(4)}"

    content = _PRIVATE_KEY_RE.sub(replace_private_key, content)

    def replace_triple(match: re.Match[str]) -> str:
        confidence = _confidence(match.group("key"), match.group("value"))
        if confidence in {None, "ambiguous"}:
            if confidence == "ambiguous" and report is not None:
                report.ambiguous(match.group("key"), source_path)
            return match.group(0)
        note(confidence)
        return f"{match.group('prefix')}{match.group('quote')}{placeholder(match.group('value'), kind='assignment', key=_clean_key(match.group('key')))}{match.group('quote')}"

    content = _TRIPLE_QUOTED_RE.sub(replace_triple, content)

    def replace_assignment(match: re.Match[str]) -> str:
        value = match.group("value")
        confidence = _confidence(match.group("key"), value)
        if confidence in {None, "ambiguous"}:
            if confidence == "ambiguous" and report is not None:
                report.ambiguous(match.group("key"), source_path)
            return match.group(0)
        quote = value[0] if len(value) >= 2 and value[0] == value[-1] and value[0] in {'\"', "'"} else ""
        inner = value[1:-1] if quote else value
        note(confidence)
        marker = placeholder(inner, kind="assignment", key=_clean_key(match.group("key")))
        return f"{match.group('prefix')}{quote}{marker}{quote}"

    content = _ASSIGNMENT_RE.sub(replace_assignment, content)

    def replace_auth_header(match: re.Match[str]) -> str:
        token = match.group("token")
        if _is_nonliteral_or_safe(token):
            return match.group(0)
        note("high")
        return f"{match.group('prefix')}{placeholder(token, kind='authorization')}"

    content = _AUTH_HEADER_RE.sub(replace_auth_header, content)

    def replace_auth(match: re.Match[str]) -> str:
        token = match.group(2)
        if _is_nonliteral_or_safe(token) or (token.isalpha() and (token.islower() or token.istitle())):
            return match.group(0)
        note("high")
        return f"{match.group(1)} {placeholder(token, kind='authorization')}"

    content = _BEARER_RE.sub(replace_auth, content)

    def replace_url(match: re.Match[str]) -> str:
        if _is_nonliteral_or_safe(match.group(2)):
            return match.group(0)
        note("high")
        return f"{match.group(1)}{placeholder(match.group(2), kind='url_password')}{match.group(3)}"

    content = _URL_PASSWORD_RE.sub(replace_url, content)
    for pattern in _PROVIDER_RES:
        def replace_provider(match: re.Match[str]) -> str:
            note("high")
            return placeholder(match.group(0), kind="token")
        content = pattern.sub(replace_provider, content)
    return content, redacted
