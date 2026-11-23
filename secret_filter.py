"""Conservative filtering for common secret files and credential values."""

from __future__ import annotations

import re
from uuid import uuid4
from pathlib import PurePosixPath, PureWindowsPath


SENSITIVE_DIRECTORIES = {
    ".aws", ".docker", ".gnupg", ".kube", ".ssh", "secrets", "secret",
}
SENSITIVE_BASENAMES = {
    ".envrc", ".git-credentials", ".netrc", ".npmrc", ".pypirc",
    "application_default_credentials.json", "credentials", "credentials.db",
    "id_dsa", "id_ecdsa", "id_ed25519", "id_rsa", "id_xmss",
    "secret", "secrets", "terraform.tfstate", "terraform.tfstate.backup",
    "tokens.db", "service-account.json", "service_account.json",
}
SENSITIVE_SUFFIXES = {
    ".env", ".key", ".pem", ".p12", ".pfx", ".ppk", ".jks",
    ".keystore", ".kdbx", ".tfstate", ".tfvars", ".ovpn",
}
SAFE_ENV_TEMPLATES = {".env.example", ".env.sample", ".env.template", ".env.dist"}
CODE_OR_DOC_EXTENSIONS = {
    ".c", ".cc", ".cpp", ".cs", ".css", ".dart", ".go", ".h", ".hpp",
    ".html", ".java", ".js", ".jsx", ".kt", ".lua", ".md", ".php",
    ".py", ".rb", ".rs", ".scss", ".sh", ".sql", ".swift", ".ts",
    ".tsx", ".bat", ".cmd", ".ps1", ".pdf",
}
SENSITIVE_WORDS = re.compile(
    r"(?:^|[._-])(?:secret|secrets|credential|credentials|password|passwd|token)(?:$|[._-])",
    re.IGNORECASE,
)
GENERATED_OR_DEPENDENCY_DIRECTORIES = {
    ".git", ".gradle", ".mypy_cache", ".next", ".nuxt", ".pytest_cache",
    ".ruff_cache", ".tox", ".turbo", ".venv", "__pycache__", "bower_components",
    "build", "coverage", "dist", "node_modules", "pods", "site-packages",
    "target", "venv", "virtualenv",
}

_KEY_VALUE_RE = re.compile(
    r"(?i)(?P<prefix>(?<![A-Za-z0-9])[\"']?(?:[A-Za-z0-9]+[_-])*"
    r"(?:api[_-]?key|access[_-]?key|secret|client[_-]?secret|"
    r"auth(?:orization)?|password|passwd|token|private[_-]?key|"
    r"credential|connection[_-]?string|subscription[_-]?key|key)"
    r"[\"']?\s*[:=]\s*)"
    r"(?P<value>\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;#}\]]+)"
)
_BEARER_RE = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}")
_URL_PASSWORD_RE = re.compile(r"(?i)(://[^:/\s]+:)[^@/\s]+(@)")
_COMMON_TOKEN_RES = (
    re.compile(r"\b(?:sk|rk)-(?:live|test)-[A-Za-z0-9]{12,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
)
_PRIVATE_KEY_RE = re.compile(
    r"(-----BEGIN (?P<label>[A-Z0-9 ]*PRIVATE KEY)-----)(.*?)"
    r"(-----END (?P=label)-----)",
    re.DOTALL,
)
_PLACEHOLDER_RE = re.compile(
    r"(?i)(?:your[_ -]|example|sample|placeholder|redacted|changeme|"
    r"change[_ -]me|insert[_ -]|replace[_ -]|<[^>]+>|\$\{|\{\{)"
)


def is_sensitive_path(name: str) -> bool:
    """Return True for common credential/config files and secret directories."""
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    windows_path = PureWindowsPath(name)
    parts = [part.casefold() for part in (*path.parts, *windows_path.parts)]
    basename = parts[-1] if parts else ""

    if any(part in SENSITIVE_DIRECTORIES for part in parts):
        return True
    if basename in SENSITIVE_BASENAMES:
        return True
    if basename.startswith(".env") and basename not in SAFE_ENV_TEMPLATES:
        return True
    if any(basename.endswith(suffix) for suffix in SENSITIVE_SUFFIXES):
        return True
    suffix = path.suffix.casefold()
    if suffix in CODE_OR_DOC_EXTENSIONS:
        return False
    stem = basename.rsplit(".", 1)[0] if "." in basename else basename
    return bool(SENSITIVE_WORDS.search(stem))


def is_generated_or_dependency_path(name: str) -> bool:
    """Return True when a path is inside common generated or dependency trees."""
    normalized = name.replace("\\", "/")
    components = PurePosixPath(normalized).parts
    return any(part.casefold() in GENERATED_OR_DEPENDENCY_DIRECTORIES for part in components)


def redact_secret_values(
    content: str,
    *,
    secret_values: dict[str, str] | None = None,
    secret_bindings: list[dict[str, str]] | None = None,
    source_path: str | None = None,
) -> tuple[str, int]:
    """Redact secrets, optionally recording reversible, unique placeholders."""
    redacted = 0

    def placeholder(
        value: str,
        *,
        kind: str,
        key: str = "",
    ) -> str:
        if secret_values is None:
            return "[REDACTED]"
        token = uuid4().hex
        secret_values[token] = value
        if secret_bindings is not None and source_path is not None:
            secret_bindings.append(
                {"token": token, "path": source_path, "key": key, "kind": kind}
            )
        return f"[[MDTK_SECRET_{token}]]"

    def assignment_key(prefix: str) -> str:
        match = re.search(r"([A-Za-z0-9_-]+)[\"']?\s*[:=]\s*$", prefix)
        return match.group(1).casefold() if match else ""

    def replace_assignment(match: re.Match[str]) -> str:
        nonlocal redacted
        value = match.group("value")
        if value[:1] in {'"', "'"}:
            quote = value[0]
            inner = value[1:-1]
            if not inner or _PLACEHOLDER_RE.search(inner):
                return match.group(0)
            redacted += 1
            return (
                f"{match.group('prefix')}{quote}"
                f"{placeholder(inner, kind='assignment', key=assignment_key(match.group('prefix')))}"
                f"{quote}"
            )
        # Keep references and expressions useful in code; redact literal-like values.
        if value.startswith(("$", "(", "{", "os.", "process.", "getenv(", "getpass(", "input(")):
            return match.group(0)
        if not value or _PLACEHOLDER_RE.search(value):
            return match.group(0)
        redacted += 1
        return (
            f"{match.group('prefix')}"
            f"{placeholder(value, kind='assignment', key=assignment_key(match.group('prefix')))}"
        )

    def replace_private_key(match: re.Match[str]) -> str:
        nonlocal redacted
        redacted += 1
        # Redact each material line rather than replacing the whole block, so
        # source line numbers and surrounding code remain stable in the export.
        body = re.sub(
            r"[^\r\n]+",
            lambda line: placeholder(line.group(0), kind="private_key"),
            match.group(3),
        )
        return f"{match.group(1)}{body}{match.group(4)}"

    content = _PRIVATE_KEY_RE.sub(replace_private_key, content)
    content = _KEY_VALUE_RE.sub(replace_assignment, content)

    def replace_bearer(match: re.Match[str]) -> str:
        nonlocal redacted
        redacted += 1
        return (
            f"{match.group(1)} "
            f"{placeholder(match.group(0).split(None, 1)[1], kind='authorization')}"
        )

    content = _BEARER_RE.sub(replace_bearer, content)

    def replace_url_password(match: re.Match[str]) -> str:
        nonlocal redacted
        redacted += 1
        password = match.group(0)[len(match.group(1)) : -len(match.group(2))]
        return f"{match.group(1)}{placeholder(password, kind='url_password')}{match.group(2)}"

    content = _URL_PASSWORD_RE.sub(replace_url_password, content)
    for pattern in _COMMON_TOKEN_RES:
        content, count = pattern.subn(
            lambda match: placeholder(match.group(0), kind="token"), content
        )
        redacted += count
    return content, redacted
