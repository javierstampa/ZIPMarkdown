"""Lazy, injectable vault backends for local reversible ZIPMarkdown data."""
from __future__ import annotations

import ctypes
import json
import os
from abc import ABC, abstractmethod
from ctypes import wintypes
from pathlib import Path
from typing import Any

from atomic_utils import atomic_write_bytes

# Kept for compatibility with vaults created before the public ZIPMarkdown name.
MAGIC = b"MDTK-SECRETS\x01"
TEST_MAGIC = b"ZIPMARKDOWN-TEST-VAULT\x01"
CRYPTPROTECT_UI_FORBIDDEN = 0x01


class VaultUnavailableError(OSError):
    pass


class VaultBackend(ABC):
    @abstractmethod
    def protect(self, data: bytes) -> bytes: ...

    @abstractmethod
    def unprotect(self, data: bytes) -> bytes: ...


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


class DPAPIBackend(VaultBackend):
    """Windows per-user DPAPI backend, initialized only when first used."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise VaultUnavailableError(
                "A protected vault is required, but Windows DPAPI is unavailable on this platform. "
                "Use Windows or process a project that does not contain protected data."
            )

    def _crypt(self, data: bytes, *, decrypt: bool) -> bytes:
        if not data:
            raise ValueError("a vault payload cannot be empty")
        source_buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        source = _DataBlob(len(data), source_buffer)
        destination = _DataBlob()
        crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        function = crypt32.CryptUnprotectData if decrypt else crypt32.CryptProtectData
        description_type = ctypes.POINTER(wintypes.LPWSTR) if decrypt else wintypes.LPCWSTR
        function.argtypes = [
            ctypes.POINTER(_DataBlob), description_type, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_DataBlob),
        ]
        function.restype = wintypes.BOOL
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree.restype = ctypes.c_void_p
        description = wintypes.LPWSTR() if decrypt else "ZIPMarkdown local secrets"
        description_argument = ctypes.byref(description) if decrypt else description
        if not function(
            ctypes.byref(source), description_argument, None, None, None,
            CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(destination),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return ctypes.string_at(destination.pbData, destination.cbData)
        finally:
            if destination.pbData:
                kernel32.LocalFree(destination.pbData)
            if decrypt and description:
                kernel32.LocalFree(description)

    def protect(self, data: bytes) -> bytes:
        return self._crypt(data, decrypt=False)

    def unprotect(self, data: bytes) -> bytes:
        return self._crypt(data, decrypt=True)


class TestVaultBackend(VaultBackend):
    """Deterministic non-encrypting backend for unit tests only; never use in production."""
    __test__ = False

    def protect(self, data: bytes) -> bytes:
        return data

    def unprotect(self, data: bytes) -> bytes:
        return data


def default_backend() -> VaultBackend:
    return DPAPIBackend()


def secrets_path_for(markdown_path: Path) -> Path:
    return Path(markdown_path).with_suffix(".secrets")


def payload_requires_vault(payload: dict[str, Any]) -> bool:
    return any(payload.get(key) for key in ("redactions", "redacted_files", "sensitive_files", "binary_files"))


def _serialize(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")


def save_secrets(path: Path, payload: dict[str, Any], *, backend: VaultBackend | None = None) -> None:
    """Atomically write a protected vault. The default backend is resolved lazily."""
    selected = backend or default_backend()
    magic = TEST_MAGIC if isinstance(selected, TestVaultBackend) else MAGIC
    atomic_write_bytes(Path(path), magic + selected.protect(_serialize(payload)), mode=0o600)


def load_secrets(path: Path, *, backend: VaultBackend | None = None) -> dict[str, Any]:
    encrypted = Path(path).read_bytes()
    if encrypted.startswith(TEST_MAGIC):
        if not isinstance(backend, TestVaultBackend):
            raise ValueError("test vaults require an explicitly injected TestVaultBackend")
        protected = encrypted[len(TEST_MAGIC):]
        selected = backend
    elif encrypted.startswith(MAGIC):
        protected = encrypted[len(MAGIC):]
        selected = backend or default_backend()
    else:
        raise ValueError(f"the file is not a ZIPMarkdown vault: {path}")
    try:
        payload = json.loads(selected.unprotect(protected).decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("the vault is damaged or cannot be decrypted by this user") from error
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise ValueError("unsupported vault version")
    return payload
