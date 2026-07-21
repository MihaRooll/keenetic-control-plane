"""Windows DPAPI CurrentUser vault. Blobs stored outside SQLite."""

from __future__ import annotations

import os
import secrets
import sys
from dataclasses import dataclass, field
from pathlib import Path

from router_control.ports.vault import CredentialRefHandle

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes


class VaultError(Exception):
    pass


@dataclass
class WindowsDpapiVault:
    """CryptProtectData / CryptUnprotectData under CurrentUser scope."""

    root: Path
    provider: str = "DPAPI.CurrentUser"
    _kinds: dict[str, str] = field(default_factory=dict)
    _revoked: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        if sys.platform != "win32":
            raise VaultError("WindowsDpapiVault requires win32")
        self.root = Path(self.root)
        self.root.mkdir(parents=True, exist_ok=True)
        meta = self.root / "kinds.json"
        if meta.exists():
            import json

            self._kinds = json.loads(meta.read_text(encoding="utf-8"))
        for marker in self.root.glob("*.revoked"):
            self._revoked.add(marker.stem)

    def _save_kinds(self) -> None:
        import json

        (self.root / "kinds.json").write_text(
            json.dumps(self._kinds), encoding="utf-8"
        )

    def _blob_path(self, credential_ref_id: str) -> Path:
        return self.root / f"{credential_ref_id}.dpapi"

    def create(self, *, kind: str, secret: str) -> CredentialRefHandle:
        if not secret:
            raise VaultError("secret must be non-empty")
        ref_id = f"cred_{secrets.token_hex(16)}"
        locator = str(self._blob_path(ref_id))
        protected = _protect(secret.encode("utf-8"))
        self._blob_path(ref_id).write_bytes(protected)
        self._kinds[ref_id] = kind
        self._save_kinds()
        return CredentialRefHandle(
            credential_ref_id=ref_id,
            kind=kind,
            provider=self.provider,
            provider_locator=locator,
        )

    def use(self, credential_ref_id: str) -> str:
        if credential_ref_id in self._revoked:
            raise VaultError("credential revoked")
        path = self._blob_path(credential_ref_id)
        if not path.exists():
            raise VaultError("credential not found")
        return _unprotect(path.read_bytes()).decode("utf-8")

    def rotate(self, credential_ref_id: str, *, secret: str) -> CredentialRefHandle:
        if credential_ref_id not in self._kinds:
            raise VaultError("credential not found")
        if credential_ref_id in self._revoked:
            raise VaultError("credential revoked")
        if not secret:
            raise VaultError("secret must be non-empty")
        protected = _protect(secret.encode("utf-8"))
        self._blob_path(credential_ref_id).write_bytes(protected)
        kind = self._kinds[credential_ref_id]
        return CredentialRefHandle(
            credential_ref_id=credential_ref_id,
            kind=kind,
            provider=self.provider,
            provider_locator=str(self._blob_path(credential_ref_id)),
        )

    def revoke(self, credential_ref_id: str) -> None:
        if credential_ref_id not in self._kinds:
            raise VaultError("credential not found")
        self._revoked.add(credential_ref_id)
        (self.root / f"{credential_ref_id}.revoked").write_text("1", encoding="utf-8")

    def delete(self, credential_ref_id: str) -> None:
        path = self._blob_path(credential_ref_id)
        if path.exists():
            os.remove(path)
        self._kinds.pop(credential_ref_id, None)
        self._revoked.discard(credential_ref_id)
        self._save_kinds()


def _protect(data: bytes) -> bytes:
    if sys.platform != "win32":
        raise VaultError("DPAPI unavailable")

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    blob_in = DATA_BLOB(len(data), ctypes.create_string_buffer(data, len(data)))
    blob_out = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(blob_in),
        None,
        None,
        None,
        None,
        0,
        ctypes.byref(blob_out),
    ):
        raise VaultError("CryptProtectData failed")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


def _unprotect(data: bytes) -> bytes:
    if sys.platform != "win32":
        raise VaultError("DPAPI unavailable")

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    blob_in = DATA_BLOB(len(data), ctypes.create_string_buffer(data, len(data)))
    blob_out = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(blob_in),
        None,
        None,
        None,
        None,
        0,
        ctypes.byref(blob_out),
    ):
        raise VaultError("CryptUnprotectData failed")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)
