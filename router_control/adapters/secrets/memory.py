"""In-memory vault for tests and offline composition."""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field

from router_control.ports.vault import CredentialRefHandle


class VaultError(Exception):
    pass


@dataclass
class MemoryVault:
    provider: str = "Memory.Test"
    _secrets: dict[str, str] = field(default_factory=dict)
    _kinds: dict[str, str] = field(default_factory=dict)
    _revoked: set[str] = field(default_factory=set)

    def create(self, *, kind: str, secret: str) -> CredentialRefHandle:
        if not secret:
            raise VaultError("secret must be non-empty")
        ref_id = f"cred_{secrets.token_hex(16)}"
        locator = f"mem:{ref_id}"
        self._secrets[ref_id] = secret
        self._kinds[ref_id] = kind
        return CredentialRefHandle(
            credential_ref_id=ref_id,
            kind=kind,
            provider=self.provider,
            provider_locator=locator,
        )

    def use(self, credential_ref_id: str) -> str:
        if credential_ref_id in self._revoked:
            raise VaultError("credential revoked")
        try:
            return self._secrets[credential_ref_id]
        except KeyError as exc:
            raise VaultError("credential not found") from exc

    def rotate(self, credential_ref_id: str, *, secret: str) -> CredentialRefHandle:
        if credential_ref_id not in self._secrets:
            raise VaultError("credential not found")
        if credential_ref_id in self._revoked:
            raise VaultError("credential revoked")
        if not secret:
            raise VaultError("secret must be non-empty")
        self._secrets[credential_ref_id] = secret
        kind = self._kinds[credential_ref_id]
        return CredentialRefHandle(
            credential_ref_id=credential_ref_id,
            kind=kind,
            provider=self.provider,
            provider_locator=f"mem:{credential_ref_id}",
        )

    def revoke(self, credential_ref_id: str) -> None:
        if credential_ref_id not in self._secrets:
            raise VaultError("credential not found")
        self._revoked.add(credential_ref_id)

    def delete(self, credential_ref_id: str) -> None:
        self._secrets.pop(credential_ref_id, None)
        self._kinds.pop(credential_ref_id, None)
        self._revoked.discard(credential_ref_id)
