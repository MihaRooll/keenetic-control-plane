"""Credential vault port — no plaintext read API."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class CredentialRefHandle:
    """Opaque handle returned to callers. Never includes secret material."""

    credential_ref_id: str
    kind: str
    provider: str
    provider_locator: str


class CredentialVaultPort(Protocol):
    def create(self, *, kind: str, secret: str) -> CredentialRefHandle:
        """Store secret; return opaque metadata handle only."""
        ...

    def use(self, credential_ref_id: str) -> str:
        """Resolve secret for in-process adapter use only. Not exposed via HTTP API."""
        ...

    def rotate(self, credential_ref_id: str, *, secret: str) -> CredentialRefHandle:
        ...

    def revoke(self, credential_ref_id: str) -> None:
        ...

    def delete(self, credential_ref_id: str) -> None:
        ...
