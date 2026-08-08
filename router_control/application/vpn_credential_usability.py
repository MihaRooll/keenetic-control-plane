"""VPN WireGuard secret-ref usability checks (fail-closed on missing/revoked)."""

from __future__ import annotations

from typing import Any, Protocol


class CredentialRefStore(Protocol):
    def get_credential_ref(self, credential_ref_id: str) -> Any | None: ...


def credential_ref_usable(store: CredentialRefStore, ref_id: str | None) -> bool:
    if not ref_id:
        return False
    row = store.get_credential_ref(ref_id)
    if row is None:
        return False
    if row["revoked_at"] is not None:
        return False
    return True


def vpn_secret_refs_usable(
    store: CredentialRefStore,
    private_ref: str | None,
    psk_ref: str | None,
) -> bool:
    if not credential_ref_usable(store, private_ref):
        return False
    if psk_ref is not None and not credential_ref_usable(store, psk_ref):
        return False
    return True


__all__ = ["credential_ref_usable", "vpn_secret_refs_usable"]
