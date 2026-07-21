"""SLICE-5 CredentialVault tests."""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
from router_control.adapters.secrets.memory import MemoryVault, VaultError
from router_control.persistence.connection import open_database
from router_control.persistence.store import PersistenceStore


def test_memory_vault_roundtrip() -> None:
    vault = MemoryVault()
    handle = vault.create(kind="RouterManagementPassword", secret="s3cret-value")
    assert handle.credential_ref_id
    assert "s3cret" not in handle.provider_locator
    assert vault.use(handle.credential_ref_id) == "s3cret-value"
    rotated = vault.rotate(handle.credential_ref_id, secret="new-secret")
    assert rotated.credential_ref_id == handle.credential_ref_id
    assert vault.use(handle.credential_ref_id) == "new-secret"
    vault.revoke(handle.credential_ref_id)
    with pytest.raises(VaultError):
        vault.use(handle.credential_ref_id)


def test_no_plaintext_api_on_handle() -> None:
    handle = MemoryVault().create(kind="VpnPrivateKey", secret="pk-material")
    assert not hasattr(handle, "secret")
    assert "pk-material" not in repr(handle)


def test_credential_ref_metadata_only_in_sqlite(tmp_path: Path) -> None:
    vault = MemoryVault()
    handle = vault.create(kind="RouterManagementPassword", secret="db-must-not-see-this")
    conn = open_database(tmp_path / "v.sqlite3")
    store = PersistenceStore(conn)
    site = store.create_site(display_name="S", now=datetime(2026, 7, 21, tzinfo=UTC))
    rid = store.enroll_router(
        site_id=site,
        display_name="R",
        vendor="V",
        model="M",
        identity_fingerprint="digest:x",
        host="127.0.0.1",
        now=datetime(2026, 7, 21, tzinfo=UTC),
    )
    store.insert_credential_ref(
        router_id=rid,
        kind=handle.kind,
        provider=handle.provider,
        provider_locator=handle.provider_locator,
        credential_ref_id=handle.credential_ref_id,
        now=datetime(2026, 7, 21, tzinfo=UTC),
    )
    store.append_audit(
        action="credential.create",
        outcome="ok",
        router_id=rid,
        summary_redacted="ref created",
        now=datetime(2026, 7, 21, tzinfo=UTC),
    )
    dump = store.dump_text_for_secret_scan()
    assert "db-must-not-see-this" not in dump


@pytest.mark.skipif(sys.platform != "win32", reason="DPAPI is Windows-only")
def test_dpapi_roundtrip(tmp_path: Path) -> None:
    from router_control.adapters.secrets.dpapi import WindowsDpapiVault

    vault = WindowsDpapiVault(root=tmp_path / "secrets")
    handle = vault.create(kind="RouterManagementPassword", secret="dpapi-secret")
    assert vault.use(handle.credential_ref_id) == "dpapi-secret"
    vault.rotate(handle.credential_ref_id, secret="dpapi-rotated")
    assert vault.use(handle.credential_ref_id) == "dpapi-rotated"


@pytest.mark.skipif(sys.platform != "win32", reason="DPAPI is Windows-only")
def test_dpapi_revoke_durable_across_reload(tmp_path: Path) -> None:
    from router_control.adapters.secrets.dpapi import VaultError, WindowsDpapiVault

    root = tmp_path / "secrets"
    vault = WindowsDpapiVault(root=root)
    handle = vault.create(kind="RouterManagementPassword", secret="dpapi-secret")
    vault.revoke(handle.credential_ref_id)

    reloaded = WindowsDpapiVault(root=root)
    with pytest.raises(VaultError, match="revoked"):
        reloaded.use(handle.credential_ref_id)
    with pytest.raises(VaultError, match="revoked"):
        reloaded.rotate(handle.credential_ref_id, secret="new-secret")
