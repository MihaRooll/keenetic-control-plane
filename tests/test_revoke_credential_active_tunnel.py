"""Revoke credential fail-closed when linked to active VPN tunnel assignment."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from router_control.adapters.secrets.memory import MemoryVault, VaultError
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie

_SYNTHETIC_SECRET = "aGVsbG8tdGhpcy1pcy1ub3QtYS1yZWFsLWF3Zy1rZXktbWF0ZXJpYWw="
_REVOKE_PATH = (
    "/api/router-control/v1/routers/{router_id}/credentials/{credential_ref_id}/revoke"
)


@pytest.fixture
def revoke_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ADAPTER_MODE", "fake")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    app = create_app(db_path=tmp_path / "revoke-active-tunnel.sqlite3", enable_worker=False)
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        client.store = app.state.host.runtime.store
        client.vault = app.state.host.runtime.vault
        yield client


def _seed_router(store: Any) -> str:
    site_id = store.create_site(display_name="Revoke Active Tunnel Lab")
    return store.enroll_router(
        site_id=site_id,
        display_name="Revoke Active Tunnel Router",
        vendor="Fake",
        model="M1",
        identity_fingerprint="digest:revoke-active-tunnel",
        host="127.0.0.1",
    )


def _seed_profile_with_active_tunnel(
    client: Any,
) -> tuple[str, str, str]:
    store = client.store
    vault: MemoryVault = client.vault
    router_id = _seed_router(store)
    handle = vault.create(kind="awg_private_key", secret=_SYNTHETIC_SECRET)
    cred_id = handle.credential_ref_id
    store.insert_credential_ref(
        router_id=router_id,
        kind=handle.kind,
        provider=handle.provider,
        provider_locator=handle.provider_locator,
        credential_ref_id=cred_id,
    )
    profile_id = store.import_profile(
        display_name="Active tunnel profile",
        vpn_kind="AmneziaWG",
        content_digest="digest-revoke-active-tunnel",
        metadata_json=json.dumps({"wg_id": "Wireguard5"}),
    )
    store.insert_profile_secret_refs(
        profile_id=profile_id,
        refs=[(cred_id, "PrivateKey")],
    )
    store.upsert_tunnel_assignment(
        router_id=router_id,
        profile_id=profile_id,
        desired_active=True,
    )
    return router_id, cred_id, profile_id


def _count_bundle_rows(store: Any) -> tuple[int, int, int]:
    ops = store.conn.execute("SELECT COUNT(*) FROM operations").fetchone()[0]
    idem = store.conn.execute("SELECT COUNT(*) FROM idempotency_records").fetchone()[0]
    jobs = store.conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
    return int(ops), int(idem), int(jobs)


def test_revoke_credential_refuses_active_tunnel_assignment(revoke_client: Any) -> None:
    router_id, cred_id, profile_id = _seed_profile_with_active_tunnel(revoke_client)
    store = revoke_client.store
    vault: MemoryVault = revoke_client.vault
    assert _count_bundle_rows(store) == (0, 0, 0)

    resp = revoke_client.post(
        _REVOKE_PATH.format(router_id=router_id, credential_ref_id=cred_id),
        headers={"Idempotency-Key": "revoke-active-tunnel"},
    )
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "credential.active_tunnel"
    assert _count_bundle_rows(store) == (0, 0, 0)

    active = store.get_active_tunnel_assignment(router_id)
    assert active is not None
    assert bool(active["desired_active"])
    assert str(active["profile_id"]) == profile_id

    cred = store.get_credential_ref(cred_id)
    assert cred is not None
    assert cred["revoked_at"] is None
    vault.use(cred_id)


def test_revoke_credential_succeeds_after_assignment_retired(revoke_client: Any) -> None:
    router_id, cred_id, _profile_id = _seed_profile_with_active_tunnel(revoke_client)
    store = revoke_client.store
    vault: MemoryVault = revoke_client.vault

    store.deactivate_tunnel_assignments(router_id)
    assert store.credential_ref_has_active_tunnel_assignment(cred_id) is False

    resp = revoke_client.post(
        _REVOKE_PATH.format(router_id=router_id, credential_ref_id=cred_id),
        headers={"Idempotency-Key": "revoke-after-retire"},
    )
    assert resp.status_code == 202

    cred = store.get_credential_ref(cred_id)
    assert cred is not None
    assert cred["revoked_at"] is not None
    with pytest.raises(VaultError, match="revoked"):
        vault.use(cred_id)
