"""VPN catalog remove host API tests (offline only)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from router_control.adapters.secrets.memory import MemoryVault, VaultError
from router_control.persistence.errors import NotFoundError
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie

_REMOVE_PATH = "/api/router-control/v1/vpn-profiles/{profile_id}/remove"
_ACTIVATE_PATH = "/api/router-control/v1/vpn-profiles/{profile_id}/activate"
_LIST_PATH = "/api/router-control/v1/vpn-profiles"
_TEST_WG = "Wireguard5"
_SYNTHETIC_SECRET = "aGVsbG8tdGhpcy1pcy1ub3QtYS1yZWFsLWF3Zy1rZXktbWF0ZXJpYWw="
_TEST_SEALED_APPLY_LEASE_OWNER = "vpn-catalog-remove-test-lease"
_ACTIVATE_IN_PROGRESS_MESSAGE = (
    "Сейчас идёт подключение этого VPN — подождите и повторите."
)


@pytest.fixture
def remove_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ADAPTER_MODE", "fake")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    app = create_app(db_path=tmp_path / "vpn-catalog-remove.sqlite3", enable_worker=False)
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        client.store = app.state.host.runtime.store
        client.vault = app.state.host.runtime.vault
        yield client


def _seed_router(store: Any) -> str:
    site_id = store.create_site(display_name="Catalog Remove Lab")
    return store.enroll_router(
        site_id=site_id,
        display_name="Catalog Remove Router",
        vendor="Fake",
        model="M1",
        identity_fingerprint="digest:catalog-remove",
        host="127.0.0.1",
    )


def _seed_profile(store: Any, *, display_name: str) -> str:
    return store.import_profile(
        display_name=display_name,
        vpn_kind="AmneziaWG",
        content_digest=f"digest-{display_name}",
        metadata_json=json.dumps({"wg_id": _TEST_WG}),
    )


def _seed_profile_with_secret(
    client: Any,
    *,
    display_name: str,
    shared_cred_id: str | None = None,
) -> tuple[str, str]:
    store = client.store
    vault: MemoryVault = client.vault
    router_id = _seed_router(store)
    if shared_cred_id is None:
        handle = vault.create(kind="awg_private_key", secret=_SYNTHETIC_SECRET)
        cred_id = handle.credential_ref_id
        store.insert_credential_ref(
            router_id=router_id,
            kind=handle.kind,
            provider=handle.provider,
            provider_locator=handle.provider_locator,
            credential_ref_id=cred_id,
        )
    else:
        cred_id = shared_cred_id
    profile_id = _seed_profile(store, display_name=display_name)
    store.insert_profile_secret_refs(
        profile_id=profile_id,
        refs=[(cred_id, "PrivateKey")],
    )
    return profile_id, cred_id


def _remove(client: Any, profile_id: str, *, confirm: bool = True) -> Any:
    body = {"confirm_catalog_remove": confirm}
    return client.post(_REMOVE_PATH.format(profile_id=profile_id), json=body)


def _seed_vpn_activate_sealed_run(
    store: Any,
    profile_id: str,
    *,
    status: str = "Running",
    finished_seconds_ago: int = 0,
    now: datetime | None = None,
) -> str:
    moment = now or datetime.now(UTC)
    intent = {"profile_id": profile_id, "wg_id": _TEST_WG, "enabled": True}
    run_id = store.begin_sealed_apply_run(
        route="vpn-profiles",
        verb="activate",
        intent_summary_redacted=intent,
        ops_planned_redacted=("create_interface",),
        lease_owner=_TEST_SEALED_APPLY_LEASE_OWNER,
        now=moment,
    )
    if status != "Running":
        store.finish_sealed_apply_run(
            run_id,
            lease_owner=_TEST_SEALED_APPLY_LEASE_OWNER,
            status=status,
            overall="applied",
            now=moment,
        )
        if finished_seconds_ago > 0:
            finished_at = moment - timedelta(seconds=finished_seconds_ago)
            store.conn.execute(
                "UPDATE sealed_apply_runs SET finished_at = ? WHERE run_id = ?",
                (finished_at.strftime("%Y-%m-%dT%H:%M:%SZ"), run_id),
            )
    return run_id


def _host_now(client: Any) -> datetime:
    return client.app.state.host.runtime.clock.now()


def test_inactive_remove_hides_from_list(remove_client) -> None:
    store = remove_client.store
    profile_id = _seed_profile(store, display_name="inactive-remove")
    resp = _remove(remove_client, profile_id)
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["profile_id"] == profile_id
    assert payload["removed_from_catalog"] is True
    assert store.list_profiles() == []
    assert store.get_profile(profile_id) is None
    retired = store.get_profile_including_superseded(profile_id)
    assert retired is not None
    assert retired["superseded_at"] is not None


def test_active_remove_returns_409_without_supersede(remove_client) -> None:
    store = remove_client.store
    router_id = _seed_router(store)
    profile_id = _seed_profile(store, display_name="active-remove")
    store.upsert_tunnel_assignment(
        router_id=router_id,
        profile_id=profile_id,
        observed_vendor_locator=_TEST_WG,
    )
    resp = _remove(remove_client, profile_id)
    assert resp.status_code == 409
    assert "Отключить" in resp.json()["error"]["message"]
    row = store.get_profile(profile_id)
    assert row is not None
    assert row["superseded_at"] is None


def test_remove_requires_confirm_true(remove_client) -> None:
    store = remove_client.store
    profile_id = _seed_profile(store, display_name="confirm-false")
    resp = _remove(remove_client, profile_id, confirm=False)
    assert resp.status_code == 400
    assert store.list_profiles()


def test_remove_requires_confirm_field(remove_client) -> None:
    store = remove_client.store
    profile_id = _seed_profile(store, display_name="confirm-missing")
    resp = remove_client.post(
        _REMOVE_PATH.format(profile_id=profile_id),
        json={},
    )
    assert resp.status_code == 422


def test_exclusive_secret_ref_revoked(remove_client) -> None:
    profile_id, cred_id = _seed_profile_with_secret(
        remove_client,
        display_name="exclusive-revoke",
    )
    vault: MemoryVault = remove_client.vault
    resp = _remove(remove_client, profile_id)
    assert resp.status_code == 200
    assert resp.json()["secrets_released"] == 1
    cred = remove_client.store.get_credential_ref(cred_id)
    assert cred is not None
    assert cred["revoked_at"] is not None
    with pytest.raises(VaultError):
        vault.use(cred_id)


def test_exclusive_revoke_vault_error_aborts_remove(remove_client, monkeypatch) -> None:
    profile_id, cred_id = _seed_profile_with_secret(
        remove_client,
        display_name="revoke-failure-abort",
    )
    store = remove_client.store
    vault: MemoryVault = remove_client.vault

    def _fail_revoke(ref_id: str) -> None:
        raise VaultError("simulated revoke failure")

    monkeypatch.setattr(vault, "revoke", _fail_revoke)

    resp = _remove(remove_client, profile_id)
    assert resp.status_code // 100 != 2
    assert resp.json()["error"]["code"] == "vpn_catalog.secret_revoke_failed"

    row = store.get_profile(profile_id)
    assert row is not None
    assert row["superseded_at"] is None
    assert store.list_profiles()
    assert store.list_profile_secret_refs(profile_id)
    cred = store.get_credential_ref(cred_id)
    assert cred is not None
    assert cred["revoked_at"] is None
    assert vault.use(cred_id) == _SYNTHETIC_SECRET


def test_shared_secret_ref_not_revoked(remove_client) -> None:
    profile_id_a, cred_id = _seed_profile_with_secret(
        remove_client,
        display_name="shared-a",
    )
    profile_id_b, _ = _seed_profile_with_secret(
        remove_client,
        display_name="shared-b",
        shared_cred_id=cred_id,
    )
    vault: MemoryVault = remove_client.vault
    resp = _remove(remove_client, profile_id_a)
    assert resp.status_code == 200
    assert resp.json()["secrets_released"] == 0
    cred = remove_client.store.get_credential_ref(cred_id)
    assert cred is not None
    assert cred["revoked_at"] is None
    assert vault.use(cred_id) == _SYNTHETIC_SECRET
    assert remove_client.store.list_profiles()
    remaining = [row["profile_id"] for row in remove_client.store.list_profiles()]
    assert profile_id_b in remaining


def test_non_vpn_live_link_blocks_revoke(remove_client) -> None:
    profile_id, cred_id = _seed_profile_with_secret(
        remove_client,
        display_name="standing-link",
    )
    remove_client.store.upsert_standing_network_preferences(
        staff_password_credential_ref_id=cred_id,
    )
    vault: MemoryVault = remove_client.vault
    resp = _remove(remove_client, profile_id)
    assert resp.status_code == 200
    assert resp.json()["secrets_released"] == 0
    cred = remove_client.store.get_credential_ref(cred_id)
    assert cred is not None
    assert cred["revoked_at"] is None
    assert vault.use(cred_id) == _SYNTHETIC_SECRET


def test_remove_response_has_no_secret_material(remove_client) -> None:
    profile_id, _ = _seed_profile_with_secret(
        remove_client,
        display_name="no-secrets-response",
    )
    resp = _remove(remove_client, profile_id)
    assert resp.status_code == 200
    text = resp.text
    assert _SYNTHETIC_SECRET not in text
    assert "PrivateKey" not in text
    assert "credential_ref_id" not in text


def test_tunnel_assignment_rows_remain_after_remove(remove_client) -> None:
    store = remove_client.store
    router_id = _seed_router(store)
    profile_id = _seed_profile(store, display_name="audit-keep")
    store.upsert_tunnel_assignment(
        router_id=router_id,
        profile_id=profile_id,
        desired_active=False,
    )
    store.deactivate_tunnel_assignments(router_id)
    before = store.list_tunnel_assignments(router_id)
    assert before
    resp = _remove(remove_client, profile_id)
    assert resp.status_code == 200
    after = store.list_tunnel_assignments(router_id)
    assert len(after) == len(before)


def test_upsert_after_supersede_fails(remove_client) -> None:
    store = remove_client.store
    router_id = _seed_router(store)
    profile_id = _seed_profile(store, display_name="superseded-upsert")
    resp = _remove(remove_client, profile_id)
    assert resp.status_code == 200
    with pytest.raises(NotFoundError):
        store.upsert_tunnel_assignment(
            router_id=router_id,
            profile_id=profile_id,
        )


def test_remove_missing_profile_404(remove_client) -> None:
    resp = _remove(remove_client, "prof_missing")
    assert resp.status_code == 404


def test_remove_already_retired_404(remove_client) -> None:
    store = remove_client.store
    profile_id = _seed_profile(store, display_name="double-remove")
    assert _remove(remove_client, profile_id).status_code == 200
    resp = _remove(remove_client, profile_id)
    assert resp.status_code == 404


def test_list_excludes_removed_profile(remove_client) -> None:
    store = remove_client.store
    keep_id = _seed_profile(store, display_name="keep-me")
    remove_id = _seed_profile(store, display_name="remove-me")
    assert _remove(remove_client, remove_id).status_code == 200
    list_resp = remove_client.get(_LIST_PATH)
    assert list_resp.status_code == 200
    ids = [item["profile_id"] for item in list_resp.json()["items"]]
    assert keep_id in ids
    assert remove_id not in ids


def test_remove_after_retire_get_profile_none_and_activate_404(remove_client) -> None:
    store = remove_client.store
    profile_id = _seed_profile(store, display_name="post-remove-activate")
    assert _remove(remove_client, profile_id).status_code == 200
    assert store.get_profile(profile_id) is None
    activate_resp = remove_client.post(
        _ACTIVATE_PATH.format(profile_id=profile_id),
        json={"confirm_live_apply": True, "wg_id": _TEST_WG},
    )
    assert activate_resp.status_code == 404
    assert activate_resp.json()["error"]["code"] == "resource.not_found"


def test_remove_blocked_while_running_vpn_activate_sealed_apply(remove_client) -> None:
    store = remove_client.store
    profile_id = _seed_profile(store, display_name="running-activate")
    _seed_vpn_activate_sealed_run(store, profile_id, status="Running")
    resp = _remove(remove_client, profile_id)
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "vpn_catalog.activate_in_progress"
    assert resp.json()["error"]["message"] == _ACTIVATE_IN_PROGRESS_MESSAGE
    assert store.get_profile(profile_id) is not None
    assert store.get_profile(profile_id)["superseded_at"] is None


def test_remove_blocked_after_recent_succeeded_activate_without_assignment(
    remove_client,
) -> None:
    store = remove_client.store
    profile_id = _seed_profile(store, display_name="recent-succeeded-activate")
    _seed_vpn_activate_sealed_run(
        store,
        profile_id,
        status="Succeeded",
        now=_host_now(remove_client),
    )
    resp = _remove(remove_client, profile_id)
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "vpn_catalog.activate_in_progress"
    assert resp.json()["error"]["message"] == _ACTIVATE_IN_PROGRESS_MESSAGE
    assert store.get_profile(profile_id) is not None


def test_remove_allowed_after_stale_succeeded_activate_without_assignment(
    remove_client,
) -> None:
    store = remove_client.store
    profile_id = _seed_profile(store, display_name="stale-succeeded-activate")
    _seed_vpn_activate_sealed_run(
        store,
        profile_id,
        status="Succeeded",
        finished_seconds_ago=121,
        now=_host_now(remove_client),
    )
    resp = _remove(remove_client, profile_id)
    assert resp.status_code == 200
    assert store.get_profile(profile_id) is None


def test_remove_with_active_assignment_blocks_as_active_not_activate_gap(
    remove_client,
) -> None:
    store = remove_client.store
    router_id = _seed_router(store)
    profile_id = _seed_profile(store, display_name="succeeded-with-assignment")
    _seed_vpn_activate_sealed_run(
        store,
        profile_id,
        status="Succeeded",
        now=_host_now(remove_client),
    )
    store.upsert_tunnel_assignment(
        router_id=router_id,
        profile_id=profile_id,
        observed_vendor_locator=_TEST_WG,
    )
    resp = _remove(remove_client, profile_id)
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "vpn_catalog.active_profile"
