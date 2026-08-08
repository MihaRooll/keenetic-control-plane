"""SLICE-3 FastAPI host TestClient coverage."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from router_control.adapters.secrets.memory import VaultError
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie


@pytest.fixture
def app_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.delenv("RC_ALLOW_FAKE_MUTATIONS", raising=False)
    application = create_app(db_path=tmp_path / "host.sqlite3", allow_fake_mutations=False)
    return application


@pytest.fixture
def client(app_env):
    from fastapi.testclient import TestClient

    with TestClient(app_env) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield c


def test_503_when_password_empty(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "")
    from fastapi.testclient import TestClient

    application = create_app(db_path=tmp_path / "a.sqlite3")
    with TestClient(application) as c:
        r = c.get("/api/router-control/v1/status")
    assert r.status_code == 503
    assert r.json()["error"]["code"] == "security.configuration_blocked"


def test_401_without_cookie(app_env) -> None:
    from fastapi.testclient import TestClient

    with TestClient(app_env) as c:
        r = c.get("/api/router-control/v1/status")
    assert r.status_code == 401


def test_ready_status(client) -> None:
    r = client.get("/api/router-control/v1/status")
    assert r.status_code == 200
    body = r.json()
    assert body["feature_state"] == "Ready"
    assert body["worker_state"] in ("Running", "Starting", "Stopped")
    assert "vpn_watchdog_enabled" in body
    assert "vpn_watchdog_poll_seconds" in body
    assert isinstance(body["vpn_watchdog_enabled"], bool)
    assert isinstance(body["vpn_watchdog_poll_seconds"], (int, float))
    assert "X-Request-Id" in r.headers


def test_status_vpn_watchdog_enabled_reflects_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import importlib

    from router_control.application import vpn_watchdog_service

    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("VPN_WATCHDOG_ENABLED", "true")
    monkeypatch.setenv("VPN_WATCHDOG_POLL_SECONDS", "60")
    importlib.reload(vpn_watchdog_service)
    from fastapi.testclient import TestClient

    application = create_app(db_path=tmp_path / "watchdog.sqlite3")
    with TestClient(application) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        body = c.get("/api/router-control/v1/status").json()
    importlib.reload(vpn_watchdog_service)
    assert body["vpn_watchdog_enabled"] is True
    assert body["vpn_watchdog_poll_seconds"] == 60.0


def test_status_vpn_watchdog_disabled_reflects_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import importlib

    from router_control.application import vpn_watchdog_service

    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.delenv("VPN_WATCHDOG_ENABLED", raising=False)
    importlib.reload(vpn_watchdog_service)
    from fastapi.testclient import TestClient

    application = create_app(db_path=tmp_path / "watchdog-off.sqlite3")
    with TestClient(application) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        body = c.get("/api/router-control/v1/status").json()
    importlib.reload(vpn_watchdog_service)
    assert body["vpn_watchdog_enabled"] is False


def test_vpn_profiles_list_includes_connection_fields(client) -> None:
    r = client.get("/api/router-control/v1/vpn-profiles")
    assert r.status_code == 200
    items = r.json()["items"]
    if items:
        sample = items[0]
        assert "is_active" in sample
        assert "assigned_wg_id" in sample
        assert isinstance(sample["is_active"], bool)


def test_vpn_profiles_list_active_assignment_shape(client, app_env) -> None:
    store = app_env.state.host.runtime.store
    site = app_env.state.host.ensure_default_site()
    router_id = store.enroll_router(
        site_id=site,
        display_name="VPN List Router",
        vendor="Fake",
        model="M1",
        identity_fingerprint="digest:list:1",
        host="127.0.0.1",
    )
    profile_id = store.import_profile(
        display_name="Active Profile",
        vpn_kind="AmneziaWG",
        content_digest="sha256:abc",
        metadata_json='{"wg_id":"Wireguard5"}',
    )
    store.upsert_tunnel_assignment(
        router_id=router_id,
        profile_id=profile_id,
        desired_active=True,
        observed_vendor_locator="Wireguard5",
        policy_metadata_json='{"wg_id":"Wireguard5","tunnel_verification_status":"tunnel_healthy"}',
    )
    inactive_id = store.import_profile(
        display_name="Idle Profile",
        vpn_kind="AmneziaWG",
        content_digest="sha256:def",
        metadata_json="{}",
    )
    r = client.get("/api/router-control/v1/vpn-profiles")
    by_id = {item["profile_id"]: item for item in r.json()["items"]}
    active = by_id[profile_id]
    assert active["is_active"] is True
    assert active["assigned_wg_id"] == "Wireguard5"
    assert active["tunnel_verification_status"] == "tunnel_healthy"
    assert by_id[inactive_id]["is_active"] is False
    assert by_id[inactive_id]["assigned_wg_id"] is None


def test_vpn_profiles_list_exposes_metadata_wg_id_for_inactive(client, app_env) -> None:
    store = app_env.state.host.runtime.store
    inactive_with_meta = store.import_profile(
        display_name="Inactive With Meta Wg",
        vpn_kind="AmneziaWG",
        content_digest="sha256:inactive-meta-wg",
        metadata_json='{"wg_id":"Wireguard7"}',
    )
    inactive_without_meta = store.import_profile(
        display_name="Inactive Without Meta Wg",
        vpn_kind="AmneziaWG",
        content_digest="sha256:inactive-no-meta-wg",
        metadata_json="{}",
    )
    r = client.get("/api/router-control/v1/vpn-profiles")
    by_id = {item["profile_id"]: item for item in r.json()["items"]}
    assert by_id[inactive_with_meta]["wg_id"] == "Wireguard7"
    assert by_id[inactive_with_meta]["assigned_wg_id"] is None
    assert by_id[inactive_without_meta]["wg_id"] is None


def test_vpn_profiles_list_prefers_assignment_wg_over_metadata(client, app_env) -> None:
    store = app_env.state.host.runtime.store
    site = app_env.state.host.ensure_default_site()
    router_id = store.enroll_router(
        site_id=site,
        display_name="VPN Stale Meta Router",
        vendor="Fake",
        model="M1",
        identity_fingerprint="digest:stale:1",
        host="127.0.0.1",
    )
    profile_id = store.import_profile(
        display_name="Stale Meta Profile",
        vpn_kind="AmneziaWG",
        content_digest="sha256:stale",
        metadata_json='{"wg_id":"Wireguard5"}',
    )
    store.upsert_tunnel_assignment(
        router_id=router_id,
        profile_id=profile_id,
        desired_active=True,
        observed_vendor_locator="Wireguard6",
        policy_metadata_json='{"wg_id":"Wireguard6","tunnel_verification_status":"tunnel_healthy"}',
    )
    r = client.get("/api/router-control/v1/vpn-profiles")
    by_id = {item["profile_id"]: item for item in r.json()["items"]}
    assert by_id[profile_id]["assigned_wg_id"] == "Wireguard6"


def test_import_profile_idempotency_mid_state_not_empty_201(app_env) -> None:
    from router_control_host.routes import _ensure_catalog_router

    store = app_env.state.host.runtime.store
    host = app_env.state.host
    sentinel = _ensure_catalog_router(host, host.ensure_default_site())
    store.create_operation_bundle(
        router_id=sentinel,
        operation_kind="import_profile",
        idempotency_key="import-mid-state",
        request_digest="sha256:import-mid",
        initial_job_status="Succeeded",
        response_ref='{"status": "InProgress"}',
        http_status=202,
    )
    existing = store.peek_idempotency(
        router_id=sentinel,
        operation_kind="import_profile",
        idempotency_key="import-mid-state",
        request_digest="sha256:import-mid",
    )
    assert existing is not None
    stored = json.loads(existing.response_ref or "{}")
    assert stored["http_status"] == 202
    assert stored["body"]["status"] == "InProgress"
    assert "profile_id" not in stored["body"]


def test_import_profile_sync_job_not_claimable(client, app_env) -> None:
    body = {
        "display_name": "Worker Race AWG",
        "wg_id": "Wireguard5",
        "vpn_kind": "AmneziaWG",
        "profile_text": """
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.0.0.9/32
Jc = 5
Jmin = 50
Jmax = 1000
S1 = 80
S2 = 80
H1 = 1
H2 = 2
H3 = 3
H4 = 4
[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
Endpoint = example.com:51820
AllowedIPs = 0.0.0.0/0
""",
    }
    r = client.post(
        "/api/router-control/v1/vpn-profiles/import",
        json=body,
        headers={"Idempotency-Key": "import-worker-race"},
    )
    assert r.status_code == 201
    profile_id = r.json()["profile_id"]
    store = app_env.state.host.runtime.store
    job_row = store._conn.execute(
        "SELECT j.job_id, j.status FROM jobs j "
        "JOIN operations o ON o.operation_id = j.operation_id "
        "WHERE o.operation_kind = 'import_profile' "
        "ORDER BY j.created_at DESC LIMIT 1"
    ).fetchone()
    assert job_row is not None
    assert job_row["status"] == "Succeeded"
    assert store.claim_job(worker_id="w-import-race") is None
    replay = client.post(
        "/api/router-control/v1/vpn-profiles/import",
        json=body,
        headers={"Idempotency-Key": "import-worker-race"},
    )
    assert replay.status_code == 201
    assert replay.json()["profile_id"] == profile_id


def test_import_profile_idempotency_in_progress_replay_returns_202(
    client, app_env, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = app_env.state.host.runtime.store
    monkeypatch.setattr(store, "update_idempotency_response", lambda *args, **kwargs: None)
    body = {
        "display_name": "InProgress AWG",
        "vpn_kind": "AmneziaWG",
        "profile_text": """
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.0.0.10/32
Jc = 5
Jmin = 50
Jmax = 1000
S1 = 80
S2 = 80
H1 = 1
H2 = 2
H3 = 3
H4 = 4
[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
Endpoint = example.com:51820
AllowedIPs = 0.0.0.0/0
""",
    }
    first = client.post(
        "/api/router-control/v1/vpn-profiles/import",
        json=body,
        headers={"Idempotency-Key": "import-in-progress-replay"},
    )
    assert first.status_code == 201
    assert first.json().get("profile_id")

    replay = client.post(
        "/api/router-control/v1/vpn-profiles/import",
        json=body,
        headers={"Idempotency-Key": "import-in-progress-replay"},
    )
    assert replay.status_code == 202
    assert replay.json()["status"] == "InProgress"
    assert "profile_id" not in replay.json()


def test_validate_profile_sync_job_not_claimable(client, app_env) -> None:
    import_body = {
        "display_name": "Validate Worker Race AWG",
        "vpn_kind": "AmneziaWG",
        "profile_text": """
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.0.0.11/32
Jc = 5
Jmin = 50
Jmax = 1000
S1 = 80
S2 = 80
H1 = 1
H2 = 2
H3 = 3
H4 = 4
[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
Endpoint = example.com:51820
AllowedIPs = 0.0.0.0/0
""",
    }
    imported = client.post(
        "/api/router-control/v1/vpn-profiles/import",
        json=import_body,
        headers={"Idempotency-Key": "validate-worker-race-import"},
    )
    assert imported.status_code == 201
    profile_id = imported.json()["profile_id"]
    validated = client.post(
        f"/api/router-control/v1/vpn-profiles/{profile_id}/validate",
        json={},
        headers={"Idempotency-Key": "validate-worker-race"},
    )
    assert validated.status_code == 200
    store = app_env.state.host.runtime.store
    job_row = store._conn.execute(
        "SELECT j.job_id, j.status FROM jobs j "
        "JOIN operations o ON o.operation_id = j.operation_id "
        "WHERE o.operation_kind = 'validate_profile' "
        "ORDER BY j.created_at DESC LIMIT 1"
    ).fetchone()
    assert job_row is not None
    assert job_row["status"] == "Succeeded"
    assert store.claim_job(worker_id="w-validate-race") is None
    replay = client.post(
        f"/api/router-control/v1/vpn-profiles/{profile_id}/validate",
        json={},
        headers={"Idempotency-Key": "validate-worker-race"},
    )
    assert replay.status_code == 200
    assert replay.json()["profile_id"] == profile_id


def test_put_credential_idempotency_conflict_on_different_secret(client) -> None:
    r = client.post(
        "/api/router-control/v1/routers",
        json={
            "display_name": "Put Cred Router",
            "vendor": "V",
            "model": "M",
            "endpoint": {"kind": "management_https", "host": "10.0.0.8", "port": 443},
            "management_password": "initial-secret",
        },
        headers={"Idempotency-Key": "enroll-put-cred"},
    )
    router_id = r.json()["router_id"]

    first = client.put(
        f"/api/router-control/v1/routers/{router_id}/credentials",
        json={"kind": "RouterManagementPassword", "secret": "secret-one"},
        headers={"Idempotency-Key": "put-cred-conflict"},
    )
    assert first.status_code == 201

    second = client.put(
        f"/api/router-control/v1/routers/{router_id}/credentials",
        json={"kind": "RouterManagementPassword", "secret": "secret-two"},
        headers={"Idempotency-Key": "put-cred-conflict"},
    )
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "idempotency.conflict"


def test_put_credential_wifi_ap_psk_does_not_rebind_router_management(client) -> None:
    r = client.post(
        "/api/router-control/v1/routers",
        json={
            "display_name": "Wifi PSK Router",
            "vendor": "V",
            "model": "M",
            "endpoint": {"kind": "management_https", "host": "10.0.0.20", "port": 443},
            "management_password": "initial-secret",
        },
        headers={"Idempotency-Key": "enroll-wifi-psk-no-rebind"},
    )
    router_id = r.json()["router_id"]
    store = client.app.state.host.runtime.store
    mgmt_cred_id = store.get_router(router_id)["credential_ref_id"]

    resp = client.put(
        f"/api/router-control/v1/routers/{router_id}/credentials",
        json={"kind": "WifiApPsk", "secret": "wifi-ap-psk-synthetic-marker"},
        headers={"Idempotency-Key": "put-wifi-psk-no-rebind"},
    )
    assert resp.status_code == 201
    assert store.get_router(router_id)["credential_ref_id"] == mgmt_cred_id


def test_put_credential_idempotency_replay_remints_after_revoke(client) -> None:
    r = client.post(
        "/api/router-control/v1/routers",
        json={
            "display_name": "Remint Router",
            "vendor": "V",
            "model": "M",
            "endpoint": {"kind": "management_https", "host": "10.0.0.23", "port": 443},
            "management_password": "initial-secret",
        },
        headers={"Idempotency-Key": "enroll-remint-after-revoke"},
    )
    router_id = r.json()["router_id"]
    vault = client.app.state.host.runtime.vault
    secret = "edit-psk-remint-aaaaaa"
    first = client.put(
        f"/api/router-control/v1/routers/{router_id}/credentials",
        json={"kind": "WifiApPsk", "secret": secret},
        headers={"Idempotency-Key": "put-remint-key"},
    )
    assert first.status_code == 201
    revoked_ref = first.json()["credential_ref_id"]
    revoke = client.post(
        f"/api/router-control/v1/routers/{router_id}/credentials/{revoked_ref}/revoke",
        headers={"Idempotency-Key": "revoke-remint-key"},
    )
    assert revoke.status_code == 202
    with pytest.raises(VaultError):
        vault.use(revoked_ref)
    replay = client.put(
        f"/api/router-control/v1/routers/{router_id}/credentials",
        json={"kind": "WifiApPsk", "secret": secret},
        headers={"Idempotency-Key": "put-remint-key"},
    )
    assert replay.status_code == 201
    fresh_ref = replay.json()["credential_ref_id"]
    assert fresh_ref != revoked_ref
    assert vault.use(fresh_ref) == secret
    get_ref = client.get(
        f"/api/router-control/v1/routers/{router_id}/credentials/{revoked_ref}"
    )
    assert get_ref.status_code == 200
    assert get_ref.json()["revoked_at"] is not None


def test_enroll_rejects_wifi_ap_psk_credential_ref(client) -> None:
    """G-2: enroll must not decrypt WifiApPsk refs or mislabel kind."""
    r = client.post(
        "/api/router-control/v1/routers",
        json={
            "display_name": "Enroll WifiApPsk Guard",
            "vendor": "V",
            "model": "M",
            "endpoint": {"kind": "management_https", "host": "10.0.0.22", "port": 443},
            "management_password": "initial-secret",
        },
        headers={"Idempotency-Key": "enroll-wifi-psk-guard"},
    )
    assert r.status_code == 202
    router_id = r.json()["router_id"]
    psk_resp = client.put(
        f"/api/router-control/v1/routers/{router_id}/credentials",
        json={"kind": "WifiApPsk", "secret": "wifi-ap-psk-synthetic-marker"},
        headers={"Idempotency-Key": "put-wifi-psk-guard"},
    )
    assert psk_resp.status_code == 201
    wifi_ref = psk_resp.json()["credential_ref_id"]

    enroll = client.post(
        "/api/router-control/v1/routers",
        json={
            "display_name": "Should Fail",
            "vendor": "V2",
            "model": "M2",
            "endpoint": {"kind": "management_https", "host": "10.0.0.23", "port": 443},
            "credential_ref_id": wifi_ref,
        },
        headers={"Idempotency-Key": "enroll-with-wifi-psk-ref"},
    )
    assert enroll.status_code == 422
    body = enroll.json()
    assert body["error"]["code"] == "request.validation_failed"
    assert "WifiApPsk" in body["error"]["message"]
    assert "wifi-ap-psk-synthetic-marker" not in enroll.text


def test_enroll_rejects_vault_only_wifi_ap_psk_without_decrypt(
    client, monkeypatch: pytest.MonkeyPatch
) -> None:
    """G-2: vault-only WifiApPsk ref must be refused without vault.use."""
    vault = client.app.state.host.runtime.vault
    handle = vault.create(kind="WifiApPsk", secret="wifi-ap-psk-vault-only-marker")
    use_calls: list[str] = []
    original_use = vault.use

    def tracking_use(ref_id: str) -> str:
        use_calls.append(ref_id)
        return original_use(ref_id)

    monkeypatch.setattr(vault, "use", tracking_use)

    enroll = client.post(
        "/api/router-control/v1/routers",
        json={
            "display_name": "Vault-Only WifiApPsk",
            "vendor": "V",
            "model": "M",
            "endpoint": {"kind": "management_https", "host": "10.0.0.24", "port": 443},
            "credential_ref_id": handle.credential_ref_id,
        },
        headers={"Idempotency-Key": "enroll-vault-only-wifi-psk-ref"},
    )
    assert enroll.status_code == 422
    body = enroll.json()
    assert body["error"]["code"] == "request.validation_failed"
    assert "WifiApPsk" in body["error"]["message"]
    assert handle.credential_ref_id not in use_calls
    assert "wifi-ap-psk-vault-only-marker" not in enroll.text


def test_put_credential_rejects_unknown_kind_structurally(client) -> None:
    r = client.post(
        "/api/router-control/v1/routers",
        json={
            "display_name": "Unknown Kind Router",
            "vendor": "V",
            "model": "M",
            "endpoint": {"kind": "management_https", "host": "10.0.0.21", "port": 443},
            "management_password": "initial-secret",
        },
        headers={"Idempotency-Key": "enroll-unknown-kind"},
    )
    router_id = r.json()["router_id"]
    store = client.app.state.host.runtime.store
    mgmt_cred_id = store.get_router(router_id)["credential_ref_id"]

    resp = client.put(
        f"/api/router-control/v1/routers/{router_id}/credentials",
        json={"kind": "RouterManagmentPassword", "secret": "typo-kind-secret"},
        headers={"Idempotency-Key": "put-unknown-kind"},
    )
    assert resp.status_code == 422
    body = resp.json()
    assert body["error"]["code"] == "request.validation_failed"
    details = body["error"]["details"]
    assert any(item.get("field") == "kind" for item in details)
    assert store.get_router(router_id)["credential_ref_id"] == mgmt_cred_id


def test_rotate_vault_error_leaves_no_orphan_queued_job(client) -> None:
    r = client.post(
        "/api/router-control/v1/routers",
        json={
            "display_name": "Rotate Fail Router",
            "vendor": "V",
            "model": "M",
            "endpoint": {"kind": "management_https", "host": "10.0.0.13", "port": 443},
            "management_password": "initial-secret",
        },
        headers={"Idempotency-Key": "enroll-rotate-fail"},
    )
    router_id = r.json()["router_id"]
    store = client.app.state.host.runtime.store

    resp = client.post(
        f"/api/router-control/v1/routers/{router_id}/credentials/cred_missing/rotate",
        json={"secret": "new-secret"},
        headers={"Idempotency-Key": "rotate-missing-cred"},
    )
    assert resp.status_code == 404
    queued_rotate = store._conn.execute(
        "SELECT COUNT(*) AS c FROM jobs j "
        "JOIN operations o ON j.operation_id = o.operation_id "
        "WHERE o.operation_kind = 'rotate_credential' AND j.status = 'Queued'"
    ).fetchone()["c"]
    assert queued_rotate == 0


def test_revoke_vault_error_leaves_no_orphan_queued_job(client) -> None:
    r = client.post(
        "/api/router-control/v1/routers",
        json={
            "display_name": "Revoke Fail Router",
            "vendor": "V",
            "model": "M",
            "endpoint": {"kind": "management_https", "host": "10.0.0.14", "port": 443},
            "management_password": "initial-secret",
        },
        headers={"Idempotency-Key": "enroll-revoke-fail"},
    )
    router_id = r.json()["router_id"]
    store = client.app.state.host.runtime.store

    resp = client.post(
        f"/api/router-control/v1/routers/{router_id}/credentials/cred_missing/revoke",
        headers={"Idempotency-Key": "revoke-missing-cred"},
    )
    assert resp.status_code == 404
    queued_revoke = store._conn.execute(
        "SELECT COUNT(*) AS c FROM jobs j "
        "JOIN operations o ON j.operation_id = o.operation_id "
        "WHERE o.operation_kind = 'revoke_credential' AND j.status = 'Queued'"
    ).fetchone()["c"]
    assert queued_revoke == 0


def test_enroll_and_idempotency(client) -> None:
    host = client.app.state.host
    assert host.worker_runtime is not None
    assert host.worker_runtime.worker is not None
    assert host.worker_runtime.worker.store is not host.runtime.store
    body = {
        "display_name": "Booth Router",
        "vendor": "FakeVendor",
        "model": "Fake-1",
        "endpoint": {"kind": "management_https", "host": "127.0.0.1", "port": 443},
        "management_password": "never-echo-this-secret",
    }
    r = client.post(
        "/api/router-control/v1/routers",
        json=body,
        headers={"Idempotency-Key": "enroll-1"},
    )
    assert r.status_code == 202
    data = r.json()
    assert "operation_id" in data
    assert "never-echo-this-secret" not in r.text
    router_id = data["router_id"]
    g = client.get(f"/api/router-control/v1/routers/{router_id}")
    assert g.status_code == 200
    assert "never-echo-this-secret" not in g.text


def test_enroll_idempotency_conflict_on_different_password(client) -> None:
    base = {
        "display_name": "Enroll Conflict Router",
        "vendor": "FakeVendor",
        "model": "Fake-Conflict",
        "endpoint": {"kind": "management_https", "host": "127.0.0.9", "port": 443},
    }
    first = client.post(
        "/api/router-control/v1/routers",
        json={**base, "management_password": "password-one"},
        headers={"Idempotency-Key": "enroll-pw-conflict"},
    )
    assert first.status_code == 202
    routers_before = len(client.get("/api/router-control/v1/routers").json()["items"])

    second = client.post(
        "/api/router-control/v1/routers",
        json={**base, "management_password": "password-two"},
        headers={"Idempotency-Key": "enroll-pw-conflict"},
    )
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "idempotency.conflict"
    assert len(client.get("/api/router-control/v1/routers").json()["items"]) == routers_before


def test_enroll_idempotent_replay_no_orphan_side_effects(client) -> None:
    body = {
        "display_name": "Replay Router",
        "vendor": "FakeVendor",
        "model": "Fake-2",
        "endpoint": {"kind": "management_https", "host": "127.0.0.8", "port": 443},
        "management_password": "enroll-secret-once",
    }
    r1 = client.post(
        "/api/router-control/v1/routers",
        json=body,
        headers={"Idempotency-Key": "enroll-replay"},
    )
    assert r1.status_code == 202
    d1 = r1.json()
    routers_before = client.get("/api/router-control/v1/routers").json()["items"]
    vault = client.app.state.host.runtime.vault
    secrets_before = len(vault._secrets)

    r2 = client.post(
        "/api/router-control/v1/routers",
        json=body,
        headers={"Idempotency-Key": "enroll-replay"},
    )
    assert r2.status_code == 202
    d2 = r2.json()
    assert d2["router_id"] == d1["router_id"]
    assert d2["operation_id"] == d1["operation_id"]
    assert d2["job_id"] == d1["job_id"]
    routers_after = client.get("/api/router-control/v1/routers").json()["items"]
    assert len(routers_after) == len(routers_before)
    assert len(vault._secrets) == secrets_before


def test_rotate_idempotency_conflict_does_not_mutate_secret(client) -> None:
    r = client.post(
        "/api/router-control/v1/routers",
        json={
            "display_name": "Rotate Router",
            "vendor": "V",
            "model": "M",
            "endpoint": {"kind": "management_https", "host": "10.0.0.9", "port": 443},
            "management_password": "initial-secret",
        },
        headers={"Idempotency-Key": "enroll-rotate"},
    )
    router_id = r.json()["router_id"]
    store = client.app.state.host.runtime.store
    vault = client.app.state.host.runtime.vault
    cred_id = store.get_router(router_id)["credential_ref_id"]
    assert vault.use(cred_id) == "initial-secret"

    first = client.post(
        f"/api/router-control/v1/routers/{router_id}/credentials/{cred_id}/rotate",
        json={"secret": "rotated-once"},
        headers={"Idempotency-Key": "rotate-conflict"},
    )
    assert first.status_code == 202
    assert vault.use(cred_id) == "rotated-once"

    second = client.post(
        f"/api/router-control/v1/routers/{router_id}/credentials/{cred_id}/rotate",
        json={"secret": "rotated-different"},
        headers={"Idempotency-Key": "rotate-conflict"},
    )
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "idempotency.conflict"
    assert vault.use(cred_id) == "rotated-once"


def test_rotate_conflict_after_peek_miss_does_not_mutate_vault(client, monkeypatch) -> None:
    """Simulate concurrent accept: peek misses while another digest already claimed.

    Old bug: vault.rotate between peek-miss and claim → 409 left loser's secret.
    Fix: create_operation_bundle claim before any vault mutate.
    """
    r = client.post(
        "/api/router-control/v1/routers",
        json={
            "display_name": "Rotate Race Router",
            "vendor": "V",
            "model": "M",
            "endpoint": {"kind": "management_https", "host": "10.0.0.11", "port": 443},
            "management_password": "initial-secret",
        },
        headers={"Idempotency-Key": "enroll-rotate-race"},
    )
    router_id = r.json()["router_id"]
    store = client.app.state.host.runtime.store
    vault = client.app.state.host.runtime.vault
    cred_id = store.get_router(router_id)["credential_ref_id"]

    first = client.post(
        f"/api/router-control/v1/routers/{router_id}/credentials/{cred_id}/rotate",
        json={"secret": "rotated-once"},
        headers={"Idempotency-Key": "rotate-race-key"},
    )
    assert first.status_code == 202
    assert vault.use(cred_id) == "rotated-once"

    monkeypatch.setattr(store, "peek_idempotency", lambda **_kwargs: None)

    second = client.post(
        f"/api/router-control/v1/routers/{router_id}/credentials/{cred_id}/rotate",
        json={"secret": "rotated-different"},
        headers={"Idempotency-Key": "rotate-race-key"},
    )
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "idempotency.conflict"
    assert vault.use(cred_id) == "rotated-once"


def test_revoke_conflict_after_peek_miss_does_not_revoke_vault(client, monkeypatch) -> None:
    """Same claim-before-mutate rule for revoke (peek miss + digest conflict)."""
    r = client.post(
        "/api/router-control/v1/routers",
        json={
            "display_name": "Revoke Race Router",
            "vendor": "V",
            "model": "M",
            "endpoint": {"kind": "management_https", "host": "10.0.0.12", "port": 443},
            "management_password": "revoke-initial",
        },
        headers={"Idempotency-Key": "enroll-revoke-race"},
    )
    router_id = r.json()["router_id"]
    store = client.app.state.host.runtime.store
    vault = client.app.state.host.runtime.vault
    cred_a = store.get_router(router_id)["credential_ref_id"]

    put = client.put(
        f"/api/router-control/v1/routers/{router_id}/credentials",
        json={"kind": "management_password", "secret": "second-cred"},
        headers={"Idempotency-Key": "put-cred-revoke-race"},
    )
    assert put.status_code == 201
    cred_b = put.json()["credential_ref_id"]
    assert vault.use(cred_b) == "second-cred"

    first = client.post(
        f"/api/router-control/v1/routers/{router_id}/credentials/{cred_a}/revoke",
        headers={"Idempotency-Key": "revoke-race-key"},
    )
    assert first.status_code == 202

    monkeypatch.setattr(store, "peek_idempotency", lambda **_kwargs: None)

    second = client.post(
        f"/api/router-control/v1/routers/{router_id}/credentials/{cred_b}/revoke",
        headers={"Idempotency-Key": "revoke-race-key"},
    )
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "idempotency.conflict"
    # Loser must not have revoked cred_b
    assert vault.use(cred_b) == "second-cred"


def test_cancel_202_to_200_idempotency_replay(client) -> None:
    r = client.post(
        "/api/router-control/v1/routers",
        json={
            "display_name": "Cancel Async Router",
            "vendor": "V",
            "model": "M",
            "endpoint": {"kind": "management_https", "host": "10.0.0.10", "port": 443},
            "management_password": "pw",
        },
        headers={"Idempotency-Key": "enroll-cancel-async"},
    )
    job_id = r.json()["job_id"]
    store = client.app.state.host.runtime.store
    claim = store.claim_job(worker_id="w1", now_epoch=1_000_000)
    assert claim is not None
    assert claim.job_id == job_id

    c1 = client.post(
        f"/api/router-control/v1/jobs/{job_id}/cancel",
        headers={"Idempotency-Key": "cancel-async-1"},
    )
    assert c1.status_code == 202
    assert c1.json()["cancel_requested"] is True

    replay_202 = client.post(
        f"/api/router-control/v1/jobs/{job_id}/cancel",
        headers={"Idempotency-Key": "cancel-async-1"},
    )
    assert replay_202.status_code == 202

    store.mark_target_job_cancelled(target_job_id=job_id)
    job = store.get_job(job_id)
    assert job is not None
    assert job["status"] == "Cancelled"

    replay_200 = client.post(
        f"/api/router-control/v1/jobs/{job_id}/cancel",
        headers={"Idempotency-Key": "cancel-async-1"},
    )
    assert replay_200.status_code == 200
    assert replay_200.json()["status"] == "Cancelled"


def test_cancel_late_succeeded_replays_409(client) -> None:
    """Late Succeeded after cancel_requested clears flag; cancel replay returns 409."""
    store = client.app.state.host.runtime.store
    now = client.app.state.host.runtime.clock.now()
    site = store.create_site(display_name="Late Cancel API", now=now)
    router_id = store.enroll_router(
        site_id=site,
        display_name="R",
        vendor="V",
        model="M",
        identity_fingerprint="digest:late-cancel-api",
        host="127.0.0.1",
        now=now,
    )
    out = store.create_operation_bundle(
        router_id=router_id,
        operation_kind="apply_plan",
        idempotency_key="late-cancel-api-op",
        request_digest="sha256:late-cancel-api-op",
        initial_job_status="Queued",
        now=now,
    )
    claim = store.claim_job(worker_id="w1", lease_seconds=300)
    assert claim is not None
    store.record_job_progress(
        job_id=out.job_id,
        lease_owner=claim.lease_owner,
        fencing_token=claim.fencing_token,
        status="Running",
        step_kind="apply",
        step_status="Succeeded",
        now=now,
    )
    first = client.post(
        f"/api/router-control/v1/jobs/{out.job_id}/cancel",
        headers={"Idempotency-Key": "cancel-late-api"},
    )
    assert first.status_code == 202
    assert first.json()["cancel_requested"] is True

    store.complete_job(
        job_id=out.job_id,
        lease_owner=claim.lease_owner,
        fencing_token=claim.fencing_token,
        status="Succeeded",
        summary_redacted="converged",
        http_status=200,
        response_body={"status": "Succeeded", "job_id": out.job_id},
        now=now,
    )
    job = store.get_job(out.job_id)
    assert job is not None and not int(job["cancel_requested"])

    replay = client.post(
        f"/api/router-control/v1/jobs/{out.job_id}/cancel",
        headers={"Idempotency-Key": "cancel-late-api"},
    )
    assert replay.status_code == 409
    assert replay.json()["error"]["code"] == "job.already_terminal"

    fresh = client.post(
        f"/api/router-control/v1/jobs/{out.job_id}/cancel",
        headers={"Idempotency-Key": "cancel-late-api-new"},
    )
    assert fresh.status_code == 409
    assert fresh.json()["error"]["code"] == "job.already_terminal"


def test_etag_412(client) -> None:
    # enroll
    r = client.post(
        "/api/router-control/v1/routers",
        json={
            "display_name": "ETag Router",
            "vendor": "V",
            "model": "M",
            "endpoint": {"kind": "management_https", "host": "10.0.0.1", "port": 443},
            "management_password": "pw",
        },
        headers={"Idempotency-Key": "enroll-etag"},
    )
    router_id = r.json()["router_id"]
    store = client.app.state.host.runtime.store
    obs = store.insert_observation(
        router_id=router_id,
        identity_fingerprint=store.get_router(router_id)["identity_fingerprint"],
        resource_version="digest:rv:1",
        state_digest="digest:st:1",
        now=client.app.state.host.runtime.clock.now(),
    )
    put = client.put(
        f"/api/router-control/v1/routers/{router_id}/desired-revision",
        json={
            "based_on_observation_id": obs,
            "assignments": [
                {"profile_id": "p1", "logical_role": "primary", "desired_active": True}
            ],
        },
        headers={"Idempotency-Key": "des-1", "If-Match": "*"},
    )
    assert put.status_code == 200
    bad = client.put(
        f"/api/router-control/v1/routers/{router_id}/desired-revision",
        json={
            "based_on_observation_id": obs,
            "assignments": [],
        },
        headers={"Idempotency-Key": "des-2", "If-Match": '"stale"'},
    )
    assert bad.status_code == 412


def test_apply_fail_closed(client) -> None:
    r = client.post(
        "/api/router-control/v1/routers",
        json={
            "display_name": "Apply Router",
            "vendor": "V",
            "model": "M",
            "endpoint": {"kind": "management_https", "host": "10.0.0.2", "port": 443},
            "management_password": "pw",
        },
        headers={"Idempotency-Key": "enroll-apply"},
    )
    router_id = r.json()["router_id"]
    apply = client.post(
        f"/api/router-control/v1/routers/{router_id}/plans/plan_missing/apply",
        headers={"Idempotency-Key": "apply-1", "If-Match": '"plan:missing"'},
    )
    assert apply.status_code == 403
    assert apply.json()["error"]["code"] == "gate.mutation_forbidden"


def test_get_plan_redacted_changes(client) -> None:
    from tests.test_deployment_cas_session import _seed_p2_plan

    store = client.app.state.host.runtime.store
    rid, plan_id, _plan_digest, _plan_etag = _seed_p2_plan(store)
    items = store.get_plan_items(plan_id)
    assert items
    sample_intent = items[0]["intent_json"]
    assert sample_intent

    r = client.get(f"/api/router-control/v1/routers/{rid}/plans/{plan_id}")
    assert r.status_code == 200
    body = r.json()
    assert body["changes"]
    assert len(body["changes"]) == len(items)
    allowed_keys = {"ordinal", "change_kind", "summary", "target_resource_id"}
    for change in body["changes"]:
        assert set(change.keys()) <= allowed_keys
        assert isinstance(change["ordinal"], int)
        assert change["change_kind"]
        assert change["summary"]
        assert "intent_json" not in change
    assert "intent_json" not in r.text
    assert str(sample_intent) not in r.text


def test_cancel_job(client) -> None:
    r = client.post(
        "/api/router-control/v1/routers",
        json={
            "display_name": "Cancel Router",
            "vendor": "V",
            "model": "M",
            "endpoint": {"kind": "management_https", "host": "10.0.0.3", "port": 443},
            "management_password": "pw",
        },
        headers={"Idempotency-Key": "enroll-cancel"},
    )
    job_id = r.json()["job_id"]
    c = client.post(
        f"/api/router-control/v1/jobs/{job_id}/cancel",
        headers={"Idempotency-Key": "cancel-1"},
    )
    assert c.status_code == 200
    assert c.json()["status"] == "Cancelled"


def test_credentials_no_secret_echo(client) -> None:
    r = client.post(
        "/api/router-control/v1/routers",
        json={
            "display_name": "Cred Router",
            "vendor": "V",
            "model": "M",
            "endpoint": {"kind": "management_https", "host": "10.0.0.4", "port": 443},
            "management_password": "pw",
        },
        headers={"Idempotency-Key": "enroll-cred"},
    )
    router_id = r.json()["router_id"]
    put = client.put(
        f"/api/router-control/v1/routers/{router_id}/credentials",
        json={"kind": "RouterManagementPassword", "secret": "another-secret-xyz"},
        headers={"Idempotency-Key": "cred-1"},
    )
    assert put.status_code == 201
    assert "another-secret-xyz" not in put.text
    listed = client.get(f"/api/router-control/v1/routers/{router_id}/credentials")
    assert listed.status_code == 200
    assert "another-secret-xyz" not in listed.text
    assert "provider_locator" not in listed.text


def test_vpn_profile_import_idempotency_replay(client) -> None:
    body = {
        "display_name": "Booth AWG",
        "vpn_kind": "AmneziaWG",
        "profile_text": """
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.0.0.2/32
Jc = 5
Jmin = 50
Jmax = 1000
S1 = 80
S2 = 80
H1 = 1
H2 = 2
H3 = 3
H4 = 4
[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
Endpoint = example.com:51820
AllowedIPs = 0.0.0.0/0
""",
    }
    r1 = client.post(
        "/api/router-control/v1/vpn-profiles/import",
        json=body,
        headers={"Idempotency-Key": "import-replay"},
    )
    assert r1.status_code == 201
    d1 = r1.json()
    profiles_before = client.get("/api/router-control/v1/vpn-profiles").json()["items"]

    r2 = client.post(
        "/api/router-control/v1/vpn-profiles/import",
        json=body,
        headers={"Idempotency-Key": "import-replay"},
    )
    assert r2.status_code == 201
    d2 = r2.json()
    assert d2["profile_id"] == d1["profile_id"]
    profiles_after = client.get("/api/router-control/v1/vpn-profiles").json()["items"]
    assert len(profiles_after) == len(profiles_before)


def test_vpn_profile_import_idempotency_conflict(client) -> None:
    base = {
        "display_name": "Conflict AWG",
        "vpn_kind": "AmneziaWG",
        "profile_text": """
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.0.0.3/32
Jc = 5
Jmin = 50
Jmax = 1000
S1 = 80
S2 = 80
H1 = 1
H2 = 2
H3 = 3
H4 = 4
[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
Endpoint = example.com:51820
AllowedIPs = 0.0.0.0/0
""",
    }
    first = client.post(
        "/api/router-control/v1/vpn-profiles/import",
        json=base,
        headers={"Idempotency-Key": "import-conflict"},
    )
    assert first.status_code == 201
    profiles_before = len(client.get("/api/router-control/v1/vpn-profiles").json()["items"])

    second = client.post(
        "/api/router-control/v1/vpn-profiles/import",
        json={
            **base,
            "profile_text": base["profile_text"].replace("10.0.0.3/32", "10.0.0.4/32"),
        },
        headers={"Idempotency-Key": "import-conflict"},
    )
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "idempotency.conflict"
    assert len(client.get("/api/router-control/v1/vpn-profiles").json()["items"]) == profiles_before


def test_get_credential_metadata_by_id(client) -> None:
    r = client.post(
        "/api/router-control/v1/routers",
        json={
            "display_name": "Cred By Id Router",
            "vendor": "V",
            "model": "M",
            "endpoint": {"kind": "management_https", "host": "10.0.0.5", "port": 443},
            "management_password": "pw",
        },
        headers={"Idempotency-Key": "enroll-cred-by-id"},
    )
    router_id = r.json()["router_id"]
    listed = client.get(f"/api/router-control/v1/routers/{router_id}/credentials")
    cred_id = listed.json()["items"][0]["credential_ref_id"]
    got = client.get(
        f"/api/router-control/v1/routers/{router_id}/credentials/{cred_id}"
    )
    assert got.status_code == 200
    body = got.json()
    assert body["credential_ref_id"] == cred_id
    assert set(body) == {
        "credential_ref_id",
        "kind",
        "provider",
        "created_at",
        "rotated_at",
        "revoked_at",
    }
    assert "provider_locator" not in got.text


def test_get_vpn_profile_and_validate(client) -> None:
    imp = client.post(
        "/api/router-control/v1/vpn-profiles/import",
        json={
            "display_name": "Detail AWG",
            "wg_id": "Wireguard5",
            "vpn_kind": "AmneziaWG",
            "profile_text": """
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.0.0.23/32
Jc = 5
Jmin = 50
Jmax = 1000
S1 = 80
S2 = 80
H1 = 1
H2 = 2
H3 = 3
H4 = 4
[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
Endpoint = example.com:51820
AllowedIPs = 0.0.0.0/0
""",
        },
        headers={"Idempotency-Key": "import-detail"},
    )
    assert imp.status_code == 201
    profile_id = imp.json()["profile_id"]
    detail = client.get(f"/api/router-control/v1/vpn-profiles/{profile_id}")
    assert detail.status_code == 200
    assert detail.json()["profile_id"] == profile_id
    validated = client.post(
        f"/api/router-control/v1/vpn-profiles/{profile_id}/validate",
        headers={"Idempotency-Key": "validate-1"},
    )
    assert validated.status_code == 200
    assert validated.json()["validation_status"] == "Valid"


def test_preflight_fake_mode(client) -> None:
    r = client.post(
        "/api/router-control/v1/routers",
        json={
            "display_name": "Preflight Router",
            "vendor": "V",
            "model": "M",
            "endpoint": {"kind": "management_https", "host": "10.0.0.6", "port": 443},
            "management_password": "pw",
        },
        headers={"Idempotency-Key": "enroll-preflight"},
    )
    router_id = r.json()["router_id"]
    pf = client.post(
        f"/api/router-control/v1/routers/{router_id}/preflight",
        headers={"Idempotency-Key": "preflight-1"},
    )
    assert pf.status_code == 202
    assert pf.json()["status"] == "Queued"


def test_auth_required_for_normalized_api_path(app_env) -> None:
    from fastapi.testclient import TestClient

    with TestClient(app_env) as c:
        r = c.get("/api//router-control/v1/status")
    assert r.status_code == 401


def test_degraded_blocks_mutation_but_status_ok(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    application = create_app(
        db_path=tmp_path / "degraded.sqlite3",
        feature_state="Degraded",
    )
    from fastapi.testclient import TestClient

    with TestClient(application) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        status = c.get("/api/router-control/v1/status")
        assert status.status_code == 200
        assert status.json()["feature_state"] == "Degraded"
        enroll = c.post(
            "/api/router-control/v1/routers",
            json={
                "display_name": "Degraded Router",
                "vendor": "V",
                "model": "M",
                "endpoint": {"kind": "management_https", "host": "10.0.0.7", "port": 443},
                "management_password": "pw",
            },
            headers={"Idempotency-Key": "degraded-enroll"},
        )
    assert enroll.status_code == 503
    assert enroll.json()["error"]["code"] == "feature.degraded"


def test_p2_plan_create_rejects_unknown_fields(client) -> None:
    site_id = client.app.state.host.ensure_default_site()
    router_id = client.app.state.host.runtime.store.enroll_router(
        site_id=site_id,
        display_name="R",
        vendor="Fake",
        model="M1",
        identity_fingerprint="digest:fp",
        host="127.0.0.1",
    )
    r = client.post(
        f"/api/router-control/v1/routers/{router_id}/plans",
        json={
            "revision_id": "rev-x",
            "observation_id": "obs-x",
            "deployment_revision_id": "dep-x",
            "extra_field": True,
        },
        headers={"Idempotency-Key": "plan-unk", "If-Match": '"rev:*"'},
    )
    assert r.status_code == 422
    body = r.json()
    if "error" in body:
        msg = body["error"]["message"]
        assert "unknown fields" in msg or "extra" in msg.lower()
    else:
        assert any("extra_field" in str(item.get("loc", [])) for item in body.get("detail", []))


def test_managed_resources_endpoint(client) -> None:
    site_id = client.app.state.host.ensure_default_site()
    router_id = client.app.state.host.runtime.store.enroll_router(
        site_id=site_id,
        display_name="R",
        vendor="Fake",
        model="M1",
        identity_fingerprint="digest:fp",
        host="127.0.0.1",
    )
    r = client.get(f"/api/router-control/v1/routers/{router_id}/managed-resources")
    assert r.status_code == 200
    assert r.json()["items"] == []


def test_openapi_p2_publications_and_deployment_contract(app_env) -> None:
    schema = app_env.openapi()
    paths = schema["paths"]
    components = schema.get("components", {}).get("schemas", {})

    def body_schema(path_key: str) -> dict:
        post = paths[path_key]["post"]
        body = post["requestBody"]["content"]["application/json"]["schema"]
        ref = body.get("$ref")
        if ref:
            name = ref.rsplit("/", 1)[-1]
            return components[name]
        return body

    pub_path = "/api/router-control/v1/event-presets/{preset_id}/publications"
    pub_post = paths[pub_path]["post"]
    assert "201" in pub_post["responses"]
    assert body_schema(pub_path).get("additionalProperties") is False
    pub_params = {p["name"]: p for p in pub_post["parameters"]}
    assert pub_params["Idempotency-Key"]["required"] is True
    assert pub_params["If-Match"]["required"] is True

    dep_path = "/api/router-control/v1/routers/{router_id}/deployment-revisions"
    dep_post = paths[dep_path]["post"]
    assert "201" in dep_post["responses"]
    assert body_schema(dep_path).get("additionalProperties") is False
    dep_params = {p["name"]: p for p in dep_post["parameters"]}
    assert dep_params["Idempotency-Key"]["required"] is True


def test_offline_host_uses_injected_vault_not_dpapi(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from router_control.adapters.secrets.memory import MemoryVault
    from router_control.composition import resolve_host_vault

    monkeypatch.delenv("RC_VAULT", raising=False)
    injected = MemoryVault()
    resolved = resolve_host_vault(vault=injected, secrets_root=tmp_path / "secrets")
    assert resolved is injected

    application = create_app(
        db_path=tmp_path / "vault-offline.sqlite3",
        adapter_mode="fake",
        vault=injected,
    )
    assert application.state.host.runtime.vault is injected


def test_fake_mode_selects_dpapi_vault_without_live_adapter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sys
    from unittest.mock import patch

    from router_control.adapters.secrets.memory import MemoryVault

    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.delenv("RC_VAULT", raising=False)
    monkeypatch.delitem(sys.modules, "pytest", raising=False)
    dpapi_stand_in = MemoryVault()
    with patch(
        "router_control.adapters.secrets.dpapi.WindowsDpapiVault",
        return_value=dpapi_stand_in,
    ) as mock_dpapi:
        application = create_app(
            db_path=tmp_path / "fake-dpapi-vault.sqlite3",
            adapter_mode="fake",
            secrets_root=tmp_path / "secrets",
            enable_worker=False,
        )
    mock_dpapi.assert_called_once_with(root=tmp_path / "secrets")
    assert application.state.host.adapter_mode == "fake"
    assert application.state.host.runtime.vault is dpapi_stand_in
