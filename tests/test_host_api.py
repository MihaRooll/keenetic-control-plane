"""SLICE-3 FastAPI host TestClient coverage."""

from __future__ import annotations

from pathlib import Path

import pytest
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
    assert r.json()["feature_state"] == "Ready"
    assert r.json()["worker_state"] == "Stopped"
    assert "X-Request-Id" in r.headers


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
        headers={"Idempotency-Key": "apply-1"},
    )
    assert apply.status_code == 403
    assert apply.json()["error"]["code"] == "gate.mutation_forbidden"


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
        "profile_document": {"interface": {"listen_port": 51820}},
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
        "profile_document": {"interface": {"listen_port": 51821}},
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
        json={**base, "profile_document": {"interface": {"listen_port": 51822}}},
        headers={"Idempotency-Key": "import-conflict"},
    )
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "idempotency.conflict"
    assert len(client.get("/api/router-control/v1/vpn-profiles").json()["items"]) == profiles_before
