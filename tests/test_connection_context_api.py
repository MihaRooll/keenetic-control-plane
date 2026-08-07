"""GET /routers/{router_id}/connection-context — server-side read of live connection context."""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from router_control.application.router_discovery import (
    ENROLLMENT_DRAFT_LIFECYCLE,
    ENROLLMENT_DRAFT_MODEL,
)
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie


def _fingerprint_for(key_bytes: bytes) -> str:
    digest = hashlib.sha256(key_bytes).digest()
    return f"SHA256:{base64.b64encode(digest).decode('ascii').rstrip('=')}"


@pytest.fixture
def app_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")
    application = create_app(db_path=tmp_path / "conn-ctx.sqlite3", allow_fake_mutations=False)
    return application


@pytest.fixture
def client(app_env):
    from fastapi.testclient import TestClient

    with TestClient(app_env) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield c


def _enroll_with_credential(
    app_env,
    *,
    display_name: str = "R1",
    model: str = "M1",
    host: str = "192.168.1.1",
    created_at: datetime | None = None,
    lifecycle: str | None = None,
) -> tuple[str, str]:
    store = app_env.state.host.runtime.store
    ts = created_at or datetime(2026, 8, 3, tzinfo=UTC)
    site = store.create_site(display_name="Lab", now=ts)
    router_id = store.enroll_router(
        site_id=site,
        display_name=display_name,
        vendor="Fake",
        model=model,
        identity_fingerprint=f"digest:fp:{display_name}",
        host=host,
        source_address="192.168.2.10",
        now=ts,
    )
    if lifecycle is not None:
        store._conn.execute(
            "UPDATE routers SET lifecycle_status = ? WHERE router_id = ?",
            (lifecycle, router_id),
        )
    cred_id = store.insert_credential_ref(
        router_id=router_id,
        kind="RouterManagementPassword",
        provider="test",
        provider_locator=f"loc-{display_name}",
        now=ts,
    )
    store.set_router_credential_ref(router_id, cred_id, now=ts)
    return router_id, cred_id


def _seed_draft_router(
    app_env,
    *,
    suffix: str,
    created_at: datetime,
    host: str = "192.168.2.1",
) -> str:
    router_id, _ = _enroll_with_credential(
        app_env,
        display_name=f"Draft {suffix}",
        model=ENROLLMENT_DRAFT_MODEL,
        host=host,
        created_at=created_at,
        lifecycle=ENROLLMENT_DRAFT_LIFECYCLE,
    )
    return router_id


def _make_live_ready(
    store,
    router_id: str,
    cred_id: str,
    *,
    pin_bytes: bytes = b"ctx-live-ready",
    pinned_at: str = "2026-08-03T12:00:00Z",
) -> str:
    pin = _fingerprint_for(pin_bytes)
    store.set_endpoint_ssh_host_key(
        router_id,
        pin,
        "ssh-ed25519",
        "learned_confirmed",
        pinned_at=pinned_at,
    )
    store.set_endpoint_management_username(router_id, "lab-operator")
    store.set_router_credential_ref(
        router_id,
        cred_id,
        now=datetime(2026, 8, 3, tzinfo=UTC),
    )
    return pin


def test_restore_candidate_requires_auth(app_env) -> None:
    from fastapi.testclient import TestClient

    with TestClient(app_env) as c:
        response = c.get("/api/router-control/v1/connection-context/restore-candidate")
    assert response.status_code == 401


def test_restore_candidate_genuine_enrolled_without_pin_reports_gaps(
    client, app_env
) -> None:
    """Enrolled record without pin is the restore candidate; gaps reported honestly."""
    router_id, cred_id = _enroll_with_credential(
        app_env,
        display_name="Lab NC-1812",
        model="NC-1812",
        host="192.168.2.1",
        lifecycle="Enrolled",
    )
    response = client.get("/api/router-control/v1/connection-context/restore-candidate")
    assert response.status_code == 200
    body = response.json()
    assert body["restore_candidate"] is True
    assert body["router_id"] == router_id
    assert body["host"] == "192.168.2.1"
    assert body["port"] == 443
    assert body["source_address"] == "192.168.2.10"
    assert body["credential_ref_id"] == cred_id
    assert body["ssh_host_key"]["confirmed"] is False
    assert body["username_available"] is False
    assert body["live_ready"] is False
    assert "ssh_host_key_sha256" in body["missing"]
    assert "username" in body["missing"]
    assert "username" not in body


def test_restore_candidate_prefers_pinned_real_router_over_newer_drafts(
    client,
    app_env,
) -> None:
    """Six newer PendingDiscovery drafts + one older pinned live-ready router."""
    base = datetime(2026, 8, 3, 10, 0, tzinfo=UTC)
    for index in range(6):
        _seed_draft_router(
            app_env,
            suffix=str(index),
            created_at=base + timedelta(minutes=index + 1),
        )
    real_id, real_cred = _enroll_with_credential(
        app_env,
        display_name="Lab NC-1812",
        model="NC-1812",
        host="192.168.2.1",
        created_at=base,
        lifecycle="Enrolled",
    )
    pin = _make_live_ready(app_env.state.host.runtime.store, real_id, real_cred)
    response = client.get("/api/router-control/v1/connection-context/restore-candidate")
    assert response.status_code == 200
    body = response.json()
    assert body["restore_candidate"] is True
    assert body["router_id"] == real_id
    assert body["host"] == "192.168.2.1"
    assert body["ssh_host_key"]["confirmed"] is True
    assert body["ssh_host_key"]["fingerprint_sha256"] == pin
    assert body["live_ready"] is True
    assert body["missing"] == []
    assert "username" not in body


def test_restore_candidate_cache_control_no_store(client, app_env) -> None:
    router_id, cred_id = _enroll_with_credential(app_env)
    _make_live_ready(app_env.state.host.runtime.store, router_id, cred_id)
    response = client.get("/api/router-control/v1/connection-context/restore-candidate")
    assert response.status_code == 200
    assert response.headers.get("Cache-Control") == "no-store"
    assert response.headers.get("Vary") == "Cookie"


def test_restore_candidate_openapi_field_set() -> None:
    from router_control_host.ssh_host_key_routes import (
        ConnectionContextResponse,
        NoRestoreCandidateResponse,
        RestoreCandidateConnectionContextResponse,
    )

    ctx_fields = set(ConnectionContextResponse.model_fields.keys())
    found_fields = set(RestoreCandidateConnectionContextResponse.model_fields.keys())
    assert found_fields == ctx_fields | {"restore_candidate"}
    assert set(NoRestoreCandidateResponse.model_fields.keys()) == {"restore_candidate"}
    assert "username" not in RestoreCandidateConnectionContextResponse.model_fields


def test_connection_context_requires_auth(app_env) -> None:
    from fastapi.testclient import TestClient

    router_id, _ = _enroll_with_credential(app_env)
    with TestClient(app_env) as c:
        response = c.get(f"/api/router-control/v1/routers/{router_id}/connection-context")
    assert response.status_code == 401


def test_connection_context_unknown_router_404(client) -> None:
    response = client.get("/api/router-control/v1/routers/rtr_nonexistent/connection-context")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "resource.not_found"


def test_connection_context_no_pin_returns_confirmed_false(client, app_env) -> None:
    router_id, cred_id = _enroll_with_credential(app_env)
    response = client.get(f"/api/router-control/v1/routers/{router_id}/connection-context")
    assert response.status_code == 200
    body = response.json()
    assert body["router_id"] == router_id
    assert body["host"] == "192.168.1.1"
    assert body["credential_ref_id"] == cred_id
    assert body["ssh_host_key"]["confirmed"] is False
    assert body["username_available"] is False
    assert body["live_ready"] is False
    assert "ssh_host_key_sha256" in body["missing"]
    assert "username" in body["missing"]
    assert "username" not in body
    assert "password" not in str(body)


def test_connection_context_full_live_ready(client, app_env) -> None:
    router_id, cred_id = _enroll_with_credential(app_env)
    store = app_env.state.host.runtime.store
    pin = _fingerprint_for(b"ctx-live-ready")
    store.set_endpoint_ssh_host_key(
        router_id,
        pin,
        "ssh-ed25519",
        "learned_confirmed",
        pinned_at="2026-08-03T12:00:00Z",
    )
    store.set_endpoint_management_username(router_id, "lab-operator")
    response = client.get(f"/api/router-control/v1/routers/{router_id}/connection-context")
    assert response.status_code == 200
    body = response.json()
    assert body["credential_ref_id"] == cred_id
    assert body["ssh_host_key"]["confirmed"] is True
    assert body["ssh_host_key"]["fingerprint_sha256"] == pin
    assert body["ssh_host_key"]["algorithm"] == "ssh-ed25519"
    assert body["ssh_host_key"]["pinned_at"] == "2026-08-03T12:00:00Z"
    assert body["ssh_host_key"]["provenance"] == "learned_confirmed"
    assert body["username_available"] is True
    assert body["live_ready"] is True
    assert body["missing"] == []
    assert "username" not in body
    assert "reachable" not in body


def test_wizard_draft_persists_management_username(client, app_env) -> None:
    response = client.post(
        "/api/router-control/v1/lab/wizard-draft-router",
        headers={"Idempotency-Key": "wizard-username-persist-1"},
        json={
            "host": "10.20.30.40",
            "username": "wizard-mgmt-user",
            "secret": "synthetic-wizard-secret-not-real",
        },
    )
    assert response.status_code == 201
    router_id = response.json()["router_id"]
    store = app_env.state.host.runtime.store
    assert store.get_endpoint_management_username(router_id) == "wizard-mgmt-user"
    ctx = client.get(f"/api/router-control/v1/routers/{router_id}/connection-context")
    assert ctx.status_code == 200
    assert ctx.json()["username_available"] is True
    assert "username" not in ctx.json()


def test_connection_context_cache_control_no_store(client, app_env) -> None:
    router_id, _ = _enroll_with_credential(app_env)
    response = client.get(f"/api/router-control/v1/routers/{router_id}/connection-context")
    assert response.status_code == 200
    assert response.headers.get("Cache-Control") == "no-store"
    assert response.headers.get("Vary") == "Cookie"


def test_connection_context_openapi_field_set() -> None:
    from router_control_host.ssh_host_key_routes import ConnectionContextResponse

    expected = {
        "router_id",
        "host",
        "port",
        "source_address",
        "credential_ref_id",
        "ssh_host_key",
        "username_available",
        "live_ready",
        "missing",
    }
    assert set(ConnectionContextResponse.model_fields.keys()) == expected
    assert "username" not in ConnectionContextResponse.model_fields


def test_management_username_post_requires_auth(app_env) -> None:
    from fastapi.testclient import TestClient

    router_id, _ = _enroll_with_credential(app_env)
    with TestClient(app_env) as c:
        response = c.post(
            f"/api/router-control/v1/routers/{router_id}/management-username",
            json={"username": "synthetic-mgmt-user"},
        )
    assert response.status_code == 401


def test_management_username_post_unknown_router_404(client) -> None:
    response = client.post(
        "/api/router-control/v1/routers/rtr_nonexistent/management-username",
        json={"username": "synthetic-mgmt-user"},
    )
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "resource.not_found"


def test_management_username_post_enables_live_ready(client, app_env) -> None:
    router_id, cred_id = _enroll_with_credential(app_env)
    store = app_env.state.host.runtime.store
    pin = _fingerprint_for(b"mgmt-user-pin")
    store.set_endpoint_ssh_host_key(
        router_id,
        pin,
        "ssh-ed25519",
        "operator_supplied",
        pinned_at="2026-08-03T12:00:00Z",
    )
    before = client.get(f"/api/router-control/v1/routers/{router_id}/connection-context")
    assert before.json()["username_available"] is False
    assert "username" in before.json()["missing"]

    response = client.post(
        f"/api/router-control/v1/routers/{router_id}/management-username",
        json={"username": "synthetic-mgmt-user"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["router_id"] == router_id
    assert body["username_available"] is True
    assert "username" not in body

    after = client.get(f"/api/router-control/v1/routers/{router_id}/connection-context")
    assert after.json()["username_available"] is True
    assert after.json()["live_ready"] is True
    assert after.json()["missing"] == []
    assert after.json()["credential_ref_id"] == cred_id


def test_management_username_post_cache_control_no_store(client, app_env) -> None:
    router_id, _ = _enroll_with_credential(app_env)
    response = client.post(
        f"/api/router-control/v1/routers/{router_id}/management-username",
        json={"username": "synthetic-mgmt-user"},
    )
    assert response.status_code == 200
    assert response.headers.get("Cache-Control") == "no-store"
    assert response.headers.get("Vary") == "Cookie"


def test_management_username_post_idempotent_overwrite(client, app_env) -> None:
    router_id, _ = _enroll_with_credential(app_env)
    first = client.post(
        f"/api/router-control/v1/routers/{router_id}/management-username",
        json={"username": "synthetic-user-a"},
    )
    second = client.post(
        f"/api/router-control/v1/routers/{router_id}/management-username",
        json={"username": "synthetic-user-b"},
    )
    assert first.status_code == 200
    assert second.status_code == 200
    store = app_env.state.host.runtime.store
    assert store.get_endpoint_management_username(router_id) == "synthetic-user-b"
