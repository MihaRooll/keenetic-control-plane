"""SSH host-key learn/confirm host API."""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import paramiko
import pytest
from router_control.adapters.netcraze.errors import SshTunnelError
from router_control.application import ssh_host_key_pin as ssh_host_key_pin_module
from router_control.application.ssh_host_key_pin import LearnCandidateResult
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie


def _fingerprint_for(key_bytes: bytes) -> str:
    digest = hashlib.sha256(key_bytes).digest()
    return f"SHA256:{base64.b64encode(digest).decode('ascii').rstrip('=')}"


@pytest.fixture
def app_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")
    application = create_app(db_path=tmp_path / "ssh-key-api.sqlite3", allow_fake_mutations=False)
    return application


@pytest.fixture
def client(app_env):
    from fastapi.testclient import TestClient

    with TestClient(app_env) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield c


def _enroll_router(app_env, *, source_address: str | None = "192.168.2.10") -> str:
    store = app_env.state.host.runtime.store
    site = store.create_site(display_name="Lab", now=datetime(2026, 7, 31, tzinfo=UTC))
    return store.enroll_router(
        site_id=site,
        display_name="R1",
        vendor="Fake",
        model="M1",
        identity_fingerprint="digest:fp:api",
        host="192.168.1.1",
        source_address=source_address,
        now=datetime(2026, 7, 31, tzinfo=UTC),
    )


def test_connection_context_get_requires_auth(app_env) -> None:
    from fastapi.testclient import TestClient

    router_id = _enroll_router(app_env)
    with TestClient(app_env) as c:
        response = c.get(
            f"/api/router-control/v1/routers/{router_id}/connection-context",
        )
    assert response.status_code == 401


def test_ssh_host_key_learn_requires_auth(app_env) -> None:
    from fastapi.testclient import TestClient

    router_id = _enroll_router(app_env)
    with TestClient(app_env) as c:
        response = c.post(
            f"/api/router-control/v1/routers/{router_id}/ssh-host-key/learn",
            json={"host": "192.168.1.1"},
        )
    assert response.status_code == 401


@patch("router_control_host.ssh_host_key_routes.learn_candidate")
def test_ssh_host_key_learn_resolves_source_from_stored_endpoint(
    mock_learn, client, app_env
) -> None:
    """Omitted source_address resolves from endpoint; bound dial receives it."""
    router_id = _enroll_router(app_env)
    store = app_env.state.host.runtime.store
    store._conn.execute(
        "UPDATE router_endpoints SET source_address = ? WHERE router_id = ?",
        ("192.168.2.10", router_id),
    )
    pin = _fingerprint_for(b"learn-resolved-source")
    mock_learn.return_value = LearnCandidateResult(
        fingerprint_sha256=pin,
        algorithm="ssh-ed25519",
        warning="Verify out-of-band",
    )
    response = client.post(
        f"/api/router-control/v1/routers/{router_id}/ssh-host-key/learn",
        json={"host": "192.168.1.1", "port": 22},
    )
    assert response.status_code == 200
    mock_learn.assert_called_once()
    assert mock_learn.call_args.kwargs["source_address"] == "192.168.2.10"


@patch("router_control_host.ssh_host_key_routes.learn_candidate")
def test_ssh_host_key_learn_fails_closed_without_resolvable_source(
    mock_learn, client, app_env
) -> None:
    """No body source and no stored endpoint source → 422, no dial."""
    router_id = _enroll_router(app_env, source_address=None)
    response = client.post(
        f"/api/router-control/v1/routers/{router_id}/ssh-host-key/learn",
        json={"host": "192.168.1.1", "port": 22},
    )
    assert response.status_code == 422
    body = response.json()
    assert body["error"]["code"] == "ssh_host_key.learn_failed"
    assert "source_address" in body["error"]["message"]
    mock_learn.assert_not_called()


@patch("router_control_host.ssh_host_key_routes.learn_candidate")
def test_ssh_host_key_learn_success(mock_learn, client, app_env) -> None:
    router_id = _enroll_router(app_env)
    pin = _fingerprint_for(b"learn-success")
    mock_learn.return_value = LearnCandidateResult(
        fingerprint_sha256=pin,
        algorithm="ssh-ed25519",
        warning="Verify out-of-band",
    )
    response = client.post(
        f"/api/router-control/v1/routers/{router_id}/ssh-host-key/learn",
        json={"host": "192.168.1.1", "port": 22},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["fingerprint_sha256"] == pin
    assert body["algorithm"] == "ssh-ed25519"
    assert body["warning"]
    pending = app_env.state.host.ssh_host_key_pending_learn.get(router_id)
    assert pending is not None
    assert pending.fingerprint_sha256 == pin


def test_ssh_host_key_learn_rejects_extra_fields(client, app_env) -> None:
    router_id = _enroll_router(app_env)
    response = client.post(
        f"/api/router-control/v1/routers/{router_id}/ssh-host-key/learn",
        json={"host": "192.168.1.1", "password": "must-not-accept"},
    )
    assert response.status_code == 422


@patch("router_control_host.ssh_host_key_routes.learn_candidate")
def test_ssh_host_key_learn_timeout_returns_422_not_500(
    mock_learn, client, app_env
) -> None:
    """Регрессия: недоступный роутер (TimeoutError) → 422 learn_failed, не 500."""
    router_id = _enroll_router(app_env)
    mock_learn.side_effect = TimeoutError("timed out")
    response = client.post(
        f"/api/router-control/v1/routers/{router_id}/ssh-host-key/learn",
        json={"host": "192.168.99.99", "port": 22},
    )
    assert response.status_code == 422
    body = response.json()
    assert body["error"]["code"] == "ssh_host_key.learn_failed"
    assert body["error"]["message"] == (
        "Could not reach the router to learn the SSH host key"
    )
    assert "timed out" not in body["error"]["message"]


@patch("router_control_host.ssh_host_key_routes.learn_candidate")
def test_ssh_host_key_learn_os_error_base_class_caught(
    mock_learn, client, app_env
) -> None:
    """Детектор: без перехвата OSError маршрут вернул бы 500 вместо 422."""
    router_id = _enroll_router(app_env)
    mock_learn.side_effect = OSError("connection refused")
    response = client.post(
        f"/api/router-control/v1/routers/{router_id}/ssh-host-key/learn",
        json={"host": "192.168.1.1"},
    )
    assert response.status_code == 422
    body = response.json()
    assert body["error"]["code"] == "ssh_host_key.learn_failed"
    assert "connection refused" not in body["error"]["message"]


@patch("router_control_host.ssh_host_key_routes.learn_candidate")
def test_ssh_host_key_learn_ssh_tunnel_error_returns_422_not_500(
    mock_learn, client, app_env
) -> None:
    """Регрессия: SshTunnelError (SSH banner/session) → 422 learn_failed, не 500."""
    router_id = _enroll_router(app_env)
    mock_learn.side_effect = SshTunnelError(
        "Could not reach the router to learn the SSH host key"
    )
    response = client.post(
        f"/api/router-control/v1/routers/{router_id}/ssh-host-key/learn",
        json={"host": "192.168.99.99", "port": 22},
    )
    assert response.status_code == 422
    body = response.json()
    assert body["error"]["code"] == "ssh_host_key.learn_failed"
    assert body["error"]["message"] == (
        "Could not reach the router to learn the SSH host key"
    )


@patch("router_control_host.ssh_host_key_routes.learn_candidate")
def test_ssh_host_key_learn_ssh_exception_returns_422_not_500(
    mock_learn, client, app_env
) -> None:
    """Регрессия: paramiko SSHException через real learn_candidate → 422, не 500."""
    real_learn = ssh_host_key_pin_module.learn_candidate

    def _learn_with_banner_failure(
        host: str,
        *,
        port: int = 22,
        connect_timeout: float = 10.0,
        source_address: str | None = None,
        **kwargs: Any,
    ) -> LearnCandidateResult:
        transport = MagicMock()
        transport.start_client.side_effect = paramiko.ssh_exception.SSHException(
            "Error reading SSH protocol banner"
        )

        def factory(**_factory_kwargs: object) -> Any:
            return transport

        return real_learn(
            host,
            port=port,
            connect_timeout=connect_timeout,
            source_address=source_address,
            transport_factory=factory,
            **kwargs,
        )

    mock_learn.side_effect = _learn_with_banner_failure
    router_id = _enroll_router(app_env)
    response = client.post(
        f"/api/router-control/v1/routers/{router_id}/ssh-host-key/learn",
        json={"host": "192.168.99.99", "port": 22},
    )
    assert response.status_code == 422
    body = response.json()
    assert body["error"]["code"] == "ssh_host_key.learn_failed"
    assert body["error"]["message"] == (
        "Could not reach the router to learn the SSH host key"
    )
    assert "Error reading SSH protocol banner" not in body["error"]["message"]
    mock_learn.assert_called_once()


def test_ssh_host_key_learn_rejects_password_field(client, app_env) -> None:
    router_id = _enroll_router(app_env)
    response = client.post(
        f"/api/router-control/v1/routers/{router_id}/ssh-host-key/learn",
        json={"host": "192.168.1.1", "management_password": "secret"},
    )
    assert response.status_code == 422


@patch("router_control_host.ssh_host_key_routes.learn_candidate")
def test_ssh_host_key_confirm_success(mock_learn, client, app_env) -> None:
    router_id = _enroll_router(app_env)
    pin = _fingerprint_for(b"confirm-success")
    mock_learn.return_value = LearnCandidateResult(
        fingerprint_sha256=pin,
        algorithm="ssh-ed25519",
        warning="Verify out-of-band",
    )
    client.post(
        f"/api/router-control/v1/routers/{router_id}/ssh-host-key/learn",
        json={"host": "192.168.1.1"},
    )
    response = client.post(
        f"/api/router-control/v1/routers/{router_id}/ssh-host-key/confirm",
        json={
            "fingerprint_sha256": pin,
            "algorithm": "ssh-ed25519",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["fingerprint_sha256"] == pin
    assert body["provenance"] == "learned_confirmed"
    assert app_env.state.host.ssh_host_key_pending_learn.get(router_id) is None


def test_ssh_host_key_confirm_without_learn_rejects(client, app_env) -> None:
    router_id = _enroll_router(app_env)
    pin = _fingerprint_for(b"no-learn")
    response = client.post(
        f"/api/router-control/v1/routers/{router_id}/ssh-host-key/confirm",
        json={
            "fingerprint_sha256": pin,
            "algorithm": "ssh-ed25519",
        },
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "ssh_host_key.invalid_pin"


@patch("router_control_host.ssh_host_key_routes.learn_candidate")
def test_ssh_host_key_confirm_wrong_echo_rejects(mock_learn, client, app_env) -> None:
    router_id = _enroll_router(app_env)
    learned = _fingerprint_for(b"learned")
    wrong = _fingerprint_for(b"wrong-echo")
    mock_learn.return_value = LearnCandidateResult(
        fingerprint_sha256=learned,
        algorithm="ssh-ed25519",
        warning="Verify out-of-band",
    )
    client.post(
        f"/api/router-control/v1/routers/{router_id}/ssh-host-key/learn",
        json={"host": "192.168.1.1"},
    )
    response = client.post(
        f"/api/router-control/v1/routers/{router_id}/ssh-host-key/confirm",
        json={
            "fingerprint_sha256": wrong,
            "algorithm": "ssh-ed25519",
        },
    )
    assert response.status_code == 422
    assert "does not match pending learn" in response.json()["error"]["message"]


@patch("router_control_host.ssh_host_key_routes.learn_candidate")
def test_ssh_host_key_confirm_pin_conflict(mock_learn, client, app_env) -> None:
    router_id = _enroll_router(app_env)
    existing = _fingerprint_for(b"existing")
    candidate = _fingerprint_for(b"candidate")
    store = app_env.state.host.runtime.store
    store.set_endpoint_ssh_host_key(
        router_id,
        existing,
        "ssh-ed25519",
        "operator_supplied",
    )
    mock_learn.return_value = LearnCandidateResult(
        fingerprint_sha256=candidate,
        algorithm="ssh-ed25519",
        warning="Verify out-of-band",
    )
    client.post(
        f"/api/router-control/v1/routers/{router_id}/ssh-host-key/learn",
        json={"host": "192.168.1.1"},
    )
    response = client.post(
        f"/api/router-control/v1/routers/{router_id}/ssh-host-key/confirm",
        json={
            "fingerprint_sha256": candidate,
            "algorithm": "ssh-ed25519",
        },
    )
    assert response.status_code == 409
    body = response.json()
    assert body["error"]["code"] == "ssh_host_key.pin_conflict"
    details = body["error"]["details"][0]
    assert details["existing_fingerprint_sha256"] == existing
    assert details["candidate_fingerprint_sha256"] == candidate


@patch("router_control_host.ssh_host_key_routes.learn_candidate")
def test_ssh_host_key_confirm_overwrite(mock_learn, client, app_env) -> None:
    router_id = _enroll_router(app_env)
    old_pin = _fingerprint_for(b"oldpin")
    new_pin = _fingerprint_for(b"newpin")
    store = app_env.state.host.runtime.store
    store.set_endpoint_ssh_host_key(
        router_id,
        old_pin,
        "ssh-ed25519",
        "operator_supplied",
    )
    mock_learn.return_value = LearnCandidateResult(
        fingerprint_sha256=new_pin,
        algorithm="ssh-ed25519",
        warning="Verify out-of-band",
    )
    client.post(
        f"/api/router-control/v1/routers/{router_id}/ssh-host-key/learn",
        json={"host": "192.168.1.1"},
    )
    response = client.post(
        f"/api/router-control/v1/routers/{router_id}/ssh-host-key/confirm",
        json={
            "fingerprint_sha256": new_pin,
            "algorithm": "ssh-ed25519",
            "allow_overwrite": True,
        },
    )
    assert response.status_code == 200
    assert response.json()["fingerprint_sha256"] == new_pin
