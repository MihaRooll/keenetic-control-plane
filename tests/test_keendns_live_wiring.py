"""Offline tests for KeenDNS live apply identity tuple wiring."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest
from router_control.adapters.netcraze.allowlist import LAB_CLASS_EXPENDABLE
from router_control.adapters.netcraze.certification import GateACertification
from router_control.adapters.netcraze.startup_backup import StartupBackupMetadata
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie
from router_control_host.wifi_live_transport import LiveIdentityTupleMismatchError, WifiLiveSession

_API = "/api/router-control/v1/keendns/apply"
_OBSERVE_API = "/api/router-control/v1/keendns/observe"
_COMPONENT_DIGEST = "a" * 64
_FINGERPRINT_DIGEST = "b" * 64
_VALID_SSH_HOST_KEY_SHA256 = "SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM"

_LIVE_CONN: dict[str, str] = {
    "host": "192.168.2.1",
    "username": "admin",
    "router_credential_ref_id": "credref:router-admin",
    "ssh_host_key_sha256": _VALID_SSH_HOST_KEY_SHA256,
    "source_address": "192.168.2.10",
}

_ROUTER_ID = "router-lab-keendns"


def _seed_live_router(client) -> None:
    store = client.test_app.state.host.runtime.store
    site_id = store.create_site(display_name="KeenDNS Live Wiring Lab")
    store.enroll_router(
        site_id=site_id,
        display_name="KeenDNS Lab Router",
        vendor="Netcraze",
        model="NC-1812",
        identity_fingerprint="digest:keendns-live-wiring",
        host=_LIVE_CONN["host"],
        port=22,
        kind="ssh_tunnel",
        source_address=_LIVE_CONN["source_address"],
        router_id=_ROUTER_ID,
    )
    store.set_endpoint_ssh_host_key(
        _ROUTER_ID,
        _LIVE_CONN["ssh_host_key_sha256"],
        "ssh-ed25519",
        "operator_supplied",
    )

_APPLY_BODY = {
    "intent_kind": "book",
    "name": "sample-name",
    "domain": "netcraze.pro",
    "mode": "auto",
    "confirm_live_apply": True,
    "router_id": _ROUTER_ID,
    **_LIVE_CONN,
}


def _open_gate_a() -> GateACertification:
    now = datetime.now(UTC)
    return GateACertification(
        status="open",
        certification="ReadOnlyCertified",
        approved_scope="SLICE-4-readonly",
        model="NC-1812",
        model_display="Ultra (NC-1812)",
        firmware_version="5.01.C.1.0-0",
        firmware_display="5.1.1",
        ndm_build="0-b592e619a0",
        bsp_build="0-f371d30955",
        update_channel="Main",
        region="EA",
        component_set_digest=_COMPONENT_DIGEST,
        device_fingerprint_digest=_FINGERPRINT_DIGEST,
        physical_id_source="show.identification_digest",
        transport="ssh_tunnel",
        ssh_host_key_algorithm="ssh-ed25519",
        ssh_host_key_fingerprint_sha256=_VALID_SSH_HOST_KEY_SHA256,
        certification_eligible=True,
        evidence_recorded_at=now,
        evidence_path="data/artifacts/gate-a-probe.json",
        expires_at=now + timedelta(days=90),
        revocation_policy="human",
        gates_b_closed=True,
        gates_c_closed=True,
        gates_d_closed=True,
    )


class _LiveKeenDnsTransport:
    keendns_live_dispatch = True

    def __init__(self) -> None:
        self.dispatched = False

    def read_json(self, command: object, body: bytes | None = None) -> dict[str, object]:
        return {"component": {"ndns": {}, "wifi": {}}}

    def execute_sealed_rci_write(self, request: object) -> list[dict[str, object]]:
        self.dispatched = True
        return [{"parse": {"status": [{"status": "message", "ident": "Cloud::KeenDNS", "message": "ok"}]}}]


@pytest.fixture
def keendns_live_client(tmp_path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", LAB_CLASS_EXPENDABLE)
    app = create_app(db_path=tmp_path / "keendns-live.sqlite3", allow_fake_mutations=True)
    app.state.host.gate_a_certification = _open_gate_a()
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        client.test_app = app
        _seed_live_router(client)
        yield client


def test_keendns_live_apply_identity_mismatch_returns_422_zero_writes(
    keendns_live_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_transport = _LiveKeenDnsTransport()
    backup_calls: list[str] = []

    @contextmanager
    def _mock_live(**_kwargs: object):
        tunnel = MagicMock()
        yield WifiLiveSession(transport=session_transport, tunnel=tunnel)

    def _raise_mismatch(*_args: object, **_kwargs: object) -> None:
        raise LiveIdentityTupleMismatchError("tuple mismatch")

    def _track_backup(**_kwargs: object) -> StartupBackupMetadata:
        backup_calls.append("backup")
        raise AssertionError("backup must not run on identity mismatch")

    monkeypatch.setattr(
        "router_control_host.keendns_apply_routes.open_wifi_live_session",
        _mock_live,
    )
    monkeypatch.setattr(
        "router_control_host.keendns_apply_routes.ensure_live_gate_a_tuple_match",
        _raise_mismatch,
    )
    monkeypatch.setattr(
        "router_control_host.keendns_apply_routes.is_win32_live_capable",
        lambda: True,
    )
    monkeypatch.setattr(
        "router_control_host.keendns_apply_routes.backup_startup_config",
        _track_backup,
    )

    resp = keendns_live_client.post(_API, json=_APPLY_BODY)
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "keendns.identity_mismatch"
    assert backup_calls == []
    assert session_transport.dispatched is False


def _patch_tuple_match_ok(monkeypatch: pytest.MonkeyPatch, module: str) -> None:
    monkeypatch.setattr(
        f"{module}.ensure_live_gate_a_tuple_match",
        lambda *_args, **_kwargs: None,
    )


def test_keendns_live_apply_tuple_match_continues(
    keendns_live_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_transport = _LiveKeenDnsTransport()
    backup_calls: list[str] = []

    @contextmanager
    def _mock_live(**_kwargs: object):
        tunnel = MagicMock()
        yield WifiLiveSession(transport=session_transport, tunnel=tunnel)

    def _mock_backup(**_kwargs: object) -> StartupBackupMetadata:
        backup_calls.append("backup")
        return StartupBackupMetadata(
            artifact_type="startup_config_backup",
            endpoint="/ci/startup-config.txt",
            content_sha256="deadbeef" * 8,
            size_bytes=128,
            encrypted_locator="data/backups/startup-keendns-live.enc",
            metadata_locator="data/backups/startup-keendns-live.meta.json",
            recorded_at=datetime.now(UTC).isoformat(),
            transport_security="ssh_tunnel_pinned",
            host="192.168.2.1",
            device_fingerprint_digest=_FINGERPRINT_DIGEST,
            ssh_host_key_fingerprint_sha256=_VALID_SSH_HOST_KEY_SHA256,
            ssh_host_key_algorithm="ssh-ed25519",
        )

    monkeypatch.setattr(
        "router_control_host.keendns_apply_routes.open_wifi_live_session",
        _mock_live,
    )
    _patch_tuple_match_ok(monkeypatch, "router_control_host.keendns_apply_routes")
    monkeypatch.setattr(
        "router_control_host.keendns_apply_routes.is_win32_live_capable",
        lambda: True,
    )
    monkeypatch.setattr(
        "router_control_host.keendns_apply_routes.backup_startup_config",
        _mock_backup,
    )

    resp = keendns_live_client.post(_API, json=_APPLY_BODY)
    assert resp.status_code == 200
    body = resp.json()
    assert body["overall"] == "applied"
    assert body["backup_basename"] == "startup-keendns-live.enc"
    assert body["backup_content_sha256"] == "deadbeef" * 8
    assert backup_calls == ["backup"]
    assert session_transport.dispatched is True


class _ObserveLiveTransport:
    def execute_rci_parse(self, cli_command: str) -> dict[str, object]:
        if cli_command == "show acme":
            return {
                "acme": {
                    "default-domain": "abc123.netcraze.io",
                    "default-domain-certificate-valid": True,
                }
            }
        if cli_command == "show ndns":
            return {"name": "", "domain": "", "access": ""}
        if cli_command == "ndns get-booked":
            return {"continued": True, "message": "No booking found"}
        return {}


def test_keendns_observe_live_path_gate_a_and_transport(
    keendns_live_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_transport = _ObserveLiveTransport()

    @contextmanager
    def _mock_live(**_kwargs: object):
        tunnel = MagicMock()
        yield WifiLiveSession(transport=session_transport, tunnel=tunnel)

    monkeypatch.setattr(
        "router_control_host.keendns_observe_routes.open_wifi_live_session",
        _mock_live,
    )
    monkeypatch.setattr(
        "router_control_host.keendns_observe_routes.is_win32_live_capable",
        lambda: True,
    )

    resp = keendns_live_client.post(
        _OBSERVE_API,
        json=_LIVE_CONN,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["default_fqdn"] == "abc123.netcraze.io"
    assert body["ssl_valid"] is True
    assert body["name_reservation"] == "not_reserved"
    assert body["certification_eligible"] is False


def test_keendns_observe_live_gate_a_closed_returns_503(
    keendns_live_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keendns_live_client.test_app.state.host.gate_a_certification = None
    monkeypatch.setattr(
        "router_control_host.keendns_observe_routes.is_win32_live_capable",
        lambda: True,
    )
    resp = keendns_live_client.post(_OBSERVE_API, json=_LIVE_CONN)
    assert resp.status_code == 503
    assert resp.json()["error"]["code"] == "keendns.gate_a_required"
