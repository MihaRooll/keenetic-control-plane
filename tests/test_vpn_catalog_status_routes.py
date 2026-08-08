"""VPN catalog-status host API tests (offline only)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie

_CATALOG_STATUS_PATH = "/api/router-control/v1/vpn-profiles/catalog-status"
_TEST_WG = "Wireguard5"
_PLACEHOLDER_PEER = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="


def _healthy_peer_readback(*, wg_id: str = _TEST_WG) -> dict[str, Any]:
    return {
        "interface": {
            "id": wg_id,
            "state": "up",
            "up": True,
            "wireguard": {
                "peer": [
                    {
                        "public-key": _PLACEHOLDER_PEER,
                        "last-handshake": 1_700_000_000,
                        "online": "yes",
                        "rxbytes": 1024,
                        "txbytes": 2048,
                    }
                ],
            },
        }
    }


class ApiFakeWireguardTransport:
    def __init__(self, *, readback_sequence: list[Any] | None = None) -> None:
        self.readback_sequence = list(readback_sequence or [])
        self.parse_commands: list[str] = []

    def execute_rci_parse(self, cli_command: str) -> Any:
        self.parse_commands.append(cli_command)
        if self.readback_sequence:
            return self.readback_sequence.pop(0)
        return {"interface": {}}

    def execute_sealed_rci_write(self, request: Any) -> Any:
        _ = request
        return [{"parse": {"prompt": "(config)", "status": []}}]


@pytest.fixture
def catalog_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ADAPTER_MODE", "fake")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    app = create_app(db_path=tmp_path / "vpn-catalog-status.sqlite3", enable_worker=False)
    transport = ApiFakeWireguardTransport()
    app.state.host.wireguard_apply_transport_factory = lambda: transport
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        client.test_transport = transport
        client.store = app.state.host.runtime.store
        yield client


def _seed_router(store: Any) -> str:
    site_id = store.create_site(display_name="Catalog Status Lab")
    return store.enroll_router(
        site_id=site_id,
        display_name="Catalog Status Router",
        vendor="Fake",
        model="M1",
        identity_fingerprint="digest:catalog-status",
        host="127.0.0.1",
    )


def _seed_profile(store: Any, *, display_name: str, metadata: dict[str, object] | None = None) -> str:
    meta = metadata if metadata is not None else {"wg_id": _TEST_WG}
    return store.import_profile(
        display_name=display_name,
        vpn_kind="AmneziaWG",
        content_digest=f"digest-{display_name}",
        metadata_json=json.dumps(meta),
    )


def _internet_status_readback(*, interface: str | None = _TEST_WG) -> dict[str, Any]:
    payload: dict[str, Any] = {"internet": "yes", "checked": "2026-08-01T12:00:00Z"}
    if interface is not None:
        payload["interface"] = interface
    return payload


def test_catalog_status_inactive_not_probed(catalog_client) -> None:
    store = catalog_client.store
    _seed_profile(store, display_name="inactive-one")
    resp = catalog_client.post(_CATALOG_STATUS_PATH, json={})
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert len(items) == 1
    item = items[0]
    assert item["is_active"] is False
    assert item["live_probed"] is False
    assert item["live_tunnel_verification_status"] is None
    assert item["probe_error"] is None
    assert item["routed_through_tunnel"] is None
    assert item["routing_probe_status"] == "not_applicable"
    assert catalog_client.test_transport.parse_commands == []


def test_catalog_status_active_healthy_requires_handshake(catalog_client) -> None:
    store = catalog_client.store
    router_id = _seed_router(store)
    profile_id = _seed_profile(store, display_name="active-one")
    store.upsert_tunnel_assignment(
        router_id=router_id,
        profile_id=profile_id,
        observed_vendor_locator=_TEST_WG,
        policy_metadata_json=json.dumps(
            {
                "wg_id": _TEST_WG,
                "tunnel_verification_status": "tunnel_healthy",
            }
        ),
    )
    transport: ApiFakeWireguardTransport = catalog_client.test_transport
    transport.readback_sequence = [
        _healthy_peer_readback(),
        _internet_status_readback(),
    ]
    resp = catalog_client.post(_CATALOG_STATUS_PATH, json={})
    assert resp.status_code == 200
    items = resp.json()["items"]
    active = next(item for item in items if item["profile_id"] == profile_id)
    assert active["live_probed"] is True
    assert active["live_tunnel_verification_status"] == "tunnel_healthy"
    assert active["probe_error"] is None
    assert active["routed_through_tunnel"] is True
    assert active["routing_probe_status"] == "ok"
    assert len([cmd for cmd in transport.parse_commands if cmd.startswith("show interface")]) == 1
    assert len([cmd for cmd in transport.parse_commands if cmd == "show internet status"]) == 1


def test_catalog_status_ignores_stored_snapshot_without_live_handshake(catalog_client) -> None:
    store = catalog_client.store
    router_id = _seed_router(store)
    profile_id = _seed_profile(store, display_name="stored-only")
    store.upsert_tunnel_assignment(
        router_id=router_id,
        profile_id=profile_id,
        observed_vendor_locator=_TEST_WG,
        policy_metadata_json=json.dumps({"tunnel_verification_status": "tunnel_healthy"}),
    )
    transport: ApiFakeWireguardTransport = catalog_client.test_transport
    transport.readback_sequence = [
        {"interface": {"id": _TEST_WG, "state": "up", "up": True}},
        _internet_status_readback(),
    ]
    resp = catalog_client.post(_CATALOG_STATUS_PATH, json={})
    assert resp.status_code == 200
    active = next(item for item in resp.json()["items"] if item["profile_id"] == profile_id)
    assert active["live_tunnel_verification_status"] != "tunnel_healthy"
    assert "tunnel_verification_status" not in active


def test_catalog_status_active_without_wg_id_probe_error(catalog_client) -> None:
    store = catalog_client.store
    router_id = _seed_router(store)
    profile_id = _seed_profile(store, display_name="active-no-wg", metadata={})
    store.upsert_tunnel_assignment(
        router_id=router_id,
        profile_id=profile_id,
        observed_vendor_locator=None,
        policy_metadata_json=json.dumps({"tunnel_verification_status": "tunnel_healthy"}),
    )
    resp = catalog_client.post(_CATALOG_STATUS_PATH, json={})
    assert resp.status_code == 200
    active = next(item for item in resp.json()["items"] if item["profile_id"] == profile_id)
    assert active["live_probed"] is False
    assert active["probe_error"] == "нет интерфейса туннеля"
    assert active["live_tunnel_verification_status"] is None
    assert active["routed_through_tunnel"] is None
    assert active["routing_probe_status"] == "not_applicable"
    assert catalog_client.test_transport.parse_commands == []


def test_catalog_status_single_probe_for_multiple_profiles(catalog_client) -> None:
    store = catalog_client.store
    router_id = _seed_router(store)
    inactive_id = _seed_profile(store, display_name="inactive-two")
    active_id = _seed_profile(store, display_name="active-two")
    store.upsert_tunnel_assignment(
        router_id=router_id,
        profile_id=active_id,
        observed_vendor_locator=_TEST_WG,
    )
    transport: ApiFakeWireguardTransport = catalog_client.test_transport
    transport.readback_sequence = [
        _healthy_peer_readback(),
        _internet_status_readback(),
    ]
    resp = catalog_client.post(_CATALOG_STATUS_PATH, json={})
    assert resp.status_code == 200
    items = {item["profile_id"]: item for item in resp.json()["items"]}
    assert inactive_id in items
    assert active_id in items
    assert items[inactive_id]["live_probed"] is False
    assert items[inactive_id]["routing_probe_status"] == "not_applicable"
    assert items[active_id]["live_probed"] is True
    show_cmds = [cmd for cmd in transport.parse_commands if cmd.startswith("show interface")]
    assert len(show_cmds) == 1
    assert len(transport.parse_commands) == 2


def test_catalog_status_routing_evidence_routed_false(catalog_client) -> None:
    store = catalog_client.store
    router_id = _seed_router(store)
    profile_id = _seed_profile(store, display_name="active-routed-false")
    store.upsert_tunnel_assignment(
        router_id=router_id,
        profile_id=profile_id,
        observed_vendor_locator=_TEST_WG,
    )
    transport: ApiFakeWireguardTransport = catalog_client.test_transport
    transport.readback_sequence = [
        _healthy_peer_readback(),
        _internet_status_readback(interface="WifiMaster1/WifiStation0"),
    ]
    resp = catalog_client.post(_CATALOG_STATUS_PATH, json={})
    assert resp.status_code == 200
    active = next(item for item in resp.json()["items"] if item["profile_id"] == profile_id)
    assert active["routed_through_tunnel"] is False
    assert active["routing_probe_status"] == "ok"


def test_catalog_status_routing_evidence_missing_interface(catalog_client) -> None:
    store = catalog_client.store
    router_id = _seed_router(store)
    profile_id = _seed_profile(store, display_name="active-routing-unknown")
    store.upsert_tunnel_assignment(
        router_id=router_id,
        profile_id=profile_id,
        observed_vendor_locator=_TEST_WG,
    )
    transport: ApiFakeWireguardTransport = catalog_client.test_transport
    transport.readback_sequence = [
        _healthy_peer_readback(),
        _internet_status_readback(interface=None),
    ]
    resp = catalog_client.post(_CATALOG_STATUS_PATH, json={})
    assert resp.status_code == 200
    active = next(item for item in resp.json()["items"] if item["profile_id"] == profile_id)
    assert active["routed_through_tunnel"] is None
    assert active["routing_probe_status"] == "unknown"
