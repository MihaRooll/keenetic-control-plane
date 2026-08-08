"""Router apply lock coverage for Wi-Fi AP, station, and KeenDNS routes."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

import pytest
from router_control.application.router_apply_lock import (
    resolve_router_apply_lock_key,
    run_with_router_apply_lock,
)
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie

import router_control_host.keendns_apply_routes as keendns_routes
import router_control_host.wifi_apply_routes as wifi_routes
import router_control_host.wifi_station_apply_routes as station_routes

_API = "/api/router-control/v1"
_VALID_SSH = "SHA256:" + "a" * 43
_ROUTER_ID = "router-lab-1"
_TEST_AP = "WifiMaster0/AccessPoint3"
_OFFLINE_PSK = "test-psk-placeholder"


class _ConnBody:
    host = "192.168.2.1"
    ssh_host_key_sha256 = _VALID_SSH
    source_address = "192.168.2.10"


class _FakeWifiTransport:
    def execute_sealed_rci_write(self, request: Any) -> list[dict[str, Any]]:
        body = json.loads(request.body.decode("utf-8"))
        _ = body
        return [{"parse": {"status": [{"ident": "Core::Interface", "message": "ok"}]}}]

    def execute_rci_parse(self, cli_command: str) -> dict[str, Any]:
        _ = cli_command
        return {
            "interface": {
                "ssid": "Staff-Private",
                "encryption": {"wpa2": True, "enabled": True},
                "state": "up",
                "up": True,
            }
        }


class _FakeStationTransport:
    wifi_station_offline_only = True

    def execute_sealed_rci_write(self, request: Any) -> list[dict[str, Any]]:
        _ = request
        return [{"parse": {"status": [{"ident": "Wifi::Station", "message": "ok"}]}}]

    def read_json(self, command: object, body: bytes | None = None) -> dict[str, object]:
        _ = command, body
        return {"station": {"state": "down"}}


class _FakeKeenDnsTransport:
    keendns_offline_only = True

    def execute_sealed_rci_write(self, request: Any) -> list[dict[str, object]]:
        _ = request
        return [{"parse": {"status": [{"status": "message", "ident": "Cloud::KeenDNS", "message": "ok"}]}}]


@pytest.fixture
def wifi_lock_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    app = create_app(db_path=tmp_path / "wifi-lock.sqlite3", allow_fake_mutations=True)
    transport = _FakeWifiTransport()
    app.state.host.wifi_apply_transport_factory = lambda: transport
    app.state.host.wifi_apply_credential_resolver = lambda _ref: _OFFLINE_PSK
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield client


@pytest.fixture
def station_lock_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    app = create_app(db_path=tmp_path / "station-lock.sqlite3", allow_fake_mutations=True)
    transport = _FakeStationTransport()
    app.state.host.wifi_station_apply_transport_factory = lambda: transport
    app.state.host.wifi_station_apply_credential_resolver = lambda _ref: _OFFLINE_PSK
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield client


@pytest.fixture
def keendns_lock_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    app = create_app(db_path=tmp_path / "keendns-lock.sqlite3", allow_fake_mutations=True)
    transport = _FakeKeenDnsTransport()
    app.state.host.keendns_apply_transport_factory = lambda: transport
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield client


@pytest.mark.parametrize(
    "helper",
    [
        wifi_routes._router_apply_lock_key,
        station_routes._router_apply_lock_key,
        keendns_routes._router_apply_lock_key,
    ],
)
def test_router_apply_lock_key_prefers_router_id(helper) -> None:
    body = _ConnBody()
    assert helper(body, _ROUTER_ID) == _ROUTER_ID
    assert helper(body, None).startswith("live:")


def test_router_apply_lock_key_live_identity_parity() -> None:
    body = _ConnBody()
    expected = resolve_router_apply_lock_key(
        None,
        live_host=body.host,
        ssh_host_key_sha256=body.ssh_host_key_sha256,
        source_address=body.source_address,
    )
    assert wifi_routes._router_apply_lock_key(body, None) == expected
    assert station_routes._router_apply_lock_key(body, None) == expected
    assert keendns_routes._router_apply_lock_key(body, None) == expected


def test_same_lock_key_serializes_under_thread_contention() -> None:
    order: list[str] = []
    first_started = threading.Event()
    release_first = threading.Event()

    def first() -> None:
        order.append("start1")
        first_started.set()
        assert release_first.wait(timeout=5.0)
        order.append("end1")

    def second() -> None:
        assert first_started.wait(timeout=5.0)
        order.append("start2")
        order.append("end2")

    lock_key = "contention-test-key"
    t1 = threading.Thread(target=lambda: run_with_router_apply_lock(lock_key, first))
    t2 = threading.Thread(target=lambda: run_with_router_apply_lock(lock_key, second))
    t1.start()
    assert first_started.wait(timeout=5.0)
    time.sleep(0.05)
    assert order == ["start1"]
    t2.start()
    time.sleep(0.05)
    assert order == ["start1"]
    release_first.set()
    t1.join(timeout=5.0)
    t2.join(timeout=5.0)
    assert order == ["start1", "end1", "start2", "end2"]


def test_wifi_apply_offline_invokes_router_apply_lock(
    wifi_lock_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock_keys: list[str | None] = []
    original = run_with_router_apply_lock

    def spy(lock_key: str | None, fn: Any) -> Any:
        lock_keys.append(lock_key)
        return original(lock_key, fn)

    monkeypatch.setattr(wifi_routes, "run_with_router_apply_lock", spy)
    payload = {
        "ap_id": _TEST_AP,
        "ssid": "Staff-Private",
        "enabled": True,
        "credential_ref_id": "credref:staff-wifi",
        "captive_portal": "Disabled",
        "guest_isolation": False,
        "wpa_mode": "WPA2",
        "band": "BAND_2_4GHZ",
        "confirm_live_apply": True,
    }
    resp = wifi_lock_client.post(f"{_API}/wifi/apply", json=payload)
    assert resp.status_code == 200
    assert lock_keys == ["__default__"]


def test_wifi_station_apply_offline_invokes_router_apply_lock(
    station_lock_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock_keys: list[str | None] = []
    original = run_with_router_apply_lock

    def spy(lock_key: str | None, fn: Any) -> Any:
        lock_keys.append(lock_key)
        return original(lock_key, fn)

    monkeypatch.setattr(station_routes, "run_with_router_apply_lock", spy)
    payload = {
        "mode": "WifiWan",
        "ssid": "Venue-Guest",
        "band": "BAND_2_4GHZ",
        "credential_ref_id": "credref:venue-wifi",
        "priority": 100,
        "confirm_live_apply": True,
    }
    resp = station_lock_client.post(f"{_API}/wifi/station/apply", json=payload)
    assert resp.status_code == 200
    assert lock_keys == ["__default__"]


def test_keendns_apply_offline_invokes_router_apply_lock(
    keendns_lock_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock_keys: list[str | None] = []
    original = run_with_router_apply_lock

    def spy(lock_key: str | None, fn: Any) -> Any:
        lock_keys.append(lock_key)
        return original(lock_key, fn)

    monkeypatch.setattr(keendns_routes, "run_with_router_apply_lock", spy)
    payload = {
        "intent_kind": "book",
        "name": "sample-name",
        "domain": "netcraze.pro",
        "mode": "auto",
        "confirm_live_apply": True,
    }
    resp = keendns_lock_client.post(f"{_API}/keendns/apply", json=payload)
    assert resp.status_code == 200
    assert lock_keys == ["__default__"]
