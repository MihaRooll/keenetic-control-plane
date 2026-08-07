"""Offline tests for Wi-Fi station sealed write allowlist arms."""

from __future__ import annotations

import ast
import importlib
import sys
from pathlib import Path

import pytest
from router_control.adapters.netcraze.allowlist import (
    build_sealed_parse_body,
    is_write_allowlisted,
)
from router_control.adapters.netcraze.sanitize import redact_sealed_cli_command
from router_control.adapters.netcraze.transport import SealedRciWriteRequest
from router_control.adapters.netcraze.wifi_station_rci import (
    WifiStationRciOperation,
    command_for,
)

from tests.test_wifi_station_apply_api import (
    ApiFakeStationLiveTransport,
    ApiFakeStationOfflineTransport,
)

_STATION = "WifiMaster1/WifiStation0"
_VALID_PSK = "test-passphrase-12345678"
_VALID_SSID = "Venue-Test"

_FIRST_SLICE_OPS: list[tuple[WifiStationRciOperation, dict[str, object]]] = [
    (WifiStationRciOperation.SET_SSID, {"ssid": _VALID_SSID}),
    (WifiStationRciOperation.SET_WPA_PSK, {"psk": _VALID_PSK}),
    (WifiStationRciOperation.ENCRYPTION_ENABLE, {}),
    (WifiStationRciOperation.ENCRYPTION_WPA2, {}),
    (WifiStationRciOperation.IP_GLOBAL, {"priority": 0}),
    (WifiStationRciOperation.IP_GLOBAL, {"priority": 100}),
    (WifiStationRciOperation.IP_ADDRESS_DHCP, {}),
    (WifiStationRciOperation.UP, {}),
    (WifiStationRciOperation.DOWN, {}),
    (WifiStationRciOperation.CLEAR_IP_ADDRESS_DHCP, {}),
    (WifiStationRciOperation.CLEAR_IP_ADDRESS, {}),
    (WifiStationRciOperation.CLEAR_WPA_PSK, {}),
    (WifiStationRciOperation.ENCRYPTION_WPA2_CLEAR, {}),
    (WifiStationRciOperation.ENCRYPTION_DISABLE, {}),
    (WifiStationRciOperation.CLEAR_SSID, {}),
]

_DEFERRED_OPS: list[tuple[WifiStationRciOperation, dict[str, object]]] = [
    (WifiStationRciOperation.SET_BSSID, {"bssid": "aa:bb:cc:dd:ee:ff"}),
    (WifiStationRciOperation.STANDBY_ENABLE, {}),
    (WifiStationRciOperation.STANDBY_TIMEOUT, {"standby_timeout": 60}),
    (WifiStationRciOperation.ENCRYPTION_WPA3, {}),
    (WifiStationRciOperation.ENCRYPTION_WPA3_CLEAR, {}),
    (WifiStationRciOperation.SET_SECURITY_LEVEL, {"security_level": "private"}),
    (WifiStationRciOperation.PMF, {}),
    (WifiStationRciOperation.PMF_FORCE, {}),
    (WifiStationRciOperation.IP_GLOBAL, {"global_auto": True}),
    (WifiStationRciOperation.IP_GLOBAL, {"global_order": 10}),
]


def _body_for(operation: WifiStationRciOperation, **kwargs: object) -> bytes:
    cli = command_for(operation, _STATION, **kwargs)
    return build_sealed_parse_body(cli)


@pytest.mark.parametrize(("operation", "kwargs"), _FIRST_SLICE_OPS)
def test_first_slice_builder_bodies_are_write_allowlisted(
    operation: WifiStationRciOperation,
    kwargs: dict[str, object],
) -> None:
    body = _body_for(operation, **kwargs)
    assert is_write_allowlisted("POST", "/rci/", body) is True


@pytest.mark.parametrize(("operation", "kwargs"), _DEFERRED_OPS)
def test_deferred_ops_remain_rejected(
    operation: WifiStationRciOperation,
    kwargs: dict[str, object],
) -> None:
    body = _body_for(operation, **kwargs)
    assert is_write_allowlisted("POST", "/rci/", body) is False


@pytest.mark.parametrize(
    ("cli",),
    [
        (f"interface WifiMaster1/WifiStation1 ssid {_VALID_SSID}",),
        (f"interface {_STATION} ssid ",),
        (f"interface {_STATION} ssid bad ssid",),
        (f"interface {_STATION} ssid  {_VALID_SSID}",),
        (f"interface {_STATION} authentication wpa-psk short",),
        (f"interface {_STATION} authentication wpa-psk  {_VALID_PSK}",),
        (f"interface {_STATION} ip global 65536",),
        (f"interface {_STATION} ip global 100000",),
        (f"interface {_STATION} ip global auto",),
        (f"interface {_STATION} ip global order 10",),
        (f"interface {_STATION} ip global +100",),
        (f"interface {_STATION} ip global 1_00",),
        (f"interface {_STATION} ip global 0100",),
        (f"interface {_STATION} ip global  100",),
        (f"interface {_STATION} ip global\t100",),
        (f"interface {_STATION} ip global \uff10",),
        (f"interface {_STATION} ip global \uff11\uff10\uff10",),
        (f"interface {_STATION} ip global \u0660",),
        (f"interface {_STATION} ip global \u0661\u0660\u0660",),
    ],
)
def test_near_miss_station_bodies_rejected(cli: str) -> None:
    body = build_sealed_parse_body(cli)
    assert is_write_allowlisted("POST", "/rci/", body) is False


def test_allowlist_module_has_no_wifi_station_rci_import_edge() -> None:
    allowlist_path = (
        Path(__file__).resolve().parents[1]
        / "router_control"
        / "adapters"
        / "netcraze"
        / "allowlist.py"
    )
    tree = ast.parse(allowlist_path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert "wifi_station_rci" not in alias.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            assert "wifi_station_rci" not in module

    sys.modules.pop("router_control.adapters.netcraze.allowlist", None)
    sys.modules.pop("router_control.adapters.netcraze.wifi_station_rci", None)
    importlib.import_module("router_control.adapters.netcraze.allowlist")
    assert "router_control.adapters.netcraze.wifi_station_rci" not in sys.modules


def test_api_fake_transports_redact_psk_in_write_commands() -> None:
    body = _body_for(WifiStationRciOperation.SET_WPA_PSK, psk=_VALID_PSK)
    request = SealedRciWriteRequest(body=body)

    offline = ApiFakeStationOfflineTransport()
    offline.execute_sealed_rci_write(request)
    assert offline.write_commands == [
        redact_sealed_cli_command(
            f"interface {_STATION} authentication wpa-psk {_VALID_PSK}"
        )
    ]
    assert _VALID_PSK not in offline.write_commands[0]

    live = ApiFakeStationLiveTransport()
    live.execute_sealed_rci_write(request)
    assert live.write_commands == [
        redact_sealed_cli_command(
            f"interface {_STATION} authentication wpa-psk {_VALID_PSK}"
        )
    ]
    assert _VALID_PSK not in live.write_commands[0]
