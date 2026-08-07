"""Netcraze allowlist interface-id validation tests."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from router_control.adapters.netcraze.allowlist import validate_interface_id
from router_control.application.vpn_policy_routing_planner import (
    compile_vpn_policy_routing_intent,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_allowlist_module_has_no_wireguard_rci_imports() -> None:
    source = (REPO_ROOT / "router_control/adapters/netcraze/allowlist.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert "wireguard_rci" not in alias.name
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            assert "wireguard_rci" not in module


@pytest.mark.parametrize(
    "station_id",
    [
        "WifiMaster0/WifiStation0",
        "WifiMaster1/WifiStation0",
    ],
)
def test_validate_interface_id_accepts_sealed_station_ids(station_id: str) -> None:
    assert validate_interface_id(station_id) == station_id


@pytest.mark.parametrize(
    "invalid_id",
    [
        "../../etc/passwd",
        "a/b/c",
        "WifiMaster9/WifiStation9",
        "/",
        "Wireguard0/x",
        "WifiMaster1/WifiStation1",
        "WifiMaster2/WifiStation0",
    ],
)
def test_validate_interface_id_rejects_slash_injection(invalid_id: str) -> None:
    with pytest.raises(ValueError, match="disallowed characters"):
        validate_interface_id(invalid_id)


def test_planner_accepts_wifi_station_uplink_interface() -> None:
    plan = compile_vpn_policy_routing_intent(
        {
            "policy_name": "vpn-station",
            "vpn_interface": "WifiMaster1/WifiStation0",
            "interface_kind": "other",
            "ip_global": {"priority": 700},
            "name_servers": [{"address": "1.1.1.1"}],
        }
    )
    assert plan.vpn_interface == "WifiMaster1/WifiStation0"
