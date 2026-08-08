"""Unit tests for VPN watchdog intent rebuild from profile metadata."""

from __future__ import annotations

import json
from pathlib import Path

from router_control.application.vpn_watchdog_service import VpnWatchdogHandle
from router_control.domain.network_intents import WireguardPeerRciShape
from router_control.persistence.connection import open_database
from router_control.persistence.store import PersistenceStore


def _handle() -> VpnWatchdogHandle:
    class _Host:
        runtime = None

    return VpnWatchdogHandle(host=_Host())


def test_watchdog_intent_carries_peer_keepalive_from_metadata(tmp_path: Path) -> None:
    store = PersistenceStore(open_database(tmp_path / "watchdog-keepalive.sqlite3"))
    profile_id = store.import_profile(
        display_name="Keepalive profile",
        vpn_kind="AmneziaWG",
        content_digest="sha256:keepalive",
        metadata_json=json.dumps(
            {
                "wg_id": "Wireguard5",
                "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                "peer_endpoint": "example.com:51820",
                "peer_allow_ips": "0.0.0.0/0",
                "peer_keepalive_interval": 25,
            }
        ),
    )
    service = _handle()
    intent = service._intent_from_assignment(
        {"profile_id": profile_id},
        store,
    )
    assert intent is not None
    assert intent.peer_keepalive_interval == 25


def test_watchdog_intent_omits_peer_keepalive_when_metadata_key_absent(
    tmp_path: Path,
) -> None:
    store = PersistenceStore(open_database(tmp_path / "watchdog-no-keepalive.sqlite3"))
    profile_id = store.import_profile(
        display_name="No keepalive profile",
        vpn_kind="AmneziaWG",
        content_digest="sha256:no-keepalive",
        metadata_json=json.dumps(
            {
                "wg_id": "Wireguard5",
                "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                "peer_endpoint": "example.com:51820",
                "peer_allow_ips": "0.0.0.0/0",
            }
        ),
    )
    service = _handle()
    intent = service._intent_from_assignment(
        {"profile_id": profile_id},
        store,
    )
    assert intent is not None
    assert intent.peer_keepalive_interval is None


def test_watchdog_intent_carries_tcp_mss_pmtu_from_metadata(tmp_path: Path) -> None:
    store = PersistenceStore(open_database(tmp_path / "watchdog-tcp-mss.sqlite3"))
    profile_id = store.import_profile(
        display_name="TCP MSS profile",
        vpn_kind="AmneziaWG",
        content_digest="sha256:tcp-mss",
        metadata_json=json.dumps(
            {
                "wg_id": "Wireguard5",
                "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                "peer_endpoint": "example.com:51820",
                "peer_allow_ips": "0.0.0.0/0",
                "tcp_mss_pmtu": True,
            }
        ),
    )
    service = _handle()
    intent = service._intent_from_assignment(
        {"profile_id": profile_id},
        store,
    )
    assert intent is not None
    assert intent.tcp_mss_pmtu is True

    from router_control.adapters.netcraze.interface_rci import InterfaceRciOperation
    from router_control.adapters.netcraze.wireguard_rci import WireguardRciOperation
    from router_control.application.wireguard_apply_planner import compile_wireguard_intent_to_ops

    plan = compile_wireguard_intent_to_ops(intent)
    ops = [op.operation for op in plan.apply_ops]
    assert WireguardRciOperation.SET_TCP_MSS.value in ops
    assert ops.index(WireguardRciOperation.SET_TCP_MSS.value) < ops.index(
        InterfaceRciOperation.UP.value
    )


def test_watchdog_intent_carries_ip_global_priority_from_metadata(tmp_path: Path) -> None:
    store = PersistenceStore(open_database(tmp_path / "watchdog-ip-global.sqlite3"))
    profile_id = store.import_profile(
        display_name="IP global profile",
        vpn_kind="AmneziaWG",
        content_digest="sha256:ip-global",
        metadata_json=json.dumps(
            {
                "wg_id": "Wireguard5",
                "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                "peer_endpoint": "example.com:51820",
                "peer_allow_ips": "0.0.0.0/0",
                "ip_global_priority": 900,
            }
        ),
    )
    service = _handle()
    intent = service._intent_from_assignment(
        {"profile_id": profile_id},
        store,
    )
    assert intent is not None
    assert intent.ip_global_priority == 900

    from router_control.adapters.netcraze.wireguard_rci import WireguardRciOperation
    from router_control.application.wireguard_apply_planner import compile_wireguard_intent_to_ops

    plan = compile_wireguard_intent_to_ops(intent)
    ops = [op.operation for op in plan.apply_ops]
    assert WireguardRciOperation.IP_GLOBAL.value in ops


def test_watchdog_intent_prefers_observed_vendor_locator_over_metadata(
    tmp_path: Path,
) -> None:
    store = PersistenceStore(open_database(tmp_path / "watchdog-locator.sqlite3"))
    profile_id = store.import_profile(
        display_name="Locator profile",
        vpn_kind="AmneziaWG",
        content_digest="sha256:locator",
        metadata_json=json.dumps(
            {
                "wg_id": "Wireguard5",
                "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                "peer_endpoint": "example.com:51820",
                "peer_allow_ips": "0.0.0.0/0",
            }
        ),
    )
    service = _handle()
    intent = service._intent_from_assignment(
        {
            "profile_id": profile_id,
            "observed_vendor_locator": "Wireguard6",
        },
        store,
    )
    assert intent is not None
    assert intent.wg_id == "Wireguard6"


def test_watchdog_intent_uses_metadata_wg_id_when_locator_absent(
    tmp_path: Path,
) -> None:
    store = PersistenceStore(open_database(tmp_path / "watchdog-meta-wg.sqlite3"))
    profile_id = store.import_profile(
        display_name="Metadata wg profile",
        vpn_kind="AmneziaWG",
        content_digest="sha256:meta-wg",
        metadata_json=json.dumps(
            {
                "wg_id": "Wireguard7",
                "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                "peer_endpoint": "example.com:51820",
                "peer_allow_ips": "0.0.0.0/0",
            }
        ),
    )
    service = _handle()
    intent = service._intent_from_assignment(
        {"profile_id": profile_id},
        store,
    )
    assert intent is not None
    assert intent.wg_id == "Wireguard7"


def test_watchdog_intent_resolves_wg_id_from_policy_metadata(
    tmp_path: Path,
) -> None:
    store = PersistenceStore(open_database(tmp_path / "watchdog-policy-wg.sqlite3"))
    profile_id = store.import_profile(
        display_name="Policy wg profile",
        vpn_kind="AmneziaWG",
        content_digest="sha256:policy-wg",
        metadata_json=json.dumps(
            {
                "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                "peer_endpoint": "example.com:51820",
                "peer_allow_ips": "0.0.0.0/0",
            }
        ),
    )
    service = _handle()
    intent = service._intent_from_assignment(
        {
            "profile_id": profile_id,
            "policy_metadata_json": json.dumps({"wg_id": "Wireguard8"}),
        },
        store,
    )
    assert intent is not None
    assert intent.wg_id == "Wireguard8"


def test_watchdog_intent_coerces_invalid_peer_rci_shape_fail_closed(
    tmp_path: Path,
) -> None:
    store = PersistenceStore(open_database(tmp_path / "watchdog-rci-shape.sqlite3"))
    profile_id = store.import_profile(
        display_name="Invalid rci shape profile",
        vpn_kind="AmneziaWG",
        content_digest="sha256:rci-shape",
        metadata_json=json.dumps(
            {
                "wg_id": "Wireguard5",
                "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                "peer_endpoint": "example.com:51820",
                "peer_allow_ips": "0.0.0.0/0",
                "peer_rci_shape": None,
            }
        ),
    )
    service = _handle()
    intent = service._intent_from_assignment(
        {"profile_id": profile_id},
        store,
    )
    assert intent is not None
    assert intent.peer_rci_shape is WireguardPeerRciShape.NESTED_RCI

    profile_id_none_str = store.import_profile(
        display_name="None string rci shape profile",
        vpn_kind="AmneziaWG",
        content_digest="sha256:rci-shape-none-str",
        metadata_json=json.dumps(
            {
                "wg_id": "Wireguard5",
                "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                "peer_endpoint": "example.com:51820",
                "peer_allow_ips": "0.0.0.0/0",
                "peer_rci_shape": "None",
            }
        ),
    )
    intent_none_str = service._intent_from_assignment(
        {"profile_id": profile_id_none_str},
        store,
    )
    assert intent_none_str is not None
    assert intent_none_str.peer_rci_shape is WireguardPeerRciShape.NESTED_RCI


def test_watchdog_intent_returns_none_without_wg_id(tmp_path: Path) -> None:
    store = PersistenceStore(open_database(tmp_path / "watchdog-no-wg.sqlite3"))
    profile_id = store.import_profile(
        display_name="No wg profile",
        vpn_kind="AmneziaWG",
        content_digest="sha256:no-wg",
        metadata_json=json.dumps(
            {
                "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                "peer_endpoint": "example.com:51820",
                "peer_allow_ips": "0.0.0.0/0",
            }
        ),
    )
    service = _handle()
    intent = service._intent_from_assignment(
        {"profile_id": profile_id, "observed_vendor_locator": ""},
        store,
    )
    assert intent is None
