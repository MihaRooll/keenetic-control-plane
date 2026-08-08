"""Unit tests for VPN watchdog intent rebuild from profile metadata."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from router_control.application.vpn_watchdog_service import VpnWatchdogHandle
from router_control.domain.network_intents import WireguardPeerRciShape
from router_control.persistence.connection import open_database
from router_control.persistence.store import PersistenceStore

_BASE_METADATA = {
    "wg_id": "Wireguard5",
    "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
    "peer_endpoint": "example.com:51820",
    "peer_allow_ips": "0.0.0.0/0",
}


def _handle() -> VpnWatchdogHandle:
    class _Host:
        runtime = None

    return VpnWatchdogHandle(host=_Host())


def _seed_router(store: PersistenceStore) -> str:
    site_id = store.create_site(display_name="Watchdog Lab")
    return store.enroll_router(
        site_id=site_id,
        display_name="Watchdog Router",
        vendor="Keenetic",
        model="Test",
        identity_fingerprint="digest:watchdog-intent",
        host="127.0.0.1",
    )


def _insert_usable_private_key(
    store: PersistenceStore,
    *,
    router_id: str | None = None,
) -> tuple[str, str]:
    rid = router_id or _seed_router(store)
    cred_id = store.insert_credential_ref(
        router_id=rid,
        kind="awg_private_key",
        provider="MemoryVault",
        provider_locator="loc-watchdog-intent",
    )
    return rid, cred_id


def _seed_profile_with_private_key(
    store: PersistenceStore,
    *,
    display_name: str,
    content_digest: str,
    metadata: dict | None = None,
    router_id: str | None = None,
    psk: bool = False,
) -> tuple[str, str, str, str | None]:
    rid, cred_id = _insert_usable_private_key(store, router_id=router_id)
    profile_id = store.import_profile(
        display_name=display_name,
        vpn_kind="AmneziaWG",
        content_digest=content_digest,
        metadata_json=json.dumps(metadata or _BASE_METADATA),
    )
    refs: list[tuple[str, str]] = [(cred_id, "PrivateKey")]
    psk_id: str | None = None
    if psk:
        psk_id = store.insert_credential_ref(
            router_id=rid,
            kind="awg_preshared_key",
            provider="MemoryVault",
            provider_locator=f"psk-{content_digest}",
        )
        refs.append((psk_id, "PresharedKey"))
    store.insert_profile_secret_refs(profile_id=profile_id, refs=refs)
    return profile_id, cred_id, rid, psk_id


def test_watchdog_intent_carries_peer_keepalive_from_metadata(tmp_path: Path) -> None:
    store = PersistenceStore(open_database(tmp_path / "watchdog-keepalive.sqlite3"))
    profile_id, _, _, _ = _seed_profile_with_private_key(
        store,
        display_name="Keepalive profile",
        content_digest="sha256:keepalive",
        metadata={**_BASE_METADATA, "peer_keepalive_interval": 25},
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
    profile_id, _, _, _ = _seed_profile_with_private_key(
        store,
        display_name="No keepalive profile",
        content_digest="sha256:no-keepalive",
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
    profile_id, _, _, _ = _seed_profile_with_private_key(
        store,
        display_name="TCP MSS profile",
        content_digest="sha256:tcp-mss",
        metadata={**_BASE_METADATA, "tcp_mss_pmtu": True},
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
    profile_id, _, _, _ = _seed_profile_with_private_key(
        store,
        display_name="IP global profile",
        content_digest="sha256:ip-global",
        metadata={**_BASE_METADATA, "ip_global_priority": 900},
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
    profile_id, _, _, _ = _seed_profile_with_private_key(
        store,
        display_name="Locator profile",
        content_digest="sha256:locator",
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
    profile_id, _, _, _ = _seed_profile_with_private_key(
        store,
        display_name="Metadata wg profile",
        content_digest="sha256:meta-wg",
        metadata={**_BASE_METADATA, "wg_id": "Wireguard7"},
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
    metadata = {
        "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
        "peer_endpoint": "example.com:51820",
        "peer_allow_ips": "0.0.0.0/0",
    }
    profile_id, _, _, _ = _seed_profile_with_private_key(
        store,
        display_name="Policy wg profile",
        content_digest="sha256:policy-wg",
        metadata=metadata,
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
    profile_id, _, _, _ = _seed_profile_with_private_key(
        store,
        display_name="Invalid rci shape profile",
        content_digest="sha256:rci-shape",
        metadata={**_BASE_METADATA, "peer_rci_shape": None},
    )
    service = _handle()
    intent = service._intent_from_assignment(
        {"profile_id": profile_id},
        store,
    )
    assert intent is not None
    assert intent.peer_rci_shape is WireguardPeerRciShape.NESTED_RCI

    profile_id_none_str, _, _, _ = _seed_profile_with_private_key(
        store,
        display_name="None string rci shape profile",
        content_digest="sha256:rci-shape-none-str",
        metadata={**_BASE_METADATA, "peer_rci_shape": "None"},
    )
    intent_none_str = service._intent_from_assignment(
        {"profile_id": profile_id_none_str},
        store,
    )
    assert intent_none_str is not None
    assert intent_none_str.peer_rci_shape is WireguardPeerRciShape.NESTED_RCI


def test_watchdog_intent_returns_none_without_wg_id(tmp_path: Path) -> None:
    store = PersistenceStore(open_database(tmp_path / "watchdog-no-wg.sqlite3"))
    metadata = {
        "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
        "peer_endpoint": "example.com:51820",
        "peer_allow_ips": "0.0.0.0/0",
    }
    profile_id, _, _, _ = _seed_profile_with_private_key(
        store,
        display_name="No wg profile",
        content_digest="sha256:no-wg",
        metadata=metadata,
    )
    service = _handle()
    intent = service._intent_from_assignment(
        {"profile_id": profile_id, "observed_vendor_locator": ""},
        store,
    )
    assert intent is None


def test_watchdog_intent_returns_none_when_private_key_revoked(tmp_path: Path) -> None:
    store = PersistenceStore(open_database(tmp_path / "watchdog-revoked-pk.sqlite3"))
    profile_id, cred_id, router_id, _ = _seed_profile_with_private_key(
        store,
        display_name="Revoked pk profile",
        content_digest="sha256:revoked-pk",
    )
    store.upsert_tunnel_assignment(
        router_id=router_id,
        profile_id=profile_id,
        desired_active=True,
    )
    store.mark_credential_revoked(cred_id, now=datetime(2026, 8, 8, tzinfo=UTC))
    service = _handle()
    intent = service._intent_from_assignment({"profile_id": profile_id}, store)
    assert intent is None


def test_watchdog_intent_returns_none_when_psk_revoked(tmp_path: Path) -> None:
    store = PersistenceStore(open_database(tmp_path / "watchdog-revoked-psk.sqlite3"))
    profile_id, _cred_id, router_id, psk_id = _seed_profile_with_private_key(
        store,
        display_name="Revoked psk profile",
        content_digest="sha256:revoked-psk",
        psk=True,
    )
    assert psk_id is not None
    store.upsert_tunnel_assignment(
        router_id=router_id,
        profile_id=profile_id,
        desired_active=True,
    )
    store.mark_credential_revoked(psk_id, now=datetime(2026, 8, 8, tzinfo=UTC))
    service = _handle()
    intent = service._intent_from_assignment({"profile_id": profile_id}, store)
    assert intent is None


def test_watchdog_intent_returns_none_without_private_key_ref(tmp_path: Path) -> None:
    store = PersistenceStore(open_database(tmp_path / "watchdog-no-pk-ref.sqlite3"))
    profile_id = store.import_profile(
        display_name="No pk ref profile",
        vpn_kind="AmneziaWG",
        content_digest="sha256:no-pk-ref",
        metadata_json=json.dumps(_BASE_METADATA),
    )
    service = _handle()
    intent = service._intent_from_assignment({"profile_id": profile_id}, store)
    assert intent is None
