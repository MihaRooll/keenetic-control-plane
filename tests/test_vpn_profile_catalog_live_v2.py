"""Targeted tests for vpn-profile-catalog-live-v2 (offline only)."""

from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from router_control.adapters.netcraze.awg_profile import parse_awg_profile_text
from router_control.adapters.netcraze.certification import GateACertification
from router_control.adapters.netcraze.startup_backup import StartupBackupMetadata
from router_control.adapters.netcraze.wireguard_rci import (
    WireguardRciOperation,
    command_for,
    parse_interface_address_cidr,
)
from router_control.adapters.secrets.memory import MemoryVault
from router_control.application.router_apply_lock import (
    resolve_router_apply_lock_key,
    run_with_router_apply_lock,
)
from router_control.application.wireguard_apply_planner import compile_wireguard_intent_to_ops
from router_control.application.wireguard_apply_service import (
    _resolve_interface_address_verification_status,
)
from router_control.domain.network_intents import WireguardIntent
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie
from router_control_host.wifi_live_transport import LiveIdentityTupleMismatchError, WifiLiveSession

SAMPLE_PROFILE = """
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.0.0.2/32
Jc = 5
Jmin = 50
Jmax = 1000
S1 = 80
S2 = 80
H1 = 1
H2 = 2
H3 = 3
H4 = 4

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
Endpoint = example.com:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""

_ASC_9 = (5, 50, 1000, 80, 80, 1, 2, 3, 4)

_VALID_SSH_HOST_KEY_SHA256 = "SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM"
_COMPONENT_DIGEST = "a" * 64
_FINGERPRINT_DIGEST = "b" * 64

_LIVE_CONN: dict[str, str] = {
    "host": "192.168.2.1",
    "username": "admin",
    "router_credential_ref_id": "credref:router-admin",
    "ssh_host_key_sha256": _VALID_SSH_HOST_KEY_SHA256,
    "source_address": "192.168.2.10",
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


@pytest.fixture
def authed_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ADAPTER_MODE", "fake")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    app = create_app(db_path=tmp_path / "vpn-catalog-v2.sqlite3", enable_worker=False)
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield client


def test_wireguard_rci_set_ip_and_ip_global_commands() -> None:
    addr, mask = parse_interface_address_cidr("10.0.0.2/32")
    assert addr == "10.0.0.2"
    assert mask == "255.255.255.255"
    assert (
        command_for(
            WireguardRciOperation.SET_IP_ADDRESS,
            "Wireguard5",
            ipv4_address=addr,
            ipv4_mask=mask,
        )
        == "interface Wireguard5 ip address 10.0.0.2 255.255.255.255"
    )
    assert (
        command_for(WireguardRciOperation.CLEAR_IP_ADDRESS, "Wireguard5")
        == "interface Wireguard5 no ip address"
    )
    assert (
        command_for(WireguardRciOperation.IP_GLOBAL, "Wireguard5", global_auto=True)
        == "interface Wireguard5 ip global auto"
    )
    assert (
        command_for(WireguardRciOperation.CLEAR_IP_GLOBAL, "Wireguard5")
        == "interface Wireguard5 no ip global"
    )


def test_clear_ip_global_not_claimed_device_proven_in_planner_notes() -> None:
    intent = WireguardIntent(
        wg_id="Wireguard5",
        enabled=True,
        asc_args=_ASC_9,
        interface_address="10.0.0.2/32",
        ip_global_auto=True,
        private_key_credential_ref_id="cred_test",
        peer_public_key="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
    )
    plan = compile_wireguard_intent_to_ops(intent)
    clear_ops = [
        op
        for op in plan.teardown_ops
        if op.operation == WireguardRciOperation.CLEAR_IP_GLOBAL.value
    ]
    assert clear_ops
    assert any("NOT device-proven" in note for op in clear_ops for note in op.notes)


def test_wireguard_rci_set_and_clear_tcp_mss_commands() -> None:
    assert (
        command_for(WireguardRciOperation.SET_TCP_MSS, "Wireguard5")
        == "interface Wireguard5 ip tcp adjust-mss pmtu"
    )
    assert (
        command_for(WireguardRciOperation.CLEAR_TCP_MSS, "Wireguard5")
        == "interface Wireguard5 no ip tcp adjust-mss"
    )


def test_clear_tcp_mss_not_claimed_device_proven_in_planner_notes() -> None:
    intent = WireguardIntent(
        wg_id="Wireguard5",
        enabled=True,
        asc_args=_ASC_9,
        tcp_mss_pmtu=True,
    )
    plan = compile_wireguard_intent_to_ops(intent)
    clear_ops = [
        op
        for op in plan.teardown_ops
        if op.operation == WireguardRciOperation.CLEAR_TCP_MSS.value
    ]
    assert clear_ops
    assert any("NOT device-proven" in note for op in clear_ops for note in op.notes)


def test_address_readback_confirmed_only_with_parsed_match() -> None:
    intent = WireguardIntent(
        wg_id="Wireguard5",
        enabled=True,
        asc_args=_ASC_9,
        interface_address="10.0.0.2/32",
    )
    unverified = _resolve_interface_address_verification_status(
        intent,
        {"id": "Wireguard5"},
        address_planned=True,
    )
    assert unverified == "address_configured_unverified"

    confirmed = _resolve_interface_address_verification_status(
        intent,
        {"id": "Wireguard5", "address": "10.0.0.2 255.255.255.255"},
        address_planned=True,
    )
    assert confirmed == "address_readback_confirmed"


def test_activate_without_confirm_live_apply_fail_closed(authed_client) -> None:
    import_resp = authed_client.post(
        "/api/router-control/v1/vpn-profiles/import",
        json={
            "display_name": "Test",
            "profile_text": SAMPLE_PROFILE,
            "vpn_kind": "AmneziaWG",
        },
        headers={"Idempotency-Key": "import-activate-gate"},
    )
    assert import_resp.status_code == 201
    profile_id = import_resp.json()["profile_id"]
    resp = authed_client.post(
        f"/api/router-control/v1/vpn-profiles/{profile_id}/activate",
        json={"confirm_live_apply": False, "wg_id": "Wireguard5"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "wireguard.confirm_required"


def test_deactivate_without_confirm_live_apply_fail_closed(authed_client) -> None:
    resp = authed_client.post(
        "/api/router-control/v1/vpn-profiles/deactivate",
        json={"confirm_live_apply": False, "wg_id": "Wireguard5"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "wireguard.confirm_required"


def test_activate_extra_forbid(authed_client) -> None:
    import_resp = authed_client.post(
        "/api/router-control/v1/vpn-profiles/import",
        json={
            "display_name": "Test",
            "profile_text": SAMPLE_PROFILE,
            "vpn_kind": "AmneziaWG",
        },
        headers={"Idempotency-Key": "import-activate-extra"},
    )
    assert import_resp.status_code == 201
    profile_id = import_resp.json()["profile_id"]
    resp = authed_client.post(
        f"/api/router-control/v1/vpn-profiles/{profile_id}/activate",
        json={
            "confirm_live_apply": True,
            "wg_id": "Wireguard5",
            "unexpected": True,
        },
    )
    assert resp.status_code == 422


def test_deactivate_extra_forbid(authed_client) -> None:
    resp = authed_client.post(
        "/api/router-control/v1/vpn-profiles/deactivate",
        json={
            "confirm_live_apply": True,
            "wg_id": "Wireguard5",
            "unexpected": True,
        },
    )
    assert resp.status_code == 422


def test_resolve_router_apply_lock_key_uses_live_identity() -> None:
    key_a = resolve_router_apply_lock_key(
        None,
        live_host="192.168.2.1",
        ssh_host_key_sha256="SHA256:abc",
        source_address="192.168.2.10",
    )
    key_b = resolve_router_apply_lock_key(
        None,
        live_host="192.168.2.1",
        ssh_host_key_sha256="SHA256:abc",
        source_address="192.168.2.10",
    )
    key_other = resolve_router_apply_lock_key(
        None,
        live_host="192.168.2.2",
        ssh_host_key_sha256="SHA256:abc",
        source_address="192.168.2.10",
    )
    assert key_a == key_b
    assert key_a.startswith("live:")
    assert key_other != key_a


def test_import_extra_forbid(authed_client) -> None:
    resp = authed_client.post(
        "/api/router-control/v1/vpn-profiles/import",
        json={
            "display_name": "Test",
            "profile_text": SAMPLE_PROFILE,
            "unexpected": True,
        },
        headers={"Idempotency-Key": "import-extra"},
    )
    assert resp.status_code == 422


def test_import_persists_metadata_and_secret_refs(authed_client) -> None:
    resp = authed_client.post(
        "/api/router-control/v1/vpn-profiles/import",
        json={
            "display_name": "Catalog AWG",
            "profile_text": SAMPLE_PROFILE,
            "vpn_kind": "AmneziaWG",
            "wg_id": "Wireguard5",
        },
        headers={"Idempotency-Key": "import-meta"},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["metadata"]["interface_address"] == "10.0.0.2/32"
    assert body["metadata"]["peer_keepalive_interval"] == 25
    assert body["wireguard_intent_fields"]["peer_public_key"].startswith("BBBB")
    assert body["wireguard_intent_fields"]["peer_keepalive_interval"] == 25
    assert len(body["credential_refs"]) >= 1
    detail = authed_client.get(
        f"/api/router-control/v1/vpn-profiles/{body['profile_id']}"
    )
    assert detail.status_code == 200
    assert detail.json()["metadata"]["wg_id"] == "Wireguard5"
    assert "AAAAAAAA" not in detail.text


def test_store_secret_refs_and_tunnel_assignments_crud(tmp_path: Path) -> None:
    from router_control.persistence.connection import open_database
    from router_control.persistence.store import PersistenceStore

    store = PersistenceStore(open_database(tmp_path / "store-crud.sqlite3"))
    site_id = store.create_site(display_name="Lab")
    router_id = store.enroll_router(
        site_id=site_id,
        display_name="R1",
        vendor="Keenetic",
        model="Test",
        identity_fingerprint="digest:test",
        host="127.0.0.1",
    )
    cred_id = store.insert_credential_ref(
        router_id=router_id,
        kind="awg_private_key",
        provider="MemoryVault",
        provider_locator="loc-1",
    )
    profile_id = store.import_profile(
        display_name="P1",
        vpn_kind="AmneziaWG",
        content_digest="sha256:abc",
        metadata_json=json.dumps({"wg_id": "Wireguard5"}),
    )
    store.insert_profile_secret_refs(
        profile_id=profile_id,
        refs=[(cred_id, "PrivateKey")],
    )
    refs = store.list_profile_secret_refs(profile_id)
    assert refs[0]["credential_ref_id"] == cred_id
    aid = store.upsert_tunnel_assignment(
        router_id=router_id,
        profile_id=profile_id,
        desired_active=True,
    )
    active = store.get_active_tunnel_assignment(router_id)
    assert active is not None
    assert active["assignment_id"] == aid
    store.deactivate_tunnel_assignments(router_id)
    assert store.get_active_tunnel_assignment(router_id) is None


def test_planner_compiles_address_before_up() -> None:
    intent = WireguardIntent(
        wg_id="Wireguard5",
        enabled=True,
        asc_args=_ASC_9,
        interface_address="10.0.0.2/32",
        ip_global_priority=100,
    )
    plan = compile_wireguard_intent_to_ops(intent)
    ops = [op.operation for op in plan.apply_ops]
    assert WireguardRciOperation.SET_IP_ADDRESS.value in ops
    assert WireguardRciOperation.IP_GLOBAL.value in ops
    assert ops.index(WireguardRciOperation.SET_IP_ADDRESS.value) < ops.index(
        WireguardRciOperation.IP_GLOBAL.value
    )
    from router_control.adapters.netcraze.interface_rci import InterfaceRciOperation

    assert ops.index(WireguardRciOperation.IP_GLOBAL.value) < ops.index(
        InterfaceRciOperation.UP.value
    )


def test_profile_metadata_persists_tcp_mss_pmtu_flag() -> None:
    from router_control_host.routes import _profile_metadata_from_parsed

    vault = MemoryVault()
    parsed = parse_awg_profile_text(SAMPLE_PROFILE, vault=vault)
    metadata = _profile_metadata_from_parsed(
        parsed,
        wg_id="Wireguard5",
        ip_global_auto=False,
        ip_global_priority=None,
        tcp_mss_pmtu=True,
    )
    assert metadata["tcp_mss_pmtu"] is True


def test_activate_intent_preserves_tcp_mss_from_metadata_when_body_omits_field(
    tmp_path: Path,
) -> None:
    from router_control.adapters.netcraze.interface_rci import InterfaceRciOperation
    from router_control.persistence.connection import open_database
    from router_control.persistence.store import PersistenceStore
    from router_control_host.routes import (
        VpnProfileActivateBody,
        _wireguard_intent_from_profile_row,
    )

    store = PersistenceStore(open_database(tmp_path / "activate-tcp-mss-omit.sqlite3"))
    profile_id = store.import_profile(
        display_name="TCP MSS activate omit",
        vpn_kind="AmneziaWG",
        content_digest="sha256:activate-tcp-mss-omit",
        metadata_json=json.dumps(
            {
                "wg_id": "Wireguard5",
                "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                "peer_endpoint": "example.com:51820",
                "peer_allow_ips": "0.0.0.0/0",
                "asc9_args": list(_ASC_9),
                "tcp_mss_pmtu": True,
            }
        ),
    )

    class _Host:
        runtime = type("Runtime", (), {"store": store})()

    row = store.get_profile(profile_id)
    assert row is not None
    body = VpnProfileActivateBody(confirm_live_apply=False)
    assert body.tcp_mss_pmtu is None

    intent = _wireguard_intent_from_profile_row(
        _Host(),
        row,
        enabled=True,
        tcp_mss_pmtu=body.tcp_mss_pmtu,
    )
    assert intent.tcp_mss_pmtu is True
    plan = compile_wireguard_intent_to_ops(intent)
    ops = [op.operation for op in plan.apply_ops]
    assert WireguardRciOperation.SET_TCP_MSS.value in ops
    assert ops.index(WireguardRciOperation.SET_TCP_MSS.value) < ops.index(
        InterfaceRciOperation.UP.value
    )


def test_activate_explicit_tcp_mss_false_overrides_metadata(tmp_path: Path) -> None:
    from router_control.persistence.connection import open_database
    from router_control.persistence.store import PersistenceStore
    from router_control_host.routes import _wireguard_intent_from_profile_row

    store = PersistenceStore(open_database(tmp_path / "activate-tcp-mss-override.sqlite3"))
    profile_id = store.import_profile(
        display_name="TCP MSS activate override",
        vpn_kind="AmneziaWG",
        content_digest="sha256:activate-tcp-mss-override",
        metadata_json=json.dumps(
            {
                "wg_id": "Wireguard5",
                "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                "peer_endpoint": "example.com:51820",
                "peer_allow_ips": "0.0.0.0/0",
                "asc9_args": list(_ASC_9),
                "tcp_mss_pmtu": True,
            }
        ),
    )

    class _Host:
        runtime = type("Runtime", (), {"store": store})()

    row = store.get_profile(profile_id)
    assert row is not None
    intent = _wireguard_intent_from_profile_row(
        _Host(),
        row,
        enabled=True,
        tcp_mss_pmtu=False,
    )
    assert intent.tcp_mss_pmtu is False
    plan = compile_wireguard_intent_to_ops(intent)
    ops = [op.operation for op in plan.apply_ops]
    assert WireguardRciOperation.SET_TCP_MSS.value not in ops


def test_merge_profile_metadata_preserves_unrelated_keys(tmp_path: Path) -> None:
    from router_control.persistence.connection import open_database
    from router_control.persistence.store import PersistenceStore

    store = PersistenceStore(open_database(tmp_path / "merge-metadata.sqlite3"))
    profile_id = store.import_profile(
        display_name="Merge metadata",
        vpn_kind="AmneziaWG",
        content_digest="sha256:merge",
        metadata_json=json.dumps({"wg_id": "Wireguard5", "peer_keepalive_interval": 25}),
    )
    store.merge_profile_metadata(
        profile_id=profile_id,
        patch={"ip_global_priority": 900, "ip_global_auto": False},
    )
    row = store.get_profile(profile_id)
    assert row is not None
    metadata = json.loads(row["metadata_json"])
    assert metadata["ip_global_priority"] == 900
    assert metadata["peer_keepalive_interval"] == 25


def test_import_with_priority_stores_metadata(authed_client) -> None:
    resp = authed_client.post(
        "/api/router-control/v1/vpn-profiles/import",
        json={
            "display_name": "Priority import",
            "profile_text": SAMPLE_PROFILE,
            "vpn_kind": "AmneziaWG",
            "ip_global_priority": 900,
        },
        headers={"Idempotency-Key": "import-priority-900"},
    )
    assert resp.status_code == 201
    assert resp.json()["metadata"]["ip_global_priority"] == 900


def test_activate_without_priority_omits_ip_global_op(tmp_path: Path) -> None:
    from router_control.persistence.connection import open_database
    from router_control.persistence.store import PersistenceStore
    from router_control_host.routes import (
        VpnProfileActivateBody,
        _wireguard_intent_from_profile_row,
    )

    store = PersistenceStore(open_database(tmp_path / "activate-no-priority.sqlite3"))
    profile_id = store.import_profile(
        display_name="No priority",
        vpn_kind="AmneziaWG",
        content_digest="sha256:no-priority",
        metadata_json=json.dumps(
            {
                "wg_id": "Wireguard5",
                "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                "peer_endpoint": "example.com:51820",
                "peer_allow_ips": "0.0.0.0/0",
                "asc9_args": list(_ASC_9),
                "interface_address": "10.0.0.2/32",
            }
        ),
    )

    class _Host:
        runtime = type("Runtime", (), {"store": store})()

    row = store.get_profile(profile_id)
    assert row is not None
    body = VpnProfileActivateBody(confirm_live_apply=False)
    assert body.ip_global_priority is None

    intent = _wireguard_intent_from_profile_row(
        _Host(),
        row,
        enabled=True,
        ip_global_priority=body.ip_global_priority,
    )
    assert intent.ip_global_priority is None
    plan = compile_wireguard_intent_to_ops(intent)
    ops = [op.operation for op in plan.apply_ops]
    assert WireguardRciOperation.IP_GLOBAL.value not in ops


def test_deactivate_with_metadata_priority_plans_clear_ip_global(tmp_path: Path) -> None:
    from router_control.persistence.connection import open_database
    from router_control.persistence.store import PersistenceStore
    from router_control_host.routes import _wireguard_intent_from_profile_row

    store = PersistenceStore(open_database(tmp_path / "deactivate-clear-ip-global.sqlite3"))
    profile_id = store.import_profile(
        display_name="Deactivate clear",
        vpn_kind="AmneziaWG",
        content_digest="sha256:deactivate-clear",
        metadata_json=json.dumps(
            {
                "wg_id": "Wireguard5",
                "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                "peer_endpoint": "example.com:51820",
                "peer_allow_ips": "0.0.0.0/0",
                "asc9_args": list(_ASC_9),
                "ip_global_priority": 900,
            }
        ),
    )

    class _Host:
        runtime = type("Runtime", (), {"store": store})()

    row = store.get_profile(profile_id)
    assert row is not None
    intent = _wireguard_intent_from_profile_row(
        _Host(),
        row,
        wg_id="Wireguard5",
        enabled=False,
    )
    assert intent.ip_global_priority == 900
    plan = compile_wireguard_intent_to_ops(intent)
    teardown_ops = [op.operation for op in plan.teardown_ops]
    assert WireguardRciOperation.CLEAR_IP_GLOBAL.value in teardown_ops


def test_activate_success_merges_priority_into_profile_metadata(tmp_path: Path) -> None:
    """Successful activate writeback path merges ip_global_priority into profile metadata."""
    from router_control.persistence.connection import open_database
    from router_control.persistence.store import PersistenceStore

    store = PersistenceStore(open_database(tmp_path / "activate-writeback.sqlite3"))
    profile_id = store.import_profile(
        display_name="Writeback",
        vpn_kind="AmneziaWG",
        content_digest="sha256:writeback",
        metadata_json=json.dumps({"wg_id": "Wireguard5", "peer_keepalive_interval": 25}),
    )
    store.merge_profile_metadata(
        profile_id=profile_id,
        patch={"ip_global_auto": False, "ip_global_priority": 900},
    )
    row = store.get_profile(profile_id)
    assert row is not None
    metadata = json.loads(row["metadata_json"])
    assert metadata["ip_global_priority"] == 900
    assert metadata["peer_keepalive_interval"] == 25

    routes_source = (
        Path(__file__).resolve().parents[1] / "router_control_host" / "routes.py"
    ).read_text(encoding="utf-8")
    upsert_idx = routes_source.find("upsert_tunnel_assignment(")
    assert upsert_idx != -1
    writeback_slice = routes_source[upsert_idx : upsert_idx + 1200]
    assert "merge_profile_metadata" in writeback_slice
    assert "ip_global_priority" in writeback_slice


def test_tunnel_four_states_unchanged_in_service_module() -> None:
    from router_control.application import wireguard_apply_service as svc

    assert svc._TUNNEL_NO_PEER == "tunnel_no_peer"
    assert svc._TUNNEL_NEVER_HANDSHAKED == "tunnel_never_handshaked"
    assert svc._TUNNEL_HEALTHY == "tunnel_healthy"
    assert svc._TUNNEL_UNVERIFIED == "tunnel_unverified"


def test_router_apply_lock_serializes_calls() -> None:
    order: list[str] = []

    def first() -> None:
        order.append("start1")
        order.append("end1")

    def second() -> None:
        order.append("start2")
        order.append("end2")

    run_with_router_apply_lock("router-1", first)
    run_with_router_apply_lock("router-1", second)
    assert order == ["start1", "end1", "start2", "end2"]


def test_parsed_awg_profile_retains_interface_address() -> None:
    vault = MemoryVault()
    parsed = parse_awg_profile_text(SAMPLE_PROFILE, vault=vault)
    assert parsed.interface_address == "10.0.0.2/32"
    assert parsed.interface_address_present is True
    assert parsed.sanitized_dict_for_apply()["interface_address"] == "10.0.0.2/32"


def _seed_catalog_router(store: Any) -> str:
    site_id = store.create_site(display_name="Activate Prior Teardown Lab")
    return store.enroll_router(
        site_id=site_id,
        display_name="Activate Prior Teardown Router",
        vendor="Fake",
        model="M1",
        identity_fingerprint="digest:activate-prior-teardown",
        host="127.0.0.1",
    )


def _seed_catalog_profile(store: Any, *, display_name: str, wg_id: str = "Wireguard5") -> str:
    return store.import_profile(
        display_name=display_name,
        vpn_kind="AmneziaWG",
        content_digest=f"digest-{display_name}",
        metadata_json=json.dumps(
            {
                "wg_id": wg_id,
                "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                "peer_endpoint": "example.com:51820",
                "peer_allow_ips": "0.0.0.0/0",
                "asc9_args": list(_ASC_9),
            }
        ),
    )


def test_activate_prior_teardown_failed_fail_closed(
    authed_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Switching profiles must not report activate success when prior teardown fails."""
    import router_control_host.routes as routes_mod
    import router_control_host.wireguard_apply_routes as wg_routes_mod
    from types import SimpleNamespace

    store = authed_client.app.state.host.runtime.store
    router_id = _seed_catalog_router(store)
    prior_profile_id = _seed_catalog_profile(store, display_name="prior-active")
    next_profile_id = _seed_catalog_profile(store, display_name="next-target", wg_id="Wireguard6")
    store.upsert_tunnel_assignment(
        router_id=router_id,
        profile_id=prior_profile_id,
        desired_active=True,
        observed_vendor_locator="Wireguard5",
    )

    apply_calls: list[object] = []

    def _track_apply(*_args: object, **_kwargs: object) -> object:
        apply_calls.append(True)
        raise AssertionError("apply_wireguard_intent must not run after failed prior teardown")

    def _failed_teardown(*_args: object, **_kwargs: object) -> object:
        return SimpleNamespace(overall="failed")

    monkeypatch.setattr(
        wg_routes_mod,
        "_validate_live_connection_fields",
        lambda *_a, **_k: None,
    )
    monkeypatch.setattr(routes_mod, "apply_wireguard_intent", _track_apply)
    monkeypatch.setattr(routes_mod, "teardown_wireguard", _failed_teardown)

    resp = authed_client.post(
        f"/api/router-control/v1/vpn-profiles/{next_profile_id}/activate",
        json={
            "confirm_live_apply": True,
            "router_id": router_id,
            "wg_id": "Wireguard6",
        },
    )
    assert resp.status_code == 422
    body = resp.json()
    assert body["error"]["code"] == "profile.activate_failed"
    assert body["error"]["message"] == "WireGuard apply failed"
    assert "prior VPN profile teardown" not in body["error"]["message"]
    assert "overall=failed" not in body["error"]["message"]
    assert apply_calls == []
    active = store.get_active_tunnel_assignment(router_id)
    assert active is not None
    assert str(active["profile_id"]) == prior_profile_id


def test_teardown_prior_profile_assignment_live_dispatch_failed_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Live prior teardown with overall != applied must raise before activate continues."""
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    from router_control.application.wireguard_apply_service import WireguardApplyServiceError
    from router_control.persistence.connection import open_database
    from router_control.persistence.store import PersistenceStore
    from router_control_host.routes import (
        VpnProfileActivateBody,
        _teardown_prior_profile_assignment,
    )
    import router_control_host.wireguard_apply_routes as wg_routes_mod

    store = PersistenceStore(open_database(tmp_path / "prior-teardown-live.sqlite3"))
    router_id = _seed_catalog_router(store)
    prior_profile_id = _seed_catalog_profile(store, display_name="prior-unit")
    next_profile_id = _seed_catalog_profile(store, display_name="next-unit", wg_id="Wireguard6")
    store.upsert_tunnel_assignment(
        router_id=router_id,
        profile_id=prior_profile_id,
        desired_active=True,
        observed_vendor_locator="Wireguard5",
    )

    host = MagicMock()
    host.runtime.store = store
    body = VpnProfileActivateBody(
        confirm_live_apply=True,
        router_id=router_id,
        host="192.168.2.1",
        username="admin",
        router_credential_ref_id="cred_test",
        ssh_host_key_sha256="SHA256:abc",
        source_address="192.168.2.10",
    )

    monkeypatch.setattr(wg_routes_mod, "_should_use_live_path", lambda *_a, **_k: True)
    monkeypatch.setattr(
        wg_routes_mod,
        "_dispatch_teardown_live",
        lambda **_k: SimpleNamespace(overall="failed"),
    )

    with pytest.raises(WireguardApplyServiceError, match="prior VPN profile teardown"):
        _teardown_prior_profile_assignment(
            host=host,
            request=MagicMock(),
            body=body,
            wg_routes=wg_routes_mod,
            router_id=router_id,
            profile_id=next_profile_id,
            logical_role="primary",
            live_params=object(),
            trail_params=None,
        )

    active = store.get_active_tunnel_assignment(router_id)
    assert active is not None
    assert str(active["profile_id"]) == prior_profile_id


def test_vpn_activate_identity_mismatch_returns_422(
    authed_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    authed_client.app.state.host.gate_a_certification = _open_gate_a()
    import_resp = authed_client.post(
        "/api/router-control/v1/vpn-profiles/import",
        json={
            "display_name": "Identity Mismatch Activate",
            "profile_text": SAMPLE_PROFILE,
            "vpn_kind": "AmneziaWG",
        },
        headers={"Idempotency-Key": "import-identity-mismatch-activate"},
    )
    assert import_resp.status_code == 201
    profile_id = import_resp.json()["profile_id"]
    backup_calls: list[str] = []

    @contextmanager
    def _mock_live(**_kwargs: object):
        yield WifiLiveSession(transport=MagicMock(), tunnel=MagicMock())

    def _raise_mismatch(*_args: object, **_kwargs: object) -> None:
        raise LiveIdentityTupleMismatchError("tuple mismatch")

    def _track_backup(**_kwargs: object) -> StartupBackupMetadata:
        backup_calls.append("backup")
        raise AssertionError("backup must not run on identity mismatch")

    monkeypatch.setattr(
        "router_control_host.wireguard_apply_routes.open_wifi_live_session",
        _mock_live,
    )
    monkeypatch.setattr(
        "router_control_host.wireguard_apply_routes.ensure_live_gate_a_tuple_match",
        _raise_mismatch,
    )
    monkeypatch.setattr(
        "router_control_host.wireguard_apply_routes.is_win32_live_capable",
        lambda: True,
    )
    monkeypatch.setattr(
        "router_control_host.wireguard_apply_routes.backup_startup_config",
        _track_backup,
    )

    resp = authed_client.post(
        f"/api/router-control/v1/vpn-profiles/{profile_id}/activate",
        json={"confirm_live_apply": True, "wg_id": "Wireguard5", **_LIVE_CONN},
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "wireguard.identity_mismatch"
    assert backup_calls == []


def test_vpn_deactivate_identity_mismatch_returns_422(
    authed_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    authed_client.app.state.host.gate_a_certification = _open_gate_a()
    backup_calls: list[str] = []

    @contextmanager
    def _mock_live(**_kwargs: object):
        yield WifiLiveSession(transport=MagicMock(), tunnel=MagicMock())

    def _raise_mismatch(*_args: object, **_kwargs: object) -> None:
        raise LiveIdentityTupleMismatchError("tuple mismatch")

    def _track_backup(**_kwargs: object) -> StartupBackupMetadata:
        backup_calls.append("backup")
        raise AssertionError("backup must not run on identity mismatch")

    monkeypatch.setattr(
        "router_control_host.wireguard_apply_routes.open_wifi_live_session",
        _mock_live,
    )
    monkeypatch.setattr(
        "router_control_host.wireguard_apply_routes.ensure_live_gate_a_tuple_match",
        _raise_mismatch,
    )
    monkeypatch.setattr(
        "router_control_host.wireguard_apply_routes.is_win32_live_capable",
        lambda: True,
    )
    monkeypatch.setattr(
        "router_control_host.wireguard_apply_routes.backup_startup_config",
        _track_backup,
    )

    resp = authed_client.post(
        "/api/router-control/v1/vpn-profiles/deactivate",
        json={"confirm_live_apply": True, "wg_id": "Wireguard5", **_LIVE_CONN},
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "wireguard.identity_mismatch"
    assert backup_calls == []

