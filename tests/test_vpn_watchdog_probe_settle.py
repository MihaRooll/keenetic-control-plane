"""Offline tests for VPN watchdog probe settle+recheck parity with activate."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
import router_control.application.wireguard_apply_service as wg_apply_service
from router_control.application.vpn_watchdog_service import VpnWatchdogHandle
from router_control.application.wireguard_apply_planner import (
    WG_HANDSHAKE_SETTLE_SECONDS_MIN,
    clamp_handshake_settle_seconds,
)
from router_control.composition import create_offline_runtime

from tests.test_wireguard_apply_service import (
    FakeWireguardApplyTransport,
    _ambiguous_zero_handshake_readback,
    _dead_peer_readback,
    _healthy_peer_readback_synthesised,
)


def _seed_active_assignment(runtime) -> tuple[str, str]:
    store = runtime.store
    site_id = store.create_site(display_name="VPN WD Probe", now=datetime(2026, 8, 8, tzinfo=UTC))
    router_id = store.enroll_router(
        site_id=site_id,
        display_name="VPN WD Probe Router",
        vendor="Keenetic",
        model="NC-1812",
        identity_fingerprint="fp-vpn-wd-probe",
        host="127.0.0.1",
        now=datetime(2026, 8, 8, tzinfo=UTC),
    )
    profile_id = store.import_profile(
        display_name="WD probe profile",
        vpn_kind="AmneziaWG",
        content_digest="sha256:vpn-wd-probe",
        metadata_json=json.dumps(
            {
                "wg_id": "Wireguard5",
                "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                "peer_endpoint": "example.com:51820",
                "peer_allow_ips": "0.0.0.0/0",
            }
        ),
    )
    store.upsert_tunnel_assignment(
        router_id=router_id,
        profile_id=profile_id,
        desired_active=True,
        observed_vendor_locator="Wireguard5",
        policy_metadata_json='{"wg_id":"Wireguard5"}',
    )
    return router_id, profile_id


def _probe_intent(runtime, router_id: str):
    handle = VpnWatchdogHandle(host=type("Host", (), {"runtime": runtime})())
    assignment = runtime.store.get_active_tunnel_assignment(router_id)
    assert assignment is not None
    intent = handle._intent_from_assignment(assignment, runtime.store)  # noqa: SLF001
    assert intent is not None
    return handle, intent


def test_probe_settle_recheck_never_handshaked_becomes_healthy(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr(wg_apply_service.time, "sleep", lambda seconds: sleeps.append(seconds))
    transport = FakeWireguardApplyTransport(
        show_interface_readback_sequence=[
            _dead_peer_readback(txbytes=100),
            _healthy_peer_readback_synthesised(),
        ]
    )
    runtime = create_offline_runtime(db_path=tmp_path / "vpn-probe-settle-healthy.sqlite3")
    router_id, _profile_id = _seed_active_assignment(runtime)
    handle, intent = _probe_intent(runtime, router_id)

    assert handle._probe_tunnel_healthy(transport, intent) is True  # noqa: SLF001
    assert sleeps == [clamp_handshake_settle_seconds(WG_HANDSHAKE_SETTLE_SECONDS_MIN)]
    assert sleeps == [20.0]
    assert transport._show_interface_parse_count == 2


def test_probe_settle_recheck_both_unhealthy_returns_false(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr(wg_apply_service.time, "sleep", lambda seconds: sleeps.append(seconds))
    transport = FakeWireguardApplyTransport(
        show_interface_readback_sequence=[
            _dead_peer_readback(txbytes=100),
            _dead_peer_readback(txbytes=200),
        ]
    )
    runtime = create_offline_runtime(db_path=tmp_path / "vpn-probe-settle-unhealthy.sqlite3")
    router_id, _profile_id = _seed_active_assignment(runtime)
    handle, intent = _probe_intent(runtime, router_id)

    assert handle._probe_tunnel_healthy(transport, intent) is False  # noqa: SLF001
    assert sleeps == [20.0]
    assert transport._show_interface_parse_count == 2


def test_probe_settle_skips_sleep_when_already_healthy(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr(wg_apply_service.time, "sleep", lambda seconds: sleeps.append(seconds))
    transport = FakeWireguardApplyTransport(
        show_interface_readback_sequence=[_healthy_peer_readback_synthesised()]
    )
    runtime = create_offline_runtime(db_path=tmp_path / "vpn-probe-no-settle.sqlite3")
    router_id, _profile_id = _seed_active_assignment(runtime)
    handle, intent = _probe_intent(runtime, router_id)

    assert handle._probe_tunnel_healthy(transport, intent) is True  # noqa: SLF001
    assert sleeps == []
    assert transport._show_interface_parse_count == 1


def test_probe_settle_recheck_ambiguous_zero_handshake_becomes_healthy(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr(wg_apply_service.time, "sleep", lambda seconds: sleeps.append(seconds))
    transport = FakeWireguardApplyTransport(
        show_interface_readback_sequence=[
            _ambiguous_zero_handshake_readback(txbytes=100),
            _healthy_peer_readback_synthesised(),
        ]
    )
    runtime = create_offline_runtime(db_path=tmp_path / "vpn-probe-ambiguous.sqlite3")
    router_id, _profile_id = _seed_active_assignment(runtime)
    handle, intent = _probe_intent(runtime, router_id)

    assert handle._probe_tunnel_healthy(transport, intent) is True  # noqa: SLF001
    assert sleeps == [20.0]
    assert transport._show_interface_parse_count == 2
