"""Offline test: VPN watchdog reapply passes handshake settle band."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest
from router_control.application import vpn_watchdog_service
from router_control.application.vpn_watchdog_service import VpnWatchdogHandle
from router_control.application.wireguard_apply_planner import (
    WG_HANDSHAKE_SETTLE_SECONDS_MIN,
    clamp_handshake_settle_seconds,
)
from router_control.composition import create_offline_runtime
from router_control.domain.network_intents import WireguardIntent, WireguardPeerRciShape


class _Transport:
    def execute_rci_parse(self, _cmd: str) -> dict[str, Any]:
        return {}


def _setup_watchdog(
    tmp_path: Any,
) -> tuple[VpnWatchdogHandle, str, WireguardIntent, dict[str, Any]]:
    runtime = create_offline_runtime(db_path=tmp_path / "vpn-wd-settle.sqlite3")
    store = runtime.store
    site_id = store.create_site(display_name="VPN WD Settle", now=datetime(2026, 8, 8, tzinfo=UTC))
    router_id = store.enroll_router(
        site_id=site_id,
        display_name="VPN WD Settle Router",
        vendor="Keenetic",
        model="NC-1812",
        identity_fingerprint="fp-vpn-wd-settle",
        host="127.0.0.1",
        now=datetime(2026, 8, 8, tzinfo=UTC),
    )
    profile_id = store.import_profile(
        display_name="WD settle profile",
        vpn_kind="AmneziaWG",
        content_digest="sha256:vpn-wd-settle",
        metadata_json=json.dumps(
            {
                "wg_id": "Wireguard5",
                "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                "peer_endpoint": "example.com:51820",
                "peer_allow_ips": "0.0.0.0/0",
            }
        ),
    )
    cred_id = store.insert_credential_ref(
        router_id=router_id,
        kind="awg_private_key",
        provider="MemoryVault",
        provider_locator="loc-vpn-wd-settle",
    )
    store.insert_profile_secret_refs(
        profile_id=profile_id,
        refs=[(cred_id, "PrivateKey")],
    )
    store.upsert_tunnel_assignment(
        router_id=router_id,
        profile_id=profile_id,
        desired_active=True,
        observed_vendor_locator="Wireguard5",
        policy_metadata_json='{"wg_id":"Wireguard5"}',
    )
    assignment = store.get_active_tunnel_assignment(router_id)
    assert assignment is not None
    host = type("Host", (), {"runtime": runtime})()
    handle = VpnWatchdogHandle(host=host)
    intent = WireguardIntent(
        wg_id="Wireguard5",
        enabled=True,
        peer_public_key="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
        peer_endpoint="example.com:51820",
        peer_allow_ips="0.0.0.0/0",
        peer_rci_shape=WireguardPeerRciShape.NESTED_RCI,
    )
    return handle, router_id, intent, assignment


def test_reapply_passes_handshake_settle_seconds(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handle, router_id, intent, assignment = _setup_watchdog(tmp_path)
    captured: dict[str, Any] = {}

    handle.backup_callback_factory = lambda _rid: lambda: None

    def _fake_apply(**kwargs: Any) -> Any:
        captured.update(kwargs)
        from router_control.application.wireguard_apply_service import WireguardApplyResult

        return WireguardApplyResult(
            overall="applied",
            wg_id=intent.wg_id,
            steps=(),
            verification=None,
            errors=(),
            logs=(),
            verification_status="pending_live_verification",
            verification_notes=(),
            rollback=None,
        )

    monkeypatch.setattr(vpn_watchdog_service, "apply_wireguard_intent", _fake_apply)
    handle._reapply_locked(router_id, intent, _Transport(), assignment)  # noqa: SLF001
    expected = clamp_handshake_settle_seconds(WG_HANDSHAKE_SETTLE_SECONDS_MIN)
    assert captured.get("handshake_settle_seconds") == expected
    assert expected == 20.0
    assert captured.get("store") is handle.host.runtime.store
    sealed = captured.get("sealed_apply_params")
    assert sealed is not None
    assert sealed.route == "vpn-profiles"
    assert sealed.verb == "watchdog_reapply"
    assert sealed.router_id == router_id
