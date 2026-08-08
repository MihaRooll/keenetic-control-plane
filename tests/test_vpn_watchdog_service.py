"""Unit tests for VPN watchdog poll/reapply streak honesty."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest

import router_control.application.vpn_watchdog_service as vpn_watchdog_service
from router_control.application.vpn_watchdog_service import (
    VPN_WATCHDOG_POLL_SECONDS,
    VpnWatchdogHandle,
    _RouterWatchState,
)
from router_control.composition import create_offline_runtime


def _seed_active_assignment(runtime) -> tuple[str, str]:
    store = runtime.store
    site_id = store.create_site(display_name="VPN WD", now=datetime(2026, 8, 8, tzinfo=UTC))
    router_id = store.enroll_router(
        site_id=site_id,
        display_name="VPN WD Router",
        vendor="Keenetic",
        model="NC-1812",
        identity_fingerprint="fp-vpn-wd",
        host="127.0.0.1",
        now=datetime(2026, 8, 8, tzinfo=UTC),
    )
    profile_id = store.import_profile(
        display_name="WD profile",
        vpn_kind="AmneziaWG",
        content_digest="sha256:vpn-wd",
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


class _Transport:
    def execute_rci_parse(self, _cmd: str) -> dict[str, Any]:
        return {}


@pytest.mark.asyncio
async def test_poll_once_clears_streak_only_when_reapply_applied(
    tmp_path, monkeypatch
) -> None:
    runtime = create_offline_runtime(db_path=tmp_path / "vpn-poll-applied.sqlite3")
    router_id, _profile_id = _seed_active_assignment(runtime)
    host = type("Host", (), {"runtime": runtime})()
    handle = VpnWatchdogHandle(host=host)
    handle.transport_factory = lambda _rid: _Transport()
    handle.backup_callback_factory = lambda _rid: lambda: None
    handle._states[str(router_id)] = _RouterWatchState(unhealthy_streak=1)  # noqa: SLF001

    monkeypatch.setattr(
        vpn_watchdog_service,
        "observe_tunnel",
        lambda _observed: type("O", (), {"verdict": "tunnel_unhealthy"})(),
    )
    monkeypatch.setattr(
        vpn_watchdog_service,
        "apply_wireguard_intent",
        lambda **kwargs: type("R", (), {"overall": "applied", "to_dict": lambda self: {}})(),
    )
    monkeypatch.setattr(
        vpn_watchdog_service,
        "run_with_router_apply_lock",
        lambda _rid, fn: fn(),
    )

    await handle._poll_once()  # noqa: SLF001
    assert handle._states[str(router_id)].unhealthy_streak == 0  # noqa: SLF001


@pytest.mark.asyncio
async def test_poll_once_keeps_streak_when_reapply_fails(
    tmp_path, monkeypatch
) -> None:
    runtime = create_offline_runtime(db_path=tmp_path / "vpn-poll-failed.sqlite3")
    router_id, _profile_id = _seed_active_assignment(runtime)
    host = type("Host", (), {"runtime": runtime})()
    handle = VpnWatchdogHandle(host=host)
    handle.transport_factory = lambda _rid: _Transport()
    handle.backup_callback_factory = lambda _rid: lambda: None
    handle._states[str(router_id)] = _RouterWatchState(unhealthy_streak=1)  # noqa: SLF001

    monkeypatch.setattr(
        vpn_watchdog_service,
        "observe_tunnel",
        lambda _observed: type("O", (), {"verdict": "tunnel_unhealthy"})(),
    )
    monkeypatch.setattr(
        vpn_watchdog_service,
        "apply_wireguard_intent",
        lambda **kwargs: type("R", (), {"overall": "failed", "to_dict": lambda self: {}})(),
    )
    monkeypatch.setattr(
        vpn_watchdog_service,
        "run_with_router_apply_lock",
        lambda _rid, fn: fn(),
    )

    await handle._poll_once()  # noqa: SLF001
    assert handle._states[str(router_id)].unhealthy_streak == 2  # noqa: SLF001


@pytest.mark.asyncio
async def test_poll_once_keeps_streak_when_backup_unavailable(
    tmp_path, monkeypatch
) -> None:
    runtime = create_offline_runtime(db_path=tmp_path / "vpn-poll-no-backup.sqlite3")
    router_id, _profile_id = _seed_active_assignment(runtime)
    host = type("Host", (), {"runtime": runtime})()
    handle = VpnWatchdogHandle(host=host)
    handle.transport_factory = lambda _rid: _Transport()
    handle.backup_callback_factory = lambda _rid: None
    handle._states[str(router_id)] = _RouterWatchState(unhealthy_streak=1)  # noqa: SLF001

    monkeypatch.setattr(
        vpn_watchdog_service,
        "observe_tunnel",
        lambda _observed: type("O", (), {"verdict": "tunnel_unhealthy"})(),
    )
    apply_calls: list[str] = []

    def _fake_apply(**_kwargs: Any) -> Any:
        apply_calls.append("apply")
        return type("R", (), {"overall": "applied", "to_dict": lambda self: {}})()

    monkeypatch.setattr(vpn_watchdog_service, "apply_wireguard_intent", _fake_apply)
    monkeypatch.setattr(
        vpn_watchdog_service,
        "run_with_router_apply_lock",
        lambda _rid, fn: fn(),
    )

    await handle._poll_once()  # noqa: SLF001
    assert apply_calls == []
    assert handle._states[str(router_id)].unhealthy_streak == 2  # noqa: SLF001
    state = handle._states[str(router_id)]  # noqa: SLF001
    assert state.backoff_seconds >= VPN_WATCHDOG_POLL_SECONDS
