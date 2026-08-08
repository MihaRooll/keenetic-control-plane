"""Unit tests for VPN watchdog poll/reapply streak honesty."""

from __future__ import annotations

import asyncio
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
    cred_id = store.insert_credential_ref(
        router_id=router_id,
        kind="awg_private_key",
        provider="MemoryVault",
        provider_locator="loc-vpn-wd",
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
    return router_id, profile_id


class _Transport:
    def execute_rci_parse(self, _cmd: str) -> dict[str, Any]:
        return {}


def _fake_apply_result(
    *,
    overall: str = "applied",
    tunnel_verification_status: str = "tunnel_healthy",
) -> Any:
    return type(
        "R",
        (),
        {
            "overall": overall,
            "tunnel_verification_status": tunnel_verification_status,
            "to_dict": lambda self: {
                "overall": overall,
                "tunnel_verification_status": tunnel_verification_status,
            },
        },
    )()


def _poll_setup(
    tmp_path,
    *,
    db_name: str,
    unhealthy_streak: int = 1,
    backoff_seconds: float | None = None,
) -> tuple[Any, VpnWatchdogHandle, str]:
    runtime = create_offline_runtime(db_path=tmp_path / db_name)
    router_id, _profile_id = _seed_active_assignment(runtime)
    host = type("Host", (), {"runtime": runtime})()
    handle = VpnWatchdogHandle(host=host)
    handle.transport_factory = lambda _rid: _Transport()
    handle.backup_callback_factory = lambda _rid: lambda: None
    state_kwargs: dict[str, Any] = {"unhealthy_streak": unhealthy_streak}
    if backoff_seconds is not None:
        state_kwargs["backoff_seconds"] = backoff_seconds
    handle._states[str(router_id)] = _RouterWatchState(**state_kwargs)  # noqa: SLF001
    return runtime, handle, router_id


def _patch_unhealthy_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        vpn_watchdog_service,
        "_observe_tunnel_with_optional_recheck",
        lambda *_args, **_kwargs: ("tunnel_unhealthy", {}, None),
    )
    monkeypatch.setattr(
        vpn_watchdog_service,
        "run_with_router_apply_lock",
        lambda _rid, fn: fn(),
    )


@pytest.mark.asyncio
async def test_poll_once_clears_streak_only_when_reapply_applied(
    tmp_path, monkeypatch
) -> None:
    _runtime, handle, router_id = _poll_setup(
        tmp_path,
        db_name="vpn-poll-applied.sqlite3",
        unhealthy_streak=1,
        backoff_seconds=180.0,
    )
    _patch_unhealthy_probe(monkeypatch)
    monkeypatch.setattr(
        vpn_watchdog_service,
        "apply_wireguard_intent",
        lambda **kwargs: _fake_apply_result(
            overall="applied",
            tunnel_verification_status="tunnel_healthy",
        ),
    )

    await handle._poll_once()  # noqa: SLF001
    state = handle._states[str(router_id)]  # noqa: SLF001
    assert state.unhealthy_streak == 0
    assert state.backoff_seconds == VPN_WATCHDOG_POLL_SECONDS


@pytest.mark.asyncio
async def test_poll_once_keeps_streak_when_reapply_applied_but_not_healthy(
    tmp_path, monkeypatch
) -> None:
    _runtime, handle, router_id = _poll_setup(
        tmp_path,
        db_name="vpn-poll-applied-not-healthy.sqlite3",
        unhealthy_streak=1,
        backoff_seconds=90.0,
    )
    _patch_unhealthy_probe(monkeypatch)
    monkeypatch.setattr(
        vpn_watchdog_service,
        "apply_wireguard_intent",
        lambda **kwargs: _fake_apply_result(
            overall="applied",
            tunnel_verification_status="tunnel_never_handshaked",
        ),
    )

    loop = asyncio.get_running_loop()
    before = loop.time()
    await handle._poll_once()  # noqa: SLF001
    after = loop.time()
    state = handle._states[str(router_id)]  # noqa: SLF001
    assert state.unhealthy_streak == 2
    assert state.backoff_seconds == 180.0
    assert state.next_poll_at >= before + 180.0
    assert state.next_poll_at <= after + 180.0


@pytest.mark.asyncio
async def test_reapply_audit_keeps_applied_outcome_when_not_healthy(
    tmp_path, monkeypatch
) -> None:
    runtime, handle, router_id = _poll_setup(
        tmp_path,
        db_name="vpn-poll-audit-applied.sqlite3",
        unhealthy_streak=1,
    )
    _patch_unhealthy_probe(monkeypatch)
    monkeypatch.setattr(
        vpn_watchdog_service,
        "apply_wireguard_intent",
        lambda **kwargs: _fake_apply_result(
            overall="applied",
            tunnel_verification_status="tunnel_never_handshaked",
        ),
    )
    audit_calls: list[dict[str, Any]] = []
    original = runtime.store.try_append_sealed_apply_audit

    def _spy(**kwargs: Any) -> None:
        audit_calls.append(kwargs)
        original(**kwargs)

    monkeypatch.setattr(runtime.store, "try_append_sealed_apply_audit", _spy)

    await handle._poll_once()  # noqa: SLF001
    reapply_audits = [
        c for c in audit_calls if c.get("action") == "vpn_watchdog.reapply"
    ]
    assert len(reapply_audits) == 1
    assert reapply_audits[0]["outcome"] == "applied"


@pytest.mark.asyncio
async def test_poll_once_keeps_streak_when_reapply_fails(
    tmp_path, monkeypatch
) -> None:
    _runtime, handle, router_id = _poll_setup(
        tmp_path,
        db_name="vpn-poll-failed.sqlite3",
        unhealthy_streak=1,
    )
    _patch_unhealthy_probe(monkeypatch)
    monkeypatch.setattr(
        vpn_watchdog_service,
        "apply_wireguard_intent",
        lambda **kwargs: _fake_apply_result(
            overall="failed",
            tunnel_verification_status="tunnel_never_handshaked",
        ),
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
        "_observe_tunnel_with_optional_recheck",
        lambda *_args, **_kwargs: ("tunnel_unhealthy", {}, None),
    )
    apply_calls: list[str] = []

    def _fake_apply(**_kwargs: Any) -> Any:
        apply_calls.append("apply")
        return _fake_apply_result()

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
