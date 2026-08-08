"""Unit tests for uplink watchdog skip/reapply logic (offline/fake)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock

import pytest
import router_control.application.uplink_watchdog_service as uplink_watchdog_service
from router_control.application.internet_status_observe import InternetStatusObservation
from router_control.application.remembered_uplink import RememberedUplinkService
from router_control.application.uplink_watchdog_service import (
    UPLINK_WATCHDOG_POLL_SECONDS,
    UplinkWatchdogHandle,
    gateway_matches_remembered_station,
    is_ethernet_like_gateway,
    is_wireguard_like_gateway,
    should_reapply_uplink,
    should_skip_uplink_reapply,
)
from router_control.composition import FixedClock, create_offline_runtime
from router_control.persistence.connection import open_database
from router_control.persistence.store import PersistenceStore

_FIXED_NOW = datetime(2026, 8, 5, 12, 0, 0, tzinfo=UTC)


def _observation(
    *,
    gateway_interface: str | None,
    internet: bool = False,
) -> InternetStatusObservation:
    return InternetStatusObservation(
        internet=internet,
        reliable=None,
        gateway_accessible=None,
        dns_accessible=None,
        captive_accessible=None,
        gateway_interface=gateway_interface,
        gateway_ssid=None,
        checked_at="2026-08-05T12:00:00Z",
        read_status="ok",
    )


def _seed_remembered_active(
    runtime,
    *,
    updated_at: datetime | None = None,
) -> tuple[str, dict[str, Any]]:
    store = runtime.store
    site_id = store.create_site(display_name="WD", now=_FIXED_NOW)
    router_id = store.enroll_router(
        site_id=site_id,
        display_name="WD Router",
        vendor="Keenetic",
        model="NC-1812",
        identity_fingerprint="fp-wd",
        host="127.0.0.1",
        now=_FIXED_NOW,
    )
    cred_id = store.insert_credential_ref(
        router_id=router_id,
        kind="WifiApPsk",
        provider="memory",
        provider_locator="wd-loc",
        now=_FIXED_NOW,
    )
    clock = FixedClock(updated_at or _FIXED_NOW)
    svc = RememberedUplinkService(store=store, clock=clock)
    remembered = svc.update_remembered(
        router_id=router_id,
        ssid="Upstream",
        band="BAND_5GHZ",
        credential_ref_id=cred_id,
        desired_active=True,
    )
    host = type("Host", (), {})()
    host.runtime = runtime
    return router_id, remembered


def _make_handle(
    host: Any,
    *,
    observation: InternetStatusObservation,
    apply_calls: list[str] | None = None,
) -> UplinkWatchdogHandle:
    handle = UplinkWatchdogHandle(host=host)

    class _ObserveTransport:
        pass

    class _ApplyTransport:
        wifi_station_live_dispatch = True

        def execute_sealed_rci_write(self, _request: Any) -> dict[str, Any]:
            return {}

        def execute_rci_parse(self, _cmd: str) -> dict[str, Any]:
            return {}

    def _observe_factory(_router_id: str) -> _ObserveTransport:
        return _ObserveTransport()

    def _apply_factory(router_id: str) -> _ApplyTransport | None:
        if apply_calls is not None:
            apply_calls.append(router_id)
        return _ApplyTransport()

    handle.observe_transport_factory = _observe_factory
    handle.apply_transport_factory = _apply_factory
    return handle


def test_gateway_matches_remembered_station_wifi() -> None:
    assert gateway_matches_remembered_station(
        "WifiMaster1/WifiStation0",
        expected_station_id="WifiMaster1/WifiStation0",
    )


def test_skip_when_gateway_matches_even_if_internet_false() -> None:
    observation = _observation(
        gateway_interface="WifiMaster0/WifiStation0",
        internet=False,
    )
    now = datetime.now(tz=UTC).timestamp()
    assert should_skip_uplink_reapply(
        observation=observation,
        expected_station_id="WifiMaster0/WifiStation0",
        suppress_until_epoch=None,
        now_epoch=now,
    )


def test_reapply_when_gateway_absent() -> None:
    observation = _observation(gateway_interface=None)
    assert should_reapply_uplink(
        observation=observation,
        expected_station_id="WifiMaster1/WifiStation0",
    )


def test_reapply_when_gateway_mismatch() -> None:
    observation = _observation(gateway_interface="GigabitEthernet0")
    assert should_reapply_uplink(
        observation=observation,
        expected_station_id="WifiMaster1/WifiStation0",
    )


def test_suppress_window_after_manual_mutation() -> None:
    observation = _observation(gateway_interface=None)
    now = datetime.now(tz=UTC).timestamp()
    suppress_until = now + UPLINK_WATCHDOG_POLL_SECONDS
    assert should_skip_uplink_reapply(
        observation=observation,
        expected_station_id="WifiMaster1/WifiStation0",
        suppress_until_epoch=suppress_until,
        now_epoch=now,
    )


def test_watchdog_reapply_records_audit_without_password(tmp_path, monkeypatch) -> None:
    runtime = create_offline_runtime(db_path=tmp_path / "watchdog.sqlite3")
    store = runtime.store
    site_id = store.create_site(display_name="WD", now=datetime(2026, 8, 5, tzinfo=UTC))
    router_id = store.enroll_router(
        site_id=site_id,
        display_name="WD Router",
        vendor="Keenetic",
        model="NC-1812",
        identity_fingerprint="fp-wd",
        host="127.0.0.1",
        now=datetime(2026, 8, 5, tzinfo=UTC),
    )
    cred_id = store.insert_credential_ref(
        router_id=router_id,
        kind="WifiApPsk",
        provider="memory",
        provider_locator="wd-loc",
        now=datetime(2026, 8, 5, tzinfo=UTC),
    )
    svc = RememberedUplinkService(store=store, clock=runtime.clock)
    remembered = svc.update_remembered(
        router_id=router_id,
        ssid="Upstream",
        band="BAND_5GHZ",
        credential_ref_id=cred_id,
        desired_active=True,
    )

    host = type("Host", (), {})()
    host.runtime = runtime

    captured: dict[str, Any] = {}

    def _fake_apply(**kwargs: Any) -> Any:
        from router_control.application.wifi_station_apply_service import WifiStationApplyResult

        captured["intent"] = kwargs.get("intent")
        return WifiStationApplyResult(
            overall="applied",
            station_id="WifiMaster1/WifiStation0",
            verification_status="uplink_verified_bounded",
            grammar_verification_status="device_accepted_grammar",
            uplink_verification_status="uplink_verified_bounded",
            steps=(),
            errors=(),
            logs=(),
        )

    monkeypatch.setattr(
        uplink_watchdog_service,
        "apply_wifi_station_intent",
        _fake_apply,
    )

    from router_control.domain.network_intents import UplinkIntent, UplinkMode, WifiBand

    handle = UplinkWatchdogHandle(
        host=host,
        backup_callback_factory=lambda _rid: (lambda: None),
    )
    handle.observe_transport_factory = lambda _rid: object()
    monkeypatch.setattr(
        uplink_watchdog_service,
        "run_internet_status_observe",
        lambda *, transport: _observation(gateway_interface=None),
    )
    intent = UplinkIntent(
        mode=UplinkMode.WIFI_WAN,
        ssid=str(remembered["ssid"]),
        band=WifiBand(str(remembered["band"])),
        credential_ref_id=str(remembered["credential_ref_id"]),
    )

    class _Transport:
        wifi_station_live_dispatch = True

        def execute_sealed_rci_write(self, _request: Any) -> dict[str, Any]:
            return {}

        def execute_rci_parse(self, _cmd: str) -> dict[str, Any]:
            return {}

    handle._reapply_locked(router_id, intent, _Transport(), remembered)  # noqa: SLF001
    assert captured["intent"].credential_ref_id == cred_id
    audits = store.conn.execute(
        "SELECT action, summary_redacted FROM audit_events ORDER BY occurred_at DESC LIMIT 1"
    ).fetchone()
    assert audits is not None
    assert audits[0] == "uplink_watchdog.reapply"
    assert "password" not in (audits[1] or "").lower()


def test_password_not_persisted_in_remembered_row(tmp_path) -> None:
    conn = open_database(tmp_path / "no-password.sqlite3")
    store = PersistenceStore(conn)
    cols = {
        row[1] for row in conn.execute('PRAGMA table_info("remembered_uplink")')
    }
    assert "password" not in cols
    row = store.get_remembered_uplink()
    assert "password" not in row


def test_is_ethernet_like_gateway() -> None:
    assert is_ethernet_like_gateway("GigabitEthernet0")
    assert is_ethernet_like_gateway("Ethernet0")
    assert not is_ethernet_like_gateway("WifiMaster1/WifiStation0")
    assert not is_ethernet_like_gateway(None)


def test_is_wireguard_like_gateway() -> None:
    assert is_wireguard_like_gateway("Wireguard9")
    assert is_wireguard_like_gateway("Wireguard5")
    assert not is_wireguard_like_gateway("WifiMaster1/WifiStation0")
    assert not is_wireguard_like_gateway("GigabitEthernet0")
    assert not is_wireguard_like_gateway(None)


def test_skip_reapply_when_live_gateway_is_ethernet() -> None:
    observation = _observation(gateway_interface="GigabitEthernet0")
    assert should_reapply_uplink(
        observation=observation,
        expected_station_id="WifiMaster1/WifiStation0",
    )


@pytest.mark.asyncio
async def test_poll_once_skips_when_desired_active_without_router_id(
    tmp_path, monkeypatch
) -> None:
    runtime = create_offline_runtime(db_path=tmp_path / "poll-no-router.sqlite3")
    store = runtime.store
    site_id = store.create_site(display_name="WD", now=_FIXED_NOW)
    fallback_router_id = store.enroll_router(
        site_id=site_id,
        display_name="Fallback Router",
        vendor="Keenetic",
        model="NC-1812",
        identity_fingerprint="fp-fallback",
        host="127.0.0.2",
        now=_FIXED_NOW,
    )
    cred_id = store.insert_credential_ref(
        router_id=fallback_router_id,
        kind="WifiApPsk",
        provider="memory",
        provider_locator="wd-loc",
        now=_FIXED_NOW,
    )
    store.upsert_remembered_uplink(
        ssid="Upstream",
        band="BAND_5GHZ",
        credential_ref_id=cred_id,
        desired_active=True,
        now=_FIXED_NOW,
    )
    host = type("Host", (), {"runtime": runtime})()
    observation = _observation(gateway_interface=None)
    observe_calls = 0

    def _observe(*, transport: Any) -> InternetStatusObservation:
        nonlocal observe_calls
        observe_calls += 1
        return observation

    handle = UplinkWatchdogHandle(host=host)
    handle.observe_transport_factory = lambda _rid: object()
    handle.apply_transport_factory = lambda _rid: None
    monkeypatch.setattr(
        uplink_watchdog_service,
        "run_internet_status_observe",
        _observe,
    )
    await handle._poll_once()  # noqa: SLF001
    assert observe_calls == 0
    assert str(fallback_router_id) not in handle._states  # noqa: SLF001


@pytest.mark.asyncio
async def test_poll_once_skips_when_desired_active_false(tmp_path, monkeypatch) -> None:
    runtime = create_offline_runtime(db_path=tmp_path / "poll-inactive.sqlite3")
    host = type("Host", (), {"runtime": runtime})()
    observation = _observation(gateway_interface=None)
    observe_calls = 0

    def _observe(*, transport: Any) -> InternetStatusObservation:
        nonlocal observe_calls
        observe_calls += 1
        return observation

    handle = UplinkWatchdogHandle(host=host)
    handle.observe_transport_factory = lambda _rid: object()
    handle.apply_transport_factory = lambda _rid: None
    monkeypatch.setattr(
        uplink_watchdog_service,
        "run_internet_status_observe",
        _observe,
    )
    await handle._poll_once()  # noqa: SLF001
    assert observe_calls == 0


@pytest.mark.asyncio
async def test_poll_once_skips_apply_when_observe_read_status_failed(
    tmp_path, monkeypatch
) -> None:
    """Failed observe must not increment streak or trigger reapply."""
    stale = datetime(2026, 8, 5, 10, 0, 0, tzinfo=UTC)
    poll_now = stale + timedelta(seconds=UPLINK_WATCHDOG_POLL_SECONDS * 3)
    runtime = create_offline_runtime(
        db_path=tmp_path / "poll-observe-failed.sqlite3",
        clock=FixedClock(stale),
    )
    router_id, _remembered = _seed_remembered_active(runtime, updated_at=stale)
    host = type("Host", (), {"runtime": runtime})()
    failed_observation = InternetStatusObservation(
        internet=False,
        reliable=None,
        gateway_accessible=None,
        dns_accessible=None,
        captive_accessible=None,
        gateway_interface=None,
        gateway_ssid=None,
        checked_at="2026-08-05T12:00:00Z",
        read_status="failed",
    )
    apply_calls: list[str] = []
    handle = _make_handle(host, observation=failed_observation, apply_calls=apply_calls)
    monkeypatch.setattr(
        uplink_watchdog_service,
        "run_internet_status_observe",
        lambda *, transport: failed_observation,
    )
    monkeypatch.setattr(
        uplink_watchdog_service,
        "datetime",
        MagicMock(
            now=lambda tz=None: poll_now,
            fromisoformat=datetime.fromisoformat,
        ),
    )
    from router_control.application.uplink_watchdog_service import _RouterWatchState

    loop_now = 1000.0
    handle._states[str(router_id)] = _RouterWatchState(  # noqa: SLF001
        unhealthy_streak=1,
        backoff_seconds=120.0,
        next_poll_at=0.0,
    )

    class _FixedLoop:
        def time(self) -> float:
            return loop_now

    monkeypatch.setattr(
        uplink_watchdog_service.asyncio,
        "get_running_loop",
        lambda: _FixedLoop(),
    )
    await handle._poll_once()  # noqa: SLF001
    assert apply_calls == []
    state = handle._states[str(router_id)]  # noqa: SLF001
    assert state.unhealthy_streak == 1
    assert state.backoff_seconds == 120.0
    assert state.next_poll_at == loop_now + UPLINK_WATCHDOG_POLL_SECONDS


@pytest.mark.asyncio
async def test_poll_once_skips_when_gateway_matches_despite_internet_false(
    tmp_path, monkeypatch
) -> None:
    runtime = create_offline_runtime(db_path=tmp_path / "poll-match.sqlite3")
    router_id, _remembered = _seed_remembered_active(runtime)
    host = type("Host", (), {"runtime": runtime})()
    observation = _observation(
        gateway_interface="WifiMaster1/WifiStation0",
        internet=False,
    )
    apply_calls: list[str] = []
    handle = _make_handle(host, observation=observation, apply_calls=apply_calls)
    monkeypatch.setattr(
        uplink_watchdog_service,
        "run_internet_status_observe",
        lambda *, transport: observation,
    )
    await handle._poll_once()  # noqa: SLF001
    assert apply_calls == []
    state = handle._states[str(router_id)]  # noqa: SLF001
    assert state.unhealthy_streak == 0


@pytest.mark.asyncio
async def test_poll_once_suppresses_after_recent_updated_at(
    tmp_path, monkeypatch
) -> None:
    recent = datetime(2026, 8, 5, 12, 0, 0, tzinfo=UTC)
    runtime = create_offline_runtime(
        db_path=tmp_path / "poll-suppress.sqlite3",
        clock=FixedClock(recent),
    )
    router_id, _remembered = _seed_remembered_active(runtime, updated_at=recent)
    host = type("Host", (), {"runtime": runtime})()
    observation = _observation(gateway_interface=None)
    apply_calls: list[str] = []
    handle = _make_handle(host, observation=observation, apply_calls=apply_calls)
    monkeypatch.setattr(
        uplink_watchdog_service,
        "run_internet_status_observe",
        lambda *, transport: observation,
    )
    monkeypatch.setattr(
        uplink_watchdog_service,
        "datetime",
        MagicMock(
            now=lambda tz=None: recent + timedelta(seconds=1),
            fromisoformat=datetime.fromisoformat,
        ),
    )
    await handle._poll_once()  # noqa: SLF001
    assert apply_calls == []
    assert handle._states[str(router_id)].unhealthy_streak == 0  # noqa: SLF001


@pytest.mark.asyncio
async def test_poll_once_skips_reapply_when_gateway_is_ethernet(
    tmp_path, monkeypatch
) -> None:
    runtime = create_offline_runtime(db_path=tmp_path / "poll-ethernet.sqlite3")
    router_id, _remembered = _seed_remembered_active(runtime)
    host = type("Host", (), {"runtime": runtime})()
    observation = _observation(gateway_interface="GigabitEthernet0")
    apply_calls: list[str] = []
    handle = _make_handle(host, observation=observation, apply_calls=apply_calls)
    from router_control.application.uplink_watchdog_service import _RouterWatchState

    handle._states[str(router_id)] = _RouterWatchState(unhealthy_streak=1)  # noqa: SLF001
    monkeypatch.setattr(
        uplink_watchdog_service,
        "run_internet_status_observe",
        lambda *, transport: observation,
    )
    await handle._poll_once()  # noqa: SLF001
    assert apply_calls == []
    assert handle._states[str(router_id)].unhealthy_streak == 0  # noqa: SLF001


@pytest.mark.asyncio
async def test_poll_once_skips_reapply_when_gateway_is_wireguard(
    tmp_path, monkeypatch
) -> None:
    runtime = create_offline_runtime(db_path=tmp_path / "poll-wireguard.sqlite3")
    router_id, _remembered = _seed_remembered_active(runtime)
    host = type("Host", (), {"runtime": runtime})()
    observation = _observation(gateway_interface="Wireguard9")
    apply_calls: list[str] = []
    handle = _make_handle(host, observation=observation, apply_calls=apply_calls)
    from router_control.application.uplink_watchdog_service import _RouterWatchState

    handle._states[str(router_id)] = _RouterWatchState(unhealthy_streak=1)  # noqa: SLF001
    monkeypatch.setattr(
        uplink_watchdog_service,
        "run_internet_status_observe",
        lambda *, transport: observation,
    )
    await handle._poll_once()  # noqa: SLF001
    assert apply_calls == []
    assert handle._states[str(router_id)].unhealthy_streak == 0  # noqa: SLF001


@pytest.mark.asyncio
async def test_poll_once_skips_router_ssh_when_host_probe_reachable(
    tmp_path, monkeypatch
) -> None:
    """Cheap host-side probe says internet is fine — no router SSH round-trip."""
    runtime = create_offline_runtime(db_path=tmp_path / "poll-host-ok.sqlite3")
    router_id, _remembered = _seed_remembered_active(runtime)
    host = type("Host", (), {"runtime": runtime})()
    observation = _observation(gateway_interface=None)
    apply_calls: list[str] = []
    handle = _make_handle(host, observation=observation, apply_calls=apply_calls)
    observe_calls = 0

    def _observe(*, transport: Any) -> InternetStatusObservation:
        nonlocal observe_calls
        observe_calls += 1
        return observation

    monkeypatch.setattr(uplink_watchdog_service, "run_internet_status_observe", _observe)
    handle.host_internet_probe = lambda: True
    await handle._poll_once()  # noqa: SLF001
    assert observe_calls == 0
    assert apply_calls == []
    state = handle._states[str(router_id)]  # noqa: SLF001
    assert state.unhealthy_streak == 0


@pytest.mark.asyncio
async def test_poll_once_escalates_to_router_when_host_probe_unreachable(
    tmp_path, monkeypatch
) -> None:
    """Host-side probe says internet is down — falls through to router-side check."""
    runtime = create_offline_runtime(db_path=tmp_path / "poll-host-down.sqlite3")
    router_id, _remembered = _seed_remembered_active(runtime)
    host = type("Host", (), {"runtime": runtime})()
    observation = _observation(gateway_interface=None)
    apply_calls: list[str] = []
    handle = _make_handle(host, observation=observation, apply_calls=apply_calls)
    observe_calls = 0

    def _observe(*, transport: Any) -> InternetStatusObservation:
        nonlocal observe_calls
        observe_calls += 1
        return observation

    monkeypatch.setattr(uplink_watchdog_service, "run_internet_status_observe", _observe)
    handle.host_internet_probe = lambda: False
    await handle._poll_once()  # noqa: SLF001
    assert observe_calls == 1
    state = handle._states[str(router_id)]  # noqa: SLF001
    assert state.unhealthy_streak == 1


@pytest.mark.asyncio
async def test_poll_once_falls_back_to_router_when_host_probe_inconclusive(
    tmp_path, monkeypatch
) -> None:
    """Host-side probe returns None (inconclusive) — falls through to router-side check."""
    runtime = create_offline_runtime(db_path=tmp_path / "poll-host-none.sqlite3")
    _router_id, _remembered = _seed_remembered_active(runtime)
    host = type("Host", (), {"runtime": runtime})()
    observation = _observation(gateway_interface="WifiMaster1/WifiStation0")
    apply_calls: list[str] = []
    handle = _make_handle(host, observation=observation, apply_calls=apply_calls)
    observe_calls = 0

    def _observe(*, transport: Any) -> InternetStatusObservation:
        nonlocal observe_calls
        observe_calls += 1
        return observation

    monkeypatch.setattr(uplink_watchdog_service, "run_internet_status_observe", _observe)
    handle.host_internet_probe = lambda: None
    await handle._poll_once()  # noqa: SLF001
    assert observe_calls == 1


@pytest.mark.asyncio
async def test_poll_once_falls_back_to_router_when_host_probe_raises(
    tmp_path, monkeypatch
) -> None:
    """Host-side probe raising must fail open to the existing router-side check."""
    runtime = create_offline_runtime(db_path=tmp_path / "poll-host-raise.sqlite3")
    _router_id, _remembered = _seed_remembered_active(runtime)
    host = type("Host", (), {"runtime": runtime})()
    observation = _observation(gateway_interface="WifiMaster1/WifiStation0")
    apply_calls: list[str] = []
    handle = _make_handle(host, observation=observation, apply_calls=apply_calls)
    observe_calls = 0

    def _observe(*, transport: Any) -> InternetStatusObservation:
        nonlocal observe_calls
        observe_calls += 1
        return observation

    def _raising_probe() -> bool | None:
        raise RuntimeError("probe boom")

    monkeypatch.setattr(uplink_watchdog_service, "run_internet_status_observe", _observe)
    handle.host_internet_probe = _raising_probe
    await handle._poll_once()  # noqa: SLF001
    assert observe_calls == 1


@pytest.mark.asyncio
async def test_poll_once_uses_router_ssh_when_no_host_probe_wired(
    tmp_path, monkeypatch
) -> None:
    """Default (no host_internet_probe wired) preserves pre-existing behavior."""
    runtime = create_offline_runtime(db_path=tmp_path / "poll-no-probe.sqlite3")
    _router_id, _remembered = _seed_remembered_active(runtime)
    host = type("Host", (), {"runtime": runtime})()
    observation = _observation(gateway_interface="WifiMaster1/WifiStation0")
    apply_calls: list[str] = []
    handle = _make_handle(host, observation=observation, apply_calls=apply_calls)
    assert handle.host_internet_probe is None
    observe_calls = 0

    def _observe(*, transport: Any) -> InternetStatusObservation:
        nonlocal observe_calls
        observe_calls += 1
        return observation

    monkeypatch.setattr(uplink_watchdog_service, "run_internet_status_observe", _observe)
    await handle._poll_once()  # noqa: SLF001
    assert observe_calls == 1


@pytest.mark.asyncio
async def test_poll_once_reapplies_after_streak_threshold(
    tmp_path, monkeypatch
) -> None:
    stale = datetime(2026, 8, 5, 10, 0, 0, tzinfo=UTC)
    poll_now = stale + timedelta(seconds=UPLINK_WATCHDOG_POLL_SECONDS * 3)
    runtime = create_offline_runtime(
        db_path=tmp_path / "poll-reapply.sqlite3",
        clock=FixedClock(stale),
    )
    router_id, _remembered = _seed_remembered_active(runtime, updated_at=stale)
    host = type("Host", (), {"runtime": runtime})()
    observation = _observation(gateway_interface=None)
    apply_calls: list[str] = []
    handle = _make_handle(host, observation=observation, apply_calls=apply_calls)
    monkeypatch.setattr(
        uplink_watchdog_service,
        "run_internet_status_observe",
        lambda *, transport: observation,
    )
    monkeypatch.setattr(
        uplink_watchdog_service,
        "apply_wifi_station_intent",
        lambda **kwargs: type("R", (), {"overall": "applied", "to_dict": lambda self: {}})(),
    )
    monkeypatch.setattr(
        uplink_watchdog_service,
        "run_with_router_apply_lock",
        lambda _rid, fn: fn(),
    )
    handle.backup_callback_factory = lambda _rid: lambda: None
    monkeypatch.setattr(
        uplink_watchdog_service,
        "datetime",
        MagicMock(
            now=lambda tz=None: poll_now,
            fromisoformat=datetime.fromisoformat,
        ),
    )
    from router_control.application.uplink_watchdog_service import _RouterWatchState

    handle._states[str(router_id)] = _RouterWatchState(unhealthy_streak=1)  # noqa: SLF001
    await handle._poll_once()  # noqa: SLF001
    assert apply_calls == [str(router_id)]
    assert handle._states[str(router_id)].unhealthy_streak == 0  # noqa: SLF001


@pytest.mark.asyncio
async def test_poll_once_keeps_streak_when_apply_transport_none(
    tmp_path, monkeypatch
) -> None:
    """apply_transport None at streak threshold must not falsely clear unhealthy_streak."""
    stale = datetime(2026, 8, 5, 10, 0, 0, tzinfo=UTC)
    poll_now = stale + timedelta(seconds=UPLINK_WATCHDOG_POLL_SECONDS * 3)
    runtime = create_offline_runtime(
        db_path=tmp_path / "poll-no-transport.sqlite3",
        clock=FixedClock(stale),
    )
    router_id, _remembered = _seed_remembered_active(runtime, updated_at=stale)
    host = type("Host", (), {"runtime": runtime})()
    observation = _observation(gateway_interface=None)
    apply_calls: list[str] = []
    handle = _make_handle(host, observation=observation, apply_calls=apply_calls)
    handle.apply_transport_factory = lambda _rid: None
    monkeypatch.setattr(
        uplink_watchdog_service,
        "run_internet_status_observe",
        lambda *, transport: observation,
    )
    monkeypatch.setattr(
        uplink_watchdog_service,
        "datetime",
        MagicMock(
            now=lambda tz=None: poll_now,
            fromisoformat=datetime.fromisoformat,
        ),
    )
    from router_control.application.uplink_watchdog_service import _RouterWatchState

    handle._states[str(router_id)] = _RouterWatchState(unhealthy_streak=1)  # noqa: SLF001
    await handle._poll_once()  # noqa: SLF001
    assert apply_calls == []
    assert handle._states[str(router_id)].unhealthy_streak == 2  # noqa: SLF001


@pytest.mark.asyncio
async def test_poll_once_keeps_streak_when_reapply_fails(
    tmp_path, monkeypatch
) -> None:
    """Failed reapply must not zero unhealthy_streak as if the tunnel healed."""
    stale = datetime(2026, 8, 5, 10, 0, 0, tzinfo=UTC)
    poll_now = stale + timedelta(seconds=UPLINK_WATCHDOG_POLL_SECONDS * 3)
    runtime = create_offline_runtime(
        db_path=tmp_path / "poll-reapply-fail.sqlite3",
        clock=FixedClock(stale),
    )
    router_id, _remembered = _seed_remembered_active(runtime, updated_at=stale)
    host = type("Host", (), {"runtime": runtime})()
    observation = _observation(gateway_interface=None)
    apply_calls: list[str] = []
    handle = _make_handle(host, observation=observation, apply_calls=apply_calls)
    monkeypatch.setattr(
        uplink_watchdog_service,
        "run_internet_status_observe",
        lambda *, transport: observation,
    )
    monkeypatch.setattr(
        uplink_watchdog_service,
        "apply_wifi_station_intent",
        lambda **kwargs: type("R", (), {"overall": "failed", "to_dict": lambda self: {}})(),
    )
    monkeypatch.setattr(
        uplink_watchdog_service,
        "run_with_router_apply_lock",
        lambda _rid, fn: fn(),
    )
    handle.backup_callback_factory = lambda _rid: lambda: None
    monkeypatch.setattr(
        uplink_watchdog_service,
        "datetime",
        MagicMock(
            now=lambda tz=None: poll_now,
            fromisoformat=datetime.fromisoformat,
        ),
    )
    from router_control.application.uplink_watchdog_service import _RouterWatchState

    handle._states[str(router_id)] = _RouterWatchState(unhealthy_streak=1)  # noqa: SLF001
    await handle._poll_once()  # noqa: SLF001
    assert apply_calls == [str(router_id)]
    assert handle._states[str(router_id)].unhealthy_streak == 2  # noqa: SLF001


@pytest.mark.asyncio
async def test_poll_once_clears_streak_when_reapply_skipped(
    tmp_path, monkeypatch
) -> None:
    """Healthy under-lock skip must clear unhealthy_streak like a successful heal."""
    stale = datetime(2026, 8, 5, 10, 0, 0, tzinfo=UTC)
    poll_now = stale + timedelta(seconds=UPLINK_WATCHDOG_POLL_SECONDS * 3)
    runtime = create_offline_runtime(
        db_path=tmp_path / "poll-reapply-skipped.sqlite3",
        clock=FixedClock(stale),
    )
    router_id, _remembered = _seed_remembered_active(runtime, updated_at=stale)
    host = type("Host", (), {"runtime": runtime})()
    observation = _observation(gateway_interface=None)
    apply_calls: list[str] = []
    handle = _make_handle(host, observation=observation, apply_calls=apply_calls)
    monkeypatch.setattr(
        uplink_watchdog_service,
        "run_internet_status_observe",
        lambda *, transport: observation,
    )
    monkeypatch.setattr(
        handle,
        "_reapply_locked",
        lambda *_args, **_kwargs: "skipped",
    )
    monkeypatch.setattr(
        uplink_watchdog_service,
        "datetime",
        MagicMock(
            now=lambda tz=None: poll_now,
            fromisoformat=datetime.fromisoformat,
        ),
    )
    from router_control.application.uplink_watchdog_service import _RouterWatchState

    handle._states[str(router_id)] = _RouterWatchState(  # noqa: SLF001
        unhealthy_streak=1,
        backoff_seconds=120.0,
    )
    await handle._poll_once()  # noqa: SLF001
    state = handle._states[str(router_id)]  # noqa: SLF001
    assert state.unhealthy_streak == 0
    assert state.backoff_seconds == UPLINK_WATCHDOG_POLL_SECONDS
