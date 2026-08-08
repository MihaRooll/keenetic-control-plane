"""Uplink watchdog under-lock remembered re-read / fail-closed tests."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import pytest
from router_control.application import uplink_watchdog_service
from router_control.application.internet_status_observe import InternetStatusObservation
from router_control.application.remembered_uplink import RememberedUplinkService
from router_control.application.uplink_watchdog_service import UplinkWatchdogHandle
from router_control.composition import create_offline_runtime
from router_control.domain.network_intents import UplinkIntent, UplinkMode, WifiBand


def _setup_watchdog(
    tmp_path: Any,
) -> tuple[UplinkWatchdogHandle, str, UplinkIntent, dict[str, Any], RememberedUplinkService, Any]:
    runtime = create_offline_runtime(db_path=tmp_path / "uplink-wd-reread.sqlite3")
    store = runtime.store
    site_id = store.create_site(display_name="WD", now=datetime(2026, 8, 8, tzinfo=UTC))
    router_id = store.enroll_router(
        site_id=site_id,
        display_name="WD Router",
        vendor="Keenetic",
        model="NC-1812",
        identity_fingerprint="fp-uplink-wd-reread",
        host="127.0.0.1",
        now=datetime(2026, 8, 8, tzinfo=UTC),
    )
    cred_id = store.insert_credential_ref(
        router_id=router_id,
        kind="WifiApPsk",
        provider="memory",
        provider_locator="wd-reread-loc",
        now=datetime(2026, 8, 8, tzinfo=UTC),
    )
    remembered_svc = RememberedUplinkService(store=store, clock=runtime.clock)
    remembered = remembered_svc.update_remembered(
        router_id=router_id,
        ssid="Upstream",
        band="BAND_5GHZ",
        credential_ref_id=cred_id,
        desired_active=True,
    )
    host = type("Host", (), {"runtime": runtime})()
    handle = UplinkWatchdogHandle(host=host)
    intent = UplinkIntent(
        mode=UplinkMode.WIFI_WAN,
        ssid=str(remembered["ssid"]),
        band=WifiBand(str(remembered["band"])),
        credential_ref_id=str(remembered["credential_ref_id"]),
    )
    return handle, router_id, intent, remembered, remembered_svc, store


class _Transport:
    wifi_station_live_dispatch = True

    def execute_sealed_rci_write(self, _request: Any) -> dict[str, Any]:
        return {}

    def execute_rci_parse(self, _cmd: str) -> dict[str, Any]:
        return {}


class _ObserveTransport:
    pass


def _observation(*, gateway_interface: str | None) -> InternetStatusObservation:
    return InternetStatusObservation(
        internet=False,
        reliable=None,
        gateway_accessible=None,
        dns_accessible=None,
        captive_accessible=None,
        gateway_interface=gateway_interface,
        gateway_ssid=None,
        checked_at="2026-08-08T12:00:00Z",
        read_status="ok",
    )


def _wire_observe_factory(
    handle: UplinkWatchdogHandle,
    monkeypatch: pytest.MonkeyPatch,
    *,
    gateway_interface: str | None = "WifiMaster1/WifiStation0",
) -> None:
    handle.observe_transport_factory = lambda _rid: _ObserveTransport()
    monkeypatch.setattr(
        uplink_watchdog_service,
        "run_internet_status_observe",
        lambda *, transport: _observation(gateway_interface=gateway_interface),
    )


def _latest_reapply_audit(store: Any) -> tuple[str, str, str]:
    audit = store.conn.execute(
        "SELECT action, outcome, summary_redacted FROM audit_events "
        "ORDER BY occurred_at DESC LIMIT 1"
    ).fetchone()
    assert audit is not None
    return audit[0], audit[1], audit[2] or ""


def _run_reapply_under_lock(
    *,
    handle: UplinkWatchdogHandle,
    router_id: str,
    intent: UplinkIntent,
    remembered: dict[str, Any],
    store: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[bool, str]:
    apply_called = False

    def _fake_apply(**_kwargs: Any) -> Any:
        nonlocal apply_called
        apply_called = True
        raise AssertionError("apply must not run under lock abort path")

    handle.backup_callback_factory = lambda _rid: lambda: None
    monkeypatch.setattr(uplink_watchdog_service, "apply_wifi_station_intent", _fake_apply)
    handle._reapply_locked(router_id, intent, _Transport(), remembered)  # noqa: SLF001
    action, outcome, summary = _latest_reapply_audit(store)
    assert action == "uplink_watchdog.reapply"
    assert outcome == "failed"
    return apply_called, summary


def test_reapply_aborts_when_desired_cleared_before_lock(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Watchdog reapply must not apply when desired_active cleared under lock."""
    handle, router_id, intent, remembered, remembered_svc, store = _setup_watchdog(tmp_path)
    remembered_svc.update_remembered(desired_active=False)
    apply_called, summary = _run_reapply_under_lock(
        handle=handle,
        router_id=router_id,
        intent=intent,
        remembered=remembered,
        store=store,
        monkeypatch=monkeypatch,
    )
    assert apply_called is False
    assert "desired cleared under lock" in summary


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(
            lambda remembered_svc, store, router_id, _cred_id: remembered_svc.update_remembered(
                ssid="DifferentUpstream"
            ),
            id="ssid",
        ),
        pytest.param(
            lambda remembered_svc, store, router_id, _cred_id: remembered_svc.update_remembered(
                band="BAND_2_4GHZ"
            ),
            id="band",
        ),
        pytest.param(
            lambda remembered_svc, store, router_id, _cred_id: remembered_svc.update_remembered(
                credential_ref_id=store.insert_credential_ref(
                    router_id=router_id,
                    kind="WifiApPsk",
                    provider="memory",
                    provider_locator="wd-reread-alt-loc",
                    now=datetime(2026, 8, 8, tzinfo=UTC),
                )
            ),
            id="credential_ref_id",
        ),
    ],
)
def test_reapply_aborts_when_identity_changed_before_lock(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
    mutate: Callable[[RememberedUplinkService, Any, str, str], None],
) -> None:
    """Watchdog reapply must not apply when remembered identity drifted under lock."""
    handle, router_id, intent, remembered, remembered_svc, store = _setup_watchdog(tmp_path)
    cred_id = str(remembered["credential_ref_id"])
    mutate(remembered_svc, store, router_id, cred_id)
    apply_called, summary = _run_reapply_under_lock(
        handle=handle,
        router_id=router_id,
        intent=intent,
        remembered=remembered,
        store=store,
        monkeypatch=monkeypatch,
    )
    assert apply_called is False
    assert "identity changed under lock" in summary


def test_reapply_applies_with_fresh_remembered_intent(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Happy path rebuilds UplinkIntent from fresh remembered row, not stale outer intent."""
    handle, router_id, _intent, remembered, _remembered_svc, store = _setup_watchdog(tmp_path)
    stale_intent = UplinkIntent(
        mode=UplinkMode.WIFI_WAN,
        ssid="StaleSSID",
        band=WifiBand.BAND_2_4GHZ,
        credential_ref_id="stale-cred-ref",
    )
    captured: dict[str, Any] = {}

    def _fake_apply(**kwargs: Any) -> Any:
        captured["intent"] = kwargs.get("intent")
        from router_control.application.wifi_station_apply_service import WifiStationApplyResult

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

    handle.backup_callback_factory = lambda _rid: lambda: None
    _wire_observe_factory(handle, monkeypatch)
    monkeypatch.setattr(uplink_watchdog_service, "apply_wifi_station_intent", _fake_apply)
    handle._reapply_locked(router_id, stale_intent, _Transport(), remembered)  # noqa: SLF001
    assert captured["intent"] is not None
    assert captured["intent"].ssid == remembered["ssid"]
    assert captured["intent"].band == WifiBand(str(remembered["band"]))
    assert captured["intent"].credential_ref_id == remembered["credential_ref_id"]
    audit = store.conn.execute(
        "SELECT action, outcome FROM audit_events ORDER BY occurred_at DESC LIMIT 1"
    ).fetchone()
    assert audit is not None
    assert audit[0] == "uplink_watchdog.reapply"
    assert audit[1] == "applied"


def test_reapply_aborts_when_gateway_wireguard_under_lock(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Under-lock re-observe must skip apply when gateway is WireGuard."""
    handle, router_id, intent, remembered, _remembered_svc, store = _setup_watchdog(tmp_path)
    apply_called = False

    def _fake_apply(**_kwargs: Any) -> Any:
        nonlocal apply_called
        apply_called = True
        raise AssertionError("apply must not run when gateway is WireGuard under lock")

    handle.backup_callback_factory = lambda _rid: lambda: None
    _wire_observe_factory(handle, monkeypatch, gateway_interface="Wireguard9")
    monkeypatch.setattr(uplink_watchdog_service, "apply_wifi_station_intent", _fake_apply)
    handle._reapply_locked(router_id, intent, _Transport(), remembered)  # noqa: SLF001
    assert apply_called is False
    action, outcome, summary = _latest_reapply_audit(store)
    assert action == "uplink_watchdog.reapply"
    assert outcome == "failed"
    assert "gateway is WireGuard under lock" in summary


def test_reapply_aborts_when_gateway_ethernet_under_lock(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Under-lock re-observe must skip apply when gateway is ethernet."""
    handle, router_id, intent, remembered, _remembered_svc, store = _setup_watchdog(tmp_path)
    apply_called = False

    def _fake_apply(**_kwargs: Any) -> Any:
        nonlocal apply_called
        apply_called = True
        raise AssertionError("apply must not run when gateway is ethernet under lock")

    handle.backup_callback_factory = lambda _rid: lambda: None
    _wire_observe_factory(handle, monkeypatch, gateway_interface="GigabitEthernet0")
    monkeypatch.setattr(uplink_watchdog_service, "apply_wifi_station_intent", _fake_apply)
    handle._reapply_locked(router_id, intent, _Transport(), remembered)  # noqa: SLF001
    assert apply_called is False
    action, outcome, summary = _latest_reapply_audit(store)
    assert action == "uplink_watchdog.reapply"
    assert outcome == "failed"
    assert "gateway is ethernet under lock" in summary


def test_reapply_aborts_when_gateway_observe_failed_under_lock(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Under-lock re-observe must skip apply when transport observe returns failed."""
    handle, router_id, intent, remembered, _remembered_svc, store = _setup_watchdog(tmp_path)
    apply_called = False

    def _fake_apply(**_kwargs: Any) -> Any:
        nonlocal apply_called
        apply_called = True
        raise AssertionError("apply must not run when gateway observe failed under lock")

    handle.backup_callback_factory = lambda _rid: lambda: None
    handle.observe_transport_factory = lambda _rid: _ObserveTransport()
    monkeypatch.setattr(
        uplink_watchdog_service,
        "run_internet_status_observe",
        lambda *, transport: InternetStatusObservation(
            internet=None,
            reliable=None,
            gateway_accessible=None,
            dns_accessible=None,
            captive_accessible=None,
            gateway_interface=None,
            gateway_ssid=None,
            checked_at=None,
            read_status="failed",
        ),
    )
    monkeypatch.setattr(uplink_watchdog_service, "apply_wifi_station_intent", _fake_apply)
    handle._reapply_locked(router_id, intent, _Transport(), remembered)  # noqa: SLF001
    assert apply_called is False
    action, outcome, summary = _latest_reapply_audit(store)
    assert action == "uplink_watchdog.reapply"
    assert outcome == "failed"
    assert "gateway observe failed under lock" in summary


@pytest.mark.parametrize(
    "observe_factory",
    [
        pytest.param(None, id="factory_none"),
        pytest.param(lambda _rid: None, id="transport_none"),
    ],
)
def test_reapply_aborts_when_observe_transport_unavailable(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
    observe_factory: Callable[[str], Any] | None,
) -> None:
    """Under-lock re-observe must fail-closed when observe transport is unavailable."""
    handle, router_id, intent, remembered, _remembered_svc, store = _setup_watchdog(tmp_path)
    apply_called = False

    def _fake_apply(**_kwargs: Any) -> Any:
        nonlocal apply_called
        apply_called = True
        raise AssertionError("apply must not run when observe transport unavailable")

    handle.observe_transport_factory = observe_factory
    handle.backup_callback_factory = lambda _rid: lambda: None
    monkeypatch.setattr(uplink_watchdog_service, "apply_wifi_station_intent", _fake_apply)
    handle._reapply_locked(router_id, intent, _Transport(), remembered)  # noqa: SLF001
    assert apply_called is False
    action, outcome, summary = _latest_reapply_audit(store)
    assert action == "uplink_watchdog.reapply"
    assert outcome == "failed"
    assert "observe transport unavailable under lock" in summary
