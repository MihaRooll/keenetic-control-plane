"""Uplink watchdog reapply startup-config backup parity tests."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock

import pytest
from router_control.adapters.netcraze.certification import GateACertification
from router_control.adapters.netcraze.startup_backup import StartupBackupError
from router_control.application import uplink_watchdog_service
from router_control.application.remembered_uplink import RememberedUplinkService
from router_control.application.uplink_watchdog_service import UplinkWatchdogHandle
from router_control.composition import create_offline_runtime
from router_control.domain.network_intents import UplinkIntent, UplinkMode, WifiBand
from router_control_host.state import HostState
from router_control_host.wifi_live_transport import WifiLiveSession
from router_control_host.wifi_station_apply_routes import (
    build_uplink_watchdog_backup_callback_factory,
)

from tests.test_uplink_watchdog_reapply_reread import _wire_observe_factory

_COMPONENT_DIGEST = "a" * 64
_FINGERPRINT_DIGEST = "b" * 64
_VALID_SSH_HOST_KEY_SHA256 = "SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM"


def _setup_watchdog(
    tmp_path: Any,
) -> tuple[UplinkWatchdogHandle, str, UplinkIntent, dict[str, Any], Any]:
    runtime = create_offline_runtime(db_path=tmp_path / "uplink-wd-backup.sqlite3")
    store = runtime.store
    site_id = store.create_site(display_name="WD", now=datetime(2026, 8, 8, tzinfo=UTC))
    router_id = store.enroll_router(
        site_id=site_id,
        display_name="WD Router",
        vendor="Keenetic",
        model="NC-1812",
        identity_fingerprint="fp-uplink-wd",
        host="127.0.0.1",
        now=datetime(2026, 8, 8, tzinfo=UTC),
    )
    cred_id = store.insert_credential_ref(
        router_id=router_id,
        kind="WifiApPsk",
        provider="memory",
        provider_locator="wd-loc",
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
    return handle, router_id, intent, remembered, store


class _Transport:
    wifi_station_live_dispatch = True

    def execute_sealed_rci_write(self, _request: Any) -> dict[str, Any]:
        return {}

    def execute_rci_parse(self, _cmd: str) -> dict[str, Any]:
        return {}


def test_reapply_passes_backup_callback_and_invokes_before_apply(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handle, router_id, intent, remembered, _store = _setup_watchdog(tmp_path)
    order: list[str] = []
    captured: dict[str, Any] = {}

    def backup_cb() -> None:
        order.append("backup")

    handle.backup_callback_factory = lambda _rid: backup_cb
    _wire_observe_factory(handle, monkeypatch)

    def _fake_apply(**kwargs: Any) -> Any:
        captured["backup_callback"] = kwargs.get("backup_callback")
        if captured["backup_callback"] is not None:
            captured["backup_callback"]()
        order.append("apply")
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

    monkeypatch.setattr(uplink_watchdog_service, "apply_wifi_station_intent", _fake_apply)
    handle._reapply_locked(router_id, intent, _Transport(), remembered)  # noqa: SLF001
    assert captured["backup_callback"] is backup_cb
    assert order == ["backup", "apply"]


def test_reapply_fail_closed_when_backup_factory_returns_none(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handle, router_id, intent, remembered, store = _setup_watchdog(tmp_path)
    apply_called = False

    def _fake_apply(**_kwargs: Any) -> Any:
        nonlocal apply_called
        apply_called = True
        raise AssertionError("apply must not run without backup")

    handle.backup_callback_factory = lambda _rid: None
    _wire_observe_factory(handle, monkeypatch)
    monkeypatch.setattr(uplink_watchdog_service, "apply_wifi_station_intent", _fake_apply)
    handle._reapply_locked(router_id, intent, _Transport(), remembered)  # noqa: SLF001
    assert apply_called is False
    audit = store.conn.execute(
        "SELECT action, outcome, summary_redacted FROM audit_events "
        "ORDER BY occurred_at DESC LIMIT 1"
    ).fetchone()
    assert audit is not None
    assert audit[0] == "uplink_watchdog.reapply"
    assert audit[1] == "failed"
    assert "startup-config backup unavailable" in (audit[2] or "")


def test_reapply_fail_closed_when_backup_factory_missing(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handle, router_id, intent, remembered, store = _setup_watchdog(tmp_path)
    apply_called = False

    def _fake_apply(**_kwargs: Any) -> Any:
        nonlocal apply_called
        apply_called = True
        raise AssertionError("apply must not run without backup factory")

    _wire_observe_factory(handle, monkeypatch)
    monkeypatch.setattr(uplink_watchdog_service, "apply_wifi_station_intent", _fake_apply)
    handle._reapply_locked(router_id, intent, _Transport(), remembered)  # noqa: SLF001
    assert apply_called is False
    audit = store.conn.execute(
        "SELECT action, outcome, summary_redacted FROM audit_events "
        "ORDER BY occurred_at DESC LIMIT 1"
    ).fetchone()
    assert audit[1] == "failed"
    assert "startup-config backup unavailable" in (audit[2] or "")


def test_reapply_startup_backup_error_audited_without_success(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handle, router_id, intent, remembered, store = _setup_watchdog(tmp_path)

    def backup_cb() -> None:
        raise StartupBackupError("backup vault unavailable")

    handle.backup_callback_factory = lambda _rid: backup_cb
    _wire_observe_factory(handle, monkeypatch)

    def _fake_apply(**kwargs: Any) -> Any:
        callback = kwargs.get("backup_callback")
        assert callback is not None
        callback()
        raise AssertionError("apply must abort when backup raises")

    monkeypatch.setattr(uplink_watchdog_service, "apply_wifi_station_intent", _fake_apply)
    handle._reapply_locked(router_id, intent, _Transport(), remembered)  # noqa: SLF001
    audit = store.conn.execute(
        "SELECT action, outcome, summary_redacted FROM audit_events "
        "ORDER BY occurred_at DESC LIMIT 1"
    ).fetchone()
    assert audit is not None
    assert audit[0] == "uplink_watchdog.reapply"
    assert audit[1] == "failed"
    assert "startup-config backup unavailable" in (audit[2] or "")
    assert "password" not in (audit[2] or "").lower()


def _open_gate_a(*, evidence_path: str = "data/artifacts/gate-a-probe.json") -> GateACertification:
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
        evidence_path=evidence_path,
        expires_at=now + timedelta(days=90),
        revocation_policy="human",
        gates_b_closed=True,
        gates_c_closed=True,
        gates_d_closed=True,
    )


def _live_host(tmp_path: Any) -> tuple[HostState, str]:
    runtime = create_offline_runtime(db_path=tmp_path / "uplink-wd-factory.sqlite3")
    store = runtime.store
    now = datetime(2026, 8, 8, tzinfo=UTC)
    site_id = store.create_site(display_name="Uplink WD Factory", now=now)
    router_id = store.enroll_router(
        site_id=site_id,
        display_name="Uplink WD Factory Router",
        vendor="Keenetic",
        model="NC-1812",
        identity_fingerprint="fp-uplink-wd-factory",
        host="192.168.2.1",
        source_address="192.168.2.10",
        now=now,
    )
    cred_id = store.insert_credential_ref(
        router_id=router_id,
        kind="WifiApPsk",
        provider="memory",
        provider_locator="uplink-wd-factory-loc",
        now=now,
    )
    store.set_router_credential_ref(router_id, cred_id, now=now)
    store.set_endpoint_ssh_host_key(
        router_id,
        _VALID_SSH_HOST_KEY_SHA256,
        "ssh-ed25519",
        "operator_supplied",
        pinned_at=now.isoformat(),
    )
    host = HostState(
        runtime=runtime,
        adapter_mode="live",
        gate_a_certification=_open_gate_a(),
    )
    return host, router_id


def _patch_live_backup_mocks(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    captured: dict[str, Any] = {}

    @contextmanager
    def _mock_live(**_kwargs: object):
        tunnel = MagicMock()
        yield WifiLiveSession(transport=MagicMock(), tunnel=tunnel)

    def _mock_backup(**kwargs: Any) -> None:
        captured["certification"] = kwargs.get("certification")

    monkeypatch.setattr(
        "router_control_host.wifi_station_apply_routes.open_wifi_live_session",
        _mock_live,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_station_apply_routes.ensure_live_gate_a_tuple_match",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_station_apply_routes.backup_startup_config",
        _mock_backup,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_station_apply_routes.is_win32_live_capable",
        lambda: True,
    )
    return captured


def test_backup_callback_factory_live_uses_current_gate_a_cert(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host, router_id = _live_host(tmp_path)
    captured = _patch_live_backup_mocks(monkeypatch)
    factory = build_uplink_watchdog_backup_callback_factory(host)
    assert factory is not None
    callback = factory(router_id)
    assert callback is not None
    callback()
    assert captured["certification"] is host.gate_a_certification


def test_backup_callback_factory_live_rereads_cert_after_refresh(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host, router_id = _live_host(tmp_path)
    captured = _patch_live_backup_mocks(monkeypatch)
    factory = build_uplink_watchdog_backup_callback_factory(host)
    assert factory is not None
    callback = factory(router_id)
    assert callback is not None
    original_cert = host.gate_a_certification
    refreshed_cert = _open_gate_a(evidence_path="data/artifacts/gate-a-refreshed.json")
    host.gate_a_certification = refreshed_cert
    callback()
    assert captured["certification"] is refreshed_cert
    assert captured["certification"] is not original_cert


def test_backup_callback_factory_live_raises_when_gate_a_closed(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host, router_id = _live_host(tmp_path)
    _patch_live_backup_mocks(monkeypatch)
    factory = build_uplink_watchdog_backup_callback_factory(host)
    assert factory is not None
    callback = factory(router_id)
    assert callback is not None
    host.gate_a_certification = None
    with pytest.raises(StartupBackupError, match="Gate A certification required"):
        callback()


def test_backup_callback_factory_injected_returns_noop(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host, router_id = _live_host(tmp_path)
    host.wifi_station_apply_transport_factory = lambda: _Transport()
    backup_called = False

    def _fail_backup(**_kwargs: Any) -> None:
        nonlocal backup_called
        backup_called = True

    monkeypatch.setattr(
        "router_control_host.wifi_station_apply_routes.backup_startup_config",
        _fail_backup,
    )
    factory = build_uplink_watchdog_backup_callback_factory(host)
    assert factory is not None
    callback = factory(router_id)
    assert callback is not None
    callback()
    assert backup_called is False


def test_backup_callback_factory_fake_returns_noop(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host, router_id = _live_host(tmp_path)
    host.adapter_mode = "fake"
    host.allow_fake_mutations = True
    backup_called = False

    def _fail_backup(**_kwargs: Any) -> None:
        nonlocal backup_called
        backup_called = True

    monkeypatch.setattr(
        "router_control_host.wifi_station_apply_routes.backup_startup_config",
        _fail_backup,
    )
    factory = build_uplink_watchdog_backup_callback_factory(host)
    assert factory is not None
    callback = factory(router_id)
    assert callback is not None
    callback()
    assert backup_called is False
