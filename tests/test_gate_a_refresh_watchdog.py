"""Offline tests for Gate A certification refresh watchdog."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
import router_control.application.gate_a_refresh_watchdog as gate_a_refresh_watchdog
from router_control.adapters.netcraze.certification import GateACertification
from router_control.application.gate_a_refresh_watchdog import GateARefreshWatchdogHandle

from tests.test_gate_a_certification import (
    COMPONENT_DIGEST,
    FINGERPRINT_DIGEST,
    SSH_HOST_KEY_ALGORITHM,
    SSH_HOST_KEY_FINGERPRINT_SHA256,
)


def _make_cert(*, recorded_at: datetime | None = None) -> GateACertification:
    recorded = recorded_at or datetime(2026, 7, 21, 17, 15, 29, 318950, tzinfo=UTC)
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
        component_set_digest=COMPONENT_DIGEST,
        device_fingerprint_digest=FINGERPRINT_DIGEST,
        physical_id_source="show.identification_digest",
        transport="ssh_tunnel",
        ssh_host_key_algorithm=SSH_HOST_KEY_ALGORITHM,
        ssh_host_key_fingerprint_sha256=SSH_HOST_KEY_FINGERPRINT_SHA256,
        certification_eligible=True,
        evidence_recorded_at=recorded,
        evidence_path="ignored-evidence.json",
        expires_at=recorded + timedelta(days=90),
        revocation_policy="test",
        opening_freshness_hours=24,
    )


def _fake_host(cert: GateACertification | None = None) -> SimpleNamespace:
    return SimpleNamespace(gate_a_certification=cert)


def test_disabled_watchdog_never_starts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gate_a_refresh_watchdog, "GATE_A_REFRESH_WATCHDOG_ENABLED", False)
    host = _fake_host(_make_cert())
    handle = GateARefreshWatchdogHandle(host)
    handle.start()
    assert handle._task is None  # noqa: SLF001


@pytest.mark.asyncio
async def test_poll_once_updates_host_certification() -> None:
    old_cert = _make_cert(
        recorded_at=datetime(2026, 7, 20, 12, 0, 0, tzinfo=UTC),
    )
    new_cert = _make_cert(
        recorded_at=datetime(2026, 7, 21, 17, 15, 29, tzinfo=UTC),
    )
    host = _fake_host(old_cert)
    handle = GateARefreshWatchdogHandle(host, loader=lambda: new_cert)
    await handle._poll_once()  # noqa: SLF001
    assert host.gate_a_certification is new_cert
    assert host.gate_a_certification is not old_cert


@pytest.mark.asyncio
async def test_poll_once_leaves_cert_unchanged_when_loader_returns_none() -> None:
    original = _make_cert()
    host = _fake_host(original)
    handle = GateARefreshWatchdogHandle(host, loader=lambda: None)
    await handle._poll_once()  # noqa: SLF001
    assert host.gate_a_certification is original


@pytest.mark.asyncio
async def test_poll_once_leaves_cert_unchanged_when_loader_raises() -> None:
    original = _make_cert()
    host = _fake_host(original)

    def _broken_loader() -> GateACertification | None:
        raise RuntimeError("disk hiccup")

    handle = GateARefreshWatchdogHandle(host, loader=_broken_loader)
    await handle._poll_once()  # noqa: SLF001
    assert host.gate_a_certification is original


@pytest.mark.asyncio
async def test_run_loop_reloads_and_stops_cleanly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gate_a_refresh_watchdog, "GATE_A_REFRESH_WATCHDOG_ENABLED", True)
    old_cert = _make_cert(
        recorded_at=datetime(2026, 7, 20, 12, 0, 0, tzinfo=UTC),
    )
    new_cert = _make_cert(
        recorded_at=datetime(2026, 7, 21, 18, 0, 0, tzinfo=UTC),
    )
    host = _fake_host(old_cert)
    handle = GateARefreshWatchdogHandle(
        host,
        loader=lambda: new_cert,
        poll_seconds=0.05,
    )
    handle.start()
    assert handle._task is not None  # noqa: SLF001
    await asyncio.sleep(0.2)
    assert host.gate_a_certification is new_cert
    await handle.stop()
    assert handle._task is None  # noqa: SLF001


def test_fake_mode_app_does_not_start_gate_a_refresh_watchdog(tmp_path) -> None:
    from fastapi.testclient import TestClient
    from router_control_host.app import create_app

    db_path = tmp_path / "fake.sqlite3"
    app = create_app(db_path=db_path, adapter_mode="fake", enable_worker=False)
    with TestClient(app) as client:
        host = client.app.state.host
        assert host.adapter_mode == "fake"
        assert host.gate_a_refresh_watchdog is None


def test_import_create_app_still_works(tmp_path) -> None:
    import router_control_host.app as app_module

    assert hasattr(app_module, "create_app")
    app = app_module.create_app(
        db_path=tmp_path / "fake.sqlite3",
        adapter_mode="fake",
        enable_worker=False,
    )
    assert app.state.host.gate_a_refresh_watchdog is None
