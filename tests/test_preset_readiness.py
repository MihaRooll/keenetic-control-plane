"""Preset readiness integration."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from router_control.application.preset_readiness import PresetReadinessService
from router_control.composition import create_offline_runtime

FIXED = datetime(2026, 7, 22, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def runtime(tmp_path: Path):
    from router_control.composition import FixedClock

    return create_offline_runtime(db_path=tmp_path / "ready.sqlite3", clock=FixedClock(FIXED))


def test_readiness_report_valid_offline(runtime) -> None:
    site_id = runtime.store.create_site(display_name="Lab", now=FIXED)
    svc = runtime.event_presets
    preset, _, _ = svc.create_preset(
        site_id=site_id,
        name="Booth",
        document=None,
        idempotency_key="k1",
        request_digest="sha256:req",
    )
    report = svc.readiness_report(preset["preset_id"])
    assert report["valid_offline"] is True
    assert report["write_ready"] is False
    assert report["ready_for_read_only_assessment"] is True


def test_commissioning_summary_read_only(runtime) -> None:
    site_id = runtime.store.create_site(display_name="Lab", now=FIXED)
    readiness = PresetReadinessService(store=runtime.store, planner=runtime.preset_planner)
    report = readiness.build_readiness_report(
        preset_id=runtime.event_presets.create_preset(
            site_id=site_id,
            name="Booth",
            document=None,
            idempotency_key="k2",
            request_digest="sha256:req2",
        )[0]["preset_id"]
    )
    assert report["commissioning_summary"] is None


def test_wpa3_readiness_no_device_verified_warning(runtime) -> None:
    from router_control.domain.event_preset import build_safe_default_document

    site_id = runtime.store.create_site(display_name="Lab", now=FIXED)
    doc = build_safe_default_document().to_canonical()
    staff = next(z for z in doc["zones"] if z["zone_id"] == "Staff")
    staff["wifi"]["wpa_mode"] = "WPA3"
    preset, _, _ = runtime.event_presets.create_preset(
        site_id=site_id,
        name="WPA3-doc",
        document=doc,
        idempotency_key="k3",
        request_digest="sha256:req3",
    )
    readiness = PresetReadinessService(store=runtime.store, planner=runtime.preset_planner)
    report = readiness.build_readiness_report(preset_id=preset["preset_id"])
    codes = {f["code"] for f in report["findings"]}
    assert "wifi_wpa_mode_not_device_verified" not in codes
    assert report["valid_offline"] is True


def test_wpa2_wpa3_mixed_readiness_no_device_verified_warning(runtime) -> None:
    from router_control.domain.event_preset import build_safe_default_document

    site_id = runtime.store.create_site(display_name="Lab", now=FIXED)
    doc = build_safe_default_document().to_canonical()
    staff = next(z for z in doc["zones"] if z["zone_id"] == "Staff")
    staff["wifi"]["wpa_mode"] = "WPA2_WPA3_MIXED"
    preset, _, _ = runtime.event_presets.create_preset(
        site_id=site_id,
        name="WPA2-WPA3-MIXED-doc",
        document=doc,
        idempotency_key="k3-mixed",
        request_digest="sha256:req3-mixed",
    )
    readiness = PresetReadinessService(store=runtime.store, planner=runtime.preset_planner)
    report = readiness.build_readiness_report(preset_id=preset["preset_id"])
    codes = {f["code"] for f in report["findings"]}
    assert "wifi_wpa_mode_not_device_verified" not in codes
    assert report["valid_offline"] is True


def test_wifi_wan_uplink_still_not_certified_in_readiness(runtime) -> None:
    from router_control.domain.event_preset import ValidationStatus, build_safe_default_document
    from router_control.domain.network_intents import parse_event_preset_document

    site_id = runtime.store.create_site(display_name="Lab", now=FIXED)
    doc = build_safe_default_document().to_canonical()
    doc["uplink"] = {
        "mode": "WifiWan",
        "ssid": "Venue-Guest",
        "credential_ref_id": "credref:venue-wifi",
        "band": "BAND_2_4GHZ",
    }
    parsed = parse_event_preset_document(doc)
    preset, _, _ = runtime.event_presets.create_preset(
        site_id=site_id,
        name="WifiWan-doc",
        document=doc,
        idempotency_key="k-wifiwan",
        request_digest="sha256:wifiwan",
    )
    readiness = PresetReadinessService(store=runtime.store, planner=runtime.preset_planner)
    report = readiness.build_readiness_report(preset_id=preset["preset_id"])
    preview = runtime.preset_planner.build_plan_preview(
        document=parsed,
        validation_status=ValidationStatus(report["validation_status"]),
    )
    uplink = next(f for f in preview["families"] if f["family"] == "uplink")
    assert uplink["support"] == "unsupported"
    assert uplink["certification_blocker"] == "wifi_wan_not_certified"
