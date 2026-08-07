"""Preset planner blockers."""

from __future__ import annotations

from router_control.application.preset_planner import PresetPlannerService
from router_control.domain.event_preset import ValidationStatus, build_safe_default_document
from router_control.domain.network_intents import (
    UplinkIntent,
    UplinkMode,
    parse_event_preset_document,
)


def test_plan_preview_lan_supported() -> None:
    doc = build_safe_default_document()
    planner = PresetPlannerService()
    preview = planner.build_plan_preview(
        document=doc,
        validation_status=ValidationStatus.VALID_OFFLINE,
    )
    lan = next(f for f in preview["families"] if f["family"] == "lan_zones")
    assert lan["support"] == "supported"
    assert preview["write_ready"] is False


def test_plan_certification_blockers() -> None:
    planner = PresetPlannerService()
    findings = planner.plan_blocker_findings()
    codes = {f.code for f in findings}
    assert "gate_b_write_blocked" in codes
    assert "awg_apply_deferred" in codes


def test_lte_uplink_deferred_in_plan() -> None:
    from dataclasses import replace

    doc = build_safe_default_document()
    doc_lte = replace(doc, uplink=UplinkIntent(mode=UplinkMode.LTE))
    planner = PresetPlannerService()
    preview = planner.build_plan_preview(
        document=doc_lte, validation_status=ValidationStatus.VALID_OFFLINE
    )
    uplink = next(f for f in preview["families"] if f["family"] == "uplink")
    assert uplink["support"] == "deferred"


def test_wifi_wan_uplink_unsupported_even_when_fully_specified() -> None:
    doc = build_safe_default_document().to_canonical()
    doc["uplink"] = {
        "mode": "WifiWan",
        "ssid": "Venue-Guest",
        "credential_ref_id": "credref:venue-wifi",
        "band": "BAND_2_4GHZ",
        "priority": 40,
    }
    parsed = parse_event_preset_document(doc)
    planner = PresetPlannerService()
    preview = planner.build_plan_preview(
        document=parsed,
        validation_status=ValidationStatus.VALID_OFFLINE,
    )
    uplink = next(f for f in preview["families"] if f["family"] == "uplink")
    assert uplink["support"] == "unsupported"
    assert uplink["certification_blocker"] == "wifi_wan_not_certified"


def test_wifi_preview_includes_wpa_mode_and_band() -> None:
    doc = build_safe_default_document()
    planner = PresetPlannerService()
    preview = planner.build_plan_preview(
        document=doc,
        validation_status=ValidationStatus.VALID_OFFLINE,
    )
    wifi = next(f for f in preview["families"] if f["family"] == "wifi")
    promo = next(i for i in wifi["items"] if i["zone_id"] == "Promo")
    assert promo["wpa_mode"] == "WPA2"
    assert promo["band"] == "BAND_2_4GHZ"
