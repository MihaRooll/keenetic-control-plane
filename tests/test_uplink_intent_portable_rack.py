"""Portable rack / WifiWan uplink intent — offline validation and planner blockers."""

from __future__ import annotations

import pytest
from router_control.application.preset_planner import PresetPlannerService
from router_control.domain.event_preset import (
    ValidationStatus,
    build_safe_default_document,
    validate_document,
)
from router_control.domain.network_intents import (
    BlockingFor,
    IntentValidationError,
    UplinkIntent,
    UplinkMode,
    WifiBand,
    parse_event_preset_document,
    uplink_preference_key,
)


def _wifi_wan_uplink(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "mode": "WifiWan",
        "ssid": "Venue-Guest",
        "credential_ref_id": "credref:venue-wifi",
    }
    base.update(overrides)
    return base


def test_ethernet_uplink_backward_compatible() -> None:
    doc = build_safe_default_document()
    assert doc.uplink.to_canonical() == {"mode": "Ethernet"}
    assert doc.uplink.priority == 100
    assert doc.uplink.captive_portal_client is False


def test_parse_wifi_wan_requires_ssid_and_credential() -> None:
    doc = build_safe_default_document().to_canonical()
    doc["uplink"] = {"mode": "WifiWan"}
    with pytest.raises(IntentValidationError, match="ssid"):
        parse_event_preset_document(doc)
    doc["uplink"] = {"mode": "WifiWan", "ssid": "Venue-Guest"}
    with pytest.raises(IntentValidationError, match="credential_ref_id"):
        parse_event_preset_document(doc)


def test_parse_wifi_wan_ok_with_defaults() -> None:
    doc = build_safe_default_document().to_canonical()
    doc["uplink"] = _wifi_wan_uplink()
    parsed = parse_event_preset_document(doc)
    assert parsed.uplink.mode is UplinkMode.WIFI_WAN
    assert parsed.uplink.ssid == "Venue-Guest"
    assert parsed.uplink.band is WifiBand.BAND_2_4GHZ
    assert parsed.uplink.credential_ref_id == "credref:venue-wifi"
    assert parsed.uplink.priority == 100


def test_parse_wifi_wan_invalid_ssid_rejected() -> None:
    doc = build_safe_default_document().to_canonical()
    doc["uplink"] = _wifi_wan_uplink(ssid="")
    with pytest.raises(IntentValidationError, match="invalid_ssid|ssid"):
        parse_event_preset_document(doc)


def test_parse_wifi_wan_malformed_bssid_rejected() -> None:
    doc = build_safe_default_document().to_canonical()
    doc["uplink"] = _wifi_wan_uplink(bssid="not-a-mac")
    with pytest.raises(IntentValidationError, match="invalid_bssid|mac"):
        parse_event_preset_document(doc)


def test_parse_wifi_wan_accepts_synthetic_bssid() -> None:
    doc = build_safe_default_document().to_canonical()
    doc["uplink"] = _wifi_wan_uplink(bssid="02:00:00:00:00:01")
    parsed = parse_event_preset_document(doc)
    assert parsed.uplink.bssid == "02:00:00:00:00:01"


def test_parse_uplink_plaintext_psk_rejected() -> None:
    doc = build_safe_default_document().to_canonical()
    doc["uplink"] = _wifi_wan_uplink(psk="secret12345")
    with pytest.raises(IntentValidationError, match="secret-shaped"):
        parse_event_preset_document(doc)


def test_non_wifi_wan_rejects_wifi_client_fields() -> None:
    doc = build_safe_default_document().to_canonical()
    doc["uplink"] = {
        "mode": "Ethernet",
        "ssid": "Venue-Guest",
        "credential_ref_id": "credref:venue-wifi",
    }
    with pytest.raises(IntentValidationError, match="only allowed for WifiWan"):
        parse_event_preset_document(doc)


def test_priority_must_be_int_not_bool() -> None:
    doc = build_safe_default_document().to_canonical()
    doc["uplink"] = {"mode": "Ethernet", "priority": True}
    with pytest.raises(IntentValidationError, match="priority must be integer"):
        parse_event_preset_document(doc)


def test_captive_portal_client_must_be_bool() -> None:
    doc = build_safe_default_document().to_canonical()
    doc["uplink"] = {"mode": "Ethernet", "captive_portal_client": "yes"}
    with pytest.raises(IntentValidationError, match="captive_portal_client must be boolean"):
        parse_event_preset_document(doc)


def test_fully_specified_wifi_wan_planner_still_unsupported() -> None:
    doc = build_safe_default_document().to_canonical()
    doc["uplink"] = _wifi_wan_uplink(
        band="BAND_5GHZ",
        bssid="02:00:00:00:00:01",
        priority=50,
    )
    parsed = parse_event_preset_document(doc)
    planner = PresetPlannerService()
    preview = planner.build_plan_preview(
        document=parsed,
        validation_status=ValidationStatus.VALID_OFFLINE,
    )
    uplink = next(f for f in preview["families"] if f["family"] == "uplink")
    assert uplink["support"] == "unsupported"
    assert uplink["certification_blocker"] == "wifi_wan_not_certified"
    item = uplink["items"][0]
    assert item["mode"] == "WifiWan"
    assert item["priority"] == 50
    assert item["ssid_redacted"] == "[present]"
    assert "apply_ops" not in preview


def test_captive_portal_client_emits_unsupported_finding() -> None:
    doc = build_safe_default_document().to_canonical()
    doc["uplink"] = {"mode": "Ethernet", "captive_portal_client": True}
    parsed = parse_event_preset_document(doc)
    _, findings = validate_document(parsed)
    finding = next(f for f in findings if f.code == "uplink_captive_portal_client_unsupported")
    assert finding.blocking_for is BlockingFor.APPLY_FRAGMENT
    assert "not supported" in finding.summary_redacted.lower()


def test_ethernet_captive_portal_client_planner_not_supported() -> None:
    doc = build_safe_default_document().to_canonical()
    doc["uplink"] = {"mode": "Ethernet", "captive_portal_client": True}
    parsed = parse_event_preset_document(doc)
    planner = PresetPlannerService()
    preview = planner.build_plan_preview(
        document=parsed,
        validation_status=ValidationStatus.VALID_OFFLINE,
    )
    uplink = next(f for f in preview["families"] if f["family"] == "uplink")
    assert uplink["support"] != "supported"
    assert uplink["support"] == "unsupported"
    assert uplink["certification_blocker"] == "uplink_captive_portal_client_unsupported"
    assert uplink["items"][0]["captive_portal_client"] is True


def test_wired_priority_preferred_over_wifi_wan() -> None:
    wired = UplinkIntent(mode=UplinkMode.ETHERNET, priority=10)
    wifi = UplinkIntent(
        mode=UplinkMode.WIFI_WAN,
        ssid="Venue-Guest",
        band=WifiBand.BAND_2_4GHZ,
        credential_ref_id="credref:venue-wifi",
        priority=50,
    )
    assert uplink_preference_key(wired) < uplink_preference_key(wifi)
