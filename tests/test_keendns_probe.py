"""KeenDNS/CrazeDNS probe parser tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from router_control.adapters.netcraze.ndns_probe import (
    NDNS_SEALED_COMPONENT_ID,
    parse_components_inventory,
    parse_get_booked,
    parse_show_ndns,
)
from router_control.application.keendns_observe import classify_keendns_status

_FIXTURE = Path("tests/fixtures/netcraze/bootstrap_components_real_device_shape.json")


def test_parse_empty_components_unknown() -> None:
    result = parse_components_inventory(None)
    assert result["parse_status"] == "unknown"
    assert result["component_ids"] is None


def test_parse_components_with_ndns_ok() -> None:
    raw = _FIXTURE.read_text(encoding="utf-8")
    result = parse_components_inventory(raw)
    assert result["parse_status"] == "ok"
    assert NDNS_SEALED_COMPONENT_ID in result["component_ids"]


def test_parse_components_without_ndns_ok() -> None:
    payload = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    component_map = dict(payload["component"])
    component_map.pop(NDNS_SEALED_COMPONENT_ID)
    payload["component"] = component_map
    result = parse_components_inventory(payload)
    assert result["parse_status"] == "ok"
    assert NDNS_SEALED_COMPONENT_ID not in result["component_ids"]


def test_parse_unfamiliar_components_unparsed() -> None:
    result = parse_components_inventory("not-json-at-all")
    assert result["parse_status"] == "unparsed"
    assert result["component_ids"] is None


def test_parse_show_ndns_empty_unknown() -> None:
    result = parse_show_ndns("")
    assert result["parse_status"] == "unknown"


def test_parse_show_ndns_unfamiliar_unparsed() -> None:
    result = parse_show_ndns("mode: cloud\nname: foo")
    assert result["parse_status"] == "unparsed"


def test_parse_get_booked_empty_unknown() -> None:
    result = parse_get_booked("")
    assert result["parse_status"] == "unknown"


@pytest.mark.parametrize(
    ("components_raw", "expected_feature"),
    [
        (None, "unknown"),
        ("", "unknown"),
        ("totally unfamiliar", "unknown"),
    ],
)
def test_classify_empty_or_unfamiliar_unknown(
    components_raw: str | None, expected_feature: str
) -> None:
    result = classify_keendns_status(components_raw=components_raw)
    assert result["feature_availability"] == expected_feature
    assert result["name_reservation"] == "unknown"
    assert result["access_mode"] == "unknown"


def test_classify_empty_body_all_unknown() -> None:
    result = classify_keendns_status()
    assert result["feature_availability"] == "unknown"
    assert result["feature_availability"] != "disabled"


def test_classify_unavailable_when_ndns_component_absent() -> None:
    payload = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    component_map = dict(payload["component"])
    component_map.pop(NDNS_SEALED_COMPONENT_ID)
    payload["component"] = component_map
    result = classify_keendns_status(components_raw=json.dumps(payload))
    assert result["feature_availability"] == "unavailable"


def test_classify_empty_show_not_disabled() -> None:
    result = classify_keendns_status(ndns_show_raw="")
    assert result["feature_availability"] == "unknown"
    assert result["feature_availability"] != "disabled"


def test_classify_unfamiliar_show_with_mode_cloud_stays_unknown() -> None:
    """Unparsed show ndns text must not invent access_mode from substring heuristics."""
    result = classify_keendns_status(ndns_show_raw="mode: cloud\nname: foo")
    assert result["access_mode"] == "unknown"
    assert result["feature_availability"] == "unknown"
    assert result["name_reservation"] == "unknown"
