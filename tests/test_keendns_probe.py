"""KeenDNS/CrazeDNS probe parser tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from router_control.adapters.netcraze.ndns_probe import (
    NDNS_SEALED_COMPONENT_ID,
    parse_components_inventory,
    parse_get_booked,
    parse_show_acme,
    parse_show_ndns,
)
from router_control.application.keendns_observe import classify_keendns_status, run_keendns_observe

_FIXTURE = Path("tests/fixtures/netcraze/bootstrap_components_real_device_shape.json")
_ACME_FIXTURE = Path("tests/fixtures/netcraze/show-acme-default-domain-v1.json")
_NDNS_EMPTY_FIXTURE = Path("tests/fixtures/netcraze/show-ndns-empty-personal-v1.json")
_SEALED_DEFAULT_DOMAIN = "1880927356f927ebc1b7fa92.netcraze.io"


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


def test_parse_show_acme_fixture_ok() -> None:
    payload = json.loads(_ACME_FIXTURE.read_text(encoding="utf-8"))
    result = parse_show_acme(payload)
    assert result["parse_status"] == "ok"
    assert result["default_domain"] == _SEALED_DEFAULT_DOMAIN
    assert result["default_domain_certificate_valid"] is True


def test_parse_show_acme_rci_wrap_ok() -> None:
    payload = [
        {
            "parse": {
                "acme": {
                    "default-domain": _SEALED_DEFAULT_DOMAIN,
                    "default-domain-certificate-valid": True,
                }
            }
        }
    ]
    result = parse_show_acme(payload)
    assert result["parse_status"] == "ok"
    assert result["default_domain"] == _SEALED_DEFAULT_DOMAIN
    assert result["default_domain_certificate_valid"] is True


def test_parse_show_acme_empty_unknown() -> None:
    result = parse_show_acme(None)
    assert result["parse_status"] == "unknown"
    assert result["default_domain"] is None


def test_parse_show_acme_missing_domain_unknown() -> None:
    result = parse_show_acme({"acme": {"default-domain": ""}})
    assert result["parse_status"] == "unknown"
    assert result["default_domain"] is None


def test_parse_show_ndns_empty_unknown() -> None:
    result = parse_show_ndns("")
    assert result["parse_status"] == "unknown"


def test_parse_show_ndns_sealed_empty_not_reserved() -> None:
    payload = json.loads(_NDNS_EMPTY_FIXTURE.read_text(encoding="utf-8"))
    result = parse_show_ndns(payload)
    assert result["parse_status"] == "not_reserved"
    assert result["name"] is None
    assert result["domain"] is None


def test_parse_show_ndns_sealed_rci_empty_not_reserved() -> None:
    payload = [{"parse": {"name": "", "domain": "", "access": ""}}]
    result = parse_show_ndns(payload)
    assert result["parse_status"] == "not_reserved"


def test_parse_show_ndns_reserved_ok() -> None:
    result = parse_show_ndns({"name": "promo", "domain": "netcraze.pro", "access": "auto"})
    assert result["parse_status"] == "ok"
    assert result["name"] == "promo"
    assert result["domain"] == "netcraze.pro"
    assert result["access_mode"] == "auto"


def test_parse_show_ndns_unfamiliar_unparsed() -> None:
    result = parse_show_ndns("mode: cloud\nname: foo")
    assert result["parse_status"] == "unparsed"


def test_parse_get_booked_empty_unknown() -> None:
    result = parse_get_booked("")
    assert result["parse_status"] == "unknown"


def test_parse_get_booked_no_booking_not_fqdn() -> None:
    result = parse_get_booked({"continued": True, "message": "No booking found"})
    assert result["parse_status"] == "not_reserved"
    assert result.get("booked_fqdn") is None


def test_parse_get_booked_fqdn_ok() -> None:
    result = parse_get_booked({"booked": "promo.netcraze.pro"})
    assert result["parse_status"] == "ok"
    assert result["booked_fqdn"] == "promo.netcraze.pro"


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


def test_classify_sealed_empty_ndns_not_reserved() -> None:
    payload = json.loads(_NDNS_EMPTY_FIXTURE.read_text(encoding="utf-8"))
    result = classify_keendns_status(ndns_show_raw=json.dumps(payload))
    assert result["name_reservation"] == "not_reserved"
    assert result["access_mode"] == "unknown"


def test_classify_unfamiliar_show_with_mode_cloud_stays_unknown() -> None:
    """Unparsed show ndns text must not invent access_mode from substring heuristics."""
    result = classify_keendns_status(ndns_show_raw="mode: cloud\nname: foo")
    assert result["access_mode"] == "unknown"
    assert result["feature_availability"] == "unknown"
    assert result["name_reservation"] == "unknown"


class _FakeObserveTransport:
    def __init__(self) -> None:
        self.commands: list[str] = []

    def execute_rci_parse(self, cli_command: str) -> object:
        self.commands.append(cli_command)
        if cli_command == "show acme":
            return json.loads(_ACME_FIXTURE.read_text(encoding="utf-8"))
        if cli_command == "show ndns":
            return json.loads(_NDNS_EMPTY_FIXTURE.read_text(encoding="utf-8"))
        if cli_command == "ndns get-booked":
            return {"continued": True, "message": "No booking found"}
        return {}


def test_run_keendns_observe_fake_transport() -> None:
    transport = _FakeObserveTransport()
    result = run_keendns_observe(transport=transport)
    assert result["default_fqdn"] == _SEALED_DEFAULT_DOMAIN
    assert result["ssl_valid"] is True
    assert result["name_reservation"] == "not_reserved"
    assert result["booked_fqdn"] is None
    assert result["certification_eligible"] is False
    assert "show acme" in transport.commands
    assert "show ndns" in transport.commands
