"""Verdict explanation invariants, secret safety, and verdict↔explanation consistency."""

from __future__ import annotations

import json
from typing import Any

import pytest
from router_control.application.verdict_explanation import (
    SUCCESS_VERDICTS,
    UNKNOWN_VERDICTS,
    VerdictExplanation,
    VerdictLiteralError,
    VerdictRejectedSignal,
    VerdictSignalReading,
    assert_explanation_has_no_secrets,
    assert_verdict_explanation_invariant,
    validate_wifi_apply_payload,
    validate_wifi_station_apply_payload,
    validate_wireguard_apply_payload,
)
from router_control.application.wifi_apply_service import observe_on_air_apply
from router_control.application.wifi_station_apply_service import observe_station_uplink
from router_control.application.wireguard_apply_service import observe_tunnel

from tests.test_wifi_apply_service import _admin_up_link_down_readback, _admin_up_link_up_readback
from tests.test_wireguard_apply_service import (
    WG_PEER_LAST_HANDSHAKE_NEVER,
    _dead_peer_readback,
    _extract_observed,
    _healthy_peer_readback_synthesised,
)


def test_success_verdict_has_no_rejected_signals() -> None:
    healthy = _extract_observed(_healthy_peer_readback_synthesised())
    observation = observe_tunnel(healthy)
    assert observation.verdict == "tunnel_healthy"
    assert observation.explanation.signals_rejected == ()
    assert_verdict_explanation_invariant(observation.verdict, observation.explanation)


def test_unknown_verdict_requires_missing_or_rejected() -> None:
    observation = observe_tunnel(None)
    assert observation.verdict == "tunnel_unverified"
    assert (
        observation.explanation.signals_missing or observation.explanation.signals_rejected
    )
    assert_verdict_explanation_invariant(observation.verdict, observation.explanation)


def test_invariant_catches_success_with_rejected_desync() -> None:
    explanation = VerdictExplanation(
        signals_read=(
            VerdictSignalReading("peer_online", True),
            VerdictSignalReading("interface_state", True),
        ),
        signals_missing=(),
        signals_rejected=(
            VerdictRejectedSignal("interface_state", "interface_state_not_evidence"),
        ),
    )
    with pytest.raises(AssertionError, match="success verdict"):
        assert_verdict_explanation_invariant("tunnel_healthy", explanation)


def test_invariant_catches_unknown_without_reason_desync() -> None:
    explanation = VerdictExplanation(
        signals_read=(),
        signals_missing=(),
        signals_rejected=(),
    )
    with pytest.raises(AssertionError, match="unknown verdict"):
        assert_verdict_explanation_invariant("tunnel_unverified", explanation)


def test_tunnel_no_peer_includes_interface_readable_in_explanation() -> None:
    """F-1: interface_readable drives tunnel_no_peer branch and must appear in signals_read."""
    observation = observe_tunnel(
        {"id": "Wireguard5", "state": "up", "up": True, "link": "up"}
    )
    assert observation.verdict == "tunnel_no_peer"
    read_signals = {item.signal: item.value for item in observation.explanation.signals_read}
    assert read_signals["interface_readable"] is True
    assert read_signals["interface_state"] is True
    assert read_signals["interface_up"] is True
    assert read_signals["link"] is True
    assert read_signals["peer_public_key"] == "absent"
    assert_verdict_explanation_invariant(observation.verdict, observation.explanation)


def test_tunnel_unverified_no_peer_rejected_signals_must_be_read() -> None:
    """F-1: rejected deceptive interface signals must also be present in signals_read."""
    observation = observe_tunnel(
        {"state": "up", "up": True, "link": "up", "connected": True}
    )
    assert observation.verdict == "tunnel_unverified"
    read_signals = {item.signal for item in observation.explanation.signals_read}
    for rejected in observation.explanation.signals_rejected:
        assert rejected.signal in read_signals
    assert_verdict_explanation_invariant(observation.verdict, observation.explanation)


def test_signals_read_values_are_normalized_not_raw_device_strings() -> None:
    """F-3: raw device tokens like state='up' must become bool in signals_read."""
    healthy = _extract_observed(_healthy_peer_readback_synthesised())
    observation = observe_tunnel(healthy)
    for reading in observation.explanation.signals_read:
        if reading.signal in {"interface_state", "interface_up", "link", "connected", "state"}:
            assert isinstance(reading.value, bool), (
                f"{reading.signal} must be normalized bool, got {reading.value!r}"
            )
        elif reading.signal == "peer_public_key":
            assert reading.value in {"present", "absent"}
        elif reading.signal in {
            "peer_last_handshake",
            "peer_rxbytes",
            "peer_txbytes",
            "txbytes",
            "rxbytes",
        }:
            assert reading.value is None or isinstance(reading.value, int)
        elif reading.signal in {"peer_online", "peer_enabled"}:
            assert isinstance(reading.value, bool)
    assert_explanation_has_no_secrets(observation.explanation)


def test_runtime_validation_rejects_raw_device_string_in_explanation() -> None:
    """F-3: validate_wireguard_apply_payload must fail-closed on raw device strings."""
    healthy = _extract_observed(_healthy_peer_readback_synthesised())
    observation = observe_tunnel(healthy)
    payload = {
        "overall": "applied",
        "wg_id": "Wireguard5",
        "steps": [],
        "errors": [],
        "logs": [],
        "tunnel_verification_status": observation.verdict,
        "verdict_explanation": observation.explanation.to_dict(),
        "extra_field_preserved": True,
    }
    bad = json.loads(json.dumps(payload))
    bad["verdict_explanation"]["signals_read"] = [
        {"signal": "interface_state", "value": "up"},
    ]
    with pytest.raises(VerdictLiteralError, match="not normalized bool"):
        validate_wireguard_apply_payload(bad)
    assert payload["extra_field_preserved"] is True


def test_invariant_catches_rejected_without_read_desync() -> None:
    explanation = VerdictExplanation(
        signals_read=(),
        signals_missing=("readback",),
        signals_rejected=(
            VerdictRejectedSignal("interface_state", "interface_state_not_evidence"),
        ),
    )
    with pytest.raises(AssertionError, match="must appear in signals_read"):
        assert_verdict_explanation_invariant("tunnel_unverified", explanation)


def test_dead_peer_explanation_rejects_deceptive_interface_up() -> None:
    observed = _extract_observed(_dead_peer_readback())
    observation = observe_tunnel(observed)
    assert observation.verdict == "tunnel_never_handshaked"
    rejected_signals = {item.signal for item in observation.explanation.signals_rejected}
    assert "interface_state" in rejected_signals or "interface_up" in rejected_signals
    assert "peer_txbytes" in rejected_signals


def test_uplink_deceptive_connected_with_link_down_in_explanation() -> None:
    readback: dict[str, Any] = {
        "associated_ssid_field_present": True,
        "associated_ssid": "Venue-Guest",
        "link": "down",
        "connected": True,
        "state": "up",
        "txbytes": 100,
        "rxbytes": 0,
    }
    observation = observe_station_uplink(
        readback,
        internet_status={"internet": "yes", "gateway": "yes", "dns": "yes"},
        intended_ssid="Venue-Guest",
    )
    assert observation.verdict == "uplink_associated_no_global"
    reasons = {item.reason for item in observation.explanation.signals_rejected}
    assert "connected_with_link_down" in reasons
    assert "txbytes_without_rxbytes" in reasons
    assert_explanation_has_no_secrets(observation.explanation)
    serialized = json.dumps(observation.explanation.to_dict())
    assert "Venue-Guest" not in serialized


def test_on_air_admin_only_rejects_connected_with_link_down() -> None:
    from router_control.application.wifi_observation_helpers import extract_interface_fields

    observed = extract_interface_fields(_admin_up_link_down_readback())
    observation = observe_on_air_apply(observed)
    assert observation.verdict == "on_air_admin_only"
    reasons = {item.reason for item in observation.explanation.signals_rejected}
    assert "connected_with_link_down" in reasons
    assert_verdict_explanation_invariant(observation.verdict, observation.explanation)


def test_on_air_verified_has_no_rejected_signals() -> None:
    from router_control.application.wifi_observation_helpers import extract_interface_fields

    observed = extract_interface_fields(_admin_up_link_up_readback())
    observation = observe_on_air_apply(observed)
    assert observation.verdict == "on_air_verified"
    assert observation.explanation.signals_rejected == ()
    assert_verdict_explanation_invariant(observation.verdict, observation.explanation)


def test_int_max_handshake_never_counts_as_healthy_with_explanation() -> None:
    observed = _extract_observed(_dead_peer_readback())
    observed["peer_online"] = "yes"
    observed["peer_rxbytes"] = 4096
    observation = observe_tunnel(observed)
    assert observation.verdict == "tunnel_never_handshaked"
    assert observation.verdict != "tunnel_healthy"
    handshake_reads = [
        item.value
        for item in observation.explanation.signals_read
        if item.signal == "peer_last_handshake"
    ]
    assert handshake_reads == [WG_PEER_LAST_HANDSHAKE_NEVER]


@pytest.mark.parametrize("verdict", sorted(SUCCESS_VERDICTS))
def test_success_verdict_set_is_consistent(verdict: str) -> None:
    assert verdict not in UNKNOWN_VERDICTS


def test_validate_wireguard_payload_rejects_invalid_tunnel_verdict() -> None:
    healthy = _extract_observed(_healthy_peer_readback_synthesised())
    observation = observe_tunnel(healthy)
    payload = {
        "overall": "applied",
        "wg_id": "Wireguard5",
        "steps": [],
        "errors": [],
        "logs": [],
        "tunnel_verification_status": "not_a_real_tunnel_verdict",
        "verdict_explanation": observation.explanation.to_dict(),
        "extra_field_preserved": {"nested": True},
    }
    with pytest.raises(VerdictLiteralError, match="tunnel_verification_status"):
        validate_wireguard_apply_payload(payload)


def test_validate_wireguard_payload_preserves_extra_fields() -> None:
    healthy = _extract_observed(_healthy_peer_readback_synthesised())
    observation = observe_tunnel(healthy)
    payload = {
        "overall": "applied",
        "wg_id": "Wireguard5",
        "steps": [],
        "errors": [],
        "logs": [],
        "tunnel_verification_status": observation.verdict,
        "configuration_verification_status": "device_accepted_configuration",
        "interface_verification_status": "interface_present_up",
        "interface_address_verification_status": "interface_address_not_configured",
        "verdict_explanation": observation.explanation.to_dict(),
        "extra_field_preserved": {"nested": True},
        "verification_notes": ["note-one"],
    }
    before = json.dumps(payload, sort_keys=True)
    validated = validate_wireguard_apply_payload(payload)
    assert json.dumps(validated, sort_keys=True) == before
    assert validated["extra_field_preserved"] == {"nested": True}


def test_validate_station_and_on_air_payload_literals() -> None:
    from router_control.application.wifi_observation_helpers import extract_interface_fields

    uplink_obs = observe_station_uplink(
        {
            "associated_ssid_field_present": True,
            "associated_ssid": "Venue-Guest",
            "link": "up",
            "connected": True,
        },
        internet_status={"internet": "yes", "gateway": "yes", "dns": "yes"},
        intended_ssid="Venue-Guest",
    )
    station_payload = {
        "overall": "applied",
        "station_id": "WifiMaster0/WifiStation0",
        "verification_status": "verified",
        "grammar_verification_status": "verified",
        "uplink_verification_status": uplink_obs.verdict,
        "notes": [],
        "steps": [],
        "errors": [],
        "logs": [],
        "verdict_explanation": uplink_obs.explanation.to_dict(),
    }
    validate_wifi_station_apply_payload(station_payload)

    on_air_obs = observe_on_air_apply(extract_interface_fields(_admin_up_link_up_readback()))
    on_air_payload = {
        "overall": "applied",
        "ap_id": "WifiMaster0/AccessPoint0",
        "on_air_verification_status": on_air_obs.verdict,
        "steps": [],
        "errors": [],
        "logs": [],
        "verdict_explanation": on_air_obs.explanation.to_dict(),
    }
    validate_wifi_apply_payload(on_air_payload)

    bad_on_air = dict(on_air_payload)
    bad_on_air["on_air_verification_status"] = "on_air_totally_unknown"
    with pytest.raises(VerdictLiteralError, match="on_air_verification_status"):
        validate_wifi_apply_payload(bad_on_air)
