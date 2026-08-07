"""Machine-readable verdict explanations shared across tunnel, uplink, and on-air families."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, ValidationError

VerdictSignalCode = Literal[
    "link",
    "connected",
    "state",
    "txbytes",
    "rxbytes",
    "broadcast",
    "peer_public_key",
    "peer_last_handshake",
    "peer_online",
    "peer_rxbytes",
    "peer_txbytes",
    "peer_enabled",
    "interface_readable",
    "interface_state",
    "interface_up",
    "associated_ssid_field_present",
    "associated_ssid_matches_intent",
    "internet_status",
    "gateway_status",
    "dns_status",
    "admin_up",
    "on_air_signal",
]

VerdictMissingSignalCode = Literal[
    "readback",
    "peer_public_key",
    "peer_last_handshake",
    "peer_online",
    "peer_rxbytes",
    "associated_ssid_field",
    "associated_ssid",
    "ssid_intent_match",
    "internet_status",
    "gateway_status",
    "dns_status",
    "internet_affirmative",
    "link",
    "broadcast",
    "on_air_signal",
    "positive_handshake",
    "positive_online",
    "positive_rxbytes",
    "uplink_settle_performed",
]

VerdictRejectionReason = Literal[
    "interface_state_not_evidence",
    "interface_up_not_evidence",
    "peer_enabled_not_evidence",
    "peer_txbytes_alone_not_evidence",
    "link_not_evidence",
    "connected_not_evidence",
    "connected_with_link_down",
    "state_up_with_link_down",
    "txbytes_without_rxbytes",
    "link_broadcast_conflict",
    "auth_type_not_evidence",
]

TunnelVerdict = Literal[
    "tunnel_no_peer",
    "tunnel_never_handshaked",
    "tunnel_healthy",
    "tunnel_unverified",
]

UplinkVerdict = Literal[
    "uplink_dispatched_unverified",
    "uplink_associated_no_global",
    "uplink_verified_bounded",
    "uplink_failed",
]

OnAirVerdict = Literal[
    "on_air_verified",
    "on_air_admin_only",
    "on_air_unverified",
    "on_air_still_broadcasting",
]

ConfigurationVerificationStatus = Literal["device_accepted_configuration"]

InterfaceVerificationStatus = Literal[
    "interface_present_up",
    "interface_present_down",
    "interface_not_up",
    "interface_id_mismatch",
    "interface_absent",
    "interface_still_present",
]

InterfaceAddressVerificationStatus = Literal[
    "interface_address_not_configured",
    "address_configured_unverified",
    "address_readback_confirmed",
]

VerdictValue = TunnelVerdict | UplinkVerdict | OnAirVerdict

_TUNNEL_VERDICTS = frozenset(
    {
        "tunnel_no_peer",
        "tunnel_never_handshaked",
        "tunnel_healthy",
        "tunnel_unverified",
    }
)
_UPLINK_VERDICTS = frozenset(
    {
        "uplink_dispatched_unverified",
        "uplink_associated_no_global",
        "uplink_verified_bounded",
        "uplink_failed",
    }
)
_ON_AIR_VERDICTS = frozenset(
    {
        "on_air_verified",
        "on_air_admin_only",
        "on_air_unverified",
        "on_air_still_broadcasting",
    }
)
_CONFIGURATION_VERIFICATION_STATUSES = frozenset({"device_accepted_configuration"})
_INTERFACE_VERIFICATION_STATUSES = frozenset(
    {
        "interface_present_up",
        "interface_present_down",
        "interface_not_up",
        "interface_id_mismatch",
        "interface_absent",
        "interface_still_present",
    }
)
_INTERFACE_ADDRESS_VERIFICATION_STATUSES = frozenset(
    {
        "interface_address_not_configured",
        "address_configured_unverified",
        "address_readback_confirmed",
    }
)

ALL_VERDICT_VALUES = _TUNNEL_VERDICTS | _UPLINK_VERDICTS | _ON_AIR_VERDICTS

SUCCESS_VERDICTS = frozenset(
    {
        "tunnel_healthy",
        "uplink_verified_bounded",
        "on_air_verified",
    }
)

UNKNOWN_VERDICTS = frozenset(
    {
        "tunnel_unverified",
        "uplink_dispatched_unverified",
        "uplink_associated_no_global",
        "on_air_unverified",
        "on_air_admin_only",
    }
)

_SECRET_VALUE_FRAGMENTS = (
    "psk",
    "password",
    "passphrase",
    "private_key",
    "preshared",
    "wpa-psk",
    "credref:",
)

_BOOLEAN_SIGNALS = frozenset(
    {
        "link",
        "connected",
        "state",
        "broadcast",
        "peer_online",
        "peer_enabled",
        "interface_readable",
        "interface_state",
        "interface_up",
        "associated_ssid_field_present",
        "associated_ssid_matches_intent",
        "internet_status",
        "gateway_status",
        "dns_status",
        "admin_up",
        "on_air_signal",
    }
)
_COUNTER_SIGNALS = frozenset(
    {
        "txbytes",
        "rxbytes",
        "peer_last_handshake",
        "peer_rxbytes",
        "peer_txbytes",
    }
)
_PEER_KEY_ENUM_VALUES = frozenset({"present", "absent"})


@dataclass(frozen=True, slots=True)
class VerdictSignalReading:
    signal: VerdictSignalCode
    value: str | int | bool | None

    def to_dict(self) -> dict[str, object]:
        return {"signal": self.signal, "value": self.value}


@dataclass(frozen=True, slots=True)
class VerdictRejectedSignal:
    signal: VerdictSignalCode
    reason: VerdictRejectionReason

    def to_dict(self) -> dict[str, object]:
        return {"signal": self.signal, "reason": self.reason}


@dataclass(frozen=True, slots=True)
class VerdictExplanation:
    signals_read: tuple[VerdictSignalReading, ...]
    signals_missing: tuple[VerdictMissingSignalCode, ...]
    signals_rejected: tuple[VerdictRejectedSignal, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "signals_read": [item.to_dict() for item in self.signals_read],
            "signals_missing": list(self.signals_missing),
            "signals_rejected": [item.to_dict() for item in self.signals_rejected],
        }


@dataclass(frozen=True, slots=True)
class VerdictObservation:
    verdict: str
    explanation: VerdictExplanation


class _StrictExplanationModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    class SignalReading(BaseModel):
        model_config = ConfigDict(extra="forbid")
        signal: VerdictSignalCode
        value: str | int | bool | None

    class RejectedSignal(BaseModel):
        model_config = ConfigDict(extra="forbid")
        signal: VerdictSignalCode
        reason: VerdictRejectionReason

    signals_read: list[SignalReading]
    signals_missing: list[VerdictMissingSignalCode]
    signals_rejected: list[RejectedSignal]


class VerdictLiteralError(ValueError):
    """Raised when a response payload carries a verdict outside the closed literal set."""


def assert_verdict_literal(value: object, *, allowed: frozenset[str], field: str) -> None:
    if not isinstance(value, str) or value not in allowed:
        raise VerdictLiteralError(f"{field}={value!r} not in closed literal set")


def normalize_up_down(value: Any) -> bool | None:
    """Normalize admin/link up-down vocabulary to bool; unknown tokens → None."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if not text:
        return None
    if text in {"up", "enabled", "true", "1"}:
        return True
    if text in {"down", "disabled", "false", "0"}:
        return False
    return None


def normalize_yes_no(value: Any) -> bool | None:
    """Normalize yes/no vocabulary to bool; unknown tokens → None."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"yes", "true", "1"}:
        return True
    if text in {"no", "false", "0"}:
        return False
    return None


def normalize_counter(value: Any) -> int | None:
    """Normalize numeric counter fields; unparseable → None."""
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def assert_normalized_signal_value(signal: VerdictSignalCode, value: object) -> None:
    """Runtime guard: explanation values must be normalized bool/int/enum/null only."""
    if signal in _BOOLEAN_SIGNALS:
        if value is not None and not isinstance(value, bool):
            raise VerdictLiteralError(
                f"verdict_explanation signal {signal!r} value {value!r} is not normalized bool|null"
            )
        return
    if signal in _COUNTER_SIGNALS:
        if value is not None and not isinstance(value, int):
            raise VerdictLiteralError(
                f"verdict_explanation signal {signal!r} value {value!r} is not normalized int|null"
            )
        return
    if signal == "peer_public_key":
        if value not in _PEER_KEY_ENUM_VALUES:
            raise VerdictLiteralError(
                f"verdict_explanation signal {signal!r} value {value!r} not in present|absent"
            )
        return
    raise VerdictLiteralError(f"verdict_explanation unknown signal {signal!r}")


def validate_verdict_explanation_dict(payload: dict[str, object]) -> None:
    try:
        _StrictExplanationModel.model_validate(payload)
    except ValidationError as exc:
        raise VerdictLiteralError(f"verdict_explanation invalid: {exc}") from exc
    signals_read_raw = payload.get("signals_read", [])
    if not isinstance(signals_read_raw, list):
        return
    for item in signals_read_raw:
        if not isinstance(item, dict):
            continue
        signal = item.get("signal")
        value = item.get("value")
        if isinstance(signal, str):
            assert_normalized_signal_value(signal, value)  # type: ignore[arg-type]
        if isinstance(value, str):
            lowered = value.lower()
            for fragment in _SECRET_VALUE_FRAGMENTS:
                if fragment in lowered:
                    raise VerdictLiteralError(
                        f"verdict_explanation signal {signal!r} "
                        f"carries secret fragment {fragment!r}"
                    )


_TPayload = TypeVar("_TPayload", bound=dict[str, object])


def validate_response_payload(
    payload: _TPayload,
    *,
    field_literals: dict[str, frozenset[str]],
) -> _TPayload:
    """Validate known verdict fields against closed literals; return same dict (no filter)."""
    for field, allowed in field_literals.items():
        if field not in payload:
            continue
        value = payload[field]
        if value is None:
            continue
        assert_verdict_literal(value, allowed=allowed, field=field)
    if "verdict_explanation" in payload and payload["verdict_explanation"] is not None:
        explanation = payload["verdict_explanation"]
        if isinstance(explanation, dict):
            validate_verdict_explanation_dict(explanation)
    return payload


def validate_wireguard_apply_payload(payload: dict[str, object]) -> dict[str, object]:
    return validate_response_payload(
        payload,
        field_literals={
            "tunnel_verification_status": _TUNNEL_VERDICTS,
            "configuration_verification_status": _CONFIGURATION_VERIFICATION_STATUSES,
            "interface_verification_status": _INTERFACE_VERIFICATION_STATUSES,
            "interface_address_verification_status": _INTERFACE_ADDRESS_VERIFICATION_STATUSES,
        },
    )


def validate_wifi_station_apply_payload(payload: dict[str, object]) -> dict[str, object]:
    return validate_response_payload(
        payload,
        field_literals={"uplink_verification_status": _UPLINK_VERDICTS},
    )


def validate_wifi_apply_payload(payload: dict[str, object]) -> dict[str, object]:
    return validate_response_payload(
        payload,
        field_literals={"on_air_verification_status": _ON_AIR_VERDICTS},
    )


def assert_verdict_observation(observation: VerdictObservation) -> VerdictObservation:
    if observation.verdict not in ALL_VERDICT_VALUES:
        raise VerdictLiteralError(f"verdict={observation.verdict!r} not in closed literal set")
    validate_verdict_explanation_dict(observation.explanation.to_dict())
    return observation


def explanation_for_skipped_observe(verdict: str) -> VerdictExplanation:
    """Minimal explanation when runtime observe did not run (offline/fake paths)."""
    if verdict == "uplink_dispatched_unverified":
        return VerdictExplanation(
            signals_read=(),
            signals_missing=("readback", "internet_affirmative", "uplink_settle_performed"),
            signals_rejected=(),
        )
    if verdict == "tunnel_unverified":
        return VerdictExplanation(
            signals_read=(),
            signals_missing=("readback",),
            signals_rejected=(),
        )
    return VerdictExplanation(
        signals_read=(),
        signals_missing=("readback",),
        signals_rejected=(),
    )


def assert_verdict_explanation_invariant(verdict: str, explanation: VerdictExplanation) -> None:
    """Verdict ↔ explanation consistency (test invariant)."""
    read_signals = {item.signal for item in explanation.signals_read}
    missing_signals = set(explanation.signals_missing)
    rejected_signals = {item.signal for item in explanation.signals_rejected}
    for rejected in explanation.signals_rejected:
        if rejected.signal not in read_signals:
            raise AssertionError(
                f"rejected signal {rejected.signal!r} must appear in signals_read"
            )
    accounted = read_signals | missing_signals | rejected_signals
    if verdict in SUCCESS_VERDICTS:
        if explanation.signals_rejected:
            raise AssertionError(
                f"success verdict {verdict!r} must not list rejected deceptive signals"
            )
    if verdict in UNKNOWN_VERDICTS:
        if not explanation.signals_missing and not explanation.signals_rejected:
            raise AssertionError(
                f"unknown verdict {verdict!r} requires non-empty missing or rejected signals"
            )
    if verdict == "tunnel_no_peer":
        if "interface_readable" not in accounted:
            raise AssertionError(
                "tunnel_no_peer requires interface_readable in explanation"
            )
        if "peer_public_key" not in accounted:
            raise AssertionError(
                "tunnel_no_peer requires peer_public_key in explanation"
            )


def assert_explanation_has_no_secrets(explanation: VerdictExplanation) -> None:
    """Ensure explanation values never carry credentials or upstream SSIDs."""
    blob = explanation.to_dict()
    serialized = str(blob).lower()
    for fragment in _SECRET_VALUE_FRAGMENTS:
        if fragment in serialized:
            raise AssertionError(f"secret fragment {fragment!r} found in verdict explanation")
    for reading in explanation.signals_read:
        if reading.signal == "associated_ssid_matches_intent":
            continue
        if isinstance(reading.value, str):
            lowered = reading.value.lower()
            if "venue-guest" in lowered or "staff-private" in lowered:
                raise AssertionError("raw upstream SSID must not appear in verdict explanation")
            if len(reading.value) > 64 and not reading.value.isdigit():
                raise AssertionError(
                    f"suspicious long string in explanation signal {reading.signal!r}"
                )


def _state_is_up_token(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, str):
        return value.strip().lower() in {"up", "enabled", "true", "1", "yes"}
    return False


def _append_unique_missing(
    missing: list[VerdictMissingSignalCode],
    code: VerdictMissingSignalCode,
) -> None:
    if code not in missing:
        missing.append(code)


def _append_unique_rejected(
    rejected: list[VerdictRejectedSignal],
    item: VerdictRejectedSignal,
) -> None:
    if item not in rejected:
        rejected.append(item)
