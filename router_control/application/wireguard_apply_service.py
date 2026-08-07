"""WireGuard/AmneziaWG Configure → Apply → Verify service (injected transport; offline-testable)."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal, Protocol, cast

from router_control.adapters.netcraze.allowlist import validate_wireguard_id
from router_control.adapters.netcraze.interface_rci import (
    InterfaceRciError,
    InterfaceRciOperation,
    InterfaceRciResult,
    execute_interface_rci,
)
from router_control.adapters.netcraze.sanitize import sanitize_mapping
from router_control.adapters.netcraze.transport import SealedRciWriteRequest
from router_control.adapters.netcraze.wireguard_rci import (
    WireguardRciError,
    WireguardRciOperation,
    WireguardRciResult,
    execute_wireguard_nested_peer_rci,
    execute_wireguard_rci,
    parse_interface_address_cidr,
)
from router_control.application.apply_pre_read import execute_pre_apply_read
from router_control.application.apply_types import ApplyOverallStatus, ApplyRollbackOutcome
from router_control.application.recovery import (
    SealedApplyTrailHandle,
    SealedApplyTrailParams,
    begin_sealed_apply_trail,
    build_sealed_apply_op_evidence,
    finish_sealed_apply_trail,
    guard_sealed_apply_trail,
    outcome_snapshot_from_apply_result,
    redact_sealed_apply_device_ack,
    serialize_pre_apply_baseline_for_trail,
    sleep_preserving_sealed_apply_lease,
)
from router_control.application.verdict_explanation import (
    VerdictExplanation,
    VerdictMissingSignalCode,
    VerdictObservation,
    VerdictRejectedSignal,
    VerdictSignalCode,
    VerdictSignalReading,
    _append_unique_missing,
    _append_unique_rejected,
    _state_is_up_token,
    assert_verdict_explanation_invariant,
    assert_verdict_observation,
    explanation_for_skipped_observe,
    normalize_counter,
    normalize_up_down,
    normalize_yes_no,
    validate_wireguard_apply_payload,
)
from router_control.application.wifi_observation_helpers import (
    ERROR_CODE_CREDENTIAL_REF_REQUIRED,
    ERROR_CODE_CREDENTIAL_RESOLUTION_FAILED,
    ERROR_CODE_NO_APPLY_OPS,
    ERROR_CODE_OP_DISPATCH_FAILED,
    ERROR_CODE_READBACK_FAILED,
    ERROR_CODE_UNSUPPORTED_OPERATION,
)
from router_control.application.wireguard_apply_planner import (
    _INTERFACE_ADDRESS_LIMITATION_NOTE,
    WG_HANDSHAKE_SETTLE_SECONDS_MAX,
    WG_HANDSHAKE_SETTLE_SECONDS_MIN,
    WireguardApplyPlan,
    WireguardApplyPlannerError,
    WireguardApplyPreState,
    WireguardSealedOpDescriptor,
    clamp_handshake_settle_seconds,
    compensate_ops_for_succeeded_wireguard_apply,
    compile_wireguard_intent_to_ops,
    derive_wireguard_pre_state,
    intent_implies_traffic_routing,
    uncovered_compensate_ops_for_succeeded_wireguard_apply,
)
from router_control.domain.network_intents import WireguardIntent

CredentialResolver = Callable[[str], str]
BackupCallback = Callable[[], None]

_MSG_CREDENTIAL_RESOLUTION_FAILED = ERROR_CODE_CREDENTIAL_RESOLUTION_FAILED
_MSG_OP_DISPATCH_FAILED = ERROR_CODE_OP_DISPATCH_FAILED
_SECRET_DISPATCH_OPS = frozenset(
    {
        WireguardRciOperation.SET_PRIVATE_KEY.value,
        WireguardRciOperation.SET_PRESHARED_KEY.value,
        WireguardRciOperation.UPSERT_PEER_NESTED.value,
    }
)


def _dispatch_failure_detail(op_name: str, exc: BaseException) -> str:
    if op_name in _SECRET_DISPATCH_OPS:
        return _MSG_OP_DISPATCH_FAILED
    return f"{type(exc).__name__}: {exc}"
_MSG_READBACK_FAILED = ERROR_CODE_READBACK_FAILED

# Field readiness chain (uplink → … → online). Apply result covers configuration +
# interface admin state only — never the end of this chain.
READINESS_ORDER_CHAIN: tuple[str, ...] = (
    "uplink",
    "dns",
    "captive_portal_cleared",
    "vpn_endpoint_reachable",
    "tunnel_up",
    "route_policy",
    "verified_egress",
    "online",
)

_CONFIGURATION_ACCEPTED = "device_accepted_configuration"
_INTERFACE_PRESENT_UP = "interface_present_up"
_INTERFACE_PRESENT_DOWN = "interface_present_down"
_INTERFACE_NOT_UP = "interface_not_up"
_INTERFACE_ID_MISMATCH = "interface_id_mismatch"
_INTERFACE_ABSENT = "interface_absent"
_INTERFACE_STILL_PRESENT = "interface_still_present"
_INTERFACE_ADDRESS_NOT_CONFIGURED = "interface_address_not_configured"
_ADDRESS_CONFIGURED_UNVERIFIED = "address_configured_unverified"
_ADDRESS_READBACK_CONFIRMED = "address_readback_confirmed"
_TUNNEL_NO_PEER: Literal["tunnel_no_peer"] = "tunnel_no_peer"
_TUNNEL_NEVER_HANDSHAKED: Literal["tunnel_never_handshaked"] = "tunnel_never_handshaked"
_TUNNEL_HEALTHY: Literal["tunnel_healthy"] = "tunnel_healthy"
_TUNNEL_UNVERIFIED: Literal["tunnel_unverified"] = "tunnel_unverified"

TunnelVerificationStatus = Literal[
    "tunnel_no_peer",
    "tunnel_never_handshaked",
    "tunnel_healthy",
    "tunnel_unverified",
]

WG_PEER_LAST_HANDSHAKE_NEVER = 2147483647

_NeverHandshakeSentinelStatus = Literal["never", "timestamp", "unconfirmed", "unknown"]

_INTERFACE_READBACK_KEYS = frozenset(
    {
        "id",
        "interface",
        "state",
        "up",
        "link",
        "type",
        "address",
        "ip_address",
        "ipv4_address",
        "ipv4",
        "ip",
    }
)
_PEER_IDENTITY_KEYS = frozenset({"public_key", "publickey", "key"})
_PEER_OBSERVE_KEYS = frozenset(
    {
        "last_handshake",
        "lasthandshake",
        "online",
        "rxbytes",
        "rx_bytes",
        "txbytes",
        "tx_bytes",
        "enabled",
    }
)


def _normalize_field_key(key: str) -> str:
    return str(key).lower().replace("-", "_")


def _parse_counter(value: Any) -> int | None:
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


def _never_handshake_sentinel_status(value: int | None) -> _NeverHandshakeSentinelStatus:
    """Classify parsed ``last-handshake`` counter.

    Only ``WG_PEER_LAST_HANDSHAKE_NEVER`` (2147483647 / INT_MAX) is the
    device-confirmed never-handshaked sentinel (OPERATOR_AWG_APPLY §3;
    SESSION_HANDOFF §5). Positive non-sentinel integers are elapsed-seconds
    timestamps (device-confirmed e.g. ``28`` on NC-1812). Zero and negative
    values have **no** confirmed firmware semantics — must not infer
    ``tunnel_never_handshaked`` from them.
    """
    if value is None:
        return "unknown"
    if value == WG_PEER_LAST_HANDSHAKE_NEVER:
        return "never"
    if value > 0:
        return "timestamp"
    return "unconfirmed"


def _parse_yes_no(value: Any) -> bool | None:
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


def _interface_readable(observed: dict[str, Any]) -> bool:
    for key in ("id", "interface"):
        value = observed.get(key)
        if value is None:
            continue
        if isinstance(value, dict):
            nested = value.get("id") or value.get("interface")
            if nested is not None and str(nested).strip():
                return True
            continue
        if str(value).strip():
            return True
    return False


def _peer_fields_from_dict(peer_dict: dict[str, Any]) -> dict[str, Any]:
    found: dict[str, Any] = {}
    for key, value in peer_dict.items():
        normalized = _normalize_field_key(key)
        if normalized in _PEER_IDENTITY_KEYS:
            found["peer_public_key"] = value
        elif normalized in {"last_handshake", "lasthandshake"}:
            found["peer_last_handshake"] = value
        elif normalized == "online":
            found["peer_online"] = value
        elif normalized in {"rxbytes", "rx_bytes"}:
            found["peer_rxbytes"] = value
        elif normalized in {"txbytes", "tx_bytes"}:
            found["peer_txbytes"] = value
        elif normalized == "enabled":
            found["peer_enabled"] = value
        elif normalized in {"remote_endpoint", "remoteendpoint"}:
            found["peer_remote_endpoint"] = value
        elif normalized in {"remote_endpoint_address", "remoteendpointaddress"}:
            found.setdefault("peer_remote_endpoint", value)
        elif normalized == "via":
            found["peer_via"] = value
    return found


def _select_peer_dict(
    peers: list[dict[str, Any]],
    *,
    match_public_key: str | None,
) -> dict[str, Any] | None:
    """Multi-peer rule: match configured apply peer public key when >1 peers; else first."""
    if not peers:
        return None
    if match_public_key and len(peers) > 1:
        target = match_public_key.strip()
        for peer in peers:
            fields = _peer_fields_from_dict(peer)
            candidate = fields.get("peer_public_key")
            if candidate is not None and str(candidate).strip() == target:
                return peer
    return peers[0]


def _find_peer_fields(
    obj: Any,
    *,
    match_public_key: str | None = None,
) -> dict[str, Any] | None:
    """Extract peer observe fields from wireguard.peer[] only.

    Interface-level wireguard.public-key is never treated as a peer. When peer[]
    has >1 entries, select the peer whose public-key matches match_public_key
    (configured apply peer) when provided; otherwise select the first peer.
    Empty peer[] → empty dict (no_peer); missing peer container → None.
    """
    if isinstance(obj, dict):
        for key, value in obj.items():
            if _normalize_field_key(key) != "peer":
                continue
            if isinstance(value, list):
                dict_peers = [item for item in value if isinstance(item, dict)]
                if not dict_peers:
                    return {}
                selected = _select_peer_dict(dict_peers, match_public_key=match_public_key)
                if selected is None:
                    return {}
                found = _peer_fields_from_dict(selected)
                return found if found.get("peer_public_key") is not None else {}
            if isinstance(value, dict):
                found = _peer_fields_from_dict(value)
                return found if found.get("peer_public_key") is not None else {}
            return {}
        for value in obj.values():
            nested = _find_peer_fields(value, match_public_key=match_public_key)
            if nested is not None:
                return nested
    elif isinstance(obj, list):
        for item in obj:
            peer = _find_peer_fields(item, match_public_key=match_public_key)
            if peer is not None:
                return peer
    return None


def _collect_tunnel_deceptive_rejections(
    observed: dict[str, Any],
    rejected: list[VerdictRejectedSignal],
) -> None:
    """Record deceptive signals that must not imply tunnel health."""
    if _state_is_up_token(observed.get("state")):
        _append_unique_rejected(
            rejected,
            VerdictRejectedSignal("interface_state", "interface_state_not_evidence"),
        )
    if _state_is_up_token(observed.get("up")):
        _append_unique_rejected(
            rejected,
            VerdictRejectedSignal("interface_up", "interface_up_not_evidence"),
        )
    if observed.get("link") is not None:
        _append_unique_rejected(rejected, VerdictRejectedSignal("link", "link_not_evidence"))
    if observed.get("connected") is not None:
        _append_unique_rejected(
            rejected,
            VerdictRejectedSignal("connected", "connected_not_evidence"),
        )
    enabled = observed.get("peer_enabled")
    if enabled is not None and _parse_yes_no(enabled) is True:
        _append_unique_rejected(
            rejected,
            VerdictRejectedSignal("peer_enabled", "peer_enabled_not_evidence"),
        )
    tx = _parse_counter(observed.get("peer_txbytes"))
    rx = _parse_counter(observed.get("peer_rxbytes"))
    if tx is not None and tx > 0 and (rx is None or rx == 0):
        _append_unique_rejected(
            rejected,
            VerdictRejectedSignal("peer_txbytes", "peer_txbytes_alone_not_evidence"),
        )


def _read_tunnel_signals(
    observed: dict[str, Any],
    readings: list[VerdictSignalReading],
) -> None:
    readings.append(
        VerdictSignalReading("interface_readable", _interface_readable(observed))
    )
    if "state" in observed:
        readings.append(
            VerdictSignalReading("interface_state", normalize_up_down(observed["state"]))
        )
    if "up" in observed:
        readings.append(
            VerdictSignalReading("interface_up", normalize_up_down(observed["up"]))
        )
    if "link" in observed:
        readings.append(VerdictSignalReading("link", normalize_up_down(observed["link"])))
    if "connected" in observed:
        readings.append(
            VerdictSignalReading("connected", normalize_up_down(observed["connected"]))
        )
    peer_key = observed.get("peer_public_key")
    readings.append(
        VerdictSignalReading("peer_public_key", "present" if peer_key is not None else "absent")
    )
    for field, signal_name in (
        ("peer_last_handshake", "peer_last_handshake"),
        ("peer_online", "peer_online"),
        ("peer_rxbytes", "peer_rxbytes"),
        ("peer_txbytes", "peer_txbytes"),
        ("peer_enabled", "peer_enabled"),
    ):
        raw = observed.get(field)
        if raw is None:
            continue
        signal = cast(VerdictSignalCode, signal_name)
        if field in {"peer_last_handshake", "peer_rxbytes", "peer_txbytes"}:
            readings.append(VerdictSignalReading(signal, normalize_counter(raw)))
        else:
            readings.append(VerdictSignalReading(signal, normalize_yes_no(raw)))


def observe_tunnel(observed: dict[str, Any] | None) -> VerdictObservation:
    """Derive tunnel verdict and machine-readable explanation from show-interface peer fields."""

    def _finalize(observation: VerdictObservation) -> VerdictObservation:
        assert_verdict_explanation_invariant(observation.verdict, observation.explanation)
        return assert_verdict_observation(observation)

    readings: list[VerdictSignalReading] = []
    missing: list[VerdictMissingSignalCode] = []
    rejected: list[VerdictRejectedSignal] = []

    if not observed:
        explanation = VerdictExplanation(
            signals_read=tuple(readings),
            signals_missing=("readback",),
            signals_rejected=tuple(rejected),
        )
        observation = VerdictObservation(verdict=_TUNNEL_UNVERIFIED, explanation=explanation)
        return _finalize(observation)
    peer_key = observed.get("peer_public_key")
    if peer_key is None:
        _read_tunnel_signals(observed, readings)
        verdict = _TUNNEL_NO_PEER if _interface_readable(observed) else _TUNNEL_UNVERIFIED
        _append_unique_missing(missing, "peer_public_key")
        if verdict == _TUNNEL_UNVERIFIED:
            _collect_tunnel_deceptive_rejections(observed, rejected)
        explanation = VerdictExplanation(
            signals_read=tuple(readings),
            signals_missing=tuple(missing),
            signals_rejected=tuple(rejected),
        )
        observation = VerdictObservation(verdict=verdict, explanation=explanation)
        return _finalize(observation)

    _read_tunnel_signals(observed, readings)
    last_handshake = _parse_counter(observed.get("peer_last_handshake"))
    online = _parse_yes_no(observed.get("peer_online"))
    rxbytes = _parse_counter(observed.get("peer_rxbytes"))

    if last_handshake is None:
        _append_unique_missing(missing, "peer_last_handshake")
    if online is None:
        _append_unique_missing(missing, "peer_online")
    if rxbytes is None:
        _append_unique_missing(missing, "peer_rxbytes")

    if last_handshake is None or online is None or rxbytes is None:
        _collect_tunnel_deceptive_rejections(observed, rejected)
        explanation = VerdictExplanation(
            signals_read=tuple(readings),
            signals_missing=tuple(missing),
            signals_rejected=tuple(rejected),
        )
        observation = VerdictObservation(verdict=_TUNNEL_UNVERIFIED, explanation=explanation)
        return _finalize(observation)

    handshake_status = _never_handshake_sentinel_status(last_handshake)
    if handshake_status == "unconfirmed":
        _append_unique_missing(missing, "peer_last_handshake")
        _collect_tunnel_deceptive_rejections(observed, rejected)
        explanation = VerdictExplanation(
            signals_read=tuple(readings),
            signals_missing=tuple(missing),
            signals_rejected=tuple(rejected),
        )
        observation = VerdictObservation(verdict=_TUNNEL_UNVERIFIED, explanation=explanation)
        return _finalize(observation)

    if handshake_status == "never":
        _append_unique_missing(missing, "positive_handshake")
        _collect_tunnel_deceptive_rejections(observed, rejected)
        explanation = VerdictExplanation(
            signals_read=tuple(readings),
            signals_missing=tuple(missing),
            signals_rejected=tuple(rejected),
        )
        observation = VerdictObservation(verdict=_TUNNEL_NEVER_HANDSHAKED, explanation=explanation)
        return _finalize(observation)

    if online is True and rxbytes > 0:
        explanation = VerdictExplanation(
            signals_read=tuple(readings),
            signals_missing=tuple(missing),
            signals_rejected=tuple(rejected),
        )
        observation = VerdictObservation(verdict=_TUNNEL_HEALTHY, explanation=explanation)
        return _finalize(observation)

    if online is False and rxbytes <= 0:
        _append_unique_missing(missing, "positive_online")
        _append_unique_missing(missing, "positive_rxbytes")
        _collect_tunnel_deceptive_rejections(observed, rejected)
        explanation = VerdictExplanation(
            signals_read=tuple(readings),
            signals_missing=tuple(missing),
            signals_rejected=tuple(rejected),
        )
        observation = VerdictObservation(verdict=_TUNNEL_NEVER_HANDSHAKED, explanation=explanation)
        return _finalize(observation)
    if online is False or rxbytes <= 0:
        if online is False:
            _append_unique_missing(missing, "positive_online")
        if rxbytes <= 0:
            _append_unique_missing(missing, "positive_rxbytes")
        _collect_tunnel_deceptive_rejections(observed, rejected)
        explanation = VerdictExplanation(
            signals_read=tuple(readings),
            signals_missing=tuple(missing),
            signals_rejected=tuple(rejected),
        )
        observation = VerdictObservation(verdict=_TUNNEL_NEVER_HANDSHAKED, explanation=explanation)
        return _finalize(observation)

    _collect_tunnel_deceptive_rejections(observed, rejected)
    explanation = VerdictExplanation(
        signals_read=tuple(readings),
        signals_missing=tuple(missing),
        signals_rejected=tuple(rejected),
    )
    observation = VerdictObservation(verdict=_TUNNEL_UNVERIFIED, explanation=explanation)
    return _finalize(observation)


def observe_tunnel_health(observed: dict[str, Any] | None) -> TunnelVerificationStatus:
    """Backward-compatible verdict-only wrapper around ``observe_tunnel`` (tests + embed checks)."""
    return cast(TunnelVerificationStatus, observe_tunnel(observed).verdict)


class WireguardApplyServiceError(ValueError):
    """Fail-closed WireGuard apply service error."""


class WireguardApplyTransport(Protocol):
    def execute_sealed_rci_write(self, request: SealedRciWriteRequest) -> Any: ...

    def execute_rci_parse(self, cli_command: str) -> Any: ...


@dataclass(frozen=True, slots=True)
class WireguardApplyStep:
    op: str
    ok: bool
    status_ident: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {"op": self.op, "ok": self.ok}
        if self.status_ident is not None:
            payload["status_ident"] = self.status_ident
        if self.error is not None:
            payload["error"] = self.error
        return payload


@dataclass(frozen=True, slots=True)
class WireguardApplyUncoveredRollbackOp:
    op: str
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {"op": self.op, "reason": self.reason}


@dataclass(frozen=True, slots=True)
class WireguardApplyRollback:
    attempted: bool
    ops: tuple[str, ...]
    outcome: ApplyRollbackOutcome
    steps: tuple[WireguardApplyStep, ...] = ()
    uncovered_ops: tuple[WireguardApplyUncoveredRollbackOp, ...] = ()

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "attempted": self.attempted,
            "ops": list(self.ops),
            "outcome": self.outcome,
        }
        if self.steps:
            payload["steps"] = [step.to_dict() for step in self.steps]
        if self.uncovered_ops:
            payload["uncovered_ops"] = [item.to_dict() for item in self.uncovered_ops]
        return payload


@dataclass(frozen=True, slots=True)
class WireguardApplyVerification:
    id_ok: bool
    up_ok: bool
    observed: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        return {
            "id_ok": self.id_ok,
            "up_ok": self.up_ok,
            "observed": self.observed,
        }


@dataclass(frozen=True, slots=True)
class WireguardApplyResult:
    overall: ApplyOverallStatus
    wg_id: str
    steps: tuple[WireguardApplyStep, ...]
    verification: WireguardApplyVerification | None
    errors: tuple[str, ...]
    logs: tuple[str, ...]
    verification_status: str | None = None
    verification_notes: tuple[str, ...] = ()
    backup_basename: str | None = None
    backup_content_sha256: str | None = None
    configuration_verification_status: str | None = None
    interface_verification_status: str | None = None
    interface_address_verification_status: str | None = None
    tunnel_verification_status: str = _TUNNEL_UNVERIFIED
    verdict_explanation: VerdictExplanation | None = None
    rollback: WireguardApplyRollback | None = None
    rollback_errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "overall": self.overall,
            "wg_id": self.wg_id,
            "steps": [step.to_dict() for step in self.steps],
            "errors": list(self.errors),
            "rollback_errors": list(self.rollback_errors),
            "logs": list(self.logs),
            "tunnel_verification_status": self.tunnel_verification_status,
        }
        if self.verdict_explanation is not None:
            payload["verdict_explanation"] = self.verdict_explanation.to_dict()
        if self.configuration_verification_status is not None:
            payload["configuration_verification_status"] = self.configuration_verification_status
        if self.interface_verification_status is not None:
            payload["interface_verification_status"] = self.interface_verification_status
        if self.interface_address_verification_status is not None:
            payload["interface_address_verification_status"] = (
                self.interface_address_verification_status
            )
        if self.verification_status is not None:
            payload["verification_status"] = self.verification_status
        if self.verification_notes:
            payload["verification_notes"] = list(self.verification_notes)
        if self.verification is not None:
            payload["verification"] = self.verification.to_dict()
        if self.backup_basename is not None:
            payload["backup_basename"] = self.backup_basename
        if self.backup_content_sha256 is not None:
            payload["backup_content_sha256"] = self.backup_content_sha256
        if self.rollback is not None:
            payload["rollback"] = self.rollback.to_dict()
        return validate_wireguard_apply_payload(payload)


def _op_to_preview_dict(op: WireguardSealedOpDescriptor) -> dict[str, object]:
    payload: dict[str, object] = {"operation": op.operation, "wg_id": op.wg_id}
    if op.asc_args is not None:
        payload["asc_args"] = op.asc_args
    if op.credential_ref_id is not None:
        payload["credential_ref_id"] = op.credential_ref_id
    if op.peer_public_key is not None:
        payload["peer_public_key"] = op.peer_public_key
    if op.peer_endpoint is not None:
        payload["peer_endpoint"] = op.peer_endpoint
    if op.peer_allow_ips is not None:
        payload["peer_allow_ips"] = op.peer_allow_ips
    if op.peer_keepalive_interval is not None:
        payload["peer_keepalive_interval"] = op.peer_keepalive_interval
    if op.peer_rci_shape is not None:
        payload["peer_rci_shape"] = op.peer_rci_shape
    if op.ipv4_address is not None:
        payload["ipv4_address"] = op.ipv4_address
    if op.ipv4_mask is not None:
        payload["ipv4_mask"] = op.ipv4_mask
    if op.global_auto:
        payload["global_auto"] = True
    if op.global_order is not None:
        payload["global_order"] = op.global_order
    if op.global_priority is not None:
        payload["global_priority"] = op.global_priority
    if op.notes:
        payload["notes"] = list(op.notes)
    return payload


def plan_to_preview_dict(plan: WireguardApplyPlan) -> dict[str, object]:
    return {
        "wg_id": plan.wg_id,
        "verification_status": plan.verification_status,
        "notes": list(plan.notes),
        "apply_ops": [_op_to_preview_dict(op) for op in plan.apply_ops],
        "teardown_ops": [_op_to_preview_dict(op) for op in plan.teardown_ops],
    }


def preview_wireguard_apply(intent: WireguardIntent, wg_id: str | None = None) -> dict[str, object]:
    """Validate + compile only; no dispatch."""
    plan = _compile_plan(intent, wg_id)
    return plan_to_preview_dict(plan)


def _status_ident(result: WireguardRciResult | InterfaceRciResult) -> str | None:
    if not result.status_entries:
        return None
    return result.status_entries[0].ident


def _step_from_result(
    op_name: str,
    result: WireguardRciResult | InterfaceRciResult,
) -> WireguardApplyStep:
    return WireguardApplyStep(op=op_name, ok=True, status_ident=_status_ident(result))


def _step_from_error(op_name: str, message: str) -> WireguardApplyStep:
    return WireguardApplyStep(op=op_name, ok=False, error=message)


def _compile_plan(intent: WireguardIntent, wg_id: str | None) -> WireguardApplyPlan:
    try:
        return compile_wireguard_intent_to_ops(intent, wg_id=wg_id)
    except (WireguardApplyPlannerError, ValueError) as exc:
        raise WireguardApplyServiceError(str(exc)) from exc


def _validate_wg_id(wg_id: str) -> str:
    try:
        return validate_wireguard_id(wg_id)
    except ValueError as exc:
        raise WireguardApplyServiceError(str(exc)) from exc


def _readback_show_interface(
    transport: WireguardApplyTransport,
    wg_id: str,
    *,
    match_peer_public_key: str | None = None,
) -> dict[str, Any]:
    command = f"show interface {wg_id}"
    raw = transport.execute_rci_parse(command)
    return _extract_show_interface_observed(raw, match_peer_public_key=match_peer_public_key)


def _extract_show_interface_observed(
    raw: Any,
    *,
    match_peer_public_key: str | None = None,
) -> dict[str, Any]:
    interface_fields = _extract_interface_fields(raw)
    peer_fields = _find_peer_fields(raw, match_public_key=match_peer_public_key) or {}
    return {**interface_fields, **peer_fields}


def _extract_interface_fields(raw: Any) -> dict[str, Any]:
    keys = _INTERFACE_READBACK_KEYS
    found = _walk_for_keys(raw, keys)
    return {key: found[key] for key in sorted(found)}


def _walk_for_keys(obj: Any, keys: frozenset[str]) -> dict[str, Any]:
    found: dict[str, Any] = {}
    if isinstance(obj, dict):
        for key, value in obj.items():
            normalized = str(key).lower().replace("-", "_")
            if normalized in keys and normalized not in found:
                found[normalized] = value
            child = _walk_for_keys(value, keys)
            for child_key, child_value in child.items():
                found.setdefault(child_key, child_value)
    elif isinstance(obj, list):
        for item in obj:
            child = _walk_for_keys(item, keys)
            for child_key, child_value in child.items():
                found.setdefault(child_key, child_value)
    return found


def _sanitize_observed(observed: dict[str, Any]) -> dict[str, object]:
    sanitized = sanitize_mapping(dict(observed))
    return {str(key): value for key, value in sanitized.items()}


def _state_is_up(state: Any) -> bool:
    if isinstance(state, bool):
        return state
    if state is None:
        return False
    text = str(state).strip().lower()
    return text in {"up", "enabled", "true", "1"}


def _state_is_down(state: Any) -> bool:
    if isinstance(state, bool):
        return not state
    if state is None:
        return True
    text = str(state).strip().lower()
    return text in {"down", "disabled", "false", "0", ""}


def _interface_id_present(observed: dict[str, Any], wg_id: str) -> bool:
    for key in ("id", "interface"):
        value = observed.get(key)
        if value is None:
            continue
        if isinstance(value, dict):
            nested = value.get("id") or value.get("interface")
            if nested is not None and str(nested).strip() == wg_id:
                return True
            continue
        if str(value).strip() == wg_id:
            return True
    return False


def _interface_absent(observed: dict[str, Any], wg_id: str) -> bool:
    if not observed:
        return True
    for key in ("id", "interface"):
        value = observed.get(key)
        if value is not None and str(value).strip() == wg_id:
            return False
    return not _interface_id_present(observed, wg_id)


def _verify_applied(
    observed: dict[str, Any],
    *,
    wg_id: str,
    enabled: bool,
) -> WireguardApplyVerification:
    sanitized = _sanitize_observed(observed)
    id_ok = _interface_id_present(observed, wg_id)
    if enabled:
        up_ok = _state_is_up(observed.get("state")) or _state_is_up(observed.get("up"))
    else:
        up_ok = _state_is_down(observed.get("state")) and _state_is_down(observed.get("up"))
    return WireguardApplyVerification(id_ok=id_ok, up_ok=up_ok, observed=sanitized)


def _verify_teardown(observed: dict[str, Any], *, wg_id: str) -> WireguardApplyVerification:
    sanitized = _sanitize_observed(observed)
    id_ok = _interface_absent(observed, wg_id)
    up_ok = _state_is_down(observed.get("state")) and _state_is_down(observed.get("up"))
    return WireguardApplyVerification(id_ok=id_ok, up_ok=up_ok, observed=sanitized)


def _interface_is_admin_up(observed: dict[str, object]) -> bool:
    return _state_is_up(observed.get("state")) or _state_is_up(observed.get("up"))


def _interface_verification_status_apply(
    verification: WireguardApplyVerification,
    *,
    enabled: bool,
) -> str:
    if not verification.id_ok:
        return _INTERFACE_ID_MISMATCH
    if _interface_is_admin_up(verification.observed):
        return _INTERFACE_PRESENT_UP
    if enabled:
        return _INTERFACE_NOT_UP
    return _INTERFACE_PRESENT_DOWN


def _interface_verification_status_teardown(verification: WireguardApplyVerification) -> str:
    if verification.id_ok and verification.up_ok:
        return _INTERFACE_ABSENT
    if not verification.id_ok:
        return _INTERFACE_STILL_PRESENT
    return _INTERFACE_NOT_UP


def _teardown_failed_steps_are_clear_private_key_only(
    steps: tuple[WireguardApplyStep, ...],
) -> bool:
    failed = [step for step in steps if not step.ok]
    return bool(failed) and all(
        step.op == WireguardRciOperation.CLEAR_PRIVATE_KEY.value for step in failed
    )


def _teardown_overall(
    *,
    steps: tuple[WireguardApplyStep, ...],
    verification: WireguardApplyVerification,
    dispatch_errors: tuple[str, ...],
) -> ApplyOverallStatus:
    if verification.id_ok and verification.up_ok:
        if dispatch_errors and not _teardown_failed_steps_are_clear_private_key_only(steps):
            return "failed"
        return "applied"
    if dispatch_errors:
        return "failed"
    return "verify_mismatch"


def _cap_tunnel_verdict_without_settle(
    tunnel_status: TunnelVerificationStatus,
    observation: VerdictObservation,
    *,
    handshake_settle_seconds: float,
) -> tuple[TunnelVerificationStatus, VerdictExplanation]:
    """Without performed settle wait, never_handshaked may be a false negative."""
    if handshake_settle_seconds > 0 or tunnel_status != _TUNNEL_NEVER_HANDSHAKED:
        return tunnel_status, observation.explanation
    missing = list(observation.explanation.signals_missing)
    _append_unique_missing(missing, "positive_handshake")
    explanation = VerdictExplanation(
        signals_read=observation.explanation.signals_read,
        signals_missing=tuple(missing),
        signals_rejected=observation.explanation.signals_rejected,
    )
    return _TUNNEL_UNVERIFIED, explanation


def _observe_tunnel_with_optional_recheck(
    transport: WireguardApplyTransport,
    *,
    wg_id: str,
    observed: dict[str, Any],
    handshake_settle_seconds: float,
    logs: list[str],
    match_peer_public_key: str | None = None,
    trail: SealedApplyTrailHandle | None = None,
) -> tuple[TunnelVerificationStatus, dict[str, Any], VerdictExplanation]:
    observation = observe_tunnel(observed)
    tunnel_status: TunnelVerificationStatus = observation.verdict  # type: ignore[assignment]
    final_observed = observed
    needs_recheck = tunnel_status == _TUNNEL_NEVER_HANDSHAKED or (
        tunnel_status == _TUNNEL_UNVERIFIED
        and _never_handshake_sentinel_status(
            _parse_counter(observed.get("peer_last_handshake"))
        )
        == "unconfirmed"
        and _parse_yes_no(observed.get("peer_online")) is not None
        and _parse_counter(observed.get("peer_rxbytes")) is not None
    )
    if handshake_settle_seconds <= 0 or not needs_recheck:
        capped_status, capped_explanation = _cap_tunnel_verdict_without_settle(
            tunnel_status,
            observation,
            handshake_settle_seconds=handshake_settle_seconds,
        )
        return capped_status, final_observed, capped_explanation

    if tunnel_status == _TUNNEL_NEVER_HANDSHAKED:
        logs.append(
            "tunnel_never_handshaked after first readback; "
            f"bounded handshake settle wait {handshake_settle_seconds}s before one recheck "
            f"(recommended band {WG_HANDSHAKE_SETTLE_SECONDS_MIN}-"
            f"{WG_HANDSHAKE_SETTLE_SECONDS_MAX}s)"
        )
    else:
        logs.append(
            "tunnel_unverified after first readback (ambiguous last-handshake); "
            f"bounded handshake settle wait {handshake_settle_seconds}s before one recheck "
            f"(recommended band {WG_HANDSHAKE_SETTLE_SECONDS_MIN}-"
            f"{WG_HANDSHAKE_SETTLE_SECONDS_MAX}s)"
        )
    sleep_preserving_sealed_apply_lease(
        trail, handshake_settle_seconds, time.sleep
    )
    try:
        recheck_observed = _readback_show_interface(
            transport,
            wg_id,
            match_peer_public_key=match_peer_public_key,
        )
    except Exception:
        logs.append("tunnel handshake recheck readback failed; keeping initial verdict")
        return tunnel_status, final_observed, observation.explanation

    recheck_observation = observe_tunnel(recheck_observed)
    recheck_status: TunnelVerificationStatus = recheck_observation.verdict  # type: ignore[assignment]
    if recheck_status != tunnel_status:
        logs.append(
            f"tunnel handshake recheck verdict: {tunnel_status} -> {recheck_status}"
        )
    else:
        logs.append(f"tunnel handshake recheck unchanged: {tunnel_status}")
    capped_status, capped_explanation = _cap_tunnel_verdict_without_settle(
        recheck_status,
        recheck_observation,
        handshake_settle_seconds=handshake_settle_seconds,
    )
    return capped_status, recheck_observed, capped_explanation


def _assemble_apply_result(
    *,
    overall: ApplyOverallStatus,
    wg_id: str,
    steps: tuple[WireguardApplyStep, ...],
    verification: WireguardApplyVerification | None,
    errors: tuple[str, ...],
    logs: tuple[str, ...],
    verification_status: str | None = None,
    verification_notes: tuple[str, ...] = (),
    backup_basename: str | None = None,
    backup_content_sha256: str | None = None,
    dispatch_ok: bool = False,
    is_teardown: bool = False,
    enabled: bool = True,
    tunnel_verification_status: TunnelVerificationStatus = _TUNNEL_UNVERIFIED,
    interface_address_verification_status: str | None = None,
    verdict_explanation: VerdictExplanation | None = None,
    rollback: WireguardApplyRollback | None = None,
    rollback_errors: tuple[str, ...] = (),
) -> WireguardApplyResult:
    configuration_status = _CONFIGURATION_ACCEPTED if dispatch_ok else None
    interface_status: str | None = None
    address_status = interface_address_verification_status
    if verification is not None:
        if is_teardown:
            interface_status = _interface_verification_status_teardown(verification)
        else:
            interface_status = _interface_verification_status_apply(verification, enabled=enabled)
    if not is_teardown and dispatch_ok and address_status is None:
        address_status = _INTERFACE_ADDRESS_NOT_CONFIGURED
    resolved_explanation = verdict_explanation
    if resolved_explanation is None:
        resolved_explanation = explanation_for_skipped_observe(tunnel_verification_status)
    return WireguardApplyResult(
        overall=overall,
        wg_id=wg_id,
        steps=steps,
        verification=verification,
        errors=errors,
        logs=logs,
        verification_status=verification_status,
        verification_notes=verification_notes,
        backup_basename=backup_basename,
        backup_content_sha256=backup_content_sha256,
        configuration_verification_status=configuration_status,
        interface_verification_status=interface_status,
        interface_address_verification_status=address_status,
        tunnel_verification_status=tunnel_verification_status,
        verdict_explanation=resolved_explanation,
        rollback=rollback,
        rollback_errors=rollback_errors,
    )


def _parse_observed_ipv4_address(value: Any) -> tuple[str, str] | None:
    if value is None:
        return None
    if isinstance(value, dict):
        addr = value.get("address") or value.get("ipv4") or value.get("ip")
        mask = value.get("mask") or value.get("netmask")
        if addr is not None and mask is not None:
            return str(addr).strip(), str(mask).strip()
        return None
    text = str(value).strip()
    if not text:
        return None
    if "/" in text:
        try:
            return parse_interface_address_cidr(text)
        except WireguardRciError:
            return None
    parts = text.split()
    if len(parts) == 2:
        return parts[0].strip(), parts[1].strip()
    return None


def _parse_observed_interface_address(observed: dict[str, Any]) -> tuple[str, str] | None:
    for key in ("address", "ip_address", "ipv4_address", "ipv4", "ip"):
        if key not in observed:
            continue
        parsed = _parse_observed_ipv4_address(observed[key])
        if parsed is not None:
            return parsed
    return None


def _resolve_interface_address_verification_status(
    intent: WireguardIntent,
    observed: dict[str, Any],
    *,
    address_planned: bool,
) -> str | None:
    if not address_planned:
        return None
    if not intent.interface_address:
        return _INTERFACE_ADDRESS_NOT_CONFIGURED
    parsed = _parse_observed_interface_address(observed)
    if parsed is None:
        return _ADDRESS_CONFIGURED_UNVERIFIED
    try:
        expected_addr, expected_mask = parse_interface_address_cidr(intent.interface_address)
    except WireguardRciError:
        return _ADDRESS_CONFIGURED_UNVERIFIED
    observed_addr, observed_mask = parsed
    if observed_addr == expected_addr and observed_mask == expected_mask:
        return _ADDRESS_READBACK_CONFIRMED
    return _ADDRESS_CONFIGURED_UNVERIFIED


def _dispatch_single_op(
    transport: WireguardApplyTransport,
    descriptor: WireguardSealedOpDescriptor,
    *,
    secret: str | None = None,
) -> WireguardRciResult | InterfaceRciResult:
    op_name = descriptor.operation
    wg_id = validate_wireguard_id(descriptor.wg_id)
    if op_name == WireguardRciOperation.CREATE_INTERFACE.value:
        return execute_wireguard_rci(transport, WireguardRciOperation.CREATE_INTERFACE, wg_id)
    if op_name == WireguardRciOperation.REMOVE_INTERFACE.value:
        return execute_wireguard_rci(transport, WireguardRciOperation.REMOVE_INTERFACE, wg_id)
    if op_name == WireguardRciOperation.SET_ASC.value:
        if descriptor.asc_args is None:
            raise WireguardRciError("asc_args is required for SET_ASC")
        return execute_wireguard_rci(
            transport,
            WireguardRciOperation.SET_ASC,
            wg_id,
            asc_args=descriptor.asc_args,
        )
    if op_name == WireguardRciOperation.SET_PRIVATE_KEY.value:
        if secret is None:
            raise WireguardRciError("secret is required for SET_PRIVATE_KEY")
        return execute_wireguard_rci(
            transport,
            WireguardRciOperation.SET_PRIVATE_KEY,
            wg_id,
            secret=secret,
        )
    if op_name == WireguardRciOperation.CLEAR_PRIVATE_KEY.value:
        return execute_wireguard_rci(transport, WireguardRciOperation.CLEAR_PRIVATE_KEY, wg_id)
    if op_name == WireguardRciOperation.ADD_PEER.value:
        if descriptor.peer_public_key is None:
            raise WireguardRciError("peer_public_key is required for ADD_PEER")
        return execute_wireguard_rci(
            transport,
            WireguardRciOperation.ADD_PEER,
            wg_id,
            peer_public_key=descriptor.peer_public_key,
        )
    if op_name == WireguardRciOperation.SET_PEER_ENDPOINT.value:
        if descriptor.peer_public_key is None or descriptor.peer_endpoint is None:
            raise WireguardRciError(
                "peer_public_key and peer_endpoint required for SET_PEER_ENDPOINT"
            )
        return execute_wireguard_rci(
            transport,
            WireguardRciOperation.SET_PEER_ENDPOINT,
            wg_id,
            peer_public_key=descriptor.peer_public_key,
            endpoint=descriptor.peer_endpoint,
        )
    if op_name == WireguardRciOperation.SET_PEER_ALLOW_IPS.value:
        if descriptor.peer_public_key is None or descriptor.peer_allow_ips is None:
            raise WireguardRciError(
                "peer_public_key and peer_allow_ips required for SET_PEER_ALLOW_IPS"
            )
        return execute_wireguard_rci(
            transport,
            WireguardRciOperation.SET_PEER_ALLOW_IPS,
            wg_id,
            peer_public_key=descriptor.peer_public_key,
            allow_ips=descriptor.peer_allow_ips,
        )
    if op_name == WireguardRciOperation.SET_PEER_KEEPALIVE.value:
        if (
            descriptor.peer_public_key is None
            or descriptor.peer_keepalive_interval is None
        ):
            raise WireguardRciError(
                "peer_public_key and peer_keepalive_interval required for SET_PEER_KEEPALIVE"
            )
        return execute_wireguard_rci(
            transport,
            WireguardRciOperation.SET_PEER_KEEPALIVE,
            wg_id,
            peer_public_key=descriptor.peer_public_key,
            keepalive_interval=descriptor.peer_keepalive_interval,
        )
    if op_name == WireguardRciOperation.REMOVE_PEER.value:
        if descriptor.peer_public_key is None:
            raise WireguardRciError("peer_public_key is required for REMOVE_PEER")
        return execute_wireguard_rci(
            transport,
            WireguardRciOperation.REMOVE_PEER,
            wg_id,
            peer_public_key=descriptor.peer_public_key,
        )
    if op_name == WireguardRciOperation.SET_PRESHARED_KEY.value:
        if secret is None or descriptor.peer_public_key is None:
            raise WireguardRciError("secret and peer_public_key required for SET_PRESHARED_KEY")
        return execute_wireguard_rci(
            transport,
            WireguardRciOperation.SET_PRESHARED_KEY,
            wg_id,
            secret=secret,
            peer_public_key=descriptor.peer_public_key,
        )
    if op_name == WireguardRciOperation.CLEAR_PRESHARED_KEY.value:
        if descriptor.peer_public_key is None:
            raise WireguardRciError("peer_public_key is required for CLEAR_PRESHARED_KEY")
        return execute_wireguard_rci(
            transport,
            WireguardRciOperation.CLEAR_PRESHARED_KEY,
            wg_id,
            peer_public_key=descriptor.peer_public_key,
        )
    if op_name == WireguardRciOperation.UPSERT_PEER_NESTED.value:
        if descriptor.peer_public_key is None:
            raise WireguardRciError("peer_public_key is required for UPSERT_PEER_NESTED")
        return execute_wireguard_nested_peer_rci(
            transport,
            wg_id,
            descriptor.peer_public_key,
            endpoint=descriptor.peer_endpoint,
            allow_ips=descriptor.peer_allow_ips,
            keepalive_interval=descriptor.peer_keepalive_interval,
            preshared_key=secret,
        )
    if op_name == WireguardRciOperation.SET_IP_ADDRESS.value:
        if descriptor.ipv4_address is None or descriptor.ipv4_mask is None:
            raise WireguardRciError("ipv4_address and ipv4_mask required for SET_IP_ADDRESS")
        return execute_wireguard_rci(
            transport,
            WireguardRciOperation.SET_IP_ADDRESS,
            wg_id,
            ipv4_address=descriptor.ipv4_address,
            ipv4_mask=descriptor.ipv4_mask,
        )
    if op_name == WireguardRciOperation.CLEAR_IP_ADDRESS.value:
        return execute_wireguard_rci(transport, WireguardRciOperation.CLEAR_IP_ADDRESS, wg_id)
    if op_name == WireguardRciOperation.IP_GLOBAL.value:
        return execute_wireguard_rci(
            transport,
            WireguardRciOperation.IP_GLOBAL,
            wg_id,
            global_auto=descriptor.global_auto,
            global_order=descriptor.global_order,
            global_priority=descriptor.global_priority,
        )
    if op_name == WireguardRciOperation.CLEAR_IP_GLOBAL.value:
        return execute_wireguard_rci(transport, WireguardRciOperation.CLEAR_IP_GLOBAL, wg_id)
    if op_name == WireguardRciOperation.SET_TCP_MSS.value:
        return execute_wireguard_rci(transport, WireguardRciOperation.SET_TCP_MSS, wg_id)
    if op_name == WireguardRciOperation.CLEAR_TCP_MSS.value:
        return execute_wireguard_rci(transport, WireguardRciOperation.CLEAR_TCP_MSS, wg_id)
    if op_name == InterfaceRciOperation.UP.value:
        return execute_interface_rci(transport, InterfaceRciOperation.UP, wg_id)
    if op_name == InterfaceRciOperation.DOWN.value:
        return execute_interface_rci(transport, InterfaceRciOperation.DOWN, wg_id)
    raise WireguardApplyServiceError(ERROR_CODE_UNSUPPORTED_OPERATION)


def _dispatch_ops(
    *,
    transport: WireguardApplyTransport,
    ops: tuple[WireguardSealedOpDescriptor, ...],
    credential_resolver: CredentialResolver,
    logs: list[str],
    continue_on_error: bool = False,
    trail: SealedApplyTrailHandle | None = None,
) -> tuple[tuple[WireguardApplyStep, ...], tuple[str, ...]]:
    steps: list[WireguardApplyStep] = []
    errors: list[str] = []
    for descriptor in ops:
        op_name = descriptor.operation
        secret: str | None = None
        if op_name in (
            WireguardRciOperation.SET_PRIVATE_KEY.value,
            WireguardRciOperation.SET_PRESHARED_KEY.value,
        ):
            if not descriptor.credential_ref_id:
                message = ERROR_CODE_CREDENTIAL_REF_REQUIRED
                steps.append(_step_from_error(op_name, message))
                errors.append(message)
                logs.append(f"dispatch failed for {op_name}: {message}")
                if not continue_on_error:
                    return tuple(steps), tuple(errors)
                continue
            try:
                secret = credential_resolver(descriptor.credential_ref_id)
            except Exception:
                steps.append(_step_from_error(op_name, _MSG_CREDENTIAL_RESOLUTION_FAILED))
                errors.append(_MSG_CREDENTIAL_RESOLUTION_FAILED)
                logs.append(f"dispatch failed for {op_name}: credential resolution failed")
                if not continue_on_error:
                    return tuple(steps), tuple(errors)
                continue
            logs.append(f"dispatched {op_name} with credential_ref (secret not logged)")
        elif (
            op_name == WireguardRciOperation.UPSERT_PEER_NESTED.value
            and descriptor.credential_ref_id
        ):
            try:
                secret = credential_resolver(descriptor.credential_ref_id)
            except Exception:
                steps.append(_step_from_error(op_name, _MSG_CREDENTIAL_RESOLUTION_FAILED))
                errors.append(_MSG_CREDENTIAL_RESOLUTION_FAILED)
                logs.append(f"dispatch failed for {op_name}: credential resolution failed")
                if not continue_on_error:
                    return tuple(steps), tuple(errors)
                continue
            logs.append(f"dispatched {op_name} with credential_ref (secret not logged)")

        intent_recorded = False
        if trail is not None:
            trail.record_op_intent(op_name)
            intent_recorded = True

        try:
            result = _dispatch_single_op(transport, descriptor, secret=secret)
        except (WireguardRciError, InterfaceRciError) as exc:
            failure_detail = _dispatch_failure_detail(op_name, exc)
            failure_step = _step_from_error(op_name, failure_detail)
            if intent_recorded and trail is not None:
                trail.record_op_failure(
                    op_name,
                    op_evidence_redacted=build_sealed_apply_op_evidence(failure_step),
                )
            steps.append(failure_step)
            errors.append(failure_detail)
            logs.append(f"dispatch failed for {op_name}: {failure_detail}")
            if not continue_on_error:
                return tuple(steps), tuple(errors)
            continue
        except Exception as exc:
            failure_detail = _dispatch_failure_detail(op_name, exc)
            failure_step = _step_from_error(op_name, failure_detail)
            if intent_recorded and trail is not None:
                trail.record_op_failure(
                    op_name,
                    op_evidence_redacted=build_sealed_apply_op_evidence(failure_step),
                )
            steps.append(failure_step)
            errors.append(failure_detail)
            logs.append(f"dispatch failed for {op_name}: {failure_detail}")
            if not continue_on_error:
                return tuple(steps), tuple(errors)
            continue
        logs.append(f"ack matched for {op_name}")
        success_step = _step_from_result(op_name, result)
        steps.append(success_step)
        if trail is not None:
            trail.record_op(
                op_name,
                op_evidence_redacted=build_sealed_apply_op_evidence(
                    success_step,
                    device_ack=redact_sealed_apply_device_ack(result),
                ),
            )
    return tuple(steps), tuple(errors)


def _rollback_not_attempted() -> WireguardApplyRollback:
    return WireguardApplyRollback(attempted=False, ops=(), outcome="not_attempted")


def _rollback_noop() -> WireguardApplyRollback:
    return WireguardApplyRollback(attempted=True, ops=(), outcome="noop")


def _finalize_rollback_outcome(
    *,
    rollback_steps: tuple[WireguardApplyStep, ...],
    rollback_errors: tuple[str, ...],
    uncovered_ops: tuple[WireguardApplyUncoveredRollbackOp, ...],
) -> ApplyRollbackOutcome:
    if rollback_errors:
        if all(step.ok for step in rollback_steps):
            outcome: ApplyRollbackOutcome = "failed"
        elif any(step.ok for step in rollback_steps):
            outcome = "partial"
        else:
            outcome = "failed"
    elif all(step.ok for step in rollback_steps):
        outcome = "succeeded"
    elif any(step.ok for step in rollback_steps):
        outcome = "partial"
    elif rollback_steps:
        outcome = "failed"
    else:
        outcome = "noop"
    if uncovered_ops and outcome == "succeeded":
        return "partial"
    if uncovered_ops and outcome == "noop":
        return "partial"
    return outcome


def _attempt_compensating_rollback(
    *,
    transport: WireguardApplyTransport,
    apply_ops: tuple[WireguardSealedOpDescriptor, ...],
    succeeded_op_names: tuple[str, ...],
    credential_resolver: CredentialResolver,
    logs: list[str],
    pre_state: WireguardApplyPreState | None = None,
) -> tuple[WireguardApplyRollback, tuple[str, ...]]:
    uncovered_pairs = uncovered_compensate_ops_for_succeeded_wireguard_apply(
        apply_ops, succeeded_op_names, pre_state=pre_state
    )
    uncovered_ops = tuple(
        WireguardApplyUncoveredRollbackOp(op=op_name, reason=reason)
        for op_name, reason in uncovered_pairs
    )
    for item in uncovered_ops:
        logs.append(f"compensate uncovered {item.op}: {item.reason}")
    compensate_ops = compensate_ops_for_succeeded_wireguard_apply(
        apply_ops, succeeded_op_names, pre_state=pre_state
    )
    if not compensate_ops and not uncovered_ops:
        return _rollback_noop(), ()
    if not compensate_ops:
        return (
            WireguardApplyRollback(
                attempted=True,
                ops=(),
                outcome="partial",
                uncovered_ops=uncovered_ops,
            ),
            (),
        )
    op_names = tuple(op.operation for op in compensate_ops)
    logs.append(f"compensating rollback for {len(compensate_ops)} ops")
    rollback_steps, rollback_errors = _dispatch_ops(
        transport=transport,
        ops=compensate_ops,
        credential_resolver=credential_resolver,
        logs=logs,
        continue_on_error=True,
    )
    if rollback_errors:
        for note in rollback_errors:
            logs.append(f"rollback note: {note}")
    outcome = _finalize_rollback_outcome(
        rollback_steps=rollback_steps,
        rollback_errors=rollback_errors,
        uncovered_ops=uncovered_ops,
    )
    return (
        WireguardApplyRollback(
            attempted=True,
            ops=op_names,
            outcome=outcome,
            steps=rollback_steps,
            uncovered_ops=uncovered_ops,
        ),
        rollback_errors,
    )


def _finalize_overall_with_rollback(
    base_overall: ApplyOverallStatus,
    *,
    rollback: WireguardApplyRollback | None,
) -> ApplyOverallStatus:
    if base_overall in {"failed", "verify_mismatch"} and rollback is not None:
        if rollback.outcome == "succeeded":
            return "rolled_back"
    return base_overall


def apply_wireguard_intent(
    *,
    intent: WireguardIntent,
    transport: WireguardApplyTransport,
    credential_resolver: CredentialResolver,
    wg_id: str | None = None,
    backup_callback: BackupCallback | None = None,
    handshake_settle_seconds: float = 0,
    compensate_on_failure: bool = True,
    store: Any | None = None,
    sealed_apply_params: SealedApplyTrailParams | None = None,
) -> WireguardApplyResult:
    normalized_wg = _validate_wg_id(wg_id or intent.wg_id)
    settled_seconds = clamp_handshake_settle_seconds(handshake_settle_seconds)
    plan = _compile_plan(intent, normalized_wg)

    if plan.verification_status == "unsupported_pending_verification":
        return _assemble_apply_result(
            overall="unsupported_pending_verification",
            wg_id=plan.wg_id,
            steps=(),
            verification=None,
            errors=tuple(plan.notes),
            logs=("ASC mode not device-verified; dispatch skipped",),
            verification_status=plan.verification_status,
            verification_notes=plan.notes,
            rollback=_rollback_not_attempted(),
        )

    if not plan.apply_ops:
        message = ERROR_CODE_NO_APPLY_OPS
        return _assemble_apply_result(
            overall="failed",
            wg_id=plan.wg_id,
            steps=(),
            verification=None,
            errors=(message,),
            logs=(message,),
            verification_status=plan.verification_status,
            verification_notes=plan.notes,
            rollback=_rollback_not_attempted(),
        )

    logs: list[str] = [f"compiled {len(plan.apply_ops)} apply ops for {plan.wg_id}"]
    if backup_callback is not None:
        backup_callback()
        logs.append("backup_callback invoked")

    pre_state: WireguardApplyPreState | None
    pre_observed: dict[str, Any] | None = None
    if compensate_on_failure:
        try:
            pre_observed = execute_pre_apply_read(
                transport,
                lambda: _readback_show_interface(
                    transport,
                    plan.wg_id,
                    match_peer_public_key=intent.peer_public_key,
                ),
            )
            pre_state = derive_wireguard_pre_state(pre_observed, wg_id=plan.wg_id)
            logs.append("pre_apply baseline read completed")
        except Exception:
            pre_state = WireguardApplyPreState(known=False)
            logs.append("pre_apply baseline read failed; compensation fail-closed")
    else:
        pre_state = None

    planned_op_names = tuple(op.operation for op in plan.apply_ops)
    trail = begin_sealed_apply_trail(
        store,
        params=sealed_apply_params,
        ops_planned=planned_op_names,
    )
    if trail is not None and pre_state is not None:
        try:
            trail.record_pre_apply_baseline(
                serialize_pre_apply_baseline_for_trail(
                    pre_state,
                    observed=pre_observed,
                )
            )
        except Exception:
            logs.append("sealed_apply pre_apply baseline trail write failed")

    def _run() -> WireguardApplyResult:
        steps, dispatch_errors = _dispatch_ops(
            transport=transport,
            ops=plan.apply_ops,
            credential_resolver=credential_resolver,
            logs=logs,
            trail=trail,
        )
        succeeded_op_names = tuple(step.op for step in steps if step.ok)

        def _finish_and_return(result: WireguardApplyResult) -> WireguardApplyResult:
            finish_sealed_apply_trail(
                trail,
                overall=result.overall,
                outcome_snapshot=outcome_snapshot_from_apply_result(result),
            )
            return result

        def _build_failure_result(
            overall: ApplyOverallStatus,
            *,
            verification: WireguardApplyVerification | None = None,
            extra_errors: tuple[str, ...] = (),
            dispatch_ok: bool = False,
            enabled: bool = True,
            tunnel_verification_status: TunnelVerificationStatus = _TUNNEL_UNVERIFIED,
            interface_address_verification_status: str | None = None,
            verdict_explanation: VerdictExplanation | None = None,
        ) -> WireguardApplyResult:
            rollback: WireguardApplyRollback | None
            rollback_errors: tuple[str, ...] = ()
            if compensate_on_failure:
                if succeeded_op_names:
                    rollback, rollback_errors = _attempt_compensating_rollback(
                        transport=transport,
                        apply_ops=plan.apply_ops,
                        succeeded_op_names=succeeded_op_names,
                        credential_resolver=credential_resolver,
                        logs=logs,
                        pre_state=pre_state,
                    )
                else:
                    rollback = _rollback_noop()
            else:
                rollback = _rollback_not_attempted()
            final_overall = _finalize_overall_with_rollback(overall, rollback=rollback)
            return _finish_and_return(
                _assemble_apply_result(
                overall=final_overall,
                wg_id=plan.wg_id,
                steps=steps,
                verification=verification,
                errors=dispatch_errors + extra_errors,
                logs=tuple(logs),
                verification_status=plan.verification_status,
                verification_notes=plan.notes,
                dispatch_ok=dispatch_ok,
                enabled=enabled,
                tunnel_verification_status=tunnel_verification_status,
                interface_address_verification_status=interface_address_verification_status,
                verdict_explanation=verdict_explanation,
                rollback=rollback,
                rollback_errors=rollback_errors,
                )
            )

        if dispatch_errors:
            return _build_failure_result("failed")

        try:
            observed = _readback_show_interface(
                transport,
                plan.wg_id,
                match_peer_public_key=intent.peer_public_key,
            )
        except Exception:
            if intent_implies_traffic_routing(intent) and not intent.interface_address:
                logs.append(
                    "traffic-routing intent: interface Address NOT configured — "
                    f"{_INTERFACE_ADDRESS_LIMITATION_NOTE}"
                )
            logs.append(_MSG_READBACK_FAILED)
            return _build_failure_result(
                "failed",
                extra_errors=(_MSG_READBACK_FAILED,),
                dispatch_ok=True,
            )

        address_planned = WireguardRciOperation.SET_IP_ADDRESS.value in succeeded_op_names
        address_status = _resolve_interface_address_verification_status(
            intent,
            observed,
            address_planned=address_planned,
        )

        tunnel_status, final_observed, tunnel_explanation = _observe_tunnel_with_optional_recheck(
            transport,
            wg_id=plan.wg_id,
            observed=observed,
            handshake_settle_seconds=settled_seconds,
            logs=logs,
            match_peer_public_key=intent.peer_public_key,
            trail=trail,
        )
        verification = _verify_applied(final_observed, wg_id=plan.wg_id, enabled=intent.enabled)
        logs.append("readback verification completed")
        overall: ApplyOverallStatus
        if verification.id_ok and verification.up_ok:
            overall = "applied"
        else:
            overall = "verify_mismatch"

        if overall != "applied":
            return _build_failure_result(
                overall,
                verification=verification,
                dispatch_ok=True,
                enabled=intent.enabled,
                tunnel_verification_status=tunnel_status,
                interface_address_verification_status=address_status,
                verdict_explanation=tunnel_explanation,
            )

        if intent_implies_traffic_routing(intent) and not intent.interface_address:
            logs.append(
                "traffic-routing intent: interface Address NOT configured — "
                f"{_INTERFACE_ADDRESS_LIMITATION_NOTE}"
            )

        return _finish_and_return(
            _assemble_apply_result(
            overall=overall,
            wg_id=plan.wg_id,
            steps=steps,
            verification=verification,
            errors=(),
            logs=tuple(logs),
            verification_status=plan.verification_status,
            verification_notes=plan.notes,
            dispatch_ok=True,
            enabled=intent.enabled,
            tunnel_verification_status=tunnel_status,
            interface_address_verification_status=address_status,
            verdict_explanation=tunnel_explanation,
            rollback=_rollback_not_attempted(),
            )
        )

    return guard_sealed_apply_trail(trail, _run)


def teardown_wireguard(
    *,
    wg_id: str,
    transport: WireguardApplyTransport,
    credential_resolver: CredentialResolver,
    intent: WireguardIntent | None = None,
    store: Any | None = None,
    sealed_apply_params: SealedApplyTrailParams | None = None,
) -> WireguardApplyResult:
    normalized_wg = _validate_wg_id(wg_id)
    teardown_intent = intent or WireguardIntent(wg_id=normalized_wg, enabled=False, asc_args=None)
    if teardown_intent.wg_id != normalized_wg:
        raise WireguardApplyServiceError(
            "intent wg_id "
            f"{teardown_intent.wg_id!r} does not match teardown target {normalized_wg!r}"
        )
    plan = _compile_plan(teardown_intent, normalized_wg)
    logs: list[str] = [f"compiled {len(plan.teardown_ops)} teardown ops for {plan.wg_id}"]

    planned_op_names = tuple(op.operation for op in plan.teardown_ops)
    trail = begin_sealed_apply_trail(
        store,
        params=sealed_apply_params,
        ops_planned=planned_op_names,
    )

    def _run() -> WireguardApplyResult:
        steps, dispatch_errors = _dispatch_ops(
            transport=transport,
            ops=plan.teardown_ops,
            credential_resolver=credential_resolver,
            logs=logs,
            continue_on_error=True,
            trail=trail,
        )

        def _finish_and_return(result: WireguardApplyResult) -> WireguardApplyResult:
            finish_sealed_apply_trail(
                trail,
                overall=result.overall,
                outcome_snapshot=outcome_snapshot_from_apply_result(result),
            )
            return result

        try:
            observed = _readback_show_interface(
                transport,
                plan.wg_id,
                match_peer_public_key=teardown_intent.peer_public_key,
            )
        except Exception:
            return _finish_and_return(
                _assemble_apply_result(
                overall="failed",
                wg_id=plan.wg_id,
                steps=steps,
                verification=None,
                errors=(*dispatch_errors, _MSG_READBACK_FAILED),
                logs=tuple(logs + [_MSG_READBACK_FAILED]),
                verification_status=plan.verification_status,
                verification_notes=plan.notes,
                dispatch_ok=not dispatch_errors,
                )
            )

        verification = _verify_teardown(observed, wg_id=plan.wg_id)
        logs.append("teardown readback verification completed")
        tunnel_observation = observe_tunnel(observed)
        tunnel_status: TunnelVerificationStatus = tunnel_observation.verdict  # type: ignore[assignment]
        overall = _teardown_overall(
            steps=steps,
            verification=verification,
            dispatch_errors=dispatch_errors,
        )

        return _finish_and_return(
            _assemble_apply_result(
            overall=overall,
            wg_id=plan.wg_id,
            steps=steps,
            verification=verification,
            errors=dispatch_errors,
            logs=tuple(logs),
            verification_status=plan.verification_status,
            verification_notes=plan.notes,
            dispatch_ok=not dispatch_errors,
            is_teardown=True,
            tunnel_verification_status=tunnel_status,
            verdict_explanation=tunnel_observation.explanation,
            )
        )

    return guard_sealed_apply_trail(trail, _run)
