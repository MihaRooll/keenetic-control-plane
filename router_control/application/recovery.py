"""Recovery classification — pre/post dispatch, resume, no blind retry."""

from __future__ import annotations

import json
import logging
import os
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, TypeVar, cast

from router_control.application.apply_types import ApplyOverallStatus
from router_control.domain.enums import StepKind
from router_control.persistence.errors import (
    ConflictError,
    RecoveryConflictError,
    SealedApplyTrailBeginError,
)
from router_control.persistence.store import PersistenceStore

_LOGGER = logging.getLogger(__name__)
_T = TypeVar("_T")

# Mirrors PersistenceStore._SEALED_APPLY_LEASE_SECONDS (store.py).
_SEALED_APPLY_LEASE_SECONDS = 30

POST_DISPATCH_STEP_KINDS = frozenset(
    {
        StepKind.APPLY.value,
        "apply",
        "handler",
        StepKind.READ_BACK.value,
        StepKind.VERIFY.value,
        StepKind.SAVE.value,
        StepKind.COMPENSATE.value,
    }
)

MUTATION_DISPATCH_KINDS = frozenset({StepKind.APPLY.value, "apply"})

_SEALED_APPLY_OP_EVIDENCE_MAX_BYTES = 2048
_SEALED_APPLY_PRE_APPLY_BASELINE_MAX_BYTES = 4096
_SEALED_APPLY_OUTCOME_SNAPSHOT_MAX_BYTES = 4096


@dataclass(frozen=True, slots=True)
class RecoveryClassification:
    pre_dispatch: bool
    post_dispatch: bool
    apply_dispatched: bool
    last_safe_step: str | None
    requires_readback: bool


def _parse_checkpoint(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def classify_job_steps(
    store: PersistenceStore, job_id: str, *, job_status: str
) -> RecoveryClassification:
    """Inspect durable steps to decide safe requeue vs RecoveryRequired."""
    steps = store.list_job_steps(job_id)
    apply_dispatched = False
    post_dispatch = False
    last_safe: str | None = None

    for step in steps:
        kind = str(step["step_kind"])
        status = str(step["status"])
        if kind in MUTATION_DISPATCH_KINDS and status in ("Running", "Succeeded"):
            apply_dispatched = True
        if kind in POST_DISPATCH_STEP_KINDS and status in ("Running", "Succeeded"):
            post_dispatch = True
        if status == "Succeeded" and kind not in MUTATION_DISPATCH_KINDS:
            last_safe = kind

    if job_status == "Running":
        post_dispatch = True

    pre_dispatch = not post_dispatch and not apply_dispatched
    requires_readback = apply_dispatched or post_dispatch
    return RecoveryClassification(
        pre_dispatch=pre_dispatch,
        post_dispatch=post_dispatch,
        apply_dispatched=apply_dispatched,
        last_safe_step=last_safe,
        requires_readback=requires_readback,
    )


def checkpoint_redacted(
    *,
    phase: str,
    last_safe_step: str | None = None,
    backup_artifact_id: str | None = None,
    apply_dispatched: bool = False,
    fail_safe: bool = False,
    ops_dispatched_redacted: tuple[str, ...] | None = None,
) -> str:
    payload: dict[str, Any] = {
        "phase": phase,
        "apply_dispatched": apply_dispatched,
        "fail_safe": fail_safe,
    }
    if last_safe_step:
        payload["last_safe_step"] = last_safe_step
    if backup_artifact_id:
        payload["backup_artifact_id"] = backup_artifact_id
    if ops_dispatched_redacted:
        payload["ops_dispatched_redacted"] = list(ops_dispatched_redacted)
    return json.dumps(payload, sort_keys=True)


def _bound_json_document(payload: dict[str, Any], *, max_bytes: int) -> str:
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    if len(text) <= max_bytes:
        return text
    trimmed = dict(payload)
    trimmed["truncated"] = True
    while len(json.dumps(trimmed, sort_keys=True, separators=(",", ":"))) > max_bytes:
        if "observed_redacted" in trimmed:
            del trimmed["observed_redacted"]
            continue
        if "device_ack" in trimmed:
            del trimmed["device_ack"]
            continue
        trimmed.pop("truncated", None)
        break
    text = json.dumps(trimmed, sort_keys=True, separators=(",", ":"))
    if len(text) > max_bytes:
        return text[: max_bytes - len("...[truncated]")] + "...[truncated]"
    return text


def _dataclass_to_trail_dict(value: Any) -> dict[str, Any]:
    from dataclasses import asdict, is_dataclass

    if is_dataclass(value) and not isinstance(value, type):
        return asdict(value)
    if isinstance(value, dict):
        return {str(key): item for key, item in value.items()}
    raise TypeError("pre_apply baseline requires dataclass or dict")


def redact_sealed_apply_device_ack(raw: Any) -> dict[str, Any] | None:
    """Redact a device parse/ack payload for durable trail storage."""
    if raw is None:
        return None
    from router_control.adapters.netcraze.sanitize import sanitize_mapping
    from router_control.application.wifi_observation_helpers import (
        sanitize_show_rc_interface_raw,
    )

    if isinstance(raw, dict):
        try:
            sanitized = sanitize_show_rc_interface_raw(raw)
        except (TypeError, ValueError):
            sanitized = sanitize_mapping(raw)
        return sanitized if isinstance(sanitized, dict) else sanitize_mapping({"value": sanitized})
    if hasattr(raw, "sanitized_dict"):
        payload = raw.sanitized_dict()
        if isinstance(payload, dict):
            return sanitize_mapping(payload)
    return None


def build_sealed_apply_op_evidence(
    step: Any,
    *,
    device_ack: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build redacted per-op evidence from an apply step (+ optional device ack)."""
    if hasattr(step, "to_dict"):
        evidence = dict(step.to_dict())
    elif isinstance(step, dict):
        evidence = dict(step)
    else:
        raise TypeError("step must expose to_dict() or be a mapping")
    if device_ack is not None:
        evidence["device_ack"] = device_ack
    return redact_sealed_apply_op_evidence(evidence)


def redact_sealed_apply_op_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    """Scrub and bound a single op evidence document for trail/audit storage."""
    from router_control.adapters.netcraze.sanitize import sanitize_mapping
    from router_control.application.wifi_observation_helpers import scrub_error_message

    scrubbed: dict[str, Any] = {}
    for key, value in evidence.items():
        if key == "device_ack" and isinstance(value, dict):
            scrubbed[key] = sanitize_mapping(value)
            continue
        if key in {"error", "router_message"} and isinstance(value, str):
            scrubbed[key] = scrub_error_message(value)
            continue
        scrubbed[key] = value
    text = json.dumps(scrubbed, sort_keys=True, separators=(",", ":"))
    if len(text) <= _SEALED_APPLY_OP_EVIDENCE_MAX_BYTES:
        return scrubbed
    bounded = dict(scrubbed)
    bounded.pop("device_ack", None)
    bounded["truncated"] = True
    return cast(
        dict[str, Any],
        json.loads(
            _bound_json_document(bounded, max_bytes=_SEALED_APPLY_OP_EVIDENCE_MAX_BYTES)
        ),
    )


def serialize_pre_apply_baseline_for_trail(
    pre_state: Any,
    *,
    observed: dict[str, Any] | None = None,
    raw: Any | None = None,
) -> dict[str, Any]:
    """Serialize compensation baseline for durable trail (no resolved secrets)."""
    from router_control.adapters.netcraze.sanitize import sanitize_mapping

    payload: dict[str, Any] = {"pre_state": _dataclass_to_trail_dict(pre_state)}
    if observed is not None:
        payload["observed_redacted"] = sanitize_mapping(
            {str(key): value for key, value in observed.items()}
        )
    device_ack = redact_sealed_apply_device_ack(raw)
    if device_ack is not None:
        payload["device_read_redacted"] = device_ack
    return cast(
        dict[str, Any],
        json.loads(
            _bound_json_document(payload, max_bytes=_SEALED_APPLY_PRE_APPLY_BASELINE_MAX_BYTES)
        ),
    )


def build_sealed_apply_outcome_snapshot(
    *,
    overall: ApplyOverallStatus,
    verdict_explanation: dict[str, Any] | None = None,
    on_air_verification_status: str | None = None,
    uplink_verification_status: str | None = None,
    rollback: dict[str, Any] | None = None,
    rollback_errors: tuple[str, ...] | list[str] = (),
) -> dict[str, Any]:
    """Terminal verdict + rollback summary for audit (not duplicated in trail mid-flight)."""
    from router_control.application.wifi_observation_helpers import scrub_error_message

    payload: dict[str, Any] = {"overall": overall}
    if on_air_verification_status is not None:
        payload["on_air_verification_status"] = on_air_verification_status
    if uplink_verification_status is not None:
        payload["uplink_verification_status"] = uplink_verification_status
    if verdict_explanation is not None:
        payload["verdict_explanation"] = verdict_explanation
    if rollback is not None:
        payload["rollback"] = rollback
    if rollback_errors:
        payload["rollback_errors"] = [
            scrub_error_message(str(item)) or "[REDACTED:error_message]"
            for item in rollback_errors
        ]
    return cast(
        dict[str, Any],
        json.loads(
            _bound_json_document(payload, max_bytes=_SEALED_APPLY_OUTCOME_SNAPSHOT_MAX_BYTES)
        ),
    )


def reconstruct_sealed_apply_incident(
    *,
    trail_row: dict[str, Any],
    audit_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Reconstruct apply incident chain from durable trail (+ optional audit outcome)."""
    ops_planned = json.loads(str(trail_row.get("ops_planned_redacted") or "[]"))
    ops_pending = json.loads(str(trail_row.get("ops_pending_redacted") or "[]"))
    ops_dispatched = json.loads(str(trail_row.get("ops_dispatched_redacted") or "[]"))
    ops_evidence = json.loads(str(trail_row.get("ops_evidence_redacted") or "{}"))
    pre_apply_raw = trail_row.get("pre_apply_baseline_redacted")
    pre_apply = json.loads(str(pre_apply_raw)) if pre_apply_raw else None
    outcome_raw = trail_row.get("outcome_snapshot_redacted")
    outcome = json.loads(str(outcome_raw)) if outcome_raw else None
    if outcome is None and audit_summary is not None:
        outcome = audit_summary.get("outcome")
    chain: dict[str, Any] = {
        "run_id": trail_row.get("run_id"),
        "status": trail_row.get("status"),
        "intent": json.loads(str(trail_row["intent_summary_redacted"])),
        "ops_planned": ops_planned,
        "ops_pending": ops_pending,
        "ops_dispatched": ops_dispatched,
        "ops_evidence": ops_evidence,
        "pre_apply_baseline": pre_apply,
        "outcome": outcome,
    }
    if audit_summary is not None:
        chain["audit_result_overall"] = (
            audit_summary.get("result", {}).get("overall")
            if isinstance(audit_summary.get("result"), dict)
            else None
        )
    return chain


def outcome_snapshot_from_apply_result(result: Any) -> dict[str, Any]:
    """Build terminal outcome snapshot from a sealed apply service result."""
    rollback = None
    if getattr(result, "rollback", None) is not None:
        rollback = result.rollback.to_dict()
    verdict = None
    if getattr(result, "verdict_explanation", None) is not None:
        verdict = result.verdict_explanation.to_dict()
    on_air = getattr(result, "on_air_verification_status", None)
    uplink = getattr(result, "uplink_verification_status", None)
    return build_sealed_apply_outcome_snapshot(
        overall=cast(ApplyOverallStatus, result.overall),
        verdict_explanation=verdict,
        on_air_verification_status=str(on_air) if on_air is not None else None,
        uplink_verification_status=str(uplink) if uplink is not None else None,
        rollback=rollback,
        rollback_errors=tuple(getattr(result, "rollback_errors", ()) or ()),
    )


@dataclass(frozen=True, slots=True)
class SealedApplyTrailParams:
    route: str
    verb: str
    intent_redacted: dict[str, Any]
    correlation_id: str | None = None
    router_id: str | None = None


@dataclass(frozen=True, slots=True)
class SealedApplyTrailHandle:
    store: PersistenceStore
    run_id: str
    lease_owner: str

    def record_pre_apply_baseline(self, baseline_redacted: dict[str, Any]) -> None:
        self.store.record_sealed_apply_pre_apply_baseline(
            self.run_id,
            baseline_redacted,
            lease_owner=self.lease_owner,
        )

    def record_op_intent(self, op_name_redacted: str) -> None:
        self.store.record_sealed_apply_op_intent(
            self.run_id, op_name_redacted, lease_owner=self.lease_owner
        )

    def record_op(
        self,
        op_name_redacted: str,
        *,
        op_evidence_redacted: dict[str, Any] | None = None,
    ) -> None:
        self.store.record_sealed_apply_op_progress(
            self.run_id,
            op_name_redacted,
            lease_owner=self.lease_owner,
            op_evidence_redacted=op_evidence_redacted,
        )

    def record_op_failure(
        self,
        op_name_redacted: str,
        *,
        op_evidence_redacted: dict[str, Any] | None = None,
    ) -> None:
        self.store.abandon_sealed_apply_op_intent(
            self.run_id,
            op_name_redacted,
            lease_owner=self.lease_owner,
            op_evidence_redacted=op_evidence_redacted,
        )

    def abandon_op_intent(self, op_name_redacted: str) -> None:
        self.store.abandon_sealed_apply_op_intent(
            self.run_id, op_name_redacted, lease_owner=self.lease_owner
        )

    def renew_lease(self, *, now_epoch: int | None = None) -> None:
        self.store.renew_sealed_apply_lease(
            self.run_id,
            lease_owner=self.lease_owner,
            now_epoch=now_epoch,
        )


def sleep_preserving_sealed_apply_lease(
    trail: SealedApplyTrailHandle | None,
    seconds: float,
    sleep_fn: Callable[[float], None],
    *,
    lease_seconds: int = _SEALED_APPLY_LEASE_SECONDS,
    renew_now_epoch: Callable[[], int | None] | None = None,
) -> None:
    """Sleep in chunks while renewing sealed-apply lease (mirrors worker heartbeat)."""
    if seconds <= 0:
        return
    if trail is None:
        sleep_fn(seconds)
        return
    interval = max(1.0, lease_seconds / 3)
    remaining = seconds
    while remaining > 0:
        chunk = min(interval, remaining)
        sleep_fn(chunk)
        remaining -= chunk
        if remaining <= 0:
            break
        now_epoch = renew_now_epoch() if renew_now_epoch is not None else None
        try:
            trail.renew_lease(now_epoch=now_epoch)
        except Exception as exc:
            _LOGGER.warning(
                "sealed_apply lease renew during settle failed run_id=%s: %s",
                trail.run_id,
                type(exc).__name__,
            )
            raise


_SUCCESS_OVERALLS = frozenset(
    {"applied", "dispatched_offline", "unsupported_pending_verification"}
)
_FAILURE_OVERALLS = frozenset({"failed", "verify_mismatch"})


def _trail_status_for_overall(overall: ApplyOverallStatus) -> str:
    if overall == "rolled_back":
        return "RolledBack"
    if overall in _SUCCESS_OVERALLS:
        return "Succeeded"
    if overall in _FAILURE_OVERALLS:
        return "Failed"
    return "Failed"


def _new_sealed_apply_lease_owner() -> str:
    return f"sar:{os.getpid()}:{uuid.uuid4().hex[:12]}"


def begin_sealed_apply_trail(
    store: PersistenceStore | None,
    *,
    params: SealedApplyTrailParams | None,
    ops_planned: tuple[str, ...],
) -> SealedApplyTrailHandle | None:
    if store is None or params is None:
        return None
    lease_owner = _new_sealed_apply_lease_owner()
    try:
        run_id = store.begin_sealed_apply_run(
            route=params.route,
            verb=params.verb,
            intent_summary_redacted=params.intent_redacted,
            ops_planned_redacted=ops_planned,
            router_id=params.router_id,
            correlation_id=params.correlation_id,
            lease_owner=lease_owner,
        )
    except Exception as exc:
        _LOGGER.warning(
            "sealed_apply trail begin failed route=%s verb=%s: %s",
            params.route,
            params.verb,
            type(exc).__name__,
        )
        raise SealedApplyTrailBeginError(
            "sealed apply trail could not be created; device dispatch blocked"
        ) from exc
    return SealedApplyTrailHandle(store=store, run_id=run_id, lease_owner=lease_owner)


def finish_sealed_apply_trail(
    handle: SealedApplyTrailHandle | None,
    *,
    overall: ApplyOverallStatus,
    error_redacted: str | None = None,
    outcome_snapshot: dict[str, Any] | None = None,
) -> None:
    if handle is None:
        return
    try:
        finished = handle.store.finish_sealed_apply_run(
            handle.run_id,
            lease_owner=handle.lease_owner,
            status=_trail_status_for_overall(overall),
            overall=overall,
            error_redacted=error_redacted,
            outcome_snapshot_redacted=outcome_snapshot,
        )
        if not finished:
            _LOGGER.warning(
                "sealed_apply trail finish skipped run_id=%s: lease lost",
                handle.run_id,
            )
    except Exception as exc:
        _LOGGER.warning(
            "sealed_apply trail finish failed run_id=%s: %s",
            handle.run_id,
            type(exc).__name__,
        )


def guard_sealed_apply_trail(
    trail: SealedApplyTrailHandle | None,
    fn: Callable[[], _T],
) -> _T:
    """Run apply body; on uncaught exception finish trail failed (never raise from finish)."""
    try:
        return fn()
    except (SystemExit, KeyboardInterrupt) as exc:
        finish_sealed_apply_trail(
            trail,
            overall="failed",
            error_redacted=type(exc).__name__,
        )
        raise exc
    except Exception as exc:
        finish_sealed_apply_trail(
            trail, overall="failed", error_redacted=type(exc).__name__
        )
        raise


def classify_recovery_matrix(
    store: PersistenceStore,
    *,
    router_id: str,
    job_id: str,
    job_status: str,
) -> RecoveryClassification:
    """Identity + read-back + boot scoped recovery classification."""
    store.assert_router_boot_known(router_id)
    return classify_job_steps(store, job_id, job_status=job_status)


def recovery_action_digest(action: str, *, job_id: str, operation_id: str) -> str:
    import hashlib

    payload = f"{action}:{job_id}:{operation_id}"
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def submit_recovery_request_cas(
    store: PersistenceStore,
    *,
    recovery_key: str,
    request_digest: str,
    recovery_action: str,
    operation_id: str | None = None,
    job_id: str | None = None,
    router_id: str | None = None,
    parent_request_id: str | None = None,
) -> tuple[int, dict[str, Any]]:
    """Persist recovery request with CAS semantics (same key+digest replay)."""
    try:
        status, row = store.submit_recovery_request(
            recovery_key=recovery_key,
            request_digest=request_digest,
            recovery_action=recovery_action,
            operation_id=operation_id,
            job_id=job_id,
            router_id=router_id,
            parent_request_id=parent_request_id,
        )
    except RecoveryConflictError as exc:
        return 409, {"error": "RecoveryConflict", "message": str(exc)}
    except ConflictError as exc:
        return 409, {"error": "Conflict", "message": str(exc)}
    body = {
        "request_id": str(row["request_id"]),
        "recovery_key": str(row["recovery_key"]),
        "request_digest": str(row["request_digest"]),
        "status": str(row["status"]),
        "recovery_action": str(row["recovery_action"]),
    }
    return status, body
