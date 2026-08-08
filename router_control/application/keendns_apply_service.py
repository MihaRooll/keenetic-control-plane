"""KeenDNS/CrazeDNS apply service — sealed ndns book/drop dispatch only."""



from __future__ import annotations



import json

from collections.abc import Callable, Mapping

from dataclasses import dataclass

from typing import Any, Literal, Protocol



from router_control.adapters.netcraze.allowlist import COMPONENTS_LIST, build_sealed_parse_body

from router_control.adapters.netcraze.ndns_probe import ndns_component_present, parse_components_inventory

from router_control.adapters.netcraze.transport import SealedRciWriteRequest

from router_control.application.apply_types import ApplyOverallStatus

from router_control.application.keendns_planner import (

    KeenDnsPlannerError,

    KeenDnsPreviewPlan,

    compile_keendns_apply_intent,

)

from router_control.application.recovery import (

    SealedApplyTrailHandle,

    SealedApplyTrailParams,

    begin_sealed_apply_trail,

    build_sealed_apply_op_evidence,

    finish_sealed_apply_trail,

    guard_sealed_apply_trail,

    outcome_snapshot_from_apply_result,

    redact_sealed_apply_device_ack,

)

from router_control.application.wifi_observation_helpers import ERROR_CODE_OP_DISPATCH_FAILED



BackupCallback = Callable[[], None]



ERROR_CODE_COMPONENT_ABSENT = "component_absent"
ERROR_CODE_INVENTORY_UNREADABLE = "inventory_unreadable"

_MSG_LIVE_DISPATCH_DISABLED = (

    "live KeenDNS apply dispatch is disabled; inject transport for offline tests only"

)

_MSG_OP_DISPATCH_FAILED = ERROR_CODE_OP_DISPATCH_FAILED





class KeenDnsApplyServiceError(ValueError):

    """Fail-closed KeenDNS apply service error."""





class KeenDnsApplyTransport(Protocol):

    keendns_offline_only: Literal[True]



    def execute_sealed_rci_write(self, request: SealedRciWriteRequest) -> Any: ...





class KeenDnsLiveTransport(Protocol):

    keendns_live_dispatch: Literal[True]



    def execute_sealed_rci_write(self, request: SealedRciWriteRequest) -> Any: ...



    def read_json(self, command: Any, body: bytes | None = None) -> Any: ...





def require_keendns_offline_transport(transport: object) -> None:

    if getattr(transport, "keendns_offline_only", False) is not True:

        raise KeenDnsApplyServiceError(_MSG_LIVE_DISPATCH_DISABLED)





def require_keendns_live_transport(transport: object) -> None:

    if getattr(transport, "keendns_live_dispatch", False) is not True:

        raise KeenDnsApplyServiceError(_MSG_LIVE_DISPATCH_DISABLED)

    if getattr(transport, "keendns_offline_only", False) is True:

        raise KeenDnsApplyServiceError(_MSG_LIVE_DISPATCH_DISABLED)





@dataclass(frozen=True, slots=True)

class KeenDnsApplyStep:

    op: str

    ok: bool

    command_redacted: str | None = None

    status_ident: str | None = None

    error: str | None = None



    def to_dict(self) -> dict[str, object]:

        payload: dict[str, object] = {"op": self.op, "operation": self.op, "ok": self.ok}

        if self.command_redacted is not None:

            payload["command_redacted"] = self.command_redacted

        if self.status_ident is not None:

            payload["status_ident"] = self.status_ident

        if self.error is not None:

            payload["error"] = self.error

        return payload





@dataclass(frozen=True, slots=True)

class KeenDnsApplyResult:

    overall: ApplyOverallStatus

    intent_kind: str

    name: str

    domain: str

    mode: str | None

    verification_status: str

    steps: tuple[KeenDnsApplyStep, ...]

    errors: tuple[str, ...]

    logs: tuple[str, ...]

    notes: tuple[str, ...] = ()

    backup_basename: str | None = None

    backup_content_sha256: str | None = None



    def to_dict(self) -> dict[str, object]:

        payload: dict[str, object] = {

            "overall": self.overall,

            "intent_kind": self.intent_kind,

            "name": self.name,

            "domain": self.domain,

            "mode": self.mode,

            "verification_status": self.verification_status,

            "notes": list(self.notes),

            "steps": [step.to_dict() for step in self.steps],

            "errors": list(self.errors),

            "logs": list(self.logs),

        }

        if self.backup_basename is not None:

            payload["backup_basename"] = self.backup_basename

        if self.backup_content_sha256 is not None:

            payload["backup_content_sha256"] = self.backup_content_sha256

        return payload





def _status_ident_from_ack(ack: Any) -> str | None:

    if not isinstance(ack, list) or not ack:

        return None

    first = ack[0]

    if not isinstance(first, dict):

        return None

    parse_block = first.get("parse")

    if not isinstance(parse_block, dict):

        return None

    status_entries = parse_block.get("status")

    if not isinstance(status_entries, list) or not status_entries:

        return None

    entry = status_entries[0]

    if isinstance(entry, dict) and isinstance(entry.get("ident"), str):

        return entry["ident"]

    return None





def _ack_has_error_status(ack: Any) -> bool:
    if not isinstance(ack, list) or not ack:
        return False
    for item in ack:
        if not isinstance(item, dict):
            continue
        parse_block = item.get("parse")
        if not isinstance(parse_block, dict):
            continue
        status_entries = parse_block.get("status")
        if not isinstance(status_entries, list) or not status_entries:
            continue
        if any(
            isinstance(entry, dict) and entry.get("status") == "error"
            for entry in status_entries
        ):
            return True
    return False


def _ack_has_affirmative_success(ack: Any) -> bool:
    if not isinstance(ack, list) or not ack:
        return False
    for item in ack:
        if not isinstance(item, dict):
            continue
        parse_block = item.get("parse")
        if not isinstance(parse_block, dict):
            continue
        status_entries = parse_block.get("status")
        if not isinstance(status_entries, list) or not status_entries:
            continue
        if any(
            isinstance(entry, dict) and entry.get("status") != "error"
            for entry in status_entries
        ):
            return True
    return False


def _ack_dispatch_unverified(ack: Any) -> bool:
    return not _ack_has_affirmative_success(ack)


def _probe_ndns_component_present(transport: object) -> bool | None:

    read_json = getattr(transport, "read_json", None)

    if read_json is None:

        return None

    try:

        payload = read_json(COMPONENTS_LIST, json.dumps({}).encode("utf-8"))

    except Exception:

        return None

    parsed = parse_components_inventory(payload)

    if parsed.get("parse_status") != "ok":

        return None

    component_ids = parsed.get("component_ids")

    if not isinstance(component_ids, tuple):

        return None

    present = ndns_component_present(component_ids)

    return present if present is not None else None





def _compile_plan(intent: Mapping[str, Any]) -> KeenDnsPreviewPlan:

    try:

        return compile_keendns_apply_intent(intent)

    except (KeenDnsPlannerError, ValueError) as exc:

        raise KeenDnsApplyServiceError(str(exc)) from exc





def _dispatch_plan(

    *,

    transport: object,

    plan: KeenDnsPreviewPlan,

    live_dispatch: bool,

    logs: list[str],

    trail: SealedApplyTrailHandle | None = None,

) -> tuple[tuple[KeenDnsApplyStep, ...], tuple[str, ...]]:

    if live_dispatch:

        require_keendns_live_transport(transport)

        component_present = _probe_ndns_component_present(transport)

        if component_present is None:

            raise KeenDnsApplyServiceError(ERROR_CODE_INVENTORY_UNREADABLE)

        if component_present is False:

            raise KeenDnsApplyServiceError(ERROR_CODE_COMPONENT_ABSENT)

    else:

        require_keendns_offline_transport(transport)



    steps: list[KeenDnsApplyStep] = []

    errors: list[str] = []



    for descriptor in plan.preview_ops:

        op_name = descriptor.operation

        command = descriptor.command_text

        body = build_sealed_parse_body(command)

        intent_recorded = False

        if trail is not None:

            trail.record_op_intent(op_name)

            intent_recorded = True

        try:

            ack = transport.execute_sealed_rci_write(SealedRciWriteRequest(body=body))

        except KeenDnsApplyServiceError:

            raise

        except Exception:

            failure = KeenDnsApplyStep(

                op=op_name,

                ok=False,

                command_redacted=command,

                error=_MSG_OP_DISPATCH_FAILED,

            )

            if intent_recorded and trail is not None:

                trail.record_op_failure(

                    op_name,

                    op_evidence_redacted=build_sealed_apply_op_evidence(failure),

                )

            steps.append(failure)

            errors.append(_MSG_OP_DISPATCH_FAILED)

            logs.append(f"dispatch failed for {op_name}")

            return tuple(steps), tuple(errors)

        if _ack_has_error_status(ack) or _ack_dispatch_unverified(ack):
            failure = KeenDnsApplyStep(
                op=op_name,
                ok=False,
                command_redacted=command,
                error=_MSG_OP_DISPATCH_FAILED,
            )
            if intent_recorded and trail is not None:
                trail.record_op_failure(
                    op_name,
                    op_evidence_redacted=build_sealed_apply_op_evidence(failure),
                )
            steps.append(failure)
            errors.append(_MSG_OP_DISPATCH_FAILED)
            if _ack_has_error_status(ack):
                logs.append(f"dispatch failed for {op_name}")
            else:
                logs.append(f"dispatch ack empty or unverified for {op_name}")
            return tuple(steps), tuple(errors)

        success = KeenDnsApplyStep(

            op=op_name,

            ok=True,

            command_redacted=command,

            status_ident=_status_ident_from_ack(ack),

        )

        steps.append(success)

        logs.append(f"ack received for {op_name}")

        if trail is not None:

            trail.record_op(

                op_name,

                op_evidence_redacted=build_sealed_apply_op_evidence(

                    success,

                    device_ack=redact_sealed_apply_device_ack(ack),

                ),

            )

    return tuple(steps), tuple(errors)





def apply_keendns_intent(

    *,

    intent: Mapping[str, Any],

    transport: object | None = None,

    live_dispatch: bool = False,

    backup_callback: BackupCallback | None = None,

    store: Any | None = None,

    trail_params: SealedApplyTrailParams | None = None,

) -> KeenDnsApplyResult:

    if transport is None:

        raise KeenDnsApplyServiceError(_MSG_LIVE_DISPATCH_DISABLED)

    if live_dispatch and backup_callback is None:

        raise KeenDnsApplyServiceError(

            "live KeenDNS apply requires startup-config backup callback"

        )



    plan = _compile_plan(intent)

    logs: list[str] = [f"compiled {len(plan.preview_ops)} sealed ndns ops"]



    if backup_callback is not None:

        backup_callback()

        logs.append("backup_callback invoked")



    trail = begin_sealed_apply_trail(

        store,

        params=trail_params,

        ops_planned=tuple(op.operation for op in plan.preview_ops),

    )



    apply_notes = (

        *plan.notes,

        "apply dispatch completed; cloud registration not verified by this host",

    )



    def _run() -> KeenDnsApplyResult:

        steps, dispatch_errors = _dispatch_plan(

            transport=transport,

            plan=plan,

            live_dispatch=live_dispatch,

            logs=logs,

            trail=trail,

        )

        if dispatch_errors:

            overall = "failed"

        elif live_dispatch:

            overall = "applied"

        else:

            overall = "dispatched_offline"

        result_notes = apply_notes
        if (
            dispatch_errors
            and live_dispatch
            and any("dispatch ack empty or unverified" in entry for entry in logs)
        ):
            result_notes = (
                *plan.notes,
                "live dispatch failed: router ack empty or unverified",
            )

        result = KeenDnsApplyResult(

            overall=overall,

            intent_kind=plan.intent_kind,

            name=plan.name,

            domain=plan.domain,

            mode=plan.mode,

            verification_status=plan.verification_status,

            steps=steps,

            errors=dispatch_errors,

            logs=tuple(logs),

            notes=result_notes,

        )

        finish_sealed_apply_trail(

            trail,

            overall=result.overall,

            outcome_snapshot=outcome_snapshot_from_apply_result(result),

        )

        return result



    return guard_sealed_apply_trail(trail, _run)





__all__ = [

    "ERROR_CODE_COMPONENT_ABSENT",

    "ERROR_CODE_INVENTORY_UNREADABLE",

    "KeenDnsApplyResult",

    "KeenDnsApplyServiceError",

    "KeenDnsApplyStep",

    "KeenDnsApplyTransport",

    "KeenDnsLiveTransport",

    "apply_keendns_intent",

    "require_keendns_live_transport",

    "require_keendns_offline_transport",

]

