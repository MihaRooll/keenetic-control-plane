"""Typed sealed RCI mutation routes — enum bodies only; live mutations fail-closed."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from typing import Annotated, Any

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from router_control.adapters.netcraze.fail_safe_rci import (
    FailSafeRciOperation,
    FailSafeRciResult,
    RciSealedWriteTransport,
    arm_fail_safe_timer_reboot_60,
    disarm_fail_safe_timer,
)
from router_control.adapters.netcraze.interface_rci import (
    InterfaceRciOperation,
    InterfaceRciResult,
    interface_down,
    interface_up,
)
from router_control.adapters.netcraze.system_rci import (
    SystemRciOperation,
    SystemRciResult,
    configuration_save,
    system_reboot,
)
from router_control.adapters.netcraze.transport import SealedRciWriteRequest
from router_control.persistence.errors import IdempotencyConflict

from router_control_host.apply_response_models import RciMutationResponse
from router_control_host.errors import error_response
from router_control_host.routes import (
    API_PREFIX,
    _live_mutation_forbidden,
    _mutation_degraded,
    _ok_headers,
)
from router_control_host.state import HostState

router = APIRouter(prefix=API_PREFIX, tags=["rci-mutations"])

IdempotencyKeyHeader = Annotated[str, Header(alias="Idempotency-Key")]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FailSafeArmBody(_StrictModel):
    operation: FailSafeRciOperation = FailSafeRciOperation.ARM_TIMER_REBOOT_60


class FailSafeDisarmBody(_StrictModel):
    operation: FailSafeRciOperation = FailSafeRciOperation.DISARM_TIMER


class InterfaceMutationBody(_StrictModel):
    operation: InterfaceRciOperation
    interface_id: str = Field(min_length=1, max_length=64)


class SystemSaveBody(_StrictModel):
    operation: SystemRciOperation = SystemRciOperation.CONFIGURATION_SAVE


class SystemRebootBody(_StrictModel):
    operation: SystemRciOperation = SystemRciOperation.REBOOT


class _FakeRciTransport:
    """Offline fake transport — returns canned structural acks without network I/O."""

    def execute_sealed_rci_write(self, request: SealedRciWriteRequest) -> list[dict[str, Any]]:
        body = json.loads(request.body.decode("utf-8"))
        command = str(body[0]["parse"])
        if command.startswith("system configuration fail-safe timer reboot"):
            ident = "Core::System::Mtd::ConfigStorage"
        elif command == "no system configuration fail-safe timer":
            ident = "Core::System::Mtd::ConfigStorage"
        elif command == "system configuration save":
            ident = "Core::System::Configuration"
        elif command == "system reboot":
            ident = "Core::System"
        elif command.startswith("interface ") and command.endswith(" up"):
            ident = "Core::Interface"
        elif command.startswith("interface ") and command.endswith(" down"):
            ident = "Core::Interface"
        else:
            ident = "Core::Unknown"
        return [
            {
                "parse": {
                    "prompt": "(config)",
                    "status": [
                        {
                            "status": "message",
                            "code": "8979152",
                            "ident": ident,
                            "message": "synthetic ack",
                        }
                    ],
                }
            }
        ]


def _state(request: Request) -> HostState:
    return request.app.state.host  # type: ignore[no-any-return]


def _digest(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(raw.encode()).hexdigest()


def _mutation_gates(host: HostState, request: Request) -> JSONResponse | None:
    degraded = _mutation_degraded(host, request)
    if degraded is not None:
        return degraded
    live_mut = _live_mutation_forbidden(host, request)
    if live_mut is not None:
        return live_mut
    allow_fake = host.adapter_mode == "fake" and (
        host.allow_fake_mutations or os.environ.get("RC_ALLOW_FAKE_MUTATIONS") == "1"
    )
    if not allow_fake:
        return error_response(
            request,
            status_code=403,
            code="gate.mutation_forbidden",
            message="Hardware mutation gates closed; RCI mutations fail-closed",
        )
    return None


def _persist_and_respond(
    host: HostState,
    request: Request,
    *,
    router_id: str,
    operation_kind: str,
    idempotency_key: str,
    request_digest: str,
    result_payload: dict[str, object],
) -> JSONResponse:
    try:
        existing = host.runtime.store.peek_idempotency(
            router_id=router_id,
            operation_kind=operation_kind,
            idempotency_key=idempotency_key,
            request_digest=request_digest,
        )
    except IdempotencyConflict as exc:
        return error_response(
            request,
            status_code=409,
            code="idempotency.conflict",
            message=str(exc),
        )
    if existing is not None and existing.response_ref:
        stored = json.loads(existing.response_ref)
        return JSONResponse(
            stored.get("body", {}),
            status_code=int(stored.get("http_status", 200)),
            headers=_ok_headers(request),
        )
    try:
        outcome = host.runtime.store.create_operation_bundle(
            router_id=router_id,
            operation_kind=operation_kind,
            idempotency_key=idempotency_key,
            request_digest=request_digest,
            actor_id="hub_admin",
            initial_job_status="Succeeded",
            http_status=200,
            now=host.runtime.clock.now(),
        )
    except IdempotencyConflict as exc:
        return error_response(
            request,
            status_code=409,
            code="idempotency.conflict",
            message=str(exc),
        )
    response_body: dict[str, object] = {
        "operation_id": outcome.operation_id,
        "job_id": outcome.job_id,
        "status": "Succeeded",
        "result": result_payload,
        "links": {
            "operation": f"{API_PREFIX}/operations/{outcome.operation_id}",
            "job": f"{API_PREFIX}/jobs/{outcome.job_id}",
        },
    }
    host.runtime.store.update_idempotency_response(
        outcome.idempotency_record_id,
        http_status=200,
        body=response_body,
    )
    return JSONResponse(response_body, status_code=200, headers=_ok_headers(request))


def _handle_typed_rci(
    request: Request,
    router_id: str,
    idempotency_key: str,
    *,
    operation_kind: str,
    digest_payload: dict[str, Any],
    dispatch: Callable[[RciSealedWriteTransport], FailSafeRciResult | SystemRciResult],
) -> JSONResponse:
    host = _state(request)
    gate = _mutation_gates(host, request)
    if gate is not None:
        return gate
    transport = _FakeRciTransport()
    try:
        result = dispatch(transport)
    except Exception as exc:
        return error_response(
            request,
            status_code=422,
            code="router.rci_mutation_failed",
            message=str(exc),
        )
    payload = dict(result.sanitized_dict())
    payload["router_id"] = router_id
    return _persist_and_respond(
        host,
        request,
        router_id=router_id,
        operation_kind=operation_kind,
        idempotency_key=idempotency_key,
        request_digest=_digest(digest_payload),
        result_payload=payload,
    )


@router.post("/routers/{router_id}/rci/fail-safe/arm", response_model=RciMutationResponse)
def rci_fail_safe_arm(
    router_id: str,
    request: Request,
    body: FailSafeArmBody,
    idempotency_key: IdempotencyKeyHeader,
) -> JSONResponse:
    if not idempotency_key or not idempotency_key.strip() or len(idempotency_key) > 128:
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="Idempotency-Key required",
        )
    if body.operation is not FailSafeRciOperation.ARM_TIMER_REBOOT_60:
        return error_response(
            request,
            status_code=422,
            code="request.validation_failed",
            message="unsupported fail-safe operation",
        )
    return _handle_typed_rci(
        request,
        router_id,
        idempotency_key.strip(),
        operation_kind="rci_fail_safe_arm",
        digest_payload={"router_id": router_id, "operation": body.operation.value},
        dispatch=arm_fail_safe_timer_reboot_60,
    )


@router.post("/routers/{router_id}/rci/fail-safe/disarm", response_model=RciMutationResponse)
def rci_fail_safe_disarm(
    router_id: str,
    request: Request,
    body: FailSafeDisarmBody,
    idempotency_key: IdempotencyKeyHeader,
) -> JSONResponse:
    if not idempotency_key or not idempotency_key.strip() or len(idempotency_key) > 128:
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="Idempotency-Key required",
        )
    if body.operation is not FailSafeRciOperation.DISARM_TIMER:
        return error_response(
            request,
            status_code=422,
            code="request.validation_failed",
            message="unsupported fail-safe operation",
        )
    return _handle_typed_rci(
        request,
        router_id,
        idempotency_key.strip(),
        operation_kind="rci_fail_safe_disarm",
        digest_payload={"router_id": router_id, "operation": body.operation.value},
        dispatch=disarm_fail_safe_timer,
    )


@router.post("/routers/{router_id}/rci/interface", response_model=RciMutationResponse)
def rci_interface_mutation(
    router_id: str,
    request: Request,
    body: InterfaceMutationBody,
    idempotency_key: IdempotencyKeyHeader,
) -> JSONResponse:
    if not idempotency_key or not idempotency_key.strip() or len(idempotency_key) > 128:
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="Idempotency-Key required",
        )
    host = _state(request)
    gate = _mutation_gates(host, request)
    if gate is not None:
        return gate
    transport = _FakeRciTransport()
    try:
        if body.operation is InterfaceRciOperation.UP:
            result: InterfaceRciResult = interface_up(transport, body.interface_id)
            kind = "rci_interface_up"
        elif body.operation is InterfaceRciOperation.DOWN:
            result = interface_down(transport, body.interface_id)
            kind = "rci_interface_down"
        else:
            return error_response(
                request,
                status_code=422,
                code="request.validation_failed",
                message="unsupported interface operation",
            )
    except Exception as exc:
        return error_response(
            request,
            status_code=422,
            code="router.rci_mutation_failed",
            message=str(exc),
        )
    payload = dict(result.sanitized_dict())
    payload["router_id"] = router_id
    return _persist_and_respond(
        host,
        request,
        router_id=router_id,
        operation_kind=kind,
        idempotency_key=idempotency_key.strip(),
        request_digest=_digest(
            {
                "router_id": router_id,
                "operation": body.operation.value,
                "interface_id": result.interface_id,
            }
        ),
        result_payload=payload,
    )


@router.post(
    "/routers/{router_id}/rci/system/configuration-save",
    response_model=RciMutationResponse,
)
def rci_system_configuration_save(
    router_id: str,
    request: Request,
    body: SystemSaveBody,
    idempotency_key: IdempotencyKeyHeader,
) -> JSONResponse:
    if not idempotency_key or not idempotency_key.strip() or len(idempotency_key) > 128:
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="Idempotency-Key required",
        )
    if body.operation is not SystemRciOperation.CONFIGURATION_SAVE:
        return error_response(
            request,
            status_code=422,
            code="request.validation_failed",
            message="unsupported system operation",
        )
    return _handle_typed_rci(
        request,
        router_id,
        idempotency_key.strip(),
        operation_kind="rci_system_configuration_save",
        digest_payload={"router_id": router_id, "operation": body.operation.value},
        dispatch=configuration_save,
    )


@router.post("/routers/{router_id}/rci/system/reboot", response_model=RciMutationResponse)
def rci_system_reboot(
    router_id: str,
    request: Request,
    body: SystemRebootBody,
    idempotency_key: IdempotencyKeyHeader,
) -> JSONResponse:
    if not idempotency_key or not idempotency_key.strip() or len(idempotency_key) > 128:
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="Idempotency-Key required",
        )
    if body.operation is not SystemRciOperation.REBOOT:
        return error_response(
            request,
            status_code=422,
            code="request.validation_failed",
            message="unsupported system operation",
        )
    return _handle_typed_rci(
        request,
        router_id,
        idempotency_key.strip(),
        operation_kind="rci_system_reboot",
        digest_payload={"router_id": router_id, "operation": body.operation.value},
        dispatch=system_reboot,
    )
