"""Commissioning API routes — read-only MVP; zero router writes."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Literal

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse
from router_control.domain.errors import (
    CommissioningCancelled,
    CommissioningConflict,
    CommissioningNotFound,
    CommissioningPreconditionFailed,
    EventPresetNotFound,
)
from router_control.persistence.store import etag_for_commissioning_run

from router_control_host.errors import error_response
from router_control_host.state import HostState

router = APIRouter(prefix="/api/router-control/v1", tags=["commissioning"])

_ETAG_RE = re.compile(r'^"([^"]+):(\d+):([^"]+)"$')


def _state(request: Request) -> HostState:
    return request.app.state.host  # type: ignore[no-any-return]


def _digest(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(raw.encode()).hexdigest()


def _ok_headers(request: Request, extra: dict[str, str] | None = None) -> dict[str, str]:
    headers = {
        "X-Request-Id": request.state.request_id,
        "X-Correlation-Id": request.state.correlation_id,
    }
    if extra:
        headers.update(extra)
    return headers


def _parse_if_match(if_match: str | None) -> int | Literal["invalid"] | None:
    if if_match is None:
        return None
    match = _ETAG_RE.match(if_match.strip())
    if not match:
        return "invalid"
    return int(match.group(2))


def _wants_async(request: Request) -> bool:
    if request.query_params.get("execution") == "async":
        return True
    prefer = request.headers.get("Prefer", "")
    return "respond-async" in prefer.lower()


def _async_accepted(request: Request, body: dict[str, Any]) -> JSONResponse:
    return JSONResponse(
        body,
        status_code=202,
        headers=_ok_headers(
            request,
            {"Location": f"/api/router-control/v1/operations/{body['operation_id']}"},
        ),
    )


def _commissioning_error(
    request: Request, exc: Exception
) -> JSONResponse:
    if isinstance(exc, CommissioningNotFound):
        return error_response(request, status_code=404, code="resource.not_found", message=str(exc))
    if isinstance(exc, CommissioningPreconditionFailed):
        return error_response(
            request, status_code=412, code="resource.precondition_failed", message=str(exc)
        )
    if isinstance(exc, CommissioningConflict):
        return error_response(request, status_code=409, code="resource.conflict", message=str(exc))
    if isinstance(exc, CommissioningCancelled):
        return error_response(
            request, status_code=409, code="commissioning.cancelled", message=str(exc)
        )
    return error_response(
        request, status_code=500, code="internal.error", message="unexpected commissioning error"
    )


@router.post("/sites/{site_id}/commissioning-runs")
def create_commissioning_run(
    site_id: str,
    request: Request,
    body: dict[str, Any],
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> JSONResponse:
    key = idempotency_key
    if not key or not key.strip() or len(key) > 128:
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="Idempotency-Key required",
        )
    host = _state(request)
    service = host.commissioning_service()
    router_id = body.get("router_id")
    mode = body.get("mode", host.adapter_mode)
    if not isinstance(router_id, str) or not router_id.strip():
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="router_id required",
        )
    req_digest = _digest({"site_id": site_id, "router_id": router_id, "mode": mode})
    try:
        run, created = service.create_run(
            site_id=site_id,
            router_id=router_id.strip(),
            mode=str(mode),
            idempotency_key=key.strip(),
            request_digest=req_digest,
            correlation_id=request.state.correlation_id,
        )
    except (
        CommissioningNotFound,
        CommissioningPreconditionFailed,
        CommissioningConflict,
    ) as exc:
        return _commissioning_error(request, exc)
    status = 201 if created else 200
    return JSONResponse(
        run,
        status_code=status,
        headers=_ok_headers(
            request,
            {
                "ETag": run["etag"],
                "Location": f"/api/router-control/v1/commissioning-runs/{run['run_id']}",
            },
        ),
    )


@router.get("/sites/{site_id}/commissioning-runs")
def list_commissioning_runs(site_id: str, request: Request) -> JSONResponse:
    host = _state(request)
    try:
        runs = host.commissioning_service().list_runs_for_site(site_id)
    except CommissioningNotFound as exc:
        return _commissioning_error(request, exc)
    return JSONResponse({"items": runs}, headers=_ok_headers(request))


@router.get("/commissioning-runs/{run_id}")
def get_commissioning_run(run_id: str, request: Request) -> JSONResponse:
    host = _state(request)
    try:
        run = host.commissioning_service().get_run(run_id)
    except CommissioningNotFound as exc:
        return _commissioning_error(request, exc)
    return JSONResponse(run, headers=_ok_headers(request, {"ETag": run["etag"]}))


@router.post("/commissioning-runs/{run_id}/assess")
def assess_commissioning_run(
    run_id: str,
    request: Request,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    if_match: str | None = Header(default=None, alias="If-Match"),
) -> JSONResponse:
    if not idempotency_key or not idempotency_key.strip() or len(idempotency_key) > 128:
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="Idempotency-Key required",
        )
    host = _state(request)
    parsed = _parse_if_match(if_match)
    if parsed == "invalid":
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="If-Match ETag invalid",
        )
    req_digest = _digest({"run_id": run_id, "action": "assess"})
    service = host.commissioning_service()
    if _wants_async(request):
        try:
            run = service.get_run(run_id)
            body = service.enqueue_assess_async(
                run_id=run_id,
                router_id=str(run["router_id"]),
                idempotency_key=idempotency_key.strip(),
                request_digest=req_digest,
                expected_version=parsed if isinstance(parsed, int) else None,
                correlation_id=request.state.correlation_id,
            )
        except (
            CommissioningNotFound,
            CommissioningPreconditionFailed,
            CommissioningConflict,
            CommissioningCancelled,
        ) as exc:
            return _commissioning_error(request, exc)
        return _async_accepted(request, body)
    try:
        run, checks, _created = service.assess_run(
            run_id=run_id,
            idempotency_key=idempotency_key.strip(),
            request_digest=req_digest,
            expected_version=parsed if isinstance(parsed, int) else None,
            correlation_id=request.state.correlation_id,
        )
    except (
        CommissioningNotFound,
        CommissioningPreconditionFailed,
        CommissioningConflict,
        CommissioningCancelled,
    ) as exc:
        return _commissioning_error(request, exc)
    return JSONResponse(
        {"run": run, "checks": checks},
        headers=_ok_headers(request, {"ETag": run["etag"]}),
    )


@router.get("/commissioning-runs/{run_id}/readiness-checks")
def list_readiness_checks(run_id: str, request: Request) -> JSONResponse:
    host = _state(request)
    try:
        checks = host.commissioning_service().list_checks(run_id)
    except CommissioningNotFound as exc:
        return _commissioning_error(request, exc)
    return JSONResponse({"items": checks}, headers=_ok_headers(request))


@router.get("/commissioning-runs/{run_id}/report")
def get_commissioning_report(run_id: str, request: Request) -> JSONResponse:
    host = _state(request)
    try:
        report = host.commissioning_service().build_report(run_id)
        run = host.commissioning_service().get_run(run_id)
        presets = host.runtime.store.list_event_presets_for_site(run["site_id"], limit=1)
        if presets:
            preset_row = presets[0]
            preset_id = str(preset_row["preset_id"])
            try:
                preset_report = host.event_preset_service().readiness_report(preset_id)
                report = {
                    **report,
                    "event_preset_readiness": {
                        "preset_id": preset_id,
                        "readiness_status": preset_report["readiness_status"],
                        "valid_offline": preset_report["valid_offline"],
                        "ready_for_read_only_assessment": preset_report[
                            "ready_for_read_only_assessment"
                        ],
                        "write_ready": False,
                    },
                }
            except EventPresetNotFound:
                report = {
                    **report,
                    "event_preset_readiness": {
                        "preset_id": preset_id,
                        "absent": True,
                        "reason": "preset_not_found",
                        "write_ready": False,
                    },
                }
            except Exception as exc:
                report = {
                    **report,
                    "event_preset_readiness": {
                        "preset_id": preset_id,
                        "absent": True,
                        "reason": "readiness_unavailable",
                        "summary_redacted": type(exc).__name__,
                        "write_ready": False,
                    },
                }
    except CommissioningNotFound as exc:
        return _commissioning_error(request, exc)
    return JSONResponse(
        report,
        headers=_ok_headers(
            request,
            {
                "ETag": etag_for_commissioning_run(
                    run_id, int(run["version"]), run.get("report_digest")
                )
            },
        ),
    )


@router.post("/commissioning-runs/{run_id}/cancel")
def cancel_commissioning_run(
    run_id: str,
    request: Request,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    if_match: str | None = Header(default=None, alias="If-Match"),
) -> JSONResponse:
    if not idempotency_key or not idempotency_key.strip() or len(idempotency_key) > 128:
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="Idempotency-Key required",
        )
    host = _state(request)
    parsed = _parse_if_match(if_match)
    if parsed == "invalid":
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="If-Match ETag invalid",
        )
    req_digest = _digest({"run_id": run_id, "action": "cancel"})
    try:
        run, _created = host.commissioning_service().cancel_run(
            run_id=run_id,
            idempotency_key=idempotency_key.strip(),
            request_digest=req_digest,
            expected_version=parsed if isinstance(parsed, int) else None,
            correlation_id=request.state.correlation_id,
        )
    except (
        CommissioningNotFound,
        CommissioningPreconditionFailed,
        CommissioningConflict,
    ) as exc:
        return _commissioning_error(request, exc)
    return JSONResponse(run, headers=_ok_headers(request, {"ETag": run["etag"]}))
