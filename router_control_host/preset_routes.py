"""Event preset API routes — offline catalog; zero router writes."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict
from router_control.application.deployment_planner import DeploymentPlannerService
from router_control.domain.errors import (
    EventPresetConflict,
    EventPresetIdempotencyConflict,
    EventPresetNotFound,
    EventPresetPreconditionFailed,
    EventPresetValidationFailed,
)
from router_control.domain.event_preset import ValidationStatus
from router_control.persistence.errors import ConflictError, NotFoundError, PreconditionFailed

from router_control_host.auth import (
    HUB_ADMIN_COOKIE_NAME,
    session_binding_from_cookie,
)
from router_control_host.errors import (
    error_response,
    intent_code_to_reason,
    operator_structured_error_response,
)
from router_control_host.routes import IdempotencyKeyHeader, IfMatchHeader
from router_control_host.state import HostState

router = APIRouter(prefix="/api/router-control/v1", tags=["event-presets"])


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CreatePublicationBody(_StrictModel):
    revision_id: str

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


def _parse_if_match(if_match: str | None) -> int | str | None:
    if if_match is None:
        return None
    match = _ETAG_RE.match(if_match.strip())
    if not match:
        return "invalid"
    return int(match.group(2))


def _preset_error(request: Request, exc: Exception) -> JSONResponse:
    if isinstance(exc, EventPresetNotFound):
        return error_response(request, status_code=404, code="resource.not_found", message=str(exc))
    if isinstance(exc, EventPresetPreconditionFailed):
        return error_response(
            request, status_code=412, code="resource.precondition_failed", message=str(exc)
        )
    if isinstance(exc, EventPresetIdempotencyConflict):
        return error_response(
            request, status_code=409, code="idempotency.conflict", message=str(exc)
        )
    if isinstance(exc, EventPresetConflict):
        return error_response(request, status_code=409, code="resource.conflict", message=str(exc))
    if isinstance(exc, EventPresetValidationFailed):
        return operator_structured_error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            reason=intent_code_to_reason(exc.reason_code),
            field=exc.field,
            context=exc.field or "document",
        )
    return error_response(
        request, status_code=500, code="internal.error", message="unexpected preset error"
    )


def _require_idempotency(request: Request, key: str | None) -> str | JSONResponse:
    if not key or not key.strip() or len(key) > 128:
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="Idempotency-Key required",
        )
    return key.strip()


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


@router.get("/sites/{site_id}/event-presets")
def list_event_presets(site_id: str, request: Request) -> JSONResponse:
    host = _state(request)
    try:
        items = host.event_preset_service().list_presets_for_site(site_id)
    except EventPresetNotFound as exc:
        return _preset_error(request, exc)
    return JSONResponse({"items": items}, headers=_ok_headers(request))


@router.post("/sites/{site_id}/event-presets")
def create_event_preset(
    site_id: str,
    request: Request,
    body: dict[str, Any],
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> JSONResponse:
    key = _require_idempotency(request, idempotency_key)
    if isinstance(key, JSONResponse):
        return key
    host = _state(request)
    name = str(body.get("name", "Event Preset"))
    document = body.get("document")
    req_digest = _digest({"site_id": site_id, "name": name, "document": document})
    try:
        preset, revision, created = host.event_preset_service().create_preset(
            site_id=site_id,
            name=name,
            document=document if isinstance(document, dict) else None,
            idempotency_key=key,
            request_digest=req_digest,
            correlation_id=request.state.correlation_id,
        )
    except (
        EventPresetNotFound,
        EventPresetPreconditionFailed,
        EventPresetIdempotencyConflict,
        EventPresetConflict,
        EventPresetValidationFailed,
    ) as exc:
        return _preset_error(request, exc)
    status = 201 if created else 200
    return JSONResponse(
        {"preset": preset, "revision": revision},
        status_code=status,
        headers=_ok_headers(
            request,
            {
                "ETag": preset["etag"],
                "Location": f"/api/router-control/v1/event-presets/{preset['preset_id']}",
            },
        ),
    )


@router.get("/event-presets/{preset_id}")
def get_event_preset(preset_id: str, request: Request) -> JSONResponse:
    host = _state(request)
    try:
        preset = host.event_preset_service().get_preset(preset_id)
    except EventPresetNotFound as exc:
        return _preset_error(request, exc)
    return JSONResponse(preset, headers=_ok_headers(request, {"ETag": preset["etag"]}))


@router.post("/event-presets/{preset_id}/revisions")
def create_event_preset_revision(
    preset_id: str,
    request: Request,
    body: dict[str, Any],
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    if_match: str | None = Header(default=None, alias="If-Match"),
) -> JSONResponse:
    key = _require_idempotency(request, idempotency_key)
    if isinstance(key, JSONResponse):
        return key
    parsed = _parse_if_match(if_match)
    if parsed == "invalid":
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="If-Match ETag invalid",
        )
    document = body.get("document")
    if not isinstance(document, dict):
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="document required",
        )
    host = _state(request)
    req_digest = _digest({"preset_id": preset_id, "document": document})
    try:
        preset, revision, created = host.event_preset_service().create_revision(
            preset_id=preset_id,
            document=document,
            idempotency_key=key,
            request_digest=req_digest,
            expected_version=parsed if isinstance(parsed, int) else None,
            correlation_id=request.state.correlation_id,
        )
    except (
        EventPresetNotFound,
        EventPresetPreconditionFailed,
        EventPresetIdempotencyConflict,
        EventPresetConflict,
        EventPresetValidationFailed,
    ) as exc:
        return _preset_error(request, exc)
    status = 201 if created else 200
    return JSONResponse(
        {"preset": preset, "revision": revision},
        status_code=status,
        headers=_ok_headers(request, {"ETag": preset["etag"]}),
    )


@router.get("/event-presets/{preset_id}/revisions/{revision_id}")
def get_event_preset_revision(preset_id: str, revision_id: str, request: Request) -> JSONResponse:
    host = _state(request)
    try:
        revision = host.event_preset_service().get_revision(preset_id, revision_id)
    except EventPresetNotFound as exc:
        return _preset_error(request, exc)
    return JSONResponse(revision, headers=_ok_headers(request, {"ETag": revision["etag"]}))


@router.post("/event-presets/{preset_id}/publish")
def publish_event_preset_revision(
    preset_id: str,
    request: Request,
    body: dict[str, Any],
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    if_match: str | None = Header(default=None, alias="If-Match"),
) -> JSONResponse:
    key = _require_idempotency(request, idempotency_key)
    if isinstance(key, JSONResponse):
        return key
    parsed = _parse_if_match(if_match)
    if parsed == "invalid":
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="If-Match ETag invalid",
        )
    revision_id = body.get("revision_id")
    if not isinstance(revision_id, str) or not revision_id.strip():
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="revision_id required",
        )
    host = _state(request)
    req_digest = _digest({"preset_id": preset_id, "revision_id": revision_id.strip()})
    try:
        preset, _created = host.event_preset_service().publish_revision(
            preset_id=preset_id,
            revision_id=revision_id.strip(),
            idempotency_key=key,
            request_digest=req_digest,
            expected_version=parsed if isinstance(parsed, int) else None,
            correlation_id=request.state.correlation_id,
        )
    except (
        EventPresetNotFound,
        EventPresetPreconditionFailed,
        EventPresetIdempotencyConflict,
        EventPresetConflict,
    ) as exc:
        return _preset_error(request, exc)
    return JSONResponse(preset, headers=_ok_headers(request, {"ETag": preset["etag"]}))


@router.post("/event-presets/{preset_id}/validate")
def validate_event_preset(
    preset_id: str,
    request: Request,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> JSONResponse:
    host = _state(request)
    if _wants_async(request):
        key = _require_idempotency(request, idempotency_key)
        if isinstance(key, JSONResponse):
            return key
        req_digest = _digest({"preset_id": preset_id, "action": "validate"})
        try:
            body = host.event_preset_service().enqueue_validate_async(
                preset_id=preset_id,
                idempotency_key=key,
                request_digest=req_digest,
                correlation_id=request.state.correlation_id,
            )
        except EventPresetNotFound as exc:
            return _preset_error(request, exc)
        return _async_accepted(request, body)
    try:
        result = host.event_preset_service().validate_preset(preset_id)
    except EventPresetNotFound as exc:
        return _preset_error(request, exc)
    return JSONResponse(result, headers=_ok_headers(request))


@router.post("/event-presets/{preset_id}/plan-preview")
def plan_preview_event_preset(
    preset_id: str,
    request: Request,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> JSONResponse:
    host = _state(request)
    if _wants_async(request):
        key = _require_idempotency(request, idempotency_key)
        if isinstance(key, JSONResponse):
            return key
        req_digest = _digest({"preset_id": preset_id, "action": "plan_readiness"})
        try:
            body = host.event_preset_service().enqueue_plan_readiness_async(
                preset_id=preset_id,
                idempotency_key=key,
                request_digest=req_digest,
                correlation_id=request.state.correlation_id,
            )
        except EventPresetNotFound as exc:
            return _preset_error(request, exc)
        return _async_accepted(request, body)
    try:
        preview = host.event_preset_service().plan_preview(preset_id)
    except EventPresetNotFound as exc:
        return _preset_error(request, exc)
    return JSONResponse(preview, headers=_ok_headers(request))


@router.get("/event-presets/{preset_id}/readiness/report")
def readiness_report(preset_id: str, request: Request) -> JSONResponse:
    host = _state(request)
    try:
        report = host.event_preset_service().readiness_report(preset_id)
    except EventPresetNotFound as exc:
        return _preset_error(request, exc)
    return JSONResponse(report, headers=_ok_headers(request))


@router.post(
    "/event-presets/{preset_id}/publications",
    responses={
        201: {"description": "Created"},
        200: {"description": "Idempotent replay"},
    },
)
def create_publication(
    preset_id: str,
    request: Request,
    body: CreatePublicationBody,
    idempotency_key: IdempotencyKeyHeader,
    if_match: IfMatchHeader,
) -> JSONResponse:
    key = _require_idempotency(request, idempotency_key)
    if isinstance(key, JSONResponse):
        return key
    parsed = _parse_if_match(if_match)
    if parsed == "invalid":
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="If-Match ETag invalid",
        )
    revision_id = body.revision_id
    host = _state(request)
    cookie = request.cookies.get(HUB_ADMIN_COOKIE_NAME)
    session_hmac = session_binding_from_cookie(cookie)
    if session_hmac is None:
        return error_response(
            request,
            status_code=403,
            code="session_binding_mismatch",
            message="Valid session required",
        )
    revision = host.runtime.store.get_event_preset_revision(revision_id.strip())
    if revision is None or str(revision["preset_id"]) != preset_id:
        return error_response(
            request, status_code=404, code="resource.not_found", message="revision not found"
        )
    if str(revision["validation_status"]) != ValidationStatus.VALID_OFFLINE.value:
        return error_response(
            request,
            status_code=422,
            code="publication.not_valid_offline",
            message="revision not ValidOffline",
        )
    preset = host.runtime.store.get_event_preset(preset_id)
    assert preset is not None
    planner = DeploymentPlannerService(store=host.runtime.store, clock=host.runtime.clock)
    canonical = host.runtime.store.revision_canonical_json(revision)
    doc_digest, schema_digest, validation_digest = planner.publication_digests(
        canonical_document=canonical,
        validation_status=ValidationStatus.VALID_OFFLINE,
    )
    lineage = planner.lineage_for_publication(
        preset_id=preset_id,
        revision_id=revision_id.strip(),
        revision_number=int(revision["revision_number"]),
        published_at=host.runtime.clock.now(),
        actor_id="hub_admin",
    )
    req_digest = _digest({"preset_id": preset_id, "revision_id": revision_id.strip()})
    try:
        row, created = host.runtime.store.create_published_preset_idempotent(
            preset_id=preset_id,
            source_revision_id=revision_id.strip(),
            site_id=str(preset["site_id"]),
            canonical_document_digest=doc_digest,
            schema_digest=schema_digest,
            validation_digest=validation_digest,
            source_lineage_json=json.dumps(lineage, sort_keys=True, separators=(",", ":")),
            publisher_session_binding_hmac=session_hmac,
            idempotency_key=key,
            request_digest=req_digest,
            expected_version=parsed if isinstance(parsed, int) else None,
            actor_id="hub_admin",
            now=host.runtime.clock.now(),
        )
    except PreconditionFailed as exc:
        return error_response(
            request, status_code=412, code="resource.precondition_failed", message=str(exc)
        )
    except (ConflictError, NotFoundError) as exc:
        status = 404 if isinstance(exc, NotFoundError) else 409
        return error_response(
            request, status_code=status, code="resource.conflict", message=str(exc)
        )
    return JSONResponse(
        {
            "published_preset_id": row["published_preset_id"],
            "preset_id": preset_id,
            "source_revision_id": row["source_revision_id"],
            "canonical_document_digest": row["canonical_document_digest"],
            "published_at": row["published_at"],
        },
        status_code=201 if created else 200,
        headers=_ok_headers(request),
    )


@router.get("/event-presets/{preset_id}/publications/{published_preset_id}")
def get_publication(preset_id: str, published_preset_id: str, request: Request) -> JSONResponse:
    host = _state(request)
    row = host.runtime.store.get_published_preset(published_preset_id)
    if row is None or str(row["preset_id"]) != preset_id:
        return error_response(
            request, status_code=404, code="resource.not_found", message="publication not found"
        )
    return JSONResponse(
        {
            "published_preset_id": row["published_preset_id"],
            "preset_id": row["preset_id"],
            "source_revision_id": row["source_revision_id"],
            "canonical_document_digest": row["canonical_document_digest"],
            "published_at": row["published_at"],
            "source_lineage": json.loads(str(row["source_lineage_json"])),
        },
        headers=_ok_headers(request),
    )
