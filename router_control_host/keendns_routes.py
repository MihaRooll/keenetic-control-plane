"""KeenDNS/CrazeDNS read-only status + preview API routes (no apply/dispatch)."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from router_control.application.keendns_observe import classify_keendns_status
from router_control.application.keendns_preview_service import (
    KeenDnsPreviewServiceError,
    preview_keendns,
)

from router_control_host.apply_response_models import KeenDnsPreviewResponse, KeenDnsStatusResponse
from router_control_host.errors import error_response
from router_control_host.routes import API_PREFIX, _ok_headers

router = APIRouter(prefix=API_PREFIX, tags=["keendns-preview"])


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class KeenDnsStatusBody(_StrictModel):
    components_raw: str | None = None
    ndns_show_raw: str | None = None
    get_booked_raw: str | None = None


class KeenDnsPreviewBody(_StrictModel):
    intent_kind: Literal["book", "drop"]
    name: str = Field(min_length=1, max_length=63)
    domain: str = Field(min_length=1, max_length=64)
    mode: Literal["auto", "cloud", "direct"] | None = None


@router.post(
    "/keendns/status",
    response_model=KeenDnsStatusResponse,
)
def keendns_status(
    request: Request, body: KeenDnsStatusBody | None = None
) -> KeenDnsStatusResponse | JSONResponse:
    payload = body or KeenDnsStatusBody()
    result = classify_keendns_status(
        components_raw=payload.components_raw,
        ndns_show_raw=payload.ndns_show_raw,
        get_booked_raw=payload.get_booked_raw,
    )
    return JSONResponse(
        KeenDnsStatusResponse.model_validate(result).model_dump(),
        status_code=200,
        headers=_ok_headers(request),
    )


@router.post(
    "/keendns/preview",
    response_model=KeenDnsPreviewResponse,
)
def keendns_preview(
    request: Request, body: KeenDnsPreviewBody
) -> KeenDnsPreviewResponse | JSONResponse:
    if body.intent_kind == "book" and body.mode is None:
        return error_response(
            request,
            status_code=422,
            code="keendns.preview_failed",
            message="mode is required for intent_kind=book",
        )
    if body.intent_kind == "drop" and body.mode is not None:
        return error_response(
            request,
            status_code=422,
            code="keendns.preview_failed",
            message="mode must be omitted for intent_kind=drop",
        )
    intent = {
        "intent_kind": body.intent_kind,
        "name": body.name,
        "domain": body.domain,
    }
    if body.mode is not None:
        intent["mode"] = body.mode
    try:
        preview = preview_keendns(intent)
    except KeenDnsPreviewServiceError as exc:
        return error_response(
            request,
            status_code=422,
            code="keendns.preview_failed",
            message=str(exc),
        )
    return JSONResponse(
        KeenDnsPreviewResponse.model_validate(preview).model_dump(),
        status_code=200,
        headers=_ok_headers(request),
    )
