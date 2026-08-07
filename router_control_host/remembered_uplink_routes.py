"""Remembered Wi-Fi uplink API — host persistence (credential_ref only)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from router_control.application.remembered_uplink import RememberedUplinkValidationError

from router_control_host.errors import operator_structured_error_response
from router_control_host.routes import API_PREFIX, _ok_headers
from router_control_host.state import HostState

router = APIRouter(prefix=API_PREFIX, tags=["remembered-uplink"])

_SECRET_SHAPED_KEYS = frozenset(
    {
        "password",
        "secret",
        "psk",
        "passphrase",
        "wpa_psk",
        "key",
        "wifi_password",
    }
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PutRememberedUplinkBody(_StrictModel):
    router_id: str | None = Field(default=None)
    ssid: str | None = None
    band: str | None = None
    station_id: str | None = None
    credential_ref_id: str | None = Field(default=None)
    desired_active: bool | None = None


def _state(request: Request) -> HostState:
    return request.app.state.host  # type: ignore[no-any-return]


def _validation_error(
    request: Request, exc: RememberedUplinkValidationError
) -> JSONResponse:
    return operator_structured_error_response(
        request,
        status_code=422,
        code=exc.code,
        reason="invalid_format",
        field=exc.field,
    )


def _reject_secret_shaped_keys(
    request: Request, raw: dict[str, Any]
) -> JSONResponse | None:
    for key in raw:
        if key in _SECRET_SHAPED_KEYS:
            return operator_structured_error_response(
                request,
                status_code=422,
                code="remembered_uplink.secret_key_forbidden",
                reason="invalid_format",
                field=key,
            )
    return None


@router.get("/remembered-uplink/watchdog-status")
def get_remembered_uplink_watchdog_status(request: Request) -> JSONResponse:
    host = _state(request)
    payload = host.uplink_watchdog_status()
    return JSONResponse(payload, headers=_ok_headers(request))


@router.get("/remembered-uplink")
def get_remembered_uplink(request: Request) -> JSONResponse:
    host = _state(request)
    payload = host.remembered_uplink_service().get_remembered()
    return JSONResponse(payload, headers=_ok_headers(request))


@router.put("/remembered-uplink")
async def put_remembered_uplink(request: Request) -> JSONResponse:
    host = _state(request)
    try:
        raw = await request.json()
    except Exception:
        return operator_structured_error_response(
            request,
            status_code=422,
            code="remembered_uplink.invalid_body",
            reason="invalid_format",
            field=None,
        )
    if not isinstance(raw, dict):
        return operator_structured_error_response(
            request,
            status_code=422,
            code="remembered_uplink.invalid_body",
            reason="invalid_format",
            field=None,
        )
    secret_guard = _reject_secret_shaped_keys(request, raw)
    if secret_guard is not None:
        return secret_guard
    try:
        body = PutRememberedUplinkBody.model_validate(raw)
    except Exception:
        return operator_structured_error_response(
            request,
            status_code=422,
            code="remembered_uplink.validation_failed",
            reason="invalid_format",
            field=None,
        )
    update_kwargs: dict[str, Any] = {}
    if "router_id" in body.model_fields_set:
        update_kwargs["router_id"] = body.router_id
    if body.ssid is not None:
        update_kwargs["ssid"] = body.ssid
    if body.band is not None:
        update_kwargs["band"] = body.band
    if "station_id" in body.model_fields_set:
        update_kwargs["station_id"] = body.station_id
    if "credential_ref_id" in body.model_fields_set:
        update_kwargs["credential_ref_id"] = body.credential_ref_id
    if body.desired_active is not None:
        update_kwargs["desired_active"] = body.desired_active
    if not update_kwargs:
        payload = host.remembered_uplink_service().get_remembered()
        return JSONResponse(payload, headers=_ok_headers(request))
    try:
        payload = host.remembered_uplink_service().update_remembered(**update_kwargs)
    except RememberedUplinkValidationError as exc:
        return _validation_error(request, exc)
    return JSONResponse(payload, headers=_ok_headers(request))


@router.delete("/remembered-uplink")
def delete_remembered_uplink(request: Request) -> JSONResponse:
    host = _state(request)
    payload = host.remembered_uplink_service().forget_remembered()
    return JSONResponse(payload, headers=_ok_headers(request))
