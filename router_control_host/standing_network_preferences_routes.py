"""Standing network preferences API — host-persisted Wi‑Fi defaults (no plaintext secrets)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from router_control.application.standing_network_preferences import (
    StandingNetworkPreferencesValidationError,
)

from router_control_host.errors import (
    operator_structured_error_response,
)
from router_control_host.routes import API_PREFIX, _ok_headers
from router_control_host.state import HostState

router = APIRouter(prefix=API_PREFIX, tags=["standing-network-preferences"])

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


class PutStandingNetworkPreferencesBody(_StrictModel):
    staff_ssid: str | None = None
    staff_password_credential_ref_id: str | None = Field(default=None)
    guest_default_ssid: str | None = None
    guest_default_enabled: bool | None = None
    staff_ap_id: str | None = Field(default=None)
    guest_ap_id: str | None = Field(default=None)


def _state(request: Request) -> HostState:
    return request.app.state.host  # type: ignore[no-any-return]


def _validation_error(
    request: Request, exc: StandingNetworkPreferencesValidationError
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
                code="standing.secret_key_forbidden",
                reason="invalid_format",
                field=key,
            )
    return None


def _reject_guest_default_enabled_true(
    request: Request, raw: dict[str, Any]
) -> JSONResponse | None:
    if raw.get("guest_default_enabled") is True:
        return operator_structured_error_response(
            request,
            status_code=422,
            code="standing.guest_default_enabled_read_only",
            reason="invalid_format",
            field="guest_default_enabled",
        )
    return None


@router.get("/standing-network-preferences")
def get_standing_network_preferences(request: Request) -> JSONResponse:
    host = _state(request)
    payload = host.standing_network_preferences_service().get_preferences()
    return JSONResponse(payload, headers=_ok_headers(request))


@router.put("/standing-network-preferences")
async def put_standing_network_preferences(request: Request) -> JSONResponse:
    host = _state(request)
    try:
        raw = await request.json()
    except Exception:
        return operator_structured_error_response(
            request,
            status_code=422,
            code="standing.invalid_body",
            reason="invalid_format",
            field=None,
        )
    if not isinstance(raw, dict):
        return operator_structured_error_response(
            request,
            status_code=422,
            code="standing.invalid_body",
            reason="invalid_format",
            field=None,
        )
    secret_guard = _reject_secret_shaped_keys(request, raw)
    if secret_guard is not None:
        return secret_guard
    enabled_guard = _reject_guest_default_enabled_true(request, raw)
    if enabled_guard is not None:
        return enabled_guard
    try:
        body = PutStandingNetworkPreferencesBody.model_validate(raw)
    except Exception:
        return operator_structured_error_response(
            request,
            status_code=422,
            code="standing.validation_failed",
            reason="invalid_format",
            field=None,
        )
    update_kwargs: dict[str, Any] = {}
    if body.staff_ssid is not None:
        update_kwargs["staff_ssid"] = body.staff_ssid
    if "staff_password_credential_ref_id" in body.model_fields_set:
        update_kwargs["staff_password_credential_ref_id"] = (
            body.staff_password_credential_ref_id
        )
    if "staff_ap_id" in body.model_fields_set:
        update_kwargs["staff_ap_id"] = body.staff_ap_id
    if "guest_ap_id" in body.model_fields_set:
        update_kwargs["guest_ap_id"] = body.guest_ap_id
    if body.guest_default_ssid is not None:
        update_kwargs["guest_default_ssid"] = body.guest_default_ssid
    if not update_kwargs:
        payload = host.standing_network_preferences_service().get_preferences()
        return JSONResponse(payload, headers=_ok_headers(request))
    try:
        payload = host.standing_network_preferences_service().update_preferences(
            **update_kwargs
        )
    except StandingNetworkPreferencesValidationError as exc:
        return _validation_error(request, exc)
    return JSONResponse(payload, headers=_ok_headers(request))
