"""Wi-Fi station (WISP) preview API routes (read-only offline compile; no dispatch)."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from router_control.application.wifi_observation_helpers import (
    ERROR_CODE_STATION_PRIORITY_REQUIRES_IP_GLOBAL,
)
from router_control.application.wifi_station_apply_planner import (
    WifiStationApplyPlannerError,
    WifiStationAuthMode,
    WifiStationPlannerOptions,
)
from router_control.application.wifi_station_apply_service import (
    WifiStationApplyServiceError,
    preview_wifi_station_apply,
)
from router_control.domain.network_intents import UplinkIntent, UplinkMode, WifiBand

from router_control_host.apply_response_models import WifiStationPreviewResponse
from router_control_host.errors import error_response
from router_control_host.routes import API_PREFIX, _ok_headers

router = APIRouter(prefix=API_PREFIX, tags=["wifi-station-preview"])

_MSG_OPEN_UNSUPPORTED = (
    "not yet supported: no verified open-network authentication grammar"
)

_PLANNER_CODE_TO_HTTP: dict[str, str] = {
    ERROR_CODE_STATION_PRIORITY_REQUIRES_IP_GLOBAL: "wifi.station_priority_requires_ip_global",
}

_PLANNER_UNSUPPORTED_MESSAGES: dict[str, str] = {
    ERROR_CODE_STATION_PRIORITY_REQUIRES_IP_GLOBAL: (
        "non-default priority requires live path include_ip_global planner option"
    ),
}


def _station_preview_error(request: Request, exc: BaseException) -> JSONResponse:
    planner_code = str(exc)
    http_code = _PLANNER_CODE_TO_HTTP.get(planner_code)
    if http_code is not None:
        return error_response(
            request,
            status_code=422,
            code=http_code,
            message=_PLANNER_UNSUPPORTED_MESSAGES.get(planner_code, planner_code),
        )
    return error_response(
        request,
        status_code=422,
        code="wifi.station_preview_failed",
        message=str(exc),
    )


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class WifiStationPreviewBody(_StrictModel):
    mode: UplinkMode = UplinkMode.WIFI_WAN
    ssid: str = Field(min_length=1, max_length=32)
    band: WifiBand = WifiBand.BAND_2_4GHZ
    credential_ref_id: str | None = Field(default=None, min_length=1)
    bssid: str | None = Field(default=None, min_length=1)
    priority: int = 100
    auth_mode: WifiStationAuthMode | None = None


@router.post("/wifi/station/preview", response_model=WifiStationPreviewResponse)
def wifi_station_preview(request: Request, body: WifiStationPreviewBody) -> JSONResponse:
    if body.mode != UplinkMode.WIFI_WAN:
        return error_response(
            request,
            status_code=422,
            code="wifi.station_preview_failed",
            message=f"station preview requires mode WifiWan, got {body.mode.value}",
        )

    auth_mode = body.auth_mode or WifiStationAuthMode.WPA2_PSK
    if auth_mode is WifiStationAuthMode.OPEN:
        return error_response(
            request,
            status_code=422,
            code="wifi.station_preview_failed",
            message=_MSG_OPEN_UNSUPPORTED,
        )

    try:
        intent = UplinkIntent(
            mode=UplinkMode.WIFI_WAN,
            ssid=body.ssid,
            band=body.band,
            credential_ref_id=body.credential_ref_id,
            bssid=body.bssid,
            priority=body.priority,
        )
        if not intent.credential_ref_id:
            raise WifiStationApplyServiceError(
                "WifiWan station apply requires credential_ref_id"
            )
        options = WifiStationPlannerOptions(auth_mode=auth_mode)
        preview = preview_wifi_station_apply(intent, options=options)
    except (WifiStationApplyServiceError, WifiStationApplyPlannerError, ValueError) as exc:
        return _station_preview_error(request, exc)

    return JSONResponse(preview, status_code=200, headers=_ok_headers(request))
