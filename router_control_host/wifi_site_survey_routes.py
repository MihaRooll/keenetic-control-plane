"""Wi-Fi site-survey read-only API routes (auth-gated; fake or live read-only session)."""

from __future__ import annotations

from typing import Any, cast

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from router_control.adapters.netcraze.site_survey import (
    SiteSurveyParseError,
    SiteSurveyRadio,
    validate_site_survey_radio,
)
from router_control.application.wifi_site_survey import (
    SiteSurveyTransport,
    WifiSiteSurveyError,
    run_wifi_site_survey,
)

from router_control_host.apply_response_models import WifiSiteSurveyResponse
from router_control_host.errors import (
    error_response,
    operator_structured_error_response,
    synthesize_operator_message,
)
from router_control_host.routes import API_PREFIX, _ok_headers
from router_control_host.state import HostState
from router_control_host.wifi_live_transport import (
    WifiLiveConnectionParams,
    connection_fields_present,
    connection_params_from_fields,
    is_win32_live_capable,
    map_wifi_live_transport_error,
    missing_connection_fields,
    open_wifi_live_session,
)

router = APIRouter(prefix=API_PREFIX, tags=["wifi-site-survey"])

_LIVE_REQUIRED_FIELDS = (
    "host",
    "username",
    "router_credential_ref_id",
    "ssh_host_key_sha256",
    "source_address",
)

class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class WifiSiteSurveyBody(_StrictModel):
    radio: SiteSurveyRadio = SiteSurveyRadio.WIFI_MASTER_0
    host: str | None = Field(default=None, min_length=1)
    username: str | None = Field(default=None, min_length=1)
    credential_ref_id: str | None = Field(default=None, min_length=1)
    router_credential_ref_id: str | None = Field(default=None, min_length=1)
    ssh_host_key_sha256: str | None = Field(default=None, min_length=1)
    source_address: str | None = Field(default=None, min_length=1)
    router_id: str | None = Field(default=None, min_length=1)
    allow_insecure_http: bool | None = None


class _LiveSiteSurveyTransport:
    def __init__(self, inner: Any) -> None:
        self._inner = inner

    def execute_site_survey(self, command: str) -> Any:
        return self._inner.execute_rci_parse(command)


class _DefaultFakeSiteSurveyTransport:
    """Offline deterministic site-survey text for fake adapter mode."""

    _SYNTH_WIFI_MASTER_0 = (
        "SSID                MAC                 Ch  Mode  Q\n"
        "SYNTH-SSID-Alpha    aa:bb:cc:dd:ee:01   6   n     85\n"
        "SYNTH-SSID-Beta     aa:bb:cc:dd:ee:02   11  ac    72\n"
    )
    _SYNTH_WIFI_MASTER_1 = (
        "SSID                MAC                 Ch  Mode  Q\n"
        "SYNTH-SSID-Gamma    aa:bb:cc:dd:ee:03   36  ac    64\n"
    )

    def __init__(self) -> None:
        self.commands: list[str] = []

    def execute_site_survey(self, command: str) -> str:
        self.commands.append(command)
        if SiteSurveyRadio.WIFI_MASTER_1.value in command:
            return self._SYNTH_WIFI_MASTER_1
        if SiteSurveyRadio.WIFI_MASTER_0.value in command:
            return self._SYNTH_WIFI_MASTER_0
        return "SSID                MAC                 Ch  Mode  Q\n"


def _state(request: Request) -> HostState:
    return request.app.state.host  # type: ignore[no-any-return]


def _resolved_router_credential_ref_id(body: WifiSiteSurveyBody) -> str | None:
    if body.router_credential_ref_id and str(body.router_credential_ref_id).strip():
        return str(body.router_credential_ref_id).strip()
    if body.credential_ref_id and str(body.credential_ref_id).strip():
        return str(body.credential_ref_id).strip()
    return None


def _live_params_from_body(
    body: WifiSiteSurveyBody,
    host: HostState,
) -> WifiLiveConnectionParams | None:
    return connection_params_from_fields(
        host=body.host,
        username=body.username,
        router_credential_ref_id=_resolved_router_credential_ref_id(body),
        ssh_host_key_sha256=body.ssh_host_key_sha256,
        source_address=body.source_address,
        router_id=body.router_id.strip() if body.router_id else None,
        store=host.runtime.store,
    )


def _should_use_live_path(body: WifiSiteSurveyBody, host: HostState) -> bool:
    return is_win32_live_capable() and _live_params_from_body(body, host) is not None


def _connection_incomplete_error(
    request: Request,
    *,
    missing: list[str],
) -> JSONResponse:
    details = [{"field": field, "reason": "required"} for field in missing]
    return operator_structured_error_response(
        request,
        status_code=422,
        code="wifi.live_connection_incomplete",
        reason="incomplete",
        details=details,
        context=", ".join(missing),
    )


def _live_params_required_error(request: Request) -> JSONResponse:
    return error_response(
        request,
        status_code=503,
        code="wifi.live_connection_required",
        message=(
            "live site-survey requires connection params: "
            + ", ".join(_LIVE_REQUIRED_FIELDS)
        ),
    )


def _live_platform_unsupported_error(request: Request) -> JSONResponse:
    return error_response(
        request,
        status_code=503,
        code="wifi.live_platform_unsupported",
        message=(
            "live Wi-Fi transport requires win32 with DPAPI-backed credential vault"
        ),
    )


def _live_transport_error(
    request: Request,
    exc: BaseException,
    *,
    router_credential_ref_id: str | None,
) -> JSONResponse:
    mapped = map_wifi_live_transport_error(
        exc,
        router_credential_ref_id=router_credential_ref_id,
    )
    return error_response(
        request,
        status_code=mapped.status_code,
        code=mapped.code,
        message=mapped.message,
    )


def _gate_a_required_error(request: Request) -> JSONResponse:
    return error_response(
        request,
        status_code=503,
        code="wifi.gate_a_required",
        message="Gate A certification required for live Wi-Fi site-survey",
    )


def _resolve_transport(
    host: HostState,
    request: Request,
) -> JSONResponse | SiteSurveyTransport:
    factory = getattr(host, "wifi_site_survey_transport_factory", None)
    if factory is not None:
        return cast(SiteSurveyTransport, factory())
    if host.adapter_mode == "fake":
        return _DefaultFakeSiteSurveyTransport()
    return error_response(
        request,
        status_code=503,
        code="feature.degraded",
        message="Wi-Fi site-survey transport not configured",
    )


def _radio_validation_error(request: Request, exc: ValueError) -> JSONResponse:
    _ = exc
    return operator_structured_error_response(
        request,
        status_code=422,
        code="wifi.site_survey_radio_forbidden",
        reason="invalid_value",
        field="radio",
    )


def _service_error(request: Request, exc: WifiSiteSurveyError) -> JSONResponse:
    _ = exc
    return error_response(
        request,
        status_code=422,
        code="wifi.site_survey_failed",
        message=synthesize_operator_message(
            code="wifi.site_survey_failed",
            reason="site_survey_failed",
        ),
    )


@router.post("/wifi/site-survey", response_model=WifiSiteSurveyResponse)
def wifi_site_survey(request: Request, body: WifiSiteSurveyBody) -> JSONResponse:
    try:
        radio = validate_site_survey_radio(body.radio.value)
    except SiteSurveyParseError as exc:
        return _radio_validation_error(request, ValueError(str(exc)))

    host = _state(request)
    router_cred_ref = _resolved_router_credential_ref_id(body)
    if connection_fields_present(
        host=body.host,
        username=body.username,
        router_credential_ref_id=router_cred_ref,
        ssh_host_key_sha256=body.ssh_host_key_sha256,
        source_address=body.source_address,
        router_id=body.router_id,
    ):
        missing = missing_connection_fields(
            host=body.host,
            username=body.username,
            router_credential_ref_id=router_cred_ref,
            ssh_host_key_sha256=body.ssh_host_key_sha256,
            source_address=body.source_address,
            router_id=body.router_id.strip() if body.router_id else None,
            store=host.runtime.store,
        )
        if missing:
            return _connection_incomplete_error(request, missing=missing)

    live_params = _live_params_from_body(body, host)
    if live_params is not None and not is_win32_live_capable():
        return _live_platform_unsupported_error(request)

    if _should_use_live_path(body, host):
        params = live_params
        assert params is not None
        cert = host.gate_a_certification
        if cert is None or not cert.is_open:
            return _gate_a_required_error(request)
        try:
            with open_wifi_live_session(params=params, vault=host.runtime.vault) as session:
                transport = _LiveSiteSurveyTransport(session.transport)
                report = run_wifi_site_survey(
                    transport=transport,
                    radio=radio,
                    transport_security="ssh_tunnel_pinned",
                )
        except Exception as exc:
            return _live_transport_error(
                request,
                exc,
                router_credential_ref_id=router_cred_ref,
            )
        payload = report.to_dict()
        if payload.get("certification_eligible") is not False:
            return error_response(
                request,
                status_code=500,
                code="internal.error",
                message="wifi site-survey must remain non-certifying",
            )
        return JSONResponse(payload, status_code=200, headers=_ok_headers(request))

    if host.adapter_mode == "live":
        return _live_params_required_error(request)

    resolved_transport = _resolve_transport(host, request)
    if isinstance(resolved_transport, JSONResponse):
        return resolved_transport

    try:
        report = run_wifi_site_survey(
            transport=resolved_transport,
            radio=radio,
            transport_security="fixture",
        )
    except WifiSiteSurveyError as exc:
        return _service_error(request, exc)

    payload = report.to_dict()
    if payload.get("certification_eligible") is not False:
        return error_response(
            request,
            status_code=500,
            code="internal.error",
            message="wifi site-survey must remain non-certifying",
        )
    return JSONResponse(payload, status_code=200, headers=_ok_headers(request))
