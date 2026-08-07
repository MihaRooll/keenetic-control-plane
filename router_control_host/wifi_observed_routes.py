"""Wi-Fi observed-state read-only API routes (auth-gated; fake or live read-only session)."""

from __future__ import annotations

from typing import Any, cast

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from router_control.adapters.netcraze.allowlist import validate_wifi_ap_id
from router_control.application.wifi_observed_state import (
    WifiObservedStateError,
    WifiObservedTransport,
    run_wifi_observed_state,
)
from router_control.domain.network_intents import (
    CaptivePortalMode,
    WifiBand,
    WifiIntent,
    WifiWpaMode,
)

from router_control_host.apply_response_models import WifiObservedStateResponse
from router_control_host.errors import (
    error_response,
    operator_structured_error_response,
    synthesize_operator_message,
)
from router_control_host.fake_wifi_device import FakeWifiDeviceState, ensure_fake_wifi_device
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

router = APIRouter(prefix=API_PREFIX, tags=["wifi-observed"])

_LIVE_REQUIRED_FIELDS = (
    "host",
    "username",
    "router_credential_ref_id",
    "ssh_host_key_sha256",
    "source_address",
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class WifiObservedDesiredFields(_StrictModel):
    ssid: str = Field(min_length=1, max_length=32)
    enabled: bool
    wpa_mode: WifiWpaMode
    band: WifiBand


class WifiObservedStateBody(_StrictModel):
    host: str | None = Field(default=None, min_length=1)
    username: str | None = Field(default=None, min_length=1)
    credential_ref_id: str | None = Field(default=None, min_length=1)
    router_credential_ref_id: str | None = Field(default=None, min_length=1)
    ssh_host_key_sha256: str | None = Field(default=None, min_length=1)
    source_address: str | None = Field(default=None, min_length=1)
    router_id: str | None = Field(default=None, min_length=1)
    allow_insecure_http: bool | None = None
    ap_ids: list[str] | None = None
    desired: WifiObservedDesiredFields | None = None
    desired_ap_id: str | None = Field(default=None, min_length=1, max_length=64)


class _DefaultFakeWifiObservedTransport:
    """Offline readbacks backed by shared per-app fake device state."""

    def __init__(self, device: FakeWifiDeviceState | None = None) -> None:
        self._device = device if device is not None else FakeWifiDeviceState()
        self.parse_commands: list[str] = []

    def execute_rci_parse(self, cli_command: str) -> dict[str, Any]:
        self.parse_commands.append(cli_command)
        parts = cli_command.split()
        if len(parts) >= 3 and parts[0].lower() == "show" and parts[1].lower() == "interface":
            return self._device.readback_for(parts[2])
        for ap_id in self._device._aps:
            if ap_id in cli_command:
                return self._device.readback_for(ap_id)
        return self._device.readback_for("")


def _state(request: Request) -> HostState:
    return request.app.state.host  # type: ignore[no-any-return]


def _intent_from_desired(body: WifiObservedDesiredFields) -> WifiIntent:
    return WifiIntent(
        ssid=body.ssid,
        enabled=body.enabled,
        credential_ref_id=None,
        captive_portal=CaptivePortalMode.DISABLED,
        guest_isolation=False,
        wpa_mode=body.wpa_mode,
        band=body.band,
    )


def _resolved_router_credential_ref_id(body: WifiObservedStateBody) -> str | None:
    if body.router_credential_ref_id and str(body.router_credential_ref_id).strip():
        return str(body.router_credential_ref_id).strip()
    if body.credential_ref_id and str(body.credential_ref_id).strip():
        return str(body.credential_ref_id).strip()
    return None


def _live_params_from_body(
    body: WifiObservedStateBody,
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


def _should_use_live_path(body: WifiObservedStateBody, host: HostState) -> bool:
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
        status_code=422,
        code="wifi.live_connection_required",
        message=(
            "live observed-state requires connection params: "
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
        message="Gate A certification required for live Wi-Fi observed-state",
    )


def _resolve_transport(host: HostState, request: Request) -> JSONResponse | WifiObservedTransport:
    factory = host.wifi_observed_transport_factory or host.wifi_apply_transport_factory
    if factory is not None:
        return cast(WifiObservedTransport, factory())
    if host.adapter_mode == "fake":
        device = ensure_fake_wifi_device(host)
        return _DefaultFakeWifiObservedTransport(device)
    return error_response(
        request,
        status_code=503,
        code="feature.degraded",
        message="Wi-Fi observed-state transport not configured",
    )


def _ap_validation_error(request: Request, exc: ValueError) -> JSONResponse:
    _ = exc
    return operator_structured_error_response(
        request,
        status_code=422,
        code="wifi.ap_forbidden",
        reason="not_allowlisted",
        field="ap_id",
    )


def _service_error(request: Request, exc: WifiObservedStateError) -> JSONResponse:
    _ = exc
    return error_response(
        request,
        status_code=422,
        code="wifi.observed_state_failed",
        message=synthesize_operator_message(
            code="wifi.observed_state_failed",
            reason="observed_state_failed",
        ),
    )


@router.post("/wifi/observed-state", response_model=WifiObservedStateResponse)
def wifi_observed_state(request: Request, body: WifiObservedStateBody) -> JSONResponse:
    if body.ap_ids:
        for ap_id in body.ap_ids:
            try:
                validate_wifi_ap_id(ap_id)
            except ValueError as exc:
                return _ap_validation_error(request, exc)
    if body.desired_ap_id:
        try:
            validate_wifi_ap_id(body.desired_ap_id)
        except ValueError as exc:
            return _ap_validation_error(request, exc)

    host = _state(request)

    desired_by_ap: dict[str, WifiIntent] | None = None
    if body.desired is not None:
        target_ap = body.desired_ap_id
        if target_ap is None and body.ap_ids and len(body.ap_ids) == 1:
            target_ap = body.ap_ids[0]
        if target_ap is None:
            return error_response(
                request,
                status_code=422,
                code="wifi.observed_state_failed",
                message="desired_ap_id required when desired intent supplied",
            )
        desired_by_ap = {target_ap: _intent_from_desired(body.desired)}

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
                report = run_wifi_observed_state(
                    transport=session.transport,
                    ap_ids=body.ap_ids,
                    desired_by_ap=desired_by_ap,
                    transport_security="ssh_tunnel_pinned",
                    https_check="not_certified",
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
                message="wifi observed-state must remain non-certifying",
            )
        return JSONResponse(payload, status_code=200, headers=_ok_headers(request))

    if host.adapter_mode == "live":
        return _live_params_required_error(request)

    transport = _resolve_transport(host, request)
    if isinstance(transport, JSONResponse):
        return transport

    try:
        report = run_wifi_observed_state(
            transport=transport,
            ap_ids=body.ap_ids,
            desired_by_ap=desired_by_ap,
            transport_security="fixture",
            https_check="not_certified",
        )
    except WifiObservedStateError as exc:
        return _service_error(request, exc)

    payload = report.to_dict()
    if payload.get("certification_eligible") is not False:
        return error_response(
            request,
            status_code=500,
            code="internal.error",
            message="wifi observed-state must remain non-certifying",
        )
    return JSONResponse(payload, status_code=200, headers=_ok_headers(request))
