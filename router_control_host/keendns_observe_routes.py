"""KeenDNS/CrazeDNS read-only live observe API routes (auth-gated; fake or live RO session)."""

from __future__ import annotations

from typing import Any, cast

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from router_control.application.keendns_observe import (
    KeenDnsObserveTransport,
    run_keendns_observe,
)

from router_control_host.apply_response_models import KeenDnsObserveResponse
from router_control_host.errors import error_response, operator_structured_error_response
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

router = APIRouter(prefix=API_PREFIX, tags=["keendns-observe"])

_LIVE_REQUIRED_FIELDS = (
    "host",
    "username",
    "router_credential_ref_id",
    "ssh_host_key_sha256",
    "source_address",
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class KeenDnsObserveBody(_StrictModel):
    host: str | None = Field(default=None, min_length=1)
    username: str | None = Field(default=None, min_length=1)
    credential_ref_id: str | None = Field(default=None, min_length=1)
    router_credential_ref_id: str | None = Field(default=None, min_length=1)
    ssh_host_key_sha256: str | None = Field(default=None, min_length=1)
    source_address: str | None = Field(default=None, min_length=1)
    router_id: str | None = Field(default=None, min_length=1)
    allow_insecure_http: bool | None = None


class _DefaultFakeKeenDnsObserveTransport:
    """Offline deterministic KeenDNS observe for fake adapter mode."""

    def __init__(
        self,
        *,
        default_fqdn: str | None = None,
        ssl_valid: bool | None = None,
    ) -> None:
        self.default_fqdn = default_fqdn
        self.ssl_valid = ssl_valid
        self.parse_commands: list[str] = []

    def execute_rci_parse(self, cli_command: str) -> dict[str, Any]:
        self.parse_commands.append(cli_command)
        if cli_command == "show acme":
            if self.default_fqdn:
                payload: dict[str, Any] = {
                    "acme": {
                        "default-domain": self.default_fqdn,
                    }
                }
                if self.ssl_valid is not None:
                    payload["acme"]["default-domain-certificate-valid"] = self.ssl_valid
                return payload
            return {"acme": {"default-domain": ""}}
        if cli_command == "show ndns":
            return {
                "name": "",
                "domain": "",
                "access": "",
            }
        if cli_command == "ndns get-booked":
            return {"continued": True, "message": "No booking found"}
        return {}


def _state(request: Request) -> HostState:
    return request.app.state.host  # type: ignore[no-any-return]


def _resolved_router_credential_ref_id(body: KeenDnsObserveBody) -> str | None:
    if body.router_credential_ref_id and str(body.router_credential_ref_id).strip():
        return str(body.router_credential_ref_id).strip()
    if body.credential_ref_id and str(body.credential_ref_id).strip():
        return str(body.credential_ref_id).strip()
    return None


def _live_params_from_body(
    body: KeenDnsObserveBody,
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


def _should_use_live_path(body: KeenDnsObserveBody, host: HostState) -> bool:
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
        code="keendns.live_connection_incomplete",
        reason="incomplete",
        details=details,
        context=", ".join(missing),
    )


def _live_params_required_error(request: Request) -> JSONResponse:
    return error_response(
        request,
        status_code=503,
        code="keendns.live_connection_required",
        message=(
            "live KeenDNS observe requires connection params: "
            + ", ".join(_LIVE_REQUIRED_FIELDS)
        ),
    )


def _live_platform_unsupported_error(request: Request) -> JSONResponse:
    return error_response(
        request,
        status_code=503,
        code="keendns.live_platform_unsupported",
        message=(
            "live KeenDNS observe transport requires win32 with DPAPI-backed credential vault"
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
    code = mapped.code.replace("wifi.", "keendns.", 1) if mapped.code.startswith("wifi.") else mapped.code
    return error_response(
        request,
        status_code=mapped.status_code,
        code=code,
        message=mapped.message,
    )


def _gate_a_required_error(request: Request) -> JSONResponse:
    return error_response(
        request,
        status_code=503,
        code="keendns.gate_a_required",
        message="Gate A certification required for live KeenDNS observe",
    )


def _resolve_transport(host: HostState, request: Request) -> JSONResponse | KeenDnsObserveTransport:
    factory = getattr(host, "keendns_observe_transport_factory", None)
    if factory is not None:
        return cast(KeenDnsObserveTransport, factory())
    if host.adapter_mode == "fake":
        return _DefaultFakeKeenDnsObserveTransport()
    return error_response(
        request,
        status_code=503,
        code="feature.degraded",
        message="KeenDNS observe transport not configured",
    )


@router.post("/keendns/observe", response_model=KeenDnsObserveResponse)
def keendns_observe(request: Request, body: KeenDnsObserveBody) -> JSONResponse:
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
                observation = run_keendns_observe(transport=session.transport)
        except Exception as exc:
            return _live_transport_error(
                request,
                exc,
                router_credential_ref_id=router_cred_ref,
            )
        payload = KeenDnsObserveResponse.model_validate(observation).model_dump()
        if payload.get("certification_eligible") is not False:
            return error_response(
                request,
                status_code=500,
                code="internal.error",
                message="KeenDNS observe must remain non-certifying",
            )
        return JSONResponse(payload, status_code=200, headers=_ok_headers(request))

    if host.adapter_mode == "live":
        return _live_params_required_error(request)

    transport = _resolve_transport(host, request)
    if isinstance(transport, JSONResponse):
        return transport

    observation = run_keendns_observe(transport=transport)
    payload = KeenDnsObserveResponse.model_validate(observation).model_dump()
    if payload.get("certification_eligible") is not False:
        return error_response(
            request,
            status_code=500,
            code="internal.error",
            message="KeenDNS observe must remain non-certifying",
        )
    return JSONResponse(payload, status_code=200, headers=_ok_headers(request))
