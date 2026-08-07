"""Host-side lab probe routes (read-only; operator workstation)."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict
from router_control.domain.errors import EventPresetNotFound

from router_control_host.apply_response_models import (
    HostHttpProbeResponse,
    HostInternetProbeResponse,
    HostTlsProbeResponse,
)
from router_control_host.errors import error_response, synthesize_operator_message
from router_control_host.host_probes import (
    DefaultHostProbeRunner,
    HostProbeRunner,
    extract_target_host,
)
from router_control_host.routes import API_PREFIX, _ok_headers
from router_control_host.state import HostState

router = APIRouter(prefix=API_PREFIX, tags=["host-probes"])


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HostHttpProbeBody(_StrictModel):
    url_ref: Literal["event_preset_local_order_url"]
    preset_id: str
    revision_id: str | None = None


class HostTlsProbeBody(_StrictModel):
    hostname_ref: Literal["event_preset_local_order_host"]
    preset_id: str
    revision_id: str | None = None


class HostInternetProbeBody(_StrictModel):
    targets_profile: Literal["default"] = "default"


def _state(request: Request) -> HostState:
    return request.app.state.host  # type: ignore[no-any-return]


def _resolve_runner(host: HostState) -> HostProbeRunner:
    runner = host.host_probe_runner
    if runner is not None:
        return runner
    return DefaultHostProbeRunner()


def _resolve_local_order_url(
    host: HostState,
    *,
    preset_id: str,
    revision_id: str | None,
) -> tuple[str | None, str | None]:
    svc = host.event_preset_service()
    try:
        if revision_id and revision_id.strip():
            rev = svc.get_revision(preset_id, revision_id.strip())
        else:
            preset = svc.get_preset(preset_id)
            current = preset.get("current_revision_id")
            if not isinstance(current, str) or not current.strip():
                return None, "host_http.preset_not_found"
            rev = svc.get_revision(preset_id, current.strip())
    except EventPresetNotFound:
        return None, "host_http.preset_not_found"
    canonical = rev.get("canonical_document")
    if not isinstance(canonical, dict):
        return None, "host_http.preset_not_found"
    url = canonical.get("local_order_url")
    if not isinstance(url, str) or not url.strip():
        return None, "host_http.preset_not_found"
    return url.strip(), None


def _resolve_local_order_hostname(
    host: HostState,
    *,
    preset_id: str,
    revision_id: str | None,
) -> tuple[str | None, str | None]:
    url, code = _resolve_local_order_url(
        host,
        preset_id=preset_id,
        revision_id=revision_id,
    )
    if url is None:
        tls_code = "host_tls.preset_not_found"
        if code and code.startswith("host_http."):
            tls_code = code.replace("host_http.", "host_tls.", 1)
        return None, tls_code
    hostname = extract_target_host(url)
    if not hostname:
        return None, "host_tls.hostname_not_allowed"
    return hostname, None


def _guard_non_certifying(payload: dict[str, object], request: Request) -> JSONResponse | None:
    if payload.get("writes_allowed") is not False:
        return error_response(
            request,
            status_code=500,
            code="internal.error",
            message="host probe must remain non-writing",
        )
    if payload.get("certification_eligible") is not False:
        return error_response(
            request,
            status_code=500,
            code="internal.error",
            message="host probe must remain non-certifying",
        )
    return None


def _host_http_failed(request: Request) -> JSONResponse:
    return error_response(
        request,
        status_code=500,
        code="host_http.failed",
        message=synthesize_operator_message(
            code="host_http.failed",
            reason="preview_failed",
        ),
    )


def _host_tls_failed(request: Request) -> JSONResponse:
    return error_response(
        request,
        status_code=500,
        code="host_tls.failed",
        message=synthesize_operator_message(
            code="host_tls.failed",
            reason="preview_failed",
        ),
    )


def _host_internet_failed(request: Request) -> JSONResponse:
    return error_response(
        request,
        status_code=500,
        code="host_internet.failed",
        message=synthesize_operator_message(
            code="host_internet.failed",
            reason="preview_failed",
        ),
    )


def _preset_not_found_response(
    request: Request,
    *,
    code: str,
) -> JSONResponse:
    return error_response(
        request,
        status_code=404,
        code=code,
        message=synthesize_operator_message(
            code=code,
            reason="preview_failed",
        ),
    )


@router.post("/lab/host-http-probe", response_model=HostHttpProbeResponse)
def host_http_probe(request: Request, body: HostHttpProbeBody) -> JSONResponse:
    host = _state(request)
    preset_id = body.preset_id.strip()
    if not preset_id:
        return _preset_not_found_response(request, code="host_http.preset_not_found")
    url, resolve_code = _resolve_local_order_url(
        host,
        preset_id=preset_id,
        revision_id=body.revision_id,
    )
    if url is None:
        return _preset_not_found_response(
            request,
            code=resolve_code or "host_http.preset_not_found",
        )
    try:
        result = _resolve_runner(host).probe_http(url=url)
        payload = result.as_dict()
    except Exception:
        return _host_http_failed(request)
    guard = _guard_non_certifying(payload, request)
    if guard is not None:
        return guard
    return JSONResponse(payload, status_code=200, headers=_ok_headers(request))


@router.post("/lab/host-tls-probe", response_model=HostTlsProbeResponse)
def host_tls_probe(request: Request, body: HostTlsProbeBody) -> JSONResponse:
    host = _state(request)
    preset_id = body.preset_id.strip()
    if not preset_id:
        return _preset_not_found_response(request, code="host_tls.preset_not_found")
    hostname, resolve_code = _resolve_local_order_hostname(
        host,
        preset_id=preset_id,
        revision_id=body.revision_id,
    )
    if hostname is None:
        code = resolve_code or "host_tls.preset_not_found"
        if "hostname_not_allowed" in code:
            return error_response(
                request,
                status_code=422,
                code=code,
                message=synthesize_operator_message(
                    code=code,
                    reason="invalid_format",
                    field="hostname_ref",
                ),
            )
        return _preset_not_found_response(request, code=code)
    try:
        result = _resolve_runner(host).probe_tls(hostname=hostname)
        payload = result.as_dict()
    except Exception:
        return _host_tls_failed(request)
    guard = _guard_non_certifying(payload, request)
    if guard is not None:
        return guard
    return JSONResponse(payload, status_code=200, headers=_ok_headers(request))


@router.post("/lab/host-internet-probe", response_model=HostInternetProbeResponse)
def host_internet_probe(request: Request, body: HostInternetProbeBody) -> JSONResponse:
    _ = body
    host = _state(request)
    try:
        result = _resolve_runner(host).probe_internet(targets_profile="default")
        payload = result.as_dict()
    except Exception:
        return _host_internet_failed(request)
    guard = _guard_non_certifying(payload, request)
    if guard is not None:
        return guard
    return JSONResponse(payload, status_code=200, headers=_ok_headers(request))
