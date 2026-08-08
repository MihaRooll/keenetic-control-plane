"""KeenDNS/CrazeDNS apply API routes (confirm-gated; injected transport)."""

from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from router_control.adapters.netcraze.allowlist import is_expendable_lab_class
from router_control.adapters.netcraze.sanitize import redact_sealed_cli_command
from router_control.adapters.netcraze.startup_backup import (
    StartupBackupError,
    backup_startup_config,
)
from router_control.adapters.netcraze.transport import SealedRciWriteRequest
from router_control.application.keendns_apply_service import (
    ERROR_CODE_COMPONENT_ABSENT,
    ERROR_CODE_INVENTORY_UNREADABLE,
    KeenDnsApplyResult,
    KeenDnsApplyServiceError,
    apply_keendns_intent,
)
from router_control.application.recovery import SealedApplyTrailParams
from router_control.application.router_apply_lock import (
    resolve_router_apply_lock_key,
    run_with_router_apply_lock,
)
from router_control.persistence.errors import SealedApplyTrailBeginError

from router_control_host.apply_response_models import KeenDnsApplyResponse
from router_control_host.errors import error_response, sealed_apply_trail_begin_error_response
from router_control_host.routes import API_PREFIX, _mutation_degraded, _ok_headers
from router_control_host.state import HostState
from router_control_host.wifi_live_transport import (
    LiveGateARequiredError,
    LiveIdentityTupleMismatchError,
    WifiLiveConnectionParams,
    connection_params_from_fields,
    ensure_live_gate_a_tuple_match,
    gate_a_required_code,
    identity_mismatch_code,
    incomplete_live_connection_fields,
    is_win32_live_capable,
    live_backup_unavailable_code,
    live_connection_incomplete_code,
    live_platform_unsupported_code,
    live_platform_unsupported_message,
    map_wifi_live_transport_error,
    normalize_live_apply_router_id,
    open_wifi_live_session,
)

_LIVE_FAMILY_PREFIX = "keendns"

router = APIRouter(prefix=API_PREFIX, tags=["keendns-apply"])


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class KeenDnsLiveConnectionFields(_StrictModel):
    host: str | None = None
    username: str | None = None
    router_credential_ref_id: str | None = None
    ssh_host_key_sha256: str | None = None
    source_address: str | None = None
    router_id: str | None = None


class KeenDnsApplyBody(KeenDnsLiveConnectionFields):
    intent_kind: Literal["book", "drop"]
    name: str = Field(min_length=1, max_length=63)
    domain: str = Field(min_length=1, max_length=64)
    mode: Literal["auto", "cloud", "direct"] | None = None
    confirm_live_apply: bool = False


class _LiveKeenDnsTransportWrapper:
    keendns_live_dispatch: Literal[True] = True

    def __init__(self, inner: Any) -> None:
        self._inner = inner

    def execute_sealed_rci_write(self, request: SealedRciWriteRequest) -> Any:
        return self._inner.execute_sealed_rci_write(request)

    def read_json(self, command: Any, body: bytes | None = None) -> Any:
        return self._inner.read_json(command, body)


class _DefaultFakeKeenDnsTransport:
    keendns_offline_only: Literal[True] = True

    def __init__(self) -> None:
        self.write_commands: list[str] = []

    def execute_sealed_rci_write(self, request: SealedRciWriteRequest) -> list[dict[str, Any]]:
        body = json.loads(request.body.decode("utf-8"))
        command = str(body[0]["parse"])
        self.write_commands.append(redact_sealed_cli_command(command))
        return [
            {
                "parse": {
                    "prompt": "(config)",
                    "status": [
                        {
                            "status": "message",
                            "code": "8979152",
                            "ident": "Cloud::KeenDNS",
                            "message": "synthetic ndns ack",
                        }
                    ],
                }
            }
        ]


def _state(request: Request) -> HostState:
    return request.app.state.host  # type: ignore[no-any-return]


def _live_params_from_body(
    body: KeenDnsLiveConnectionFields,
    host: HostState,
) -> WifiLiveConnectionParams | None:
    return connection_params_from_fields(
        host=body.host,
        username=body.username,
        router_credential_ref_id=body.router_credential_ref_id,
        ssh_host_key_sha256=body.ssh_host_key_sha256,
        source_address=body.source_address,
        router_id=body.router_id.strip() if body.router_id else None,
        store=host.runtime.store,
    )


def _should_use_live_path(body: KeenDnsLiveConnectionFields, host: HostState) -> bool:
    return is_win32_live_capable() and _live_params_from_body(body, host) is not None


def _router_apply_lock_key(
    body: KeenDnsLiveConnectionFields,
    router_id: str | None,
) -> str:
    return resolve_router_apply_lock_key(
        router_id,
        live_host=body.host,
        ssh_host_key_sha256=body.ssh_host_key_sha256,
        source_address=body.source_address,
    )


def _connection_incomplete_error(
    request: Request,
    *,
    missing: list[str],
) -> JSONResponse:
    return error_response(
        request,
        status_code=422,
        code=live_connection_incomplete_code(_LIVE_FAMILY_PREFIX),
        message=f"incomplete live connection params; missing: {', '.join(missing)}",
    )


def _validate_live_connection_fields(
    request: Request,
    body: KeenDnsLiveConnectionFields,
    host: HostState,
) -> JSONResponse | None:
    missing = incomplete_live_connection_fields(
        host=body.host,
        username=body.username,
        router_credential_ref_id=body.router_credential_ref_id,
        ssh_host_key_sha256=body.ssh_host_key_sha256,
        source_address=body.source_address,
        router_id=body.router_id.strip() if body.router_id else None,
        store=host.runtime.store,
    )
    if missing:
        return _connection_incomplete_error(request, missing=missing)
    return None


def _gate_a_required_error(request: Request, message: str) -> JSONResponse:
    return error_response(
        request,
        status_code=503,
        code=gate_a_required_code(_LIVE_FAMILY_PREFIX),
        message=message,
    )


def _expendable_required_error(request: Request) -> JSONResponse:
    return error_response(
        request,
        status_code=503,
        code="keendns.expendable_required",
        message=(
            "KeenDNS cloud apply requires expendable lab class "
            "(ROUTER_CONTROL_LAB_CLASS=expendable_development_router)"
        ),
    )


def _live_backup_unavailable_error(request: Request, message: str) -> JSONResponse:
    return error_response(
        request,
        status_code=503,
        code=live_backup_unavailable_code(_LIVE_FAMILY_PREFIX),
        message=message,
    )


def _identity_mismatch_error(request: Request) -> JSONResponse:
    return error_response(
        request,
        status_code=422,
        code=identity_mismatch_code(_LIVE_FAMILY_PREFIX),
        message="live device identity does not match recorded Gate A tuple",
    )


def _live_platform_unsupported_error(request: Request) -> JSONResponse:
    return error_response(
        request,
        status_code=503,
        code=live_platform_unsupported_code(_LIVE_FAMILY_PREFIX),
        message=live_platform_unsupported_message(),
    )


def _component_absent_error(request: Request) -> JSONResponse:
    return error_response(
        request,
        status_code=503,
        code="keendns.component_absent",
        message="ndns component not installed on router; cloud booking unavailable",
    )


def _inventory_unreadable_error(request: Request) -> JSONResponse:
    return error_response(
        request,
        status_code=503,
        code="keendns.inventory_unreadable",
        message="router component inventory unreadable; retry after connection stabilizes",
    )


def _service_error(request: Request, exc: KeenDnsApplyServiceError) -> JSONResponse:
    message = str(exc)
    if message == ERROR_CODE_COMPONENT_ABSENT:
        return _component_absent_error(request)
    if message == ERROR_CODE_INVENTORY_UNREADABLE:
        return _inventory_unreadable_error(request)
    return error_response(
        request,
        status_code=422,
        code="keendns.apply_failed",
        message=message,
    )


def _resolve_transport(
    host: HostState,
    request: Request,
) -> JSONResponse | _DefaultFakeKeenDnsTransport:
    factory = getattr(host, "keendns_apply_transport_factory", None)
    if factory is not None:
        return factory()
    allow_fake = host.adapter_mode == "fake" and (
        host.allow_fake_mutations or os.environ.get("RC_ALLOW_FAKE_MUTATIONS") == "1"
    )
    if allow_fake:
        return _DefaultFakeKeenDnsTransport()
    return error_response(
        request,
        status_code=503,
        code="feature.degraded",
        message="KeenDNS apply transport not configured",
    )


def _intent_from_body(body: KeenDnsApplyBody) -> dict[str, object]:
    intent: dict[str, object] = {
        "intent_kind": body.intent_kind,
        "name": body.name,
        "domain": body.domain,
    }
    if body.mode is not None:
        intent["mode"] = body.mode
    return intent


def _intent_redacted(body: KeenDnsApplyBody) -> dict[str, object]:
    payload: dict[str, object] = {
        "intent_kind": body.intent_kind,
        "name": body.name.strip().lower(),
        "domain": body.domain.strip().lower(),
    }
    if body.mode is not None:
        payload["mode"] = body.mode
    return payload


def _sealed_apply_trail_params(
    request: Request,
    *,
    intent_redacted: dict[str, object],
    router_id: str | None,
) -> SealedApplyTrailParams:
    return SealedApplyTrailParams(
        route="keendns",
        verb="apply",
        intent_redacted=intent_redacted,
        correlation_id=getattr(request.state, "correlation_id", None),
        router_id=router_id,
    )


def _result_with_backup(
    result: KeenDnsApplyResult,
    *,
    basename: str,
    content_sha256: str,
) -> KeenDnsApplyResult:
    return replace(
        result,
        backup_basename=basename,
        backup_content_sha256=content_sha256,
    )


def _dispatch_apply_live(
    *,
    host: HostState,
    body: KeenDnsApplyBody,
    params: WifiLiveConnectionParams,
    intent: dict[str, object],
    sealed_apply_params: SealedApplyTrailParams | None = None,
) -> KeenDnsApplyResult:
    cert = host.gate_a_certification
    if cert is None or not cert.is_open:
        raise LiveGateARequiredError(
            "Gate A certification required for live apply (startup-config backup)"
        )

    vault = host.runtime.vault
    backup_basename: str | None = None
    backup_sha256: str | None = None

    with open_wifi_live_session(params=params, vault=vault) as session:
        ensure_live_gate_a_tuple_match(
            session,
            cert,
            router_id=body.router_id.strip() if body.router_id else None,
        )
        transport = _LiveKeenDnsTransportWrapper(session.transport)

        def backup_callback() -> None:
            nonlocal backup_basename, backup_sha256
            if backup_basename is not None:
                return
            meta = backup_startup_config(tunnel=session.tunnel, certification=cert)
            backup_basename = Path(meta.encrypted_locator).name
            backup_sha256 = meta.content_sha256

        result = apply_keendns_intent(
            intent=intent,
            transport=transport,
            live_dispatch=True,
            backup_callback=backup_callback,
            store=host.runtime.store,
            trail_params=sealed_apply_params,
        )

    if backup_basename is not None and backup_sha256 is not None:
        return _result_with_backup(
            result,
            basename=backup_basename,
            content_sha256=backup_sha256,
        )
    return result


@router.post("/keendns/apply", response_model=KeenDnsApplyResponse)
def keendns_apply(request: Request, body: KeenDnsApplyBody) -> JSONResponse:
    if not body.confirm_live_apply:
        return error_response(
            request,
            status_code=400,
            code="keendns.confirm_required",
            message="confirm_live_apply must be true to dispatch KeenDNS apply",
        )
    if body.intent_kind == "book" and body.mode is None:
        return error_response(
            request,
            status_code=422,
            code="keendns.apply_failed",
            message="mode is required for intent_kind=book",
        )
    if body.intent_kind == "drop" and body.mode is not None:
        return error_response(
            request,
            status_code=422,
            code="keendns.apply_failed",
            message="mode must be omitted for intent_kind=drop",
        )

    host = _state(request)
    degraded = _mutation_degraded(host, request)
    if degraded is not None:
        return degraded

    incomplete = _validate_live_connection_fields(request, body, host)
    if incomplete is not None:
        return incomplete

    live_params = _live_params_from_body(body, host)
    if live_params is not None and not is_win32_live_capable():
        return _live_platform_unsupported_error(request)

    intent = _intent_from_body(body)
    intent_redacted = _intent_redacted(body)
    router_id = body.router_id.strip() if body.router_id else None
    lock_key = _router_apply_lock_key(body, router_id)
    trail_params = _sealed_apply_trail_params(
        request,
        intent_redacted=intent_redacted,
        router_id=router_id,
    )

    if _should_use_live_path(body, host):
        if not is_expendable_lab_class():
            return _expendable_required_error(request)
        params = live_params
        assert params is not None
        if host.gate_a_certification is None or not host.gate_a_certification.is_open:
            return _gate_a_required_error(
                request,
                "Gate A certification required for live apply (startup-config backup)",
            )
        if normalize_live_apply_router_id(router_id) is None:
            return _connection_incomplete_error(request, missing=["router_id"])
        try:
            result = run_with_router_apply_lock(
                lock_key,
                lambda: _dispatch_apply_live(
                    host=host,
                    body=body,
                    params=params,
                    intent=intent,
                    sealed_apply_params=trail_params,
                ),
            )
        except LiveIdentityTupleMismatchError:
            return _identity_mismatch_error(request)
        except StartupBackupError as exc:
            return _live_backup_unavailable_error(request, str(exc))
        except SealedApplyTrailBeginError as exc:
            return sealed_apply_trail_begin_error_response(request, exc)
        except LiveGateARequiredError as exc:
            return _gate_a_required_error(request, str(exc))
        except KeenDnsApplyServiceError as exc:
            return _service_error(request, exc)
        except Exception as exc:
            mapped = map_wifi_live_transport_error(
                exc,
                router_credential_ref_id=body.router_credential_ref_id,
                code_prefix=_LIVE_FAMILY_PREFIX,
            )
            return error_response(
                request,
                status_code=mapped.status_code,
                code=mapped.code,
                message=mapped.message,
            )
        return JSONResponse(result.to_dict(), status_code=200, headers=_ok_headers(request))

    transport = _resolve_transport(host, request)
    if isinstance(transport, JSONResponse):
        return transport
    try:
        result = run_with_router_apply_lock(
            lock_key,
            lambda: apply_keendns_intent(
                intent=intent,
                transport=transport,
                store=host.runtime.store,
                trail_params=trail_params,
            ),
        )
    except SealedApplyTrailBeginError as exc:
        return sealed_apply_trail_begin_error_response(request, exc)
    except KeenDnsApplyServiceError as exc:
        return _service_error(request, exc)
    return JSONResponse(result.to_dict(), status_code=200, headers=_ok_headers(request))
