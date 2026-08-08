"""Wi-Fi apply/preview/teardown API routes (confirm-gated; injected transport)."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from router_control.adapters.netcraze.allowlist import validate_wifi_ap_id
from router_control.adapters.netcraze.sanitize import redact_sealed_cli_command
from router_control.adapters.netcraze.startup_backup import (
    StartupBackupError,
    backup_startup_config,
)
from router_control.adapters.netcraze.transport import SealedRciWriteRequest
from router_control.application.recovery import SealedApplyTrailParams
from router_control.application.router_apply_lock import (
    resolve_router_apply_lock_key,
    run_with_router_apply_lock,
)
from router_control.application.wifi_apply_service import (
    WifiApplyResult,
    WifiApplyServiceError,
    WifiApplyTransport,
    apply_wifi_intent,
    preview_wifi_apply,
    teardown_wifi_ap,
)
from router_control.application.wifi_observation_helpers import (
    ERROR_CODE_CAPTIVE_PORTAL_UNSUPPORTED,
    ERROR_CODE_CREDENTIAL_REF_REQUIRED,
    ERROR_CODE_GUEST_ISOLATION_UNSUPPORTED,
)
from router_control.domain.network_intents import (
    CaptivePortalMode,
    WifiBand,
    WifiIntent,
    WifiWpaMode,
)
from router_control.persistence.errors import SealedApplyTrailBeginError

from router_control_host.apply_response_models import (
    WifiApplyResponse,
    WifiPreviewResponse,
)
from router_control_host.errors import (
    error_response,
    operator_structured_error_response,
    sealed_apply_trail_begin_error_response,
    synthesize_operator_message,
)
from router_control_host.fake_wifi_device import FakeWifiDeviceState, ensure_fake_wifi_device
from router_control_host.routes import API_PREFIX, _mutation_degraded, _ok_headers
from router_control_host.state import HostState
from router_control_host.wifi_live_transport import (
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

_LIVE_FAMILY_PREFIX = "wifi"

_PLANNER_CODE_TO_HTTP: dict[str, str] = {
    ERROR_CODE_GUEST_ISOLATION_UNSUPPORTED: "wifi.guest_isolation_unsupported",
    ERROR_CODE_CAPTIVE_PORTAL_UNSUPPORTED: "wifi.captive_portal_unsupported",
    ERROR_CODE_CREDENTIAL_REF_REQUIRED: "wifi.credential_ref_required",
}

_PLANNER_STRUCTURED: dict[str, tuple[str, str]] = {
    ERROR_CODE_CREDENTIAL_REF_REQUIRED: ("wifi.credential_ref_required", "credential_ref_required"),
}

_PLANNER_UNSUPPORTED_MESSAGES: dict[str, str] = {
    ERROR_CODE_GUEST_ISOLATION_UNSUPPORTED: (
        "guest_isolation=true is unsupported until device-verified grammar exists"
    ),
    ERROR_CODE_CAPTIVE_PORTAL_UNSUPPORTED: (
        "captive_portal=Enabled is unsupported until device-verified grammar exists"
    ),
}

router = APIRouter(prefix=API_PREFIX, tags=["wifi-apply"])


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class WifiIntentFields(_StrictModel):
    ssid: str = Field(min_length=1, max_length=32)
    enabled: bool
    credential_ref_id: str | None = None
    captive_portal: CaptivePortalMode = CaptivePortalMode.DISABLED
    guest_isolation: bool
    wpa_mode: WifiWpaMode
    band: WifiBand

    @field_validator("band", mode="before")
    @classmethod
    def validate_band(cls, value: object) -> object:
        if value is None or isinstance(value, WifiBand):
            return value
        valid = [member.value for member in WifiBand]
        if value not in valid:
            raise ValueError(
                f"band must be one of: {', '.join(valid)} (got {value!r})"
            )
        return value

    @field_validator("captive_portal", mode="before")
    @classmethod
    def validate_captive_portal(cls, value: object) -> object:
        if value is None or isinstance(value, CaptivePortalMode):
            return value
        valid = [member.value for member in CaptivePortalMode]
        if value not in valid:
            raise ValueError(
                f"captive_portal must be one of: {', '.join(valid)} (got {value!r})"
            )
        return value


class WifiLiveConnectionFields(_StrictModel):
    host: str | None = None
    username: str | None = None
    router_credential_ref_id: str | None = None
    ssh_host_key_sha256: str | None = None
    source_address: str | None = None
    router_id: str | None = None


class WifiPreviewBody(WifiIntentFields):
    ap_id: str = Field(min_length=1, max_length=64)


class WifiApplyBody(WifiPreviewBody, WifiLiveConnectionFields):
    confirm_live_apply: bool = False
    compensate_on_failure: bool = True
    idempotent: bool = False


class WifiTeardownBody(WifiLiveConnectionFields):
    ap_id: str = Field(min_length=1, max_length=64)
    wpa_mode: WifiWpaMode
    confirm_live_teardown: bool = False
    confirm_live_apply: bool = False


class _DefaultFakeWifiTransport:
    """Offline fake transport with shared per-app device state."""

    def __init__(self, device: FakeWifiDeviceState | None = None) -> None:
        self._device = device if device is not None else FakeWifiDeviceState()
        self.write_commands: list[str] = []
        self.parse_commands: list[str] = []

    def execute_sealed_rci_write(self, request: SealedRciWriteRequest) -> list[dict[str, Any]]:
        body = json.loads(request.body.decode("utf-8"))
        command = str(body[0]["parse"])
        redacted = redact_sealed_cli_command(command)
        self.write_commands.append(redacted)
        self._device.apply_command(command)
        return [
            {
                "parse": {
                    "prompt": "(config)",
                    "status": [
                        {
                            "status": "message",
                            "code": "8979152",
                            "ident": "Core::Interface",
                            "message": "synthetic ack",
                        }
                    ],
                }
            }
        ]

    def execute_rci_parse(self, cli_command: str) -> dict[str, Any]:
        self.parse_commands.append(cli_command)
        for ap_id in self._device._aps:
            if ap_id in cli_command:
                return self._device.readback_for(ap_id)
        if "AccessPoint" in cli_command or "WifiMaster" in cli_command:
            parts = cli_command.split()
            if len(parts) >= 3 and parts[0].lower() == "show" and parts[1].lower() == "interface":
                return self._device.readback_for(parts[2])
        return self._device.readback_for("")


def _state(request: Request) -> HostState:
    return request.app.state.host  # type: ignore[no-any-return]


def _intent_from_body(body: WifiIntentFields) -> WifiIntent:
    return WifiIntent(
        ssid=body.ssid,
        enabled=body.enabled,
        credential_ref_id=body.credential_ref_id,
        captive_portal=body.captive_portal,
        guest_isolation=body.guest_isolation,
        wpa_mode=body.wpa_mode,
        band=body.band,
    )


def _live_params_from_body(
    body: WifiLiveConnectionFields,
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


def _should_use_live_path(body: WifiLiveConnectionFields, host: HostState) -> bool:
    return is_win32_live_capable() and _live_params_from_body(body, host) is not None


def _router_apply_lock_key(
    body: WifiLiveConnectionFields,
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
    details = [{"field": field, "reason": "required"} for field in missing]
    return operator_structured_error_response(
        request,
        status_code=422,
        code=live_connection_incomplete_code(_LIVE_FAMILY_PREFIX),
        reason="incomplete",
        details=details,
        context=", ".join(missing),
    )


def _validate_live_connection_fields(
    request: Request,
    body: WifiLiveConnectionFields,
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


def _ap_validation_error(request: Request, exc: ValueError) -> JSONResponse:
    _ = exc
    return operator_structured_error_response(
        request,
        status_code=422,
        code="wifi.ap_forbidden",
        reason="not_allowlisted",
        field="ap_id",
    )


def _wifi_planner_error_response(
    request: Request,
    exc: BaseException,
) -> JSONResponse | None:
    planner_code = str(exc)
    structured = _PLANNER_STRUCTURED.get(planner_code)
    if structured is not None:
        http_code, reason = structured
        return operator_structured_error_response(
            request,
            status_code=422,
            code=http_code,
            reason=reason,
            field="credential_ref_id",
        )
    mapped_code = _PLANNER_CODE_TO_HTTP.get(planner_code)
    if mapped_code is None:
        return None
    return error_response(
        request,
        status_code=422,
        code=mapped_code,
        message=_PLANNER_UNSUPPORTED_MESSAGES.get(planner_code, planner_code),
    )


def _wifi_preview_error(request: Request, exc: BaseException) -> JSONResponse:
    mapped = _wifi_planner_error_response(request, exc)
    if mapped is not None:
        return mapped
    _ = exc
    return error_response(
        request,
        status_code=422,
        code="wifi.preview_failed",
        message=synthesize_operator_message(
            code="wifi.preview_failed",
            reason="preview_failed",
        ),
    )


def _wifi_apply_error(request: Request, exc: WifiApplyServiceError) -> JSONResponse:
    mapped = _wifi_planner_error_response(request, exc)
    if mapped is not None:
        return mapped
    _ = exc
    return error_response(
        request,
        status_code=422,
        code="wifi.apply_failed",
        message=synthesize_operator_message(
            code="wifi.apply_failed",
            reason="apply_failed",
        ),
    )


def _validate_wifi_ap_credential_ref(
    request: Request,
    host: HostState,
    credential_ref_id: str | None,
) -> JSONResponse | None:
    if not credential_ref_id or not str(credential_ref_id).strip():
        return None
    if host.wifi_apply_credential_resolver is not None:
        return None
    ref_id = str(credential_ref_id).strip()
    row = host.runtime.store.get_credential_ref(ref_id)
    if row is None:
        return operator_structured_error_response(
            request,
            status_code=404,
            code="wifi.credential_not_found",
            reason="credential_not_found",
            field="credential_ref_id",
            details=[{"field": "credential_ref_id", "reason": "not_found"}],
        )
    if row["revoked_at"] is not None:
        return operator_structured_error_response(
            request,
            status_code=422,
            code="wifi.credential_unusable",
            reason="credential_unusable",
            field="credential_ref_id",
            details=[{"field": "credential_ref_id", "reason": "revoked"}],
        )
    if str(row["kind"]) != "WifiApPsk":
        return operator_structured_error_response(
            request,
            status_code=422,
            code="wifi.credential_unusable",
            reason="credential_kind_invalid",
            field="credential_ref_id",
            details=[
                {
                    "field": "credential_ref_id",
                    "reason": "invalid_kind",
                    "expected": "WifiApPsk",
                }
            ],
        )
    return None


def _credential_resolver(host: HostState) -> Callable[[str], str]:
    if host.wifi_apply_credential_resolver is not None:
        return host.wifi_apply_credential_resolver

    vault = host.runtime.vault
    store = host.runtime.store

    def resolve(ref_id: str) -> str:
        row = store.get_credential_ref(ref_id)
        if row is None:
            raise ValueError("credential not found")
        if row["revoked_at"] is not None:
            raise ValueError("credential revoked")
        if str(row["kind"]) != "WifiApPsk":
            raise ValueError("credential kind invalid for Wi-Fi apply")
        return vault.use(ref_id)

    return resolve


def _resolve_transport(host: HostState, request: Request) -> JSONResponse | WifiApplyTransport:
    if host.wifi_apply_transport_factory is not None:
        return cast(WifiApplyTransport, host.wifi_apply_transport_factory())
    allow_fake = host.adapter_mode == "fake" and (
        host.allow_fake_mutations or os.environ.get("RC_ALLOW_FAKE_MUTATIONS") == "1"
    )
    if allow_fake:
        device = ensure_fake_wifi_device(host)
        return _DefaultFakeWifiTransport(device)
    return error_response(
        request,
        status_code=503,
        code="feature.degraded",
        message="Wi-Fi apply transport not configured",
    )


def _apply_gates(host: HostState, request: Request) -> JSONResponse | None:
    degraded = _mutation_degraded(host, request)
    if degraded is not None:
        return degraded
    return None


def _gate_a_required_error(request: Request, message: str) -> JSONResponse:
    return error_response(
        request,
        status_code=503,
        code=gate_a_required_code(_LIVE_FAMILY_PREFIX),
        message=message,
    )


def _live_backup_unavailable_error(request: Request) -> JSONResponse:
    code = live_backup_unavailable_code(_LIVE_FAMILY_PREFIX)
    return error_response(
        request,
        status_code=503,
        code=code,
        message=synthesize_operator_message(
            code=code,
            reason="live_backup_unavailable",
        ),
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


def _result_with_backup(
    result: WifiApplyResult,
    *,
    basename: str,
    content_sha256: str,
) -> WifiApplyResult:
    return replace(
        result,
        backup_basename=basename,
        backup_content_sha256=content_sha256,
    )


def _wifi_apply_intent_redacted(body: WifiIntentFields, *, ap_id: str) -> dict[str, object]:
    payload: dict[str, object] = {
        "ap_id": ap_id,
        "enabled": body.enabled,
        "captive_portal": body.captive_portal.value,
        "guest_isolation": body.guest_isolation,
        "wpa_mode": body.wpa_mode.value,
        "band": body.band.value,
    }
    if body.credential_ref_id:
        payload["credential_ref_id"] = body.credential_ref_id
    return payload


def _wifi_teardown_intent_redacted(body: WifiTeardownBody) -> dict[str, object]:
    return {"ap_id": body.ap_id, "wpa_mode": body.wpa_mode.value}


def _sealed_apply_trail_params(
    request: Request,
    *,
    route: str,
    verb: str,
    intent_redacted: dict[str, object],
    router_id: str | None,
) -> SealedApplyTrailParams:
    return SealedApplyTrailParams(
        route=route,
        verb=verb,
        intent_redacted=intent_redacted,
        correlation_id=getattr(request.state, "correlation_id", None),
        router_id=router_id,
    )


def _record_wifi_sealed_audit(
    host: HostState,
    request: Request,
    *,
    verb: str,
    intent_redacted: dict[str, object],
    result: WifiApplyResult | None = None,
    outcome: str | None = None,
    error_message: str | None = None,
    exception_type: str | None = None,
    router_id: str | None = None,
) -> None:
    final_outcome = outcome or (result.overall if result is not None else "unknown")
    result_payload = result.to_dict() if result is not None else None
    from router_control.application.recovery import outcome_snapshot_from_apply_result

    outcome_snapshot = (
        outcome_snapshot_from_apply_result(result) if result is not None else None
    )
    host.runtime.store.try_append_sealed_apply_audit(
        action=f"sealed_apply.wifi.{verb}",
        outcome=final_outcome,
        route="wifi",
        verb=verb,
        intent_redacted=intent_redacted,
        router_id=router_id,
        correlation_id=getattr(request.state, "correlation_id", None),
        result_payload=result_payload,
        outcome_snapshot=outcome_snapshot,
        error_message=error_message,
        exception_type=exception_type,
    )


def _dispatch_apply_live(
    *,
    host: HostState,
    body: WifiApplyBody,
    params: WifiLiveConnectionParams,
    sealed_apply_params: SealedApplyTrailParams | None = None,
) -> WifiApplyResult:
    cert = host.gate_a_certification
    if cert is None or not cert.is_open:
        raise WifiApplyServiceError(
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

        def backup_callback() -> None:
            nonlocal backup_basename, backup_sha256
            if backup_basename is not None:
                return
            meta = backup_startup_config(tunnel=session.tunnel, certification=cert)
            backup_basename = Path(meta.encrypted_locator).name
            backup_sha256 = meta.content_sha256

        result = apply_wifi_intent(
            intent=_intent_from_body(body),
            ap_id=body.ap_id,
            transport=session.transport,
            credential_resolver=_credential_resolver(host),
            backup_callback=backup_callback,
            compensate_on_failure=body.compensate_on_failure,
            idempotent=body.idempotent,
            store=host.runtime.store,
            sealed_apply_params=sealed_apply_params,
        )

    if backup_basename is not None and backup_sha256 is not None:
        return _result_with_backup(
            result,
            basename=backup_basename,
            content_sha256=backup_sha256,
        )
    return result


def _dispatch_teardown_live(
    *,
    host: HostState,
    body: WifiTeardownBody,
    params: WifiLiveConnectionParams,
    sealed_apply_params: SealedApplyTrailParams | None = None,
) -> WifiApplyResult:
    cert = host.gate_a_certification
    if cert is None or not cert.is_open:
        raise WifiApplyServiceError(
            "Gate A certification required for live teardown (startup-config backup)"
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
        meta = backup_startup_config(tunnel=session.tunnel, certification=cert)
        backup_basename = Path(meta.encrypted_locator).name
        backup_sha256 = meta.content_sha256
        result = teardown_wifi_ap(
            ap_id=body.ap_id,
            transport=session.transport,
            wpa_mode=body.wpa_mode,
            store=host.runtime.store,
            sealed_apply_params=sealed_apply_params,
        )

    if backup_basename is not None and backup_sha256 is not None:
        return _result_with_backup(
            result,
            basename=backup_basename,
            content_sha256=backup_sha256,
        )
    return result


@router.post("/wifi/preview", response_model=WifiPreviewResponse)
def wifi_preview(request: Request, body: WifiPreviewBody) -> JSONResponse:
    host = _state(request)
    try:
        validate_wifi_ap_id(body.ap_id)
    except ValueError as exc:
        return _ap_validation_error(request, exc)
    credential_error = _validate_wifi_ap_credential_ref(
        request, host, body.credential_ref_id
    )
    if credential_error is not None:
        return credential_error
    try:
        plan = preview_wifi_apply(_intent_from_body(body), body.ap_id)
    except (WifiApplyServiceError, ValueError) as exc:
        return _wifi_preview_error(request, exc)
    return JSONResponse(plan, status_code=200, headers=_ok_headers(request))


@router.post("/wifi/apply", response_model=WifiApplyResponse)
def wifi_apply(request: Request, body: WifiApplyBody) -> JSONResponse:
    if not body.confirm_live_apply:
        return error_response(
            request,
            status_code=400,
            code="wifi.confirm_required",
            message="confirm_live_apply must be true to dispatch apply",
        )
    host = _state(request)
    gate = _apply_gates(host, request)
    if gate is not None:
        return gate
    try:
        validate_wifi_ap_id(body.ap_id)
    except ValueError as exc:
        return _ap_validation_error(request, exc)

    credential_error = _validate_wifi_ap_credential_ref(
        request, host, body.credential_ref_id
    )
    if credential_error is not None:
        return credential_error

    incomplete = _validate_live_connection_fields(request, body, host)
    if incomplete is not None:
        return incomplete

    live_params = _live_params_from_body(body, host)
    if live_params is not None and not is_win32_live_capable():
        return _live_platform_unsupported_error(request)

    intent_redacted = _wifi_apply_intent_redacted(body, ap_id=body.ap_id)
    router_id = body.router_id.strip() if body.router_id else None
    lock_key = _router_apply_lock_key(body, router_id)
    trail_params = _sealed_apply_trail_params(
        request,
        route="wifi",
        verb="apply",
        intent_redacted=intent_redacted,
        router_id=router_id,
    )
    result: WifiApplyResult | None = None

    if _should_use_live_path(body, host):
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
                    sealed_apply_params=trail_params,
                ),
            )
        except LiveIdentityTupleMismatchError:
            return _identity_mismatch_error(request)
        except StartupBackupError as exc:
            _ = exc
            return _live_backup_unavailable_error(request)
        except SealedApplyTrailBeginError as exc:
            _record_wifi_sealed_audit(
                host,
                request,
                verb="apply",
                intent_redacted=intent_redacted,
                outcome="failed",
                error_message=str(exc),
                router_id=router_id,
            )
            return sealed_apply_trail_begin_error_response(request, exc)
        except WifiApplyServiceError as exc:
            _record_wifi_sealed_audit(
                host,
                request,
                verb="apply",
                intent_redacted=intent_redacted,
                outcome="failed",
                error_message=str(exc),
                router_id=router_id,
            )
            return _wifi_apply_error(request, exc)
        except Exception as exc:
            _record_wifi_sealed_audit(
                host,
                request,
                verb="apply",
                intent_redacted=intent_redacted,
                outcome="error",
                exception_type=type(exc).__name__,
                router_id=router_id,
            )
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
        _record_wifi_sealed_audit(
            host,
            request,
            verb="apply",
            intent_redacted=intent_redacted,
            result=result,
            router_id=router_id,
        )
        return JSONResponse(result.to_dict(), status_code=200, headers=_ok_headers(request))

    transport = _resolve_transport(host, request)
    if isinstance(transport, JSONResponse):
        return transport
    try:
        result = run_with_router_apply_lock(
            lock_key,
            lambda: apply_wifi_intent(
                intent=_intent_from_body(body),
                ap_id=body.ap_id,
                transport=transport,
                credential_resolver=_credential_resolver(host),
                compensate_on_failure=body.compensate_on_failure,
                idempotent=body.idempotent,
                store=host.runtime.store,
                sealed_apply_params=trail_params,
            ),
        )
    except SealedApplyTrailBeginError as exc:
        _record_wifi_sealed_audit(
            host,
            request,
            verb="apply",
            intent_redacted=intent_redacted,
            outcome="failed",
            error_message=str(exc),
            router_id=router_id,
        )
        return sealed_apply_trail_begin_error_response(request, exc)
    except WifiApplyServiceError as exc:
        _record_wifi_sealed_audit(
            host,
            request,
            verb="apply",
            intent_redacted=intent_redacted,
            outcome="failed",
            error_message=str(exc),
            router_id=router_id,
        )
        return _wifi_apply_error(request, exc)
    except Exception as exc:
        _record_wifi_sealed_audit(
            host,
            request,
            verb="apply",
            intent_redacted=intent_redacted,
            outcome="error",
            exception_type=type(exc).__name__,
            router_id=router_id,
        )
        raise
    _record_wifi_sealed_audit(
        host,
        request,
        verb="apply",
        intent_redacted=intent_redacted,
        result=result,
        router_id=router_id,
    )
    return JSONResponse(result.to_dict(), status_code=200, headers=_ok_headers(request))


@router.post("/wifi/teardown", response_model=WifiApplyResponse)
def wifi_teardown(request: Request, body: WifiTeardownBody) -> JSONResponse:
    confirmed = body.confirm_live_teardown or body.confirm_live_apply
    if not confirmed:
        return error_response(
            request,
            status_code=400,
            code="wifi.confirm_required",
            message="confirm_live_teardown or confirm_live_apply must be true to dispatch teardown",
        )
    host = _state(request)
    gate = _apply_gates(host, request)
    if gate is not None:
        return gate
    try:
        validate_wifi_ap_id(body.ap_id)
    except ValueError as exc:
        return _ap_validation_error(request, exc)

    incomplete = _validate_live_connection_fields(request, body, host)
    if incomplete is not None:
        return incomplete

    live_params = _live_params_from_body(body, host)
    if live_params is not None and not is_win32_live_capable():
        return _live_platform_unsupported_error(request)

    intent_redacted = _wifi_teardown_intent_redacted(body)
    router_id = body.router_id.strip() if body.router_id else None
    lock_key = _router_apply_lock_key(body, router_id)
    trail_params = _sealed_apply_trail_params(
        request,
        route="wifi",
        verb="teardown",
        intent_redacted=intent_redacted,
        router_id=router_id,
    )
    result: WifiApplyResult | None = None

    if _should_use_live_path(body, host):
        params = live_params
        assert params is not None
        if host.gate_a_certification is None or not host.gate_a_certification.is_open:
            return _gate_a_required_error(
                request,
                "Gate A certification required for live teardown (startup-config backup)",
            )
        if normalize_live_apply_router_id(router_id) is None:
            return _connection_incomplete_error(request, missing=["router_id"])
        try:
            result = run_with_router_apply_lock(
                lock_key,
                lambda: _dispatch_teardown_live(
                    host=host,
                    body=body,
                    params=params,
                    sealed_apply_params=trail_params,
                ),
            )
        except LiveIdentityTupleMismatchError:
            return _identity_mismatch_error(request)
        except StartupBackupError as exc:
            _ = exc
            return _live_backup_unavailable_error(request)
        except SealedApplyTrailBeginError as exc:
            _record_wifi_sealed_audit(
                host,
                request,
                verb="teardown",
                intent_redacted=intent_redacted,
                outcome="failed",
                error_message=str(exc),
                router_id=router_id,
            )
            return sealed_apply_trail_begin_error_response(request, exc)
        except WifiApplyServiceError as exc:
            _record_wifi_sealed_audit(
                host,
                request,
                verb="teardown",
                intent_redacted=intent_redacted,
                outcome="failed",
                error_message=str(exc),
                router_id=router_id,
            )
            return _wifi_apply_error(request, exc)
        except Exception as exc:
            _record_wifi_sealed_audit(
                host,
                request,
                verb="teardown",
                intent_redacted=intent_redacted,
                outcome="error",
                exception_type=type(exc).__name__,
                router_id=router_id,
            )
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
        _record_wifi_sealed_audit(
            host,
            request,
            verb="teardown",
            intent_redacted=intent_redacted,
            result=result,
            router_id=router_id,
        )
        return JSONResponse(result.to_dict(), status_code=200, headers=_ok_headers(request))

    transport = _resolve_transport(host, request)
    if isinstance(transport, JSONResponse):
        return transport
    try:
        result = run_with_router_apply_lock(
            lock_key,
            lambda: teardown_wifi_ap(
                ap_id=body.ap_id,
                transport=transport,
                wpa_mode=body.wpa_mode,
                store=host.runtime.store,
                sealed_apply_params=trail_params,
            ),
        )
    except SealedApplyTrailBeginError as exc:
        _record_wifi_sealed_audit(
            host,
            request,
            verb="teardown",
            intent_redacted=intent_redacted,
            outcome="failed",
            error_message=str(exc),
            router_id=router_id,
        )
        return sealed_apply_trail_begin_error_response(request, exc)
    except WifiApplyServiceError as exc:
        _record_wifi_sealed_audit(
            host,
            request,
            verb="teardown",
            intent_redacted=intent_redacted,
            outcome="failed",
            error_message=str(exc),
            router_id=router_id,
        )
        return _wifi_apply_error(request, exc)
    except Exception as exc:
        _record_wifi_sealed_audit(
            host,
            request,
            verb="teardown",
            intent_redacted=intent_redacted,
            outcome="error",
            exception_type=type(exc).__name__,
            router_id=router_id,
        )
        raise
    _record_wifi_sealed_audit(
        host,
        request,
        verb="teardown",
        intent_redacted=intent_redacted,
        result=result,
        router_id=router_id,
    )
    return JSONResponse(result.to_dict(), status_code=200, headers=_ok_headers(request))
