"""APIRouter /api/router-control/v1 — contract-aligned core routes.

Apply (`POST .../plans/{plan_id}/apply`) is fail-closed by default (403
``gate.mutation_forbidden``). When ``RC_ALLOW_FAKE_MUTATIONS=1`` **and**
``RC_ADAPTER_MODE=fake`` (tests/simulation only), apply enqueues durable jobs
against the offline FakeAdapter composition — never live router I/O.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import uuid
from datetime import timedelta
from pathlib import Path
from typing import Annotated, Any, cast

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from router_control.adapters.netcraze.awg_profile import (
    DUALSTACK_IPV6_OPERATOR_NOTE,
    AwgProfileError,
    ParsedAwgProfile,
    parse_awg_profile_text,
    require_asc9_args_for_compile,
)
from router_control.adapters.netcraze.certification import DEFAULT_OBSERVATION_TTL_SECONDS
from router_control.adapters.netcraze.live_probe import LiveProbeTarget
from router_control.adapters.netcraze.ssh_tunnel import (
    SshSourceAddressInvalid,
    SshTunnelError,
    host_is_private,
    preflight_source_address_bind,
    validate_source_address,
    validate_ssh_tunnel_host,
)
from router_control.adapters.secrets.memory import VaultError
from router_control.application.deployment_planner import DEFAULT_REQUIRED_FAMILIES
from router_control.application.router_apply_lock import (
    resolve_router_apply_lock_key,
    run_with_router_apply_lock,
)
from router_control.application.wireguard_apply_planner import clamp_handshake_settle_seconds
from router_control.application.wireguard_apply_service import (
    WireguardApplyResult,
    WireguardApplyServiceError,
    apply_wireguard_intent,
    teardown_wireguard,
)
from router_control.domain.credential_kinds import CREDENTIAL_PUT_KIND_ALLOWLIST
from router_control.domain.ids import RouterId
from router_control.domain.network_intents import (
    IntentValidationError,
    WireguardIntent,
    WireguardPeerRciShape,
)
from router_control.persistence.errors import (
    ConflictError,
    IdempotencyConflict,
    NotFoundError,
    PreconditionFailed,
)
from router_control.persistence.store import etag_for_plan, etag_for_plan_version, etag_for_revision

from router_control_host.auth import (
    HUB_ADMIN_COOKIE_NAME,
    session_binding_from_cookie,
)
from router_control_host.errors import (
    error_body,
    error_response,
    operator_structured_error_response,
    sealed_apply_trail_begin_error_response,
    synthesize_operator_message,
)
from router_control_host.state import HostState
from router_control_host.wifi_live_transport import (
    LiveGateARequiredError,
    LiveIdentityTupleMismatchError,
    is_win32_live_capable,
    map_wifi_live_transport_error,
    normalize_live_apply_router_id,
)

IdempotencyKeyHeader = Annotated[str, Header(alias="Idempotency-Key")]
IfMatchHeader = Annotated[str, Header(alias="If-Match")]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CreateDeploymentRevisionBody(_StrictModel):
    published_preset_id: str
    execution_target: str = "Lab"


class CreateDesiredRevisionBody(_StrictModel):
    deployment_revision_id: str
    observation_id: str


class CreatePlanBody(_StrictModel):
    revision_id: str
    observation_id: str
    deployment_revision_id: str | None = None
    adopt_acknowledged: bool = False


class ConfirmPlanBody(_StrictModel):
    plan_digest: str
    adopt_acknowledged: bool = False
    risk_acknowledged: bool | None = None


class VpnProfileParsePreviewBody(_StrictModel):
    profile_text: str = Field(min_length=1, max_length=65536)


class VpnProfileImportBody(_StrictModel):
    display_name: str = Field(min_length=1, max_length=128)
    profile_text: str = Field(min_length=1, max_length=65536)
    vpn_kind: str = "AmneziaWG"
    wg_id: str = Field(default="Wireguard5", min_length=1, max_length=32)
    ip_global_auto: bool = False
    ip_global_priority: int | None = Field(default=None, ge=0, le=65535)
    tcp_mss_pmtu: bool = False


class VpnProfileLiveConnectionFields(_StrictModel):
    host: str | None = None
    username: str | None = None
    router_credential_ref_id: str | None = None
    ssh_host_key_sha256: str | None = None
    source_address: str | None = None
    router_id: str | None = None


class VpnProfileActivateBody(VpnProfileLiveConnectionFields):
    wg_id: str | None = Field(default=None, min_length=1, max_length=32)
    logical_role: str = "primary"
    confirm_live_apply: bool = False
    handshake_settle_seconds: float = Field(default=0, ge=0)
    ip_global_auto: bool = False
    ip_global_priority: int | None = Field(default=None, ge=0, le=65535)
    tcp_mss_pmtu: bool | None = None


class VpnProfileDeactivateBody(VpnProfileLiveConnectionFields):
    wg_id: str = Field(min_length=1, max_length=32)
    logical_role: str = "primary"
    confirm_live_apply: bool = False


class EnrollEndpointBody(_StrictModel):
    kind: str | None = None
    host: str | None = None
    port: int | None = None
    username: str | None = None
    source_address: str | None = None


class EnrollRouterBody(_StrictModel):
    site_id: str | None = None
    display_name: str
    vendor: str
    model: str
    hardware_revision: str | None = None
    endpoint: EnrollEndpointBody | None = None
    management_password: str | None = None
    credential_ref_id: str | None = None


class PreflightRouterBody(_StrictModel):
    observation_ttl_seconds: int | None = None
    source_address: str | None = None


class PutCredentialBody(_StrictModel):
    secret: str = Field(min_length=1)
    kind: str = Field(default="RouterManagementPassword")


class RotateCredentialBody(_StrictModel):
    secret: str = Field(min_length=1)


def _validate_credential_kind(request: Request, kind: str) -> JSONResponse | None:
    if kind in CREDENTIAL_PUT_KIND_ALLOWLIST:
        return None
    return operator_structured_error_response(
        request,
        status_code=422,
        code="request.validation_failed",
        reason="invalid_value",
        field="kind",
    )


API_PREFIX = "/api/router-control/v1"
router = APIRouter(prefix=API_PREFIX)

_P2_CREATE_PLAN_KEYS = frozenset(
    {"revision_id", "observation_id", "deployment_revision_id", "adopt_acknowledged"}
)
_P2_CONFIRM_PLAN_KEYS = frozenset({"plan_digest", "adopt_acknowledged"})
_P2_PUBLICATION_KEYS = frozenset({"revision_id"})
_P2_DEPLOYMENT_KEYS = frozenset({"published_preset_id", "execution_target"})


def _reject_unknown_body_fields(
    request: Request, body: dict[str, Any], allowed: frozenset[str]
) -> JSONResponse | None:
    unknown = set(body.keys()) - allowed
    if unknown:
        return error_response(
            request,
            status_code=422,
            code="request.validation_failed",
            message=f"unknown fields: {sorted(unknown)}",
        )
    return None


def _p2_stale_response(request: Request, exc: ConflictError | PreconditionFailed) -> JSONResponse:
    msg = str(exc)
    if isinstance(exc, PreconditionFailed) or "stale_observation" in msg:
        code = "stale_observation"
        status = 412 if isinstance(exc, PreconditionFailed) else 422
    elif "stale_credential" in msg:
        code = "stale_credential"
        status = 422
    elif "stale_certification" in msg:
        code = "stale_certification"
        status = 422
    elif "tuple_mismatch" in msg:
        code = "tuple_mismatch"
        status = 422
    elif "digest_mismatch" in msg:
        code = "digest_mismatch"
        status = 409
    else:
        code = "plan.stale"
        status = 409
    return error_response(request, status_code=status, code=code, message=msg)


def _state(request: Request) -> HostState:
    return request.app.state.host  # type: ignore[no-any-return]


def _require_idempotency(key: str | None) -> str:
    if not key or not key.strip() or len(key) > 128:
        return "missing"
    return key.strip()


def _digest(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(raw.encode()).hexdigest()


def _fail_op_on_vault_error(
    host: HostState,
    request: Request,
    outcome: Any,
    exc: VaultError,
) -> JSONResponse:
    msg = str(exc)
    if "not found" in msg:
        status, code = 404, "resource.not_found"
    else:
        status, code = 400, "request.validation_failed"
    request_id = getattr(request.state, "request_id", "req_unknown")
    correlation_id = getattr(request.state, "correlation_id", request_id)
    body = error_body(
        code=code,
        message=msg,
        request_id=request_id,
        correlation_id=correlation_id,
    )
    host.runtime.store.fail_accepted_operation_bundle(
        operation_id=outcome.operation_id,
        job_id=outcome.job_id,
        idempotency_record_id=outcome.idempotency_record_id,
        http_status=status,
        error_body=body,
        now=host.runtime.clock.now(),
    )
    return error_response(request, status_code=status, code=code, message=msg)


def _ok_headers(request: Request, extra: dict[str, str] | None = None) -> dict[str, str]:
    headers = {
        "X-Request-Id": request.state.request_id,
        "X-Correlation-Id": request.state.correlation_id,
    }
    if extra:
        headers.update(extra)
    return headers


def _replay_idempotency_response(
    request: Request,
    existing: Any,
    *,
    host: HostState,
    fallback_body: dict[str, Any] | None = None,
) -> JSONResponse:
    """Replay idempotency; in-progress without terminal body must not claim Queued."""
    stored = json.loads(existing.response_ref or "{}")
    body_out = stored.get("body")
    http_status = stored.get("http_status")
    if body_out is not None and http_status is not None:
        return JSONResponse(
            body_out,
            status_code=int(http_status),
            headers=_ok_headers(
                request,
                {"Location": f"{API_PREFIX}/operations/{existing.operation_id}"},
            ),
        )
    if existing.status == "InProgress":
        return error_response(
            request,
            status_code=409,
            code="idempotency.in_progress",
            message="operation in progress; retry later",
        )
    if fallback_body is not None:
        return JSONResponse(
            fallback_body,
            status_code=int(http_status or 202),
            headers=_ok_headers(
                request,
                {"Location": f"{API_PREFIX}/operations/{existing.operation_id}"},
            ),
        )
    op_row = host.runtime.store.get_operation(existing.operation_id)
    queued_fallback = {
        "operation_id": existing.operation_id,
        "job_id": existing.job_id,
        "status": "Queued",
        "router_id": op_row["router_id"] if op_row else None,
        "links": {
            "operation": f"{API_PREFIX}/operations/{existing.operation_id}",
            "job": f"{API_PREFIX}/jobs/{existing.job_id}",
        },
    }
    return JSONResponse(
        queued_fallback,
        status_code=int(http_status or 202),
        headers=_ok_headers(
            request,
            {"Location": f"{API_PREFIX}/operations/{existing.operation_id}"},
        ),
    )


def _live_gate_a_closed(host: HostState, request: Request) -> JSONResponse | None:
    if host.adapter_mode == "live" and not host.gate_a_open():
        return error_response(
            request,
            status_code=403,
            code="gate.a_closed",
            message="Gate A closed; live observe not authorized",
        )
    return None


def _router_certification_status(host: HostState, row: Any) -> str:
    cert = host.gate_a_certification
    if cert is None or not cert.is_open:
        return "Unknown"
    fingerprint = str(row["identity_fingerprint"] or "")
    if fingerprint == cert.device_fingerprint_digest and row["lifecycle_status"] == "Enrolled":
        return "ReadOnlyCertified"
    return "Unknown"


def _resolve_management_username(endpoint: dict[str, Any]) -> str | None:
    username = endpoint.get("username") or os.environ.get("RC_NETCRAZE_USERNAME")
    if isinstance(username, str) and username.strip():
        return username.strip()
    return None


def _live_mutation_forbidden(host: HostState, request: Request) -> JSONResponse | None:
    if host.adapter_mode == "live":
        return error_response(
            request,
            status_code=403,
            code="gate.mutation_forbidden",
            message="Hardware mutation gates closed; live mutations forbidden",
        )
    return None


def _mutation_degraded(host: HostState, request: Request) -> JSONResponse | None:
    if host.feature_state == "Degraded":
        return error_response(
            request,
            status_code=503,
            code="feature.degraded",
            message="Feature Degraded; mutations blocked",
        )
    return None


def _resolve_enroll_credential(
    host: HostState,
    request: Request,
    *,
    password: str | None,
    credential_ref_id: str | None,
) -> tuple[str, str, str, str, bool] | JSONResponse:
    """Return credential ref metadata; created=True when vault.create ran."""
    if password and credential_ref_id:
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="management_password and credential_ref_id are mutually exclusive",
        )
    if credential_ref_id:
        ref_id = str(credential_ref_id).strip()
        if not ref_id:
            return error_response(
                request,
                status_code=400,
                code="request.validation_failed",
                message="credential_ref_id required",
            )
        row = host.runtime.store.get_credential_ref(ref_id)
        if row is not None:
            if row["revoked_at"] is not None:
                return error_response(
                    request,
                    status_code=400,
                    code="request.validation_failed",
                    message="credential ref revoked",
                )
            kind = str(row["kind"])
        else:
            try:
                kind = host.runtime.vault.get_kind(ref_id)
            except VaultError as exc:
                msg = str(exc)
                if "not found" in msg:
                    status, code = 404, "resource.not_found"
                else:
                    status, code = 400, "request.validation_failed"
                return error_response(
                    request,
                    status_code=status,
                    code=code,
                    message=msg if status != 404 else "credential ref not found",
                )
        if kind != "RouterManagementPassword":
            return error_response(
                request,
                status_code=422,
                code="request.validation_failed",
                message=(
                    f"credential_ref_id kind {kind} is not valid for router enrollment; "
                    "expected RouterManagementPassword"
                ),
            )
        try:
            host.runtime.vault.use(ref_id)
        except VaultError as exc:
            msg = str(exc)
            if "not found" in msg:
                status, code = 404, "resource.not_found"
            else:
                status, code = 400, "request.validation_failed"
            return error_response(
                request,
                status_code=status,
                code=code,
                message=msg,
            )
        provider = getattr(host.runtime.vault, "provider", "CredentialVault")
        return ref_id, kind, str(provider), f"ref:{ref_id}", False
    if not password:
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="management_password or credential_ref_id required",
        )
    handle = host.runtime.vault.create(kind="RouterManagementPassword", secret=password)
    return (
        handle.credential_ref_id,
        handle.kind,
        handle.provider,
        handle.provider_locator,
        True,
    )


def _enroll_digest(
    body: dict[str, Any], *, password: str | None, credential_ref_id: str | None
) -> str:
    payload = {
        k: v for k, v in body.items() if k not in ("management_password", "credential_ref_id")
    }
    if password:
        payload["management_password_sha256"] = hashlib.sha256(password.encode()).hexdigest()
    elif credential_ref_id:
        payload["credential_ref_id"] = str(credential_ref_id).strip()
    return _digest(payload)


def _validate_live_enroll_endpoint(
    request: Request,
    endpoint: dict[str, Any],
) -> str | JSONResponse:
    """Strict management host validation before vault/SQLite/probe side effects."""
    ssh_host = str(endpoint.get("host", ""))
    if not ssh_host.strip():
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="endpoint.host is required for live enroll",
        )
    try:
        validated_host = validate_ssh_tunnel_host(ssh_host)
    except SshTunnelError as exc:
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message=str(exc),
        )
    if not host_is_private(validated_host):
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="endpoint.host must be a private management address",
        )
    return validated_host


def _resolve_source_address_field(
    request: Request,
    raw: object | None,
    *,
    required: bool,
    field_name: str = "source_address",
) -> str | None | JSONResponse:
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        if required:
            return error_response(
                request,
                status_code=400,
                code="request.validation_failed",
                message=f"{field_name} is required for live or ssh_tunnel transport",
            )
        return None
    try:
        validated = validate_source_address(str(raw).strip())
    except SshSourceAddressInvalid as exc:
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message=str(exc),
        )
    try:
        preflight_source_address_bind(validated)
    except SshSourceAddressInvalid as exc:
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message=str(exc),
        )
    return validated


def _endpoint_requires_source_address(host: HostState, endpoint: dict[str, Any]) -> bool:
    if host.adapter_mode == "live":
        return True
    transport = str(endpoint.get("transport") or "").strip().lower()
    kind = str(endpoint.get("kind") or "").strip().lower()
    return transport == "ssh_tunnel" or kind == "ssh_tunnel"


def _rollback_enroll_credential(
    host: HostState,
    *,
    credential_ref_id: str,
    created: bool,
) -> None:
    if created:
        host.runtime.vault.delete(credential_ref_id)


def _profile_detail(host: HostState, row: Any) -> dict[str, Any]:
    unsupported = json.loads(row["unsupported_fields_json"] or "[]")
    metadata = json.loads(row["metadata_json"] or "{}")
    refs = host.runtime.store.list_profile_secret_refs(str(row["profile_id"]))
    credential_refs = [
        {
            "role": ref["role"],
            "credential_ref_id": ref["credential_ref_id"],
            "kind": ref["role"],
        }
        for ref in refs
    ]
    payload: dict[str, Any] = {
        "profile_id": row["profile_id"],
        "display_name": row["display_name"],
        "vpn_kind": row["vpn_kind"],
        "parser_version": row["parser_version"],
        "content_digest": row["content_digest"],
        "validation_status": row["validation_status"],
        "unsupported_fields": unsupported,
        "credential_refs": credential_refs,
        "metadata": metadata,
        "created_at": row["created_at"],
        "superseded_at": row["superseded_at"],
    }
    if metadata:
        payload["wireguard_intent_fields"] = {
            key: metadata[key]
            for key in (
                "wg_id",
                "peer_public_key",
                "peer_endpoint",
                "peer_allow_ips",
                "peer_keepalive_interval",
                "interface_address",
                "asc9_args",
                "awg_param_names",
                "peer_rci_shape",
                "ip_global_auto",
                "ip_global_priority",
                "tcp_mss_pmtu",
            )
            if key in metadata
        }
    if "AllowedIPs" in unsupported:
        payload["operator_notes"] = [DUALSTACK_IPV6_OPERATOR_NOTE]
    return payload


def _profile_metadata_from_parsed(
    parsed: ParsedAwgProfile,
    *,
    wg_id: str,
    ip_global_auto: bool,
    ip_global_priority: int | None,
    tcp_mss_pmtu: bool = False,
) -> dict[str, Any]:
    asc9_args: list[int] | None = None
    try:
        asc_tuple = require_asc9_args_for_compile(parsed)
        asc9_args = list(asc_tuple)
    except AwgProfileError:
        asc9_args = None
    metadata: dict[str, Any] = {
        "wg_id": wg_id,
        "peer_public_key": parsed.peer_public_key,
        "peer_endpoint": parsed.peer_endpoint,
        "peer_allow_ips": parsed.peer_allow_ips,
        "interface_address": parsed.interface_address,
        "awg_param_names": list(parsed.awg_param_names),
        "peer_rci_shape": WireguardPeerRciShape.NESTED_RCI.value,
        "ip_global_auto": ip_global_auto,
        "tcp_mss_pmtu": tcp_mss_pmtu,
    }
    if asc9_args is not None:
        metadata["asc9_args"] = asc9_args
    if ip_global_priority is not None:
        metadata["ip_global_priority"] = ip_global_priority
    if parsed.peer_keepalive_interval is not None:
        metadata["peer_keepalive_interval"] = parsed.peer_keepalive_interval
    return metadata


def _wireguard_intent_from_profile_row(
    host: HostState,
    row: Any,
    *,
    wg_id: str | None = None,
    enabled: bool = True,
    ip_global_auto: bool | None = None,
    ip_global_priority: int | None = None,
    tcp_mss_pmtu: bool | None = None,
    peer_keepalive_interval: int | None = None,
) -> WireguardIntent:
    metadata = json.loads(row["metadata_json"] or "{}")
    target_wg = wg_id or str(metadata.get("wg_id") or "Wireguard5")
    refs = host.runtime.store.list_profile_secret_refs(str(row["profile_id"]))
    private_ref: str | None = None
    psk_ref: str | None = None
    for ref in refs:
        if ref["role"] == "PrivateKey":
            private_ref = str(ref["credential_ref_id"])
        elif ref["role"] == "PresharedKey":
            psk_ref = str(ref["credential_ref_id"])
    asc_raw = metadata.get("asc9_args")
    asc_args = tuple(asc_raw) if isinstance(asc_raw, list) else None
    resolved_ip_global_auto = (
        ip_global_auto
        if ip_global_auto is not None
        else bool(metadata.get("ip_global_auto", False))
    )
    resolved_ip_global_priority = (
        ip_global_priority
        if ip_global_priority is not None
        else metadata.get("ip_global_priority")
    )
    resolved_tcp_mss_pmtu = (
        tcp_mss_pmtu
        if tcp_mss_pmtu is not None
        else bool(metadata.get("tcp_mss_pmtu", False))
    )
    metadata_keepalive = metadata.get("peer_keepalive_interval")
    resolved_peer_keepalive_interval = (
        peer_keepalive_interval
        if peer_keepalive_interval is not None
        else (
            metadata_keepalive
            if isinstance(metadata_keepalive, int) and not isinstance(metadata_keepalive, bool)
            else None
        )
    )
    return WireguardIntent(
        wg_id=target_wg,
        enabled=enabled,
        asc_args=asc_args,
        private_key_credential_ref_id=private_ref,
        preshared_key_credential_ref_id=psk_ref,
        peer_public_key=metadata.get("peer_public_key"),
        peer_endpoint=metadata.get("peer_endpoint"),
        peer_allow_ips=metadata.get("peer_allow_ips"),
        peer_keepalive_interval=resolved_peer_keepalive_interval,
        peer_rci_shape=WireguardPeerRciShape(
            str(metadata.get("peer_rci_shape", WireguardPeerRciShape.NESTED_RCI.value))
        ),
        interface_address=metadata.get("interface_address"),
        ip_global_auto=resolved_ip_global_auto,
        ip_global_priority=resolved_ip_global_priority,
        tcp_mss_pmtu=resolved_tcp_mss_pmtu,
    )


def _profile_mutation_intent_redacted(
    profile_id: str,
    intent: WireguardIntent,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "profile_id": profile_id,
        "wg_id": intent.wg_id,
        "enabled": intent.enabled,
    }
    if intent.private_key_credential_ref_id is not None:
        payload["private_key_credential_ref_id"] = intent.private_key_credential_ref_id
    if intent.preshared_key_credential_ref_id is not None:
        payload["preshared_key_credential_ref_id"] = intent.preshared_key_credential_ref_id
    if intent.peer_allow_ips is not None:
        payload["peer_allow_ips"] = intent.peer_allow_ips
    if intent.peer_keepalive_interval is not None:
        payload["peer_keepalive_interval"] = intent.peer_keepalive_interval
    return payload


def _profile_apply_success(result: WireguardApplyResult) -> bool:
    return result.overall == "applied"


def _teardown_prior_profile_assignment(
    *,
    host: HostState,
    request: Request,
    body: VpnProfileLiveConnectionFields,
    wg_routes: Any,
    router_id: str,
    profile_id: str,
    logical_role: str,
    live_params: Any,
    trail_params: Any,
) -> None:
    prior = host.runtime.store.get_active_tunnel_assignment(
        router_id, logical_role=logical_role
    )
    if prior is None or str(prior["profile_id"]) == profile_id:
        return
    prior_row = host.runtime.store.get_profile(str(prior["profile_id"]))
    if prior_row is None:
        return
    prior_intent = _wireguard_intent_from_profile_row(host, prior_row, enabled=False)
    if wg_routes._should_use_live_path(
        cast(wg_routes.WireguardLiveConnectionFields, body), host
    ):
        assert live_params is not None
        prior_teardown = wg_routes._dispatch_teardown_live(
            host=host,
            intent=prior_intent,
            params=live_params,
            sealed_apply_params=trail_params,
            router_id=router_id,
        )
    else:
        transport = wg_routes._resolve_transport(host, request)
        if isinstance(transport, JSONResponse):
            raise WireguardApplyServiceError("transport resolution failed")
        prior_teardown = teardown_wireguard(
            wg_id=prior_intent.wg_id,
            transport=transport,
            credential_resolver=wg_routes._credential_resolver(host),
            intent=prior_intent,
            store=host.runtime.store,
            sealed_apply_params=trail_params,
        )
    if not _profile_apply_success(prior_teardown):
        raise WireguardApplyServiceError(
            "prior VPN profile teardown did not complete successfully "
            f"(overall={prior_teardown.overall})"
        )
    # Fail-closed: router teardown already succeeded; catalog/DB must not keep
    # the torn-down profile active (watchdog would otherwise revive stale A).
    cleared = host.runtime.store.deactivate_tunnel_assignments(
        router_id,
        logical_role=logical_role,
        now=host.runtime.clock.now(),
    )
    if cleared == 0:
        raise WireguardApplyServiceError(
            "prior VPN profile teardown succeeded but clearing tunnel assignment failed"
        )


def _write_gates_summary(host: HostState) -> dict[str, Any]:
    """Fail-closed write-gate summary for operator UI; never claims WriteCertified."""
    gate_b = "closed"
    if host.gate_a_certification is not None:
        gates = host.gate_a_certification.sanitized_status_payload().get("gates") or {}
        gate_b = str(gates.get("B", "closed"))
    write_certified = False
    return {
        "blocked": not write_certified,
        "write_certified": write_certified,
        "reason": "Gate B not WriteCertified; Apply and live-write forbidden",
        "gate_b": gate_b,
    }


_HOST_ROOT = Path(__file__).resolve().parents[1]


def _artifacts_dir() -> Path:
    raw = os.environ.get("RC_ARTIFACTS_DIR", "").strip()
    if raw:
        return Path(raw)
    return _HOST_ROOT / "data" / "artifacts"


_OBSERVED_INTERFACE_KEYS = frozenset(
    {
        "interface_id_hash",
        "role",
        "interface_type",
        "link_up",
        "connected",
        "private_prefixes",
        "uplink_hash",
        "bridge_hash",
        "segment_hash",
        "uncertainty",
        "bridge",
        "segment",
    }
)


def _sanitize_observed_interface_item(raw: object) -> dict[str, Any] | None:
    """Allowlist keys aligned with topology_probe._sanitized_interface_mapping."""
    if not isinstance(raw, dict):
        return None
    return {key: raw[key] for key in _OBSERVED_INTERFACE_KEYS if key in raw}


def _load_observed_interfaces_payload() -> dict[str, Any]:
    """Read latest local topology-*.json artifact; no network I/O."""
    artifacts_dir = _artifacts_dir()
    if not artifacts_dir.is_dir():
        return {
            "items": [],
            "note": "topology artifact directory missing; run observe probe first",
        }
    candidates = sorted(
        artifacts_dir.glob("topology-*.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if not candidates:
        return {
            "items": [],
            "note": "no topology-*.json artifacts found; run observe probe first",
        }
    latest = candidates[0]
    try:
        payload = json.loads(latest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {
            "items": [],
            "note": "latest topology artifact unreadable",
        }
    findings = payload.get("findings") or {}
    raw_items = findings.get("sanitized_interfaces")
    items: list[dict[str, Any]] = []
    if isinstance(raw_items, list):
        for raw in raw_items:
            sanitized = _sanitize_observed_interface_item(raw)
            if sanitized is not None:
                items.append(sanitized)
    body: dict[str, Any] = {
        "items": items,
        "artifact_name": latest.name,
    }
    if not items:
        body["note"] = "artifact has no sanitized_interfaces"
    return body


@router.get("/status")
def get_status(request: Request) -> JSONResponse:
    host = _state(request)
    rows = host.runtime.store.list_routers(limit=200)
    total = len(rows)
    enrolled = sum(1 for row in rows if row["lifecycle_status"] == "Enrolled")
    body: dict[str, Any] = {
        "feature_state": host.feature_state,
        "hub_available": True,
        "database_state": "Ok",
        "adapter_mode": host.adapter_mode,
        "default_site_id": host.resolve_site_id(),
        "routers_summary": {"total": total, "enrolled": enrolled, "degraded": 0},
        "write_gates": _write_gates_summary(host),
        "links": {"routers": f"{API_PREFIX}/routers"},
    }
    body.update(host.worker_status())
    body.update(host.vpn_watchdog_status())
    if host.gate_a_certification is not None:
        body.update(host.gate_a_certification.sanitized_status_payload())
    return JSONResponse(body, headers=_ok_headers(request))


@router.get(
    "/observed-interfaces",
    summary="Observed router interfaces (read-only local artifact)",
    response_description="Sanitized interfaces from latest topology-*.json artifact",
)
def get_observed_interfaces(request: Request) -> JSONResponse:
    """Return sanitized_interfaces from the newest local topology artifact (no live I/O)."""
    body = _load_observed_interfaces_payload()
    return JSONResponse(body, headers=_ok_headers(request))


@router.get("/routers")
def list_routers(request: Request) -> JSONResponse:
    host = _state(request)
    items = []
    for row in host.runtime.store.list_routers():
        items.append(
            {
                "router_id": row["router_id"],
                "display_name": row["display_name"],
                "vendor": row["vendor"],
                "model": row["model"],
                "lifecycle_status": row["lifecycle_status"],
                "certification_status": _router_certification_status(host, row),
                "updated_at": row["updated_at"],
            }
        )
    return JSONResponse(
        {"items": items, "next_cursor": None, "limit": 50},
        headers=_ok_headers(request),
    )


@router.post("/routers")
async def enroll_router(
    request: Request,
    body: EnrollRouterBody,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> JSONResponse:
    host = _state(request)
    if isinstance(_require_idempotency(idempotency_key), str) and not (
        idempotency_key and idempotency_key.strip()
    ):
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="Idempotency-Key required",
        )
    assert idempotency_key is not None
    degraded = _mutation_degraded(host, request)
    if degraded is not None:
        return degraded
    gate = _live_gate_a_closed(host, request)
    if gate is not None:
        return gate
    body_dict = body.model_dump(mode="json")
    password = body_dict.get("management_password")
    credential_ref_id = body_dict.get("credential_ref_id")
    if host.adapter_mode != "live" and not password and not credential_ref_id:
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="management_password or credential_ref_id required",
        )
    site_id = body.site_id or host.ensure_default_site()
    endpoint = (
        body.endpoint.model_dump(mode="json", exclude_none=True)
        if body.endpoint is not None
        else {}
    )
    if host.adapter_mode == "live":
        cert = host.gate_a_certification
        if cert is None:
            return error_response(
                request,
                status_code=403,
                code="gate.a_closed",
                message="Gate A certification not loaded",
            )
        if not cert.matches_enroll_request(
            model=body.model,
            vendor=body.vendor,
        ):
            return error_response(
                request,
                status_code=422,
                code="router.identity_mismatch",
                message="enroll model/vendor does not match Gate A certified tuple",
            )
        validated_host = _validate_live_enroll_endpoint(request, endpoint)
        if isinstance(validated_host, JSONResponse):
            return validated_host
        if _resolve_management_username(endpoint) is None:
            return error_response(
                request,
                status_code=400,
                code="request.validation_failed",
                message="endpoint.username or RC_NETCRAZE_USERNAME required for live enroll",
            )
        endpoint = {**endpoint, "host": validated_host}
    requires_source = _endpoint_requires_source_address(host, endpoint)
    validated_source = _resolve_source_address_field(
        request,
        endpoint.get("source_address"),
        required=requires_source,
        field_name="endpoint.source_address",
    )
    if isinstance(validated_source, JSONResponse):
        return validated_source
    digest = _enroll_digest(
        body_dict,
        password=str(password) if password else None,
        credential_ref_id=str(credential_ref_id) if credential_ref_id else None,
    )
    key = idempotency_key.strip()
    # Idempotency before any vault/SQLite side effects (enroll has no router_id yet).
    try:
        existing = host.runtime.store.peek_idempotency(
            operation_kind="enroll",
            idempotency_key=key,
            request_digest=digest,
            router_id=None,
        )
    except IdempotencyConflict:
        return error_response(
            request,
            status_code=409,
            code="idempotency.conflict",
            message="same key different digest",
        )
    if existing is not None:
        return _replay_idempotency_response(request, existing, host=host)

    resolved = _resolve_enroll_credential(
        host,
        request,
        password=str(password) if password else None,
        credential_ref_id=str(credential_ref_id) if credential_ref_id else None,
    )
    if isinstance(resolved, JSONResponse):
        return resolved
    ref_id, cred_kind, cred_provider, cred_locator, created_ref = resolved
    try:
        router_id, outcome = host.runtime.store.enroll_router_with_operation(
            site_id=site_id,
            display_name=body.display_name,
            vendor=body.vendor,
            model=body.model,
            identity_fingerprint=(
                "digest:enroll:"
                + hashlib.sha256(router_seed(body_dict).encode()).hexdigest()[:16]
            ),
            host=endpoint.get("host", "127.0.0.1"),
            port=int(endpoint.get("port", 443)),
            kind=endpoint.get("kind", "management_https"),
            hardware_revision=body.hardware_revision,
            credential_ref_id=ref_id,
            credential_kind=cred_kind,
            credential_provider=cred_provider,
            credential_provider_locator=cred_locator,
            idempotency_key=key,
            request_digest=digest,
            actor_id="hub_admin",
            correlation_id=request.state.correlation_id,
            now=host.runtime.clock.now(),
            defer_success_response=host.adapter_mode == "live",
            source_address=validated_source,
        )
    except IdempotencyConflict:
        _rollback_enroll_credential(host, credential_ref_id=ref_id, created=created_ref)
        return error_response(
            request,
            status_code=409,
            code="idempotency.conflict",
            message="same key different digest",
        )
    except Exception:
        _rollback_enroll_credential(host, credential_ref_id=ref_id, created=created_ref)
        raise

    if not outcome.created:
        _rollback_enroll_credential(host, credential_ref_id=ref_id, created=created_ref)
        return _replay_idempotency_response(request, outcome, host=host)

    if host.adapter_mode == "live":
        assert host.gate_a_certification is not None
        username = _resolve_management_username(endpoint)
        assert username is not None
        probe_target = LiveProbeTarget(
            ssh_host=str(endpoint.get("host")),
            username=username,
            credential_ref_id=ref_id,
            router_id=RouterId(router_id),
            source_address=validated_source,
        )
        try:
            evidence = await asyncio.to_thread(host.run_read_only_probe, probe_target)
        except Exception:
            _rollback_enroll_credential(host, credential_ref_id=ref_id, created=created_ref)
            err = error_body(
                code="router.identity_mismatch",
                message="live enroll identity probe failed",
                request_id=request.state.request_id,
                correlation_id=request.state.correlation_id,
            )
            host.runtime.store.fail_live_enroll_probe(
                router_id=router_id,
                operation_id=outcome.operation_id,
                job_id=outcome.job_id,
                idempotency_record_id=outcome.idempotency_record_id,
                http_status=422,
                error_body=err,
                orphan_credential_ref_id=ref_id if created_ref else None,
                delete_orphan_credential_ref=created_ref,
                now=host.runtime.clock.now(),
            )
            return error_response(
                request,
                status_code=422,
                code="router.identity_mismatch",
                message="live enroll identity probe failed",
            )

        if not host.gate_a_certification.matches_probe_evidence(dict(evidence)):
            _rollback_enroll_credential(host, credential_ref_id=ref_id, created=created_ref)
            err = error_body(
                code="router.identity_mismatch",
                message="live enroll identity tuple mismatch",
                request_id=request.state.request_id,
                correlation_id=request.state.correlation_id,
            )
            host.runtime.store.fail_live_enroll_probe(
                router_id=router_id,
                operation_id=outcome.operation_id,
                job_id=outcome.job_id,
                idempotency_record_id=outcome.idempotency_record_id,
                http_status=422,
                error_body=err,
                orphan_credential_ref_id=ref_id if created_ref else None,
                delete_orphan_credential_ref=created_ref,
                now=host.runtime.clock.now(),
            )
            return error_response(
                request,
                status_code=422,
                code="router.identity_mismatch",
                message="live enroll identity tuple mismatch",
            )

        fingerprint = str(
            evidence.get("device_fingerprint_digest") or evidence.get("device_fingerprint")
        )
        accepted = {
            "operation_id": outcome.operation_id,
            "job_id": outcome.job_id,
            "status": "Succeeded",
            "router_id": router_id,
            "lifecycle_status": "Enrolled",
            "certification_status": "ReadOnlyCertified",
            "identity_fingerprint": fingerprint,
            "links": {
                "operation": f"{API_PREFIX}/operations/{outcome.operation_id}",
                "job": f"{API_PREFIX}/jobs/{outcome.job_id}",
            },
        }
        host.runtime.store.finalize_live_enroll(
            router_id=router_id,
            identity_fingerprint=fingerprint,
            operation_id=outcome.operation_id,
            job_id=outcome.job_id,
            idempotency_record_id=outcome.idempotency_record_id,
            body=accepted,
            now=host.runtime.clock.now(),
        )
        return JSONResponse(
            accepted,
            status_code=202,
            headers=_ok_headers(
                request,
                {"Location": f"{API_PREFIX}/operations/{outcome.operation_id}"},
            ),
        )

    accepted = json.loads(outcome.response_ref or "{}").get("body") or {
        "operation_id": outcome.operation_id,
        "job_id": outcome.job_id,
        "status": "Queued",
        "router_id": router_id,
        "links": {
            "operation": f"{API_PREFIX}/operations/{outcome.operation_id}",
            "job": f"{API_PREFIX}/jobs/{outcome.job_id}",
        },
    }
    return JSONResponse(
        accepted,
        status_code=202,
        headers=_ok_headers(
            request,
            {"Location": f"{API_PREFIX}/operations/{outcome.operation_id}"},
        ),
    )


def router_seed(body: dict[str, Any]) -> str:
    return f"{body.get('display_name')}:{body.get('vendor')}:{body.get('model')}"


@router.get("/routers/{router_id}")
def get_router(router_id: str, request: Request) -> JSONResponse:
    host = _state(request)
    row = host.runtime.store.get_router(router_id)
    if row is None:
        return error_response(
            request, status_code=404, code="resource.not_found", message="router not found"
        )
    rev = host.runtime.store.get_desired_revision(router_id)
    return JSONResponse(
        {
            "router_id": row["router_id"],
            "display_name": row["display_name"],
            "vendor": row["vendor"],
            "model": row["model"],
            "site_id": row["site_id"],
            "hardware_revision": row["hardware_revision"],
            "identity_fingerprint": row["identity_fingerprint"],
            "lifecycle_status": row["lifecycle_status"],
            "certification_status": _router_certification_status(host, row),
            "endpoints": [],
            "current_desired_revision_id": rev["revision_id"] if rev else None,
            "applied_revision_id": None,
            "reconcile_status": "Unknown",
            "updated_at": row["updated_at"],
        },
        headers=_ok_headers(request),
    )


@router.post("/routers/{router_id}/preflight", status_code=202)
async def preflight_router(
    router_id: str,
    request: Request,
    idempotency_key: str = Header(..., alias="Idempotency-Key"),
    body: PreflightRouterBody | None = None,
) -> JSONResponse:
    host = _state(request)
    if not idempotency_key or not idempotency_key.strip():
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="Idempotency-Key required",
        )
    degraded = _mutation_degraded(host, request)
    if degraded is not None:
        return degraded
    gate = _live_gate_a_closed(host, request)
    if gate is not None:
        return gate
    if host.runtime.store.get_router(router_id) is None:
        return error_response(
            request, status_code=404, code="resource.not_found", message="router not found"
        )
    raw_body: dict[str, Any] = (
        body.model_dump(mode="json", exclude_none=True) if body is not None else {}
    )
    digest = _digest(raw_body)
    key = idempotency_key.strip()
    try:
        existing = host.runtime.store.peek_idempotency(
            router_id=router_id,
            operation_kind="preflight",
            idempotency_key=key,
            request_digest=digest,
        )
    except IdempotencyConflict:
        return error_response(
            request,
            status_code=409,
            code="idempotency.conflict",
            message="same key different digest",
        )
    if existing is not None:
        return _replay_idempotency_response(
            request,
            existing,
            host=host,
            fallback_body={
                "operation_id": existing.operation_id,
                "job_id": existing.job_id,
                "status": "Queued",
                "links": {
                    "operation": f"{API_PREFIX}/operations/{existing.operation_id}",
                    "job": f"{API_PREFIX}/jobs/{existing.job_id}",
                },
            },
        )

    live_preflight_ready: tuple[Any, str, int, str, str | None] | None = None
    if host.adapter_mode == "live":
        router_row = host.runtime.store.get_router(router_id)
        assert router_row is not None
        endpoint_row = host.runtime.store.get_primary_endpoint(router_id)
        if endpoint_row is None:
            return error_response(
                request,
                status_code=404,
                code="resource.not_found",
                message="router endpoint not found",
            )
        cred_id = router_row["credential_ref_id"]
        if not cred_id:
            return error_response(
                request,
                status_code=400,
                code="request.validation_failed",
                message="router credential not configured",
            )
        endpoint_dict = {"host": endpoint_row["host"]}
        username = _resolve_management_username(endpoint_dict)
        if username is None:
            return error_response(
                request,
                status_code=400,
                code="request.validation_failed",
                message="RC_NETCRAZE_USERNAME required for live preflight",
            )
        source_raw = raw_body.get("source_address") or endpoint_row["source_address"]
        requires_source = (
            host.adapter_mode == "live"
            or str(endpoint_row["kind"]).lower() == "ssh_tunnel"
        )
        validated_source = _resolve_source_address_field(
            request,
            source_raw,
            required=requires_source,
        )
        if isinstance(validated_source, JSONResponse):
            return validated_source
        stored_source = endpoint_row["source_address"]
        if stored_source and validated_source and str(stored_source) != validated_source:
            return error_response(
                request,
                status_code=400,
                code="request.validation_failed",
                message="source_address mismatch with enrolled endpoint",
            )
        live_preflight_ready = (
            endpoint_row,
            username,
            int(raw_body.get("observation_ttl_seconds", DEFAULT_OBSERVATION_TTL_SECONDS)),
            str(cred_id),
            validated_source,
        )

    if host.adapter_mode == "live":
        outcome = host.runtime.store.create_operation_bundle(
            router_id=router_id,
            operation_kind="preflight",
            idempotency_key=key,
            request_digest=digest,
            actor_id="hub_admin",
            correlation_id=request.state.correlation_id,
            initial_job_status="Running",
            now=host.runtime.clock.now(),
        )
    else:
        outcome = host.runtime.store.create_operation_bundle(
            router_id=router_id,
            operation_kind="preflight",
            idempotency_key=key,
            request_digest=digest,
            actor_id="hub_admin",
            correlation_id=request.state.correlation_id,
            initial_job_status="Queued",
            http_status=202,
            now=host.runtime.clock.now(),
        )
    if not outcome.created:
        return _replay_idempotency_response(
            request,
            outcome,
            host=host,
            fallback_body={
                "operation_id": outcome.operation_id,
                "job_id": outcome.job_id,
                "status": "Queued",
                "links": {
                    "operation": f"{API_PREFIX}/operations/{outcome.operation_id}",
                    "job": f"{API_PREFIX}/jobs/{outcome.job_id}",
                },
            },
        )

    if host.adapter_mode == "live":
        assert live_preflight_ready is not None
        endpoint_row, username, ttl_seconds, cred_id, validated_source = live_preflight_ready
        probe_target = LiveProbeTarget(
            ssh_host=str(endpoint_row["host"]),
            username=username,
            credential_ref_id=cred_id,
            router_id=RouterId(router_id),
            source_address=validated_source,
        )
        try:
            evidence = await asyncio.to_thread(host.run_read_only_probe, probe_target)
        except Exception:
            err = error_body(
                code="router.identity_mismatch",
                message="live preflight identity probe failed",
                request_id=request.state.request_id,
                correlation_id=request.state.correlation_id,
            )
            host.runtime.store.fail_accepted_operation_bundle(
                operation_id=outcome.operation_id,
                job_id=outcome.job_id,
                idempotency_record_id=outcome.idempotency_record_id,
                http_status=422,
                error_body=err,
                now=host.runtime.clock.now(),
            )
            return error_response(
                request,
                status_code=422,
                code="router.identity_mismatch",
                message="live preflight identity probe failed",
            )

        cert = host.gate_a_certification
        assert cert is not None
        if not cert.matches_probe_evidence(dict(evidence)):
            err = error_body(
                code="router.identity_mismatch",
                message="live preflight identity tuple mismatch",
                request_id=request.state.request_id,
                correlation_id=request.state.correlation_id,
            )
            host.runtime.store.fail_accepted_operation_bundle(
                operation_id=outcome.operation_id,
                job_id=outcome.job_id,
                idempotency_record_id=outcome.idempotency_record_id,
                http_status=422,
                error_body=err,
                now=host.runtime.clock.now(),
            )
            return error_response(
                request,
                status_code=422,
                code="router.identity_mismatch",
                message="live preflight identity tuple mismatch",
            )

        fingerprint = str(
            evidence.get("device_fingerprint_digest") or evidence.get("device_fingerprint")
        )
        component_digest = str(evidence.get("component_set_digest", ""))
        observation_id = host.runtime.store.insert_observation(
            router_id=router_id,
            identity_fingerprint=fingerprint,
            resource_version=fingerprint,
            state_digest=component_digest,
            collection_status="Succeeded",
            source="netcraze-readonly-live",
            ttl_seconds=ttl_seconds,
            now=host.runtime.clock.now(),
        )
        completed = {
            "operation_id": outcome.operation_id,
            "job_id": outcome.job_id,
            "status": "Succeeded",
            "observation_id": observation_id,
            "certification_status": "ReadOnlyCertified",
            "links": {
                "operation": f"{API_PREFIX}/operations/{outcome.operation_id}",
                "job": f"{API_PREFIX}/jobs/{outcome.job_id}",
            },
        }
        host.runtime.store.finalize_live_preflight(
            router_id=router_id,
            operation_id=outcome.operation_id,
            job_id=outcome.job_id,
            idempotency_record_id=outcome.idempotency_record_id,
            observation_id=observation_id,
            body=completed,
            now=host.runtime.clock.now(),
        )
        return JSONResponse(
            completed,
            status_code=200,
            headers=_ok_headers(
                request,
                {"Location": f"{API_PREFIX}/operations/{outcome.operation_id}"},
            ),
        )

    accepted = {
        "operation_id": outcome.operation_id,
        "job_id": outcome.job_id,
        "status": "Queued",
        "links": {
            "operation": f"{API_PREFIX}/operations/{outcome.operation_id}",
            "job": f"{API_PREFIX}/jobs/{outcome.job_id}",
        },
    }
    if not outcome.created and outcome.response_ref:
        stored = json.loads(outcome.response_ref)
        return JSONResponse(
            stored.get("body", accepted),
            status_code=int(stored.get("http_status", 202)),
            headers=_ok_headers(
                request,
                {"Location": f"{API_PREFIX}/operations/{outcome.operation_id}"},
            ),
        )
    host.runtime.store.update_idempotency_response(
        outcome.idempotency_record_id, http_status=202, body=accepted
    )
    return JSONResponse(
        accepted,
        status_code=202,
        headers=_ok_headers(
            request,
            {"Location": f"{API_PREFIX}/operations/{outcome.operation_id}"},
        ),
    )


@router.get("/routers/{router_id}/credentials")
def list_credentials(router_id: str, request: Request) -> JSONResponse:
    host = _state(request)
    if host.runtime.store.get_router(router_id) is None:
        return error_response(
            request, status_code=404, code="resource.not_found", message="router not found"
        )
    items = []
    for row in host.runtime.store.list_credential_refs(router_id):
        items.append(
            {
                "credential_ref_id": row["credential_ref_id"],
                "kind": row["kind"],
                "provider": row["provider"],
                "created_at": row["created_at"],
                "rotated_at": row["rotated_at"],
                "revoked_at": row["revoked_at"],
            }
        )
    return JSONResponse({"items": items}, headers=_ok_headers(request))


@router.get("/routers/{router_id}/credentials/{credential_ref_id}")
def get_credential(
    router_id: str,
    credential_ref_id: str,
    request: Request,
) -> JSONResponse:
    host = _state(request)
    if host.runtime.store.get_router(router_id) is None:
        return error_response(
            request, status_code=404, code="resource.not_found", message="router not found"
        )
    row = host.runtime.store.get_credential_ref(credential_ref_id)
    if row is None or str(row["router_id"]) != router_id:
        return error_response(
            request,
            status_code=404,
            code="resource.not_found",
            message="credential not found",
        )
    return JSONResponse(
        {
            "credential_ref_id": row["credential_ref_id"],
            "kind": row["kind"],
            "provider": row["provider"],
            "created_at": row["created_at"],
            "rotated_at": row["rotated_at"],
            "revoked_at": row["revoked_at"],
        },
        headers=_ok_headers(request),
    )


def _put_credential_stored_body(response_ref: str | None) -> dict[str, Any] | None:
    if not response_ref:
        return None
    stored = json.loads(response_ref)
    body_out = stored.get("body", stored)
    return body_out if isinstance(body_out, dict) else None


def _put_credential_replay_response(
    request: Request,
    *,
    response_ref: str | None,
) -> JSONResponse | None:
    if not response_ref:
        return None
    stored = json.loads(response_ref)
    body_out = stored.get("body", stored)
    return JSONResponse(
        body_out,
        status_code=int(stored.get("http_status", 201)),
        headers=_ok_headers(request),
    )


def _put_credential_replay_usable(host: HostState, response_ref: str | None) -> bool:
    body_out = _put_credential_stored_body(response_ref)
    if body_out is None:
        return False
    ref_id = body_out.get("credential_ref_id")
    if not ref_id or not str(ref_id).strip():
        return False
    row = host.runtime.store.get_credential_ref(str(ref_id).strip())
    return row is not None and row["revoked_at"] is None


@router.put("/routers/{router_id}/credentials")
async def put_credential(
    router_id: str,
    request: Request,
    body: PutCredentialBody,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> JSONResponse:
    host = _state(request)
    if not idempotency_key or not idempotency_key.strip():
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="Idempotency-Key required",
        )
    degraded = _mutation_degraded(host, request)
    if degraded is not None:
        return degraded
    if host.runtime.store.get_router(router_id) is None:
        return error_response(
            request, status_code=404, code="resource.not_found", message="router not found"
        )
    kind_error = _validate_credential_kind(request, body.kind)
    if kind_error is not None:
        return kind_error
    secret = body.secret
    kind = body.kind
    if not secret:
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="secret required",
        )
    digest = _digest(
        {
            "kind": kind,
            "secret_sha256": hashlib.sha256(secret.encode()).hexdigest(),
        }
    )
    key = idempotency_key.strip()
    try:
        existing = host.runtime.store.peek_idempotency(
            router_id=router_id,
            operation_kind="put_credential",
            idempotency_key=key,
            request_digest=digest,
        )
    except IdempotencyConflict:
        return error_response(
            request,
            status_code=409,
            code="idempotency.conflict",
            message="same key different digest",
        )
    if existing is not None and existing.response_ref:
        if _put_credential_replay_usable(host, existing.response_ref):
            replay = _put_credential_replay_response(
                request, response_ref=existing.response_ref
            )
            assert replay is not None
            return replay
        prior_body = _put_credential_stored_body(existing.response_ref)
        prior_ref = (
            str(prior_body["credential_ref_id"]).strip()
            if prior_body and prior_body.get("credential_ref_id")
            else None
        )
        if prior_ref is not None:
            handle = host.runtime.vault.create(kind=kind, secret=secret)
            created_at = host.runtime.clock.now().strftime("%Y-%m-%dT%H:%M:%SZ")
            try:
                reminted = host.runtime.store.remint_put_credential(
                    idempotency_record_id=existing.idempotency_record_id,
                    router_id=router_id,
                    credential_ref_id=handle.credential_ref_id,
                    kind=handle.kind,
                    provider=handle.provider,
                    provider_locator=handle.provider_locator,
                    response_body={"kind": kind, "created_at": created_at},
                    now=host.runtime.clock.now(),
                )
            except Exception:
                host.runtime.vault.delete(handle.credential_ref_id)
                raise
            return JSONResponse(reminted, status_code=201, headers=_ok_headers(request))

    created_at = host.runtime.clock.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    handle = host.runtime.vault.create(kind=kind, secret=secret)
    try:
        outcome = host.runtime.store.put_credential_with_operation(
            router_id=router_id,
            credential_ref_id=handle.credential_ref_id,
            kind=handle.kind,
            provider=handle.provider,
            provider_locator=handle.provider_locator,
            idempotency_key=key,
            request_digest=digest,
            actor_id="hub_admin",
            response_body={"kind": kind, "created_at": created_at},
            now=host.runtime.clock.now(),
        )
    except IdempotencyConflict:
        host.runtime.vault.delete(handle.credential_ref_id)
        return error_response(
            request,
            status_code=409,
            code="idempotency.conflict",
            message="same key different digest",
        )
    except Exception:
        host.runtime.vault.delete(handle.credential_ref_id)
        raise

    if not outcome.created:
        host.runtime.vault.delete(handle.credential_ref_id)
        if _put_credential_replay_usable(host, outcome.response_ref):
            replay = _put_credential_replay_response(
                request, response_ref=outcome.response_ref
            )
            assert replay is not None
            return replay
        prior_body = _put_credential_stored_body(outcome.response_ref)
        prior_ref = (
            str(prior_body["credential_ref_id"]).strip()
            if prior_body and prior_body.get("credential_ref_id")
            else None
        )
        if prior_ref is not None:
            remint_handle = host.runtime.vault.create(kind=kind, secret=secret)
            try:
                reminted = host.runtime.store.remint_put_credential(
                    idempotency_record_id=outcome.idempotency_record_id,
                    router_id=router_id,
                    credential_ref_id=remint_handle.credential_ref_id,
                    kind=remint_handle.kind,
                    provider=remint_handle.provider,
                    provider_locator=remint_handle.provider_locator,
                    response_body={"kind": kind, "created_at": created_at},
                    now=host.runtime.clock.now(),
                )
            except Exception:
                host.runtime.vault.delete(remint_handle.credential_ref_id)
                raise
            return JSONResponse(reminted, status_code=201, headers=_ok_headers(request))
        stored = json.loads(outcome.response_ref or "{}")
        return JSONResponse(
            stored.get("body", stored),
            status_code=int(stored.get("http_status", 201)),
            headers=_ok_headers(request),
        )
    stored = json.loads(outcome.response_ref or "{}")
    return JSONResponse(
        stored.get("body")
        or {
            "credential_ref_id": handle.credential_ref_id,
            "kind": kind,
            "created_at": created_at,
        },
        status_code=201,
        headers=_ok_headers(request),
    )


@router.post("/routers/{router_id}/credentials/{credential_ref_id}/rotate")
async def rotate_credential(
    router_id: str,
    credential_ref_id: str,
    request: Request,
    body: RotateCredentialBody,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> JSONResponse:
    host = _state(request)
    if not idempotency_key or not idempotency_key.strip():
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="Idempotency-Key required",
        )
    degraded = _mutation_degraded(host, request)
    if degraded is not None:
        return degraded
    cred_row = host.runtime.store.get_credential_ref(credential_ref_id)
    if cred_row is None or str(cred_row["router_id"]) != router_id:
        return error_response(
            request,
            status_code=404,
            code="resource.not_found",
            message="credential not found",
        )
    kind_error = _validate_credential_kind(request, str(cred_row["kind"]))
    if kind_error is not None:
        return kind_error
    secret = body.secret
    if not secret:
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="secret required",
        )
    key = idempotency_key.strip()
    digest = _digest(
        {
            "credential_ref_id": credential_ref_id,
            "secret_sha256": hashlib.sha256(secret.encode()).hexdigest(),
        }
    )
    try:
        existing = host.runtime.store.peek_idempotency(
            router_id=router_id,
            operation_kind="rotate_credential",
            idempotency_key=key,
            request_digest=digest,
        )
    except IdempotencyConflict:
        return error_response(
            request,
            status_code=409,
            code="idempotency.conflict",
            message="same key different digest",
        )
    if existing is not None:
        stored = json.loads(existing.response_ref or "{}")
        body_out = stored.get("body") or {
            "operation_id": existing.operation_id,
            "job_id": existing.job_id,
            "status": "Queued",
            "links": {
                "operation": f"{API_PREFIX}/operations/{existing.operation_id}",
                "job": f"{API_PREFIX}/jobs/{existing.job_id}",
            },
        }
        return JSONResponse(
            body_out,
            status_code=int(stored.get("http_status", 202)),
            headers=_ok_headers(request),
        )

    # Claim idempotency before vault mutate (API §4.3/§7.5): conflict must not
    # touch secrets. create_operation_bundle uses BEGIN IMMEDIATE + UNIQUE key.
    try:
        outcome = host.runtime.store.create_operation_bundle(
            router_id=router_id,
            operation_kind="rotate_credential",
            idempotency_key=key,
            request_digest=digest,
            actor_id="hub_admin",
            initial_job_status="Succeeded",
            response_ref=json.dumps(
                {
                    "status": "Queued",
                }
            ),
            http_status=202,
            now=host.runtime.clock.now(),
        )
    except IdempotencyConflict:
        return error_response(
            request,
            status_code=409,
            code="idempotency.conflict",
            message="same key different digest",
        )
    accepted = {
        "operation_id": outcome.operation_id,
        "job_id": outcome.job_id,
        "status": "Queued",
        "links": {
            "operation": f"{API_PREFIX}/operations/{outcome.operation_id}",
            "job": f"{API_PREFIX}/jobs/{outcome.job_id}",
        },
    }
    if not outcome.created:
        if outcome.response_ref:
            stored = json.loads(outcome.response_ref)
            return JSONResponse(
                stored.get("body", accepted),
                status_code=int(stored.get("http_status", 202)),
                headers=_ok_headers(request),
            )
        return JSONResponse(accepted, status_code=202, headers=_ok_headers(request))

    try:
        host.runtime.vault.rotate(credential_ref_id, secret=secret)
    except VaultError as exc:
        return _fail_op_on_vault_error(host, request, outcome, exc)
    host.runtime.store.mark_credential_rotated(credential_ref_id, now=host.runtime.clock.now())
    host.runtime.store.update_idempotency_response(
        outcome.idempotency_record_id, http_status=202, body=accepted
    )
    return JSONResponse(accepted, status_code=202, headers=_ok_headers(request))


@router.post("/routers/{router_id}/credentials/{credential_ref_id}/revoke")
async def revoke_credential(
    router_id: str,
    credential_ref_id: str,
    request: Request,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> JSONResponse:
    host = _state(request)
    if not idempotency_key or not idempotency_key.strip():
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="Idempotency-Key required",
        )
    degraded = _mutation_degraded(host, request)
    if degraded is not None:
        return degraded
    key = idempotency_key.strip()
    digest = _digest({"credential_ref_id": credential_ref_id})
    try:
        existing = host.runtime.store.peek_idempotency(
            router_id=router_id,
            operation_kind="revoke_credential",
            idempotency_key=key,
            request_digest=digest,
        )
    except IdempotencyConflict:
        return error_response(
            request,
            status_code=409,
            code="idempotency.conflict",
            message="same key different digest",
        )
    if existing is not None:
        stored = json.loads(existing.response_ref or "{}")
        body_out = stored.get("body") or {
            "operation_id": existing.operation_id,
            "job_id": existing.job_id,
            "status": "Queued",
            "links": {
                "operation": f"{API_PREFIX}/operations/{existing.operation_id}",
                "job": f"{API_PREFIX}/jobs/{existing.job_id}",
            },
        }
        return JSONResponse(
            body_out,
            status_code=int(stored.get("http_status", 202)),
            headers=_ok_headers(request),
        )

    # Claim before vault revoke — same critical-section rule as rotate.
    try:
        outcome = host.runtime.store.create_operation_bundle(
            router_id=router_id,
            operation_kind="revoke_credential",
            idempotency_key=key,
            request_digest=digest,
            actor_id="hub_admin",
            initial_job_status="Succeeded",
            response_ref=json.dumps({"status": "Queued"}),
            http_status=202,
            now=host.runtime.clock.now(),
        )
    except IdempotencyConflict:
        return error_response(
            request,
            status_code=409,
            code="idempotency.conflict",
            message="same key different digest",
        )
    accepted = {
        "operation_id": outcome.operation_id,
        "job_id": outcome.job_id,
        "status": "Queued",
        "links": {
            "operation": f"{API_PREFIX}/operations/{outcome.operation_id}",
            "job": f"{API_PREFIX}/jobs/{outcome.job_id}",
        },
    }
    if not outcome.created:
        if outcome.response_ref:
            stored = json.loads(outcome.response_ref)
            return JSONResponse(
                stored.get("body", accepted),
                status_code=int(stored.get("http_status", 202)),
                headers=_ok_headers(request),
            )
        return JSONResponse(accepted, status_code=202, headers=_ok_headers(request))

    try:
        host.runtime.vault.revoke(credential_ref_id)
    except VaultError as exc:
        return _fail_op_on_vault_error(host, request, outcome, exc)
    host.runtime.store.mark_credential_revoked(credential_ref_id, now=host.runtime.clock.now())
    host.runtime.store.update_idempotency_response(
        outcome.idempotency_record_id, http_status=202, body=accepted
    )
    return JSONResponse(accepted, status_code=202, headers=_ok_headers(request))


@router.get("/vpn-profiles")
def list_profiles(request: Request) -> JSONResponse:
    host = _state(request)
    active_by_profile: dict[str, dict[str, Any]] = {}
    for assignment in host.runtime.store.list_active_tunnel_assignments():
        profile_id = str(assignment["profile_id"])
        if profile_id not in active_by_profile:
            active_by_profile[profile_id] = assignment
    items = []
    for row in host.runtime.store.list_profiles():
        profile_id = str(row["profile_id"])
        metadata = json.loads(row["metadata_json"] or "{}")
        active_assignment: dict[str, Any] | None = active_by_profile.get(profile_id)
        is_active = active_assignment is not None
        assigned_wg_id: str | None = None
        tunnel_verification_status: str | None = None
        if is_active and active_assignment is not None:
            assigned_wg_id = None
            if active_assignment.get("observed_vendor_locator"):
                assigned_wg_id = str(active_assignment["observed_vendor_locator"])
            policy_raw = active_assignment.get("policy_metadata_json")
            if policy_raw:
                policy = json.loads(policy_raw)
                if not assigned_wg_id and policy.get("wg_id"):
                    assigned_wg_id = str(policy["wg_id"])
                tvs = policy.get("tunnel_verification_status")
                if isinstance(tvs, str) and tvs:
                    tunnel_verification_status = tvs
            if not assigned_wg_id:
                meta_wg = metadata.get("wg_id")
                if meta_wg is not None:
                    assigned_wg_id = str(meta_wg)
        item: dict[str, Any] = {
            "profile_id": row["profile_id"],
            "display_name": row["display_name"],
            "vpn_kind": row["vpn_kind"],
            "validation_status": row["validation_status"],
            "content_digest": row["content_digest"],
            "created_at": row["created_at"],
            "is_active": is_active,
            "assigned_wg_id": assigned_wg_id,
        }
        if tunnel_verification_status is not None:
            item["tunnel_verification_status"] = tunnel_verification_status
        items.append(item)
    return JSONResponse(
        {"items": items, "next_cursor": None, "limit": 50},
        headers=_ok_headers(request),
    )


_AWG_PROFILE_FIELD_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^unknown (?:interface|peer) field: (.+)$"), "unknown_fields"),
    (re.compile(r"^duplicate (?:interface|peer) field: (.+)$"), "invalid_format"),
    (re.compile(r"^missing or empty required field: (.+)$"), "invalid_value"),
    (re.compile(r"^invalid obfuscation integer for (.+)$"), "out_of_range"),
)


def _awg_profile_field_and_reason(exc: AwgProfileError) -> tuple[str | None, str]:
    message = str(exc)
    for pattern, reason in _AWG_PROFILE_FIELD_PATTERNS:
        match = pattern.match(message)
        if match:
            return match.group(1), reason
    lowered = message.lower()
    if "allow_ips" in lowered:
        return "AllowedIPs", "invalid_value"
    return None, "profile_validation_failed"


def _awg_profile_validation_error(request: Request, exc: AwgProfileError) -> JSONResponse:
    field, reason = _awg_profile_field_and_reason(exc)
    _ = exc
    if field is not None:
        return operator_structured_error_response(
            request,
            status_code=422,
            code="profile.validation_failed",
            reason=reason,
            field=field,
        )
    return error_response(
        request,
        status_code=422,
        code="profile.validation_failed",
        message=synthesize_operator_message(
            code="profile.validation_failed",
            reason="profile_validation_failed",
        ),
    )


@router.post("/vpn-profiles/parse-preview")
def parse_profile_preview(
    request: Request,
    body: VpnProfileParsePreviewBody,
) -> JSONResponse:
    """Parse AWG profile text once; store secrets in vault; return sanitized metadata only."""
    host = _state(request)
    degraded = _mutation_degraded(host, request)
    if degraded is not None:
        return degraded
    try:
        parsed = parse_awg_profile_text(body.profile_text, vault=host.runtime.vault)
    except AwgProfileError as exc:
        return _awg_profile_validation_error(request, exc)
    return JSONResponse(parsed.sanitized_dict_for_apply(), headers=_ok_headers(request))


_SYNC_PROFILE_IDEMPOTENCY_PLACEHOLDER = json.dumps({"status": "InProgress"})


def _sync_profile_idempotency_replayable(stored: dict[str, Any]) -> bool:
    body = stored.get("body", stored)
    if not isinstance(body, dict):
        return bool(body)
    return body.get("status") != "InProgress"


def _sync_profile_idempotency_response(
    request: Request,
    *,
    stored: dict[str, Any],
    default_status: int,
) -> JSONResponse | None:
    if not _sync_profile_idempotency_replayable(stored):
        return None
    body = stored.get("body", stored)
    return JSONResponse(
        body,
        status_code=int(stored.get("http_status", default_status)),
        headers=_ok_headers(request),
    )


def _sync_profile_idempotency_in_progress_response(
    request: Request,
    *,
    stored: dict[str, Any],
) -> JSONResponse | None:
    if _sync_profile_idempotency_replayable(stored):
        return None
    body = stored.get("body", stored)
    return JSONResponse(
        body,
        status_code=int(stored.get("http_status", 202)),
        headers=_ok_headers(request),
    )


@router.post("/vpn-profiles/import")
async def import_profile(
    request: Request,
    body: VpnProfileImportBody,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> JSONResponse:
    host = _state(request)
    if not idempotency_key or not idempotency_key.strip():
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="Idempotency-Key required",
        )
    degraded = _mutation_degraded(host, request)
    if degraded is not None:
        return degraded
    if body.vpn_kind != "AmneziaWG":
        return error_response(
            request,
            status_code=422,
            code="profile.validation_failed",
            message="Only AmneziaWG supported in v1",
        )
    if body.ip_global_auto and body.ip_global_priority is not None:
        return error_response(
            request,
            status_code=422,
            code="request.validation_failed",
            message="ip_global_auto and ip_global_priority are mutually exclusive",
        )
    try:
        parsed = parse_awg_profile_text(body.profile_text, vault=host.runtime.vault)
    except AwgProfileError as exc:
        return _awg_profile_validation_error(request, exc)

    content_digest = parsed.profile_digest
    metadata = _profile_metadata_from_parsed(
        parsed,
        wg_id=body.wg_id,
        ip_global_auto=body.ip_global_auto,
        ip_global_priority=body.ip_global_priority,
        tcp_mss_pmtu=body.tcp_mss_pmtu,
    )
    key = idempotency_key.strip()
    digest = _digest(
        {
            "display_name": body.display_name,
            "digest": content_digest,
            "wg_id": body.wg_id,
        }
    )
    site = host.ensure_default_site()
    sentinel = _ensure_catalog_router(host, site)
    try:
        existing = host.runtime.store.peek_idempotency(
            router_id=sentinel,
            operation_kind="import_profile",
            idempotency_key=key,
            request_digest=digest,
        )
    except IdempotencyConflict:
        return error_response(
            request,
            status_code=409,
            code="idempotency.conflict",
            message="same key different digest",
        )
    if existing is not None and existing.response_ref:
        stored = json.loads(existing.response_ref)
        replay = _sync_profile_idempotency_response(
            request, stored=stored, default_status=201
        )
        if replay is not None:
            return replay
        in_progress = _sync_profile_idempotency_in_progress_response(
            request, stored=stored
        )
        if in_progress is not None:
            return in_progress

    try:
        outcome = host.runtime.store.create_operation_bundle(
            router_id=sentinel,
            operation_kind="import_profile",
            idempotency_key=key,
            request_digest=digest,
            actor_id="hub_admin",
            correlation_id=request.state.correlation_id,
            initial_job_status="Succeeded",
            response_ref=_SYNC_PROFILE_IDEMPOTENCY_PLACEHOLDER,
            http_status=202,
            now=host.runtime.clock.now(),
        )
    except IdempotencyConflict:
        return error_response(
            request,
            status_code=409,
            code="idempotency.conflict",
            message="same key different digest",
        )
    if not outcome.created:
        if outcome.response_ref:
            stored = json.loads(outcome.response_ref)
            replay = _sync_profile_idempotency_response(
                request, stored=stored, default_status=201
            )
            if replay is not None:
                return replay
            in_progress = _sync_profile_idempotency_in_progress_response(
                request, stored=stored
            )
            if in_progress is not None:
                return in_progress

    profile_id = host.runtime.store.import_profile(
        display_name=body.display_name,
        vpn_kind=body.vpn_kind,
        content_digest=content_digest,
        metadata_json=json.dumps(metadata, sort_keys=True),
        unsupported_fields_json=(
            json.dumps(list(parsed.unsupported_fields))
            if parsed.unsupported_fields
            else None
        ),
        now=host.runtime.clock.now(),
    )
    vault_provider = getattr(host.runtime.vault, "provider", "CredentialVault")
    for ref in parsed.credential_refs:
        existing_cred = host.runtime.store.get_credential_ref(ref.credential_ref_id)
        if existing_cred is None:
            host.runtime.store.insert_credential_ref(
                router_id=sentinel,
                kind=ref.kind,
                provider=vault_provider,
                provider_locator=ref.credential_ref_id,
                credential_ref_id=ref.credential_ref_id,
                now=host.runtime.clock.now(),
            )
    host.runtime.store.insert_profile_secret_refs(
        profile_id=profile_id,
        refs=[(ref.credential_ref_id, ref.role) for ref in parsed.credential_refs],
        now=host.runtime.clock.now(),
    )
    row = host.runtime.store.get_profile(profile_id)
    assert row is not None
    response_body = _profile_detail(host, row)
    host.runtime.store.update_idempotency_response(
        outcome.idempotency_record_id, http_status=201, body=response_body
    )
    return JSONResponse(response_body, status_code=201, headers=_ok_headers(request))


@router.get("/vpn-profiles/{profile_id}")
def get_profile(profile_id: str, request: Request) -> JSONResponse:
    host = _state(request)
    row = host.runtime.store.get_profile(profile_id)
    if row is None:
        return error_response(
            request, status_code=404, code="resource.not_found", message="profile not found"
        )
    return JSONResponse(_profile_detail(host, row), headers=_ok_headers(request))


@router.post("/vpn-profiles/{profile_id}/validate")
async def validate_profile(
    profile_id: str,
    request: Request,
    idempotency_key: str = Header(..., alias="Idempotency-Key"),
) -> JSONResponse:
    host = _state(request)
    if not idempotency_key or not idempotency_key.strip():
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="Idempotency-Key required",
        )
    degraded = _mutation_degraded(host, request)
    if degraded is not None:
        return degraded
    row = host.runtime.store.get_profile(profile_id)
    if row is None:
        return error_response(
            request, status_code=404, code="resource.not_found", message="profile not found"
        )
    raw_body: dict[str, Any] = {}
    if request.headers.get("content-length") not in (None, "0"):
        raw_body = await request.json()
    parser_version = str(raw_body.get("parser_version", row["parser_version"]))
    validation_status = "Valid" if row["vpn_kind"] == "AmneziaWG" else "Invalid"
    digest = _digest({"profile_id": profile_id, "parser_version": parser_version})
    key = idempotency_key.strip()
    sentinel = _ensure_catalog_router(host, host.ensure_default_site())
    try:
        existing = host.runtime.store.peek_idempotency(
            router_id=sentinel,
            operation_kind="validate_profile",
            idempotency_key=key,
            request_digest=digest,
        )
    except IdempotencyConflict:
        return error_response(
            request,
            status_code=409,
            code="idempotency.conflict",
            message="same key different digest",
        )
    if existing is not None and existing.response_ref:
        stored = json.loads(existing.response_ref)
        replay = _sync_profile_idempotency_response(
            request, stored=stored, default_status=200
        )
        if replay is not None:
            return replay
        in_progress = _sync_profile_idempotency_in_progress_response(
            request, stored=stored
        )
        if in_progress is not None:
            return in_progress

    try:
        outcome = host.runtime.store.create_operation_bundle(
            router_id=sentinel,
            operation_kind="validate_profile",
            idempotency_key=key,
            request_digest=digest,
            actor_id="hub_admin",
            correlation_id=request.state.correlation_id,
            initial_job_status="Succeeded",
            response_ref=_SYNC_PROFILE_IDEMPOTENCY_PLACEHOLDER,
            http_status=202,
            now=host.runtime.clock.now(),
        )
    except IdempotencyConflict:
        return error_response(
            request,
            status_code=409,
            code="idempotency.conflict",
            message="same key different digest",
        )
    if not outcome.created:
        if outcome.response_ref:
            stored = json.loads(outcome.response_ref)
            replay = _sync_profile_idempotency_response(
                request, stored=stored, default_status=200
            )
            if replay is not None:
                return replay
            in_progress = _sync_profile_idempotency_in_progress_response(
                request, stored=stored
            )
            if in_progress is not None:
                return in_progress

    host.runtime.store.update_profile_validation(
        profile_id=profile_id,
        validation_status=validation_status,
        parser_version=parser_version,
    )
    updated = host.runtime.store.get_profile(profile_id)
    assert updated is not None
    detail = _profile_detail(host, updated)
    host.runtime.store.update_idempotency_response(
        outcome.idempotency_record_id, http_status=200, body=detail
    )
    return JSONResponse(detail, status_code=200, headers=_ok_headers(request))


@router.post("/vpn-profiles/{profile_id}/activate")
def activate_vpn_profile(
    profile_id: str,
    request: Request,
    body: VpnProfileActivateBody,
) -> JSONResponse:
    if not body.confirm_live_apply:
        return error_response(
            request,
            status_code=400,
            code="wireguard.confirm_required",
            message="confirm_live_apply must be true to dispatch activate",
        )
    host = _state(request)
    degraded = _mutation_degraded(host, request)
    if degraded is not None:
        return degraded
    row = host.runtime.store.get_profile(profile_id)
    if row is None:
        return error_response(
            request, status_code=404, code="resource.not_found", message="profile not found"
        )
    try:
        intent = _wireguard_intent_from_profile_row(
            host,
            row,
            wg_id=body.wg_id,
            enabled=True,
            ip_global_auto=body.ip_global_auto,
            ip_global_priority=body.ip_global_priority,
            tcp_mss_pmtu=body.tcp_mss_pmtu,
        )
    except (IntentValidationError, ValueError) as exc:
        _ = exc
        return error_response(
            request,
            status_code=422,
            code="profile.activate_failed",
            message=synthesize_operator_message(
                code="profile.activate_failed",
                reason="profile_validation_failed",
            ),
        )
    from router_control.adapters.netcraze.startup_backup import StartupBackupError
    from router_control.persistence.errors import SealedApplyTrailBeginError

    from router_control_host import wireguard_apply_routes as wg_routes

    gate = wg_routes._apply_gates(host, request)
    if gate is not None:
        return gate

    incomplete = wg_routes._validate_live_connection_fields(
        request, cast(wg_routes.WireguardLiveConnectionFields, body), host
    )
    if incomplete is not None:
        return incomplete

    live_params = wg_routes._live_params_from_body(
        cast(wg_routes.WireguardLiveConnectionFields, body), host
    )
    if live_params is not None and not is_win32_live_capable():
        return wg_routes._live_platform_unsupported_error(request)

    router_id = body.router_id.strip() if body.router_id else None
    lock_key = resolve_router_apply_lock_key(
        router_id,
        live_host=body.host,
        ssh_host_key_sha256=body.ssh_host_key_sha256,
        source_address=body.source_address,
    )
    intent_redacted = _profile_mutation_intent_redacted(profile_id, intent)
    trail_params = wg_routes._sealed_apply_trail_params(
        request,
        route="vpn-profiles",
        verb="activate",
        intent_redacted=intent_redacted,
        router_id=router_id,
    )
    result: WireguardApplyResult | None = None

    def _dispatch_activate() -> WireguardApplyResult:
        if router_id:
            _teardown_prior_profile_assignment(
                host=host,
                request=request,
                body=body,
                wg_routes=wg_routes,
                router_id=router_id,
                profile_id=profile_id,
                logical_role=body.logical_role,
                live_params=live_params,
                trail_params=trail_params,
            )
        if wg_routes._should_use_live_path(
            cast(wg_routes.WireguardLiveConnectionFields, body), host
        ):
            assert live_params is not None
            return wg_routes._dispatch_apply_live(
                host=host,
                intent=intent,
                params=live_params,
                handshake_settle_seconds=clamp_handshake_settle_seconds(
                    body.handshake_settle_seconds
                ),
                sealed_apply_params=trail_params,
                router_id=router_id,
            )
        transport = wg_routes._resolve_transport(host, request)
        if isinstance(transport, JSONResponse):
            raise WireguardApplyServiceError("transport resolution failed")
        return apply_wireguard_intent(
            intent=intent,
            transport=transport,
            credential_resolver=wg_routes._credential_resolver(host),
            handshake_settle_seconds=clamp_handshake_settle_seconds(
                body.handshake_settle_seconds
            ),
            store=host.runtime.store,
            sealed_apply_params=trail_params,
        )

    if wg_routes._should_use_live_path(
        cast(wg_routes.WireguardLiveConnectionFields, body), host
    ):
        assert live_params is not None
        if host.gate_a_certification is None or not host.gate_a_certification.is_open:
            return wg_routes._gate_a_required_error(
                request,
                "Gate A certification required for live activate (startup-config backup)",
            )
        if normalize_live_apply_router_id(router_id) is None:
            return wg_routes._connection_incomplete_error(
                request, missing=["router_id"]
            )
        try:
            result = run_with_router_apply_lock(lock_key, _dispatch_activate)
        except LiveIdentityTupleMismatchError:
            return wg_routes._identity_mismatch_error(request)
        except StartupBackupError:
            return wg_routes._live_backup_unavailable_error(request)
        except SealedApplyTrailBeginError as exc:
            wg_routes._record_wireguard_sealed_audit(
                host,
                request,
                verb="activate",
                intent_redacted=intent_redacted,
                outcome="failed",
                error_message=wg_routes._synthesised_trail_begin_failed_message(),
                router_id=router_id,
                route="vpn-profiles",
            )
            return sealed_apply_trail_begin_error_response(request, exc)
        except WireguardApplyServiceError as exc:
            wg_routes._record_wireguard_sealed_audit(
                host,
                request,
                verb="activate",
                intent_redacted=intent_redacted,
                outcome="failed",
                error_message=wg_routes._synthesised_apply_failed_message(),
                router_id=router_id,
                route="vpn-profiles",
            )
            _ = exc
            return error_response(
                request,
                status_code=422,
                code="profile.activate_failed",
                message=wg_routes._synthesised_apply_failed_message(),
            )
        except Exception as exc:
            wg_routes._record_wireguard_sealed_audit(
                host,
                request,
                verb="activate",
                intent_redacted=intent_redacted,
                outcome="error",
                exception_type=type(exc).__name__,
                router_id=router_id,
                route="vpn-profiles",
            )
            mapped = map_wifi_live_transport_error(
                exc,
                router_credential_ref_id=body.router_credential_ref_id,
                code_prefix=wg_routes._LIVE_FAMILY_PREFIX,
            )
            return error_response(
                request,
                status_code=mapped.status_code,
                code=mapped.code,
                message=mapped.message,
            )
        wg_routes._record_wireguard_sealed_audit(
            host,
            request,
            verb="activate",
            intent_redacted=intent_redacted,
            result=result,
            router_id=router_id,
            route="vpn-profiles",
        )
    else:
        transport = wg_routes._resolve_transport(host, request)
        if isinstance(transport, JSONResponse):
            return transport
        try:
            result = run_with_router_apply_lock(lock_key, _dispatch_activate)
        except SealedApplyTrailBeginError as exc:
            wg_routes._record_wireguard_sealed_audit(
                host,
                request,
                verb="activate",
                intent_redacted=intent_redacted,
                outcome="failed",
                error_message=wg_routes._synthesised_trail_begin_failed_message(),
                router_id=router_id,
                route="vpn-profiles",
            )
            return sealed_apply_trail_begin_error_response(request, exc)
        except WireguardApplyServiceError as exc:
            wg_routes._record_wireguard_sealed_audit(
                host,
                request,
                verb="activate",
                intent_redacted=intent_redacted,
                outcome="failed",
                error_message=wg_routes._synthesised_apply_failed_message(),
                router_id=router_id,
                route="vpn-profiles",
            )
            _ = exc
            return error_response(
                request,
                status_code=422,
                code="profile.activate_failed",
                message=wg_routes._synthesised_apply_failed_message(),
            )
        except Exception:
            wg_routes._record_wireguard_sealed_audit(
                host,
                request,
                verb="activate",
                intent_redacted=intent_redacted,
                outcome="error",
                router_id=router_id,
                route="vpn-profiles",
            )
            raise
        wg_routes._record_wireguard_sealed_audit(
            host,
            request,
            verb="activate",
            intent_redacted=intent_redacted,
            result=result,
            router_id=router_id,
            route="vpn-profiles",
        )

    assert result is not None
    if router_id and _profile_apply_success(result):
        host.runtime.store.upsert_tunnel_assignment(
            router_id=router_id,
            profile_id=profile_id,
            logical_role=body.logical_role,
            desired_active=True,
            observed_vendor_locator=intent.wg_id,
            policy_metadata_json=json.dumps(
                {
                    "wg_id": intent.wg_id,
                    "tunnel_verification_status": result.tunnel_verification_status,
                },
                sort_keys=True,
            ),
            now=host.runtime.clock.now(),
        )
        if intent.ip_global_priority is not None or intent.ip_global_auto:
            metadata_patch: dict[str, Any] = {"ip_global_auto": intent.ip_global_auto}
            if intent.ip_global_priority is not None:
                metadata_patch["ip_global_priority"] = intent.ip_global_priority
            host.runtime.store.merge_profile_metadata(
                profile_id=profile_id,
                patch=metadata_patch,
            )
    payload = result.to_dict()
    payload["profile_id"] = profile_id
    payload["activated"] = _profile_apply_success(result)
    return JSONResponse(payload, status_code=200, headers=_ok_headers(request))


@router.post("/vpn-profiles/deactivate")
def deactivate_vpn_profile(
    request: Request,
    body: VpnProfileDeactivateBody,
) -> JSONResponse:
    if not body.confirm_live_apply:
        return error_response(
            request,
            status_code=400,
            code="wireguard.confirm_required",
            message="confirm_live_apply must be true to dispatch deactivate",
        )
    host = _state(request)
    degraded = _mutation_degraded(host, request)
    if degraded is not None:
        return degraded
    from router_control.adapters.netcraze.startup_backup import StartupBackupError
    from router_control.persistence.errors import SealedApplyTrailBeginError

    from router_control_host import wireguard_apply_routes as wg_routes

    gate = wg_routes._apply_gates(host, request)
    if gate is not None:
        return gate

    incomplete = wg_routes._validate_live_connection_fields(
        request, cast(wg_routes.WireguardLiveConnectionFields, body), host
    )
    if incomplete is not None:
        return incomplete

    live_params = wg_routes._live_params_from_body(
        cast(wg_routes.WireguardLiveConnectionFields, body), host
    )
    if live_params is not None and not is_win32_live_capable():
        return wg_routes._live_platform_unsupported_error(request)

    router_id = body.router_id.strip() if body.router_id else None
    lock_key = resolve_router_apply_lock_key(
        router_id,
        live_host=body.host,
        ssh_host_key_sha256=body.ssh_host_key_sha256,
        source_address=body.source_address,
    )

    assignment = (
        host.runtime.store.get_active_tunnel_assignment(
            router_id or "",
            logical_role=body.logical_role,
        )
        if router_id
        else None
    )
    if assignment is not None:
        observed = assignment.get("observed_vendor_locator")
        if observed:
            observed_wg = str(observed).strip()
            request_wg = body.wg_id.strip()
            if observed_wg and observed_wg != request_wg:
                return error_response(
                    request,
                    status_code=422,
                    code="profile.deactivate_wg_mismatch",
                    message=(
                        "wg_id does not match active tunnel assignment "
                        f"(observed={observed_wg}, requested={request_wg})"
                    ),
                )
    intent = WireguardIntent(wg_id=body.wg_id, enabled=False, asc_args=None)
    profile_id = str(assignment["profile_id"]) if assignment is not None else None
    if assignment is not None:
        row = host.runtime.store.get_profile(str(assignment["profile_id"]))
        if row is not None:
            intent = _wireguard_intent_from_profile_row(host, row, wg_id=body.wg_id, enabled=False)

    intent_redacted = _profile_mutation_intent_redacted(
        profile_id or "unknown",
        intent,
    )
    trail_params = wg_routes._sealed_apply_trail_params(
        request,
        route="vpn-profiles",
        verb="deactivate",
        intent_redacted=intent_redacted,
        router_id=router_id,
    )
    result: WireguardApplyResult | None = None

    def _dispatch_deactivate() -> WireguardApplyResult:
        if wg_routes._should_use_live_path(
            cast(wg_routes.WireguardLiveConnectionFields, body), host
        ):
            assert live_params is not None
            return wg_routes._dispatch_teardown_live(
                host=host,
                intent=intent,
                params=live_params,
                sealed_apply_params=trail_params,
                router_id=router_id,
            )
        transport = wg_routes._resolve_transport(host, request)
        if isinstance(transport, JSONResponse):
            raise WireguardApplyServiceError("transport resolution failed")
        return teardown_wireguard(
            wg_id=body.wg_id,
            transport=transport,
            credential_resolver=wg_routes._credential_resolver(host),
            intent=intent,
            store=host.runtime.store,
            sealed_apply_params=trail_params,
        )

    if wg_routes._should_use_live_path(
        cast(wg_routes.WireguardLiveConnectionFields, body), host
    ):
        assert live_params is not None
        if host.gate_a_certification is None or not host.gate_a_certification.is_open:
            return wg_routes._gate_a_required_error(
                request,
                "Gate A certification required for live deactivate (startup-config backup)",
            )
        if normalize_live_apply_router_id(router_id) is None:
            return wg_routes._connection_incomplete_error(
                request, missing=["router_id"]
            )
        try:
            result = run_with_router_apply_lock(lock_key, _dispatch_deactivate)
        except LiveIdentityTupleMismatchError:
            return wg_routes._identity_mismatch_error(request)
        except StartupBackupError:
            return wg_routes._live_backup_unavailable_error(request)
        except SealedApplyTrailBeginError as exc:
            wg_routes._record_wireguard_sealed_audit(
                host,
                request,
                verb="deactivate",
                intent_redacted=intent_redacted,
                outcome="failed",
                error_message=wg_routes._synthesised_trail_begin_failed_message(),
                router_id=router_id,
                route="vpn-profiles",
            )
            return sealed_apply_trail_begin_error_response(request, exc)
        except LiveGateARequiredError as exc:
            return wg_routes._gate_a_required_error(request, str(exc))
        except WireguardApplyServiceError as exc:
            wg_routes._record_wireguard_sealed_audit(
                host,
                request,
                verb="deactivate",
                intent_redacted=intent_redacted,
                outcome="failed",
                error_message=wg_routes._synthesised_apply_failed_message(),
                router_id=router_id,
                route="vpn-profiles",
            )
            _ = exc
            return error_response(
                request,
                status_code=422,
                code="profile.deactivate_failed",
                message=wg_routes._synthesised_apply_failed_message(),
            )
        except Exception as exc:
            wg_routes._record_wireguard_sealed_audit(
                host,
                request,
                verb="deactivate",
                intent_redacted=intent_redacted,
                outcome="error",
                exception_type=type(exc).__name__,
                router_id=router_id,
                route="vpn-profiles",
            )
            mapped = map_wifi_live_transport_error(
                exc,
                router_credential_ref_id=body.router_credential_ref_id,
                code_prefix=wg_routes._LIVE_FAMILY_PREFIX,
            )
            return error_response(
                request,
                status_code=mapped.status_code,
                code=mapped.code,
                message=mapped.message,
            )
        wg_routes._record_wireguard_sealed_audit(
            host,
            request,
            verb="deactivate",
            intent_redacted=intent_redacted,
            result=result,
            router_id=router_id,
            route="vpn-profiles",
        )
    else:
        transport = wg_routes._resolve_transport(host, request)
        if isinstance(transport, JSONResponse):
            return transport
        try:
            result = run_with_router_apply_lock(lock_key, _dispatch_deactivate)
        except SealedApplyTrailBeginError as exc:
            wg_routes._record_wireguard_sealed_audit(
                host,
                request,
                verb="deactivate",
                intent_redacted=intent_redacted,
                outcome="failed",
                error_message=wg_routes._synthesised_trail_begin_failed_message(),
                router_id=router_id,
                route="vpn-profiles",
            )
            return sealed_apply_trail_begin_error_response(request, exc)
        except WireguardApplyServiceError as exc:
            wg_routes._record_wireguard_sealed_audit(
                host,
                request,
                verb="deactivate",
                intent_redacted=intent_redacted,
                outcome="failed",
                error_message=wg_routes._synthesised_apply_failed_message(),
                router_id=router_id,
                route="vpn-profiles",
            )
            _ = exc
            return error_response(
                request,
                status_code=422,
                code="profile.deactivate_failed",
                message=wg_routes._synthesised_apply_failed_message(),
            )
        except Exception:
            wg_routes._record_wireguard_sealed_audit(
                host,
                request,
                verb="deactivate",
                intent_redacted=intent_redacted,
                outcome="error",
                router_id=router_id,
                route="vpn-profiles",
            )
            raise
        wg_routes._record_wireguard_sealed_audit(
            host,
            request,
            verb="deactivate",
            intent_redacted=intent_redacted,
            result=result,
            router_id=router_id,
            route="vpn-profiles",
        )

    assert result is not None
    if router_id and _profile_apply_success(result):
        if assignment is not None:
            observed = assignment.get("observed_vendor_locator")
            if observed:
                observed_wg = str(observed).strip()
                if observed_wg and observed_wg != body.wg_id.strip():
                    return error_response(
                        request,
                        status_code=422,
                        code="profile.deactivate_wg_mismatch",
                        message=(
                            "wg_id does not match active tunnel assignment "
                            f"(observed={observed_wg}, requested={body.wg_id.strip()})"
                        ),
                    )
        host.runtime.store.deactivate_tunnel_assignments(
            router_id, logical_role=body.logical_role, now=host.runtime.clock.now()
        )
    payload = result.to_dict()
    payload["deactivated"] = _profile_apply_success(result)
    return JSONResponse(payload, status_code=200, headers=_ok_headers(request))


def _ensure_catalog_router(host: HostState, site_id: str) -> str:
    for row in host.runtime.store.list_routers(limit=200):
        if row["display_name"] == "__catalog__":
            return str(row["router_id"])
    return host.runtime.store.enroll_router(
        site_id=site_id,
        display_name="__catalog__",
        vendor="Catalog",
        model="None",
        identity_fingerprint="digest:catalog",
        host="127.0.0.1",
        now=host.runtime.clock.now(),
    )


@router.get("/routers/{router_id}/desired-revision")
def get_desired(router_id: str, request: Request) -> JSONResponse:
    host = _state(request)
    rev = host.runtime.store.get_desired_revision(router_id)
    if rev is None:
        return error_response(
            request, status_code=404, code="resource.not_found", message="no desired revision"
        )
    etag = etag_for_revision(rev["revision_id"], rev["canonical_digest"])
    return JSONResponse(
        {
            "revision_id": rev["revision_id"],
            "router_id": rev["router_id"],
            "revision_number": rev["revision_number"],
            "canonical_digest": rev["canonical_digest"],
            "etag": etag,
            "based_on_observation_id": rev["based_on_observation_id"],
            "assignments": [],
            "created_at": rev["created_at"],
            "desired_document": json.loads(rev["desired_document_json"] or "{}"),
        },
        headers=_ok_headers(request, {"ETag": etag}),
    )


@router.put("/routers/{router_id}/desired-revision")
async def put_desired(
    router_id: str,
    request: Request,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    if_match: str | None = Header(default=None, alias="If-Match"),
) -> JSONResponse:
    host = _state(request)
    if not idempotency_key or not idempotency_key.strip():
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="Idempotency-Key required",
        )
    degraded = _mutation_degraded(host, request)
    if degraded is not None:
        return degraded
    if if_match is None:
        return error_response(
            request,
            status_code=428,
            code="precondition.required",
            message="If-Match required",
        )
    body = await request.json()
    try:
        rev_id, etag, number = host.runtime.store.put_desired_revision(
            router_id=router_id,
            canonical_digest=_digest(body),
            based_on_observation_id=body["based_on_observation_id"],
            if_match=if_match,
            desired_document_json=json.dumps({"assignments": body.get("assignments", [])}),
            actor_id="hub_admin",
            reason=body.get("reason"),
            now=host.runtime.clock.now(),
        )
    except PreconditionFailed as exc:
        return error_response(
            request,
            status_code=412,
            code="revision.precondition_failed",
            message=str(exc),
        )
    host.runtime.store.create_operation_bundle(
        router_id=router_id,
        operation_kind="put_desired_revision",
        idempotency_key=idempotency_key.strip(),
        request_digest=_digest(body),
        actor_id="hub_admin",
        initial_job_status="Succeeded",
        http_status=200,
        now=host.runtime.clock.now(),
    )
    return JSONResponse(
        {
            "revision_id": rev_id,
            "router_id": router_id,
            "revision_number": number,
            "canonical_digest": _digest(body),
            "etag": etag,
            "based_on_observation_id": body["based_on_observation_id"],
            "assignments": body.get("assignments", []),
            "created_at": host.runtime.clock.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "desired_document": {"assignments": body.get("assignments", [])},
        },
        headers=_ok_headers(request, {"ETag": etag}),
    )


@router.post(
    "/routers/{router_id}/plans",
    responses={
        201: {"description": "Created"},
        422: {"description": "Validation Error"},
    },
)
async def create_plan(
    router_id: str,
    request: Request,
    body: CreatePlanBody,
    idempotency_key: IdempotencyKeyHeader,
    if_match: IfMatchHeader,
) -> JSONResponse:
    host = _state(request)
    if not idempotency_key or not idempotency_key.strip():
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="Idempotency-Key required",
        )
    degraded = _mutation_degraded(host, request)
    if degraded is not None:
        return degraded
    cookie = request.cookies.get(HUB_ADMIN_COOKIE_NAME)
    session_hmac = session_binding_from_cookie(cookie)
    deployment_revision_id = body.deployment_revision_id
    body_dict = body.model_dump()
    if deployment_revision_id:
        if session_hmac is None:
            return error_response(
                request,
                status_code=403,
                code="session_binding_mismatch",
                message="Valid session required for P2 plan",
            )
        try:
            dep = host.runtime.store.get_deployment_revision(str(deployment_revision_id))
            if dep is None:
                raise NotFoundError("deployment not found")
            planner = host.deployment_service()
            doc, _status = planner.document_from_published(str(dep["published_preset_id"]))
            topology = planner.build_topology_binding(doc)
            items = planner.compile_typed_plan_items(doc, topology=topology)
            families = json.loads(str(dep["required_families_json"]))
            cert_snapshots = host.runtime.store.build_family_cert_snapshots(
                router_id, families
            )
            for item in items:
                family = item["intent_kind"]
                snap = next((s for s in cert_snapshots if s["family"] == family), None)
                if snap is not None:
                    item["family_cert_snapshot_json"] = snap
            expires_at = (
                host.runtime.clock.now() + timedelta(seconds=3600)
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
            desired_row = host.runtime.store.get_desired_revision(router_id)
            assert desired_row is not None  # create_p2_plan validates desired state exists
            observation_row = host.runtime.store.get_observation(body.observation_id)
            assert observation_row is not None  # create_p2_plan validates observation_id
            digest_payload = planner.build_change_plan_digest_payload(
                router_id=router_id,
                deployment_revision_id=str(deployment_revision_id),
                deployment_digest=str(dep["canonical_desired_digest"]),
                desired_revision_id=body.revision_id,
                desired_digest=str(desired_row["canonical_digest"]),
                observation_id=body.observation_id,
                observation_state_digest=str(observation_row["state_digest"]),
                observation_resource_version=str(observation_row["resource_version"]),
                execution_target=str(dep["execution_target"]),
                family_cert_snapshots=cert_snapshots,
                items=items,
                risk_class="Medium",
                requires_backup=True,
                requires_fail_safe=True,
                expires_at=expires_at,
                adopt_acknowledged=body.adopt_acknowledged,
            )
            plan_digest = planner.compute_change_plan_digest(digest_payload)
            plan_id, etag = host.runtime.store.create_p2_plan(
                router_id=router_id,
                revision_id=body.revision_id,
                observation_id=body.observation_id,
                deployment_revision_id=str(deployment_revision_id),
                session_binding_hmac=session_hmac,
                plan_digest=plan_digest,
                items=items,
                if_match=if_match,
                actor_id="hub_admin",
                now=host.runtime.clock.now(),
            )
        except PreconditionFailed as exc:
            return _p2_stale_response(request, exc)
        except ConflictError as exc:
            msg = str(exc)
            if any(
                token in msg
                for token in (
                    "digest_mismatch",
                    "stale_credential",
                    "stale_certification",
                    "tuple_mismatch",
                )
            ):
                return _p2_stale_response(request, exc)
            return error_response(
                request, status_code=409, code="plan.stale", message=str(exc)
            )
        except NotFoundError as exc:
            return error_response(
                request, status_code=404, code="resource.not_found", message=str(exc)
            )
        plan = host.runtime.store.get_plan(plan_id)
        assert plan is not None
        host.runtime.store.create_operation_bundle(
            router_id=router_id,
            operation_kind="create_plan",
            idempotency_key=idempotency_key.strip(),
            request_digest=_digest(body_dict),
            plan_id=plan_id,
            actor_id="hub_admin",
            initial_job_status="Succeeded",
            http_status=201,
            now=host.runtime.clock.now(),
        )
        return JSONResponse(
            {
                "plan_id": plan_id,
                "router_id": router_id,
                "revision_id": plan["revision_id"],
                "observation_id": plan["observation_id"],
                "plan_digest": plan["plan_digest"],
                "plan_version": int(plan["plan_version"]),
                "confirmation_state": plan["confirmation_state"],
                "expires_at": plan["expires_at"],
                "deployment_revision_id": plan["deployment_revision_id"],
                "etag": etag,
            },
            status_code=201,
            headers=_ok_headers(request, {"ETag": etag}),
        )
    try:
        plan_id, etag = host.runtime.store.create_plan(
            router_id=router_id,
            revision_id=body.revision_id,
            observation_id=body.observation_id,
            if_match=if_match,
            actor_id="hub_admin",
            now=host.runtime.clock.now(),
        )
    except PreconditionFailed as exc:
        return error_response(
            request,
            status_code=412,
            code="plan.precondition_failed",
            message=str(exc),
        )
    except (ConflictError, NotFoundError) as exc:
        return error_response(
            request, status_code=409, code="plan.stale", message=str(exc)
        )
    plan = host.runtime.store.get_plan(plan_id)
    assert plan is not None
    host.runtime.store.create_operation_bundle(
        router_id=router_id,
        operation_kind="create_plan",
        idempotency_key=idempotency_key.strip(),
        request_digest=_digest(body_dict),
        plan_id=plan_id,
        actor_id="hub_admin",
        initial_job_status="Succeeded",
        http_status=201,
        now=host.runtime.clock.now(),
    )
    return JSONResponse(
        {
            "plan_id": plan_id,
            "router_id": router_id,
            "revision_id": plan["revision_id"],
            "observation_id": plan["observation_id"],
            "plan_digest": plan["plan_digest"],
            "confirmation_state": plan["confirmation_state"],
            "expires_at": plan["expires_at"],
            "risk_class": plan["risk_class"],
            "requires_backup": bool(plan["requires_backup"]),
            "requires_fail_safe": bool(plan["requires_fail_safe"]),
            "changes": [{"ordinal": 0, "change_kind": "ensure-assignment", "summary": "offline"}],
            "etag": etag,
        },
        status_code=201,
        headers=_ok_headers(request, {"ETag": etag}),
    )


def _redacted_plan_changes(store: Any, plan_id: str) -> list[dict[str, Any]]:
    """Redacted plan item summaries — intent_kind/ownership_action only; never intent_json."""
    changes: list[dict[str, Any]] = []
    for row in store.list_plan_items(plan_id):
        kind = str(row["intent_kind"] or row["change_kind"] or "unknown")
        action = str(row["ownership_action"] or "").strip()
        summary = f"{kind} ({action.lower()})" if action else kind
        entry: dict[str, Any] = {
            "ordinal": int(row["ordinal"]),
            "change_kind": kind,
            "summary": summary,
        }
        target = row["target_resource_id"]
        if target:
            entry["target_resource_id"] = str(target)
        changes.append(entry)
    return changes


@router.get("/routers/{router_id}/plans/{plan_id}")
def get_plan(router_id: str, plan_id: str, request: Request) -> JSONResponse:
    host = _state(request)
    plan = host.runtime.store.get_plan(plan_id)
    if plan is None or plan["router_id"] != router_id:
        return error_response(
            request, status_code=404, code="resource.not_found", message="plan not found"
        )
    etag = (
        etag_for_plan_version(plan_id, int(plan["plan_version"]))
        if plan["session_binding_hmac"]
        else etag_for_plan(plan_id, plan["plan_digest"])
    )
    return JSONResponse(
        {
            "plan_id": plan_id,
            "router_id": router_id,
            "revision_id": plan["revision_id"],
            "observation_id": plan["observation_id"],
            "plan_digest": plan["plan_digest"],
            "plan_version": int(plan["plan_version"] or 1),
            "confirmation_state": plan["confirmation_state"],
            "expires_at": plan["expires_at"],
            "risk_class": plan["risk_class"],
            "requires_backup": bool(plan["requires_backup"]),
            "requires_fail_safe": bool(plan["requires_fail_safe"]),
            "changes": _redacted_plan_changes(host.runtime.store, plan_id),
            "etag": etag,
            "confirmed_at": plan["confirmed_at"],
        },
        headers=_ok_headers(request, {"ETag": etag}),
    )


@router.post("/routers/{router_id}/plans/{plan_id}/confirm")
async def confirm_plan(
    router_id: str,
    plan_id: str,
    request: Request,
    body: ConfirmPlanBody,
    idempotency_key: IdempotencyKeyHeader,
    if_match: IfMatchHeader,
) -> JSONResponse:
    host = _state(request)
    if not idempotency_key or not idempotency_key.strip():
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="Idempotency-Key required",
        )
    degraded = _mutation_degraded(host, request)
    if degraded is not None:
        return degraded
    plan_row = host.runtime.store.get_plan(plan_id)
    if plan_row is None or plan_row["router_id"] != router_id:
        return error_response(
            request, status_code=404, code="resource.not_found", message="plan not found"
        )
    if not plan_row["session_binding_hmac"]:
        return error_response(
            request,
            status_code=412,
            code="plan.unbound_requires_recompile",
            message="unbound_plan_requires_recompile",
        )
    cookie = request.cookies.get(HUB_ADMIN_COOKIE_NAME)
    session_hmac = session_binding_from_cookie(cookie)
    if session_hmac is None or not hmac.compare_digest(
        session_hmac, str(plan_row["session_binding_hmac"])
    ):
        return error_response(
            request,
            status_code=403,
            code="session_binding_mismatch",
            message="plan session binding mismatch",
        )
    try:
        plan = host.runtime.store.confirm_p2_plan(
            plan_id=plan_id,
            plan_digest=body.plan_digest,
            if_match=if_match,
            session_binding_hmac=session_hmac,
            adopt_acknowledged=body.adopt_acknowledged,
            actor_id="hub_admin",
            now=host.runtime.clock.now(),
        )
    except PreconditionFailed as exc:
        return _p2_stale_response(request, exc)
    except ConflictError as exc:
        msg = str(exc)
        if "session_binding" in msg:
            return error_response(
                request,
                status_code=403,
                code="session_binding_mismatch",
                message=msg,
            )
        if "adopt" in msg:
            return error_response(
                request,
                status_code=422,
                code="adopt_acknowledgment_required",
                message=msg,
            )
        if any(
            token in msg
            for token in (
                "digest_mismatch",
                "stale_credential",
                "stale_certification",
                "tuple_mismatch",
            )
        ):
            return _p2_stale_response(request, exc)
        code = "plan.expired" if "expired" in msg else "plan.stale"
        return error_response(request, status_code=409, code=code, message=msg)
    etag = etag_for_plan_version(plan_id, int(plan["plan_version"]))
    host.runtime.store.create_operation_bundle(
        router_id=router_id,
        operation_kind="confirm_plan",
        idempotency_key=idempotency_key.strip(),
        request_digest=_digest(body.model_dump()),
        plan_id=plan_id,
        actor_id="hub_admin",
        initial_job_status="Succeeded",
        http_status=200,
        now=host.runtime.clock.now(),
    )
    return JSONResponse(
        {
            "plan_id": plan_id,
            "router_id": router_id,
            "confirmation_state": plan["confirmation_state"],
            "confirmed_at": plan["confirmed_at"],
            "plan_digest": plan["plan_digest"],
            "plan_version": int(plan["plan_version"]),
            "etag": etag,
        },
        headers=_ok_headers(request, {"ETag": etag}),
    )


@router.post(
    "/routers/{router_id}/plans/{plan_id}/apply",
    responses={202: {"description": "Accepted"}},
)
async def apply_plan(
    router_id: str,
    plan_id: str,
    request: Request,
    idempotency_key: IdempotencyKeyHeader,
    if_match: IfMatchHeader,
) -> JSONResponse:
    """Apply MUST fail closed unless RC_ALLOW_FAKE_MUTATIONS=1 (simulation only)."""
    host = _state(request)
    if not idempotency_key or not idempotency_key.strip():
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="Idempotency-Key required",
        )
    degraded = _mutation_degraded(host, request)
    if degraded is not None:
        return degraded
    live_mut = _live_mutation_forbidden(host, request)
    if live_mut is not None:
        return live_mut
    allow_fake = host.adapter_mode == "fake" and (
        host.allow_fake_mutations or os.environ.get("RC_ALLOW_FAKE_MUTATIONS") == "1"
    )
    if not allow_fake:
        return error_response(
            request,
            status_code=403,
            code="gate.mutation_forbidden",
            message="Hardware mutation gates closed; apply fail-closed",
        )
    # Fake simulation path only — still no live router
    plan = host.runtime.store.get_plan(plan_id)
    if plan is None or plan["confirmation_state"] != "Confirmed":
        return error_response(
            request,
            status_code=409,
            code="plan.stale",
            message="plan not confirmed",
        )
    if not plan["session_binding_hmac"]:
        return error_response(
            request,
            status_code=412,
            code="plan.unbound_requires_recompile",
            message="unbound_plan_requires_recompile",
        )
    cookie = request.cookies.get(HUB_ADMIN_COOKIE_NAME)
    session_hmac = session_binding_from_cookie(cookie)
    if session_hmac is None or not hmac.compare_digest(
        session_hmac, str(plan["session_binding_hmac"])
    ):
        return error_response(
            request,
            status_code=403,
            code="session_binding_mismatch",
            message="plan session binding mismatch",
        )
    try:
        host.runtime.store.assert_p2_plan_fresh(plan_id, now=host.runtime.clock.now())
    except PreconditionFailed as exc:
        return _p2_stale_response(request, exc)
    except ConflictError as exc:
        return _p2_stale_response(request, exc)
    expected = etag_for_plan_version(plan_id, int(plan["plan_version"]))
    if if_match.strip() != expected:
        return error_response(
            request,
            status_code=412,
            code="plan.precondition_failed",
            message="If-Match plan ETag mismatch",
        )
    outcome = host.runtime.store.create_operation_bundle(
        router_id=router_id,
        operation_kind="apply_plan",
        idempotency_key=idempotency_key.strip(),
        request_digest=_digest({"plan_id": plan_id}),
        plan_id=plan_id,
        actor_id="hub_admin",
        initial_job_status="Queued",
        dispatch_payload={"plan_id": plan_id, "confirmed": True},
        now=host.runtime.clock.now(),
    )
    return JSONResponse(
        {
            "operation_id": outcome.operation_id,
            "job_id": outcome.job_id,
            "status": "Queued",
            "links": {
                "operation": f"{API_PREFIX}/operations/{outcome.operation_id}",
                "job": f"{API_PREFIX}/jobs/{outcome.job_id}",
            },
        },
        status_code=202,
        headers=_ok_headers(
            request,
            {"Location": f"{API_PREFIX}/operations/{outcome.operation_id}"},
        ),
    )


@router.get("/operations/{operation_id}")
def get_operation(operation_id: str, request: Request) -> JSONResponse:
    host = _state(request)
    op = host.runtime.store.get_operation(operation_id)
    if op is None:
        return error_response(
            request, status_code=404, code="resource.not_found", message="operation not found"
        )
    return JSONResponse(
        {
            "operation_id": op["operation_id"],
            "router_id": op["router_id"],
            "operation_kind": op["operation_kind"],
            "aggregate_status": op["aggregate_status"],
            "plan_id": op["plan_id"],
            "created_at": op["created_at"],
            "updated_at": op["updated_at"],
            "terminal_at": op["terminal_at"],
            "recovery_required": op["aggregate_status"] == "RecoveryRequired",
            "jobs": f"{API_PREFIX}/operations/{operation_id}/jobs",
        },
        headers=_ok_headers(request),
    )


@router.get("/operations/{operation_id}/jobs")
def list_operation_jobs(operation_id: str, request: Request) -> JSONResponse:
    host = _state(request)
    items = [
        {
            "job_id": j["job_id"],
            "attempt": j["attempt"],
            "status": j["status"],
            "recovery_state": j["recovery_state"],
            "cancel_requested": bool(j["cancel_requested"]),
        }
        for j in host.runtime.store.list_jobs_for_operation(operation_id)
    ]
    return JSONResponse({"items": items}, headers=_ok_headers(request))


@router.get("/jobs/{job_id}")
def get_job(job_id: str, request: Request) -> JSONResponse:
    host = _state(request)
    job = host.runtime.store.get_job(job_id)
    if job is None:
        return error_response(
            request, status_code=404, code="resource.not_found", message="job not found"
        )
    steps = [
        {
            "step_id": s["step_id"],
            "ordinal": s["ordinal"],
            "step_kind": s["step_kind"],
            "status": s["status"],
            "error_redacted": s["error_redacted"],
            "checkpoint_redacted": bool(s["checkpoint_json"]),
        }
        for s in host.runtime.store.list_job_steps(job_id)
    ]
    op = host.runtime.store.get_operation(str(job["operation_id"]))
    return JSONResponse(
        {
            "job_id": job["job_id"],
            "operation_id": job["operation_id"],
            "router_id": job["router_id"],
            "attempt": job["attempt"],
            "status": job["status"],
            "recovery_state": job["recovery_state"],
            "aggregate_status": op["aggregate_status"] if op else None,
            "cancel_requested": bool(job["cancel_requested"]),
            "steps": steps,
            "started_at": job["started_at"],
            "finished_at": job["finished_at"],
            "recovery_actions": {
                "resume": f"{API_PREFIX}/jobs/{job_id}/resume",
                "compensate": f"{API_PREFIX}/jobs/{job_id}/compensate",
            }
            if job["status"] == "RecoveryRequired"
            else None,
        },
        headers=_ok_headers(request),
    )


@router.post("/jobs/{job_id}/resume")
async def resume_job(
    job_id: str,
    request: Request,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> JSONResponse:
    host = _state(request)
    if not idempotency_key or not idempotency_key.strip():
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="Idempotency-Key required",
        )
    live_mut = _live_mutation_forbidden(host, request)
    if live_mut is not None:
        return live_mut
    if not (
        host.adapter_mode == "fake"
        and (host.allow_fake_mutations or os.environ.get("RC_ALLOW_FAKE_MUTATIONS") == "1")
    ):
        return error_response(
            request,
            status_code=403,
            code="gate.mutation_forbidden",
            message="Recovery resume forbidden outside fake mode",
        )
    try:
        http_status, body = host.runtime.store.resume_recovery_job(
            target_job_id=job_id,
            action="resume",
            idempotency_key=idempotency_key.strip(),
            request_digest=_digest({"job_id": job_id, "action": "resume"}),
            actor_id="hub_admin",
            now=host.runtime.clock.now(),
        )
    except NotFoundError:
        return error_response(
            request, status_code=404, code="resource.not_found", message="job not found"
        )
    except ConflictError as exc:
        return error_response(
            request,
            status_code=409,
            code="job.recovery_not_allowed",
            message=str(exc),
        )
    except IdempotencyConflict as exc:
        return error_response(
            request,
            status_code=409,
            code="idempotency.conflict",
            message=str(exc),
        )
    return JSONResponse(body, status_code=http_status, headers=_ok_headers(request))


@router.post("/jobs/{job_id}/compensate")
async def compensate_job(
    job_id: str,
    request: Request,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> JSONResponse:
    host = _state(request)
    if not idempotency_key or not idempotency_key.strip():
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="Idempotency-Key required",
        )
    live_mut = _live_mutation_forbidden(host, request)
    if live_mut is not None:
        return live_mut
    if not (
        host.adapter_mode == "fake"
        and (host.allow_fake_mutations or os.environ.get("RC_ALLOW_FAKE_MUTATIONS") == "1")
    ):
        return error_response(
            request,
            status_code=403,
            code="gate.mutation_forbidden",
            message="Recovery compensate forbidden outside fake mode",
        )
    try:
        http_status, body = host.runtime.store.resume_recovery_job(
            target_job_id=job_id,
            action="compensate",
            idempotency_key=idempotency_key.strip(),
            request_digest=_digest({"job_id": job_id, "action": "compensate"}),
            actor_id="hub_admin",
            now=host.runtime.clock.now(),
        )
    except NotFoundError:
        return error_response(
            request, status_code=404, code="resource.not_found", message="job not found"
        )
    except ConflictError as exc:
        return error_response(
            request,
            status_code=409,
            code="job.recovery_not_allowed",
            message=str(exc),
        )
    except IdempotencyConflict as exc:
        return error_response(
            request,
            status_code=409,
            code="idempotency.conflict",
            message=str(exc),
        )
    return JSONResponse(body, status_code=http_status, headers=_ok_headers(request))


@router.get("/jobs/{job_id}/backup-artifact")
def get_job_backup_artifact(job_id: str, request: Request) -> JSONResponse:
    host = _state(request)
    job = host.runtime.store.get_job(job_id)
    if job is None:
        return error_response(
            request, status_code=404, code="resource.not_found", message="job not found"
        )
    artifact_id: str | None = None
    for step in reversed(host.runtime.store.list_job_steps(job_id)):
        cp = step["checkpoint_json"]
        if not cp:
            continue
        try:
            data = json.loads(str(cp))
            artifact_id = str(data.get("backup_artifact_id") or "") or None
            if artifact_id:
                break
        except json.JSONDecodeError:
            continue
    if not artifact_id:
        return error_response(
            request,
            status_code=404,
            code="resource.not_found",
            message="no backup artifact for job",
        )
    redacted = host.runtime.store.get_backup_artifact_redacted(artifact_id)
    if redacted is None:
        return error_response(
            request,
            status_code=404,
            code="resource.not_found",
            message="backup artifact not found",
        )
    return JSONResponse(redacted, headers=_ok_headers(request))


@router.post("/jobs/{job_id}/cancel")
async def cancel_job(
    job_id: str,
    request: Request,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> JSONResponse:
    host = _state(request)
    if not idempotency_key or not idempotency_key.strip():
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="Idempotency-Key required",
        )
    degraded = _mutation_degraded(host, request)
    if degraded is not None:
        return degraded
    try:
        http_status, body, _outcome = host.runtime.store.cancel_job(
            target_job_id=job_id,
            idempotency_key=idempotency_key.strip(),
            request_digest=_digest({"job_id": job_id}),
            actor_id="hub_admin",
            now=host.runtime.clock.now(),
        )
    except NotFoundError:
        return error_response(
            request, status_code=404, code="resource.not_found", message="job not found"
        )
    except ConflictError as exc:
        return error_response(
            request,
            status_code=409,
            code="job.already_terminal",
            message=str(exc),
        )
    except IdempotencyConflict as exc:
        return error_response(
            request,
            status_code=409,
            code="idempotency.conflict",
            message=str(exc),
        )
    return JSONResponse(body, status_code=http_status, headers=_ok_headers(request))


@router.post(
    "/routers/{router_id}/deployment-revisions",
    responses={
        201: {"description": "Created"},
        200: {"description": "Idempotent replay"},
    },
)
async def create_deployment_revision(
    router_id: str,
    request: Request,
    body: CreateDeploymentRevisionBody,
    idempotency_key: IdempotencyKeyHeader,
) -> JSONResponse:
    host = _state(request)
    key = _require_idempotency(idempotency_key)
    if key == "missing":
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="Idempotency-Key required",
        )
    cookie = request.cookies.get(HUB_ADMIN_COOKIE_NAME)
    session_hmac = session_binding_from_cookie(cookie)
    if session_hmac is None:
        return error_response(
            request,
            status_code=403,
            code="session_binding_mismatch",
            message="Valid session required",
        )
    planner = host.deployment_service()
    published_preset_id = body.published_preset_id
    execution_target = body.execution_target
    try:
        doc, status = planner.document_from_published(published_preset_id)
        if status.value != "ValidOffline":
            return error_response(
                request,
                status_code=422,
                code="publication.not_valid_offline",
                message="published revision not ValidOffline",
            )
        topology = planner.build_topology_binding(doc)
        desired_doc, desired_digest = planner.build_canonical_desired(
            document=doc,
            topology=topology,
            published_preset_id=published_preset_id,
            deployment_revision_id="pending",
        )
        router_row = host.runtime.store.get_router(router_id)
        if router_row is None:
            return error_response(
                request, status_code=404, code="resource.not_found", message="router not found"
            )
        pub = host.runtime.store.get_published_preset(published_preset_id)
        assert pub is not None
        row, created = host.runtime.store.create_deployment_revision_idempotent(
            published_preset_id=published_preset_id,
            router_id=router_id,
            site_id=str(router_row["site_id"]),
            execution_target=execution_target,
            identity_tuple_json=json.dumps({"fingerprint": router_row["identity_fingerprint"]}),
            evidence_digest="sha256:fake-evidence",
            required_families_json=json.dumps(list(DEFAULT_REQUIRED_FAMILIES)),
            credential_ref_versions_json=json.dumps([]),
            topology_bindings_json=json.dumps(topology.to_canonical()),
            canonical_desired_json=json.dumps(desired_doc, sort_keys=True, separators=(",", ":")),
            canonical_desired_digest=desired_digest,
            actor_session_binding_hmac=session_hmac,
            idempotency_key=key,
            request_digest=_digest(body.model_dump()),
            now=host.runtime.clock.now(),
        )
    except NotFoundError:
        return error_response(
            request, status_code=404, code="resource.not_found", message="resource not found"
        )
    except ConflictError as exc:
        return error_response(
            request, status_code=409, code="resource.conflict", message=str(exc)
        )
    status_code = 201 if created else 200
    return JSONResponse(
        {
            "deployment_revision_id": row["deployment_revision_id"],
            "router_id": router_id,
            "published_preset_id": published_preset_id,
            "execution_target": row["execution_target"],
            "canonical_desired_digest": row["canonical_desired_digest"],
        },
        status_code=status_code,
        headers=_ok_headers(request),
    )


@router.get("/routers/{router_id}/deployment-revisions/{deployment_revision_id}")
def get_deployment_revision(
    router_id: str, deployment_revision_id: str, request: Request
) -> JSONResponse:
    host = _state(request)
    row = host.runtime.store.get_deployment_revision(deployment_revision_id)
    if row is None or str(row["router_id"]) != router_id:
        return error_response(
            request, status_code=404, code="resource.not_found", message="deployment not found"
        )
    return JSONResponse(
        {
            "deployment_revision_id": row["deployment_revision_id"],
            "router_id": router_id,
            "published_preset_id": row["published_preset_id"],
            "execution_target": row["execution_target"],
            "canonical_desired_digest": row["canonical_desired_digest"],
        },
        headers=_ok_headers(request),
    )


@router.get("/routers/{router_id}/deployment-revisions/{deployment_revision_id}/readiness")
def deployment_readiness(
    router_id: str, deployment_revision_id: str, request: Request
) -> JSONResponse:
    host = _state(request)
    from router_control.domain.enums import ExecutionTarget

    row = host.runtime.store.get_deployment_revision(deployment_revision_id)
    if row is None or str(row["router_id"]) != router_id:
        return error_response(
            request, status_code=404, code="resource.not_found", message="deployment not found"
        )
    report = host.deployment_service().deployment_readiness(
        router_id=router_id,
        deployment_revision_id=deployment_revision_id,
        execution_target=ExecutionTarget(str(row["execution_target"])),
    )
    return JSONResponse(report, headers=_ok_headers(request))


@router.post(
    "/routers/{router_id}/desired-revisions",
    responses={
        201: {"description": "Created"},
        200: {"description": "Idempotent replay"},
    },
)
async def create_desired_revision_from_deployment(
    router_id: str,
    request: Request,
    body: CreateDesiredRevisionBody,
    idempotency_key: IdempotencyKeyHeader,
) -> JSONResponse:
    host = _state(request)
    key = _require_idempotency(idempotency_key)
    if key == "missing":
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="Idempotency-Key required",
        )
    deployment_revision_id = body.deployment_revision_id
    observation_id = body.observation_id
    try:
        rev_id, etag, created = host.runtime.store.create_desired_from_deployment(
            router_id=router_id,
            deployment_revision_id=str(deployment_revision_id),
            based_on_observation_id=str(observation_id),
            idempotency_key=key,
            request_digest=_digest(body.model_dump()),
            actor_id="hub_admin",
            now=host.runtime.clock.now(),
        )
    except (NotFoundError, PreconditionFailed) as exc:
        status = 404 if isinstance(exc, NotFoundError) else 412
        return error_response(
            request, status_code=status, code="resource.not_found", message=str(exc)
        )
    except ConflictError as exc:
        return error_response(
            request, status_code=409, code="resource.conflict", message=str(exc)
        )
    return JSONResponse(
        {"revision_id": rev_id, "etag": etag},
        status_code=201 if created else 200,
        headers=_ok_headers(request, {"ETag": etag}),
    )


@router.get("/routers/{router_id}/revision-state")
def get_revision_state(router_id: str, request: Request) -> JSONResponse:
    host = _state(request)
    state = host.runtime.store.get_revision_state(router_id)
    if state is None:
        return error_response(
            request, status_code=404, code="resource.not_found", message="router not found"
        )
    return JSONResponse(state, headers=_ok_headers(request))


@router.get("/routers/{router_id}/family-certifications/status")
def family_cert_status(router_id: str, request: Request) -> JSONResponse:
    host = _state(request)
    rows = host.runtime.store.list_active_family_certifications(router_id)
    return JSONResponse(
        {
            "router_id": router_id,
            "items": [
                {
                    "certification_id": r["certification_id"],
                    "family": r["family"],
                    "certification_level": r["certification_level"],
                    "valid_until": r["valid_until"],
                }
                for r in rows
            ],
        },
        headers=_ok_headers(request),
    )


@router.post("/routers/{router_id}/family-certifications")
async def create_family_certification(router_id: str, request: Request) -> JSONResponse:
    host = _state(request)
    body = await request.json()
    now = host.runtime.clock.now()
    valid_until = (now + __import__("datetime").timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    cert_id = host.runtime.store.upsert_family_certification(
        router_id=router_id,
        family=str(body["family"]),
        identity_tuple_digest=str(body.get("identity_tuple_digest", "sha256:tuple")),
        shape_digest=str(body.get("shape_digest", "sha256:shape")),
        codec_digest=str(body.get("codec_digest", "sha256:codec")),
        executor_digest=str(body.get("executor_digest", "sha256:executor")),
        evidence_digest=str(body.get("evidence_digest", "sha256:evidence")),
        certification_level=str(body.get("certification_level", "LabProven")),
        valid_from=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        valid_until=valid_until,
        now=now,
    )
    return JSONResponse(
        {"certification_id": cert_id},
        status_code=201,
        headers=_ok_headers(request),
    )


@router.get("/routers/{router_id}/plans/{plan_id}/verification")
def get_plan_verification(router_id: str, plan_id: str, request: Request) -> JSONResponse:
    host = _state(request)
    plan = host.runtime.store.get_plan(plan_id)
    if plan is None or plan["router_id"] != router_id:
        return error_response(
            request, status_code=404, code="resource.not_found", message="plan not found"
        )
    jobs = host.runtime.store.list_jobs_for_plan(plan_id)
    if not jobs:
        return error_response(
            request, status_code=404, code="resource.not_found", message="verification not found"
        )
    report = host.runtime.store.get_plan_verify_report(plan_id, str(jobs[0]["job_id"]))
    if report is None:
        return error_response(
            request, status_code=404, code="resource.not_found", message="verification not found"
        )
    return JSONResponse(
        {
            "plan_id": plan_id,
            "overall_status": report["overall_status"],
            "checks": json.loads(str(report["checks_json"])),
        },
        headers=_ok_headers(request),
    )


@router.get("/routers/{router_id}/managed-resources")
def list_managed_resources(router_id: str, request: Request) -> JSONResponse:
    host = _state(request)
    if host.runtime.store.get_router(router_id) is None:
        return error_response(
            request, status_code=404, code="resource.not_found", message="router not found"
        )
    rows = host.runtime.store.list_managed_resources(router_id)
    items = [
        {
            "resource_id": row["resource_id"],
            "router_id": row["router_id"],
            "resource_kind": row["resource_kind"],
            "logical_key": row["logical_key"],
            "owner": row["owner"],
            "lifecycle_status": row["lifecycle_status"],
            "creating_revision_id": row["creating_revision_id"],
        }
        for row in rows
    ]
    return JSONResponse({"items": items}, headers=_ok_headers(request))


def new_request_id() -> str:
    return f"req_{uuid.uuid4().hex[:16]}"
