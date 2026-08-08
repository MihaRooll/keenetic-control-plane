"""WireGuard/AmneziaWG apply/preview/teardown API routes (confirm-gated; injected transport)."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any, Literal, cast

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from router_control.adapters.netcraze.allowlist import (
    is_wireguard_nested_peer_body,
    validate_wireguard_id,
)
from router_control.adapters.netcraze.sanitize import (
    redact_sealed_cli_command,
    redact_sealed_nested_body,
)
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
from router_control.application.wireguard_apply_planner import clamp_handshake_settle_seconds
from router_control.application.wireguard_apply_service import (
    WireguardApplyResult,
    WireguardApplyServiceError,
    WireguardApplyTransport,
    _interface_readable,
    _readback_show_interface,
    apply_wireguard_intent,
    observe_tunnel,
    preview_wireguard_apply,
    teardown_wireguard,
)
from router_control.domain.network_intents import (
    IntentValidationError,
    WireguardIntent,
    parse_network_intent,
)
from router_control.persistence.errors import SealedApplyTrailBeginError

from router_control_host.apply_response_models import (
    TunnelVerificationStatus,
    VerdictExplanationResponse,
    WireguardApplyResponse,
    WireguardObserveResponse,
    WireguardPreviewResponse,
)
from router_control_host.errors import (
    error_response,
    intent_code_to_reason,
    operator_structured_error_response,
    sealed_apply_trail_begin_error_response,
    synthesize_operator_message,
)
from router_control_host.routes import API_PREFIX, _mutation_degraded, _ok_headers
from router_control_host.state import HostState
from router_control_host.wifi_live_transport import (
    LiveIdentityTupleMismatchError,
    WifiLiveConnectionParams,
    WifiLiveSession,
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
    open_wifi_live_session,
)

_LIVE_FAMILY_PREFIX = "wireguard"

router = APIRouter(prefix=API_PREFIX, tags=["wireguard-apply"])


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class WireguardIntentFields(_StrictModel):
    wg_id: str = Field(min_length=1, max_length=32)
    enabled: bool
    asc_args: list[int] | None = None
    private_key_credential_ref_id: str | None = None
    preshared_key_credential_ref_id: str | None = None
    peer_public_key: str | None = None
    peer_endpoint: str | None = None
    peer_allow_ips: str | None = None
    peer_keepalive_interval: int | None = Field(default=None, ge=3, le=3600)
    peer_rci_shape: Literal["path_style", "nested_rci"] = "nested_rci"
    interface_address: str | None = None
    ip_global_priority: int | None = Field(default=None, ge=0, le=65535)
    ip_global_auto: bool = False
    tcp_mss_pmtu: bool = False


class WireguardLiveConnectionFields(_StrictModel):
    host: str | None = None
    username: str | None = None
    router_credential_ref_id: str | None = None
    ssh_host_key_sha256: str | None = None
    source_address: str | None = None
    router_id: str | None = None


class WireguardPreviewBody(WireguardIntentFields):
    pass


class WireguardApplyBody(WireguardIntentFields, WireguardLiveConnectionFields):
    confirm_live_apply: bool = False
    handshake_settle_seconds: float = Field(
        default=0,
        ge=0,
        description=(
            "Optional bounded handshake settle wait before one tunnel recheck; "
            "0 = no wait; values >0 clamp to 20–30 seconds"
        ),
    )


class WireguardTeardownBody(WireguardIntentFields, WireguardLiveConnectionFields):
    confirm_live_teardown: bool = False
    confirm_live_apply: bool = False


class WireguardObserveBody(WireguardLiveConnectionFields):
    wg_id: str = Field(min_length=1, max_length=32)
    peer_public_key: str | None = None


class _DefaultFakeWireguardTransport:
    """Offline fake transport with canned acks and stateful readback."""

    def __init__(self) -> None:
        self.write_commands: list[str] = []
        self.nested_write_bodies: list[dict[str, Any]] = []
        self.parse_commands: list[str] = []
        self._wg_id: str | None = None
        self._exists = False
        self._up = False
        self._applied_readback: dict[str, Any] = {"interface": {}}

    def _sync_readback(self) -> None:
        if not self._exists or self._wg_id is None:
            self._applied_readback = {"interface": {}}
            return
        state = "up" if self._up else "down"
        self._applied_readback = {
            "interface": {
                "id": self._wg_id,
                "state": state,
                "up": self._up,
                "type": "Wireguard",
            }
        }

    def _apply_command_side_effect(self, command: str) -> None:
        if command.startswith("no interface "):
            removed_id = command.removeprefix("no interface ").strip()
            if self._wg_id == removed_id:
                self._wg_id = None
                self._exists = False
                self._up = False
            self._sync_readback()
            return
        if command.endswith(" up"):
            wg_id = command.removesuffix(" up").removeprefix("interface ").strip()
            self._wg_id = wg_id
            self._exists = True
            self._up = True
            self._sync_readback()
            return
        if command.endswith(" down"):
            wg_id = command.removesuffix(" down").removeprefix("interface ").strip()
            self._wg_id = wg_id
            self._exists = True
            self._up = False
            self._sync_readback()
            return
        if " wireguard private-key " in command:
            prefix = command.split(" wireguard private-key ", 1)[0]
            wg_id = prefix.removeprefix("interface ").strip()
            self._wg_id = wg_id
            self._exists = True
            self._sync_readback()
            return
        if " wireguard peer " in command and " preshared-key " not in command:
            wg_id = command.split(" wireguard peer ", 1)[0].removeprefix("interface ").strip()
            self._wg_id = wg_id
            self._exists = True
            self._sync_readback()
            return
        if " preshared-key " in command:
            wg_id = command.split(" wireguard peer ", 1)[0].removeprefix("interface ").strip()
            self._wg_id = wg_id
            self._exists = True
            self._sync_readback()
            return
        if " no wireguard private-key" in command:
            self._sync_readback()
            return
        if " no wireguard peer " in command:
            self._sync_readback()
            return
        if " wireguard asc " in command:
            wg_id = command.split(" wireguard asc ", 1)[0].removeprefix("interface ").strip()
            self._wg_id = wg_id
            self._exists = True
            self._sync_readback()
            return
        if (
            command.startswith("interface Wireguard")
            and " wireguard " not in command
            and not command.endswith(" down")
            and not command.endswith(" up")
        ):
            wg_id = command.removeprefix("interface ").strip()
            self._wg_id = wg_id
            self._exists = True
            self._up = False
            self._sync_readback()

    def _apply_nested_peer_side_effect(self, body: dict[str, Any]) -> None:
        interface = body.get("interface")
        if not isinstance(interface, dict) or len(interface) != 1:
            return
        wg_id = next(iter(interface.keys()))
        self._wg_id = str(wg_id)
        self._exists = True
        self._sync_readback()

    def execute_sealed_rci_write(self, request: SealedRciWriteRequest) -> list[dict[str, Any]]:
        body_bytes = request.body
        if is_wireguard_nested_peer_body(body_bytes):
            nested = json.loads(body_bytes.decode("utf-8"))
            self._apply_nested_peer_side_effect(nested)
            self.nested_write_bodies.append(redact_sealed_nested_body(nested))
            return [
                {
                    "parse": {
                        "prompt": "(config)",
                        "status": [
                            {
                                "status": "message",
                                "code": "8979152",
                                "ident": "Core::Interface",
                                "message": "synthetic nested ack",
                            }
                        ],
                    }
                }
            ]
        body = json.loads(body_bytes.decode("utf-8"))
        command = str(body[0]["parse"])
        self._apply_command_side_effect(command)
        self.write_commands.append(redact_sealed_cli_command(command))
        prompt = "(config)"
        if (
            command.startswith("interface Wireguard")
            and " wireguard " not in command
            and not command.endswith(" down")
            and not command.endswith(" up")
            and not command.startswith("no interface")
        ):
            prompt = "(config-if)"
        return [
            {
                "parse": {
                    "prompt": prompt,
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
        return dict(self._applied_readback)


class _EphemeralLiveWireguardTransport:
    """Opens a fresh pinned SSH session for each RCI call (watchdog poll/reapply)."""

    def __init__(
        self,
        *,
        params: WifiLiveConnectionParams,
        vault: Any,
        host: HostState,
        router_id: str | None = None,
    ) -> None:
        self._params = params
        self._vault = vault
        self._host = host
        self._router_id = router_id

    def _ensure_tuple_match(self, session: WifiLiveSession) -> None:
        cert = self._host.gate_a_certification
        if cert is None or not cert.is_open:
            raise LiveIdentityTupleMismatchError(
                "Gate A certification required for live mutation"
            )
        ensure_live_gate_a_tuple_match(
            session,
            cert,
            router_id=self._router_id,
        )

    def execute_sealed_rci_write(self, request: SealedRciWriteRequest) -> list[dict[str, Any]]:
        with open_wifi_live_session(params=self._params, vault=self._vault) as session:
            self._ensure_tuple_match(session)
            return cast(
                list[dict[str, Any]],
                session.transport.execute_sealed_rci_write(request),
            )

    def execute_rci_parse(self, cli_command: str) -> dict[str, Any]:
        with open_wifi_live_session(params=self._params, vault=self._vault) as session:
            self._ensure_tuple_match(session)
            return cast(dict[str, Any], session.transport.execute_rci_parse(cli_command))


def _resolve_vpn_watchdog_connection_params(
    host: HostState,
    router_id: str,
) -> WifiLiveConnectionParams | None:
    cert = host.gate_a_certification
    if cert is None or not cert.is_open:
        return None
    store = host.runtime.store
    row = store.get_router(router_id)
    if row is None:
        return None
    endpoint = store.get_primary_endpoint(router_id)
    if endpoint is None:
        return None
    cred_id = str(row["credential_ref_id"] or "")
    if not cred_id:
        for cref in store.list_credential_refs(router_id):
            if cref["revoked_at"] is None:
                cred_id = str(cref["credential_ref_id"])
                break
    if not cred_id:
        return None
    source_raw = endpoint["source_address"]
    if source_raw is None or not str(source_raw).strip():
        return None
    return connection_params_from_fields(
        host=str(endpoint["host"]),
        username=os.environ.get("RC_NETCRAZE_USERNAME", "admin"),
        router_credential_ref_id=cred_id,
        ssh_host_key_sha256=cert.ssh_host_key_fingerprint_sha256,
        source_address=str(source_raw).strip(),
        router_id=router_id,
        store=store,
    )


def build_vpn_watchdog_transport_factory(
    host: HostState,
) -> Callable[[str], WireguardApplyTransport | None] | None:
    """Resolve per-router transport for env-gated VPN watchdog (fake inject or live store)."""
    if host.wireguard_apply_transport_factory is not None:
        injected = host.wireguard_apply_transport_factory

        def _injected(_router_id: str) -> WireguardApplyTransport:
            return cast(WireguardApplyTransport, injected())

        return _injected

    allow_fake = host.adapter_mode == "fake" and (
        host.allow_fake_mutations or os.environ.get("RC_ALLOW_FAKE_MUTATIONS") == "1"
    )
    if allow_fake:

        def _fake(_router_id: str) -> WireguardApplyTransport:
            return _DefaultFakeWireguardTransport()

        return _fake

    if host.adapter_mode != "live":
        return None

    vault = host.runtime.vault

    def _live(router_id: str) -> WireguardApplyTransport | None:
        cert = host.gate_a_certification
        if cert is None or not cert.is_open:
            return None
        params = _resolve_vpn_watchdog_connection_params(host, router_id)
        if params is None or not is_win32_live_capable():
            return None
        return _EphemeralLiveWireguardTransport(
            params=params,
            vault=vault,
            host=host,
            router_id=router_id,
        )

    return _live


def build_vpn_watchdog_backup_callback_factory(
    host: HostState,
) -> Callable[[str], Callable[[], None] | None] | None:
    """Gate-A-gated startup-config backup closure for env-gated VPN watchdog reapply."""
    if host.wireguard_apply_transport_factory is not None:

        def _injected(_router_id: str) -> Callable[[], None]:
            return lambda: None

        return _injected

    allow_fake = host.adapter_mode == "fake" and (
        host.allow_fake_mutations or os.environ.get("RC_ALLOW_FAKE_MUTATIONS") == "1"
    )
    if allow_fake:

        def _fake(_router_id: str) -> Callable[[], None]:
            return lambda: None

        return _fake

    if host.adapter_mode != "live" or not host.gate_a_open():
        return None

    vault = host.runtime.vault

    def _live(router_id: str) -> Callable[[], None] | None:
        params = _resolve_vpn_watchdog_connection_params(host, router_id)
        if params is None or not is_win32_live_capable():
            return None

        def backup_callback() -> None:
            cert = host.gate_a_certification
            if cert is None or not cert.is_open:
                raise StartupBackupError("Gate A certification required for watchdog backup")
            with open_wifi_live_session(params=params, vault=vault) as session:
                ensure_live_gate_a_tuple_match(session, cert)
                backup_startup_config(tunnel=session.tunnel, certification=cert)

        return backup_callback

    return _live


def _state(request: Request) -> HostState:
    return request.app.state.host  # type: ignore[no-any-return]


def _intent_payload_from_body(body: WireguardIntentFields) -> dict[str, Any]:
    payload: dict[str, Any] = {"wg_id": body.wg_id, "enabled": body.enabled}
    if body.asc_args is not None:
        payload["asc_args"] = body.asc_args
    if body.private_key_credential_ref_id is not None:
        payload["private_key_credential_ref_id"] = body.private_key_credential_ref_id
    if body.preshared_key_credential_ref_id is not None:
        payload["preshared_key_credential_ref_id"] = body.preshared_key_credential_ref_id
    if body.peer_public_key is not None:
        payload["peer_public_key"] = body.peer_public_key
    if body.peer_endpoint is not None:
        payload["peer_endpoint"] = body.peer_endpoint
    if body.peer_allow_ips is not None:
        payload["peer_allow_ips"] = body.peer_allow_ips
    if body.peer_keepalive_interval is not None:
        payload["peer_keepalive_interval"] = body.peer_keepalive_interval
    if body.peer_rci_shape != "nested_rci":
        payload["peer_rci_shape"] = body.peer_rci_shape
    if body.interface_address is not None:
        payload["interface_address"] = body.interface_address
    if body.ip_global_auto:
        payload["ip_global_auto"] = True
    if body.ip_global_priority is not None:
        payload["ip_global_priority"] = body.ip_global_priority
    if body.tcp_mss_pmtu:
        payload["tcp_mss_pmtu"] = True
    return payload


def _wireguard_intent_redacted(body: WireguardIntentFields) -> dict[str, Any]:
    """Audit/trail intent: credential refs and non-secret operational fields only."""
    payload: dict[str, Any] = {"wg_id": body.wg_id, "enabled": body.enabled}
    if body.private_key_credential_ref_id is not None:
        payload["private_key_credential_ref_id"] = body.private_key_credential_ref_id
    if body.preshared_key_credential_ref_id is not None:
        payload["preshared_key_credential_ref_id"] = body.preshared_key_credential_ref_id
    if body.peer_allow_ips is not None:
        payload["peer_allow_ips"] = body.peer_allow_ips
    if body.peer_keepalive_interval is not None:
        payload["peer_keepalive_interval"] = body.peer_keepalive_interval
    if body.peer_rci_shape != "nested_rci":
        payload["peer_rci_shape"] = body.peer_rci_shape
    return payload


def _sealed_apply_trail_params(
    request: Request,
    *,
    route: str,
    verb: str,
    intent_redacted: dict[str, Any],
    router_id: str | None,
) -> SealedApplyTrailParams:
    return SealedApplyTrailParams(
        route=route,
        verb=verb,
        intent_redacted=intent_redacted,
        correlation_id=getattr(request.state, "correlation_id", None),
        router_id=router_id,
    )


def _record_wireguard_sealed_audit(
    host: HostState,
    request: Request,
    *,
    verb: str,
    intent_redacted: dict[str, Any],
    result: WireguardApplyResult | None = None,
    outcome: str | None = None,
    error_message: str | None = None,
    exception_type: str | None = None,
    router_id: str | None = None,
    route: str = "wireguard",
) -> None:
    final_outcome = outcome or (result.overall if result is not None else "unknown")
    result_payload = result.to_dict() if result is not None else None
    from router_control.application.recovery import outcome_snapshot_from_apply_result

    outcome_snapshot = (
        outcome_snapshot_from_apply_result(result) if result is not None else None
    )
    action_route = route if route != "wireguard" else "wireguard"
    host.runtime.store.try_append_sealed_apply_audit(
        action=f"sealed_apply.{action_route}.{verb}",
        outcome=final_outcome,
        route=route,
        verb=verb,
        intent_redacted=intent_redacted,
        router_id=router_id,
        correlation_id=getattr(request.state, "correlation_id", None),
        result_payload=result_payload,
        outcome_snapshot=outcome_snapshot,
        error_message=error_message,
        exception_type=exception_type,
    )


def _credential_resolver(host: HostState) -> Callable[[str], str]:
    if host.wireguard_apply_credential_resolver is not None:
        return host.wireguard_apply_credential_resolver

    vault = host.runtime.vault

    def resolve(ref_id: str) -> str:
        return vault.use(ref_id)

    return resolve


def _intent_from_body(body: WireguardIntentFields) -> WireguardIntent:
    return parse_network_intent("wireguard", _intent_payload_from_body(body))


def _live_params_from_body(
    body: WireguardLiveConnectionFields,
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


def _should_use_live_path(body: WireguardLiveConnectionFields, host: HostState) -> bool:
    return is_win32_live_capable() and _live_params_from_body(body, host) is not None


def _router_apply_lock_key(
    body: WireguardLiveConnectionFields,
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
    body: WireguardLiveConnectionFields,
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


def _wg_validation_error(request: Request, exc: ValueError) -> JSONResponse:
    _ = exc
    return operator_structured_error_response(
        request,
        status_code=422,
        code="wireguard.wg_forbidden",
        reason="not_allowlisted",
        field="wg_id",
    )


def _wireguard_intent_error_code(domain_code: str) -> str:
    if domain_code == "invalid_wg_id":
        return "wireguard.wg_forbidden"
    if domain_code.startswith("wireguard."):
        return domain_code
    return f"wireguard.{domain_code}"


def _intent_validation_error(request: Request, exc: IntentValidationError) -> JSONResponse:
    if exc.code == "invalid_wg_id":
        return _wg_validation_error(request, ValueError(exc.message))
    reason = intent_code_to_reason(exc.code)
    return operator_structured_error_response(
        request,
        status_code=422,
        code=_wireguard_intent_error_code(exc.code),
        reason=reason,
        field=exc.field,
    )


def _service_error(request: Request, exc: WireguardApplyServiceError) -> JSONResponse:
    _ = exc
    return error_response(
        request,
        status_code=422,
        code="wireguard.apply_failed",
        message=synthesize_operator_message(
            code="wireguard.apply_failed",
            reason="wireguard_apply_failed",
        ),
    )


def _wireguard_preview_error(request: Request, exc: BaseException) -> JSONResponse:
    _ = exc
    return error_response(
        request,
        status_code=422,
        code="wireguard.preview_failed",
        message=synthesize_operator_message(
            code="wireguard.preview_failed",
            reason="wireguard_preview_failed",
        ),
    )


def _synthesised_apply_failed_message() -> str:
    return synthesize_operator_message(
        code="wireguard.apply_failed",
        reason="wireguard_apply_failed",
    )


def _synthesised_trail_begin_failed_message() -> str:
    return synthesize_operator_message(
        code="sealed_apply.trail_begin_failed",
        reason="trail_begin_failed",
    )


def _resolve_transport(host: HostState, request: Request) -> JSONResponse | WireguardApplyTransport:
    if host.wireguard_apply_transport_factory is not None:
        return cast(WireguardApplyTransport, host.wireguard_apply_transport_factory())
    allow_fake = host.adapter_mode == "fake" and (
        host.allow_fake_mutations or os.environ.get("RC_ALLOW_FAKE_MUTATIONS") == "1"
    )
    if allow_fake:
        return _DefaultFakeWireguardTransport()
    return error_response(
        request,
        status_code=503,
        code="feature.degraded",
        message="WireGuard apply transport not configured",
    )


def _resolve_observe_transport(
    host: HostState,
    request: Request,
) -> JSONResponse | WireguardApplyTransport:
    if host.wireguard_apply_transport_factory is not None:
        return cast(WireguardApplyTransport, host.wireguard_apply_transport_factory())
    if host.adapter_mode == "fake":
        return _DefaultFakeWireguardTransport()
    return error_response(
        request,
        status_code=503,
        code="feature.degraded",
        message="WireGuard observe transport not configured",
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
    result: WireguardApplyResult,
    *,
    basename: str,
    content_sha256: str,
) -> WireguardApplyResult:
    return replace(
        result,
        backup_basename=basename,
        backup_content_sha256=content_sha256,
    )


def _dispatch_apply_live(
    *,
    host: HostState,
    intent: WireguardIntent,
    params: WifiLiveConnectionParams,
    handshake_settle_seconds: float = 0,
    sealed_apply_params: SealedApplyTrailParams | None = None,
) -> WireguardApplyResult:
    cert = host.gate_a_certification
    if cert is None or not cert.is_open:
        raise WireguardApplyServiceError(
            "Gate A certification required for live apply (startup-config backup)"
        )

    vault = host.runtime.vault
    backup_basename: str | None = None
    backup_sha256: str | None = None

    with open_wifi_live_session(params=params, vault=vault) as session:
        ensure_live_gate_a_tuple_match(session, cert)

        def backup_callback() -> None:
            nonlocal backup_basename, backup_sha256
            if backup_basename is not None:
                return
            meta = backup_startup_config(tunnel=session.tunnel, certification=cert)
            backup_basename = Path(meta.encrypted_locator).name
            backup_sha256 = meta.content_sha256

        result = apply_wireguard_intent(
            intent=intent,
            transport=session.transport,
            credential_resolver=_credential_resolver(host),
            backup_callback=backup_callback,
            handshake_settle_seconds=handshake_settle_seconds,
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
    intent: WireguardIntent,
    params: WifiLiveConnectionParams,
    sealed_apply_params: SealedApplyTrailParams | None = None,
) -> WireguardApplyResult:
    cert = host.gate_a_certification
    if cert is None or not cert.is_open:
        raise WireguardApplyServiceError(
            "Gate A certification required for live teardown (startup-config backup)"
        )

    vault = host.runtime.vault
    backup_basename: str | None = None
    backup_sha256: str | None = None

    with open_wifi_live_session(params=params, vault=vault) as session:
        ensure_live_gate_a_tuple_match(session, cert)
        meta = backup_startup_config(tunnel=session.tunnel, certification=cert)
        backup_basename = Path(meta.encrypted_locator).name
        backup_sha256 = meta.content_sha256
        result = teardown_wireguard(
            wg_id=intent.wg_id,
            transport=session.transport,
            credential_resolver=_credential_resolver(host),
            intent=intent,
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


@router.post("/wireguard/preview", response_model=WireguardPreviewResponse)
def wireguard_preview(request: Request, body: WireguardPreviewBody) -> JSONResponse:
    try:
        intent = _intent_from_body(body)
    except IntentValidationError as exc:
        return _intent_validation_error(request, exc)
    try:
        plan = preview_wireguard_apply(intent)
    except (WireguardApplyServiceError, ValueError) as exc:
        return _wireguard_preview_error(request, exc)
    return JSONResponse(plan, status_code=200, headers=_ok_headers(request))


@router.post("/wireguard/apply", response_model=WireguardApplyResponse)
def wireguard_apply(request: Request, body: WireguardApplyBody) -> JSONResponse:
    if not body.confirm_live_apply:
        return error_response(
            request,
            status_code=400,
            code="wireguard.confirm_required",
            message="confirm_live_apply must be true to dispatch apply",
        )
    host = _state(request)
    gate = _apply_gates(host, request)
    if gate is not None:
        return gate
    try:
        intent = _intent_from_body(body)
    except IntentValidationError as exc:
        return _intent_validation_error(request, exc)

    incomplete = _validate_live_connection_fields(request, body, host)
    if incomplete is not None:
        return incomplete

    live_params = _live_params_from_body(body, host)
    if live_params is not None and not is_win32_live_capable():
        return _live_platform_unsupported_error(request)

    intent_redacted = _wireguard_intent_redacted(body)
    router_id = body.router_id.strip() if body.router_id else None
    lock_key = _router_apply_lock_key(body, router_id)
    trail_params = _sealed_apply_trail_params(
        request,
        route="wireguard",
        verb="apply",
        intent_redacted=intent_redacted,
        router_id=router_id,
    )
    result: WireguardApplyResult | None = None

    if _should_use_live_path(body, host):
        params = live_params
        assert params is not None
        if host.gate_a_certification is None or not host.gate_a_certification.is_open:
            return _gate_a_required_error(
                request,
                "Gate A certification required for live apply (startup-config backup)",
            )
        try:
            result = run_with_router_apply_lock(
                lock_key,
                lambda: _dispatch_apply_live(
                    host=host,
                    intent=intent,
                    params=params,
                    handshake_settle_seconds=clamp_handshake_settle_seconds(
                        body.handshake_settle_seconds
                    ),
                    sealed_apply_params=trail_params,
                ),
            )
        except LiveIdentityTupleMismatchError:
            return _identity_mismatch_error(request)
        except StartupBackupError as exc:
            _ = exc
            return _live_backup_unavailable_error(request)
        except SealedApplyTrailBeginError as exc:
            _record_wireguard_sealed_audit(
                host,
                request,
                verb="apply",
                intent_redacted=intent_redacted,
                outcome="failed",
                error_message=_synthesised_trail_begin_failed_message(),
                router_id=router_id,
            )
            return sealed_apply_trail_begin_error_response(request, exc)
        except WireguardApplyServiceError as exc:
            _record_wireguard_sealed_audit(
                host,
                request,
                verb="apply",
                intent_redacted=intent_redacted,
                outcome="failed",
                error_message=_synthesised_apply_failed_message(),
                router_id=router_id,
            )
            return _service_error(request, exc)
        except Exception as exc:
            _record_wireguard_sealed_audit(
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
        _record_wireguard_sealed_audit(
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
            lambda: apply_wireguard_intent(
                intent=intent,
                transport=transport,
                credential_resolver=_credential_resolver(host),
                handshake_settle_seconds=clamp_handshake_settle_seconds(
                    body.handshake_settle_seconds
                ),
                store=host.runtime.store,
                sealed_apply_params=trail_params,
            ),
        )
    except SealedApplyTrailBeginError as exc:
        _record_wireguard_sealed_audit(
            host,
            request,
            verb="apply",
            intent_redacted=intent_redacted,
            outcome="failed",
            error_message=_synthesised_trail_begin_failed_message(),
            router_id=router_id,
        )
        return sealed_apply_trail_begin_error_response(request, exc)
    except WireguardApplyServiceError as exc:
        _record_wireguard_sealed_audit(
            host,
            request,
            verb="apply",
            intent_redacted=intent_redacted,
            outcome="failed",
            error_message=_synthesised_apply_failed_message(),
            router_id=router_id,
        )
        return _service_error(request, exc)
    except Exception as exc:
        _record_wireguard_sealed_audit(
            host,
            request,
            verb="apply",
            intent_redacted=intent_redacted,
            outcome="error",
            exception_type=type(exc).__name__,
            router_id=router_id,
        )
        raise
    _record_wireguard_sealed_audit(
        host,
        request,
        verb="apply",
        intent_redacted=intent_redacted,
        result=result,
        router_id=router_id,
    )
    return JSONResponse(result.to_dict(), status_code=200, headers=_ok_headers(request))


@router.post("/wireguard/teardown", response_model=WireguardApplyResponse)
def wireguard_teardown(request: Request, body: WireguardTeardownBody) -> JSONResponse:
    confirmed = body.confirm_live_teardown or body.confirm_live_apply
    if not confirmed:
        return error_response(
            request,
            status_code=400,
            code="wireguard.confirm_required",
            message="confirm_live_teardown or confirm_live_apply must be true to dispatch teardown",
        )
    host = _state(request)
    gate = _apply_gates(host, request)
    if gate is not None:
        return gate
    try:
        validate_wireguard_id(body.wg_id)
    except ValueError as exc:
        return _wg_validation_error(request, exc)
    try:
        intent = _intent_from_body(body)
    except IntentValidationError as exc:
        return _intent_validation_error(request, exc)

    incomplete = _validate_live_connection_fields(request, body, host)
    if incomplete is not None:
        return incomplete

    live_params = _live_params_from_body(body, host)
    if live_params is not None and not is_win32_live_capable():
        return _live_platform_unsupported_error(request)

    intent_redacted = _wireguard_intent_redacted(body)
    router_id = body.router_id.strip() if body.router_id else None
    lock_key = _router_apply_lock_key(body, router_id)
    trail_params = _sealed_apply_trail_params(
        request,
        route="wireguard",
        verb="teardown",
        intent_redacted=intent_redacted,
        router_id=router_id,
    )
    result: WireguardApplyResult | None = None

    if _should_use_live_path(body, host):
        params = live_params
        assert params is not None
        if host.gate_a_certification is None or not host.gate_a_certification.is_open:
            return _gate_a_required_error(
                request,
                "Gate A certification required for live teardown (startup-config backup)",
            )
        try:
            result = run_with_router_apply_lock(
                lock_key,
                lambda: _dispatch_teardown_live(
                    host=host,
                    intent=intent,
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
            _record_wireguard_sealed_audit(
                host,
                request,
                verb="teardown",
                intent_redacted=intent_redacted,
                outcome="failed",
                error_message=_synthesised_trail_begin_failed_message(),
                router_id=router_id,
            )
            return sealed_apply_trail_begin_error_response(request, exc)
        except WireguardApplyServiceError as exc:
            _record_wireguard_sealed_audit(
                host,
                request,
                verb="teardown",
                intent_redacted=intent_redacted,
                outcome="failed",
                error_message=_synthesised_apply_failed_message(),
                router_id=router_id,
            )
            return _service_error(request, exc)
        except Exception as exc:
            _record_wireguard_sealed_audit(
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
        _record_wireguard_sealed_audit(
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
            lambda: teardown_wireguard(
                wg_id=body.wg_id,
                transport=transport,
                credential_resolver=_credential_resolver(host),
                intent=intent,
                store=host.runtime.store,
                sealed_apply_params=trail_params,
            ),
        )
    except SealedApplyTrailBeginError as exc:
        _record_wireguard_sealed_audit(
            host,
            request,
            verb="teardown",
            intent_redacted=intent_redacted,
            outcome="failed",
            error_message=_synthesised_trail_begin_failed_message(),
            router_id=router_id,
        )
        return sealed_apply_trail_begin_error_response(request, exc)
    except WireguardApplyServiceError as exc:
        _record_wireguard_sealed_audit(
            host,
            request,
            verb="teardown",
            intent_redacted=intent_redacted,
            outcome="failed",
            error_message=_synthesised_apply_failed_message(),
            router_id=router_id,
        )
        return _service_error(request, exc)
    except Exception as exc:
        _record_wireguard_sealed_audit(
            host,
            request,
            verb="teardown",
            intent_redacted=intent_redacted,
            outcome="error",
            exception_type=type(exc).__name__,
            router_id=router_id,
        )
        raise
    _record_wireguard_sealed_audit(
        host,
        request,
        verb="teardown",
        intent_redacted=intent_redacted,
        result=result,
        router_id=router_id,
    )
    return JSONResponse(result.to_dict(), status_code=200, headers=_ok_headers(request))


def _build_observe_response(*, wg_id: str, observed: dict[str, Any]) -> WireguardObserveResponse:
    observation = observe_tunnel(observed)
    return WireguardObserveResponse(
        wg_id=wg_id,
        tunnel_verification_status=cast(TunnelVerificationStatus, observation.verdict),
        verdict_explanation=VerdictExplanationResponse.model_validate(
            observation.explanation.to_dict()
        ),
        interface_readable=_interface_readable(observed),
    )


@router.post("/wireguard/observe", response_model=WireguardObserveResponse)
def wireguard_observe(request: Request, body: WireguardObserveBody) -> JSONResponse:
    host = _state(request)
    try:
        validate_wireguard_id(body.wg_id)
    except ValueError as exc:
        return _wg_validation_error(request, exc)

    incomplete = _validate_live_connection_fields(request, body, host)
    if incomplete is not None:
        return incomplete

    live_params = _live_params_from_body(body, host)
    if live_params is not None and not is_win32_live_capable():
        return _live_platform_unsupported_error(request)

    if _should_use_live_path(body, host):
        params = live_params
        assert params is not None
        if host.gate_a_certification is None or not host.gate_a_certification.is_open:
            return _gate_a_required_error(
                request,
                "Gate A certification required for live observe",
            )
        try:
            vault = host.runtime.vault
            with open_wifi_live_session(params=params, vault=vault) as session:
                observed = _readback_show_interface(
                    session.transport,
                    body.wg_id,
                    match_peer_public_key=body.peer_public_key,
                )
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
        response = _build_observe_response(wg_id=body.wg_id, observed=observed)
        return JSONResponse(response.model_dump(), status_code=200, headers=_ok_headers(request))

    transport = _resolve_observe_transport(host, request)
    if isinstance(transport, JSONResponse):
        return transport
    try:
        observed = _readback_show_interface(
            transport,
            body.wg_id,
            match_peer_public_key=body.peer_public_key,
        )
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
    response = _build_observe_response(wg_id=body.wg_id, observed=observed)
    return JSONResponse(response.model_dump(), status_code=200, headers=_ok_headers(request))
