"""Wi-Fi station (WISP) apply/teardown API routes (confirm-gated; injected transport)."""

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
from router_control.adapters.netcraze.sanitize import redact_sealed_cli_command
from router_control.adapters.netcraze.startup_backup import (
    StartupBackupError,
    backup_startup_config,
)
from router_control.adapters.netcraze.transport import SealedRciWriteRequest
from router_control.adapters.netcraze.wifi_station_rci import validate_wifi_station_id
from router_control.application.recovery import SealedApplyTrailParams
from router_control.application.router_apply_lock import (
    resolve_router_apply_lock_key,
    run_with_router_apply_lock,
)
from router_control.application.wifi_observation_helpers import (
    ERROR_CODE_STATION_PRIORITY_REQUIRES_IP_GLOBAL,
)
from router_control.application.wifi_station_apply_planner import (
    WifiStationApplyPlannerError,
    WifiStationAuthMode,
    WifiStationPlannerOptions,
    station_id_for_band,
)
from router_control.application.internet_status_observe import InternetStatusTransport
from router_control.application.wifi_station_apply_service import (
    WifiStationApplyResult,
    WifiStationApplyServiceError,
    WifiStationApplyTransport,
    apply_wifi_station_intent,
    teardown_wifi_station,
)
from router_control.domain.network_intents import UplinkIntent, UplinkMode, WifiBand
from router_control.persistence.errors import SealedApplyTrailBeginError

from router_control_host.apply_response_models import WifiStationApplyResponse
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
    open_wifi_live_session,
)

_LIVE_FAMILY_PREFIX = "wifi.station"

router = APIRouter(prefix=API_PREFIX, tags=["wifi-station-apply"])

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


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class WifiStationIntentFields(_StrictModel):
    mode: UplinkMode = UplinkMode.WIFI_WAN
    ssid: str = Field(min_length=1, max_length=32)
    band: WifiBand = WifiBand.BAND_2_4GHZ
    credential_ref_id: str | None = Field(default=None, min_length=1)
    bssid: str | None = Field(default=None, min_length=1)
    priority: int = 100
    auth_mode: WifiStationAuthMode | None = None


class WifiLiveConnectionFields(_StrictModel):
    host: str | None = None
    username: str | None = None
    router_credential_ref_id: str | None = None
    ssh_host_key_sha256: str | None = None
    source_address: str | None = None
    router_id: str | None = None


class WifiStationApplyBody(WifiStationIntentFields, WifiLiveConnectionFields):
    confirm_live_apply: bool = False
    compensate_on_failure: bool = True
    idempotent: bool = False
    uplink_settle_seconds: float = Field(
        default=25.0,
        ge=0,
        description="Bounded uplink settle wait (seconds); clamped to 20-30 when >0 on live path",
    )


class WifiStationTeardownBody(WifiStationIntentFields, WifiLiveConnectionFields):
    confirm_live_teardown: bool = False
    confirm_live_apply: bool = False


class _LiveStationTransportWrapper:
    """Marks live session transport for station apply service guard."""

    wifi_station_live_dispatch: Literal[True] = True

    def __init__(self, inner: Any) -> None:
        self._inner = inner

    def execute_sealed_rci_write(self, request: SealedRciWriteRequest) -> Any:
        return self._inner.execute_sealed_rci_write(request)

    def execute_rci_parse(self, cli_command: str) -> Any:
        return self._inner.execute_rci_parse(cli_command)


_ACK_BY_FRAGMENT: tuple[tuple[str, str], ...] = (
    (" no authentication wpa-psk", "WPA PSK removed."),
    (" no encryption wpa2", "WPA2 algorithms disabled."),
    (" no encryption enable", "wireless encryption disabled."),
    (" no ssid", "SSID reset."),
    (" no ip address dhcp", "Stopped DHCP client on station."),
    (" no ip address", "IP address cleared."),
    (" ssid ", "SSID saved."),
    (" encryption enable", "wireless encryption enabled."),
    (" encryption wpa2", "WPA2 algorithms enabled."),
    (" authentication wpa-psk", "WPA PSK set."),
    (" ip global ", "Core::Configurator: Done."),
    (" ip address dhcp", "Started DHCP client on station."),
    (" up", "interface is up."),
    (" down", "interface is down."),
)


def _station_ack_for_body(body: bytes) -> list[dict[str, Any]]:
    text = body.decode("utf-8", errors="replace").lower()
    message = "synthetic ack"
    for fragment, ack_message in _ACK_BY_FRAGMENT:
        if fragment in text:
            message = ack_message
            break
    return [
        {
            "parse": {
                "prompt": "(config)",
                "status": [
                    {
                        "status": "message",
                        "code": "8979152",
                        "ident": "Network::Interface",
                        "message": message,
                    }
                ],
            }
        }
    ]


class _DefaultFakeStationTransport:
    """Offline fake transport with canned acks."""

    wifi_station_offline_only: Literal[True] = True

    def __init__(self) -> None:
        self.write_commands: list[str] = []

    def execute_sealed_rci_write(self, request: SealedRciWriteRequest) -> list[dict[str, Any]]:
        body = json.loads(request.body.decode("utf-8"))
        command = str(body[0]["parse"])
        self.write_commands.append(redact_sealed_cli_command(command))
        return _station_ack_for_body(request.body)


class _EphemeralLiveInternetStatusTransport:
    """Opens a fresh pinned SSH session for each internet-status observe call."""

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

    def _ensure_tuple_match(self, session: Any) -> None:
        cert = self._host.gate_a_certification
        if cert is None or not cert.is_open:
            raise LiveGateARequiredError(
                "Gate A certification required for live mutation"
            )
        ensure_live_gate_a_tuple_match(
            session,
            cert,
            router_id=self._router_id,
        )

    def execute_rci_parse(self, cli_command: str) -> dict[str, Any]:
        with open_wifi_live_session(params=self._params, vault=self._vault) as session:
            self._ensure_tuple_match(session)
            return cast(dict[str, Any], session.transport.execute_rci_parse(cli_command))


class _EphemeralLiveStationApplyTransport:
    """Opens a fresh pinned SSH session for each station apply/teardown call."""

    wifi_station_live_dispatch: Literal[True] = True

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

    def _ensure_tuple_match(self, session: Any) -> None:
        cert = self._host.gate_a_certification
        if cert is None or not cert.is_open:
            raise LiveGateARequiredError(
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


def _resolve_uplink_watchdog_connection_params(
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


def build_uplink_watchdog_backup_callback_factory(
    host: HostState,
) -> Callable[[str], Callable[[], None] | None] | None:
    """Gate-A-gated startup-config backup closure for env-gated uplink watchdog reapply."""
    if host.wifi_station_apply_transport_factory is not None:

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

    if host.adapter_mode != "live":
        return None

    vault = host.runtime.vault

    def _live(router_id: str) -> Callable[[], None] | None:
        cert = host.gate_a_certification
        if cert is None or not cert.is_open:
            return None
        params = _resolve_uplink_watchdog_connection_params(host, router_id)
        if params is None or not is_win32_live_capable():
            return None

        def backup_callback() -> None:
            cert = host.gate_a_certification
            if cert is None or not cert.is_open:
                raise StartupBackupError("Gate A certification required for watchdog backup")
            with open_wifi_live_session(params=params, vault=vault) as session:
                ensure_live_gate_a_tuple_match(
                    session,
                    cert,
                    router_id=router_id,
                )
                backup_startup_config(tunnel=session.tunnel, certification=cert)

        return backup_callback

    return _live


def build_uplink_watchdog_observe_transport_factory(
    host: HostState,
) -> Callable[[str], InternetStatusTransport | None] | None:
    """Resolve per-router observe transport for env-gated uplink watchdog."""
    if host.internet_status_transport_factory is not None:
        injected = host.internet_status_transport_factory

        def _injected(_router_id: str) -> InternetStatusTransport:
            return cast(InternetStatusTransport, injected())

        return _injected

    allow_fake = host.adapter_mode == "fake" and (
        host.allow_fake_mutations or os.environ.get("RC_ALLOW_FAKE_MUTATIONS") == "1"
    )
    if allow_fake:
        from router_control_host.internet_status_routes import (
            _DefaultFakeInternetStatusTransport,
        )

        def _fake(_router_id: str) -> InternetStatusTransport:
            return _DefaultFakeInternetStatusTransport()

        return _fake

    if host.adapter_mode != "live":
        return None

    vault = host.runtime.vault

    def _live(router_id: str) -> InternetStatusTransport | None:
        cert = host.gate_a_certification
        if cert is None or not cert.is_open:
            return None
        params = _resolve_uplink_watchdog_connection_params(host, router_id)
        if params is None or not is_win32_live_capable():
            return None
        return _EphemeralLiveInternetStatusTransport(
            params=params,
            vault=vault,
            host=host,
            router_id=router_id,
        )

    return _live


def build_uplink_watchdog_apply_transport_factory(
    host: HostState,
) -> Callable[[str], WifiStationApplyTransport | None] | None:
    """Resolve per-router apply transport for env-gated uplink watchdog."""
    if host.wifi_station_apply_transport_factory is not None:
        injected = host.wifi_station_apply_transport_factory

        def _injected(_router_id: str) -> WifiStationApplyTransport:
            return cast(WifiStationApplyTransport, injected())

        return _injected

    allow_fake = host.adapter_mode == "fake" and (
        host.allow_fake_mutations or os.environ.get("RC_ALLOW_FAKE_MUTATIONS") == "1"
    )
    if allow_fake:

        def _fake(_router_id: str) -> WifiStationApplyTransport:
            return _DefaultFakeStationTransport()

        return _fake

    if host.adapter_mode != "live":
        return None

    vault = host.runtime.vault

    def _live(router_id: str) -> WifiStationApplyTransport | None:
        cert = host.gate_a_certification
        if cert is None or not cert.is_open:
            return None
        params = _resolve_uplink_watchdog_connection_params(host, router_id)
        if params is None or not is_win32_live_capable():
            return None
        return _EphemeralLiveStationApplyTransport(
            params=params,
            vault=vault,
            host=host,
            router_id=router_id,
        )

    return _live


def _state(request: Request) -> HostState:
    return request.app.state.host  # type: ignore[no-any-return]


def _intent_from_body(body: WifiStationIntentFields) -> UplinkIntent:
    return UplinkIntent(
        mode=UplinkMode.WIFI_WAN,
        ssid=body.ssid,
        band=body.band,
        credential_ref_id=body.credential_ref_id,
        bssid=body.bssid,
        priority=body.priority,
    )


def _options_from_body(body: WifiStationIntentFields) -> WifiStationPlannerOptions:
    auth_mode = body.auth_mode or WifiStationAuthMode.WPA2_PSK
    return WifiStationPlannerOptions(auth_mode=auth_mode)


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
    return error_response(
        request,
        status_code=422,
        code=live_connection_incomplete_code(_LIVE_FAMILY_PREFIX),
        message=f"incomplete live connection params; missing: {', '.join(missing)}",
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


def _station_planner_error_response(
    request: Request,
    exc: BaseException,
) -> JSONResponse | None:
    planner_code = str(exc)
    http_code = _PLANNER_CODE_TO_HTTP.get(planner_code)
    if http_code is None:
        return None
    return error_response(
        request,
        status_code=422,
        code=http_code,
        message=_PLANNER_UNSUPPORTED_MESSAGES.get(planner_code, planner_code),
    )


def _service_error(request: Request, exc: WifiStationApplyServiceError) -> JSONResponse:
    mapped = _station_planner_error_response(request, exc)
    if mapped is not None:
        return mapped
    return error_response(
        request,
        status_code=422,
        code="wifi.station_apply_failed",
        message=str(exc),
    )


def _credential_resolver(host: HostState) -> Callable[[str], str]:
    if host.wifi_station_apply_credential_resolver is not None:
        return host.wifi_station_apply_credential_resolver

    vault = host.runtime.vault

    def resolve(ref_id: str) -> str:
        return vault.use(ref_id)

    return resolve


def _resolve_transport(
    host: HostState,
    request: Request,
) -> JSONResponse | WifiStationApplyTransport:
    if host.wifi_station_apply_transport_factory is not None:
        return cast(WifiStationApplyTransport, host.wifi_station_apply_transport_factory())
    allow_fake = host.adapter_mode == "fake" and (
        host.allow_fake_mutations or os.environ.get("RC_ALLOW_FAKE_MUTATIONS") == "1"
    )
    if allow_fake:
        return _DefaultFakeStationTransport()
    return error_response(
        request,
        status_code=503,
        code="feature.degraded",
        message="Wi-Fi station apply transport not configured",
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


def _result_with_backup(
    result: WifiStationApplyResult,
    *,
    basename: str,
    content_sha256: str,
) -> WifiStationApplyResult:
    return replace(
        result,
        backup_basename=basename,
        backup_content_sha256=content_sha256,
    )


def _wifi_station_intent_redacted(body: WifiStationIntentFields) -> dict[str, object]:
    payload: dict[str, object] = {
        "mode": body.mode.value,
        "band": body.band.value,
        "priority": body.priority,
        "auth_mode": (body.auth_mode or WifiStationAuthMode.WPA2_PSK).value,
    }
    if body.credential_ref_id:
        payload["credential_ref_id"] = body.credential_ref_id
    if body.bssid:
        payload["bssid"] = body.bssid
    return payload


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


def _record_wifi_station_sealed_audit(
    host: HostState,
    request: Request,
    *,
    verb: str,
    intent_redacted: dict[str, object],
    result: WifiStationApplyResult | None = None,
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
        action=f"sealed_apply.wifi.station.{verb}",
        outcome=final_outcome,
        route="wifi.station",
        verb=verb,
        intent_redacted=intent_redacted,
        router_id=router_id,
        correlation_id=getattr(request.state, "correlation_id", None),
        result_payload=result_payload,
        outcome_snapshot=outcome_snapshot,
        error_message=error_message,
        exception_type=exception_type,
    )


def _validate_intent_body(
    request: Request,
    body: WifiStationIntentFields,
) -> JSONResponse | tuple[UplinkIntent, WifiStationPlannerOptions]:
    if body.mode != UplinkMode.WIFI_WAN:
        return error_response(
            request,
            status_code=422,
            code="wifi.station_apply_failed",
            message=f"station apply requires mode WifiWan, got {body.mode.value}",
        )
    auth_mode = body.auth_mode or WifiStationAuthMode.WPA2_PSK
    if auth_mode is WifiStationAuthMode.OPEN:
        return error_response(
            request,
            status_code=422,
            code="wifi.station_apply_failed",
            message=_MSG_OPEN_UNSUPPORTED,
        )
    try:
        intent = _intent_from_body(body)
        options = _options_from_body(body)
        if not intent.credential_ref_id:
            raise WifiStationApplyServiceError(
                "WifiWan station apply requires credential_ref_id"
            )
        station_id = station_id_for_band(intent.band or WifiBand.BAND_2_4GHZ)
        validate_wifi_station_id(station_id)
    except (WifiStationApplyServiceError, WifiStationApplyPlannerError, ValueError) as exc:
        mapped = _station_planner_error_response(request, exc)
        if mapped is not None:
            return mapped
        return error_response(
            request,
            status_code=422,
            code="wifi.station_apply_failed",
            message=str(exc),
        )
    return intent, options


def _dispatch_apply_live(
    *,
    host: HostState,
    body: WifiStationApplyBody,
    params: WifiLiveConnectionParams,
    intent: UplinkIntent,
    options: WifiStationPlannerOptions,
    sealed_apply_params: SealedApplyTrailParams | None = None,
) -> WifiStationApplyResult:
    cert = host.gate_a_certification
    if cert is None or not cert.is_open:
        raise WifiStationApplyServiceError(
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
        transport = _LiveStationTransportWrapper(session.transport)

        def backup_callback() -> None:
            nonlocal backup_basename, backup_sha256
            if backup_basename is not None:
                return
            meta = backup_startup_config(tunnel=session.tunnel, certification=cert)
            backup_basename = Path(meta.encrypted_locator).name
            backup_sha256 = meta.content_sha256

        result = apply_wifi_station_intent(
            intent=intent,
            transport=transport,
            credential_resolver=_credential_resolver(host),
            options=options,
            live_dispatch=True,
            backup_callback=backup_callback,
            compensate_on_failure=body.compensate_on_failure,
            idempotent=body.idempotent,
            uplink_settle_seconds=body.uplink_settle_seconds,
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
    params: WifiLiveConnectionParams,
    intent: UplinkIntent,
    options: WifiStationPlannerOptions,
    host_state: HostState,
    sealed_apply_params: SealedApplyTrailParams | None = None,
) -> WifiStationApplyResult:
    cert = host_state.gate_a_certification
    if cert is None or not cert.is_open:
        raise WifiStationApplyServiceError(
            "Gate A certification required for live teardown (startup-config backup)"
        )

    vault = host_state.runtime.vault
    backup_basename: str | None = None
    backup_sha256: str | None = None

    with open_wifi_live_session(params=params, vault=vault) as session:
        ensure_live_gate_a_tuple_match(session, cert)
        meta = backup_startup_config(tunnel=session.tunnel, certification=cert)
        backup_basename = Path(meta.encrypted_locator).name
        backup_sha256 = meta.content_sha256
        transport = _LiveStationTransportWrapper(session.transport)
        result = teardown_wifi_station(
            intent=intent,
            transport=transport,
            credential_resolver=_credential_resolver(host_state),
            options=options,
            live_dispatch=True,
            store=host_state.runtime.store,
            sealed_apply_params=sealed_apply_params,
        )

    if backup_basename is not None and backup_sha256 is not None:
        return _result_with_backup(
            result,
            basename=backup_basename,
            content_sha256=backup_sha256,
        )
    return result


@router.post("/wifi/station/apply", response_model=WifiStationApplyResponse)
def wifi_station_apply(request: Request, body: WifiStationApplyBody) -> JSONResponse:
    if not body.confirm_live_apply:
        return error_response(
            request,
            status_code=400,
            code="wifi.station_confirm_required",
            message="confirm_live_apply must be true to dispatch station apply",
        )
    host = _state(request)
    gate = _apply_gates(host, request)
    if gate is not None:
        return gate

    validated = _validate_intent_body(request, body)
    if isinstance(validated, JSONResponse):
        return validated
    intent, options = validated

    incomplete = _validate_live_connection_fields(request, body, host)
    if incomplete is not None:
        return incomplete

    live_params = _live_params_from_body(body, host)
    if live_params is not None and not is_win32_live_capable():
        return _live_platform_unsupported_error(request)

    intent_redacted = _wifi_station_intent_redacted(body)
    router_id = body.router_id.strip() if body.router_id else None
    lock_key = _router_apply_lock_key(body, router_id)
    trail_params = _sealed_apply_trail_params(
        request,
        route="wifi.station",
        verb="apply",
        intent_redacted=intent_redacted,
        router_id=router_id,
    )
    result: WifiStationApplyResult | None = None

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
                    body=body,
                    params=params,
                    intent=intent,
                    options=options,
                    sealed_apply_params=trail_params,
                ),
            )
        except LiveIdentityTupleMismatchError:
            return _identity_mismatch_error(request)
        except StartupBackupError as exc:
            return _live_backup_unavailable_error(request, str(exc))
        except SealedApplyTrailBeginError as exc:
            _record_wifi_station_sealed_audit(
                host,
                request,
                verb="apply",
                intent_redacted=intent_redacted,
                outcome="failed",
                error_message=str(exc),
                router_id=router_id,
            )
            return sealed_apply_trail_begin_error_response(request, exc)
        except WifiStationApplyServiceError as exc:
            _record_wifi_station_sealed_audit(
                host,
                request,
                verb="apply",
                intent_redacted=intent_redacted,
                outcome="failed",
                error_message=str(exc),
                router_id=router_id,
            )
            return _service_error(request, exc)
        except Exception as exc:
            _record_wifi_station_sealed_audit(
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
        _record_wifi_station_sealed_audit(
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
            lambda: apply_wifi_station_intent(
                intent=intent,
                transport=transport,
                credential_resolver=_credential_resolver(host),
                options=options,
                store=host.runtime.store,
                sealed_apply_params=trail_params,
            ),
        )
    except SealedApplyTrailBeginError as exc:
        _record_wifi_station_sealed_audit(
            host,
            request,
            verb="apply",
            intent_redacted=intent_redacted,
            outcome="failed",
            error_message=str(exc),
            router_id=router_id,
        )
        return sealed_apply_trail_begin_error_response(request, exc)
    except WifiStationApplyServiceError as exc:
        _record_wifi_station_sealed_audit(
            host,
            request,
            verb="apply",
            intent_redacted=intent_redacted,
            outcome="failed",
            error_message=str(exc),
            router_id=router_id,
        )
        return _service_error(request, exc)
    except Exception as exc:
        _record_wifi_station_sealed_audit(
            host,
            request,
            verb="apply",
            intent_redacted=intent_redacted,
            outcome="error",
            exception_type=type(exc).__name__,
            router_id=router_id,
        )
        raise
    _record_wifi_station_sealed_audit(
        host,
        request,
        verb="apply",
        intent_redacted=intent_redacted,
        result=result,
        router_id=router_id,
    )
    return JSONResponse(result.to_dict(), status_code=200, headers=_ok_headers(request))


@router.post("/wifi/station/teardown", response_model=WifiStationApplyResponse)
def wifi_station_teardown(request: Request, body: WifiStationTeardownBody) -> JSONResponse:
    confirmed = body.confirm_live_teardown or body.confirm_live_apply
    if not confirmed:
        return error_response(
            request,
            status_code=400,
            code="wifi.station_confirm_required",
            message=(
                "confirm_live_teardown or confirm_live_apply must be true "
                "to dispatch station teardown"
            ),
        )
    host = _state(request)
    gate = _apply_gates(host, request)
    if gate is not None:
        return gate

    validated = _validate_intent_body(request, body)
    if isinstance(validated, JSONResponse):
        return validated
    intent, options = validated

    incomplete = _validate_live_connection_fields(request, body, host)
    if incomplete is not None:
        return incomplete

    live_params = _live_params_from_body(body, host)
    if live_params is not None and not is_win32_live_capable():
        return _live_platform_unsupported_error(request)

    intent_redacted = _wifi_station_intent_redacted(body)
    router_id = body.router_id.strip() if body.router_id else None
    lock_key = _router_apply_lock_key(body, router_id)
    trail_params = _sealed_apply_trail_params(
        request,
        route="wifi.station",
        verb="teardown",
        intent_redacted=intent_redacted,
        router_id=router_id,
    )
    result: WifiStationApplyResult | None = None

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
                    params=params,
                    intent=intent,
                    options=options,
                    host_state=host,
                    sealed_apply_params=trail_params,
                ),
            )
        except LiveIdentityTupleMismatchError:
            return _identity_mismatch_error(request)
        except StartupBackupError as exc:
            return _live_backup_unavailable_error(request, str(exc))
        except SealedApplyTrailBeginError as exc:
            _record_wifi_station_sealed_audit(
                host,
                request,
                verb="teardown",
                intent_redacted=intent_redacted,
                outcome="failed",
                error_message=str(exc),
                router_id=router_id,
            )
            return sealed_apply_trail_begin_error_response(request, exc)
        except WifiStationApplyServiceError as exc:
            _record_wifi_station_sealed_audit(
                host,
                request,
                verb="teardown",
                intent_redacted=intent_redacted,
                outcome="failed",
                error_message=str(exc),
                router_id=router_id,
            )
            return _service_error(request, exc)
        except Exception as exc:
            _record_wifi_station_sealed_audit(
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
        _record_wifi_station_sealed_audit(
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
            lambda: teardown_wifi_station(
                intent=intent,
                transport=transport,
                credential_resolver=_credential_resolver(host),
                options=options,
                store=host.runtime.store,
                sealed_apply_params=trail_params,
            ),
        )
    except SealedApplyTrailBeginError as exc:
        _record_wifi_station_sealed_audit(
            host,
            request,
            verb="teardown",
            intent_redacted=intent_redacted,
            outcome="failed",
            error_message=str(exc),
            router_id=router_id,
        )
        return sealed_apply_trail_begin_error_response(request, exc)
    except WifiStationApplyServiceError as exc:
        _record_wifi_station_sealed_audit(
            host,
            request,
            verb="teardown",
            intent_redacted=intent_redacted,
            outcome="failed",
            error_message=str(exc),
            router_id=router_id,
        )
        return _service_error(request, exc)
    except Exception as exc:
        _record_wifi_station_sealed_audit(
            host,
            request,
            verb="teardown",
            intent_redacted=intent_redacted,
            outcome="error",
            exception_type=type(exc).__name__,
            router_id=router_id,
        )
        raise
    _record_wifi_station_sealed_audit(
        host,
        request,
        verb="teardown",
        intent_redacted=intent_redacted,
        result=result,
        router_id=router_id,
    )
    return JSONResponse(result.to_dict(), status_code=200, headers=_ok_headers(request))
