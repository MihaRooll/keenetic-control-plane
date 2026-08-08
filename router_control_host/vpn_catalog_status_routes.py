"""VPN catalog live status enrichment routes (read-only; one active probe max)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from router_control.adapters.netcraze.allowlist import validate_wireguard_id
from router_control.application.internet_status_observe import run_internet_status_observe
from router_control.application.wireguard_apply_service import (
    WireguardApplyTransport,
    _readback_show_interface,
    observe_tunnel,
)

from router_control_host.errors import error_response, operator_structured_error_response
from router_control_host.routes import API_PREFIX, _ok_headers
from router_control_host.state import HostState
from router_control_host.wifi_live_transport import (
    WifiLiveConnectionParams,
    connection_fields_present,
    connection_params_from_fields,
    gate_a_required_code,
    incomplete_live_connection_fields,
    is_win32_live_capable,
    live_connection_incomplete_code,
    live_platform_unsupported_code,
    live_platform_unsupported_message,
    map_wifi_live_transport_error,
    open_wifi_live_session,
)
from router_control_host.wireguard_apply_routes import (
    _DefaultFakeWireguardTransport,
    _resolve_observe_transport,
)

router = APIRouter(prefix=API_PREFIX, tags=["vpn-catalog-status"])

_LIVE_FAMILY_PREFIX = "vpn_catalog"
_PROBE_NO_WG_ERROR = "нет интерфейса туннеля"
_PROBE_TRANSPORT_ERROR = "Не удалось прочитать состояние туннеля на роутере"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class VpnCatalogStatusBody(_StrictModel):
    host: str | None = Field(default=None, min_length=1)
    username: str | None = Field(default=None, min_length=1)
    router_credential_ref_id: str | None = Field(default=None, min_length=1)
    ssh_host_key_sha256: str | None = Field(default=None, min_length=1)
    source_address: str | None = Field(default=None, min_length=1)
    router_id: str | None = Field(default=None, min_length=1)


def _state(request: Request) -> HostState:
    return request.app.state.host  # type: ignore[no-any-return]


def _live_params_from_body(
    body: VpnCatalogStatusBody,
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


def _should_use_live_path(body: VpnCatalogStatusBody, host: HostState) -> bool:
    return is_win32_live_capable() and _live_params_from_body(body, host) is not None


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


def _live_params_required_error(request: Request) -> JSONResponse:
    return error_response(
        request,
        status_code=503,
        code=f"{_LIVE_FAMILY_PREFIX}.live_connection_required",
        message="live catalog-status requires connection params for active profile probe",
    )


def _live_platform_unsupported_error(request: Request) -> JSONResponse:
    return error_response(
        request,
        status_code=503,
        code=live_platform_unsupported_code(_LIVE_FAMILY_PREFIX),
        message=live_platform_unsupported_message(),
    )


def _gate_a_required_error(request: Request) -> JSONResponse:
    return error_response(
        request,
        status_code=503,
        code=gate_a_required_code(_LIVE_FAMILY_PREFIX),
        message="Gate A certification required for live VPN catalog-status probe",
    )


def _wg_validation_error(request: Request, exc: ValueError) -> JSONResponse:
    _ = exc
    return operator_structured_error_response(
        request,
        status_code=422,
        code="wireguard.wg_forbidden",
        reason="not_allowlisted",
        field="wg_id",
    )


def _catalog_rows(host: HostState) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    active_by_profile: dict[str, dict[str, Any]] = {}
    for assignment in host.runtime.store.list_active_tunnel_assignments():
        profile_id = str(assignment["profile_id"])
        if profile_id not in active_by_profile:
            active_by_profile[profile_id] = assignment

    rows: list[dict[str, Any]] = []
    for row in host.runtime.store.list_profiles():
        profile_id = str(row["profile_id"])
        metadata = json.loads(row["metadata_json"] or "{}")
        active_assignment = active_by_profile.get(profile_id)
        is_active = active_assignment is not None
        assigned_wg_id: str | None = None
        if is_active and active_assignment is not None:
            if active_assignment.get("observed_vendor_locator"):
                assigned_wg_id = str(active_assignment["observed_vendor_locator"])
            policy_raw = active_assignment.get("policy_metadata_json")
            if policy_raw:
                policy = json.loads(policy_raw)
                if not assigned_wg_id and policy.get("wg_id"):
                    assigned_wg_id = str(policy["wg_id"])
            if not assigned_wg_id:
                meta_wg = metadata.get("wg_id")
                if meta_wg is not None:
                    assigned_wg_id = str(meta_wg)
        rows.append(
            {
                "profile_id": profile_id,
                "display_name": row["display_name"],
                "vpn_kind": row["vpn_kind"],
                "validation_status": row["validation_status"],
                "is_active": is_active,
                "assigned_wg_id": assigned_wg_id,
            }
        )
    return rows, active_by_profile


def _inactive_live_fields() -> dict[str, Any]:
    return {
        "live_probed": False,
        "live_tunnel_verification_status": None,
        "probe_error": None,
        "observed_at": None,
        "routed_through_tunnel": None,
        "routing_probe_status": "not_applicable",
    }


def _probe_routing_evidence(
    transport: WireguardApplyTransport,
    wg_id: str,
) -> tuple[str, bool | None]:
    observation = run_internet_status_observe(transport=transport)
    if observation.read_status != "ok":
        return "failed", None
    gateway_interface = observation.gateway_interface
    if not gateway_interface:
        return "unknown", None
    return "ok", gateway_interface.strip() == wg_id.strip()


def _probe_with_transport(
    transport: WireguardApplyTransport,
    wg_id: str,
) -> dict[str, Any]:
    observed_at = datetime.now(UTC).isoformat()
    try:
        observed = _readback_show_interface(transport, wg_id)
    except Exception:
        return {
            "live_probed": False,
            "live_tunnel_verification_status": None,
            "probe_error": _PROBE_TRANSPORT_ERROR,
            "observed_at": observed_at,
            "routed_through_tunnel": None,
            "routing_probe_status": "not_applicable",
        }
    observation = observe_tunnel(observed)
    routing_probe_status, routed_through_tunnel = _probe_routing_evidence(transport, wg_id)
    return {
        "live_probed": True,
        "live_tunnel_verification_status": observation.verdict,
        "probe_error": None,
        "observed_at": observed_at,
        "routing_probe_status": routing_probe_status,
        "routed_through_tunnel": routed_through_tunnel,
    }


def _resolve_fake_transport(
    host: HostState,
    request: Request,
) -> JSONResponse | WireguardApplyTransport:
    resolved = _resolve_observe_transport(host, request)
    if isinstance(resolved, JSONResponse):
        if host.adapter_mode == "fake":
            return _DefaultFakeWireguardTransport()
        return resolved
    return resolved


@router.post("/vpn-profiles/catalog-status")
def vpn_catalog_status(request: Request, body: VpnCatalogStatusBody) -> JSONResponse:
    host = _state(request)
    if connection_fields_present(
        host=body.host,
        username=body.username,
        router_credential_ref_id=body.router_credential_ref_id,
        ssh_host_key_sha256=body.ssh_host_key_sha256,
        source_address=body.source_address,
        router_id=body.router_id,
    ):
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

    rows, _active_by_profile = _catalog_rows(host)
    active_probe_target: tuple[str, str] | None = None
    for row in rows:
        if row["is_active"] is True:
            wg_id = row.get("assigned_wg_id")
            if isinstance(wg_id, str) and wg_id.strip():
                active_probe_target = (str(row["profile_id"]), wg_id.strip())
            break

    live_probe_result: dict[str, dict[str, Any]] = {}
    if active_probe_target is not None:
        profile_id, wg_id = active_probe_target
        try:
            validate_wireguard_id(wg_id)
        except ValueError as exc:
            return _wg_validation_error(request, exc)

        live_params = _live_params_from_body(body, host)
        if live_params is not None and not is_win32_live_capable():
            return _live_platform_unsupported_error(request)

        if _should_use_live_path(body, host):
            params = live_params
            assert params is not None
            if host.gate_a_certification is None or not host.gate_a_certification.is_open:
                return _gate_a_required_error(request)
            try:
                with open_wifi_live_session(params=params, vault=host.runtime.vault) as session:
                    live_probe_result[profile_id] = _probe_with_transport(
                        session.transport,
                        wg_id,
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
        elif host.adapter_mode == "live":
            return _live_params_required_error(request)
        else:
            transport = _resolve_fake_transport(host, request)
            if isinstance(transport, JSONResponse):
                return transport
            try:
                live_probe_result[profile_id] = _probe_with_transport(
                    transport,
                    wg_id,
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

    items: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        if row["is_active"] is not True:
            item.update(_inactive_live_fields())
        elif not row.get("assigned_wg_id"):
            item.update(
                {
                    "live_probed": False,
                    "live_tunnel_verification_status": None,
                    "probe_error": _PROBE_NO_WG_ERROR,
                    "observed_at": None,
                    "routed_through_tunnel": None,
                    "routing_probe_status": "not_applicable",
                }
            )
        else:
            probe_fields = live_probe_result.get(str(row["profile_id"]))
            if probe_fields is None:
                item.update(_inactive_live_fields())
            else:
                item.update(probe_fields)
        items.append(item)

    return JSONResponse({"items": items}, status_code=200, headers=_ok_headers(request))
