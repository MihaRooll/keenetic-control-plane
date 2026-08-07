"""VLAN / DHCP / DNS / firewall preview API routes (read-only offline compile; no dispatch)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, StrictInt
from router_control.adapters.netcraze.allowlist import validate_interface_id
from router_control.adapters.netcraze.dhcp_rci import (
    validate_ipv4_address,
    validate_lease_seconds,
    validate_mac_address,
)
from router_control.adapters.netcraze.dns_rci import (
    validate_local_fqdn,
    validate_upstream_resolver,
)
from router_control.adapters.netcraze.rci_validation import RciValidationError
from router_control.adapters.netcraze.vlan_rci import validate_vlan_bridge_id
from router_control.application.dhcp_apply_planner import DhcpApplyPlannerError
from router_control.application.dhcp_apply_service import (
    DhcpApplyServiceError,
    preview_dhcp_apply,
)
from router_control.application.dns_apply_planner import DnsApplyPlannerError
from router_control.application.dns_apply_service import (
    DnsApplyServiceError,
    preview_dns_apply,
)
from router_control.application.firewall_apply_planner import FirewallApplyPlannerError
from router_control.application.firewall_apply_service import (
    FirewallApplyServiceError,
    preview_firewall_apply,
)
from router_control.application.vlan_apply_planner import VlanApplyPlannerError
from router_control.application.vlan_apply_service import (
    VlanApplyServiceError,
    preview_vlan_apply,
)
from router_control.domain.network_intents import (
    FirewallAction,
    FirewallDestinationFamily,
)

from router_control_host.apply_response_models import (
    DhcpPreviewResponse,
    DnsPreviewResponse,
    FirewallPreviewResponse,
    VlanPreviewResponse,
)
from router_control_host.errors import (
    error_response,
    operator_structured_error_response,
    rci_code_to_reason,
    synthesize_operator_message,
)
from router_control_host.routes import API_PREFIX, _ok_headers

router = APIRouter(prefix=API_PREFIX, tags=["network-family-preview"])

_DHCP_LEASE_MIN = 60
_DHCP_LEASE_MAX = 604_800
_VLAN_ID_MIN = 1
_VLAN_ID_MAX = 4094


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _validate_zone_id(zone_id: str) -> str:
    try:
        return validate_interface_id(zone_id)
    except ValueError as exc:
        raise RciValidationError(code="not_allowlisted", field="zone_id") from exc


class VlanPreviewBody(_StrictModel):
    bridge_id: str = Field(min_length=1, max_length=64)
    zone_id: str = Field(min_length=1, max_length=64)
    vlan_id: StrictInt = Field(ge=_VLAN_ID_MIN, le=_VLAN_ID_MAX)
    ipv4_cidr: str = Field(min_length=1)
    ipv4_gateway: str = Field(min_length=1)


class DhcpReservationBody(_StrictModel):
    mac_address: str = Field(min_length=1)
    ipv4_address: str = Field(min_length=1)


class DhcpPreviewBody(_StrictModel):
    zone_id: str = Field(min_length=1, max_length=64)
    pool_start: str = Field(min_length=1)
    pool_end: str = Field(min_length=1)
    lease_seconds: StrictInt = Field(ge=_DHCP_LEASE_MIN, le=_DHCP_LEASE_MAX)
    reservations: list[DhcpReservationBody]


class DnsPreviewBody(_StrictModel):
    zone_id: str = Field(min_length=1, max_length=64)
    local_fqdn: str = Field(min_length=1)
    upstream_resolvers: list[str] = Field(min_length=1)


class FirewallRuleBody(_StrictModel):
    action: FirewallAction
    destination_family: FirewallDestinationFamily
    ordinal: StrictInt = Field(ge=0)


class FirewallPreviewBody(_StrictModel):
    zone_id: str = Field(min_length=1, max_length=64)
    rules: list[FirewallRuleBody] = Field(min_length=1)


def _find_rci_validation_error(exc: BaseException) -> RciValidationError | None:
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, RciValidationError):
            return current
        current = current.__cause__ or current.__context__
    return None


def _preview_error(
    request: Request,
    *,
    code: str,
    exc: Exception,
) -> JSONResponse:
    rci_exc = exc if isinstance(exc, RciValidationError) else _find_rci_validation_error(exc)
    if rci_exc is not None:
        return operator_structured_error_response(
            request,
            status_code=422,
            code=code,
            reason=rci_code_to_reason(rci_exc.code),
            field=rci_exc.field,
        )
    return error_response(
        request,
        status_code=422,
        code=code,
        message=synthesize_operator_message(code=code, reason="preview_failed"),
    )


@router.post("/vlan/preview", response_model=VlanPreviewResponse)
def vlan_preview(request: Request, body: VlanPreviewBody) -> VlanPreviewResponse | JSONResponse:
    try:
        bridge_id = validate_vlan_bridge_id(body.bridge_id)
        zone_id = _validate_zone_id(body.zone_id)
        intent: dict[str, Any] = {
            "zone_id": zone_id,
            "vlan_id": body.vlan_id,
            "ipv4_cidr": body.ipv4_cidr,
            "ipv4_gateway": body.ipv4_gateway,
        }
        preview = preview_vlan_apply(intent, bridge_id)
    except (VlanApplyServiceError, VlanApplyPlannerError, ValueError) as exc:
        return _preview_error(request, code="vlan.preview_failed", exc=exc)

    return JSONResponse(
        VlanPreviewResponse.model_validate(preview).model_dump(),
        status_code=200,
        headers=_ok_headers(request),
    )


@router.post("/dhcp/preview", response_model=DhcpPreviewResponse)
def dhcp_preview(request: Request, body: DhcpPreviewBody) -> DhcpPreviewResponse | JSONResponse:
    try:
        zone_id = _validate_zone_id(body.zone_id)
        validate_lease_seconds(body.lease_seconds)
        reservations = [
            {
                "mac_address": validate_mac_address(entry.mac_address),
                "ipv4_address": validate_ipv4_address(entry.ipv4_address),
            }
            for entry in body.reservations
        ]
        intent: dict[str, Any] = {
            "zone_id": zone_id,
            "pool_start": body.pool_start,
            "pool_end": body.pool_end,
            "lease_seconds": body.lease_seconds,
            "reservations": reservations,
        }
        preview = preview_dhcp_apply(intent)
    except (DhcpApplyServiceError, DhcpApplyPlannerError, ValueError) as exc:
        return _preview_error(request, code="dhcp.preview_failed", exc=exc)

    return JSONResponse(
        DhcpPreviewResponse.model_validate(preview).model_dump(),
        status_code=200,
        headers=_ok_headers(request),
    )


@router.post("/dns/preview", response_model=DnsPreviewResponse)
def dns_preview(request: Request, body: DnsPreviewBody) -> DnsPreviewResponse | JSONResponse:
    try:
        zone_id = _validate_zone_id(body.zone_id)
        local_fqdn = validate_local_fqdn(body.local_fqdn)
        upstream_resolvers = [
            validate_upstream_resolver(resolver) for resolver in body.upstream_resolvers
        ]
        intent: dict[str, Any] = {
            "zone_id": zone_id,
            "local_fqdn": local_fqdn,
            "upstream_resolvers": upstream_resolvers,
        }
        preview = preview_dns_apply(intent)
    except (DnsApplyServiceError, DnsApplyPlannerError, ValueError) as exc:
        return _preview_error(request, code="dns.preview_failed", exc=exc)

    return JSONResponse(
        DnsPreviewResponse.model_validate(preview).model_dump(),
        status_code=200,
        headers=_ok_headers(request),
    )


@router.post("/firewall/preview", response_model=FirewallPreviewResponse)
def firewall_preview(
    request: Request, body: FirewallPreviewBody
) -> FirewallPreviewResponse | JSONResponse:
    try:
        zone_id = _validate_zone_id(body.zone_id)
        intent: dict[str, Any] = {
            "zone_id": zone_id,
            "rules": [rule.model_dump() for rule in body.rules],
        }
        preview = preview_firewall_apply(intent)
    except (FirewallApplyServiceError, FirewallApplyPlannerError, ValueError) as exc:
        return _preview_error(request, code="firewall.preview_failed", exc=exc)

    return JSONResponse(
        FirewallPreviewResponse.model_validate(preview).model_dump(),
        status_code=200,
        headers=_ok_headers(request),
    )
