"""VPN policy-routing preview API routes (read-only offline compile; no dispatch)."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, StrictInt
from router_control.adapters.netcraze.vpn_policy_rci import (
    IP_GLOBAL_BOUND_MAX,
    IP_GLOBAL_BOUND_MIN,
)
from router_control.application.vpn_policy_routing_planner import VpnPolicyRoutingPlannerError
from router_control.application.vpn_policy_routing_service import (
    VpnPolicyRoutingServiceError,
    preview_vpn_policy_routing,
)

from router_control_host.apply_response_models import VpnPolicyPreviewResponse
from router_control_host.errors import error_response, synthesize_operator_message
from router_control_host.routes import API_PREFIX, _ok_headers

router = APIRouter(prefix=API_PREFIX, tags=["vpn-policy-preview"])


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class VpnPolicyNameServerBody(_StrictModel):
    address: str = Field(min_length=1)
    domain: str | None = Field(default=None, min_length=1)
    on_interface: str | None = Field(default=None, min_length=1)


class VpnPolicyIpGlobalPriorityBody(_StrictModel):
    priority: StrictInt = Field(ge=IP_GLOBAL_BOUND_MIN, le=IP_GLOBAL_BOUND_MAX)


class VpnPolicyIpGlobalOrderBody(_StrictModel):
    order: StrictInt = Field(ge=IP_GLOBAL_BOUND_MIN, le=IP_GLOBAL_BOUND_MAX)


class VpnPolicyPreviewBody(_StrictModel):
    policy_name: str = Field(min_length=1, max_length=64)
    vpn_interface: str = Field(min_length=1, max_length=64)
    interface_kind: str | None = Field(default=None, min_length=1)
    address_configured: bool | None = None
    ip_global: Literal["auto"] | VpnPolicyIpGlobalPriorityBody | VpnPolicyIpGlobalOrderBody
    name_servers: list[VpnPolicyNameServerBody] | None = None


def _ip_global_to_intent(
    ip_global: Literal["auto"] | VpnPolicyIpGlobalPriorityBody | VpnPolicyIpGlobalOrderBody,
) -> str | dict[str, int]:
    if isinstance(ip_global, str):
        return ip_global
    if isinstance(ip_global, VpnPolicyIpGlobalPriorityBody):
        return {"priority": ip_global.priority}
    return {"order": ip_global.order}


@router.post(
    "/vpn/policy-routing/preview",
    response_model=VpnPolicyPreviewResponse,
)
def vpn_policy_routing_preview(
    request: Request, body: VpnPolicyPreviewBody
) -> VpnPolicyPreviewResponse | JSONResponse:
    try:
        intent: dict[str, Any] = {
            "policy_name": body.policy_name,
            "vpn_interface": body.vpn_interface,
            "ip_global": _ip_global_to_intent(body.ip_global),
        }
        if body.interface_kind is not None:
            intent["interface_kind"] = body.interface_kind
        if body.address_configured is not None:
            intent["address_configured"] = body.address_configured
        if body.name_servers is not None:
            intent["name_servers"] = [entry.model_dump() for entry in body.name_servers]
        preview = preview_vpn_policy_routing(intent)
    except (VpnPolicyRoutingServiceError, VpnPolicyRoutingPlannerError, ValueError) as exc:
        _ = exc
        return error_response(
            request,
            status_code=422,
            code="vpn.policy_routing_preview_failed",
            message=synthesize_operator_message(
                code="vpn.policy_routing_preview_failed",
                reason="preview_failed",
            ),
        )

    return JSONResponse(
        VpnPolicyPreviewResponse.model_validate(preview).model_dump(),
        status_code=200,
        headers=_ok_headers(request),
    )
