"""Router discovery API — bounded local candidate enumeration."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict
from router_control.application.router_discovery import (
    RouterDiscoveryError,
    run_router_discovery,
)

from router_control_host.apply_response_models import RouterDiscoveryResponse
from router_control_host.errors import error_response
from router_control_host.host_route_table import platform_host_route_table
from router_control_host.routes import API_PREFIX, _ok_headers
from router_control_host.state import HostState

router = APIRouter(prefix=API_PREFIX, tags=["router-discovery"])


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RouterDiscoveryBody(_StrictModel):
    include_default_gateway: bool = True
    include_known_endpoints: bool = True
    preferred_source_address: str | None = None
    probe: bool = False


def _state(request: Request) -> HostState:
    return request.app.state.host  # type: ignore[no-any-return]


@router.post("/lab/router-discovery", response_model=RouterDiscoveryResponse)
def router_discovery(request: Request, body: RouterDiscoveryBody) -> JSONResponse:
    host = _state(request)
    try:
        report: dict[str, Any] = run_router_discovery(
            store=host.runtime.store,
            include_default_gateway=body.include_default_gateway,
            include_known_endpoints=body.include_known_endpoints,
            preferred_source_address=body.preferred_source_address,
            probe=body.probe,
            route_table=platform_host_route_table(),
            identity_probe=host.router_discovery_identity_probe,
            gate_a=host.gate_a_certification,
            vault=host.runtime.vault,
        )
    except RouterDiscoveryError as exc:
        return error_response(
            request,
            status_code=422,
            code="router_discovery.failed",
            message=str(exc),
        )
    if report.get("certification_eligible") is not False:
        return error_response(
            request,
            status_code=500,
            code="internal.error",
            message="router discovery must remain non-certifying",
        )
    return JSONResponse(report, status_code=200, headers=_ok_headers(request))
