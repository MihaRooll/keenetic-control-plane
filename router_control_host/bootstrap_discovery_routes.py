"""Bootstrap discovery API — non-certifying read-only lab observe."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from router_control.application.bootstrap_discovery import (
    BootstrapDiscoveryError,
    run_bootstrap_discovery,
)

from router_control_host.apply_response_models import BootstrapDiscoveryResponse
from router_control_host.errors import error_response
from router_control_host.routes import API_PREFIX, _ok_headers
from router_control_host.state import HostState

router = APIRouter(prefix=API_PREFIX, tags=["bootstrap-discovery"])


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class BootstrapDiscoveryBody(_StrictModel):
    host: str = Field(min_length=1)
    username: str = Field(min_length=1)
    credential_ref_id: str = Field(min_length=1)
    allow_insecure_http: bool


def _state(request: Request) -> HostState:
    return request.app.state.host  # type: ignore[no-any-return]


@router.post("/lab/bootstrap-discovery", response_model=BootstrapDiscoveryResponse)
def bootstrap_discovery(request: Request, body: BootstrapDiscoveryBody) -> JSONResponse:
    host = _state(request)
    try:
        report: dict[str, Any] = run_bootstrap_discovery(
            host=body.host.strip(),
            username=body.username.strip(),
            credential_ref_id=body.credential_ref_id.strip(),
            vault=host.runtime.vault,
            allow_insecure_http=body.allow_insecure_http,
        )
    except BootstrapDiscoveryError as exc:
        return error_response(
            request,
            status_code=422,
            code="bootstrap.discovery_failed",
            message=str(exc),
        )
    if report.get("certification_eligible") is not False:
        return error_response(
            request,
            status_code=500,
            code="internal.error",
            message="bootstrap discovery must remain non-certifying",
        )
    return JSONResponse(report, status_code=200, headers=_ok_headers(request))
