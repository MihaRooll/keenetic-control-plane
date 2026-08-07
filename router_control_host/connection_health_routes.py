"""Connection health API — fact-derived green/yellow/red summary."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict
from router_control.application.connection_health import (
    ConnectionHealthError,
    assess_connection_health,
)

from router_control_host.apply_response_models import ConnectionHealthResponse
from router_control_host.errors import error_response
from router_control_host.routes import API_PREFIX, _ok_headers
from router_control_host.state import HostState

router = APIRouter(prefix=API_PREFIX, tags=["connection-health"])


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ConnectionHealthBody(_StrictModel):
    router_id: str | None = None
    host: str | None = None
    source_address: str | None = None
    credential_ref_id: str | None = None
    ssh_host_key_sha256: str | None = None
    probe: bool = True


def _state(request: Request) -> HostState:
    return request.app.state.host  # type: ignore[no-any-return]


@router.post("/lab/connection-health", response_model=ConnectionHealthResponse)
def connection_health(request: Request, body: ConnectionHealthBody) -> JSONResponse:
    host = _state(request)
    try:
        report: dict[str, Any] = assess_connection_health(
            store=host.runtime.store,
            vault=host.runtime.vault,
            router_id=body.router_id.strip() if body.router_id else None,
            host=body.host.strip() if body.host else None,
            source_address=body.source_address.strip() if body.source_address else None,
            credential_ref_id=body.credential_ref_id.strip() if body.credential_ref_id else None,
            ssh_host_key_sha256=body.ssh_host_key_sha256.strip()
            if body.ssh_host_key_sha256
            else None,
            probe=body.probe,
            gate_a=host.gate_a_certification,
            probe_port=host.connection_health_probe_port,
        )
    except ConnectionHealthError as exc:
        return error_response(
            request,
            status_code=422,
            code="connection_health.failed",
            message=str(exc),
        )
    if report.get("certification_eligible") is not False:
        return error_response(
            request,
            status_code=500,
            code="internal.error",
            message="connection health must remain non-certifying",
        )
    return JSONResponse(report, status_code=200, headers=_ok_headers(request))
