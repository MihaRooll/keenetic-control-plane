"""SSH host-key learn/confirm API for Add-router wizard (explicit TOFU)."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from router_control.adapters.netcraze.errors import SshTunnelError
from router_control.application.ssh_host_key_pin import (
    SshHostKeyPinConflict,
    confirm_pin,
    learn_candidate,
    record_pending_learn,
)
from router_control.persistence.errors import NotFoundError, PreconditionFailed

from router_control_host.errors import error_response
from router_control_host.routes import API_PREFIX, _ok_headers
from router_control_host.state import HostState
from router_control_host.wifi_live_transport import missing_connection_fields

router = APIRouter(prefix=API_PREFIX, tags=["ssh-host-key"])

_LEARN_NETWORK_FAILURE_MESSAGE = (
    "Could not reach the router to learn the SSH host key"
)

_OPERATOR_STATE_HEADERS = {
    "Cache-Control": "no-store",
    "Vary": "Cookie",
}


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SshHostKeyLearnBody(_StrictModel):
    host: str = Field(min_length=1)
    port: int = Field(default=22, ge=1, le=65535)
    source_address: str | None = None


class SshHostKeyConfirmBody(_StrictModel):
    fingerprint_sha256: str = Field(min_length=1)
    algorithm: str = Field(min_length=1)
    allow_overwrite: bool = False


class SshHostKeyContext(_StrictModel):
    confirmed: bool
    fingerprint_sha256: str | None = None
    algorithm: str | None = None
    pinned_at: str | None = None
    provenance: str | None = None


class ConnectionContextResponse(_StrictModel):
    router_id: str
    host: str | None = None
    port: int | None = None
    source_address: str | None = None
    credential_ref_id: str | None = None
    ssh_host_key: SshHostKeyContext
    username_available: bool
    live_ready: bool
    missing: list[str]


class NoRestoreCandidateResponse(_StrictModel):
    restore_candidate: Literal[False] = False


class RestoreCandidateConnectionContextResponse(ConnectionContextResponse):
    restore_candidate: Literal[True] = True


RestoreCandidateResult = Annotated[
    RestoreCandidateConnectionContextResponse | NoRestoreCandidateResponse,
    Field(discriminator="restore_candidate"),
]


class ManagementUsernameBody(_StrictModel):
    username: str = Field(min_length=1)


class ManagementUsernameResponse(_StrictModel):
    router_id: str
    username_available: bool = True


def _state(request: Request) -> HostState:
    return request.app.state.host  # type: ignore[no-any-return]


def _operator_state_headers(request: Request) -> dict[str, str]:
    return _ok_headers(request, _OPERATOR_STATE_HEADERS)


def _resolve_learn_source_address(
    host: HostState,
    router_id: str,
    body_source: str | None,
) -> str | None:
    """Resolve bind source: explicit body value, else stored endpoint for router."""
    if body_source and str(body_source).strip():
        return str(body_source).strip()
    endpoint = host.runtime.store.get_connection_binding_endpoint(router_id)
    if endpoint is not None and endpoint["source_address"]:
        return str(endpoint["source_address"]).strip()
    return None


def _connection_context_payload(
    host: HostState,
    router_id: str,
) -> ConnectionContextResponse | None:
    store = host.runtime.store
    row = store.get_router(router_id)
    if row is None:
        return None
    endpoint = store.get_connection_binding_endpoint(router_id)
    pin = store.get_endpoint_ssh_host_key(router_id)
    stored_username = store.get_endpoint_management_username(router_id)
    endpoint_host = str(endpoint["host"]) if endpoint is not None else None
    endpoint_port = int(endpoint["port"]) if endpoint is not None else None
    source_address = (
        str(endpoint["source_address"]).strip()
        if endpoint is not None and endpoint["source_address"]
        else None
    )
    credential_ref_id = row["credential_ref_id"]
    credential_ref_text = (
        str(credential_ref_id).strip() if credential_ref_id else None
    )
    missing = missing_connection_fields(
        host=endpoint_host,
        username=stored_username,
        router_credential_ref_id=credential_ref_text,
        ssh_host_key_sha256=pin.fingerprint_sha256 if pin is not None else None,
        router_id=router_id,
        store=store,
    )
    ssh_host_key = SshHostKeyContext(
        confirmed=pin is not None,
        fingerprint_sha256=pin.fingerprint_sha256 if pin is not None else None,
        algorithm=pin.algorithm if pin is not None else None,
        pinned_at=pin.pinned_at if pin is not None else None,
        provenance=pin.provenance if pin is not None else None,
    )
    return ConnectionContextResponse(
        router_id=router_id,
        host=endpoint_host,
        port=endpoint_port,
        source_address=source_address,
        credential_ref_id=credential_ref_text,
        ssh_host_key=ssh_host_key,
        username_available=stored_username is not None,
        live_ready=len(missing) == 0,
        missing=missing,
    )


@router.get(
    "/connection-context/restore-candidate",
    response_model=RestoreCandidateResult,
)
def get_restore_candidate_connection_context(
    request: Request,
    response: Response,
) -> RestoreCandidateConnectionContextResponse | NoRestoreCandidateResponse:
    """Return connection context for the best restorable router in one read."""
    host = _state(request)
    router_id = host.runtime.store.find_restore_candidate_router_id()
    if router_id is None:
        for key, value in _operator_state_headers(request).items():
            response.headers[key] = value
        return NoRestoreCandidateResponse()
    payload = _connection_context_payload(host, router_id)
    if payload is None or not payload.host:
        for key, value in _operator_state_headers(request).items():
            response.headers[key] = value
        return NoRestoreCandidateResponse()
    for key, value in _operator_state_headers(request).items():
        response.headers[key] = value
    return RestoreCandidateConnectionContextResponse(**payload.model_dump())


@router.get(
    "/routers/{router_id}/connection-context",
    response_model=ConnectionContextResponse,
)
def get_connection_context(
    router_id: str,
    request: Request,
    response: Response,
) -> ConnectionContextResponse | JSONResponse:
    """Read server-held live connection context for a router (no reachability claim)."""
    host = _state(request)
    payload = _connection_context_payload(host, router_id)
    if payload is None:
        return error_response(
            request,
            status_code=404,
            code="resource.not_found",
            message="router not found",
        )
    for key, value in _operator_state_headers(request).items():
        response.headers[key] = value
    return payload


@router.post(
    "/routers/{router_id}/management-username",
    response_model=ManagementUsernameResponse,
)
def set_management_username(
    router_id: str,
    request: Request,
    response: Response,
    body: ManagementUsernameBody,
) -> ManagementUsernameResponse | JSONResponse:
    """Persist management username on the pin-bound endpoint row (value never echoed)."""
    host = _state(request)
    store = host.runtime.store
    if store.get_router(router_id) is None:
        return error_response(
            request,
            status_code=404,
            code="resource.not_found",
            message="router not found",
        )
    try:
        store.set_endpoint_management_username(router_id, body.username.strip())
    except NotFoundError:
        return error_response(
            request,
            status_code=404,
            code="resource.not_found",
            message="router not found",
        )
    except PreconditionFailed as exc:
        return error_response(
            request,
            status_code=422,
            code="request.validation_failed",
            message=str(exc),
        )
    for key, value in _operator_state_headers(request).items():
        response.headers[key] = value
    return ManagementUsernameResponse(router_id=router_id, username_available=True)


@router.post("/routers/{router_id}/ssh-host-key/learn")
def ssh_host_key_learn(
    router_id: str,
    request: Request,
    body: SshHostKeyLearnBody,
) -> JSONResponse:
    host = _state(request)
    if host.runtime.store.get_router(router_id) is None:
        return error_response(
            request,
            status_code=404,
            code="router.not_found",
            message="router not found",
        )
    resolved_source = _resolve_learn_source_address(
        host,
        router_id,
        body.source_address,
    )
    if resolved_source is None:
        return error_response(
            request,
            status_code=422,
            code="ssh_host_key.learn_failed",
            message="source_address is required for bound SSH dial",
        )
    try:
        result = learn_candidate(
            body.host.strip(),
            port=body.port,
            source_address=resolved_source,
        )
    except SshTunnelError as exc:
        return error_response(
            request,
            status_code=422,
            code="ssh_host_key.learn_failed",
            message=str(exc),
        )
    except OSError:
        return error_response(
            request,
            status_code=422,
            code="ssh_host_key.learn_failed",
            message=_LEARN_NETWORK_FAILURE_MESSAGE,
        )
    payload: dict[str, Any] = {
        "fingerprint_sha256": result.fingerprint_sha256,
        "algorithm": result.algorithm,
        "warning": result.warning,
    }
    record_pending_learn(host.ssh_host_key_pending_learn, router_id, result)
    return JSONResponse(payload, status_code=200, headers=_ok_headers(request))


@router.post("/routers/{router_id}/ssh-host-key/confirm")
def ssh_host_key_confirm(
    router_id: str,
    request: Request,
    body: SshHostKeyConfirmBody,
) -> JSONResponse:
    host = _state(request)
    try:
        pinned = confirm_pin(
            host.runtime.store,
            router_id,
            body.fingerprint_sha256,
            body.algorithm,
            pending_registry=host.ssh_host_key_pending_learn,
            allow_overwrite=body.allow_overwrite,
        )
    except NotFoundError:
        return error_response(
            request,
            status_code=404,
            code="router.not_found",
            message="router not found",
        )
    except PreconditionFailed as exc:
        return error_response(
            request,
            status_code=422,
            code="ssh_host_key.invalid_pin",
            message=str(exc),
        )
    except SshHostKeyPinConflict as exc:
        return error_response(
            request,
            status_code=409,
            code="ssh_host_key.pin_conflict",
            message=str(exc),
            details=[
                {
                    "existing_fingerprint_sha256": exc.existing.fingerprint_sha256,
                    "existing_algorithm": exc.existing.algorithm,
                    "candidate_fingerprint_sha256": exc.candidate_fingerprint_sha256,
                    "candidate_algorithm": exc.candidate_algorithm,
                }
            ],
        )
    payload = {
        "fingerprint_sha256": pinned.fingerprint_sha256,
        "algorithm": pinned.algorithm,
        "pinned_at": pinned.pinned_at,
        "provenance": pinned.provenance,
    }
    return JSONResponse(payload, status_code=200, headers=_ok_headers(request))
