"""Wizard draft router enrollment — Gate A closed OK, no live probe.

Justification: Add-router wizard needs ``router_id`` + ``credential_ref_id`` before
bootstrap discovery and SSH host-key pin, but ``POST /routers`` returns
``gate.a_closed`` in live mode before vault/SQLite. This thin lab endpoint creates
vault credential + SQLite row without device writes, identity probe, or Gate A open.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from router_control.persistence.errors import IdempotencyConflict

from router_control_host.errors import error_response
from router_control_host.routes import API_PREFIX, _digest, _ok_headers, _require_idempotency
from router_control_host.state import HostState

router = APIRouter(prefix=API_PREFIX, tags=["wizard-draft"])


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class WizardDraftRouterBody(_StrictModel):
    host: str = Field(min_length=1)
    username: str = Field(min_length=1)
    secret: str = Field(min_length=1)
    display_name: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    allow_insecure_http: bool = False


def _state(request: Request) -> HostState:
    return request.app.state.host  # type: ignore[no-any-return]


def _wizard_draft_digest(body: dict[str, Any]) -> str:
    payload = {k: v for k, v in body.items() if k != "secret"}
    secret = body.get("secret")
    if secret:
        payload["secret_sha256"] = hashlib.sha256(str(secret).encode()).hexdigest()
    return _digest(payload)


def _parse_wizard_endpoint(
    raw_host: str,
    *,
    allow_insecure_http: bool,
    port: int | None,
) -> tuple[str, int, str]:
    stripped = raw_host.strip()
    if "://" in stripped:
        parsed = urlparse(stripped)
        hostname = parsed.hostname or stripped
        resolved_port = port
        if resolved_port is None:
            if parsed.port is not None:
                resolved_port = parsed.port
            elif parsed.scheme == "http":
                resolved_port = 80
            else:
                resolved_port = 443
        use_http = parsed.scheme == "http" or allow_insecure_http
    else:
        hostname = stripped
        resolved_port = port if port is not None else (80 if allow_insecure_http else 443)
        use_http = allow_insecure_http
    kind = "management_http" if use_http else "management_https"
    return hostname, resolved_port, kind


def _wizard_response_body(
    *,
    router_id: str,
    credential_ref_id: str,
    username: str,
    operation_id: str,
    job_id: str,
) -> dict[str, Any]:
    return {
        "router_id": router_id,
        "credential_ref_id": credential_ref_id,
        "username": username,
        "certification_eligible": False,
        "certification_status": "NotCertified",
        "gate_a_status": "closed",
        "lifecycle_status": "PendingEnrollment",
        "handoff_note": (
            "Draft enrollment only — Gate A not open; not ready for Wi-Fi management"
        ),
        "operation_id": operation_id,
        "links": {
            "operation": f"{API_PREFIX}/operations/{operation_id}",
            "job": f"{API_PREFIX}/jobs/{job_id}",
        },
    }


def _replay_from_outcome(outcome: Any) -> tuple[dict[str, Any], int]:
    stored = json.loads(outcome.response_ref or "{}")
    body = stored.get("body") or {}
    status = int(stored.get("http_status", 201))
    return body, status


@router.post("/lab/wizard-draft-router")
def wizard_draft_router(
    request: Request,
    body: WizardDraftRouterBody,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
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
    assert isinstance(key, str)
    body_dict = body.model_dump(mode="json")
    endpoint_host, endpoint_port, endpoint_kind = _parse_wizard_endpoint(
        body.host,
        allow_insecure_http=body.allow_insecure_http,
        port=body.port,
    )
    display_name = (body.display_name or "").strip() or f"Router at {endpoint_host}"
    digest = _wizard_draft_digest(body_dict)
    idem_key = key
    try:
        existing = host.runtime.store.peek_idempotency(
            operation_kind="enroll",
            idempotency_key=idem_key,
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
        replay_body, replay_status = _replay_from_outcome(existing)
        return JSONResponse(replay_body, status_code=replay_status, headers=_ok_headers(request))

    handle = host.runtime.vault.create(kind="RouterManagementPassword", secret=body.secret)
    site_id = host.ensure_default_site()
    try:
        router_id, outcome = host.runtime.store.enroll_router_with_operation(
            site_id=site_id,
            display_name=display_name,
            vendor="Keenetic",
            model="PendingDiscovery",
            identity_fingerprint="digest:wizard-draft:pending",
            host=endpoint_host,
            port=endpoint_port,
            kind=endpoint_kind,
            hardware_revision=None,
            credential_ref_id=handle.credential_ref_id,
            credential_kind=handle.kind,
            credential_provider=handle.provider,
            credential_provider_locator=handle.provider_locator,
            idempotency_key=idem_key,
            request_digest=digest,
            actor_id="hub_admin",
            correlation_id=request.state.correlation_id,
            now=host.runtime.clock.now(),
            defer_success_response=False,
        )
    except IdempotencyConflict:
        return error_response(
            request,
            status_code=409,
            code="idempotency.conflict",
            message="same key different digest",
        )

    if not outcome.created:
        replay_body, replay_status = _replay_from_outcome(outcome)
        return JSONResponse(replay_body, status_code=replay_status, headers=_ok_headers(request))

    host.runtime.store.set_endpoint_management_username(
        router_id,
        body.username.strip(),
        now=host.runtime.clock.now(),
    )

    response_body = _wizard_response_body(
        router_id=router_id,
        credential_ref_id=handle.credential_ref_id,
        username=body.username.strip(),
        operation_id=outcome.operation_id,
        job_id=outcome.job_id,
    )
    host.runtime.store.update_idempotency_response(
        outcome.idempotency_record_id,
        http_status=201,
        body=response_body,
    )
    return JSONResponse(response_body, status_code=201, headers=_ok_headers(request))
