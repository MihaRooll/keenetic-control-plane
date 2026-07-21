"""APIRouter /api/router-control/v1 — contract-aligned core routes.

Apply (`POST .../plans/{plan_id}/apply`) is fail-closed by default (403
``gate.mutation_forbidden``). When ``RC_ALLOW_FAKE_MUTATIONS=1`` (tests/simulation
only), apply enqueues durable jobs against the offline FakeAdapter composition —
never live router I/O; hardware gates A–D remain closed.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from typing import Any

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse
from router_control.adapters.secrets.memory import VaultError
from router_control.persistence.errors import (
    ConflictError,
    IdempotencyConflict,
    NotFoundError,
    PreconditionFailed,
)
from router_control.persistence.store import etag_for_plan, etag_for_revision

from router_control_host.errors import error_body, error_response
from router_control_host.state import HostState

API_PREFIX = "/api/router-control/v1"
router = APIRouter(prefix=API_PREFIX)


def _state(request: Request) -> HostState:
    return request.app.state.host  # type: ignore[no-any-return]


def _require_idempotency(key: str | None) -> str | JSONResponse:
    if not key or not key.strip() or len(key) > 128:
        return "missing"
    return key.strip()


def _digest(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(raw.encode()).hexdigest()


def _fail_op_on_vault_error(
    host: HostState,
    request: Request,
    outcome: Any,
    exc: VaultError,
) -> JSONResponse:
    msg = str(exc)
    if "not found" in msg:
        status, code = 404, "resource.not_found"
    else:
        status, code = 400, "request.validation_failed"
    request_id = getattr(request.state, "request_id", "req_unknown")
    correlation_id = getattr(request.state, "correlation_id", request_id)
    body = error_body(
        code=code,
        message=msg,
        request_id=request_id,
        correlation_id=correlation_id,
    )
    host.runtime.store.fail_accepted_operation_bundle(
        operation_id=outcome.operation_id,
        job_id=outcome.job_id,
        idempotency_record_id=outcome.idempotency_record_id,
        http_status=status,
        error_body=body,
        now=host.runtime.clock.now(),
    )
    return error_response(request, status_code=status, code=code, message=msg)


def _ok_headers(request: Request, extra: dict[str, str] | None = None) -> dict[str, str]:
    headers = {
        "X-Request-Id": request.state.request_id,
        "X-Correlation-Id": request.state.correlation_id,
    }
    if extra:
        headers.update(extra)
    return headers


@router.get("/status")
def get_status(request: Request) -> JSONResponse:
    host = _state(request)
    total = len(host.runtime.store.list_routers(limit=200))
    body = {
        "feature_state": host.feature_state,
        "hub_available": True,
        "database_state": "Ok",
        "worker_state": "Stopped",
        "routers_summary": {"total": total, "enrolled": total, "degraded": 0},
        "links": {"routers": f"{API_PREFIX}/routers"},
    }
    return JSONResponse(body, headers=_ok_headers(request))


@router.get("/routers")
def list_routers(request: Request) -> JSONResponse:
    host = _state(request)
    items = []
    for row in host.runtime.store.list_routers():
        items.append(
            {
                "router_id": row["router_id"],
                "display_name": row["display_name"],
                "vendor": row["vendor"],
                "model": row["model"],
                "lifecycle_status": row["lifecycle_status"],
                "certification_status": "Unknown",
                "updated_at": row["updated_at"],
            }
        )
    return JSONResponse(
        {"items": items, "next_cursor": None, "limit": 50},
        headers=_ok_headers(request),
    )


@router.post("/routers")
async def enroll_router(
    request: Request,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> JSONResponse:
    host = _state(request)
    if isinstance(_require_idempotency(idempotency_key), str) and not (
        idempotency_key and idempotency_key.strip()
    ):
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="Idempotency-Key required",
        )
    assert idempotency_key is not None
    body = await request.json()
    unknown = set(body) - {
        "site_id",
        "display_name",
        "vendor",
        "model",
        "hardware_revision",
        "endpoint",
        "management_password",
    }
    if unknown:
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="Unknown fields",
        )
    password = body.get("management_password")
    if not password:
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="management_password required",
        )
    site_id = body.get("site_id") or host.ensure_default_site()
    endpoint = body.get("endpoint") or {}
    digest = _digest(
        {
            **{k: v for k, v in body.items() if k != "management_password"},
            "management_password_sha256": hashlib.sha256(password.encode()).hexdigest(),
        }
    )
    key = idempotency_key.strip()
    # Idempotency before any vault/SQLite side effects (enroll has no router_id yet).
    try:
        existing = host.runtime.store.peek_idempotency(
            operation_kind="enroll",
            idempotency_key=key,
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
        stored = json.loads(existing.response_ref or "{}")
        body_out = stored.get("body")
        if not body_out:
            op_row = host.runtime.store.get_operation(existing.operation_id)
            body_out = {
                "operation_id": existing.operation_id,
                "job_id": existing.job_id,
                "status": "Queued",
                "router_id": op_row["router_id"] if op_row else None,
            }
        return JSONResponse(
            body_out,
            status_code=int(stored.get("http_status", 202)),
            headers=_ok_headers(
                request,
                {"Location": f"{API_PREFIX}/operations/{existing.operation_id}"},
            ),
        )

    handle = host.runtime.vault.create(kind="RouterManagementPassword", secret=password)
    try:
        router_id, outcome = host.runtime.store.enroll_router_with_operation(
            site_id=site_id,
            display_name=body["display_name"],
            vendor=body["vendor"],
            model=body["model"],
            identity_fingerprint=(
                "digest:enroll:"
                + hashlib.sha256(router_seed(body).encode()).hexdigest()[:16]
            ),
            host=endpoint.get("host", "127.0.0.1"),
            port=int(endpoint.get("port", 443)),
            kind=endpoint.get("kind", "management_https"),
            hardware_revision=body.get("hardware_revision"),
            credential_ref_id=handle.credential_ref_id,
            credential_kind=handle.kind,
            credential_provider=handle.provider,
            credential_provider_locator=handle.provider_locator,
            idempotency_key=key,
            request_digest=digest,
            actor_id="hub_admin",
            correlation_id=request.state.correlation_id,
            now=host.runtime.clock.now(),
        )
    except IdempotencyConflict:
        host.runtime.vault.delete(handle.credential_ref_id)
        return error_response(
            request,
            status_code=409,
            code="idempotency.conflict",
            message="same key different digest",
        )
    except Exception:
        host.runtime.vault.delete(handle.credential_ref_id)
        raise

    if not outcome.created:
        host.runtime.vault.delete(handle.credential_ref_id)
        stored = json.loads(outcome.response_ref or "{}")
        body_out = stored.get("body") or {}
        return JSONResponse(
            body_out,
            status_code=int(stored.get("http_status", 202)),
            headers=_ok_headers(
                request,
                {"Location": f"{API_PREFIX}/operations/{outcome.operation_id}"},
            ),
        )

    accepted = json.loads(outcome.response_ref or "{}").get("body") or {
        "operation_id": outcome.operation_id,
        "job_id": outcome.job_id,
        "status": "Queued",
        "router_id": router_id,
        "links": {
            "operation": f"{API_PREFIX}/operations/{outcome.operation_id}",
            "job": f"{API_PREFIX}/jobs/{outcome.job_id}",
        },
    }
    return JSONResponse(
        accepted,
        status_code=202,
        headers=_ok_headers(
            request,
            {"Location": f"{API_PREFIX}/operations/{outcome.operation_id}"},
        ),
    )


def router_seed(body: dict[str, Any]) -> str:
    return f"{body.get('display_name')}:{body.get('vendor')}:{body.get('model')}"


@router.get("/routers/{router_id}")
def get_router(router_id: str, request: Request) -> JSONResponse:
    host = _state(request)
    row = host.runtime.store.get_router(router_id)
    if row is None:
        return error_response(
            request, status_code=404, code="resource.not_found", message="router not found"
        )
    rev = host.runtime.store.get_desired_revision(router_id)
    return JSONResponse(
        {
            "router_id": row["router_id"],
            "display_name": row["display_name"],
            "vendor": row["vendor"],
            "model": row["model"],
            "site_id": row["site_id"],
            "hardware_revision": row["hardware_revision"],
            "identity_fingerprint": row["identity_fingerprint"],
            "lifecycle_status": row["lifecycle_status"],
            "certification_status": "Unknown",
            "endpoints": [],
            "current_desired_revision_id": rev["revision_id"] if rev else None,
            "applied_revision_id": None,
            "reconcile_status": "Unknown",
            "updated_at": row["updated_at"],
        },
        headers=_ok_headers(request),
    )


@router.get("/routers/{router_id}/credentials")
def list_credentials(router_id: str, request: Request) -> JSONResponse:
    host = _state(request)
    if host.runtime.store.get_router(router_id) is None:
        return error_response(
            request, status_code=404, code="resource.not_found", message="router not found"
        )
    items = []
    for row in host.runtime.store.list_credential_refs(router_id):
        items.append(
            {
                "credential_ref_id": row["credential_ref_id"],
                "kind": row["kind"],
                "provider": row["provider"],
                "created_at": row["created_at"],
                "rotated_at": row["rotated_at"],
                "revoked_at": row["revoked_at"],
            }
        )
    return JSONResponse({"items": items}, headers=_ok_headers(request))


@router.put("/routers/{router_id}/credentials")
async def put_credential(
    router_id: str,
    request: Request,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> JSONResponse:
    host = _state(request)
    if not idempotency_key or not idempotency_key.strip():
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="Idempotency-Key required",
        )
    if host.runtime.store.get_router(router_id) is None:
        return error_response(
            request, status_code=404, code="resource.not_found", message="router not found"
        )
    body = await request.json()
    secret = body.get("secret")
    kind = body.get("kind", "RouterManagementPassword")
    if not secret:
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="secret required",
        )
    digest = _digest(
        {
            "kind": kind,
            "secret_sha256": hashlib.sha256(secret.encode()).hexdigest(),
        }
    )
    key = idempotency_key.strip()
    try:
        existing = host.runtime.store.peek_idempotency(
            router_id=router_id,
            operation_kind="put_credential",
            idempotency_key=key,
            request_digest=digest,
        )
    except IdempotencyConflict:
        return error_response(
            request,
            status_code=409,
            code="idempotency.conflict",
            message="same key different digest",
        )
    if existing is not None and existing.response_ref:
        stored = json.loads(existing.response_ref)
        return JSONResponse(
            stored.get("body", stored),
            status_code=int(stored.get("http_status", 201)),
            headers=_ok_headers(request),
        )

    created_at = host.runtime.clock.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    handle = host.runtime.vault.create(kind=kind, secret=secret)
    try:
        outcome = host.runtime.store.put_credential_with_operation(
            router_id=router_id,
            credential_ref_id=handle.credential_ref_id,
            kind=handle.kind,
            provider=handle.provider,
            provider_locator=handle.provider_locator,
            idempotency_key=key,
            request_digest=digest,
            actor_id="hub_admin",
            response_body={"kind": kind, "created_at": created_at},
            now=host.runtime.clock.now(),
        )
    except IdempotencyConflict:
        host.runtime.vault.delete(handle.credential_ref_id)
        return error_response(
            request,
            status_code=409,
            code="idempotency.conflict",
            message="same key different digest",
        )
    except Exception:
        host.runtime.vault.delete(handle.credential_ref_id)
        raise

    if not outcome.created:
        host.runtime.vault.delete(handle.credential_ref_id)
        stored = json.loads(outcome.response_ref or "{}")
        return JSONResponse(
            stored.get("body", stored),
            status_code=int(stored.get("http_status", 201)),
            headers=_ok_headers(request),
        )
    stored = json.loads(outcome.response_ref or "{}")
    return JSONResponse(
        stored.get("body")
        or {
            "credential_ref_id": handle.credential_ref_id,
            "kind": kind,
            "created_at": created_at,
        },
        status_code=201,
        headers=_ok_headers(request),
    )


@router.post("/routers/{router_id}/credentials/{credential_ref_id}/rotate")
async def rotate_credential(
    router_id: str,
    credential_ref_id: str,
    request: Request,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> JSONResponse:
    host = _state(request)
    if not idempotency_key or not idempotency_key.strip():
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="Idempotency-Key required",
        )
    body = await request.json()
    secret = body.get("secret")
    if not secret:
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="secret required",
        )
    key = idempotency_key.strip()
    digest = _digest(
        {
            "credential_ref_id": credential_ref_id,
            "secret_sha256": hashlib.sha256(secret.encode()).hexdigest(),
        }
    )
    try:
        existing = host.runtime.store.peek_idempotency(
            router_id=router_id,
            operation_kind="rotate_credential",
            idempotency_key=key,
            request_digest=digest,
        )
    except IdempotencyConflict:
        return error_response(
            request,
            status_code=409,
            code="idempotency.conflict",
            message="same key different digest",
        )
    if existing is not None:
        stored = json.loads(existing.response_ref or "{}")
        body_out = stored.get("body") or {
            "operation_id": existing.operation_id,
            "job_id": existing.job_id,
            "status": "Queued",
            "links": {
                "operation": f"{API_PREFIX}/operations/{existing.operation_id}",
                "job": f"{API_PREFIX}/jobs/{existing.job_id}",
            },
        }
        return JSONResponse(
            body_out,
            status_code=int(stored.get("http_status", 202)),
            headers=_ok_headers(request),
        )

    # Claim idempotency before vault mutate (API §4.3/§7.5): conflict must not
    # touch secrets. create_operation_bundle uses BEGIN IMMEDIATE + UNIQUE key.
    try:
        outcome = host.runtime.store.create_operation_bundle(
            router_id=router_id,
            operation_kind="rotate_credential",
            idempotency_key=key,
            request_digest=digest,
            actor_id="hub_admin",
            initial_job_status="Queued",
            response_ref=json.dumps(
                {
                    "status": "Queued",
                }
            ),
            http_status=202,
            now=host.runtime.clock.now(),
        )
    except IdempotencyConflict:
        return error_response(
            request,
            status_code=409,
            code="idempotency.conflict",
            message="same key different digest",
        )
    accepted = {
        "operation_id": outcome.operation_id,
        "job_id": outcome.job_id,
        "status": "Queued",
        "links": {
            "operation": f"{API_PREFIX}/operations/{outcome.operation_id}",
            "job": f"{API_PREFIX}/jobs/{outcome.job_id}",
        },
    }
    if not outcome.created:
        if outcome.response_ref:
            stored = json.loads(outcome.response_ref)
            return JSONResponse(
                stored.get("body", accepted),
                status_code=int(stored.get("http_status", 202)),
                headers=_ok_headers(request),
            )
        return JSONResponse(accepted, status_code=202, headers=_ok_headers(request))

    try:
        host.runtime.vault.rotate(credential_ref_id, secret=secret)
    except VaultError as exc:
        return _fail_op_on_vault_error(host, request, outcome, exc)
    host.runtime.store.mark_credential_rotated(credential_ref_id, now=host.runtime.clock.now())
    host.runtime.store.update_idempotency_response(
        outcome.idempotency_record_id, http_status=202, body=accepted
    )
    return JSONResponse(accepted, status_code=202, headers=_ok_headers(request))


@router.post("/routers/{router_id}/credentials/{credential_ref_id}/revoke")
async def revoke_credential(
    router_id: str,
    credential_ref_id: str,
    request: Request,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> JSONResponse:
    host = _state(request)
    if not idempotency_key or not idempotency_key.strip():
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="Idempotency-Key required",
        )
    key = idempotency_key.strip()
    digest = _digest({"credential_ref_id": credential_ref_id})
    try:
        existing = host.runtime.store.peek_idempotency(
            router_id=router_id,
            operation_kind="revoke_credential",
            idempotency_key=key,
            request_digest=digest,
        )
    except IdempotencyConflict:
        return error_response(
            request,
            status_code=409,
            code="idempotency.conflict",
            message="same key different digest",
        )
    if existing is not None:
        stored = json.loads(existing.response_ref or "{}")
        body_out = stored.get("body") or {
            "operation_id": existing.operation_id,
            "job_id": existing.job_id,
            "status": "Queued",
            "links": {
                "operation": f"{API_PREFIX}/operations/{existing.operation_id}",
                "job": f"{API_PREFIX}/jobs/{existing.job_id}",
            },
        }
        return JSONResponse(
            body_out,
            status_code=int(stored.get("http_status", 202)),
            headers=_ok_headers(request),
        )

    # Claim before vault revoke — same critical-section rule as rotate.
    try:
        outcome = host.runtime.store.create_operation_bundle(
            router_id=router_id,
            operation_kind="revoke_credential",
            idempotency_key=key,
            request_digest=digest,
            actor_id="hub_admin",
            initial_job_status="Queued",
            http_status=202,
            now=host.runtime.clock.now(),
        )
    except IdempotencyConflict:
        return error_response(
            request,
            status_code=409,
            code="idempotency.conflict",
            message="same key different digest",
        )
    accepted = {
        "operation_id": outcome.operation_id,
        "job_id": outcome.job_id,
        "status": "Queued",
        "links": {
            "operation": f"{API_PREFIX}/operations/{outcome.operation_id}",
            "job": f"{API_PREFIX}/jobs/{outcome.job_id}",
        },
    }
    if not outcome.created:
        if outcome.response_ref:
            stored = json.loads(outcome.response_ref)
            return JSONResponse(
                stored.get("body", accepted),
                status_code=int(stored.get("http_status", 202)),
                headers=_ok_headers(request),
            )
        return JSONResponse(accepted, status_code=202, headers=_ok_headers(request))

    try:
        host.runtime.vault.revoke(credential_ref_id)
    except VaultError as exc:
        return _fail_op_on_vault_error(host, request, outcome, exc)
    host.runtime.store.mark_credential_revoked(credential_ref_id, now=host.runtime.clock.now())
    host.runtime.store.update_idempotency_response(
        outcome.idempotency_record_id, http_status=202, body=accepted
    )
    return JSONResponse(accepted, status_code=202, headers=_ok_headers(request))


@router.get("/vpn-profiles")
def list_profiles(request: Request) -> JSONResponse:
    host = _state(request)
    items = []
    for row in host.runtime.store.list_profiles():
        items.append(
            {
                "profile_id": row["profile_id"],
                "display_name": row["display_name"],
                "vpn_kind": row["vpn_kind"],
                "validation_status": row["validation_status"],
                "content_digest": row["content_digest"],
                "created_at": row["created_at"],
            }
        )
    return JSONResponse(
        {"items": items, "next_cursor": None, "limit": 50},
        headers=_ok_headers(request),
    )


@router.post("/vpn-profiles/import")
async def import_profile(
    request: Request,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> JSONResponse:
    host = _state(request)
    if not idempotency_key or not idempotency_key.strip():
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="Idempotency-Key required",
        )
    body = await request.json()
    # Write-only secrets never echoed
    private_key = body.pop("private_key", None)
    body.pop("preshared_key", None)
    vpn_kind = body.get("vpn_kind", "AmneziaWG")
    if vpn_kind != "AmneziaWG":
        return error_response(
            request,
            status_code=422,
            code="profile.validation_failed",
            message="Only AmneziaWG supported in v1",
        )
    doc = body.get("profile_document") or {}
    content_digest = "sha256:" + hashlib.sha256(
        json.dumps(doc, sort_keys=True).encode()
    ).hexdigest()
    key = idempotency_key.strip()
    digest = _digest({"display_name": body["display_name"], "digest": content_digest})
    site = host.ensure_default_site()
    sentinel = _ensure_catalog_router(host, site)
    try:
        existing = host.runtime.store.peek_idempotency(
            router_id=sentinel,
            operation_kind="import_profile",
            idempotency_key=key,
            request_digest=digest,
        )
    except IdempotencyConflict:
        return error_response(
            request,
            status_code=409,
            code="idempotency.conflict",
            message="same key different digest",
        )
    if existing is not None and existing.response_ref:
        stored = json.loads(existing.response_ref)
        return JSONResponse(
            stored.get("body", stored),
            status_code=int(stored.get("http_status", 201)),
            headers=_ok_headers(request),
        )

    # Claim idempotency before profile catalog / vault mutate (API §4.3/§7.3).
    try:
        outcome = host.runtime.store.create_operation_bundle(
            router_id=sentinel,
            operation_kind="import_profile",
            idempotency_key=key,
            request_digest=digest,
            actor_id="hub_admin",
            correlation_id=request.state.correlation_id,
            initial_job_status="Queued",
            http_status=202,
            response_ref=json.dumps({"status": "InProgress"}),
            now=host.runtime.clock.now(),
        )
    except IdempotencyConflict:
        return error_response(
            request,
            status_code=409,
            code="idempotency.conflict",
            message="same key different digest",
        )
    if not outcome.created:
        stored = json.loads(outcome.response_ref or "{}")
        return JSONResponse(
            stored.get("body", stored),
            status_code=int(stored.get("http_status", 201)),
            headers=_ok_headers(request),
        )

    if private_key:
        host.runtime.vault.create(kind="VpnPrivateKey", secret=private_key)
    profile_id = host.runtime.store.import_profile(
        display_name=body["display_name"],
        vpn_kind=vpn_kind,
        content_digest=content_digest,
        now=host.runtime.clock.now(),
    )
    created_at = host.runtime.clock.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    response_body = {
        "profile_id": profile_id,
        "display_name": body["display_name"],
        "vpn_kind": vpn_kind,
        "parser_version": "1",
        "content_digest": content_digest,
        "validation_status": "Valid",
        "unsupported_fields": [],
        "credential_refs": [],
        "created_at": created_at,
    }
    host.runtime.store.update_idempotency_response(
        outcome.idempotency_record_id, http_status=201, body=response_body
    )
    return JSONResponse(
        response_body,
        status_code=201,
        headers=_ok_headers(request),
    )


def _ensure_catalog_router(host: HostState, site_id: str) -> str:
    for row in host.runtime.store.list_routers(limit=200):
        if row["display_name"] == "__catalog__":
            return str(row["router_id"])
    return host.runtime.store.enroll_router(
        site_id=site_id,
        display_name="__catalog__",
        vendor="Catalog",
        model="None",
        identity_fingerprint="digest:catalog",
        host="127.0.0.1",
        now=host.runtime.clock.now(),
    )


@router.get("/routers/{router_id}/desired-revision")
def get_desired(router_id: str, request: Request) -> JSONResponse:
    host = _state(request)
    rev = host.runtime.store.get_desired_revision(router_id)
    if rev is None:
        return error_response(
            request, status_code=404, code="resource.not_found", message="no desired revision"
        )
    etag = etag_for_revision(rev["revision_id"], rev["canonical_digest"])
    return JSONResponse(
        {
            "revision_id": rev["revision_id"],
            "router_id": rev["router_id"],
            "revision_number": rev["revision_number"],
            "canonical_digest": rev["canonical_digest"],
            "etag": etag,
            "based_on_observation_id": rev["based_on_observation_id"],
            "assignments": [],
            "created_at": rev["created_at"],
            "desired_document": json.loads(rev["desired_document_json"] or "{}"),
        },
        headers=_ok_headers(request, {"ETag": etag}),
    )


@router.put("/routers/{router_id}/desired-revision")
async def put_desired(
    router_id: str,
    request: Request,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    if_match: str | None = Header(default=None, alias="If-Match"),
) -> JSONResponse:
    host = _state(request)
    if not idempotency_key or not idempotency_key.strip():
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="Idempotency-Key required",
        )
    if if_match is None:
        return error_response(
            request,
            status_code=428,
            code="precondition.required",
            message="If-Match required",
        )
    body = await request.json()
    try:
        rev_id, etag, number = host.runtime.store.put_desired_revision(
            router_id=router_id,
            canonical_digest=_digest(body),
            based_on_observation_id=body["based_on_observation_id"],
            if_match=if_match,
            desired_document_json=json.dumps({"assignments": body.get("assignments", [])}),
            actor_id="hub_admin",
            reason=body.get("reason"),
            now=host.runtime.clock.now(),
        )
    except PreconditionFailed as exc:
        return error_response(
            request,
            status_code=412,
            code="revision.precondition_failed",
            message=str(exc),
        )
    host.runtime.store.create_operation_bundle(
        router_id=router_id,
        operation_kind="put_desired_revision",
        idempotency_key=idempotency_key.strip(),
        request_digest=_digest(body),
        actor_id="hub_admin",
        initial_job_status="Succeeded",
        http_status=200,
        now=host.runtime.clock.now(),
    )
    return JSONResponse(
        {
            "revision_id": rev_id,
            "router_id": router_id,
            "revision_number": number,
            "canonical_digest": _digest(body),
            "etag": etag,
            "based_on_observation_id": body["based_on_observation_id"],
            "assignments": body.get("assignments", []),
            "created_at": host.runtime.clock.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "desired_document": {"assignments": body.get("assignments", [])},
        },
        headers=_ok_headers(request, {"ETag": etag}),
    )


@router.post("/routers/{router_id}/plans")
async def create_plan(
    router_id: str,
    request: Request,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    if_match: str | None = Header(default=None, alias="If-Match"),
) -> JSONResponse:
    host = _state(request)
    if not idempotency_key or not idempotency_key.strip():
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="Idempotency-Key required",
        )
    if if_match is None:
        return error_response(
            request,
            status_code=428,
            code="precondition.required",
            message="If-Match required",
        )
    body = await request.json()
    try:
        plan_id, etag = host.runtime.store.create_plan(
            router_id=router_id,
            revision_id=body["revision_id"],
            observation_id=body["observation_id"],
            if_match=if_match,
            actor_id="hub_admin",
            now=host.runtime.clock.now(),
        )
    except PreconditionFailed as exc:
        return error_response(
            request,
            status_code=412,
            code="plan.precondition_failed",
            message=str(exc),
        )
    except (ConflictError, NotFoundError) as exc:
        return error_response(
            request, status_code=409, code="plan.stale", message=str(exc)
        )
    plan = host.runtime.store.get_plan(plan_id)
    assert plan is not None
    host.runtime.store.create_operation_bundle(
        router_id=router_id,
        operation_kind="create_plan",
        idempotency_key=idempotency_key.strip(),
        request_digest=_digest(body),
        plan_id=plan_id,
        actor_id="hub_admin",
        initial_job_status="Succeeded",
        http_status=201,
        now=host.runtime.clock.now(),
    )
    return JSONResponse(
        {
            "plan_id": plan_id,
            "router_id": router_id,
            "revision_id": plan["revision_id"],
            "observation_id": plan["observation_id"],
            "plan_digest": plan["plan_digest"],
            "confirmation_state": plan["confirmation_state"],
            "expires_at": plan["expires_at"],
            "risk_class": plan["risk_class"],
            "requires_backup": bool(plan["requires_backup"]),
            "requires_fail_safe": bool(plan["requires_fail_safe"]),
            "changes": [{"ordinal": 0, "change_kind": "ensure-assignment", "summary": "offline"}],
            "etag": etag,
        },
        status_code=201,
        headers=_ok_headers(request, {"ETag": etag}),
    )


@router.get("/routers/{router_id}/plans/{plan_id}")
def get_plan(router_id: str, plan_id: str, request: Request) -> JSONResponse:
    host = _state(request)
    plan = host.runtime.store.get_plan(plan_id)
    if plan is None or plan["router_id"] != router_id:
        return error_response(
            request, status_code=404, code="resource.not_found", message="plan not found"
        )
    etag = etag_for_plan(plan_id, plan["plan_digest"])
    return JSONResponse(
        {
            "plan_id": plan_id,
            "router_id": router_id,
            "revision_id": plan["revision_id"],
            "observation_id": plan["observation_id"],
            "plan_digest": plan["plan_digest"],
            "confirmation_state": plan["confirmation_state"],
            "expires_at": plan["expires_at"],
            "risk_class": plan["risk_class"],
            "requires_backup": bool(plan["requires_backup"]),
            "requires_fail_safe": bool(plan["requires_fail_safe"]),
            "changes": [],
            "etag": etag,
            "confirmed_at": plan["confirmed_at"],
        },
        headers=_ok_headers(request, {"ETag": etag}),
    )


@router.post("/routers/{router_id}/plans/{plan_id}/confirm")
async def confirm_plan(
    router_id: str,
    plan_id: str,
    request: Request,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    if_match: str | None = Header(default=None, alias="If-Match"),
) -> JSONResponse:
    host = _state(request)
    if not idempotency_key or not idempotency_key.strip():
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="Idempotency-Key required",
        )
    if if_match is None:
        return error_response(
            request,
            status_code=428,
            code="precondition.required",
            message="If-Match required",
        )
    body = await request.json()
    if not body.get("risk_acknowledged"):
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="risk_acknowledged must be true",
        )
    try:
        plan = host.runtime.store.confirm_plan(
            plan_id=plan_id,
            plan_digest=body["plan_digest"],
            if_match=if_match,
            actor_id="hub_admin",
            now=host.runtime.clock.now(),
        )
    except PreconditionFailed as exc:
        return error_response(
            request,
            status_code=412,
            code="plan.precondition_failed",
            message=str(exc),
        )
    except ConflictError as exc:
        code = "plan.expired" if "expired" in str(exc) else "plan.stale"
        return error_response(request, status_code=409, code=code, message=str(exc))
    etag = etag_for_plan(plan_id, plan["plan_digest"])
    host.runtime.store.create_operation_bundle(
        router_id=router_id,
        operation_kind="confirm_plan",
        idempotency_key=idempotency_key.strip(),
        request_digest=_digest(body),
        plan_id=plan_id,
        actor_id="hub_admin",
        initial_job_status="Succeeded",
        http_status=200,
        now=host.runtime.clock.now(),
    )
    return JSONResponse(
        {
            "plan_id": plan_id,
            "router_id": router_id,
            "confirmation_state": plan["confirmation_state"],
            "confirmed_at": plan["confirmed_at"],
            "plan_digest": plan["plan_digest"],
            "etag": etag,
        },
        headers=_ok_headers(request, {"ETag": etag}),
    )


@router.post("/routers/{router_id}/plans/{plan_id}/apply")
async def apply_plan(
    router_id: str,
    plan_id: str,
    request: Request,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    if_match: str | None = Header(default=None, alias="If-Match"),
) -> JSONResponse:
    """Apply MUST fail closed unless RC_ALLOW_FAKE_MUTATIONS=1 (simulation only)."""
    host = _state(request)
    if not idempotency_key or not idempotency_key.strip():
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="Idempotency-Key required",
        )
    allow_fake = host.allow_fake_mutations or os.environ.get("RC_ALLOW_FAKE_MUTATIONS") == "1"
    if not allow_fake:
        return error_response(
            request,
            status_code=403,
            code="gate.mutation_forbidden",
            message="Hardware mutation gates closed; apply fail-closed",
        )
    if if_match is None:
        return error_response(
            request,
            status_code=428,
            code="precondition.required",
            message="If-Match required",
        )
    # Fake simulation path only — still no live router
    plan = host.runtime.store.get_plan(plan_id)
    if plan is None or plan["confirmation_state"] != "Confirmed":
        return error_response(
            request,
            status_code=409,
            code="plan.stale",
            message="plan not confirmed",
        )
    expected = etag_for_plan(plan_id, plan["plan_digest"])
    if if_match.strip() != expected:
        return error_response(
            request,
            status_code=412,
            code="plan.precondition_failed",
            message="If-Match plan ETag mismatch",
        )
    outcome = host.runtime.store.create_operation_bundle(
        router_id=router_id,
        operation_kind="apply_plan",
        idempotency_key=idempotency_key.strip(),
        request_digest=_digest({"plan_id": plan_id}),
        plan_id=plan_id,
        actor_id="hub_admin",
        initial_job_status="Queued",
        now=host.runtime.clock.now(),
    )
    return JSONResponse(
        {
            "operation_id": outcome.operation_id,
            "job_id": outcome.job_id,
            "status": "Queued",
            "links": {
                "operation": f"{API_PREFIX}/operations/{outcome.operation_id}",
                "job": f"{API_PREFIX}/jobs/{outcome.job_id}",
            },
        },
        status_code=202,
        headers=_ok_headers(
            request,
            {"Location": f"{API_PREFIX}/operations/{outcome.operation_id}"},
        ),
    )


@router.get("/operations/{operation_id}")
def get_operation(operation_id: str, request: Request) -> JSONResponse:
    host = _state(request)
    op = host.runtime.store.get_operation(operation_id)
    if op is None:
        return error_response(
            request, status_code=404, code="resource.not_found", message="operation not found"
        )
    return JSONResponse(
        {
            "operation_id": op["operation_id"],
            "router_id": op["router_id"],
            "operation_kind": op["operation_kind"],
            "aggregate_status": op["aggregate_status"],
            "plan_id": op["plan_id"],
            "created_at": op["created_at"],
            "updated_at": op["updated_at"],
            "terminal_at": op["terminal_at"],
            "jobs": f"{API_PREFIX}/operations/{operation_id}/jobs",
        },
        headers=_ok_headers(request),
    )


@router.get("/operations/{operation_id}/jobs")
def list_operation_jobs(operation_id: str, request: Request) -> JSONResponse:
    host = _state(request)
    items = [
        {
            "job_id": j["job_id"],
            "attempt": j["attempt"],
            "status": j["status"],
            "cancel_requested": bool(j["cancel_requested"]),
        }
        for j in host.runtime.store.list_jobs_for_operation(operation_id)
    ]
    return JSONResponse({"items": items}, headers=_ok_headers(request))


@router.get("/jobs/{job_id}")
def get_job(job_id: str, request: Request) -> JSONResponse:
    host = _state(request)
    job = host.runtime.store.get_job(job_id)
    if job is None:
        return error_response(
            request, status_code=404, code="resource.not_found", message="job not found"
        )
    steps = [
        {
            "step_id": s["step_id"],
            "ordinal": s["ordinal"],
            "step_kind": s["step_kind"],
            "status": s["status"],
            "error_redacted": s["error_redacted"],
        }
        for s in host.runtime.store.list_job_steps(job_id)
    ]
    return JSONResponse(
        {
            "job_id": job["job_id"],
            "operation_id": job["operation_id"],
            "router_id": job["router_id"],
            "attempt": job["attempt"],
            "status": job["status"],
            "cancel_requested": bool(job["cancel_requested"]),
            "steps": steps,
            "started_at": job["started_at"],
            "finished_at": job["finished_at"],
        },
        headers=_ok_headers(request),
    )


@router.post("/jobs/{job_id}/cancel")
async def cancel_job(
    job_id: str,
    request: Request,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> JSONResponse:
    host = _state(request)
    if not idempotency_key or not idempotency_key.strip():
        return error_response(
            request,
            status_code=400,
            code="request.validation_failed",
            message="Idempotency-Key required",
        )
    try:
        http_status, body, _outcome = host.runtime.store.cancel_job(
            target_job_id=job_id,
            idempotency_key=idempotency_key.strip(),
            request_digest=_digest({"job_id": job_id}),
            actor_id="hub_admin",
            now=host.runtime.clock.now(),
        )
    except NotFoundError:
        return error_response(
            request, status_code=404, code="resource.not_found", message="job not found"
        )
    except ConflictError as exc:
        return error_response(
            request,
            status_code=409,
            code="job.already_terminal",
            message=str(exc),
        )
    except IdempotencyConflict as exc:
        return error_response(
            request,
            status_code=409,
            code="idempotency.conflict",
            message=str(exc),
        )
    return JSONResponse(body, status_code=http_status, headers=_ok_headers(request))


def new_request_id() -> str:
    return f"req_{uuid.uuid4().hex[:16]}"
