"""Operator entry page API routes (offline catalog; zero guest writes)."""

from __future__ import annotations

import os
from typing import Any, Literal

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from router_control.application.entry_pages import (
    EntryPageNotFound,
    EntryPageValidationError,
)

from router_control_host.errors import (
    error_response,
    operator_structured_error_response,
    synthesize_operator_message,
)
from router_control_host.public_entry_routes import public_security_headers
from router_control_host.routes import API_PREFIX, _ok_headers
from router_control_host.state import HostState

router = APIRouter(prefix=API_PREFIX, tags=["entry-pages"])


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CreateEntryPageBody(_StrictModel):
    audience: Literal["guest", "staff"]


class SaveDraftBody(_StrictModel):
    document: dict[str, Any] = Field(...)


class PublishBody(_StrictModel):
    revision_id: str


class EmptyBody(_StrictModel):
    pass


def _state(request: Request) -> HostState:
    return request.app.state.host  # type: ignore[no-any-return]


def _list_item(page: dict[str, Any]) -> dict[str, Any]:
    published_revision_id = page.get("published_revision_id")
    return {
        "page_id": page["page_id"],
        "audience": page["audience"],
        "slug": page["slug"],
        "title": page.get("title"),
        "has_draft": bool(page.get("has_draft")),
        "published": published_revision_id is not None,
        "current_revision_id": page.get("current_revision_id"),
        "published_revision_id": published_revision_id,
        "public_path": page.get("public_path"),
    }


def _get_page_for_current_site(host: HostState, page_id: str) -> dict[str, Any] | None:
    svc = host.entry_page_service()
    site_id = host.resolve_site_id()
    try:
        page = svc.get_page(page_id)
    except EntryPageNotFound:
        return None
    if str(page.get("site_id")) != site_id:
        return None
    return page


def _entry_not_found(request: Request, *, code: str) -> JSONResponse:
    return error_response(
        request,
        status_code=404,
        code=code,
        message=synthesize_operator_message(
            code=code,
            reason="preview_failed",
        ),
    )


def _entry_validation_error(request: Request, exc: EntryPageValidationError) -> JSONResponse:
    return operator_structured_error_response(
        request,
        status_code=422,
        code=exc.code,
        reason="invalid_format",
        field=exc.field,
    )


def _guard_guest_reachable(payload: dict[str, object], request: Request) -> JSONResponse | None:
    if payload.get("guest_reachable") is not None:
        return error_response(
            request,
            status_code=500,
            code="internal.error",
            message="entry self-check must not claim guest reachability",
        )
    if payload.get("writes_allowed") is not False:
        return error_response(
            request,
            status_code=500,
            code="internal.error",
            message="entry self-check must remain non-writing",
        )
    if payload.get("certification_eligible") is not False:
        return error_response(
            request,
            status_code=500,
            code="internal.error",
            message="entry self-check must remain non-certifying",
        )
    return None


def build_self_check_payload(
    host: HostState,
    *,
    page_id: str,
) -> dict[str, object]:
    svc = host.entry_page_service()
    page = svc.get_page(page_id)
    published_revision_id = page.get("published_revision_id")
    published = published_revision_id is not None
    render_ok: bool | None = None
    reason_code = "entry.not_published"
    if published:
        html_body, render_reason = svc.render_document_for_page(
            page_id,
            published_only=True,
        )
        if html_body is not None:
            render_ok = True
            reason_code = render_reason
        else:
            render_ok = False
            reason_code = render_reason
    bind_raw = os.environ.get("RC_PUBLIC_ENTRY_BIND")
    if bind_raw is None or not str(bind_raw).strip():
        public_zone_enabled: bool | None = None
    else:
        public_zone_enabled = True
    return {
        "checked_from": "operator_host",
        "published": published,
        "render_ok": render_ok,
        "public_zone_enabled": public_zone_enabled,
        "guest_reachable": None,
        "guest_reachable_reason": "guest_device_check_required",
        "public_path": str(page.get("public_path") or ""),
        "reason_code": reason_code,
        "writes_allowed": False,
        "certification_eligible": False,
    }


def _revision_document(
    host: HostState,
    page_id: str,
    revision_id: str | None,
) -> dict[str, Any] | None:
    if not revision_id:
        return None
    try:
        revision = host.entry_page_service().get_revision(page_id, str(revision_id))
    except EntryPageNotFound:
        return None
    document = revision.get("document")
    return document if isinstance(document, dict) else None


@router.get("/entry-pages")
def list_entry_pages(request: Request) -> JSONResponse:
    host = _state(request)
    site_id = host.resolve_site_id()
    items = [_list_item(page) for page in host.entry_page_service().list_pages(site_id)]
    return JSONResponse({"items": items}, headers=_ok_headers(request))


@router.post("/entry-pages")
def create_entry_page(request: Request, body: CreateEntryPageBody) -> JSONResponse:
    host = _state(request)
    site_id = host.resolve_site_id()
    try:
        page = host.entry_page_service().ensure_page(site_id, body.audience)
    except EntryPageValidationError as exc:
        return _entry_validation_error(request, exc)
    return JSONResponse(_list_item(page), status_code=201, headers=_ok_headers(request))


@router.get("/entry-pages/{page_id}")
def get_entry_page(page_id: str, request: Request) -> JSONResponse:
    host = _state(request)
    page = _get_page_for_current_site(host, page_id)
    if page is None:
        return _entry_not_found(request, code="entry.page_not_found")
    payload = {
        **_list_item(page),
        "draft_document": _revision_document(host, page_id, page.get("current_revision_id")),
        "published_document": _revision_document(host, page_id, page.get("published_revision_id")),
    }
    return JSONResponse(payload, headers=_ok_headers(request))


@router.put("/entry-pages/{page_id}/draft")
def save_entry_page_draft(
    page_id: str,
    request: Request,
    body: SaveDraftBody,
) -> JSONResponse:
    host = _state(request)
    if _get_page_for_current_site(host, page_id) is None:
        return _entry_not_found(request, code="entry.page_not_found")
    try:
        result = host.entry_page_service().save_draft(page_id, body.document)
    except EntryPageNotFound as exc:
        return _entry_not_found(request, code=exc.code)
    except EntryPageValidationError as exc:
        return _entry_validation_error(request, exc)
    return JSONResponse(
        {
            **_list_item(result),
            "revision": result.get("revision"),
        },
        headers=_ok_headers(request),
    )


@router.post("/entry-pages/{page_id}/publish")
def publish_entry_page(page_id: str, request: Request, body: PublishBody) -> JSONResponse:
    host = _state(request)
    if _get_page_for_current_site(host, page_id) is None:
        return _entry_not_found(request, code="entry.page_not_found")
    try:
        page = host.entry_page_service().publish(page_id, body.revision_id.strip())
    except EntryPageNotFound as exc:
        return _entry_not_found(request, code=exc.code)
    return JSONResponse(_list_item(page), headers=_ok_headers(request))


@router.post("/entry-pages/{page_id}/unpublish")
def unpublish_entry_page(page_id: str, request: Request, body: EmptyBody) -> JSONResponse:
    _ = body
    host = _state(request)
    if _get_page_for_current_site(host, page_id) is None:
        return _entry_not_found(request, code="entry.page_not_found")
    try:
        page = host.entry_page_service().unpublish(page_id)
    except EntryPageNotFound as exc:
        return _entry_not_found(request, code=exc.code)
    return JSONResponse(_list_item(page), headers=_ok_headers(request))


@router.post("/entry-pages/{page_id}/self-check")
def self_check_entry_page(page_id: str, request: Request, body: EmptyBody) -> JSONResponse:
    _ = body
    host = _state(request)
    if _get_page_for_current_site(host, page_id) is None:
        return _entry_not_found(request, code="entry.page_not_found")
    try:
        payload = build_self_check_payload(host, page_id=page_id)
    except EntryPageNotFound as exc:
        return _entry_not_found(request, code=exc.code)
    guard = _guard_guest_reachable(payload, request)
    if guard is not None:
        return guard
    return JSONResponse(payload, headers=_ok_headers(request))


@router.get("/entry-pages/{page_id}/draft-preview", response_model=None)
def draft_preview_entry_page(page_id: str, request: Request) -> HTMLResponse | JSONResponse:
    host = _state(request)
    if _get_page_for_current_site(host, page_id) is None:
        return HTMLResponse(
            content="Not found",
            status_code=404,
            headers=public_security_headers(),
        )
    try:
        html_body, reason = host.entry_page_service().render_document_for_page(
            page_id,
            published_only=False,
        )
    except EntryPageNotFound:
        return HTMLResponse(
            content="Not found",
            status_code=404,
            headers=public_security_headers(),
        )
    if html_body is None:
        return error_response(
            request,
            status_code=422,
            code=reason,
            message=synthesize_operator_message(
                code=reason,
                reason="preview_failed",
            ),
        )
    return HTMLResponse(content=html_body, headers=public_security_headers())
