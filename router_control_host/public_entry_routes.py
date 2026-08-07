"""Public guest entry zone routes — /p/* only; no operator surface."""

from __future__ import annotations

import time
from collections.abc import Callable
from importlib import resources
from typing import Any
from urllib.parse import parse_qsl

from fastapi import APIRouter, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, Response
from router_control.application.entry_pages import EntryPageNotFound
from starlette.exceptions import HTTPException as StarletteHTTPException

from router_control_host.state import HostState

router = APIRouter(tags=["public-entry"])

_NOT_FOUND_BODY = "Страница не найдена."
_MAX_SUBMIT_BODY_BYTES = 8 * 1024
_MAX_FIELD_VALUE_LEN = 500
_SUBMIT_RATE_MAX = 20
_SUBMIT_RATE_WINDOW_SECONDS = 60
_SUBMIT_RATE_PER_SLUG_MAX = 10
_SUBMIT_RATE_MAX_TRACKED_SLUGS = 256

_CONTENT_SECURITY_POLICY = (
    "default-src 'none'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "form-action 'self'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'"
)


def public_security_headers(*, content_type: str | None = None) -> dict[str, str]:
    headers = {
        "Content-Security-Policy": _CONTENT_SECURITY_POLICY,
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Cache-Control": "no-store",
        "X-Robots-Tag": "noindex",
    }
    if content_type is not None:
        headers["Content-Type"] = content_type
    return headers


def public_guest_error_message(
    code: str,
    *,
    reason: str | None = None,
    field: str | None = None,
) -> str:
    """Short neutral Russian copy for guest-facing JSON errors."""
    _ = field
    if code == "entry.rate_limited":
        return "Слишком много запросов. Попробуйте позже."
    if code == "entry.submissions_disabled":
        return "Отправка формы временно недоступна."
    if code == "entry.validation_failed":
        if reason in {"invalid_format", "invalid_body"}:
            return "Неверный формат запроса."
        if reason == "out_of_range":
            return "Слишком большой запрос."
        if reason in {"not_allowlisted", "missing_required", "invalid_option"}:
            return "Неверные данные формы."
        return "Не удалось обработать запрос."
    if code == "entry.page_not_found":
        return "Страница не найдена."
    if code == "http.method_not_allowed":
        return "Метод не поддерживается."
    if code == "resource.not_found":
        return "Страница не найдена."
    if code == "request.validation_failed":
        return "Неверный формат запроса."
    if code == "internal.error":
        return "Произошла ошибка. Попробуйте позже."
    return "Не удалось обработать запрос."


def public_error_body(
    *,
    code: str,
    message: str,
    details: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Guest error envelope without operator ids or correlation fields."""
    return {
        "error": {
            "code": code,
            "message": message,
            "details": details or [],
        }
    }


def public_error_response(
    request: Request,
    *,
    status_code: int,
    code: str,
    reason: str | None = None,
    field: str | None = None,
) -> JSONResponse:
    _ = request
    return JSONResponse(
        status_code=status_code,
        content=public_error_body(
            code=code,
            message=public_guest_error_message(code, reason=reason, field=field),
        ),
        headers=public_security_headers(),
    )


def public_guest_not_found_response() -> HTMLResponse:
    return HTMLResponse(
        content=_NOT_FOUND_BODY,
        status_code=404,
        headers=public_security_headers(content_type="text/html; charset=utf-8"),
    )


def public_guest_starlette_http_error_response(
    request: Request,
    exc: StarletteHTTPException,
) -> JSONResponse | HTMLResponse:
    _ = request
    status = exc.status_code
    if status == 404:
        return public_guest_not_found_response()
    if status == 405:
        return JSONResponse(
            status_code=405,
            content=public_error_body(
                code="http.method_not_allowed",
                message=public_guest_error_message("http.method_not_allowed"),
            ),
            headers=public_security_headers(),
        )
    code = {
        400: "request.validation_failed",
        401: "auth.required",
        403: "auth.forbidden",
        409: "resource.conflict",
        412: "resource.precondition_failed",
        422: "request.validation_failed",
        503: "service.unavailable",
    }.get(status, f"http.{status}")
    return JSONResponse(
        status_code=status,
        content=public_error_body(
            code=code,
            message=public_guest_error_message(code),
        ),
        headers=public_security_headers(),
    )


def public_validation_error_response(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    _ = exc
    return public_error_response(
        request,
        status_code=422,
        code="request.validation_failed",
        reason="invalid_format",
    )


class _SubmitRateBucket:
    """In-process sliding-window submit throttle (per slug + global)."""

    def __init__(
        self,
        *,
        max_events: int,
        window_seconds: int,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._max_events = max_events
        self._window_seconds = window_seconds
        self._clock = clock or time.monotonic
        self._events: list[float] = []

    def is_blocked(self) -> bool:
        self._prune()
        return len(self._events) >= self._max_events

    def record(self) -> None:
        self._prune()
        self._events.append(self._clock())

    def reset(self) -> None:
        self._events.clear()

    def _prune(self) -> None:
        cutoff = self._clock() - self._window_seconds
        self._events = [stamp for stamp in self._events if stamp > cutoff]

    def is_stale(self) -> bool:
        self._prune()
        return not self._events


class EntrySubmitRateLimiter:
    def __init__(
        self,
        *,
        global_max: int = _SUBMIT_RATE_MAX,
        per_slug_max: int = _SUBMIT_RATE_PER_SLUG_MAX,
        window_seconds: int = _SUBMIT_RATE_WINDOW_SECONDS,
        max_tracked_slugs: int = _SUBMIT_RATE_MAX_TRACKED_SLUGS,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._global = _SubmitRateBucket(
            max_events=global_max,
            window_seconds=window_seconds,
            clock=clock,
        )
        self._per_slug_max = per_slug_max
        self._window_seconds = window_seconds
        self._max_tracked_slugs = max_tracked_slugs
        self._clock = clock or time.monotonic
        self._slug_buckets: dict[str, _SubmitRateBucket] = {}

    def _evict_stale_slug_buckets(self) -> None:
        stale = [slug for slug, bucket in self._slug_buckets.items() if bucket.is_stale()]
        for slug in stale:
            del self._slug_buckets[slug]

    def _at_slug_capacity(self, slug: str) -> bool:
        return slug not in self._slug_buckets and len(self._slug_buckets) >= self._max_tracked_slugs

    def is_blocked(self, slug: str) -> bool:
        self._evict_stale_slug_buckets()
        if self._global.is_blocked():
            return True
        if self._at_slug_capacity(slug):
            return True
        bucket = self._slug_buckets.get(slug)
        if bucket is None:
            return False
        return bucket.is_blocked()

    def record(self, slug: str) -> None:
        self._evict_stale_slug_buckets()
        if self._at_slug_capacity(slug):
            return
        self._global.record()
        bucket = self._slug_buckets.get(slug)
        if bucket is None:
            bucket = _SubmitRateBucket(
                max_events=self._per_slug_max,
                window_seconds=self._window_seconds,
                clock=self._clock,
            )
            self._slug_buckets[slug] = bucket
        bucket.record()

    def reset(self) -> None:
        self._global.reset()
        self._slug_buckets.clear()

    @property
    def tracked_slug_count(self) -> int:
        self._evict_stale_slug_buckets()
        return len(self._slug_buckets)


_submit_rate_limiter: EntrySubmitRateLimiter | None = None


def get_entry_submit_rate_limiter() -> EntrySubmitRateLimiter:
    global _submit_rate_limiter
    if _submit_rate_limiter is None:
        _submit_rate_limiter = EntrySubmitRateLimiter()
    return _submit_rate_limiter


def set_entry_submit_rate_limiter_for_tests(limiter: EntrySubmitRateLimiter | None) -> None:
    global _submit_rate_limiter
    _submit_rate_limiter = limiter


def _state(request: Request) -> HostState:
    return request.app.state.host  # type: ignore[no-any-return]


def _not_found_response() -> HTMLResponse:
    return public_guest_not_found_response()


def _load_stylesheet_bytes() -> bytes:
    css_path = resources.files("router_control_host").joinpath("web", "entry-page.css")
    with resources.as_file(css_path) as file_path:
        return file_path.read_bytes()


def _allowed_field_names(document: dict[str, Any], *, audience: str) -> set[str]:
    fields = document.get("fields") or []
    names = {str(field["name"]) for field in fields if isinstance(field, dict)}
    if audience == "staff":
        names.add("role")
    return names


def _parse_form_body(raw: bytes) -> dict[str, str] | None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    pairs = parse_qsl(text, keep_blank_values=True)
    values: dict[str, str] = {}
    for key, value in pairs:
        if key in values:
            return None
        values[key] = value
    return values


def _validate_submission(
    document: dict[str, Any],
    parsed: dict[str, str],
    *,
    audience: str,
) -> str | None:
    """Return a neutral validation reason code, or None when valid."""
    if audience == "staff":
        role = parsed.get("role", "")
        roles = document.get("roles") or []
        if not role.strip():
            return "missing_required"
        if role not in roles:
            return "invalid_option"
        if len(role) > _MAX_FIELD_VALUE_LEN:
            return "out_of_range"
    for field in document.get("fields") or []:
        if not isinstance(field, dict):
            continue
        name = str(field["name"])
        value = parsed.get(name, "")
        if field.get("required") and not value.strip():
            return "missing_required"
        if name not in parsed:
            continue
        if len(value) > _MAX_FIELD_VALUE_LEN:
            return "out_of_range"
        kind = str(field.get("kind", ""))
        if kind == "select":
            options = field.get("options") or []
            if value not in options:
                return "invalid_option"
    return None


@router.get("/p/_assets/entry-page.css")
def public_entry_stylesheet() -> Response:
    return Response(
        content=_load_stylesheet_bytes(),
        media_type="text/css",
        headers=public_security_headers(),
    )


@router.get("/p/{slug}")
def public_entry_page(slug: str, request: Request) -> HTMLResponse:
    host = _state(request)
    svc = host.entry_page_service()
    try:
        page = svc.get_page_by_slug(slug)
    except EntryPageNotFound:
        return _not_found_response()
    html_body, _reason = svc.render_document_for_page(
        str(page["page_id"]),
        published_only=True,
    )
    if html_body is None:
        return _not_found_response()
    return HTMLResponse(
        content=html_body,
        headers=public_security_headers(content_type="text/html; charset=utf-8"),
    )


@router.post("/p/{slug}/submit", response_model=None)
async def public_entry_submit(slug: str, request: Request) -> HTMLResponse | JSONResponse:
    content_type = (request.headers.get("content-type") or "").split(";", 1)[0].strip().lower()
    if content_type != "application/x-www-form-urlencoded":
        return public_error_response(
            request,
            status_code=422,
            code="entry.validation_failed",
            reason="invalid_format",
            field="content-type",
        )
    raw = await request.body()
    if len(raw) > _MAX_SUBMIT_BODY_BYTES:
        return public_error_response(
            request,
            status_code=413,
            code="entry.validation_failed",
            reason="out_of_range",
            field="body",
        )
    limiter = get_entry_submit_rate_limiter()
    if limiter.is_blocked(slug):
        return _not_found_response()
    host = _state(request)
    svc = host.entry_page_service()
    try:
        page = svc.get_page_by_slug(slug)
    except EntryPageNotFound:
        return _not_found_response()
    page_id = str(page["page_id"])
    published_revision_id = page.get("published_revision_id")
    if not published_revision_id:
        return _not_found_response()
    try:
        revision = svc.get_revision(page_id, str(published_revision_id))
    except EntryPageNotFound:
        return _not_found_response()
    document = revision.get("document")
    if not isinstance(document, dict):
        return _not_found_response()
    if not bool(document.get("submissions_enabled")):
        return public_error_response(
            request,
            status_code=422,
            code="entry.submissions_disabled",
            reason="disabled",
        )
    parsed = _parse_form_body(raw)
    if parsed is None:
        return public_error_response(
            request,
            status_code=422,
            code="entry.validation_failed",
            reason="invalid_body",
            field="body",
        )
    allowed = _allowed_field_names(document, audience=str(page["audience"]))
    for field_name in parsed:
        if field_name not in allowed:
            return public_error_response(
                request,
                status_code=422,
                code="entry.validation_failed",
                reason="not_allowlisted",
                field="fields",
            )
    validation_reason = _validate_submission(
        document,
        parsed,
        audience=str(page["audience"]),
    )
    if validation_reason is not None:
        return public_error_response(
            request,
            status_code=422,
            code="entry.validation_failed",
            reason=validation_reason,
            field="fields",
        )
    limiter.record(slug)
    return JSONResponse(
        {"accepted": True},
        headers=public_security_headers(),
    )
