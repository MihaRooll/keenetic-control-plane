"""Standalone session bootstrap — login/logout for prototype host."""

from __future__ import annotations

from html import escape
from importlib import resources
from importlib.resources.abc import Traversable
from typing import TypeVar

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from router_control_host.auth import (
    StandaloneLoopbackConfig,
    adapter_mode_for_unsafe_bypass,
    apply_hub_admin_cookie,
    classify_request_provenance,
    clear_hub_admin_cookie,
    get_login_throttle,
    header_singleton_value,
    hub_admin_password,
    is_unsafe_auth_bypass_active,
    unsafe_dev_auth_bypass_allowed,
    verify_hub_admin_password,
)

router = APIRouter(include_in_schema=False)

LOGIN_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "connect-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)

DEFAULT_AUTHENTICATED_LANDING_PATH = "/settings/router-control/hub"

ALLOWED_NEXT_PATHS: frozenset[str] = frozenset(
    {
        "/settings/router-control",
        "/settings/router-control/",
        "/settings/router-control/hub",
        "/settings/router-control/hub/",
    }
)


def _web_package_root() -> Traversable:
    return resources.files("router_control_host").joinpath("web")


_ResponseT = TypeVar("_ResponseT", bound=Response)


def _session_security_headers(*, no_store: bool = True) -> dict[str, str]:
    headers = {
        "Content-Security-Policy": LOGIN_CSP,
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
    }
    if no_store:
        headers["Cache-Control"] = "no-store"
    return headers


def _attach_session_security(response: _ResponseT, *, no_store: bool = True) -> _ResponseT:
    for key, value in _session_security_headers(no_store=no_store).items():
        response.headers[key] = value
    return response


def _request_ids(request: Request) -> tuple[str, str]:
    request_id = getattr(request.state, "request_id", "req_unknown")
    correlation_id = getattr(request.state, "correlation_id", request_id)
    return request_id, correlation_id


def _standalone_profile(request: Request) -> StandaloneLoopbackConfig | None:
    try:
        profile = getattr(request.app.state, "standalone_loopback", None)
    except KeyError:
        return None
    if isinstance(profile, StandaloneLoopbackConfig):
        return profile
    return None


def same_origin_post(request: Request) -> bool:
    """CSRF provenance for login/logout POST; Origin authoritative when present."""
    profile = _standalone_profile(request)
    if profile is not None:
        expected_origin = profile.expected_origin
        request_hostname = profile.hostname
    else:
        expected_origin = f"{request.url.scheme}://{request.url.netloc}"
        request_hostname = request.url.hostname or ""

    path = request.url.path
    allow_null_origin = (
        profile is not None
        and request.method.upper() == "POST"
        and path in ("/login", "/logout")
    )

    return classify_request_provenance(
        origin=header_singleton_value(request.headers.getlist("origin")),
        origin_count=len(request.headers.getlist("origin")),
        referer=header_singleton_value(request.headers.getlist("referer")),
        referer_count=len(request.headers.getlist("referer")),
        method=request.method,
        expected_origin=expected_origin,
        request_hostname=request_hostname,
        sec_fetch_site=header_singleton_value(request.headers.getlist("sec-fetch-site")),
        sec_fetch_site_count=len(request.headers.getlist("sec-fetch-site")),
        sec_fetch_mode=header_singleton_value(request.headers.getlist("sec-fetch-mode")),
        sec_fetch_mode_count=len(request.headers.getlist("sec-fetch-mode")),
        sec_fetch_dest=header_singleton_value(request.headers.getlist("sec-fetch-dest")),
        sec_fetch_dest_count=len(request.headers.getlist("sec-fetch-dest")),
        allow_null_origin=allow_null_origin,
    )


def _resolve_next(next_path: str | None) -> str:
    if not next_path:
        return DEFAULT_AUTHENTICATED_LANDING_PATH
    candidate = next_path.strip()
    if candidate not in ALLOWED_NEXT_PATHS:
        return DEFAULT_AUTHENTICATED_LANDING_PATH
    return candidate


def _configuration_blocked_response(request: Request) -> HTMLResponse:
    request_id, correlation_id = _request_ids(request)
    response = HTMLResponse(
        content=(
            "<!DOCTYPE html><html lang=\"ru\"><head><meta charset=\"utf-8\">"
            "<title>Router Control — недоступно</title></head>"
            "<body><p>Сервис не настроен.</p></body></html>"
        ),
        status_code=503,
        media_type="text/html; charset=utf-8",
    )
    response.headers["X-Request-Id"] = request_id
    response.headers["X-Correlation-Id"] = correlation_id
    return _attach_session_security(response)


def _auth_failure_html(request: Request, *, status_code: int = 401) -> HTMLResponse:
    request_id, correlation_id = _request_ids(request)
    response = HTMLResponse(
        content=(
            "<!DOCTYPE html><html lang=\"ru\"><head><meta charset=\"utf-8\">"
            "<title>Router Control — вход</title></head>"
            "<body><p>Неверные учётные данные.</p>"
            "<p><a href=\"/login\">Повторить вход</a></p></body></html>"
        ),
        status_code=status_code,
        media_type="text/html; charset=utf-8",
    )
    response.headers["X-Request-Id"] = request_id
    response.headers["X-Correlation-Id"] = correlation_id
    return _attach_session_security(response)


def _serve_public_asset(
    request: Request,
    *,
    filename: str,
    media_type: str,
    as_bytes: bool,
) -> Response:
    if not hub_admin_password():
        return _configuration_blocked_response(request)
    asset_path = _web_package_root().joinpath(filename)
    with resources.as_file(asset_path) as file_path:
        content = file_path.read_bytes() if as_bytes else file_path.read_text(encoding="utf-8")
    response: Response = Response(content=content, media_type=media_type)
    request_id, correlation_id = _request_ids(request)
    response.headers["X-Request-Id"] = request_id
    response.headers["X-Correlation-Id"] = correlation_id
    return _attach_session_security(response)


def _request_time_bypass_allowed(request: Request) -> bool:
    if is_unsafe_auth_bypass_active():
        return True
    host = getattr(request.app.state, "host", None)
    return unsafe_dev_auth_bypass_allowed(
        armed=bool(getattr(request.app.state, "unsafe_dev_auth_disabled", False)),
        standalone_active=getattr(request.app.state, "standalone_loopback", None) is not None,
        adapter_mode=adapter_mode_for_unsafe_bypass(host),
    )


@router.get("/login", response_class=HTMLResponse)
def serve_login_page(request: Request, next: str | None = None) -> Response:
    if _request_time_bypass_allowed(request):
        return RedirectResponse(url="/settings/router-control", status_code=302)
    if not hub_admin_password():
        return _configuration_blocked_response(request)
    login_path = _web_package_root().joinpath("login.html")
    with resources.as_file(login_path) as file_path:
        content = file_path.read_text(encoding="utf-8")
    resolved_next = _resolve_next(next)
    hidden_next_field = (
        f'<input type="hidden" name="next" value="{escape(resolved_next, quote=True)}">'
    )
    content = content.replace(
        '<button type="submit">',
        f'{hidden_next_field}\n      <button type="submit">',
        1,
    )
    response = HTMLResponse(content=content, media_type="text/html; charset=utf-8")
    request_id, correlation_id = _request_ids(request)
    response.headers["X-Request-Id"] = request_id
    response.headers["X-Correlation-Id"] = correlation_id
    return _attach_session_security(response)


@router.get("/login.js")
def serve_login_js(request: Request) -> Response:
    return _serve_public_asset(
        request,
        filename="login.js",
        media_type="application/javascript; charset=utf-8",
        as_bytes=True,
    )


@router.get("/login.css")
def serve_login_css(request: Request) -> Response:
    return _serve_public_asset(
        request,
        filename="login.css",
        media_type="text/css; charset=utf-8",
        as_bytes=False,
    )


@router.post("/login")
def login_submit(
    request: Request,
    password: str = Form(...),
    next: str | None = Form(default=None),
) -> Response:
    configured = bool(hub_admin_password())
    if not configured:
        return _configuration_blocked_response(request)

    origin_ok = same_origin_post(request)
    if not origin_ok:
        return _auth_failure_html(request, status_code=401)

    throttle = get_login_throttle()
    if throttle.is_blocked():
        return _auth_failure_html(request, status_code=401)

    password_ok = verify_hub_admin_password(password)
    if not password_ok:
        throttle.record_failure()
        return _auth_failure_html(request, status_code=401)

    throttle.reset()
    destination = _resolve_next(next)
    response = RedirectResponse(url=destination, status_code=303)
    apply_hub_admin_cookie(response, request)
    request_id, correlation_id = _request_ids(request)
    response.headers["X-Request-Id"] = request_id
    response.headers["X-Correlation-Id"] = correlation_id
    return _attach_session_security(response)


@router.post("/logout")
def logout_post(request: Request) -> Response:
    if not hub_admin_password():
        return _configuration_blocked_response(request)
    if not same_origin_post(request):
        return _auth_failure_html(request, status_code=401)
    response = RedirectResponse(url="/login", status_code=303)
    clear_hub_admin_cookie(response, request)
    request_id, correlation_id = _request_ids(request)
    response.headers["X-Request-Id"] = request_id
    response.headers["X-Correlation-Id"] = correlation_id
    return _attach_session_security(response)


@router.get("/logout")
def logout_get(request: Request) -> Response:
    if not hub_admin_password():
        return _configuration_blocked_response(request)
    request_id, correlation_id = _request_ids(request)
    response = Response(status_code=405)
    response.headers["Allow"] = "POST"
    response.headers["X-Request-Id"] = request_id
    response.headers["X-Correlation-Id"] = correlation_id
    return _attach_session_security(response)
