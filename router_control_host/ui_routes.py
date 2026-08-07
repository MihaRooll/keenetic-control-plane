"""Prototype management UI — buildless SPA shell and packaged assets."""

from __future__ import annotations

from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import PurePosixPath

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from router_control_host.auth import auth_gate
from router_control_host.errors import error_body

UI_PREFIX = "/settings/router-control"
ASSETS_PREFIX = f"{UI_PREFIX}/assets"

ALLOWED_ASSETS: frozenset[str] = frozenset({"styles.css", "app.js", "ui-field-manifest.json"})

CONTENT_TYPES: dict[str, str] = {
    "styles.css": "text/css; charset=utf-8",
    "app.js": "application/javascript; charset=utf-8",
    "ui-field-manifest.json": "application/json; charset=utf-8",
}

CSP_VALUE = (
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

router = APIRouter(include_in_schema=False)


def _web_package_root() -> Traversable:
    return resources.files("router_control_host").joinpath("web")


def _security_headers() -> dict[str, str]:
    return {
        "Content-Security-Policy": CSP_VALUE,
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
    }


def _attach_security(response: Response) -> Response:
    for key, value in _security_headers().items():
        response.headers[key] = value
    return response


def _auth_error_response(request: Request, decision: object) -> JSONResponse:
    request_id = getattr(request.state, "request_id", "req_unknown")
    correlation_id = getattr(request.state, "correlation_id", request_id)
    status_code = getattr(decision, "status_code", 401) or 401
    code = getattr(decision, "code", None) or "auth.required"
    message = getattr(decision, "message", None) or "forbidden"
    return JSONResponse(
        status_code=status_code,
        content=error_body(
            code=code,
            message=message,
            request_id=request_id,
            correlation_id=correlation_id,
        ),
        headers={
            "X-Request-Id": request_id,
            "X-Correlation-Id": correlation_id,
            **_security_headers(),
        },
    )


def _path_has_traversal(path: str) -> bool:
    if "\x00" in path or ".." in path:
        return True
    parts = PurePosixPath(path).parts
    return any(part == ".." for part in parts)


def _resolve_asset_name(raw: str) -> str | None:
    if _path_has_traversal(raw):
        return None
    name = PurePosixPath(raw).name
    if name != raw.strip("/").split("/")[-1]:
        return None
    if name not in ALLOWED_ASSETS:
        return None
    return name


@router.get(UI_PREFIX, response_class=HTMLResponse)
@router.get(f"{UI_PREFIX}/", response_class=HTMLResponse)
def serve_ui_shell(request: Request) -> Response:
    decision = auth_gate(request.cookies.get("hub_admin"))
    if decision.status_code is not None:
        return _auth_error_response(request, decision)
    index_path = _web_package_root().joinpath("index.html")
    with resources.as_file(index_path) as file_path:
        content = file_path.read_text(encoding="utf-8")
    response = HTMLResponse(content=content, media_type="text/html; charset=utf-8")
    request_id = getattr(request.state, "request_id", None)
    correlation_id = getattr(request.state, "correlation_id", None)
    if request_id:
        response.headers["X-Request-Id"] = request_id
    if correlation_id:
        response.headers["X-Correlation-Id"] = correlation_id
    return _attach_security(response)


@router.get(f"{ASSETS_PREFIX}/{{asset_name}}")
def serve_ui_asset(asset_name: str, request: Request) -> Response:
    decision = auth_gate(request.cookies.get("hub_admin"))
    if decision.status_code is not None:
        return _auth_error_response(request, decision)
    resolved = _resolve_asset_name(asset_name)
    if resolved is None:
        request_id = getattr(request.state, "request_id", "req_unknown")
        correlation_id = getattr(request.state, "correlation_id", request_id)
        return JSONResponse(
            status_code=404,
            content=error_body(
                code="resource.not_found",
                message="asset not found",
                request_id=request_id,
                correlation_id=correlation_id,
            ),
            headers=_security_headers(),
        )
    asset_path = _web_package_root().joinpath(resolved)
    with resources.as_file(asset_path) as file_path:
        content = file_path.read_bytes()
    response = Response(
        content=content,
        media_type=CONTENT_TYPES.get(resolved, "application/octet-stream"),
    )
    request_id = getattr(request.state, "request_id", None)
    correlation_id = getattr(request.state, "correlation_id", None)
    if request_id:
        response.headers["X-Request-Id"] = request_id
    if correlation_id:
        response.headers["X-Correlation-Id"] = correlation_id
    return _attach_security(response)
