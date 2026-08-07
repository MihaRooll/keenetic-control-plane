"""LOCAL HUB — buildless iPad PWA shell and packaged assets."""

from __future__ import annotations

from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import PurePosixPath
from urllib.parse import unquote

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from router_control_host.auth import auth_gate
from router_control_host.errors import error_body
from router_control_host.ui_routes import CSP_VALUE, UI_PREFIX

HUB_PREFIX = f"{UI_PREFIX}/hub"
HUB_PAGE_PATHS: frozenset[str] = frozenset({HUB_PREFIX, f"{HUB_PREFIX}/"})
HUB_VERSION = "0.1.0"

ALLOWED_EXTENSIONS: frozenset[str] = frozenset(
    {".html", ".js", ".css", ".json", ".webmanifest", ".svg", ".png", ".ico", ".woff2", ".txt"}
)

CONTENT_TYPES: dict[str, str] = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".webmanifest": "application/manifest+json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
    ".txt": "text/plain; charset=utf-8",
}

NO_STORE_ASSETS: frozenset[str] = frozenset({"index.html", "sw.js", "runtime.json"})

router = APIRouter(include_in_schema=False)


def _hub_package_root() -> Traversable:
    return resources.files("router_control_host").joinpath("web", "hub")


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


def _attach_request_ids(request: Request, response: Response) -> Response:
    request_id = getattr(request.state, "request_id", None)
    correlation_id = getattr(request.state, "correlation_id", None)
    if request_id:
        response.headers["X-Request-Id"] = request_id
    if correlation_id:
        response.headers["X-Correlation-Id"] = correlation_id
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


def _not_found_response(request: Request) -> JSONResponse:
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


def _path_has_traversal(path: str) -> bool:
    if "\x00" in path:
        return True
    candidates = [path]
    decoded = unquote(path)
    if decoded not in candidates:
        candidates.append(decoded)
    double_decoded = unquote(decoded)
    if double_decoded not in candidates:
        candidates.append(double_decoded)
    for candidate in candidates:
        if "\\" in candidate:
            return True
        if candidate.startswith("/"):
            return True
        if ".." in candidate:
            return True
        path_obj = PurePosixPath(candidate)
        if path_obj.is_absolute():
            return True
        if any(part == ".." for part in path_obj.parts):
            return True
    return False


def _resolve_hub_relative_path(relative_path: str) -> str | None:
    if _path_has_traversal(relative_path):
        return None
    path_obj = PurePosixPath(relative_path)
    if not path_obj.parts:
        return None
    suffix = path_obj.suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        return None
    return "/".join(path_obj.parts)


def _read_hub_asset(relative_path: str) -> bytes | None:
    resolved = _resolve_hub_relative_path(relative_path)
    if resolved is None:
        return None
    root_anchor = _hub_package_root()
    asset_anchor = root_anchor.joinpath(*PurePosixPath(resolved).parts)
    try:
        with resources.as_file(root_anchor) as root_path:
            with resources.as_file(asset_anchor) as file_path:
                root_resolved = root_path.resolve()
                file_resolved = file_path.resolve()
                try:
                    file_resolved.relative_to(root_resolved)
                except ValueError:
                    return None
                if not file_path.is_file():
                    return None
                return file_path.read_bytes()
    except (FileNotFoundError, IsADirectoryError, OSError):
        return None


def _cache_control_for(relative_path: str) -> str:
    basename = PurePosixPath(relative_path).name
    if basename in NO_STORE_ASSETS:
        return "no-store"
    return "no-cache"


def _content_type_for(relative_path: str) -> str:
    suffix = PurePosixPath(relative_path).suffix.lower()
    return CONTENT_TYPES.get(suffix, "application/octet-stream")


def _serve_bytes(
    request: Request,
    *,
    content: bytes,
    relative_path: str,
    media_type: str,
) -> Response:
    response = Response(content=content, media_type=media_type)
    response.headers["Cache-Control"] = _cache_control_for(relative_path)
    basename = PurePosixPath(relative_path).name
    if basename == "sw.js":
        response.headers["Service-Worker-Allowed"] = f"{HUB_PREFIX}/"
    _attach_request_ids(request, response)
    return _attach_security(response)


@router.get(HUB_PREFIX, response_class=HTMLResponse)
@router.get(f"{HUB_PREFIX}/", response_class=HTMLResponse)
def serve_hub_shell(request: Request) -> Response:
    decision = auth_gate(request.cookies.get("hub_admin"))
    if decision.status_code is not None:
        return _auth_error_response(request, decision)
    content = _read_hub_asset("index.html")
    if content is None:
        return _not_found_response(request)
    return _serve_bytes(
        request,
        content=content,
        relative_path="index.html",
        media_type="text/html; charset=utf-8",
    )


@router.get(f"{HUB_PREFIX}/runtime.json")
def serve_hub_runtime(request: Request) -> Response:
    decision = auth_gate(request.cookies.get("hub_admin"))
    if decision.status_code is not None:
        return _auth_error_response(request, decision)
    host = request.app.state.host
    payload = {
        "adapter_mode": host.adapter_mode,
        "unsafe_auth_disabled": bool(getattr(request.app.state, "unsafe_dev_auth_disabled", False)),
        "hub_version": HUB_VERSION,
    }
    response = JSONResponse(content=payload, media_type="application/json; charset=utf-8")
    response.headers["Cache-Control"] = "no-store"
    _attach_request_ids(request, response)
    return _attach_security(response)


@router.get(f"{HUB_PREFIX}/{{asset_path:path}}")
def serve_hub_asset(asset_path: str, request: Request) -> Response:
    decision = auth_gate(request.cookies.get("hub_admin"))
    if decision.status_code is not None:
        return _auth_error_response(request, decision)
    content = _read_hub_asset(asset_path)
    if content is None:
        return _not_found_response(request)
    return _serve_bytes(
        request,
        content=content,
        relative_path=asset_path,
        media_type=_content_type_for(asset_path),
    )
