"""Separate ASGI app for public guest entry zone (/p/* only)."""

from __future__ import annotations

import os
import posixpath
from collections.abc import Sequence
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from router_control.composition import create_offline_runtime, resolve_host_vault
from starlette.datastructures import MutableHeaders
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.routing import BaseRoute, Host, Mount
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from router_control_host.app import resolve_adapter_mode
from router_control_host.public_entry_routes import (
    public_error_response,
    public_guest_not_found_response,
    public_guest_starlette_http_error_response,
    public_security_headers,
    public_validation_error_response,
)
from router_control_host.public_entry_routes import (
    router as public_entry_router,
)
from router_control_host.state import HostState


def iter_public_route_paths(routes: Sequence[BaseRoute], *, prefix: str = "") -> list[str]:
    """Collect every mounted path, including Mount/Host/WebSocketRoute nesting."""
    paths: list[str] = []
    for route in routes:
        segment = getattr(route, "path", "")
        path = f"{prefix}{segment}"
        if isinstance(route, (Mount, Host)):
            paths.extend(iter_public_route_paths(route.routes, prefix=path))
        else:
            paths.append(path)
    return paths


def normalize_public_route_path(path: str) -> str:
    """Normalize a mounted route path; reject traversal outside the declared prefix."""
    normalized = posixpath.normpath(path)
    if not normalized.startswith("/"):
        normalized = f"/{normalized}"
    return normalized


def is_allowed_public_zone_path(path: str) -> bool:
    """Allow exactly /p or paths under /p/; reject /ptrap, /P/x, ../ escapes, etc."""
    normalized = normalize_public_route_path(path)
    return normalized == "/p" or normalized.startswith("/p/")


def assert_public_zone_route_isolation(routes: Sequence[BaseRoute]) -> None:
    """Fail closed at construction if any route is outside /p or /p/*."""
    for path in iter_public_route_paths(routes):
        if not is_allowed_public_zone_path(path):
            msg = (
                "Public entry zone must expose only /p or /p/* routes; "
                f"found forbidden path: {path!r}"
            )
            raise RuntimeError(msg)


class PublicZoneRouteIsolationMiddleware:
    """Re-assert /p-only route isolation on every HTTP request (post-construction guard)."""

    def __init__(self, app: ASGIApp, *, fastapi_app: FastAPI) -> None:
        self._app = app
        self._fastapi_app = fastapi_app
        self._contamination_detected = False

    def __getattr__(self, name: str) -> object:
        return getattr(self._app, name)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            try:
                assert_public_zone_route_isolation(self._fastapi_app.routes)
            except RuntimeError:
                self._contamination_detected = True
                response = public_guest_not_found_response()
                await response(scope, receive, send)
                return
        await self._app(scope, receive, send)


class PublicSecurityHeadersMiddleware:
    """Apply guest security headers on every HTTP response, including error paths."""

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    def __getattr__(self, name: str) -> object:
        return getattr(self._app, name)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for key, value in public_security_headers().items():
                    if key.lower() != "content-type":
                        headers[key] = value
            await send(message)

        await self._app(scope, receive, send_with_headers)


def create_public_app(
    *,
    db_path: Path | str | None = None,
    adapter_mode: str | None = None,
    secrets_root: Path | str | None = None,
) -> FastAPI:
    mode = resolve_adapter_mode(adapter_mode)
    if mode != "fake":
        runtime = create_offline_runtime(
            db_path=db_path,
            vault=resolve_host_vault(secrets_root=secrets_root),
        )
    else:
        runtime = create_offline_runtime(
            db_path=db_path,
            vault=resolve_host_vault(secrets_root=secrets_root),
        )
    host_state = HostState(
        runtime=runtime,
        adapter_mode=mode,
        allow_fake_mutations=os.environ.get("RC_ALLOW_FAKE_MUTATIONS") == "1",
    )
    app = FastAPI(
        title="Router Control Public Entry Zone",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.exception_handler(StarletteHTTPException)
    async def handle_starlette_http_exception(
        request: Request, exc: StarletteHTTPException
    ) -> JSONResponse | HTMLResponse:
        return public_guest_starlette_http_error_response(request, exc)

    @app.exception_handler(RequestValidationError)
    async def handle_request_validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return public_validation_error_response(request, exc)

    @app.exception_handler(Exception)
    async def handle_unhandled_exception(
        request: Request, exc: Exception
    ) -> JSONResponse | HTMLResponse:
        if isinstance(exc, RequestValidationError):
            return public_validation_error_response(request, exc)
        if isinstance(exc, StarletteHTTPException):
            return public_guest_starlette_http_error_response(request, exc)
        return public_error_response(
            request,
            status_code=500,
            code="internal.error",
        )

    app.state.host = host_state
    app.include_router(public_entry_router)
    assert_public_zone_route_isolation(app.routes)
    isolated = PublicZoneRouteIsolationMiddleware(app, fastapi_app=app)
    return PublicSecurityHeadersMiddleware(isolated)  # type: ignore[return-value]


def __getattr__(name: str) -> FastAPI:
    """Lazy ASGI app for `uvicorn router_control_host.public_app:app`."""
    if name == "app":
        return create_public_app()
    raise AttributeError(name)
