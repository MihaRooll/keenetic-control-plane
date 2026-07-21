"""ASGI app factory for Router Control prototype host."""

from __future__ import annotations

import os
import uuid
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from router_control.composition import create_offline_runtime

from router_control_host.auth import auth_gate
from router_control_host.errors import error_body
from router_control_host.routes import API_PREFIX, router
from router_control_host.state import HostState


def create_app(
    *,
    db_path: Path | str | None = None,
    allow_fake_mutations: bool | None = None,
) -> FastAPI:
    app = FastAPI(title="Router Control Prototype Host", version="0.1.0")
    runtime = create_offline_runtime(db_path=db_path)
    fake_flag = (
        allow_fake_mutations
        if allow_fake_mutations is not None
        else os.environ.get("RC_ALLOW_FAKE_MUTATIONS") == "1"
    )
    app.state.host = HostState(runtime=runtime, allow_fake_mutations=fake_flag)

    @app.middleware("http")
    async def auth_and_correlation(request: Request, call_next):  # type: ignore[no-untyped-def]
        request_id = request.headers.get("X-Request-Id") or f"req_{uuid.uuid4().hex[:16]}"
        correlation_id = request.headers.get("X-Correlation-Id") or request_id
        request.state.request_id = request_id
        request.state.correlation_id = correlation_id

        if request.url.path.startswith(API_PREFIX):
            cookie = request.cookies.get("hub_admin")
            decision = auth_gate(cookie)
            if decision.status_code is not None:
                return JSONResponse(
                    status_code=decision.status_code,
                    content=error_body(
                        code=decision.code or "auth.required",
                        message=decision.message or "forbidden",
                        request_id=request_id,
                        correlation_id=correlation_id,
                    ),
                    headers={
                        "X-Request-Id": request_id,
                        "X-Correlation-Id": correlation_id,
                    },
                )

        response = await call_next(request)
        response.headers.setdefault("X-Request-Id", request_id)
        response.headers.setdefault("X-Correlation-Id", correlation_id)
        return response

    app.include_router(router)
    return app


def __getattr__(name: str) -> FastAPI:
    """Lazy ASGI app for `uvicorn router_control_host.app:app` (avoids import-time DB)."""
    if name == "app":
        return create_app()
    raise AttributeError(name)
