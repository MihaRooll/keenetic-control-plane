"""ASGI app factory for Router Control prototype host."""

from __future__ import annotations

import logging
import os
import sys
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import cast
from urllib.parse import quote, unquote

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from router_control.adapters.netcraze.certification import (
    GateACertification,
    try_load_gate_a_certification,
)
from router_control.adapters.netcraze.live_probe import (
    ReadOnlyProbeFn,
    SoftConnectionHealthProbe,
    build_pinned_ssh_probe_fn,
    build_soft_candidate_identity_probe,
    build_soft_readonly_health_probe_fn,
)
from router_control.application.connection_health import ConnectionHealthProbePort
from router_control.application.router_discovery import CandidateIdentityProbePort
from router_control.composition import (
    LiveRuntime,
    OfflineRuntime,
    create_live_runtime,
    create_offline_runtime,
    resolve_host_vault,
)
from router_control.ports.vault import CredentialVaultPort
from starlette.exceptions import HTTPException as StarletteHTTPException

from router_control_host.auth import (
    StandaloneLoopbackConfig,
    adapter_mode_for_unsafe_bypass,
    auth_gate,
    hub_admin_password,
    is_unsafe_auth_bypass_active,
    reset_unsafe_auth_bypass_for_request,
    resolve_standalone_loopback_config,
    resolve_unsafe_disable_auth_env,
    set_unsafe_auth_bypass_for_request,
    unsafe_dev_auth_bypass_allowed,
    validate_hub_admin_cookie,
    validate_standalone_authority,
)
from router_control_host.bootstrap_discovery_routes import router as bootstrap_discovery_router
from router_control_host.commissioning_routes import router as commissioning_router
from router_control_host.connection_health_routes import router as connection_health_router
from router_control_host.entry_page_routes import router as entry_page_router
from router_control_host.errors import (
    error_body,
    error_response,
    starlette_http_error_response,
    validation_error_response,
)
from router_control_host.host_probe_routes import router as host_probe_router
from router_control_host.hub_routes import HUB_PAGE_PATHS
from router_control_host.hub_routes import router as hub_router
from router_control_host.internet_status_routes import router as internet_status_router
from router_control_host.keendns_apply_routes import router as keendns_apply_router
from router_control_host.keendns_routes import router as keendns_router
from router_control_host.network_family_preview_routes import (
    router as network_family_preview_router,
)
from router_control_host.preset_routes import router as preset_router
from router_control_host.rci_mutation_routes import router as rci_mutation_router
from router_control_host.remembered_uplink_routes import router as remembered_uplink_router
from router_control_host.router_discovery_routes import router as router_discovery_router
from router_control_host.routes import API_PREFIX, router
from router_control_host.session_routes import (
    DEFAULT_AUTHENTICATED_LANDING_PATH,
)
from router_control_host.session_routes import (
    router as session_router,
)
from router_control_host.ssh_host_key_routes import router as ssh_host_key_router
from router_control_host.standing_network_preferences_routes import (
    router as standing_network_preferences_router,
)
from router_control_host.state import HostState
from router_control_host.traffic_discovery_routes import router as traffic_discovery_router
from router_control_host.ui_routes import UI_PREFIX
from router_control_host.ui_routes import router as ui_router
from router_control_host.vpn_catalog_remove_routes import router as vpn_catalog_remove_router
from router_control_host.vpn_catalog_status_routes import router as vpn_catalog_status_router
from router_control_host.vpn_policy_preview_routes import router as vpn_policy_preview_router
from router_control_host.wifi_apply_routes import router as wifi_apply_router
from router_control_host.wifi_observed_routes import router as wifi_observed_router
from router_control_host.wifi_site_survey_routes import router as wifi_site_survey_router
from router_control_host.wifi_station_apply_routes import router as wifi_station_apply_router
from router_control_host.wifi_station_preview_routes import router as wifi_station_preview_router
from router_control_host.wireguard_apply_routes import router as wireguard_apply_router
from router_control_host.wizard_draft_routes import router as wizard_draft_router
from router_control_host.worker_runtime import start_worker_runtime, stop_worker_runtime

logger = logging.getLogger(__name__)
UNSAFE_AUTH_ARMED_MESSAGE = "AUTH DISABLED — DEV ONLY, LOOPBACK+FAKE ONLY"


def resolve_adapter_mode(adapter_mode: str | None = None) -> str:
    raw = (adapter_mode or os.environ.get("RC_ADAPTER_MODE", "fake")).strip().lower()
    return raw if raw in ("fake", "live") else "fake"


def normalize_api_path(path: str) -> str | None:
    """Normalize path for auth; reject traversal and suspicious forms."""
    try:
        decoded = unquote(path)
    except Exception:
        return None
    if "\x00" in decoded or ".." in decoded:
        return None
    normalized = decoded
    while "//" in normalized:
        normalized = normalized.replace("//", "/")
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    return normalized


def create_app(
    *,
    db_path: Path | str | None = None,
    allow_fake_mutations: bool | None = None,
    adapter_mode: str | None = None,
    feature_state: str | None = None,
    gate_a_certification: GateACertification | None = None,
    read_only_probe_fn: ReadOnlyProbeFn | None = None,
    connection_health_probe_port: ConnectionHealthProbePort | None = None,
    router_discovery_identity_probe: CandidateIdentityProbePort | None = None,
    secrets_root: Path | str | None = None,
    skip_gate_a_load: bool = False,
    vault: CredentialVaultPort | None = None,
    enable_worker: bool = True,
    standalone_loopback_auth: bool | None = None,
    public_base_url: str | None = None,
    authority_test_server: tuple[str, int] | None = None,
    unsafe_disable_auth: bool | None = None,
) -> FastAPI:
    mode = resolve_adapter_mode(adapter_mode)
    fake_flag = (
        allow_fake_mutations
        if allow_fake_mutations is not None
        else os.environ.get("RC_ALLOW_FAKE_MUTATIONS") == "1"
    )
    resolved_gate_a = gate_a_certification
    resolved_probe_fn = read_only_probe_fn
    resolved_health_probe = connection_health_probe_port
    resolved_discovery_probe = router_discovery_identity_probe
    built_soft_health_probe: SoftConnectionHealthProbe | None = None
    runtime: LiveRuntime | OfflineRuntime
    if mode == "live":
        runtime = create_live_runtime(db_path=db_path, secrets_root=secrets_root, vault=vault)
        if not skip_gate_a_load and resolved_gate_a is None:
            resolved_gate_a = try_load_gate_a_certification()
        if resolved_probe_fn is None and resolved_gate_a is not None and resolved_gate_a.is_open:
            resolved_probe_fn = build_pinned_ssh_probe_fn(
                resolved_gate_a,
                vault=runtime.vault,
                clock=runtime.clock,
            )
        if (
            resolved_health_probe is None
            and resolved_gate_a is not None
            and resolved_gate_a.is_open
        ):
            resolved_health_probe = build_soft_readonly_health_probe_fn(
                resolved_gate_a,
                vault=runtime.vault,
                clock=runtime.clock,
            )
            built_soft_health_probe = resolved_health_probe
        if (
            resolved_discovery_probe is None
            and built_soft_health_probe is not None
            and resolved_gate_a is not None
            and resolved_gate_a.is_open
        ):
            resolved_discovery_probe = build_soft_candidate_identity_probe(built_soft_health_probe)
    else:
        runtime = create_offline_runtime(
            db_path=db_path,
            vault=resolve_host_vault(vault=vault, secrets_root=secrets_root),
        )

    host_state = HostState(
        runtime=runtime,
        allow_fake_mutations=fake_flag,
        adapter_mode=mode,
        feature_state=feature_state or "Ready",
        gate_a_certification=resolved_gate_a,
        read_only_probe_fn=resolved_probe_fn,
        connection_health_probe_port=resolved_health_probe,
        router_discovery_identity_probe=resolved_discovery_probe,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        from router_control.application.gate_a_refresh_watchdog import GateARefreshWatchdogHandle
        from router_control.application.internet_status_observe import InternetStatusTransport
        from router_control.application.uplink_watchdog_service import UplinkWatchdogHandle
        from router_control.application.vpn_watchdog_service import VpnWatchdogHandle
        from router_control.application.wifi_station_apply_service import WifiStationApplyTransport

        from router_control_host.wireguard_apply_routes import (
            build_vpn_watchdog_backup_callback_factory,
            build_vpn_watchdog_transport_factory,
        )

        host = app.state.host
        transport_factory = build_vpn_watchdog_transport_factory(host)
        backup_callback_factory = build_vpn_watchdog_backup_callback_factory(host)
        credential_resolver = host.wireguard_apply_credential_resolver
        vpn_watchdog = VpnWatchdogHandle(
            host,
            transport_factory=transport_factory,
            credential_resolver=credential_resolver,
            backup_callback_factory=backup_callback_factory,
        )
        host.vpn_watchdog = vpn_watchdog
        vpn_watchdog.start()

        def _uplink_observe_factory(_router_id: str) -> InternetStatusTransport | None:
            factory = getattr(host, "internet_status_transport_factory", None)
            if factory is None:
                return None
            return cast(InternetStatusTransport, factory())

        def _uplink_apply_factory(_router_id: str) -> WifiStationApplyTransport | None:
            factory = getattr(host, "wifi_station_apply_transport_factory", None)
            if factory is None:
                return None
            return cast(WifiStationApplyTransport, factory())

        def _uplink_host_internet_probe() -> bool | None:
            from router_control_host.host_probes import DefaultHostProbeRunner

            runner = host.host_probe_runner or DefaultHostProbeRunner()
            return runner.probe_internet(targets_profile="default").internet_reachable

        from router_control_host.wifi_station_apply_routes import (
            build_uplink_watchdog_backup_callback_factory,
        )

        uplink_backup_callback_factory = build_uplink_watchdog_backup_callback_factory(host)
        uplink_watchdog = UplinkWatchdogHandle(
            host,
            observe_transport_factory=_uplink_observe_factory,
            apply_transport_factory=_uplink_apply_factory,
            credential_resolver=host.wifi_station_apply_credential_resolver,
            backup_callback_factory=uplink_backup_callback_factory,
            host_internet_probe=_uplink_host_internet_probe,
        )
        host.uplink_watchdog = uplink_watchdog
        uplink_watchdog.start()

        gate_a_refresh_watchdog: GateARefreshWatchdogHandle | None = None
        if host.adapter_mode == "live" and host.gate_a_certification is not None:
            gate_a_refresh_watchdog = GateARefreshWatchdogHandle(host)
            host.gate_a_refresh_watchdog = gate_a_refresh_watchdog
            gate_a_refresh_watchdog.start()

        if enable_worker:
            handle = start_worker_runtime(
                host_state.runtime,
                adapter_mode=host_state.adapter_mode,
                allow_fake_mutations=host_state.allow_fake_mutations,
            )
            host_state.worker_runtime = handle
        yield
        if gate_a_refresh_watchdog is not None:
            await gate_a_refresh_watchdog.stop()
            host.gate_a_refresh_watchdog = None
        await uplink_watchdog.stop()
        host.uplink_watchdog = None
        await vpn_watchdog.stop()
        host.vpn_watchdog = None
        stop_worker_runtime(host_state.worker_runtime)
        host_state.worker_runtime = None

    app = FastAPI(
        title="Router Control Prototype Host",
        version="0.1.0",
        lifespan=lifespan,
    )

    @app.exception_handler(StarletteHTTPException)
    async def handle_starlette_http_exception(
        request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        return starlette_http_error_response(request, exc)

    @app.exception_handler(RequestValidationError)
    async def handle_request_validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return validation_error_response(request, exc)

    @app.exception_handler(Exception)
    async def handle_unhandled_exception(request: Request, exc: Exception) -> JSONResponse:
        if isinstance(exc, RequestValidationError):
            return validation_error_response(request, exc)
        if isinstance(exc, StarletteHTTPException):
            return starlette_http_error_response(request, exc)
        return error_response(
            request,
            status_code=500,
            code="internal.error",
            message="An internal error occurred",
        )

    app.state.host = host_state
    standalone_profile: StandaloneLoopbackConfig | None = resolve_standalone_loopback_config(
        standalone_loopback_auth=standalone_loopback_auth,
        public_base_url=public_base_url,
    )
    app.state.standalone_loopback = standalone_profile
    app.state.authority_test_server = authority_test_server
    requested_unsafe_disable = (
        unsafe_disable_auth
        if unsafe_disable_auth is not None
        else resolve_unsafe_disable_auth_env()
    )
    armed_unsafe_disable = (
        requested_unsafe_disable and standalone_profile is not None and mode == "fake"
    )
    app.state.unsafe_dev_auth_disabled = armed_unsafe_disable
    if armed_unsafe_disable:
        logger.warning(UNSAFE_AUTH_ARMED_MESSAGE)
        print(UNSAFE_AUTH_ARMED_MESSAGE, file=sys.stderr)
    elif requested_unsafe_disable:
        ignored_msg = (
            "RC_UNSAFE_DISABLE_AUTH=1 IGNORED — requires standalone loopback profile "
            "and RC_ADAPTER_MODE=fake (live adapter always requires auth)"
        )
        logger.warning(ignored_msg)
        print(ignored_msg, file=sys.stderr)

    def _authority_denied_response(request: Request) -> Response:
        request_id = getattr(request.state, "request_id", f"req_{uuid.uuid4().hex[:16]}")
        correlation_id = getattr(request.state, "correlation_id", request_id)
        normalized = normalize_api_path(request.url.path)
        decoded_path = unquote(request.url.path)
        under_api = (normalized and normalized.startswith(API_PREFIX)) or (
            normalized is None
            and (API_PREFIX in decoded_path or "/router-control/v1" in decoded_path)
        )
        under_ui = (normalized and normalized.startswith(UI_PREFIX)) or (
            normalized is None and UI_PREFIX in decoded_path
        )
        if under_api or under_ui:
            return JSONResponse(
                status_code=401,
                content=error_body(
                    code="auth.required",
                    message="Authority validation failed",
                    request_id=request_id,
                    correlation_id=correlation_id,
                ),
                headers={
                    "X-Request-Id": request_id,
                    "X-Correlation-Id": correlation_id,
                },
            )
        return HTMLResponse(
            content=(
                "<!DOCTYPE html><html lang=\"ru\"><head><meta charset=\"utf-8\">"
                "<title>Router Control — вход</title></head>"
                "<body><p>Неверные учётные данные.</p>"
                "<p><a href=\"/login\">Повторить вход</a></p></body></html>"
            ),
            status_code=401,
            media_type="text/html; charset=utf-8",
            headers={
                "X-Request-Id": request_id,
                "X-Correlation-Id": correlation_id,
            },
        )

    @app.middleware("http")
    async def auth_and_correlation(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        request_id = request.headers.get("X-Request-Id") or f"req_{uuid.uuid4().hex[:16]}"
        correlation_id = request.headers.get("X-Correlation-Id") or request_id
        request.state.request_id = request_id
        request.state.correlation_id = correlation_id

        host = getattr(request.app.state, "host", None)
        bypass_allowed = unsafe_dev_auth_bypass_allowed(
            armed=bool(getattr(request.app.state, "unsafe_dev_auth_disabled", False)),
            standalone_active=getattr(request.app.state, "standalone_loopback", None) is not None,
            adapter_mode=adapter_mode_for_unsafe_bypass(host),
        )
        bypass_token = set_unsafe_auth_bypass_for_request(bypass_allowed)
        try:
            normalized = normalize_api_path(request.url.path)
            decoded_path = unquote(request.url.path)
            under_api = (normalized and normalized.startswith(API_PREFIX)) or (
                normalized is None
                and (API_PREFIX in decoded_path or "/router-control/v1" in decoded_path)
            )
            under_ui = (normalized and normalized.startswith(UI_PREFIX)) or (
                normalized is None and UI_PREFIX in decoded_path
            )
            if under_api:
                if normalized is None:
                    return JSONResponse(
                        status_code=400,
                        content=error_body(
                            code="request.validation_failed",
                            message="Invalid API path",
                            request_id=request_id,
                            correlation_id=correlation_id,
                        ),
                        headers={
                            "X-Request-Id": request_id,
                            "X-Correlation-Id": correlation_id,
                        },
                    )
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
            elif under_ui:
                if normalized is None:
                    return JSONResponse(
                        status_code=400,
                        content=error_body(
                            code="request.validation_failed",
                            message="Invalid UI path",
                            request_id=request_id,
                            correlation_id=correlation_id,
                        ),
                        headers={
                            "X-Request-Id": request_id,
                            "X-Correlation-Id": correlation_id,
                        },
                    )
                cookie = request.cookies.get("hub_admin")
                decision = auth_gate(cookie)
                if decision.status_code is not None:
                    if (
                        decision.status_code == 401
                        and request.method == "GET"
                        and normalized in HUB_PAGE_PATHS
                    ):
                        redirect = RedirectResponse(
                            url=f"/login?next={quote(normalized, safe='')}",
                            status_code=302,
                        )
                        redirect.headers["X-Request-Id"] = request_id
                        redirect.headers["X-Correlation-Id"] = correlation_id
                        return redirect
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
        finally:
            reset_unsafe_auth_bypass_for_request(bypass_token)

    @app.middleware("http")
    async def standalone_loopback_authority(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        profile = app.state.standalone_loopback
        if profile is None:
            return await call_next(request)
        test_server = app.state.authority_test_server
        server = test_server if test_server is not None else request.scope.get("server")
        if not validate_standalone_authority(
            host_values=request.headers.getlist("host"),
            expected_host=profile.expected_host,
            server=server,
            expected_port=profile.port,
            headers=request.headers,
        ):
            return _authority_denied_response(request)
        return await call_next(request)

    @app.get("/")
    def root_landing(request: Request) -> RedirectResponse:
        if is_unsafe_auth_bypass_active():
            return RedirectResponse(url="/settings/router-control", status_code=302)
        cookie = request.cookies.get("hub_admin")
        if hub_admin_password() and validate_hub_admin_cookie(cookie):
            return RedirectResponse(
                url=DEFAULT_AUTHENTICATED_LANDING_PATH, status_code=302
            )
        return RedirectResponse(url="/login", status_code=302)

    @app.get("/favicon.ico")
    def favicon() -> Response:
        from importlib import resources

        favicon_path = resources.files("router_control_host").joinpath("web", "favicon.svg")
        with resources.as_file(favicon_path) as file_path:
            content = file_path.read_bytes()
        return Response(content=content, media_type="image/svg+xml")

    app.include_router(session_router)
    app.include_router(router)
    app.include_router(rci_mutation_router)
    app.include_router(wifi_apply_router)
    app.include_router(wifi_observed_router)
    app.include_router(wifi_site_survey_router)
    app.include_router(internet_status_router)
    app.include_router(wifi_station_preview_router)
    app.include_router(vpn_policy_preview_router)
    app.include_router(vpn_catalog_status_router)
    app.include_router(vpn_catalog_remove_router)
    app.include_router(keendns_router)
    app.include_router(keendns_apply_router)
    app.include_router(network_family_preview_router)
    app.include_router(wifi_station_apply_router)
    app.include_router(wireguard_apply_router)
    app.include_router(traffic_discovery_router)
    app.include_router(bootstrap_discovery_router)
    app.include_router(router_discovery_router)
    app.include_router(connection_health_router)
    app.include_router(host_probe_router)
    app.include_router(entry_page_router)
    app.include_router(standing_network_preferences_router)
    app.include_router(remembered_uplink_router)
    app.include_router(wizard_draft_router)
    app.include_router(ssh_host_key_router)
    app.include_router(commissioning_router)
    app.include_router(preset_router)
    app.include_router(ui_router)
    app.include_router(hub_router)
    return app


def __getattr__(name: str) -> FastAPI:
    """Lazy ASGI app for `uvicorn router_control_host.app:app` (avoids import-time DB)."""
    if name == "app":
        return create_app()
    raise AttributeError(name)
