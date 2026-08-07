"""Signed hub_admin cookie for prototype host (not Hub-parity)."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from collections.abc import Callable, Mapping
from contextvars import ContextVar, Token
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from starlette.requests import Request
    from starlette.responses import Response

HUB_ADMIN_COOKIE_NAME = "hub_admin"
HUB_ADMIN_TOKEN_PREFIX = "hub_admin:v2"
SESSION_DOMAIN = "rc-proto-session:v1"
PLAN_SESSION_BINDING_DOMAIN = "rc-plan-session:v1"
DEFAULT_SESSION_TTL_SECONDS = 8 * 3600
CLOCK_SKEW_TOLERANCE_SECONDS = 60
LOGIN_THROTTLE_MAX_FAILURES = 10
LOGIN_THROTTLE_WINDOW_SECONDS = 60
ORIGIN_NULL_LITERAL = "null"
MULTIPLE_HEADER_SENTINEL = "__MULTIPLE__"

FORWARDED_HEADER_NAMES = frozenset(
    {
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-port",
        "x-forwarded-proto",
    }
)

_auth_clock: Callable[[], int] | None = None
_unsafe_auth_bypass_active: ContextVar[bool] = ContextVar(
    "_unsafe_auth_bypass_active", default=False
)
UNSAFE_DISABLE_AUTH_ENV = "RC_UNSAFE_DISABLE_AUTH"


class AuthFailureClass(StrEnum):
    CONFIGURATION_BLOCKED = "configuration_blocked"
    ORIGIN_REJECTED = "origin_rejected"
    CREDENTIALS_REJECTED = "credentials_rejected"
    MISSING_TOKEN = "missing_token"
    MALFORMED_TOKEN = "malformed_token"
    INVALID_TIMESTAMPS = "invalid_timestamps"
    NOT_YET_VALID = "not_yet_valid"
    EXPIRED = "expired"
    INVALID_SIGNATURE = "invalid_signature"


@dataclass(frozen=True, slots=True)
class AuthDecision:
    status_code: int | None  # None = proceed
    code: str | None = None
    message: str | None = None


def set_auth_clock_for_tests(clock: Callable[[], int] | None) -> None:
    """Inject deterministic unix clock for tests; pass None to reset."""
    global _auth_clock
    _auth_clock = clock


def auth_now_unix() -> int:
    if _auth_clock is not None:
        return _auth_clock()
    return int(time.time())


def hub_admin_password() -> str:
    return os.environ.get("HUB_ADMIN_PASSWORD", "").strip()


def session_ttl_seconds() -> int:
    return DEFAULT_SESSION_TTL_SECONDS


def session_signing_key() -> str:
    configured_secret = os.environ.get("HUB_ADMIN_SESSION_SECRET", "").strip()
    if configured_secret:
        return configured_secret
    pwd = hub_admin_password()
    if not pwd:
        return ""
    return hmac.new(
        pwd.encode("utf-8"),
        b"rc-proto-session:v1",
        hashlib.sha256,
    ).hexdigest()


def _sign_payload(payload: str) -> str:
    key = session_signing_key()
    if not key:
        raise ValueError("session signing key unavailable")
    message = f"{SESSION_DOMAIN}|{payload}".encode()
    return hmac.new(key.encode(), message, hashlib.sha256).hexdigest()


def mint_hub_admin_cookie(password: str | None = None, *, now: int | None = None) -> str:
    pwd = (password if password is not None else hub_admin_password()).strip()
    if not pwd:
        raise ValueError("HUB_ADMIN_PASSWORD empty")
    if session_signing_key() == "":
        raise ValueError("session signing key unavailable")
    issued_at = auth_now_unix() if now is None else now
    expires_at = issued_at + session_ttl_seconds()
    sid = secrets.token_hex(16)
    payload = f"{HUB_ADMIN_TOKEN_PREFIX}|{issued_at}|{expires_at}|{sid}"
    signature = _sign_payload(payload)
    return f"{payload}.{signature}"


def extract_session_id(cookie_value: str | None) -> str | None:
    if not cookie_value or not validate_hub_admin_cookie(cookie_value):
        return None
    payload = cookie_value.rsplit(".", 1)[0]
    parts = payload.split("|")
    if len(parts) != 4 or parts[0] != HUB_ADMIN_TOKEN_PREFIX:
        return None
    sid = parts[3]
    return sid if sid else None


def plan_session_binding_hmac(sid: str) -> str:
    key = session_signing_key()
    if not key:
        raise ValueError("session signing key unavailable")
    message = f"{PLAN_SESSION_BINDING_DOMAIN}|{sid}".encode()
    return hmac.new(key.encode(), message, hashlib.sha256).hexdigest()


def verify_plan_session_binding(cookie_value: str | None, expected_hmac: str | None) -> bool:
    if not expected_hmac:
        return False
    sid = extract_session_id(cookie_value)
    if sid is None:
        return False
    computed = plan_session_binding_hmac(sid)
    return hmac.compare_digest(computed, expected_hmac)


def session_binding_from_cookie(cookie_value: str | None) -> str | None:
    sid = extract_session_id(cookie_value)
    if sid is None:
        return None
    return plan_session_binding_hmac(sid)


def classify_hub_admin_cookie(cookie_value: str | None) -> AuthFailureClass | None:
    """Return failure class for diagnostics/tests; None when token is valid."""
    if not cookie_value:
        return AuthFailureClass.MISSING_TOKEN
    if session_signing_key() == "":
        return AuthFailureClass.CONFIGURATION_BLOCKED

    try:
        payload, signature = cookie_value.rsplit(".", 1)
    except ValueError:
        return AuthFailureClass.MALFORMED_TOKEN

    if not payload.startswith(f"{HUB_ADMIN_TOKEN_PREFIX}|") or not signature:
        return AuthFailureClass.MALFORMED_TOKEN

    parts = payload.split("|")
    if len(parts) != 4 or parts[0] != HUB_ADMIN_TOKEN_PREFIX:
        return AuthFailureClass.MALFORMED_TOKEN

    try:
        issued_at = int(parts[1])
        expires_at = int(parts[2])
    except ValueError:
        return AuthFailureClass.MALFORMED_TOKEN

    if not parts[3]:
        return AuthFailureClass.MALFORMED_TOKEN

    if expires_at <= issued_at:
        return AuthFailureClass.INVALID_TIMESTAMPS

    now = auth_now_unix()
    if issued_at > now + CLOCK_SKEW_TOLERANCE_SECONDS:
        return AuthFailureClass.NOT_YET_VALID
    if now >= expires_at:
        return AuthFailureClass.EXPIRED

    expected = _sign_payload(payload)
    if not hmac.compare_digest(expected, signature):
        return AuthFailureClass.INVALID_SIGNATURE
    return None


def validate_hub_admin_cookie(cookie_value: str | None) -> bool:
    return classify_hub_admin_cookie(cookie_value) is None


def verify_hub_admin_password(submitted: str) -> bool:
    """Timing-safe compare; outer whitespace stripped on submit and env."""
    configured = hub_admin_password()
    if not configured:
        return False
    normalized = submitted.strip()
    return hmac.compare_digest(normalized.encode("utf-8"), configured.encode("utf-8"))


def _is_loopback_hostname(hostname: str) -> bool:
    normalized = hostname.strip().lower()
    if normalized.endswith("."):
        return False
    return normalized in {"127.0.0.1", "::1", "localhost"}


@dataclass(frozen=True, slots=True)
class StandaloneLoopbackConfig:
    """Validated standalone loopback authority profile (prototype host only)."""

    public_base_url: str
    expected_origin: str
    expected_host: str
    hostname: str
    port: int
    scheme: str


def parse_public_base_url(url: str) -> StandaloneLoopbackConfig:
    """Parse canonical HTTP loopback base URL; reject userinfo/path/query/fragment."""
    raw = url.strip()
    if not raw:
        raise ValueError("public_base_url empty")
    parsed = urlparse(raw)
    if parsed.scheme != "http":
        raise ValueError("public_base_url must use http scheme")
    if parsed.username or parsed.password:
        raise ValueError("public_base_url must not contain userinfo")
    if parsed.path not in ("", "/"):
        raise ValueError("public_base_url must not contain path")
    if parsed.query or parsed.fragment:
        raise ValueError("public_base_url must not contain query or fragment")
    if parsed.port is None:
        raise ValueError("public_base_url must include explicit port")
    hostname = parsed.hostname
    if not hostname or not _is_loopback_hostname(hostname):
        raise ValueError("public_base_url hostname must be loopback")
    expected_origin = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
    return StandaloneLoopbackConfig(
        public_base_url=expected_origin,
        expected_origin=expected_origin,
        expected_host=parsed.netloc,
        hostname=hostname,
        port=parsed.port,
        scheme=parsed.scheme,
    )


def resolve_standalone_loopback_config(
    *,
    standalone_loopback_auth: bool | None,
    public_base_url: str | None,
) -> StandaloneLoopbackConfig | None:
    enabled = standalone_loopback_auth
    if enabled is None:
        enabled = os.environ.get("RC_STANDALONE_LOOPBACK_AUTH", "").strip() == "1"
    if not enabled:
        return None
    configured_url = public_base_url
    if configured_url is None:
        configured_url = os.environ.get("RC_PUBLIC_BASE_URL", "").strip()
    if not configured_url:
        raise ValueError("RC_PUBLIC_BASE_URL required when standalone loopback auth enabled")
    return parse_public_base_url(configured_url)


def has_untrusted_forwarded_headers(headers: Mapping[str, str]) -> bool:
    for key in headers:
        if key.lower() in FORWARDED_HEADER_NAMES:
            return True
    return False


def _malformed_bracketed_host(raw: str) -> bool:
    """True when Host looks like broken bracketed IPv6 (e.g. unclosed ``[``)."""
    if not raw.startswith("["):
        return False
    close = raw.find("]")
    if close == -1:
        return True
    if "[" in raw[1:close]:
        return True
    suffix = raw[close + 1 :]
    if suffix == "":
        return False
    if not suffix.startswith(":"):
        return True
    port = suffix[1:]
    return not port.isdigit()


def validate_host_authority(*, host_values: list[str], expected_host: str) -> bool:
    if len(host_values) != 1:
        return False
    raw = host_values[0]
    if raw != expected_host:
        return False
    if raw.endswith("."):
        return False
    if "@" in raw:
        return False
    if raw.strip() != raw:
        return False
    if _malformed_bracketed_host(raw):
        return False
    return True


def validate_asgi_server_address(
    server: tuple[str, int] | list[str | int] | None,
    *,
    expected_port: int,
) -> bool:
    if server is None or len(server) != 2:
        return False
    host_raw, port_raw = server[0], server[1]
    if not isinstance(port_raw, int) or port_raw <= 0:
        return False
    if port_raw != expected_port:
        return False
    host = str(host_raw)
    return _is_loopback_hostname(host)


def validate_standalone_authority(
    *,
    host_values: list[str],
    expected_host: str,
    server: tuple[str, int] | list[str | int] | None,
    expected_port: int,
    headers: Mapping[str, str],
) -> bool:
    if has_untrusted_forwarded_headers(headers):
        return False
    if not validate_host_authority(host_values=host_values, expected_host=expected_host):
        return False
    return validate_asgi_server_address(server, expected_port=expected_port)


class LoginThrottle:
    """In-process sliding-window login failure throttle (prototype host)."""

    def __init__(
        self,
        *,
        max_failures: int = LOGIN_THROTTLE_MAX_FAILURES,
        window_seconds: int = LOGIN_THROTTLE_WINDOW_SECONDS,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._max_failures = max_failures
        self._window_seconds = window_seconds
        self._clock = clock or time.monotonic
        self._failure_times: list[float] = []

    def is_blocked(self) -> bool:
        self._prune()
        return len(self._failure_times) >= self._max_failures

    def record_failure(self) -> None:
        self._prune()
        self._failure_times.append(self._clock())

    def reset(self) -> None:
        self._failure_times.clear()

    def failure_count(self) -> int:
        self._prune()
        return len(self._failure_times)

    def _prune(self) -> None:
        cutoff = self._clock() - self._window_seconds
        self._failure_times = [stamp for stamp in self._failure_times if stamp > cutoff]


_login_throttle: LoginThrottle | None = None


def get_login_throttle() -> LoginThrottle:
    global _login_throttle
    if _login_throttle is None:
        _login_throttle = LoginThrottle()
    return _login_throttle


def set_login_throttle_for_tests(throttle: LoginThrottle | None) -> None:
    global _login_throttle
    _login_throttle = throttle


def header_singleton_value(values: list[str]) -> str | None:
    if not values:
        return None
    if len(values) > 1:
        return MULTIPLE_HEADER_SENTINEL
    return values[0]


def classify_request_provenance(
    *,
    origin: str | None,
    origin_count: int = 1,
    referer: str | None,
    referer_count: int = 0,
    method: str,
    expected_origin: str,
    request_hostname: str,
    sec_fetch_site: str | None,
    sec_fetch_site_count: int = 0,
    sec_fetch_mode: str | None,
    sec_fetch_mode_count: int = 0,
    sec_fetch_dest: str | None,
    sec_fetch_dest_count: int = 0,
    allow_null_origin: bool = False,
) -> bool:
    """Pure CSRF provenance check (strings + method only; no Request secrets).

    Precedence: Origin (if header present) → Referer (if non-empty) → Fetch Metadata
    fallback on loopback POST only. Exact ``Origin: null`` accepted only when
    ``allow_null_origin`` and Fetch Metadata gates pass.
    """
    if origin_count > 1 or origin == MULTIPLE_HEADER_SENTINEL:
        return False
    if referer_count > 1 or referer == MULTIPLE_HEADER_SENTINEL:
        return False
    if (
        sec_fetch_site_count > 1
        or sec_fetch_mode_count > 1
        or sec_fetch_dest_count > 1
        or sec_fetch_site == MULTIPLE_HEADER_SENTINEL
        or sec_fetch_mode == MULTIPLE_HEADER_SENTINEL
        or sec_fetch_dest == MULTIPLE_HEADER_SENTINEL
    ):
        return False

    if origin is not None:
        if origin == ORIGIN_NULL_LITERAL:
            if not allow_null_origin:
                return False
            if method.upper() != "POST":
                return False
            if referer is not None and referer.strip():
                return False
            if sec_fetch_site != "same-origin":
                return False
            if sec_fetch_mode != "navigate":
                return False
            if sec_fetch_dest != "document":
                return False
            return True
        if origin == "":
            return False
        return origin == expected_origin

    if referer is not None and referer.strip():
        parsed = urlparse(referer)
        referer_origin = f"{parsed.scheme}://{parsed.netloc}"
        return referer_origin == expected_origin

    if method.upper() != "POST":
        return False
    if not _is_loopback_hostname(request_hostname):
        return False
    if sec_fetch_site != "same-origin":
        return False
    if sec_fetch_mode != "navigate":
        return False
    if sec_fetch_dest != "document":
        return False
    return True


def classify_login_submit_failure(
    *,
    password_configured: bool,
    same_origin: bool,
    password_valid: bool,
) -> AuthFailureClass | None:
    """Pure helper for tests; not exposed to HTTP clients."""
    if not password_configured:
        return AuthFailureClass.CONFIGURATION_BLOCKED
    if not same_origin:
        return AuthFailureClass.ORIGIN_REJECTED
    if not password_valid:
        return AuthFailureClass.CREDENTIALS_REJECTED
    return None


def cookie_secure_flag(request: Request) -> bool:
    return request.url.scheme == "https"


def apply_hub_admin_cookie(response: Response, request: Request) -> None:
    response.set_cookie(
        key=HUB_ADMIN_COOKIE_NAME,
        value=mint_hub_admin_cookie(),
        httponly=True,
        samesite="lax",
        path="/",
        max_age=session_ttl_seconds(),
        secure=cookie_secure_flag(request),
    )


def clear_hub_admin_cookie(response: Response, request: Request) -> None:
    response.set_cookie(
        key=HUB_ADMIN_COOKIE_NAME,
        value="",
        max_age=0,
        httponly=True,
        samesite="lax",
        path="/",
        secure=cookie_secure_flag(request),
    )


def resolve_unsafe_disable_auth_env() -> bool:
    """True when RC_UNSAFE_DISABLE_AUTH=1 (env-only; never persisted)."""
    return os.environ.get(UNSAFE_DISABLE_AUTH_ENV, "").strip() == "1"


def adapter_mode_for_unsafe_bypass(host: object | None) -> str:
    """Resolve adapter_mode for unsafe bypass predicate (fail-closed on missing/unknown)."""
    if host is None:
        return "unknown"
    from router_control_host.state import HostState

    if not isinstance(host, HostState):
        return "unknown"
    mode = host.adapter_mode
    if not isinstance(mode, str):
        return "unknown"
    normalized = mode.strip().lower()
    return normalized or "unknown"


def unsafe_dev_auth_bypass_allowed(
    *,
    armed: bool,
    standalone_active: bool,
    adapter_mode: str,
) -> bool:
    """Request-time bypass predicate: armed boot intent + standalone loopback + fake adapter."""
    return armed and standalone_active and adapter_mode == "fake"


def set_unsafe_auth_bypass_for_request(allowed: bool) -> Token[bool]:
    return _unsafe_auth_bypass_active.set(allowed)


def reset_unsafe_auth_bypass_for_request(token: Token[bool]) -> None:
    _unsafe_auth_bypass_active.reset(token)


def is_unsafe_auth_bypass_active() -> bool:
    return _unsafe_auth_bypass_active.get()


def auth_gate(
    cookie_value: str | None,
    *,
    bypass_allowed: bool | None = None,
) -> AuthDecision:
    """Auth order: unsafe bypass → empty password → 503; invalid cookie → 401; else proceed.

    ``bypass_allowed`` when not None is an explicit force-allow for unit tests only;
    it does **not** read the boot arm bit (``unsafe_dev_auth_disabled`` on app state).
    """
    bypass = (
        bypass_allowed
        if bypass_allowed is not None
        else _unsafe_auth_bypass_active.get()
    )
    if bypass:
        return AuthDecision(status_code=None)
    if not hub_admin_password():
        return AuthDecision(
            status_code=503,
            code="security.configuration_blocked",
            message="HUB_ADMIN_PASSWORD is not configured",
        )
    if not validate_hub_admin_cookie(cookie_value):
        return AuthDecision(
            status_code=401,
            code="auth.required",
            message="Valid hub_admin session required",
        )
    return AuthDecision(status_code=None)
