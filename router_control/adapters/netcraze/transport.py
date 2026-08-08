"""HTTPS transport with Digest and x-ndw2-interactive auth; frozen allowlist."""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import re
import secrets
import socket
import ssl
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol, cast
from urllib.parse import urlparse

from router_control.adapters.netcraze.allowlist import (
    COMPONENTS_LIST,
    COMPONENTS_LIST_STATUS,
    DEFAULT_CONTINUATION_BUDGET_SECONDS,
    DEFAULT_DISCOVERY_MAX_BYTES,
    MAX_CONTINUATION_ROUNDS,
    RCI_WRITE_PATH,
    HttpMethod,
    ReadCommand,
    is_allowlisted,
    is_bootstrap_discovery_allowlisted,
    is_discovery_allowlisted,
    is_expendable_lab_class,
    is_write_allowlisted,
)
from router_control.adapters.netcraze.errors import (
    AllowlistViolation,
    AuthFailed,
    ContinuationUnsupported,
    FeatureAbsent,
    TransportError,
    TransportTimeout,
)

_DIGEST_PARAM_RE = re.compile(r'(\w+)=(?:"([^"]*)"|([^,]*))')

_COOKIE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-]+$")

_UNSAFE_INTERPOLATED_VALUE_RE = re.compile(r'[\x00-\x1f\x7f"\\]')

_UNSAFE_MANAGEMENT_HOST_RE = re.compile(r"[\x00-\x1f\x7f\r\n]")

_LEGACY_IPV4_PART_RE = re.compile(r"(?:[0-9]+|0[xX][0-9A-Fa-f]+)")

_AUTH_PATH = "/auth"

# Upper bound on a sealed RCI write body; sealed parse templates are tiny.
MAX_RCI_WRITE_BODY_BYTES = 4096


class AuthStrategy(StrEnum):
    DIGEST = "digest"

    INTERACTIVE = "interactive"


@dataclass(frozen=True, slots=True)
class TransportTarget:
    hostname: str

    port: int

    use_tls: bool

    scheme: str


@dataclass(frozen=True, slots=True)
class HttpExchange:
    status: int

    headers: dict[str, str]

    body: bytes

    set_cookies: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SealedRciWriteRequest:
    """Pre-serialized, write-allowlist-checked RCI POST body for /rci/."""

    body: bytes = field(repr=False)


class HttpClient(Protocol):
    def request(
        self,
        *,
        host: str,
        port: int,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes | None,
        connect_timeout: float,
        read_timeout: float,
        ssl_context: ssl.SSLContext | None,
        connect_host: str | None = None,
        server_hostname: str | None = None,
    ) -> HttpExchange: ...

    def request_limited(
        self,
        *,
        host: str,
        port: int,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes | None,
        connect_timeout: float,
        read_timeout: float,
        ssl_context: ssl.SSLContext | None,
        max_bytes: int,
        connect_host: str | None = None,
        server_hostname: str | None = None,
    ) -> HttpExchange: ...


class _SniHttpsConnection(http.client.HTTPSConnection):
    """Dial pinned IP while preserving TLS SNI for the logical management hostname."""

    def __init__(
        self,
        pinned_ip: str,
        port: int,
        *,
        server_hostname: str,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(pinned_ip, port, timeout=timeout, context=context)
        self._server_hostname = server_hostname

    def connect(self) -> None:
        inner = cast(Any, self)
        self.sock = socket.create_connection(
            (self.host, self.port),
            self.timeout,
            inner.source_address,
        )
        if inner._tunnel_host:
            inner._tunnel()
        self.sock = inner._context.wrap_socket(self.sock, server_hostname=self._server_hostname)


def _stdlib_http_connection(
    *,
    connect_host: str,
    port: int,
    connect_timeout: float,
    read_timeout: float,
    ssl_context: ssl.SSLContext | None,
    server_hostname: str | None = None,
) -> http.client.HTTPConnection | http.client.HTTPSConnection:
    timeout = max(connect_timeout, read_timeout)
    if ssl_context is not None:
        if server_hostname and server_hostname != connect_host:
            return _SniHttpsConnection(
                connect_host,
                port,
                server_hostname=server_hostname,
                timeout=timeout,
                context=ssl_context,
            )
        return http.client.HTTPSConnection(
            connect_host,
            port,
            timeout=timeout,
            context=ssl_context,
        )
    return http.client.HTTPConnection(connect_host, port, timeout=timeout)


@dataclass
class StdlibHttpClient:
    """Default http.client-backed transport for live probe use."""

    def request(
        self,
        *,
        host: str,
        port: int,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes | None,
        connect_timeout: float,
        read_timeout: float,
        ssl_context: ssl.SSLContext | None,
        connect_host: str | None = None,
        server_hostname: str | None = None,
    ) -> HttpExchange:

        dial_host = connect_host or host
        conn = _stdlib_http_connection(
            connect_host=dial_host,
            port=port,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
            ssl_context=ssl_context,
            server_hostname=server_hostname,
        )

        try:
            conn.request(method, path, body=body, headers=headers)

            response = conn.getresponse()

            raw_headers = response.getheaders()

            header_map = {k.lower(): v for k, v in raw_headers}

            set_cookies = tuple(v for k, v in raw_headers if k.lower() == "set-cookie")

            payload = response.read()

            return HttpExchange(
                status=response.status,
                headers=header_map,
                body=payload,
                set_cookies=set_cookies,
            )

        except TimeoutError as exc:
            raise TransportTimeout("read timeout") from exc

        except OSError as exc:
            if "timed out" in str(exc).lower():
                raise TransportTimeout(str(exc)) from exc

            raise TransportError(str(exc)) from exc

        finally:
            conn.close()

    def request_limited(
        self,
        *,
        host: str,
        port: int,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes | None,
        connect_timeout: float,
        read_timeout: float,
        ssl_context: ssl.SSLContext | None,
        max_bytes: int,
        connect_host: str | None = None,
        server_hostname: str | None = None,
    ) -> HttpExchange:
        """Read at most max_bytes + 1 so callers can detect oversize responses."""
        dial_host = connect_host or host
        conn = _stdlib_http_connection(
            connect_host=dial_host,
            port=port,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
            ssl_context=ssl_context,
            server_hostname=server_hostname,
        )
        try:
            conn.request(method, path, body=body, headers=headers)
            response = conn.getresponse()
            raw_headers = response.getheaders()
            return HttpExchange(
                status=response.status,
                headers={k.lower(): v for k, v in raw_headers},
                body=response.read(max_bytes + 1),
                set_cookies=tuple(v for k, v in raw_headers if k.lower() == "set-cookie"),
            )
        except TimeoutError as exc:
            raise TransportTimeout("read timeout") from exc
        except OSError as exc:
            if "timed out" in str(exc).lower():
                raise TransportTimeout(str(exc)) from exc
            raise TransportError(str(exc)) from exc
        finally:
            conn.close()


@dataclass
class NetcrazeTransport:
    host: str

    username: str

    password: str = field(repr=False)

    port: int = 443

    use_tls: bool = True

    allow_insecure_http: bool = False

    pinned_connect_host: str | None = None

    management_host_header: str = ""

    connect_timeout: float = 5.0

    read_timeout: float = 15.0

    continuation_budget_seconds: float = DEFAULT_CONTINUATION_BUDGET_SECONDS

    ssl_context: ssl.SSLContext | None = None

    http_client: HttpClient = field(default_factory=StdlibHttpClient, repr=False)

    _digest_challenge: dict[str, str] | None = field(default=None, init=False, repr=False)

    _nc: int = field(default=0, init=False, repr=False)

    _session_cookie_name: str | None = field(default=None, init=False, repr=False)

    _session_cookie_value: str | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:

        if self.use_tls and self.ssl_context is None:
            self.ssl_context = ssl.create_default_context()

        if not self.use_tls:
            self.ssl_context = None

    @property
    def transport_security_label(self) -> str:

        return "insecure_http" if not self.use_tls else "https"

    @property
    def https_check_label(self) -> str:

        return "not_certified"

    @property
    def gate_a_certification_eligible(self) -> bool:

        return False

    def fetch_allowlisted(self, command: ReadCommand, body: bytes | None = None) -> Any:

        if not is_allowlisted(command.method, command.path):
            raise AllowlistViolation(f"command not allowlisted: {command.method} {command.path}")

        return self._fetch_with_continuation(command, body)

    def fetch_discovery_read(
        self,
        command: ReadCommand,
        *,
        max_bytes: int = DEFAULT_DISCOVERY_MAX_BYTES,
    ) -> Any:
        """Refuse discovery reads on plain HTTP unless bootstrap opt-in is enabled."""
        if not self.allow_insecure_http:
            raise TransportError("discovery read requires pinned SSH tunnel transport")
        if not is_expendable_lab_class():
            raise TransportError("bootstrap discovery requires expendable lab class")
        if not is_bootstrap_discovery_allowlisted(command.method, command.path):
            raise AllowlistViolation(
                f"command not bootstrap-discovery-allowlisted: {command.method} {command.path}"
            )
        if command.method == HttpMethod.POST and command.path == COMPONENTS_LIST.path:
            return self._fetch_bootstrap_components_list(max_bytes=max_bytes)
        return self._fetch_bootstrap_get_json(command, max_bytes=max_bytes)

    def _fetch_bootstrap_post_json(
        self,
        command: ReadCommand,
        body: bytes,
        *,
        max_bytes: int,
    ) -> Any:
        path = command.path
        method = command.method
        headers = self._base_headers(body)
        exchange = self._send_limited(method, path, headers, body, max_bytes=max_bytes)

        if exchange.status == 401:
            challenge = exchange.headers.get("www-authenticate", "")
            strategy = _select_auth_strategy(challenge)
            if strategy is AuthStrategy.DIGEST:
                parsed = _parse_digest_challenge(challenge)
                self._digest_challenge = _validated_digest_challenge(parsed)
                headers["Authorization"] = self._build_digest_header(method, path)
            elif strategy is AuthStrategy.INTERACTIVE:
                self._run_interactive_auth(challenge)
                self._apply_session_cookie(headers)
            exchange = self._send_limited(method, path, headers, body, max_bytes=max_bytes)
            if exchange.status == 401:
                raise AuthFailed("authentication failed after retry")

        if exchange.status == 404:
            raise FeatureAbsent(f"feature absent: HTTP 404 for {path}")

        if exchange.status >= 400:
            raise TransportError(f"HTTP {exchange.status}")

        if len(exchange.body) > max_bytes:
            raise TransportError("discovery response exceeds size bound")

        return _loads_json_response(exchange.body, strict_utf8=False)

    def _fetch_bootstrap_components_list(
        self,
        *,
        max_bytes: int = DEFAULT_DISCOVERY_MAX_BYTES,
    ) -> Any:
        """Bootstrap-only: POST once, then bounded GET poll while continued."""
        body = json.dumps({}).encode("utf-8")
        deadline = time.monotonic() + self.continuation_budget_seconds

        payload = self._fetch_bootstrap_post_json(
            COMPONENTS_LIST,
            body,
            max_bytes=max_bytes,
        )
        if not _response_continued(payload):
            return payload

        for round_idx in range(MAX_CONTINUATION_ROUNDS):
            if time.monotonic() > deadline:
                raise ContinuationUnsupported("continuation time budget exceeded")

            payload = self._fetch_bootstrap_get_json(
                COMPONENTS_LIST_STATUS,
                max_bytes=max_bytes,
            )
            if not _response_continued(payload):
                return payload

            if round_idx + 1 >= MAX_CONTINUATION_ROUNDS:
                raise ContinuationUnsupported("continuation max rounds exceeded")

        raise ContinuationUnsupported("continuation polling failed")

    def _fetch_bootstrap_get_json(
        self,
        command: ReadCommand,
        *,
        max_bytes: int,
    ) -> Any:
        path = command.path
        method = command.method
        headers = self._base_headers(None)
        exchange = self._send_limited(method, path, headers, None, max_bytes=max_bytes)

        if exchange.status == 401:
            challenge = exchange.headers.get("www-authenticate", "")
            strategy = _select_auth_strategy(challenge)
            if strategy is AuthStrategy.DIGEST:
                parsed = _parse_digest_challenge(challenge)
                self._digest_challenge = _validated_digest_challenge(parsed)
                headers["Authorization"] = self._build_digest_header(method, path)
            elif strategy is AuthStrategy.INTERACTIVE:
                self._run_interactive_auth(challenge)
                self._apply_session_cookie(headers)
            exchange = self._send_limited(method, path, headers, None, max_bytes=max_bytes)
            if exchange.status == 401:
                raise AuthFailed("authentication failed after retry")

        if exchange.status == 404:
            raise FeatureAbsent(f"feature absent: HTTP 404 for {path}")

        if exchange.status >= 400:
            raise TransportError(f"HTTP {exchange.status}")

        if len(exchange.body) > max_bytes:
            raise TransportError("discovery response exceeds size bound")

        return _loads_json_response(exchange.body, strict_utf8=False)

    def read_json(self, command: ReadCommand, body: bytes | None = None) -> Any:

        payload = self.fetch_allowlisted(command, body)

        if isinstance(payload, (dict, list)):
            return payload

        raise TransportError("allowlisted response is not JSON object or array")

    def execute_rci_parse(self, cli_command: str) -> Any:
        """Dispatch a single NDMS CLI command via RCI parse: POST /rci/ [{"parse": cmd}].

        Deliberately bypasses the read-only allowlist; callers must gate this behind
        explicit operator authorization. Returns parsed JSON (list/dict).
        """
        from router_control.application.apply_pre_read import execute_transport_io

        return execute_transport_io(
            self, lambda: self._execute_rci_parse_unlocked(cli_command)
        )

    def _execute_rci_parse_unlocked(self, cli_command: str) -> Any:
        command = cli_command.strip()
        if not command:
            raise TransportError("empty RCI parse command")
        path = "/rci/"
        body = json.dumps([{"parse": command}]).encode("utf-8")
        headers: dict[str, str] = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        self._apply_session_cookie(headers)
        exchange = self._send("POST", path, headers, body)
        if exchange.status == 401:
            challenge = exchange.headers.get("www-authenticate", "")
            strategy = _select_auth_strategy(challenge)
            if strategy is AuthStrategy.DIGEST:
                parsed = _parse_digest_challenge(challenge)
                self._digest_challenge = _validated_digest_challenge(parsed)
                headers["Authorization"] = self._build_digest_header("POST", path)
            elif strategy is AuthStrategy.INTERACTIVE:
                self._run_interactive_auth(challenge)
                self._apply_session_cookie(headers)
            exchange = self._send("POST", path, headers, body)
            if exchange.status == 401:
                raise AuthFailed("authentication failed after retry")
        if exchange.status >= 400:
            raise TransportError(f"HTTP {exchange.status}")
        return _loads_json_response(exchange.body, strict_utf8=False)

    def execute_sealed_rci_write(self, request: SealedRciWriteRequest) -> Any:
        """Dispatch a sealed, write-allowlisted RCI body to POST /rci/ (fail-closed).

        Only bodies accepted by is_write_allowlisted are sent; everything else is
        rejected before any I/O. Returns parsed JSON (list/dict).
        """
        from router_control.application.apply_pre_read import execute_transport_io

        return execute_transport_io(
            self, lambda: self._execute_sealed_rci_write_unlocked(request)
        )

    def _execute_sealed_rci_write_unlocked(self, request: SealedRciWriteRequest) -> Any:
        body = request.body
        path = RCI_WRITE_PATH
        if len(body) > MAX_RCI_WRITE_BODY_BYTES:
            raise TransportError("sealed RCI write body exceeds size bound")
        if not is_write_allowlisted("POST", path, body):
            raise AllowlistViolation("sealed RCI write body is not allowlisted")
        headers: dict[str, str] = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        self._apply_session_cookie(headers)
        exchange = self._send("POST", path, headers, body)
        if exchange.status == 401:
            challenge = exchange.headers.get("www-authenticate", "")
            strategy = _select_auth_strategy(challenge)
            if strategy is AuthStrategy.DIGEST:
                parsed = _parse_digest_challenge(challenge)
                self._digest_challenge = _validated_digest_challenge(parsed)
                headers["Authorization"] = self._build_digest_header("POST", path)
            elif strategy is AuthStrategy.INTERACTIVE:
                self._run_interactive_auth(challenge)
                self._apply_session_cookie(headers)
            exchange = self._send("POST", path, headers, body)
            if exchange.status == 401:
                raise AuthFailed("authentication failed after retry")
        if exchange.status >= 400:
            raise TransportError(f"HTTP {exchange.status}")
        return _loads_json_response(exchange.body, strict_utf8=True)

    def _fetch_with_continuation(self, command: ReadCommand, body: bytes | None) -> Any:

        deadline = time.monotonic() + self.continuation_budget_seconds

        for round_idx in range(MAX_CONTINUATION_ROUNDS):
            if time.monotonic() > deadline:
                raise ContinuationUnsupported("continuation time budget exceeded")

            payload = self._request_json(command, body)

            if not _response_continued(payload):
                return payload

            if round_idx + 1 >= MAX_CONTINUATION_ROUNDS:
                raise ContinuationUnsupported("continuation max rounds exceeded")

        raise ContinuationUnsupported("continuation polling failed")

    def _request_json(self, command: ReadCommand, body: bytes | None) -> Any:

        raw = self._request(command.method, command.path, body)

        return _loads_json_response(raw, strict_utf8=False)

    def _request(self, method: str, path: str, body: bytes | None) -> bytes:

        if not is_allowlisted(method, path):
            raise AllowlistViolation(f"path not allowlisted: {method} {path}")

        headers = self._base_headers(body)

        exchange = self._send(method, path, headers, body)

        if exchange.status == 401:
            challenge = exchange.headers.get("www-authenticate", "")

            strategy = _select_auth_strategy(challenge)

            if strategy is AuthStrategy.DIGEST:
                parsed = _parse_digest_challenge(challenge)

                self._digest_challenge = _validated_digest_challenge(parsed)

                headers["Authorization"] = self._build_digest_header(method, path)

            elif strategy is AuthStrategy.INTERACTIVE:
                self._run_interactive_auth(challenge)

                self._apply_session_cookie(headers)

            exchange = self._send(method, path, headers, body)

            if exchange.status == 401:
                raise AuthFailed("authentication failed after retry")

        if exchange.status >= 400:
            raise TransportError(f"HTTP {exchange.status}")

        return exchange.body

    def _base_headers(self, body: bytes | None) -> dict[str, str]:

        headers = {"Accept": "application/json"}

        if body is not None:
            headers["Content-Type"] = "application/json"

        self._apply_session_cookie(headers)

        return headers

    def _apply_session_cookie(self, headers: dict[str, str]) -> None:

        pair = self._session_cookie_pair()

        if pair is not None:
            name, value = pair

            headers["Cookie"] = f"{name}={value}"

    def _session_cookie_pair(self) -> tuple[str, str] | None:

        if self._session_cookie_name and self._session_cookie_value is not None:
            return self._session_cookie_name, self._session_cookie_value

        return None

    def _set_session_cookie(self, name: str, value: str) -> None:

        _validate_cookie_token(name)

        _validate_cookie_token(value)

        self._session_cookie_name = name

        self._session_cookie_value = value

    def _run_interactive_auth(self, challenge_header: str) -> None:

        params = _parse_auth_params(challenge_header, "x-ndw2-interactive")

        endpoint = params.get("endpoint", "")

        if endpoint != _AUTH_PATH:
            raise AuthFailed("interactive challenge endpoint invalid")

        session_cookie_raw = params.get("session_cookie", "")

        if not session_cookie_raw:
            raise AuthFailed("interactive challenge missing session cookie")

        cookie_name = _validate_cookie_name_only(session_cookie_raw)

        self._session_cookie_name = cookie_name

        self._session_cookie_value = None

        get_headers: dict[str, str] = {"Accept": "application/json"}

        challenge_exchange = self._raw_exchange("GET", _AUTH_PATH, get_headers, None)

        if challenge_exchange.status != 401:
            raise AuthFailed("interactive authentication challenge failed")

        token = _validate_interactive_challenge_field(
            challenge_exchange.headers.get("x-ndm-challenge", "")
        )

        realm = _validate_interactive_challenge_field(
            challenge_exchange.headers.get("x-ndm-realm", "")
        )

        name, value = _extract_mandatory_set_cookie(
            challenge_exchange,
            expected_name=cookie_name,
        )

        self._set_session_cookie(name, value)

        computed = _compute_interactive_response(token, self.username, realm, self.password)

        post_body = json.dumps({"login": self.username, "password": computed}).encode("utf-8")

        post_headers: dict[str, str] = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        self._apply_session_cookie(post_headers)

        post_exchange = self._raw_exchange("POST", _AUTH_PATH, post_headers, post_body)

        if post_exchange.status < 200 or post_exchange.status >= 300:
            raise AuthFailed("interactive authentication post failed")

        updated = _extract_optional_set_cookie(
            post_exchange,
            expected_name=self._session_cookie_name,
        )

        if updated is not None:
            self._set_session_cookie(*updated)

        final_headers: dict[str, str] = {"Accept": "application/json"}

        self._apply_session_cookie(final_headers)

        final_exchange = self._raw_exchange("GET", _AUTH_PATH, final_headers, None)

        if final_exchange.status < 200 or final_exchange.status >= 300:
            raise AuthFailed("interactive authentication finalize failed")

        updated = _extract_optional_set_cookie(
            final_exchange,
            expected_name=self._session_cookie_name,
        )

        if updated is not None:
            self._set_session_cookie(*updated)

        elif self._session_cookie_pair() is None:
            raise AuthFailed("interactive session cookie missing after auth")

    def _raw_exchange(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes | None,
    ) -> HttpExchange:

        if path != _AUTH_PATH or method not in {"GET", "POST"}:
            raise AuthFailed("internal auth path violation")

        return self._send(method, path, headers, body)

    def _management_host_header_value(self) -> str | None:

        header = self.management_host_header.strip()

        return header or None

    def _tcp_dial_host(self) -> str:

        if self.pinned_connect_host:
            return self.pinned_connect_host

        return self.host

    def _tls_server_hostname(self) -> str | None:
        """When TCP dials a pinned IP, TLS SNI may still use the logical hostname."""
        if not self.use_tls or self.pinned_connect_host is None:
            return None

        return self._management_host_header_value()

    def _http_client_kwargs(self) -> dict[str, Any]:
        dial_host = self._tcp_dial_host()

        kwargs: dict[str, Any] = {
            "host": dial_host,
            "port": self.port,
            "connect_timeout": self.connect_timeout,
            "read_timeout": self.read_timeout,
            "ssl_context": self.ssl_context,
        }

        if self.pinned_connect_host is not None:
            kwargs["connect_host"] = dial_host

        server_hostname = self._tls_server_hostname()

        if server_hostname is not None:
            kwargs["server_hostname"] = server_hostname

        return kwargs

    def _send(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes | None,
    ) -> HttpExchange:

        outbound_headers = dict(headers)

        management_host = self._management_host_header_value()

        if management_host is not None:
            outbound_headers["Host"] = management_host

        try:
            return self.http_client.request(
                method=method,
                path=path,
                headers=outbound_headers,
                body=body,
                **self._http_client_kwargs(),
            )

        except TransportTimeout:
            raise

        except AllowlistViolation:
            raise

        except AuthFailed:
            raise

        except TransportError:
            raise

        except Exception as exc:  # pragma: no cover - defensive normalization
            raise TransportError(str(exc)) from exc

    def _send_limited(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes | None,
        *,
        max_bytes: int,
    ) -> HttpExchange:
        outbound_headers = dict(headers)
        management_host = self._management_host_header_value()
        if management_host is not None:
            outbound_headers["Host"] = management_host
        try:
            return self.http_client.request_limited(
                method=method,
                path=path,
                headers=outbound_headers,
                body=body,
                max_bytes=max_bytes,
                **self._http_client_kwargs(),
            )
        except (TransportTimeout, AllowlistViolation, AuthFailed, TransportError):
            raise
        except Exception as exc:  # pragma: no cover - defensive normalization
            raise TransportError(str(exc)) from exc

    def _build_digest_header(self, method: str, path: str) -> str:

        if not self._digest_challenge:
            raise AuthFailed("missing digest challenge")

        challenge = self._digest_challenge

        username = _validate_digest_interpolated(self.username)

        realm = _validate_digest_interpolated(challenge.get("realm", ""))

        nonce = _validate_digest_interpolated(challenge.get("nonce", ""))

        qop = _validate_digest_interpolated(challenge.get("qop", "auth"))

        algorithm = challenge.get("algorithm", "MD5")

        opaque = challenge.get("opaque")

        if opaque is not None:
            opaque = _validate_digest_interpolated(opaque)

        if algorithm.upper() != "MD5":
            raise AuthFailed("unsupported digest algorithm")

        self._nc += 1

        nc = f"{self._nc:08x}"

        cnonce = secrets.token_hex(8)

        ha1 = _md5(f"{username}:{realm}:{self.password}")

        ha2 = _md5(f"{method}:{path}")

        if qop:
            response = _md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")

            header = (
                f'Digest username="{username}", realm="{realm}", nonce="{nonce}", '
                f'uri="{path}", algorithm=MD5, response="{response}", qop={qop}, nc={nc}, '
                f'cnonce="{cnonce}"'
            )

            if opaque is not None:
                header += f', opaque="{opaque}"'

            return header

        response = _md5(f"{ha1}:{nonce}:{ha2}")

        header = (
            f'Digest username="{username}", realm="{realm}", nonce="{nonce}", '
            f'uri="{path}", algorithm=MD5, response="{response}"'
        )

        if opaque is not None:
            header += f', opaque="{opaque}"'

        return header


@dataclass
class SshTunnelNetcrazeTransport(NetcrazeTransport):
    """RCI transport over pinned SSH local forward; labels certify authenticated encryption."""

    ssh_host_key_algorithm: str = ""
    ssh_host_key_fingerprint_sha256: str = ""
    source_address: str = ""

    def __post_init__(self) -> None:

        super().__post_init__()

        if not self.management_host_header:
            raise ValueError("management host header is required for SSH tunnel transport")

        validated = resolve_ssh_management_host_header(
            self.management_host_header,
            tcp_host=self.host,
        )

        object.__setattr__(self, "management_host_header", validated)

        if self.source_address:
            from router_control.adapters.netcraze.ssh_tunnel import validate_source_address

            object.__setattr__(
                self,
                "source_address",
                validate_source_address(self.source_address),
            )

    def _management_host_header_value(self) -> str | None:

        return resolve_ssh_management_host_header(
            self.management_host_header,
            tcp_host=self.host,
        )

    @property
    def transport_security_label(self) -> str:

        return "ssh_tunnel"

    @property
    def https_check_label(self) -> str:

        if self.ssh_host_key_algorithm and self.ssh_host_key_fingerprint_sha256:
            return "ssh_host_key_pinned"
        return "not_certified"

    @property
    def gate_a_certification_eligible(self) -> bool:

        return bool(self.ssh_host_key_algorithm and self.ssh_host_key_fingerprint_sha256)

    def fetch_startup_config_bounded(self, *, max_bytes: int) -> HttpExchange:
        """Fetch only the fixed startup-config endpoint with bounded response reading."""
        path = "/ci/startup-config.txt"
        headers = self._base_headers(None)
        headers["Accept"] = "text/plain"
        exchange = self._send_limited("GET", path, headers, None, max_bytes=max_bytes)

        if exchange.status == 401:
            challenge = exchange.headers.get("www-authenticate", "")
            strategy = _select_auth_strategy(challenge)
            if strategy is AuthStrategy.DIGEST:
                parsed = _parse_digest_challenge(challenge)
                self._digest_challenge = _validated_digest_challenge(parsed)
                headers["Authorization"] = self._build_digest_header("GET", path)
            elif strategy is AuthStrategy.INTERACTIVE:
                self._run_interactive_auth(challenge)
                self._apply_session_cookie(headers)
            exchange = self._send_limited("GET", path, headers, None, max_bytes=max_bytes)
            if exchange.status == 401:
                raise AuthFailed("authentication failed after retry")

        return exchange

    def fetch_discovery_read(
        self,
        command: ReadCommand,
        *,
        max_bytes: int = DEFAULT_DISCOVERY_MAX_BYTES,
    ) -> Any:
        """Fetch only discovery-allowlisted reads over pinned SSH with source bind."""
        if not is_discovery_allowlisted(command.method, command.path):
            raise AllowlistViolation(
                f"command not discovery-allowlisted: {command.method} {command.path}"
            )
        if not self.gate_a_certification_eligible:
            raise TransportError("discovery read requires pinned SSH host key")
        if not self.source_address:
            raise TransportError("discovery read requires validated source_address")
        path = command.path
        method = command.method
        headers = self._base_headers(None)
        exchange = self._send_limited(method, path, headers, None, max_bytes=max_bytes)

        if exchange.status == 401:
            challenge = exchange.headers.get("www-authenticate", "")
            strategy = _select_auth_strategy(challenge)
            if strategy is AuthStrategy.DIGEST:
                parsed = _parse_digest_challenge(challenge)
                self._digest_challenge = _validated_digest_challenge(parsed)
                headers["Authorization"] = self._build_digest_header(method, path)
            elif strategy is AuthStrategy.INTERACTIVE:
                self._run_interactive_auth(challenge)
                self._apply_session_cookie(headers)
            exchange = self._send_limited(method, path, headers, None, max_bytes=max_bytes)
            if exchange.status == 401:
                raise AuthFailed("authentication failed after retry")

        if exchange.status >= 400:
            raise TransportError(f"HTTP {exchange.status}")

        if len(exchange.body) > max_bytes:
            raise TransportError("discovery response exceeds size bound")

        return _loads_json_response(exchange.body, strict_utf8=False)


def _select_auth_strategy(challenge: str) -> AuthStrategy:

    normalized = challenge.strip().lower()

    if normalized.startswith("digest"):
        return AuthStrategy.DIGEST

    if normalized.startswith("x-ndw2-interactive"):
        return AuthStrategy.INTERACTIVE

    raise AuthFailed("unsupported authentication challenge")


def _parse_auth_params(header: str, scheme_prefix: str) -> dict[str, str]:

    normalized = header.strip()

    prefix = scheme_prefix.lower()

    if not normalized.lower().startswith(prefix):
        raise AuthFailed("challenge scheme mismatch")

    rest = normalized[len(scheme_prefix) :].strip()

    params: dict[str, str] = {}

    for match in _DIGEST_PARAM_RE.finditer(rest):
        key = match.group(1).lower()

        value = match.group(2) if match.group(2) is not None else match.group(3)

        params[key] = value.strip()

    return params


def _parse_digest_challenge(header: str) -> dict[str, str]:

    return _parse_auth_params(header, "Digest")


def _validated_digest_challenge(challenge: dict[str, str]) -> dict[str, str]:

    validated: dict[str, str] = {}

    for key, value in challenge.items():
        if key == "algorithm":
            validated[key] = value.strip()

            continue

        validated[key] = _validate_digest_interpolated(value)

    return validated


def _validate_cookie_token(token: str) -> None:

    if not token or not _COOKIE_TOKEN_RE.match(token):
        raise AuthFailed("invalid cookie token")


def _validate_cookie_name_only(raw: str) -> str:

    stripped = raw.strip()

    if not stripped or "=" in stripped:
        raise AuthFailed("invalid session cookie name")

    if _UNSAFE_INTERPOLATED_VALUE_RE.search(stripped):
        raise AuthFailed("invalid session cookie name")

    _validate_cookie_token(stripped)

    return stripped


def _all_set_cookies(exchange: HttpExchange) -> tuple[str, ...]:

    if exchange.set_cookies:
        return exchange.set_cookies

    fallback = exchange.headers.get("set-cookie")

    if fallback:
        return (fallback,)

    return ()


def _parse_set_cookie_name_value(raw: str) -> tuple[str, str] | None:

    cookie_part = raw.split(";", 1)[0].strip()

    if not cookie_part or "=" not in cookie_part:
        return None

    name, _, value = cookie_part.partition("=")

    name = name.strip()

    value = value.strip()

    if not name:
        return None

    return name, value


def _extract_mandatory_set_cookie(
    exchange: HttpExchange,
    *,
    expected_name: str,
) -> tuple[str, str]:

    matching: list[tuple[str, str]] = []

    for raw in _all_set_cookies(exchange):
        parsed = _parse_set_cookie_name_value(raw)

        if parsed is None:
            continue

        name, value = parsed

        if name != expected_name:
            continue

        try:
            _validate_cookie_token(name)

            _validate_cookie_token(value)

        except AuthFailed as exc:
            raise AuthFailed("authentication failed") from exc

        matching.append((name, value))

    if len(matching) != 1:
        raise AuthFailed("authentication failed")

    return matching[0]


def _extract_optional_set_cookie(
    exchange: HttpExchange,
    *,
    expected_name: str | None,
) -> tuple[str, str] | None:

    if expected_name is None:
        return None

    matching: list[tuple[str, str]] = []

    for raw in _all_set_cookies(exchange):
        parsed = _parse_set_cookie_name_value(raw)

        if parsed is None:
            continue

        name, value = parsed

        if name != expected_name:
            continue

        try:
            _validate_cookie_token(name)

            _validate_cookie_token(value)

        except AuthFailed as exc:
            raise AuthFailed("authentication failed") from exc

        matching.append((name, value))

    if len(matching) > 1:
        raise AuthFailed("authentication failed")

    if len(matching) == 1:
        return matching[0]

    return None


def _validate_interactive_challenge_field(value: str) -> str:

    stripped = value.strip()

    if not stripped or _UNSAFE_INTERPOLATED_VALUE_RE.search(stripped):
        raise AuthFailed("interactive challenge headers missing")

    return stripped


def _validate_digest_interpolated(value: str) -> str:

    stripped = value.strip()

    if not stripped or _UNSAFE_INTERPOLATED_VALUE_RE.search(stripped):
        raise AuthFailed("invalid digest challenge")

    return stripped


def _compute_interactive_response(token: str, login: str, realm: str, password: str) -> str:

    ha1 = _md5(f"{login}:{realm}:{password}")

    return _sha256_hex(f"{token}{ha1}")


def _loads_json_response(raw: bytes, *, strict_utf8: bool) -> Any:
    """Decode HTTP JSON body; read paths tolerate invalid UTF-8 but fail closed on corruption."""
    try:
        if strict_utf8:
            text = raw.decode("utf-8")
        else:
            text = raw.decode("utf-8", errors="replace")
            if "\ufffd" in text:
                raise TransportError("response payload encoding corrupted")
    except UnicodeDecodeError as exc:
        raise TransportError("response payload is not valid UTF-8") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise TransportError("invalid JSON response") from exc


def _response_continued(payload: Any) -> bool:

    if isinstance(payload, dict):
        continued = payload.get("continued")

        return continued is True

    return False


def _md5(value: str) -> str:

    return hashlib.md5(value.encode("utf-8")).hexdigest()


def _sha256_hex(value: str) -> str:

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _parse_dotted_ipv4_authority(candidate: str) -> ipaddress.IPv4Address | None:

    parts = candidate.split(".")

    if len(parts) != 4:
        return None

    if any(len(part) > 1 and part.startswith("0") for part in parts):
        return None

    try:
        octets = [int(part, 10) for part in parts]

    except ValueError:
        return None

    if any(octet < 0 or octet > 255 for octet in octets):
        return None

    return ipaddress.IPv4Address(".".join(str(octet) for octet in octets))


def _parse_authority_ip(
    candidate: str,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:

    inner = candidate.strip()

    if inner.startswith("[") and inner.endswith("]"):
        inner = inner[1:-1]

    try:
        return ipaddress.ip_address(inner)

    except ValueError:
        return _parse_dotted_ipv4_authority(inner)


def _looks_like_legacy_ipv4_authority(candidate: str) -> bool:

    inner = candidate[:-1] if candidate.endswith(".") else candidate

    parts = inner.split(".")

    return 1 <= len(parts) <= 4 and all(_LEGACY_IPV4_PART_RE.fullmatch(part) for part in parts)


def _reject_trailing_port(candidate: str) -> None:

    if candidate.startswith("[") and "]:" in candidate:
        raise ValueError("management host must not include port")

    parsed = _parse_authority_ip(candidate)

    if parsed is not None and isinstance(parsed, ipaddress.IPv6Address):
        return

    if ":" not in candidate:
        return

    prefix, suffix = candidate.rsplit(":", 1)

    if not suffix.isdigit() or not (1 <= int(suffix) <= 65535):
        return

    if _parse_authority_ip(prefix) is not None:
        raise ValueError("management host must not include port")


def _canonicalize_host_authority(authority: str) -> str:

    inner = authority.strip()

    if inner.startswith("[") and inner.endswith("]"):
        inner = inner[1:-1]

    parsed = _parse_authority_ip(inner)

    if parsed is not None:
        if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
            return str(parsed.ipv4_mapped)

        return str(parsed)

    host = inner.lower()

    if host.endswith("."):
        host = host[:-1]

    return host


def is_loopback_management_host(authority: str) -> bool:

    canonical = _canonicalize_host_authority(authority)

    if canonical == "localhost":
        return True

    parsed = _parse_authority_ip(canonical)

    if parsed is None:
        return False

    if parsed.is_loopback:
        return True

    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        return parsed.ipv4_mapped.is_loopback

    return False


def resolve_ssh_management_host_header(management: str, *, tcp_host: str) -> str:

    validated = validate_management_host_authority(management)

    if is_loopback_management_host(validated):
        raise ValueError("management host must not be loopback")

    if _canonicalize_host_authority(validated) == _canonicalize_host_authority(tcp_host):
        raise ValueError("management host must differ from transport TCP endpoint")

    return validated


def validate_management_host_authority(authority: str) -> str:

    if not authority or not authority.strip():
        raise ValueError("management host is required")

    candidate = authority.strip()

    if _UNSAFE_MANAGEMENT_HOST_RE.search(candidate):
        raise ValueError("management host contains invalid characters")

    if any(ch in candidate for ch in ("@", "/", "?", "#")):
        raise ValueError("management host must not contain userinfo or URL components")

    _reject_trailing_port(candidate)

    if candidate.startswith("["):
        if not candidate.endswith("]") or candidate.count("[") != 1:
            raise ValueError("malformed IPv6 management host")

        inner = candidate[1:-1]

        if not inner or ":" not in inner:
            raise ValueError("malformed IPv6 management host")

        parsed = _parse_authority_ip(f"[{inner}]")

        if parsed is None or not isinstance(parsed, ipaddress.IPv6Address):
            raise ValueError("malformed IPv6 management host")

        return f"[{parsed.compressed}]"

    parsed_ip = _parse_authority_ip(candidate)

    if parsed_ip is None and candidate.endswith("."):
        parsed_ip = _parse_authority_ip(candidate[:-1])

    if parsed_ip is not None:
        if isinstance(parsed_ip, ipaddress.IPv6Address):
            return f"[{parsed_ip.compressed}]"

        return str(parsed_ip)

    if ":" in candidate:
        raise ValueError("malformed management host")

    if _looks_like_legacy_ipv4_authority(candidate):
        raise ValueError("ambiguous numeric management host")

    if not _is_valid_hostname(candidate):
        raise ValueError("malformed management host")

    return candidate


def derive_management_host_header(host: str) -> str:

    from urllib.parse import unquote

    target = parse_transport_target(host)

    hostname = unquote(target.hostname or "")

    return validate_management_host_authority(hostname)


def _is_valid_hostname(hostname: str) -> bool:

    if not hostname or len(hostname) > 253:
        return False

    if hostname.endswith("."):
        hostname = hostname[:-1]

    labels = hostname.split(".")

    if not labels or any(not label for label in labels):
        return False

    label_re = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")

    return all(label_re.match(label) for label in labels)


def _host_contains_userinfo(host: str) -> bool:

    if "://" in host:
        parsed = urlparse(host)

        return parsed.username is not None or parsed.password is not None

    return "@" in host


def normalize_management_host(host: str) -> str:
    """Strip scheme, userinfo, and port for management-host identity matching."""
    candidate = host.strip()
    if not candidate:
        return ""

    authority = candidate.split("/", 1)[0]
    if "://" in candidate:
        parsed = urlparse(candidate)
        hostname = parsed.hostname
    else:
        parsed = urlparse(f"//{authority}")
        hostname = parsed.hostname

    if hostname:
        return hostname.strip()

    fallback = authority
    if fallback.count(":") == 1 and not fallback.startswith("["):
        fallback = fallback.split(":", 1)[0]
    return fallback.strip()


def parse_transport_target(host: str) -> TransportTarget:

    if _host_contains_userinfo(host):
        raise ValueError("host must not contain embedded credentials")

    if "://" in host:
        parsed = urlparse(host)

        scheme = (parsed.scheme or "https").lower()

        hostname = parsed.hostname or host

        if scheme == "https":
            port = parsed.port or 443

            use_tls = True

        elif scheme == "http":
            port = parsed.port or 80

            use_tls = False

        else:
            raise ValueError(f"unsupported scheme: {scheme}")

        return TransportTarget(hostname=hostname, port=port, use_tls=use_tls, scheme=scheme)

    if ":" in host and host.count(":") == 1:
        hostname, port_str = host.rsplit(":", 1)

        return TransportTarget(
            hostname=hostname,
            port=int(port_str),
            use_tls=True,
            scheme="https",
        )

    return TransportTarget(hostname=host, port=443, use_tls=True, scheme="https")


def host_port_from_target(host: str, *, default_port: int = 443) -> tuple[str, int]:

    target = parse_transport_target(host)

    if "://" not in host and ":" not in host:
        return target.hostname, default_port

    return target.hostname, target.port
