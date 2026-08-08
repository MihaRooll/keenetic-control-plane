"""Host-key-pinned SSH local forward to verified router management RCI HTTP (port 80)."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import logging
import re
import select
import socket
import socketserver
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from router_control.adapters.netcraze.errors import (
    SshHostKeyMismatch,
    SshHostKeyMissing,
    SshHostKeyUnsupported,
    SshHostNotPrivate,
    SshParamikoMissing,
    SshTransientConnectionError,
    SshTunnelError,
)

logger = logging.getLogger(__name__)

REMOTE_RCI_PORT = 80
SSH_PORT = 22
LOCAL_BIND_HOST = "127.0.0.1"


class SshSourceAddressBindError(SshTunnelError):
    """Outbound TCP bind to source_address failed — no fallback permitted."""


class SshSourceAddressInvalid(SshTunnelError):
    """source_address is not a literal private unicast IP."""


_SUPPORTED_KEY_TYPES = frozenset({"ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256"})

_FAIL_SAFE_TIMER_REBOOT_60_COMMAND = "system configuration fail-safe timer reboot 60"
_FAIL_SAFE_EXEC_STDOUT_CAP = 4096
_FAIL_SAFE_EXEC_STDERR_CAP = 1024
_FAIL_SAFE_ACK_PATTERNS = (
    re.compile(rb"(?i)fail[-\s]?safe"),
    re.compile(rb"(?i)timer"),
    re.compile(rb"(?i)reboot"),
    re.compile(rb"(?i)\b60\b"),
)


def _lazy_import_paramiko() -> Any:
    try:
        import paramiko  # type: ignore[import-untyped]
    except ImportError as exc:
        raise SshParamikoMissing(
            "paramiko is required for SSH tunnel transport; install hardware extra"
        ) from exc
    return paramiko


_SHA256_FINGERPRINT_DIGEST_RE = re.compile(r"^[A-Za-z0-9+/]{43}$")


def normalize_sha256_fingerprint(value: str) -> str:
    stripped = value.strip()
    if not stripped:
        raise SshHostKeyMissing("SSH host key SHA256 fingerprint is required")
    upper = stripped.upper()
    if upper.startswith("SHA256:"):
        digest_part = stripped.split(":", 1)[1].strip()
    else:
        digest_part = stripped
    if not digest_part:
        raise SshHostKeyMissing("SSH host key SHA256 fingerprint is required")
    if not _SHA256_FINGERPRINT_DIGEST_RE.fullmatch(digest_part):
        raise SshHostKeyMissing(
            "SSH host key SHA256 fingerprint digest must be 43-character OpenSSH base64"
        )
    return f"SHA256:{digest_part}"


def compute_host_key_fingerprint(key: Any) -> tuple[str, str]:
    key_type = str(getattr(key, "get_name", lambda: "")())
    if key_type not in _SUPPORTED_KEY_TYPES:
        raise SshHostKeyUnsupported(f"unsupported SSH host key type: {key_type or 'unknown'}")
    key_bytes = key.asbytes()
    digest = hashlib.sha256(key_bytes).digest()
    fingerprint = f"SHA256:{base64.b64encode(digest).decode('ascii').rstrip('=')}"
    return key_type, fingerprint


def strip_host_brackets(hostname: str) -> str:
    candidate = hostname.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        return candidate[1:-1]
    return candidate


_HOST_DNS_RESOLVE_TIMEOUT_S = 3.0

# Cloud instance metadata (link-local 169.254.169.0/24) must not qualify as lab-private SSH.
_CLOUD_METADATA_IPV4_NETWORK = ipaddress.IPv4Network("169.254.169.0/24")


def _is_cloud_metadata_ipv4(addr: ipaddress.IPv4Address) -> bool:
    return addr in _CLOUD_METADATA_IPV4_NETWORK


def _address_is_private_like(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(addr, ipaddress.IPv4Address) and _is_cloud_metadata_ipv4(addr):
        return False
    return bool(addr.is_private or addr.is_link_local or addr.is_loopback)


def _getaddrinfo_bounded(
    hostname: str,
    *,
    timeout: float = _HOST_DNS_RESOLVE_TIMEOUT_S,
) -> list[tuple[int, int, int, str, tuple[str, int]]] | None:
    """Resolve hostname with bounded wait; None on timeout or resolver failure."""
    result: list[list[tuple[int, int, int, str, tuple[str, int]]]] = []
    error: list[OSError] = []

    def _resolve() -> None:
        try:
            raw = socket.getaddrinfo(
                hostname,
                0,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
            )
            result.append(raw)
        except OSError as exc:
            error.append(exc)

    thread = threading.Thread(target=_resolve, daemon=True, name="ssh-tunnel-dns")
    thread.start()
    thread.join(timeout=timeout)
    if thread.is_alive():
        return None
    if error:
        return None
    return result[0] if result else None


def _split_literal_zone(candidate: str) -> tuple[str, str | None]:
    if "%" in candidate:
        ip_part, zone = candidate.split("%", 1)
        return ip_part, zone or None
    return candidate, None


def _format_connect_address_from_sockaddr(sockaddr: tuple[Any, ...]) -> str:
    if not sockaddr:
        raise ValueError("empty sockaddr")
    host = str(sockaddr[0])
    if len(sockaddr) >= 4 and sockaddr[3]:
        scope_id = int(sockaddr[3])
        if scope_id and "%" not in host:
            return f"{host}%{scope_id}"
    return host


def resolve_private_connect_targets(hostname: str) -> list[str]:
    """Resolve once and return vetted private-like dial targets; fail-closed otherwise."""
    candidate = strip_host_brackets(hostname.strip())
    if not candidate:
        raise SshHostNotPrivate("SSH host must be in a private address range")

    ip_part, _zone = _split_literal_zone(candidate)
    try:
        addr = ipaddress.ip_address(ip_part)
    except ValueError:
        pass
    else:
        if not _address_is_private_like(addr):
            raise SshHostNotPrivate("SSH host must be in a private address range")
        return [candidate]

    infos = _getaddrinfo_bounded(candidate)
    if not infos:
        raise SshHostNotPrivate("SSH host must be in a private address range")

    targets: list[str] = []
    seen: set[str] = set()
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        try:
            addr = ipaddress.ip_address(_split_literal_zone(str(sockaddr[0]))[0])
        except ValueError:
            raise SshHostNotPrivate("SSH host must be in a private address range") from None
        if not _address_is_private_like(addr):
            raise SshHostNotPrivate("SSH host must be in a private address range")
        connect_host = _format_connect_address_from_sockaddr(sockaddr)
        if connect_host not in seen:
            seen.add(connect_host)
            targets.append(connect_host)

    if not targets:
        raise SshHostNotPrivate("SSH host must be in a private address range")
    return targets


def host_is_private(hostname: str) -> bool:
    try:
        resolve_private_connect_targets(hostname)
        return True
    except SshHostNotPrivate:
        return False


def _connect_private_tcp(
    host: str,
    port: int,
    *,
    timeout: float,
    source_address: str | None = None,
    allow_loopback_test_seam: bool = False,
    allow_non_private: bool = False,
    dial_targets: list[str] | None = None,
) -> socket.socket:
    """Dial SSH/TCP using a pinned vetted address set (no hostname re-resolve)."""
    if dial_targets is None:
        if allow_non_private:
            dial_targets = [strip_host_brackets(host)]
        elif allow_loopback_test_seam:
            candidate = strip_host_brackets(host.strip())
            try:
                dial_targets = resolve_private_connect_targets(host)
            except SshHostNotPrivate:
                dial_targets = [candidate] if candidate else []
                if not dial_targets:
                    raise SshHostNotPrivate("SSH host must be in a private address range") from None
        else:
            dial_targets = resolve_private_connect_targets(host)

    last_error: OSError | None = None
    for target in dial_targets:
        try:
            return create_bound_tcp_connection(
                target,
                port,
                timeout=timeout,
                source_address=source_address,
                allow_loopback_test_seam=allow_loopback_test_seam,
            )
        except OSError as exc:
            last_error = exc
    if last_error is not None:
        raise last_error
    raise SshHostNotPrivate("SSH host must be in a private address range")


def validate_source_address(
    address: str,
    *,
    allow_loopback_test_seam: bool = False,
) -> str:
    """Validate literal private unicast source bind address."""

    candidate = address.strip()
    if not candidate:
        raise SshSourceAddressInvalid("source_address must be a non-empty literal IP")
    try:
        addr = ipaddress.ip_address(candidate)
    except ValueError as exc:
        raise SshSourceAddressInvalid(
            "source_address must be a literal IPv4 or IPv6 address"
        ) from exc
    if addr.is_multicast or addr.is_unspecified:
        raise SshSourceAddressInvalid("source_address must not be wildcard or multicast")
    if isinstance(addr, ipaddress.IPv4Address) and int(addr) == 0xFFFFFFFF:
        raise SshSourceAddressInvalid("source_address must not be broadcast")
    if addr.is_loopback and not allow_loopback_test_seam:
        raise SshSourceAddressInvalid("source_address must not be loopback")
    if getattr(addr, "is_link_local", False):
        raise SshSourceAddressInvalid("source_address must be a private unicast address")
    if not addr.is_private:
        raise SshSourceAddressInvalid("source_address must be a private unicast address")
    return str(addr)


def source_address_class(address: str) -> str:
    addr = ipaddress.ip_address(address)
    if addr.version == 4:
        return "private_ipv4_literal"
    return "private_ipv6_literal"


def preflight_source_address_bind(
    source_address: str,
    *,
    allow_loopback_test_seam: bool = False,
) -> str:
    """Verify local source_address is bindable before credential materialization."""

    bound = validate_source_address(
        source_address,
        allow_loopback_test_seam=allow_loopback_test_seam,
    )
    addr = ipaddress.ip_address(bound)
    family = socket.AF_INET if addr.version == 4 else socket.AF_INET6
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.bind((bound, 0))
    except OSError as exc:
        raise SshSourceAddressBindError(
            f"failed to bind outbound TCP to source_address {bound}"
        ) from exc
    finally:
        sock.close()
    return bound


def create_bound_tcp_connection(
    host: str,
    port: int,
    *,
    timeout: float,
    source_address: str | None = None,
    allow_loopback_test_seam: bool = False,
) -> socket.socket:
    """Create outbound TCP connection, optionally bound to source_address."""

    connect_target = (strip_host_brackets(host), port)
    if source_address is None:
        return socket.create_connection(connect_target, timeout=timeout)
    bound = validate_source_address(
        source_address,
        allow_loopback_test_seam=allow_loopback_test_seam,
    )
    addr = ipaddress.ip_address(bound)
    family = socket.AF_INET if addr.version == 4 else socket.AF_INET6
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.bind((bound, 0))
    except OSError as exc:
        sock.close()
        raise SshSourceAddressBindError(
            f"failed to bind outbound TCP to source_address {bound}"
        ) from exc
    try:
        sock.connect(connect_target)
    except OSError:
        sock.close()
        raise
    return sock


def validate_ssh_tunnel_host(host: str) -> str:
    from router_control.adapters.netcraze.transport import (
        is_loopback_management_host,
        validate_management_host_authority,
    )

    try:
        validated = validate_management_host_authority(host)
    except ValueError as exc:
        raise SshTunnelError(str(exc)) from None
    if is_loopback_management_host(validated):
        raise SshTunnelError("SSH host must not be loopback")
    return validated


def sanitize_ssh_error_message(message: str, *, password: str) -> str:
    sanitized = message
    if password:
        sanitized = sanitized.replace(password, "[REDACTED]")
    return sanitized


@dataclass(frozen=True, slots=True)
class LearnedSshHostKey:
    """Public host-key material from a pre-auth SSH handshake (not a session)."""

    algorithm: str
    fingerprint_sha256: str


def learn_ssh_host_key(
    host: str,
    *,
    port: int = SSH_PORT,
    connect_timeout: float = 10.0,
    source_address: str | None = None,
    allow_loopback_test_seam: bool = False,
    transport_factory: Callable[..., Any] | None = None,
) -> LearnedSshHostKey:
    """Retrieve remote SSH host key without authentication or usable tunnel."""
    canonical_host = validate_ssh_tunnel_host(host)
    if source_address is not None:
        validate_source_address(
            source_address,
            allow_loopback_test_seam=allow_loopback_test_seam,
        )
    if allow_loopback_test_seam:
        try:
            dial_targets = resolve_private_connect_targets(canonical_host)
        except SshHostNotPrivate:
            dial_targets = [strip_host_brackets(canonical_host)]
    else:
        dial_targets = resolve_private_connect_targets(canonical_host)
    transport: Any | None = None
    sock: socket.socket | None = None
    paramiko = _lazy_import_paramiko()
    ssh_exception_cls = getattr(
        getattr(paramiko, "ssh_exception", None),
        "SSHException",
        None,
    )
    if ssh_exception_cls is None:
        raise SshParamikoMissing("Paramiko SSHException type unavailable")
    try:
        try:
            if transport_factory is not None:
                transport = transport_factory(
                    host=canonical_host,
                    port=port,
                    connect_timeout=connect_timeout,
                    source_address=source_address,
                    allow_loopback_test_seam=allow_loopback_test_seam,
                )
                transport.start_client(timeout=connect_timeout)
            else:
                sock = _connect_private_tcp(
                    canonical_host,
                    port,
                    timeout=connect_timeout,
                    source_address=source_address,
                    allow_loopback_test_seam=allow_loopback_test_seam,
                    dial_targets=dial_targets,
                )
                transport = paramiko.Transport(sock)
                sock = None
                transport.start_client(timeout=connect_timeout)
            server_key = transport.get_remote_server_key()
            algorithm, fingerprint = compute_host_key_fingerprint(server_key)
            return LearnedSshHostKey(algorithm=algorithm, fingerprint_sha256=fingerprint)
        except ssh_exception_cls:
            raise SshTunnelError(
                "Could not reach the router to learn the SSH host key"
            ) from None
    finally:
        if transport is not None:
            try:
                transport.close()
            except Exception:
                logger.debug("learn_ssh_host_key transport close failed", exc_info=True)
        elif sock is not None:
            sock.close()


@dataclass(frozen=True, slots=True)
class SshTunnelConfig:
    ssh_host: str
    username: str
    host_key_sha256: str
    password: str = field(repr=False)
    connect_timeout: float = 10.0
    auth_timeout: float = 10.0
    channel_timeout: float = 15.0
    allow_non_private: bool = False
    source_address: str | None = None
    allow_loopback_test_seam: bool = False
    connect_retry_attempts: int = 2
    connect_retry_delay_seconds: float = 0.5


class _ForwardHandler(socketserver.BaseRequestHandler):
    ssh_transport: Any
    remote_host: str
    remote_port: int
    channel_timeout: float

    def handle(self) -> None:
        try:
            chan = self.ssh_transport.open_channel(
                "direct-tcpip",
                (self.remote_host, self.remote_port),
                self.request.getpeername(),
                timeout=self.channel_timeout,
            )
        except Exception:
            return
        if chan is None:
            return
        try:
            while True:
                readable, _, _ = select.select([self.request, chan], [], [], 1.0)
                if self.request in readable:
                    data = self.request.recv(4096)
                    if not data:
                        break
                    chan.sendall(data)
                if chan in readable:
                    data = chan.recv(4096)
                    if not data:
                        break
                    self.request.sendall(data)
        finally:
            chan.close()


class _ForwardServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


@dataclass
class PinnedSshTunnel:
    """Context-managed pinned SSH tunnel forwarding local ephemeral port to router RCI."""

    config: SshTunnelConfig
    _transport_factory: Callable[[SshTunnelConfig], Any] | None = field(default=None, repr=False)

    _transport: Any = field(default=None, init=False, repr=False)
    _forward_server: _ForwardServer | None = field(default=None, init=False, repr=False)
    _local_port: int = field(default=0, init=False, repr=False)
    _host_key_algorithm: str = field(default="", init=False, repr=False)
    _host_key_fingerprint_sha256: str = field(default="", init=False, repr=False)
    _remote_rci_host: str = field(default="", init=False, repr=False)
    _pinned_ssh_targets: list[str] = field(default_factory=list, init=False, repr=False)
    _closed: bool = field(default=False, init=False, repr=False)

    def __enter__(self) -> PinnedSshTunnel:
        self.open()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    @property
    def local_host(self) -> str:
        return LOCAL_BIND_HOST

    @property
    def local_port(self) -> int:
        if self._local_port == 0:
            raise SshTunnelError("SSH tunnel is not open")
        return self._local_port

    @property
    def host_key_algorithm(self) -> str:
        return self._host_key_algorithm

    @property
    def host_key_fingerprint_sha256(self) -> str:
        return self._host_key_fingerprint_sha256

    def open(self) -> None:
        if self._transport is not None:
            return
        canonical_ssh_host = validate_ssh_tunnel_host(self.config.ssh_host)
        if self.config.allow_non_private:
            self._pinned_ssh_targets = [strip_host_brackets(canonical_ssh_host)]
        else:
            self._pinned_ssh_targets = resolve_private_connect_targets(canonical_ssh_host)
        self._remote_rci_host = canonical_ssh_host
        expected_fingerprint = normalize_sha256_fingerprint(self.config.host_key_sha256)
        if self.config.source_address is not None:
            validate_source_address(
                self.config.source_address,
                allow_loopback_test_seam=self.config.allow_loopback_test_seam,
            )
        transport = self._acquire_transport_with_retry(expected_fingerprint)
        self._start_forwarder(transport)
        self._transport = transport

    def _acquire_transport_with_retry(self, expected_fingerprint: str) -> Any:
        max_attempts = max(1, self.config.connect_retry_attempts)
        last_transient_error: SshTransientConnectionError | None = None
        for attempt in range(max_attempts):
            try:
                if self._transport_factory is not None:
                    transport = self._transport_factory(self.config)
                    self._verify_host_key(transport, expected_fingerprint)
                    return transport
                return self._connect_transport(expected_fingerprint)
            except SshTransientConnectionError as exc:
                last_transient_error = exc
                if attempt + 1 >= max_attempts:
                    raise
                time.sleep(self.config.connect_retry_delay_seconds)
        raise last_transient_error or SshTunnelError("SSH connection failed")

    @property
    def tcp_connect_host(self) -> str:
        return strip_host_brackets(self._remote_rci_host)

    def _authenticate_transport(self, transport: Any, paramiko: Any) -> None:
        auth_exception = getattr(
            getattr(paramiko, "ssh_exception", None),
            "AuthenticationException",
            None,
        )
        try:
            remaining = transport.auth_password(
                self.config.username,
                self.config.password,
                event=None,
            )
        except Exception as exc:
            if auth_exception is not None and isinstance(exc, auth_exception):
                raise SshTunnelError("SSH authentication failed") from None
            raise
        if remaining:
            raise SshTunnelError("SSH authentication failed")

    def _verify_host_key(self, transport: Any, expected_fingerprint: str) -> None:
        server_key = transport.get_remote_server_key()
        algorithm, fingerprint = compute_host_key_fingerprint(server_key)
        if fingerprint != expected_fingerprint:
            raise SshHostKeyMismatch("SSH host key fingerprint mismatch")
        self._host_key_algorithm = algorithm
        self._host_key_fingerprint_sha256 = fingerprint

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._forward_server is not None:
            try:
                self._forward_server.shutdown()
            except OSError:
                pass
            try:
                self._forward_server.server_close()
            except OSError:
                pass
            self._forward_server = None
        if self._transport is not None:
            try:
                self._transport.close()
            except Exception:
                logger.debug("SSH transport close failed", exc_info=True)
            self._transport = None
        self._local_port = 0

    def _connect_transport(self, expected_fingerprint: str) -> Any:
        paramiko = _lazy_import_paramiko()
        sock: socket.socket | None = None
        transport: Any | None = None
        try:
            sock = _connect_private_tcp(
                self._remote_rci_host,
                SSH_PORT,
                timeout=self.config.connect_timeout,
                source_address=self.config.source_address,
                allow_loopback_test_seam=self.config.allow_loopback_test_seam,
                allow_non_private=self.config.allow_non_private,
                dial_targets=self._pinned_ssh_targets,
            )
            transport = paramiko.Transport(sock)
            sock = None
            transport.auth_timeout = self.config.auth_timeout
            transport.start_client(timeout=self.config.connect_timeout)
            server_key = transport.get_remote_server_key()
            algorithm, fingerprint = compute_host_key_fingerprint(server_key)
            if fingerprint != expected_fingerprint:
                raise SshHostKeyMismatch("SSH host key fingerprint mismatch")
            self._host_key_algorithm = algorithm
            self._host_key_fingerprint_sha256 = fingerprint
            self._authenticate_transport(transport, paramiko)
            return transport
        except SshTunnelError:
            if transport is not None:
                transport.close()
            elif sock is not None:
                sock.close()
            raise
        except SshSourceAddressBindError:
            if transport is not None:
                transport.close()
            elif sock is not None:
                sock.close()
            raise
        except Exception as exc:
            if transport is not None:
                transport.close()
            elif sock is not None:
                sock.close()
            message = sanitize_ssh_error_message(str(exc), password=self.config.password)
            if isinstance(exc, (TimeoutError, socket.timeout)):
                raise SshTransientConnectionError("SSH connection timed out") from None
            raise SshTransientConnectionError(message) from None

    def _start_forwarder(self, transport: Any) -> None:
        if not self._host_key_algorithm:
            server_key = transport.get_remote_server_key()
            algorithm, fingerprint = compute_host_key_fingerprint(server_key)
            self._host_key_algorithm = algorithm
            self._host_key_fingerprint_sha256 = fingerprint

        handler = type(
            "PinnedForwardHandler",
            (_ForwardHandler,),
            {
                "ssh_transport": transport,
                "remote_host": strip_host_brackets(self._remote_rci_host),
                "remote_port": REMOTE_RCI_PORT,
                "channel_timeout": self.config.channel_timeout,
            },
        )
        server = _ForwardServer((LOCAL_BIND_HOST, 0), handler)
        self._local_port = int(server.server_address[1])
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self._forward_server = server


def _sha256_hex(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _read_bounded_channel_stream(channel: Any, *, cap: int, is_stderr: bool) -> bytes:
    stream = channel.stderr if is_stderr else channel
    chunks: list[bytes] = []
    total = 0
    while total < cap:
        try:
            chunk = stream.recv(min(4096, cap - total))
        except Exception:
            break
        if not chunk:
            break
        appended = chunk[: cap - total]
        appended_len = len(appended)
        if appended_len == 0:
            break
        chunks.append(appended)
        total += appended_len
    return b"".join(chunks)


def _fail_safe_ack_matched(stdout: bytes, stderr: bytes) -> bool:
    combined = stdout + stderr
    if not combined:
        return False
    matched = 0
    for pattern in _FAIL_SAFE_ACK_PATTERNS:
        if pattern.search(combined):
            matched += 1
    return matched >= len(_FAIL_SAFE_ACK_PATTERNS)


@dataclass(frozen=True, slots=True)
class FailSafeExecAck:
    ack_matched: bool
    exit_status: int
    stdout_byte_count: int
    stderr_byte_count: int
    stdout_sha256: str
    stderr_sha256: str


@dataclass
class FailSafeExecSession:
    channel: Any
    ack: FailSafeExecAck

    def close(self) -> bool:
        if self.channel is None:
            return True
        try:
            self.channel.close()
        except Exception:
            return False
        closed = bool(getattr(self.channel, "closed", True))
        self.channel = None
        return closed

    @property
    def is_closed(self) -> bool:
        if self.channel is None:
            return True
        return bool(getattr(self.channel, "closed", False))


def exec_fail_safe_timer_reboot_60(
    transport: Any,
    *,
    password: str,
    channel_timeout: float = 15.0,
    exec_timeout: float = 30.0,
    stdout_cap: int = _FAIL_SAFE_EXEC_STDOUT_CAP,
    stderr_cap: int = _FAIL_SAFE_EXEC_STDERR_CAP,
) -> FailSafeExecSession:
    """Sealed Paramiko exec for the single allowlisted fail-safe timer command."""
    is_active = getattr(transport, "is_active", None)
    if not callable(is_active) or not bool(is_active()):
        raise SshTunnelError("SSH transport is not active")
    paramiko = _lazy_import_paramiko()
    channel: Any | None = None
    try:
        channel = transport.open_session(timeout=channel_timeout)
        channel.settimeout(exec_timeout)
        channel.exec_command(_FAIL_SAFE_TIMER_REBOOT_60_COMMAND)
        stdout_bytes = _read_bounded_channel_stream(channel, cap=stdout_cap, is_stderr=False)
        stderr_bytes = _read_bounded_channel_stream(channel, cap=stderr_cap, is_stderr=True)
        exit_status = int(channel.recv_exit_status())
    except Exception as exc:
        if channel is not None:
            try:
                channel.close()
            except Exception:
                logger.debug("fail-safe exec channel close failed", exc_info=True)
        auth_exception = getattr(
            getattr(paramiko, "ssh_exception", None),
            "AuthenticationException",
            None,
        )
        if auth_exception is not None and isinstance(exc, auth_exception):
            raise SshTunnelError("SSH authentication failed") from None
        message = sanitize_ssh_error_message(str(exc), password=password)
        if isinstance(exc, (TimeoutError, socket.timeout)):
            raise SshTunnelError("fail-safe exec timed out") from None
        raise SshTunnelError(message) from None

    ack = FailSafeExecAck(
        ack_matched=_fail_safe_ack_matched(stdout_bytes, stderr_bytes),
        exit_status=exit_status,
        stdout_byte_count=len(stdout_bytes),
        stderr_byte_count=len(stderr_bytes),
        stdout_sha256=_sha256_hex(stdout_bytes),
        stderr_sha256=_sha256_hex(stderr_bytes),
    )
    return FailSafeExecSession(channel=channel, ack=ack)


_SHOW_INTERFACE_HOME_COMMAND = b"show interface Home"
_SHELL_SHOW_INTERFACE_HOME_SEND = b"show interface Home\r\n"
_DISCOVERY_EXEC_STDOUT_CAP = 4096
_DISCOVERY_EXEC_STDERR_CAP = 1024
_DISCOVERY_SHELL_READ_CAP = 8192
_DISCOVERY_SHELL_STAGE_TIMEOUT = 15.0
_DISCOVERY_EXEC_TIMEOUT = 20.0
_DISCOVERY_PROMPT_RE = re.compile(rb"\(config(?:-ssh)?\)>\s*$")
_DISCOVERY_EXEC_ERROR_CODES = frozenset(
    {
        "transport_inactive",
        "channel_open_failed",
        "exec_timeout",
        "read_truncated",
        "exit_status_unavailable",
        "channel_close_failed",
        "exec_rejected",
    }
)
_DISCOVERY_SHELL_ERROR_CODES = frozenset(
    {
        "transport_inactive",
        "channel_open_failed",
        "pty_failed",
        "shell_invoke_failed",
        "initial_prompt_timeout",
        "command_send_failed",
        "prompt_return_timeout",
        "prompt_ambiguous",
        "read_truncated",
        "channel_close_failed",
        "shell_rejected",
    }
)


def _buffer_has_prompt_suffix(buffer: bytes) -> bool:
    stripped = buffer.rstrip(b"\r\n \t")
    if not stripped:
        return False
    return _DISCOVERY_PROMPT_RE.search(stripped) is not None


def _strip_prompt_framing(buffer: bytes) -> bytes:
    lines = buffer.splitlines(keepends=True)
    if not lines:
        return b""
    while lines and not lines[-1].strip():
        lines.pop()
    if lines and _buffer_has_prompt_suffix(lines[-1]):
        lines.pop()
    while lines and not lines[-1].strip():
        lines.pop()
    return b"".join(lines)


def _strip_command_echo(buffer: bytes, command: bytes) -> tuple[bytes, bool]:
    normalized = buffer.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    command_line = command.strip().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    if not command_line:
        return buffer, False
    lines = normalized.split(b"\n")
    for index, line in enumerate(lines):
        if line.strip() == command_line:
            remainder = b"\n".join(lines[index + 1 :])
            return remainder.replace(b"\n", b"\r\n"), True
    command_text = command_line.decode("ascii", errors="ignore").strip()
    if command_text and command_text.encode("ascii", errors="ignore") in normalized:
        start = normalized.find(command_text.encode("ascii", errors="ignore"))
        if start >= 0:
            end = start + len(command_text)
            return normalized[end:].lstrip(b"\r\n"), True
    return buffer, False


def _extract_shell_response_body(raw: bytes, command: bytes) -> tuple[bytes, bool, bool]:
    without_trailing_prompt = _strip_prompt_framing(raw)
    body, echo_stripped = _strip_command_echo(without_trailing_prompt, command.strip())
    body = _strip_prompt_framing(body)
    prompt_ambiguous = bool(raw) and not _buffer_has_prompt_suffix(raw)
    return body, echo_stripped, prompt_ambiguous


@dataclass(frozen=True, slots=True)
class ShowInterfaceHomeExecResult:
    classification: str
    channel_opened: bool
    exec_dispatched: bool
    exit_status_observed: bool
    exit_status: int | None
    stdout_byte_count: int
    stderr_byte_count: int
    stdout_sha256: str
    stderr_sha256: str
    response_body_byte_count: int
    response_body_sha256: str
    response_body_nonempty: bool
    truncated: bool
    timed_out: bool
    channel_closed_verified: bool
    error_code: str | None


@dataclass(frozen=True, slots=True)
class ShowInterfaceHomeShellResult:
    classification: str
    pty_allocated: bool
    shell_invoked: bool
    initial_prompt_observed: bool
    command_sent: bool
    prompt_return_observed: bool
    response_body_byte_count: int
    response_body_sha256: str
    response_body_nonempty: bool
    echo_stripped: bool
    truncated: bool
    timed_out: bool
    prompt_ambiguous: bool
    channel_closed_verified: bool
    error_code: str | None


@dataclass
class PinnedSshTransport:
    """Context-managed pinned SSH transport without RCI forward (read-only discovery)."""

    config: SshTunnelConfig
    _transport_factory: Callable[[SshTunnelConfig], Any] | None = field(default=None, repr=False)

    _transport: Any = field(default=None, init=False, repr=False)
    _host_key_algorithm: str = field(default="", init=False, repr=False)
    _host_key_fingerprint_sha256: str = field(default="", init=False, repr=False)
    _remote_host: str = field(default="", init=False, repr=False)
    _pinned_ssh_targets: list[str] = field(default_factory=list, init=False, repr=False)
    _closed: bool = field(default=False, init=False, repr=False)

    def __enter__(self) -> PinnedSshTransport:
        self.open()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    @property
    def transport(self) -> Any:
        if self._transport is None:
            raise SshTunnelError("SSH transport is not open")
        return self._transport

    @property
    def host_key_algorithm(self) -> str:
        return self._host_key_algorithm

    @property
    def host_key_fingerprint_sha256(self) -> str:
        return self._host_key_fingerprint_sha256

    @property
    def tcp_connect_host(self) -> str:
        return strip_host_brackets(self._remote_host)

    def open(self) -> None:
        if self._transport is not None:
            return
        canonical_ssh_host = validate_ssh_tunnel_host(self.config.ssh_host)
        if self.config.allow_non_private:
            self._pinned_ssh_targets = [strip_host_brackets(canonical_ssh_host)]
        else:
            self._pinned_ssh_targets = resolve_private_connect_targets(canonical_ssh_host)
        self._remote_host = canonical_ssh_host
        expected_fingerprint = normalize_sha256_fingerprint(self.config.host_key_sha256)
        if self.config.source_address is not None:
            validate_source_address(
                self.config.source_address,
                allow_loopback_test_seam=self.config.allow_loopback_test_seam,
            )
        self._transport = self._acquire_transport_with_retry(expected_fingerprint)

    def _acquire_transport_with_retry(self, expected_fingerprint: str) -> Any:
        max_attempts = max(1, self.config.connect_retry_attempts)
        last_transient_error: SshTransientConnectionError | None = None
        for attempt in range(max_attempts):
            try:
                if self._transport_factory is not None:
                    transport = self._transport_factory(self.config)
                    self._verify_host_key(transport, expected_fingerprint)
                    return transport
                return self._connect_transport(expected_fingerprint)
            except SshTransientConnectionError as exc:
                last_transient_error = exc
                if attempt + 1 >= max_attempts:
                    raise
                time.sleep(self.config.connect_retry_delay_seconds)
        raise last_transient_error or SshTunnelError("SSH connection failed")

    def close(self) -> bool:
        if self._closed:
            return self._transport is None
        self._closed = True
        if self._transport is None:
            return True
        try:
            self._transport.close()
        except Exception:
            logger.debug("SSH discovery transport close failed", exc_info=True)
            return False
        self._transport = None
        return True

    def _verify_host_key(self, transport: Any, expected_fingerprint: str) -> None:
        server_key = transport.get_remote_server_key()
        algorithm, fingerprint = compute_host_key_fingerprint(server_key)
        if fingerprint != expected_fingerprint:
            raise SshHostKeyMismatch("SSH host key fingerprint mismatch")
        self._host_key_algorithm = algorithm
        self._host_key_fingerprint_sha256 = fingerprint

    def _connect_transport(self, expected_fingerprint: str) -> Any:
        paramiko = _lazy_import_paramiko()
        sock: socket.socket | None = None
        transport: Any | None = None
        try:
            sock = _connect_private_tcp(
                self._remote_host,
                SSH_PORT,
                timeout=self.config.connect_timeout,
                source_address=self.config.source_address,
                allow_loopback_test_seam=self.config.allow_loopback_test_seam,
                allow_non_private=self.config.allow_non_private,
                dial_targets=self._pinned_ssh_targets,
            )
            transport = paramiko.Transport(sock)
            sock = None
            transport.auth_timeout = self.config.auth_timeout
            transport.start_client(timeout=self.config.connect_timeout)
            server_key = transport.get_remote_server_key()
            algorithm, fingerprint = compute_host_key_fingerprint(server_key)
            if fingerprint != expected_fingerprint:
                raise SshHostKeyMismatch("SSH host key fingerprint mismatch")
            self._host_key_algorithm = algorithm
            self._host_key_fingerprint_sha256 = fingerprint
            self._authenticate_transport(transport, paramiko)
            return transport
        except SshTunnelError:
            if transport is not None:
                transport.close()
            elif sock is not None:
                sock.close()
            raise
        except SshSourceAddressBindError:
            if transport is not None:
                transport.close()
            elif sock is not None:
                sock.close()
            raise
        except Exception as exc:
            if transport is not None:
                transport.close()
            elif sock is not None:
                sock.close()
            message = sanitize_ssh_error_message(str(exc), password=self.config.password)
            if isinstance(exc, (TimeoutError, socket.timeout)):
                raise SshTransientConnectionError("SSH connection timed out") from None
            raise SshTransientConnectionError(message) from None

    def _authenticate_transport(self, transport: Any, paramiko: Any) -> None:
        auth_exception = getattr(
            getattr(paramiko, "ssh_exception", None),
            "AuthenticationException",
            None,
        )
        try:
            remaining = transport.auth_password(
                self.config.username,
                self.config.password,
                event=None,
            )
        except Exception as exc:
            if auth_exception is not None and isinstance(exc, auth_exception):
                raise SshTunnelError("SSH authentication failed") from None
            raise
        if remaining:
            raise SshTunnelError("SSH authentication failed")


def _read_shell_until_prompt(
    channel: Any,
    *,
    cap: int,
    stage_timeout: float,
) -> tuple[bytes, bool, bool]:
    deadline = time.monotonic() + stage_timeout
    chunks: list[bytes] = []
    total = 0
    timed_out = False
    truncated = False
    while total < cap and time.monotonic() < deadline:
        remaining = min(4096, cap - total)
        try:
            if channel.recv_ready():
                chunk = channel.recv(remaining)
            else:
                _, readable, _ = select.select([channel], [], [], 0.2)
                if not readable:
                    continue
                chunk = channel.recv(remaining)
        except Exception:
            break
        if not chunk:
            break
        if not isinstance(chunk, (bytes, bytearray)):
            break
        chunk_bytes = bytes(chunk)
        chunks.append(chunk_bytes[: cap - total])
        total += len(chunks[-1])
        if _buffer_has_prompt_suffix(b"".join(chunks)):
            break
    else:
        if total >= cap:
            truncated = True
        elif time.monotonic() >= deadline:
            timed_out = True
    return b"".join(chunks), timed_out, truncated


def exec_show_interface_home(
    transport: Any,
    *,
    password: str,
    channel_timeout: float = 15.0,
    exec_timeout: float = _DISCOVERY_EXEC_TIMEOUT,
    stdout_cap: int = _DISCOVERY_EXEC_STDOUT_CAP,
    stderr_cap: int = _DISCOVERY_EXEC_STDERR_CAP,
) -> ShowInterfaceHomeExecResult:
    """Sealed Paramiko exec for fixed read-only show interface Home."""
    is_active = getattr(transport, "is_active", None)
    if not callable(is_active) or not bool(is_active()):
        return ShowInterfaceHomeExecResult(
            classification="exec_inconclusive",
            channel_opened=False,
            exec_dispatched=False,
            exit_status_observed=False,
            exit_status=None,
            stdout_byte_count=0,
            stderr_byte_count=0,
            stdout_sha256=_sha256_hex(b""),
            stderr_sha256=_sha256_hex(b""),
            response_body_byte_count=0,
            response_body_sha256=_sha256_hex(b""),
            response_body_nonempty=False,
            truncated=False,
            timed_out=False,
            channel_closed_verified=True,
            error_code="transport_inactive",
        )

    paramiko = _lazy_import_paramiko()
    channel: Any | None = None
    channel_opened = False
    exec_dispatched = False
    exit_status_observed = False
    exit_status: int | None = None
    truncated = False
    timed_out = False
    error_code: str | None = None
    stdout_bytes = b""
    stderr_bytes = b""
    try:
        channel = transport.open_session(timeout=channel_timeout)
        channel_opened = True
        channel.settimeout(exec_timeout)
        channel.exec_command(_SHOW_INTERFACE_HOME_COMMAND)
        exec_dispatched = True
        stdout_bytes = _read_bounded_channel_stream(channel, cap=stdout_cap, is_stderr=False)
        stderr_bytes = _read_bounded_channel_stream(channel, cap=stderr_cap, is_stderr=True)
        truncated = len(stdout_bytes) >= stdout_cap or len(stderr_bytes) >= stderr_cap
        exit_status = int(channel.recv_exit_status())
        exit_status_observed = True
    except Exception as exc:
        auth_exception = getattr(
            getattr(paramiko, "ssh_exception", None),
            "SSHException",
            None,
        )
        if auth_exception is not None and isinstance(exc, auth_exception):
            error_code = "exec_rejected"
        elif isinstance(exc, (TimeoutError, socket.timeout)):
            timed_out = True
            error_code = "exec_timeout"
        else:
            message = sanitize_ssh_error_message(str(exc), password=password).lower()
            if "not allowed" in message or "unsupported" in message or "refused" in message:
                error_code = "exec_rejected"
            else:
                error_code = "channel_open_failed"
    finally:
        channel_closed_verified = True
        if channel is not None:
            try:
                channel.close()
            except Exception:
                channel_closed_verified = False
            closed = bool(getattr(channel, "closed", True))
            channel_closed_verified = channel_closed_verified and closed

    response_body = stdout_bytes
    response_body_nonempty = bool(response_body.strip())
    classification = "exec_inconclusive"
    if error_code == "exec_rejected" or (
        exit_status_observed
        and exit_status is not None
        and exit_status != 0
        and not response_body_nonempty
    ):
        classification = "exec_rejected"
        if error_code is None:
            error_code = "exec_rejected"
    elif (
        exec_dispatched
        and exit_status_observed
        and exit_status == 0
        and response_body_nonempty
        and not truncated
        and not timed_out
        and channel_closed_verified
    ):
        classification = "exec_supported"
    else:
        if truncated and error_code is None:
            error_code = "read_truncated"
        if timed_out and error_code is None:
            error_code = "exec_timeout"
        if not channel_closed_verified and error_code is None:
            error_code = "channel_close_failed"
        if not exit_status_observed and exec_dispatched and error_code is None:
            error_code = "exit_status_unavailable"

    if error_code is not None and error_code not in _DISCOVERY_EXEC_ERROR_CODES:
        error_code = None

    return ShowInterfaceHomeExecResult(
        classification=classification,
        channel_opened=channel_opened,
        exec_dispatched=exec_dispatched,
        exit_status_observed=exit_status_observed,
        exit_status=exit_status,
        stdout_byte_count=len(stdout_bytes),
        stderr_byte_count=len(stderr_bytes),
        stdout_sha256=_sha256_hex(stdout_bytes),
        stderr_sha256=_sha256_hex(stderr_bytes),
        response_body_byte_count=len(response_body),
        response_body_sha256=_sha256_hex(response_body),
        response_body_nonempty=response_body_nonempty,
        truncated=truncated,
        timed_out=timed_out,
        channel_closed_verified=channel_closed_verified,
        error_code=error_code,
    )


def shell_show_interface_home(
    transport: Any,
    *,
    password: str,
    channel_timeout: float = 15.0,
    stage_timeout: float = _DISCOVERY_SHELL_STAGE_TIMEOUT,
    read_cap: int = _DISCOVERY_SHELL_READ_CAP,
) -> ShowInterfaceHomeShellResult:
    """Sealed interactive shell framing probe for fixed read-only show interface Home."""
    is_active = getattr(transport, "is_active", None)
    if not callable(is_active) or not bool(is_active()):
        return ShowInterfaceHomeShellResult(
            classification="shell_inconclusive",
            pty_allocated=False,
            shell_invoked=False,
            initial_prompt_observed=False,
            command_sent=False,
            prompt_return_observed=False,
            response_body_byte_count=0,
            response_body_sha256=_sha256_hex(b""),
            response_body_nonempty=False,
            echo_stripped=False,
            truncated=False,
            timed_out=False,
            prompt_ambiguous=True,
            channel_closed_verified=True,
            error_code="transport_inactive",
        )

    _lazy_import_paramiko()
    channel: Any | None = None
    pty_allocated = False
    shell_invoked = False
    initial_prompt_observed = False
    command_sent = False
    prompt_return_observed = False
    truncated = False
    timed_out = False
    prompt_ambiguous = False
    echo_stripped = False
    error_code: str | None = None
    raw_response = b""
    try:
        channel = transport.open_session(timeout=channel_timeout)
        channel.settimeout(stage_timeout)
        try:
            channel.get_pty()
            pty_allocated = True
        except Exception:
            error_code = "pty_failed"
            raise
        try:
            channel.invoke_shell()
            shell_invoked = True
        except Exception:
            error_code = "shell_invoke_failed"
            raise
        initial_buffer, initial_timeout, initial_truncated = _read_shell_until_prompt(
            channel,
            cap=read_cap // 2,
            stage_timeout=stage_timeout,
        )
        truncated = truncated or initial_truncated
        timed_out = timed_out or initial_timeout
        initial_prompt_observed = _buffer_has_prompt_suffix(initial_buffer)
        if not initial_prompt_observed:
            error_code = "initial_prompt_timeout"
        else:
            try:
                channel.send(_SHELL_SHOW_INTERFACE_HOME_SEND)
                command_sent = True
            except Exception:
                error_code = "command_send_failed"
                raise
            response_buffer, return_timeout, return_truncated = _read_shell_until_prompt(
                channel,
                cap=read_cap,
                stage_timeout=stage_timeout,
            )
            truncated = truncated or return_truncated
            timed_out = timed_out or return_timeout
            raw_response = initial_buffer + response_buffer
            prompt_return_observed = _buffer_has_prompt_suffix(response_buffer)
            if not prompt_return_observed:
                error_code = "prompt_return_timeout"
    except Exception as exc:
        message = sanitize_ssh_error_message(str(exc), password=password).lower()
        if error_code is None and ("not allowed" in message or "unsupported" in message):
            error_code = "shell_rejected"
        elif error_code is None:
            error_code = "channel_open_failed"
    finally:
        channel_closed_verified = True
        if channel is not None:
            try:
                channel.close()
            except Exception:
                channel_closed_verified = False
            closed = bool(getattr(channel, "closed", True))
            channel_closed_verified = channel_closed_verified and closed

    body, echo_stripped, prompt_ambiguous_body = _extract_shell_response_body(
        raw_response,
        _SHOW_INTERFACE_HOME_COMMAND,
    )
    prompt_ambiguous = prompt_ambiguous or prompt_ambiguous_body
    response_body_nonempty = bool(body.strip())

    classification = "shell_inconclusive"
    if error_code == "shell_rejected":
        classification = "shell_rejected"
    elif (
        shell_invoked
        and initial_prompt_observed
        and command_sent
        and prompt_return_observed
        and echo_stripped
        and response_body_nonempty
        and not truncated
        and not timed_out
        and not prompt_ambiguous
        and channel_closed_verified
    ):
        classification = "shell_framing_observed"
    elif error_code in {"pty_failed", "shell_invoke_failed"} or (
        shell_invoked is False and error_code is not None
    ):
        classification = "shell_rejected"
    else:
        if truncated and error_code is None:
            error_code = "read_truncated"
        if timed_out and error_code is None:
            error_code = "prompt_return_timeout"
        if prompt_ambiguous and error_code is None:
            error_code = "prompt_ambiguous"
        if not channel_closed_verified and error_code is None:
            error_code = "channel_close_failed"

    if error_code is not None and error_code not in _DISCOVERY_SHELL_ERROR_CODES:
        error_code = None

    return ShowInterfaceHomeShellResult(
        classification=classification,
        pty_allocated=pty_allocated,
        shell_invoked=shell_invoked,
        initial_prompt_observed=initial_prompt_observed,
        command_sent=command_sent,
        prompt_return_observed=prompt_return_observed,
        response_body_byte_count=len(body),
        response_body_sha256=_sha256_hex(body),
        response_body_nonempty=response_body_nonempty,
        echo_stripped=echo_stripped,
        truncated=truncated,
        timed_out=timed_out,
        prompt_ambiguous=prompt_ambiguous,
        channel_closed_verified=channel_closed_verified,
        error_code=error_code,
    )


def close_rci_transport_verified(transport: Any) -> bool:
    """Clear RCI session state and verify no active session cookies remain."""
    transport._session_cookie_name = None
    transport._session_cookie_value = None
    transport._digest_challenge = None
    pair_fn = getattr(transport, "_session_cookie_pair", None)
    if callable(pair_fn) and pair_fn() is not None:
        return False
    if getattr(transport, "_digest_challenge", None) is not None:
        return False
    return True


__all__ = [
    "FailSafeExecAck",
    "FailSafeExecSession",
    "LearnedSshHostKey",
    "PinnedSshTransport",
    "ShowInterfaceHomeExecResult",
    "ShowInterfaceHomeShellResult",
    "SshTunnelError",
    "close_rci_transport_verified",
    "exec_show_interface_home",
    "shell_show_interface_home",
    "LOCAL_BIND_HOST",
    "REMOTE_RCI_PORT",
    "SSH_PORT",
    "PinnedSshTunnel",
    "SshTunnelConfig",
    "SshSourceAddressBindError",
    "SshSourceAddressInvalid",
    "compute_host_key_fingerprint",
    "create_bound_tcp_connection",
    "preflight_source_address_bind",
    "exec_fail_safe_timer_reboot_60",
    "host_is_private",
    "learn_ssh_host_key",
    "normalize_sha256_fingerprint",
    "sanitize_ssh_error_message",
    "source_address_class",
    "strip_host_brackets",
    "validate_source_address",
    "validate_ssh_tunnel_host",
]
