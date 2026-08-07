"""Host-side connectivity probes (stdlib only; injectable for tests)."""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal, Protocol, cast
from urllib.parse import urlparse

CONNECT_TIMEOUT_S = 3.0
HTTP_TLS_BUDGET_S = 6.0
INTERNET_BUDGET_S = 8.0
BODY_READ_CAP = 65536
DNS_RESOLVE_TIMEOUT_S = CONNECT_TIMEOUT_S

# Generic public connectivity anchors — not product-specific endpoints.
INTERNET_DNS_TARGETS: tuple[str, ...] = ("one.one.one.one", "dns.google")
INTERNET_TCP_TARGETS: tuple[str, ...] = ("1.1.1.1", "8.8.8.8")
INTERNET_TCP_PORT = 443

_ALLOWED_IPV4_NETWORKS: tuple[ipaddress.IPv4Network, ...] = (
    cast(ipaddress.IPv4Network, ipaddress.ip_network("10.0.0.0/8")),
    cast(ipaddress.IPv4Network, ipaddress.ip_network("172.16.0.0/12")),
    cast(ipaddress.IPv4Network, ipaddress.ip_network("192.168.0.0/16")),
)
_ALLOWED_IPV6_NETWORK = ipaddress.ip_network("fc00::/7")

_DNS_MAX_LIVE_THREADS = 32
_DNS_ACTIVE_THREADS: set[threading.Thread] = set()
_DNS_LOCK = threading.Lock()

AddrInfoList = list[tuple[int, int, int, str, tuple[str, int]]]
DnsResolveError = Literal["timeout", "unavailable"]

CheckedFrom = Literal["operator_host"]


def is_allowed_event_preset_target(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    """RFC1918 IPv4 or ULA IPv6 only; rejects loopback, link-local, public, etc."""
    if isinstance(addr, ipaddress.IPv6Address):
        mapped = addr.ipv4_mapped
        if mapped is not None:
            return is_allowed_event_preset_target(mapped)
    if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
        return False
    if addr.is_reserved:
        return False
    if isinstance(addr, ipaddress.IPv4Address):
        if int(addr) == 0xFFFFFFFF:
            return False
        return any(addr in network for network in _ALLOWED_IPV4_NETWORKS)
    if isinstance(addr, ipaddress.IPv6Address):
        return addr in _ALLOWED_IPV6_NETWORK
    return False


def _wildcard_hostname_match(pattern: str, host: str) -> bool:
    if pattern.startswith("*."):
        suffix = pattern[1:]
        if not host.endswith(suffix):
            return False
        prefix = host[: -len(suffix)]
        return bool(prefix) and "." not in prefix
    return pattern == host


def _prune_dns_threads() -> None:
    with _DNS_LOCK:
        for thread in tuple(_DNS_ACTIVE_THREADS):
            if not thread.is_alive():
                _DNS_ACTIVE_THREADS.discard(thread)


def _getaddrinfo_bounded(
    hostname: str,
    port: int,
    *,
    timeout: float = DNS_RESOLVE_TIMEOUT_S,
) -> tuple[AddrInfoList | None, DnsResolveError | None]:
    """Resolve with bounded wait; one daemon thread per call.

    getaddrinfo is not cancellable — on timeout the resolver thread is abandoned
    but remains in _DNS_ACTIVE_THREADS until it finishes, capping live threads.
    """
    _prune_dns_threads()
    with _DNS_LOCK:
        if len(_DNS_ACTIVE_THREADS) >= _DNS_MAX_LIVE_THREADS:
            return None, "unavailable"

    result: list[AddrInfoList] = []
    error: list[OSError] = []

    def _resolve() -> None:
        try:
            raw = socket.getaddrinfo(
                hostname,
                port,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
            )
            result.append(cast(AddrInfoList, raw))
        except OSError as exc:
            error.append(exc)

    thread = threading.Thread(target=_resolve, daemon=True, name="host-probe-dns")
    with _DNS_LOCK:
        _DNS_ACTIVE_THREADS.add(thread)
    thread.start()
    thread.join(timeout=timeout)
    if thread.is_alive():
        return None, "timeout"
    with _DNS_LOCK:
        _DNS_ACTIVE_THREADS.discard(thread)
    if error:
        raise error[0]
    if result:
        return result[0], None
    return None, "timeout"


def _pick_pinned_address(
    infos: list[tuple[int, int, int, str, tuple[str, int]]],
    *,
    not_allowed_code: str,
) -> tuple[str | None, str | None]:
    pinned_ip: str | None = None
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        ip_str = str(sockaddr[0])
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if not is_allowed_event_preset_target(addr):
            return None, not_allowed_code
        if pinned_ip is None:
            pinned_ip = ip_str
    if pinned_ip is None:
        return None, not_allowed_code
    return pinned_ip, None


def extract_target_host(url: str) -> str | None:
    try:
        parsed = urlparse(url.strip())
        hostname = parsed.hostname
        if not hostname:
            return None
        return hostname.lower()
    except (ValueError, AttributeError):
        return None


def parse_http_scheme(url: str) -> tuple[str | None, str | None]:
    """Return (scheme, reason_code) — scheme is http/https or None with reason."""
    try:
        parsed = urlparse(url.strip())
    except ValueError:
        return None, "host_http.unparseable_url"
    scheme = (parsed.scheme or "").lower()
    if scheme in ("http", "https"):
        return scheme, None
    if not scheme:
        return None, "host_http.unparseable_url"
    return None, "host_http.url_not_allowed"


@dataclass(frozen=True)
class ResolvedPin:
    hostname: str
    pinned_ip: str
    port: int
    path: str


def resolve_and_pin(url: str) -> tuple[ResolvedPin | None, str | None]:
    """Resolve hostname once, fail-closed on mixed allowlist, pin for connect."""
    try:
        parsed = urlparse(url.strip())
    except ValueError:
        return None, "host_http.unparseable_url"
    hostname = parsed.hostname
    if not hostname:
        return None, "host_http.unparseable_url"
    scheme = (parsed.scheme or "").lower()
    if scheme == "https":
        port = parsed.port or 443
    elif scheme == "http":
        port = parsed.port or 80
    else:
        return None, "host_http.url_not_allowed"
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    try:
        infos, dns_err = _getaddrinfo_bounded(hostname, port)
    except OSError:
        return None, "host_http.dns_failed"
    if dns_err == "unavailable":
        return None, "host_http.dns_unavailable"
    if dns_err == "timeout" or infos is None:
        return None, "host_http.dns_timeout"
    pinned_ip, reason = _pick_pinned_address(
        infos,
        not_allowed_code="host_http.target_address_not_allowed",
    )
    if pinned_ip is None:
        return None, reason
    return (
        ResolvedPin(
            hostname=hostname.lower(),
            pinned_ip=pinned_ip,
            port=port,
            path=path,
        ),
        None,
    )


def resolve_hostname_pin(hostname: str, port: int) -> tuple[str | None, str | None]:
    """Pin TLS/connect target to one allowlisted address; reject mixed resolution."""
    try:
        infos, dns_err = _getaddrinfo_bounded(hostname, port)
    except OSError:
        return None, "host_tls.dns_failed"
    if dns_err == "unavailable":
        return None, "host_tls.dns_unavailable"
    if dns_err == "timeout" or infos is None:
        return None, "host_tls.dns_timeout"
    return _pick_pinned_address(
        infos,
        not_allowed_code="host_tls.target_address_not_allowed",
    )


def _http_status_class(status: int) -> str:
    return f"{status // 100}xx"


def _read_body_capped(
    response: http.client.HTTPResponse,
    cap: int = BODY_READ_CAP,
    *,
    deadline: float | None = None,
) -> int:
    remaining = cap
    total_read = 0
    while remaining > 0:
        if deadline is not None and time.monotonic() > deadline:
            break
        chunk = response.read(min(8192, remaining))
        if not chunk or not isinstance(chunk, (bytes, bytearray)):
            break
        chunk_len = len(chunk)
        remaining -= chunk_len
        total_read += chunk_len
    return total_read


def _cert_not_after_iso(cert: dict[str, object]) -> str | None:
    not_after = cert.get("notAfter")
    if not isinstance(not_after, str):
        return None
    try:
        dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
        return dt.isoformat().replace("+00:00", "Z")
    except ValueError:
        return None


def _cert_hostname_match(cert: dict[str, object], hostname: str) -> bool:
    host = hostname.lower().rstrip(".")
    subject = cert.get("subject")
    if isinstance(subject, tuple):
        for rdn in subject:
            if not isinstance(rdn, tuple):
                continue
            for attr_type, value in rdn:
                if attr_type == "commonName" and isinstance(value, str):
                    cn = value.lower().rstrip(".")
                    if cn == host or _wildcard_hostname_match(cn, host):
                        return True
    san = cert.get("subjectAltName")
    if isinstance(san, tuple):
        for entry in san:
            if not isinstance(entry, tuple) or len(entry) != 2:
                continue
            kind, value = entry
            if kind != "DNS" or not isinstance(value, str):
                continue
            name = value.lower().rstrip(".")
            if name == host or _wildcard_hostname_match(name, host):
                return True
    return False


def _issuer_summary(cert: dict[str, object]) -> str | None:
    issuer = cert.get("issuer")
    if not isinstance(issuer, tuple):
        return None
    org: str | None = None
    cn: str | None = None
    for rdn in issuer:
        if not isinstance(rdn, tuple):
            continue
        for attr_type, value in rdn:
            if not isinstance(value, str):
                continue
            if attr_type == "organizationName":
                org = value
            elif attr_type == "commonName":
                cn = value
    if org and cn and org != cn:
        return f"{org} ({cn})"
    return org or cn


def _cert_not_expired(cert: dict[str, object]) -> bool | None:
    not_after = cert.get("notAfter")
    if not isinstance(not_after, str):
        return None
    try:
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
    except ValueError:
        return None
    return datetime.now(tz=UTC) < expiry


def _tls_aggregate_verdict(
    *,
    reachable: bool,
    cert_trusted: bool,
    hostname_match: bool | None,
    not_expired: bool | None,
) -> tuple[Literal["ok", "warning", "unknown", "failed"], str]:
    if not reachable:
        return "unknown", "host_tls.unreachable"
    if not_expired is False:
        return "failed", "host_tls.certificate_expired"
    if hostname_match is False:
        return "failed", "host_tls.hostname_mismatch"
    if cert_trusted and hostname_match is True and not_expired is True:
        return "ok", "host_tls.ok"
    if not cert_trusted:
        return "warning", "host_tls.untrusted_issuer"
    return "warning", "host_tls.partial"


class _SniHttpsConnection(http.client.HTTPSConnection):
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


@dataclass
class HostHttpProbeResult:
    checked_from: CheckedFrom = "operator_host"
    reachable: bool | None = None
    http_status_class: str | None = None
    latency_ms: int | None = None
    reason_code: str = "host_http.pending"
    target_host: str | None = None
    scheme: str | None = None
    redirect_followed: Literal[False] = False
    writes_allowed: Literal[False] = False
    certification_eligible: Literal[False] = False
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return {
            "checked_from": self.checked_from,
            "reachable": self.reachable,
            "http_status_class": self.http_status_class,
            "latency_ms": self.latency_ms,
            "reason_code": self.reason_code,
            "target_host": self.target_host,
            "scheme": self.scheme,
            "redirect_followed": self.redirect_followed,
            "writes_allowed": self.writes_allowed,
            "certification_eligible": self.certification_eligible,
            "notes": list(self.notes),
        }


@dataclass
class HostTlsProbeResult:
    checked_from: CheckedFrom = "operator_host"
    reachable: bool | None = None
    cert_trusted: bool | None = None
    hostname_match: bool | None = None
    not_expired: bool | None = None
    aggregate_status: Literal["ok", "warning", "unknown", "failed"] = "unknown"
    not_after: str | None = None
    issuer_summary: str | None = None
    chain_inspected: Literal[False] = False
    reason_code: str = "host_tls.pending"
    target_host: str | None = None
    writes_allowed: Literal[False] = False
    certification_eligible: Literal[False] = False
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return {
            "checked_from": self.checked_from,
            "reachable": self.reachable,
            "cert_trusted": self.cert_trusted,
            "hostname_match": self.hostname_match,
            "not_expired": self.not_expired,
            "aggregate_status": self.aggregate_status,
            "not_after": self.not_after,
            "issuer_summary": self.issuer_summary,
            "chain_inspected": self.chain_inspected,
            "reason_code": self.reason_code,
            "target_host": self.target_host,
            "writes_allowed": self.writes_allowed,
            "certification_eligible": self.certification_eligible,
            "notes": list(self.notes),
        }


@dataclass
class HostInternetProbeResult:
    checked_from: CheckedFrom = "operator_host"
    dns_ok: bool | None = None
    tcp_ok: bool | None = None
    internet_reachable: bool | None = None
    reason_code: str = "host_internet.pending"
    source_bound: Literal[False] = False
    writes_allowed: Literal[False] = False
    certification_eligible: Literal[False] = False
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return {
            "checked_from": self.checked_from,
            "dns_ok": self.dns_ok,
            "tcp_ok": self.tcp_ok,
            "internet_reachable": self.internet_reachable,
            "reason_code": self.reason_code,
            "source_bound": self.source_bound,
            "writes_allowed": self.writes_allowed,
            "certification_eligible": self.certification_eligible,
            "notes": list(self.notes),
        }


class HostProbeRunner(Protocol):
    def probe_http(self, *, url: str) -> HostHttpProbeResult: ...

    def probe_tls(self, *, hostname: str) -> HostTlsProbeResult: ...

    def probe_internet(self, *, targets_profile: str) -> HostInternetProbeResult: ...


class DefaultHostProbeRunner:
    """Real stdlib probe implementation."""

    def probe_http(self, *, url: str) -> HostHttpProbeResult:
        result = HostHttpProbeResult()
        result.target_host = extract_target_host(url)
        scheme, scheme_reason = parse_http_scheme(url)
        result.scheme = scheme
        if scheme is None:
            result.reason_code = scheme_reason or "host_http.url_not_allowed"
            return result
        notes = list(result.notes)
        if scheme == "http":
            notes.append("Plain HTTP is not encrypted.")
        result.notes = notes

        pin, pin_reason = resolve_and_pin(url)
        if pin is None:
            result.reason_code = pin_reason or "host_http.target_address_not_allowed"
            result.reachable = None
            return result

        deadline = time.monotonic() + HTTP_TLS_BUDGET_S
        start = time.monotonic()
        conn: http.client.HTTPConnection | http.client.HTTPSConnection | None = None
        try:
            if scheme == "https":
                notes.append(
                    "HTTPS reachability does not verify the certificate; "
                    "use the TLS probe for trust and hostname checks."
                )
                result.notes = notes
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = _SniHttpsConnection(
                    pin.pinned_ip,
                    pin.port,
                    server_hostname=pin.hostname,
                    timeout=CONNECT_TIMEOUT_S,
                    context=ctx,
                )
            else:
                conn = http.client.HTTPConnection(
                    pin.pinned_ip,
                    pin.port,
                    timeout=CONNECT_TIMEOUT_S,
                )
            conn.putrequest("GET", pin.path)
            conn.putheader("Host", pin.hostname)
            conn.endheaders()
            if time.monotonic() > deadline:
                result.reachable = None
                result.reason_code = "host_http.timeout"
                return result
            response = conn.getresponse()
            _read_body_capped(response, deadline=deadline)
            elapsed_ms = int((time.monotonic() - start) * 1000)
            status = response.status
            result.latency_ms = elapsed_ms
            result.http_status_class = _http_status_class(status)
            if 200 <= status < 300:
                result.reachable = True
                result.reason_code = "host_http.reachable"
            elif 300 <= status < 400:
                result.reachable = None
                result.reason_code = "host_http.redirect_not_followed"
            elif 400 <= status < 600:
                result.reachable = False
                result.reason_code = "host_http.http_error"
            else:
                result.reachable = None
                result.reason_code = "host_http.unexpected_status"
        except TimeoutError:
            result.reachable = None
            result.reason_code = "host_http.timeout"
        except ConnectionRefusedError:
            result.reachable = False
            result.reason_code = "host_http.connection_refused"
            result.notes = list(result.notes) + [
                "TCP connection refused at the pinned address: "
                "nothing accepted the connection (application not answering)."
            ]
        except OSError:
            result.reachable = None
            result.reason_code = "host_http.unreachable"
        finally:
            if conn is not None:
                conn.close()
        return result

    def probe_tls(self, *, hostname: str) -> HostTlsProbeResult:
        result = HostTlsProbeResult()
        host = hostname.strip().lower().rstrip(".")
        result.target_host = host or None
        if not host:
            result.reason_code = "host_tls.hostname_not_allowed"
            result.aggregate_status = "unknown"
            return result

        pinned_ip, pin_reason = resolve_hostname_pin(host, 443)
        if pinned_ip is None:
            result.reason_code = pin_reason or "host_tls.target_address_not_allowed"
            result.reachable = None
            result.not_expired = None
            result.aggregate_status = "unknown"
            return result

        result.notes = [
            "Python 3.11 inspects the leaf certificate only; chain_inspected is false.",
        ]
        cert: dict[str, object] | None = None
        cert_trusted = False
        reachable = False

        try:
            ctx_verify = ssl.create_default_context()
            with socket.create_connection(
                (pinned_ip, 443),
                timeout=CONNECT_TIMEOUT_S,
            ) as sock:
                with ctx_verify.wrap_socket(sock, server_hostname=host) as ssock:
                    peer = ssock.getpeercert()
                    if isinstance(peer, dict):
                        cert = cast(dict[str, object], peer)
                    cert_trusted = True
                    reachable = True
        except ssl.SSLCertVerificationError:
            reachable = True
            cert_trusted = False
        except (TimeoutError, ConnectionRefusedError, OSError, ssl.SSLError):
            result.reachable = None
            result.not_expired = None
            result.reason_code = "host_tls.unreachable"
            result.aggregate_status = "unknown"
            return result

        if cert is None and reachable:
            try:
                ctx_insecure = ssl.create_default_context()
                ctx_insecure.check_hostname = False
                ctx_insecure.verify_mode = ssl.CERT_NONE
                with socket.create_connection(
                    (pinned_ip, 443),
                    timeout=CONNECT_TIMEOUT_S,
                ) as sock:
                    with ctx_insecure.wrap_socket(sock, server_hostname=host) as ssock:
                        peer = ssock.getpeercert()
                        if isinstance(peer, dict):
                            cert = cast(dict[str, object], peer)
            except (TimeoutError, ConnectionRefusedError, OSError, ssl.SSLError):
                result.reachable = None
                result.not_expired = None
                result.reason_code = "host_tls.unreachable"
                result.aggregate_status = "unknown"
                return result

        result.reachable = reachable
        result.cert_trusted = cert_trusted
        if cert is None:
            result.reason_code = "host_tls.no_certificate"
            result.aggregate_status = "unknown"
            return result

        result.not_after = _cert_not_after_iso(cert)
        result.issuer_summary = _issuer_summary(cert)
        result.hostname_match = _cert_hostname_match(cert, host)
        result.not_expired = _cert_not_expired(cert)

        aggregate_status, reason_code = _tls_aggregate_verdict(
            reachable=reachable,
            cert_trusted=cert_trusted,
            hostname_match=result.hostname_match,
            not_expired=result.not_expired,
        )
        result.aggregate_status = aggregate_status
        result.reason_code = reason_code
        return result

    def probe_internet(self, *, targets_profile: str) -> HostInternetProbeResult:
        _ = targets_profile
        result = HostInternetProbeResult()
        deadline = time.monotonic() + INTERNET_BUDGET_S

        dns_success = 0
        dns_failed = 0
        dns_timed_out = 0
        dns_unavailable = False
        for name in INTERNET_DNS_TARGETS:
            if time.monotonic() > deadline:
                break
            try:
                infos, dns_err = _getaddrinfo_bounded(
                    name,
                    INTERNET_TCP_PORT,
                    timeout=min(
                        DNS_RESOLVE_TIMEOUT_S,
                        max(0.0, deadline - time.monotonic()),
                    ),
                )
                if dns_err == "unavailable":
                    dns_unavailable = True
                elif dns_err == "timeout":
                    dns_timed_out += 1
                elif infos is not None:
                    dns_success += 1
            except OSError:
                dns_failed += 1
        dns_completed = dns_success + dns_failed
        if dns_unavailable:
            result.dns_ok = None
        elif dns_completed == 0:
            result.dns_ok = None
        elif dns_success > dns_completed // 2:
            result.dns_ok = True
        elif dns_success == 0:
            result.dns_ok = False
        else:
            result.dns_ok = None

        tcp_success = 0
        for ip in INTERNET_TCP_TARGETS:
            if time.monotonic() > deadline:
                break
            try:
                with socket.create_connection((ip, INTERNET_TCP_PORT), timeout=CONNECT_TIMEOUT_S):
                    tcp_success += 1
            except OSError:
                pass
        tcp_total = len(INTERNET_TCP_TARGETS)
        if tcp_success > tcp_total // 2:
            result.tcp_ok = True
        elif tcp_success == 0:
            result.tcp_ok = False
        else:
            result.tcp_ok = None

        if result.dns_ok is True and result.tcp_ok is True:
            result.internet_reachable = True
            result.reason_code = "host_internet.reachable"
        elif dns_unavailable:
            result.internet_reachable = None
            result.reason_code = "host_internet.dns_unavailable"
        elif dns_completed == 0 and dns_timed_out > 0:
            result.internet_reachable = None
            result.reason_code = "host_internet.dns_timeout"
        elif result.dns_ok is False and result.tcp_ok is False:
            result.internet_reachable = False
            result.reason_code = "host_internet.offline_or_unreachable"
        elif result.dns_ok is False:
            result.internet_reachable = None
            result.reason_code = "host_internet.dns_failed"
        elif result.tcp_ok is False:
            result.internet_reachable = None
            result.reason_code = "host_internet.no_route"
        else:
            result.internet_reachable = None
            result.reason_code = "host_internet.inconclusive"
        return result


_DEFAULT_RUNNER = DefaultHostProbeRunner()


def default_host_probe_runner() -> HostProbeRunner:
    return _DEFAULT_RUNNER
