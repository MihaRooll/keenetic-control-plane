"""Tests for host-side lab probes (no real network I/O)."""

from __future__ import annotations

import ast
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from router_control.adapters.netcraze.ssh_tunnel import host_is_private
from router_control.domain.event_preset import build_safe_default_document
from router_control_host.host_probes import (
    BODY_READ_CAP,
    INTERNET_DNS_TARGETS,
    DefaultHostProbeRunner,
    HostHttpProbeResult,
    HostInternetProbeResult,
    HostTlsProbeResult,
    _cert_hostname_match,
    _getaddrinfo_bounded,
    _read_body_capped,
    _tls_aggregate_verdict,
    is_allowed_event_preset_target,
    resolve_and_pin,
)

_API = "/api/router-control/v1"
_CANARY_HOST = "canary-secret-host.example"
_CANARY_URL = f"http://{_CANARY_HOST}:8080/secret/path?q=1"
_PIN_HOST = "router_control_host.host_probes.resolve_hostname_pin"
_PIN_CONN = "router_control_host.host_probes.socket.create_connection"
_PRIVATE_PIN = ("192.168.1.10", None)


class FakeHostProbeRunner:
    def __init__(
        self,
        *,
        http: HostHttpProbeResult | None = None,
        tls: HostTlsProbeResult | None = None,
        internet: HostInternetProbeResult | None = None,
    ) -> None:
        self._http = http or HostHttpProbeResult(
            reachable=True,
            http_status_class="2xx",
            latency_ms=12,
            reason_code="host_http.reachable",
            target_host="orders.booth.local",
            scheme="http",
            notes=["Plain HTTP is not encrypted."],
        )
        self._tls = tls or HostTlsProbeResult(
            reachable=True,
            cert_trusted=True,
            hostname_match=True,
            not_expired=True,
            aggregate_status="ok",
            not_after="2030-01-01T00:00:00Z",
            issuer_summary="Test CA",
            reason_code="host_tls.ok",
            target_host="orders.booth.local",
            notes=["Python 3.11 inspects the leaf certificate only; chain_inspected is false."],
        )
        self._internet = internet or HostInternetProbeResult(
            dns_ok=True,
            tcp_ok=True,
            internet_reachable=True,
            reason_code="host_internet.reachable",
        )
        self.http_calls: list[str] = []
        self.tls_calls: list[str] = []
        self.internet_calls: list[str] = []

    def probe_http(self, *, url: str) -> HostHttpProbeResult:
        self.http_calls.append(url)
        return self._http

    def probe_tls(self, *, hostname: str) -> HostTlsProbeResult:
        self.tls_calls.append(hostname)
        return self._tls

    def probe_internet(self, *, targets_profile: str) -> HostInternetProbeResult:
        self.internet_calls.append(targets_profile)
        return self._internet


class _MutableProbePayload:
    def __init__(self, payload: dict[str, object]) -> None:
        self._payload = payload

    def as_dict(self) -> dict[str, object]:
        return dict(self._payload)


class BadWritesAllowedRunner:
    def probe_http(self, *, url: str) -> _MutableProbePayload:
        _ = url
        return _MutableProbePayload(
            {
                "writes_allowed": True,
                "certification_eligible": False,
                "reachable": True,
                "reason_code": "host_http.reachable",
            }
        )

    def probe_tls(self, *, hostname: str) -> HostTlsProbeResult:
        _ = hostname
        return HostTlsProbeResult()

    def probe_internet(self, *, targets_profile: str) -> HostInternetProbeResult:
        _ = targets_profile
        return HostInternetProbeResult()


class BadCertificationEligibleRunner:
    def probe_http(self, *, url: str) -> HostHttpProbeResult:
        _ = url
        return HostHttpProbeResult()

    def probe_tls(self, *, hostname: str) -> _MutableProbePayload:
        _ = hostname
        return _MutableProbePayload(
            {
                "writes_allowed": False,
                "certification_eligible": True,
                "aggregate_status": "ok",
                "reason_code": "host_tls.ok",
            }
        )

    def probe_internet(self, *, targets_profile: str) -> HostInternetProbeResult:
        _ = targets_profile
        return HostInternetProbeResult()


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    from fastapi.testclient import TestClient
    from router_control_host.app import create_app
    from router_control_host.auth import mint_hub_admin_cookie

    app = create_app(db_path=tmp_path / "host-probes.sqlite3", enable_worker=False)
    with TestClient(app) as tc:
        tc.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield tc


def _create_preset_with_url(
    client: Any,
    *,
    local_order_url: str,
    preset_name: str = "Probe Booth",
) -> dict[str, Any]:
    site_id = client.app.state.host.ensure_default_site()
    create = client.post(
        f"{_API}/sites/{site_id}/event-presets",
        json={"name": preset_name},
        headers={"Idempotency-Key": f"host-probe-{preset_name}"},
    )
    assert create.status_code == 201
    preset = create.json()["preset"]
    doc = client.get(
        f"{_API}/event-presets/{preset['preset_id']}/revisions/"
        f"{preset['current_revision_id']}"
    ).json()["canonical_document"]
    doc["local_order_url"] = local_order_url
    rev = client.post(
        f"{_API}/event-presets/{preset['preset_id']}/revisions",
        json={"document": doc},
        headers={
            "Idempotency-Key": f"host-probe-rev-{preset_name}",
            "If-Match": preset["etag"],
        },
    )
    assert rev.status_code in (200, 201)
    updated = rev.json()["preset"]
    return {
        "preset_id": updated["preset_id"],
        "revision_id": rev.json()["revision"]["revision_id"],
        "etag": updated["etag"],
    }


def _assert_lab_flags(body: dict[str, Any]) -> None:
    assert body["writes_allowed"] is False
    assert body["certification_eligible"] is False


def test_host_http_probe_positive_injected(client) -> None:
    client.app.state.host.host_probe_runner = FakeHostProbeRunner()
    preset = _create_preset_with_url(client, local_order_url="http://192.168.1.10/")
    resp = client.post(
        f"{_API}/lab/host-http-probe",
        json={
            "url_ref": "event_preset_local_order_url",
            "preset_id": preset["preset_id"],
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    _assert_lab_flags(body)
    assert body["reachable"] is True
    assert body["http_status_class"] == "2xx"
    assert body["checked_from"] == "operator_host"
    assert body["redirect_followed"] is False


def test_host_tls_probe_ok_injected(client) -> None:
    client.app.state.host.host_probe_runner = FakeHostProbeRunner()
    preset = _create_preset_with_url(client, local_order_url="https://orders.booth.local/")
    resp = client.post(
        f"{_API}/lab/host-tls-probe",
        json={
            "hostname_ref": "event_preset_local_order_host",
            "preset_id": preset["preset_id"],
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    _assert_lab_flags(body)
    assert body["aggregate_status"] == "ok"
    assert body["chain_inspected"] is False


def test_host_internet_probe_positive_injected(client) -> None:
    client.app.state.host.host_probe_runner = FakeHostProbeRunner()
    resp = client.post(f"{_API}/lab/host-internet-probe", json={})
    assert resp.status_code == 200
    body = resp.json()
    _assert_lab_flags(body)
    assert body["source_bound"] is False
    assert body["internet_reachable"] is True


def test_host_http_probe_rejects_writes_allowed_true(client) -> None:
    client.app.state.host.host_probe_runner = BadWritesAllowedRunner()
    preset = _create_preset_with_url(client, local_order_url="http://192.168.1.10/")
    resp = client.post(
        f"{_API}/lab/host-http-probe",
        json={
            "url_ref": "event_preset_local_order_url",
            "preset_id": preset["preset_id"],
        },
    )
    assert resp.status_code == 500
    assert resp.json()["error"]["code"] == "internal.error"


def test_host_tls_probe_rejects_certification_eligible_true(client) -> None:
    client.app.state.host.host_probe_runner = BadCertificationEligibleRunner()
    preset = _create_preset_with_url(client, local_order_url="https://orders.booth.local/")
    resp = client.post(
        f"{_API}/lab/host-tls-probe",
        json={
            "hostname_ref": "event_preset_local_order_host",
            "preset_id": preset["preset_id"],
        },
    )
    assert resp.status_code == 500
    assert resp.json()["error"]["code"] == "internal.error"


def test_host_http_timeout_via_core() -> None:
    runner = DefaultHostProbeRunner()
    pin = resolve_and_pin("http://192.168.1.10/")
    assert pin[0] is not None
    with patch("router_control_host.host_probes.http.client.HTTPConnection") as conn_cls:
        conn = MagicMock()
        conn_cls.return_value = conn
        conn.putrequest.side_effect = TimeoutError()
        result = runner.probe_http(url="http://192.168.1.10/")
    assert result.reachable is None
    assert result.reason_code == "host_http.timeout"


def test_host_http_connection_refused_via_core() -> None:
    runner = DefaultHostProbeRunner()
    with patch("router_control_host.host_probes.http.client.HTTPConnection") as conn_cls:
        conn = MagicMock()
        conn_cls.return_value = conn
        conn.putrequest.side_effect = ConnectionRefusedError()
        result = runner.probe_http(url="http://192.168.1.10/")
    assert result.reachable is False
    assert result.reason_code == "host_http.connection_refused"


def test_host_http_unparseable_url(client) -> None:
    client.app.state.host.host_probe_runner = DefaultHostProbeRunner()
    preset = _create_preset_with_url(client, local_order_url="://broken")
    resp = client.post(
        f"{_API}/lab/host-http-probe",
        json={
            "url_ref": "event_preset_local_order_url",
            "preset_id": preset["preset_id"],
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["reachable"] is None
    assert "unparseable" in body["reason_code"]


def test_host_http_non_http_scheme(client) -> None:
    runner = DefaultHostProbeRunner()
    client.app.state.host.host_probe_runner = runner
    preset = _create_preset_with_url(client, local_order_url="ftp://192.168.1.10/file")
    resp = client.post(
        f"{_API}/lab/host-http-probe",
        json={
            "url_ref": "event_preset_local_order_url",
            "preset_id": preset["preset_id"],
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["reachable"] is None
    assert body["reason_code"] == "host_http.url_not_allowed"


def test_host_http_loopback_rejected(client) -> None:
    runner = DefaultHostProbeRunner()
    client.app.state.host.host_probe_runner = runner
    preset = _create_preset_with_url(client, local_order_url="http://127.0.0.1/")
    resp = client.post(
        f"{_API}/lab/host-http-probe",
        json={
            "url_ref": "event_preset_local_order_url",
            "preset_id": preset["preset_id"],
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["reachable"] is None
    assert body["reason_code"] == "host_http.target_address_not_allowed"


def test_host_http_link_local_metadata_rejected(client) -> None:
    runner = DefaultHostProbeRunner()
    client.app.state.host.host_probe_runner = runner
    preset = _create_preset_with_url(
        client,
        local_order_url="http://169.254.169.254/",
    )
    with patch("router_control_host.host_probes.socket.getaddrinfo") as gai:
        gai.return_value = [
            (2, 1, 6, "", ("169.254.169.254", 80)),
        ]
        resp = client.post(
            f"{_API}/lab/host-http-probe",
            json={
                "url_ref": "event_preset_local_order_url",
                "preset_id": preset["preset_id"],
            },
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["reachable"] is None
    assert body["reason_code"] == "host_http.target_address_not_allowed"


def test_host_http_public_address_rejected(client) -> None:
    runner = DefaultHostProbeRunner()
    client.app.state.host.host_probe_runner = runner
    preset = _create_preset_with_url(client, local_order_url="http://8.8.8.8/")
    with patch("router_control_host.host_probes.socket.getaddrinfo") as gai:
        gai.return_value = [
            (2, 1, 6, "", ("8.8.8.8", 80)),
        ]
        resp = client.post(
            f"{_API}/lab/host-http-probe",
            json={
                "url_ref": "event_preset_local_order_url",
                "preset_id": preset["preset_id"],
            },
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["reachable"] is None
    assert body["reason_code"] == "host_http.target_address_not_allowed"


def test_host_http_redirect_not_followed() -> None:
    runner = DefaultHostProbeRunner()
    with patch("router_control_host.host_probes.resolve_and_pin") as pin:
        from router_control_host.host_probes import ResolvedPin

        pin.return_value = (
            ResolvedPin(hostname="orders.booth.local", pinned_ip="192.168.1.10", port=80, path="/"),
            None,
        )
        with patch("router_control_host.host_probes.http.client.HTTPConnection") as conn_cls:
            conn = MagicMock()
            conn_cls.return_value = conn
            response = MagicMock()
            response.status = 302
            response.read.return_value = b""
            conn.getresponse.return_value = response
            result = runner.probe_http(url="http://192.168.1.10/")
    assert result.http_status_class == "3xx"
    assert result.redirect_followed is False
    assert result.reachable is None


def test_host_http_oversized_body_capped() -> None:
    response = MagicMock()
    oversized = b"x" * 8192
    chunks = [oversized] * 20 + [b""]
    response.read.side_effect = chunks
    total_read = _read_body_capped(response, BODY_READ_CAP)
    assert total_read <= BODY_READ_CAP
    assert total_read == BODY_READ_CAP

    runner = DefaultHostProbeRunner()
    with patch("router_control_host.host_probes.resolve_and_pin") as pin:
        from router_control_host.host_probes import ResolvedPin

        pin.return_value = (
            ResolvedPin(hostname="orders.booth.local", pinned_ip="192.168.1.10", port=80, path="/"),
            None,
        )
        with patch("router_control_host.host_probes.http.client.HTTPConnection") as conn_cls:
            conn = MagicMock()
            conn_cls.return_value = conn
            probe_response = MagicMock()
            probe_response.status = 200
            probe_response.read.side_effect = chunks
            conn.getresponse.return_value = probe_response
            result = runner.probe_http(url="http://192.168.1.10/")
    assert result.reachable is True
    assert oversized.decode("ascii") not in str(result.as_dict())


def test_host_http_missing_preset(client) -> None:
    resp = client.post(
        f"{_API}/lab/host-http-probe",
        json={
            "url_ref": "event_preset_local_order_url",
            "preset_id": "missing-preset-id",
        },
    )
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "host_http.preset_not_found"


def test_host_http_missing_revision(client) -> None:
    preset = _create_preset_with_url(client, local_order_url="http://192.168.1.10/")
    resp = client.post(
        f"{_API}/lab/host-http-probe",
        json={
            "url_ref": "event_preset_local_order_url",
            "preset_id": preset["preset_id"],
            "revision_id": "missing-revision",
        },
    )
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "host_http.preset_not_found"


def test_host_tls_expired() -> None:
    runner = DefaultHostProbeRunner()
    cert = {
        "subject": ((("commonName", "orders.booth.local"),),),
        "issuer": ((("organizationName", "Test CA"),),),
        "notAfter": "Jan  1 00:00:00 2020 GMT",
        "subjectAltName": (("DNS", "orders.booth.local"),),
    }
    with patch(_PIN_HOST, return_value=_PRIVATE_PIN):
        with patch("router_control_host.host_probes.ssl.create_default_context") as ctx_factory:
            ctx = MagicMock()
            ctx_factory.return_value = ctx
            ssock = MagicMock()
            ssock.getpeercert.return_value = cert
            ssock.__enter__ = MagicMock(return_value=ssock)
            ssock.__exit__ = MagicMock(return_value=False)
            sock = MagicMock()
            sock.__enter__ = MagicMock(return_value=sock)
            sock.__exit__ = MagicMock(return_value=False)
            ctx.wrap_socket.return_value = ssock
            with patch(_PIN_CONN, return_value=sock):
                result = runner.probe_tls(hostname="orders.booth.local")
    assert result.not_expired is False
    assert result.aggregate_status == "failed"


def test_host_tls_hostname_mismatch() -> None:
    runner = DefaultHostProbeRunner()
    cert = {
        "subject": ((("commonName", "other.local"),),),
        "issuer": ((("organizationName", "Test CA"),),),
        "notAfter": "Jan  1 00:00:00 2030 GMT",
        "subjectAltName": (("DNS", "other.local"),),
    }
    with patch(_PIN_HOST, return_value=_PRIVATE_PIN):
        with patch("router_control_host.host_probes.ssl.create_default_context") as ctx_factory:
            ctx = MagicMock()
            ctx_factory.return_value = ctx
            ssock = MagicMock()
            ssock.getpeercert.return_value = cert
            ssock.__enter__ = MagicMock(return_value=ssock)
            ssock.__exit__ = MagicMock(return_value=False)
            sock = MagicMock()
            sock.__enter__ = MagicMock(return_value=sock)
            sock.__exit__ = MagicMock(return_value=False)
            ctx.wrap_socket.return_value = ssock
            with patch(_PIN_CONN, return_value=sock):
                result = runner.probe_tls(hostname="orders.booth.local")
    assert result.hostname_match is False
    assert result.aggregate_status == "failed"


def test_host_tls_untrusted_warning_never_ok() -> None:
    import ssl

    runner = DefaultHostProbeRunner()
    cert = {
        "subject": ((("commonName", "orders.booth.local"),),),
        "issuer": ((("organizationName", "Self Signed"),),),
        "notAfter": "Jan  1 00:00:00 2030 GMT",
        "subjectAltName": (("DNS", "orders.booth.local"),),
    }
    untrusted_ssock = MagicMock()
    untrusted_ssock.getpeercert.return_value = cert
    untrusted_ssock.__enter__ = MagicMock(return_value=untrusted_ssock)
    untrusted_ssock.__exit__ = MagicMock(return_value=False)
    with patch(_PIN_HOST, return_value=_PRIVATE_PIN):
        with patch("router_control_host.host_probes.ssl.create_default_context") as ctx_factory:
            ctx = MagicMock()
            ctx_factory.return_value = ctx
            ctx.wrap_socket.side_effect = [
                ssl.SSLCertVerificationError("untrusted"),
                untrusted_ssock,
            ]
            sock = MagicMock()
            sock.__enter__ = MagicMock(return_value=sock)
            sock.__exit__ = MagicMock(return_value=False)
            with patch(_PIN_CONN, return_value=sock):
                result = runner.probe_tls(hostname="orders.booth.local")
    assert result.aggregate_status == "warning"
    assert result.aggregate_status != "ok"
    assert result.cert_trusted is False


def test_host_tls_unreachable_not_expired_none() -> None:
    runner = DefaultHostProbeRunner()
    with patch(
        "router_control_host.host_probes.resolve_hostname_pin",
        return_value=(None, "host_tls.dns_failed"),
    ):
        result = runner.probe_tls(hostname="orders.booth.local")
    assert result.reachable is None
    assert result.not_expired is None
    assert result.aggregate_status == "unknown"


def test_host_internet_all_fail_not_500(client) -> None:
    runner = DefaultHostProbeRunner()
    client.app.state.host.host_probe_runner = runner
    with patch("router_control_host.host_probes.socket.getaddrinfo", side_effect=OSError()):
        conn_patch = "router_control_host.host_probes.socket.create_connection"
        with patch(conn_patch, side_effect=OSError()):
            resp = client.post(f"{_API}/lab/host-internet-probe", json={})
    assert resp.status_code == 200
    body = resp.json()
    assert body["internet_reachable"] is False
    _assert_lab_flags(body)


@pytest.mark.parametrize(
    ("addr", "allowed"),
    [
        ("10.0.0.1", True),
        ("172.16.0.1", True),
        ("192.168.1.20", True),
        ("fd00::1", True),
        ("::ffff:10.0.0.1", True),
        ("127.0.0.1", False),
        ("::1", False),
        ("::ffff:127.0.0.1", False),
        ("0.0.0.0", False),
        ("0.0.0.1", False),
        ("169.254.169.254", False),
        ("fe80::1", False),
        ("224.0.0.1", False),
        ("255.255.255.255", False),
        ("100.64.0.1", False),
        ("192.0.2.1", False),
        ("198.51.100.1", False),
        ("203.0.113.1", False),
        ("198.18.0.1", False),
        ("2001:db8::1", False),
        ("64:ff9b::7f00:1", False),
        ("8.8.8.8", False),
        ("2001:4860:4860::8888", False),
    ],
)
def test_address_classifier_parametrized(addr: str, allowed: bool) -> None:
    parsed = ipaddress.ip_address(addr)
    assert is_allowed_event_preset_target(parsed) is allowed


def test_ssh_tunnel_host_is_private_unsuitable_for_probes() -> None:
    assert host_is_private("127.0.0.1") is True
    assert host_is_private("169.254.169.254") is True
    assert host_is_private("metadata.local") is True
    assert is_allowed_event_preset_target(ipaddress.ip_address("127.0.0.1")) is False
    assert is_allowed_event_preset_target(ipaddress.ip_address("169.254.169.254")) is False


def test_host_probes_source_no_binding_or_ssh_tunnel_import() -> None:
    source_path = Path(__file__).resolve().parents[1] / "router_control_host" / "host_probes.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == "bind":
                raise AssertionError("host_probes.py must not call bind()")
        if isinstance(node, ast.keyword) and node.arg == "source_address":
            raise AssertionError("host_probes.py must not pass source_address=")
    text = source_path.read_text(encoding="utf-8")
    assert "ssh_tunnel" not in text


def test_host_http_no_echo_canary(client) -> None:
    client.app.state.host.host_probe_runner = FakeHostProbeRunner()

    def _boom(*, url: str) -> HostHttpProbeResult:
        raise RuntimeError(f"probe failed for {url}")

    client.app.state.host.host_probe_runner.probe_http = _boom  # type: ignore[method-assign]
    preset = _create_preset_with_url(client, local_order_url=_CANARY_URL)
    resp = client.post(
        f"{_API}/lab/host-http-probe",
        json={
            "url_ref": "event_preset_local_order_url",
            "preset_id": preset["preset_id"],
        },
    )
    assert resp.status_code == 500
    blob = resp.text
    assert _CANARY_HOST not in blob
    assert "8080" not in blob
    assert "/secret" not in blob


def test_host_tls_no_echo_canary(client) -> None:
    def _boom(*, hostname: str) -> HostTlsProbeResult:
        raise RuntimeError(f"tls failed for {hostname}")

    client.app.state.host.host_probe_runner = FakeHostProbeRunner()
    client.app.state.host.host_probe_runner.probe_tls = _boom  # type: ignore[method-assign]
    preset = _create_preset_with_url(client, local_order_url=f"https://{_CANARY_HOST}/")
    resp = client.post(
        f"{_API}/lab/host-tls-probe",
        json={
            "hostname_ref": "event_preset_local_order_host",
            "preset_id": preset["preset_id"],
        },
    )
    assert resp.status_code == 500
    assert _CANARY_HOST not in resp.text


def test_routes_in_openapi(client) -> None:
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    paths = resp.json()["paths"]
    assert f"{_API}/lab/host-http-probe" in paths
    assert f"{_API}/lab/host-tls-probe" in paths
    assert f"{_API}/lab/host-internet-probe" in paths


def test_default_document_local_order_url_is_https() -> None:
    doc = build_safe_default_document()
    assert doc.local_order_url.startswith("https://")


@pytest.mark.parametrize(
    (
        "reachable",
        "cert_trusted",
        "hostname_match",
        "not_expired",
        "expected_status",
        "expected_reason",
    ),
    [
        (True, True, True, True, "ok", "host_tls.ok"),
        (True, True, True, False, "failed", "host_tls.certificate_expired"),
        (True, True, False, True, "failed", "host_tls.hostname_mismatch"),
        (True, True, False, False, "failed", "host_tls.certificate_expired"),
        (True, True, None, True, "warning", "host_tls.partial"),
        (True, True, None, False, "failed", "host_tls.certificate_expired"),
        (True, True, None, None, "warning", "host_tls.partial"),
        (True, False, True, True, "warning", "host_tls.untrusted_issuer"),
        (True, False, True, False, "failed", "host_tls.certificate_expired"),
        (True, False, False, True, "failed", "host_tls.hostname_mismatch"),
        (True, False, False, False, "failed", "host_tls.certificate_expired"),
        (True, False, None, True, "warning", "host_tls.untrusted_issuer"),
        (True, False, None, False, "failed", "host_tls.certificate_expired"),
        (True, False, None, None, "warning", "host_tls.untrusted_issuer"),
        (False, True, True, True, "unknown", "host_tls.unreachable"),
        (False, True, True, False, "unknown", "host_tls.unreachable"),
        (False, True, False, True, "unknown", "host_tls.unreachable"),
        (False, True, False, False, "unknown", "host_tls.unreachable"),
        (False, True, None, True, "unknown", "host_tls.unreachable"),
        (False, True, None, False, "unknown", "host_tls.unreachable"),
        (False, True, None, None, "unknown", "host_tls.unreachable"),
        (False, False, True, True, "unknown", "host_tls.unreachable"),
        (False, False, True, False, "unknown", "host_tls.unreachable"),
        (False, False, False, True, "unknown", "host_tls.unreachable"),
        (False, False, False, False, "unknown", "host_tls.unreachable"),
        (False, False, None, True, "unknown", "host_tls.unreachable"),
        (False, False, None, False, "unknown", "host_tls.unreachable"),
        (False, False, None, None, "unknown", "host_tls.unreachable"),
    ],
)
def test_tls_aggregate_verdict_all_combinations(
    reachable: bool,
    cert_trusted: bool,
    hostname_match: bool | None,
    not_expired: bool | None,
    expected_status: str,
    expected_reason: str,
) -> None:
    status, reason = _tls_aggregate_verdict(
        reachable=reachable,
        cert_trusted=cert_trusted,
        hostname_match=hostname_match,
        not_expired=not_expired,
    )
    assert status == expected_status
    assert reason == expected_reason
    if status == "ok":
        assert reachable is True
        assert cert_trusted is True
        assert hostname_match is True
        assert not_expired is True


def test_host_tls_expired_and_untrusted_reports_failed() -> None:
    runner = DefaultHostProbeRunner()
    cert = {
        "subject": ((("commonName", "orders.booth.local"),),),
        "issuer": ((("organizationName", "Self Signed"),),),
        "notAfter": "Jan  1 00:00:00 2020 GMT",
        "subjectAltName": (("DNS", "orders.booth.local"),),
    }
    import ssl

    untrusted_ssock = MagicMock()
    untrusted_ssock.getpeercert.return_value = cert
    untrusted_ssock.__enter__ = MagicMock(return_value=untrusted_ssock)
    untrusted_ssock.__exit__ = MagicMock(return_value=False)
    with patch(_PIN_HOST, return_value=_PRIVATE_PIN):
        with patch("router_control_host.host_probes.ssl.create_default_context") as ctx_factory:
            ctx = MagicMock()
            ctx_factory.return_value = ctx
            ctx.wrap_socket.side_effect = [
                ssl.SSLCertVerificationError("untrusted"),
                untrusted_ssock,
            ]
            sock = MagicMock()
            sock.__enter__ = MagicMock(return_value=sock)
            sock.__exit__ = MagicMock(return_value=False)
            with patch(_PIN_CONN, return_value=sock):
                result = runner.probe_tls(hostname="orders.booth.local")
    assert result.aggregate_status == "failed"
    assert result.reason_code == "host_tls.certificate_expired"


def test_wildcard_hostname_match_single_label_only() -> None:
    cert = {
        "subject": ((("commonName", "*.example.com"),),),
        "issuer": ((("organizationName", "Test CA"),),),
        "notAfter": "Jan  1 00:00:00 2030 GMT",
        "subjectAltName": (("DNS", "*.example.com"),),
    }
    assert _cert_hostname_match(cert, "foo.example.com") is True
    assert _cert_hostname_match(cert, "a.b.example.com") is False


def test_resolve_and_pin_rejects_mixed_public_private() -> None:
    with patch("router_control_host.host_probes._getaddrinfo_bounded") as gai:
        gai.return_value = (
            [
                (2, 1, 6, "", ("192.168.1.10", 80)),
                (2, 1, 6, "", ("8.8.8.8", 80)),
            ],
            None,
        )
        pin, reason = resolve_and_pin("http://orders.booth.local/")
    assert pin is None
    assert reason == "host_http.target_address_not_allowed"


def test_resolve_and_pin_dns_timeout() -> None:
    bounded = "router_control_host.host_probes._getaddrinfo_bounded"
    with patch(bounded, return_value=(None, "timeout")):
        pin, reason = resolve_and_pin("http://192.168.1.10/")
    assert pin is None
    assert reason == "host_http.dns_timeout"


_DNS_INTERNAL_LIMIT_CODES = frozenset(
    {
        "host_http.dns_unavailable",
        "host_http.dns_timeout",
        "host_tls.dns_unavailable",
        "host_tls.dns_timeout",
        "host_internet.dns_unavailable",
        "host_internet.dns_timeout",
        "host_internet.inconclusive",
    }
)

_NETWORK_FACT_FIELDS = (
    ("host_http", "reachable"),
    ("host_tls", "reachable"),
    ("host_internet", "internet_reachable"),
    ("host_internet", "dns_ok"),
    ("host_internet", "tcp_ok"),
)


def _fake_getaddrinfo(
    host: str,
    port: int,
    *_args: object,
    **_kwargs: object,
) -> list[tuple[int, int, int, str, tuple[str, int]]]:
    if host in ("one.one.one.one", "dns.google"):
        return [(2, 1, 6, "", ("1.1.1.1", port))]
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return [(2, 1, 6, "", ("192.168.1.10", port))]
    return [(2, 1, 6, "", (host, port))]


def _fake_tcp_connection(*args: object, **kwargs: object) -> MagicMock:
    _ = args, kwargs
    conn = MagicMock()
    conn.__enter__ = MagicMock(return_value=conn)
    conn.__exit__ = MagicMock(return_value=False)
    return conn


def _tls_success_patches() -> tuple[Any, ...]:
    cert = {
        "subject": ((("commonName", "orders.booth.local"),),),
        "issuer": ((("organizationName", "Test CA"),),),
        "notAfter": "Jan  1 00:00:00 2030 GMT",
        "subjectAltName": (("DNS", "orders.booth.local"),),
    }
    ctx = MagicMock()
    ssock = MagicMock()
    ssock.getpeercert.return_value = cert
    ssock.__enter__ = MagicMock(return_value=ssock)
    ssock.__exit__ = MagicMock(return_value=False)
    sock = MagicMock()
    sock.__enter__ = MagicMock(return_value=sock)
    sock.__exit__ = MagicMock(return_value=False)
    ctx.wrap_socket.return_value = ssock
    return ctx, sock


def test_concurrent_three_probes_no_internal_dns_limit() -> None:
    runner = DefaultHostProbeRunner()
    ctx, sock = _tls_success_patches()
    release = threading.Event()
    pending_lock = threading.Lock()
    pending = 0

    def stall_first_wave(
        *args: object, **kwargs: object,
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        nonlocal pending
        host = str(args[0])
        port = int(args[1])
        with pending_lock:
            pending += 1
            if pending == 3:
                release.set()
        assert release.wait(timeout=5.0)
        return _fake_getaddrinfo(host, port, *args[2:], **kwargs)

    gai = "router_control_host.host_probes.socket.getaddrinfo"

    def run_http() -> HostHttpProbeResult:
        with patch(gai, side_effect=stall_first_wave):
            with patch("router_control_host.host_probes.http.client.HTTPConnection") as conn_cls:
                conn = MagicMock()
                conn_cls.return_value = conn
                response = MagicMock()
                response.status = 200
                response.read.return_value = b""
                conn.getresponse.return_value = response
                return runner.probe_http(url="http://orders.booth.local/")

    def run_tls() -> HostTlsProbeResult:
        with patch(gai, side_effect=stall_first_wave):
            ssl_ctx = "router_control_host.host_probes.ssl.create_default_context"
            with patch(ssl_ctx, return_value=ctx):
                with patch(_PIN_CONN, return_value=sock):
                    return runner.probe_tls(hostname="orders.booth.local")

    def run_internet() -> HostInternetProbeResult:
        with patch(gai, side_effect=stall_first_wave):
            with patch(_PIN_CONN, side_effect=_fake_tcp_connection):
                return runner.probe_internet(targets_profile="default")

    results: dict[str, HostHttpProbeResult | HostTlsProbeResult | HostInternetProbeResult] = {}
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = {
            pool.submit(run_http): "http",
            pool.submit(run_tls): "tls",
            pool.submit(run_internet): "internet",
        }
        for future in as_completed(futures):
            key = futures[future]
            results[key] = future.result()

    http = results["http"]
    tls = results["tls"]
    internet = results["internet"]
    assert http.reason_code == "host_http.reachable", http.reason_code
    assert http.reachable is True
    assert tls.reason_code == "host_tls.ok", tls.reason_code
    assert internet.reason_code == "host_internet.reachable", internet.reason_code
    assert internet.internet_reachable is True
    for probe in (http, tls, internet):
        assert probe.reason_code not in _DNS_INTERNAL_LIMIT_CODES


def test_getaddrinfo_bounded_timeout_reason() -> None:
    def slow_getaddrinfo(
        *args: object, **kwargs: object,
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        _ = args, kwargs
        threading.Event().wait(10.0)
        return [(2, 1, 6, "", ("192.168.1.10", 80))]

    with patch("router_control_host.host_probes.socket.getaddrinfo", side_effect=slow_getaddrinfo):
        infos, err = _getaddrinfo_bounded("orders.booth.local", 80, timeout=0.05)
        assert infos is None
        assert err == "timeout"
        pin, reason = resolve_and_pin("http://192.168.1.10/")
    assert pin is None
    assert reason == "host_http.dns_timeout"


def test_dns_internal_limit_never_reports_network_false() -> None:
    runner = DefaultHostProbeRunner()
    bounded = "router_control_host.host_probes._getaddrinfo_bounded"
    with patch(bounded, return_value=(None, "unavailable")):
        http = runner.probe_http(url="http://192.168.1.10/")
        tls = runner.probe_tls(hostname="orders.booth.local")
        internet = runner.probe_internet(targets_profile="default")
    assert http.reachable is None
    assert http.reason_code == "host_http.dns_unavailable"
    assert tls.reachable is None
    assert tls.reason_code == "host_tls.dns_unavailable"
    assert internet.internet_reachable is None
    assert internet.reason_code == "host_internet.dns_unavailable"
    assert internet.dns_ok is None
    for probe_name, field in _NETWORK_FACT_FIELDS:
        if probe_name == "host_http":
            assert getattr(http, field) is not False
        elif probe_name == "host_tls":
            assert getattr(tls, field) is not False
        else:
            assert getattr(internet, field) is not False

    with patch(bounded, return_value=(None, "timeout")):
        http = runner.probe_http(url="http://192.168.1.10/")
        tls = runner.probe_tls(hostname="orders.booth.local")
        internet = runner.probe_internet(targets_profile="default")
    assert http.reachable is None
    assert http.reason_code == "host_http.dns_timeout"
    assert tls.reachable is None
    assert tls.reason_code == "host_tls.dns_timeout"
    assert internet.internet_reachable is None
    assert internet.reason_code == "host_internet.dns_timeout"
    assert internet.dns_ok is None
    for probe_name, field in _NETWORK_FACT_FIELDS:
        if probe_name == "host_http":
            assert getattr(http, field) is not False
        elif probe_name == "host_tls":
            assert getattr(tls, field) is not False
        else:
            assert getattr(internet, field) is not False


def test_host_internet_all_dns_timeout_tcp_fail_is_unknown() -> None:
    import time

    from router_control_host.host_probes import DNS_RESOLVE_TIMEOUT_S

    def slow_getaddrinfo(
        *args: object,
        **kwargs: object,
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        _ = args, kwargs
        time.sleep(DNS_RESOLVE_TIMEOUT_S + 1.0)
        return [(2, 1, 6, "", ("1.1.1.1", 443))]

    runner = DefaultHostProbeRunner()
    gai = "router_control_host.host_probes.socket.getaddrinfo"
    conn = "router_control_host.host_probes.socket.create_connection"
    with patch(gai, side_effect=slow_getaddrinfo):
        with patch(conn, side_effect=OSError()):
            result = runner.probe_internet(targets_profile="default")
    assert result.dns_ok is None
    assert result.internet_reachable is None
    assert result.reason_code == "host_internet.dns_timeout"


def test_host_internet_mixed_dns_timeout_and_success_uses_completed_only() -> None:
    runner = DefaultHostProbeRunner()
    targets = list(INTERNET_DNS_TARGETS)
    assert len(targets) >= 2

    def mixed_bounded(
        hostname: str,
        port: int,
        *,
        timeout: float = 3.0,
    ) -> tuple[list[tuple[int, int, int, str, tuple[str, int]]] | None, str | None]:
        _ = timeout
        if hostname == targets[0]:
            return (None, "timeout")
        return ([(2, 1, 6, "", ("1.1.1.1", port))], None)

    bounded = "router_control_host.host_probes._getaddrinfo_bounded"
    conn = "router_control_host.host_probes.socket.create_connection"
    with patch(bounded, side_effect=mixed_bounded):
        with patch(conn, side_effect=_fake_tcp_connection):
            result = runner.probe_internet(targets_profile="default")
    assert result.dns_ok is True
    assert result.tcp_ok is True
    assert result.internet_reachable is True
    assert result.reason_code == "host_internet.reachable"


def test_host_internet_genuine_offline_still_refutes() -> None:
    runner = DefaultHostProbeRunner()
    gai = "router_control_host.host_probes.socket.getaddrinfo"
    conn = "router_control_host.host_probes.socket.create_connection"
    with patch(gai, side_effect=OSError()):
        with patch(conn, side_effect=OSError()):
            result = runner.probe_internet(targets_profile="default")
    assert result.dns_ok is False
    assert result.tcp_ok is False
    assert result.internet_reachable is False
    assert result.reason_code == "host_internet.offline_or_unreachable"


def test_https_probe_notes_certificate_not_verified() -> None:
    runner = DefaultHostProbeRunner()
    with patch("router_control_host.host_probes.resolve_and_pin") as pin:
        from router_control_host.host_probes import ResolvedPin

        pin.return_value = (
            ResolvedPin(
                hostname="orders.booth.local",
                pinned_ip="192.168.1.10",
                port=443,
                path="/",
            ),
            None,
        )
        with patch("router_control_host.host_probes._SniHttpsConnection") as conn_cls:
            conn = MagicMock()
            conn_cls.return_value = conn
            response = MagicMock()
            response.status = 200
            response.read.return_value = b""
            conn.getresponse.return_value = response
            result = runner.probe_http(url="https://192.168.1.10/")
    assert any("does not verify the certificate" in note for note in result.notes)
    conn_cls.assert_called_once()
    assert conn_cls.call_args.kwargs["server_hostname"] == "orders.booth.local"
