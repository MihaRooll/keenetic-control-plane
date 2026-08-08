"""Transport opt-in for bootstrap discovery reads over plain HTTP."""

from __future__ import annotations

import json
import ssl
from dataclasses import dataclass, field
from unittest.mock import patch

import pytest
from router_control.adapters.netcraze.allowlist import (
    COMPONENTS_LIST,
    COMPONENTS_LIST_STATUS,
    MAX_CONTINUATION_ROUNDS,
    SHOW_INTERFACE,
    SHOW_IP_HTTP,
    SHOW_IP_ROUTE,
    SHOW_IP_SSH,
    SHOW_SYSTEM,
)
from router_control.adapters.netcraze.errors import (
    AllowlistViolation,
    AuthFailed,
    ContinuationUnsupported,
    TransportError,
)
from router_control.adapters.netcraze.transport import HttpExchange, NetcrazeTransport


@dataclass
class MockHttpClient:
    responses: list[HttpExchange] = field(default_factory=list)
    calls: list[tuple[str, str]] = field(default_factory=list)
    request_details: list[dict[str, object]] = field(default_factory=list)

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
        ssl_context: object | None,
        connect_host: str | None = None,
        server_hostname: str | None = None,
    ) -> HttpExchange:
        self.calls.append((method, path))
        self.request_details.append(
            {
                "host": host,
                "connect_host": connect_host,
                "server_hostname": server_hostname,
                "host_header": headers.get("Host", headers.get("host")),
            }
        )
        if not self.responses:
            raise TransportError("no mock responses left")
        return self.responses.pop(0)

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
        ssl_context: object | None,
        max_bytes: int,
        connect_host: str | None = None,
        server_hostname: str | None = None,
    ) -> HttpExchange:
        return self.request(
            host=host,
            port=port,
            method=method,
            path=path,
            headers=headers,
            body=body,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
            ssl_context=ssl_context,
            connect_host=connect_host,
            server_hostname=server_hostname,
        )


def _json_exchange(payload: object) -> HttpExchange:
    return HttpExchange(
        status=200,
        headers={"content-type": "application/json"},
        body=json.dumps(payload).encode("utf-8"),
    )


def test_default_plain_transport_refuses_discovery_read() -> None:
    transport = NetcrazeTransport(
        host="192.168.2.1",
        username="admin",
        password="lab-password",
        use_tls=False,
        http_client=MockHttpClient(),
    )
    with pytest.raises(TransportError, match="pinned SSH"):
        transport.fetch_discovery_read(SHOW_INTERFACE)


def test_opt_in_requires_expendable_lab_class(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ROUTER_CONTROL_LAB_CLASS", raising=False)
    transport = NetcrazeTransport(
        host="192.168.2.1",
        username="admin",
        password="lab-password",
        use_tls=False,
        allow_insecure_http=True,
        http_client=MockHttpClient(),
    )
    with pytest.raises(TransportError, match="expendable lab class"):
        transport.fetch_discovery_read(SHOW_INTERFACE)


def test_opt_in_allowlists_bootstrap_commands_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")
    payload = {"interface": []}
    client = MockHttpClient(responses=[_json_exchange(payload)])
    transport = NetcrazeTransport(
        host="192.168.2.1",
        username="admin",
        password="lab-password",
        use_tls=False,
        allow_insecure_http=True,
        http_client=client,
    )
    result = transport.fetch_discovery_read(SHOW_INTERFACE)
    assert result == payload
    assert client.calls == [("GET", "/rci/show/interface")]


def test_opt_in_refuses_non_bootstrap_discovery_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")
    transport = NetcrazeTransport(
        host="192.168.2.1",
        username="admin",
        password="lab-password",
        use_tls=False,
        allow_insecure_http=True,
        http_client=MockHttpClient(),
    )
    with pytest.raises(AllowlistViolation, match="bootstrap-discovery-allowlisted"):
        transport.fetch_discovery_read(SHOW_IP_ROUTE)


def test_opt_in_components_list_uses_post_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")
    payload = {"component": {"ndm": {"installed": True}}}
    client = MockHttpClient(responses=[_json_exchange(payload)])
    transport = NetcrazeTransport(
        host="192.168.2.1",
        username="admin",
        password="lab-password",
        use_tls=False,
        allow_insecure_http=True,
        http_client=client,
    )
    result = transport.fetch_discovery_read(COMPONENTS_LIST)
    assert result == payload
    assert client.calls[0] == ("POST", "/rci/components/list")


def test_bootstrap_components_list_post_then_get_poll(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")
    final_payload = {
        "sandbox": "stable",
        "firmware": {"version": "5.01.C.1.0-0"},
        "component": {"ndm": {"installed": True}},
    }
    client = MockHttpClient(
        responses=[
            _json_exchange({"continued": True}),
            _json_exchange(final_payload),
        ]
    )
    transport = NetcrazeTransport(
        host="192.168.2.1",
        username="admin",
        password="lab-password",
        use_tls=False,
        allow_insecure_http=True,
        http_client=client,
    )
    result = transport.fetch_discovery_read(COMPONENTS_LIST)
    assert result == final_payload
    assert client.calls == [
        ("POST", "/rci/components/list"),
        ("GET", "/rci/components/list"),
    ]


def test_bootstrap_components_list_never_completes_within_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")
    continued = _json_exchange({"continued": True})
    client = MockHttpClient(
        responses=[continued] * (MAX_CONTINUATION_ROUNDS + 2),
    )
    transport = NetcrazeTransport(
        host="192.168.2.1",
        username="admin",
        password="lab-password",
        use_tls=False,
        allow_insecure_http=True,
        continuation_budget_seconds=30.0,
        http_client=client,
    )
    with pytest.raises(ContinuationUnsupported):
        transport.fetch_discovery_read(COMPONENTS_LIST)
    get_calls = [call for call in client.calls if call == ("GET", "/rci/components/list")]
    assert len(get_calls) <= MAX_CONTINUATION_ROUNDS
    assert client.calls[0] == ("POST", "/rci/components/list")


def test_bootstrap_components_list_time_budget_exceeded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")
    continued = _json_exchange({"continued": True})
    client = MockHttpClient(
        responses=[
            continued,
            continued,
        ]
    )
    monotonic_values = iter([0.0, 0.5, 2.0])

    def fake_monotonic() -> float:
        return next(monotonic_values)

    monkeypatch.setattr(
        "router_control.adapters.netcraze.transport.time.monotonic",
        fake_monotonic,
    )
    transport = NetcrazeTransport(
        host="192.168.2.1",
        username="admin",
        password="lab-password",
        use_tls=False,
        allow_insecure_http=True,
        continuation_budget_seconds=1.0,
        http_client=client,
    )
    with pytest.raises(ContinuationUnsupported, match="time budget exceeded"):
        transport.fetch_discovery_read(COMPONENTS_LIST)
    assert client.calls == [
        ("POST", "/rci/components/list"),
        ("GET", "/rci/components/list"),
    ]


def test_bootstrap_components_list_status_not_in_gate_a_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")
    transport = NetcrazeTransport(
        host="192.168.2.1",
        username="admin",
        password="lab-password",
        use_tls=False,
        http_client=MockHttpClient(),
    )
    with pytest.raises(AllowlistViolation, match="not allowlisted"):
        transport.fetch_allowlisted(COMPONENTS_LIST_STATUS)


def test_plain_transport_stays_non_certifying(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")
    transport = NetcrazeTransport(
        host="192.168.2.1",
        username="admin",
        password="lab-password",
        use_tls=False,
        allow_insecure_http=True,
        http_client=MockHttpClient(responses=[_json_exchange({})]),
    )
    transport.fetch_discovery_read(SHOW_SYSTEM)
    assert transport.gate_a_certification_eligible is False
    assert transport.transport_security_label == "insecure_http"
    assert transport.https_check_label == "not_certified"


def _not_found_exchange() -> HttpExchange:
    return HttpExchange(status=404, headers={}, body=b"")


def test_bootstrap_get_404_raises_feature_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")
    client = MockHttpClient(responses=[_not_found_exchange()])
    transport = NetcrazeTransport(
        host="192.168.2.1",
        username="admin",
        password="lab-password",
        use_tls=False,
        allow_insecure_http=True,
        http_client=client,
    )
    from router_control.adapters.netcraze.errors import FeatureAbsent

    with pytest.raises(FeatureAbsent, match="404"):
        transport.fetch_discovery_read(SHOW_IP_SSH)


def test_bootstrap_get_auth_failure_stays_hard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")
    challenge = 'Digest realm="x", nonce="abc123", qop="auth"'
    client = MockHttpClient(
        responses=[
            HttpExchange(status=401, headers={"www-authenticate": challenge}, body=b""),
            HttpExchange(status=401, headers={}, body=b""),
        ]
    )
    transport = NetcrazeTransport(
        host="192.168.2.1",
        username="admin",
        password="lab-password",
        use_tls=False,
        allow_insecure_http=True,
        http_client=client,
    )
    with pytest.raises(AuthFailed, match="authentication failed"):
        transport.fetch_discovery_read(SHOW_IP_HTTP)


def test_bootstrap_get_transport_failure_stays_hard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")

    class FailingClient:
        def request(self, **_kwargs: object) -> HttpExchange:
            raise TransportError("connection refused")

        def request_limited(self, **_kwargs: object) -> HttpExchange:
            raise TransportError("connection refused")

    transport = NetcrazeTransport(
        host="192.168.2.1",
        username="admin",
        password="lab-password",
        use_tls=False,
        allow_insecure_http=True,
        http_client=FailingClient(),
    )
    with pytest.raises(TransportError, match="connection refused"):
        transport.fetch_discovery_read(SHOW_IP_SSH)


def test_pinned_bootstrap_https_keeps_host_and_sni_on_logical_hostname(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")
    pinned_ip = "192.168.1.50"
    logical_host = "router.local"
    client = MockHttpClient(responses=[_json_exchange({"hostname": logical_host})])
    transport = NetcrazeTransport(
        host=pinned_ip,
        pinned_connect_host=pinned_ip,
        management_host_header=logical_host,
        username="admin",
        password="lab-password",
        use_tls=True,
        allow_insecure_http=True,
        ssl_context=ssl.create_default_context(),
        http_client=client,
    )
    transport.fetch_discovery_read(SHOW_SYSTEM)
    detail = client.request_details[0]
    assert detail["host"] == pinned_ip
    assert detail["connect_host"] == pinned_ip
    assert detail["server_hostname"] == logical_host
    assert detail["host_header"] == logical_host


def test_stdlib_pinned_https_uses_sni_connection() -> None:
    captured: dict[str, object] = {}

    class RecordingSniConnection:
        def __init__(
            self,
            pinned_ip: str,
            port: int,
            *,
            server_hostname: str,
            timeout: float,
            context: ssl.SSLContext,
        ) -> None:
            captured["connect_host"] = pinned_ip
            captured["server_hostname"] = server_hostname
            captured["port"] = port

        def request(
            self,
            method: str,
            path: str,
            body: bytes | None,
            headers: dict[str, str],
        ) -> None:
            captured["host_header"] = headers.get("Host")

        def getresponse(self) -> object:
            class Response:
                status = 200

                def getheaders(self) -> list[tuple[str, str]]:
                    return [("Content-Type", "application/json")]

                def read(self) -> bytes:
                    return b"{}"

            return Response()

        def close(self) -> None:
            return None

    with patch(
        "router_control.adapters.netcraze.transport._SniHttpsConnection",
        RecordingSniConnection,
    ):
        transport = NetcrazeTransport(
            host="192.168.1.50",
            pinned_connect_host="192.168.1.50",
            management_host_header="router.local",
            username="admin",
            password="lab-password",
            use_tls=True,
            allow_insecure_http=True,
            ssl_context=ssl.create_default_context(),
        )
        transport._send("GET", "/rci/show/system", {"Accept": "application/json"}, None)

    assert captured["connect_host"] == "192.168.1.50"
    assert captured["server_hostname"] == "router.local"
    assert captured["host_header"] == "router.local"
