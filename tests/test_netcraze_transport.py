"""Netcraze transport tests (mocked HTTP, no live network)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import patch

import pytest
from router_control.adapters.netcraze.allowlist import (
    COMPONENTS_LIST,
    MAX_CONTINUATION_ROUNDS,
    SHOW_INTERFACE,
    SHOW_SYSTEM,
)
from router_control.adapters.netcraze.errors import (
    AllowlistViolation,
    AuthFailed,
    ContinuationUnsupported,
    TransportError,
    TransportTimeout,
)
from router_control.adapters.netcraze.transport import (
    HttpExchange,
    NetcrazeTransport,
    SshTunnelNetcrazeTransport,
    StdlibHttpClient,
    _loads_json_response,
    derive_management_host_header,
    is_loopback_management_host,
    parse_transport_target,
    resolve_ssh_management_host_header,
    validate_management_host_authority,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "netcraze"


@dataclass
class MockHttpClient:
    responses: list[HttpExchange] = field(default_factory=list)
    calls: list[tuple[str, str, str, str]] = field(default_factory=list)
    request_details: list[dict[str, object]] = field(default_factory=list)
    fail_with: Exception | None = None

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
    ) -> HttpExchange:
        if self.fail_with is not None:
            raise self.fail_with
        cookie = headers.get("Cookie", headers.get("cookie", ""))
        self.calls.append(
            (
                method,
                path,
                headers.get("Authorization", headers.get("authorization", "")),
                cookie,
            )
        )
        self.request_details.append(
            {
                "host": host,
                "port": port,
                "method": method,
                "path": path,
                "host_header": headers.get("Host", headers.get("host")),
                "headers": dict(headers),
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
    ) -> HttpExchange:
        exchange = self.request(
            host=host,
            port=port,
            method=method,
            path=path,
            headers=headers,
            body=body,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
            ssl_context=ssl_context,
        )
        if len(exchange.body) > max_bytes + 1:
            return HttpExchange(
                status=exchange.status,
                headers=exchange.headers,
                body=exchange.body[: max_bytes + 1],
                set_cookies=exchange.set_cookies,
            )
        return exchange


def _load(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def _challenge() -> HttpExchange:
    return HttpExchange(
        status=401,
        headers={
            "www-authenticate": (
                'Digest realm="Netcraze", nonce="abc123", qop="auth", algorithm=MD5'
            )
        },
        body=b"",
    )


def _ok_json(name: str) -> HttpExchange:
    return HttpExchange(status=200, headers={"content-type": "application/json"}, body=_load(name))


def test_repr_hides_password() -> None:
    transport = NetcrazeTransport(
        host="192.168.1.1",
        username="admin",
        password="lab-password-plaintext",
        http_client=MockHttpClient(),
    )
    rendered = repr(transport)
    assert "lab-password-plaintext" not in rendered
    assert "admin" in rendered


def test_default_uses_tls_even_on_non_443_port() -> None:
    transport = NetcrazeTransport(
        host="192.168.1.1",
        username="admin",
        password="lab-password",
        port=8443,
        http_client=MockHttpClient(),
    )
    assert transport.use_tls is True
    assert transport.ssl_context is not None


def test_use_tls_false_disables_ssl_context() -> None:
    transport = NetcrazeTransport(
        host="192.168.1.1",
        username="admin",
        password="lab-password",
        use_tls=False,
        http_client=MockHttpClient(),
    )
    assert transport.ssl_context is None


def test_digest_challenge_then_success() -> None:
    client = MockHttpClient(
        responses=[
            _challenge(),
            _ok_json("system.json"),
            _challenge(),
            _ok_json("components_list.json"),
        ]
    )
    transport = NetcrazeTransport(
        host="192.168.1.1",
        username="admin",
        password="lab-password",
        http_client=client,
    )
    payload = transport.read_json(SHOW_SYSTEM)
    assert payload["model"] == "NC-1812"
    assert len(client.calls) == 2
    assert client.calls[0][2] == ""
    assert client.calls[1][2].startswith("Digest ")


def test_loads_json_response_read_path_detects_corrupted_utf8() -> None:
    with pytest.raises(TransportError, match="encoding corrupted"):
        _loads_json_response(b'{"model": "NC-1812\xc0"}', strict_utf8=False)


def test_loads_json_response_read_path_valid_utf8() -> None:
    payload = _loads_json_response(b'{"ok": true}', strict_utf8=False)
    assert payload == {"ok": True}


def test_loads_json_response_write_path_strict_utf8() -> None:
    with pytest.raises(TransportError, match="not valid UTF-8"):
        _loads_json_response(b'{"status": "\xc0"}', strict_utf8=True)


def test_read_json_corrupted_utf8_fail_closed_not_plausible_data() -> None:
    client = MockHttpClient(
        responses=[
            _challenge(),
            HttpExchange(
                status=200,
                headers={"content-type": "application/json"},
                body=b'{"model": "NC-1812\xc0"}',
            ),
        ]
    )
    transport = NetcrazeTransport(
        host="192.168.1.1",
        username="admin",
        password="lab-password",
        http_client=client,
    )
    with pytest.raises(TransportError, match="encoding corrupted"):
        transport.read_json(SHOW_SYSTEM)


def test_auth_failure_after_retry() -> None:
    client = MockHttpClient(
        responses=[
            _challenge(),
            HttpExchange(status=401, headers={}, body=b""),
        ]
    )
    transport = NetcrazeTransport(
        host="192.168.1.1",
        username="admin",
        password="wrong",
        http_client=client,
    )
    with pytest.raises(AuthFailed):
        transport.read_json(SHOW_SYSTEM)


def test_timeout_normalized() -> None:
    client = MockHttpClient(fail_with=TransportTimeout("socket timeout"))
    transport = NetcrazeTransport(
        host="192.168.1.1",
        username="admin",
        password="lab-password",
        http_client=client,
    )
    with pytest.raises(TransportTimeout):
        transport.read_json(SHOW_SYSTEM)


def test_allowlist_accepts_new_get_paths() -> None:
    from router_control.adapters.netcraze.allowlist import is_allowlisted

    assert is_allowlisted("GET", "/rci/show/identification")
    assert is_allowlisted("GET", "/rci/show/version")


def test_allowlist_rejects_other_paths() -> None:
    transport = NetcrazeTransport(host="192.168.1.1", username="u", password="p")
    with pytest.raises(AllowlistViolation):
        transport._request("GET", "/rci/show/running-config", None)


def test_continuation_bounded() -> None:
    continued = HttpExchange(
        status=200,
        headers={"content-type": "application/json"},
        body=json.dumps({"continued": True}).encode(),
    )
    client = MockHttpClient(responses=[_challenge(), continued] * MAX_CONTINUATION_ROUNDS)
    transport = NetcrazeTransport(
        host="192.168.1.1",
        username="admin",
        password="lab-password",
        http_client=client,
        continuation_budget_seconds=5.0,
    )
    with pytest.raises(ContinuationUnsupported):
        transport.read_json(SHOW_SYSTEM)


def test_continuation_resolves() -> None:
    continued = HttpExchange(
        status=200,
        headers={"content-type": "application/json"},
        body=json.dumps({"continued": True, "components": []}).encode(),
    )
    final = _ok_json("components_list.json")
    client = MockHttpClient(
        responses=[
            _challenge(),
            continued,
            _challenge(),
            final,
        ]
    )
    transport = NetcrazeTransport(
        host="192.168.1.1",
        username="admin",
        password="lab-password",
        http_client=client,
    )
    payload = transport.read_json(COMPONENTS_LIST, b"{}")
    assert isinstance(payload, list)


def _interactive_challenge() -> HttpExchange:
    return HttpExchange(
        status=401,
        headers={
            "www-authenticate": (
                'x-ndw2-interactive endpoint="/auth" session_cookie="synth_cookie"'
            )
        },
        body=b"",
    )


def _auth_get_challenge() -> HttpExchange:
    return HttpExchange(
        status=401,
        headers={
            "x-ndm-challenge": "SYNTH_TOKEN",
            "x-ndm-realm": "SYNTH_REALM",
        },
        set_cookies=("synth_cookie=synth_init",),
        body=b"{}",
    )


def _auth_post_ok() -> HttpExchange:
    return HttpExchange(status=200, headers={}, body=b"{}")


_INTERACTIVE_EXPECTED_HASH = "ae228e4836a769915a008803cb7d5ca6421368462fad4c6a5ea908ff50dbf555"


def test_interactive_auth_sequence_and_hash_vector() -> None:
    client = MockHttpClient(
        responses=[
            _interactive_challenge(),
            _auth_get_challenge(),
            _auth_post_ok(),
            HttpExchange(
                status=200,
                headers={"set-cookie": "synth_cookie=synth_session"},
                body=b"{}",
            ),
            _ok_json("system.json"),
            _ok_json("components_list.json"),
        ]
    )
    transport = NetcrazeTransport(
        host="192.168.1.1",
        username="synthuser",
        password="synthpass",
        use_tls=False,
        http_client=client,
    )
    system = transport.read_json(SHOW_SYSTEM)
    assert system["model"] == "NC-1812"
    transport.read_json(COMPONENTS_LIST, b"{}")
    assert [call[0:2] for call in client.calls[:5]] == [
        ("GET", "/rci/show/system"),
        ("GET", "/auth"),
        ("POST", "/auth"),
        ("GET", "/auth"),
        ("GET", "/rci/show/system"),
    ]
    assert client.calls[1][3] == ""
    assert client.calls[2][3] == "synth_cookie=synth_init"
    assert client.calls[3][3] == "synth_cookie=synth_init"
    assert client.calls[4][3] == "synth_cookie=synth_session"


def test_interactive_post_body_uses_hardcoded_hash() -> None:
    captured: dict[str, bytes | None] = {"body": None}

    class BodyCapturingClient(MockHttpClient):
        def request(self, **kwargs):  # type: ignore[no-untyped-def]
            if kwargs["method"] == "POST" and kwargs["path"] == "/auth":
                captured["body"] = kwargs["body"]
            return super().request(**kwargs)

    client = BodyCapturingClient(
        responses=[
            _interactive_challenge(),
            _auth_get_challenge(),
            _auth_post_ok(),
            HttpExchange(
                status=200,
                headers={"set-cookie": "synth_cookie=synth_session"},
                body=b"{}",
            ),
            _ok_json("system.json"),
        ]
    )
    transport = NetcrazeTransport(
        host="192.168.1.1",
        username="synthuser",
        password="synthpass",
        use_tls=False,
        http_client=client,
    )
    transport.read_json(SHOW_SYSTEM)
    assert captured["body"] is not None
    payload = json.loads(captured["body"].decode("utf-8"))
    assert payload["login"] == "synthuser"
    assert payload["password"] == _INTERACTIVE_EXPECTED_HASH


def test_interactive_repr_hides_session_and_password() -> None:
    transport = NetcrazeTransport(
        host="192.168.1.1",
        username="synthuser",
        password="synthpass",
        http_client=MockHttpClient(),
    )
    transport._set_session_cookie("synth_cookie", "synth_session")  # noqa: SLF001
    rendered = repr(transport)
    assert "synthpass" not in rendered
    assert "synth_session" not in rendered
    assert "synth_cookie" not in rendered


def test_interactive_second_rci_401_fails() -> None:
    client = MockHttpClient(
        responses=[
            _interactive_challenge(),
            _auth_get_challenge(),
            _auth_post_ok(),
            HttpExchange(
                status=200,
                headers={"set-cookie": "synth_cookie=synth_session"},
                body=b"{}",
            ),
            HttpExchange(status=401, headers={}, body=b""),
        ]
    )
    transport = NetcrazeTransport(
        host="192.168.1.1",
        username="synthuser",
        password="synthpass",
        use_tls=False,
        http_client=client,
    )
    with pytest.raises(AuthFailed):
        transport.read_json(SHOW_SYSTEM)


@pytest.mark.parametrize(
    "challenge",
    [
        'x-ndw2-interactive endpoint="/other" session_cookie="synth_cookie"',
        'x-ndw2-interactive endpoint="/auth"',
        'x-ndw2-interactive endpoint="/auth" session_cookie="bad name"',
        'x-ndw2-interactive endpoint="/auth" session_cookie="synth_cookie=synth_init"',
        "Bearer realm=lab",
    ],
)
def test_malformed_or_unknown_challenge_fails_closed(challenge: str) -> None:
    client = MockHttpClient(
        responses=[HttpExchange(status=401, headers={"www-authenticate": challenge}, body=b"")]
    )
    transport = NetcrazeTransport(
        host="192.168.1.1",
        username="synthuser",
        password="synthpass",
        http_client=client,
    )
    with pytest.raises(AuthFailed):
        transport.read_json(SHOW_SYSTEM)


def test_interactive_missing_challenge_headers_fail_closed() -> None:
    client = MockHttpClient(
        responses=[
            _interactive_challenge(),
            HttpExchange(
                status=401,
                headers={},
                set_cookies=("synth_cookie=synth_init",),
                body=b"{}",
            ),
        ]
    )
    transport = NetcrazeTransport(
        host="192.168.1.1",
        username="synthuser",
        password="synthpass",
        http_client=client,
    )
    with pytest.raises(AuthFailed):
        transport.read_json(SHOW_SYSTEM)


def test_parse_transport_target_http_and_https() -> None:
    http_target = parse_transport_target("http://192.168.1.1:80")
    assert http_target.hostname == "192.168.1.1"
    assert http_target.port == 80
    assert http_target.use_tls is False
    assert http_target.scheme == "http"
    https_target = parse_transport_target("https://192.168.1.1:8443")
    assert https_target.port == 8443
    assert https_target.use_tls is True
    assert https_target.scheme == "https"
    bare = parse_transport_target("192.168.1.1")
    assert bare.use_tls is True
    assert bare.port == 443


def test_transport_security_labels_for_insecure_http() -> None:
    transport = NetcrazeTransport(
        host="192.168.1.1",
        username="admin",
        password="lab-password",
        use_tls=False,
        http_client=MockHttpClient(),
    )
    assert transport.transport_security_label == "insecure_http"
    assert transport.https_check_label == "not_certified"
    assert transport.gate_a_certification_eligible is False


def test_interactive_auth_get_failure_before_post() -> None:
    client = MockHttpClient(
        responses=[
            _interactive_challenge(),
            HttpExchange(status=403, headers={}, body=b""),
        ]
    )
    transport = NetcrazeTransport(
        host="192.168.1.1",
        username="synthuser",
        password="synthpass",
        use_tls=False,
        http_client=client,
    )
    with pytest.raises(AuthFailed, match="interactive authentication challenge failed"):
        transport.read_json(SHOW_SYSTEM)
    assert all(call[0] != "POST" for call in client.calls)


def test_interactive_whitespace_only_challenge_headers_fail_closed() -> None:
    client = MockHttpClient(
        responses=[
            _interactive_challenge(),
            HttpExchange(
                status=401,
                headers={"x-ndm-challenge": "   ", "x-ndm-realm": "SYNTH_REALM"},
                set_cookies=("synth_cookie=synth_init",),
                body=b"{}",
            ),
        ]
    )
    transport = NetcrazeTransport(
        host="192.168.1.1",
        username="synthuser",
        password="synthpass",
        http_client=client,
    )
    with pytest.raises(AuthFailed, match="interactive challenge headers missing") as exc_info:
        transport.read_json(SHOW_SYSTEM)
    assert "   " not in str(exc_info.value)


def test_interactive_extracts_expected_cookie_from_multiple_set_cookie() -> None:
    client = MockHttpClient(
        responses=[
            _interactive_challenge(),
            HttpExchange(
                status=401,
                headers={
                    "x-ndm-challenge": "SYNTH_TOKEN",
                    "x-ndm-realm": "SYNTH_REALM",
                },
                set_cookies=(
                    "other_cookie=other_value",
                    "synth_cookie=synth_init",
                    "another=ignored",
                ),
                body=b"{}",
            ),
            _auth_post_ok(),
            HttpExchange(
                status=200,
                headers={"set-cookie": "ignored_last=wrong"},
                set_cookies=(
                    "other_cookie=other_value",
                    "synth_cookie=synth_session",
                    "another=ignored",
                ),
                body=b"{}",
            ),
            _ok_json("system.json"),
        ]
    )
    transport = NetcrazeTransport(
        host="192.168.1.1",
        username="synthuser",
        password="synthpass",
        use_tls=False,
        http_client=client,
    )
    transport.read_json(SHOW_SYSTEM)
    assert client.calls[2][3] == "synth_cookie=synth_init"
    assert client.calls[4][3] == "synth_cookie=synth_session"


def test_repr_hides_http_client_after_sensitive_calls() -> None:
    client = MockHttpClient(
        responses=[
            _interactive_challenge(),
            _auth_get_challenge(),
            _auth_post_ok(),
            HttpExchange(
                status=200,
                headers={"set-cookie": "synth_cookie=synth_session"},
                body=b"{}",
            ),
            _ok_json("system.json"),
        ]
    )
    transport = NetcrazeTransport(
        host="192.168.1.1",
        username="synthuser",
        password="synthpass",
        use_tls=False,
        http_client=client,
    )
    transport.read_json(SHOW_SYSTEM)
    rendered = repr(transport)
    assert "synthpass" not in rendered
    assert "synth_session" not in rendered
    assert "synth_cookie=synth_session" not in rendered
    assert "MockHttpClient" not in rendered
    assert "SYNTH_TOKEN" not in rendered


def test_digest_crlf_in_nonce_fails_without_leak() -> None:
    injected = "Net\r\nInjected"
    client = MockHttpClient(
        responses=[
            HttpExchange(
                status=401,
                headers={
                    "www-authenticate": (
                        f'Digest realm="{injected}", nonce="abc123", qop="auth", algorithm=MD5'
                    )
                },
                body=b"",
            ),
        ]
    )
    transport = NetcrazeTransport(
        host="192.168.1.1",
        username="admin",
        password="lab-password",
        http_client=client,
    )
    with pytest.raises(AuthFailed, match="invalid digest challenge") as exc_info:
        transport.read_json(SHOW_SYSTEM)
    assert injected not in str(exc_info.value)
    assert len(client.calls) == 1


def test_interactive_crlf_in_session_cookie_name_fails_without_leak() -> None:
    injected = "synth\r\nInjected"
    client = MockHttpClient(
        responses=[
            HttpExchange(
                status=401,
                headers={
                    "www-authenticate": (
                        f'x-ndw2-interactive endpoint="/auth" session_cookie="{injected}"'
                    )
                },
                body=b"",
            ),
        ]
    )
    transport = NetcrazeTransport(
        host="192.168.1.1",
        username="synthuser",
        password="synthpass",
        http_client=client,
    )
    with pytest.raises(AuthFailed) as exc_info:
        transport.read_json(SHOW_SYSTEM)
    rendered = str(exc_info.value) + repr(exc_info.value) + repr(transport)
    assert injected not in rendered
    assert len(client.calls) == 1


def test_interactive_crlf_in_realm_fails_without_leak() -> None:
    injected = 'realm"\r\nInjected: yes'
    client = MockHttpClient(
        responses=[
            _interactive_challenge(),
            HttpExchange(
                status=401,
                headers={"x-ndm-challenge": "SYNTH_TOKEN", "x-ndm-realm": injected},
                set_cookies=("synth_cookie=synth_init",),
                body=b"{}",
            ),
        ]
    )
    transport = NetcrazeTransport(
        host="192.168.1.1",
        username="synthuser",
        password="synthpass",
        http_client=client,
    )
    with pytest.raises(AuthFailed, match="interactive challenge headers missing") as exc_info:
        transport.read_json(SHOW_SYSTEM)
    assert injected not in str(exc_info.value)


def test_parse_transport_target_rejects_userinfo() -> None:
    with pytest.raises(ValueError, match="embedded credentials") as exc_info:
        parse_transport_target("http://secret:token@192.168.1.1")
    assert "secret" not in str(exc_info.value)
    assert "token" not in str(exc_info.value)
    with pytest.raises(ValueError, match="embedded credentials"):
        parse_transport_target("user@192.168.1.1")


@pytest.mark.parametrize("status", [200, 302, 403])
def test_interactive_first_get_rejects_non_401(status: int) -> None:
    client = MockHttpClient(
        responses=[
            _interactive_challenge(),
            HttpExchange(
                status=status,
                headers={
                    "x-ndm-challenge": "SYNTH_TOKEN",
                    "x-ndm-realm": "SYNTH_REALM",
                },
                set_cookies=("synth_cookie=synth_init",),
                body=b"{}",
            ),
        ]
    )
    transport = NetcrazeTransport(
        host="192.168.1.1",
        username="synthuser",
        password="synthpass",
        use_tls=False,
        http_client=client,
    )
    with pytest.raises(AuthFailed, match="interactive authentication challenge failed"):
        transport.read_json(SHOW_SYSTEM)
    assert all(call[0] != "POST" for call in client.calls)


@pytest.mark.parametrize(
    "set_cookies",
    [
        (),
        ("other_cookie=other_value",),
        ("synth_cookie",),
        ("synth_cookie=",),
        ("synth_cookie=bad value",),
        ("synth_cookie=synth_a", "synth_cookie=synth_b"),
    ],
)
def test_interactive_mandatory_set_cookie_fail_closed(set_cookies: tuple[str, ...]) -> None:
    client = MockHttpClient(
        responses=[
            _interactive_challenge(),
            HttpExchange(
                status=401,
                headers={
                    "x-ndm-challenge": "SYNTH_TOKEN",
                    "x-ndm-realm": "SYNTH_REALM",
                },
                set_cookies=set_cookies,
                body=b"{}",
            ),
        ]
    )
    transport = NetcrazeTransport(
        host="192.168.1.1",
        username="synthuser",
        password="synthpass",
        use_tls=False,
        http_client=client,
    )
    with pytest.raises(AuthFailed, match="authentication failed") as exc_info:
        transport.read_json(SHOW_SYSTEM)
    assert "synth" not in str(exc_info.value).lower()
    assert all(call[0] != "POST" for call in client.calls)


def test_interactive_malformed_sibling_does_not_mask_valid_cookie() -> None:
    client = MockHttpClient(
        responses=[
            _interactive_challenge(),
            HttpExchange(
                status=401,
                headers={
                    "x-ndm-challenge": "SYNTH_TOKEN",
                    "x-ndm-realm": "SYNTH_REALM",
                },
                set_cookies=(
                    ";;;",
                    "other=val",
                    "synth_cookie=synth_init",
                ),
                body=b"{}",
            ),
            _auth_post_ok(),
            HttpExchange(
                status=200,
                headers={"set-cookie": "synth_cookie=synth_session"},
                body=b"{}",
            ),
            _ok_json("system.json"),
        ]
    )
    transport = NetcrazeTransport(
        host="192.168.1.1",
        username="synthuser",
        password="synthpass",
        use_tls=False,
        http_client=client,
    )
    transport.read_json(SHOW_SYSTEM)
    assert client.calls[2][3] == "synth_cookie=synth_init"


@pytest.mark.parametrize("status", [199, 302, 401, 500])
def test_interactive_post_rejects_non_2xx(status: int) -> None:
    client = MockHttpClient(
        responses=[
            _interactive_challenge(),
            _auth_get_challenge(),
            HttpExchange(status=status, headers={}, body=b""),
        ]
    )
    transport = NetcrazeTransport(
        host="192.168.1.1",
        username="synthuser",
        password="synthpass",
        use_tls=False,
        http_client=client,
    )
    with pytest.raises(AuthFailed, match="interactive authentication post failed"):
        transport.read_json(SHOW_SYSTEM)
    assert len(client.calls) == 3
    assert client.calls[-1][0:2] == ("POST", "/auth")
    assert sum(1 for call in client.calls if call[1].startswith("/rci/")) == 1


@pytest.mark.parametrize("status", [199, 302, 401, 500])
def test_interactive_final_get_rejects_non_2xx(status: int) -> None:
    client = MockHttpClient(
        responses=[
            _interactive_challenge(),
            _auth_get_challenge(),
            _auth_post_ok(),
            HttpExchange(status=status, headers={}, body=b""),
        ]
    )
    transport = NetcrazeTransport(
        host="192.168.1.1",
        username="synthuser",
        password="synthpass",
        use_tls=False,
        http_client=client,
    )
    with pytest.raises(AuthFailed, match="interactive authentication finalize failed"):
        transport.read_json(SHOW_SYSTEM)
    assert len(client.calls) == 4
    assert client.calls[-1][0:2] == ("GET", "/auth")
    assert sum(1 for call in client.calls if call[1].startswith("/rci/")) == 1


def test_interactive_final_get_rejects_duplicate_matching_cookies() -> None:
    client = MockHttpClient(
        responses=[
            _interactive_challenge(),
            _auth_get_challenge(),
            _auth_post_ok(),
            HttpExchange(
                status=200,
                headers={},
                set_cookies=("synth_cookie=synth_a", "synth_cookie=synth_b"),
                body=b"{}",
            ),
        ]
    )
    transport = NetcrazeTransport(
        host="192.168.1.1",
        username="synthuser",
        password="synthpass",
        use_tls=False,
        http_client=client,
    )
    with pytest.raises(AuthFailed, match="authentication failed") as exc_info:
        transport.read_json(SHOW_SYSTEM)
    assert "synth_a" not in str(exc_info.value)
    assert "synth_b" not in str(exc_info.value)


def _ssh_tunnel_transport(
    client: MockHttpClient,
    **overrides: object,
) -> SshTunnelNetcrazeTransport:
    defaults = {
        "host": "127.0.0.1",
        "port": 54321,
        "use_tls": False,
        "username": "admin",
        "password": "lab-password",
        "management_host_header": "192.168.1.1",
        "http_client": client,
    }
    defaults.update(overrides)
    return SshTunnelNetcrazeTransport(**defaults)  # type: ignore[arg-type]


def test_direct_transport_does_not_set_explicit_host() -> None:
    client = MockHttpClient(responses=[_challenge(), _ok_json("system.json")])
    transport = NetcrazeTransport(
        host="192.168.1.1",
        username="admin",
        password="lab-password",
        http_client=client,
    )
    transport.read_json(SHOW_SYSTEM)
    assert client.request_details[0]["host"] == "192.168.1.1"
    assert client.request_details[0]["host_header"] is None
    assert client.request_details[1]["host_header"] is None


def test_ssh_transport_host_header_distinct_from_tcp_endpoint() -> None:
    client = MockHttpClient(responses=[_challenge(), _ok_json("system.json")])
    transport = _ssh_tunnel_transport(client)
    transport.read_json(SHOW_SYSTEM)
    first = client.request_details[0]
    assert first["host"] == "127.0.0.1"
    assert first["port"] == 54321
    assert first["host_header"] == "192.168.1.1"
    assert first["host_header"] != first["host"]


def test_ssh_transport_same_host_across_digest_retry() -> None:
    client = MockHttpClient(
        responses=[
            _challenge(),
            _ok_json("system.json"),
        ]
    )
    transport = _ssh_tunnel_transport(client)
    transport.read_json(SHOW_SYSTEM)
    host_headers = [detail["host_header"] for detail in client.request_details]
    assert host_headers == ["192.168.1.1", "192.168.1.1"]


def test_ssh_transport_same_host_across_interactive_auth_flow() -> None:
    client = MockHttpClient(
        responses=[
            _interactive_challenge(),
            _auth_get_challenge(),
            _auth_post_ok(),
            HttpExchange(
                status=200,
                headers={"set-cookie": "synth_cookie=synth_session"},
                body=b"{}",
            ),
            _ok_json("system.json"),
        ]
    )
    transport = _ssh_tunnel_transport(client, username="synthuser", password="synthpass")
    transport.read_json(SHOW_SYSTEM)
    host_headers = [detail["host_header"] for detail in client.request_details]
    assert host_headers == ["192.168.1.1"] * 5
    assert [detail["host"] for detail in client.request_details] == ["127.0.0.1"] * 5


def test_ssh_transport_requires_management_host_header() -> None:
    with pytest.raises(ValueError, match="management host header is required"):
        SshTunnelNetcrazeTransport(
            host="127.0.0.1",
            port=54321,
            use_tls=False,
            username="admin",
            password="lab-password",
            http_client=MockHttpClient(),
        )


def test_ssh_transport_rejects_management_host_same_as_tcp_endpoint() -> None:
    with pytest.raises(ValueError, match="must not be loopback"):
        SshTunnelNetcrazeTransport(
            host="127.0.0.1",
            port=54321,
            use_tls=False,
            username="admin",
            password="lab-password",
            management_host_header="127.0.0.1",
            http_client=MockHttpClient(),
        )


@pytest.mark.parametrize(
    "management_host_header",
    [
        "127.0.0.1",
        "127.0.0.1.",
        "::1",
        "[::1]",
        "0:0:0:0:0:0:0:1",
        "::ffff:127.0.0.1",
        "localhost",
        "LOCALHOST",
        "localhost.",
    ],
)
def test_ssh_transport_rejects_equivalent_loopback_management_hosts(
    management_host_header: str,
) -> None:
    with pytest.raises(ValueError, match="must not be loopback"):
        SshTunnelNetcrazeTransport(
            host="127.0.0.1",
            port=54321,
            use_tls=False,
            username="admin",
            password="lab-password",
            management_host_header=management_host_header,
            http_client=MockHttpClient(),
        )


def test_ssh_transport_rejects_loopback_management_even_when_tcp_is_private() -> None:
    with pytest.raises(ValueError, match="must not be loopback"):
        SshTunnelNetcrazeTransport(
            host="192.168.1.1",
            port=54321,
            use_tls=False,
            username="admin",
            password="lab-password",
            management_host_header="127.0.0.1",
            http_client=MockHttpClient(),
        )


@pytest.mark.parametrize(
    "management_host_header",
    [
        "127.1",
        "127.0.1",
        "0177.0.0.1",
        "127.00.0.1",
        "127.000.000.001",
        "2130706433",
        "0177.1",
        "0x7f.1",
    ],
)
def test_ssh_transport_rejects_legacy_ipv4_management_hosts(
    management_host_header: str,
) -> None:
    with pytest.raises(ValueError, match="ambiguous numeric management host"):
        SshTunnelNetcrazeTransport(
            host="192.168.1.1",
            port=54321,
            use_tls=False,
            username="admin",
            password="lab-password",
            management_host_header=management_host_header,
            http_client=MockHttpClient(),
        )


@pytest.mark.parametrize(
    "authority",
    [
        "127.0.0.1",
        "127.0.0.1.",
        "[::1]",
        "::1",
        "::ffff:127.0.0.1",
        "localhost",
        "LOCALHOST",
    ],
)
def test_is_loopback_management_host_detects_equivalents(authority: str) -> None:
    assert is_loopback_management_host(authority) is True


@pytest.mark.parametrize(
    "authority",
    [
        "192.168.1.1",
        "router.local",
        "[fe80::1]",
        "fe80::1",
    ],
)
def test_is_loopback_management_host_allows_private_non_loopback(authority: str) -> None:
    assert is_loopback_management_host(authority) is False


def test_resolve_ssh_management_host_header_rejects_loopback_before_tcp_check() -> None:
    with pytest.raises(ValueError, match="must not be loopback"):
        resolve_ssh_management_host_header("127.0.0.1", tcp_host="192.168.1.1")


@pytest.mark.parametrize(
    "authority",
    [
        "192.168.1.1",
        "router.local",
        "[fe80::1]",
    ],
)
def test_resolve_ssh_management_host_header_allows_normal_private_hosts(authority: str) -> None:
    assert resolve_ssh_management_host_header(authority, tcp_host="127.0.0.1") == authority


def test_ssh_transport_post_init_mutation_cannot_emit_unsafe_host() -> None:
    client = MockHttpClient(responses=[_challenge(), _ok_json("system.json")])
    transport = _ssh_tunnel_transport(client)
    transport.management_host_header = "bad\r\nInjected"
    with pytest.raises(ValueError):
        transport.read_json(SHOW_SYSTEM)
    assert not client.request_details


@pytest.mark.parametrize(
    ("authority", "expected"),
    [
        ("192.168.1.1", "192.168.1.1"),
        ("router.local", "router.local"),
        ("[fe80::1]", "[fe80::1]"),
        ("fe80::1", "[fe80::1]"),
        ("fd00::1:2", "[fd00::1:2]"),
        ("fe80::1:8080", "[fe80::1:8080]"),
        ("2001:db8::1:80", "[2001:db8::1:80]"),
    ],
)
def test_validate_management_host_authority_accepts_valid(authority: str, expected: str) -> None:
    assert validate_management_host_authority(authority) == expected


@pytest.mark.parametrize(
    "authority",
    [
        "",
        "192.168.1.1:8080",
        "secret:token@192.168.1.1",
        "192.168.1.1/admin",
        "192.168.1.1?x=1",
        "192.168.1.1#frag",
        "bad\r\nInjected",
        "[fe80::1",
        "fe80::1]",
        "[192.168.1.1]",
        "host:abc",
        "[fe80::1]:8080",
    ],
)
def test_validate_management_host_authority_rejects_injection(authority: str) -> None:
    with pytest.raises(ValueError) as exc_info:
        validate_management_host_authority(authority)
    if authority:
        assert authority not in str(exc_info.value)


@pytest.mark.parametrize(
    "authority",
    [
        "127.1",
        "127.0.1",
        "0177.0.0.1",
        "127.00.0.1",
        "127.000.000.001",
        "2130706433",
        "0177.1",
        "0x7f.1",
    ],
)
def test_validate_management_host_authority_rejects_legacy_ipv4(authority: str) -> None:
    with pytest.raises(ValueError, match="ambiguous numeric management host") as exc_info:
        validate_management_host_authority(authority)
    assert authority not in str(exc_info.value)


def test_derive_management_host_header_from_probe_target() -> None:
    assert derive_management_host_header("192.168.1.1") == "192.168.1.1"
    assert derive_management_host_header("https://192.168.1.1:8443") == "192.168.1.1"
    assert derive_management_host_header("http://192.168.1.1:80") == "192.168.1.1"


def test_derive_management_host_header_rejects_encoded_crlf() -> None:
    with pytest.raises(ValueError, match="invalid characters"):
        derive_management_host_header("http://192.168.1.1%0d%0aInjected/")


def test_derive_management_host_header_accepts_ipv6_decimal_hextet() -> None:
    assert derive_management_host_header("fe80::1:8080") == "[fe80::1:8080]"
    assert derive_management_host_header("http://[fd00::1:2]/") == "[fd00::1:2]"


def test_derive_management_host_header_rejects_bracketed_ipv6_with_port() -> None:
    with pytest.raises(ValueError, match="must not include port"):
        derive_management_host_header("[fe80::1]:8080")


def test_stdlib_explicit_host_header_is_passed_through() -> None:
    captured: dict[str, object] = {}

    class RecordingConnection:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            captured["connect_host"] = host
            captured["connect_port"] = port

        def request(
            self,
            method: str,
            path: str,
            body: bytes | None,
            headers: dict[str, str],
        ) -> None:
            captured["method"] = method
            captured["path"] = path
            captured["headers"] = dict(headers)

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
        "router_control.adapters.netcraze.transport.http.client.HTTPConnection",
        RecordingConnection,
    ):
        transport = SshTunnelNetcrazeTransport(
            host="127.0.0.1",
            port=54321,
            use_tls=False,
            username="admin",
            password="lab-password",
            management_host_header="192.168.1.1",
            http_client=StdlibHttpClient(),
        )
        transport._send("GET", "/rci/show/system", {"Accept": "application/json"}, None)

    assert captured["connect_host"] == "127.0.0.1"
    assert captured["connect_port"] == 54321
    assert captured["headers"]["Host"] == "192.168.1.1"


def test_plain_transport_refuses_discovery_read() -> None:
    transport = NetcrazeTransport(
        host="192.168.1.1",
        username="admin",
        password="lab-password",
        http_client=MockHttpClient(),
    )
    with pytest.raises(TransportError, match="pinned SSH"):
        transport.fetch_discovery_read(SHOW_INTERFACE)


def test_ssh_discovery_requires_pin_and_source_address() -> None:
    client = MockHttpClient()
    transport = _ssh_tunnel_transport(client)
    with pytest.raises(TransportError, match="pinned SSH"):
        transport.fetch_discovery_read(SHOW_INTERFACE)

    transport_pinned = _ssh_tunnel_transport(
        client,
        ssh_host_key_algorithm="ssh-ed25519",
        ssh_host_key_fingerprint_sha256="SHA256:abcdef",
    )
    with pytest.raises(TransportError, match="source_address"):
        transport_pinned.fetch_discovery_read(SHOW_INTERFACE)


def test_ssh_discovery_fetch_uses_fixed_path_not_allowlisted() -> None:
    payload = {"interface": []}
    body = json.dumps(payload).encode("utf-8")
    client = MockHttpClient(
        responses=[
            HttpExchange(status=200, headers={"content-type": "application/json"}, body=body)
        ]
    )
    transport = _ssh_tunnel_transport(
        client,
        ssh_host_key_algorithm="ssh-ed25519",
        ssh_host_key_fingerprint_sha256="SHA256:abcdef",
        source_address="192.168.1.144",
    )
    result = transport.fetch_discovery_read(SHOW_INTERFACE)
    assert result == payload
    assert client.calls[0][1] == "/rci/show/interface"


def test_fetch_allowlisted_rejects_show_interface() -> None:
    client = MockHttpClient()
    transport = NetcrazeTransport(
        host="192.168.1.1",
        username="admin",
        password="lab-password",
        http_client=client,
    )
    with pytest.raises(AllowlistViolation):
        transport.fetch_allowlisted(SHOW_INTERFACE)
    assert client.calls == []

