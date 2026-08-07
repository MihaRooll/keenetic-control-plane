"""Synthetic tests for pinned SSH tunnel transport (no live network)."""

from __future__ import annotations

import base64
import hashlib
from typing import Any, cast
from unittest.mock import MagicMock, patch

import pytest
from router_control.adapters.netcraze.errors import (
    SshHostKeyMismatch,
    SshHostKeyMissing,
    SshHostNotPrivate,
    SshParamikoMissing,
    SshTransientConnectionError,
    SshTunnelError,
)
from router_control.adapters.netcraze.ssh_tunnel import (
    REMOTE_RCI_PORT,
    PinnedSshTransport,
    PinnedSshTunnel,
    SshTunnelConfig,
    compute_host_key_fingerprint,
    host_is_private,
    normalize_sha256_fingerprint,
    sanitize_ssh_error_message,
    validate_ssh_tunnel_host,
)
from router_control.adapters.netcraze.transport import SshTunnelNetcrazeTransport


class _FakeKey:
    def __init__(self, key_type: str, key_bytes: bytes) -> None:
        self._key_type = key_type
        self._key_bytes = key_bytes

    def get_name(self) -> str:
        return self._key_type

    def asbytes(self) -> bytes:
        return self._key_bytes


def _fingerprint_for(key_bytes: bytes) -> str:
    digest = hashlib.sha256(key_bytes).digest()
    return f"SHA256:{base64.b64encode(digest).decode('ascii').rstrip('=')}"


def _make_config(**overrides: object) -> SshTunnelConfig:
    defaults = {
        "ssh_host": "192.168.1.1",
        "username": "lab-user",
        "password": "synth-secret",
        "host_key_sha256": _fingerprint_for(b"test-host-key"),
    }
    defaults.update(overrides)
    return SshTunnelConfig(**defaults)  # type: ignore[arg-type]


def test_normalize_sha256_fingerprint_requires_value() -> None:
    with pytest.raises(SshHostKeyMissing):
        normalize_sha256_fingerprint("")
    with pytest.raises(SshHostKeyMissing):
        normalize_sha256_fingerprint("SHA256:")


def test_normalize_sha256_fingerprint_accepts_bare_and_prefixed_digest() -> None:
    valid = _fingerprint_for(b"test-host-key")
    bare = valid.split(":", 1)[1]
    assert normalize_sha256_fingerprint(bare) == valid
    assert normalize_sha256_fingerprint(valid) == valid
    gate_a_pin = "lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM"
    assert normalize_sha256_fingerprint(f"SHA256:{gate_a_pin}") == f"SHA256:{gate_a_pin}"


def test_normalize_sha256_fingerprint_rejects_invalid_digest_shape() -> None:
    with pytest.raises(SshHostKeyMissing, match="43-character OpenSSH base64"):
        normalize_sha256_fingerprint("abc123")
    with pytest.raises(SshHostKeyMissing, match="43-character OpenSSH base64"):
        normalize_sha256_fingerprint("!!!not-base64!!!")


def test_compute_host_key_fingerprint_ed25519() -> None:
    key_bytes = b"synthetic-ed25519-public"
    algorithm, fingerprint = compute_host_key_fingerprint(_FakeKey("ssh-ed25519", key_bytes))
    assert algorithm == "ssh-ed25519"
    assert fingerprint == _fingerprint_for(key_bytes)


def test_host_is_private_ranges() -> None:
    assert host_is_private("192.168.1.1") is True
    assert host_is_private("8.8.8.8") is False
    assert host_is_private("[fd00::1]") is True
    assert host_is_private("2606:4700:4700::1111") is False


def test_password_hidden_in_config_repr() -> None:
    config = _make_config()
    assert "synth-secret" not in repr(config)


def test_sanitize_ssh_error_message_redacts_password() -> None:
    message = sanitize_ssh_error_message("auth failed for synth-secret", password="synth-secret")
    assert "synth-secret" not in message
    assert "[REDACTED]" in message


def test_fixed_remote_forward_port() -> None:
    assert REMOTE_RCI_PORT == 80


def test_forward_destination_uses_validated_ssh_host() -> None:
    key_bytes = b"pinned-key"
    fingerprint = _fingerprint_for(key_bytes)
    fake_transport = MagicMock()
    fake_transport.get_remote_server_key.return_value = _FakeKey("ssh-ed25519", key_bytes)
    fake_transport.auth_password.return_value = []

    config = _make_config(ssh_host="192.168.1.1", host_key_sha256=fingerprint)
    tunnel = PinnedSshTunnel(config, _transport_factory=lambda _cfg: fake_transport)
    with tunnel:
        assert tunnel._forward_server is not None
        handler_cls = cast(Any, tunnel._forward_server.RequestHandlerClass)
        assert handler_cls.remote_host == "192.168.1.1"
        assert handler_cls.remote_port == 80


def test_forward_destination_canonicalizes_ssh_host() -> None:
    key_bytes = b"pinned-key"
    fingerprint = _fingerprint_for(key_bytes)
    fake_transport = MagicMock()
    fake_transport.get_remote_server_key.return_value = _FakeKey("ssh-ed25519", key_bytes)
    fake_transport.auth_password.return_value = []

    config = _make_config(ssh_host="192.168.1.1.", host_key_sha256=fingerprint)
    tunnel = PinnedSshTunnel(config, _transport_factory=lambda _cfg: fake_transport)
    with tunnel:
        assert tunnel._forward_server is not None
        handler_cls = cast(Any, tunnel._forward_server.RequestHandlerClass)
        assert handler_cls.remote_host == "192.168.1.1"
        assert handler_cls.remote_port == 80


def test_rejects_loopback_ssh_host() -> None:
    config = _make_config(ssh_host="127.0.0.1")
    tunnel = PinnedSshTunnel(config)
    with pytest.raises(SshTunnelError, match="must not be loopback"):
        tunnel.open()


@pytest.mark.parametrize(
    "ssh_host",
    [
        "192.168.1",
        "user@192.168.1.1",
        "192.168.1.1/path",
        "192.168.1.1\r\n",
    ],
)
def test_rejects_malformed_ssh_host(ssh_host: str) -> None:
    config = _make_config(ssh_host=ssh_host)
    tunnel = PinnedSshTunnel(config)
    with pytest.raises(SshTunnelError):
        tunnel.open()


def test_validate_ssh_tunnel_host_rejects_loopback() -> None:
    with pytest.raises(SshTunnelError, match="must not be loopback"):
        validate_ssh_tunnel_host("127.0.0.1")


_GATE_A_STYLE_PIN = "SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM"


def test_ssh_tunnel_transport_labels() -> None:
    transport = SshTunnelNetcrazeTransport(
        host="127.0.0.1",
        port=54321,
        use_tls=False,
        username="lab-user",
        password="secret",
        management_host_header="192.168.1.1",
        ssh_host_key_algorithm="ssh-ed25519",
        ssh_host_key_fingerprint_sha256=_GATE_A_STYLE_PIN,
    )
    assert transport.transport_security_label == "ssh_tunnel"
    assert transport.https_check_label == "ssh_host_key_pinned"
    assert transport.gate_a_certification_eligible is True


def test_ssh_tunnel_transport_not_eligible_without_pin_metadata() -> None:
    transport = SshTunnelNetcrazeTransport(
        host="127.0.0.1",
        port=54321,
        use_tls=False,
        username="lab-user",
        password="secret",
        management_host_header="192.168.1.1",
    )
    assert transport.gate_a_certification_eligible is False
    assert transport.https_check_label == "not_certified"


def test_ssh_tunnel_transport_partial_pin_metadata_not_certifying() -> None:
    transport = SshTunnelNetcrazeTransport(
        host="127.0.0.1",
        port=54321,
        use_tls=False,
        username="lab-user",
        password="secret",
        management_host_header="192.168.1.1",
        ssh_host_key_algorithm="ssh-ed25519",
    )
    assert transport.gate_a_certification_eligible is False
    assert transport.https_check_label == "not_certified"


def test_missing_paramiko_fail_closed() -> None:
    config = _make_config()
    with patch(
        "router_control.adapters.netcraze.ssh_tunnel._lazy_import_paramiko",
        side_effect=SshParamikoMissing("missing"),
    ):
        tunnel = PinnedSshTunnel(config)
        with pytest.raises(SshParamikoMissing):
            tunnel.open()


def test_rejects_non_private_ssh_host_by_default() -> None:
    config = _make_config(ssh_host="8.8.8.8")
    tunnel = PinnedSshTunnel(config)
    with pytest.raises(SshHostNotPrivate):
        tunnel.open()


def test_host_key_mismatch_before_auth_password() -> None:
    key_bytes = b"actual-key-material"
    expected = _fingerprint_for(b"other-key-material")
    call_order: list[str] = []

    fake_transport = MagicMock()
    fake_transport.get_remote_server_key.return_value = _FakeKey("ssh-ed25519", key_bytes)

    def _auth_password(username: str, password: str, event: object = None) -> list[str]:
        call_order.append("auth_password")
        return []

    fake_transport.auth_password.side_effect = _auth_password

    config = _make_config(host_key_sha256=expected)

    def factory(_cfg: SshTunnelConfig) -> MagicMock:
        call_order.append("connect")
        return fake_transport

    tunnel = PinnedSshTunnel(config, _transport_factory=factory)
    with pytest.raises(SshHostKeyMismatch):
        tunnel.open()
    assert call_order == ["connect"]
    fake_transport.auth_password.assert_not_called()


def test_correct_pin_opens_tunnel_and_closes() -> None:
    key_bytes = b"pinned-key"
    fingerprint = _fingerprint_for(key_bytes)
    fake_transport = MagicMock()
    fake_transport.get_remote_server_key.return_value = _FakeKey("ssh-ed25519", key_bytes)
    fake_transport.auth_password.return_value = []

    config = _make_config(host_key_sha256=fingerprint)

    def factory(_cfg: SshTunnelConfig) -> MagicMock:
        return fake_transport

    tunnel = PinnedSshTunnel(config, _transport_factory=factory)
    with tunnel:
        assert tunnel.local_port > 0
        assert tunnel.host_key_algorithm == "ssh-ed25519"
        assert tunnel.host_key_fingerprint_sha256 == fingerprint
    fake_transport.close.assert_called_once()


def test_auth_failure_closes_transport_on_empty_success_list_inverted() -> None:
    """Paramiko returns [] on auth success; must not treat that as failure."""
    key_bytes = b"pinned-key"
    fingerprint = _fingerprint_for(key_bytes)
    fake_transport = MagicMock()
    fake_transport.get_remote_server_key.return_value = _FakeKey("ssh-ed25519", key_bytes)
    fake_transport.auth_password.return_value = []
    fake_sock = MagicMock()

    config = _make_config(host_key_sha256=fingerprint)

    fake_paramiko = MagicMock()
    fake_paramiko.Transport.return_value = fake_transport

    with patch(
        "router_control.adapters.netcraze.ssh_tunnel._lazy_import_paramiko",
        return_value=fake_paramiko,
    ):
        with patch(
            "router_control.adapters.netcraze.ssh_tunnel.socket.create_connection",
            return_value=fake_sock,
        ):
            tunnel = PinnedSshTunnel(config)
            with tunnel:
                assert tunnel.local_port > 0
    fake_transport.close.assert_called_once()


def test_auth_failure_on_remaining_methods() -> None:
    key_bytes = b"pinned-key"
    fingerprint = _fingerprint_for(key_bytes)
    fake_transport = MagicMock()
    fake_transport.get_remote_server_key.return_value = _FakeKey("ssh-ed25519", key_bytes)
    fake_transport.auth_password.return_value = ["publickey"]
    fake_sock = MagicMock()

    config = _make_config(host_key_sha256=fingerprint)

    fake_paramiko = MagicMock()
    fake_paramiko.Transport.return_value = fake_transport

    with patch(
        "router_control.adapters.netcraze.ssh_tunnel._lazy_import_paramiko",
        return_value=fake_paramiko,
    ):
        with patch(
            "router_control.adapters.netcraze.ssh_tunnel.socket.create_connection",
            return_value=fake_sock,
        ):
            tunnel = PinnedSshTunnel(config)
            with pytest.raises(SshTunnelError, match="SSH authentication failed"):
                tunnel.open()
    fake_transport.close.assert_called()


def test_auth_failure_on_authentication_exception() -> None:
    key_bytes = b"pinned-key"
    fingerprint = _fingerprint_for(key_bytes)
    fake_transport = MagicMock()
    fake_transport.get_remote_server_key.return_value = _FakeKey("ssh-ed25519", key_bytes)

    class FakeAuthException(Exception):
        pass

    fake_transport.auth_password.side_effect = FakeAuthException("bad password")
    fake_sock = MagicMock()

    config = _make_config(host_key_sha256=fingerprint)

    fake_paramiko = MagicMock()
    fake_paramiko.Transport.return_value = fake_transport
    fake_paramiko.ssh_exception.AuthenticationException = FakeAuthException

    with patch(
        "router_control.adapters.netcraze.ssh_tunnel._lazy_import_paramiko",
        return_value=fake_paramiko,
    ):
        with patch(
            "router_control.adapters.netcraze.ssh_tunnel.socket.create_connection",
            return_value=fake_sock,
        ):
            tunnel = PinnedSshTunnel(config)
            with pytest.raises(SshTunnelError, match="SSH authentication failed"):
                tunnel.open()
    fake_transport.close.assert_called()


def test_auth_timeout_wired_before_password_auth() -> None:
    key_bytes = b"pinned-key"
    fingerprint = _fingerprint_for(key_bytes)
    fake_transport = MagicMock()
    fake_transport.get_remote_server_key.return_value = _FakeKey("ssh-ed25519", key_bytes)
    fake_transport.auth_password.return_value = []
    fake_sock = MagicMock()

    config = _make_config(host_key_sha256=fingerprint, auth_timeout=7.5)

    fake_paramiko = MagicMock()
    fake_paramiko.Transport.return_value = fake_transport

    with patch(
        "router_control.adapters.netcraze.ssh_tunnel._lazy_import_paramiko",
        return_value=fake_paramiko,
    ):
        with patch(
            "router_control.adapters.netcraze.ssh_tunnel.socket.create_connection",
            return_value=fake_sock,
        ):
            tunnel = PinnedSshTunnel(config)
            with tunnel:
                assert tunnel.local_port > 0
    assert fake_transport.auth_timeout == 7.5


def test_connect_timeout_normalized() -> None:
    config = _make_config(connect_timeout=1.0)

    with patch(
        "router_control.adapters.netcraze.ssh_tunnel._lazy_import_paramiko",
        return_value=MagicMock(),
    ):
        with patch(
            "router_control.adapters.netcraze.ssh_tunnel.socket.create_connection",
            side_effect=TimeoutError("timed out"),
        ):
            tunnel = PinnedSshTunnel(config)
            with pytest.raises(SshTunnelError, match="SSH connection timed out"):
                tunnel.open()


def test_probe_evidence_ssh_tunnel_artifact_fields() -> None:
    import json
    from datetime import UTC, datetime
    from pathlib import Path

    from router_control.adapters.netcraze.adapter import NetcrazeReadOnlyAdapter
    from router_control.domain.ids import RouterId

    class FixedClock:
        def now(self) -> datetime:
            return datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC)

    fixtures = Path(__file__).resolve().parent / "fixtures" / "netcraze"

    def _load(name: str) -> object:
        return json.loads((fixtures / name).read_text(encoding="utf-8"))

    key_bytes = b"artifact-key"
    fingerprint = _fingerprint_for(key_bytes)

    class SshRecordingTransport:
        transport_security_label = "ssh_tunnel"
        https_check_label = "ssh_host_key_pinned"
        gate_a_certification_eligible = True
        ssh_host_key_algorithm = "ssh-ed25519"
        ssh_host_key_fingerprint_sha256 = fingerprint

        def read_json(self, command, body=None):  # type: ignore[no-untyped-def]
            from router_control.adapters.netcraze.allowlist import (
                COMPONENTS_LIST,
                SHOW_IDENTIFICATION,
                SHOW_SYSTEM,
                SHOW_VERSION,
            )

            if command is SHOW_SYSTEM:
                return _load("system_telemetry_only.json")
            if command is COMPONENTS_LIST:
                return _load("components_observed.json")
            if command is SHOW_IDENTIFICATION:
                return _load("identification_both_ids.json")
            if command is SHOW_VERSION:
                return _load("version_match.json")
            raise AssertionError("unexpected command")

    adapter = NetcrazeReadOnlyAdapter(
        router_id=RouterId("router-lab-001"),
        transport=SshRecordingTransport(),  # type: ignore[arg-type]
        clock=FixedClock(),
    )
    evidence = adapter.probe_gate_a_evidence()

    assert evidence["transport_security"] == "ssh_tunnel"
    assert evidence["https_check"] == "ssh_host_key_pinned"
    assert evidence["ssh_host_key_algorithm"] == "ssh-ed25519"
    assert evidence["ssh_host_key_fingerprint_sha256"] == fingerprint
    assert evidence["gate_a_certification_eligible"] is True
    assert evidence["certification_eligible"] is True
    assert evidence["identity_complete"] is True


def test_validate_source_address_accepts_private_literal() -> None:
    from router_control.adapters.netcraze.ssh_tunnel import (
        source_address_class,
        validate_source_address,
    )

    assert validate_source_address("192.168.1.144") == "192.168.1.144"
    assert source_address_class("192.168.1.144") == "private_ipv4_literal"
    assert source_address_class("fd00::1") == "private_ipv6_literal"


@pytest.mark.parametrize(
    "address",
    ["0.0.0.0", "255.255.255.255", "127.0.0.1", "8.8.8.8", "224.0.0.1"],
)
def test_validate_source_address_rejects_non_private_or_special(address: str) -> None:
    from router_control.adapters.netcraze.ssh_tunnel import (
        SshSourceAddressInvalid,
        validate_source_address,
    )

    with pytest.raises(SshSourceAddressInvalid):
        validate_source_address(address)


def test_create_bound_tcp_connection_uses_source_address() -> None:
    from router_control.adapters.netcraze.ssh_tunnel import create_bound_tcp_connection

    sock_instance = MagicMock()
    with patch(
        "router_control.adapters.netcraze.ssh_tunnel.socket.socket",
        return_value=sock_instance,
    ) as socket_ctor:
        sock = create_bound_tcp_connection(
            "192.168.1.1",
            22,
            timeout=1.0,
            source_address="192.168.1.144",
        )
    assert sock is sock_instance
    socket_ctor.assert_called_once()
    sock_instance.settimeout.assert_called_once_with(1.0)
    sock_instance.bind.assert_called_once_with(("192.168.1.144", 0))
    sock_instance.connect.assert_called_once_with(("192.168.1.1", 22))


def test_create_bound_tcp_connection_remote_refuse_raises_oserror_not_bind_error() -> None:
    from router_control.adapters.netcraze.ssh_tunnel import create_bound_tcp_connection

    sock_instance = MagicMock()
    sock_instance.connect.side_effect = OSError("connection refused")
    with patch(
        "router_control.adapters.netcraze.ssh_tunnel.socket.socket",
        return_value=sock_instance,
    ):
        with pytest.raises(OSError, match="connection refused"):
            create_bound_tcp_connection(
                "192.168.1.1",
                22,
                timeout=1.0,
                source_address="192.168.1.144",
            )
    sock_instance.close.assert_called_once()


def test_create_bound_tcp_connection_bind_failure_has_no_fallback() -> None:
    from router_control.adapters.netcraze.ssh_tunnel import (
        SshSourceAddressBindError,
        create_bound_tcp_connection,
    )

    sock_instance = MagicMock()
    sock_instance.bind.side_effect = OSError("cannot assign requested address")
    with patch(
        "router_control.adapters.netcraze.ssh_tunnel.socket.socket",
        return_value=sock_instance,
    ):
        with pytest.raises(SshSourceAddressBindError, match="failed to bind"):
            create_bound_tcp_connection(
                "192.168.1.1",
                22,
                timeout=1.0,
                source_address="192.168.1.144",
            )
    sock_instance.close.assert_called_once()
    sock_instance.connect.assert_not_called()


def test_pinned_tunnel_open_passes_source_address_to_tcp_connect() -> None:
    key_bytes = b"pinned-key"
    fingerprint = _fingerprint_for(key_bytes)
    fake_transport = MagicMock()
    fake_transport.get_remote_server_key.return_value = _FakeKey("ssh-ed25519", key_bytes)
    fake_transport.auth_password.return_value = []
    fake_sock = MagicMock()

    config = _make_config(
        host_key_sha256=fingerprint,
        source_address="192.168.1.144",
    )

    fake_paramiko = MagicMock()
    fake_paramiko.Transport.return_value = fake_transport

    with patch(
        "router_control.adapters.netcraze.ssh_tunnel.create_bound_tcp_connection",
        return_value=fake_sock,
    ) as bound_connect:
        with patch(
            "router_control.adapters.netcraze.ssh_tunnel._lazy_import_paramiko",
            return_value=fake_paramiko,
        ):
            tunnel = PinnedSshTunnel(config)
            with tunnel:
                assert tunnel.local_port > 0
    bound_connect.assert_called_once()
    assert bound_connect.call_args.kwargs["source_address"] == "192.168.1.144"


def test_pinned_ssh_transport_opens_without_forwarder() -> None:
    key_bytes = b"pinned-key"
    fingerprint = _fingerprint_for(key_bytes)
    fake_transport = MagicMock()
    fake_transport.get_remote_server_key.return_value = _FakeKey("ssh-ed25519", key_bytes)
    fake_transport.auth_password.return_value = []
    fake_transport.is_active.return_value = True

    config = _make_config(host_key_sha256=fingerprint, source_address="192.168.1.144")

    transport_ctx = PinnedSshTransport(
        config,
        _transport_factory=lambda _cfg: fake_transport,
    )
    with transport_ctx:
        assert transport_ctx.host_key_algorithm == "ssh-ed25519"
        assert transport_ctx.host_key_fingerprint_sha256 == fingerprint
    fake_transport.close.assert_called()


def test_exec_show_interface_home_classifies_rejected_exit() -> None:
    from router_control.adapters.netcraze.ssh_tunnel import exec_show_interface_home

    channel = MagicMock()
    channel.recv.side_effect = [b"", b"permission denied"]
    channel.recv_exit_status.return_value = 1
    channel.closed = True
    transport = MagicMock()
    transport.is_active.return_value = True
    transport.open_session.return_value = channel

    result = exec_show_interface_home(transport, password="synth-secret")
    assert result.classification == "exec_rejected"
    assert "show interface Home" not in repr(result)


def test_shell_show_interface_home_fail_closed_on_prompt_ambiguity() -> None:
    from router_control.adapters.netcraze.ssh_tunnel import shell_show_interface_home

    channel = MagicMock()
    channel.recv_ready.return_value = True
    channel.recv.side_effect = [b"partial output without prompt", b""] + [b""] * 20
    channel.closed = True
    transport = MagicMock()
    transport.is_active.return_value = True
    transport.open_session.return_value = channel
    channel.get_pty.return_value = None
    channel.invoke_shell.return_value = None

    result = shell_show_interface_home(transport, password="synth-secret", stage_timeout=0.2)
    assert result.classification == "shell_inconclusive"
    assert result.response_body_nonempty is False


@pytest.mark.parametrize(
    "prompt_tail",
    [
        b"Router# ",
        b"Welcome> ",
        b"(config)# ",
        b"> ",
        b"# ",
    ],
)
def test_discovery_prompt_rejects_non_netcraze_suffixes(prompt_tail: bytes) -> None:
    from router_control.adapters.netcraze.ssh_tunnel import shell_show_interface_home

    channel = MagicMock()
    channel.recv_ready.return_value = True
    body = b"Interface Home state up\r\n"
    command_echo = b"show interface Home\r\n"
    channel.recv.side_effect = [
        prompt_tail,
        command_echo + body + prompt_tail,
        b"",
    ] + [b""] * 20
    channel.closed = True
    transport = MagicMock()
    transport.is_active.return_value = True
    transport.open_session.return_value = channel
    channel.get_pty.return_value = None
    channel.invoke_shell.return_value = None

    result = shell_show_interface_home(transport, password="synth-secret", stage_timeout=0.2)
    assert result.classification != "shell_framing_observed"
    assert result.initial_prompt_observed is False or result.prompt_return_observed is False


@pytest.mark.parametrize(
    "prompt_tail",
    [
        b"(config)> ",
        b"(config-ssh)> ",
        b"(config)>   ",
        b"(config-ssh)>   ",
    ],
)
def test_discovery_prompt_accepts_netcraze_config_prompts(prompt_tail: bytes) -> None:
    from router_control.adapters.netcraze.ssh_tunnel import shell_show_interface_home

    channel = MagicMock()
    channel.recv_ready.return_value = True
    body = b"Interface Home state up\r\n"
    command_echo = b"show interface Home\r\n"
    channel.recv.side_effect = [
        prompt_tail,
        command_echo + body + prompt_tail,
        b"",
    ] + [b""] * 20
    channel.closed = True
    transport = MagicMock()
    transport.is_active.return_value = True
    transport.open_session.return_value = channel
    channel.get_pty.return_value = None
    channel.invoke_shell.return_value = None

    result = shell_show_interface_home(transport, password="synth-secret", stage_timeout=0.2)
    assert result.classification == "shell_framing_observed"
    assert result.initial_prompt_observed is True
    assert result.prompt_return_observed is True


def test_learn_ssh_host_key_mock_transport_no_auth() -> None:
    from router_control.adapters.netcraze.ssh_tunnel import learn_ssh_host_key

    key_bytes = b"learn-only-key"
    fingerprint = _fingerprint_for(key_bytes)
    fake_key = _FakeKey("ssh-ed25519", key_bytes)
    transport = MagicMock()
    transport.get_remote_server_key.return_value = fake_key

    def factory(**_kwargs: object) -> Any:
        return transport

    learned = learn_ssh_host_key(
        "192.168.1.1",
        transport_factory=factory,
    )
    assert learned.algorithm == "ssh-ed25519"
    assert learned.fingerprint_sha256 == fingerprint
    transport.start_client.assert_called_once()
    transport.get_remote_server_key.assert_called_once()
    transport.auth_password.assert_not_called()
    transport.auth_none.assert_not_called()
    transport.close.assert_called_once()


def test_learn_ssh_host_key_start_client_ssh_exception() -> None:
    """SSHException during banner read → SshTunnelError with operator-facing message."""
    import paramiko
    from router_control.adapters.netcraze.ssh_tunnel import learn_ssh_host_key

    transport = MagicMock()
    transport.start_client.side_effect = paramiko.ssh_exception.SSHException(
        "Error reading SSH protocol banner"
    )

    def factory(**_kwargs: object) -> Any:
        return transport

    with pytest.raises(
        SshTunnelError, match="Could not reach the router to learn the SSH host key"
    ):
        learn_ssh_host_key("192.168.1.1", transport_factory=factory)
    transport.close.assert_called_once()


def test_learn_ssh_host_key_get_remote_server_key_ssh_exception() -> None:
    """SSHException after handshake → same SshTunnelError translation."""
    import paramiko
    from router_control.adapters.netcraze.ssh_tunnel import learn_ssh_host_key

    transport = MagicMock()
    transport.get_remote_server_key.side_effect = paramiko.ssh_exception.SSHException(
        "No existing session"
    )

    def factory(**_kwargs: object) -> Any:
        return transport

    with pytest.raises(
        SshTunnelError, match="Could not reach the router to learn the SSH host key"
    ):
        learn_ssh_host_key("192.168.1.1", transport_factory=factory)
    transport.close.assert_called_once()


def test_transient_failure_retried_and_succeeds_on_second_attempt() -> None:
    key_bytes = b"pinned-key"
    fingerprint = _fingerprint_for(key_bytes)
    fake_transport = MagicMock()
    fake_transport.get_remote_server_key.return_value = _FakeKey("ssh-ed25519", key_bytes)
    fake_transport.auth_password.return_value = []
    call_count = 0

    def factory(_cfg: SshTunnelConfig) -> MagicMock:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise SshTransientConnectionError("banner reset")
        return fake_transport

    config = _make_config(host_key_sha256=fingerprint)
    tunnel = PinnedSshTunnel(config, _transport_factory=factory)
    with tunnel:
        assert tunnel.local_port > 0
        assert tunnel.host_key_algorithm == "ssh-ed25519"
        assert tunnel.host_key_fingerprint_sha256 == fingerprint
    assert call_count == 2


def test_transient_failure_exhausts_retries_and_raises() -> None:
    call_count = 0

    def factory(_cfg: SshTunnelConfig) -> MagicMock:
        nonlocal call_count
        call_count += 1
        raise SshTransientConnectionError("persistent reset")

    config = _make_config()
    tunnel = PinnedSshTunnel(config, _transport_factory=factory)
    with pytest.raises(SshTransientConnectionError, match="persistent reset"):
        tunnel.open()
    assert call_count == 2


def test_non_transient_host_key_mismatch_not_retried() -> None:
    call_count = 0

    def factory(_cfg: SshTunnelConfig) -> MagicMock:
        nonlocal call_count
        call_count += 1
        raise SshHostKeyMismatch("pin mismatch")

    config = _make_config()
    tunnel = PinnedSshTunnel(config, _transport_factory=factory)
    with pytest.raises(SshHostKeyMismatch, match="pin mismatch"):
        tunnel.open()
    assert call_count == 1


def test_non_transient_auth_failure_not_retried() -> None:
    call_count = 0

    def factory(_cfg: SshTunnelConfig) -> MagicMock:
        nonlocal call_count
        call_count += 1
        raise SshTunnelError("auth failed")

    config = _make_config()
    tunnel = PinnedSshTunnel(config, _transport_factory=factory)
    with pytest.raises(SshTunnelError, match="auth failed"):
        tunnel.open()
    assert call_count == 1


def test_connect_retry_attempts_one_disables_retry() -> None:
    call_count = 0

    def factory(_cfg: SshTunnelConfig) -> MagicMock:
        nonlocal call_count
        call_count += 1
        raise SshTransientConnectionError("banner reset")

    config = _make_config(connect_retry_attempts=1)
    tunnel = PinnedSshTunnel(config, _transport_factory=factory)
    with pytest.raises(SshTransientConnectionError, match="banner reset"):
        tunnel.open()
    assert call_count == 1


def test_connect_transport_wraps_connection_reset_as_transient() -> None:
    config = _make_config(connect_retry_attempts=1)

    with patch(
        "router_control.adapters.netcraze.ssh_tunnel._lazy_import_paramiko",
        return_value=MagicMock(),
    ):
        with patch(
            "router_control.adapters.netcraze.ssh_tunnel.create_bound_tcp_connection",
            side_effect=ConnectionResetError("simulated reset"),
        ):
            tunnel = PinnedSshTunnel(config)
            with pytest.raises(SshTransientConnectionError, match="simulated reset"):
                tunnel.open()


def test_pinned_ssh_transport_transient_failure_retried_and_succeeds() -> None:
    key_bytes = b"pinned-key"
    fingerprint = _fingerprint_for(key_bytes)
    fake_transport = MagicMock()
    fake_transport.get_remote_server_key.return_value = _FakeKey("ssh-ed25519", key_bytes)
    fake_transport.auth_password.return_value = []
    fake_transport.is_active.return_value = True
    call_count = 0

    def factory(_cfg: SshTunnelConfig) -> MagicMock:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise SshTransientConnectionError("banner reset")
        return fake_transport

    config = _make_config(host_key_sha256=fingerprint)
    transport_ctx = PinnedSshTransport(config, _transport_factory=factory)
    with transport_ctx:
        assert transport_ctx.host_key_algorithm == "ssh-ed25519"
        assert transport_ctx.host_key_fingerprint_sha256 == fingerprint
    assert call_count == 2


def test_pinned_ssh_transport_transient_failure_exhausts_retries() -> None:
    call_count = 0

    def factory(_cfg: SshTunnelConfig) -> MagicMock:
        nonlocal call_count
        call_count += 1
        raise SshTransientConnectionError("persistent reset")

    config = _make_config()
    transport_ctx = PinnedSshTransport(config, _transport_factory=factory)
    with pytest.raises(SshTransientConnectionError, match="persistent reset"):
        transport_ctx.open()
    assert call_count == 2


def test_pinned_ssh_transport_host_key_mismatch_not_retried() -> None:
    call_count = 0

    def factory(_cfg: SshTunnelConfig) -> MagicMock:
        nonlocal call_count
        call_count += 1
        raise SshHostKeyMismatch("pin mismatch")

    config = _make_config()
    transport_ctx = PinnedSshTransport(config, _transport_factory=factory)
    with pytest.raises(SshHostKeyMismatch, match="pin mismatch"):
        transport_ctx.open()
    assert call_count == 1


def test_pinned_ssh_transport_auth_failure_not_retried() -> None:
    call_count = 0

    def factory(_cfg: SshTunnelConfig) -> MagicMock:
        nonlocal call_count
        call_count += 1
        raise SshTunnelError("auth failed")

    config = _make_config()
    transport_ctx = PinnedSshTransport(config, _transport_factory=factory)
    with pytest.raises(SshTunnelError, match="auth failed"):
        transport_ctx.open()
    assert call_count == 1


def test_pinned_ssh_transport_connect_retry_attempts_one_disables_retry() -> None:
    call_count = 0

    def factory(_cfg: SshTunnelConfig) -> MagicMock:
        nonlocal call_count
        call_count += 1
        raise SshTransientConnectionError("banner reset")

    config = _make_config(connect_retry_attempts=1)
    transport_ctx = PinnedSshTransport(config, _transport_factory=factory)
    with pytest.raises(SshTransientConnectionError, match="banner reset"):
        transport_ctx.open()
    assert call_count == 1
