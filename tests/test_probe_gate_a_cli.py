"""Gate A probe CLI guard tests (no network, no DPAPI)."""

from __future__ import annotations

import importlib.util
import socket
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from router_control.adapters.netcraze.identity import OperatorIdentityHints

REPO_ROOT = Path(__file__).resolve().parents[1]
PROBE_SCRIPT = REPO_ROOT / "scripts" / "probe-gate-a.py"


def _load_probe_module():
    spec = importlib.util.spec_from_file_location("probe_gate_a_cli", PROBE_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def probe():
    return _load_probe_module()


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("192.168.1.1", True),
        ("10.0.0.5", True),
        ("172.16.0.1", True),
        ("127.0.0.1", True),
        ("8.8.8.8", False),
        ("1.1.1.1", False),
        ("https://192.168.1.1", True),
    ],
)
def test_host_is_private(probe, host: str, expected: bool) -> None:
    assert probe._host_is_private(host) is expected


def test_host_is_private_public_hostname_resolves_fail_closed(probe) -> None:
    with patch(
        "router_control.adapters.netcraze.ssh_tunnel.socket.getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))],
    ):
        assert probe._host_is_private("example.com") is False


def test_host_is_private_router_local_requires_private_resolve(probe) -> None:
    with patch(
        "router_control.adapters.netcraze.ssh_tunnel.socket.getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.50", 0))],
    ):
        assert probe._host_is_private("router.local") is True
    with patch(
        "router_control.adapters.netcraze.ssh_tunnel.socket.getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0))],
    ):
        assert probe._host_is_private("router.local") is False


def test_refuses_non_private_host_without_flag(probe) -> None:
    argv = [
        "probe-gate-a.py",
        "--host",
        "8.8.8.8",
        "--credential-ref",
        "cred_test",
        "--username",
        "lab-user",
    ]
    with patch.object(sys, "argv", argv):
        assert probe.main() == 2


def test_refuses_plain_http_without_flag(probe) -> None:
    argv = [
        "probe-gate-a.py",
        "--host",
        "http://192.168.1.1:80",
        "--credential-ref",
        "cred_test",
        "--username",
        "lab-user",
    ]
    with patch.object(sys, "argv", argv):
        assert probe.main() == 2


def test_refuses_plain_http_to_non_private_even_with_flag(probe) -> None:
    argv = [
        "probe-gate-a.py",
        "--host",
        "http://8.8.8.8:80",
        "--credential-ref",
        "cred_test",
        "--username",
        "lab-user",
        "--allow-insecure-http",
        "--allow-non-private",
    ]
    with patch.object(sys, "argv", argv):
        assert probe.main() == 2


def test_validate_target_allows_private_http_with_flag(probe) -> None:
    assert (
        probe._validate_target(
            "http://192.168.1.1:80",
            allow_non_private=False,
            allow_insecure_http=True,
        )
        == 0
    )


@pytest.mark.parametrize("token", ["apply", "backup", "mutate", "write"])
def test_refuses_mutation_like_extra_tokens(probe, token: str) -> None:
    argv = [
        "probe-gate-a.py",
        "--host",
        "192.168.1.1",
        "--credential-ref",
        "cred_test",
        "--username",
        "lab-user",
        token,
    ]
    with patch.object(sys, "argv", argv):
        assert probe.main() == 2


def test_refuses_ssh_tunnel_without_host_key_pin(probe) -> None:
    argv = [
        "probe-gate-a.py",
        "--host",
        "192.168.1.1",
        "--credential-ref",
        "cred_test",
        "--username",
        "lab-user",
        "--ssh-tunnel",
    ]
    with patch.object(sys, "argv", argv):
        assert probe.main() == 2


def test_cli_parses_ssh_tunnel_args(probe) -> None:
    argv = [
        "probe-gate-a.py",
        "--host",
        "192.168.1.1",
        "--credential-ref",
        "cred_test",
        "--username",
        "lab-user",
        "--ssh-tunnel",
        "--ssh-host-key-sha256",
        "SHA256:abc123",
    ]
    parsed = probe._build_parser().parse_args(argv[1:])
    assert parsed.ssh_tunnel is True
    assert parsed.ssh_host_key_sha256 == "SHA256:abc123"


def test_cli_parses_identity_hint_args(probe) -> None:
    argv = [
        "probe-gate-a.py",
        "--host",
        "192.168.1.1",
        "--credential-ref",
        "cred_test",
        "--username",
        "lab-user",
        "--expected-model",
        "Netcraze Ultra NC-1812",
        "--update-channel",
        "Main",
    ]
    parsed = probe._build_parser().parse_args(argv[1:])
    assert parsed.expected_model == "Netcraze Ultra NC-1812"
    assert parsed.update_channel == "Main"


def test_main_wires_cli_hints_to_adapter(probe, tmp_path: Path) -> None:
    captured: dict[str, object] = {}
    artifact_path = tmp_path / "gate-a-probe-evidence.json"

    class FakeAdapter:
        def __init__(self, *, router_id, transport, clock, identity_hints=None) -> None:
            captured["router_id"] = router_id
            captured["identity_hints"] = identity_hints

        def probe_gate_a_evidence(self) -> dict[str, object]:
            return {
                "model": "Netcraze Ultra NC-1812",
                "firmware_version": "5.01.C.1.0-0",
                "firmware_display_title": "5.1.1",
                "component_set_digest": "sha256:abc",
                "device_fingerprint": "sha256:def",
                "evidence_recorded_at": "2026-07-21T12:00:00+00:00",
                "identity_shape": "observed",
                "identity_complete": False,
                "fingerprint_status": "provisional",
                "model_source": "operator_ui_hint",
                "update_channel_source": "operator_ui_hint",
                "build_source": "unknown",
                "physical_identifier_source": "missing",
                "gate_a_certification_eligible": False,
                "certification_eligible": False,
            }

    argv = [
        "probe-gate-a.py",
        "--host",
        "192.168.1.1",
        "--credential-ref",
        "cred_test",
        "--username",
        "lab-user",
        "--expected-model",
        "Netcraze Ultra NC-1812",
        "--update-channel",
        "Main",
        "--artifact-out",
        str(artifact_path),
    ]

    fake_vault = MagicMock()
    fake_vault.use.return_value = "lab-password"

    with patch.object(sys, "platform", "win32"):
        with patch(
            "router_control.adapters.secrets.dpapi.WindowsDpapiVault",
            return_value=fake_vault,
        ):
            with patch(
                "router_control.adapters.netcraze.transport.NetcrazeTransport",
            ):
                with patch(
                    "router_control.adapters.netcraze.adapter.NetcrazeReadOnlyAdapter",
                    FakeAdapter,
                ):
                    with patch.object(sys, "argv", argv):
                        assert probe.main() == 0

    hints = captured["identity_hints"]
    assert isinstance(hints, OperatorIdentityHints)
    assert hints.expected_model == "Netcraze Ultra NC-1812"
    assert hints.update_channel == "Main"
    fake_vault.use.assert_called_once_with("cred_test")
    assert artifact_path.is_file()
    assert "Netcraze Ultra NC-1812" in artifact_path.read_text(encoding="utf-8")


def test_main_wires_ssh_tunnel_management_host_from_router_target(probe, tmp_path: Path) -> None:
    captured: dict[str, object] = {}
    artifact_path = tmp_path / "gate-a-probe-ssh-evidence.json"

    class FakeTunnel:
        local_host = "127.0.0.1"
        local_port = 54321
        host_key_algorithm = "ssh-ed25519"
        host_key_fingerprint_sha256 = "SHA256:abc123"

        def __init__(self, config) -> None:
            self.config = config

        def __enter__(self) -> FakeTunnel:
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            return None

    class FakeAdapter:
        def __init__(self, *, router_id, transport, clock, identity_hints=None) -> None:
            captured["transport"] = transport

        def probe_gate_a_evidence(self) -> dict[str, object]:
            return {
                "model": "NC-1812",
                "firmware_version": "5.01.C.1.0-0",
                "firmware_display_title": "5.1.1",
                "component_set_digest": "sha256:abc",
                "device_fingerprint": "sha256:def",
                "evidence_recorded_at": "2026-07-21T12:00:00+00:00",
                "identity_shape": "observed",
                "identity_complete": False,
                "fingerprint_status": "provisional",
                "model_source": "unknown",
                "update_channel_source": "unknown",
                "build_source": "unknown",
                "physical_identifier_source": "missing",
                "gate_a_certification_eligible": True,
                "certification_eligible": True,
            }

    argv = [
        "probe-gate-a.py",
        "--host",
        "192.168.1.1",
        "--credential-ref",
        "cred_test",
        "--username",
        "lab-user",
        "--ssh-tunnel",
        "--ssh-host-key-sha256",
        "SHA256:abc123",
        "--artifact-out",
        str(artifact_path),
    ]

    fake_vault = MagicMock()
    fake_vault.use.return_value = "lab-password"

    with patch.object(sys, "platform", "win32"):
        with patch(
            "router_control.adapters.secrets.dpapi.WindowsDpapiVault",
            return_value=fake_vault,
        ):
            with patch(
                "router_control.adapters.netcraze.ssh_tunnel.PinnedSshTunnel",
                FakeTunnel,
            ):
                with patch(
                    "router_control.adapters.netcraze.adapter.NetcrazeReadOnlyAdapter",
                    FakeAdapter,
                ):
                    with patch.object(sys, "argv", argv):
                        assert probe.main() == 0

    transport = captured["transport"]
    assert transport.host == "127.0.0.1"
    assert transport.port == 54321
    assert transport.management_host_header == "192.168.1.1"
    assert transport.use_tls is False
    assert artifact_path.is_file()


@pytest.mark.parametrize(
    "host",
    [
        "host:abc",
        "http://192.168.1.1%0d%0aInjected/",
        "[fe80::1]:8080",
    ],
)
def test_ssh_tunnel_malformed_host_exits_before_vault(probe, host: str) -> None:
    argv = [
        "probe-gate-a.py",
        "--host",
        host,
        "--credential-ref",
        "cred_test",
        "--username",
        "lab-user",
        "--ssh-tunnel",
        "--ssh-host-key-sha256",
        "SHA256:abc123",
    ]

    fake_vault = MagicMock()
    tunnel_ctor = MagicMock()

    with patch.object(sys, "platform", "win32"):
        with patch(
            "router_control.adapters.secrets.dpapi.WindowsDpapiVault",
            return_value=fake_vault,
        ):
            with patch(
                "router_control.adapters.netcraze.ssh_tunnel.PinnedSshTunnel",
                tunnel_ctor,
            ):
                with patch.object(sys, "argv", argv):
                    assert probe.main() == 2

    fake_vault.use.assert_not_called()
    tunnel_ctor.assert_not_called()


def test_cli_parses_source_address_arg(probe) -> None:
    argv = [
        "probe-gate-a.py",
        "--host",
        "192.168.1.1",
        "--credential-ref",
        "cred_test",
        "--username",
        "lab-user",
        "--source-address",
        "192.168.1.144",
    ]
    parsed = probe._build_parser().parse_args(argv[1:])
    assert parsed.source_address == "192.168.1.144"


def test_source_address_without_ssh_tunnel_exits_before_vault(probe) -> None:
    argv = [
        "probe-gate-a.py",
        "--host",
        "192.168.1.1",
        "--credential-ref",
        "cred_test",
        "--username",
        "lab-user",
        "--source-address",
        "192.168.1.144",
    ]

    fake_vault = MagicMock()

    with patch.object(sys, "platform", "win32"):
        with patch(
            "router_control.adapters.secrets.dpapi.WindowsDpapiVault",
            return_value=fake_vault,
        ):
            with patch.object(sys, "argv", argv):
                assert probe.main() == 2

    fake_vault.use.assert_not_called()


def test_source_address_bind_preflight_runs_before_vault(probe, tmp_path: Path) -> None:
    call_order: list[str] = []
    artifact_path = tmp_path / "gate-a-probe-source-bind.json"

    class FakeTunnel:
        local_host = "127.0.0.1"
        local_port = 54321
        host_key_algorithm = "ssh-ed25519"
        host_key_fingerprint_sha256 = "SHA256:abc123"

        def __init__(self, config) -> None:
            call_order.append("tunnel")

        def __enter__(self) -> FakeTunnel:
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            return None

    class FakeAdapter:
        def __init__(self, *, router_id, transport, clock, identity_hints=None) -> None:
            call_order.append("adapter")

        def probe_gate_a_evidence(self) -> dict[str, object]:
            return {
                "model": "NC-1812",
                "firmware_version": "5.01.C.1.0-0",
                "firmware_display_title": "5.1.1",
                "component_set_digest": "sha256:abc",
                "device_fingerprint": "sha256:def",
                "evidence_recorded_at": "2026-07-21T12:00:00+00:00",
                "identity_shape": "observed",
                "identity_complete": False,
                "fingerprint_status": "provisional",
                "model_source": "unknown",
                "update_channel_source": "unknown",
                "build_source": "unknown",
                "physical_identifier_source": "missing",
                "gate_a_certification_eligible": True,
                "certification_eligible": True,
            }

    fake_vault = MagicMock()

    def vault_use(ref: str) -> str:
        call_order.append("vault")
        return "lab-password"

    fake_vault.use.side_effect = vault_use

    def fake_preflight(source_address: str, **kwargs: object) -> str:
        call_order.append("preflight")
        return source_address

    argv = [
        "probe-gate-a.py",
        "--host",
        "192.168.1.1",
        "--credential-ref",
        "cred_test",
        "--username",
        "lab-user",
        "--ssh-tunnel",
        "--ssh-host-key-sha256",
        "SHA256:abc123",
        "--source-address",
        "192.168.1.144",
        "--artifact-out",
        str(artifact_path),
    ]

    with patch.object(sys, "platform", "win32"):
        with patch(
            "router_control.adapters.secrets.dpapi.WindowsDpapiVault",
            return_value=fake_vault,
        ):
            with patch(
                "router_control.adapters.netcraze.ssh_tunnel.preflight_source_address_bind",
                fake_preflight,
            ):
                with patch(
                    "router_control.adapters.netcraze.ssh_tunnel.PinnedSshTunnel",
                    FakeTunnel,
                ):
                    with patch(
                        "router_control.adapters.netcraze.adapter.NetcrazeReadOnlyAdapter",
                        FakeAdapter,
                    ):
                        with patch.object(sys, "argv", argv):
                            assert probe.main() == 0

    assert call_order.index("preflight") < call_order.index("vault")
    payload = artifact_path.read_text(encoding="utf-8")
    assert '"source_address": "192.168.1.144"' in payload


def test_ssh_tunnel_transport_receives_source_address(probe, tmp_path: Path) -> None:
    captured: dict[str, str] = {}
    artifact_path = tmp_path / "gate-a-probe-transport-source.json"

    class FakeTunnel:
        local_host = "127.0.0.1"
        local_port = 54321
        host_key_algorithm = "ssh-ed25519"
        host_key_fingerprint_sha256 = "SHA256:abc123"

        def __init__(self, config) -> None:
            self.config = config

        def __enter__(self) -> FakeTunnel:
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            return None

    class FakeAdapter:
        def __init__(self, *, router_id, transport, clock, identity_hints=None) -> None:
            captured["source_address"] = transport.source_address

        def probe_gate_a_evidence(self) -> dict[str, object]:
            return {
                "model": "NC-1812",
                "firmware_version": "5.01.C.1.0-0",
                "firmware_display_title": "5.1.1",
                "component_set_digest": "sha256:abc",
                "device_fingerprint": "sha256:def",
                "evidence_recorded_at": "2026-07-21T12:00:00+00:00",
                "identity_shape": "observed",
                "identity_complete": False,
                "fingerprint_status": "provisional",
                "model_source": "unknown",
                "update_channel_source": "unknown",
                "build_source": "unknown",
                "physical_identifier_source": "missing",
                "gate_a_certification_eligible": True,
                "certification_eligible": True,
            }

    fake_vault = MagicMock()
    fake_vault.use.return_value = "lab-password"

    argv = [
        "probe-gate-a.py",
        "--host",
        "192.168.1.1",
        "--credential-ref",
        "cred_test",
        "--username",
        "lab-user",
        "--ssh-tunnel",
        "--ssh-host-key-sha256",
        "SHA256:abc123",
        "--source-address",
        "192.168.1.144",
        "--artifact-out",
        str(artifact_path),
    ]

    with patch.object(sys, "platform", "win32"):
        with patch(
            "router_control.adapters.secrets.dpapi.WindowsDpapiVault",
            return_value=fake_vault,
        ):
            with patch(
                "router_control.adapters.netcraze.ssh_tunnel.preflight_source_address_bind",
                side_effect=lambda value, **_: value,
            ):
                with patch(
                    "router_control.adapters.netcraze.ssh_tunnel.PinnedSshTunnel",
                    FakeTunnel,
                ):
                    with patch(
                        "router_control.adapters.netcraze.adapter.NetcrazeReadOnlyAdapter",
                        FakeAdapter,
                    ):
                        with patch.object(sys, "argv", argv):
                            assert probe.main() == 0

    assert captured["source_address"] == "192.168.1.144"


def test_ssh_tunnel_preflight_runs_before_vault_on_success(probe, tmp_path: Path) -> None:
    call_order: list[str] = []
    artifact_path = tmp_path / "gate-a-probe-order.json"

    class FakeTunnel:
        local_host = "127.0.0.1"
        local_port = 54321
        host_key_algorithm = "ssh-ed25519"
        host_key_fingerprint_sha256 = "SHA256:abc123"

        def __init__(self, config) -> None:
            call_order.append("tunnel")

        def __enter__(self) -> FakeTunnel:
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            return None

    class FakeAdapter:
        def __init__(self, *, router_id, transport, clock, identity_hints=None) -> None:
            call_order.append("adapter")

        def probe_gate_a_evidence(self) -> dict[str, object]:
            return {
                "model": "NC-1812",
                "firmware_version": "5.01.C.1.0-0",
                "firmware_display_title": "5.1.1",
                "component_set_digest": "sha256:abc",
                "device_fingerprint": "sha256:def",
                "evidence_recorded_at": "2026-07-21T12:00:00+00:00",
                "identity_shape": "observed",
                "identity_complete": False,
                "fingerprint_status": "provisional",
                "model_source": "unknown",
                "update_channel_source": "unknown",
                "build_source": "unknown",
                "physical_identifier_source": "missing",
                "gate_a_certification_eligible": True,
                "certification_eligible": True,
            }

    fake_vault = MagicMock()

    def vault_use(ref: str) -> str:
        call_order.append("vault")
        return "lab-password"

    fake_vault.use.side_effect = vault_use

    argv = [
        "probe-gate-a.py",
        "--host",
        "192.168.1.1",
        "--credential-ref",
        "cred_test",
        "--username",
        "lab-user",
        "--ssh-tunnel",
        "--ssh-host-key-sha256",
        "SHA256:abc123",
        "--artifact-out",
        str(artifact_path),
    ]

    with patch.object(sys, "platform", "win32"):
        with patch(
            "router_control.adapters.secrets.dpapi.WindowsDpapiVault",
            return_value=fake_vault,
        ):
            with patch(
                "router_control.adapters.netcraze.ssh_tunnel.PinnedSshTunnel",
                FakeTunnel,
            ):
                with patch(
                    "router_control.adapters.netcraze.adapter.NetcrazeReadOnlyAdapter",
                    FakeAdapter,
                ):
                    with patch.object(sys, "argv", argv):
                        assert probe.main() == 0

    assert call_order.index("vault") < call_order.index("tunnel")
    assert call_order.index("tunnel") < call_order.index("adapter")


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1",
        "127.0.0.1.",
        "[::1]",
        "::1",
        "::ffff:127.0.0.1",
        "localhost",
        "127.1",
        "127.0.1",
        "0177.0.0.1",
        "127.00.0.1",
        "2130706433",
        "0177.1",
        "0x7f.1",
    ],
)
def test_ssh_tunnel_loopback_management_host_exits_before_vault(probe, host: str) -> None:
    argv = [
        "probe-gate-a.py",
        "--host",
        host,
        "--credential-ref",
        "cred_test",
        "--username",
        "lab-user",
        "--ssh-tunnel",
        "--ssh-host-key-sha256",
        "SHA256:abc123",
    ]

    fake_vault = MagicMock()
    tunnel_ctor = MagicMock()

    with patch.object(sys, "platform", "win32"):
        with patch(
            "router_control.adapters.secrets.dpapi.WindowsDpapiVault",
            return_value=fake_vault,
        ):
            with patch(
                "router_control.adapters.netcraze.ssh_tunnel.PinnedSshTunnel",
                tunnel_ctor,
            ):
                with patch.object(sys, "argv", argv):
                    assert probe.main() == 2

    fake_vault.use.assert_not_called()
    tunnel_ctor.assert_not_called()


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1",
        "127.0.0.1.",
        "[::1]",
        "::1",
        "::ffff:127.0.0.1",
        "localhost",
        "127.1",
        "127.0.1",
        "0177.0.0.1",
        "127.00.0.1",
        "2130706433",
        "0177.1",
        "0x7f.1",
    ],
)
def test_ssh_tunnel_loopback_management_host_exits_before_vault_allow_non_private(
    probe, host: str
) -> None:
    argv = [
        "probe-gate-a.py",
        "--host",
        host,
        "--credential-ref",
        "cred_test",
        "--username",
        "lab-user",
        "--ssh-tunnel",
        "--ssh-host-key-sha256",
        "SHA256:abc123",
        "--allow-non-private",
    ]

    fake_vault = MagicMock()
    tunnel_ctor = MagicMock()

    with patch.object(sys, "platform", "win32"):
        with patch(
            "router_control.adapters.secrets.dpapi.WindowsDpapiVault",
            return_value=fake_vault,
        ):
            with patch(
                "router_control.adapters.netcraze.ssh_tunnel.PinnedSshTunnel",
                tunnel_ctor,
            ):
                with patch.object(sys, "argv", argv):
                    assert probe.main() == 2

    fake_vault.use.assert_not_called()
    tunnel_ctor.assert_not_called()


def test_ssh_tunnel_preflight_accepts_canonical_private_ipv4_without_network(probe) -> None:
    assert probe._validate_ssh_tunnel_preflight(
        "192.168.1.1",
        allow_non_private=False,
    ) == (0, "192.168.1.1", "192.168.1.1")
