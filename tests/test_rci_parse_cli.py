"""Offline tests for scripts/rci-parse.py transport wiring."""

from __future__ import annotations

import importlib.util
import sys
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parents[1]
RCI_PARSE_CLI = REPO_ROOT / "scripts" / "rci-parse.py"

_GATE_A_STYLE_PIN = "SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM"
_LAB_SOURCE = "192.168.1.144"


def _load_cli():
    spec = importlib.util.spec_from_file_location("rci_parse_cli", RCI_PARSE_CLI)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_rci_parse_propagates_source_address_to_transport() -> None:
    cli = _load_cli()
    captured: dict[str, str] = {}

    class FakeTunnel:
        local_host = "127.0.0.1"
        local_port = 54321
        host_key_algorithm = "ssh-ed25519"
        host_key_fingerprint_sha256 = _GATE_A_STYLE_PIN

        def __init__(self, config) -> None:
            self.config = config

        def __enter__(self) -> FakeTunnel:
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            return None

    class FakeTransport:
        def __init__(self, **kwargs: object) -> None:
            captured["source_address"] = str(kwargs.get("source_address", ""))

        def execute_rci_parse(self, command: str) -> dict[str, object]:
            return {"parse": {"status": [{"status": "ok"}]}}

    argv = [
        "rci-parse.py",
        "--host",
        "192.168.1.1",
        "--credential-ref",
        "cred_test",
        "--username",
        "lab-user",
        "--ssh-host-key-sha256",
        _GATE_A_STYLE_PIN,
        "--source-address",
        _LAB_SOURCE,
        "--command",
        "show version",
    ]
    stdout = StringIO()
    fake_vault = MagicMock()
    fake_vault.use.return_value = "lab-password"

    with patch.object(sys, "platform", "win32"), patch.object(sys, "argv", argv), patch.object(
        sys, "stdout", stdout
    ), patch(
        "router_control.adapters.secrets.dpapi.WindowsDpapiVault",
        return_value=fake_vault,
    ), patch(
        "router_control.adapters.netcraze.ssh_tunnel.preflight_source_address_bind",
        side_effect=lambda value, **_: value,
    ), patch(
        "router_control.adapters.netcraze.ssh_tunnel.PinnedSshTunnel",
        FakeTunnel,
    ), patch(
        "router_control.adapters.netcraze.transport.SshTunnelNetcrazeTransport",
        FakeTransport,
    ):
        assert cli.main() == 0

    assert captured["source_address"] == _LAB_SOURCE
