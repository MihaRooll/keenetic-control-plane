"""Offline tests for probe-nc1812-awg-shape CLI."""

from __future__ import annotations

import importlib.util
import json
import sys
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
CLI_SCRIPT = REPO_ROOT / "scripts" / "probe-nc1812-awg-shape.py"

SYNTH_PASSWORD = "SENTINEL-PASSWORD-ORACLE"
SYNTH_PRIVATE_KEY = "SENTINEL-PRIVATE-KEY-ORACLE"
SYNTH_PRESHARED = "SENTINEL-PRESHARED-ORACLE"
GATE_A_PIN = "SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM"


def _load_module():
    spec = importlib.util.spec_from_file_location("probe_nc1812_awg_shape_cli", CLI_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def cli_module():
    return _load_module()


def _transport_guard():
    return patch(
        "router_control.adapters.netcraze.rci_live.open_pinned_rci_transport",
        side_effect=AssertionError("open_pinned_rci_transport must not be called in validate mode"),
    )


def test_validate_default_exits_zero_and_prints_plan(cli_module) -> None:
    stdout = StringIO()
    argv = ["probe-nc1812-awg-shape.py"]
    with _transport_guard(), patch.object(sys, "argv", argv), patch.object(sys, "stdout", stdout):
        assert cli_module.main() == 0
    plan = json.loads(stdout.getvalue())
    assert plan["mode"] == "validate"
    assert plan["mutation_allowed"] is False
    assert plan["write_shapes_registered"] is False
    assert plan["certification_eligible"] is False
    assert plan["gate_a_tuple"]["model"] == "NC-1812"
    assert plan["gate_a_tuple"]["firmware_version"] == "5.01.C.1.0-0"
    assert plan["gate_a_tuple"]["transport"] == "ssh_tunnel"
    assert plan["gate_a_tuple"]["ssh_host_key_fingerprint_sha256"] == GATE_A_PIN
    assert plan["source_address"] == "192.168.2.10"
    commands = plan["commands_planned"]
    assert len(commands) == 5
    parse_commands = [entry["command"] for entry in commands if entry["kind"] == "parse"]
    assert parse_commands == [
        "help interface",
        "help wireguard",
        "help AmneziaWG",
        "show interface",
    ]
    discovery = [entry for entry in commands if entry["kind"] == "discovery_read"]
    assert len(discovery) == 1
    assert discovery[0]["path"] == "/rci/show/interface"
    assert SYNTH_PASSWORD not in stdout.getvalue()


def test_is_ro_parse_command_enforces_show_help_only(cli_module) -> None:
    assert cli_module.is_ro_parse_command("show interface") is True
    assert cli_module.is_ro_parse_command("help wireguard") is True
    assert cli_module.is_ro_parse_command("interface Bridge0 up") is False
    assert cli_module.is_ro_parse_command("system configuration save") is False
    for entry in cli_module.build_planned_commands():
        if entry["kind"] == "parse":
            assert cli_module.is_ro_parse_command(entry["command"])


def test_sanitize_discovery_response_redacts_secrets(cli_module) -> None:
    payload = {
        "interface": {
            "Wireguard0": {
                "PrivateKey": SYNTH_PRIVATE_KEY,
                "PresharedKey": SYNTH_PRESHARED,
                "password": SYNTH_PASSWORD,
            }
        }
    }
    sanitized = cli_module.sanitize_discovery_response(payload)
    blob = json.dumps(sanitized)
    assert SYNTH_PRIVATE_KEY not in blob
    assert SYNTH_PRESHARED not in blob
    assert SYNTH_PASSWORD not in blob
    assert "REDACTED" in blob


def test_sanitize_discovery_response_list_preserves_help_content(cli_module) -> None:
    payload = [
        {"message": "help interface syntax", "kind": "help"},
        {"PrivateKey": SYNTH_PRIVATE_KEY, "name": "Wireguard0"},
        "plain help line",
    ]
    sanitized = cli_module.sanitize_discovery_response(payload)
    blob = json.dumps(sanitized)
    assert sanitized["sanitized"][0]["message"] == "help interface syntax"
    assert sanitized["sanitized"][2] == "plain help line"
    assert "help interface syntax" in blob
    assert "plain help line" in blob
    assert SYNTH_PRIVATE_KEY not in blob
    assert sanitized["sanitized"][1]["PrivateKey"] == "REDACTED"
    assert sanitized["structure"]["top_type"] == "array"
    assert sanitized["structure"]["top_count"] == 3


def test_build_live_artifact_schema_includes_tuple_binding(cli_module) -> None:
    artifact = cli_module.build_live_artifact(
        host="192.168.2.1",
        source_address="192.168.2.10",
        credential_ref="cred_db65665dd59f600bdd23544d85564c83",
        ssh_pin=GATE_A_PIN,
        commands_issued=cli_module.build_planned_commands(),
        responses=[],
    )
    assert artifact["host"] == "192.168.2.1"
    assert artifact["source_address"] == "192.168.2.10"
    assert artifact["credential_ref"] == "cred_db65665dd59f600bdd23544d85564c83"
    assert artifact["mutation_performed"] is False
    assert artifact["mutation_allowed"] is False
    assert artifact["write_shapes_registered"] is False
    assert artifact["certification_eligible"] is False
    assert artifact["gate_a_tuple"]["model"] == "NC-1812"
    assert artifact["gate_a_tuple"]["firmware_version"] == "5.01.C.1.0-0"
    assert artifact["gate_a_tuple"]["transport"] == "ssh_tunnel"
    assert artifact["gate_a_tuple"]["ssh_host_key_fingerprint_sha256"] == GATE_A_PIN
    assert artifact["commands_issued"]
    assert "responses" in artifact


def test_live_probe_missing_args_returns_two(cli_module) -> None:
    argv = ["probe-nc1812-awg-shape.py", "--live-probe"]
    stderr = StringIO()
    with patch.object(sys, "argv", argv), patch.object(sys, "stderr", stderr):
        assert cli_module.main() == 2
    assert "--host" in stderr.getvalue()


def test_live_probe_refuses_wrong_source(cli_module) -> None:
    argv = [
        "probe-nc1812-awg-shape.py",
        "--live-probe",
        "--host",
        "192.168.2.1",
        "--credential-ref",
        "cred_oracle",
        "--username",
        "admin",
        "--ssh-host-key-sha256",
        GATE_A_PIN,
        "--source-address",
        "192.168.1.144",
    ]
    stderr = StringIO()
    with patch.object(sys, "argv", argv), patch.object(sys, "stderr", stderr):
        assert cli_module.main() == 2
    assert "192.168.2.10" in stderr.getvalue()


def test_refuses_password_env(cli_module, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWG_PASSWORD", SYNTH_PASSWORD)
    argv = ["probe-nc1812-awg-shape.py"]
    stderr = StringIO()
    with _transport_guard(), patch.object(sys, "argv", argv), patch.object(sys, "stderr", stderr):
        assert cli_module.main() == 2
    assert "Refusing password environment variable" in stderr.getvalue()


def test_refuses_mutation_extra_token(cli_module) -> None:
    argv = ["probe-nc1812-awg-shape.py", "save"]
    stderr = StringIO()
    with _transport_guard(), patch.object(sys, "argv", argv), patch.object(sys, "stderr", stderr):
        assert cli_module.main() == 2
    assert "Refusing mutation-like command" in stderr.getvalue()


def test_cli_has_no_execute_or_raw_command_args(cli_module) -> None:
    parser = cli_module._build_parser()
    actions = {action.dest for action in parser._actions if action.dest != "help"}
    forbidden = {"execute", "operation", "raw", "command", "rci_path"}
    assert forbidden.isdisjoint(actions)
    assert "live_probe" in actions


def test_live_probe_mocked_writes_sanitized_artifact(cli_module, tmp_path: Path) -> None:
    secret_payload = {
        "interface": {
            "AmneziaWG0": {
                "PrivateKey": SYNTH_PRIVATE_KEY,
                "PresharedKey": SYNTH_PRESHARED,
                "password": SYNTH_PASSWORD,
            }
        }
    }
    list_help_response = [
        {"message": "help interface syntax", "kind": "help"},
        {"PrivateKey": SYNTH_PRIVATE_KEY, "topic": "wireguard"},
    ]
    transport = MagicMock()
    transport.execute_rci_parse.side_effect = [
        list_help_response,
        {"parse": {"status": [{"status": "ok"}]}},
        {"parse": {"status": [{"status": "ok"}]}},
        {"parse": {"status": [{"status": "ok"}]}},
    ]

    def fetch_with_source_address_check(*_args, **_kwargs):
        assert transport.source_address == "192.168.2.10"
        return secret_payload

    transport.fetch_discovery_read.side_effect = fetch_with_source_address_check

    out = tmp_path / "awg-artifact.json"
    argv = [
        "probe-nc1812-awg-shape.py",
        "--live-probe",
        "--host",
        "192.168.2.1",
        "--credential-ref",
        "cred_db65665dd59f600bdd23544d85564c83",
        "--username",
        "admin",
        "--ssh-host-key-sha256",
        GATE_A_PIN,
        "--source-address",
        "192.168.2.10",
        "--artifact-out",
        str(out),
    ]
    with patch.object(sys, "argv", argv), patch.object(sys, "platform", "win32"), patch(
        "router_control.adapters.secrets.dpapi.WindowsDpapiVault"
    ) as mock_vault, patch(
        "router_control.adapters.netcraze.rci_live.open_pinned_rci_transport"
    ) as mock_transport_ctx, patch(
        "router_control.adapters.netcraze.ssh_tunnel.preflight_source_address_bind",
    ):
        mock_vault.return_value.use.return_value = "vault-password-not-logged"
        transport.source_address = "192.168.2.10"
        mock_transport_ctx.return_value.__enter__.return_value = transport
        assert cli_module.main() == 0

    blob = out.read_text(encoding="utf-8")
    artifact = json.loads(blob)
    assert artifact["mutation_performed"] is False
    assert SYNTH_PRIVATE_KEY not in blob
    assert SYNTH_PRESHARED not in blob
    assert SYNTH_PASSWORD not in blob
    assert artifact["gate_a_tuple"]["ssh_host_key_fingerprint_sha256"] == GATE_A_PIN
    assert transport.execute_rci_parse.call_count == 4
    transport.fetch_discovery_read.assert_called_once()
    parse_responses = [entry for entry in artifact["responses"] if entry["kind"] == "parse"]
    first_list = parse_responses[0]["response"]
    assert first_list["sanitized"][0]["message"] == "help interface syntax"
    assert first_list["sanitized"][1]["PrivateKey"] == "REDACTED"
    assert first_list["structure"]["top_type"] == "array"
