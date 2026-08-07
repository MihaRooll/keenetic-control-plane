"""Offline tests for sealed interface/save RCI operator CLIs."""

from __future__ import annotations

import importlib.util
import json
import sys
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest
from router_control.adapters.netcraze.allowlist import body_sha256, build_sealed_parse_body

REPO_ROOT = Path(__file__).resolve().parents[1]
INTERFACE_CLI = REPO_ROOT / "scripts" / "interface-rci-op.py"
SYSTEM_SAVE_CLI = REPO_ROOT / "scripts" / "system-rci-save.py"


def _load_cli(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def interface_cli():
    return _load_cli(INTERFACE_CLI, "interface_rci_op_cli")


@pytest.fixture(scope="module")
def system_save_cli():
    return _load_cli(SYSTEM_SAVE_CLI, "system_rci_save_cli")


def _expected_digest(cli: str) -> str:
    return body_sha256(build_sealed_parse_body(cli))


def _transport_guard():
    return patch(
        "router_control.adapters.netcraze.rci_live.open_pinned_rci_transport",
        side_effect=AssertionError("open_pinned_rci_transport must not be called in validate mode"),
    )


@pytest.mark.parametrize(
    ("operation", "interface_id", "expected_cli"),
    [
        ("up", "GigabitEthernet1", "interface GigabitEthernet1 up"),
        ("down", "Bridge0", "interface Bridge0 down"),
    ],
)
def test_interface_validate_mode_success(
    interface_cli,
    operation: str,
    interface_id: str,
    expected_cli: str,
) -> None:
    argv = [
        "interface-rci-op.py",
        "--operation",
        operation,
        "--interface-id",
        interface_id,
    ]
    stdout = StringIO()
    with _transport_guard(), patch.object(sys, "argv", argv), patch.object(sys, "stdout", stdout):
        assert interface_cli.main() == 0
    plan = json.loads(stdout.getvalue())
    assert plan == {
        "mode": "validate",
        "operation": operation,
        "interface_id": interface_id,
        "cli": expected_cli,
        "body_sha256": _expected_digest(expected_cli),
        "write_allowlisted": True,
        "bytes": len(build_sealed_parse_body(expected_cli)),
    }


def test_system_save_validate_mode_success(system_save_cli) -> None:
    expected_cli = "system configuration save"
    argv = ["system-rci-save.py"]
    stdout = StringIO()
    with _transport_guard(), patch.object(sys, "argv", argv), patch.object(sys, "stdout", stdout):
        assert system_save_cli.main() == 0
    plan = json.loads(stdout.getvalue())
    assert plan == {
        "mode": "validate",
        "operation": "configuration_save",
        "cli": expected_cli,
        "body_sha256": _expected_digest(expected_cli),
        "write_allowlisted": True,
        "bytes": len(build_sealed_parse_body(expected_cli)),
    }


@pytest.mark.parametrize("interface_id", ["Wifi Master0", "a/b"])
def test_interface_invalid_id_fail_closed(interface_cli, interface_id: str) -> None:
    argv = [
        "interface-rci-op.py",
        "--operation",
        "up",
        "--interface-id",
        interface_id,
    ]
    stderr = StringIO()
    with _transport_guard(), patch.object(sys, "argv", argv), patch.object(sys, "stderr", stderr):
        assert interface_cli.main() != 0
    assert "invalid interface id" in stderr.getvalue()


def test_system_save_does_not_expose_reboot(system_save_cli) -> None:
    source = SYSTEM_SAVE_CLI.read_text(encoding="utf-8")
    assert "system_reboot" not in source
    assert "REBOOT" not in source


def test_interface_cli_has_execute_flag(interface_cli) -> None:
    parser = interface_cli._build_parser()
    actions = {action.dest for action in parser._actions if action.dest != "help"}
    assert "execute" in actions
    assert "operation" in actions
    assert "interface_id" in actions


def test_system_save_cli_has_execute_flag(system_save_cli) -> None:
    parser = system_save_cli._build_parser()
    actions = {action.dest for action in parser._actions if action.dest != "help"}
    assert "execute" in actions
    assert "operation" not in actions
