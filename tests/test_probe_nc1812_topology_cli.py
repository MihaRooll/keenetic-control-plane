"""Offline tests for probe-nc1812-topology CLI."""

from __future__ import annotations

import importlib.util
import json
import sys
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
CLI_SCRIPT = REPO_ROOT / "scripts" / "probe-nc1812-topology.py"
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "netcraze"

SYNTH_PASSWORD = "SENTINEL-PASSWORD-ORACLE"


def _load_module():
    spec = importlib.util.spec_from_file_location("probe_nc1812_topology_cli", CLI_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def cli_module():
    return _load_module()


def test_fixture_dry_run_writes_artifact(cli_module, tmp_path: Path) -> None:
    out = tmp_path / "topology-artifact.json"
    argv = [
        "probe-nc1812-topology.py",
        "--fixture",
        "topology_interface_wan_isolated.json",
        "--artifact-out",
        str(out),
        "--source-address",
        "192.168.1.144",
    ]
    with patch.object(sys, "argv", argv):
        assert cli_module.main() == 0
    artifact = json.loads(out.read_text(encoding="utf-8"))
    assert artifact["certification_eligible"] is False
    assert artifact["findings"]["classification"] == "proven_wan_isolated"
    assert SYNTH_PASSWORD not in out.read_text(encoding="utf-8")


def test_live_requires_source_address_before_vault(cli_module) -> None:
    argv = [
        "probe-nc1812-topology.py",
        "--host",
        "192.168.1.1",
        "--credential-ref",
        "cred_oracle",
        "--username",
        "lab-user",
        "--ssh-host-key-sha256",
        "SHA256:oraclepin",
        "--artifact-out",
        "data/artifacts/topology.json",
    ]
    stderr = StringIO()
    with patch.object(sys, "argv", argv), patch.object(sys, "stderr", stderr):
        assert cli_module.main() == 2
    assert "--source-address" in stderr.getvalue()


def test_live_rejects_plain_http_without_ssh(cli_module, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    argv = [
        "probe-nc1812-topology.py",
        "--host",
        "https://192.168.1.1",
        "--credential-ref",
        "cred_oracle",
        "--username",
        "lab-user",
        "--ssh-host-key-sha256",
        "SHA256:oraclepin",
        "--source-address",
        "192.168.1.144",
        "--artifact-out",
        "data/artifacts/topology.json",
    ]
    stderr = StringIO()
    with patch.object(sys, "argv", argv), patch.object(sys, "stderr", stderr), patch(
        "router_control.adapters.secrets.dpapi.WindowsDpapiVault",
        side_effect=AssertionError("vault must not be called without SSH preflight"),
    ):
        assert cli_module.main() != 0


def test_cli_has_no_raw_operation_args(cli_module) -> None:
    parser = cli_module._build_parser()
    actions = {action.dest for action in parser._actions if action.dest != "help"}
    forbidden = {"operation", "raw", "command", "path", "rci_path"}
    assert forbidden.isdisjoint(actions)


def test_fixture_missing_file_returns_nonzero(cli_module, tmp_path: Path) -> None:
    argv = [
        "probe-nc1812-topology.py",
        "--fixture",
        "missing_topology.json",
        "--artifact-out",
        str(tmp_path / "out.json"),
    ]
    with patch.object(sys, "argv", argv):
        assert cli_module.main() == 3


def test_fixture_shape_out_writes_structural_fingerprint(
    cli_module, tmp_path: Path, monkeypatch
) -> None:
    fixtures_dir = tmp_path / "fixtures"
    fixtures_dir.mkdir()
    failing = {
        "interface": {
            "SENTINEL-IFACE-ID-ORACLE": {
                "type": "ISP",
                "role": "wan",
                "address": ["203.0.113.50/24"],
                "password": "SENTINEL-PASSWORD-ORACLE",
            }
        }
    }
    (fixtures_dir / "topology_map_keyed_fail.json").write_text(
        json.dumps(failing),
        encoding="utf-8",
    )
    monkeypatch.setattr(cli_module, "FIXTURES_DIR", fixtures_dir)
    artifact_out = tmp_path / "artifact.json"
    shape_out = tmp_path / "shape.json"
    argv = [
        "probe-nc1812-topology.py",
        "--fixture",
        "topology_map_keyed_fail.json",
        "--artifact-out",
        str(artifact_out),
        "--shape-out",
        str(shape_out),
        "--source-address",
        "192.168.1.144",
    ]
    stderr = StringIO()
    with patch.object(sys, "argv", argv), patch.object(sys, "stderr", stderr):
        assert cli_module.main() == 4
    assert not artifact_out.exists()
    shape_blob = shape_out.read_text(encoding="utf-8")
    shape = json.loads(shape_blob)
    assert shape["certification_eligible"] is False
    assert shape["operation_path"] == "/rci/show/interface"
    assert shape["source_address"] == "192.168.1.144"
    assert shape["structure"]["top_type"] == "object"
    assert "SENTINEL-PASSWORD-ORACLE" not in shape_blob
    assert "SENTINEL-IFACE-ID-ORACLE" not in shape_blob
    assert "203.0.113.50" not in shape_blob
    assert "{" not in stderr.getvalue()


def test_fixture_keyed_v2_wan_isolated_writes_artifact(cli_module, tmp_path: Path) -> None:
    out = tmp_path / "topology-keyed-artifact.json"
    argv = [
        "probe-nc1812-topology.py",
        "--fixture",
        "topology_observed_keyed_wan_isolated.json",
        "--artifact-out",
        str(out),
        "--source-address",
        "192.168.1.144",
    ]
    with patch.object(sys, "argv", argv):
        assert cli_module.main() == 0
    artifact = json.loads(out.read_text(encoding="utf-8"))
    assert artifact["certification_eligible"] is False
    assert artifact["parser_version"] == "topology-interface-v2.3"
    assert artifact["findings"]["classification"] == "proven_wan_isolated"
    blob = out.read_text(encoding="utf-8")
    assert "upstream-wan-001" not in blob
    assert SYNTH_PASSWORD not in blob


def test_fixture_without_shape_out_on_parse_failure_unchanged(
    cli_module, tmp_path: Path, monkeypatch
) -> None:
    fixtures_dir = tmp_path / "fixtures"
    fixtures_dir.mkdir()
    (fixtures_dir / "topology_map_keyed_fail.json").write_text(
        json.dumps({"interface": {"bad": {"type": "ISP"}}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(cli_module, "FIXTURES_DIR", fixtures_dir)
    shape_out = tmp_path / "shape.json"
    argv = [
        "probe-nc1812-topology.py",
        "--fixture",
        "topology_map_keyed_fail.json",
        "--artifact-out",
        str(tmp_path / "artifact.json"),
        "--source-address",
        "192.168.1.144",
    ]
    with patch.object(sys, "argv", argv):
        assert cli_module.main() == 4
    assert not shape_out.exists()
