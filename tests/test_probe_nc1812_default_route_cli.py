"""Offline tests for probe-nc1812-default-route CLI."""

from __future__ import annotations

import importlib.util
import json
import sys
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest
from router_control.adapters.netcraze.route_topology_probe import PARSER_VERSION

REPO_ROOT = Path(__file__).resolve().parents[1]
CLI_SCRIPT = REPO_ROOT / "scripts" / "probe-nc1812-default-route.py"
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "netcraze"

SYNTH_PASSWORD = "SENTINEL-PASSWORD-ORACLE"


def _load_module():
    spec = importlib.util.spec_from_file_location("probe_nc1812_default_route_cli", CLI_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def cli_module():
    return _load_module()


def test_fixture_dry_run_writes_artifact(cli_module, tmp_path: Path) -> None:
    out = tmp_path / "default-route-artifact.json"
    argv = [
        "probe-nc1812-default-route.py",
        "--fixture",
        "default_route_single.json",
        "--artifact-out",
        str(out),
        "--source-address",
        "192.168.1.144",
    ]
    with patch.object(sys, "argv", argv):
        assert cli_module.main() == 0
    artifact = json.loads(out.read_text(encoding="utf-8"))
    assert artifact["certification_eligible"] is False
    assert artifact["findings"]["classification"] == "one_default_route"
    assert SYNTH_PASSWORD not in out.read_text(encoding="utf-8")


def test_live_requires_source_address_before_vault(cli_module) -> None:
    argv = [
        "probe-nc1812-default-route.py",
        "--host",
        "192.168.1.1",
        "--credential-ref",
        "cred_oracle",
        "--username",
        "lab-user",
        "--ssh-host-key-sha256",
        "SHA256:oraclepin",
        "--artifact-out",
        "data/artifacts/default-route.json",
    ]
    stderr = StringIO()
    with patch.object(sys, "argv", argv), patch.object(sys, "stderr", stderr):
        assert cli_module.main() == 2
    assert "--source-address" in stderr.getvalue()


def test_cli_has_no_raw_operation_args(cli_module) -> None:
    parser = cli_module._build_parser()
    actions = {action.dest for action in parser._actions if action.dest != "help"}
    forbidden = {"operation", "raw", "command", "path", "rci_path"}
    assert forbidden.isdisjoint(actions)


def test_fixture_missing_file_returns_nonzero(cli_module, tmp_path: Path) -> None:
    argv = [
        "probe-nc1812-default-route.py",
        "--fixture",
        "missing_default_route.json",
        "--artifact-out",
        str(tmp_path / "out.json"),
    ]
    with patch.object(sys, "argv", argv):
        assert cli_module.main() == 3


def test_fixture_shape_out_writes_structural_fingerprint(
    cli_module, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixtures_dir = tmp_path / "fixtures"
    fixtures_dir.mkdir()
    failing = {"unexpected": [{"destination": "0.0.0.0/0", "password": SYNTH_PASSWORD}]}
    (fixtures_dir / "route_shape_fail.json").write_text(json.dumps(failing), encoding="utf-8")
    monkeypatch.setattr(cli_module, "FIXTURES_DIR", fixtures_dir)
    artifact_out = tmp_path / "artifact.json"
    shape_out = tmp_path / "shape.json"
    argv = [
        "probe-nc1812-default-route.py",
        "--fixture",
        "route_shape_fail.json",
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
    shape = json.loads(shape_out.read_text(encoding="utf-8"))
    assert shape["certification_eligible"] is False
    assert "structure" in shape
    assert shape["structure"]["top_type"] == "object"
    assert SYNTH_PASSWORD not in shape_out.read_text(encoding="utf-8")


def test_fixture_shape_out_list_wrapper_writes_list_fingerprint(
    cli_module, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixtures_dir = tmp_path / "fixtures"
    fixtures_dir.mkdir()
    failing: object = [[], []]
    (fixtures_dir / "route_list_shape_fail.json").write_text(json.dumps(failing), encoding="utf-8")
    monkeypatch.setattr(cli_module, "FIXTURES_DIR", fixtures_dir)
    shape_out = tmp_path / "shape.json"
    argv = [
        "probe-nc1812-default-route.py",
        "--fixture",
        "route_list_shape_fail.json",
        "--artifact-out",
        str(tmp_path / "artifact.json"),
        "--shape-out",
        str(shape_out),
        "--source-address",
        "192.168.1.144",
    ]
    with patch.object(sys, "argv", argv):
        assert cli_module.main() == 4
    shape = json.loads(shape_out.read_text(encoding="utf-8"))
    assert shape["structure"]["top_type"] == "array"
    assert shape["structure"]["top_count"] == 2
    assert shape["structure"]["element_type_histogram"] == {"array": 2}
    blob = shape_out.read_text(encoding="utf-8")
    assert SYNTH_PASSWORD not in blob
    assert "0.0.0.0" not in blob


def test_topology_artifact_correlation_fixture(
    cli_module, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    route_out = tmp_path / "route.json"
    topo_out = tmp_path / "topo.json"
    from router_control.adapters.netcraze.topology_probe import build_topology_artifact

    topo_payload = json.loads(
        (FIXTURES / "topology_interface_wan_isolated.json").read_text(encoding="utf-8")
    )
    topo_raw = (FIXTURES / "topology_interface_wan_isolated.json").read_bytes()
    topo_artifact = build_topology_artifact(
        payload=topo_payload,
        raw_bytes=topo_raw,
        source_address="192.168.1.144",
        source_address_class="private_ipv4_literal",
        gate_a_tuple_digest="sha256:" + "a" * 64,
        gate_a_evidence_digest="sha256:" + "b" * 64,
        transport_security="fixture",
        https_check="fixture",
        ssh_host_key_algorithm="fixture",
        ssh_host_key_fingerprint_sha256="SHA256:fixture",
    )
    topo_out.write_text(json.dumps(topo_artifact, indent=2), encoding="utf-8")

    def _aligned_digests(*, fixture_name: str):
        return ("sha256:" + "a" * 64, "sha256:" + "b" * 64)

    monkeypatch.setattr(cli_module, "_fixture_digests", _aligned_digests)
    argv = [
        "probe-nc1812-default-route.py",
        "--fixture",
        "default_route_single.json",
        "--artifact-out",
        str(route_out),
        "--topology-artifact",
        str(topo_out),
        "--source-address",
        "192.168.1.144",
    ]
    with patch.object(sys, "argv", argv):
        assert cli_module.main() == 0

    artifact = json.loads(route_out.read_text(encoding="utf-8"))
    assert "topology_correlation" in artifact
    assert artifact["topology_correlation"]["status"] in {"match", "ambiguous", "mismatch"}


def test_fixture_empty_wrapper_dry_run(cli_module, tmp_path: Path) -> None:
    out = tmp_path / "default-route-empty-wrapper.json"
    argv = [
        "probe-nc1812-default-route.py",
        "--fixture",
        "default_route_observed_empty_wrapper.json",
        "--artifact-out",
        str(out),
        "--source-address",
        "192.168.1.144",
    ]
    with patch.object(sys, "argv", argv):
        assert cli_module.main() == 0
    artifact = json.loads(out.read_text(encoding="utf-8"))
    assert artifact["parser_version"] == PARSER_VERSION
    assert artifact["findings"]["classification"] == "no_default_route"
    assert artifact["findings"]["default_route_count"] == 0
    assert artifact["findings"]["default_outbound_interface_hashes"] == []
    assert SYNTH_PASSWORD not in out.read_text(encoding="utf-8")
