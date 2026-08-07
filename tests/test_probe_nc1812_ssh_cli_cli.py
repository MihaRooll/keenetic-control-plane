"""Offline tests for probe-nc1812-ssh-cli CLI."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import uuid
from datetime import UTC, datetime, timedelta
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
CLI_SCRIPT = REPO_ROOT / "scripts" / "probe-nc1812-ssh-cli.py"
STATUS_PATH = REPO_ROOT / "docs" / "STATUS.yaml"
VERIFICATION_RECEIPTS_DIR = REPO_ROOT / "data" / "artifacts" / "verification-receipts"

SYNTH_PASSWORD = "SENTINEL-PASSWORD-ORACLE"
CONTRACT_ID = "nc1812-ssh-cli-channel-discovery-20260723"


def _load_module():
    spec = importlib.util.spec_from_file_location("probe_nc1812_ssh_cli_cli", CLI_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def cli_module():
    return _load_module()


def _status_yaml() -> str:
    return (
        "gates:\n"
        "  A:\n"
        "    status: open\n"
        "    certification: ReadOnlyCertified\n"
        "  B:\n"
        "    status: completed_failed\n"
        "    certification: CertificationTrialAuthorized\n"
        "    not_write_certified: true\n"
        "  C:\n"
        "    status: closed\n"
        "  D:\n"
        "    status: closed\n"
    )


def _write_verification_receipt() -> tuple[str, str]:
    VERIFICATION_RECEIPTS_DIR.mkdir(parents=True, exist_ok=True)
    name = f"test-cli-ssh-{uuid.uuid4().hex}.json"
    rel_path = f"data/artifacts/verification-receipts/{name}"
    abs_path = REPO_ROOT / rel_path
    payload = {
        "contract_id": CONTRACT_ID,
        "p1_complete": True,
        "p2_complete": True,
        "p3_complete": True,
    }
    abs_path.write_text(json.dumps(payload), encoding="utf-8")
    digest = f"sha256:{hashlib.sha256(abs_path.read_bytes()).hexdigest()}"
    return rel_path, digest


@pytest.fixture
def cli_auth_bundle(tmp_path: Path):
    created_receipts: list[Path] = []
    status_path = tmp_path / "STATUS.yaml"
    status_path.write_text(_status_yaml(), encoding="utf-8")
    rel_path, receipt_digest = _write_verification_receipt()
    created_receipts.append(REPO_ROOT / rel_path)

    def _sample_authorization_path() -> Path:
        opens = datetime.now(UTC) - timedelta(minutes=5)
        expires = opens + timedelta(hours=1)
        payload = {
            "contract_id": CONTRACT_ID,
            "human_decision": "approve",
            "probe_id": "ssh-cli-cli-validate-001",
            "authorization_recorded_at": opens.isoformat(),
            "typed_operations": [
                "ssh_exec_show_interface_home",
                "ssh_shell_show_interface_home",
            ],
            "mutation_allowed": False,
            "source_address": "192.168.2.10",
            "evidence_sha256": "24c6df7eeb2648af25a1ed6d795ad634f32c4fa664555a67f9ff00d57ee9d4f3",
            "opens_at": opens.isoformat(),
            "expires_at": expires.isoformat(),
            "status_source_digest": (
                f"sha256:{hashlib.sha256(status_path.read_bytes()).hexdigest()}"
            ),
            "verification_receipt_sha256": receipt_digest,
            "verification_receipt_path": rel_path,
            "gates": {
                "B": {"status": "completed_failed", "not_write_certified": True},
                "C": {"status": "closed"},
                "D": {"status": "closed"},
            },
            "gate_a_tuple_binding": {
                "model": "NC-1812",
                "firmware_version": "5.01.C.1.0-0",
                "ndm_build": "0",
                "bsp_build": "0",
                "update_channel": "Main",
                "region": "EA",
                "component_set_digest": "sha256:" + "c" * 64,
                "device_fingerprint_digest": "sha256:" + "d" * 64,
                "transport": "ssh_tunnel",
                "ssh_host_key_algorithm": "ssh-ed25519",
            },
        }
        path = tmp_path / "auth.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    yield _sample_authorization_path, status_path

    for receipt in created_receipts:
        receipt.unlink(missing_ok=True)


def test_validate_default_exits_zero(cli_module, cli_auth_bundle) -> None:
    auth_path_fn, status_path = cli_auth_bundle
    auth_path = auth_path_fn()
    out = status_path.parent / "artifact.json"
    argv = [
        "probe-nc1812-ssh-cli.py",
        "--authorization",
        str(auth_path),
        "--artifact-out",
        str(out),
        "--status-path",
        str(status_path),
    ]
    with patch.object(sys, "argv", argv):
        assert cli_module.main() == 0
    artifact = json.loads(out.read_text(encoding="utf-8"))
    assert artifact["result"] == "validated"
    assert artifact["certification_eligible"] is False
    assert SYNTH_PASSWORD not in out.read_text(encoding="utf-8")


def test_validate_exits_three_on_digest_mismatch(cli_module, cli_auth_bundle) -> None:
    auth_path_fn, status_path = cli_auth_bundle
    auth_path = auth_path_fn()
    payload = json.loads(auth_path.read_text(encoding="utf-8"))
    payload["status_source_digest"] = "sha256:" + "f" * 64
    auth_path.write_text(json.dumps(payload), encoding="utf-8")
    argv = [
        "probe-nc1812-ssh-cli.py",
        "--authorization",
        str(auth_path),
        "--status-path",
        str(status_path),
    ]
    stderr = StringIO()
    with patch.object(sys, "argv", argv), patch.object(sys, "stderr", stderr):
        assert cli_module.main() == 3
    assert "status_source_digest mismatch" in stderr.getvalue()


def test_validate_exits_three_on_status_gate_reject(cli_module, tmp_path: Path) -> None:
    status_path = tmp_path / "STATUS.yaml"
    status_path.write_text(
        _status_yaml().replace("completed_failed", "open", 1),
        encoding="utf-8",
    )
    rel_path, receipt_digest = _write_verification_receipt()
    try:
        opens = datetime.now(UTC) - timedelta(minutes=5)
        expires = opens + timedelta(hours=1)
        payload = {
            "contract_id": CONTRACT_ID,
            "human_decision": "approve",
            "probe_id": "ssh-cli-cli-gate-reject",
            "typed_operations": [
                "ssh_exec_show_interface_home",
                "ssh_shell_show_interface_home",
            ],
            "mutation_allowed": False,
            "source_address": "192.168.2.10",
            "evidence_sha256": "24c6df7eeb2648af25a1ed6d795ad634f32c4fa664555a67f9ff00d57ee9d4f3",
            "opens_at": opens.isoformat(),
            "expires_at": expires.isoformat(),
            "status_source_digest": (
                f"sha256:{hashlib.sha256(status_path.read_bytes()).hexdigest()}"
            ),
            "verification_receipt_sha256": receipt_digest,
            "verification_receipt_path": rel_path,
            "gates": {
                "B": {"status": "completed_failed", "not_write_certified": True},
                "C": {"status": "closed"},
                "D": {"status": "closed"},
            },
            "gate_a_tuple_binding": {
                "model": "NC-1812",
                "firmware_version": "5.01.C.1.0-0",
                "ndm_build": "0",
                "bsp_build": "0",
                "update_channel": "Main",
                "region": "EA",
                "component_set_digest": "sha256:" + "c" * 64,
                "device_fingerprint_digest": "sha256:" + "d" * 64,
                "transport": "ssh_tunnel",
                "ssh_host_key_algorithm": "ssh-ed25519",
            },
        }
        auth_path = tmp_path / "auth.json"
        auth_path.write_text(json.dumps(payload), encoding="utf-8")
        argv = [
            "probe-nc1812-ssh-cli.py",
            "--authorization",
            str(auth_path),
            "--status-path",
            str(status_path),
        ]
        stderr = StringIO()
        with patch.object(sys, "argv", argv), patch.object(sys, "stderr", stderr):
            assert cli_module.main() == 3
        assert "Gate B must not be open" in stderr.getvalue()
    finally:
        (REPO_ROOT / rel_path).unlink(missing_ok=True)


def test_live_probe_requires_authorization(cli_module) -> None:
    argv = [
        "probe-nc1812-ssh-cli.py",
        "--live-probe",
        "--host",
        "192.168.1.1",
        "--credential-ref",
        "cred_oracle",
        "--username",
        "lab-user",
        "--ssh-host-key-sha256",
        "SHA256:oraclepin",
        "--source-address",
        "192.168.2.10",
    ]
    stderr = StringIO()
    with patch.object(sys, "argv", argv), patch.object(sys, "stderr", stderr):
        assert cli_module.main() == 2
    assert "--authorization" in stderr.getvalue()


def test_refuses_password_env(cli_module, cli_auth_bundle, monkeypatch: pytest.MonkeyPatch) -> None:
    auth_path = cli_auth_bundle[0]()
    monkeypatch.setenv("RC_ROUTER_PASSWORD", SYNTH_PASSWORD)
    argv = [
        "probe-nc1812-ssh-cli.py",
        "--authorization",
        str(auth_path),
        "--status-path",
        str(cli_auth_bundle[1]),
    ]
    stderr = StringIO()
    with patch.object(sys, "argv", argv), patch.object(sys, "stderr", stderr):
        assert cli_module.main() == 2
    assert "Refusing password environment variable" in stderr.getvalue()


def test_refuses_extra_args(cli_module, cli_auth_bundle) -> None:
    auth_path = cli_auth_bundle[0]()
    argv = [
        "probe-nc1812-ssh-cli.py",
        "--authorization",
        str(auth_path),
        "--status-path",
        str(cli_auth_bundle[1]),
        "unexpected-arg",
    ]
    stderr = StringIO()
    with patch.object(sys, "argv", argv), patch.object(sys, "stderr", stderr):
        assert cli_module.main() == 2
    assert "Refusing unexpected arguments" in stderr.getvalue()


def test_cli_has_no_execute_or_raw_command_args(cli_module) -> None:
    parser = cli_module._build_parser()
    actions = {action.dest for action in parser._actions if action.dest != "help"}
    forbidden = {"execute", "operation", "raw", "command", "path", "rci_path"}
    assert forbidden.isdisjoint(actions)


def test_live_probe_refuses_wrong_source(cli_module, cli_auth_bundle) -> None:
    auth_path = cli_auth_bundle[0]()
    argv = [
        "probe-nc1812-ssh-cli.py",
        "--live-probe",
        "--authorization",
        str(auth_path),
        "--host",
        "192.168.1.1",
        "--credential-ref",
        "cred_oracle",
        "--username",
        "lab-user",
        "--ssh-host-key-sha256",
        "SHA256:oraclepin",
        "--source-address",
        "192.168.1.1",
        "--status-path",
        str(cli_auth_bundle[1]),
    ]
    stderr = StringIO()
    with patch.object(sys, "argv", argv), patch.object(sys, "stderr", stderr):
        assert cli_module.main() == 2
    assert "192.168.2.10" in stderr.getvalue()
