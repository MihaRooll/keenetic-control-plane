"""Gate B/C AWG certification CLI tests — guards, dry-run, no secrets."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
CLI_SCRIPT = REPO_ROOT / "scripts" / "certify-gate-b-awg.py"

SAMPLE_PROFILE = """
[Interface]
PrivateKey = EXAMPLE_PRIVATE_KEY_PLACEHOLDER_AAAAAAAAAAAAAAAAAAAAAAAA
Address = 10.0.0.2/32
Jc = 5
Jmin = 50
Jmax = 1000
S1 = 80
S2 = 80
H1 = 1
H2 = 2
H3 = 3
H4 = 4

[Peer]
PublicKey = EXAMPLE_PUBLIC_KEY_PLACEHOLDER_BBBBBBBBBBBBBBBBBBBBBBBBBBBB
PresharedKey = EXAMPLE_PSK_PLACEHOLDER_CCCCCCCCCCCCCCCCCCCCCCCCCCCC
Endpoint = EXAMPLE_ENDPOINT:51820
AllowedIPs = 0.0.0.0/0
"""

COMPONENT_DIGEST = "sha256:de72a7af2255a1993c382ffd41143b8061525137b0d8e192811a32babf852f2f"
FINGERPRINT_DIGEST = "sha256:eb58946c0d18b3cb259c2687e474d10907dfdbbcf39c88992202917c37855169"
WINDOW_OPEN = datetime(2026, 7, 21, 20, 34, 31, tzinfo=UTC)


def _load_cli():
    spec = importlib.util.spec_from_file_location("certify_gate_b_awg_cli", CLI_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def cli():
    return _load_cli()


def _auth_payload() -> dict[str, object]:
    window_close = WINDOW_OPEN + timedelta(seconds=3600)
    return {
        "contract_id": "gate-bc-awg-certification-20260721",
        "human_decision": "approve",
        "authorization_recorded_at": WINDOW_OPEN.isoformat(),
        "gates": {
            "B": {
                "status": "certification_trial_authorized",
                "certification": "CertificationTrialAuthorized",
                "capability_family": "AmneziaWG",
                "approved_scope": "lab_awg_only",
            },
            "C": {
                "status": "open",
                "scope": "dedicated_lab",
                "capability_family": "AmneziaWG",
                "opens_at": WINDOW_OPEN.isoformat(),
                "expires_at": window_close.isoformat(),
                "duration_seconds": 3600,
            },
            "D": {"status": "closed"},
        },
        "gate_a_tuple_binding": {
            "model": "NC-1812",
            "firmware_version": "5.01.C.1.0-0",
            "ndm_build": "0-b592e619a0",
            "bsp_build": "0-f371d30955",
            "update_channel": "Main",
            "region": "EA",
            "component_set_digest": COMPONENT_DIGEST,
            "device_fingerprint_digest": FINGERPRINT_DIGEST,
            "transport": "ssh_tunnel",
            "ssh_host_key_algorithm": "ssh-ed25519",
        },
        "candidate_order": ["keenetic50-compat", "fi-ip", "de-ip"],
        "write_shapes_registered": False,
        "registered_shape_ops": [],
    }


def _gate_a_payload(evidence_path: str) -> dict[str, object]:
    return {
        "status": "open",
        "certification": "ReadOnlyCertified",
        "approved_scope": "SLICE-4-readonly",
        "model": "NC-1812",
        "firmware_version": "5.01.C.1.0-0",
        "ndm_build": "0-b592e619a0",
        "bsp_build": "0-f371d30955",
        "update_channel": "Main",
        "region": "EA",
        "component_set_digest": COMPONENT_DIGEST,
        "device_fingerprint_digest": FINGERPRINT_DIGEST,
        "physical_id_source": "show.identification_digest",
        "transport": "ssh_tunnel",
        "ssh_host_key_algorithm": "ssh-ed25519",
        "ssh_host_key_fingerprint_sha256": "SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM",
        "certification_eligible": True,
        "evidence_recorded_at": "2026-07-21T17:15:29.318950+00:00",
        "evidence_path": evidence_path,
        "expires_after_days": 90,
        "gates": {
            "A": {"status": "open", "certification": "ReadOnlyCertified"},
            "B": {"status": "closed"},
            "C": {"status": "closed"},
            "D": {"status": "closed"},
        },
    }


def _probe_evidence() -> dict[str, object]:
    return {
        "model": "NC-1812",
        "firmware_version": "5.01.C.1.0-0",
        "build": "0-b592e619a0",
        "bsp_build": "0-f371d30955",
        "update_channel": "Main",
        "region": "EA",
        "component_set_digest": COMPONENT_DIGEST,
        "device_fingerprint": FINGERPRINT_DIGEST,
        "transport_security": "ssh_tunnel",
        "ssh_host_key_algorithm": "ssh-ed25519",
        "ssh_host_key_fingerprint_sha256": "SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM",
        "certification_eligible": True,
        "identity_complete": True,
        "evidence_recorded_at": "2026-07-21T17:15:29.318950+00:00",
    }


def _status_yaml() -> str:
    return (
        "current_phase:\n"
        "  id: p3-shared-netcraze-executor\n"
        "  complete: true\n"
        "lineage:\n"
        "  p1_complete: true\n"
        "  p2_complete: true\n"
        "  p3_complete: true\n"
        "gates:\n"
        "  A:\n"
        "    status: open\n"
        "    certification: ReadOnlyCertified\n"
        "  B:\n"
        "    status: certification_trial_authorized\n"
        "    certification: CertificationTrialAuthorized\n"
        "  C:\n"
        "    status: open\n"
        "  D:\n"
        "    status: closed\n"
    )


def _attach_execute_prerequisite(
    *,
    auth_payload: dict[str, object],
    status_path: Path,
    receipt_path: Path,
) -> None:
    status_digest = f"sha256:{hashlib.sha256(status_path.read_bytes()).hexdigest()}"
    receipt_payload = {
        "p1_complete": True,
        "p2_complete": True,
        "p3_complete": True,
        "contract_id": auth_payload["contract_id"],
    }
    receipt_path.write_text(json.dumps(receipt_payload), encoding="utf-8")
    receipt_digest = f"sha256:{hashlib.sha256(receipt_path.read_bytes()).hexdigest()}"
    auth_payload["status_source_digest"] = status_digest
    auth_payload["verification_receipt_sha256"] = receipt_digest
    auth_payload["verification_receipt_path"] = str(receipt_path.resolve())


@pytest.fixture
def lab_paths(tmp_path: Path) -> dict[str, Path]:
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps(_probe_evidence()), encoding="utf-8")
    digest = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
    gate_a_path = tmp_path / "gate-a.json"
    gate_a = _gate_a_payload(str(evidence_path))
    gate_a["evidence_sha256"] = digest
    gate_a_path.write_text(json.dumps(gate_a), encoding="utf-8")
    auth_path = tmp_path / "auth.json"
    auth_payload = _auth_payload()
    status_path = tmp_path / "STATUS.yaml"
    status_path.write_text(_status_yaml(), encoding="utf-8")
    receipt_path = tmp_path / "verification-receipt.json"
    _attach_execute_prerequisite(
        auth_payload=auth_payload,
        status_path=status_path,
        receipt_path=receipt_path,
    )
    auth_path.write_text(json.dumps(auth_payload), encoding="utf-8")
    profile_path = tmp_path / "profile.conf"
    profile_path.write_text(SAMPLE_PROFILE, encoding="utf-8")
    artifact_path = tmp_path / "artifact.json"
    return {
        "evidence": evidence_path,
        "gate_a": gate_a_path,
        "auth": auth_path,
        "status": status_path,
        "profile": profile_path,
        "artifact": artifact_path,
    }


def test_refuses_password_env(
    cli,
    lab_paths: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("RC_ROUTER_PASSWORD", "secret")
    argv = [
        "certify-gate-b-awg.py",
        "--authorization-config",
        str(lab_paths["auth"]),
        "--gate-a-config",
        str(lab_paths["gate_a"]),
        "--gate-a-evidence",
        str(lab_paths["evidence"]),
        "--status-path",
        str(lab_paths["status"]),
        "--profile-path",
        str(lab_paths["profile"]),
        "--artifact-out",
        str(lab_paths["artifact"]),
    ]
    with patch.object(sys, "argv", argv):
        assert cli.main() == 2


@pytest.mark.parametrize("token", ["save", "reboot", "mutate"])
def test_refuses_mutation_extra_tokens(cli, token: str) -> None:
    argv = [
        "certify-gate-b-awg.py",
        "--profile-path",
        "ignored.conf",
        token,
    ]
    with patch.object(sys, "argv", argv):
        assert cli.main() == 2


def test_dry_run_stops_at_unknown_shape(
    cli,
    lab_paths: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("RC_ROUTER_PASSWORD", raising=False)
    frozen = WINDOW_OPEN + timedelta(minutes=10)
    argv = [
        "certify-gate-b-awg.py",
        "--authorization-config",
        str(lab_paths["auth"]),
        "--gate-a-config",
        str(lab_paths["gate_a"]),
        "--gate-a-evidence",
        str(lab_paths["evidence"]),
        "--status-path",
        str(lab_paths["status"]),
        "--profile-path",
        str(lab_paths["profile"]),
        "--artifact-out",
        str(lab_paths["artifact"]),
    ]
    with patch.object(sys, "argv", argv):
        monkeypatch.setattr(cli, "_current_utc", lambda: frozen)
        code = cli.main()
    assert code == 0
    artifact = json.loads(lab_paths["artifact"].read_text(encoding="utf-8"))
    assert artifact["write_certified_claim"] is False
    assert artifact["runner_status"] == "stopped"
    assert "EXAMPLE_PRIVATE_KEY" not in json.dumps(artifact)
    assert "EXAMPLE_PSK" not in json.dumps(artifact)
    assert "EXAMPLE_ENDPOINT" not in json.dumps(artifact)


def test_execute_requires_win32_dpapi_vault(
    cli,
    lab_paths: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("RC_ROUTER_PASSWORD", raising=False)
    frozen = WINDOW_OPEN + timedelta(minutes=10)
    argv = [
        "certify-gate-b-awg.py",
        "--execute",
        "--source-address",
        "192.168.1.144",
        "--authorization-config",
        str(lab_paths["auth"]),
        "--gate-a-config",
        str(lab_paths["gate_a"]),
        "--gate-a-evidence",
        str(lab_paths["evidence"]),
        "--status-path",
        str(lab_paths["status"]),
        "--profile-path",
        str(lab_paths["profile"]),
    ]
    with patch.object(sys, "platform", "linux"):
        with patch.object(sys, "argv", argv):
            monkeypatch.setattr(cli, "_current_utc", lambda: frozen)
            assert cli.main() == 2


def test_execute_on_win32_uses_dpapi_vault(
    cli,
    lab_paths: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from router_control.adapters.secrets.memory import MemoryVault

    monkeypatch.delenv("RC_ROUTER_PASSWORD", raising=False)
    frozen = WINDOW_OPEN + timedelta(minutes=10)
    argv = [
        "certify-gate-b-awg.py",
        "--execute",
        "--source-address",
        "192.168.1.144",
        "--authorization-config",
        str(lab_paths["auth"]),
        "--gate-a-config",
        str(lab_paths["gate_a"]),
        "--gate-a-evidence",
        str(lab_paths["evidence"]),
        "--status-path",
        str(lab_paths["status"]),
        "--profile-path",
        str(lab_paths["profile"]),
        "--artifact-out",
        str(lab_paths["artifact"]),
    ]
    with patch.object(sys, "platform", "win32"):
        with patch(
            "router_control.adapters.secrets.dpapi.WindowsDpapiVault",
            return_value=MemoryVault(),
        ) as vault_cls:
            with patch.object(sys, "argv", argv):
                monkeypatch.setattr(cli, "_current_utc", lambda: frozen)
                code = cli.main()
    assert code in (0, 4)
    vault_cls.assert_called_once()


def test_execute_without_source_address_exits_nonzero(
    cli,
    lab_paths: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("RC_ROUTER_PASSWORD", raising=False)
    frozen = WINDOW_OPEN + timedelta(minutes=10)
    argv = [
        "certify-gate-b-awg.py",
        "--execute",
        "--authorization-config",
        str(lab_paths["auth"]),
        "--gate-a-config",
        str(lab_paths["gate_a"]),
        "--gate-a-evidence",
        str(lab_paths["evidence"]),
        "--status-path",
        str(lab_paths["status"]),
        "--profile-path",
        str(lab_paths["profile"]),
    ]
    with patch.object(sys, "argv", argv):
        monkeypatch.setattr(cli, "_current_utc", lambda: frozen)
        assert cli.main() == 2


def test_execute_refused_without_verification_receipt(
    cli,
    lab_paths: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("RC_ROUTER_PASSWORD", raising=False)
    frozen = WINDOW_OPEN + timedelta(minutes=10)
    auth_payload = json.loads(lab_paths["auth"].read_text(encoding="utf-8"))
    auth_payload.pop("verification_receipt_sha256", None)
    lab_paths["auth"].write_text(json.dumps(auth_payload), encoding="utf-8")
    argv = [
        "certify-gate-b-awg.py",
        "--execute",
        "--source-address",
        "192.168.1.144",
        "--authorization-config",
        str(lab_paths["auth"]),
        "--gate-a-config",
        str(lab_paths["gate_a"]),
        "--gate-a-evidence",
        str(lab_paths["evidence"]),
        "--status-path",
        str(lab_paths["status"]),
        "--profile-path",
        str(lab_paths["profile"]),
    ]
    with patch.object(sys, "argv", argv):
        monkeypatch.setattr(cli, "_current_utc", lambda: frozen)
        assert cli.main() == 2
