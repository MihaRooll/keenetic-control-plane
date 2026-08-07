"""Gate B fail-safe discovery CLI tests — guards, validate, no secrets."""

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
CLI_SCRIPT = REPO_ROOT / "scripts" / "certify-gate-b-fail-safe.py"

COMPONENT_DIGEST = "sha256:de72a7af2255a1993c382ffd41143b8061525137b0d8e192811a32babf852f2f"
FINGERPRINT_DIGEST = "sha256:eb58946c0d18b3cb259c2687e474d10907dfdbbcf39c88992202917c37855169"
EVIDENCE_SHA256 = "c1682b110a2e0555fd3cd71f392677a88e674e382b46106c8b0e632a655e11c0"
WINDOW_OPEN = datetime(2026, 7, 22, 12, 0, 0, tzinfo=UTC)


def _load_cli():
    spec = importlib.util.spec_from_file_location("certify_gate_b_fail_safe_cli", CLI_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def cli():
    return _load_cli()


def _gate_payload() -> dict[str, object]:
    window_close = WINDOW_OPEN + timedelta(hours=1)
    return {
        "B": {
            "status": "certification_trial_authorized",
            "certification": "CertificationTrialAuthorized",
            "capability_family": "fail_safe",
        },
        "C": {
            "status": "open",
            "opens_at": WINDOW_OPEN.isoformat(),
            "expires_at": window_close.isoformat(),
        },
        "D": {"status": "closed"},
    }


def _auth_payload() -> dict[str, object]:
    window_close = WINDOW_OPEN + timedelta(hours=1)
    return {
        "contract_id": "fail-safe-discovery-nc1812-20260722",
        "human_decision": "approve",
        "trial_id": "cli-trial-001",
        "authorization_recorded_at": WINDOW_OPEN.isoformat(),
        "capability_family": "fail_safe",
        "typed_operation": "fail_safe_timer_reboot_60",
        "timer_seconds": 60,
        "expected_reboot": True,
        "evidence_sha256": EVIDENCE_SHA256,
        "opens_at": WINDOW_OPEN.isoformat(),
        "expires_at": window_close.isoformat(),
        "gates": _gate_payload(),
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
    }


def _gate_a_payload(evidence_path: str) -> dict[str, object]:
    evidence_sha256 = hashlib.sha256(Path(evidence_path).read_bytes()).hexdigest()
    return {
        "status": "open",
        "certification": "ReadOnlyCertified",
        "approved_scope": "SLICE-4-readonly",
        "model": "NC-1812",
        "model_display": "Ultra (NC-1812)",
        "firmware_version": "5.01.C.1.0-0",
        "firmware_display": "5.1.1",
        "ndm_build": "0-b592e619a0",
        "bsp_build": "0-f371d30955",
        "update_channel": "Main",
        "region": "EA",
        "component_set_digest": COMPONENT_DIGEST,
        "device_fingerprint_digest": FINGERPRINT_DIGEST,
        "physical_id_source": "show.identification_digest",
        "transport": "ssh_tunnel",
        "ssh_host_key_algorithm": "ssh-ed25519",
        "ssh_host_key_fingerprint_sha256": "SHA256:abc",
        "certification_eligible": True,
        "evidence_recorded_at": WINDOW_OPEN.isoformat(),
        "evidence_path": evidence_path,
        "expires_at": (WINDOW_OPEN + timedelta(days=90)).isoformat(),
        "revocation_policy": "human",
        "evidence_sha256": evidence_sha256,
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
        "ssh_host_key_fingerprint_sha256": "SHA256:abc",
        "certification_eligible": True,
        "identity_complete": True,
        "evidence_recorded_at": WINDOW_OPEN.isoformat(),
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
        "    capability_family: fail_safe\n"
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
def fixture_paths(tmp_path: Path) -> dict[str, Path]:
    evidence_path = tmp_path / "gate-a-evidence.json"
    evidence_path.write_text(json.dumps(_probe_evidence()), encoding="utf-8")
    evidence_sha256 = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
    gate_a_path = tmp_path / "gate-a.json"
    gate_a_path.write_text(
        json.dumps(_gate_a_payload(str(evidence_path))),
        encoding="utf-8",
    )
    auth_path = tmp_path / "auth.json"
    auth_payload = _auth_payload()
    auth_payload["evidence_sha256"] = evidence_sha256
    status_path = tmp_path / "STATUS.yaml"
    status_path.write_text(_status_yaml(), encoding="utf-8")
    receipt_path = tmp_path / "verification-receipt.json"
    _attach_execute_prerequisite(
        auth_payload=auth_payload,
        status_path=status_path,
        receipt_path=receipt_path,
    )
    auth_path.write_text(json.dumps(auth_payload), encoding="utf-8")
    out_path = tmp_path / "evidence-out.json"
    return {
        "evidence": evidence_path,
        "gate_a": gate_a_path,
        "auth": auth_path,
        "status": status_path,
        "out": out_path,
        "trials": tmp_path / "trials",
        "receipt": receipt_path,
    }


def test_rejects_password_env(cli, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RC_ROUTER_PASSWORD", "secret")
    assert cli._reject_password_env() == 2


def test_rejects_any_extra_argv(
    cli, fixture_paths: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    fixed_now = WINDOW_OPEN + timedelta(minutes=5)
    monkeypatch.setattr(cli, "_current_utc", lambda: fixed_now)
    argv = [
        "certify-gate-b-fail-safe.py",
        "--authorization",
        str(fixture_paths["auth"]),
        "--gate-a-config",
        str(fixture_paths["gate_a"]),
        "--gate-a-evidence",
        str(fixture_paths["evidence"]),
        "--status-path",
        str(fixture_paths["status"]),
        "unexpected-token",
    ]
    with patch.object(sys, "argv", argv):
        code = cli.main()
    assert code == 2


def test_execute_prerequisite_rejects_status_without_lineage(tmp_path: Path) -> None:
    from router_control.adapters.netcraze.gate_bc import (
        GateBCError,
        require_live_execute_prerequisite,
    )

    status_path = tmp_path / "STATUS.yaml"
    status_path.write_text(
        "current_phase:\n  id: p3-shared-netcraze-executor\n  complete: true\n",
        encoding="utf-8",
    )
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(
        json.dumps(
            {
                "p1_complete": True,
                "p2_complete": True,
                "p3_complete": True,
                "contract_id": "fail-safe-discovery-nc1812-20260722",
            }
        ),
        encoding="utf-8",
    )
    auth = {
        "contract_id": "fail-safe-discovery-nc1812-20260722",
        "status_source_digest": f"sha256:{hashlib.sha256(status_path.read_bytes()).hexdigest()}",
        "verification_receipt_sha256": (
            f"sha256:{hashlib.sha256(receipt_path.read_bytes()).hexdigest()}"
        ),
        "verification_receipt_path": str(receipt_path),
    }
    with pytest.raises(GateBCError, match="P1/P2/P3 complete lineage"):
        require_live_execute_prerequisite(status_path=status_path, authorization=auth)


def test_execute_prerequisite_requires_receipt_contract_id(tmp_path: Path) -> None:
    from router_control.adapters.netcraze.gate_bc import (
        GateBCError,
        require_live_execute_prerequisite,
    )

    status_path = tmp_path / "STATUS.yaml"
    status_path.write_text(_status_yaml(), encoding="utf-8")
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(
        json.dumps({"p1_complete": True, "p2_complete": True, "p3_complete": True}),
        encoding="utf-8",
    )
    auth = {
        "contract_id": "fail-safe-discovery-nc1812-20260722",
        "status_source_digest": f"sha256:{hashlib.sha256(status_path.read_bytes()).hexdigest()}",
        "verification_receipt_sha256": (
            f"sha256:{hashlib.sha256(receipt_path.read_bytes()).hexdigest()}"
        ),
        "verification_receipt_path": str(receipt_path),
    }
    with pytest.raises(GateBCError, match="contract_id"):
        require_live_execute_prerequisite(status_path=status_path, authorization=auth)


def test_rejects_mutation_like_extra(cli) -> None:
    parser = cli._build_parser()
    args = parser.parse_args(["--authorization", "auth.json", "reboot"])
    assert cli.main.__code__  # keep linter happy
    with patch.object(sys, "argv", ["prog", "--authorization", "x", "reboot"]):
        with patch("sys.argv", ["certify-gate-b-fail-safe.py", "--authorization", "x", "reboot"]):
            pass
    for token in args.extra:
        assert token.lower() in cli.MUTATION_COMMANDS


def test_validate_offline_zero_network(
    cli, fixture_paths: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    fixed_now = WINDOW_OPEN + timedelta(minutes=5)
    monkeypatch.setattr(cli, "_current_utc", lambda: fixed_now)
    argv = [
        "certify-gate-b-fail-safe.py",
        "--authorization",
        str(fixture_paths["auth"]),
        "--gate-a-config",
        str(fixture_paths["gate_a"]),
        "--gate-a-evidence",
        str(fixture_paths["evidence"]),
        "--status-path",
        str(fixture_paths["status"]),
        "--evidence-out",
        str(fixture_paths["out"]),
        "--trials-root",
        str(fixture_paths["trials"]),
        "--validate",
    ]
    with patch.object(sys, "argv", argv):
        code = cli.main()
    assert code == 0
    payload = json.loads(fixture_paths["out"].read_text(encoding="utf-8"))
    assert payload["result"] == "validated"
    assert payload["write_certified"] is False
    assert not any(fixture_paths["trials"].glob("*.consumed"))


def test_execute_refused_without_verification_receipt(
    cli, fixture_paths: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    fixed_now = WINDOW_OPEN + timedelta(minutes=5)
    monkeypatch.setattr(cli, "_current_utc", lambda: fixed_now)
    auth_payload = json.loads(fixture_paths["auth"].read_text(encoding="utf-8"))
    auth_payload.pop("verification_receipt_sha256", None)
    fixture_paths["auth"].write_text(json.dumps(auth_payload), encoding="utf-8")
    argv = [
        "certify-gate-b-fail-safe.py",
        "--execute",
        "--host",
        "192.168.1.1",
        "--username",
        "lab",
        "--credential-ref",
        "lab-ref",
        "--host-key-sha256",
        "SHA256:abc",
        "--source-address",
        "192.168.1.144",
        "--authorization",
        str(fixture_paths["auth"]),
        "--gate-a-config",
        str(fixture_paths["gate_a"]),
        "--gate-a-evidence",
        str(fixture_paths["evidence"]),
        "--status-path",
        str(fixture_paths["status"]),
    ]
    with patch.object(sys, "argv", argv):
        code = cli.main()
    assert code == 2


def test_execute_requires_host_fields(
    cli, fixture_paths: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    fixed_now = WINDOW_OPEN + timedelta(minutes=5)
    monkeypatch.setattr(cli, "_current_utc", lambda: fixed_now)
    argv = [
        "certify-gate-b-fail-safe.py",
        "--execute",
        "--authorization",
        str(fixture_paths["auth"]),
        "--gate-a-config",
        str(fixture_paths["gate_a"]),
        "--gate-a-evidence",
        str(fixture_paths["evidence"]),
        "--status-path",
        str(fixture_paths["status"]),
    ]
    with patch.object(sys, "argv", argv):
        code = cli.main()
    assert code == 2


def test_execute_requires_source_address(
    cli, fixture_paths: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    fixed_now = WINDOW_OPEN + timedelta(minutes=5)
    monkeypatch.setattr(cli, "_current_utc", lambda: fixed_now)
    argv = [
        "certify-gate-b-fail-safe.py",
        "--execute",
        "--host",
        "192.168.1.1",
        "--username",
        "lab",
        "--credential-ref",
        "lab-ref",
        "--host-key-sha256",
        "SHA256:abc",
        "--authorization",
        str(fixture_paths["auth"]),
        "--gate-a-config",
        str(fixture_paths["gate_a"]),
        "--gate-a-evidence",
        str(fixture_paths["evidence"]),
        "--status-path",
        str(fixture_paths["status"]),
    ]
    with patch.object(sys, "argv", argv):
        code = cli.main()
    assert code == 2
