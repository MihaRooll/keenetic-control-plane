"""Gate B/C AWG authorization loader tests."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from router_control.adapters.netcraze.awg_certification import CandidatePhase
from router_control.adapters.netcraze.awg_hardware import (
    AwgHardwareBoundary,
    HardwareExecutionResult,
    RegisteredShape,
    ShapeRegistry,
    TypedOperation,
)
from router_control.adapters.netcraze.certification import GateACertification
from router_control.adapters.netcraze.gate_bc import (
    GateBCAuthorization,
    GateBCError,
    GateCExpired,
    TupleDrift,
    load_gate_bc_authorization,
    require_live_execute_prerequisite,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
COMMITTED_GATE_A_CONFIG = REPO_ROOT / "docs" / "gate-a-certification.json"

COMPONENT_DIGEST = "sha256:23bd35bc1bcbf8523495ff7fb37ef2ded597ce9d07b9c1c968ae1f9e4aa4de80"
FINGERPRINT_DIGEST = "sha256:c34adec44383c0dc1f31833bb6d7885a8e9af454722af0c6bfba3761ac71e6fd"
WINDOW_OPEN = datetime(2026, 7, 21, 20, 34, 31, tzinfo=UTC)
WINDOW_CLOSE = WINDOW_OPEN + timedelta(seconds=3600)

PROBE_EVIDENCE = {
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
}


def _auth_payload(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
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
                "expires_at": WINDOW_CLOSE.isoformat(),
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
    base.update(overrides)
    return base


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
def auth_paths(tmp_path: Path) -> tuple[Path, Path]:
    config_path = tmp_path / "auth.json"
    status_path = tmp_path / "STATUS.yaml"
    status_path.write_text(_status_yaml(), encoding="utf-8")
    auth_payload = _auth_payload()
    receipt_path = tmp_path / "verification-receipt.json"
    _attach_execute_prerequisite(
        auth_payload=auth_payload,
        status_path=status_path,
        receipt_path=receipt_path,
    )
    config_path.write_text(json.dumps(auth_payload), encoding="utf-8")
    return config_path, status_path


def test_execute_prerequisite_rejects_status_without_lineage(tmp_path: Path) -> None:
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
                "contract_id": "gate-bc-awg-certification-20260721",
            }
        ),
        encoding="utf-8",
    )
    auth = {
        "contract_id": "gate-bc-awg-certification-20260721",
        "status_source_digest": f"sha256:{hashlib.sha256(status_path.read_bytes()).hexdigest()}",
        "verification_receipt_sha256": (
            f"sha256:{hashlib.sha256(receipt_path.read_bytes()).hexdigest()}"
        ),
        "verification_receipt_path": str(receipt_path),
    }
    with pytest.raises(GateBCError, match="P1/P2/P3 complete lineage"):
        require_live_execute_prerequisite(status_path=status_path, authorization=auth)


def test_execute_prerequisite_rejects_tampered_receipt_digest(tmp_path: Path) -> None:
    status_path = tmp_path / "STATUS.yaml"
    status_path.write_text(_status_yaml(), encoding="utf-8")
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(
        json.dumps(
            {
                "p1_complete": True,
                "p2_complete": True,
                "p3_complete": True,
                "contract_id": "gate-bc-awg-certification-20260721",
            }
        ),
        encoding="utf-8",
    )
    auth = {
        "contract_id": "gate-bc-awg-certification-20260721",
        "status_source_digest": f"sha256:{hashlib.sha256(status_path.read_bytes()).hexdigest()}",
        "verification_receipt_sha256": "sha256:" + ("0" * 64),
        "verification_receipt_path": str(receipt_path),
    }
    with pytest.raises(GateBCError, match="verification_receipt_sha256 mismatch"):
        require_live_execute_prerequisite(status_path=status_path, authorization=auth)


def test_load_trial_authorization_not_write_certified(auth_paths: tuple[Path, Path]) -> None:
    config_path, status_path = auth_paths
    auth = load_gate_bc_authorization(
        config_path=config_path,
        status_path=status_path,
        now=WINDOW_OPEN + timedelta(minutes=10),
    )
    assert auth.gate_b_certification == "CertificationTrialAuthorized"
    assert auth.gate_b_status == "certification_trial_authorized"
    assert auth.gate_c_duration_seconds == 3600


def test_rejects_write_certified_in_auth(tmp_path: Path) -> None:
    payload = _auth_payload()
    gates = dict(payload["gates"])  # type: ignore[arg-type]
    gate_b = dict(gates["B"])  # type: ignore[index]
    gate_b["certification"] = "WriteCertified"
    gates["B"] = gate_b
    payload["gates"] = gates
    config_path = tmp_path / "bad.json"
    config_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(GateBCError, match="WriteCertified"):
        load_gate_bc_authorization(
            config_path=config_path,
            status_path=tmp_path / "missing.yaml",
            require_status_alignment=False,
            now=WINDOW_OPEN + timedelta(minutes=5),
        )


def test_gate_c_expired_at_load(auth_paths: tuple[Path, Path]) -> None:
    config_path, status_path = auth_paths
    with pytest.raises(GateCExpired):
        load_gate_bc_authorization(
            config_path=config_path,
            status_path=status_path,
            now=WINDOW_CLOSE + timedelta(seconds=1),
        )


def _gate_a_with_opening_freshness(
    *,
    evidence_recorded_at: datetime,
    opening_freshness_hours: int,
) -> GateACertification:
    return GateACertification(
        status="open",
        certification="ReadOnlyCertified",
        approved_scope="SLICE-4-readonly",
        model="NC-1812",
        model_display="Ultra (NC-1812)",
        firmware_version="5.01.C.1.0-0",
        firmware_display="5.1.1",
        ndm_build="0-b592e619a0",
        bsp_build="0-f371d30955",
        update_channel="Main",
        region="EA",
        component_set_digest=COMPONENT_DIGEST,
        device_fingerprint_digest=FINGERPRINT_DIGEST,
        physical_id_source="show.identification_digest",
        transport="ssh_tunnel",
        ssh_host_key_algorithm="ssh-ed25519",
        ssh_host_key_fingerprint_sha256="SHA256:example",
        certification_eligible=True,
        evidence_recorded_at=evidence_recorded_at,
        evidence_path="ignored.json",
        expires_at=evidence_recorded_at + timedelta(days=90),
        revocation_policy="test",
        opening_freshness_hours=opening_freshness_hours,
    )


def test_writes_permitted_gate_a_freshness_uses_injected_now(
    auth_paths: tuple[Path, Path],
) -> None:
    """Explicit now controls Gate A opening freshness; stale now rejects inside Gate C."""
    config_path, status_path = auth_paths
    auth = load_gate_bc_authorization(
        config_path=config_path,
        status_path=status_path,
        now=WINDOW_OPEN + timedelta(minutes=5),
    )
    evidence_recorded_at = WINDOW_OPEN - timedelta(hours=1, minutes=34, seconds=31)
    gate_a = _gate_a_with_opening_freshness(
        evidence_recorded_at=evidence_recorded_at,
        opening_freshness_hours=2,
    )
    fresh_now = WINDOW_OPEN + timedelta(minutes=5)
    stale_now = WINDOW_OPEN + timedelta(minutes=35)
    assert gate_a.is_open_at(fresh_now)
    assert not gate_a.is_open_at(stale_now)
    assert auth.gate_c_is_open(stale_now)

    auth.writes_permitted(
        gate_a=gate_a,
        capability_family="AmneziaWG",
        probe_evidence=PROBE_EVIDENCE,
        now=fresh_now,
    )
    with pytest.raises(GateBCError, match="Gate A ReadOnlyCertified is not open"):
        auth.writes_permitted(
            gate_a=gate_a,
            capability_family="AmneziaWG",
            probe_evidence=PROBE_EVIDENCE,
            now=stale_now,
        )


def test_writes_permitted_requires_open_gate_c(auth_paths: tuple[Path, Path]) -> None:
    config_path, status_path = auth_paths
    auth = load_gate_bc_authorization(
        config_path=config_path,
        status_path=status_path,
        now=WINDOW_OPEN + timedelta(minutes=5),
    )
    from router_control.adapters.netcraze.certification import GateACertification

    gate_a = GateACertification(
        status="open",
        certification="ReadOnlyCertified",
        approved_scope="SLICE-4-readonly",
        model="NC-1812",
        model_display="Ultra (NC-1812)",
        firmware_version="5.01.C.1.0-0",
        firmware_display="5.1.1",
        ndm_build="0-b592e619a0",
        bsp_build="0-f371d30955",
        update_channel="Main",
        region="EA",
        component_set_digest=COMPONENT_DIGEST,
        device_fingerprint_digest=FINGERPRINT_DIGEST,
        physical_id_source="show.identification_digest",
        transport="ssh_tunnel",
        ssh_host_key_algorithm="ssh-ed25519",
        ssh_host_key_fingerprint_sha256="SHA256:example",
        certification_eligible=True,
        evidence_recorded_at=WINDOW_OPEN,
        evidence_path="ignored.json",
        expires_at=WINDOW_OPEN + timedelta(days=90),
        revocation_policy="test",
    )
    auth.writes_permitted(
        gate_a=gate_a,
        capability_family="AmneziaWG",
        probe_evidence=PROBE_EVIDENCE,
        now=WINDOW_OPEN + timedelta(minutes=5),
    )
    with pytest.raises(GateCExpired):
        auth.writes_permitted(
            gate_a=gate_a,
            capability_family="AmneziaWG",
            probe_evidence=PROBE_EVIDENCE,
            now=WINDOW_CLOSE + timedelta(seconds=1),
        )


def test_tuple_drift_closes_writes(auth_paths: tuple[Path, Path]) -> None:
    config_path, status_path = auth_paths
    auth = load_gate_bc_authorization(
        config_path=config_path,
        status_path=status_path,
        now=WINDOW_OPEN + timedelta(minutes=5),
    )
    from router_control.adapters.netcraze.certification import GateACertification

    gate_a = GateACertification(
        status="open",
        certification="ReadOnlyCertified",
        approved_scope="SLICE-4-readonly",
        model="NC-1812",
        model_display="Ultra (NC-1812)",
        firmware_version="5.01.C.1.0-0",
        firmware_display="5.1.1",
        ndm_build="0-b592e619a0",
        bsp_build="0-f371d30955",
        update_channel="Main",
        region="EA",
        component_set_digest=COMPONENT_DIGEST,
        device_fingerprint_digest=FINGERPRINT_DIGEST,
        physical_id_source="show.identification_digest",
        transport="ssh_tunnel",
        ssh_host_key_algorithm="ssh-ed25519",
        ssh_host_key_fingerprint_sha256="SHA256:example",
        certification_eligible=True,
        evidence_recorded_at=WINDOW_OPEN,
        evidence_path="ignored.json",
        expires_at=WINDOW_OPEN + timedelta(days=90),
        revocation_policy="test",
    )
    drift = dict(PROBE_EVIDENCE)
    drift["model"] = "WRONG"
    with pytest.raises(TupleDrift):
        auth.writes_permitted(
            gate_a=gate_a,
            capability_family="AmneziaWG",
            probe_evidence=drift,
            now=WINDOW_OPEN + timedelta(minutes=5),
        )


def test_status_alignment_required(auth_paths: tuple[Path, Path]) -> None:
    config_path, status_path = auth_paths
    status_path.write_text("gates:\n  B:\n    status: closed\n", encoding="utf-8")
    with pytest.raises(GateBCError, match="STATUS.yaml does not declare"):
        load_gate_bc_authorization(
            config_path=config_path,
            status_path=status_path,
            now=WINDOW_OPEN + timedelta(minutes=5),
        )


def test_gate_d_must_stay_closed(tmp_path: Path) -> None:
    payload = _auth_payload()
    gates = dict(payload["gates"])  # type: ignore[arg-type]
    gates["D"] = {"status": "open"}
    payload["gates"] = gates
    config_path = tmp_path / "bad.json"
    config_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(GateBCError, match="Gate D"):
        load_gate_bc_authorization(
            config_path=config_path,
            require_status_alignment=False,
            now=WINDOW_OPEN + timedelta(minutes=5),
        )


def test_gate_a_certification_json_keeps_nested_gates_bcd_closed() -> None:
    config = json.loads(COMMITTED_GATE_A_CONFIG.read_text(encoding="utf-8"))
    assert config["gates"] == {
        "A": {
            "status": "open",
            "certification": "ReadOnlyCertified",
        },
        "B": {"status": "closed"},
        "C": {"status": "closed"},
        "D": {"status": "closed"},
    }


SAMPLE_AWG_PROFILE = """
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


def _gate_a_certification() -> GateACertification:
    return GateACertification(
        status="open",
        certification="ReadOnlyCertified",
        approved_scope="SLICE-4-readonly",
        model="NC-1812",
        model_display="Ultra (NC-1812)",
        firmware_version="5.01.C.1.0-0",
        firmware_display="5.1.1",
        ndm_build="0-b592e619a0",
        bsp_build="0-f371d30955",
        update_channel="Main",
        region="EA",
        component_set_digest=COMPONENT_DIGEST,
        device_fingerprint_digest=FINGERPRINT_DIGEST,
        physical_id_source="show.identification_digest",
        transport="ssh_tunnel",
        ssh_host_key_algorithm="ssh-ed25519",
        ssh_host_key_fingerprint_sha256="SHA256:example",
        certification_eligible=True,
        evidence_recorded_at=WINDOW_OPEN,
        evidence_path="ignored.json",
        expires_at=WINDOW_OPEN + timedelta(days=90),
        revocation_policy="test",
    )


def _gate_bc_authorization(tmp_path: Path) -> GateBCAuthorization:
    config_path = tmp_path / "auth.json"
    status_path = tmp_path / "STATUS.yaml"
    config_path.write_text(json.dumps(_auth_payload()), encoding="utf-8")
    status_path.write_text(_status_yaml(), encoding="utf-8")
    return load_gate_bc_authorization(
        config_path=config_path,
        status_path=status_path,
        now=WINDOW_OPEN + timedelta(minutes=10),
    )


def _register_shape(
    registry: ShapeRegistry,
    operation: TypedOperation,
    *,
    path_suffix: str | None = None,
) -> None:
    registry.register_shape(
        RegisteredShape(
            operation=operation,
            method="POST",
            path=f"/rci/example/{path_suffix or operation.value}",
            body_keys=("mode",),
            tuple_component_set_digest=COMPONENT_DIGEST,
            tuple_device_fingerprint_digest=FINGERPRINT_DIGEST,
            adapter_version="netcraze-awg-v0",
        )
    )


def _register_pre_verify_shapes(registry: ShapeRegistry) -> None:
    for operation in (
        TypedOperation.FAIL_SAFE_BEGIN,
        TypedOperation.AWG_IMPORT,
        TypedOperation.AWG_FIELD_PARITY_READBACK,
        TypedOperation.HANDSHAKE_OBSERVE,
        TypedOperation.APPLICATION_REACHABILITY_OBSERVE,
    ):
        _register_shape(registry, operation)


class RecordingHardware(AwgHardwareBoundary):
    def __init__(
        self,
        registry: ShapeRegistry,
        *,
        transport: object | None = None,
    ) -> None:
        super().__init__(registry=registry, transport=transport)  # type: ignore[arg-type]
        self.executed: list[TypedOperation] = []

    def execute(self, operation: TypedOperation | str, **kwargs: object) -> HardwareExecutionResult:
        op = TypedOperation(operation) if isinstance(operation, str) else operation
        self.executed.append(op)
        return super().execute(operation, **kwargs)  # type: ignore[arg-type]


@pytest.fixture
def runner_lab(tmp_path: Path) -> dict[str, object]:
    from router_control.adapters.secrets.memory import MemoryVault

    profile_path = tmp_path / "profile.conf"
    profile_path.write_text(SAMPLE_AWG_PROFILE, encoding="utf-8")
    auth_dir = tmp_path / "auth"
    auth_dir.mkdir()
    return {
        "gate_a": _gate_a_certification(),
        "gate_bc": _gate_bc_authorization(auth_dir),
        "vault": MemoryVault(),
        "probe_evidence": dict(PROBE_EVIDENCE),
        "profile_path": profile_path,
        "now": WINDOW_OPEN + timedelta(minutes=10),
    }


def test_runner_attempts_rollback_on_mid_candidate_shape_unknown(
    runner_lab: dict[str, object],
) -> None:
    from router_control.adapters.netcraze.awg_certification import CertificationRunner

    registry = ShapeRegistry()
    _register_shape(registry, TypedOperation.FAIL_SAFE_BEGIN)
    hardware = RecordingHardware(registry)
    runner = CertificationRunner(
        gate_a=runner_lab["gate_a"],  # type: ignore[arg-type]
        gate_bc=runner_lab["gate_bc"],  # type: ignore[arg-type]
        hardware=hardware,
        vault=runner_lab["vault"],  # type: ignore[arg-type]
        probe_evidence=runner_lab["probe_evidence"],  # type: ignore[arg-type]
        dry_run=True,
        now=runner_lab["now"],  # type: ignore[arg-type]
    )
    evidence = runner.run_profiles(
        {"keenetic50-compat": runner_lab["profile_path"]},  # type: ignore[arg-type]
        require_all_candidates=False,
    )
    outcome = evidence["candidates"][0]["outcome"]
    assert outcome["status"] == "stopped"
    assert TypedOperation.BASELINE_RESTORE.value in outcome["steps_completed"]
    assert TypedOperation.CONFIG_SAVE not in hardware.executed
    assert TypedOperation.ROUTER_REBOOT not in hardware.executed


def test_runner_skips_disruptive_tail_until_pre_verify_complete(
    runner_lab: dict[str, object],
) -> None:
    from router_control.adapters.netcraze.awg_certification import CertificationRunner

    registry = ShapeRegistry()
    _register_shape(registry, TypedOperation.FAIL_SAFE_BEGIN)
    hardware = RecordingHardware(registry)
    runner = CertificationRunner(
        gate_a=runner_lab["gate_a"],  # type: ignore[arg-type]
        gate_bc=runner_lab["gate_bc"],  # type: ignore[arg-type]
        hardware=hardware,
        vault=runner_lab["vault"],  # type: ignore[arg-type]
        probe_evidence=runner_lab["probe_evidence"],  # type: ignore[arg-type]
        dry_run=False,
        now=runner_lab["now"],  # type: ignore[arg-type]
    )
    runner.run_profiles(
        {"keenetic50-compat": runner_lab["profile_path"]},  # type: ignore[arg-type]
        require_all_candidates=False,
    )
    assert TypedOperation.CONFIG_SAVE not in hardware.executed
    assert TypedOperation.ROUTER_REBOOT not in hardware.executed


def test_runner_dry_run_never_invokes_disruptive_ops(
    runner_lab: dict[str, object],
) -> None:
    from router_control.adapters.netcraze.awg_certification import CertificationRunner

    registry = ShapeRegistry()
    _register_pre_verify_shapes(registry)
    _register_shape(registry, TypedOperation.CONFIG_SAVE)
    _register_shape(registry, TypedOperation.ROUTER_REBOOT)
    _register_shape(registry, TypedOperation.BASELINE_RESTORE)
    hardware = RecordingHardware(registry)
    runner = CertificationRunner(
        gate_a=runner_lab["gate_a"],  # type: ignore[arg-type]
        gate_bc=runner_lab["gate_bc"],  # type: ignore[arg-type]
        hardware=hardware,
        vault=runner_lab["vault"],  # type: ignore[arg-type]
        probe_evidence=runner_lab["probe_evidence"],  # type: ignore[arg-type]
        dry_run=True,
        now=runner_lab["now"],  # type: ignore[arg-type]
    )
    evidence = runner.run_profiles(
        {"keenetic50-compat": runner_lab["profile_path"]},  # type: ignore[arg-type]
        require_all_candidates=False,
    )
    assert TypedOperation.CONFIG_SAVE not in hardware.executed
    assert TypedOperation.ROUTER_REBOOT not in hardware.executed
    assert evidence["runner_status"] == "stopped"


def test_runner_stops_without_next_candidate_after_failure(
    runner_lab: dict[str, object],
    tmp_path: Path,
) -> None:
    from router_control.adapters.netcraze.awg_certification import CertificationRunner

    second_profile = tmp_path / "second.conf"
    second_profile.write_text(SAMPLE_AWG_PROFILE, encoding="utf-8")
    hardware = RecordingHardware(ShapeRegistry())
    runner = CertificationRunner(
        gate_a=runner_lab["gate_a"],  # type: ignore[arg-type]
        gate_bc=runner_lab["gate_bc"],  # type: ignore[arg-type]
        hardware=hardware,
        vault=runner_lab["vault"],  # type: ignore[arg-type]
        probe_evidence=runner_lab["probe_evidence"],  # type: ignore[arg-type]
        dry_run=True,
        now=runner_lab["now"],  # type: ignore[arg-type]
    )
    evidence = runner.run_profiles(
        {
            "keenetic50-compat": runner_lab["profile_path"],  # type: ignore[arg-type]
            "fi-ip": second_profile,
        },
        require_all_candidates=False,
    )
    assert len(evidence["candidates"]) == 1
    assert evidence["stopped_candidate"] == "keenetic50-compat"


def test_runner_post_reboot_verify_fail_closed_without_transport(
    runner_lab: dict[str, object],
) -> None:
    from router_control.adapters.netcraze.awg_certification import CertificationRunner

    registry = ShapeRegistry()
    _register_pre_verify_shapes(registry)
    _register_shape(registry, TypedOperation.CONFIG_SAVE)
    _register_shape(registry, TypedOperation.ROUTER_REBOOT)
    hardware = RecordingHardware(registry)
    runner = CertificationRunner(
        gate_a=runner_lab["gate_a"],  # type: ignore[arg-type]
        gate_bc=runner_lab["gate_bc"],  # type: ignore[arg-type]
        hardware=hardware,
        vault=runner_lab["vault"],  # type: ignore[arg-type]
        probe_evidence=runner_lab["probe_evidence"],  # type: ignore[arg-type]
        dry_run=False,
        now=runner_lab["now"],  # type: ignore[arg-type]
    )
    evidence = runner.run_profiles(
        {"keenetic50-compat": runner_lab["profile_path"]},  # type: ignore[arg-type]
        require_all_candidates=False,
    )
    outcome = evidence["candidates"][0]["outcome"]
    assert outcome["status"] != "passed"
    assert outcome["status"] in {"stopped", "gate_bc_error"}
    assert evidence.get("runner_status") != "all_candidates_passed"
    assert TypedOperation.CONFIG_SAVE not in hardware.executed
    assert TypedOperation.ROUTER_REBOOT not in hardware.executed


def test_runner_tuple_drift_attempts_rollback(runner_lab: dict[str, object]) -> None:
    from router_control.adapters.netcraze.awg_certification import CertificationRunner

    class _StubTransport:
        def execute_shape(
            self,
            *,
            method: str,
            path: str,
            body_keys: tuple[str, ...],
        ) -> dict[str, object]:
            return {"status": "executed"}

    registry = ShapeRegistry()
    _register_shape(registry, TypedOperation.FAIL_SAFE_BEGIN)
    _register_shape(registry, TypedOperation.AWG_IMPORT)
    _register_shape(registry, TypedOperation.BASELINE_RESTORE)
    hardware = RecordingHardware(registry, transport=_StubTransport())  # type: ignore[arg-type]

    def execute_with_drift(
        operation: TypedOperation | str,
        **kwargs: object,
    ) -> HardwareExecutionResult:
        op = TypedOperation(operation) if isinstance(operation, str) else operation
        hardware.executed.append(op)
        if op == TypedOperation.AWG_IMPORT:
            raise TupleDrift("simulated tuple drift during import")
        return AwgHardwareBoundary.execute(hardware, operation, **kwargs)  # type: ignore[arg-type]

    hardware.execute = execute_with_drift  # type: ignore[method-assign]
    runner = CertificationRunner(
        gate_a=runner_lab["gate_a"],  # type: ignore[arg-type]
        gate_bc=runner_lab["gate_bc"],  # type: ignore[arg-type]
        hardware=hardware,
        vault=runner_lab["vault"],  # type: ignore[arg-type]
        probe_evidence=runner_lab["probe_evidence"],  # type: ignore[arg-type]
        dry_run=False,
        now=runner_lab["now"],  # type: ignore[arg-type]
    )
    evidence = runner.run_profiles(
        {"keenetic50-compat": runner_lab["profile_path"]},  # type: ignore[arg-type]
        require_all_candidates=False,
    )
    outcome = evidence["candidates"][0]["outcome"]
    assert outcome["status"] == "tuple_drift"
    assert TypedOperation.BASELINE_RESTORE.value in outcome["steps_completed"]
    assert outcome["rollback_status"] in {"succeeded", "failed"}


def test_runner_gate_bc_error_after_mutation_attempts_rollback(
    runner_lab: dict[str, object],
) -> None:
    from router_control.adapters.netcraze.awg_certification import CertificationRunner

    class _StubTransport:
        def execute_shape(
            self,
            *,
            method: str,
            path: str,
            body_keys: tuple[str, ...],
        ) -> dict[str, object]:
            return {"status": "executed"}

    registry = ShapeRegistry()
    _register_shape(registry, TypedOperation.FAIL_SAFE_BEGIN)
    _register_shape(registry, TypedOperation.AWG_IMPORT)
    _register_shape(registry, TypedOperation.BASELINE_RESTORE)
    hardware = RecordingHardware(registry, transport=_StubTransport())  # type: ignore[arg-type]

    def execute_with_gate_bc_error(
        operation: TypedOperation | str,
        **kwargs: object,
    ) -> HardwareExecutionResult:
        op = TypedOperation(operation) if isinstance(operation, str) else operation
        hardware.executed.append(op)
        if op == TypedOperation.AWG_IMPORT:
            raise GateBCError("simulated GateBCError during import")
        return AwgHardwareBoundary.execute(hardware, operation, **kwargs)  # type: ignore[arg-type]

    hardware.execute = execute_with_gate_bc_error  # type: ignore[method-assign]
    runner = CertificationRunner(
        gate_a=runner_lab["gate_a"],  # type: ignore[arg-type]
        gate_bc=runner_lab["gate_bc"],  # type: ignore[arg-type]
        hardware=hardware,
        vault=runner_lab["vault"],  # type: ignore[arg-type]
        probe_evidence=runner_lab["probe_evidence"],  # type: ignore[arg-type]
        dry_run=False,
        now=runner_lab["now"],  # type: ignore[arg-type]
    )
    evidence = runner.run_profiles(
        {"keenetic50-compat": runner_lab["profile_path"]},  # type: ignore[arg-type]
        require_all_candidates=False,
    )
    outcome = evidence["candidates"][0]["outcome"]
    assert outcome["status"] == "gate_bc_error"
    assert outcome["error_type"] == "GateBCError"
    assert TypedOperation.BASELINE_RESTORE.value in outcome["steps_completed"]
    assert outcome["rollback_status"] == "succeeded"


def test_runner_failed_rollback_recorded_on_candidate_outcome(
    runner_lab: dict[str, object],
) -> None:
    from router_control.adapters.netcraze.awg_certification import CertificationRunner

    registry = ShapeRegistry()
    _register_shape(registry, TypedOperation.FAIL_SAFE_BEGIN)
    _register_shape(registry, TypedOperation.AWG_IMPORT)
    _register_shape(registry, TypedOperation.BASELINE_RESTORE)
    hardware = RecordingHardware(registry)

    def execute_with_stop_on_rollback(
        operation: TypedOperation | str,
        **kwargs: object,
    ) -> HardwareExecutionResult:
        op = TypedOperation(operation) if isinstance(operation, str) else operation
        hardware.executed.append(op)
        if op == TypedOperation.AWG_IMPORT:
            raise GateBCError("simulated GateBCError during import")
        if op == TypedOperation.BASELINE_RESTORE:
            raise GateBCError("simulated rollback failure")
        return AwgHardwareBoundary.execute(hardware, operation, **kwargs)  # type: ignore[arg-type]

    hardware.execute = execute_with_stop_on_rollback  # type: ignore[method-assign]
    runner = CertificationRunner(
        gate_a=runner_lab["gate_a"],  # type: ignore[arg-type]
        gate_bc=runner_lab["gate_bc"],  # type: ignore[arg-type]
        hardware=hardware,
        vault=runner_lab["vault"],  # type: ignore[arg-type]
        probe_evidence=runner_lab["probe_evidence"],  # type: ignore[arg-type]
        dry_run=False,
        now=runner_lab["now"],  # type: ignore[arg-type]
    )
    evidence = runner.run_profiles(
        {"keenetic50-compat": runner_lab["profile_path"]},  # type: ignore[arg-type]
        require_all_candidates=False,
    )
    outcome = evidence["candidates"][0]["outcome"]
    assert outcome["rollback_status"] == "failed"
    assert CandidatePhase.ROLLBACK.value in outcome["steps_completed"]
