"""AWG certification runner fail-closed tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from router_control.adapters.netcraze.awg_certification import (
    CAPABILITY_FAMILY,
    CertificationRunner,
)
from router_control.adapters.netcraze.awg_hardware import (
    DISRUPTIVE_TAIL,
    AwgHardwareBoundary,
    HardwareExecutionResult,
    RegisteredShape,
    ShapeRegistry,
    TypedOperation,
)
from router_control.adapters.netcraze.awg_profile import parse_awg_profile_path
from router_control.adapters.netcraze.certification import GateACertification
from router_control.adapters.netcraze.gate_bc import GateBCAuthorization, GateBCTupleBinding
from router_control.adapters.secrets.memory import MemoryVault

COMPONENT_DIGEST = "sha256:de72a7af2255a1993c382ffd41143b8061525137b0d8e192811a32babf852f2f"
FINGERPRINT_DIGEST = "sha256:eb58946c0d18b3cb259c2687e474d10907dfdbbcf39c88992202917c37855169"
WINDOW_OPEN = datetime(2026, 7, 21, 20, 34, 31, tzinfo=UTC)
NOW = WINDOW_OPEN + timedelta(minutes=10)

SAMPLE_AWG_PROFILE = """
[Interface]
PrivateKey = EXAMPLE_PRIVATE_KEY_PLACEHOLDER_AAAAAAAAAAAAAAAAAAAAAAAA
Address = 10.0.0.2/32

[Peer]
PublicKey = EXAMPLE_PUBLIC_KEY_PLACEHOLDER_BBBBBBBBBBBBBBBBBBBBBBBBBBBB
Endpoint = EXAMPLE_ENDPOINT:51820
AllowedIPs = 0.0.0.0/0
"""


class VerifiedTransport:
    def execute_shape(
        self,
        *,
        method: str,
        path: str,
        body_keys: tuple[str, ...],
    ) -> dict[str, Any]:
        return {"status": "executed"}


class MockAwgHardware(AwgHardwareBoundary):
    def __init__(self, registry: ShapeRegistry, *, profile_digest: str) -> None:
        super().__init__(registry=registry, transport=VerifiedTransport())
        self.profile_digest = profile_digest
        self.executed: list[TypedOperation] = []

    def execute(self, operation: TypedOperation | str, **kwargs: object) -> HardwareExecutionResult:
        op = TypedOperation(operation) if isinstance(operation, str) else operation
        if op in DISRUPTIVE_TAIL or op == TypedOperation.BASELINE_RESTORE:
            return super().execute(operation, **kwargs)  # type: ignore[arg-type]
        self.executed.append(op)
        base = {
            "operation": op.value,
            "profile_encoding_used": True,
            "profile_digest": self.profile_digest,
            "read_back_verified": True,
            "handshake_verified": True,
            "application_reachability_verified": True,
        }
        if op == TypedOperation.HANDSHAKE_OBSERVE:
            return HardwareExecutionResult(
                operation=op,
                status="handshake_verified",
                sanitized={**base, "handshake_verified": True},
            )
        if op == TypedOperation.APPLICATION_REACHABILITY_OBSERVE:
            return HardwareExecutionResult(
                operation=op,
                status="reachability_verified",
                sanitized={**base, "application_reachability_verified": True},
            )
        if op == TypedOperation.AWG_FIELD_PARITY_READBACK:
            return HardwareExecutionResult(
                operation=op,
                status="read_back_verified",
                sanitized={**base, "read_back_verified": True},
            )
        if op == TypedOperation.AWG_IMPORT:
            return HardwareExecutionResult(
                operation=op,
                status="import_verified",
                sanitized={
                    **base,
                    "profile_encoding_used": True,
                    "profile_digest": self.profile_digest,
                },
            )
        return HardwareExecutionResult(
            operation=op,
            status="passed",
            sanitized=base,
        )


def _gate_a() -> GateACertification:
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


def _gate_bc() -> GateBCAuthorization:
    return GateBCAuthorization(
        contract_id="gate-bc-awg-certification-20260721",
        human_decision="approve",
        authorization_recorded_at=WINDOW_OPEN,
        gate_b_status="certification_trial_authorized",
        gate_b_certification="CertificationTrialAuthorized",
        capability_family="AmneziaWG",
        approved_scope="lab_awg_only",
        gate_c_status="open",
        gate_c_opens_at=WINDOW_OPEN,
        gate_c_expires_at=WINDOW_OPEN + timedelta(seconds=3600),
        gate_d_status="closed",
        tuple_binding=GateBCTupleBinding(
            model="NC-1812",
            firmware_version="5.01.C.1.0-0",
            ndm_build="0-b592e619a0",
            bsp_build="0-f371d30955",
            update_channel="Main",
            region="EA",
            component_set_digest=COMPONENT_DIGEST,
            device_fingerprint_digest=FINGERPRINT_DIGEST,
            transport="ssh_tunnel",
            ssh_host_key_algorithm="ssh-ed25519",
        ),
        candidate_order=("keenetic50-compat", "fi-ip", "de-ip"),
        write_shapes_registered=False,
    )


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
    }


def _register_pre_verify_shapes(registry: ShapeRegistry) -> None:
    for operation in (
        TypedOperation.FAIL_SAFE_BEGIN,
        TypedOperation.AWG_IMPORT,
        TypedOperation.AWG_FIELD_PARITY_READBACK,
        TypedOperation.HANDSHAKE_OBSERVE,
        TypedOperation.APPLICATION_REACHABILITY_OBSERVE,
    ):
        registry.register_shape(
            RegisteredShape(
                operation=operation,
                method="POST",
                path=f"/rci/example/{operation.value}",
                body_keys=("mode",),
                tuple_component_set_digest=COMPONENT_DIGEST,
                tuple_device_fingerprint_digest=FINGERPRINT_DIGEST,
                adapter_version="netcraze-awg-v0",
            )
        )


@pytest.fixture
def profile_path(tmp_path: Path) -> Path:
    path = tmp_path / "profile.conf"
    path.write_text(SAMPLE_AWG_PROFILE, encoding="utf-8")
    return path


def test_dry_run_stops_without_success_shaped_execute(profile_path: Path) -> None:
    registry = ShapeRegistry()
    _register_pre_verify_shapes(registry)
    parsed = parse_awg_profile_path(profile_path, vault=MemoryVault())
    hardware = MockAwgHardware(registry, profile_digest=parsed.profile_digest)
    runner = CertificationRunner(
        gate_a=_gate_a(),
        gate_bc=_gate_bc(),
        hardware=hardware,
        vault=MemoryVault(),
        probe_evidence=_probe_evidence(),
        dry_run=True,
        now=NOW,
    )
    evidence = runner.run_profiles(
        {"keenetic50-compat": profile_path},
        require_all_candidates=False,
    )
    assert evidence["runner_status"] == "stopped"
    assert evidence["candidates"][0]["outcome"]["status"] == "stopped"
    assert TypedOperation.CONFIG_SAVE not in hardware.executed


def test_live_path_cannot_pass_without_handshake_verification(profile_path: Path) -> None:
    registry = ShapeRegistry()
    _register_pre_verify_shapes(registry)
    parsed = parse_awg_profile_path(profile_path, vault=MemoryVault())

    class IncompleteHardware(MockAwgHardware):
        def execute(
            self, operation: TypedOperation | str, **kwargs: object
        ) -> HardwareExecutionResult:
            op = TypedOperation(operation) if isinstance(operation, str) else operation
            if op == TypedOperation.HANDSHAKE_OBSERVE:
                return HardwareExecutionResult(
                    operation=op,
                    status="observed_only",
                    sanitized={"handshake_verified": False},
                )
            return super().execute(operation, **kwargs)

    hardware = IncompleteHardware(registry, profile_digest=parsed.profile_digest)
    runner = CertificationRunner(
        gate_a=_gate_a(),
        gate_bc=_gate_bc(),
        hardware=hardware,
        vault=MemoryVault(),
        probe_evidence=_probe_evidence(),
        dry_run=False,
        now=NOW,
    )
    evidence = runner.run_profiles(
        {"keenetic50-compat": profile_path},
        require_all_candidates=False,
    )
    assert evidence["candidates"][0]["outcome"]["status"] == "stopped"
    assert evidence["write_certified_claim"] is False


def test_live_pre_verify_with_full_verification_does_not_claim_passed(
    profile_path: Path,
) -> None:
    registry = ShapeRegistry()
    _register_pre_verify_shapes(registry)
    parsed = parse_awg_profile_path(profile_path, vault=MemoryVault())
    hardware = MockAwgHardware(registry, profile_digest=parsed.profile_digest)
    runner = CertificationRunner(
        gate_a=_gate_a(),
        gate_bc=_gate_bc(),
        hardware=hardware,
        vault=MemoryVault(),
        probe_evidence=_probe_evidence(),
        dry_run=False,
        now=NOW,
    )
    evidence = runner.run_profiles(
        {"keenetic50-compat": profile_path},
        require_all_candidates=False,
    )
    outcome = evidence["candidates"][0]["outcome"]
    assert outcome["status"] != "passed"
    assert evidence.get("runner_status") != "all_candidates_passed"
    assert evidence["write_certified_claim"] is False
    assert evidence["capability_family"] == CAPABILITY_FAMILY


def test_passed_outcome_includes_compensation_verification_evidence(
    profile_path: Path,
) -> None:
    registry = ShapeRegistry()
    _register_pre_verify_shapes(registry)
    for operation in (
        TypedOperation.CONFIG_SAVE,
        TypedOperation.ROUTER_REBOOT,
        TypedOperation.BASELINE_RESTORE,
    ):
        registry.register_shape(
            RegisteredShape(
                operation=operation,
                method="POST",
                path=f"/rci/example/{operation.value}",
                body_keys=("mode",),
                tuple_component_set_digest=COMPONENT_DIGEST,
                tuple_device_fingerprint_digest=FINGERPRINT_DIGEST,
                adapter_version="netcraze-awg-v0",
            )
        )
    parsed = parse_awg_profile_path(profile_path, vault=MemoryVault())
    hardware = MockAwgHardware(registry, profile_digest=parsed.profile_digest)
    runner = CertificationRunner(
        gate_a=_gate_a(),
        gate_bc=_gate_bc(),
        hardware=hardware,
        vault=MemoryVault(),
        probe_evidence=_probe_evidence(),
        dry_run=False,
        now=NOW,
    )
    evidence = runner.run_profiles(
        {"keenetic50-compat": profile_path},
        require_all_candidates=False,
    )
    outcome = evidence["candidates"][0]["outcome"]
    if outcome["status"] == "passed":
        compensation = outcome["compensation_evidence"]
        assert compensation["compensation_verified"] is True
        assert compensation["verification_method"] == (
            "post_reboot_verify_with_gate_bc_recertification"
        )
        assert evidence["runner_status"] == "all_candidates_passed"
    else:
        compensation = outcome.get("compensation_evidence") or {}
        assert not (
            compensation.get("compensation_required") is False
            and outcome["status"] == "passed"
        )


def test_pass_compensation_evidence_rejects_incomplete_verify() -> None:
    runner = CertificationRunner(
        gate_a=_gate_a(),
        gate_bc=_gate_bc(),
        hardware=MockAwgHardware(ShapeRegistry(), profile_digest="sha256:example"),
        vault=MemoryVault(),
        probe_evidence=_probe_evidence(),
        dry_run=False,
        now=NOW,
    )
    with pytest.raises(Exception, match="compensation"):
        runner._pass_compensation_evidence(
            completed=["post_reboot_verify"],
            verify_step={"status": "observed_only", "checks": []},
        )
