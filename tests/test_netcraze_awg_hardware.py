"""AWG hardware boundary tests — typed ops, empty registry fail-closed."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from router_control.adapters.netcraze.awg_hardware import (
    TYPED_OPERATIONS,
    AwgHardwareBoundary,
    CommandShapeUnknown,
    RegisteredShape,
    ShapeRegistry,
    TypedOperation,
)
from router_control.adapters.netcraze.certification import GateACertification
from router_control.adapters.netcraze.gate_bc import (
    GateBCAuthorization,
    GateBCError,
    GateBCTupleBinding,
)
from router_control.adapters.netcraze.typed_executor import SharedTypedOperationExecutor

COMPONENT_DIGEST = "sha256:de72a7af2255a1993c382ffd41143b8061525137b0d8e192811a32babf852f2f"
FINGERPRINT_DIGEST = "sha256:eb58946c0d18b3cb259c2687e474d10907dfdbbcf39c88992202917c37855169"
NOW = datetime(2026, 7, 21, 20, 40, 0, tzinfo=UTC)


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
        evidence_recorded_at=NOW - timedelta(hours=1),
        evidence_path="ignored.json",
        expires_at=NOW + timedelta(days=90),
        revocation_policy="test",
    )


def _gate_bc() -> GateBCAuthorization:
    opens = datetime(2026, 7, 21, 20, 34, 31, tzinfo=UTC)
    return GateBCAuthorization(
        contract_id="gate-bc-awg-certification-20260721",
        human_decision="approve",
        authorization_recorded_at=opens,
        gate_b_status="certification_trial_authorized",
        gate_b_certification="CertificationTrialAuthorized",
        capability_family="AmneziaWG",
        approved_scope="lab_awg_only",
        gate_c_status="open",
        gate_c_opens_at=opens,
        gate_c_expires_at=opens + timedelta(seconds=3600),
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


def test_allowlist_size() -> None:
    assert len(TYPED_OPERATIONS) == 9


def test_empty_registry_fails_closed() -> None:
    hardware = AwgHardwareBoundary()
    assert len(hardware.registry) == 0
    with pytest.raises(CommandShapeUnknown):
        hardware.execute(
            TypedOperation.FAIL_SAFE_BEGIN,
            gate_a=_gate_a(),
            gate_bc=_gate_bc(),
            probe_evidence=_probe_evidence(),
            now=NOW,
        )


def test_no_generic_executor_surface() -> None:
    hardware = AwgHardwareBoundary()
    forbidden = ("execute_rci", "raw_rci", "send_command")
    for name in forbidden:
        assert not hasattr(hardware, name)


def test_execute_gate_a_freshness_uses_injected_now() -> None:
    """Hardware boundary rejects stale Gate A freshness via explicit now, not wall clock."""
    opens = datetime(2026, 7, 21, 20, 34, 31, tzinfo=UTC)
    evidence_recorded_at = opens - timedelta(hours=1, minutes=34, seconds=31)
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
        evidence_recorded_at=evidence_recorded_at,
        evidence_path="ignored.json",
        expires_at=evidence_recorded_at + timedelta(days=90),
        revocation_policy="test",
        opening_freshness_hours=2,
    )
    gate_bc = _gate_bc()
    fresh_now = opens + timedelta(minutes=5)
    stale_now = opens + timedelta(minutes=35)
    assert gate_a.is_open_at(fresh_now)
    assert not gate_a.is_open_at(stale_now)
    assert gate_bc.gate_c_is_open(stale_now)

    registry = ShapeRegistry()
    registry.register_shape(
        RegisteredShape(
            operation=TypedOperation.FAIL_SAFE_BEGIN,
            method="POST",
            path="/rci/example/fail-safe/begin",
            body_keys=("mode",),
            tuple_component_set_digest=COMPONENT_DIGEST,
            tuple_device_fingerprint_digest=FINGERPRINT_DIGEST,
            adapter_version="netcraze-awg-v0",
        )
    )

    class _StubTransport:
        def execute_shape(
            self,
            *,
            method: str,
            path: str,
            body_keys: tuple[str, ...],
        ) -> dict[str, object]:
            return {"status": "executed"}

    hardware = AwgHardwareBoundary(registry=registry, transport=_StubTransport())  # type: ignore[arg-type]
    hardware.execute(
        TypedOperation.FAIL_SAFE_BEGIN,
        gate_a=gate_a,
        gate_bc=gate_bc,
        probe_evidence=_probe_evidence(),
        now=fresh_now,
    )
    with pytest.raises(GateBCError, match="Gate A ReadOnlyCertified is not open"):
        hardware.execute(
            TypedOperation.FAIL_SAFE_BEGIN,
            gate_a=gate_a,
            gate_bc=gate_bc,
            probe_evidence=_probe_evidence(),
            now=stale_now,
        )


def test_gate_check_before_shape_lookup() -> None:
    hardware = AwgHardwareBoundary()
    expired = NOW + timedelta(hours=2)
    with pytest.raises(Exception, match="Gate C|expired"):
        hardware.execute(
            TypedOperation.AWG_IMPORT,
            gate_a=_gate_a(),
            gate_bc=_gate_bc(),
            probe_evidence=_probe_evidence(),
            now=expired,
        )


def test_missing_transport_fails_closed() -> None:
    registry = ShapeRegistry()
    gate_a = _gate_a()
    registry.register_shape(
        RegisteredShape(
            operation=TypedOperation.FAIL_SAFE_BEGIN,
            method="POST",
            path="/rci/example/fail-safe/begin",
            body_keys=("mode",),
            tuple_component_set_digest=COMPONENT_DIGEST,
            tuple_device_fingerprint_digest=FINGERPRINT_DIGEST,
            adapter_version="netcraze-awg-v0",
        )
    )
    hardware = AwgHardwareBoundary(registry=registry)
    with pytest.raises(Exception, match="active transport required"):
        hardware.execute(
            TypedOperation.FAIL_SAFE_BEGIN,
            gate_a=gate_a,
            gate_bc=_gate_bc(),
            probe_evidence=_probe_evidence(),
            now=NOW,
        )


def test_sanitized_shape_registration_no_secrets() -> None:
    registry = ShapeRegistry()
    gate_a = _gate_a()
    artifact = {
        "operation": "fail_safe_begin",
        "method": "POST",
        "path": "/rci/example/fail-safe/begin",
        "body_keys": ["mode", "timeout"],
        "tuple_component_set_digest": COMPONENT_DIGEST,
        "tuple_device_fingerprint_digest": FINGERPRINT_DIGEST,
    }
    shape = registry.register_from_discovery_artifact(
        artifact,
        gate_a=gate_a,
        adapter_version="netcraze-awg-v0",
    )
    encoded = json.dumps(shape.sanitized_dict())
    assert "password" not in encoded.lower()
    assert "privatekey" not in encoded.lower()


def test_observe_operations_route_through_shared_executor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = ShapeRegistry()
    for operation in (
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

    calls: list[str] = []
    original = SharedTypedOperationExecutor.execute_certification

    def tracking_execute(self, registered, **kwargs):  # type: ignore[no-untyped-def]
        calls.append(registered.spec.operation_id)
        return original(self, registered, **kwargs)

    monkeypatch.setattr(
        SharedTypedOperationExecutor,
        "execute_certification",
        tracking_execute,
    )

    class _StubTransport:
        def execute_shape(
            self,
            *,
            method: str,
            path: str,
            body_keys: tuple[str, ...],
        ) -> dict[str, object]:
            return {"status": "executed"}

    hardware = AwgHardwareBoundary(registry=registry, transport=_StubTransport())  # type: ignore[arg-type]
    for operation in (
        TypedOperation.AWG_FIELD_PARITY_READBACK,
        TypedOperation.HANDSHAKE_OBSERVE,
        TypedOperation.APPLICATION_REACHABILITY_OBSERVE,
    ):
        hardware.execute(
            operation,
            gate_a=_gate_a(),
            gate_bc=_gate_bc(),
            probe_evidence=_probe_evidence(),
            now=NOW,
        )
    assert calls == [
        "awg_field_parity_readback",
        "handshake_observe",
        "application_reachability_observe",
    ]


def test_poll_continuation_missing_response_fails_closed() -> None:
    from router_control.adapters.netcraze.awg_hardware import ShapeHttpTransport
    from router_control.adapters.netcraze.codec import ContinuationToken
    from router_control.adapters.netcraze.typed_executor import ExecutorError

    class _StubTransport:
        def execute_shape(self, *, method: str, path: str, body_keys: tuple[str, ...]) -> dict:
            return {"continued": True, "continuation_token": "tok-1"}

    shape = RegisteredShape(
        operation=TypedOperation.AWG_IMPORT,
        method="POST",
        path="/rci/amnezia/import",
        body_keys=("profile_fields", "credential_refs"),
        tuple_component_set_digest=COMPONENT_DIGEST,
        tuple_device_fingerprint_digest=FINGERPRINT_DIGEST,
        adapter_version="netcraze-awg-v0",
    )
    transport = ShapeHttpTransport(
        transport=_StubTransport(),  # type: ignore[arg-type]
        shape=shape,
        wire_endpoint_identifier="/rci/amnezia/import",
    )
    with pytest.raises(ExecutorError, match="poll response missing"):
        transport.poll_continuation(
            token=ContinuationToken(token="tok-1", poll_spec_id="poll", round_index=0)
        )
