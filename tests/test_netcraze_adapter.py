"""Netcraze read-only adapter port tests (mocked transport)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import pytest
from router_control.adapters.netcraze.adapter import NetcrazeReadOnlyAdapter, build_router_identity
from router_control.adapters.netcraze.allowlist import (
    COMPONENTS_LIST,
    SHOW_IDENTIFICATION,
    SHOW_SYSTEM,
    SHOW_VERSION,
)
from router_control.adapters.netcraze.errors import IdentityParseError, NetcrazeAdapterError
from router_control.adapters.netcraze.identity import parse_identity
from router_control.adapters.netcraze.operation_spec import (
    SYNTHETIC_REGISTERED_OPERATIONS,
    build_registered_operation,
)
from router_control.adapters.netcraze.shape_registry import (
    CertifiedOperationRegistry,
    LabObservedEvidence,
    OperationPromotionRegistry,
    ShapePromotionState,
    promote_through_pipeline,
)
from router_control.adapters.netcraze.transport import NetcrazeTransport
from router_control.adapters.netcraze.typed_executor import (
    LiveMutationPolicy,
    SharedTypedOperationExecutor,
)
from router_control.domain.entities import BackupArtifact, ChangePlan, ChangePlanItem
from router_control.domain.enums import CertificationStatus, PlanConfirmationState
from router_control.domain.errors import IdentityMismatch, MutationForbidden
from router_control.domain.ids import (
    ArtifactId,
    ObservationId,
    OperationId,
    PlanId,
    ResourceId,
    RevisionId,
    RouterId,
)
from router_control.ports.router_control import ReadBackResult

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "netcraze"


def _lab_evidence(operation: object) -> LabObservedEvidence:
    op = operation  # RegisteredOperation from synthetic fixtures
    return LabObservedEvidence(
        tuple_component_set_digest=op.tuple_component_set_digest,
        tuple_device_fingerprint_digest=op.tuple_device_fingerprint_digest,
        gate_a_evidence_digest=op.gate_a_evidence_digest,
        evidence_digest=op.evidence_digest,
        trial_authorized=True,
        artifact_digest_verified=True,
    )


def _candidate_from_lab(lab: object) -> object:
    return build_registered_operation(
        lab.spec,
        promotion_state=ShapePromotionState.CANDIDATE.value,
        tuple_component_set_digest=lab.tuple_component_set_digest,
        tuple_device_fingerprint_digest=lab.tuple_device_fingerprint_digest,
        gate_a_evidence_digest=lab.gate_a_evidence_digest,
        adapter_version=lab.adapter_version,
        evidence_digest=lab.evidence_digest,
    )


@dataclass
class RecordingTransport(NetcrazeTransport):
    fetch_calls: list[str] = field(default_factory=list)

    def fetch_allowlisted(self, command, body=None):  # type: ignore[no-untyped-def]
        self.fetch_calls.append(command.name)
        system = json.loads((FIXTURES / "system.json").read_text(encoding="utf-8"))
        components = json.loads((FIXTURES / "components_list.json").read_text(encoding="utf-8"))
        if command is SHOW_SYSTEM:
            return system
        if command is COMPONENTS_LIST:
            return components
        if command is SHOW_IDENTIFICATION:
            return {}
        if command is SHOW_VERSION:
            return {}
        raise AssertionError("unexpected command")


class FixedClock:
    def now(self) -> datetime:
        return datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC)


def _parsed_identity():
    system = json.loads((FIXTURES / "system.json").read_text(encoding="utf-8"))
    components = json.loads((FIXTURES / "components_list.json").read_text(encoding="utf-8"))
    return parse_identity(system, components)


def _adapter() -> tuple[NetcrazeReadOnlyAdapter, RecordingTransport]:
    transport = RecordingTransport(host="192.168.1.1", username="admin", password="secret")
    adapter = NetcrazeReadOnlyAdapter(
        router_id=RouterId("router-lab-001"),
        transport=transport,
        clock=FixedClock(),
    )
    return adapter, transport


@pytest.mark.asyncio
async def test_check_identity_match_and_mismatch() -> None:
    adapter, _ = _adapter()
    parsed = _parsed_identity()
    expected = build_router_identity(parsed, RouterId("router-lab-001"))
    result = await adapter.check_identity(expected)
    assert result.matched is True
    assert result.observed_fingerprint_digest == parsed.fingerprint_digest

    wrong = build_router_identity(parsed, RouterId("router-lab-001"))
    wrong = wrong.__class__(
        router_id=wrong.router_id,
        vendor=wrong.vendor,
        model=wrong.model,
        fingerprint_digest="sha256:deadbeef",
    )
    with pytest.raises(IdentityMismatch):
        await adapter.check_identity(wrong)


@pytest.mark.asyncio
async def test_fingerprint_stable_for_same_fixture() -> None:
    first = _parsed_identity()
    second = _parsed_identity()
    assert first.fingerprint_digest == second.fingerprint_digest


@pytest.mark.asyncio
async def test_get_capabilities_observed_unknown_not_certified() -> None:
    adapter, transport = _adapter()
    cap = await adapter.get_capabilities(RouterId("router-lab-001"))
    assert cap.certification_status is CertificationStatus.UNKNOWN
    assert cap.firmware_digest == _parsed_identity().firmware_digest
    assert transport.fetch_calls == [
        "show_system",
        "components_list",
        "show_identification",
        "show_version",
    ]


@pytest.mark.asyncio
async def test_load_identity_fetch_order() -> None:
    adapter, transport = _adapter()
    adapter._load_identity()
    assert transport.fetch_calls == [
        "show_system",
        "components_list",
        "show_identification",
        "show_version",
    ]


@pytest.mark.asyncio
async def test_observe_returns_digests_only() -> None:
    adapter, _ = _adapter()
    obs = await adapter.observe(RouterId("router-lab-001"))
    parsed = _parsed_identity()
    assert obs.identity_fingerprint_digest == parsed.fingerprint_digest
    assert obs.state_digest == parsed.component_set_digest


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "method_name",
    [
        "create_backup",
        "begin_fail_safe",
        "apply_plan",
        "read_back",
        "verify_postconditions",
        "save_configuration",
        "compensate",
    ],
)
async def test_mutations_raise_without_transport(method_name: str) -> None:
    adapter, transport = _adapter()
    transport.fetch_calls.clear()
    method = getattr(adapter, method_name)
    plan = ChangePlan(
        plan_id=PlanId("plan-001"),
        router_id=RouterId("router-lab-001"),
        revision_id=RevisionId("rev-001"),
        observation_id=ObservationId("obs-001"),
        expected_desired_digest="digest:desired:001",
        observed_resource_version="digest:rv:001",
        items=(ChangePlanItem(ResourceId("res-001"), "intent", "digest:intent:001"),),
        confirmation_state=PlanConfirmationState.CONFIRMED,
        expires_at=datetime(2026, 7, 21, 13, 0, 0, tzinfo=UTC),
        created_at=datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC),
        actor="test",
    )
    with pytest.raises(MutationForbidden):
        if method_name == "create_backup":
            await method(RouterId("router-lab-001"), OperationId("op-001"))
        elif method_name == "begin_fail_safe":
            await method(RouterId("router-lab-001"))
        elif method_name == "apply_plan":
            await method(plan)
        elif method_name == "read_back":
            await method(RouterId("router-lab-001"), PlanId("plan-001"))
        elif method_name == "verify_postconditions":
            read_back = ReadBackResult(
                plan_id=PlanId("plan-001"),
                state_digest="digest:state:001",
                resource_version="digest:rv:001",
                identity_fingerprint_digest="sha256:abc",
                outcome_known=True,
            )
            await method(plan, read_back)
        elif method_name == "save_configuration":
            await method(RouterId("router-lab-001"))
        elif method_name == "compensate":
            backup = BackupArtifact(
                artifact_id=ArtifactId("artifact-001"),
                router_id=RouterId("router-lab-001"),
                operation_id=OperationId("op-001"),
                content_digest="digest:backup:001",
                storage_locator_digest="digest:loc:001",
                identity_fingerprint_digest="sha256:abc",
                created_at=datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC),
            )
            await method(RouterId("router-lab-001"), backup)
    assert transport.fetch_calls == []


@pytest.mark.asyncio
async def test_mutations_denied_before_certified_registry() -> None:
    adapter, transport = _adapter()
    transport.fetch_calls.clear()
    with pytest.raises(MutationForbidden, match="live mutation policy not injected"):
        await adapter.apply_plan(
            ChangePlan(
                plan_id=PlanId("plan-001"),
                router_id=RouterId("router-lab-001"),
                revision_id=RevisionId("rev-001"),
                observation_id=ObservationId("obs-001"),
                expected_desired_digest="digest:desired:001",
                observed_resource_version="digest:rv:001",
                items=(
                    ChangePlanItem(ResourceId("res-001"), "intent", "digest:intent:001"),
                ),
                confirmation_state=PlanConfirmationState.CONFIRMED,
                expires_at=datetime(2026, 7, 21, 13, 0, 0, tzinfo=UTC),
                created_at=datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC),
                actor="test",
            )
        )
    assert transport.fetch_calls == []


def test_unknown_json_shape_fail_closed() -> None:
    with pytest.raises(IdentityParseError):
        parse_identity({"unexpected": True}, [])


@pytest.mark.asyncio
async def test_check_identity_fail_closed_for_observed_shape() -> None:
    system = json.loads((FIXTURES / "system_telemetry_only.json").read_text(encoding="utf-8"))
    components = json.loads((FIXTURES / "components_observed.json").read_text(encoding="utf-8"))
    transport = RecordingTransport(host="192.168.1.1", username="admin", password="secret")

    class ObservedTransport(RecordingTransport):
        def fetch_allowlisted(self, command, body=None):  # type: ignore[no-untyped-def]
            if command is SHOW_SYSTEM:
                return system
            if command is COMPONENTS_LIST:
                return components
            if command is SHOW_IDENTIFICATION:
                return {}
            if command is SHOW_VERSION:
                return {}
            raise AssertionError("unexpected command")

    transport = ObservedTransport(host="192.168.1.1", username="admin", password="secret")
    adapter = NetcrazeReadOnlyAdapter(
        router_id=RouterId("router-lab-001"),
        transport=transport,
        clock=FixedClock(),
    )
    parsed = parse_identity(system, components)
    expected = build_router_identity(parsed, RouterId("router-lab-001"))
    with pytest.raises(IdentityParseError):
        await adapter.check_identity(expected)


def test_default_adapter_shares_certified_registry_with_executor() -> None:
    adapter, _ = _adapter()
    assert adapter.typed_executor.registry is adapter.certified_registry


def test_adapter_rebinds_empty_independent_defaults() -> None:
    left = CertifiedOperationRegistry()
    right = CertifiedOperationRegistry()
    transport = RecordingTransport(host="192.168.1.1", username="admin", password="secret")
    adapter = NetcrazeReadOnlyAdapter(
        router_id=RouterId("router-lab-001"),
        transport=transport,
        clock=FixedClock(),
        certified_registry=left,
        typed_executor=SharedTypedOperationExecutor(registry=right),
    )
    assert adapter.typed_executor.registry is left


def test_adapter_rejects_mismatched_registry_digest() -> None:
    populated = CertifiedOperationRegistry()
    empty = CertifiedOperationRegistry()
    lab = SYNTHETIC_REGISTERED_OPERATIONS[0]
    promote_through_pipeline(
        staging=OperationPromotionRegistry(),
        runtime=populated,
        candidate=_candidate_from_lab(lab),
        evidence=_lab_evidence(lab),
    )
    transport = RecordingTransport(host="192.168.1.1", username="admin", password="secret")
    with pytest.raises(NetcrazeAdapterError, match="same CertifiedOperationRegistry"):
        NetcrazeReadOnlyAdapter(
            router_id=RouterId("router-lab-001"),
            transport=transport,
            clock=FixedClock(),
            certified_registry=populated,
            typed_executor=SharedTypedOperationExecutor(registry=empty),
        )


@pytest.mark.asyncio
async def test_populated_registry_without_policy_denies_before_transport() -> None:
    populated = CertifiedOperationRegistry()
    lab = SYNTHETIC_REGISTERED_OPERATIONS[0]
    promote_through_pipeline(
        staging=OperationPromotionRegistry(),
        runtime=populated,
        candidate=_candidate_from_lab(lab),
        evidence=_lab_evidence(lab),
    )
    transport = RecordingTransport(host="192.168.1.1", username="admin", password="secret")
    adapter = NetcrazeReadOnlyAdapter(
        router_id=RouterId("router-lab-001"),
        transport=transport,
        clock=FixedClock(),
        certified_registry=populated,
        typed_executor=SharedTypedOperationExecutor(registry=populated),
    )
    transport.fetch_calls.clear()
    with pytest.raises(MutationForbidden, match="live mutation policy not injected"):
        await adapter.apply_plan(
            ChangePlan(
                plan_id=PlanId("plan-001"),
                router_id=RouterId("router-lab-001"),
                revision_id=RevisionId("rev-001"),
                observation_id=ObservationId("obs-001"),
                expected_desired_digest="digest:desired:001",
                observed_resource_version="digest:rv:001",
                items=(
                    ChangePlanItem(ResourceId("res-001"), "intent", "digest:intent:001"),
                ),
                confirmation_state=PlanConfirmationState.CONFIRMED,
                expires_at=datetime(2026, 7, 21, 13, 0, 0, tzinfo=UTC),
                created_at=datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC),
                actor="test",
            )
        )
    assert transport.fetch_calls == []


@pytest.mark.asyncio
async def test_live_mutation_policy_rejects_p1_effect_context_mismatch() -> None:
    populated = CertifiedOperationRegistry()
    lab = SYNTHETIC_REGISTERED_OPERATIONS[0]
    promote_through_pipeline(
        staging=OperationPromotionRegistry(),
        runtime=populated,
        candidate=_candidate_from_lab(lab),
        evidence=_lab_evidence(lab),
    )
    transport = RecordingTransport(host="192.168.1.1", username="admin", password="secret")
    adapter = NetcrazeReadOnlyAdapter(
        router_id=RouterId("router-lab-001"),
        transport=transport,
        clock=FixedClock(),
        certified_registry=populated,
        typed_executor=SharedTypedOperationExecutor(registry=populated),
        live_mutation_policy=LiveMutationPolicy(
            allowed_operation="apply_plan",
            certified_registry_digest=populated.content_digest(),
            p1_effect_context_id="ctx-policy",
            t4_contract_id="t4-test",
            gate_b_write_certified=True,
            gate_c_open=True,
            gate_d_closed=True,
        ),
        active_p1_effect_context_id="ctx-runtime-mismatch",
    )
    transport.fetch_calls.clear()
    with pytest.raises(MutationForbidden, match="P1 effect context mismatch"):
        await adapter.apply_plan(
            ChangePlan(
                plan_id=PlanId("plan-001"),
                router_id=RouterId("router-lab-001"),
                revision_id=RevisionId("rev-001"),
                observation_id=ObservationId("obs-001"),
                expected_desired_digest="digest:desired:001",
                observed_resource_version="digest:rv:001",
                items=(
                    ChangePlanItem(ResourceId("res-001"), "intent", "digest:intent:001"),
                ),
                confirmation_state=PlanConfirmationState.CONFIRMED,
                expires_at=datetime(2026, 7, 21, 13, 0, 0, tzinfo=UTC),
                created_at=datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC),
                actor="test",
            )
        )
    assert transport.fetch_calls == []
