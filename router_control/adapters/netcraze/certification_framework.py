"""Offline certification planner/runner — deterministic packets, no dispatch."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from router_control.adapters.netcraze.capability_families import (
    DISRUPTIVE_LAN_FAMILIES,
    FAMILY_DEPENDENCY_ORDER,
    PLAN_INDEPENDENT_FAMILIES,
    CapabilityFamily,
    FamilyCatalog,
    TupleBinding,
    families_before,
    normalize_family_for_gate_bc,
    parse_capability_family,
)
from router_control.adapters.netcraze.evidence_manifest import EvidenceManifest
from router_control.adapters.netcraze.gate_bc import GateBCAuthorization, GateBCError
from router_control.adapters.netcraze.shape_registry import FamilyShapeRegistry
from router_control.domain.errors import DispatchForbidden

CONTRACT_ID = "m5-certification-framework-20260722"


@dataclass(frozen=True, slots=True)
class PrerequisiteItem:
    check_id: str
    description: str
    required: bool
    satisfied: bool

    def sanitized_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "description": self.description,
            "required": self.required,
            "satisfied": self.satisfied,
        }


@dataclass(frozen=True, slots=True)
class PrerequisiteChecklist:
    items: tuple[PrerequisiteItem, ...]

    @property
    def all_required_satisfied(self) -> bool:
        return all(item.satisfied for item in self.items if item.required)

    def sanitized_dict(self) -> dict[str, Any]:
        return {
            "items": [item.sanitized_dict() for item in self.items],
            "all_required_satisfied": self.all_required_satisfied,
        }


def evaluate_prerequisites(
    *,
    family: CapabilityFamily,
    catalog: FamilyCatalog,
    tuple_binding: TupleBinding | None,
    gate_bc: GateBCAuthorization | None,
    registry: FamilyShapeRegistry,
    probe_evidence: dict[str, Any] | None,
    now: datetime | None = None,
    startup_backup_verified: bool = False,
) -> PrerequisiteChecklist:
    current = (now or datetime.now(UTC)).astimezone(UTC)
    items: list[PrerequisiteItem] = []

    deps = families_before(family)
    deps_ok = catalog.dependency_satisfied(family) if deps else True
    items.append(
        PrerequisiteItem(
            check_id="dependency_order",
            description=f"prior families satisfied for {family.value}",
            required=True,
            satisfied=deps_ok,
        )
    )

    tuple_ok = tuple_binding is not None
    if tuple_binding and probe_evidence:
        tuple_ok = tuple_binding.matches_evidence(probe_evidence)
    items.append(
        PrerequisiteItem(
            check_id="tuple_binding",
            description="exact tuple binding aligned with probe evidence",
            required=True,
            satisfied=tuple_ok,
        )
    )

    gate_a_ok = False
    gate_c_ok = False
    family_match = False
    if gate_bc is not None:
        gate_a_ok = gate_bc.gate_b_status == "certification_trial_authorized"
        gate_c_ok = gate_bc.gate_c_is_open(current) if gate_bc.gate_c_status == "open" else False
        family_match = normalize_family_for_gate_bc(family.value) == gate_bc.capability_family

    items.append(
        PrerequisiteItem(
            check_id="gate_b_trial",
            description="Gate B CertificationTrialAuthorized (checklist only)",
            required=False,
            satisfied=gate_a_ok,
        )
    )
    items.append(
        PrerequisiteItem(
            check_id="gate_c_window",
            description="Gate C lab window open (checklist only)",
            required=False,
            satisfied=gate_c_ok,
        )
    )
    items.append(
        PrerequisiteItem(
            check_id="gate_bc_family_match",
            description="Gate B/C capability family matches target family",
            required=False,
            satisfied=family_match,
        )
    )

    shapes_ok = len(registry.for_family(family)) > 0
    items.append(
        PrerequisiteItem(
            check_id="write_shapes_registered",
            description="evidence-backed write shapes registered for family",
            required=True,
            satisfied=shapes_ok,
        )
    )

    if family in DISRUPTIVE_LAN_FAMILIES:
        fail_safe_ok = catalog.write_certified_readiness(CapabilityFamily.FAIL_SAFE)
        items.append(
            PrerequisiteItem(
                check_id="fail_safe_observed",
                description="fail-safe WriteCertified prerequisite for disruptive LAN family",
                required=True,
                satisfied=fail_safe_ok,
            )
        )

    items.append(
        PrerequisiteItem(
            check_id="startup_backup",
            description="startup-config backup artifact recorded (T4 checklist)",
            required=True,
            satisfied=startup_backup_verified,
        )
    )

    return PrerequisiteChecklist(items=tuple(items))


@dataclass
class CertificationPlanner:
    catalog: FamilyCatalog = field(default_factory=FamilyCatalog)
    registry: FamilyShapeRegistry = field(default_factory=FamilyShapeRegistry)

    def plan(
        self,
        family: CapabilityFamily | str,
        *,
        tuple_binding: TupleBinding | None = None,
        gate_bc: GateBCAuthorization | None = None,
        probe_evidence: dict[str, Any] | None = None,
        manifest: EvidenceManifest | None = None,
        now: datetime | None = None,
        startup_backup_verified: bool = False,
    ) -> dict[str, Any]:
        resolved = parse_capability_family(family) if isinstance(family, str) else family
        current = (now or datetime.now(UTC)).astimezone(UTC)

        checklist = evaluate_prerequisites(
            family=resolved,
            catalog=self.catalog,
            tuple_binding=tuple_binding,
            gate_bc=gate_bc,
            registry=self.registry,
            probe_evidence=probe_evidence,
            now=current,
            startup_backup_verified=startup_backup_verified,
        )

        dependency_index = FAMILY_DEPENDENCY_ORDER.index(resolved)
        prior_families = [f.value for f in families_before(resolved)]

        fail_safe_step = (
            "activate_fail_safe"
            if resolved == CapabilityFamily.FAIL_SAFE
            else "confirm_fail_safe_active"
        )
        packet: dict[str, Any] = {
            "contract_id": CONTRACT_ID,
            "mode": "offline_plan",
            "dispatch_permitted": False,
            "capability_family": resolved.value,
            "family_state": self.catalog.get_state(resolved).value,
            "dependency_order_index": dependency_index,
            "prior_families": prior_families,
            "prerequisite_checklist": checklist.sanitized_dict(),
            "write_certified_claim": False,
            "registry_size": len(self.registry.for_family(resolved)),
            "planned_at": current.isoformat(),
            "campaign_steps": [
                "observe_baseline",
                "verify_tuple_binding",
                fail_safe_step,
                "execute_typed_operations",
                "read_back_postconditions",
                "record_sanitized_evidence",
            ],
            "first_live_campaign_note": (
                "deferred until P1-P3 live substrate + fresh exact T4 Human Gate"
                if resolved == CapabilityFamily.FAIL_SAFE
                or resolved in PLAN_INDEPENDENT_FAMILIES
                else "requires fail_safe WriteCertified prerequisite"
            ),
        }

        if tuple_binding is not None:
            packet["tuple_binding"] = tuple_binding.sanitized_dict()
        if manifest is not None:
            packet["manifest"] = {
                "manifest_id": manifest.manifest_id,
                "provenance_tier": manifest.provenance_tier.value,
                "registration_eligible": manifest.registration_eligible,
                "hash_pending": manifest.hash_is_pending,
            }

        return packet


@dataclass
class CertificationRunner:
    planner: CertificationPlanner = field(default_factory=CertificationPlanner)
    fixtures: dict[str, Any] = field(default_factory=dict)

    def plan_from_fixtures(
        self,
        family: CapabilityFamily | str,
        *,
        fixture_id: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        fixture = self.fixtures.get(fixture_id)
        if fixture is None:
            raise GateBCError(f"unknown fixture: {fixture_id}")
        if not isinstance(fixture, dict):
            raise GateBCError("fixture must be an object")

        tuple_data = fixture.get("tuple_binding")
        tuple_binding = None
        if isinstance(tuple_data, dict):
            tuple_binding = TupleBinding(
                model=str(tuple_data["model"]),
                firmware_version=str(tuple_data["firmware_version"]),
                ndm_build=str(tuple_data["ndm_build"]),
                bsp_build=str(tuple_data["bsp_build"]),
                update_channel=str(tuple_data["update_channel"]),
                region=str(tuple_data["region"]),
                component_set_digest=str(tuple_data["component_set_digest"]),
                device_fingerprint_digest=str(tuple_data["device_fingerprint_digest"]),
                transport=str(tuple_data["transport"]),
                ssh_host_key_algorithm=str(tuple_data["ssh_host_key_algorithm"]),
            )

        probe_raw = fixture.get("probe_evidence")
        probe_evidence = probe_raw if isinstance(probe_raw, dict) else None
        packet = self.planner.plan(
            family,
            tuple_binding=tuple_binding,
            probe_evidence=probe_evidence,
            now=now,
        )
        packet["fixture_id"] = fixture_id
        packet["fixture_replay"] = True
        return packet

    def dispatch(self, *_args: Any, **_kwargs: Any) -> None:
        raise DispatchForbidden(
            "certification runner dispatch is unconditionally forbidden in offline framework"
        )

    def execute_live(self, *_args: Any, **_kwargs: Any) -> None:
        raise DispatchForbidden(
            "certification runner live execution is unconditionally forbidden in offline framework"
        )


__all__ = [
    "CONTRACT_ID",
    "CertificationPlanner",
    "CertificationRunner",
    "PrerequisiteChecklist",
    "PrerequisiteItem",
    "evaluate_prerequisites",
]
