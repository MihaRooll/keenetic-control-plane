"""AWG Gate B/C certification runner — sanitized evidence, strict lifecycle."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from router_control.adapters.netcraze.awg_hardware import (
    DISRUPTIVE_TAIL,
    AwgHardwareBoundary,
    CommandShapeUnknown,
    HardwareExecutionResult,
    TypedOperation,
)
from router_control.adapters.netcraze.awg_profile import (
    AwgProfileError,
    ParsedAwgProfile,
    parse_awg_profile_path,
)
from router_control.adapters.netcraze.certification import GateACertification
from router_control.adapters.netcraze.gate_bc import GateBCAuthorization, GateBCError, TupleDrift
from router_control.adapters.netcraze.sanitize import sanitize_mapping
from router_control.ports.vault import CredentialVaultPort

CANDIDATE_ORDER: tuple[str, ...] = ("keenetic50-compat", "fi-ip", "de-ip")
CAPABILITY_FAMILY = "AmneziaWG"


class CandidatePhase(StrEnum):
    BASELINE_OBSERVE = "baseline_observe"
    FAIL_SAFE_BEGIN = "fail_safe_begin"
    AWG_IMPORT = "awg_import"
    FIELD_PARITY_READBACK = "field_parity_readback"
    HANDSHAKE_OBSERVE = "handshake_observe"
    APPLICATION_REACHABILITY = "application_reachability"
    SAVE = "config_save"
    REBOOT = "router_reboot"
    VERIFY = "post_reboot_verify"
    ROLLBACK = "baseline_restore"


PRE_VERIFY_STEPS: tuple[CandidatePhase, ...] = (
    CandidatePhase.BASELINE_OBSERVE,
    CandidatePhase.FAIL_SAFE_BEGIN,
    CandidatePhase.AWG_IMPORT,
    CandidatePhase.FIELD_PARITY_READBACK,
    CandidatePhase.HANDSHAKE_OBSERVE,
    CandidatePhase.APPLICATION_REACHABILITY,
)

_VERIFIED_EXECUTION_STATUSES = frozenset(
    {
        "passed",
        "verified",
        "executed",
        "handshake_verified",
        "reachability_verified",
        "read_back_verified",
        "import_verified",
    }
)

PHASE_TO_OPERATION: dict[CandidatePhase, TypedOperation | None] = {
    CandidatePhase.BASELINE_OBSERVE: None,
    CandidatePhase.FAIL_SAFE_BEGIN: TypedOperation.FAIL_SAFE_BEGIN,
    CandidatePhase.AWG_IMPORT: TypedOperation.AWG_IMPORT,
    CandidatePhase.FIELD_PARITY_READBACK: TypedOperation.AWG_FIELD_PARITY_READBACK,
    CandidatePhase.HANDSHAKE_OBSERVE: TypedOperation.HANDSHAKE_OBSERVE,
    CandidatePhase.APPLICATION_REACHABILITY: TypedOperation.APPLICATION_REACHABILITY_OBSERVE,
    CandidatePhase.SAVE: TypedOperation.CONFIG_SAVE,
    CandidatePhase.REBOOT: TypedOperation.ROUTER_REBOOT,
    CandidatePhase.VERIFY: None,
    CandidatePhase.ROLLBACK: TypedOperation.BASELINE_RESTORE,
}


class CertificationStop(GateBCError):
    """Runner stopped fail-closed — sanitized evidence captured."""


def _require_verified_status(*, phase: CandidatePhase, status: str) -> None:
    normalized = status.strip().lower()
    if normalized not in _VERIFIED_EXECUTION_STATUSES:
        raise CertificationStop(
            f"phase {phase.value} lacks verified execution status (got {status!r})"
        )


def _validate_hardware_result(
    *,
    phase: CandidatePhase,
    operation: TypedOperation,
    result: HardwareExecutionResult,
    profile: ParsedAwgProfile | None,
) -> None:
    _require_verified_status(phase=phase, status=result.status)
    sanitized = result.sanitized
    if operation == TypedOperation.AWG_IMPORT:
        if profile is None:
            raise CertificationStop("AWG import requires parsed profile")
        if not sanitized.get("profile_encoding_used"):
            raise CertificationStop("AWG import missing encoded profile payload evidence")
        if sanitized.get("profile_digest") != profile.profile_digest:
            raise CertificationStop("AWG import profile digest mismatch")
    if operation == TypedOperation.AWG_FIELD_PARITY_READBACK:
        if not sanitized.get("read_back_verified"):
            raise CertificationStop("AWG field parity read-back not verified")
    if operation == TypedOperation.HANDSHAKE_OBSERVE:
        if not sanitized.get("handshake_verified"):
            raise CertificationStop("AWG handshake observation not verified")
    if operation == TypedOperation.APPLICATION_REACHABILITY_OBSERVE:
        if not sanitized.get("application_reachability_verified"):
            raise CertificationStop("AWG application reachability not verified")


@dataclass(frozen=True, slots=True)
class CandidateOutcome:
    candidate_id: str
    status: str
    stopped_phase: str | None
    error_type: str | None
    steps_completed: tuple[str, ...]
    rollback_status: str
    verify_step: dict[str, Any] | None = None


@dataclass
class CertificationRunner:
    gate_a: GateACertification
    gate_bc: GateBCAuthorization
    hardware: AwgHardwareBoundary
    vault: CredentialVaultPort
    probe_evidence: dict[str, Any]
    dry_run: bool = True
    now: datetime | None = None
    source_address: str | None = None
    _outcomes: list[CandidateOutcome] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.gate_bc.candidate_order != CANDIDATE_ORDER:
            raise GateBCError("candidate_order mismatch")

    def _current_now(self) -> datetime:
        return (self.now or datetime.now(UTC)).astimezone(UTC)

    def _source_requirement_evidence(self) -> dict[str, str]:
        if self.source_address is None:
            return {}
        from router_control.adapters.netcraze.ssh_tunnel import (
            source_address_class,
            validate_source_address,
        )

        validated = validate_source_address(self.source_address)
        return {
            "source_address_required": validated,
            "source_address_class": source_address_class(validated),
        }

    def _baseline_observe(self) -> dict[str, Any]:
        return {
            "phase": CandidatePhase.BASELINE_OBSERVE.value,
            "gate_a_open": self.gate_a.is_open,
            "component_set_digest": self.gate_a.component_set_digest,
            "device_fingerprint_digest": self.gate_a.device_fingerprint_digest,
        }

    def _run_post_reboot_verify(self, *, profile: ParsedAwgProfile) -> dict[str, Any]:
        if self.dry_run:
            raise CertificationStop("dry_run refuses post-reboot verify execution path")
        reprobe_steps: list[str] = []
        for phase in (
            CandidatePhase.FIELD_PARITY_READBACK,
            CandidatePhase.HANDSHAKE_OBSERVE,
            CandidatePhase.APPLICATION_REACHABILITY,
        ):
            step = self._run_phase(phase, profile=profile)
            reprobe_steps.append(step["phase"])
        try:
            self.gate_bc.writes_permitted(
                gate_a=self.gate_a,
                capability_family=CAPABILITY_FAMILY,
                probe_evidence=self.probe_evidence,
                now=self._current_now(),
            )
        except GateBCError as exc:
            raise CertificationStop(f"post-reboot verify failed: {exc}") from exc
        return {
            "phase": CandidatePhase.VERIFY.value,
            "status": "passed",
            "checks": [
                "field_parity_readback",
                "handshake_observe",
                "application_reachability",
                "gate_bc_writes_permitted",
            ],
            "reprobe_steps": reprobe_steps,
        }

    def _run_phase(
        self,
        phase: CandidatePhase,
        *,
        profile: ParsedAwgProfile | None = None,
    ) -> dict[str, Any]:
        operation = PHASE_TO_OPERATION.get(phase)
        if operation is None:
            if phase == CandidatePhase.BASELINE_OBSERVE:
                return self._baseline_observe()
            if phase == CandidatePhase.VERIFY:
                return self._run_post_reboot_verify(profile=profile)  # type: ignore[arg-type]
            return {"phase": phase.value, "status": "observed"}

        if self.dry_run:
            if operation in DISRUPTIVE_TAIL:
                raise CertificationStop(f"dry_run refuses disruptive operation: {operation.value}")
            if operation == TypedOperation.BASELINE_RESTORE:
                return {
                    "phase": phase.value,
                    "status": "dry_run_rollback_simulated",
                }
            raise CertificationStop(
                f"dry_run refuses unverified mutative phase: {operation.value}"
            )

        try:
            execute_kwargs: dict[str, Any] = {
                "gate_a": self.gate_a,
                "gate_bc": self.gate_bc,
                "probe_evidence": self.probe_evidence,
                "capability_family": CAPABILITY_FAMILY,
                "now": self._current_now(),
            }
            if operation == TypedOperation.AWG_IMPORT and profile is not None:
                execute_kwargs["profile_digest"] = profile.profile_digest
                execute_kwargs["profile_fields"] = {
                    "profile_fields": list(profile.interface_field_names),
                }
                execute_kwargs["credential_refs"] = [
                    {
                        "role": ref.role,
                        "credential_ref_id": ref.credential_ref_id,
                        "kind": ref.kind,
                    }
                    for ref in profile.credential_refs
                ]
            result = self.hardware.execute(
                operation,
                **execute_kwargs,
            )
            _validate_hardware_result(
                phase=phase,
                operation=operation,
                result=result,
                profile=profile,
            )
            return {
                "phase": phase.value,
                "status": result.status,
                "sanitized": result.sanitized,
                "compensation_evidence_required": operation in DISRUPTIVE_TAIL,
            }
        except CommandShapeUnknown as exc:
            raise CertificationStop(str(exc)) from exc

    def _phase_is_mutative(self, phase: CandidatePhase) -> bool:
        return PHASE_TO_OPERATION.get(phase) is not None

    def _attempt_rollback(self, completed: list[str]) -> str:
        try:
            rollback = self._run_phase(CandidatePhase.ROLLBACK)
            completed.append(rollback["phase"])
            return "succeeded"
        except (CertificationStop, GateBCError):
            if CandidatePhase.ROLLBACK.value not in completed:
                completed.append(CandidatePhase.ROLLBACK.value)
            return "failed"

    def _compensation_evidence(
        self,
        *,
        rollback_status: str,
        completed: list[str],
    ) -> dict[str, Any]:
        return {
            "rollback_status": rollback_status,
            "rollback_phase_recorded": CandidatePhase.ROLLBACK.value in completed,
            "compensation_required": True,
            "compensation_verified": rollback_status in {"succeeded", "failed"},
        }

    def _pass_compensation_evidence(
        self,
        *,
        completed: list[str],
        verify_step: dict[str, Any],
    ) -> dict[str, Any]:
        verify_phase = CandidatePhase.VERIFY.value
        if verify_phase not in completed:
            raise CertificationStop("passed outcome missing post-reboot verify phase")
        if verify_step.get("status") != "passed":
            raise CertificationStop("passed outcome lacks verified post-reboot compensation")
        checks = verify_step.get("checks")
        if not isinstance(checks, list) or not checks:
            raise CertificationStop("passed outcome lacks compensation verification checks")
        return {
            "compensation_required": True,
            "compensation_verified": True,
            "verification_method": "post_reboot_verify_with_gate_bc_recertification",
            "rollback_status": "not_needed",
            "rollback_plan_exercised": False,
            "verified_not_needed_evidence": {
                "verify_phase": verify_phase,
                "checks": list(checks),
                "reprobe_steps": list(verify_step.get("reprobe_steps") or []),
            },
        }

    def _outcome_compensation_evidence(
        self,
        *,
        outcome: CandidateOutcome,
        verify_step: dict[str, Any] | None,
    ) -> dict[str, Any]:
        if outcome.status == "passed":
            if verify_step is None:
                raise CertificationStop("passed outcome missing compensation verification context")
            return self._pass_compensation_evidence(
                completed=list(outcome.steps_completed),
                verify_step=verify_step,
            )
        if outcome.rollback_status != "not_attempted":
            return self._compensation_evidence(
                rollback_status=outcome.rollback_status,
                completed=list(outcome.steps_completed),
            )
        return {"compensation_required": False}

    def _finalize_candidate(
        self,
        *,
        candidate_id: str,
        completed: list[str],
        exc: Exception,
        status: str,
        mutation_attempted: bool,
    ) -> CandidateOutcome:
        rollback_status = "not_attempted"
        if mutation_attempted:
            rollback_status = self._attempt_rollback(completed)
        return CandidateOutcome(
            candidate_id=candidate_id,
            status=status,
            stopped_phase=completed[-1] if completed else None,
            error_type=exc.__class__.__name__,
            steps_completed=tuple(completed),
            rollback_status=rollback_status,
        )

    def _run_candidate(
        self,
        candidate_id: str,
        profile: ParsedAwgProfile,
    ) -> CandidateOutcome:
        completed: list[str] = []
        mutation_attempted = False
        try:
            baseline = self._baseline_observe()
            completed.append(baseline["phase"])

            for phase in PRE_VERIFY_STEPS[1:]:
                if self._phase_is_mutative(phase):
                    mutation_attempted = True
                step = self._run_phase(phase, profile=profile)
                completed.append(step["phase"])

            if self.dry_run:
                raise CertificationStop(
                    "dry_run: pre-verify blocked — transport and verification evidence required"
                )

            for phase in (CandidatePhase.SAVE, CandidatePhase.REBOOT):
                mutation_attempted = True
                step = self._run_phase(phase, profile=profile)
                completed.append(step["phase"])

            verify = self._run_post_reboot_verify(profile=profile)
            completed.append(verify["phase"])
            pass_evidence = self._pass_compensation_evidence(
                completed=completed,
                verify_step=verify,
            )
            if not pass_evidence.get("compensation_verified"):
                raise CertificationStop("passed outcome lacks compensation verification evidence")
            return CandidateOutcome(
                candidate_id=candidate_id,
                status="passed",
                stopped_phase=None,
                error_type=None,
                steps_completed=tuple(completed),
                rollback_status="not_attempted",
                verify_step=verify,
            )
        except CertificationStop as exc:
            return self._finalize_candidate(
                candidate_id=candidate_id,
                completed=completed,
                exc=exc,
                status="stopped",
                mutation_attempted=mutation_attempted,
            )
        except TupleDrift as exc:
            return self._finalize_candidate(
                candidate_id=candidate_id,
                completed=completed,
                exc=exc,
                status="tuple_drift",
                mutation_attempted=True,
            )
        except GateBCError as exc:
            if not mutation_attempted:
                raise
            return self._finalize_candidate(
                candidate_id=candidate_id,
                completed=completed,
                exc=exc,
                status="gate_bc_error",
                mutation_attempted=True,
            )

    def run_profiles(
        self,
        profiles: dict[str, Path | str],
        *,
        require_all_candidates: bool = True,
    ) -> dict[str, Any]:
        evidence: dict[str, Any] = {
            "contract_id": self.gate_bc.contract_id,
            "capability_family": CAPABILITY_FAMILY,
            "dry_run": self.dry_run,
            "write_certified_claim": False,
            "certification_trial_only": True,
            "candidate_order": list(CANDIDATE_ORDER),
            "write_shapes_registered": self.gate_bc.write_shapes_registered,
            "registry_size": len(self.hardware.registry),
            "recorded_at": self._current_now().isoformat(),
            "candidates": [],
        }
        evidence.update(self._source_requirement_evidence())

        candidate_ids = CANDIDATE_ORDER if require_all_candidates else tuple(
            candidate for candidate in CANDIDATE_ORDER if candidate in profiles
        )
        if not candidate_ids:
            raise GateBCError("no candidate profiles supplied")

        for candidate_id in candidate_ids:
            if candidate_id not in profiles:
                raise GateBCError(f"missing profile for candidate {candidate_id}")
            try:
                parsed = parse_awg_profile_path(profiles[candidate_id], vault=self.vault)
            except AwgProfileError as exc:
                raise CertificationStop(str(exc)) from exc

            outcome = self._run_candidate(candidate_id, parsed)
            self._outcomes.append(outcome)
            evidence["candidates"].append(
                {
                    "candidate_id": candidate_id,
                    "profile": parsed.sanitized_dict(),
                    "outcome": {
                        "status": outcome.status,
                        "stopped_phase": outcome.stopped_phase,
                        "error_type": outcome.error_type,
                        "steps_completed": list(outcome.steps_completed),
                        "rollback_status": outcome.rollback_status,
                        "compensation_evidence": self._outcome_compensation_evidence(
                            outcome=outcome,
                            verify_step=outcome.verify_step,
                        ),
                    },
                }
            )
            if outcome.status != "passed":
                evidence["runner_status"] = "stopped"
                evidence["stopped_candidate"] = candidate_id
                return sanitize_mapping(evidence)

        evidence["runner_status"] = "all_candidates_passed"
        return sanitize_mapping(evidence)

    def build_evidence(
        self,
        *,
        profile_path: Path | str | None = None,
        candidate_id: str | None = None,
    ) -> dict[str, Any]:
        if profile_path is None:
            raise GateBCError("profile_path is required")
        profiles = {candidate_id or CANDIDATE_ORDER[0]: profile_path}
        return self.run_profiles(profiles)


def build_certification_evidence(
    *,
    gate_a: GateACertification,
    gate_bc: GateBCAuthorization,
    hardware: AwgHardwareBoundary,
    vault: CredentialVaultPort,
    probe_evidence: dict[str, Any],
    profiles: dict[str, Path | str],
    dry_run: bool = True,
    now: datetime | None = None,
) -> dict[str, Any]:
    runner = CertificationRunner(
        gate_a=gate_a,
        gate_bc=gate_bc,
        hardware=hardware,
        vault=vault,
        probe_evidence=probe_evidence,
        dry_run=dry_run,
        now=now,
    )
    return runner.run_profiles(profiles)


__all__ = [
    "CANDIDATE_ORDER",
    "CAPABILITY_FAMILY",
    "CandidateOutcome",
    "CandidatePhase",
    "CertificationRunner",
    "CertificationStop",
    "DISRUPTIVE_TAIL",
    "PRE_VERIFY_STEPS",
    "build_certification_evidence",
]
