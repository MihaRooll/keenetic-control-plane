"""Generalized per-family typed shape registry — empty/default-deny."""



from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any

from router_control.adapters.netcraze.capability_families import (
    CapabilityFamily,
    parse_capability_family,
)
from router_control.adapters.netcraze.gate_bc import GateBCError
from router_control.adapters.netcraze.operation_spec import RegisteredOperation

_SHA256_PREFIX_RE = re.compile(r"^sha256:[a-f0-9]{64}$")

_SECRET_LIKE = frozenset({"password", "privatekey", "presharedkey", "secret", "token"})





class ShapeRegistryError(GateBCError):

    """Shape registry validation or lookup failure."""





class CommandShapeUnknown(ShapeRegistryError):

    """No evidence-backed registered shape exists for the typed operation."""





class ShapePromotionState(StrEnum):

    CANDIDATE = "candidate"

    LAB_OBSERVED = "lab_observed"

    CERTIFIED = "certified"

    REVOKED = "revoked"





CANDIDATE_PROMOTION_STATES: frozenset[ShapePromotionState] = frozenset(

    {ShapePromotionState.CANDIDATE}

)

LAB_OBSERVED_PROMOTION_STATES: frozenset[ShapePromotionState] = frozenset(

    {ShapePromotionState.LAB_OBSERVED}

)

RUNTIME_LOAD_PROMOTION_STATE = ShapePromotionState.CERTIFIED





@dataclass(frozen=True, slots=True)

class LabObservedEvidence:

    """Evidence bundle required before Candidate→LabObserved promotion."""



    tuple_component_set_digest: str

    tuple_device_fingerprint_digest: str

    gate_a_evidence_digest: str

    evidence_digest: str

    trial_authorized: bool

    artifact_digest_verified: bool



    def matches_operation(self, operation: RegisteredOperation) -> bool:

        return (

            operation.tuple_component_set_digest == self.tuple_component_set_digest

            and operation.tuple_device_fingerprint_digest

            == self.tuple_device_fingerprint_digest

            and operation.gate_a_evidence_digest == self.gate_a_evidence_digest

            and operation.evidence_digest == self.evidence_digest

        )





@dataclass(frozen=True, slots=True)

class FamilyRegisteredShape:

    family: CapabilityFamily

    operation_id: str

    method: str

    path: str

    body_keys: tuple[str, ...]

    tuple_component_set_digest: str

    tuple_device_fingerprint_digest: str

    adapter_version: str

    evidence_hash: str | None = None



    def sanitized_dict(self) -> dict[str, Any]:

        payload: dict[str, Any] = {

            "family": self.family.value,

            "operation_id": self.operation_id,

            "method": self.method,

            "path": self.path,

            "body_keys": list(self.body_keys),

            "tuple_component_set_digest": self.tuple_component_set_digest,

            "tuple_device_fingerprint_digest": self.tuple_device_fingerprint_digest,

            "adapter_version": self.adapter_version,

        }

        if self.evidence_hash is not None:

            payload["evidence_hash"] = self.evidence_hash

        return payload





def _validate_digest(value: str, *, field: str) -> None:

    if not _SHA256_PREFIX_RE.match(value.strip().lower()):

        raise ShapeRegistryError(f"{field} must be sha256:<64-hex>")





def _validate_body_keys(body_keys: tuple[str, ...]) -> None:

    if not body_keys:

        raise ShapeRegistryError("shape body_keys must be non-empty")

    for key in body_keys:

        if not key.strip():

            raise ShapeRegistryError("shape body_keys must be non-empty identifiers")

        normalized = key.strip().lower().replace("-", "_")

        if normalized in _SECRET_LIKE or "secret" in normalized or "password" in normalized:

            raise ShapeRegistryError("shape body_keys must not include secret-like fields")





class FamilyShapeRegistry:

    """Evidence-backed shape registry keyed by (family, operation_id) — empty by default."""



    def __init__(self) -> None:

        self._shapes: dict[tuple[CapabilityFamily, str], FamilyRegisteredShape] = {}



    def __len__(self) -> int:

        return len(self._shapes)



    def is_registered(self, family: CapabilityFamily | str, operation_id: str) -> bool:

        resolved = parse_capability_family(family) if isinstance(family, str) else family

        return (resolved, operation_id) in self._shapes



    def registered_keys(self) -> frozenset[tuple[CapabilityFamily, str]]:

        return frozenset(self._shapes)



    def register_shape(self, shape: FamilyRegisteredShape) -> None:

        if not shape.path.startswith("/"):

            raise ShapeRegistryError("shape path must be absolute")

        method = shape.method.upper()

        if method not in {"GET", "POST", "PUT", "DELETE", "PATCH"}:

            raise ShapeRegistryError(f"unsupported HTTP method: {shape.method}")

        _validate_body_keys(shape.body_keys)

        _validate_digest(shape.tuple_component_set_digest, field="tuple_component_set_digest")

        _validate_digest(

            shape.tuple_device_fingerprint_digest,

            field="tuple_device_fingerprint_digest",

        )



        key = (shape.family, shape.operation_id)

        if key in self._shapes:

            existing = self._shapes[key]

            if existing.sanitized_dict() != shape.sanitized_dict():

                raise ShapeRegistryError(

                    f"ambiguous duplicate shape for {shape.family.value}/{shape.operation_id}"

                )

            return

        self._shapes[key] = shape



    def register_from_manifest_entry(

        self,

        entry: dict[str, Any],

        *,

        family: CapabilityFamily,

        component_set_digest: str,

        device_fingerprint_digest: str,

        adapter_version: str,

    ) -> FamilyRegisteredShape:

        operation_id = str(entry.get("operation_id", "")).strip()

        if not operation_id:

            raise ShapeRegistryError("manifest entry missing operation_id")

        method = str(entry.get("method", "")).upper()

        path = str(entry.get("path", ""))

        body_keys_raw = entry.get("body_keys") or []

        if not isinstance(body_keys_raw, list):

            raise ShapeRegistryError("manifest entry body_keys must be a list")

        tuple_ref = entry.get("tuple_binding") or {}

        if isinstance(tuple_ref, dict):

            comp = str(tuple_ref.get("component_set_digest", component_set_digest))

            fp = str(tuple_ref.get("device_fingerprint_digest", device_fingerprint_digest))

        else:

            comp = component_set_digest

            fp = device_fingerprint_digest

        if comp != component_set_digest:

            raise ShapeRegistryError("manifest entry tuple component_set_digest mismatch")

        if fp != device_fingerprint_digest:

            raise ShapeRegistryError("manifest entry tuple device_fingerprint_digest mismatch")

        evidence_hash = entry.get("evidence_hash")

        if evidence_hash is None:

            raise ShapeRegistryError("manifest entry missing evidence_hash")

        evidence_hash = str(evidence_hash)

        if evidence_hash == "hash_pending":

            raise ShapeRegistryError("hash_pending manifests cannot register shapes")

        _validate_digest(evidence_hash, field="evidence_hash")



        shape = FamilyRegisteredShape(

            family=family,

            operation_id=operation_id,

            method=method,

            path=path,

            body_keys=tuple(str(item) for item in body_keys_raw),

            tuple_component_set_digest=comp,

            tuple_device_fingerprint_digest=fp,

            adapter_version=adapter_version,

            evidence_hash=evidence_hash,

        )

        self.register_shape(shape)

        return shape



    def get(self, family: CapabilityFamily | str, operation_id: str) -> FamilyRegisteredShape:

        resolved = parse_capability_family(family) if isinstance(family, str) else family

        try:

            return self._shapes[(resolved, operation_id)]

        except KeyError as exc:

            raise CommandShapeUnknown(

                f"no registered shape for {resolved.value}/{operation_id}"

            ) from exc



    def for_family(self, family: CapabilityFamily | str) -> frozenset[str]:

        resolved = parse_capability_family(family) if isinstance(family, str) else family

        return frozenset(op for fam, op in self._shapes if fam == resolved)





def assert_no_generic_rci_executor(callable_name: str) -> None:

    forbidden = (
        "execute_rci",
        "execute_rci_parse",
        "raw_rci",
        "send_command",
        "arbitrary_path",
    )

    if callable_name in forbidden:

        raise ShapeRegistryError("generic RCI executor is forbidden")





class CertifiedOperationUnknown(ShapeRegistryError):

    """No certified registered operation exists for the typed operation."""





class PromotionError(ShapeRegistryError):

    """Operation promotion state transition rejected."""





@dataclass

class CertifiedOperationRegistry:

    """Runtime registry — loads Certified promotion state only; empty by default."""



    def __init__(self) -> None:

        self._operations: dict[tuple[CapabilityFamily, str], RegisteredOperation] = {}

        self._promotion_grants: set[tuple[CapabilityFamily, str]] = set()



    def __len__(self) -> int:

        return len(self._operations)



    def is_empty(self) -> bool:

        return len(self._operations) == 0

    def content_digest(self) -> str:
        """Deterministic snapshot digest for registry equality checks."""

        entries: list[dict[str, str]] = []
        for family, operation_id in sorted(
            self._operations,
            key=lambda item: (item[0].value, item[1]),
        ):
            operation = self._operations[(family, operation_id)]
            entries.append(
                {
                    "family": family.value,
                    "operation_id": operation_id,
                    "spec_digest": operation.spec.spec_digest,
                    "promotion_state": operation.promotion_state,
                }
            )
        payload = json.dumps(entries, sort_keys=True, separators=(",", ":"))
        return f"sha256:{hashlib.sha256(payload.encode()).hexdigest()}"

    def register_operation(self, operation: RegisteredOperation) -> None:

        """Direct mint forbidden — use promote_lab_observed_to_certified only."""

        if operation.promotion_state != RUNTIME_LOAD_PROMOTION_STATE.value:

            raise PromotionError(

                f"runtime registry accepts only {RUNTIME_LOAD_PROMOTION_STATE.value} operations"

            )

        key = (operation.spec.family, operation.spec.operation_id)

        if key not in self._promotion_grants:

            raise PromotionError(

                "direct certified mint forbidden — promotion pipeline required"

            )

        self._install_certified(operation)



    def _install_certified(self, operation: RegisteredOperation) -> None:

        key = (operation.spec.family, operation.spec.operation_id)

        if key in self._operations:

            existing = self._operations[key]

            if existing.spec.spec_digest != operation.spec.spec_digest:

                del self._operations[key]

                self._promotion_grants.discard(key)

                raise PromotionError(

                    f"digest change revokes prior certified registration for "

                    f"{key[0].value}/{key[1]}"

                )

            return

        self._operations[key] = operation



    def get_registered(

        self,

        family: CapabilityFamily | str,

        operation_id: str,

    ) -> RegisteredOperation:

        resolved = parse_capability_family(family) if isinstance(family, str) else family

        try:

            operation = self._operations[(resolved, operation_id)]

        except KeyError as exc:

            raise CertifiedOperationUnknown(

                f"no certified operation for {resolved.value}/{operation_id}"

            ) from exc

        if operation.promotion_state != ShapePromotionState.CERTIFIED.value:

            raise PromotionError("runtime registry entry is not certified")

        return operation



    def revoke_on_digest_change(

        self,

        family: CapabilityFamily | str,

        operation_id: str,

        *,

        next_spec_digest: str,

    ) -> None:

        resolved = parse_capability_family(family) if isinstance(family, str) else family

        key = (resolved, operation_id)

        existing = self._operations.get(key)

        if existing is None:

            return

        if existing.spec.spec_digest != next_spec_digest:

            del self._operations[key]

            self._promotion_grants.discard(key)



    def promote_lab_observed_to_certified(

        self,

        operation: RegisteredOperation,

        *,

        lab_evidence_verified: bool,

        independent_promotion: bool,

        persistent_family_certification: bool,

    ) -> RegisteredOperation:

        if operation.promotion_state != ShapePromotionState.LAB_OBSERVED.value:

            raise PromotionError("only lab_observed operations may promote to certified")

        if not lab_evidence_verified:

            raise PromotionError("lab observed exact tuple/T4/evidence required")

        if not independent_promotion or not persistent_family_certification:

            raise PromotionError(

                "independent promotion and persistent family certification required"

            )

        key = (operation.spec.family, operation.spec.operation_id)

        self.revoke_on_digest_change(

            operation.spec.family,

            operation.spec.operation_id,

            next_spec_digest=operation.spec.spec_digest,

        )

        promoted = replace(operation, promotion_state=ShapePromotionState.CERTIFIED.value)

        self._promotion_grants.add(key)

        self.register_operation(promoted)

        return promoted





@dataclass

class OperationPromotionRegistry:

    """Candidate/lab_observed staging — never used for runtime dispatch."""



    def __init__(self) -> None:

        self._staging: dict[tuple[CapabilityFamily, str], RegisteredOperation] = {}



    def register_candidate(self, operation: RegisteredOperation) -> None:

        if operation.promotion_state not in {s.value for s in CANDIDATE_PROMOTION_STATES}:

            raise PromotionError("candidate registry accepts candidate state only")

        key = (operation.spec.family, operation.spec.operation_id)

        self._staging[key] = operation



    def mark_lab_observed(

        self,

        operation: RegisteredOperation,

        *,

        evidence: LabObservedEvidence,

    ) -> RegisteredOperation:

        if operation.promotion_state != ShapePromotionState.CANDIDATE.value:

            raise PromotionError("only candidate operations may become lab_observed")

        if not evidence.trial_authorized:

            raise PromotionError("Gate B/C trial authorization required for lab_observed")

        if not evidence.artifact_digest_verified:

            raise PromotionError("verified artifact digest required for lab_observed")

        if not evidence.matches_operation(operation):

            raise PromotionError("lab_observed evidence tuple/digest mismatch")

        observed = replace(operation, promotion_state=ShapePromotionState.LAB_OBSERVED.value)

        key = (operation.spec.family, operation.spec.operation_id)

        self._staging[key] = observed

        return observed



    def revoke(self, family: CapabilityFamily | str, operation_id: str) -> None:

        resolved = parse_capability_family(family) if isinstance(family, str) else family

        key = (resolved, operation_id)

        if key not in self._staging:

            raise PromotionError(f"no staged operation to revoke: {resolved.value}/{operation_id}")

        existing = self._staging[key]

        self._staging[key] = replace(existing, promotion_state=ShapePromotionState.REVOKED.value)





def promote_through_pipeline(

    *,

    staging: OperationPromotionRegistry,

    runtime: CertifiedOperationRegistry,

    candidate: RegisteredOperation,

    evidence: LabObservedEvidence,

) -> RegisteredOperation:

    """Test/helper path: Candidate→LabObserved→Certified with evidence checks."""

    staging.register_candidate(candidate)

    observed = staging.mark_lab_observed(candidate, evidence=evidence)

    return runtime.promote_lab_observed_to_certified(

        observed,

        lab_evidence_verified=True,

        independent_promotion=True,

        persistent_family_certification=True,

    )





__all__ = [

    "CANDIDATE_PROMOTION_STATES",

    "CertifiedOperationRegistry",

    "CertifiedOperationUnknown",

    "CommandShapeUnknown",

    "FamilyRegisteredShape",

    "FamilyShapeRegistry",

    "LAB_OBSERVED_PROMOTION_STATES",

    "LabObservedEvidence",

    "OperationPromotionRegistry",

    "PromotionError",

    "RUNTIME_LOAD_PROMOTION_STATE",

    "ShapePromotionState",

    "ShapeRegistryError",

    "assert_no_generic_rci_executor",

    "promote_through_pipeline",

]


