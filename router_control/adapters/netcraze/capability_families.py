"""Per-family capability catalog — dependency order and certification state."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from router_control.adapters.netcraze.tuple_evidence import tuple_evidence_fields_or_none


class CapabilityFamily(StrEnum):
    FAIL_SAFE = "fail_safe"
    VLAN = "vlan"
    DHCP = "dhcp"
    DNS = "dns"
    WIFI = "wifi"
    FIREWALL = "firewall"
    AMNEZIAWG = "amneziawg"
    ROUTES = "routes"


FAMILY_DEPENDENCY_ORDER: tuple[CapabilityFamily, ...] = (
    CapabilityFamily.FAIL_SAFE,
    CapabilityFamily.VLAN,
    CapabilityFamily.DHCP,
    CapabilityFamily.DNS,
    CapabilityFamily.WIFI,
    CapabilityFamily.FIREWALL,
    CapabilityFamily.AMNEZIAWG,
    CapabilityFamily.ROUTES,
)

FAMILY_ALIASES: dict[str, CapabilityFamily] = {
    "fail_safe": CapabilityFamily.FAIL_SAFE,
    "Fail-safe Configuration": CapabilityFamily.FAIL_SAFE,
    "vlan": CapabilityFamily.VLAN,
    "dhcp": CapabilityFamily.DHCP,
    "dns": CapabilityFamily.DNS,
    "wifi": CapabilityFamily.WIFI,
    "firewall": CapabilityFamily.FIREWALL,
    "amneziawg": CapabilityFamily.AMNEZIAWG,
    "AmneziaWG": CapabilityFamily.AMNEZIAWG,
    "routes": CapabilityFamily.ROUTES,
}


class FamilyCertificationState(StrEnum):
    UNKNOWN = "Unknown"
    CANDIDATE_OBSERVED = "CandidateObserved"
    TRIAL_AUTHORIZED = "TrialAuthorized"
    WRITE_CERTIFIED = "WriteCertified"
    UNSUPPORTED = "Unsupported"
    REVOKED = "Revoked"


DEFAULT_FAMILY_STATE = FamilyCertificationState.UNKNOWN

DISRUPTIVE_LAN_FAMILIES: frozenset[CapabilityFamily] = frozenset(
    {
        CapabilityFamily.VLAN,
        CapabilityFamily.DHCP,
        CapabilityFamily.DNS,
        CapabilityFamily.WIFI,
        CapabilityFamily.FIREWALL,
    }
)
PLAN_INDEPENDENT_FAMILIES: frozenset[CapabilityFamily] = frozenset(
    {
        CapabilityFamily.AMNEZIAWG,
        CapabilityFamily.ROUTES,
    }
)

_STATE_SATISFACTION_RANK: dict[FamilyCertificationState, int] = {
    FamilyCertificationState.UNKNOWN: 0,
    FamilyCertificationState.CANDIDATE_OBSERVED: 1,
    FamilyCertificationState.TRIAL_AUTHORIZED: 2,
    FamilyCertificationState.WRITE_CERTIFIED: 3,
}

_NEVER_SATISFY_STATES = frozenset(
    {
        FamilyCertificationState.UNSUPPORTED,
        FamilyCertificationState.REVOKED,
    }
)


@dataclass(frozen=True, slots=True)
class TupleBinding:
    model: str
    firmware_version: str
    ndm_build: str
    bsp_build: str
    update_channel: str
    region: str
    component_set_digest: str
    device_fingerprint_digest: str
    transport: str
    ssh_host_key_algorithm: str

    def matches_evidence(self, evidence: dict[str, Any]) -> bool:
        fields = tuple_evidence_fields_or_none(evidence)
        if fields is None:
            return False
        return (
            str(evidence.get("model", "")) == self.model
            and str(evidence.get("firmware_version", "")) == self.firmware_version
            and fields.ndm_build == self.ndm_build
            and str(evidence.get("bsp_build", "")) == self.bsp_build
            and str(evidence.get("update_channel", "")) == self.update_channel
            and str(evidence.get("region", "")) == self.region
            and str(evidence.get("component_set_digest", "")) == self.component_set_digest
            and fields.device_fingerprint_digest == self.device_fingerprint_digest
            and fields.transport == self.transport
            and str(evidence.get("ssh_host_key_algorithm", "")) == self.ssh_host_key_algorithm
        )

    def sanitized_dict(self) -> dict[str, str]:
        return {
            "model": self.model,
            "firmware_version": self.firmware_version,
            "ndm_build": self.ndm_build,
            "bsp_build": self.bsp_build,
            "update_channel": self.update_channel,
            "region": self.region,
            "component_set_digest": self.component_set_digest,
            "device_fingerprint_digest": self.device_fingerprint_digest,
            "transport": self.transport,
            "ssh_host_key_algorithm": self.ssh_host_key_algorithm,
        }


def parse_capability_family(value: str) -> CapabilityFamily:
    normalized = value.strip()
    if normalized in FAMILY_ALIASES:
        return FAMILY_ALIASES[normalized]
    try:
        return CapabilityFamily(normalized.lower())
    except ValueError as exc:
        raise ValueError(f"unknown capability family: {value}") from exc


def normalize_family_for_gate_bc(value: str) -> str:
    """Map family literals to canonical gate binding form."""
    family = parse_capability_family(value)
    if family == CapabilityFamily.AMNEZIAWG:
        return "AmneziaWG"
    return family.value


def families_before(family: CapabilityFamily) -> tuple[CapabilityFamily, ...]:
    order = FAMILY_DEPENDENCY_ORDER
    try:
        index = order.index(family)
    except ValueError as exc:
        raise ValueError(f"family not in dependency order: {family}") from exc
    return order[:index]


@dataclass
class FamilyCatalog:
    """In-memory per-family certification state — default Unknown."""

    tuple_binding: TupleBinding | None = None
    _states: dict[CapabilityFamily, FamilyCertificationState] = field(default_factory=dict)

    def get_state(self, family: CapabilityFamily | str) -> FamilyCertificationState:
        resolved = parse_capability_family(family) if isinstance(family, str) else family
        return self._states.get(resolved, DEFAULT_FAMILY_STATE)

    def set_state(
        self,
        family: CapabilityFamily | str,
        state: FamilyCertificationState,
    ) -> None:
        resolved = parse_capability_family(family) if isinstance(family, str) else family
        if state == FamilyCertificationState.WRITE_CERTIFIED:
            raise ValueError(
                "WriteCertified cannot be set via catalog — requires verified evidence"
            )
        self._states[resolved] = state

    def dependency_satisfied(
        self,
        family: CapabilityFamily,
        *,
        required_state: FamilyCertificationState | None = None,
    ) -> bool:
        resolved = parse_capability_family(family) if isinstance(family, str) else family
        if resolved in PLAN_INDEPENDENT_FAMILIES:
            return True
        effective_required = (
            required_state
            if required_state is not None
            else FamilyCertificationState.WRITE_CERTIFIED
        )
        if effective_required not in _STATE_SATISFACTION_RANK:
            return False
        required_rank = _STATE_SATISFACTION_RANK[effective_required]
        for prior in families_before(resolved):
            prior_state = self.get_state(prior)
            if prior_state in _NEVER_SATISFY_STATES:
                return False
            prior_rank = _STATE_SATISFACTION_RANK.get(prior_state)
            if prior_rank is None or prior_rank < required_rank:
                return False
        return True

    def write_certified_readiness(self, family: CapabilityFamily | str) -> bool:
        """True only when family holds verified WriteCertified."""
        resolved = parse_capability_family(family) if isinstance(family, str) else family
        return self.get_state(resolved) == FamilyCertificationState.WRITE_CERTIFIED

    def all_families(self) -> tuple[CapabilityFamily, ...]:
        return FAMILY_DEPENDENCY_ORDER

    def snapshot(self) -> dict[str, str]:
        return {family.value: self.get_state(family).value for family in FAMILY_DEPENDENCY_ORDER}


__all__ = [
    "DEFAULT_FAMILY_STATE",
    "DISRUPTIVE_LAN_FAMILIES",
    "FAMILY_ALIASES",
    "FAMILY_DEPENDENCY_ORDER",
    "CapabilityFamily",
    "FamilyCatalog",
    "FamilyCertificationState",
    "PLAN_INDEPENDENT_FAMILIES",
    "TupleBinding",
    "families_before",
    "normalize_family_for_gate_bc",
    "parse_capability_family",
]
