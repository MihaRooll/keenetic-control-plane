"""Tests for capability family catalog."""

from __future__ import annotations

import pytest
from router_control.adapters.netcraze.capability_families import (
    FAMILY_DEPENDENCY_ORDER,
    CapabilityFamily,
    FamilyCatalog,
    FamilyCertificationState,
    TupleBinding,
    families_before,
    normalize_family_for_gate_bc,
    parse_capability_family,
)

COMPONENT_DIGEST = "sha256:de72a7af2255a1993c382ffd41143b8061525137b0d8e192811a32babf852f2f"
FINGERPRINT_DIGEST = "sha256:eb58946c0d18b3cb259c2687e474d10907dfdbbcf39c88992202917c37855169"


def test_all_families_in_dependency_order() -> None:
    expected = {
        "fail_safe",
        "vlan",
        "dhcp",
        "dns",
        "wifi",
        "firewall",
        "amneziawg",
        "routes",
    }
    assert {f.value for f in FAMILY_DEPENDENCY_ORDER} == expected
    assert FAMILY_DEPENDENCY_ORDER[0] == CapabilityFamily.FAIL_SAFE


def test_default_state_unknown() -> None:
    catalog = FamilyCatalog()
    for family in FAMILY_DEPENDENCY_ORDER:
        assert catalog.get_state(family) == FamilyCertificationState.UNKNOWN


def test_write_certified_cannot_be_set() -> None:
    catalog = FamilyCatalog()
    with pytest.raises(ValueError, match="WriteCertified"):
        catalog.set_state(CapabilityFamily.VLAN, FamilyCertificationState.WRITE_CERTIFIED)


def test_family_aliases() -> None:
    assert parse_capability_family("AmneziaWG") == CapabilityFamily.AMNEZIAWG
    assert normalize_family_for_gate_bc("amneziawg") == "AmneziaWG"


def test_families_before_routes() -> None:
    prior = families_before(CapabilityFamily.ROUTES)
    assert prior[-1] == CapabilityFamily.AMNEZIAWG
    assert CapabilityFamily.FAIL_SAFE in prior


def test_tuple_binding_matches_probe_evidence() -> None:
    binding = TupleBinding(
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
    )
    evidence = {
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
    assert binding.matches_evidence(evidence)


def test_dependency_fail_safe_write_certified_required_for_vlan() -> None:
    catalog = FamilyCatalog()
    assert not catalog.dependency_satisfied(CapabilityFamily.VLAN)
    catalog.set_state(CapabilityFamily.FAIL_SAFE, FamilyCertificationState.TRIAL_AUTHORIZED)
    assert not catalog.dependency_satisfied(CapabilityFamily.VLAN)
    catalog.set_state(CapabilityFamily.FAIL_SAFE, FamilyCertificationState.CANDIDATE_OBSERVED)
    assert not catalog.dependency_satisfied(CapabilityFamily.VLAN)


def test_trial_authorized_never_satisfies_write_certified_readiness() -> None:
    catalog = FamilyCatalog()
    catalog.set_state(CapabilityFamily.FAIL_SAFE, FamilyCertificationState.TRIAL_AUTHORIZED)
    assert not catalog.write_certified_readiness(CapabilityFamily.FAIL_SAFE)


def test_amneziawg_dependency_independent() -> None:
    catalog = FamilyCatalog()
    assert catalog.dependency_satisfied(CapabilityFamily.AMNEZIAWG)


def test_dependency_dhcp_requires_write_certified_chain() -> None:
    catalog = FamilyCatalog()
    catalog._states[CapabilityFamily.FAIL_SAFE] = FamilyCertificationState.WRITE_CERTIFIED
    catalog._states[CapabilityFamily.VLAN] = FamilyCertificationState.TRIAL_AUTHORIZED
    assert not catalog.dependency_satisfied(CapabilityFamily.DHCP)
    catalog._states[CapabilityFamily.VLAN] = FamilyCertificationState.WRITE_CERTIFIED
    assert catalog.dependency_satisfied(CapabilityFamily.DHCP)
