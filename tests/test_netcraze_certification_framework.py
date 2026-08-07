"""Tests for offline certification framework."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from router_control.adapters.netcraze.capability_families import (
    CapabilityFamily,
    FamilyCatalog,
    FamilyCertificationState,
    TupleBinding,
)
from router_control.adapters.netcraze.certification_framework import (
    CertificationPlanner,
    CertificationRunner,
    evaluate_prerequisites,
)
from router_control.domain.errors import DispatchForbidden

COMPONENT_DIGEST = "sha256:de72a7af2255a1993c382ffd41143b8061525137b0d8e192811a32babf852f2f"
FINGERPRINT_DIGEST = "sha256:eb58946c0d18b3cb259c2687e474d10907dfdbbcf39c88992202917c37855169"
NOW = datetime(2026, 7, 22, 12, 0, 0, tzinfo=UTC)


def _tuple_binding() -> TupleBinding:
    return TupleBinding(
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


def test_planner_deterministic_packet() -> None:
    planner = CertificationPlanner()
    packet_a = planner.plan(CapabilityFamily.FAIL_SAFE, now=NOW)
    packet_b = planner.plan(CapabilityFamily.FAIL_SAFE, now=NOW)
    assert packet_a["capability_family"] == "fail_safe"
    assert packet_a["dispatch_permitted"] is False
    assert packet_a["write_certified_claim"] is False
    assert packet_a["mode"] == "offline_plan"
    assert packet_a["planned_at"] == packet_b["planned_at"]
    assert packet_a["first_live_campaign_note"] == (
        "deferred until P1-P3 live substrate + fresh exact T4 Human Gate"
    )


def test_vlan_requires_fail_safe_write_certified_prerequisite() -> None:
    catalog = FamilyCatalog()
    catalog.set_state(CapabilityFamily.FAIL_SAFE, FamilyCertificationState.TRIAL_AUTHORIZED)
    planner = CertificationPlanner(catalog=catalog)
    packet = planner.plan(CapabilityFamily.VLAN, now=NOW)
    checklist = packet["prerequisite_checklist"]["items"]
    fail_safe_item = next(item for item in checklist if item["check_id"] == "fail_safe_observed")
    assert fail_safe_item["required"] is True
    assert fail_safe_item["satisfied"] is False
    assert packet["first_live_campaign_note"] == "requires fail_safe WriteCertified prerequisite"


def test_other_families_require_fail_safe_note() -> None:
    planner = CertificationPlanner()
    packet = planner.plan(CapabilityFamily.VLAN, now=NOW)
    assert packet["first_live_campaign_note"] == "requires fail_safe WriteCertified prerequisite"


def test_dispatch_always_forbidden() -> None:
    runner = CertificationRunner()
    with pytest.raises(DispatchForbidden):
        runner.dispatch()
    with pytest.raises(DispatchForbidden):
        runner.execute_live()


def test_plan_from_fixtures() -> None:
    catalog = FamilyCatalog()
    catalog.set_state(CapabilityFamily.FAIL_SAFE, FamilyCertificationState.CANDIDATE_OBSERVED)
    planner = CertificationPlanner(catalog=catalog)
    runner = CertificationRunner(
        planner=planner,
        fixtures={
            "lab-default": {
                "tuple_binding": _tuple_binding().sanitized_dict(),
                "probe_evidence": {
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
                },
            }
        },
    )
    packet = runner.plan_from_fixtures(
        CapabilityFamily.FAIL_SAFE,
        fixture_id="lab-default",
        now=NOW,
    )
    assert packet["fixture_replay"] is True
    assert packet["dispatch_permitted"] is False


def test_startup_backup_unsatisfied_by_default() -> None:
    planner = CertificationPlanner()
    packet = planner.plan(CapabilityFamily.FAIL_SAFE, now=NOW)
    checklist = packet["prerequisite_checklist"]["items"]
    backup_item = next(item for item in checklist if item["check_id"] == "startup_backup")
    assert backup_item["required"] is True
    assert backup_item["satisfied"] is False


def test_startup_backup_satisfied_when_verified() -> None:
    planner = CertificationPlanner()
    checklist = evaluate_prerequisites(
        family=CapabilityFamily.FAIL_SAFE,
        catalog=planner.catalog,
        tuple_binding=None,
        gate_bc=None,
        registry=planner.registry,
        probe_evidence=None,
        now=NOW,
        startup_backup_verified=True,
    )
    backup_item = next(item for item in checklist.items if item.check_id == "startup_backup")
    assert backup_item.satisfied is True


def test_amneziawg_skips_fail_safe_observed_prerequisite() -> None:
    planner = CertificationPlanner()
    packet = planner.plan(CapabilityFamily.AMNEZIAWG, now=NOW)
    checklist = packet["prerequisite_checklist"]["items"]
    check_ids = {item["check_id"] for item in checklist}
    assert "fail_safe_observed" not in check_ids
    assert packet["first_live_campaign_note"] == (
        "deferred until P1-P3 live substrate + fresh exact T4 Human Gate"
    )


def test_routes_skips_fail_safe_observed_prerequisite() -> None:
    planner = CertificationPlanner()
    packet = planner.plan(CapabilityFamily.ROUTES, now=NOW)
    checklist = packet["prerequisite_checklist"]["items"]
    check_ids = {item["check_id"] for item in checklist}
    assert "fail_safe_observed" not in check_ids
