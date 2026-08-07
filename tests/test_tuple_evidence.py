"""Tests for canonical tuple evidence field normalization."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest
from router_control.adapters.netcraze.capability_families import TupleBinding
from router_control.adapters.netcraze.certification import GateACertification
from router_control.adapters.netcraze.fail_safe_certification import FailSafeTupleBinding
from router_control.adapters.netcraze.gate_bc import GateBCAuthorization, GateBCTupleBinding
from router_control.adapters.netcraze.ssh_cli_discovery import SshCliTupleBinding
from router_control.adapters.netcraze.tuple_evidence import (
    TupleEvidenceConflictError,
    extract_tuple_evidence_match_fields,
    resolve_alias_pair,
    tuple_evidence_fields_or_none,
)

COMPONENT_DIGEST = "sha256:" + "a" * 64
FINGERPRINT_DIGEST = "sha256:" + "b" * 64
HOST_KEY_FINGERPRINT = "SHA256:" + "c" * 43


def _gate_binding() -> GateBCTupleBinding:
    return GateBCTupleBinding(
        model="M",
        firmware_version="1.0",
        ndm_build="canonical-build",
        bsp_build="bsp",
        update_channel="Main",
        region="EA",
        component_set_digest=COMPONENT_DIGEST,
        device_fingerprint_digest=FINGERPRINT_DIGEST,
        transport="ssh_tunnel",
        ssh_host_key_algorithm="ssh-ed25519",
    )


def _cap_binding() -> TupleBinding:
    binding = _gate_binding()
    return TupleBinding(
        model=binding.model,
        firmware_version=binding.firmware_version,
        ndm_build=binding.ndm_build,
        bsp_build=binding.bsp_build,
        update_channel=binding.update_channel,
        region=binding.region,
        component_set_digest=binding.component_set_digest,
        device_fingerprint_digest=binding.device_fingerprint_digest,
        transport=binding.transport,
        ssh_host_key_algorithm=binding.ssh_host_key_algorithm,
    )


def _fail_safe_binding() -> FailSafeTupleBinding:
    binding = _gate_binding()
    return FailSafeTupleBinding(
        model=binding.model,
        firmware_version=binding.firmware_version,
        ndm_build=binding.ndm_build,
        bsp_build=binding.bsp_build,
        update_channel=binding.update_channel,
        region=binding.region,
        component_set_digest=binding.component_set_digest,
        device_fingerprint_digest=binding.device_fingerprint_digest,
        transport=binding.transport,
        ssh_host_key_algorithm=binding.ssh_host_key_algorithm,
    )


def _ssh_cli_binding() -> SshCliTupleBinding:
    binding = _gate_binding()
    return SshCliTupleBinding(
        model=binding.model,
        firmware_version=binding.firmware_version,
        ndm_build=binding.ndm_build,
        bsp_build=binding.bsp_build,
        update_channel=binding.update_channel,
        region=binding.region,
        component_set_digest=binding.component_set_digest,
        device_fingerprint_digest=binding.device_fingerprint_digest,
        transport=binding.transport,
        ssh_host_key_algorithm=binding.ssh_host_key_algorithm,
    )


def _gate_a_certification() -> GateACertification:
    recorded = datetime(2026, 1, 1, tzinfo=UTC)
    return GateACertification(
        status="open",
        certification="ReadOnlyCertified",
        approved_scope="SLICE-4-readonly",
        model="M",
        model_display="M",
        firmware_version="1.0",
        firmware_display="1.0",
        ndm_build="canonical-build",
        bsp_build="bsp",
        update_channel="Main",
        region="EA",
        component_set_digest=COMPONENT_DIGEST,
        device_fingerprint_digest=FINGERPRINT_DIGEST,
        physical_id_source="synthetic",
        transport="ssh_tunnel",
        ssh_host_key_algorithm="ssh-ed25519",
        ssh_host_key_fingerprint_sha256=HOST_KEY_FINGERPRINT,
        certification_eligible=True,
        evidence_recorded_at=recorded,
        evidence_path="synthetic-evidence.json",
        expires_at=recorded + timedelta(days=90),
        revocation_policy="test",
    )


def _match_context() -> tuple[
    GateBCAuthorization,
    TupleBinding,
    FailSafeTupleBinding,
    SshCliTupleBinding,
    GateACertification,
]:
    gate_binding = _gate_binding()
    auth = type("Auth", (), {"tuple_binding": gate_binding})()
    return (
        auth,
        _cap_binding(),
        _fail_safe_binding(),
        _ssh_cli_binding(),
        _gate_a_certification(),
    )


def _gate_a_evidence(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "model": "M",
        "firmware_version": "1.0",
        "ndm_build": "canonical-build",
        "bsp_build": "bsp",
        "update_channel": "Main",
        "region": "EA",
        "component_set_digest": COMPONENT_DIGEST,
        "device_fingerprint_digest": FINGERPRINT_DIGEST,
        "transport": "ssh_tunnel",
        "ssh_host_key_algorithm": "ssh-ed25519",
        "ssh_host_key_fingerprint_sha256": HOST_KEY_FINGERPRINT,
        "certification_eligible": True,
        "identity_complete": True,
    }
    payload.update(overrides)
    return payload


def _base_evidence(**overrides: str) -> dict[str, str]:
    payload = {
        "model": "M",
        "firmware_version": "1.0",
        "ndm_build": "canonical-build",
        "bsp_build": "bsp",
        "update_channel": "Main",
        "region": "EA",
        "component_set_digest": COMPONENT_DIGEST,
        "device_fingerprint_digest": FINGERPRINT_DIGEST,
        "transport": "ssh_tunnel",
        "ssh_host_key_algorithm": "ssh-ed25519",
    }
    payload.update(overrides)
    return payload


def test_matching_duplicate_aliases_accepted() -> None:
    evidence = _base_evidence(build="canonical-build", transport_security="ssh_tunnel")
    fields = extract_tuple_evidence_match_fields(evidence)
    assert fields.ndm_build == "canonical-build"
    assert fields.transport == "ssh_tunnel"


def test_conflicting_ndm_build_raises() -> None:
    evidence = _base_evidence(build="alias-build")
    with pytest.raises(
        TupleEvidenceConflictError,
        match="conflicting tuple evidence keys 'ndm_build'",
    ):
        extract_tuple_evidence_match_fields(evidence)


def test_conflicting_transport_raises() -> None:
    evidence = _base_evidence(transport_security="other_transport")
    with pytest.raises(
        TupleEvidenceConflictError,
        match="conflicting tuple evidence keys 'transport'",
    ):
        extract_tuple_evidence_match_fields(evidence)


def test_conflicting_fingerprint_raises() -> None:
    evidence = _base_evidence(device_fingerprint="sha256:" + "c" * 64)
    with pytest.raises(
        TupleEvidenceConflictError,
        match="conflicting tuple evidence keys 'device_fingerprint_digest'",
    ):
        extract_tuple_evidence_match_fields(evidence)


def test_missing_canonical_uses_alias() -> None:
    evidence = _base_evidence()
    del evidence["ndm_build"]
    del evidence["transport"]
    del evidence["device_fingerprint_digest"]
    evidence["build"] = "canonical-build"
    evidence["transport_security"] = "ssh_tunnel"
    evidence["device_fingerprint"] = FINGERPRINT_DIGEST
    fields = extract_tuple_evidence_match_fields(evidence)
    assert fields.ndm_build == "canonical-build"
    assert fields.transport == "ssh_tunnel"
    assert fields.device_fingerprint_digest == FINGERPRINT_DIGEST


def test_empty_alias_value_falls_back_to_canonical() -> None:
    evidence = _base_evidence(build="", transport_security="")
    fields = extract_tuple_evidence_match_fields(evidence)
    assert fields.ndm_build == "canonical-build"
    assert fields.transport == "ssh_tunnel"


def test_both_empty_returns_empty_string() -> None:
    evidence = {"ndm_build": "", "build": ""}
    assert resolve_alias_pair(evidence, canonical="ndm_build", alias="build") == ""


def test_wrong_key_case_is_not_normalized() -> None:
    evidence = {"NDM_BUILD": "canonical-build", "build": "alias-build"}
    assert resolve_alias_pair(evidence, canonical="ndm_build", alias="build") == "alias-build"


def test_gate_bc_and_capability_families_agree_on_conflicting_aliases() -> None:
    gate_binding = _gate_binding()
    cap_binding = _cap_binding()
    auth = type("Auth", (), {"tuple_binding": gate_binding})()

    evidence = _base_evidence(build="alias-build")
    gate_match = GateBCAuthorization.matches_probe_evidence(auth, evidence)
    cap_match = cap_binding.matches_evidence(evidence)
    assert gate_match is False
    assert cap_match is False
    assert gate_match == cap_match


def test_gate_bc_and_capability_families_agree_on_conflicting_transport() -> None:
    gate_binding = _gate_binding()
    cap_binding = _cap_binding()
    auth = type("Auth", (), {"tuple_binding": gate_binding})()

    evidence = _base_evidence(transport_security="other_transport")
    gate_match = GateBCAuthorization.matches_probe_evidence(auth, evidence)
    cap_match = cap_binding.matches_evidence(evidence)
    assert gate_match is False
    assert cap_match is False
    assert gate_match == cap_match


def test_tuple_evidence_fields_or_none_returns_none_on_conflict() -> None:
    evidence = _base_evidence(build="alias-build")
    assert tuple_evidence_fields_or_none(evidence) is None


_CONFLICT_CASES = (
    pytest.param({"build": "alias-build"}, id="ndm_build_vs_build"),
    pytest.param({"transport_security": "other_transport"}, id="transport_vs_transport_security"),
    pytest.param(
        {"device_fingerprint": "sha256:" + "c" * 64},
        id="device_fingerprint_vs_digest",
    ),
)


def _matcher_registry(
    auth: GateBCAuthorization,
    cap_binding: TupleBinding,
    fail_safe_binding: FailSafeTupleBinding,
    ssh_cli_binding: SshCliTupleBinding,
    gate_a: GateACertification,
) -> dict[str, Callable[[dict[str, object]], bool]]:
    return {
        "tuple_evidence_fields_or_none": lambda evidence: (
            tuple_evidence_fields_or_none(evidence) is not None
        ),
        "gate_bc": lambda evidence: GateBCAuthorization.matches_probe_evidence(
            auth, evidence  # type: ignore[arg-type]
        ),
        "capability_families": cap_binding.matches_evidence,
        "gate_a_certification": gate_a.matches_probe_evidence,
        "fail_safe_certification": fail_safe_binding.matches_probe_evidence,
        "ssh_cli_discovery": ssh_cli_binding.matches_probe_evidence,
    }


@pytest.mark.parametrize("conflict_overrides", _CONFLICT_CASES)
@pytest.mark.parametrize(
    "matcher_name",
    (
        "tuple_evidence_fields_or_none",
        "gate_bc",
        "capability_families",
        "gate_a_certification",
        "fail_safe_certification",
        "ssh_cli_discovery",
    ),
)
def test_all_matchers_deny_on_conflicting_aliases(
    matcher_name: str,
    conflict_overrides: dict[str, str],
) -> None:
    auth, cap_binding, fail_safe_binding, ssh_cli_binding, gate_a = _match_context()
    matchers = _matcher_registry(
        auth, cap_binding, fail_safe_binding, ssh_cli_binding, gate_a
    )
    if matcher_name == "gate_a_certification":
        evidence = _gate_a_evidence(**conflict_overrides)
    else:
        evidence = _base_evidence(**conflict_overrides)
    assert matchers[matcher_name](evidence) is False
