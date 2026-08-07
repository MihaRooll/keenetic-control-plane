"""Netcraze dual-shape identity parser tests."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest
from router_control.adapters.netcraze.allowlist import (
    ALLOWLIST,
    COMPONENTS_LIST,
    SHOW_IDENTIFICATION,
    SHOW_SYSTEM,
    SHOW_VERSION,
)
from router_control.adapters.netcraze.errors import IdentityParseError
from router_control.adapters.netcraze.identity import (
    COMPONENT_SET_DIGEST_ALGORITHM,
    COMPONENT_SET_DIGEST_ALGORITHM_LEGACY,
    OperatorIdentityHints,
    extract_hw_id_tokens,
    parse_identity,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "netcraze"

SYNTH_SERIAL = "SYNTH-SERIAL-ABC123"
SYNTH_SERVICETAG = "SYNTH-STAG-XYZ789"
SYNTH_SERIAL_ONLY = "SYNTH-SERIAL-ONLY-001"
CANONICAL_HW_ID = "NC-1812"

LEGACY_FINGERPRINT_DIGEST = (
    "sha256:8c547d85bdb1d057b9ca3fa2b9f117b3da4183867327767e478f8a139f94b380"
)
LEGACY_FIRMWARE_DIGEST = (
    "sha256:8b306fee9aa86300effbff6599b2ab52e1289da1b783f729f55e7272372c0f96"
)
LEGACY_COMPONENT_SET_DIGEST = (
    "sha256:e96f7f9550f3f575b372673d1db0182037a55bfee2fa636f1be0d605718c54ae"
)
OBSERVED_INSTALLED_COMPONENT_IDS = sorted(
    ["comp-alpha", "comp-epsilon"]
)
DUAL_POPULATION_INSTALLED_IDS = sorted(
    json.loads(
        (Path(__file__).resolve().parents[1]
         / "data" / "artifacts" / "component-install-marker-truth-20260801.json").read_text(
            encoding="utf-8"
        )
    )["entries_with_installed_key"]
)


def _load(name: str) -> object:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _digest_sorted_ids(ids: list[str]) -> str:
    canonical = json.dumps(ids, separators=(",", ":"))
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


def _digest_physical(value: str, label: str) -> str:
    material = f"{label}:{value}"
    return f"sha256:{hashlib.sha256(material.encode('utf-8')).hexdigest()}"


def _observed_parse(**kwargs: object):
    defaults = {
        "system_payload": _load("system_telemetry_only.json"),
        "components_payload": _load("components_observed.json"),
    }
    defaults.update(kwargs)
    return parse_identity(
        defaults["system_payload"],
        defaults["components_payload"],
        identification_payload=defaults.get("identification_payload"),
        version_payload=defaults.get("version_payload"),
        hints=defaults.get("hints"),
    )


def _assert_no_raw_physical_leak(parsed: object, *raw_values: str) -> None:
    surfaces = [
        repr(parsed),
        json.dumps(getattr(parsed, "__dict__", {}), default=str),
    ]
    if hasattr(parsed, "fingerprint_digest"):
        surfaces.append(parsed.fingerprint_digest)
    for surface in surfaces:
        for raw in raw_values:
            assert raw not in surface


def test_allowlist_exactly_four_commands() -> None:
    assert len(ALLOWLIST) == 4
    assert ALLOWLIST == frozenset(
        {SHOW_SYSTEM, COMPONENTS_LIST, SHOW_IDENTIFICATION, SHOW_VERSION}
    )


def test_allowlist_new_get_paths() -> None:
    from router_control.adapters.netcraze.allowlist import is_allowlisted

    assert is_allowlisted("GET", "/rci/show/identification")
    assert is_allowlisted("GET", "/rci/show/version")
    assert not is_allowlisted("GET", "/rci/show/running-config")
    assert not is_allowlisted("POST", "/rci/show/identification")


def test_legacy_fixture_digests_remain_stable() -> None:
    first = parse_identity(_load("system.json"), _load("components_list.json"))
    second = parse_identity(_load("system.json"), _load("components_list.json"))
    assert first.identity_shape == "legacy"
    assert first.identity_complete is True
    assert first.fingerprint_status == "stable"
    assert first.fingerprint_digest == LEGACY_FINGERPRINT_DIGEST
    assert first.component_set_digest == LEGACY_COMPONENT_SET_DIGEST
    assert first.component_set_digest_algorithm == COMPONENT_SET_DIGEST_ALGORITHM_LEGACY
    assert first.firmware_digest == LEGACY_FIRMWARE_DIGEST
    assert first.fingerprint_digest == second.fingerprint_digest
    assert first.component_set_digest == second.component_set_digest
    assert first.firmware_digest == second.firmware_digest
    assert first.firmware_version == "5.01"


def test_observed_raw_firmware_and_display_title() -> None:
    parsed = parse_identity(
        _load("system_telemetry_only.json"),
        _load("components_observed.json"),
    )
    assert parsed.identity_shape == "observed"
    assert parsed.firmware_version == "5.01.C.1.0-0"
    assert parsed.firmware_display_title == "5.1.1"
    assert parsed.title is None


def test_observed_installed_only_component_digest() -> None:
    parsed = parse_identity(
        _load("system_telemetry_only.json"),
        _load("components_observed.json"),
    )
    assert parsed.component_set_digest == _digest_sorted_ids(OBSERVED_INSTALLED_COMPONENT_IDS)


def test_observed_excludes_available_only_components() -> None:
    system = _load("system_telemetry_only.json")
    components = copy.deepcopy(_load("components_observed.json"))
    baseline = parse_identity(system, components)
    assert baseline.component_set_digest == _digest_sorted_ids(OBSERVED_INSTALLED_COMPONENT_IDS)
    components["component"]["comp-delta"]["version"] = "9.9.9"
    components["component"]["comp-delta"]["description"] = "mutated available-only metadata"
    mutated = parse_identity(system, components)
    assert mutated.component_set_digest == baseline.component_set_digest
    assert mutated.component_set_digest == _digest_sorted_ids(OBSERVED_INSTALLED_COMPONENT_IDS)


def test_observed_ignores_system_telemetry_for_claims() -> None:
    parsed = parse_identity(
        _load("system_telemetry_only.json"),
        _load("components_observed.json"),
    )
    assert parsed.model == "unknown"
    assert parsed.system_raw == {}
    assert parsed.public_system == {}
    blob = json.dumps(
        {
            "model": parsed.model,
            "firmware_version": parsed.firmware_version,
            "fingerprint_digest": parsed.fingerprint_digest,
        }
    )
    assert "FAKE-HOSTNAME-LEAK" not in blob


def test_observed_fingerprint_stable_when_telemetry_changes() -> None:
    telemetry_a = {
        "hostname": "telemetry-a",
        "domain": "a.example",
        "runtime": {"uptime": 1},
    }
    telemetry_b = {
        "hostname": "telemetry-b",
        "domain": "b.example",
        "runtime": {"uptime": 999},
        "model": "different-model",
    }
    components = _load("components_observed.json")
    first = parse_identity(telemetry_a, components)
    second = parse_identity(telemetry_b, components)
    assert first.fingerprint_digest == second.fingerprint_digest
    assert first.component_set_digest == second.component_set_digest


def test_observed_without_hints_unknown_and_incomplete() -> None:
    parsed = parse_identity(
        _load("system_telemetry_only.json"),
        _load("components_observed.json"),
    )
    assert parsed.model == "unknown"
    assert parsed.update_channel is None
    assert parsed.model_source == "unknown"
    assert parsed.update_channel_source == "unknown"
    assert parsed.identity_complete is False
    assert parsed.fingerprint_status == "provisional"
    assert parsed.build_source == "unknown"
    assert parsed.physical_identifier_source == "missing"


def test_observed_with_compatible_hint_no_disagreement() -> None:
    parsed = _observed_parse(
        identification_payload=_load("identification_both_ids.json"),
        version_payload=_load("version_match.json"),
        hints=OperatorIdentityHints(expected_model="Netcraze Ultra NC-1812"),
    )
    assert parsed.model == CANONICAL_HW_ID
    assert parsed.model_disagreement is False
    assert parsed.identity_complete is True


def test_blank_hints_treated_as_absent() -> None:
    parsed = parse_identity(
        _load("system_telemetry_only.json"),
        _load("components_observed.json"),
        hints=OperatorIdentityHints(expected_model="   ", update_channel=""),
    )
    assert parsed.model == "unknown"
    assert parsed.update_channel is None
    assert parsed.model_source == "unknown"


def test_observed_shape_selected_over_legacy_system_fields() -> None:
    parsed = parse_identity(_load("system.json"), _load("components_observed.json"))
    assert parsed.identity_shape == "observed"
    assert parsed.firmware_version == "5.01.C.1.0-0"


def test_observed_without_installed_components_fail_closed() -> None:
    components = {
        "firmware": {"version": "1.0.0", "title": "1.0"},
        "component": {
            "available-only": {"available": True},
        },
    }
    with pytest.raises(IdentityParseError):
        parse_identity(_load("system_telemetry_only.json"), components)


def test_observed_real_device_component_version_only_shape() -> None:
    """Device sends {id, version} per component — no installed key (SESSION_HANDOFF §2.2)."""
    components = {
        "firmware": {"version": "5.01.C.1.0-0", "title": "5.1.1"},
        "component": {
            "wireguard": {"version": "0.9.20"},
            "wireguard-server": {"version": "0.9.20"},
            "ssh": {"version": "1.0.0"},
        },
    }
    parsed = parse_identity(_load("system_telemetry_only.json"), components)
    assert parsed.component_set_digest == _digest_sorted_ids(
        sorted(["wireguard", "wireguard-server", "ssh"])
    )


def test_observed_installed_false_and_null_excluded() -> None:
    components = {
        "firmware": {"version": "5.01.C.1.0-0", "title": "5.1.1"},
        "component": {
            "installed-yes": {"installed": True, "version": "1.0"},
            "installed-no": {"installed": False, "version": "1.0"},
            "installed-null": {"installed": None},
        },
    }
    parsed = parse_identity(_load("system_telemetry_only.json"), components)
    assert parsed.component_set_digest == _digest_sorted_ids(["installed-yes"])


def test_observed_skips_unrecognized_metadata_keeps_installed_digest() -> None:
    components = {
        "firmware": {"version": "5.01.C.1.0-0", "title": "5.1.1"},
        "component": {
            "wireguard": {"version": "0.9.20"},
            "catalogue-stub": {"description": "not installable"},
        },
    }
    parsed = parse_identity(_load("system_telemetry_only.json"), components)
    assert parsed.component_set_digest == _digest_sorted_ids(["wireguard"])


def test_fail_closed_synthetic_physical_not_leaked_on_component_failure() -> None:
    components = {
        "firmware": {"version": "5.01.C.1.0-0", "title": "5.1.1"},
        "component": {
            "available-only": {"available": True},
        },
    }
    with pytest.raises(IdentityParseError) as exc_info:
        parse_identity(
            _load("system_telemetry_only.json"),
            components,
            identification_payload=_load("identification_both_ids.json"),
            version_payload=_load("version_match.json"),
        )
    exc = exc_info.value
    leak_surfaces = [str(exc), repr(exc), *(str(arg) for arg in exc.args)]
    for surface in leak_surfaces:
        assert SYNTH_SERIAL not in surface
        assert SYNTH_SERVICETAG not in surface


def test_missing_identification_ids_incomplete() -> None:
    parsed = _observed_parse(
        identification_payload=_load("identification_empty.json"),
        version_payload=_load("version_match.json"),
    )
    assert parsed.physical_identifier_source == "missing"
    assert parsed.identity_complete is False
    assert parsed.fingerprint_status == "provisional"


def test_both_physical_ids_hashed_not_retained() -> None:
    parsed = _observed_parse(
        identification_payload=_load("identification_both_ids.json"),
        version_payload=_load("version_match.json"),
    )
    assert parsed.physical_identifier_source == "show.identification_digest"
    _assert_no_raw_physical_leak(parsed, SYNTH_SERIAL, SYNTH_SERVICETAG)
    stable_repeat = _observed_parse(
        identification_payload=_load("identification_both_ids.json"),
        version_payload=_load("version_match.json"),
    )
    assert stable_repeat.fingerprint_digest == parsed.fingerprint_digest


def test_serial_only_physical_incomplete() -> None:
    parsed = _observed_parse(
        identification_payload=_load("identification_serial_only.json"),
        version_payload=_load("version_match.json"),
    )
    assert parsed.physical_identifier_source == "missing"
    assert parsed.identity_complete is False
    _assert_no_raw_physical_leak(parsed, SYNTH_SERIAL_ONLY)


def test_canonical_model_from_version_hw_id() -> None:
    parsed = _observed_parse(
        identification_payload=_load("identification_both_ids.json"),
        version_payload=_load("version_match.json"),
    )
    assert parsed.model == CANONICAL_HW_ID
    assert parsed.model_source == "rci_version"
    assert parsed.model_display == "Netcraze Ultra NC-1812"
    assert parsed.model_display_source == "rci_version_display"


def test_hw_id_conflict_incomplete() -> None:
    parsed = _observed_parse(
        identification_payload=_load("identification_hwid_conflict.json"),
        version_payload=_load("version_match.json"),
    )
    assert parsed.model_disagreement is True
    assert parsed.identity_complete is False


def test_competing_version_hw_id_incomplete() -> None:
    parsed = _observed_parse(
        identification_payload=_load("identification_both_ids.json"),
        version_payload=_load("version_model_conflict.json"),
    )
    assert parsed.model == "NC-1820"
    assert parsed.model_disagreement is True
    assert parsed.identity_complete is False


def test_model_hint_conflict_incomplete() -> None:
    conflict = _observed_parse(
        identification_payload=_load("identification_both_ids.json"),
        version_payload=_load("version_match.json"),
        hints=OperatorIdentityHints(expected_model="Netcraze Ultra NC-1820"),
    )
    assert conflict.model_disagreement is True
    assert conflict.identity_complete is False


def test_model_hint_no_token_disagreement() -> None:
    parsed = _observed_parse(
        identification_payload=_load("identification_both_ids.json"),
        version_payload=_load("version_match.json"),
        hints=OperatorIdentityHints(expected_model="Netcraze Ultra"),
    )
    assert parsed.model_disagreement is True
    assert parsed.identity_complete is False
    assert parsed.fingerprint_status == "provisional"


def test_model_hint_canonical_plus_competing_token_disagreement() -> None:
    parsed = _observed_parse(
        identification_payload=_load("identification_both_ids.json"),
        version_payload=_load("version_match.json"),
        hints=OperatorIdentityHints(expected_model="Netcraze Ultra NC-1812 and NC-1820"),
    )
    assert parsed.model_disagreement is True
    assert parsed.identity_complete is False
    assert parsed.fingerprint_status == "provisional"


def test_model_hint_case_variant_disagreement() -> None:
    parsed = _observed_parse(
        identification_payload=_load("identification_both_ids.json"),
        version_payload=_load("version_match.json"),
        hints=OperatorIdentityHints(expected_model="nc-1812"),
    )
    assert parsed.model_disagreement is True
    assert parsed.identity_complete is False
    assert parsed.fingerprint_status == "provisional"


def test_partial_token_hint_disagreement() -> None:
    parsed = _observed_parse(
        identification_payload=_load("identification_both_ids.json"),
        version_payload=_load("version_match.json"),
        hints=OperatorIdentityHints(expected_model="Netcraze Ultra NC-181"),
    )
    assert parsed.model_disagreement is True
    assert parsed.identity_complete is False


def test_token_extraction_boundary_attacks() -> None:
    assert extract_hw_id_tokens("Netcraze Ultra NC-1812") == frozenset({"NC-1812"})
    assert extract_hw_id_tokens("prefixNC-1812suffix") == frozenset()
    assert extract_hw_id_tokens("NC-181") == frozenset({"NC-181"})
    assert extract_hw_id_tokens("XNC-18120") == frozenset({"XNC-18120"})
    assert extract_hw_id_tokens("NC-1812 and NC-1820") == frozenset({"NC-1812", "NC-1820"})


def test_display_field_competing_token_disagreement() -> None:
    version = copy.deepcopy(_load("version_match.json"))
    version["model"] = "Netcraze Ultra NC-1820"
    parsed = _observed_parse(
        identification_payload=_load("identification_both_ids.json"),
        version_payload=version,
    )
    assert parsed.model_disagreement is True
    assert parsed.identity_complete is False


def test_version_match_agreement() -> None:
    parsed = _observed_parse(
        identification_payload=_load("identification_both_ids.json"),
        version_payload=_load("version_match.json"),
    )
    assert parsed.firmware_sources_agreement is True
    assert parsed.firmware_version == "5.01.C.1.0-0"


def test_version_mismatch_non_certifying() -> None:
    parsed = _observed_parse(
        identification_payload=_load("identification_both_ids.json"),
        version_payload=_load("version_mismatch.json"),
    )
    assert parsed.firmware_sources_agreement is False
    assert parsed.identity_complete is False
    assert parsed.fingerprint_status == "provisional"
    assert parsed.firmware_version == "5.01.C.1.0-0"


def test_no_version_raw_agreement_unknown() -> None:
    parsed = _observed_parse(
        identification_payload=_load("identification_both_ids.json"),
        version_payload={"hw_id": "NC-1812", "ndm": {"exact": "SYNTH-NDM-BUILD-100"}},
    )
    assert parsed.firmware_sources_agreement is None
    assert parsed.identity_complete is False


def test_nested_build_wins_over_flat() -> None:
    parsed = _observed_parse(
        identification_payload=_load("identification_both_ids.json"),
        version_payload=_load("version_nested_build_priority.json"),
    )
    assert parsed.build == "SYNTH-NDM-NESTED-WINS"
    assert parsed.build_source == "rci_version_ndm_exact"
    assert parsed.bsp_build == "SYNTH-BSP-SEPARATE"
    assert parsed.bsp_build_source == "rci_version_bsp_exact"


def test_bsp_not_used_as_ndm_build() -> None:
    parsed = _observed_parse(
        identification_payload=_load("identification_both_ids.json"),
        version_payload={
            "hw_id": "NC-1812",
            "version": "5.01.C.1.0-0",
            "bsp": {"exact": "SYNTH-BSP-ONLY"},
        },
    )
    assert parsed.build is None
    assert parsed.bsp_build == "SYNTH-BSP-ONLY"
    assert parsed.identity_complete is False


def test_flat_only_build_displayed_but_incomplete() -> None:
    parsed = _observed_parse(
        identification_payload=_load("identification_both_ids.json"),
        version_payload={
            "hw_id": "NC-1812",
            "version": "5.01.C.1.0-0",
            "release": "5.01.C.1.0-0",
            "build": "SYNTH-FLAT-BUILD-ONLY",
        },
    )
    assert parsed.build == "SYNTH-FLAT-BUILD-ONLY"
    assert parsed.build_source == "rci_version"
    assert parsed.identity_complete is False
    assert parsed.fingerprint_status == "provisional"


def test_version_release_internal_disagreement() -> None:
    parsed = _observed_parse(
        identification_payload=_load("identification_both_ids.json"),
        version_payload={
            "hw_id": "NC-1812",
            "version": "5.01.C.1.0-0",
            "release": "5.01.C.1.0-1",
            "ndm": {"exact": "SYNTH-NDM-BUILD-100"},
        },
    )
    assert parsed.firmware_sources_agreement is False
    assert parsed.identity_complete is False
    assert parsed.fingerprint_status == "provisional"


def test_sandbox_stable_maps_to_main() -> None:
    parsed = _observed_parse(
        identification_payload=_load("identification_both_ids.json"),
        version_payload=_load("version_match.json"),
    )
    assert parsed.sandbox == "stable"
    assert parsed.sandbox_source == "rci_version"
    assert parsed.update_channel == "Main"
    assert parsed.update_channel_source == "rci_version_sandbox_ui_map"


def test_unknown_sandbox_no_channel_map() -> None:
    parsed = _observed_parse(
        identification_payload=_load("identification_both_ids.json"),
        version_payload=_load("version_unknown_sandbox.json"),
    )
    assert parsed.sandbox == "beta-preview"
    assert parsed.update_channel is None
    assert parsed.update_channel_source == "unknown"


def test_unknown_sandbox_operator_hint_fallback() -> None:
    parsed = _observed_parse(
        identification_payload=_load("identification_both_ids.json"),
        version_payload=_load("version_unknown_sandbox.json"),
        hints=OperatorIdentityHints(update_channel="Main"),
    )
    assert parsed.update_channel == "Main"
    assert parsed.update_channel_source == "operator_ui_hint"


def test_region_not_update_channel() -> None:
    parsed = _observed_parse(
        identification_payload=_load("identification_both_ids.json"),
        version_payload={
            "hw_id": "NC-1812",
            "version": "5.01.C.1.0-0",
            "region": "SYNTH-REGION-EU",
        },
    )
    assert parsed.region == "SYNTH-REGION-EU"
    assert parsed.update_channel is None
    assert parsed.update_channel_source == "unknown"


def test_completeness_true_certification_still_false_via_evidence_fields() -> None:
    parsed = _observed_parse(
        identification_payload=_load("identification_both_ids.json"),
        version_payload=_load("version_match.json"),
    )
    assert parsed.identity_complete is True
    assert parsed.fingerprint_status == "stable"
    assert parsed.model_source == "rci_version"


def test_fingerprint_claims_include_digests_not_raw() -> None:
    parsed = _observed_parse(
        identification_payload=_load("identification_both_ids.json"),
        version_payload=_load("version_match.json"),
    )
    from router_control.adapters.netcraze.identity import _digest_canonical

    claims = {
        "vendor": "Netcraze",
        "release": "5.01.C.1.0-0",
        "component_set_digest": parsed.component_set_digest,
        "model": CANONICAL_HW_ID,
        "build": "SYNTH-NDM-BUILD-100",
        "serial_digest": _digest_physical(SYNTH_SERIAL, "serial"),
        "servicetag_digest": _digest_physical(SYNTH_SERVICETAG, "servicetag"),
    }
    assert parsed.fingerprint_digest == _digest_canonical(claims)
    _assert_no_raw_physical_leak(parsed, SYNTH_SERIAL, SYNTH_SERVICETAG)


def test_observed_dual_population_digest_hashes_installed_key_set() -> None:
    """MODE A: digest must hash installed-key IDs, not version-only catalogue stubs."""
    parsed = parse_identity(
        _load("system_telemetry_only.json"),
        _load("components_dual_population_20260801.json"),
    )
    assert parsed.component_set_digest == _digest_sorted_ids(DUAL_POPULATION_INSTALLED_IDS)
    assert parsed.component_set_digest_algorithm == COMPONENT_SET_DIGEST_ALGORITHM
    assert len(DUAL_POPULATION_INSTALLED_IDS) == 40


def test_observed_dual_population_catalogue_stub_does_not_change_digest() -> None:
    """Adding a catalogue stub without installed key must not alter MODE A digest."""
    system = _load("system_telemetry_only.json")
    baseline = parse_identity(
        system, _load("components_dual_population_20260801.json")
    )
    components = copy.deepcopy(_load("components_dual_population_20260801.json"))
    components["component"]["brand-new-catalog-pkg"] = {"version": "9.9.9"}
    mutated = parse_identity(system, components)
    assert mutated.component_set_digest == baseline.component_set_digest


def test_observed_mode_a_unknown_installed_form_excluded() -> None:
    """dict/list installed values are unknown (not True) under MODE A."""
    components = {
        "firmware": {"version": "5.01.C.1.0-0", "title": "5.1.1"},
        "component": {
            "installed-yes": {"installed": True},
            "installed-nested": {"installed": {"nested": True}},
            "installed-list": {"installed": [1, 2]},
        },
    }
    parsed = parse_identity(_load("system_telemetry_only.json"), components)
    assert parsed.component_set_digest == _digest_sorted_ids(["installed-yes"])


def test_observed_mode_a_only_unknown_and_false_raises() -> None:
    """When no entry resolves to True, parse fails closed."""
    components = {
        "firmware": {"version": "5.01.C.1.0-0", "title": "5.1.1"},
        "component": {
            "installed-no": {"installed": False},
            "installed-nested": {"installed": {"nested": True}},
            "catalogue-stub": {"version": "1.0.0"},
        },
    }
    with pytest.raises(IdentityParseError):
        parse_identity(_load("system_telemetry_only.json"), components)


def test_observed_version_string_in_installed_key_counts_installed() -> None:
    """KEY FIX: version-like installed string must count as True under MODE A."""
    components = {
        "firmware": {"version": "5.01.C.1.0-0", "title": "5.1.1"},
        "component": {
            "wireguard": {"installed": "5.01.C.1.0-0", "version": "5.01.C.1.0-0"},
            "acl": {"version": "0.9.20"},
        },
    }
    parsed = parse_identity(_load("system_telemetry_only.json"), components)
    assert parsed.component_set_digest == _digest_sorted_ids(["wireguard"])


def test_fingerprint_excludes_display_metadata() -> None:
    baseline = _observed_parse(
        identification_payload=_load("identification_both_ids.json"),
        version_payload=_load("version_match.json"),
    )
    mutated_version = copy.deepcopy(_load("version_match.json"))
    mutated_version["model"] = "Different Display Name NC-1812"
    mutated_version["description"] = "Mutated description NC-1812"
    mutated = _observed_parse(
        identification_payload=_load("identification_both_ids.json"),
        version_payload=mutated_version,
    )
    assert mutated.fingerprint_digest == baseline.fingerprint_digest
    assert mutated.model_display != baseline.model_display
