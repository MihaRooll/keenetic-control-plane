"""Offline tests for default-route probe parser, classifier, and artifact builder."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import router_control.adapters.netcraze.sanitize as sanitize_mod
from router_control.adapters.netcraze.allowlist import SHOW_IP_ROUTE
from router_control.adapters.netcraze.route_topology_probe import (
    PARSER_VERSION,
    DefaultRouteClassification,
    RouteTopologyProbeError,
    TopologyCorrelationStatus,
    build_default_route_artifact,
    build_default_route_shape_artifact,
    classify_default_routes,
    classify_parser_error,
    correlate_with_topology_artifact,
    digest_structure_fingerprint,
    parse_default_routes,
)
from router_control.adapters.netcraze.sanitize import (
    _STRUCTURE_MAX_ENTRIES,
    _STRUCTURE_MAX_OUTPUT_BYTES,
    describe_list_structure,
    hash_interface_id,
)
from router_control.adapters.netcraze.topology_probe import (
    PARSER_VERSION_V2,
    PARSER_VERSION_V2_LEGACY,
    build_topology_artifact,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "netcraze"

SYNTH_SECRET = "SENTINEL-SECRET-ORACLE"
SYNTH_IFACE = "SENTINEL-IFACE-ID-ORACLE"
SYNTH_GATEWAY = "203.0.113.50"
SYNTH_DEST = "198.51.100.0/24"


def _load(name: str) -> tuple[object, bytes]:
    raw = (FIXTURES / name).read_bytes()
    return json.loads(raw.decode("utf-8")), raw


def _artifact_kwargs(payload: object, raw: bytes) -> dict[str, object]:
    return {
        "payload": payload,
        "raw_bytes": raw,
        "source_address": "192.168.1.144",
        "source_address_class": "private_ipv4_literal",
        "gate_a_tuple_digest": "sha256:" + "a" * 64,
        "gate_a_evidence_digest": "sha256:" + "b" * 64,
        "transport_security": "ssh_tunnel",
        "https_check": "ssh_host_key_pinned",
        "ssh_host_key_algorithm": "ssh-ed25519",
        "ssh_host_key_fingerprint_sha256": "SHA256:oraclepin",
    }


def _route_payload_with_canaries(payload: object) -> tuple[object, bytes]:
    if isinstance(payload, list):
        if payload and all(isinstance(entry, dict) for entry in payload):
            new_routes: list[object] = []
            for route in payload:
                entry = dict(route)
                if entry.get("destination") == "0.0.0.0/0":
                    entry["interface"] = SYNTH_IFACE
                    entry["password"] = SYNTH_SECRET
                else:
                    entry["interface"] = SYNTH_IFACE
                    entry["gateway"] = SYNTH_GATEWAY
                    entry["destination"] = SYNTH_DEST
                    entry["password"] = SYNTH_SECRET
                new_routes.append(entry)
            mutated: object = new_routes
            raw = json.dumps(mutated).encode("utf-8")
            return mutated, raw
        assert len(payload) == 1 and isinstance(payload[0], list)
        routes = payload[0]
        new_routes = []
        for route in routes:
            if not isinstance(route, dict):
                new_routes.append(route)
                continue
            entry = dict(route)
            if entry.get("destination") == "0.0.0.0/0":
                entry["interface"] = SYNTH_IFACE
                entry["password"] = SYNTH_SECRET
            else:
                entry["interface"] = SYNTH_IFACE
                entry["gateway"] = SYNTH_GATEWAY
                entry["destination"] = SYNTH_DEST
                entry["password"] = SYNTH_SECRET
            new_routes.append(entry)
        mutated = [new_routes]
        raw = json.dumps(mutated).encode("utf-8")
        return mutated, raw
    assert isinstance(payload, dict)
    mutated = json.loads(json.dumps(payload))
    routes = mutated.get("route")
    if isinstance(routes, list):
        new_routes = []
        for route in routes:
            if not isinstance(route, dict):
                new_routes.append(route)
                continue
            entry = dict(route)
            if entry.get("destination") == "0.0.0.0/0":
                entry["interface"] = SYNTH_IFACE
                entry["password"] = SYNTH_SECRET
            else:
                entry["interface"] = SYNTH_IFACE
                entry["gateway"] = SYNTH_GATEWAY
                entry["destination"] = SYNTH_DEST
                entry["password"] = SYNTH_SECRET
            new_routes.append(entry)
        mutated["route"] = new_routes
    raw = json.dumps(mutated).encode("utf-8")
    return mutated, raw


def _wrap_v1_as_observed(v1_payload: object) -> tuple[object, bytes]:
    assert isinstance(v1_payload, dict)
    routes = v1_payload["route"]
    wrapped: object = [routes]
    return wrapped, json.dumps(wrapped).encode("utf-8")


def _dict_route_to_direct_array(v1_payload: object) -> tuple[object, bytes]:
    assert isinstance(v1_payload, dict)
    routes = v1_payload["route"]
    assert isinstance(routes, list)
    direct: object = routes
    return direct, json.dumps(direct).encode("utf-8")


def _assert_artifact_has_no_canaries(blob: str) -> None:
    for forbidden in (
        SYNTH_SECRET, SYNTH_IFACE, SYNTH_GATEWAY, SYNTH_DEST, "203.0.113", "198.51.100"
    ):
        assert forbidden not in blob


@pytest.mark.parametrize(
    ("fixture", "expected"),
    [
        ("default_route_single.json", DefaultRouteClassification.ONE_DEFAULT_ROUTE),
        ("default_route_multiple.json", DefaultRouteClassification.MULTIPLE_DEFAULT_ROUTES),
        ("default_route_ambiguous.json", DefaultRouteClassification.AMBIGUOUS),
    ],
)
def test_classify_fixtures(fixture: str, expected: DefaultRouteClassification) -> None:
    payload, _ = _load(fixture)
    routes = parse_default_routes(payload)
    assert classify_default_routes(routes) == expected


@pytest.mark.parametrize(
    ("fixture", "expected"),
    [
        ("default_route_single.json", DefaultRouteClassification.ONE_DEFAULT_ROUTE),
        ("default_route_multiple.json", DefaultRouteClassification.MULTIPLE_DEFAULT_ROUTES),
        ("default_route_ambiguous.json", DefaultRouteClassification.AMBIGUOUS),
    ],
)
def test_direct_array_matches_dict_route_model(
    fixture: str, expected: DefaultRouteClassification
) -> None:
    v1_payload, _ = _load(fixture)
    dict_routes = parse_default_routes(v1_payload)
    direct_payload, direct_raw = _dict_route_to_direct_array(v1_payload)
    direct_routes = parse_default_routes(direct_payload)
    assert direct_routes == dict_routes
    assert classify_default_routes(direct_routes) == expected
    direct_payload, direct_raw = _route_payload_with_canaries(direct_payload)
    artifact = build_default_route_artifact(**_artifact_kwargs(direct_payload, direct_raw))
    assert artifact["parser_version"] == PARSER_VERSION
    assert artifact["findings"]["classification"] == expected.value
    blob = json.dumps(artifact)
    _assert_artifact_has_no_canaries(blob)


def test_station_uplink_bare_default_route_classified() -> None:
    payload, _ = _load("default_route_station_uplink_bare.json")
    routes = parse_default_routes(payload)
    assert len(routes) == 1
    assert classify_default_routes(routes) == DefaultRouteClassification.ONE_DEFAULT_ROUTE
    assert routes[0].gateway_private_class == "192.168.0.0/16"


def test_direct_array_empty_no_default_route() -> None:
    payload: object = []
    raw = json.dumps(payload).encode("utf-8")
    routes = parse_default_routes(payload)
    assert routes == ()
    assert classify_default_routes(routes) == DefaultRouteClassification.NO_DEFAULT_ROUTE
    artifact = build_default_route_artifact(**_artifact_kwargs(payload, raw))
    assert artifact["parser_version"] == PARSER_VERSION
    findings = artifact["findings"]
    assert findings["classification"] == DefaultRouteClassification.NO_DEFAULT_ROUTE.value
    assert findings["default_route_count"] == 0


def test_non_default_routes_dropped() -> None:
    payload, _ = _load("default_route_single.json")
    payload, raw = _route_payload_with_canaries(payload)
    routes = parse_default_routes(payload)
    assert len(routes) == 1
    assert routes[0].interface_id_hash == hash_interface_id(SYNTH_IFACE)
    artifact = build_default_route_artifact(**_artifact_kwargs(payload, raw))
    blob = json.dumps(artifact)
    _assert_artifact_has_no_canaries(blob)
    assert "Home" not in blob
    assert "192.168.1.0/24" not in blob
    assert "10.0.0.1" not in blob


def test_artifact_is_non_certifying_and_bounded() -> None:
    payload, _ = _load("default_route_single.json")
    payload, raw = _route_payload_with_canaries(payload)
    artifact = build_default_route_artifact(**_artifact_kwargs(payload, raw))
    assert artifact["certification_eligible"] is False
    assert artifact["operation_path"] == SHOW_IP_ROUTE.path
    assert artifact["parser_version"] == PARSER_VERSION
    assert artifact["raw_payload_sha256"].startswith("sha256:")
    findings = artifact["findings"]
    assert findings["classification"] == DefaultRouteClassification.ONE_DEFAULT_ROUTE.value
    assert findings["default_route_count"] == 1
    blob = json.dumps(artifact)
    _assert_artifact_has_no_canaries(blob)
    assert "ISP" not in blob


def test_gateway_emits_private_class_only() -> None:
    payload, _ = _load("default_route_single.json")
    payload, raw = _route_payload_with_canaries(payload)
    artifact = build_default_route_artifact(**_artifact_kwargs(payload, raw))
    routes = artifact["findings"]["sanitized_default_routes"]
    assert routes[0]["gateway_private_class"] == "10.0.0.0/8"
    blob = json.dumps(artifact)
    _assert_artifact_has_no_canaries(blob)
    assert "10.0.0.1" not in blob


def test_unknown_shape_raises_and_shape_artifact() -> None:
    payload = {
        "unexpected": [
            {
                "destination": SYNTH_DEST,
                "gateway": SYNTH_GATEWAY,
                "interface": SYNTH_IFACE,
                "password": SYNTH_SECRET,
            }
        ]
    }
    raw = json.dumps(payload).encode("utf-8")
    with pytest.raises(RouteTopologyProbeError, match="missing route list"):
        parse_default_routes(payload)
    error = RouteTopologyProbeError("route payload missing route list")
    shape = build_default_route_shape_artifact(
        **_artifact_kwargs(payload, raw),
        parser_error=error,
    )
    assert shape["certification_eligible"] is False
    assert shape["parser_error_class"] == classify_parser_error(error)
    assert "structure" in shape
    shape_blob = json.dumps(shape)
    _assert_artifact_has_no_canaries(shape_blob)
    assert "0.0.0.0" not in shape_blob


def test_correlation_rejects_non_v22_topology_parser() -> None:
    route_payload, route_raw = _load("default_route_single.json")
    topo_payload, topo_raw = _load("topology_interface_wan_isolated.json")
    kwargs = _artifact_kwargs(route_payload, route_raw)
    topo_kwargs = _artifact_kwargs(topo_payload, topo_raw)
    route_artifact = build_default_route_artifact(**kwargs)
    topology_artifact = build_topology_artifact(**topo_kwargs)
    assert topology_artifact["parser_version"] != PARSER_VERSION_V2
    route_artifact["gate_a_tuple_digest"] = topology_artifact["gate_a_tuple_digest"]
    route_artifact["gate_a_evidence_digest"] = topology_artifact["gate_a_evidence_digest"]
    route_artifact["source_address"] = topology_artifact["source_address"]

    result = correlate_with_topology_artifact(route_artifact, topology_artifact)
    assert result.status != TopologyCorrelationStatus.MATCH
    assert result.status == TopologyCorrelationStatus.AMBIGUOUS
    assert "topology_parser_unsupported" in result.notes


def test_correlation_mismatch_when_hashes_do_not_overlap() -> None:
    route_payload, route_raw = _load("default_route_single.json")
    topo_payload, topo_raw = _load("topology_interface_wan_isolated.json")
    assert isinstance(topo_payload, dict)
    topo_mutated = json.loads(json.dumps(topo_payload))
    iface_list = list(topo_mutated["interface"])
    iface_list[0] = dict(iface_list[0])
    iface_list[0]["id"] = "OtherWAN"
    topo_mutated["interface"] = iface_list
    topo_raw_mutated = json.dumps(topo_mutated).encode("utf-8")
    kwargs = _artifact_kwargs(route_payload, route_raw)
    topo_kwargs = _artifact_kwargs(topo_mutated, topo_raw_mutated)
    route_artifact = build_default_route_artifact(**kwargs)
    topology_artifact = build_topology_artifact(**topo_kwargs)
    topology_artifact["parser_version"] = PARSER_VERSION_V2
    route_artifact["gate_a_tuple_digest"] = topology_artifact["gate_a_tuple_digest"]
    route_artifact["gate_a_evidence_digest"] = topology_artifact["gate_a_evidence_digest"]
    route_artifact["source_address"] = topology_artifact["source_address"]

    result = correlate_with_topology_artifact(route_artifact, topology_artifact)
    assert result.status == TopologyCorrelationStatus.MISMATCH
    assert hash_interface_id("ISP") in result.default_outbound_hashes
    assert hash_interface_id("OtherWAN") in result.connected_non_lan_hashes
    assert not result.overlapping_hashes


def test_correlation_match_with_topology() -> None:
    route_payload, route_raw = _load("default_route_single.json")
    topo_payload, topo_raw = _load("topology_interface_wan_isolated.json")
    kwargs = _artifact_kwargs(route_payload, route_raw)
    topo_kwargs = _artifact_kwargs(topo_payload, topo_raw)
    route_artifact = build_default_route_artifact(**kwargs)
    topology_artifact = build_topology_artifact(**topo_kwargs)
    topology_artifact["parser_version"] = PARSER_VERSION_V2
    route_artifact["gate_a_tuple_digest"] = topology_artifact["gate_a_tuple_digest"]
    route_artifact["gate_a_evidence_digest"] = topology_artifact["gate_a_evidence_digest"]
    route_artifact["source_address"] = topology_artifact["source_address"]

    result = correlate_with_topology_artifact(route_artifact, topology_artifact)
    assert result.status == TopologyCorrelationStatus.MATCH
    assert hash_interface_id("ISP") in result.overlapping_hashes
    assert result.topology_classification == "proven_wan_isolated"


def test_correlation_mismatch_tuple_digest() -> None:
    route_payload, route_raw = _load("default_route_single.json")
    topo_payload, topo_raw = _load("topology_interface_wan_isolated.json")
    route_artifact = build_default_route_artifact(**_artifact_kwargs(route_payload, route_raw))
    topology_artifact = build_topology_artifact(**_artifact_kwargs(topo_payload, topo_raw))
    topology_artifact["gate_a_tuple_digest"] = "sha256:" + "c" * 64

    result = correlate_with_topology_artifact(route_artifact, topology_artifact)
    assert result.status == TopologyCorrelationStatus.TUPLE_MISMATCH


def test_correlation_does_not_promote_wan_isolated_from_route_alone() -> None:
    route_payload, route_raw = _load("default_route_single.json")
    topo_payload, topo_raw = _load("topology_interface_ambiguous.json")
    kwargs = _artifact_kwargs(route_payload, route_raw)
    topo_kwargs = _artifact_kwargs(topo_payload, topo_raw)
    route_artifact = build_default_route_artifact(**kwargs)
    topology_artifact = build_topology_artifact(**topo_kwargs)
    topology_artifact["parser_version"] = PARSER_VERSION_V2
    route_artifact["gate_a_tuple_digest"] = topology_artifact["gate_a_tuple_digest"]
    route_artifact["gate_a_evidence_digest"] = topology_artifact["gate_a_evidence_digest"]
    route_artifact["source_address"] = topology_artifact["source_address"]

    result = correlate_with_topology_artifact(route_artifact, topology_artifact)
    assert result.topology_classification == "ambiguous"
    assert "topology_does_not_prove_wan_isolated" in result.notes


def test_multiple_defaults_block_correlation_match() -> None:
    route_payload, route_raw = _load("default_route_multiple.json")
    topo_payload, topo_raw = _load("topology_interface_wan_isolated.json")
    kwargs = _artifact_kwargs(route_payload, route_raw)
    topo_kwargs = _artifact_kwargs(topo_payload, topo_raw)
    route_artifact = build_default_route_artifact(**kwargs)
    topology_artifact = build_topology_artifact(**topo_kwargs)
    topology_artifact["parser_version"] = PARSER_VERSION_V2
    route_artifact["gate_a_tuple_digest"] = topology_artifact["gate_a_tuple_digest"]
    route_artifact["gate_a_evidence_digest"] = topology_artifact["gate_a_evidence_digest"]
    route_artifact["source_address"] = topology_artifact["source_address"]

    result = correlate_with_topology_artifact(route_artifact, topology_artifact)
    assert result.status == TopologyCorrelationStatus.AMBIGUOUS
    assert "route_classification_blocks_uplink_claim" in result.notes


def test_shape_digest_stable() -> None:
    payload = {"bad": True}
    raw = json.dumps(payload).encode("utf-8")
    error = RouteTopologyProbeError("route payload shape invalid")
    shape = build_default_route_shape_artifact(
        **_artifact_kwargs(payload, raw),
        parser_error=error,
    )
    digest = digest_structure_fingerprint(
        structure=shape["structure"],
        parser_error_class=shape["parser_error_class"],
    )
    assert shape["structure_canonical_digest"] == digest


def test_empty_observed_wrapper_no_default_route() -> None:
    payload, raw = _load("default_route_observed_empty_wrapper.json")
    assert payload == [[]]
    routes = parse_default_routes(payload)
    assert routes == ()
    assert classify_default_routes(routes) == DefaultRouteClassification.NO_DEFAULT_ROUTE
    artifact = build_default_route_artifact(**_artifact_kwargs(payload, raw))
    assert artifact["parser_version"] == PARSER_VERSION
    findings = artifact["findings"]
    assert findings["classification"] == DefaultRouteClassification.NO_DEFAULT_ROUTE.value
    assert findings["default_route_count"] == 0
    assert findings["default_outbound_interface_hashes"] == []
    assert findings["gateway_private_classes"] == []
    assert findings["sanitized_default_routes"] == []
    blob = json.dumps(artifact)
    _assert_artifact_has_no_canaries(blob)


def test_empty_wrapper_correlation_blocks_uplink_without_isolation() -> None:
    route_payload, route_raw = _load("default_route_observed_empty_wrapper.json")
    topo_payload, topo_raw = _load("topology_interface_wan_isolated.json")
    kwargs = _artifact_kwargs(route_payload, route_raw)
    topo_kwargs = _artifact_kwargs(topo_payload, topo_raw)
    route_artifact = build_default_route_artifact(**kwargs)
    topology_artifact = build_topology_artifact(**topo_kwargs)
    topology_artifact["parser_version"] = PARSER_VERSION_V2
    route_artifact["gate_a_tuple_digest"] = topology_artifact["gate_a_tuple_digest"]
    route_artifact["gate_a_evidence_digest"] = topology_artifact["gate_a_evidence_digest"]
    route_artifact["source_address"] = topology_artifact["source_address"]

    result = correlate_with_topology_artifact(route_artifact, topology_artifact)
    assert result.status == TopologyCorrelationStatus.AMBIGUOUS
    assert result.status != TopologyCorrelationStatus.MATCH
    assert "route_classification_blocks_uplink_claim" in result.notes
    assert not result.default_outbound_hashes
    assert not result.overlapping_hashes


@pytest.mark.parametrize(
    ("fixture", "expected"),
    [
        ("default_route_single.json", DefaultRouteClassification.ONE_DEFAULT_ROUTE),
        ("default_route_multiple.json", DefaultRouteClassification.MULTIPLE_DEFAULT_ROUTES),
        ("default_route_ambiguous.json", DefaultRouteClassification.AMBIGUOUS),
    ],
)
def test_observed_wrapper_nonempty_matches_v1(
    fixture: str, expected: DefaultRouteClassification
) -> None:
    v1_payload, _ = _load(fixture)
    wrapped, raw = _wrap_v1_as_observed(v1_payload)
    wrapped, raw = _route_payload_with_canaries(wrapped)
    routes = parse_default_routes(wrapped)
    assert classify_default_routes(routes) == expected
    artifact = build_default_route_artifact(**_artifact_kwargs(wrapped, raw))
    assert artifact["parser_version"] == PARSER_VERSION
    assert artifact["findings"]["classification"] == expected.value
    blob = json.dumps(artifact)
    _assert_artifact_has_no_canaries(blob)


@pytest.mark.parametrize(
    ("invalid_payload", "expected_message"),
    [
        ([[], []], "route list shape invalid"),
        ([[[{"destination": "0.0.0.0/0"}]]], "route list shape invalid"),
        ([1, []], "route list shape invalid"),
        (
            [{"destination": "0.0.0.0/0", "interface": "ISP"}, []],
            "route list shape invalid",
        ),
        ({"routes": []}, "missing route list"),
    ],
)
def test_observed_wrapper_invalid_shapes_fail_closed(
    invalid_payload: object, expected_message: str
) -> None:
    with pytest.raises(RouteTopologyProbeError, match=expected_message):
        parse_default_routes(invalid_payload)
    raw = json.dumps(invalid_payload).encode("utf-8")
    error = RouteTopologyProbeError(expected_message)
    shape = build_default_route_shape_artifact(
        **_artifact_kwargs(invalid_payload, raw),
        parser_error=error,
    )
    assert shape["parser_error_class"] == classify_parser_error(error)
    assert "structure" in shape
    _assert_artifact_has_no_canaries(json.dumps(shape))


def _valid_default_route_entry() -> dict[str, object]:
    return {
        "destination": "0.0.0.0/0",
        "interface": "ISP",
        "gateway": "10.0.0.1",
        "metric": 0,
        "type": "unicast",
        "state": "active",
    }


def test_wrapper_mixed_scalar_and_dict_rejects_fail_closed() -> None:
    """F-1: mixed types in wrapper inner list must not classify as one_default_route."""
    payload: object = [[1, _valid_default_route_entry()]]
    with pytest.raises(RouteTopologyProbeError, match="route list shape invalid"):
        parse_default_routes(payload)
    error = RouteTopologyProbeError("route list shape invalid")
    assert classify_parser_error(error) == "route_list_shape_invalid"


def test_v1_nested_list_under_route_rejects_fail_closed() -> None:
    """F-2: nested list under v1 dict route must not silently no_default_route."""
    payload: object = {"route": [[_valid_default_route_entry()]]}
    with pytest.raises(RouteTopologyProbeError, match="route list shape invalid"):
        parse_default_routes(payload)
    error = RouteTopologyProbeError("route list shape invalid")
    assert classify_parser_error(error) == "route_list_shape_invalid"


def _assert_list_structure_bounds(structure: dict[str, object]) -> None:
    assert len(structure["dynamic_top_key_hashes"]) <= _STRUCTURE_MAX_ENTRIES
    assert len(structure["secret_field_categories"]) <= _STRUCTURE_MAX_ENTRIES
    assert len(structure["field_samples"]) <= _STRUCTURE_MAX_ENTRIES
    for sample in structure["field_samples"]:
        dynamic_hashes = sample.get("dynamic_key_hashes")
        if dynamic_hashes is not None:
            assert len(dynamic_hashes) <= _STRUCTURE_MAX_ENTRIES
    encoded = json.dumps(structure, sort_keys=True, separators=(",", ":"))
    assert len(encoded) <= _STRUCTURE_MAX_OUTPUT_BYTES


_FORBIDDEN_LENGTH_METADATA_KEYS = frozenset(
    {"length", "nbytes", "str_len", "string_length", "byte_length", "char_length", "strlen"}
)


def _assert_list_structure_has_no_length_metadata(structure: dict[str, object]) -> None:
    def walk(value: object) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                normalized = key.strip().lower().replace("-", "_")
                assert normalized not in _FORBIDDEN_LENGTH_METADATA_KEYS, (
                    f"forbidden length metadata key: {key!r}"
                )
                assert not normalized.endswith("_length"), f"forbidden length metadata key: {key!r}"
                assert not normalized.endswith("_nbytes"), f"forbidden length metadata key: {key!r}"
                walk(child)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(structure)
    blob = json.dumps(structure, sort_keys=True, separators=(",", ":"))
    for pattern in (
        '"length":',
        '"nbytes":',
        '"str_len":',
        '"string_length":',
        '"byte_length":',
    ):
        assert pattern not in blob


def test_describe_list_structure_rejects_non_array() -> None:
    with pytest.raises(ValueError, match="JSON array"):
        describe_list_structure({"route": []})


def test_describe_list_structure_empty() -> None:
    structure = describe_list_structure([])
    assert structure["top_type"] == "array"
    assert structure["top_count"] == 0
    assert structure["element_type_histogram"] == {}
    assert structure["dynamic_top_key_hashes"] == []
    assert structure["truncated"] is False
    root_samples = [s for s in structure["field_samples"] if s.get("path") == "<root>"]
    assert root_samples
    assert root_samples[0]["container_type"] == "array"
    assert root_samples[0]["count"] == 0


def test_describe_list_structure_nested_wrapper() -> None:
    payload: object = [
        [
            {
                "destination": "0.0.0.0/0",
                "interface": SYNTH_IFACE,
                "gateway": SYNTH_GATEWAY,
                "type": "unicast",
                "state": "active",
                "password": SYNTH_SECRET,
            }
        ]
    ]
    structure = describe_list_structure(payload)
    blob = json.dumps(structure)
    _assert_artifact_has_no_canaries(blob)
    assert structure["top_type"] == "array"
    assert structure["top_count"] == 1
    assert structure["element_type_histogram"] == {"array": 1}
    assert any(item["category"] == "password" for item in structure["secret_field_categories"])
    paths = {sample["path"] for sample in structure["field_samples"]}
    assert "<root>" in paths
    assert "[0]" in paths
    allowlisted_names = {
        field["name"]
        for sample in structure["field_samples"]
        for field in sample.get("allowlisted_fields", [])
    }
    assert "interface" in allowlisted_names
    assert "type" in allowlisted_names
    assert "state" in allowlisted_names
    assert "gateway" in allowlisted_names
    assert "destination" not in allowlisted_names
    assert SYNTH_IFACE not in blob
    assert "0.0.0.0" not in blob


def test_describe_list_structure_mixed_outer_types() -> None:
    structure = describe_list_structure([1, {"type": "unicast"}, "x"])
    assert structure["top_count"] == 3
    assert structure["element_type_histogram"] == {"number": 1, "object": 1, "string": 1}
    blob = json.dumps(structure)
    _assert_artifact_has_no_canaries(blob)


def test_describe_list_structure_oversize_truncates() -> None:
    payload = [
        {"destination": f"10.0.{index}.0/24", "interface": f"if-{index}", "type": "unicast"}
        for index in range(40)
    ]
    structure = describe_list_structure(payload)
    assert structure["truncated"] is True
    assert structure["top_count"] == 40
    _assert_list_structure_bounds(structure)
    blob = json.dumps(structure)
    _assert_artifact_has_no_canaries(blob)
    _assert_list_structure_has_no_length_metadata(structure)
    assert "if-0" not in blob


def test_describe_list_structure_nested_array_histogram_covers_full_list() -> None:
    payload: object = [[{"type": "unicast"}] + list(range(40))]
    structure = describe_list_structure(payload)
    assert structure["truncated"] is True
    nested = next(sample for sample in structure["field_samples"] if sample["path"] == "[0]")
    assert nested["count"] == 41
    histogram = nested["element_type_histogram"]
    assert histogram == {"object": 1, "number": 40}
    assert sum(histogram.values()) == nested["count"]
    blob = json.dumps(structure)
    _assert_artifact_has_no_canaries(blob)
    _assert_list_structure_has_no_length_metadata(structure)


def test_describe_list_structure_output_bytes_truncates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_byte_cap = 2500
    monkeypatch.setattr(sanitize_mod, "_STRUCTURE_MAX_OUTPUT_BYTES", output_byte_cap)
    payload = [{f"password_{index}": "x" for index in range(200)}]
    structure = describe_list_structure(payload)
    assert structure["truncated"] is True
    encoded = json.dumps(structure, sort_keys=True, separators=(",", ":"))
    assert len(encoded) <= output_byte_cap
    blob = json.dumps(structure)
    _assert_artifact_has_no_canaries(blob)
    _assert_list_structure_has_no_length_metadata(structure)


def test_describe_list_structure_deep_nesting_truncates() -> None:
    payload: object = [[[[{"type": "unicast"}]]]]
    structure = describe_list_structure(payload)
    assert structure["truncated"] is True


def test_describe_list_structure_digest_stable() -> None:
    payload: object = [[{"type": "unicast", "state": "active", "interface": "ISP"}]]
    structure_a = describe_list_structure(payload)
    structure_b = describe_list_structure(payload)
    digest_a = digest_structure_fingerprint(
        structure=structure_a,
        parser_error_class="route_list_shape_invalid",
    )
    digest_b = digest_structure_fingerprint(
        structure=structure_b,
        parser_error_class="route_list_shape_invalid",
    )
    assert digest_a == digest_b


def test_list_wrapper_shape_artifact_emits_fingerprint() -> None:
    invalid_payload: object = [[], []]
    raw = json.dumps(invalid_payload).encode("utf-8")
    error = RouteTopologyProbeError("route list shape invalid")
    shape = build_default_route_shape_artifact(
        **_artifact_kwargs(invalid_payload, raw),
        parser_error=error,
    )
    structure = shape["structure"]
    assert structure["top_type"] == "array"
    assert structure["top_count"] == 2
    assert structure["element_type_histogram"] == {"array": 2}
    assert shape["certification_eligible"] is False
    blob = json.dumps(shape)
    _assert_artifact_has_no_canaries(blob)
    expected = digest_structure_fingerprint(
        structure=structure,
        parser_error_class=shape["parser_error_class"],
    )
    assert shape["structure_canonical_digest"] == expected


def _topology_artifact_with_interfaces(
    interfaces: list[dict[str, object]],
    *,
    parser_version: str,
) -> dict[str, object]:
    return {
        "parser_version": parser_version,
        "gate_a_tuple_digest": "sha256:" + "a" * 64,
        "gate_a_evidence_digest": "sha256:" + "b" * 64,
        "source_address": "192.168.1.144",
        "findings": {
            "classification": "proven_wan_isolated",
            "sanitized_interfaces": interfaces,
        },
    }


def test_uplink_hash_ignores_deceptive_connected_true_link_down() -> None:
    from router_control.adapters.netcraze.route_topology_probe import (
        _connected_non_lan_interface_hashes,
    )

    artifact = _topology_artifact_with_interfaces(
        [
            {
                "role": "wan",
                "link_up": False,
                "connected": True,
                "interface_id_hash": hash_interface_id("ISP"),
            }
        ],
        parser_version=PARSER_VERSION_V2,
    )
    assert _connected_non_lan_interface_hashes(artifact) == ()


def test_uplink_hash_connected_only_without_link_excluded_v23() -> None:
    from router_control.adapters.netcraze.route_topology_probe import (
        _connected_non_lan_interface_hashes,
    )

    artifact = _topology_artifact_with_interfaces(
        [
            {
                "role": "wan",
                "link_up": None,
                "connected": True,
                "interface_id_hash": hash_interface_id("ISP"),
            }
        ],
        parser_version=PARSER_VERSION_V2,
    )
    assert _connected_non_lan_interface_hashes(artifact) == ()


def test_uplink_hash_link_up_true_connected_false_included() -> None:
    from router_control.adapters.netcraze.route_topology_probe import (
        _connected_non_lan_interface_hashes,
    )

    wan_hash = hash_interface_id("ISP")
    artifact = _topology_artifact_with_interfaces(
        [
            {
                "role": "wan",
                "link_up": True,
                "connected": False,
                "interface_id_hash": wan_hash,
            }
        ],
        parser_version=PARSER_VERSION_V2,
    )
    assert _connected_non_lan_interface_hashes(artifact) == (wan_hash,)


def test_uplink_hash_both_absent_excluded_v23() -> None:
    from router_control.adapters.netcraze.route_topology_probe import (
        _connected_non_lan_interface_hashes,
    )

    artifact = _topology_artifact_with_interfaces(
        [
            {
                "role": "wan",
                "interface_id_hash": hash_interface_id("ISP"),
            }
        ],
        parser_version=PARSER_VERSION_V2,
    )
    assert _connected_non_lan_interface_hashes(artifact) == ()


def test_legacy_v22_artifact_with_link_up_still_correlates() -> None:
    """v2.2 artifacts remain readable when link_up is an explicit bool."""
    route_payload, route_raw = _load("default_route_single.json")
    kwargs = _artifact_kwargs(route_payload, route_raw)
    route_artifact = build_default_route_artifact(**kwargs)
    wan_hash = hash_interface_id("ISP")
    topology_artifact = _topology_artifact_with_interfaces(
        [
            {
                "role": "wan",
                "link_up": True,
                "connected": True,
                "interface_id_hash": wan_hash,
            }
        ],
        parser_version=PARSER_VERSION_V2_LEGACY,
    )
    route_artifact["gate_a_tuple_digest"] = topology_artifact["gate_a_tuple_digest"]
    route_artifact["gate_a_evidence_digest"] = topology_artifact["gate_a_evidence_digest"]
    route_artifact["source_address"] = topology_artifact["source_address"]

    result = correlate_with_topology_artifact(route_artifact, topology_artifact)
    assert result.status == TopologyCorrelationStatus.MATCH
    assert wan_hash in result.connected_non_lan_hashes
    assert wan_hash in result.overlapping_hashes


def test_legacy_v22_connected_only_does_not_match() -> None:
    """Spoofed v2.2 with connected-only must not infer uplink activity."""
    route_payload, route_raw = _load("default_route_single.json")
    kwargs = _artifact_kwargs(route_payload, route_raw)
    route_artifact = build_default_route_artifact(**kwargs)
    wan_hash = hash_interface_id("ISP")
    topology_artifact = _topology_artifact_with_interfaces(
        [
            {
                "role": "wan",
                "connected": True,
                "interface_id_hash": wan_hash,
            }
        ],
        parser_version=PARSER_VERSION_V2_LEGACY,
    )
    topology_artifact["findings"]["classification"] = "ambiguous"
    route_artifact["gate_a_tuple_digest"] = topology_artifact["gate_a_tuple_digest"]
    route_artifact["gate_a_evidence_digest"] = topology_artifact["gate_a_evidence_digest"]
    route_artifact["source_address"] = topology_artifact["source_address"]

    result = correlate_with_topology_artifact(route_artifact, topology_artifact)
    assert result.status != TopologyCorrelationStatus.MATCH
    assert result.status == TopologyCorrelationStatus.AMBIGUOUS
    assert result.connected_non_lan_hashes == ()
    assert result.overlapping_hashes == ()
    assert "insufficient_hashes_for_match" in result.notes


def test_legacy_v22_non_bool_link_up_not_connected_fallback() -> None:
    from router_control.adapters.netcraze.route_topology_probe import (
        _connected_non_lan_interface_hashes,
    )

    wan_hash = hash_interface_id("ISP")
    artifact = _topology_artifact_with_interfaces(
        [
            {
                "role": "wan",
                "link_up": "up",
                "connected": True,
                "interface_id_hash": wan_hash,
            }
        ],
        parser_version=PARSER_VERSION_V2_LEGACY,
    )
    assert _connected_non_lan_interface_hashes(artifact) == ()
