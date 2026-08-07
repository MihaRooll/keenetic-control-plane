"""Offline tests for topology probe parser, classifier, and artifact builder."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from router_control.adapters.netcraze.allowlist import SHOW_INTERFACE
from router_control.adapters.netcraze.sanitize import (
    _STRUCTURE_ALLOWLISTED_FIELDS,
    _STRUCTURE_MAX_ENTRIES,
    _STRUCTURE_MAX_OUTPUT_BYTES,
    classify_private_prefix,
    describe_structure,
    hash_interface_id,
)
from router_control.adapters.netcraze.topology_probe import (
    MAX_KEYED_CANDIDATES,
    PARSER_VERSION,
    PARSER_VERSION_V2,
    TopologyClassification,
    TopologyProbeError,
    build_topology_artifact,
    build_topology_shape_artifact,
    classify_parser_error,
    classify_topology,
    digest_structure_fingerprint,
    parse_topology_interfaces,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "netcraze"

SYNTH_MAC = "DE:AD:BE:EF:00:01"
SYNTH_SSID = "SENTINEL-SSID-ORACLE"
SYNTH_SECRET = "SENTINEL-SECRET-ORACLE"
SYNTH_ID = "SENTINEL-IFACE-ID-ORACLE"
SYNTH_IP = "203.0.113.50"


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


@pytest.mark.parametrize(
    ("fixture", "expected"),
    [
        ("topology_interface_wan_isolated.json", TopologyClassification.PROVEN_WAN_ISOLATED),
        ("topology_interface_overlap.json", TopologyClassification.LAN_TO_LAN_OR_OVERLAP),
        ("topology_interface_ambiguous.json", TopologyClassification.AMBIGUOUS),
    ],
)
def test_classify_fixtures(fixture: str, expected: TopologyClassification) -> None:
    payload, _ = _load(fixture)
    interfaces = parse_topology_interfaces(payload)
    assert classify_topology(interfaces) == expected


def test_artifact_is_non_certifying_and_bounded() -> None:
    payload, raw = _load("topology_interface_wan_isolated.json")
    artifact = build_topology_artifact(**_artifact_kwargs(payload, raw))
    assert artifact["certification_eligible"] is False
    assert artifact["operation_path"] == SHOW_INTERFACE.path
    assert artifact["parser_version"] == PARSER_VERSION
    assert artifact["raw_payload_sha256"].startswith("sha256:")
    assert "findings" in artifact
    blob = json.dumps(artifact)
    assert SYNTH_MAC not in blob
    assert SYNTH_SSID not in blob
    assert SYNTH_SECRET not in blob
    assert "interface" not in blob.lower() or "interface_id_hash" in blob


def test_parse_rejects_mac_and_unknown_shape() -> None:
    payload, _ = _load("topology_interface_wan_isolated.json")
    assert isinstance(payload, dict)
    bad = dict(payload)
    iface_list = list(bad["interface"])
    iface_list[0] = dict(iface_list[0])
    iface_list[0]["mac"] = SYNTH_MAC
    bad["interface"] = iface_list
    with pytest.raises(TopologyProbeError, match="shape invalid"):
        parse_topology_interfaces(bad)


def test_parse_rejects_name_inferred_role_only() -> None:
    payload = {
        "interface": [
            {
                "id": "ISP",
                "type": "ISP",
                "role": "unknown",
                "link": "up",
                "connected": True,
                "address": ["10.0.0.5/24"],
                "bridge": None,
                "segment": None,
                "uplink": None,
            },
            {
                "id": "Home",
                "type": "Bridge",
                "role": "lan",
                "link": "up",
                "connected": True,
                "address": ["192.168.1.1/24"],
                "bridge": "Bridge0",
                "segment": "Home",
                "uplink": None,
            },
        ]
    }
    interfaces = parse_topology_interfaces(payload)
    assert classify_topology(interfaces) == TopologyClassification.AMBIGUOUS
    artifact = build_topology_artifact(**_artifact_kwargs(payload, json.dumps(payload).encode()))
    assert artifact["findings"]["classification"] == TopologyClassification.AMBIGUOUS.value


def test_f1_shared_segment_with_null_wan_bridge_not_isolated() -> None:
    """F-1: shared non-empty segment must not prove isolation when WAN bridge is null."""
    payload = {
        "interface": [
            {
                "id": "ISP",
                "type": "ISP",
                "role": "wan",
                "link": "up",
                "connected": True,
                "address": ["10.0.0.5/24"],
                "bridge": None,
                "segment": "Home",
                "uplink": None,
            },
            {
                "id": "Home",
                "type": "Bridge",
                "role": "lan",
                "link": "up",
                "connected": True,
                "address": ["192.168.1.1/24"],
                "bridge": "Bridge0",
                "segment": "Home",
                "uplink": None,
            },
        ]
    }
    interfaces = parse_topology_interfaces(payload)
    assert classify_topology(interfaces) == TopologyClassification.LAN_TO_LAN_OR_OVERLAP


def test_f2_overlapping_unequal_cidrs_not_isolated() -> None:
    """F-2: overlapping prefixes must not rely on exact CIDR string equality."""
    payload = {
        "interface": [
            {
                "id": "ISP",
                "type": "ISP",
                "role": "wan",
                "link": "up",
                "connected": True,
                "address": ["10.0.0.0/16"],
                "bridge": None,
                "segment": None,
                "uplink": None,
            },
            {
                "id": "Home",
                "type": "Bridge",
                "role": "lan",
                "link": "up",
                "connected": True,
                "address": ["10.0.1.0/24"],
                "bridge": "Bridge0",
                "segment": "Home",
                "uplink": None,
            },
        ]
    }
    interfaces = parse_topology_interfaces(payload)
    assert classify_topology(interfaces) == TopologyClassification.LAN_TO_LAN_OR_OVERLAP


def test_f3_wan_uplink_matching_lan_id_not_isolated() -> None:
    """F-3: WAN uplink referencing LAN interface id must not prove isolation."""
    payload = {
        "interface": [
            {
                "id": "ISP",
                "type": "ISP",
                "role": "wan",
                "link": "up",
                "connected": True,
                "address": ["10.0.0.5/24"],
                "bridge": None,
                "segment": None,
                "uplink": "Home",
            },
            {
                "id": "Home",
                "type": "Bridge",
                "role": "lan",
                "link": "up",
                "connected": True,
                "address": ["192.168.1.1/24"],
                "bridge": "Bridge0",
                "segment": "Home",
                "uplink": None,
            },
        ]
    }
    interfaces = parse_topology_interfaces(payload)
    assert classify_topology(interfaces) == TopologyClassification.LAN_TO_LAN_OR_OVERLAP


def test_f5_unresolved_wan_uplink_not_isolated() -> None:
    """F-5: WAN uplink not resolving to a listed interface id must not prove isolation."""
    payload = {
        "interface": [
            {
                "id": "ISP",
                "type": "ISP",
                "role": "wan",
                "link": "up",
                "connected": True,
                "address": ["10.0.0.5/24"],
                "bridge": None,
                "segment": None,
                "uplink": "ExternalPhy",
            },
            {
                "id": "Home",
                "type": "Bridge",
                "role": "lan",
                "link": "up",
                "connected": True,
                "address": ["192.168.1.1/24"],
                "bridge": "Bridge0",
                "segment": "Home",
                "uplink": None,
            },
        ]
    }
    interfaces = parse_topology_interfaces(payload)
    assert classify_topology(interfaces) == TopologyClassification.AMBIGUOUS


def test_f6_unresolved_lan_uplink_not_isolated() -> None:
    """F-6: LAN uplink not resolving to a listed interface id must not prove isolation."""
    payload = {
        "interface": [
            {
                "id": "ISP",
                "type": "ISP",
                "role": "wan",
                "link": "up",
                "connected": True,
                "address": ["10.0.0.5/24"],
                "bridge": None,
                "segment": None,
                "uplink": None,
            },
            {
                "id": "Home",
                "type": "Bridge",
                "role": "lan",
                "link": "up",
                "connected": True,
                "address": ["192.168.1.1/24"],
                "bridge": "Bridge0",
                "segment": "Home",
                "uplink": "ExternalPhy",
            },
        ]
    }
    interfaces = parse_topology_interfaces(payload)
    assert classify_topology(interfaces) == TopologyClassification.AMBIGUOUS


def test_f4_missing_role_yields_ambiguous_not_error() -> None:
    """F-4: missing role yields ambiguous classification instead of hard parse error."""
    payload = {
        "interface": [
            {
                "id": "ISP",
                "type": "ISP",
                "link": "up",
                "connected": True,
                "address": ["10.0.0.5/24"],
                "bridge": None,
                "segment": None,
                "uplink": None,
            },
            {
                "id": "Home",
                "type": "Bridge",
                "role": "lan",
                "link": "up",
                "connected": True,
                "address": ["192.168.1.1/24"],
                "bridge": "Bridge0",
                "segment": "Home",
                "uplink": None,
            },
        ]
    }
    interfaces = parse_topology_interfaces(payload)
    assert classify_topology(interfaces) == TopologyClassification.AMBIGUOUS
    artifact = build_topology_artifact(**_artifact_kwargs(payload, json.dumps(payload).encode()))
    assert artifact["findings"]["classification"] == TopologyClassification.AMBIGUOUS.value


def test_topology_errors_do_not_embed_payload_fragments() -> None:
    exc = TopologyProbeError("topology payload shape invalid")
    text = str(exc)
    assert SYNTH_SECRET not in text
    assert "{" not in text


def test_public_address_dropped_from_prefixes() -> None:
    payload = {
        "interface": [
            {
                "id": "ISP",
                "type": "ISP",
                "role": "wan",
                "link": "up",
                "connected": True,
                "address": ["8.8.8.8/24"],
                "bridge": None,
                "segment": None,
                "uplink": None,
            },
            {
                "id": "Home",
                "type": "Bridge",
                "role": "lan",
                "link": "up",
                "connected": True,
                "address": ["192.168.1.1/24"],
                "bridge": "Bridge0",
                "segment": "Home",
                "uplink": None,
            },
        ]
    }
    interfaces = parse_topology_interfaces(payload)
    assert classify_topology(interfaces) == TopologyClassification.AMBIGUOUS


def _assert_structure_bounds(structure: dict[str, object]) -> None:
    assert len(structure["dynamic_top_key_hashes"]) <= _STRUCTURE_MAX_ENTRIES
    assert len(structure["secret_field_categories"]) <= _STRUCTURE_MAX_ENTRIES
    assert len(structure["field_samples"]) <= _STRUCTURE_MAX_ENTRIES
    for sample in structure["field_samples"]:
        dynamic_hashes = sample.get("dynamic_key_hashes")
        if dynamic_hashes is not None:
            assert len(dynamic_hashes) <= _STRUCTURE_MAX_ENTRIES
    encoded = json.dumps(structure, sort_keys=True, separators=(",", ":"))
    assert len(encoded) <= _STRUCTURE_MAX_OUTPUT_BYTES


def _assert_structure_has_no_canaries(blob: str) -> None:
    for forbidden in (SYNTH_MAC, SYNTH_SSID, SYNTH_SECRET, SYNTH_ID, SYNTH_IP, "ISP", "Home"):
        assert forbidden not in blob


def _shape_kwargs(payload: object, raw: bytes, error: TopologyProbeError) -> dict[str, object]:
    return {
        "payload": payload,
        "raw_bytes": raw,
        "parser_error": error,
        "source_address": "192.168.1.144",
        "source_address_class": "private_ipv4_literal",
        "gate_a_tuple_digest": "sha256:" + "c" * 64,
        "gate_a_evidence_digest": "sha256:" + "d" * 64,
        "transport_security": "fixture",
        "https_check": "fixture",
        "ssh_host_key_algorithm": "fixture",
        "ssh_host_key_fingerprint_sha256": "SHA256:fixture",
    }


def test_describe_structure_rejects_non_object() -> None:
    with pytest.raises(ValueError, match="JSON object"):
        describe_structure([])


def test_describe_structure_map_keyed_interface() -> None:
    payload = {
        "interface": {
            SYNTH_ID: {
                "type": "ISP",
                "role": "wan",
                "link": "up",
                "connected": True,
                "address": [f"{SYNTH_IP}/24"],
                "password": SYNTH_SECRET,
            }
        }
    }
    structure = describe_structure(payload)
    blob = json.dumps(structure)
    _assert_structure_has_no_canaries(blob)
    assert structure["top_type"] == "object"
    assert structure["top_count"] == 1
    assert "dynamic_key_hashes" in json.dumps(structure)
    assert any(item["category"] == "password" for item in structure["secret_field_categories"])
    assert not any(
        item["category"] == "address" for item in structure["secret_field_categories"]
    )
    allowlisted_names = {
        field["name"]
        for sample in structure["field_samples"]
        for field in sample.get("allowlisted_fields", [])
    }
    assert "address" in allowlisted_names


def test_describe_structure_expanded_allowlist_emits_name_and_type_only() -> None:
    """Field-name discovery: new AC-1 names surface as name+type; sensitive names stay
    categorized."""
    payload = {
        "interface": {
            SYNTH_ID: {
                "type": "Bridge",
                "state": "up",
                "up": True,
                "mtu": 1500,
                "gateway": "10.0.0.1",
                "defaultgw": True,
                "mask": "255.255.255.0",
                "members": ["Port0", "Port1"],
                "member": "Port0",
                "addresses": ["10.0.2.0/24"],
                "traits": {"wifi": False},
                "parent": "Bridge0",
                "via": "ISP",
                "port": "GigabitEthernet0",
                "network": "10.0.0.0/24",
                "prefix": "24",
                "prefix-length": 24,
                "security-level": "public",
                "role": "lan",
                "link": "up",
                "connected": True,
                "bridge": "Bridge1",
                "segment": "SegmentA",
                "id": SYNTH_ID,
                "dns": "8.8.8.8",
                "mac": SYNTH_MAC,
            }
        }
    }
    structure = describe_structure(payload)
    blob = json.dumps(structure)
    _assert_structure_has_no_canaries(blob)
    assert "255.255.255.0" not in blob
    assert "8.8.8.8" not in blob
    assert "10.0.0.1" not in blob
    assert "10.0.2.0/24" not in blob
    assert "Bridge1" not in blob
    assert "SegmentA" not in blob
    assert "Port0" not in blob
    allowlisted_names = {
        field["name"]
        for sample in structure["field_samples"]
        for field in sample.get("allowlisted_fields", [])
    }
    for name in (
        "type",
        "state",
        "up",
        "mtu",
        "gateway",
        "defaultgw",
        "mask",
        "members",
        "member",
        "addresses",
        "traits",
        "parent",
        "via",
        "port",
        "network",
        "prefix",
        "prefix-length",
        "security-level",
        "role",
        "link",
        "connected",
        "bridge",
        "segment",
        "interface",
    ):
        assert name in allowlisted_names, name
    categories = {item["category"] for item in structure["secret_field_categories"]}
    assert "identifier" in categories
    assert "address" in categories
    assert "mac" in categories
    # never named alongside a sensitive category
    assert "id" not in allowlisted_names
    assert "dns" not in allowlisted_names
    assert "mac" not in allowlisted_names


def test_structure_allowlisted_fields_matches_ac1_closed_set() -> None:
    """Drift guard: AC-1's closed allowlist must not silently grow or shrink."""
    assert _STRUCTURE_ALLOWLISTED_FIELDS == frozenset(
        {
            "type",
            "link",
            "connected",
            "state",
            "up",
            "traits",
            "address",
            "addresses",
            "ip",
            "mask",
            "prefix",
            "prefix-length",
            "network",
            "gateway",
            "defaultgw",
            "security-level",
            "role",
            "bridge",
            "segment",
            "uplink",
            "parent",
            "via",
            "interface",
            "member",
            "members",
            "port",
            "mtu",
        }
    )


def test_describe_structure_map_keyed_dynamic_ids_always_hashed() -> None:
    """Map-keyed interface top keys (interface identifiers) are never named literally."""
    payload = {
        "interface": {
            SYNTH_ID: {"type": "Bridge", "state": "up"},
            "AnotherIfaceName": {"type": "ISP", "state": "down"},
        }
    }
    structure = describe_structure(payload)
    blob = json.dumps(structure)
    _assert_structure_has_no_canaries(blob)
    assert "AnotherIfaceName" not in blob
    dynamic_hash_samples = [
        sample
        for sample in structure["field_samples"]
        if sample.get("dynamic_key_hashes")
    ]
    assert dynamic_hash_samples
    for sample in dynamic_hash_samples:
        for digest in sample["dynamic_key_hashes"]:
            assert digest.startswith("sha256:")


def test_describe_structure_list_interface() -> None:
    payload = {
        "interface": [
            {
                "id": SYNTH_ID,
                "type": "ISP",
                "role": "wan",
                "link": "up",
                "connected": True,
                "address": [f"{SYNTH_IP}/24"],
                "mac": SYNTH_MAC,
                "ssid": SYNTH_SSID,
            }
        ]
    }
    structure = describe_structure(payload)
    blob = json.dumps(structure)
    _assert_structure_has_no_canaries(blob)
    array_samples = [
        item for item in structure["field_samples"] if item["container_type"] == "array"
    ]
    assert array_samples
    assert array_samples[0]["count"] == 1
    assert any(item["category"] == "mac" for item in structure["secret_field_categories"])


def test_describe_structure_wrapped_payload() -> None:
    payload = {"show": {"interface": [{"id": SYNTH_ID, "type": "ISP"}]}}
    structure = describe_structure(payload)
    blob = json.dumps(structure)
    _assert_structure_has_no_canaries(blob)
    assert structure["dynamic_top_key_hashes"]


def test_describe_structure_deep_nesting_truncates() -> None:
    payload: dict[str, object] = {"interface": {"a": {"b": {"c": {"d": "nested"}}}}}
    structure = describe_structure(payload)
    assert structure["truncated"] is True


def test_describe_structure_oversize_truncates() -> None:
    payload = {"interface": {f"iface-{index}": {"type": "Bridge"} for index in range(40)}}
    structure = describe_structure(payload)
    assert structure["truncated"] is True
    _assert_structure_bounds(structure)
    interface_samples = [
        item
        for item in structure["field_samples"]
        if item.get("container_type") == "object" and item.get("dynamic_key_hashes")
    ]
    assert interface_samples
    assert len(interface_samples[0]["dynamic_key_hashes"]) <= _STRUCTURE_MAX_ENTRIES


def test_describe_structure_many_top_keys_truncates() -> None:
    payload = {f"k{index}": index for index in range(500)}
    structure = describe_structure(payload)
    assert structure["truncated"] is True
    _assert_structure_bounds(structure)


def test_describe_structure_many_secrets_truncates() -> None:
    payload = {f"password_{index}": "x" for index in range(200)}
    structure = describe_structure(payload)
    assert structure["truncated"] is True
    assert len(structure["secret_field_categories"]) <= _STRUCTURE_MAX_ENTRIES
    _assert_structure_bounds(structure)


def test_build_topology_shape_artifact_envelope() -> None:
    payload = {"interface": {SYNTH_ID: {"type": "ISP", "password": SYNTH_SECRET}}}
    raw = json.dumps(payload).encode("utf-8")
    error = TopologyProbeError("topology interface list shape invalid")
    artifact = build_topology_shape_artifact(**_shape_kwargs(payload, raw, error))
    blob = json.dumps(artifact)
    _assert_structure_has_no_canaries(blob)
    assert artifact["certification_eligible"] is False
    assert artifact["operation_path"] == "/rci/show/interface"
    assert artifact["source_address"] == "192.168.1.144"
    assert artifact["parser_error_class"] == "interface_list_shape_invalid"
    assert artifact["structure_canonical_digest"].startswith("sha256:")
    assert "findings" not in artifact


def test_build_topology_shape_artifact_preserves_secret_field_categories() -> None:
    payload = {
        "interface": {
            SYNTH_ID: {
                "type": "ISP",
                "role": "wan",
                "password": SYNTH_SECRET,
                "address": [f"{SYNTH_IP}/24"],
            }
        }
    }
    raw = json.dumps(payload).encode("utf-8")
    error = TopologyProbeError("topology interface list shape invalid")
    artifact = build_topology_shape_artifact(**_shape_kwargs(payload, raw, error))
    categories = artifact["structure"]["secret_field_categories"]
    assert isinstance(categories, list)
    assert categories
    assert all(isinstance(item, dict) and "category" in item for item in categories)
    assert any(item["category"] == "password" for item in categories)
    assert not any(item["category"] == "address" for item in categories)
    allowlisted_names = {
        field["name"]
        for sample in artifact["structure"]["field_samples"]
        for field in sample.get("allowlisted_fields", [])
    }
    assert "address" in allowlisted_names
    blob = json.dumps(artifact)
    _assert_structure_has_no_canaries(blob)


def test_build_topology_shape_artifact_digest_matches_emitted_structure() -> None:
    payload = {"interface": {SYNTH_ID: {"type": "ISP", "description": "leak-me"}}}
    raw = json.dumps(payload).encode("utf-8")
    error = TopologyProbeError("topology interface list shape invalid")
    artifact = build_topology_shape_artifact(**_shape_kwargs(payload, raw, error))
    expected = digest_structure_fingerprint(
        structure=artifact["structure"],
        parser_error_class=artifact["parser_error_class"],
    )
    assert artifact["structure_canonical_digest"] == expected


def test_build_topology_shape_artifact_preserves_sha256_path_tokens() -> None:
    payload = {"show": {"interface": [{"id": SYNTH_ID, "type": "ISP"}]}}
    raw = json.dumps(payload).encode("utf-8")
    error = TopologyProbeError("topology payload shape invalid")
    artifact = build_topology_shape_artifact(**_shape_kwargs(payload, raw, error))
    structure_blob = json.dumps(artifact["structure"])
    assert "sha256:" in structure_blob
    assert "REDACTED" not in structure_blob
    assert artifact["structure"]["dynamic_top_key_hashes"]
    for digest in artifact["structure"]["dynamic_top_key_hashes"]:
        assert digest.startswith("sha256:")


def test_structure_digest_is_deterministic() -> None:
    payload = {"interface": {SYNTH_ID: {"type": "ISP", "description": "leak-me"}}}
    structure = describe_structure(payload)
    digest_a = digest_structure_fingerprint(
        structure=structure,
        parser_error_class="interface_list_shape_invalid",
    )
    digest_b = digest_structure_fingerprint(
        structure=describe_structure(payload),
        parser_error_class="interface_list_shape_invalid",
    )
    assert digest_a == digest_b


def test_classify_parser_error_is_stable() -> None:
    assert (
        classify_parser_error(TopologyProbeError("topology payload shape invalid"))
        == "payload_shape_invalid"
    )
    assert (
        classify_parser_error(TopologyProbeError("topology keyed candidates empty"))
        == "keyed_candidates_empty"
    )
    assert classify_parser_error(TopologyProbeError("unexpected")) == "topology_parse_failed"


@pytest.mark.parametrize(
    ("fixture", "expected"),
    [
        ("topology_observed_keyed_wan_isolated.json", TopologyClassification.PROVEN_WAN_ISOLATED),
        ("topology_observed_keyed_overlap.json", TopologyClassification.LAN_TO_LAN_OR_OVERLAP),
        ("topology_observed_keyed_ambiguous.json", TopologyClassification.AMBIGUOUS),
    ],
)
def test_classify_keyed_v2_fixtures(fixture: str, expected: TopologyClassification) -> None:
    payload, _ = _load(fixture)
    interfaces = parse_topology_interfaces(payload)
    assert all(iface.keyed_parse for iface in interfaces)
    assert classify_topology(interfaces) == expected


def test_keyed_v2_artifact_parser_version_and_non_certifying() -> None:
    payload, raw = _load("topology_observed_keyed_wan_isolated.json")
    artifact = build_topology_artifact(**_artifact_kwargs(payload, raw))
    assert artifact["certification_eligible"] is False
    assert artifact["parser_version"] == PARSER_VERSION_V2
    blob = json.dumps(artifact)
    assert "upstream-wan-001" not in blob
    assert "home-bridge-002" not in blob
    assert "Bridge0" not in blob
    assert (
        artifact["findings"]["classification"]
        == TopologyClassification.PROVEN_WAN_ISOLATED.value
    )
    sanitized = artifact["findings"]["sanitized_interfaces"]
    assert all("bridge_hash" in item for item in sanitized)
    assert all("bridge" not in item for item in sanitized)


def test_keyed_v2_root_direct_mapping_without_interface_wrapper() -> None:
    payload = {
        "upstream-wan-001": {
            "type": "ISP",
            "role": "wan",
            "state": "up",
            "connected": True,
            "address": ["10.0.0.5/24"],
        },
        "home-bridge-002": {
            "type": "Bridge",
            "traits": ["Bridge", "Home"],
            "link": "down",
            "connected": True,
            "ip": "192.168.1.1",
            "mask": "255.255.255.0",
            "bridge": "Bridge0",
            "segment": "Home",
        },
        "firmware_label": "stable",
    }
    interfaces = parse_topology_interfaces(payload)
    assert len(interfaces) == 2
    wan = next(
        i for i in interfaces if i.interface_id_hash == hash_interface_id("upstream-wan-001")
    )
    lan = next(
        i for i in interfaces if i.interface_id_hash == hash_interface_id("home-bridge-002")
    )
    assert wan.link_up is None
    assert wan.connected is True
    assert lan.link_up is False
    assert lan.connected is True
    assert classify_topology(interfaces) == TopologyClassification.AMBIGUOUS


def test_keyed_v2_role_precedence_and_traits() -> None:
    payload = {
        "iface-a": {
            "type": "ISP",
            "security-level": "public",
            "traits": ["Internet"],
            "connected": True,
            "link": "up",
            "address": ["10.0.0.5/24"],
        },
        "iface-b": {
            "type": "Bridge",
            "security-level": "private",
            "traits": ["Bridge", "Home"],
            "connected": True,
            "link": "up",
            "address": ["192.168.2.1/24"],
        },
    }
    interfaces = parse_topology_interfaces(payload)
    roles = {iface.interface_id_hash: iface.role for iface in interfaces}
    assert roles[hash_interface_id("iface-a")] == "wan"
    assert roles[hash_interface_id("iface-b")] == "lan"


def test_keyed_v2_traits_conflict_yields_empty_role() -> None:
    payload = {
        "iface-a": {
            "type": "ISP",
            "traits": ["Internet", "Bridge"],
            "connected": True,
            "link": "up",
            "address": ["10.0.0.5/24"],
        },
        "iface-b": {
            "type": "Bridge",
            "role": "lan",
            "connected": True,
            "link": "up",
            "address": ["192.168.1.1/24"],
        },
    }
    interfaces = parse_topology_interfaces(payload)
    wan = next(i for i in interfaces if i.interface_id_hash == hash_interface_id("iface-a"))
    assert wan.role == ""
    assert classify_topology(interfaces) == TopologyClassification.AMBIGUOUS


def test_keyed_v2_never_uses_name_for_role() -> None:
    payload = {
        "ISP": {
            "type": "ISP",
            "traits": ["Bridge"],
            "connected": True,
            "link": "up",
            "address": ["10.0.0.5/24"],
        },
        "Home": {
            "type": "Bridge",
            "role": "lan",
            "connected": True,
            "link": "up",
            "address": ["192.168.1.1/24"],
        },
    }
    interfaces = parse_topology_interfaces(payload)
    assert classify_topology(interfaces) == TopologyClassification.AMBIGUOUS


def test_keyed_v2_strips_drop_keys_and_omits_from_output() -> None:
    payload = {
        "iface-a": {
            "type": "ISP",
            "role": "wan",
            "connected": True,
            "link": "up",
            "address": ["10.0.0.5/24"],
            "mac": SYNTH_MAC,
            "description": "SYNTH-DESCRIPTION-ORACLE",
        },
        "iface-b": {
            "type": "Bridge",
            "role": "lan",
            "connected": True,
            "link": "up",
            "address": ["192.168.1.1/24"],
        },
    }
    interfaces = parse_topology_interfaces(payload)
    assert len(interfaces) == 2
    artifact = build_topology_artifact(**_artifact_kwargs(payload, json.dumps(payload).encode()))
    blob = json.dumps(artifact)
    assert SYNTH_MAC not in blob
    assert "SYNTH-DESCRIPTION-ORACLE" not in blob
    assert "mac" not in blob
    assert "description" not in blob
    sanitized = artifact["findings"]["sanitized_interfaces"]
    for item in sanitized:
        assert "mac" not in item
        assert "description" not in item


def test_keyed_v2_rejects_duplicate_id_hashes() -> None:
    duplicate_id = "iface-dup"
    payload = {
        duplicate_id: {
            "type": "ISP",
            "role": "wan",
            "connected": True,
            "link": "up",
            "address": ["10.0.0.5/24"],
        },
        f"  {duplicate_id}  ": {
            "type": "Bridge",
            "role": "lan",
            "connected": True,
            "link": "up",
            "address": ["192.168.1.1/24"],
        },
    }
    with pytest.raises(TopologyProbeError, match="duplicate interface id"):
        parse_topology_interfaces(payload)


def test_keyed_v2_rejects_oversize_candidates() -> None:
    payload = {
        f"iface-{index}": {
            "type": "Bridge",
            "role": "lan",
            "connected": True,
            "link": "up",
            "address": [f"192.168.{index % 256}.1/24"],
        }
        for index in range(MAX_KEYED_CANDIDATES + 1)
    }
    with pytest.raises(TopologyProbeError, match="oversize"):
        parse_topology_interfaces(payload)


def test_keyed_v2_rejects_zero_candidates() -> None:
    with pytest.raises(TopologyProbeError, match="keyed candidates empty"):
        parse_topology_interfaces({"version": 1, "label": "lab"})


def test_keyed_v2_ignores_missing_link_connected_state_non_candidate() -> None:
    payload = {
        "iface-a": {"type": "ISP", "role": "wan", "address": ["10.0.0.5/24"]},
        "iface-b": {
            "type": "Bridge",
            "role": "lan",
            "connected": True,
            "link": "up",
            "address": ["192.168.1.1/24"],
        },
    }
    interfaces = parse_topology_interfaces(payload)
    assert len(interfaces) == 1
    assert interfaces[0].interface_id_hash == hash_interface_id("iface-b")


def test_keyed_v2_malformed_consumed_field_omits_and_records_uncertainty() -> None:
    payload = {
        "iface-valid": {
            "type": "Bridge",
            "role": "lan",
            "connected": True,
            "link": "up",
            "address": ["192.168.1.1/24"],
        },
        "iface-bad-traits": {
            "type": "ISP",
            "role": "wan",
            "traits": {"not": "list"},
            "connected": True,
            "link": "up",
            "address": ["10.0.0.5/24"],
        },
    }
    interfaces = parse_topology_interfaces(payload)
    assert len(interfaces) == 2
    wan = next(
        i for i in interfaces if i.interface_id_hash == hash_interface_id("iface-bad-traits")
    )
    assert "traits" in wan.uncertainty
    assert classify_topology(interfaces) == TopologyClassification.AMBIGUOUS


def test_keyed_v2_malformed_role_omits_and_records_uncertainty() -> None:
    payload = {
        "iface-valid": {
            "type": "Bridge",
            "role": "lan",
            "connected": True,
            "link": "up",
            "address": ["192.168.1.1/24"],
        },
        "iface-bad-role": {
            "type": "ISP",
            "role": 42,
            "traits": ["Internet"],
            "connected": True,
            "link": "up",
            "address": ["10.0.0.5/24"],
        },
    }
    interfaces = parse_topology_interfaces(payload)
    assert len(interfaces) == 2
    wan = next(i for i in interfaces if i.interface_id_hash == hash_interface_id("iface-bad-role"))
    assert "role" in wan.uncertainty
    assert wan.role == "wan"
    assert classify_topology(interfaces) == TopologyClassification.AMBIGUOUS


def test_keyed_v2_malformed_address_omits_and_records_uncertainty() -> None:
    payload = {
        "iface-valid": {
            "type": "Bridge",
            "role": "lan",
            "connected": True,
            "link": "up",
            "address": ["192.168.1.1/24"],
        },
        "iface-bad-address": {
            "type": "ISP",
            "role": "wan",
            "connected": True,
            "link": "up",
            "address": [123],
        },
    }
    interfaces = parse_topology_interfaces(payload)
    assert len(interfaces) == 2
    wan = next(
        i for i in interfaces if i.interface_id_hash == hash_interface_id("iface-bad-address")
    )
    assert "address" in wan.uncertainty
    assert wan.private_prefixes == ()
    assert classify_topology(interfaces) == TopologyClassification.AMBIGUOUS


def test_keyed_v2_present_unparseable_link_uses_valid_signal_and_records_uncertainty() -> None:
    """Present-but-unparseable link leaves link_up unknown; connected stays independent."""
    payload = {
        "wan": {
            "type": "ISP",
            "role": "wan",
            "link": ["up"],
            "connected": True,
            "address": ["10.0.0.5/24"],
        },
        "lan": {
            "type": "Bridge",
            "role": "lan",
            "link": "up",
            "connected": True,
            "address": ["192.168.1.1/24"],
        },
    }
    interfaces = parse_topology_interfaces(payload)
    assert len(interfaces) == 2
    wan = next(i for i in interfaces if i.interface_id_hash == hash_interface_id("wan"))
    assert "link" in wan.uncertainty
    assert wan.link_up is None
    assert wan.connected is True
    assert classify_topology(interfaces) == TopologyClassification.AMBIGUOUS


@pytest.mark.parametrize(
    ("link_value", "expected_link_up"),
    [
        ("enabled", True),
        ("1", True),
        (1, None),
    ],
    ids=["str_enabled", "str_one", "int_one_unknown"],
)
def test_topology_v1_list_link_recognized_not_dropped(
    link_value: object,
    expected_link_up: bool | None,
) -> None:
    """Shared parser gates v1 list parse — present link keys must not drop interface (F-1)."""
    payload = {
        "interface": [
            {
                "id": "GigabitEthernet0",
                "type": "GigabitEthernet",
                "role": "wan",
                "link": link_value,
                "connected": True,
                "address": ["10.0.0.5/24"],
            },
            {
                "id": "Bridge0",
                "type": "Bridge",
                "role": "lan",
                "link": "up",
                "connected": True,
                "address": ["192.168.1.1/24"],
            },
        ]
    }
    interfaces = parse_topology_interfaces(payload)
    assert len(interfaces) == 2
    wan_hash = hash_interface_id("GigabitEthernet0")
    wan = next(i for i in interfaces if i.interface_id_hash == wan_hash)
    assert wan.link_up is expected_link_up
    assert wan.connected is True


@pytest.mark.parametrize(
    ("link_value", "expected_link_up", "expect_link_uncertainty"),
    [
        ("enabled", True, False),
        ("1", True, False),
        (1, None, True),
    ],
    ids=["str_enabled", "str_one", "int_one_unknown"],
)
def test_topology_keyed_link_recognized_not_dropped(
    link_value: object,
    expected_link_up: bool | None,
    expect_link_uncertainty: bool,
) -> None:
    """Keyed v2 must keep interface when link key present — shared parser, no drop (F-1)."""
    payload = {
        "wan": {
            "type": "ISP",
            "role": "wan",
            "link": link_value,
            "connected": True,
            "address": ["10.0.0.5/24"],
        },
        "lan": {
            "type": "Bridge",
            "role": "lan",
            "link": "up",
            "connected": True,
            "address": ["192.168.1.1/24"],
        },
    }
    interfaces = parse_topology_interfaces(payload)
    assert len(interfaces) == 2
    wan = next(i for i in interfaces if i.interface_id_hash == hash_interface_id("wan"))
    assert wan.link_up is expected_link_up
    assert wan.connected is True
    if expect_link_uncertainty:
        assert "link" in wan.uncertainty
    else:
        assert "link" not in wan.uncertainty


def test_keyed_v2_present_unparseable_connected_uses_valid_signal_and_records_uncertainty() -> None:
    """Present-but-unparseable connected leaves connected unknown; link_up stays independent."""
    payload = {
        "wan": {
            "type": "ISP",
            "role": "wan",
            "link": "up",
            "connected": {"unexpected": "object"},
            "address": ["10.0.0.5/24"],
        },
        "lan": {
            "type": "Bridge",
            "role": "lan",
            "link": "up",
            "connected": True,
            "address": ["192.168.1.1/24"],
        },
    }
    interfaces = parse_topology_interfaces(payload)
    assert len(interfaces) == 2
    wan = next(i for i in interfaces if i.interface_id_hash == hash_interface_id("wan"))
    assert "connected" in wan.uncertainty
    assert wan.link_up is True
    assert wan.connected is None
    assert classify_topology(interfaces) == TopologyClassification.AMBIGUOUS


def test_keyed_v2_present_non_list_non_str_address_omits_and_records_uncertainty() -> None:
    """Present address with wrong container type omits fact and records uncertainty."""
    payload = {
        "iface-valid": {
            "type": "Bridge",
            "role": "lan",
            "connected": True,
            "link": "up",
            "address": ["192.168.1.1/24"],
        },
        "iface-bad-address-type": {
            "type": "ISP",
            "role": "wan",
            "connected": True,
            "link": "up",
            "address": {"ip": "10.0.0.5/24"},
        },
    }
    interfaces = parse_topology_interfaces(payload)
    assert len(interfaces) == 2
    wan = next(
        i for i in interfaces if i.interface_id_hash == hash_interface_id("iface-bad-address-type")
    )
    assert "address" in wan.uncertainty
    assert wan.private_prefixes == ()
    assert classify_topology(interfaces) == TopologyClassification.AMBIGUOUS


def test_keyed_v2_present_non_str_mask_omits_and_records_uncertainty() -> None:
    """Present mask with non-str type omits mask contribution and records uncertainty."""
    payload = {
        "iface-valid": {
            "type": "Bridge",
            "role": "lan",
            "connected": True,
            "link": "up",
            "address": ["192.168.1.1/24"],
        },
        "iface-bad-mask": {
            "type": "ISP",
            "role": "wan",
            "connected": True,
            "link": "up",
            "ip": "10.0.0.5",
            "mask": 24,
        },
    }
    interfaces = parse_topology_interfaces(payload)
    assert len(interfaces) == 2
    wan = next(i for i in interfaces if i.interface_id_hash == hash_interface_id("iface-bad-mask"))
    assert "mask" in wan.uncertainty
    assert wan.private_prefixes == ()
    assert classify_topology(interfaces) == TopologyClassification.AMBIGUOUS


def test_keyed_v2_invalid_string_mask_beside_ready_cidr_records_uncertainty() -> None:
    """Orphan invalid-string mask beside ready CIDR records mask and blocks proven."""
    payload = {
        "wan-iface": {
            "type": "ISP",
            "role": "wan",
            "connected": True,
            "link": "up",
            "address": ["10.0.0.5/24"],
            "mask": "not-a-mask",
        },
        "lan-iface": {
            "type": "Bridge",
            "role": "lan",
            "connected": True,
            "link": "up",
            "address": ["192.168.1.1/24"],
        },
    }
    interfaces = parse_topology_interfaces(payload)
    wan = next(i for i in interfaces if i.interface_id_hash == hash_interface_id("wan-iface"))
    assert "mask" in wan.uncertainty
    assert wan.private_prefixes == ("10.0.0.0/24",)
    assert classify_topology(interfaces) == TopologyClassification.AMBIGUOUS


@pytest.mark.parametrize("bad_key,bad_value", [("prefix", "not-a-prefix"), ("prefix-length", True)])
def test_keyed_v2_orphan_bad_prefix_beside_ready_cidr_blocks_proven(
    bad_key: str, bad_value: object
) -> None:
    """Orphan malformed prefix/prefix-length beside ready CIDR blocks proven isolation."""
    payload = {
        "wan-iface": {
            "type": "ISP",
            "role": "wan",
            "connected": True,
            "link": "up",
            "address": ["10.0.0.5/24"],
            bad_key: bad_value,
        },
        "lan-iface": {
            "type": "Bridge",
            "role": "lan",
            "connected": True,
            "link": "up",
            "address": ["192.168.1.1/24"],
        },
    }
    interfaces = parse_topology_interfaces(payload)
    wan = next(i for i in interfaces if i.interface_id_hash == hash_interface_id("wan-iface"))
    assert bad_key in wan.uncertainty
    assert wan.private_prefixes == ("10.0.0.0/24",)
    assert classify_topology(interfaces) == TopologyClassification.AMBIGUOUS


def test_keyed_v2_invalid_string_mask_partial_octets_records_uncertainty() -> None:
    """Invalid partial mask string beside ready CIDR records mask uncertainty."""
    payload = {
        "wan-iface": {
            "type": "ISP",
            "role": "wan",
            "connected": True,
            "link": "up",
            "address": ["10.0.0.5/24"],
            "mask": "255.255.255",
        },
        "lan-iface": {
            "type": "Bridge",
            "role": "lan",
            "connected": True,
            "link": "up",
            "address": ["192.168.1.1/24"],
        },
    }
    interfaces = parse_topology_interfaces(payload)
    wan = next(i for i in interfaces if i.interface_id_hash == hash_interface_id("wan-iface"))
    assert "mask" in wan.uncertainty
    assert classify_topology(interfaces) == TopologyClassification.AMBIGUOUS


def test_keyed_v2_strips_case_insensitive_drop_keys_and_omits_canaries() -> None:
    """F-4: uppercase drop keys stripped; canaries absent from sanitized output."""
    payload = {
        "iface-a": {
            "type": "ISP",
            "role": "wan",
            "connected": True,
            "link": "up",
            "address": ["10.0.0.5/24"],
            "MAC": SYNTH_MAC,
            "Description": "SYNTH-DESCRIPTION-ORACLE",
        },
        "iface-b": {
            "type": "Bridge",
            "role": "lan",
            "connected": True,
            "link": "up",
            "address": ["192.168.1.1/24"],
            "SSID": SYNTH_SSID,
        },
    }
    interfaces = parse_topology_interfaces(payload)
    assert len(interfaces) == 2
    artifact = build_topology_artifact(**_artifact_kwargs(payload, json.dumps(payload).encode()))
    blob = json.dumps(artifact)
    assert SYNTH_MAC not in blob
    assert SYNTH_SSID not in blob
    assert "SYNTH-DESCRIPTION-ORACLE" not in blob
    for drop_name in ("MAC", "mac", "Description", "description", "SSID", "ssid"):
        assert drop_name not in blob
    sanitized = artifact["findings"]["sanitized_interfaces"]
    for item in sanitized:
        for drop_name in ("mac", "description", "ssid"):
            assert drop_name not in item


def test_keyed_v2_mixed_root_fixture_strips_and_classifies() -> None:
    """Mixed live-shape root: non-candidates ignored; drop keys stripped; ambiguous (public WAN)."""
    payload, raw = _load("topology_observed_mixed_root.json")
    interfaces = parse_topology_interfaces(payload)
    assert len(interfaces) == 2
    assert classify_topology(interfaces) == TopologyClassification.AMBIGUOUS
    artifact = build_topology_artifact(**_artifact_kwargs(payload, raw))
    assert artifact["parser_version"] == PARSER_VERSION_V2
    assert artifact["findings"]["classification"] == TopologyClassification.AMBIGUOUS.value
    assert artifact["findings"]["interfaces_observed"] == 2
    blob = json.dumps(artifact)
    assert SYNTH_MAC not in blob
    assert SYNTH_SSID not in blob
    assert "SYNTH-DESCRIPTION-ORACLE" not in blob
    assert "upstream-wan-001" not in blob
    assert "home-bridge-002" not in blob


def test_keyed_v2_disconnected_wan_not_proven() -> None:
    payload = {
        "upstream-wan-001": {
            "type": "ISP",
            "role": "wan",
            "link": "down",
            "connected": False,
            "address": ["10.0.0.5/24"],
        },
        "home-bridge-002": {
            "type": "Bridge",
            "role": "lan",
            "link": "up",
            "connected": True,
            "address": ["192.168.1.1/24"],
        },
    }
    interfaces = parse_topology_interfaces(payload)
    assert classify_topology(interfaces) == TopologyClassification.AMBIGUOUS


def test_keyed_v2_shared_bridge_hash_overlap() -> None:
    payload = {
        "upstream-wan-001": {
            "type": "ISP",
            "role": "wan",
            "connected": True,
            "link": "up",
            "address": ["10.0.0.5/24"],
            "bridge": "SharedBridge",
        },
        "home-bridge-002": {
            "type": "Bridge",
            "role": "lan",
            "connected": True,
            "link": "up",
            "address": ["192.168.1.1/24"],
            "bridge": "SharedBridge",
        },
    }
    interfaces = parse_topology_interfaces(payload)
    assert classify_topology(interfaces) == TopologyClassification.LAN_TO_LAN_OR_OVERLAP


def test_keyed_v2_bare_host_ip_without_mask_yields_no_private_prefixes() -> None:
    """AC-3: bare host strings must not default to /32 private prefixes."""
    payload = {
        "wan-iface": {
            "type": "ISP",
            "role": "wan",
            "connected": True,
            "link": "up",
            "ip": "10.0.0.5",
        },
        "lan-iface": {
            "type": "Bridge",
            "role": "lan",
            "connected": True,
            "link": "up",
            "ip": "192.168.1.1",
        },
    }
    interfaces = parse_topology_interfaces(payload)
    wan = next(i for i in interfaces if i.interface_id_hash == hash_interface_id("wan-iface"))
    lan = next(i for i in interfaces if i.interface_id_hash == hash_interface_id("lan-iface"))
    assert wan.private_prefixes == ()
    assert lan.private_prefixes == ()
    assert classify_topology(interfaces) == TopologyClassification.AMBIGUOUS


def test_keyed_v2_bare_host_in_address_list_ignored() -> None:
    """AC-3: bare host in address list must not produce /32 network prefix."""
    payload = {
        "wan-iface": {
            "type": "ISP",
            "role": "wan",
            "connected": True,
            "link": "up",
            "address": ["10.0.0.5"],
        },
        "lan-iface": {
            "type": "Bridge",
            "role": "lan",
            "connected": True,
            "link": "up",
            "address": ["192.168.1.1/24"],
        },
    }
    interfaces = parse_topology_interfaces(payload)
    wan = next(i for i in interfaces if i.interface_id_hash == hash_interface_id("wan-iface"))
    assert wan.private_prefixes == ()
    assert classify_topology(interfaces) == TopologyClassification.AMBIGUOUS


def test_keyed_v2_uppercase_role_is_normalized() -> None:
    """Explicit role wan|lan is matched case-insensitively after trim."""
    payload = {
        "wan-iface": {
            "type": "ISP",
            "role": "WAN",
            "connected": True,
            "link": "up",
            "address": ["10.0.0.5/24"],
        },
        "lan-iface": {
            "type": "Bridge",
            "role": "lan",
            "connected": True,
            "link": "up",
            "address": ["192.168.1.1/24"],
        },
    }
    interfaces = parse_topology_interfaces(payload)
    wan = next(i for i in interfaces if i.interface_id_hash == hash_interface_id("wan-iface"))
    assert wan.role == "wan"
    assert classify_topology(interfaces) == TopologyClassification.PROVEN_WAN_ISOLATED


def test_keyed_v2_uppercase_role_resolves_via_traits_when_present() -> None:
    """Traits are matched case-insensitively when explicit role is absent."""
    payload = {
        "wan-iface": {
            "type": "ISP",
            "role": "WAN",
            "traits": ["Internet"],
            "connected": True,
            "link": "up",
            "address": ["10.0.0.5/24"],
        },
        "lan-iface": {
            "type": "Bridge",
            "role": "lan",
            "connected": True,
            "link": "up",
            "address": ["192.168.1.1/24"],
        },
    }
    interfaces = parse_topology_interfaces(payload)
    wan = next(i for i in interfaces if i.interface_id_hash == hash_interface_id("wan-iface"))
    assert wan.role == "wan"
    assert classify_topology(interfaces) == TopologyClassification.PROVEN_WAN_ISOLATED


def test_classify_private_prefix_rfc1918_and_ula_only() -> None:
    assert classify_private_prefix("10.1.2.3/24") == "10.1.2.0/24"
    assert classify_private_prefix("172.16.0.1/16") == "172.16.0.0/16"
    assert classify_private_prefix("192.168.5.1/24") == "192.168.5.0/24"
    assert classify_private_prefix("fd12:3456:789a:1::1/64") is not None
    assert classify_private_prefix("100.64.0.1/10") is None
    assert classify_private_prefix("169.254.1.1/16") is None
    assert classify_private_prefix("8.8.8.8/24") is None


def test_keyed_v2_uncertain_fixture_overlap_with_uncertainty_not_proven() -> None:
    """Unknown state, object address, malformed relation: overlap may fire; never proven."""
    payload, raw = _load("topology_observed_keyed_uncertain.json")
    interfaces = parse_topology_interfaces(payload)
    assert len(interfaces) == 2
    wan = next(
        i for i in interfaces if i.interface_id_hash == hash_interface_id("upstream-wan-001")
    )
    lan = next(
        i for i in interfaces if i.interface_id_hash == hash_interface_id("home-bridge-002")
    )
    assert "state" in wan.uncertainty
    assert "address" in lan.uncertainty
    assert "bridge" in lan.uncertainty
    assert classify_topology(interfaces) == TopologyClassification.LAN_TO_LAN_OR_OVERLAP
    artifact = build_topology_artifact(**_artifact_kwargs(payload, raw))
    assert artifact["parser_version"] == PARSER_VERSION_V2
    assert (
        artifact["findings"]["classification"]
        == TopologyClassification.LAN_TO_LAN_OR_OVERLAP.value
    )
    assert (
        artifact["findings"]["classification"]
        != TopologyClassification.PROVEN_WAN_ISOLATED.value
    )
    blob = json.dumps(artifact)
    assert SYNTH_SECRET not in blob
    assert SYNTH_MAC not in blob
    assert "maybe-up" not in blob
    assert "upstream-wan-001" not in blob
    for item in artifact["findings"]["sanitized_interfaces"]:
        assert "uncertainty" in item
        for name in item["uncertainty"]:
            assert isinstance(name, str)
            assert name in (
                "state",
                "address",
                "bridge",
                "link",
                "connected",
                "role",
                "traits",
                "security-level",
                "ip",
                "network",
                "mask",
                "prefix",
                "prefix-length",
                "segment",
                "uplink",
                "addresses",
            )


def test_keyed_v2_overlap_precedence_over_uncertainty() -> None:
    """Positive prefix overlap returns lan_to_lan_or_overlap even with iface uncertainty."""
    payload = {
        "wan-iface": {
            "type": "ISP",
            "role": "wan",
            "link": "up",
            "connected": True,
            "state": "unknown-state",
            "address": ["10.0.0.0/16"],
        },
        "lan-iface": {
            "type": "Bridge",
            "role": "lan",
            "link": "up",
            "connected": True,
            "address": ["10.0.1.0/24"],
            "traits": {"not": "list"},
        },
    }
    interfaces = parse_topology_interfaces(payload)
    assert any(iface.uncertainty for iface in interfaces)
    assert classify_topology(interfaces) == TopologyClassification.LAN_TO_LAN_OR_OVERLAP


def test_keyed_v2_uncertainty_blocks_proven_without_overlap() -> None:
    payload = {
        "wan-iface": {
            "type": "ISP",
            "role": "wan",
            "link": "up",
            "connected": True,
            "state": "unknown-state",
            "address": ["10.0.0.5/24"],
        },
        "lan-iface": {
            "type": "Bridge",
            "role": "lan",
            "link": "up",
            "connected": True,
            "address": ["192.168.1.1/24"],
        },
    }
    interfaces = parse_topology_interfaces(payload)
    assert classify_topology(interfaces) == TopologyClassification.AMBIGUOUS


def test_keyed_v2_artifact_emits_uncertainty_names_only() -> None:
    payload, raw = _load("topology_observed_keyed_wan_isolated.json")
    artifact = build_topology_artifact(**_artifact_kwargs(payload, raw))
    for item in artifact["findings"]["sanitized_interfaces"]:
        assert item["uncertainty"] == []


def test_v1_compat_unchanged_parser_version() -> None:
    payload, raw = _load("topology_interface_wan_isolated.json")
    artifact = build_topology_artifact(**_artifact_kwargs(payload, raw))
    assert artifact["parser_version"] == PARSER_VERSION
    interfaces = parse_topology_interfaces(payload)
    assert all(not iface.keyed_parse for iface in interfaces)


def _keyed_wan_lan_payload(*, wan: dict[str, object], lan: dict[str, object]) -> dict[str, object]:
    return {
        "upstream-wan-001": {
            "type": "ISP",
            "role": "wan",
            "address": ["10.0.0.5/24"],
            **wan,
        },
        "home-bridge-002": {
            "type": "Bridge",
            "role": "lan",
            "address": ["192.168.1.1/24"],
            **lan,
        },
    }


def test_keyed_v2_deceptive_connected_true_link_down_not_proven() -> None:
    """Live-found trap: connected true while link down must not prove WAN uplink."""
    payload = _keyed_wan_lan_payload(
        wan={"link": "down", "connected": True},
        lan={"link": "up", "connected": True},
    )
    interfaces = parse_topology_interfaces(payload)
    wan = next(
        i for i in interfaces if i.interface_id_hash == hash_interface_id("upstream-wan-001")
    )
    assert wan.link_up is False
    assert wan.connected is True
    assert classify_topology(interfaces) == TopologyClassification.AMBIGUOUS


def test_keyed_v2_connected_only_without_link_not_proven() -> None:
    payload = _keyed_wan_lan_payload(
        wan={"connected": True},
        lan={"link": "up", "connected": True},
    )
    interfaces = parse_topology_interfaces(payload)
    wan = next(
        i for i in interfaces if i.interface_id_hash == hash_interface_id("upstream-wan-001")
    )
    assert wan.link_up is None
    assert wan.connected is True
    assert classify_topology(interfaces) == TopologyClassification.AMBIGUOUS


def test_keyed_v2_link_up_connected_false_still_proves_on_link() -> None:
    payload = _keyed_wan_lan_payload(
        wan={"link": "up", "connected": False},
        lan={"link": "up", "connected": False},
    )
    interfaces = parse_topology_interfaces(payload)
    wan = next(
        i for i in interfaces if i.interface_id_hash == hash_interface_id("upstream-wan-001")
    )
    assert wan.link_up is True
    assert wan.connected is False
    assert classify_topology(interfaces) == TopologyClassification.PROVEN_WAN_ISOLATED


def test_keyed_v2_mixed_case_role_and_traits_classify_same_as_canonical() -> None:
    payload = {
        "iface-a": {
            "type": "ISP",
            "role": "WAN",
            "security-level": "public",
            "traits": ["internet"],
            "connected": True,
            "link": "up",
            "address": ["10.0.0.5/24"],
        },
        "iface-b": {
            "type": "Bridge",
            "role": "LAN",
            "security-level": "private",
            "traits": ["bridge", "home"],
            "connected": True,
            "link": "up",
            "address": ["192.168.2.1/24"],
        },
    }
    interfaces = parse_topology_interfaces(payload)
    roles = {iface.interface_id_hash: iface.role for iface in interfaces}
    assert roles[hash_interface_id("iface-a")] == "wan"
    assert roles[hash_interface_id("iface-b")] == "lan"
    assert classify_topology(interfaces) == TopologyClassification.PROVEN_WAN_ISOLATED


def test_v1_mixed_case_explicit_role_classifies() -> None:
    payload = {
        "interface": [
            {
                "id": "ISP",
                "type": "ISP",
                "role": "WAN",
                "link": "up",
                "connected": True,
                "address": ["10.0.0.5/24"],
                "bridge": None,
                "segment": None,
                "uplink": None,
            },
            {
                "id": "Home",
                "type": "Bridge",
                "role": "LAN",
                "link": "up",
                "connected": True,
                "address": ["192.168.1.1/24"],
                "bridge": "Bridge0",
                "segment": "Home",
                "uplink": None,
            },
        ]
    }
    interfaces = parse_topology_interfaces(payload)
    assert classify_topology(interfaces) == TopologyClassification.PROVEN_WAN_ISOLATED


def test_keyed_v2_no_link_connected_signals_not_proven() -> None:
    payload = _keyed_wan_lan_payload(
        wan={"state": "up"},
        lan={"state": "up"},
    )
    interfaces = parse_topology_interfaces(payload)
    wan = next(
        i for i in interfaces if i.interface_id_hash == hash_interface_id("upstream-wan-001")
    )
    assert wan.link_up is None
    assert wan.connected is None
    assert classify_topology(interfaces) == TopologyClassification.AMBIGUOUS
