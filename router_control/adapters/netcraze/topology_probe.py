"""Non-certifying topology observation from GET /rci/show/interface (discovery read)."""

from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, TypeGuard

from router_control.adapters.netcraze.allowlist import SHOW_INTERFACE
from router_control.adapters.netcraze.sanitize import (
    classify_private_prefix,
    describe_structure,
    hash_interface_id,
    sanitize_mapping,
)
from router_control.application.wifi_observation_helpers import (
    parse_up_down_flag,
    resolve_device_connected,
    resolve_link_up,
)

PARSER_VERSION = "topology-interface-v1"
# v2.3: link_up from link only; connected independent; proven WAN requires link_up=True.
PARSER_VERSION_V2 = "topology-interface-v2.3"
PARSER_VERSION_V2_LEGACY = "topology-interface-v2.2"
SUPPORTED_KEYED_PARSER_VERSIONS = frozenset({PARSER_VERSION_V2, PARSER_VERSION_V2_LEGACY})
OPERATION_NAME = "show_interface_discovery"

MAX_KEYED_CANDIDATES = 64

_EXPLICIT_WAN_ROLES = frozenset({"wan"})
_EXPLICIT_LAN_ROLES = frozenset({"lan"})

_WAN_TRAITS = frozenset({"internet", "wan"})
_LAN_TRAITS = frozenset({"bridge", "lan", "home", "guest"})

_DROP_INTERFACE_KEYS = frozenset(
    {
        "mac",
        "macaddr",
        "mac_address",
        "ssid",
        "description",
        "dns",
        "hostname",
        "password",
        "secret",
        "token",
    }
)


class TopologyClassification(StrEnum):
    PROVEN_WAN_ISOLATED = "proven_wan_isolated"
    LAN_TO_LAN_OR_OVERLAP = "lan_to_lan_or_overlap"
    AMBIGUOUS = "ambiguous"


class TopologyProbeError(Exception):
    """Safe topology probe failure — never embeds raw payload fragments."""


@dataclass(frozen=True, slots=True)
class SanitizedInterface:
    interface_id_hash: str
    role: str
    interface_type: str
    link_up: bool | None
    connected: bool | None
    private_prefixes: tuple[str, ...]
    bridge: str | None
    segment: str | None
    uplink_hash: str | None
    bridge_hash: str | None = None
    segment_hash: str | None = None
    keyed_parse: bool = False
    uncertainty: tuple[str, ...] = ()


def _sha256_payload(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _link_signal_value_recognized(key: str, value: object) -> bool:
    if key == "link":
        return parse_up_down_flag(value) is not None
    if key == "connected":
        return resolve_device_connected({"connected": value}) is not None
    if key == "state":
        return parse_up_down_flag(value) is not None
    return False


def _entry_has_link_signal_keys(entry: dict[str, object]) -> bool:
    return any(key in entry for key in _LINK_CONNECTED_STATE_KEYS)


def _resolve_connected(entry: dict[str, object]) -> bool | None:
    """Opaque device connected flag — never cross-filled from link/state."""
    return resolve_device_connected(entry)


def _resolve_link_connected(entry: dict[str, object]) -> tuple[bool | None, bool | None] | None:
    if not _entry_has_link_signal_keys(entry):
        return None
    return resolve_link_up(entry), _resolve_connected(entry)


def _keyed_link_signals(
    entry: dict[str, object],
) -> tuple[tuple[bool | None, bool | None] | None, tuple[str, ...]]:
    uncertainty: list[str] = []
    for key in _LINK_CONNECTED_STATE_KEYS:
        if key not in entry:
            continue
        if not _link_signal_value_recognized(key, entry[key]):
            uncertainty.append(key)
    resolved = _resolve_link_connected(entry)
    if resolved is None:
        return None, tuple(sorted(set(uncertainty)))
    return resolved, tuple(sorted(set(uncertainty)))


_LINK_CONNECTED_STATE_KEYS = ("link", "connected", "state")


def _normalize_role(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    if normalized in _EXPLICIT_WAN_ROLES:
        return "wan"
    if normalized in _EXPLICIT_LAN_ROLES:
        return "lan"
    return None


def _trait_tokens(raw: object) -> frozenset[str]:
    if not isinstance(raw, list):
        return frozenset()
    known_traits = _WAN_TRAITS | _LAN_TRAITS
    return frozenset(
        item.strip().lower()
        for item in raw
        if isinstance(item, str) and item.strip().lower() in known_traits
    )


def _resolve_role_v2(entry: dict[str, object]) -> str:
    explicit = _normalize_role(entry.get("role"))
    if explicit is not None:
        return explicit

    traits = _trait_tokens(entry.get("traits"))
    wan_traits = traits & _WAN_TRAITS
    lan_traits = traits & _LAN_TRAITS

    security = entry.get("security-level")
    if isinstance(security, str):
        normalized = security.strip().lower()
        if normalized == "public" and wan_traits and not lan_traits:
            return "wan"
        if normalized == "private" and lan_traits and not wan_traits:
            return "lan"

    if wan_traits and not lan_traits:
        return "wan"
    if lan_traits and not wan_traits:
        return "lan"
    return ""


def _mask_to_prefixlen(mask: str) -> int | None:
    candidate = mask.strip()
    if not candidate:
        return None
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{candidate}", strict=False).prefixlen
    except ValueError:
        return None


def _compose_cidr(ip: str, entry: dict[str, object]) -> str | None:
    candidate = ip.strip()
    if not candidate:
        return None
    if "/" in candidate:
        return candidate
    prefix_len = entry.get("prefix-length")
    if prefix_len is None:
        prefix_len = entry.get("prefix")
    if isinstance(prefix_len, bool):
        return None
    if isinstance(prefix_len, int):
        return f"{candidate}/{prefix_len}"
    if isinstance(prefix_len, str):
        stripped = prefix_len.strip()
        if stripped.isdigit():
            return f"{candidate}/{int(stripped)}"
    mask = entry.get("mask")
    if isinstance(mask, str):
        resolved = _mask_to_prefixlen(mask)
        if resolved is not None:
            return f"{candidate}/{resolved}"
    return None


def _append_private_prefix(prefixes: list[str], cidr: str) -> bool:
    candidate = cidr.strip()
    if not candidate or "/" not in candidate:
        return True
    classified = classify_private_prefix(candidate)
    if classified is None:
        return True
    if classified not in prefixes:
        prefixes.append(classified)
    return True


def _parse_address_prefixes(raw: object) -> tuple[str, ...] | None:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        return None
    prefixes: list[str] = []
    for item in raw:
        if not isinstance(item, str):
            return None
        if not _append_private_prefix(prefixes, item):
            return None
    return tuple(prefixes)


def _collect_private_prefixes(entry: dict[str, object]) -> tuple[str, ...] | None:
    prefixes: list[str] = []

    if "address" in entry:
        address_raw = entry["address"]
        if address_raw is not None and not isinstance(address_raw, (list, str)):
            return None
    else:
        address_raw = None

    if "mask" in entry and not isinstance(entry["mask"], str):
        return None

    if isinstance(address_raw, list):
        parsed = _parse_address_prefixes(address_raw)
        if parsed is None:
            return None
        for prefix in parsed:
            if prefix not in prefixes:
                prefixes.append(prefix)
    elif isinstance(address_raw, str):
        composed = _compose_cidr(address_raw.strip(), entry)
        if composed is not None and not _append_private_prefix(prefixes, composed):
            return None

    for list_field in ("addresses",):
        list_raw = entry.get(list_field)
        if list_raw is None:
            continue
        if not isinstance(list_raw, list):
            return None
        for item in list_raw:
            if not isinstance(item, str):
                return None
            if not _append_private_prefix(prefixes, item):
                return None

    for ip_field in ("ip", "network"):
        ip_raw = entry.get(ip_field)
        if ip_raw is None:
            continue
        if not isinstance(ip_raw, str) or not ip_raw.strip():
            return None
        composed = _compose_cidr(ip_raw.strip(), entry)
        if composed is not None and not _append_private_prefix(prefixes, composed):
            return None

    return tuple(prefixes)


def _optional_relation_hash(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return None
        return hash_interface_id(stripped)
    return None


def _entry_has_drop_keys(entry: dict[str, object]) -> bool:
    return any(key.lower() in _DROP_INTERFACE_KEYS for key in entry)


def _strip_drop_keys(entry: dict[str, object]) -> dict[str, object]:
    return {
        key: value
        for key, value in entry.items()
        if key.lower() not in _DROP_INTERFACE_KEYS
    }


def _is_keyed_candidate(entry: object) -> TypeGuard[dict[str, object]]:
    if not isinstance(entry, dict):
        return False
    raw_type = entry.get("type")
    if not isinstance(raw_type, str) or not raw_type.strip():
        return False
    resolved, _ = _keyed_link_signals(entry)
    return resolved is not None


def _malformed_optional_address_keys(entry: dict[str, object]) -> tuple[str, ...]:
    uncertainty: list[str] = []

    if "prefix-length" in entry:
        prefix_len = entry["prefix-length"]
        if prefix_len is not None:
            if isinstance(prefix_len, bool):
                uncertainty.append("prefix-length")
            elif isinstance(prefix_len, int):
                pass
            elif isinstance(prefix_len, str):
                if not prefix_len.strip().isdigit():
                    uncertainty.append("prefix-length")
            else:
                uncertainty.append("prefix-length")

    if "prefix" in entry:
        prefix = entry["prefix"]
        if prefix is not None:
            if isinstance(prefix, bool):
                uncertainty.append("prefix")
            elif isinstance(prefix, int):
                pass
            elif isinstance(prefix, str):
                if not prefix.strip().isdigit():
                    uncertainty.append("prefix")
            else:
                uncertainty.append("prefix")

    if "mask" in entry:
        mask_raw = entry["mask"]
        if mask_raw is not None:
            if not isinstance(mask_raw, str):
                uncertainty.append("mask")
            elif _mask_to_prefixlen(mask_raw) is None:
                uncertainty.append("mask")

    return tuple(sorted(set(uncertainty)))


def _compose_cidr_keyed(ip: str, entry: dict[str, object]) -> tuple[str | None, tuple[str, ...]]:
    uncertainty: list[str] = []
    candidate = ip.strip()
    if not candidate:
        return None, ()
    if "/" in candidate:
        uncertainty.extend(_malformed_optional_address_keys(entry))
        return candidate, tuple(sorted(set(uncertainty)))

    resolved_len: int | None = None
    if "prefix-length" in entry:
        prefix_len = entry["prefix-length"]
        if prefix_len is None:
            pass
        elif isinstance(prefix_len, bool):
            uncertainty.append("prefix-length")
        elif isinstance(prefix_len, int):
            resolved_len = prefix_len
        elif isinstance(prefix_len, str):
            stripped = prefix_len.strip()
            if stripped.isdigit():
                resolved_len = int(stripped)
            else:
                uncertainty.append("prefix-length")
        else:
            uncertainty.append("prefix-length")

    if resolved_len is None and "prefix" in entry:
        prefix = entry["prefix"]
        if prefix is None:
            pass
        elif isinstance(prefix, bool):
            uncertainty.append("prefix")
        elif isinstance(prefix, int):
            resolved_len = prefix
        elif isinstance(prefix, str):
            stripped = prefix.strip()
            if stripped.isdigit():
                resolved_len = int(stripped)
            else:
                uncertainty.append("prefix")
        else:
            uncertainty.append("prefix")

    if resolved_len is not None:
        return f"{candidate}/{resolved_len}", tuple(sorted(set(uncertainty)))

    mask = entry.get("mask")
    if isinstance(mask, str):
        resolved = _mask_to_prefixlen(mask)
        if resolved is not None:
            return f"{candidate}/{resolved}", tuple(sorted(set(uncertainty)))
        if entry.get("mask") is not None:
            uncertainty.append("mask")

    return None, tuple(sorted(set(uncertainty)))


def _collect_private_prefixes_keyed(
    entry: dict[str, object],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    prefixes: list[str] = []
    uncertainty: list[str] = []

    if "address" in entry:
        address_raw = entry["address"]
        if address_raw is None:
            pass
        elif isinstance(address_raw, list):
            bad = False
            for item in address_raw:
                if not isinstance(item, str):
                    bad = True
                    continue
                if not _append_private_prefix(prefixes, item):
                    bad = True
            if bad:
                uncertainty.append("address")
        elif isinstance(address_raw, str):
            composed, addr_uncertainty = _compose_cidr_keyed(address_raw.strip(), entry)
            uncertainty.extend(addr_uncertainty)
            if composed is not None and not _append_private_prefix(prefixes, composed):
                uncertainty.append("address")
        else:
            uncertainty.append("address")

    uncertainty.extend(_malformed_optional_address_keys(entry))

    for list_field in ("addresses",):
        list_raw = entry.get(list_field)
        if list_raw is None:
            continue
        if not isinstance(list_raw, list):
            uncertainty.append(list_field)
            continue
        bad = False
        for item in list_raw:
            if not isinstance(item, str):
                bad = True
                continue
            if not _append_private_prefix(prefixes, item):
                bad = True
        if bad:
            uncertainty.append(list_field)

    for ip_field in ("ip", "network"):
        ip_raw = entry.get(ip_field)
        if ip_raw is None:
            continue
        if not isinstance(ip_raw, str) or not ip_raw.strip():
            uncertainty.append(ip_field)
            continue
        composed, addr_uncertainty = _compose_cidr_keyed(ip_raw.strip(), entry)
        uncertainty.extend(addr_uncertainty)
        if composed is not None and not _append_private_prefix(prefixes, composed):
            uncertainty.append(ip_field)

    return tuple(prefixes), tuple(sorted(set(uncertainty)))


def _parse_interface_entry(entry: object) -> SanitizedInterface | None:
    if not isinstance(entry, dict):
        return None
    if _entry_has_drop_keys(entry):
        return None
    raw_id = entry.get("id")
    raw_type = entry.get("type")
    raw_role = entry.get("role")
    if not isinstance(raw_id, str) or not raw_id.strip():
        return None
    if not isinstance(raw_type, str) or not raw_type.strip():
        return None
    role = _normalize_role(raw_role) or ""
    resolved = _resolve_link_connected(entry)
    if resolved is None:
        return None
    link_up, connected = resolved
    prefixes = _parse_address_prefixes(entry.get("address"))
    if prefixes is None:
        return None
    bridge = entry.get("bridge")
    segment = entry.get("segment")
    uplink = entry.get("uplink")
    if bridge is not None and not isinstance(bridge, (str, type(None))):
        return None
    if segment is not None and not isinstance(segment, (str, type(None))):
        return None
    if uplink is not None and not isinstance(uplink, (str, type(None))):
        return None
    bridge_value = bridge.strip() if isinstance(bridge, str) and bridge.strip() else None
    segment_value = segment.strip() if isinstance(segment, str) and segment.strip() else None
    return SanitizedInterface(
        interface_id_hash=hash_interface_id(raw_id),
        role=role,
        interface_type=raw_type.strip(),
        link_up=link_up,
        connected=connected,
        private_prefixes=prefixes,
        bridge=bridge_value,
        segment=segment_value,
        uplink_hash=_optional_relation_hash(uplink),
        keyed_parse=False,
    )


def _parse_keyed_candidate(entry: object, *, interface_id_hash: str) -> SanitizedInterface | None:
    if not isinstance(entry, dict):
        return None
    raw_type = entry.get("type")
    if not isinstance(raw_type, str) or not raw_type.strip():
        return None
    uncertainty: list[str] = []
    resolved, link_uncertainty = _keyed_link_signals(entry)
    if resolved is None:
        return None
    uncertainty.extend(link_uncertainty)
    link_up, connected = resolved

    role_entry = dict(entry)
    raw_role = entry.get("role")
    if raw_role is not None and not isinstance(raw_role, str):
        uncertainty.append("role")
        role_entry.pop("role", None)
    raw_traits = entry.get("traits")
    if raw_traits is not None and not isinstance(raw_traits, list):
        uncertainty.append("traits")
        role_entry.pop("traits", None)
    security = entry.get("security-level")
    if security is not None and not isinstance(security, str):
        uncertainty.append("security-level")
        role_entry.pop("security-level", None)

    prefixes, prefix_uncertainty = _collect_private_prefixes_keyed(entry)
    uncertainty.extend(prefix_uncertainty)

    bridge_hash: str | None = None
    segment_hash: str | None = None
    uplink_hash: str | None = None
    bridge = entry.get("bridge")
    if bridge is not None:
        if isinstance(bridge, str):
            bridge_hash = _optional_relation_hash(bridge)
        else:
            uncertainty.append("bridge")
    segment = entry.get("segment")
    if segment is not None:
        if isinstance(segment, str):
            segment_hash = _optional_relation_hash(segment)
        else:
            uncertainty.append("segment")
    uplink = entry.get("uplink")
    if uplink is not None:
        if isinstance(uplink, str):
            uplink_hash = _optional_relation_hash(uplink)
        else:
            uncertainty.append("uplink")

    return SanitizedInterface(
        interface_id_hash=interface_id_hash,
        role=_resolve_role_v2(role_entry),
        interface_type=raw_type.strip(),
        link_up=link_up,
        connected=connected,
        private_prefixes=prefixes,
        bridge=None,
        segment=None,
        uplink_hash=uplink_hash,
        bridge_hash=bridge_hash,
        segment_hash=segment_hash,
        keyed_parse=True,
        uncertainty=tuple(sorted(set(uncertainty))),
    )


def _parse_v1_interface_list(interfaces_raw: list[object]) -> tuple[SanitizedInterface, ...]:
    if not interfaces_raw:
        raise TopologyProbeError("topology interface list empty")
    parsed: list[SanitizedInterface] = []
    for entry in interfaces_raw:
        item = _parse_interface_entry(entry)
        if item is None:
            raise TopologyProbeError("topology interface entry shape invalid")
        parsed.append(item)
    return tuple(parsed)


def _resolve_keyed_root(payload: dict[str, object]) -> dict[str, object]:
    interfaces_raw = payload.get("interface")
    if isinstance(interfaces_raw, dict):
        return interfaces_raw
    return payload


def _parse_keyed_topology(keyed_root: dict[str, object]) -> tuple[SanitizedInterface, ...]:
    candidates: list[tuple[str, dict[str, object]]] = []
    for raw_key, value in keyed_root.items():
        if not isinstance(raw_key, str):
            continue
        if _is_keyed_candidate(value):
            candidates.append((raw_key, value))

    if not candidates:
        raise TopologyProbeError("topology keyed candidates empty")
    if len(candidates) > MAX_KEYED_CANDIDATES:
        raise TopologyProbeError("topology keyed candidates oversize")

    seen_hashes: set[str] = set()
    parsed: list[SanitizedInterface] = []
    for raw_key, entry in candidates:
        interface_id_hash = hash_interface_id(raw_key)
        if interface_id_hash in seen_hashes:
            raise TopologyProbeError("topology duplicate interface id")
        seen_hashes.add(interface_id_hash)
        stripped = _strip_drop_keys(entry)
        item = _parse_keyed_candidate(stripped, interface_id_hash=interface_id_hash)
        if item is None:
            raise TopologyProbeError("topology keyed candidate shape invalid")
        parsed.append(item)
    return tuple(parsed)


def _detect_parser_version(payload: dict[str, object]) -> str:
    interfaces_raw = payload.get("interface")
    if isinstance(interfaces_raw, list):
        return PARSER_VERSION
    return PARSER_VERSION_V2


def parse_topology_interfaces(payload: object) -> tuple[SanitizedInterface, ...]:
    """Deny-by-default parse of observed interface list or keyed-bundle shapes."""
    if not isinstance(payload, dict):
        raise TopologyProbeError("topology payload shape invalid")
    interfaces_raw = payload.get("interface")
    if isinstance(interfaces_raw, list):
        return _parse_v1_interface_list(interfaces_raw)
    return _parse_keyed_topology(_resolve_keyed_root(payload))


def _prefix_sets_overlap(wan_prefixes: set[str], lan_prefixes: set[str]) -> bool | None:
    """Return True if overlap, False if distinct, None if any prefix is invalid."""
    wan_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    lan_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for prefix in wan_prefixes:
        try:
            wan_networks.append(ipaddress.ip_network(prefix, strict=False))
        except ValueError:
            return None
    for prefix in lan_prefixes:
        try:
            lan_networks.append(ipaddress.ip_network(prefix, strict=False))
        except ValueError:
            return None
    for wan_net in wan_networks:
        for lan_net in lan_networks:
            if wan_net.overlaps(lan_net):
                return True
    return False


def _bridge_relation(iface: SanitizedInterface) -> str | None:
    if iface.keyed_parse:
        return iface.bridge_hash
    return iface.bridge


def _segment_relation(iface: SanitizedInterface) -> str | None:
    if iface.keyed_parse:
        return iface.segment_hash
    return iface.segment


def classify_topology(interfaces: tuple[SanitizedInterface, ...]) -> TopologyClassification:
    """Classify WAN/LAN isolation with positive structural proof requirement."""
    if any(iface.role not in _EXPLICIT_WAN_ROLES | _EXPLICIT_LAN_ROLES for iface in interfaces):
        return TopologyClassification.AMBIGUOUS

    wan_ifaces = [iface for iface in interfaces if iface.role == "wan"]
    lan_ifaces = [iface for iface in interfaces if iface.role == "lan"]
    if not wan_ifaces or not lan_ifaces:
        return TopologyClassification.AMBIGUOUS

    keyed_parse = bool(interfaces) and interfaces[0].keyed_parse
    if keyed_parse and not any(wan.link_up is True for wan in wan_ifaces):
        return TopologyClassification.AMBIGUOUS

    wan_prefixes: set[str] = set()
    lan_prefixes: set[str] = set()
    for iface in wan_ifaces:
        if not iface.private_prefixes:
            return TopologyClassification.AMBIGUOUS
        wan_prefixes.update(iface.private_prefixes)
    for iface in lan_ifaces:
        if not iface.private_prefixes:
            return TopologyClassification.AMBIGUOUS
        lan_prefixes.update(iface.private_prefixes)

    prefix_overlap = _prefix_sets_overlap(wan_prefixes, lan_prefixes)
    if prefix_overlap is None:
        return TopologyClassification.AMBIGUOUS
    if prefix_overlap:
        return TopologyClassification.LAN_TO_LAN_OR_OVERLAP

    wan_bridges = {_bridge_relation(iface) for iface in wan_ifaces if _bridge_relation(iface)}
    lan_bridges = {_bridge_relation(iface) for iface in lan_ifaces if _bridge_relation(iface)}
    if wan_bridges & lan_bridges:
        return TopologyClassification.LAN_TO_LAN_OR_OVERLAP

    wan_segments = {_segment_relation(iface) for iface in wan_ifaces if _segment_relation(iface)}
    lan_segments = {_segment_relation(iface) for iface in lan_ifaces if _segment_relation(iface)}
    if wan_segments & lan_segments:
        return TopologyClassification.LAN_TO_LAN_OR_OVERLAP

    wan_uplinks = {iface.uplink_hash for iface in wan_ifaces if iface.uplink_hash}
    lan_uplinks = {iface.uplink_hash for iface in lan_ifaces if iface.uplink_hash}
    lan_id_hashes = {iface.interface_id_hash for iface in lan_ifaces}
    wan_id_hashes = {iface.interface_id_hash for iface in wan_ifaces}
    if wan_uplinks & lan_uplinks:
        return TopologyClassification.LAN_TO_LAN_OR_OVERLAP
    if wan_uplinks & lan_id_hashes:
        return TopologyClassification.LAN_TO_LAN_OR_OVERLAP
    if lan_uplinks & wan_id_hashes:
        return TopologyClassification.LAN_TO_LAN_OR_OVERLAP

    if any(iface.uncertainty for iface in interfaces):
        return TopologyClassification.AMBIGUOUS

    all_id_hashes = {iface.interface_id_hash for iface in interfaces}
    for wan in wan_ifaces:
        if wan.uplink_hash is not None and wan.uplink_hash not in all_id_hashes:
            return TopologyClassification.AMBIGUOUS
    for lan in lan_ifaces:
        if lan.uplink_hash is not None and lan.uplink_hash not in all_id_hashes:
            return TopologyClassification.AMBIGUOUS

    if not keyed_parse:
        for wan in wan_ifaces:
            if wan.bridge is not None or wan.segment is not None:
                return TopologyClassification.AMBIGUOUS

        for lan in lan_ifaces:
            if lan.bridge is None and lan.segment is None:
                return TopologyClassification.AMBIGUOUS

    return TopologyClassification.PROVEN_WAN_ISOLATED


_PARSER_ERROR_CLASSES: dict[str, str] = {
    "topology payload shape invalid": "payload_shape_invalid",
    "topology payload missing interface list": "missing_interface",
    "topology interface list shape invalid": "interface_list_shape_invalid",
    "topology interface list empty": "interface_list_empty",
    "topology interface entry shape invalid": "interface_entry_shape_invalid",
    "topology keyed candidates empty": "keyed_candidates_empty",
    "topology duplicate interface id": "keyed_duplicate_interface_id",
    "topology keyed candidates oversize": "keyed_candidates_oversize",
    "topology keyed candidate shape invalid": "keyed_candidate_shape_invalid",
}


def classify_parser_error(error: TopologyProbeError) -> str:
    """Map safe topology parser errors to stable diagnostic classes."""
    return _PARSER_ERROR_CLASSES.get(str(error), "topology_parse_failed")


def _safe_describe_structure(payload: object) -> dict[str, Any]:
    if isinstance(payload, dict):
        return describe_structure(payload)
    if isinstance(payload, list):
        top_type = "array"
    elif isinstance(payload, str):
        top_type = "string"
    elif isinstance(payload, bool):
        top_type = "boolean"
    elif isinstance(payload, (int, float)) and not isinstance(payload, bool):
        top_type = "number"
    elif payload is None:
        top_type = "null"
    else:
        top_type = "unknown"
    return {
        "top_type": top_type,
        "top_count": 0,
        "value_type_histogram": {top_type: 1},
        "dynamic_top_key_hashes": [],
        "secret_field_categories": [],
        "field_samples": [],
        "truncated": False,
    }


def digest_structure_fingerprint(*, structure: dict[str, Any], parser_error_class: str) -> str:
    canonical = json.dumps(
        {"parser_error_class": parser_error_class, "structure": structure},
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


def build_topology_shape_artifact(
    *,
    payload: object,
    raw_bytes: bytes,
    parser_error: TopologyProbeError,
    source_address: str,
    source_address_class: str,
    gate_a_tuple_digest: str,
    gate_a_evidence_digest: str,
    transport_security: str,
    https_check: str,
    ssh_host_key_algorithm: str,
    ssh_host_key_fingerprint_sha256: str,
) -> dict[str, Any]:
    """Build non-certifying structural fingerprint when topology parse fails."""
    parser_error_class = classify_parser_error(parser_error)
    structure = _safe_describe_structure(payload)
    structure_digest = digest_structure_fingerprint(
        structure=structure,
        parser_error_class=parser_error_class,
    )
    parser_version = PARSER_VERSION
    if isinstance(payload, dict):
        parser_version = _detect_parser_version(payload)
    artifact: dict[str, Any] = {
        "certification_eligible": False,
        "operation": OPERATION_NAME,
        "operation_method": SHOW_INTERFACE.method,
        "operation_path": SHOW_INTERFACE.path,
        "parser_version": parser_version,
        "source_address": source_address,
        "source_address_class": source_address_class,
        "transport_security": transport_security,
        "https_check": https_check,
        "ssh_host_key_algorithm": ssh_host_key_algorithm,
        "ssh_host_key_fingerprint_sha256": ssh_host_key_fingerprint_sha256,
        "gate_a_tuple_digest": gate_a_tuple_digest,
        "gate_a_evidence_digest": gate_a_evidence_digest,
        "raw_payload_sha256": _sha256_payload(raw_bytes),
        "parser_error_class": parser_error_class,
        "structure_canonical_digest": structure_digest,
        "structure": structure,
    }
    sanitized = sanitize_mapping(
        {key: value for key, value in artifact.items() if key != "structure"}
    )
    sanitized["structure"] = structure
    return sanitized


def _sanitized_interface_mapping(iface: SanitizedInterface) -> dict[str, object]:
    payload: dict[str, object] = {
        "interface_id_hash": iface.interface_id_hash,
        "role": iface.role,
        "interface_type": iface.interface_type,
        "link_up": iface.link_up,
        "connected": iface.connected,
        "private_prefixes": list(iface.private_prefixes),
        "uplink_hash": iface.uplink_hash,
    }
    if iface.keyed_parse:
        payload["bridge_hash"] = iface.bridge_hash
        payload["segment_hash"] = iface.segment_hash
        payload["uncertainty"] = list(iface.uncertainty)
    else:
        payload["bridge"] = iface.bridge
        payload["segment"] = iface.segment
    return sanitize_mapping(payload)


def build_topology_artifact(
    *,
    payload: object,
    raw_bytes: bytes,
    source_address: str,
    source_address_class: str,
    gate_a_tuple_digest: str,
    gate_a_evidence_digest: str,
    transport_security: str,
    https_check: str,
    ssh_host_key_algorithm: str,
    ssh_host_key_fingerprint_sha256: str,
) -> dict[str, Any]:
    """Build sanitized non-certifying topology artifact."""
    if not isinstance(payload, dict):
        raise TopologyProbeError("topology payload shape invalid")
    parser_version = _detect_parser_version(payload)
    interfaces = parse_topology_interfaces(payload)
    classification = classify_topology(interfaces)
    wan_prefixes = sorted(
        {prefix for iface in interfaces if iface.role == "wan" for prefix in iface.private_prefixes}
    )
    lan_prefixes = sorted(
        {prefix for iface in interfaces if iface.role == "lan" for prefix in iface.private_prefixes}
    )
    sanitized_interfaces = [_sanitized_interface_mapping(iface) for iface in interfaces]
    artifact: dict[str, Any] = {
        "certification_eligible": False,
        "operation": OPERATION_NAME,
        "operation_method": SHOW_INTERFACE.method,
        "operation_path": SHOW_INTERFACE.path,
        "parser_version": parser_version,
        "source_address": source_address,
        "source_address_class": source_address_class,
        "transport_security": transport_security,
        "https_check": https_check,
        "ssh_host_key_algorithm": ssh_host_key_algorithm,
        "ssh_host_key_fingerprint_sha256": ssh_host_key_fingerprint_sha256,
        "gate_a_tuple_digest": gate_a_tuple_digest,
        "gate_a_evidence_digest": gate_a_evidence_digest,
        "raw_payload_sha256": _sha256_payload(raw_bytes),
        "findings": sanitize_mapping(
            {
                "classification": classification.value,
                "interfaces_observed": len(interfaces),
                "wan_private_prefixes": wan_prefixes,
                "lan_private_prefixes": lan_prefixes,
                "sanitized_interfaces": sanitized_interfaces,
            }
        ),
    }
    return sanitize_mapping(artifact)


def digest_gate_a_tuple(
    *,
    model: str,
    firmware_version: str,
    ndm_build: str,
    component_set_digest: str,
    device_fingerprint_digest: str,
) -> str:
    canonical = json.dumps(
        {
            "model": model,
            "firmware_version": firmware_version,
            "ndm_build": ndm_build,
            "component_set_digest": component_set_digest,
            "device_fingerprint_digest": device_fingerprint_digest,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


def digest_evidence_record(evidence: dict[str, object]) -> str:
    canonical = json.dumps(evidence, sort_keys=True, separators=(",", ":"), default=str)
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


__all__ = [
    "OPERATION_NAME",
    "PARSER_VERSION",
    "PARSER_VERSION_V2",
    "PARSER_VERSION_V2_LEGACY",
    "SUPPORTED_KEYED_PARSER_VERSIONS",
    "SHOW_INTERFACE",
    "TopologyClassification",
    "TopologyProbeError",
    "SanitizedInterface",
    "build_topology_artifact",
    "build_topology_shape_artifact",
    "classify_parser_error",
    "classify_topology",
    "digest_evidence_record",
    "digest_gate_a_tuple",
    "digest_structure_fingerprint",
    "parse_topology_interfaces",
]
