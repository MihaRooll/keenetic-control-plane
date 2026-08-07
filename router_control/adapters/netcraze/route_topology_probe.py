"""Non-certifying default-route observation from GET /rci/show/ip/route (discovery read)."""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from router_control.adapters.netcraze.allowlist import SHOW_IP_ROUTE
from router_control.adapters.netcraze.sanitize import (
    classify_private_prefix,
    describe_list_structure,
    describe_structure,
    hash_interface_id,
    sanitize_mapping,
)
from router_control.adapters.netcraze.topology_probe import (
    SUPPORTED_KEYED_PARSER_VERSIONS,
    digest_evidence_record,
    digest_gate_a_tuple,
    digest_structure_fingerprint,
)

# default-route-v1.3: Keenetic bare /rci/show/ip/route entries omit type/state (flags/proto
# only); infer unicast/active for explicit 0.0.0.0/0 when interface present.
PARSER_VERSION = "default-route-v1.3"
OPERATION_NAME = "show_ip_route_discovery"
OPERATION_PATH = "/rci/show/ip/route"

_DEFAULT_DESTINATION = "0.0.0.0/0"
_SAFE_ROUTE_TYPES = frozenset({"unicast"})
_SAFE_ROUTE_STATES = frozenset({"active"})
_DESTINATION_KEYS = ("destination", "dst", "network")
_INTERFACE_KEYS = ("interface", "iface", "ifname", "dev")
_GATEWAY_KEYS = ("gateway", "gw", "via", "nexthop")


class DefaultRouteClassification(StrEnum):
    ONE_DEFAULT_ROUTE = "one_default_route"
    MULTIPLE_DEFAULT_ROUTES = "multiple_default_routes"
    NO_DEFAULT_ROUTE = "no_default_route"
    AMBIGUOUS = "ambiguous"


class RouteTopologyProbeError(Exception):
    """Safe default-route probe failure — never embeds raw payload fragments."""


class TopologyCorrelationStatus(StrEnum):
    MATCH = "match"
    MISMATCH = "mismatch"
    AMBIGUOUS = "ambiguous"
    TUPLE_MISMATCH = "tuple_mismatch"


@dataclass(frozen=True, slots=True)
class SanitizedDefaultRoute:
    interface_id_hash: str
    gateway_private_class: str | None
    metric: int | None
    route_type: str
    route_state: str


@dataclass(frozen=True, slots=True)
class TopologyCorrelationResult:
    status: TopologyCorrelationStatus
    default_outbound_hashes: tuple[str, ...]
    connected_non_lan_hashes: tuple[str, ...]
    overlapping_hashes: tuple[str, ...]
    topology_classification: str
    notes: tuple[str, ...]


def _sha256_payload(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _first_string(entry: dict[str, object], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = entry.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _safe_bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1", "default"}:
            return True
        if lowered in {"false", "no", "0"}:
            return False
    return None


def _is_explicit_default(entry: dict[str, object]) -> bool:
    for key in ("default", "is_default", "default_route"):
        if key not in entry:
            continue
        parsed = _safe_bool(entry[key])
        if parsed is True:
            return True
        if parsed is False:
            return False
    destination = _first_string(entry, _DESTINATION_KEYS)
    if destination is not None and destination in {_DEFAULT_DESTINATION, "0.0.0.0"}:
        return True
    return False


def _normalize_destination(entry: dict[str, object]) -> str | None:
    destination = _first_string(entry, _DESTINATION_KEYS)
    if destination is None:
        return None
    if destination == "0.0.0.0":
        return _DEFAULT_DESTINATION
    return destination


def _safe_metric(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _safe_route_type(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    if normalized in _SAFE_ROUTE_TYPES:
        return normalized
    return None


def _safe_route_state(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    if normalized in _SAFE_ROUTE_STATES:
        return normalized
    return None


def _classify_gateway_private_network(gateway: str) -> str | None:
    candidate = gateway.strip()
    if not candidate or candidate in {"0.0.0.0", "::"}:
        return None
    if "/" in candidate:
        return classify_private_prefix(candidate)
    try:
        addr = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv4Address):
        for block in (
            ipaddress.IPv4Network("10.0.0.0/8"),
            ipaddress.IPv4Network("172.16.0.0/12"),
            ipaddress.IPv4Network("192.168.0.0/16"),
        ):
            if addr in block:
                return str(block)
        return None
    ula = ipaddress.IPv6Network("fc00::/7")
    if addr in ula:
        return str(ula)
    return None


def _validate_route_entry_list(entries: list[object]) -> None:
    for entry in entries:
        if not isinstance(entry, dict):
            raise RouteTopologyProbeError("route list shape invalid")


def _resolve_route_list(payload: object) -> list[object]:
    if isinstance(payload, dict):
        routes_raw = payload.get("route")
        if isinstance(routes_raw, list):
            _validate_route_entry_list(routes_raw)
            return routes_raw
        raise RouteTopologyProbeError("route payload missing route list")
    if isinstance(payload, list):
        if all(isinstance(entry, dict) for entry in payload):
            _validate_route_entry_list(payload)
            return payload
        if len(payload) == 1 and isinstance(payload[0], list):
            inner = payload[0]
            _validate_route_entry_list(inner)
            return inner
        raise RouteTopologyProbeError("route list shape invalid")
    raise RouteTopologyProbeError("route payload shape invalid")


def _parse_default_route_entry(entry: object) -> SanitizedDefaultRoute | None:
    if not isinstance(entry, dict):
        return None
    if not _is_explicit_default(entry):
        return None
    destination = _normalize_destination(entry)
    if destination is not None and destination not in {_DEFAULT_DESTINATION}:
        return None
    route_type = _safe_route_type(entry.get("type"))
    route_state = _safe_route_state(entry.get("state"))
    raw_iface = _first_string(entry, _INTERFACE_KEYS)
    if raw_iface is None:
        return None
    # Keenetic live GET /rci/show/ip/route often omits type/state on usable defaults.
    if route_type is None:
        route_type = "unicast"
    if route_state is None:
        route_state = "active"
    gateway_raw = _first_string(entry, _GATEWAY_KEYS)
    gateway_class = _classify_gateway_private_network(gateway_raw) if gateway_raw else None
    return SanitizedDefaultRoute(
        interface_id_hash=hash_interface_id(raw_iface),
        gateway_private_class=gateway_class,
        metric=_safe_metric(entry.get("metric")),
        route_type=route_type,
        route_state=route_state,
    )


def parse_default_routes(payload: object) -> tuple[SanitizedDefaultRoute, ...]:
    """Deny-by-default parse of synthetic default-route fixture shapes only."""
    if not isinstance(payload, (dict, list)):
        raise RouteTopologyProbeError("route payload shape invalid")
    routes_raw = _resolve_route_list(payload)
    if not routes_raw:
        return ()
    parsed: list[SanitizedDefaultRoute] = []
    for entry in routes_raw:
        item = _parse_default_route_entry(entry)
        if item is not None:
            parsed.append(item)
    return tuple(parsed)


def classify_default_routes(
    routes: tuple[SanitizedDefaultRoute, ...],
) -> DefaultRouteClassification:
    if not routes:
        return DefaultRouteClassification.NO_DEFAULT_ROUTE
    if len(routes) > 1:
        return DefaultRouteClassification.MULTIPLE_DEFAULT_ROUTES
    if routes[0].gateway_private_class is None:
        return DefaultRouteClassification.AMBIGUOUS
    return DefaultRouteClassification.ONE_DEFAULT_ROUTE


_PARSER_ERROR_CLASSES: dict[str, str] = {
    "route payload shape invalid": "payload_shape_invalid",
    "route payload missing route list": "missing_route_list",
    "route list shape invalid": "route_list_shape_invalid",
}


def classify_parser_error(error: RouteTopologyProbeError) -> str:
    """Map safe route parser errors to stable diagnostic classes."""
    return _PARSER_ERROR_CLASSES.get(str(error), "route_parse_failed")


def _safe_describe_structure(payload: object) -> dict[str, Any]:
    if isinstance(payload, dict):
        return describe_structure(payload)
    if isinstance(payload, list):
        return describe_list_structure(payload)
    if isinstance(payload, str):
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


def _sanitized_route_mapping(route: SanitizedDefaultRoute) -> dict[str, object]:
    payload: dict[str, object] = {
        "interface_id_hash": route.interface_id_hash,
        "route_type": route.route_type,
        "route_state": route.route_state,
    }
    if route.gateway_private_class is not None:
        payload["gateway_private_class"] = route.gateway_private_class
    if route.metric is not None:
        payload["metric"] = route.metric
    return sanitize_mapping(payload)


def build_default_route_artifact(
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
    """Build sanitized non-certifying default-route artifact."""
    if not isinstance(payload, (dict, list)):
        raise RouteTopologyProbeError("route payload shape invalid")
    _resolve_route_list(payload)
    routes = parse_default_routes(payload)
    classification = classify_default_routes(routes)
    sanitized_routes = [_sanitized_route_mapping(route) for route in routes]
    outbound_hashes = sorted({route.interface_id_hash for route in routes})
    gateway_classes = sorted(
        {route.gateway_private_class for route in routes if route.gateway_private_class}
    )
    artifact: dict[str, Any] = {
        "certification_eligible": False,
        "operation": OPERATION_NAME,
        "operation_method": SHOW_IP_ROUTE.method,
        "operation_path": SHOW_IP_ROUTE.path,
        "parser_version": PARSER_VERSION,
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
                "default_route_count": len(routes),
                "default_outbound_interface_hashes": outbound_hashes,
                "gateway_private_classes": gateway_classes,
                "sanitized_default_routes": sanitized_routes,
            }
        ),
    }
    return sanitize_mapping(artifact)


def build_default_route_shape_artifact(
    *,
    payload: object,
    raw_bytes: bytes,
    parser_error: RouteTopologyProbeError,
    source_address: str,
    source_address_class: str,
    gate_a_tuple_digest: str,
    gate_a_evidence_digest: str,
    transport_security: str,
    https_check: str,
    ssh_host_key_algorithm: str,
    ssh_host_key_fingerprint_sha256: str,
) -> dict[str, Any]:
    """Build non-certifying structural fingerprint when route parse fails."""
    parser_error_class = classify_parser_error(parser_error)
    structure = _safe_describe_structure(payload)
    structure_digest = digest_structure_fingerprint(
        structure=structure,
        parser_error_class=parser_error_class,
    )
    artifact: dict[str, Any] = {
        "certification_eligible": False,
        "operation": OPERATION_NAME,
        "operation_method": SHOW_IP_ROUTE.method,
        "operation_path": SHOW_IP_ROUTE.path,
        "parser_version": PARSER_VERSION,
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


def _interface_uplink_active(item: dict[str, object]) -> bool:
    """True only when link_up is an explicit bool True; fail-closed otherwise."""
    link_up = item.get("link_up")
    return link_up is True


def _connected_non_lan_interface_hashes(topology_artifact: dict[str, object]) -> tuple[str, ...]:
    findings = topology_artifact.get("findings")
    if not isinstance(findings, dict):
        return ()
    interfaces_raw = findings.get("sanitized_interfaces")
    if not isinstance(interfaces_raw, list):
        return ()
    hashes: list[str] = []
    for item in interfaces_raw:
        if not isinstance(item, dict):
            continue
        role = item.get("role")
        iface_hash = item.get("interface_id_hash")
        if not isinstance(role, str):
            continue
        if not _interface_uplink_active(item):
            continue
        if not isinstance(iface_hash, str) or not iface_hash.startswith("sha256:"):
            continue
        if role == "lan":
            continue
        hashes.append(iface_hash)
    return tuple(sorted(set(hashes)))


def correlate_with_topology_artifact(
    route_artifact: dict[str, object],
    topology_artifact: dict[str, object],
) -> TopologyCorrelationResult:
    """Correlate default outbound hashes with topology connected non-LAN interfaces."""
    notes: list[str] = []
    for key in ("gate_a_tuple_digest", "gate_a_evidence_digest", "source_address"):
        if route_artifact.get(key) != topology_artifact.get(key):
            return TopologyCorrelationResult(
                status=TopologyCorrelationStatus.TUPLE_MISMATCH,
                default_outbound_hashes=(),
                connected_non_lan_hashes=(),
                overlapping_hashes=(),
                topology_classification="",
                notes=(f"{key}_mismatch",),
            )

    topology_parser = topology_artifact.get("parser_version")
    if topology_parser not in SUPPORTED_KEYED_PARSER_VERSIONS:
        return TopologyCorrelationResult(
            status=TopologyCorrelationStatus.AMBIGUOUS,
            default_outbound_hashes=(),
            connected_non_lan_hashes=(),
            overlapping_hashes=(),
            topology_classification="",
            notes=("topology_parser_unsupported",),
        )

    topology_findings = topology_artifact.get("findings")
    topology_classification = ""
    if isinstance(topology_findings, dict):
        raw_class = topology_findings.get("classification")
        if isinstance(raw_class, str):
            topology_classification = raw_class

    route_findings = route_artifact.get("findings")
    default_hashes: tuple[str, ...] = ()
    route_classification = ""
    if isinstance(route_findings, dict):
        raw_hashes = route_findings.get("default_outbound_interface_hashes")
        if isinstance(raw_hashes, list):
            default_hashes = tuple(
                sorted(
                    h
                    for h in raw_hashes
                    if isinstance(h, str) and h.startswith("sha256:")
                )
            )
        raw_route_class = route_findings.get("classification")
        if isinstance(raw_route_class, str):
            route_classification = raw_route_class

    if route_classification in {
        DefaultRouteClassification.MULTIPLE_DEFAULT_ROUTES.value,
        DefaultRouteClassification.AMBIGUOUS.value,
        DefaultRouteClassification.NO_DEFAULT_ROUTE.value,
    }:
        notes.append("route_classification_blocks_uplink_claim")

    connected_non_lan = _connected_non_lan_interface_hashes(topology_artifact)
    overlapping = tuple(sorted(set(default_hashes) & set(connected_non_lan)))

    if route_classification != DefaultRouteClassification.ONE_DEFAULT_ROUTE.value:
        status = TopologyCorrelationStatus.AMBIGUOUS
    elif not default_hashes or not connected_non_lan:
        status = TopologyCorrelationStatus.AMBIGUOUS
        notes.append("insufficient_hashes_for_match")
    elif len(overlapping) == 1:
        status = TopologyCorrelationStatus.MATCH
    elif overlapping:
        status = TopologyCorrelationStatus.AMBIGUOUS
        notes.append("multiple_overlapping_hashes")
    else:
        status = TopologyCorrelationStatus.MISMATCH

    if topology_classification != "proven_wan_isolated":
        notes.append("topology_does_not_prove_wan_isolated")

    return TopologyCorrelationResult(
        status=status,
        default_outbound_hashes=default_hashes,
        connected_non_lan_hashes=connected_non_lan,
        overlapping_hashes=overlapping,
        topology_classification=topology_classification,
        notes=tuple(sorted(set(notes))),
    )


__all__ = [
    "DefaultRouteClassification",
    "OPERATION_NAME",
    "OPERATION_PATH",
    "PARSER_VERSION",
    "RouteTopologyProbeError",
    "SanitizedDefaultRoute",
    "TopologyCorrelationResult",
    "TopologyCorrelationStatus",
    "build_default_route_artifact",
    "build_default_route_shape_artifact",
    "classify_default_routes",
    "classify_parser_error",
    "correlate_with_topology_artifact",
    "digest_evidence_record",
    "digest_gate_a_tuple",
    "digest_structure_fingerprint",
    "parse_default_routes",
]
