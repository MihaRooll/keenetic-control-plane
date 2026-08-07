"""Bounded local router-candidate discovery — read-only, non-certifying."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from router_control.adapters.netcraze.certification import GateACertification
from router_control.adapters.netcraze.ssh_tunnel import (
    host_is_private,
    normalize_sha256_fingerprint,
    source_address_class,
    validate_source_address,
)
from router_control.adapters.netcraze.transport import is_loopback_management_host
from router_control.adapters.netcraze.tuple_evidence import tuple_evidence_fields_or_none
from router_control.persistence.store import PersistenceStore
from router_control.ports.vault import CredentialVaultPort

IdentityState = Literal["known_match", "known_mismatch", "unknown"]
CandidateOrigin = Literal["default_gateway", "known_endpoint", "local_subnet_gateway"]

# Wizard draft enrollment placeholders — must stay aligned with wizard_draft_routes.py.
ENROLLMENT_DRAFT_MODEL = "PendingDiscovery"
ENROLLMENT_DRAFT_IDENTITY_FINGERPRINT = "digest:wizard-draft:pending"
ENROLLMENT_DRAFT_LIFECYCLE = "PendingEnrollment"


class RouterDiscoveryError(Exception):
    """Policy failure during router discovery."""


@dataclass(frozen=True, slots=True)
class DefaultGatewayRoute:
    gateway_host: str
    source_address: str | None = None
    route_if_index: int | None = None
    route_label: str | None = None


@dataclass(frozen=True, slots=True)
class LocalHostIPv4Interface:
    address: str
    prefix_length: int
    if_index: int | None = None
    if_label: str | None = None


class HostRouteTablePort(Protocol):
    def list_ipv4_default_gateways(self) -> list[DefaultGatewayRoute]: ...

    def list_ipv4_host_interfaces(self) -> list[LocalHostIPv4Interface]: ...


class EmptyHostRouteTablePort:
    def list_ipv4_default_gateways(self) -> list[DefaultGatewayRoute]:
        return []

    def list_ipv4_host_interfaces(self) -> list[LocalHostIPv4Interface]:
        return []


@dataclass(frozen=True, slots=True)
class CandidateProbeTarget:
    host: str
    port: int
    source_address: str | None
    router_id: str | None
    credential_ref_id: str | None


class CandidateIdentityProbePort(Protocol):
    def probe(self, target: CandidateProbeTarget) -> dict[str, Any]: ...


class NotConfiguredCandidateProbe:
    def probe(self, target: CandidateProbeTarget) -> dict[str, Any]:
        raise RuntimeError("probe not configured")


@dataclass(frozen=True, slots=True)
class _CandidateKey:
    host: str
    port: int
    source_address: str | None


@dataclass
class _MutableCandidate:
    host: str
    port: int
    source_address: str | None
    source_address_class: str | None
    candidate_origin: CandidateOrigin
    router_id: str | None = None
    route_if_index: int | None = None
    route_label: str | None = None


def _normalize_host(host: str) -> str:
    candidate = host.strip()
    if candidate.lower().startswith("http://"):
        candidate = candidate[7:]
    elif candidate.lower().startswith("https://"):
        candidate = candidate[8:]
    if "/" in candidate:
        candidate = candidate.split("/", 1)[0]
    if candidate.count(":") == 1 and not candidate.startswith("["):
        candidate = candidate.split(":", 1)[0]
    return candidate.strip()


def _host_exclusion_reason(host: str) -> str | None:
    normalized = _normalize_host(host)
    if not normalized:
        raise RouterDiscoveryError("host must be non-empty")
    if is_loopback_management_host(normalized):
        return "loopback_not_management_candidate"
    if not host_is_private(normalized):
        return "non_private_management_address"
    return None


def _is_apipa_ipv4(address: str) -> bool:
    return address.startswith("169.254.")


def _is_loopback_ipv4(address: str) -> bool:
    return is_loopback_management_host(address)


def _conventional_subnet_first_host(address: str, prefix_length: int) -> str | None:
    try:
        iface = ipaddress.IPv4Interface(f"{address}/{prefix_length}")
    except ValueError:
        return None
    net = iface.network
    candidate_addr = net.network_address + 1
    if candidate_addr > net.broadcast_address:
        return None
    if candidate_addr == iface.ip:
        return None
    return str(candidate_addr)


_CANDIDATE_ORIGIN_PRIORITY: dict[CandidateOrigin, int] = {
    "known_endpoint": 3,
    "default_gateway": 2,
    "local_subnet_gateway": 1,
}


def _probe_evidence_complete_for_identity(evidence: dict[str, Any] | None) -> bool:
    if evidence is None:
        return False
    if not bool(evidence.get("identity_complete")):
        return False
    fields = tuple_evidence_fields_or_none(evidence)
    if fields is None:
        return False
    if not fields.ndm_build or not fields.transport or not fields.device_fingerprint_digest:
        return False
    required_string_keys = (
        "model",
        "firmware_version",
        "bsp_build",
        "update_channel",
        "region",
        "component_set_digest",
        "ssh_host_key_algorithm",
        "ssh_host_key_fingerprint_sha256",
    )
    for key in required_string_keys:
        value = evidence.get(key)
        if not isinstance(value, str) or not value.strip():
            return False
    if bool(evidence.get("certification_eligible")) is not True:
        return False
    return True


def _credentials_required_for_candidate(
    *,
    identity_state: IdentityState,
    reason_code: str,
    credential_ref_resolvable: bool,
) -> bool:
    if reason_code == "enrollment_match_identity_unverified":
        return not credential_ref_resolvable
    if identity_state == "unknown":
        return True
    return False


def _resolve_source_address(
    raw: str | None,
    *,
    preferred: str | None,
) -> tuple[str | None, str | None]:
    if preferred is not None:
        validated = validate_source_address(preferred)
        return validated, source_address_class(validated)
    if raw is None:
        return None, None
    stripped = raw.strip()
    if not stripped:
        return None, None
    validated = validate_source_address(stripped)
    return validated, source_address_class(validated)


def _has_ssh_host_key_pin(
    store: PersistenceStore,
    *,
    router_id: str | None,
    gate_a: GateACertification | None,
) -> bool:
    if router_id is not None:
        pin = store.get_endpoint_ssh_host_key(router_id)
        if pin is not None:
            return True
    return gate_a is not None


def _probe_eligible(
    store: PersistenceStore,
    vault: CredentialVaultPort | None,
    *,
    item: _MutableCandidate,
    credential_ref_id: str | None,
    gate_a: GateACertification | None,
) -> bool:
    if not _has_ssh_host_key_pin(store, router_id=item.router_id, gate_a=gate_a):
        return False
    return _credential_ref_resolvable(
        store,
        vault,
        router_id=item.router_id,
        credential_ref_id=credential_ref_id,
    )


def _credential_ref_resolvable(
    store: PersistenceStore,
    vault: CredentialVaultPort | None,
    *,
    router_id: str | None,
    credential_ref_id: str | None,
) -> bool:
    ref_id = credential_ref_id
    if ref_id is None and router_id is not None:
        refs = store.list_credential_refs(router_id)
        for row in refs:
            if row["revoked_at"] is None:
                ref_id = str(row["credential_ref_id"])
                break
    if ref_id is None:
        return False
    cred_row = store.get_credential_ref(ref_id)
    if cred_row is None or cred_row["revoked_at"] is not None:
        return False
    if vault is None:
        return True
    try:
        vault.use(ref_id)
    except Exception:
        return False
    return True


def _router_asserts_real_device_model(router_row: Any) -> bool:
    """True when the stored model is a non-empty claim about the physical device."""
    model = str(router_row["model"]).strip()
    if not model:
        return False
    return model != ENROLLMENT_DRAFT_MODEL


def _is_enrollment_draft(router_row: Any) -> bool:
    """True when enrollment is unfinished and no real device model was asserted."""
    if str(router_row["lifecycle_status"]) != ENROLLMENT_DRAFT_LIFECYCLE:
        return False
    return not _router_asserts_real_device_model(router_row)


def _classify_identity_local(
    *,
    router_id: str | None,
    router_row: Any | None,
    gate_a: GateACertification | None,
    store: PersistenceStore,
) -> tuple[IdentityState, str]:
    if router_id is None or router_row is None:
        return "unknown", "unenrolled_host"

    lifecycle = str(router_row["lifecycle_status"])
    if lifecycle == "IdentityMismatch":
        return "known_mismatch", "lifecycle_identity_mismatch"

    pin = store.get_endpoint_ssh_host_key(router_id)
    if gate_a is None:
        if pin is None:
            return "unknown", "missing_gate_a_and_pin"
        return "unknown", "missing_gate_a_tuple"

    if _is_enrollment_draft(router_row):
        return "unknown", "enrollment_draft_model_unknown"

    router_model = str(router_row["model"])
    if router_model != gate_a.model:
        return "known_mismatch", "tuple_model_mismatch"

    if pin is None:
        return "unknown", "missing_ssh_host_key_pin"

    pin_norm = normalize_sha256_fingerprint(pin.fingerprint_sha256)
    gate_pin_norm = normalize_sha256_fingerprint(gate_a.ssh_host_key_fingerprint_sha256)
    if pin_norm != gate_pin_norm:
        return "known_mismatch", "host_key_pin_mismatch"

    return "unknown", "enrollment_match_identity_unverified"


def _classify_identity_probe(
    *,
    gate_a: GateACertification | None,
    probe_evidence: dict[str, Any] | None,
    fallback_state: IdentityState,
    fallback_reason: str,
) -> tuple[IdentityState, str]:
    if probe_evidence is None:
        return fallback_state, fallback_reason
    if gate_a is None:
        return "unknown", "probe_without_gate_a_tuple"
    if not _probe_evidence_complete_for_identity(probe_evidence):
        return "unknown", "probe_evidence_incomplete"
    if gate_a.matches_probe_evidence(probe_evidence):
        return "known_match", "probe_tuple_match"
    return "known_mismatch", "probe_tuple_mismatch"


def _append_excluded_candidate(
    excluded: list[dict[str, Any]],
    *,
    host: str,
    port: int | None,
    candidate_origin: CandidateOrigin | None,
    reason_code: str,
) -> None:
    entry: dict[str, Any] = {"host": host, "reason_code": reason_code}
    if port is not None:
        entry["port"] = port
    if candidate_origin is not None:
        entry["candidate_origin"] = candidate_origin
    excluded.append(entry)


def _collect_known_endpoint_candidates(
    store: PersistenceStore,
    *,
    preferred_source_address: str | None,
    excluded: list[dict[str, Any]],
) -> list[_MutableCandidate]:
    out: list[_MutableCandidate] = []
    for router_row in store.list_routers(limit=200):
        router_id = str(router_row["router_id"])
        endpoint = store.get_primary_endpoint(router_id)
        if endpoint is None or not int(endpoint["is_enabled"]):
            continue
        raw_host = str(endpoint["host"])
        exclusion = _host_exclusion_reason(raw_host)
        port = int(endpoint["port"])
        if exclusion is not None:
            _append_excluded_candidate(
                excluded,
                host=_normalize_host(raw_host) or raw_host.strip(),
                port=port,
                candidate_origin="known_endpoint",
                reason_code=exclusion,
            )
            continue
        host = _normalize_host(raw_host)
        source_address, source_class = _resolve_source_address(
            str(endpoint["source_address"]) if endpoint["source_address"] else None,
            preferred=preferred_source_address,
        )
        out.append(
            _MutableCandidate(
                host=host,
                port=port,
                source_address=source_address,
                source_address_class=source_class,
                candidate_origin="known_endpoint",
                router_id=router_id,
            )
        )
    return out


def _collect_default_gateway_candidates(
    route_table: HostRouteTablePort,
    *,
    preferred_source_address: str | None,
    excluded: list[dict[str, Any]],
    routes: list[DefaultGatewayRoute] | None = None,
) -> list[_MutableCandidate]:
    out: list[_MutableCandidate] = []
    gateway_routes = (
        routes if routes is not None else route_table.list_ipv4_default_gateways()
    )
    for route in gateway_routes:
        raw_host = route.gateway_host
        exclusion = _host_exclusion_reason(raw_host)
        if exclusion is not None:
            _append_excluded_candidate(
                excluded,
                host=_normalize_host(raw_host) or raw_host.strip(),
                port=443,
                candidate_origin="default_gateway",
                reason_code=exclusion,
            )
            continue
        host = _normalize_host(raw_host)
        source_address, source_class = _resolve_source_address(
            route.source_address,
            preferred=preferred_source_address,
        )
        out.append(
            _MutableCandidate(
                host=host,
                port=443,
                source_address=source_address,
                source_address_class=source_class,
                candidate_origin="default_gateway",
                route_if_index=route.route_if_index,
                route_label=route.route_label,
            )
        )
    return out


def _collect_local_subnet_gateway_candidates(
    route_table: HostRouteTablePort,
    *,
    preferred_source_address: str | None,
    excluded: list[dict[str, Any]],
    default_gateway_hosts: set[str],
    default_gateway_if_indexes: set[int],
    default_gateway_source_addresses: set[str],
) -> list[_MutableCandidate]:
    out: list[_MutableCandidate] = []
    for iface in route_table.list_ipv4_host_interfaces():
        address = iface.address.strip()
        if not address:
            continue
        if iface.prefix_length <= 0:
            continue
        if _is_loopback_ipv4(address) or _is_apipa_ipv4(address):
            continue
        if iface.if_index is not None and iface.if_index in default_gateway_if_indexes:
            continue
        try:
            normalized_address = str(ipaddress.ip_address(address))
        except ValueError:
            normalized_address = address
        if normalized_address in default_gateway_source_addresses:
            continue
        try:
            iface_network = ipaddress.IPv4Interface(
                f"{address}/{iface.prefix_length}"
            ).network
        except ValueError:
            iface_network = None
        if iface_network is not None:
            subnet_covered_by_default_gateway = False
            for gw_host in default_gateway_hosts:
                try:
                    gw_ip = ipaddress.ip_address(gw_host)
                except ValueError:
                    continue
                if isinstance(gw_ip, ipaddress.IPv4Address) and gw_ip in iface_network:
                    subnet_covered_by_default_gateway = True
                    break
            if subnet_covered_by_default_gateway:
                continue
        conventional_host = _conventional_subnet_first_host(address, iface.prefix_length)
        if conventional_host is None:
            continue
        if conventional_host in default_gateway_hosts:
            continue
        exclusion = _host_exclusion_reason(conventional_host)
        if exclusion is not None:
            _append_excluded_candidate(
                excluded,
                host=conventional_host,
                port=443,
                candidate_origin="local_subnet_gateway",
                reason_code=exclusion,
            )
            continue
        host = _normalize_host(conventional_host)
        source_address, source_class = _resolve_source_address(
            address,
            preferred=preferred_source_address,
        )
        out.append(
            _MutableCandidate(
                host=host,
                port=443,
                source_address=source_address,
                source_address_class=source_class,
                candidate_origin="local_subnet_gateway",
                route_if_index=iface.if_index,
                route_label=iface.if_label,
            )
        )
    return out


def _default_gateway_fetch_failed(route_table: HostRouteTablePort) -> bool:
    """True when the host default-gateway route read failed (dedup data unreliable)."""
    raw = getattr(route_table, "last_source_diagnostics", None)
    if raw is None:
        return False
    if isinstance(raw, dict):
        items: list[Any] = list(raw.values())
    elif isinstance(raw, list):
        items = list(raw)
    else:
        return False
    for item in items:
        if (
            isinstance(item, dict)
            and item.get("source") == "default_gateway"
            and item.get("status") == "failed"
        ):
            return True
    return False


def _gather_route_table_diagnostics(
    route_table: HostRouteTablePort,
    *,
    enabled_sources: frozenset[str] | None = None,
    always_include_failed_sources: frozenset[str] = frozenset(),
) -> tuple[list[dict[str, Any]], list[str]]:
    raw = getattr(route_table, "last_source_diagnostics", None)
    if raw is None:
        return [], []
    if isinstance(raw, dict):
        diagnostics = list(raw.values())
    elif isinstance(raw, list):
        diagnostics = list(raw)
    else:
        return [], []
    if enabled_sources is not None:
        diagnostics = [
            item
            for item in diagnostics
            if isinstance(item, dict)
            and (
                item.get("source") in enabled_sources
                or (
                    item.get("source") in always_include_failed_sources
                    and item.get("status") == "failed"
                )
            )
        ]
    degraded = [
        str(item["source"])
        for item in diagnostics
        if isinstance(item, dict) and item.get("status") == "failed"
    ]
    return diagnostics, degraded


def _merge_candidates(items: list[_MutableCandidate]) -> dict[_CandidateKey, _MutableCandidate]:
    merged: dict[_CandidateKey, _MutableCandidate] = {}
    for item in items:
        key = _CandidateKey(item.host, item.port, item.source_address)
        existing = merged.get(key)
        if existing is None:
            merged[key] = item
            continue
        incoming_priority = _CANDIDATE_ORIGIN_PRIORITY[item.candidate_origin]
        existing_priority = _CANDIDATE_ORIGIN_PRIORITY[existing.candidate_origin]
        if incoming_priority <= existing_priority:
            continue
        item.route_if_index = item.route_if_index or existing.route_if_index
        item.route_label = item.route_label or existing.route_label
        if item.router_id is None:
            item.router_id = existing.router_id
        merged[key] = item
    return merged


def _resolve_router_credential_ref(store: PersistenceStore, router_id: str | None) -> str | None:
    if router_id is None:
        return None
    for row in store.list_credential_refs(router_id):
        if row["revoked_at"] is None:
            return str(row["credential_ref_id"])
    router = store.get_router(router_id)
    if router is not None and router["credential_ref_id"]:
        return str(router["credential_ref_id"])
    return None


def run_router_discovery(
    *,
    store: PersistenceStore,
    include_default_gateway: bool = True,
    include_known_endpoints: bool = True,
    preferred_source_address: str | None = None,
    probe: bool = False,
    route_table: HostRouteTablePort | None = None,
    identity_probe: CandidateIdentityProbePort | None = None,
    gate_a: GateACertification | None = None,
    vault: CredentialVaultPort | None = None,
) -> dict[str, Any]:
    if preferred_source_address is not None:
        validate_source_address(preferred_source_address)

    table = route_table or EmptyHostRouteTablePort()
    probe_port: CandidateIdentityProbePort = identity_probe or NotConfiguredCandidateProbe()

    excluded_candidates: list[dict[str, Any]] = []
    collected: list[_MutableCandidate] = []
    if include_known_endpoints:
        collected.extend(
            _collect_known_endpoint_candidates(
                store,
                preferred_source_address=preferred_source_address,
                excluded=excluded_candidates,
            )
        )
    default_routes = table.list_ipv4_default_gateways()
    default_gateway_dedup_unreliable = _default_gateway_fetch_failed(table)
    if include_default_gateway:
        collected.extend(
            _collect_default_gateway_candidates(
                table,
                preferred_source_address=preferred_source_address,
                excluded=excluded_candidates,
                routes=default_routes,
            )
        )
    default_gateway_hosts = {
        item.host for item in collected if item.candidate_origin == "default_gateway"
    }
    default_gateway_if_indexes: set[int] = set()
    default_gateway_source_addresses: set[str] = set()
    for route in default_routes:
        if route.route_if_index is not None:
            default_gateway_if_indexes.add(route.route_if_index)
        if route.source_address:
            source = route.source_address.strip()
            if source:
                try:
                    default_gateway_source_addresses.add(str(ipaddress.ip_address(source)))
                except ValueError:
                    default_gateway_source_addresses.add(source)
    if not default_gateway_dedup_unreliable:
        collected.extend(
            _collect_local_subnet_gateway_candidates(
                table,
                preferred_source_address=preferred_source_address,
                excluded=excluded_candidates,
                default_gateway_hosts=default_gateway_hosts,
                default_gateway_if_indexes=default_gateway_if_indexes,
                default_gateway_source_addresses=default_gateway_source_addresses,
            )
        )

    merged = _merge_candidates(collected)
    probed_hosts: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []

    for item in merged.values():
        router_row = store.get_router(item.router_id) if item.router_id else None
        local_state, local_reason = _classify_identity_local(
            router_id=item.router_id,
            router_row=router_row,
            gate_a=gate_a,
            store=store,
        )
        identity_state = local_state
        reason_code = local_reason
        probe_evidence: dict[str, Any] | None = None

        credential_ref_id = _resolve_router_credential_ref(store, item.router_id)
        credential_ref_resolvable = _credential_ref_resolvable(
            store,
            vault,
            router_id=item.router_id,
            credential_ref_id=credential_ref_id,
        )
        credentials_required = _credentials_required_for_candidate(
            identity_state=identity_state,
            reason_code=reason_code,
            credential_ref_resolvable=credential_ref_resolvable,
        )
        writes_allowed = False

        if probe:
            if identity_probe is None:
                raise RouterDiscoveryError("probe not configured")
            if _probe_eligible(
                store,
                vault,
                item=item,
                credential_ref_id=credential_ref_id,
                gate_a=gate_a,
            ):
                target = CandidateProbeTarget(
                    host=item.host,
                    port=item.port,
                    source_address=item.source_address,
                    router_id=item.router_id,
                    credential_ref_id=credential_ref_id,
                )
                probe_evidence = probe_port.probe(target)
                probed_hosts.append(
                    {
                        "host": item.host,
                        "port": item.port,
                        "source_address": item.source_address,
                    }
                )
                identity_state, reason_code = _classify_identity_probe(
                    gate_a=gate_a,
                    probe_evidence=probe_evidence,
                    fallback_state=local_state,
                    fallback_reason=local_reason,
                )
                credential_ref_resolvable = _credential_ref_resolvable(
                    store,
                    vault,
                    router_id=item.router_id,
                    credential_ref_id=credential_ref_id,
                )
                credentials_required = _credentials_required_for_candidate(
                    identity_state=identity_state,
                    reason_code=reason_code,
                    credential_ref_resolvable=credential_ref_resolvable,
                )
            elif item.candidate_origin in ("default_gateway", "local_subnet_gateway"):
                credentials_required = True

        payload: dict[str, Any] = {
            "host": item.host,
            "port": item.port,
            "source_address": item.source_address,
            "candidate_origin": item.candidate_origin,
            "identity_state": identity_state,
            "credentials_required": credentials_required,
            "writes_allowed": writes_allowed,
            "reason_code": reason_code,
        }
        if item.source_address_class is not None:
            payload["source_address_class"] = item.source_address_class
        if item.router_id is not None:
            payload["router_id"] = item.router_id
        if item.route_if_index is not None:
            payload["route_if_index"] = item.route_if_index
        if item.route_label is not None:
            payload["route_label"] = item.route_label
        if probe_evidence is not None:
            evidence_complete = _probe_evidence_complete_for_identity(probe_evidence)
            payload["facts"] = {
                "probe_reachable": probe_evidence.get("reachable"),
                "probe_tuple_match": (
                    gate_a.matches_probe_evidence(probe_evidence)
                    if gate_a is not None and evidence_complete
                    else None
                ),
            }
        candidates.append(payload)

    sources: list[str] = []
    if include_default_gateway:
        sources.append("default_gateway")
    sources.append("local_subnet_gateway")
    if include_known_endpoints:
        sources.append("known_endpoint")

    enabled_route_sources = frozenset({"local_subnet_gateway"})
    always_surface_failed_sources = frozenset({"default_gateway"})
    if include_default_gateway:
        enabled_route_sources = frozenset({"local_subnet_gateway", "default_gateway"})
        always_surface_failed_sources = frozenset()
    source_diagnostics, degraded_sources = _gather_route_table_diagnostics(
        table,
        enabled_sources=enabled_route_sources,
        always_include_failed_sources=always_surface_failed_sources,
    )

    return {
        "candidates": candidates,
        "excluded_candidates": excluded_candidates,
        "bounds": {
            "sources": sources,
            "subnet_scan": False,
            "free_form_hosts": False,
            "credential_stuffing": False,
            "description": (
                "Candidates limited to IPv4 default gateway(s) from the local host "
                "routing table, enrolled router endpoint hosts, and one conventional "
                "first-host point per local IPv4 interface without a default route "
                "(not a subnet scan)."
            ),
        },
        "certification_eligible": False,
        "probed_hosts": probed_hosts,
        "source_diagnostics": source_diagnostics,
        "degraded_sources": degraded_sources,
    }


__all__ = [
    "CandidateIdentityProbePort",
    "CandidateProbeTarget",
    "DefaultGatewayRoute",
    "ENROLLMENT_DRAFT_IDENTITY_FINGERPRINT",
    "ENROLLMENT_DRAFT_LIFECYCLE",
    "ENROLLMENT_DRAFT_MODEL",
    "EmptyHostRouteTablePort",
    "HostRouteTablePort",
    "IdentityState",
    "LocalHostIPv4Interface",
    "NotConfiguredCandidateProbe",
    "RouterDiscoveryError",
    "run_router_discovery",
]
