"""Shared VPN tunnel-assignment helpers (wg_id resolve, policy metadata, teardown intent)."""

from __future__ import annotations

import json
from typing import Any

from router_control.domain.network_intents import WireguardIntent, WireguardPeerRciShape


def assignment_policy_metadata(assignment: dict[str, Any]) -> dict[str, Any]:
    raw = assignment.get("policy_metadata_json")
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def resolve_assignment_wg_id(
    assignment: dict[str, Any],
    *,
    profile_metadata: dict[str, Any] | None = None,
) -> str | None:
    """Resolve wg_id: observed_vendor_locator → policy_metadata.wg_id → profile metadata.wg_id."""
    observed = assignment.get("observed_vendor_locator")
    if observed:
        observed_wg = str(observed).strip()
        if observed_wg:
            return observed_wg
    policy = assignment_policy_metadata(assignment)
    policy_wg = policy.get("wg_id")
    if policy_wg and str(policy_wg).strip():
        return str(policy_wg).strip()
    if profile_metadata is not None:
        meta_wg = profile_metadata.get("wg_id")
        if meta_wg is not None and str(meta_wg).strip():
            return str(meta_wg).strip()
    return None


def merge_teardown_metadata(
    *,
    profile_metadata: dict[str, Any] | None,
    policy_metadata: dict[str, Any],
) -> dict[str, Any]:
    """Merge profile metadata with assignment policy snapshot (policy wins on overlap)."""
    merged: dict[str, Any] = dict(profile_metadata or {})
    merged.update(policy_metadata)
    return merged


def coerce_peer_rci_shape(raw: object) -> WireguardPeerRciShape:
    if raw is None:
        return WireguardPeerRciShape.NESTED_RCI
    try:
        shape = WireguardPeerRciShape(str(raw))
    except ValueError:
        return WireguardPeerRciShape.NESTED_RCI
    if shape is WireguardPeerRciShape.PATH_STYLE:
        return WireguardPeerRciShape.NESTED_RCI
    return shape


def _coerce_ip_global_priority(raw: object) -> int | None:
    if isinstance(raw, int) and not isinstance(raw, bool):
        return raw
    return None


def _coerce_bool(raw: object, *, default: bool = False) -> bool:
    return raw if isinstance(raw, bool) else default


def _coerce_keepalive(raw: object) -> int | None:
    if isinstance(raw, int) and not isinstance(raw, bool):
        return raw
    return None


def wireguard_intent_from_metadata_dict(
    *,
    wg_id: str,
    metadata: dict[str, Any],
    enabled: bool = False,
) -> WireguardIntent:
    """Best-effort WireguardIntent from assignment/policy metadata (orphan teardown).

    Invalid enum/priority fields are skipped (fail-closed sanitize) rather than raising.
    """
    asc_raw = metadata.get("asc9_args")
    asc_args = tuple(asc_raw) if isinstance(asc_raw, list) else None
    peer_public_key = metadata.get("peer_public_key")
    peer_endpoint = metadata.get("peer_endpoint")
    peer_allow_ips = metadata.get("peer_allow_ips")
    interface_address = metadata.get("interface_address")
    if peer_public_key is not None and not isinstance(peer_public_key, str):
        peer_public_key = None
    if peer_endpoint is not None and not isinstance(peer_endpoint, str):
        peer_endpoint = None
    if peer_allow_ips is not None and not isinstance(peer_allow_ips, str):
        peer_allow_ips = None
    if interface_address is not None and not isinstance(interface_address, str):
        interface_address = None
    return WireguardIntent(
        wg_id=wg_id,
        enabled=enabled,
        asc_args=asc_args,
        peer_public_key=peer_public_key,
        peer_endpoint=peer_endpoint,
        peer_allow_ips=peer_allow_ips,
        peer_keepalive_interval=_coerce_keepalive(metadata.get("peer_keepalive_interval")),
        peer_rci_shape=coerce_peer_rci_shape(metadata.get("peer_rci_shape")),
        interface_address=interface_address,
        ip_global_auto=_coerce_bool(metadata.get("ip_global_auto"), default=False),
        ip_global_priority=_coerce_ip_global_priority(metadata.get("ip_global_priority")),
        tcp_mss_pmtu=_coerce_bool(metadata.get("tcp_mss_pmtu"), default=False),
    )
