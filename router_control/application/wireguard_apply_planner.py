"""Offline WireGuard/AmneziaWG intent → sealed RCI op descriptor compiler.

ASC-9 apply/teardown sequences are device-verified (NC-1812, 2026-07-24).
16-arg ASC and I1-I5 encodings are documented but NOT device-verified — compiler
returns ``unsupported_pending_verification`` with empty ops.
Secret/peer ops compile with ``verification_status=pending_live_verification`` —
CLI grammar is documentation-sourced, NOT device-certified.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from router_control.adapters.netcraze.allowlist import (
    validate_asc_args,
    validate_peer_allow_ips_list,
    validate_wireguard_id,
)
from router_control.adapters.netcraze.interface_rci import InterfaceRciOperation
from router_control.adapters.netcraze.wireguard_rci import (
    WireguardRciOperation,
    parse_interface_address_cidr,
)
from router_control.application.grammar_doc_refs import build_planner_op_notes
from router_control.domain.network_intents import WireguardIntent, WireguardPeerRciShape

_SECRET_UNVERIFIED_NOTE = (
    "AWG secret tunnel overall verification_status remains pending_live_verification "
    "(preshared-key not device-verified; path-style peer transport REJECTED live on "
    "5.01.C.1.0-0; NOT tunnel connectivity; NOT WriteCertified)"
)
_PRESHARED_KEY_UNVERIFIED_NOTE = (
    "preshared-key not device-verified; pending_live_verification"
)
_PRIVATE_KEY_PARTIAL_VERIFIED_NOTE = (
    "private-key transport partially device-verified on dedicated lab NC-1812 "
    "(router 192.168.2.1) 2026-07-24 "
    "(evidence: data/artifacts/awg-secret-tunnel-wireguard5-live-probe-192.168.2.1-20260724.json); "
    "nested_rci peer write device-verified ACCEPTED 2026-07-24 "
    "(evidence: data/artifacts/awg-peer-nested-rci-live-reverify-192.168.2.1-20260724.json); "
    "preshared-key remains pending_live_verification (secret/WriteCertified axis); "
    "tunnel-health observe path DEVICE-CONFIRMED separately — NOT egress via VPN."
)
_PLAN_PRIVATE_KEY_PARTIAL_NOTE = (
    "private-key transport partially device-verified; "
    "nested_rci peer write device-verified ACCEPTED 2026-07-24; "
    "preshared-key pending_live_verification (secret axis only — "
    "NOT WriteCertified; tunnel observe DEVICE-CONFIRMED on separate note)."
)
_NESTED_PEER_NOTE = (
    "WireGuard peer upsert uses nested RCI JSON resource write: peer[] array "
    "with key=pubkey and nested endpoint/allow-ips/keepalive-interval objects "
    "under interface.WireguardN.wireguard; device-verified write ACCEPTED on "
    "5.01.C.1.0-0 (2026-07-24; evidence: "
    "data/artifacts/awg-peer-nested-rci-live-reverify-192.168.2.1-20260724.json); "
    "NOT WriteCertified; NOT tunnel connectivity claim"
)

_WG_RCI = "router_control/adapters/netcraze/wireguard_rci.py"
_IF_RCI = "router_control/adapters/netcraze/interface_rci.py"
_WIREGUARD_FAMILY = "wireguard"


def _wg_op_notes(
    operation: str,
    *,
    sealed_template: str,
    extra: tuple[str, ...] = (),
) -> tuple[str, ...]:
    return build_planner_op_notes(
        _WIREGUARD_FAMILY,
        operation,
        sealed_template=sealed_template,
        extra=extra,
    )


_WG_HANDSHAKE_SETTLE_SECONDS_MIN = 20
_WG_HANDSHAKE_SETTLE_SECONDS_MAX = 30
_WG_TUNNEL_OBSERVE_NOTE = (
    "Tunnel health from show interface peer fields only (WireGuard path does NOT read "
    "show rc); dead-peer and tunnel_healthy branches DEVICE-CONFIRMED on expendable lab "
    "NC-1812 2026-07-31 (evidence: data/artifacts/wg-awg-real-tunnel-attempt-20260731.json); "
    "bounded handshake settle "
    f"{_WG_HANDSHAKE_SETTLE_SECONDS_MIN}-{_WG_HANDSHAKE_SETTLE_SECONDS_MAX}s "
    "may apply before one recheck; immediate tunnel_never_handshaked is NOT "
    "configuration failure; NOT egress via VPN; NOT routing/kill-switch/IPv6/address."
)
_INTERFACE_ADDRESS_CONFIGURED_NOTE = (
    "WireGuard interface Address compiles to sealed SET_IP_ADDRESS before UP; "
    "readback confirmation requires parsed show-interface address matching intent — "
    "otherwise address_configured_unverified (NOT device-proven egress)."
)
_INTERFACE_ADDRESS_LIMITATION_NOTE = _INTERFACE_ADDRESS_CONFIGURED_NOTE
_IP_GLOBAL_UNVERIFIED_CLEAR_NOTE = (
    "CLEAR_IP_GLOBAL grammar `interface {wg} no ip global` is documentation-sourced — "
    "NOT device-proven; teardown best-effort only."
)
_TCP_MSS_UNVERIFIED_CLEAR_NOTE = (
    "CLEAR_TCP_MSS grammar `interface {wg} no ip tcp adjust-mss` is documentation-sourced — "
    "NOT device-proven; teardown best-effort only."
)
_TCP_MSS_NOT_TUNNEL_EVIDENCE_NOTE = (
    "TCP MSS PMTU clamp on VPN interface is NOT tunnel-working evidence and may not fix "
    "router captive_accessible (router's own traffic vs forwarded)."
)

WG_HANDSHAKE_SETTLE_SECONDS_MIN = _WG_HANDSHAKE_SETTLE_SECONDS_MIN
WG_HANDSHAKE_SETTLE_SECONDS_MAX = _WG_HANDSHAKE_SETTLE_SECONDS_MAX


def intent_implies_traffic_routing(intent: WireguardIntent) -> bool:
    """True when intent expects routable tunnel traffic (not merely interface create/up)."""
    if intent.peer_allow_ips is not None and str(intent.peer_allow_ips).strip():
        return True
    return False


def clamp_handshake_settle_seconds(value: float) -> float:
    """Return 0 (no wait) or clamp caller-supplied settle into [20, 30] seconds."""
    if value <= 0:
        return 0.0
    return float(
        max(_WG_HANDSHAKE_SETTLE_SECONDS_MIN, min(_WG_HANDSHAKE_SETTLE_SECONDS_MAX, value))
    )


class WireguardApplyPlannerError(ValueError):
    """Fail-closed compiler error for WireGuard apply planning."""


@dataclass(frozen=True, slots=True)
class WireguardSealedOpDescriptor:
    operation: str
    wg_id: str
    asc_args: str | None = None
    credential_ref_id: str | None = None
    peer_public_key: str | None = None
    peer_endpoint: str | None = None
    peer_allow_ips: str | None = None
    peer_keepalive_interval: int | None = None
    peer_rci_shape: str | None = None
    ipv4_address: str | None = None
    ipv4_mask: str | None = None
    global_auto: bool = False
    global_order: int | None = None
    global_priority: int | None = None
    tcp_mss_pmtu: bool = False
    notes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class WireguardApplyPlan:
    wg_id: str
    apply_ops: tuple[WireguardSealedOpDescriptor, ...]
    teardown_ops: tuple[WireguardSealedOpDescriptor, ...]
    verification_status: str
    notes: tuple[str, ...] = ()


def _asc_args_to_string(asc_args: tuple[int, ...]) -> str:
    return " ".join(str(value) for value in asc_args)


def _validate_intent_peer_allow_ips(intent: WireguardIntent) -> None:
    if not intent.peer_allow_ips:
        return
    try:
        validate_peer_allow_ips_list(intent.peer_allow_ips)
    except ValueError as exc:
        raise WireguardApplyPlannerError(str(exc)) from exc


def _validate_intent_asc_args(intent: WireguardIntent) -> None:
    if intent.asc_args is None:
        return
    if len(intent.asc_args) == 16:
        return
    if len(intent.asc_args) != 9:
        raise WireguardApplyPlannerError("asc_args must contain exactly 9 integers for apply")
    if any(value < 0 for value in intent.asc_args):
        raise WireguardApplyPlannerError("asc_args must contain non-negative integers")
    try:
        validate_asc_args(_asc_args_to_string(intent.asc_args))
    except ValueError as exc:
        raise WireguardApplyPlannerError(str(exc)) from exc


def _unverified_secret_op_notes(operation: str, *, sealed_template: str) -> tuple[str, ...]:
    return _wg_op_notes(
        operation,
        sealed_template=sealed_template,
        extra=(_SECRET_UNVERIFIED_NOTE,),
    )


def _private_key_op_notes() -> tuple[str, ...]:
    return _wg_op_notes(
        WireguardRciOperation.SET_PRIVATE_KEY.value,
        sealed_template=f"wireguard_rci.command_for SET_PRIVATE_KEY ({_WG_RCI})",
        extra=(_PRIVATE_KEY_PARTIAL_VERIFIED_NOTE,),
    )


def _nested_peer_op_notes(*, has_psk: bool) -> tuple[str, ...]:
    notes = _wg_op_notes(
        WireguardRciOperation.UPSERT_PEER_NESTED.value,
        sealed_template=f"wireguard_rci.command_for UPSERT_PEER_NESTED ({_WG_RCI})",
        extra=(_NESTED_PEER_NOTE,),
    )
    if has_psk:
        return notes + (_PRESHARED_KEY_UNVERIFIED_NOTE,)
    return notes


def _append_interface_address_op(
    ops: list[WireguardSealedOpDescriptor],
    intent: WireguardIntent,
    wg_id: str,
) -> None:
    if not intent.interface_address:
        return
    try:
        addr, mask = parse_interface_address_cidr(intent.interface_address)
    except Exception as exc:
        raise WireguardApplyPlannerError(str(exc)) from exc
    ops.append(
        WireguardSealedOpDescriptor(
            operation=WireguardRciOperation.SET_IP_ADDRESS.value,
            wg_id=wg_id,
            ipv4_address=addr,
            ipv4_mask=mask,
            notes=_wg_op_notes(
                WireguardRciOperation.SET_IP_ADDRESS.value,
                sealed_template=f"wireguard_rci.command_for SET_IP_ADDRESS ({_WG_RCI})",
                extra=(_INTERFACE_ADDRESS_CONFIGURED_NOTE,),
            ),
        )
    )


def _append_ip_global_op(
    ops: list[WireguardSealedOpDescriptor],
    intent: WireguardIntent,
    wg_id: str,
) -> None:
    if not intent.ip_global_auto and intent.ip_global_priority is None:
        return
    ops.append(
        WireguardSealedOpDescriptor(
            operation=WireguardRciOperation.IP_GLOBAL.value,
            wg_id=wg_id,
            global_auto=intent.ip_global_auto,
            global_priority=intent.ip_global_priority,
            notes=_wg_op_notes(
                WireguardRciOperation.IP_GLOBAL.value,
                sealed_template=f"wireguard_rci.command_for IP_GLOBAL ({_WG_RCI})",
                extra=(
                    "interface ip global before UP — wifi-station precedent; "
                    "NOT kill-switch/policy-routing beyond ip global",
                ),
            ),
        )
    )


def _append_tcp_mss_op(
    ops: list[WireguardSealedOpDescriptor],
    intent: WireguardIntent,
    wg_id: str,
) -> None:
    if not intent.tcp_mss_pmtu:
        return
    ops.append(
        WireguardSealedOpDescriptor(
            operation=WireguardRciOperation.SET_TCP_MSS.value,
            wg_id=wg_id,
            tcp_mss_pmtu=True,
            notes=_wg_op_notes(
                WireguardRciOperation.SET_TCP_MSS.value,
                sealed_template=f"wireguard_rci.command_for SET_TCP_MSS ({_WG_RCI})",
                extra=(_TCP_MSS_NOT_TUNNEL_EVIDENCE_NOTE,),
            ),
        )
    )


def _append_nested_peer_ops(
    ops: list[WireguardSealedOpDescriptor],
    intent: WireguardIntent,
    wg_id: str,
) -> None:
    if not intent.peer_public_key:
        return
    ops.append(
        WireguardSealedOpDescriptor(
            operation=WireguardRciOperation.UPSERT_PEER_NESTED.value,
            wg_id=wg_id,
            credential_ref_id=intent.preshared_key_credential_ref_id,
            peer_public_key=intent.peer_public_key,
            peer_endpoint=intent.peer_endpoint,
            peer_allow_ips=intent.peer_allow_ips,
            peer_keepalive_interval=intent.peer_keepalive_interval,
            peer_rci_shape=WireguardPeerRciShape.NESTED_RCI.value,
            notes=_nested_peer_op_notes(has_psk=bool(intent.preshared_key_credential_ref_id)),
        )
    )


def _apply_ops(intent: WireguardIntent, wg_id: str) -> tuple[WireguardSealedOpDescriptor, ...]:
    if intent.peer_rci_shape is WireguardPeerRciShape.PATH_STYLE:
        raise WireguardApplyPlannerError(
            "peer_rci_shape=path_style is REJECTED on NC-1812 5.01.C.1.0-0; "
            "use nested_rci (device-verified write accepted 2026-07-24)"
        )
    ops: list[WireguardSealedOpDescriptor] = [
        WireguardSealedOpDescriptor(
            operation=WireguardRciOperation.CREATE_INTERFACE.value,
            wg_id=wg_id,
            notes=_wg_op_notes(
                WireguardRciOperation.CREATE_INTERFACE.value,
                sealed_template=f"wireguard_rci.command_for CREATE_INTERFACE ({_WG_RCI}:109)",
            ),
        )
    ]
    if intent.private_key_credential_ref_id:
        ops.append(
            WireguardSealedOpDescriptor(
                operation=WireguardRciOperation.SET_PRIVATE_KEY.value,
                wg_id=wg_id,
                credential_ref_id=intent.private_key_credential_ref_id,
                notes=_private_key_op_notes(),
            )
        )
    _append_interface_address_op(ops, intent, wg_id)
    _append_nested_peer_ops(ops, intent, wg_id)
    if intent.asc_args is not None and len(intent.asc_args) == 9:
        ops.append(
            WireguardSealedOpDescriptor(
                operation=WireguardRciOperation.SET_ASC.value,
                wg_id=wg_id,
                asc_args=_asc_args_to_string(intent.asc_args),
                notes=_wg_op_notes(
                    WireguardRciOperation.SET_ASC.value,
                    sealed_template=f"wireguard_rci.command_for SET_ASC 9-arg ({_WG_RCI}:116)",
                ),
            )
        )
    _append_ip_global_op(ops, intent, wg_id)
    _append_tcp_mss_op(ops, intent, wg_id)
    if intent.enabled:
        ops.append(
            WireguardSealedOpDescriptor(
                operation=InterfaceRciOperation.UP.value,
                wg_id=wg_id,
                notes=_wg_op_notes(
                    InterfaceRciOperation.UP.value,
                    sealed_template=f"interface_rci.command_for UP ({_IF_RCI}:62)",
                    extra=(
                        "generic interface up — NOT in asc-9 T4 step list; "
                        "OPERATOR_AWG_APPLY.md maps enabled→interface up",
                    ),
                ),
            )
        )
    return tuple(ops)


def _teardown_ops(intent: WireguardIntent, wg_id: str) -> tuple[WireguardSealedOpDescriptor, ...]:
    ops: list[WireguardSealedOpDescriptor] = [
        WireguardSealedOpDescriptor(
            operation=InterfaceRciOperation.DOWN.value,
            wg_id=wg_id,
            notes=_wg_op_notes(
                InterfaceRciOperation.DOWN.value,
                sealed_template=f"interface_rci.command_for DOWN ({_IF_RCI}:64)",
                extra=("teardown best-effort down before peer removal",),
            ),
        )
    ]
    if intent.ip_global_auto or intent.ip_global_priority is not None:
        ops.append(
            WireguardSealedOpDescriptor(
                operation=WireguardRciOperation.CLEAR_IP_GLOBAL.value,
                wg_id=wg_id,
                notes=_wg_op_notes(
                    WireguardRciOperation.CLEAR_IP_GLOBAL.value,
                    sealed_template=f"wireguard_rci.command_for CLEAR_IP_GLOBAL ({_WG_RCI})",
                    extra=(_IP_GLOBAL_UNVERIFIED_CLEAR_NOTE,),
                ),
            )
        )
    if intent.tcp_mss_pmtu:
        ops.append(
            WireguardSealedOpDescriptor(
                operation=WireguardRciOperation.CLEAR_TCP_MSS.value,
                wg_id=wg_id,
                notes=_wg_op_notes(
                    WireguardRciOperation.CLEAR_TCP_MSS.value,
                    sealed_template=f"wireguard_rci.command_for CLEAR_TCP_MSS ({_WG_RCI})",
                    extra=(_TCP_MSS_UNVERIFIED_CLEAR_NOTE,),
                ),
            )
        )
    if intent.interface_address:
        ops.append(
            WireguardSealedOpDescriptor(
                operation=WireguardRciOperation.CLEAR_IP_ADDRESS.value,
                wg_id=wg_id,
                notes=_wg_op_notes(
                    WireguardRciOperation.CLEAR_IP_ADDRESS.value,
                    sealed_template=f"wireguard_rci.command_for CLEAR_IP_ADDRESS ({_WG_RCI})",
                ),
            )
        )
    if intent.peer_public_key:
        ops.append(
            WireguardSealedOpDescriptor(
                operation=WireguardRciOperation.REMOVE_PEER.value,
                wg_id=wg_id,
                peer_public_key=intent.peer_public_key,
                notes=_unverified_secret_op_notes(
                    WireguardRciOperation.REMOVE_PEER.value,
                    sealed_template=f"wireguard_rci.command_for REMOVE_PEER ({_WG_RCI})",
                ),
            )
        )
    if intent.private_key_credential_ref_id:
        ops.append(
            WireguardSealedOpDescriptor(
                operation=WireguardRciOperation.CLEAR_PRIVATE_KEY.value,
                wg_id=wg_id,
                notes=_unverified_secret_op_notes(
                    WireguardRciOperation.CLEAR_PRIVATE_KEY.value,
                    sealed_template=f"wireguard_rci.command_for CLEAR_PRIVATE_KEY ({_WG_RCI})",
                ),
            )
        )
    ops.append(
        WireguardSealedOpDescriptor(
            operation=WireguardRciOperation.REMOVE_INTERFACE.value,
            wg_id=wg_id,
            notes=_wg_op_notes(
                WireguardRciOperation.REMOVE_INTERFACE.value,
                sealed_template=f"wireguard_rci.command_for REMOVE_INTERFACE ({_WG_RCI}:111)",
            ),
        )
    )
    return tuple(ops)


_UNCOVERED_COMPENSATION_REASON = "no sealed negation grammar (unverified)"

_PRE_EXISTING_COMPENSATION_REASON = (
    "pre-existing configuration; compensation would destroy foreign state"
)
_PRE_STATE_UNKNOWN_COMPENSATION_REASON = (
    "pre-apply state unknown; compensation skipped (fail-closed)"
)
_PRIVATE_KEY_STATE_UNKNOWN_COMPENSATION_REASON = (
    "pre-apply private-key state unknown; clear would destroy foreign state"
)
_ADMIN_UP_STATE_UNKNOWN_COMPENSATION_REASON = (
    "pre-apply admin-up state unknown; down would destroy foreign state"
)
_PEER_STATE_UNKNOWN_COMPENSATION_REASON = (
    "pre-apply peer state unknown; remove would destroy foreign state"
)

_APPLY_TO_COMPENSATE: dict[str, str] = {
    WireguardRciOperation.CREATE_INTERFACE.value: WireguardRciOperation.REMOVE_INTERFACE.value,
    WireguardRciOperation.SET_PRIVATE_KEY.value: WireguardRciOperation.CLEAR_PRIVATE_KEY.value,
    WireguardRciOperation.SET_IP_ADDRESS.value: WireguardRciOperation.CLEAR_IP_ADDRESS.value,
    WireguardRciOperation.UPSERT_PEER_NESTED.value: WireguardRciOperation.REMOVE_PEER.value,
    WireguardRciOperation.IP_GLOBAL.value: WireguardRciOperation.CLEAR_IP_GLOBAL.value,
    WireguardRciOperation.SET_TCP_MSS.value: WireguardRciOperation.CLEAR_TCP_MSS.value,
    InterfaceRciOperation.UP.value: InterfaceRciOperation.DOWN.value,
}


@dataclass(frozen=True, slots=True)
class WireguardApplyPreState:
    """Observed device state immediately before apply dispatch (compensation baseline)."""

    known: bool
    interface_existed: bool = False
    was_admin_up: bool | None = None
    had_peer: bool | None = None
    had_private_key: bool | None = None
    had_ip_address: bool | None = None
    had_ip_global: bool | None = None


def _pre_state_is_up(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    text = str(value).strip().lower()
    return text in {"up", "enabled", "true", "1"}


def _observed_identity_status(observed: dict[str, Any], wg_id: str) -> str:
    """Return ``match``, ``mismatch``, or ``unknown`` for target *wg_id* identity."""
    if not observed:
        return "unknown"
    target = wg_id.strip()
    for key in ("id", "interface"):
        value = observed.get(key)
        if value is None:
            continue
        if isinstance(value, dict):
            nested = value.get("id") or value.get("interface")
            if nested is None:
                continue
            nested_text = str(nested).strip()
            if not nested_text:
                continue
            return "match" if nested_text == target else "mismatch"
        text = str(value).strip()
        if not text:
            continue
        return "match" if text == target else "mismatch"
    return "unknown"


def derive_wireguard_pre_state(
    observed: dict[str, Any],
    *,
    wg_id: str,
) -> WireguardApplyPreState:
    """Derive compensation baseline from pre-apply ``show interface`` observation."""
    identity = _observed_identity_status(observed, wg_id)
    if identity == "unknown":
        return WireguardApplyPreState(known=False)
    if identity == "mismatch":
        return WireguardApplyPreState(known=False)
    was_admin_up = _pre_state_is_up(observed.get("state")) or _pre_state_is_up(observed.get("up"))
    peer_public_key = observed.get("peer_public_key")
    had_peer = peer_public_key is not None and str(peer_public_key).strip() != ""
    public_key = observed.get("public_key")
    if public_key is None:
        public_key = observed.get("public-key")
    if public_key is not None and str(public_key).strip():
        had_private_key = True
    else:
        had_private_key = None
    return WireguardApplyPreState(
        known=True,
        interface_existed=True,
        was_admin_up=was_admin_up,
        had_peer=had_peer,
        had_private_key=had_private_key,
    )


def _wireguard_compensation_blocked_reason(
    apply_op: str,
    pre_state: WireguardApplyPreState | None,
) -> str | None:
    if pre_state is None:
        return None
    if not pre_state.known:
        return _PRE_STATE_UNKNOWN_COMPENSATION_REASON
    if apply_op == WireguardRciOperation.CREATE_INTERFACE.value and pre_state.interface_existed:
        return _PRE_EXISTING_COMPENSATION_REASON
    if apply_op == InterfaceRciOperation.UP.value:
        if pre_state.was_admin_up is None:
            return _ADMIN_UP_STATE_UNKNOWN_COMPENSATION_REASON
        if pre_state.was_admin_up:
            return _PRE_EXISTING_COMPENSATION_REASON
    if apply_op == WireguardRciOperation.SET_PRIVATE_KEY.value:
        if pre_state.had_private_key is None:
            return _PRIVATE_KEY_STATE_UNKNOWN_COMPENSATION_REASON
        if pre_state.had_private_key:
            return _PRE_EXISTING_COMPENSATION_REASON
    if apply_op == WireguardRciOperation.UPSERT_PEER_NESTED.value:
        if pre_state.had_peer is None:
            return _PEER_STATE_UNKNOWN_COMPENSATION_REASON
        if pre_state.had_peer:
            return _PRE_EXISTING_COMPENSATION_REASON
    return None


def compensate_ops_for_succeeded_wireguard_apply(
    apply_ops: tuple[WireguardSealedOpDescriptor, ...],
    succeeded_op_names: tuple[str, ...],
    pre_state: WireguardApplyPreState | None = None,
) -> tuple[WireguardSealedOpDescriptor, ...]:
    """Return reverse-order compensating descriptors for succeeded apply ops only."""
    name_to_desc = {op.operation: op for op in apply_ops}
    compensate: list[WireguardSealedOpDescriptor] = []
    for op_name in reversed(succeeded_op_names):
        compensate_op = _APPLY_TO_COMPENSATE.get(op_name)
        if compensate_op is None:
            continue
        if _wireguard_compensation_blocked_reason(op_name, pre_state) is not None:
            continue
        orig = name_to_desc.get(op_name)
        if orig is None:
            continue
        compensate.append(
            WireguardSealedOpDescriptor(
                operation=compensate_op,
                wg_id=orig.wg_id,
                peer_public_key=orig.peer_public_key,
                ipv4_address=orig.ipv4_address,
                ipv4_mask=orig.ipv4_mask,
                global_auto=orig.global_auto,
                global_order=orig.global_order,
                global_priority=orig.global_priority,
                tcp_mss_pmtu=orig.tcp_mss_pmtu,
            )
        )
    return tuple(compensate)


def uncovered_compensate_ops_for_succeeded_wireguard_apply(
    apply_ops: tuple[WireguardSealedOpDescriptor, ...],
    succeeded_op_names: tuple[str, ...],
    pre_state: WireguardApplyPreState | None = None,
) -> tuple[tuple[str, str], ...]:
    """Return apply op names that succeeded but have no sealed compensating operation."""
    name_to_desc = {op.operation: op for op in apply_ops}
    uncovered: list[tuple[str, str]] = []
    for op_name in succeeded_op_names:
        if op_name in _APPLY_TO_COMPENSATE:
            blocked = _wireguard_compensation_blocked_reason(op_name, pre_state)
            if blocked is not None:
                uncovered.append((op_name, blocked))
            continue
        if op_name not in name_to_desc:
            continue
        reason = _UNCOVERED_COMPENSATION_REASON
        if op_name == WireguardRciOperation.SET_ASC.value:
            reason = _UNCOVERED_COMPENSATION_REASON
        if op_name == WireguardRciOperation.CLEAR_IP_GLOBAL.value:
            reason = _IP_GLOBAL_UNVERIFIED_CLEAR_NOTE
        if op_name == WireguardRciOperation.CLEAR_TCP_MSS.value:
            reason = _TCP_MSS_UNVERIFIED_CLEAR_NOTE
        uncovered.append((op_name, reason))
    return tuple(uncovered)


def compile_wireguard_intent_to_ops(
    intent: WireguardIntent,
    wg_id: str | None = None,
) -> WireguardApplyPlan:
    target_id = validate_wireguard_id(wg_id or intent.wg_id)
    if intent.wg_id != target_id:
        raise WireguardApplyPlannerError(
            f"wg_id {intent.wg_id!r} does not match target {target_id!r}"
        )

    if intent.asc_args is not None and len(intent.asc_args) == 16:
        return WireguardApplyPlan(
            wg_id=target_id,
            apply_ops=(),
            teardown_ops=(),
            verification_status="unsupported_pending_verification",
            notes=(
                "16-arg ASC grammar is DOCUMENTED-BUT-NOT-DEVICE-VERIFIED; "
                "only 9-arg ASC is device-verified on NC-1812",
            ),
        )

    if intent.peer_rci_shape is WireguardPeerRciShape.PATH_STYLE:
        return WireguardApplyPlan(
            wg_id=target_id,
            apply_ops=(),
            teardown_ops=(),
            verification_status="unsupported",
            notes=(
                "peer_rci_shape=path_style is REJECTED on NC-1812 5.01.C.1.0-0; "
                "use nested_rci (device-verified write accepted 2026-07-24); "
                "no dispatch",
            ),
        )

    _validate_intent_asc_args(intent)
    _validate_intent_peer_allow_ips(intent)

    has_secret_ops = intent.has_secret_ops
    verification_status = (
        "pending_live_verification" if has_secret_ops else "device_verified_asc9"
    )
    notes: tuple[str, ...] = ()
    if has_secret_ops:
        notes = (_SECRET_UNVERIFIED_NOTE,)
        if intent.private_key_credential_ref_id:
            notes = notes + (_PLAN_PRIVATE_KEY_PARTIAL_NOTE,)

    tunnel_notes = (_WG_TUNNEL_OBSERVE_NOTE, _INTERFACE_ADDRESS_LIMITATION_NOTE)
    notes = notes + tunnel_notes if notes else tunnel_notes

    return WireguardApplyPlan(
        wg_id=target_id,
        apply_ops=_apply_ops(intent, target_id),
        teardown_ops=_teardown_ops(intent, target_id),
        verification_status=verification_status,
        notes=notes,
    )
