"""Property-based invariants for offline apply planners (all network families)."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import fields
from typing import Any, get_args

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st
from router_control.adapters.netcraze.dhcp_rci import DhcpRciOperation
from router_control.adapters.netcraze.dns_rci import DnsRciOperation
from router_control.adapters.netcraze.firewall_rci import FirewallRciOperation
from router_control.adapters.netcraze.interface_rci import InterfaceRciOperation
from router_control.adapters.netcraze.vlan_rci import VlanRciOperation
from router_control.adapters.netcraze.vpn_policy_rci import VpnPolicyRciOperation
from router_control.adapters.netcraze.wifi_rci import WifiApRciOperation
from router_control.adapters.netcraze.wifi_station_rci import WifiStationRciOperation
from router_control.adapters.netcraze.wireguard_rci import WireguardRciOperation
from router_control.application.dhcp_apply_planner import (
    DhcpApplyPreState,
    compensate_ops_for_succeeded_dhcp_apply,
    compile_dhcp_intent_to_ops,
)
from router_control.application.dhcp_apply_service import preview_dhcp_apply
from router_control.application.dns_apply_planner import (
    DnsApplyPreState,
    compensate_ops_for_succeeded_dns_apply,
    compile_dns_intent_to_ops,
)
from router_control.application.dns_apply_service import preview_dns_apply
from router_control.application.firewall_apply_planner import (
    FirewallApplyPreState,
    compensate_ops_for_succeeded_firewall_apply,
    compile_firewall_intent_to_ops,
)
from router_control.application.firewall_apply_service import preview_firewall_apply
from router_control.application.vlan_apply_planner import (
    VlanApplyPreState,
    compensate_ops_for_succeeded_vlan_apply,
    compile_vlan_intent_to_ops,
)
from router_control.application.vpn_policy_routing_planner import (
    VpnPolicyApplyPreState,
    compensate_ops_for_succeeded_vpn_policy_apply,
    compile_vpn_policy_routing_intent,
)
from router_control.application.vpn_policy_routing_service import preview_vpn_policy_routing
from router_control.application.wifi_apply_planner import (
    WifiApplyPreState,
    compensate_ops_for_succeeded_apply,
    compile_wifi_intent_to_ops,
)
from router_control.application.wifi_apply_service import preview_wifi_apply
from router_control.application.wifi_observation_helpers import (
    ERROR_CODE_STATION_PRIORITY_REQUIRES_IP_GLOBAL,
)
from router_control.application.wifi_station_apply_planner import (
    WifiStationApplyPlannerError,
    WifiStationApplyPreState,
    WifiStationAuthMode,
    WifiStationPlannerOptions,
    compensate_ops_for_succeeded_station_apply,
    compile_uplink_intent_to_station_ops,
)
from router_control.application.wifi_station_apply_service import preview_wifi_station_apply
from router_control.application.wireguard_apply_planner import (
    WireguardApplyPlannerError,
    compile_wireguard_intent_to_ops,
)
from router_control.application.wireguard_apply_service import preview_wireguard_apply
from router_control.domain.network_intents import (
    CaptivePortalMode,
    UplinkIntent,
    UplinkMode,
    WifiBand,
    WifiIntent,
    WifiWpaMode,
    WireguardIntent,
    WireguardPeerRciShape,
)

_PROP = settings(max_examples=8, deadline=None)

_WIFI_AP_IDS = (
    "WifiMaster0/AccessPoint3",
    "WifiMaster0/AccessPoint4",
    "WifiMaster1/AccessPoint5",
    "WifiMaster1/AccessPoint6",
)
_WG_IDS = ("Wireguard5", "Wireguard6", "Wireguard7", "Wireguard8", "Wireguard9")
_BRIDGE_IDS = ("Bridge3", "Bridge4", "Bridge5")
_PLAINTEXT_SECRET_MARKERS = (
    "password",
    "passphrase",
    "private_key",
    "preshared",
    "pre_shared_key",
    "secret",
)
_GRAMMAR_NOTE_MARKERS = (
    "grammar",
    "verified",
    "offline_unverified",
    "источник не зафиксирован",
    "help-verified",
    "device-",
    ".md",
    "operator_vpn",
    "discovery",
    "unverified",
    "wifi_rci",
    "wireguard_rci",
    "interface_rci",
    "dns_rci",
    "dhcp_rci",
    "firewall_rci",
    "vlan_rci",
    "wifi_station_rci",
    "sealed template",
)
_DEVICE_VERIFIED_PREFIX = "device_verified"
_BASE64_LIKE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

_WIFI_AP_OPS = frozenset(op.value for op in WifiApRciOperation)
_WIFI_STATION_OPS = frozenset(op.value for op in WifiStationRciOperation)
_WIREGUARD_OPS = frozenset(op.value for op in WireguardRciOperation) | frozenset(
    op.value for op in InterfaceRciOperation
)
_DHCP_OPS = frozenset(op.value for op in DhcpRciOperation)
_DNS_OPS = frozenset(op.value for op in DnsRciOperation)
_FIREWALL_OPS = frozenset(op.value for op in FirewallRciOperation)
_VLAN_OPS = frozenset(op.value for op in VlanRciOperation)
_VPN_POLICY_OPS = frozenset(op.value for op in VpnPolicyRciOperation)

_FORBIDDEN_WG_OPS = frozenset(
    {
        WireguardRciOperation.ADD_PEER.value,
        WireguardRciOperation.SET_PEER_ENDPOINT.value,
        WireguardRciOperation.SET_PEER_ALLOW_IPS.value,
        WireguardRciOperation.SET_PEER_KEEPALIVE.value,
        WireguardRciOperation.SET_PRESHARED_KEY.value,
    }
)

_WIFI_AP_APPLY_TO_COMPENSATE: dict[str, str] = {
    WifiApRciOperation.SET_SSID.value: WifiApRciOperation.CLEAR_SSID.value,
    WifiApRciOperation.SET_WPA_PSK.value: WifiApRciOperation.CLEAR_WPA_PSK.value,
    WifiApRciOperation.ENCRYPTION_ENABLE.value: WifiApRciOperation.ENCRYPTION_DISABLE.value,
    WifiApRciOperation.ENCRYPTION_WPA2.value: WifiApRciOperation.ENCRYPTION_WPA2_CLEAR.value,
    WifiApRciOperation.ENCRYPTION_WPA3.value: WifiApRciOperation.ENCRYPTION_WPA3_CLEAR.value,
    WifiApRciOperation.UP.value: WifiApRciOperation.DOWN.value,
}

_WIFI_STATION_APPLY_TO_COMPENSATE: dict[str, str] = {
    WifiStationRciOperation.SET_SSID.value: WifiStationRciOperation.CLEAR_SSID.value,
    WifiStationRciOperation.SET_WPA_PSK.value: WifiStationRciOperation.CLEAR_WPA_PSK.value,
    WifiStationRciOperation.ENCRYPTION_ENABLE.value: (
        WifiStationRciOperation.ENCRYPTION_DISABLE.value
    ),
    WifiStationRciOperation.ENCRYPTION_WPA2.value: (
        WifiStationRciOperation.ENCRYPTION_WPA2_CLEAR.value
    ),
    WifiStationRciOperation.UP.value: WifiStationRciOperation.DOWN.value,
    WifiStationRciOperation.IP_ADDRESS_DHCP.value: (
        WifiStationRciOperation.CLEAR_IP_ADDRESS_DHCP.value
    ),
}

_VLAN_APPLY_TO_COMPENSATE: dict[str, str] = {
    VlanRciOperation.CREATE_BRIDGE.value: VlanRciOperation.REMOVE_BRIDGE.value,
    VlanRciOperation.SET_IP_ADDRESS.value: VlanRciOperation.CLEAR_IP_ADDRESS.value,
    VlanRciOperation.UP.value: VlanRciOperation.DOWN.value,
}

_DHCP_APPLY_TO_COMPENSATE: dict[str, str] = {
    DhcpRciOperation.SET_POOL.value: DhcpRciOperation.CLEAR_POOL.value,
    DhcpRciOperation.BIND_HOST.value: DhcpRciOperation.UNBIND_HOST.value,
}

_DNS_APPLY_TO_COMPENSATE: dict[str, str] = {
    DnsRciOperation.SET_STATIC_HOST.value: DnsRciOperation.CLEAR_STATIC_HOST.value,
    DnsRciOperation.SET_UPSTREAM.value: DnsRciOperation.CLEAR_UPSTREAM.value,
}

_FIREWALL_APPLY_TO_COMPENSATE: dict[str, str] = {
    FirewallRciOperation.ADD_RULE.value: FirewallRciOperation.REMOVE_RULE.value,
}

_VPN_POLICY_APPLY_TO_COMPENSATE: dict[str, str] = {
    VpnPolicyRciOperation.CREATE_POLICY.value: VpnPolicyRciOperation.REMOVE_POLICY.value,
    VpnPolicyRciOperation.SET_NAME_SERVER.value: VpnPolicyRciOperation.CLEAR_NAME_SERVER.value,
}


def _notes_have_grammar_reference(notes: Sequence[str]) -> bool:
    joined = " ".join(notes).lower()
    return any(marker in joined for marker in _GRAMMAR_NOTE_MARKERS)


def _assert_ops_in_allowlist(ops: Sequence[Any], allowlist: frozenset[str], family: str) -> None:
    for op in ops:
        assert op.operation in allowlist, (
            f"{family} emitted non-allowlisted op {op.operation!r}"
        )


def _assert_strict_grammar_ops(ops: Sequence[Any], family: str) -> None:
    for op in ops:
        notes = getattr(op, "notes", ()) or ()
        assert notes, f"{family} op {op.operation} lacks grammar-source notes (finding)"
        assert _notes_have_grammar_reference(notes), (
            f"{family} op {op.operation} notes lack grammar reference: {notes!r}"
        )


def _preview_json(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True)


def _assert_preview_has_no_plaintext_secrets(
    preview: Mapping[str, Any],
    *,
    leak_marker: str,
) -> None:
    serialized = _preview_json(preview).lower()
    assert leak_marker.lower() not in serialized
    for marker in _PLAINTEXT_SECRET_MARKERS:
        assert f'"{marker}"' not in serialized
    for value in preview.values():
        if isinstance(value, str) and _BASE64_LIKE.fullmatch(value):
            pytest.fail(f"preview contains base64-like secret material: {value[:16]}...")


def _assert_teardown_reverses_mapped_apply(
    apply_ops: Sequence[Any],
    teardown_ops: Sequence[Any],
    mapping: Mapping[str, str],
) -> None:
    mapped_apply = [op for op in apply_ops if op.operation in mapping]
    expected = [mapping[op.operation] for op in reversed(mapped_apply)]
    actual = [op.operation for op in teardown_ops if op.operation in mapping.values()]
    assert actual == expected



def _matched_apply_descriptors_for_compensate(
    apply_ops: Sequence[Any],
    succeeded: tuple[str, ...],
    mapping: Mapping[str, str],
    blocked: Callable[[str], bool],
) -> list[Any]:
    matched_prefix: list[Any] = []
    succeeded_idx = 0
    for op in apply_ops:
        if succeeded_idx >= len(succeeded):
            break
        if op.operation == succeeded[succeeded_idx]:
            matched_prefix.append(op)
            succeeded_idx += 1
    filtered = [
        op for op in matched_prefix if op.operation in mapping and not blocked(op.operation)
    ]
    return list(reversed(filtered))


def _assert_compensation_reverses_succeeded_apply(
    apply_ops: Sequence[Any],
    compensate_fn: Callable[..., tuple[Any, ...]],
    mapping: Mapping[str, str],
    *,
    pre_state: Any | None = None,
    is_blocked: Callable[[str], bool] | None = None,
    verify_compensate_pair: Callable[[Any, Any], None] | None = None,
) -> None:
    """Compensation must undo succeeded apply ops in reverse order, skipping blocked ops."""
    succeeded = tuple(op.operation for op in apply_ops)
    blocked = is_blocked or (lambda _op: False)
    if pre_state is None:
        compensate = compensate_fn(apply_ops, succeeded)
    else:
        compensate = compensate_fn(apply_ops, succeeded, pre_state)
    expected = [
        mapping[op_name]
        for op_name in reversed(succeeded)
        if op_name in mapping and not blocked(op_name)
    ]
    actual = [op.operation for op in compensate]
    assert actual == expected
    if verify_compensate_pair is not None:
        matched_apply = _matched_apply_descriptors_for_compensate(
            apply_ops, succeeded, mapping, blocked
        )
        assert len(matched_apply) == len(compensate)
        for apply_desc, comp_desc in zip(matched_apply, compensate, strict=True):
            verify_compensate_pair(apply_desc, comp_desc)


def _verify_dhcp_compensate_pair(apply_desc: Any, comp_desc: Any) -> None:
    assert comp_desc.mac_address == apply_desc.mac_address


def _verify_dns_compensate_pair(apply_desc: Any, comp_desc: Any) -> None:
    assert comp_desc.upstream_resolver == apply_desc.upstream_resolver


def _verify_firewall_compensate_pair(apply_desc: Any, comp_desc: Any) -> None:
    assert comp_desc.ordinal == apply_desc.ordinal


def _verify_vpn_policy_compensate_pair(apply_desc: Any, comp_desc: Any) -> None:
    assert comp_desc.name_server_address == apply_desc.name_server_address


def _wifi_ap_compensation_blocked(op_name: str, pre_state: WifiApplyPreState | None) -> bool:
    from router_control.application.wifi_apply_planner import _wifi_compensation_blocked_reason

    return _wifi_compensation_blocked_reason(op_name, pre_state) is not None


def _wifi_station_compensation_blocked(
    op_name: str,
    pre_state: WifiStationApplyPreState | None,
) -> bool:
    from router_control.application.wifi_station_apply_planner import (
        _station_compensation_blocked_reason,
    )

    return _station_compensation_blocked_reason(op_name, pre_state) is not None


def _vlan_compensation_blocked(op_name: str, pre_state: VlanApplyPreState | None) -> bool:
    from router_control.application.vlan_apply_planner import _vlan_compensation_blocked_reason

    return _vlan_compensation_blocked_reason(op_name, pre_state) is not None


def _dhcp_compensation_blocked(op_name: str, pre_state: DhcpApplyPreState | None) -> bool:
    from router_control.application.dhcp_apply_planner import _dhcp_compensation_blocked_reason

    return _dhcp_compensation_blocked_reason(op_name, pre_state) is not None


def _dns_compensation_blocked(op_name: str, pre_state: DnsApplyPreState | None) -> bool:
    from router_control.application.dns_apply_planner import _dns_compensation_blocked_reason

    return _dns_compensation_blocked_reason(op_name, pre_state) is not None


def _firewall_compensation_blocked(
    op_name: str,
    pre_state: FirewallApplyPreState | None,
) -> bool:
    from router_control.application.firewall_apply_planner import (
        _firewall_compensation_blocked_reason,
    )

    return _firewall_compensation_blocked_reason(op_name, pre_state) is not None


def _vpn_policy_compensation_blocked(
    op_name: str,
    pre_state: VpnPolicyApplyPreState | None,
) -> bool:
    from router_control.application.vpn_policy_routing_planner import (
        _vpn_policy_compensation_blocked_reason,
    )

    return _vpn_policy_compensation_blocked_reason(op_name, pre_state) is not None


_ssid_text = st.from_regex(r"[A-Za-z0-9][A-Za-z0-9 _-]{0,30}", fullmatch=True)
_cred_ref = st.from_regex(r"credref:[a-z0-9-]{4,24}", fullmatch=True)
def _assert_wireguard_teardown_reverses_apply(
    apply_ops: Sequence[Any],
    teardown_ops: Sequence[Any],
) -> None:
    mapping = {
        InterfaceRciOperation.UP.value: InterfaceRciOperation.DOWN.value,
        WireguardRciOperation.UPSERT_PEER_NESTED.value: WireguardRciOperation.REMOVE_PEER.value,
        WireguardRciOperation.SET_PRIVATE_KEY.value: WireguardRciOperation.CLEAR_PRIVATE_KEY.value,
        WireguardRciOperation.CREATE_INTERFACE.value: WireguardRciOperation.REMOVE_INTERFACE.value,
    }
    apply_names = [op.operation for op in apply_ops]
    expected = [mapping[name] for name in reversed(apply_names) if name in mapping]
    actual = [op.operation for op in teardown_ops if op.operation in mapping.values()]
    if InterfaceRciOperation.UP.value not in apply_names:
        actual = [name for name in actual if name != InterfaceRciOperation.DOWN.value]
    assert actual == expected


_ipv4_dotted = st.builds(
    lambda a, b, c, d: f"{a}.{b}.{c}.{d}",
    st.integers(min_value=1, max_value=254),
    st.integers(min_value=0, max_value=254),
    st.integers(min_value=0, max_value=254),
    st.integers(min_value=1, max_value=254),
)


@st.composite
def wifi_intent_strategy(draw: st.DrawFn) -> tuple[WifiIntent, str]:
    ap_id = draw(st.sampled_from(_WIFI_AP_IDS))
    band = WifiBand.BAND_5GHZ if ap_id.startswith("WifiMaster1/") else WifiBand.BAND_2_4GHZ
    enabled = draw(st.booleans())
    credential_ref_id = draw(_cred_ref) if enabled else None
    intent = WifiIntent(
        ssid=draw(_ssid_text),
        enabled=enabled,
        credential_ref_id=credential_ref_id,
        captive_portal=CaptivePortalMode.DISABLED,
        guest_isolation=False,
        wpa_mode=draw(st.sampled_from(list(WifiWpaMode))),
        band=band,
    )
    return intent, ap_id


@st.composite
def wireguard_intent_strategy(draw: st.DrawFn) -> WireguardIntent:
    wg_id = draw(st.sampled_from(_WG_IDS))
    enabled = draw(st.booleans())
    include_asc = draw(st.booleans())
    asc_args = (
        tuple(draw(st.integers(min_value=0, max_value=100)) for _ in range(9))
        if include_asc
        else None
    )
    include_peer = draw(st.booleans())
    peer_public_key = (
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=" if include_peer else None
    )
    private_ref = draw(st.one_of(st.none(), _cred_ref))
    psk_ref = draw(st.one_of(st.none(), _cred_ref)) if include_peer else None
    peer_allow_ips = draw(st.one_of(st.none(), st.just("10.0.0.0/8, 192.168.1.0/24")))
    return WireguardIntent(
        wg_id=wg_id,
        enabled=enabled,
        asc_args=asc_args,
        private_key_credential_ref_id=private_ref,
        preshared_key_credential_ref_id=psk_ref,
        peer_public_key=peer_public_key,
        peer_endpoint="vpn.example.com:51820" if include_peer else None,
        peer_allow_ips=peer_allow_ips,
        peer_keepalive_interval=25 if include_peer else None,
    )


@st.composite
def station_intent_strategy(draw: st.DrawFn) -> UplinkIntent:
    band = draw(st.sampled_from([WifiBand.BAND_2_4GHZ, WifiBand.BAND_5GHZ]))
    return UplinkIntent(
        mode=UplinkMode.WIFI_WAN,
        ssid=draw(_ssid_text),
        band=band,
        credential_ref_id=draw(_cred_ref),
        priority=draw(st.integers(min_value=0, max_value=255)),
        captive_portal_client=False,
    )


@st.composite
def station_plan_input_strategy(
    draw: st.DrawFn,
) -> tuple[UplinkIntent, WifiStationPlannerOptions]:
    band = draw(st.sampled_from([WifiBand.BAND_2_4GHZ, WifiBand.BAND_5GHZ]))
    priority = draw(st.integers(min_value=0, max_value=255))
    if priority != 100:
        include_ip_global = True
    else:
        include_ip_global = draw(st.booleans())
    intent = UplinkIntent(
        mode=UplinkMode.WIFI_WAN,
        ssid=draw(_ssid_text),
        band=band,
        credential_ref_id=draw(_cred_ref),
        priority=priority,
        captive_portal_client=False,
    )
    options = WifiStationPlannerOptions(include_ip_global=include_ip_global)
    return intent, options


@st.composite
def station_invalid_priority_ip_global_strategy(
    draw: st.DrawFn,
) -> tuple[UplinkIntent, WifiStationPlannerOptions]:
    band = draw(st.sampled_from([WifiBand.BAND_2_4GHZ, WifiBand.BAND_5GHZ]))
    priority = draw(st.integers(min_value=0, max_value=255).filter(lambda p: p != 100))
    intent = UplinkIntent(
        mode=UplinkMode.WIFI_WAN,
        ssid=draw(_ssid_text),
        band=band,
        credential_ref_id=draw(_cred_ref),
        priority=priority,
        captive_portal_client=False,
    )
    options = WifiStationPlannerOptions(include_ip_global=False)
    return intent, options


@st.composite
def station_include_ip_global_strategy(
    draw: st.DrawFn,
) -> tuple[UplinkIntent, WifiStationPlannerOptions]:
    band = draw(st.sampled_from([WifiBand.BAND_2_4GHZ, WifiBand.BAND_5GHZ]))
    priority = draw(st.integers(min_value=0, max_value=255))
    intent = UplinkIntent(
        mode=UplinkMode.WIFI_WAN,
        ssid=draw(_ssid_text),
        band=band,
        credential_ref_id=draw(_cred_ref),
        priority=priority,
        captive_portal_client=False,
    )
    options = WifiStationPlannerOptions(include_ip_global=True)
    return intent, options


@st.composite
def dhcp_intent_strategy(draw: st.DrawFn) -> dict[str, Any]:
    host = draw(st.integers(min_value=1, max_value=254))
    reservations = []
    for idx in range(draw(st.integers(min_value=0, max_value=3))):
        reservations.append(
            {
                "mac_address": f"aa:bb:cc:00:00:{idx + 1:02x}",
                "ipv4_address": f"10.{host}.0.{50 + idx}",
            }
        )
    return {
        "zone_id": draw(st.sampled_from(["Guest", "Promo", "Staff"])),
        "pool_start": f"10.{host}.0.100",
        "pool_end": f"10.{host}.0.200",
        "lease_seconds": draw(st.integers(min_value=60, max_value=604800)),
        "reservations": reservations,
    }


@st.composite
def dns_intent_strategy(draw: st.DrawFn) -> dict[str, Any]:
    label = draw(st.from_regex(r"[a-z]{3,8}", fullmatch=True))
    return {
        "zone_id": draw(st.sampled_from(["Guest", "Promo", "Staff"])),
        "local_fqdn": f"{label}.example.test",
        "upstream_resolvers": draw(
            st.lists(
                st.sampled_from(["1.1.1.1", "8.8.8.8", "9.9.9.9"]),
                min_size=1,
                max_size=3,
                unique=True,
            )
        ),
    }


@st.composite
def firewall_intent_strategy(draw: st.DrawFn) -> dict[str, Any]:
    ordinals = draw(
        st.lists(st.integers(min_value=1, max_value=90), min_size=1, max_size=4, unique=True)
    )
    rules = [
        {
            "action": draw(st.sampled_from(["Allow", "Deny"])),
            "destination_family": draw(
                st.sampled_from(["Dns", "Internet", "OrderPage"])
            ),
            "ordinal": ordinal,
        }
        for ordinal in ordinals
    ]
    return {"zone_id": draw(st.sampled_from(["Guest", "Promo", "Staff"])), "rules": rules}


@st.composite
def vlan_intent_strategy(draw: st.DrawFn) -> tuple[dict[str, Any], str]:
    host = draw(st.integers(min_value=1, max_value=254))
    gateway = draw(st.integers(min_value=2, max_value=250))
    intent = {
        "zone_id": draw(st.sampled_from(["guest", "staff", "promo"])),
        "vlan_id": draw(st.integers(min_value=2, max_value=4000)),
        "ipv4_cidr": f"10.{host}.0.0/24",
        "ipv4_gateway": f"10.{host}.0.{gateway}",
    }
    return intent, draw(st.sampled_from(_BRIDGE_IDS))


@st.composite
def vpn_policy_intent_strategy(draw: st.DrawFn) -> dict[str, Any]:
    use_priority = draw(st.booleans())
    ip_global: dict[str, Any] | str
    if use_priority:
        ip_global = {"priority": draw(st.integers(min_value=0, max_value=65535))}
    else:
        ip_global = draw(st.one_of(st.just("auto"), st.just({"order": 700})))
    return {
        "policy_name": draw(st.from_regex(r"vpn-[a-z0-9-]{3,12}", fullmatch=True)),
        "vpn_interface": draw(st.sampled_from(["GigabitEthernet1", "GigabitEthernet2"])),
        "interface_kind": "other",
        "ip_global": ip_global,
        "name_servers": draw(
            st.one_of(
                st.just([]),
                st.just([{"address": "1.1.1.1"}]),
                st.just([{"address": "8.8.8.8", "domain": "example.test"}]),
            )
        ),
    }


@given(payload=wifi_intent_strategy())
@_PROP
def test_wifi_ap_preview_never_leaks_plaintext_secrets(payload: tuple[WifiIntent, str]) -> None:
    intent, ap_id = payload
    assume(not intent.enabled or intent.credential_ref_id is not None)
    leak_marker = "LEAK-MARKER-WIFI-AP-PLAINTEXT-SECRET"
    preview = preview_wifi_apply(intent, ap_id)
    _assert_preview_has_no_plaintext_secrets(preview, leak_marker=leak_marker)


@given(payload=station_plan_input_strategy())
@_PROP
def test_wifi_station_preview_never_leaks_plaintext_secrets(
    payload: tuple[UplinkIntent, WifiStationPlannerOptions],
) -> None:
    intent, options = payload
    leak_marker = "LEAK-MARKER-STATION-PLAINTEXT-SECRET"
    preview = preview_wifi_station_apply(intent, options=options)
    _assert_preview_has_no_plaintext_secrets(preview, leak_marker=leak_marker)


@given(intent=wireguard_intent_strategy())
@_PROP
def test_wireguard_preview_never_leaks_plaintext_secrets(intent: WireguardIntent) -> None:
    assume(intent.asc_args is None or len(intent.asc_args) == 9)
    leak_marker = "LEAK-MARKER-WIREGUARD-PLAINTEXT-SECRET"
    preview = preview_wireguard_apply(intent)
    _assert_preview_has_no_plaintext_secrets(preview, leak_marker=leak_marker)


@given(payload=wifi_intent_strategy())
@_PROP
def test_wifi_ap_teardown_reverses_mapped_apply(payload: tuple[WifiIntent, str]) -> None:
    intent, ap_id = payload
    assume(not intent.enabled or intent.credential_ref_id is not None)
    plan = compile_wifi_intent_to_ops(intent, ap_id)
    if not plan.apply_ops:
        assert plan.teardown_ops
        return
    _assert_teardown_reverses_mapped_apply(
        plan.apply_ops,
        plan.teardown_ops,
        _WIFI_AP_APPLY_TO_COMPENSATE,
    )


@given(payload=wifi_intent_strategy())
@_PROP
def test_wifi_ap_compensation_reverses_succeeded_apply(payload: tuple[WifiIntent, str]) -> None:
    intent, ap_id = payload
    assume(not intent.enabled or intent.credential_ref_id is not None)
    plan = compile_wifi_intent_to_ops(intent, ap_id)
    if not plan.apply_ops:
        return
    _assert_compensation_reverses_succeeded_apply(
        plan.apply_ops,
        compensate_ops_for_succeeded_apply,
        _WIFI_AP_APPLY_TO_COMPENSATE,
    )


@st.composite
def wifi_pre_state_strategy(draw: st.DrawFn) -> WifiApplyPreState:
    had_psk = draw(st.one_of(st.none(), st.booleans()))
    return WifiApplyPreState(
        known=draw(st.booleans()),
        had_ssid=draw(st.booleans()),
        had_psk=had_psk,
        encryption_enabled=draw(st.booleans()),
        had_wpa2=draw(st.booleans()),
        had_wpa3=draw(st.booleans()),
        was_admin_up=draw(st.booleans()),
    )


@given(payload=wifi_intent_strategy(), pre_state=wifi_pre_state_strategy())
@_PROP
def test_wifi_ap_compensation_respects_pre_state_blocked_ops(
    payload: tuple[WifiIntent, str],
    pre_state: WifiApplyPreState,
) -> None:
    intent, ap_id = payload
    assume(not intent.enabled or intent.credential_ref_id is not None)
    plan = compile_wifi_intent_to_ops(intent, ap_id)
    if not plan.apply_ops:
        return
    _assert_compensation_reverses_succeeded_apply(
        plan.apply_ops,
        compensate_ops_for_succeeded_apply,
        _WIFI_AP_APPLY_TO_COMPENSATE,
        pre_state=pre_state,
        is_blocked=lambda op: _wifi_ap_compensation_blocked(op, pre_state),
    )


@given(intent=wireguard_intent_strategy())
@_PROP
def test_wireguard_teardown_is_reverse_of_apply(intent: WireguardIntent) -> None:
    assume(intent.peer_rci_shape is not WireguardPeerRciShape.PATH_STYLE)
    assume(intent.asc_args is None or len(intent.asc_args) == 9)
    plan = compile_wireguard_intent_to_ops(intent)
    _assert_wireguard_teardown_reverses_apply(plan.apply_ops, plan.teardown_ops)


@given(payload=station_plan_input_strategy())
@_PROP
def test_wifi_station_teardown_reverses_mapped_apply(
    payload: tuple[UplinkIntent, WifiStationPlannerOptions],
) -> None:
    intent, options = payload
    plan = compile_uplink_intent_to_station_ops(intent, options=options)
    _assert_teardown_reverses_mapped_apply(
        plan.apply_ops,
        plan.teardown_ops,
        _WIFI_STATION_APPLY_TO_COMPENSATE,
    )


@given(payload=station_plan_input_strategy())
@_PROP
def test_wifi_station_compensation_reverses_succeeded_apply(
    payload: tuple[UplinkIntent, WifiStationPlannerOptions],
) -> None:
    intent, options = payload
    plan = compile_uplink_intent_to_station_ops(intent, options=options)
    _assert_compensation_reverses_succeeded_apply(
        plan.apply_ops,
        compensate_ops_for_succeeded_station_apply,
        _WIFI_STATION_APPLY_TO_COMPENSATE,
    )


@st.composite
def station_pre_state_strategy(draw: st.DrawFn) -> WifiStationApplyPreState:
    had_psk = draw(st.one_of(st.none(), st.booleans()))
    had_dhcp = draw(st.one_of(st.none(), st.booleans()))
    return WifiStationApplyPreState(
        known=draw(st.booleans()),
        had_ssid=draw(st.booleans()),
        had_psk=had_psk,
        encryption_enabled=draw(st.booleans()),
        had_wpa2=draw(st.booleans()),
        was_admin_up=draw(st.booleans()),
        had_dhcp_client=had_dhcp,
    )


@given(payload=station_plan_input_strategy(), pre_state=station_pre_state_strategy())
@_PROP
def test_wifi_station_compensation_respects_pre_state_blocked_ops(
    payload: tuple[UplinkIntent, WifiStationPlannerOptions],
    pre_state: WifiStationApplyPreState,
) -> None:
    intent, options = payload
    plan = compile_uplink_intent_to_station_ops(intent, options=options)
    _assert_compensation_reverses_succeeded_apply(
        plan.apply_ops,
        compensate_ops_for_succeeded_station_apply,
        _WIFI_STATION_APPLY_TO_COMPENSATE,
        pre_state=pre_state,
        is_blocked=lambda op: _wifi_station_compensation_blocked(op, pre_state),
    )


@given(intent=dhcp_intent_strategy())
@_PROP
def test_dhcp_teardown_reverses_bind_and_pool(intent: dict[str, Any]) -> None:
    plan = compile_dhcp_intent_to_ops(intent)
    mapping = {
        DhcpRciOperation.SET_POOL.value: DhcpRciOperation.CLEAR_POOL.value,
        DhcpRciOperation.BIND_HOST.value: DhcpRciOperation.UNBIND_HOST.value,
    }
    _assert_teardown_reverses_mapped_apply(plan.apply_ops, plan.teardown_ops, mapping)


@given(intent=dns_intent_strategy())
@_PROP
def test_dns_teardown_reverses_upstream_and_static_host(intent: dict[str, Any]) -> None:
    plan = compile_dns_intent_to_ops(intent)
    mapping = {
        DnsRciOperation.SET_STATIC_HOST.value: DnsRciOperation.CLEAR_STATIC_HOST.value,
        DnsRciOperation.SET_UPSTREAM.value: DnsRciOperation.CLEAR_UPSTREAM.value,
    }
    _assert_teardown_reverses_mapped_apply(plan.apply_ops, plan.teardown_ops, mapping)


@given(intent=firewall_intent_strategy())
@_PROP
def test_firewall_teardown_reverses_rules(intent: dict[str, Any]) -> None:
    plan = compile_firewall_intent_to_ops(intent)
    mapping = {
        FirewallRciOperation.ADD_RULE.value: FirewallRciOperation.REMOVE_RULE.value,
    }
    _assert_teardown_reverses_mapped_apply(plan.apply_ops, plan.teardown_ops, mapping)


@given(payload=vlan_intent_strategy())
@_PROP
def test_vlan_teardown_reverses_apply(payload: tuple[dict[str, Any], str]) -> None:
    intent, bridge_id = payload
    plan = compile_vlan_intent_to_ops(intent, bridge_id)
    mapping = {
        VlanRciOperation.CREATE_BRIDGE.value: VlanRciOperation.REMOVE_BRIDGE.value,
        VlanRciOperation.SET_IP_ADDRESS.value: VlanRciOperation.CLEAR_IP_ADDRESS.value,
        VlanRciOperation.UP.value: VlanRciOperation.DOWN.value,
    }
    _assert_teardown_reverses_mapped_apply(plan.apply_ops, plan.teardown_ops, mapping)


@given(payload=vlan_intent_strategy())
@_PROP
def test_vlan_compensation_reverses_succeeded_apply(payload: tuple[dict[str, Any], str]) -> None:
    intent, bridge_id = payload
    plan = compile_vlan_intent_to_ops(intent, bridge_id)
    if not plan.apply_ops:
        return
    _assert_compensation_reverses_succeeded_apply(
        plan.apply_ops,
        compensate_ops_for_succeeded_vlan_apply,
        _VLAN_APPLY_TO_COMPENSATE,
    )


@st.composite
def vlan_pre_state_strategy(draw: st.DrawFn) -> VlanApplyPreState:
    return VlanApplyPreState(
        known=draw(st.booleans()),
        bridge_existed=draw(st.one_of(st.none(), st.booleans())),
        had_ip=draw(st.one_of(st.none(), st.booleans())),
        was_admin_up=draw(st.one_of(st.none(), st.booleans())),
    )


@given(payload=vlan_intent_strategy(), pre_state=vlan_pre_state_strategy())
@_PROP
def test_vlan_compensation_respects_pre_state_blocked_ops(
    payload: tuple[dict[str, Any], str],
    pre_state: VlanApplyPreState,
) -> None:
    intent, bridge_id = payload
    plan = compile_vlan_intent_to_ops(intent, bridge_id)
    if not plan.apply_ops:
        return
    _assert_compensation_reverses_succeeded_apply(
        plan.apply_ops,
        compensate_ops_for_succeeded_vlan_apply,
        _VLAN_APPLY_TO_COMPENSATE,
        pre_state=pre_state,
        is_blocked=lambda op: _vlan_compensation_blocked(op, pre_state),
    )


@given(intent=dhcp_intent_strategy())
@_PROP
def test_dhcp_compensation_reverses_succeeded_apply(intent: dict[str, Any]) -> None:
    plan = compile_dhcp_intent_to_ops(intent)
    _assert_compensation_reverses_succeeded_apply(
        plan.apply_ops,
        compensate_ops_for_succeeded_dhcp_apply,
        _DHCP_APPLY_TO_COMPENSATE,
        verify_compensate_pair=_verify_dhcp_compensate_pair,
    )


@st.composite
def dhcp_pre_state_strategy(draw: st.DrawFn) -> DhcpApplyPreState:
    return DhcpApplyPreState(
        known=draw(st.booleans()),
        pool_existed=draw(st.one_of(st.none(), st.booleans())),
        had_lease=draw(st.one_of(st.none(), st.booleans())),
        had_reservations=draw(st.one_of(st.none(), st.booleans())),
    )


@given(intent=dhcp_intent_strategy(), pre_state=dhcp_pre_state_strategy())
@_PROP
def test_dhcp_compensation_respects_pre_state_blocked_ops(
    intent: dict[str, Any],
    pre_state: DhcpApplyPreState,
) -> None:
    plan = compile_dhcp_intent_to_ops(intent)
    _assert_compensation_reverses_succeeded_apply(
        plan.apply_ops,
        compensate_ops_for_succeeded_dhcp_apply,
        _DHCP_APPLY_TO_COMPENSATE,
        pre_state=pre_state,
        is_blocked=lambda op: _dhcp_compensation_blocked(op, pre_state),
        verify_compensate_pair=_verify_dhcp_compensate_pair,
    )


@given(intent=dns_intent_strategy())
@_PROP
def test_dns_compensation_reverses_succeeded_apply(intent: dict[str, Any]) -> None:
    plan = compile_dns_intent_to_ops(intent)
    _assert_compensation_reverses_succeeded_apply(
        plan.apply_ops,
        compensate_ops_for_succeeded_dns_apply,
        _DNS_APPLY_TO_COMPENSATE,
        verify_compensate_pair=_verify_dns_compensate_pair,
    )


@st.composite
def dns_pre_state_strategy(draw: st.DrawFn) -> DnsApplyPreState:
    return DnsApplyPreState(
        known=draw(st.booleans()),
        had_static_host=draw(st.one_of(st.none(), st.booleans())),
        had_upstreams=draw(st.one_of(st.none(), st.booleans())),
    )


@given(intent=dns_intent_strategy(), pre_state=dns_pre_state_strategy())
@_PROP
def test_dns_compensation_respects_pre_state_blocked_ops(
    intent: dict[str, Any],
    pre_state: DnsApplyPreState,
) -> None:
    plan = compile_dns_intent_to_ops(intent)
    _assert_compensation_reverses_succeeded_apply(
        plan.apply_ops,
        compensate_ops_for_succeeded_dns_apply,
        _DNS_APPLY_TO_COMPENSATE,
        pre_state=pre_state,
        is_blocked=lambda op: _dns_compensation_blocked(op, pre_state),
        verify_compensate_pair=_verify_dns_compensate_pair,
    )


@given(intent=firewall_intent_strategy())
@_PROP
def test_firewall_compensation_reverses_succeeded_apply(intent: dict[str, Any]) -> None:
    plan = compile_firewall_intent_to_ops(intent)
    _assert_compensation_reverses_succeeded_apply(
        plan.apply_ops,
        compensate_ops_for_succeeded_firewall_apply,
        _FIREWALL_APPLY_TO_COMPENSATE,
        verify_compensate_pair=_verify_firewall_compensate_pair,
    )


@st.composite
def firewall_pre_state_strategy(draw: st.DrawFn) -> FirewallApplyPreState:
    return FirewallApplyPreState(
        known=draw(st.booleans()),
        had_rules=draw(st.one_of(st.none(), st.booleans())),
    )


@given(intent=firewall_intent_strategy(), pre_state=firewall_pre_state_strategy())
@_PROP
def test_firewall_compensation_respects_pre_state_blocked_ops(
    intent: dict[str, Any],
    pre_state: FirewallApplyPreState,
) -> None:
    plan = compile_firewall_intent_to_ops(intent)
    _assert_compensation_reverses_succeeded_apply(
        plan.apply_ops,
        compensate_ops_for_succeeded_firewall_apply,
        _FIREWALL_APPLY_TO_COMPENSATE,
        pre_state=pre_state,
        is_blocked=lambda op: _firewall_compensation_blocked(op, pre_state),
        verify_compensate_pair=_verify_firewall_compensate_pair,
    )


@given(intent=vpn_policy_intent_strategy())
@_PROP
def test_vpn_policy_compensation_reverses_succeeded_apply(intent: dict[str, Any]) -> None:
    plan = compile_vpn_policy_routing_intent(intent)
    _assert_compensation_reverses_succeeded_apply(
        plan.apply_ops,
        compensate_ops_for_succeeded_vpn_policy_apply,
        _VPN_POLICY_APPLY_TO_COMPENSATE,
        verify_compensate_pair=_verify_vpn_policy_compensate_pair,
    )


@st.composite
def vpn_policy_pre_state_strategy(draw: st.DrawFn) -> VpnPolicyApplyPreState:
    return VpnPolicyApplyPreState(
        known=draw(st.booleans()),
        policy_existed=draw(st.one_of(st.none(), st.booleans())),
        had_name_servers=draw(st.one_of(st.none(), st.booleans())),
        had_ip_global=draw(st.one_of(st.none(), st.booleans())),
    )


@given(intent=vpn_policy_intent_strategy(), pre_state=vpn_policy_pre_state_strategy())
@_PROP
def test_vpn_policy_compensation_respects_pre_state_blocked_ops(
    intent: dict[str, Any],
    pre_state: VpnPolicyApplyPreState,
) -> None:
    plan = compile_vpn_policy_routing_intent(intent)
    _assert_compensation_reverses_succeeded_apply(
        plan.apply_ops,
        compensate_ops_for_succeeded_vpn_policy_apply,
        _VPN_POLICY_APPLY_TO_COMPENSATE,
        pre_state=pre_state,
        is_blocked=lambda op: _vpn_policy_compensation_blocked(op, pre_state),
        verify_compensate_pair=_verify_vpn_policy_compensate_pair,
    )


@given(intent=vpn_policy_intent_strategy())
@_PROP
def test_vpn_policy_teardown_reverses_apply(intent: dict[str, Any]) -> None:
    plan = compile_vpn_policy_routing_intent(intent)
    mapping = {
        VpnPolicyRciOperation.SET_NAME_SERVER.value: VpnPolicyRciOperation.CLEAR_NAME_SERVER.value,
        VpnPolicyRciOperation.CREATE_POLICY.value: VpnPolicyRciOperation.REMOVE_POLICY.value,
    }
    _assert_teardown_reverses_mapped_apply(plan.apply_ops, plan.teardown_ops, mapping)


@given(intent=vpn_policy_intent_strategy())
@_PROP
def test_vpn_policy_ops_have_grammar_source(intent: dict[str, Any]) -> None:
    plan = compile_vpn_policy_routing_intent(intent)
    _assert_strict_grammar_ops(plan.apply_ops, "vpn_policy")
    _assert_strict_grammar_ops(plan.teardown_ops, "vpn_policy")


@given(intent=dhcp_intent_strategy())
@_PROP
def test_dhcp_ops_have_grammar_source(intent: dict[str, Any]) -> None:
    plan = compile_dhcp_intent_to_ops(intent)
    _assert_strict_grammar_ops(plan.apply_ops, "dhcp")
    _assert_strict_grammar_ops(plan.teardown_ops, "dhcp")


@given(intent=dns_intent_strategy())
@_PROP
def test_dns_ops_have_grammar_source(intent: dict[str, Any]) -> None:
    plan = compile_dns_intent_to_ops(intent)
    _assert_strict_grammar_ops(plan.apply_ops, "dns")
    _assert_strict_grammar_ops(plan.teardown_ops, "dns")


@given(intent=firewall_intent_strategy())
@_PROP
def test_firewall_ops_have_grammar_source(intent: dict[str, Any]) -> None:
    plan = compile_firewall_intent_to_ops(intent)
    _assert_strict_grammar_ops(plan.apply_ops, "firewall")
    _assert_strict_grammar_ops(plan.teardown_ops, "firewall")


@given(payload=vlan_intent_strategy())
@_PROP
def test_vlan_ops_have_grammar_source(payload: tuple[dict[str, Any], str]) -> None:
    intent, bridge_id = payload
    plan = compile_vlan_intent_to_ops(intent, bridge_id)
    _assert_strict_grammar_ops(plan.apply_ops, "vlan")
    _assert_strict_grammar_ops(plan.teardown_ops, "vlan")


@given(payload=wifi_intent_strategy())
@_PROP
def test_wifi_ap_ops_stay_in_allowlist(payload: tuple[WifiIntent, str]) -> None:
    intent, ap_id = payload
    assume(not intent.enabled or intent.credential_ref_id is not None)
    plan = compile_wifi_intent_to_ops(intent, ap_id)
    _assert_ops_in_allowlist(plan.apply_ops, _WIFI_AP_OPS, "wifi_ap")
    _assert_ops_in_allowlist(plan.teardown_ops, _WIFI_AP_OPS, "wifi_ap")


@given(payload=station_plan_input_strategy())
@_PROP
def test_wifi_station_ops_stay_in_allowlist(
    payload: tuple[UplinkIntent, WifiStationPlannerOptions],
) -> None:
    intent, options = payload
    plan = compile_uplink_intent_to_station_ops(intent, options=options)
    _assert_ops_in_allowlist(plan.apply_ops, _WIFI_STATION_OPS, "wifi_station")
    _assert_ops_in_allowlist(plan.teardown_ops, _WIFI_STATION_OPS, "wifi_station")


@given(intent=wireguard_intent_strategy())
@_PROP
def test_wireguard_ops_stay_in_allowlist(intent: WireguardIntent) -> None:
    assume(intent.asc_args is None or len(intent.asc_args) == 9)
    assume(intent.peer_rci_shape is not WireguardPeerRciShape.PATH_STYLE)
    plan = compile_wireguard_intent_to_ops(intent)
    _assert_ops_in_allowlist(plan.apply_ops, _WIREGUARD_OPS, "wireguard")
    _assert_ops_in_allowlist(plan.teardown_ops, _WIREGUARD_OPS, "wireguard")
    for op in plan.apply_ops + plan.teardown_ops:
        assert op.operation not in _FORBIDDEN_WG_OPS


@given(intent=dhcp_intent_strategy())
@_PROP
def test_dhcp_ops_stay_in_allowlist(intent: dict[str, Any]) -> None:
    plan = compile_dhcp_intent_to_ops(intent)
    _assert_ops_in_allowlist(plan.apply_ops, _DHCP_OPS, "dhcp")
    _assert_ops_in_allowlist(plan.teardown_ops, _DHCP_OPS, "dhcp")


@given(intent=dns_intent_strategy())
@_PROP
def test_dns_ops_stay_in_allowlist(intent: dict[str, Any]) -> None:
    plan = compile_dns_intent_to_ops(intent)
    _assert_ops_in_allowlist(plan.apply_ops, _DNS_OPS, "dns")
    _assert_ops_in_allowlist(plan.teardown_ops, _DNS_OPS, "dns")


@given(intent=firewall_intent_strategy())
@_PROP
def test_firewall_ops_stay_in_allowlist(intent: dict[str, Any]) -> None:
    plan = compile_firewall_intent_to_ops(intent)
    _assert_ops_in_allowlist(plan.apply_ops, _FIREWALL_OPS, "firewall")
    _assert_ops_in_allowlist(plan.teardown_ops, _FIREWALL_OPS, "firewall")


@given(payload=vlan_intent_strategy())
@_PROP
def test_vlan_ops_stay_in_allowlist(payload: tuple[dict[str, Any], str]) -> None:
    intent, bridge_id = payload
    plan = compile_vlan_intent_to_ops(intent, bridge_id)
    _assert_ops_in_allowlist(plan.apply_ops, _VLAN_OPS, "vlan")
    _assert_ops_in_allowlist(plan.teardown_ops, _VLAN_OPS, "vlan")


@given(intent=vpn_policy_intent_strategy())
@_PROP
def test_vpn_policy_ops_stay_in_allowlist(intent: dict[str, Any]) -> None:
    plan = compile_vpn_policy_routing_intent(intent)
    _assert_ops_in_allowlist(plan.apply_ops, _VPN_POLICY_OPS, "vpn_policy")
    _assert_ops_in_allowlist(plan.teardown_ops, _VPN_POLICY_OPS, "vpn_policy")
    assert all(
        "permit_global" not in op.operation and "permit-global" not in op.operation
        for op in plan.apply_ops + plan.teardown_ops
    )


@given(payload=wifi_intent_strategy())
@_PROP
def test_wifi_ap_compilation_is_deterministic(payload: tuple[WifiIntent, str]) -> None:
    intent, ap_id = payload
    assume(not intent.enabled or intent.credential_ref_id is not None)
    first = preview_wifi_apply(intent, ap_id)
    second = preview_wifi_apply(intent, ap_id)
    assert first == second


@given(intent=wireguard_intent_strategy())
@_PROP
def test_wireguard_compilation_is_deterministic(intent: WireguardIntent) -> None:
    assume(intent.asc_args is None or len(intent.asc_args) == 9)
    first = preview_wireguard_apply(intent)
    second = preview_wireguard_apply(intent)
    assert first == second


@given(intent=dhcp_intent_strategy())
@_PROP
def test_dhcp_compilation_is_deterministic(intent: dict[str, Any]) -> None:
    assert preview_dhcp_apply(intent) == preview_dhcp_apply(intent)


@given(intent=vpn_policy_intent_strategy())
@_PROP
def test_vpn_policy_compilation_is_deterministic(intent: dict[str, Any]) -> None:
    assert preview_vpn_policy_routing(intent) == preview_vpn_policy_routing(intent)


@given(intent=wireguard_intent_strategy())
@_PROP
def test_wireguard_verification_status_respects_secret_ops(intent: WireguardIntent) -> None:
    assume(intent.asc_args is None or len(intent.asc_args) == 9)
    plan = compile_wireguard_intent_to_ops(intent)
    if intent.has_secret_ops:
        assert plan.verification_status == "pending_live_verification"
    elif plan.apply_ops or plan.teardown_ops:
        assert plan.verification_status == "device_verified_asc9"


@given(intent=dhcp_intent_strategy())
@_PROP
def test_offline_planners_never_claim_device_verified(intent: dict[str, Any]) -> None:
    for preview in (
        preview_dhcp_apply(intent),
        preview_dns_apply(
            {
                "zone_id": intent["zone_id"],
                "local_fqdn": "host.example.test",
                "upstream_resolvers": ["1.1.1.1"],
            }
        ),
        preview_firewall_apply(
            {
                "zone_id": intent["zone_id"],
                "rules": [
                    {
                        "action": "Allow",
                        "destination_family": "Dns",
                        "ordinal": 10,
                    }
                ],
            }
        ),
    ):
        status = str(preview["verification_status"])
        assert not status.startswith(_DEVICE_VERIFIED_PREFIX)


@given(intent=vpn_policy_intent_strategy())
@_PROP
def test_vpn_policy_never_claims_device_verified(intent: dict[str, Any]) -> None:
    preview = preview_vpn_policy_routing(intent)
    status = str(preview["verification_status"])
    assert status == "help_verified_grammar_unapplied"
    assert not status.startswith(_DEVICE_VERIFIED_PREFIX)


@given(payload=station_intent_strategy())
@_PROP
def test_wifi_station_rejects_open_and_captive(payload: UplinkIntent) -> None:
    with pytest.raises(WifiStationApplyPlannerError):
        compile_uplink_intent_to_station_ops(
            payload,
            options=WifiStationPlannerOptions(auth_mode=WifiStationAuthMode.OPEN),
        )
    captive = UplinkIntent(
        mode=payload.mode,
        ssid=payload.ssid,
        band=payload.band,
        credential_ref_id=payload.credential_ref_id,
        priority=payload.priority,
        captive_portal_client=True,
    )
    with pytest.raises(WifiStationApplyPlannerError):
        compile_uplink_intent_to_station_ops(captive)


@given(payload=station_invalid_priority_ip_global_strategy())
@_PROP
def test_wifi_station_non_default_priority_without_ip_global_rejected(
    payload: tuple[UplinkIntent, WifiStationPlannerOptions],
) -> None:
    intent, options = payload
    with pytest.raises(
        WifiStationApplyPlannerError,
        match=ERROR_CODE_STATION_PRIORITY_REQUIRES_IP_GLOBAL,
    ):
        compile_uplink_intent_to_station_ops(intent, options=options)


@given(payload=station_include_ip_global_strategy())
@_PROP
def test_wifi_station_include_ip_global_propagates_priority(
    payload: tuple[UplinkIntent, WifiStationPlannerOptions],
) -> None:
    intent, options = payload
    plan = compile_uplink_intent_to_station_ops(intent, options=options)
    ip_global_ops = [
        op for op in plan.apply_ops if op.operation == WifiStationRciOperation.IP_GLOBAL.value
    ]
    assert len(ip_global_ops) == 1
    assert ip_global_ops[0].priority == intent.priority


@given(intent=wireguard_intent_strategy())
@_PROP
def test_wireguard_rejects_ipv6_allow_ips(intent: WireguardIntent) -> None:
    ipv6_intent = WireguardIntent(
        wg_id=intent.wg_id,
        enabled=intent.enabled,
        asc_args=intent.asc_args,
        peer_public_key=intent.peer_public_key or "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
        peer_allow_ips="0.0.0.0/0, ::/0",
    )
    with pytest.raises(WireguardApplyPlannerError):
        compile_wireguard_intent_to_ops(ipv6_intent)


@given(intent=wireguard_intent_strategy())
@_PROP
def test_wireguard_rejects_path_style_peer(intent: WireguardIntent) -> None:
    path_style = WireguardIntent(
        wg_id=intent.wg_id,
        enabled=intent.enabled,
        asc_args=intent.asc_args,
        peer_rci_shape=WireguardPeerRciShape.PATH_STYLE,
        peer_public_key="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
    )
    plan = compile_wireguard_intent_to_ops(path_style)
    assert plan.apply_ops == ()
    assert plan.teardown_ops == ()
    assert plan.verification_status == "unsupported"
    assert WireguardRciOperation.ADD_PEER.value not in [
        op.operation for op in plan.apply_ops
    ]


@given(payload=wifi_intent_strategy())
@_PROP
def test_wifi_ap_ops_have_grammar_source(payload: tuple[WifiIntent, str]) -> None:
    intent, ap_id = payload
    assume(not intent.enabled or intent.credential_ref_id is not None)
    plan = compile_wifi_intent_to_ops(intent, ap_id)
    _assert_strict_grammar_ops(plan.apply_ops, "wifi_ap")
    _assert_strict_grammar_ops(plan.teardown_ops, "wifi_ap")


@given(payload=station_plan_input_strategy())
@_PROP
def test_wifi_station_ops_have_grammar_source(
    payload: tuple[UplinkIntent, WifiStationPlannerOptions],
) -> None:
    intent, options = payload
    plan = compile_uplink_intent_to_station_ops(intent, options=options)
    _assert_strict_grammar_ops(plan.apply_ops, "wifi_station")
    _assert_strict_grammar_ops(plan.teardown_ops, "wifi_station")


@given(intent=wireguard_intent_strategy())
@_PROP
def test_wireguard_ops_have_grammar_source(intent: WireguardIntent) -> None:
    assume(intent.asc_args is None or len(intent.asc_args) == 9)
    assume(intent.peer_rci_shape is not WireguardPeerRciShape.PATH_STYLE)
    plan = compile_wireguard_intent_to_ops(intent)
    _assert_strict_grammar_ops(plan.apply_ops, "wireguard")
    _assert_strict_grammar_ops(plan.teardown_ops, "wireguard")


def test_proof_grammar_source_property_is_not_tautological() -> None:
    """Breaking grammar-note enforcement must fail the property helper."""
    class _Op:
        notes: tuple[str, ...] = ()

        def __init__(self, operation: str) -> None:
            self.operation = operation

    with pytest.raises(AssertionError, match="grammar-source notes"):
        _assert_strict_grammar_ops([_Op("wifi_ap_set_ssid")], "wifi_ap")


def test_proof_allowlist_property_is_not_tautological() -> None:
    """Breaking allowlist enforcement must fail the property test."""
    intent = compile_dhcp_intent_to_ops(
        {
            "zone_id": "Guest",
            "pool_start": "10.10.0.100",
            "pool_end": "10.10.0.200",
            "lease_seconds": 86400,
            "reservations": [],
        }
    )
    poisoned = list(intent.apply_ops)
    poisoned[0] = type(intent.apply_ops[0])(
        **{
            f.name: getattr(poisoned[0], f.name)
            for f in fields(poisoned[0])
            if f.name != "operation"
        },
        operation="dhcp_invented_op",
    )
    with pytest.raises(AssertionError, match="non-allowlisted"):
        _assert_ops_in_allowlist(poisoned, _DHCP_OPS, "dhcp")


def test_proof_preview_secret_property_is_not_tautological() -> None:
    preview = preview_wifi_apply(
        WifiIntent(
            ssid="Staff",
            enabled=True,
            credential_ref_id="credref:safe-ref",
            captive_portal=CaptivePortalMode.DISABLED,
            guest_isolation=False,
        ),
        "WifiMaster0/AccessPoint3",
    )
    leaked = dict(preview)
    leaked["passphrase"] = "LEAK-MARKER-WIFI-AP-PLAINTEXT-SECRET"
    with pytest.raises(AssertionError):
        _assert_preview_has_no_plaintext_secrets(
            leaked,
            leak_marker="LEAK-MARKER-WIFI-AP-PLAINTEXT-SECRET",
        )


def test_proof_teardown_reverse_property_is_not_tautological() -> None:
    class _Op:
        def __init__(self, operation: str) -> None:
            self.operation = operation

    apply_ops = [_Op(DhcpRciOperation.BIND_HOST.value)]
    teardown_ops = [_Op(DhcpRciOperation.CLEAR_POOL.value)]
    with pytest.raises(AssertionError):
        _assert_teardown_reverses_mapped_apply(
            apply_ops,
            teardown_ops,
            {DhcpRciOperation.BIND_HOST.value: DhcpRciOperation.UNBIND_HOST.value},
        )


def test_proof_compensation_reverse_property_is_not_tautological() -> None:
    class _Op:
        def __init__(self, operation: str) -> None:
            self.operation = operation

    apply_ops = [
        _Op(WifiApRciOperation.SET_SSID.value),
        _Op(WifiApRciOperation.UP.value),
    ]

    def _broken_compensate(
        _apply: tuple[Any, ...],
        succeeded: tuple[str, ...],
        _pre_state: Any | None = None,
    ) -> tuple[_Op, ...]:
        # Wrong order: CLEAR_SSID before DOWN (should be reverse apply order).
        return (
            _Op(WifiApRciOperation.CLEAR_SSID.value),
            _Op(WifiApRciOperation.DOWN.value),
        )

    with pytest.raises(AssertionError):
        _assert_compensation_reverses_succeeded_apply(
            apply_ops,
            _broken_compensate,
            _WIFI_AP_APPLY_TO_COMPENSATE,
        )


@pytest.mark.parametrize("seed", [0, 1, 42, 99, 12345, 99999])
def test_planner_property_suite_stable_across_hypothesis_seeds(seed: int) -> None:
    """Multi-seed smoke: compensation/teardown properties must not flake on seed choice."""
    from hypothesis import Phase
    from hypothesis import seed as hypothesis_seed

    @hypothesis_seed(seed)
    @given(payload=wifi_intent_strategy())
    @settings(max_examples=4, deadline=None, phases=[Phase.generate])
    def _wifi_ap(payload: tuple[WifiIntent, str]) -> None:
        intent, ap_id = payload
        assume(not intent.enabled or intent.credential_ref_id is not None)
        plan = compile_wifi_intent_to_ops(intent, ap_id)
        if plan.apply_ops:
            _assert_teardown_reverses_mapped_apply(
                plan.apply_ops,
                plan.teardown_ops,
                _WIFI_AP_APPLY_TO_COMPENSATE,
            )
            _assert_compensation_reverses_succeeded_apply(
                plan.apply_ops,
                compensate_ops_for_succeeded_apply,
                _WIFI_AP_APPLY_TO_COMPENSATE,
            )

    @hypothesis_seed(seed)
    @given(payload=station_plan_input_strategy())
    @settings(max_examples=4, deadline=None, phases=[Phase.generate])
    def _wifi_station(payload: tuple[UplinkIntent, WifiStationPlannerOptions]) -> None:
        intent, options = payload
        plan = compile_uplink_intent_to_station_ops(intent, options=options)
        _assert_teardown_reverses_mapped_apply(
            plan.apply_ops,
            plan.teardown_ops,
            _WIFI_STATION_APPLY_TO_COMPENSATE,
        )
        _assert_compensation_reverses_succeeded_apply(
            plan.apply_ops,
            compensate_ops_for_succeeded_station_apply,
            _WIFI_STATION_APPLY_TO_COMPENSATE,
        )

    _wifi_ap()
    _wifi_station()


def test_apply_response_verification_status_literals_match_code() -> None:
    """Contract guard: closed Literal enums must cover planner-emitted values."""
    from router_control_host.apply_response_models import (
        GrammarVerificationStatus,
        VpnPolicyPreviewVerificationStatus,
        WifiApRciErrorCategoryLiteral,
        WifiPreviewVerificationStatus,
        WireguardPlanVerificationStatus,
    )

    wifi_preview_values = frozenset(get_args(WifiPreviewVerificationStatus))
    assert "device_verified_wpa2" in wifi_preview_values

    wg_values = frozenset(get_args(WireguardPlanVerificationStatus))
    assert wg_values == frozenset(
        {
            "device_verified_asc9",
            "pending_live_verification",
            "unsupported_pending_verification",
            "unsupported",
        }
    )

    grammar_values = frozenset(get_args(GrammarVerificationStatus))
    assert grammar_values == frozenset({"device_accepted_grammar"})

    vpn_values = frozenset(get_args(VpnPolicyPreviewVerificationStatus))
    assert vpn_values == frozenset({"help_verified_grammar_unapplied"})

    error_values = frozenset(get_args(WifiApRciErrorCategoryLiteral))
    assert error_values == frozenset(
        {
            "unsupported_grammar",
            "rejected_by_router",
            "auth_or_permission",
            "resource_not_found",
            "transport_or_timeout",
            "unknown",
        }
    )


def test_proof_apply_response_verification_literal_contract_is_not_tautological() -> None:
    from router_control_host.apply_response_models import GrammarVerificationStatus

    allowed = frozenset(get_args(GrammarVerificationStatus))
    assert "device_accepted_grammar" in allowed
    assert "invented_status" not in allowed


def test_wifi_ap_grammar_doc_anchor_refs_resolve() -> None:
    from router_control.application.grammar_doc_refs import (
        _WIFI_SSID_SECTION,
        _WIFI_WPA_SECTION,
        GrammarDocRef,
        verify_grammar_doc_ref,
    )

    assert verify_grammar_doc_ref(_WIFI_SSID_SECTION)
    assert verify_grammar_doc_ref(_WIFI_WPA_SECTION)
    assert verify_grammar_doc_ref(
        GrammarDocRef(_WIFI_SSID_SECTION.path, _WIFI_SSID_SECTION.anchor, "no ssid")
    )
    assert verify_grammar_doc_ref(
        GrammarDocRef(_WIFI_WPA_SECTION.path, _WIFI_WPA_SECTION.anchor, "no encryption wpa2")
    )


def test_wifi_ap_wpa3_clear_note_is_not_false_doc_line_citation() -> None:
    from router_control.adapters.netcraze.wifi_rci import WifiApRciOperation
    from router_control.application.wifi_apply_planner import _wifi_ap_op_notes

    notes = _wifi_ap_op_notes(WifiApRciOperation.ENCRYPTION_WPA3_CLEAR)
    joined = " ".join(notes)
    assert "OPERATOR_WIFI_DISCOVERY.md:244" not in joined
    assert "wifi-wpa3-live-reverify-192.168.2.1-20260724.json" in joined
    assert "wifi_ap_encryption_wpa3_clear" in joined


def test_station_clear_ip_notes_cite_probe_evidence_not_teardown_row() -> None:
    from router_control.adapters.netcraze.wifi_station_rci import WifiStationRciOperation
    from router_control.application.wifi_station_apply_planner import _wifi_station_op_notes

    for op in (
        WifiStationRciOperation.CLEAR_IP_ADDRESS_DHCP,
        WifiStationRciOperation.CLEAR_IP_ADDRESS,
    ):
        joined = " ".join(_wifi_station_op_notes(op))
        assert ":87" not in joined
        assert "docs/OPERATOR_WIFI_DISCOVERY.md#" in joined
        assert "no ip address" in joined.lower()


def _compiled_planner_ops_for_property_test() -> list[tuple[str, Any]]:
    from router_control.application.dhcp_apply_planner import compile_dhcp_intent_to_ops
    from router_control.application.dns_apply_planner import compile_dns_intent_to_ops
    from router_control.application.firewall_apply_planner import compile_firewall_intent_to_ops
    from router_control.application.vlan_apply_planner import compile_vlan_intent_to_ops
    from router_control.application.vpn_policy_routing_planner import (
        compile_vpn_policy_routing_intent,
    )
    from router_control.application.wifi_apply_planner import compile_wifi_intent_to_ops
    from router_control.application.wifi_station_apply_planner import (
        compile_uplink_intent_to_station_ops,
    )
    from router_control.application.wireguard_apply_planner import compile_wireguard_intent_to_ops
    from router_control.domain.network_intents import (
        CaptivePortalMode,
        UplinkIntent,
        UplinkMode,
        WifiBand,
        WifiIntent,
        WifiWpaMode,
        WireguardIntent,
    )

    wifi_intent = WifiIntent(
        ssid="PropTest",
        enabled=True,
        credential_ref_id="cred-wifi-1",
        captive_portal=CaptivePortalMode.DISABLED,
        guest_isolation=False,
        wpa_mode=WifiWpaMode.WPA2,
        band=WifiBand.BAND_2_4GHZ,
    )
    station_intent = UplinkIntent(
        mode=UplinkMode.WIFI_WAN,
        ssid="PropStation",
        band=WifiBand.BAND_5GHZ,
        credential_ref_id="cred-station-1",
        priority=100,
        captive_portal_client=False,
    )
    wg_intent = WireguardIntent(
        wg_id="Wireguard5",
        enabled=True,
        asc_args=(1, 2, 3, 4, 5, 6, 7, 8, 9),
        peer_public_key="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
        peer_endpoint="vpn.example.com:51820",
        private_key_credential_ref_id="cred-wg-1",
    )
    vpn_intent = {
        "policy_name": "PropPolicy",
        "vpn_interface": "Wireguard5",
        "ip_global": {"priority": 100},
        "interface_kind": "wireguard",
        "address_configured": True,
    }
    vlan_intent = {
        "zone_id": "zone-prop",
        "vlan_id": 20,
        "ipv4_cidr": "10.20.0.0/24",
        "ipv4_gateway": "10.20.0.1",
    }
    dhcp_intent = {
        "zone_id": "zone-prop",
        "pool_start": "10.20.0.50",
        "pool_end": "10.20.0.100",
        "lease_seconds": 3600,
        "reservations": [{"mac_address": "aa:bb:cc:00:00:01", "ipv4_address": "10.20.0.51"}],
    }
    dns_intent = {
        "zone_id": "zone-prop",
        "local_fqdn": "host.example.com",
        "upstream_resolvers": ["8.8.8.8"],
    }
    fw_intent = {
        "zone_id": "Guest",
        "rules": [{"action": "Allow", "destination_family": "Internet", "ordinal": 1}],
    }

    families: list[tuple[str, Any]] = []
    wifi_plan = compile_wifi_intent_to_ops(wifi_intent, "WifiMaster0/AccessPoint3")
    families.append(("wifi_ap", wifi_plan))
    station_plan = compile_uplink_intent_to_station_ops(station_intent)
    families.append(("wifi_station", station_plan))
    wg_plan = compile_wireguard_intent_to_ops(wg_intent)
    families.append(("wireguard", wg_plan))
    vpn_plan = compile_vpn_policy_routing_intent(vpn_intent)
    families.append(("vpn_policy", vpn_plan))
    vlan_plan = compile_vlan_intent_to_ops(vlan_intent, "Bridge3")
    families.append(("vlan", vlan_plan))
    dhcp_plan = compile_dhcp_intent_to_ops(dhcp_intent)
    families.append(("dhcp", dhcp_plan))
    dns_plan = compile_dns_intent_to_ops(dns_intent)
    families.append(("dns", dns_plan))
    fw_plan = compile_firewall_intent_to_ops(fw_intent)
    families.append(("firewall", fw_plan))
    return families


def test_all_compiled_ops_grammar_doc_refs_resolve_or_mark_unconfirmed() -> None:
    from router_control.application.grammar_doc_refs import (
        UNCONFIRMED_SOURCE_MARKER,
        effective_ref,
        extract_doc_ref_from_notes,
        registry_entry,
        verify_grammar_doc_ref,
    )

    unconfirmed_seen: list[str] = []
    for family, plan in _compiled_planner_ops_for_property_test():
        for op in (*plan.apply_ops, *plan.teardown_ops):
            notes = getattr(op, "notes", ()) or ()
            assert notes, f"{family} op {op.operation} lacks grammar-source notes"
            entry = registry_entry(family, op.operation)
            if entry.unconfirmed or entry.ref is None:
                assert UNCONFIRMED_SOURCE_MARKER in " ".join(notes), (
                    f"{family}/{op.operation} expected unconfirmed marker"
                )
                unconfirmed_seen.append(f"{family}/{op.operation}")
                continue
            doc_ref = extract_doc_ref_from_notes(notes)
            assert doc_ref is not None, f"{family}/{op.operation} missing path#anchor citation"
            ref = effective_ref(entry)
            assert ref is not None
            assert verify_grammar_doc_ref(ref), (
                f"{family}/{op.operation} registry ref failed: "
                f"{ref.format()} snippet={ref.snippet!r}"
            )
            assert doc_ref == ref.format(), (
                f"{family}/{op.operation} notes cite {doc_ref} but registry expects {ref.format()}"
            )
    assert unconfirmed_seen, "expected at least one honestly unconfirmed op in smoke corpus"
