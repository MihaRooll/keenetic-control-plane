"""Typed, sealed RCI WireGuard/AmneziaWG interface-config operations."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from router_control.adapters.netcraze.allowlist import (
    build_sealed_parse_body,
    build_wireguard_nested_peer_body,
    normalize_nested_peer_allow_ips,
    validate_asc_args,
    validate_keepalive_interval,
    validate_peer_allow_ips,
    validate_peer_endpoint,
    validate_peer_public_key,
    validate_wg_key_shape,
    validate_wireguard_id,
)
from router_control.adapters.netcraze.fail_safe_rci import (
    FailSafeStatusEntry,
    RciSealedWriteTransport,
    collect_rci_status_and_prompt,
)
from router_control.adapters.netcraze.rci_prompt import (
    RCI_PROMPT_CONFIG,
    RCI_PROMPT_CONFIG_IF,
    is_allowlisted_rci_prompt,
    normalize_rci_prompt,
)
from router_control.adapters.netcraze.tcp_mss_validation import (
    TCP_MSS_MODE_PMTU,
    validate_tcp_mss_bound,
)
from router_control.adapters.netcraze.transport import SealedRciWriteRequest
from router_control.adapters.netcraze.vlan_rci import (
    validate_ipv4_dotted_mask,
    validate_ipv4_gateway,
)
from router_control.adapters.netcraze.vpn_policy_rci import validate_ip_global_bound

# Bare `interface WireguardN` create enters interface-config context and returns
# "(config-if)" instead of the global "(config)" prompt; asc/remove stay on "(config)".
_ALLOWED_PROMPTS = frozenset({RCI_PROMPT_CONFIG, RCI_PROMPT_CONFIG_IF})
_SUCCESS_STATUS_KINDS = frozenset({"message", "warning"})
_ERROR_STATUS_KIND = "error"


class WireguardRciError(Exception):
    """RCI WireGuard operation failed or returned an unverifiable ack."""


class WireguardRciOperation(StrEnum):
    CREATE_INTERFACE = "wireguard_create_interface"
    REMOVE_INTERFACE = "wireguard_remove_interface"
    SET_ASC = "wireguard_set_asc"
    SET_PRIVATE_KEY = "wireguard_set_private_key"
    CLEAR_PRIVATE_KEY = "wireguard_clear_private_key"
    ADD_PEER = "wireguard_add_peer"
    SET_PEER_ENDPOINT = "wireguard_set_peer_endpoint"
    SET_PEER_ALLOW_IPS = "wireguard_set_peer_allow_ips"
    SET_PEER_KEEPALIVE = "wireguard_set_peer_keepalive"
    REMOVE_PEER = "wireguard_remove_peer"
    SET_PRESHARED_KEY = "wireguard_set_preshared_key"
    CLEAR_PRESHARED_KEY = "wireguard_clear_preshared_key"
    UPSERT_PEER_NESTED = "wireguard_upsert_peer_nested"
    SET_IP_ADDRESS = "wireguard_set_ip_address"
    CLEAR_IP_ADDRESS = "wireguard_clear_ip_address"
    IP_GLOBAL = "wireguard_ip_global"
    CLEAR_IP_GLOBAL = "wireguard_clear_ip_global"
    SET_TCP_MSS = "wireguard_set_tcp_mss"
    CLEAR_TCP_MSS = "wireguard_clear_tcp_mss"


@dataclass(frozen=True, slots=True)
class WireguardRciResult:
    operation: WireguardRciOperation
    wg_id: str
    asc_args: str | None
    ack_matched: bool
    prompt: str
    status_entries: tuple[FailSafeStatusEntry, ...]
    peer_public_key: str | None = None
    peer_endpoint: str | None = None
    peer_allow_ips: str | None = None
    peer_keepalive_interval: int | None = None
    ipv4_address: str | None = None
    ipv4_mask: str | None = None
    global_auto: bool | None = None
    global_order: int | None = None
    global_priority: int | None = None

    def sanitized_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "operation": self.operation.value,
            "wg_id": self.wg_id,
            "ack_matched": self.ack_matched,
            "prompt": self.prompt,
            "status": [
                {
                    "status": entry.status,
                    "code": entry.code,
                    "ident": entry.ident,
                }
                for entry in self.status_entries
            ],
        }
        if self.asc_args is not None:
            payload["asc_args"] = self.asc_args
        if self.peer_public_key is not None:
            payload["peer_public_key"] = self.peer_public_key
        if self.peer_endpoint is not None:
            payload["peer_endpoint"] = self.peer_endpoint
        if self.peer_allow_ips is not None:
            payload["peer_allow_ips"] = self.peer_allow_ips
        if self.peer_keepalive_interval is not None:
            payload["peer_keepalive_interval"] = self.peer_keepalive_interval
        if self.ipv4_address is not None:
            payload["ipv4_address"] = self.ipv4_address
        if self.ipv4_mask is not None:
            payload["ipv4_mask"] = self.ipv4_mask
        if self.global_auto is not None:
            payload["global_auto"] = self.global_auto
        if self.global_order is not None:
            payload["global_order"] = self.global_order
        if self.global_priority is not None:
            payload["global_priority"] = self.global_priority
        return payload


def parse_interface_address_cidr(cidr: str) -> tuple[str, str]:
    """Parse WireGuard ``Address`` CIDR into (host_ipv4, dotted_mask)."""
    text = str(cidr).strip()
    if not text:
        raise WireguardRciError("interface address CIDR is empty")
    try:
        network = ipaddress.IPv4Network(text, strict=False)
    except ValueError as exc:
        raise WireguardRciError(f"invalid interface address CIDR: {exc}") from exc
    if network.prefixlen == 32:
        host = str(network.network_address)
    else:
        hosts = list(network.hosts())
        host = str(hosts[0]) if hosts else str(network.network_address)
    return validate_ipv4_gateway(host), str(network.netmask)


def command_for(
    operation: WireguardRciOperation,
    wg_id: str,
    *,
    asc_args: str | None = None,
    secret: str | None = None,
    peer_public_key: str | None = None,
    endpoint: str | None = None,
    allow_ips: str | None = None,
    keepalive_interval: int | None = None,
    ipv4_address: str | None = None,
    ipv4_mask: str | None = None,
    global_auto: bool = False,
    global_order: int | None = None,
    global_priority: int | None = None,
) -> str:
    wg = validate_wireguard_id(wg_id)
    if operation is WireguardRciOperation.CREATE_INTERFACE:
        return f"interface {wg}"
    if operation is WireguardRciOperation.REMOVE_INTERFACE:
        return f"no interface {wg}"
    if operation is WireguardRciOperation.SET_ASC:
        if asc_args is None:
            raise WireguardRciError("asc_args is required for SET_ASC")
        normalized_asc = validate_asc_args(asc_args)
        return f"interface {wg} wireguard asc {normalized_asc}"
    if operation is WireguardRciOperation.SET_PRIVATE_KEY:
        if secret is None:
            raise WireguardRciError("secret is required for SET_PRIVATE_KEY")
        normalized_secret = validate_wg_key_shape(secret)
        return f"interface {wg} wireguard private-key {normalized_secret}"
    if operation is WireguardRciOperation.CLEAR_PRIVATE_KEY:
        return f"interface {wg} no wireguard private-key"
    if operation is WireguardRciOperation.ADD_PEER:
        if peer_public_key is None:
            raise WireguardRciError("peer_public_key is required for ADD_PEER")
        pubkey = validate_peer_public_key(peer_public_key)
        return f"interface {wg} wireguard peer {pubkey}"
    if operation is WireguardRciOperation.SET_PEER_ENDPOINT:
        if peer_public_key is None or endpoint is None:
            raise WireguardRciError(
                "peer_public_key and endpoint are required for SET_PEER_ENDPOINT"
            )
        pubkey = validate_peer_public_key(peer_public_key)
        normalized_endpoint = validate_peer_endpoint(endpoint)
        return f"interface {wg} wireguard peer {pubkey} endpoint {normalized_endpoint}"
    if operation is WireguardRciOperation.SET_PEER_ALLOW_IPS:
        if peer_public_key is None or allow_ips is None:
            raise WireguardRciError(
                "peer_public_key and allow_ips are required for SET_PEER_ALLOW_IPS"
            )
        pubkey = validate_peer_public_key(peer_public_key)
        allow_ipv4, allow_mask = validate_peer_allow_ips(allow_ips)
        return f"interface {wg} wireguard peer {pubkey} allow-ips {allow_ipv4} {allow_mask}"
    if operation is WireguardRciOperation.SET_PEER_KEEPALIVE:
        if peer_public_key is None or keepalive_interval is None:
            raise WireguardRciError(
                "peer_public_key and keepalive_interval are required for SET_PEER_KEEPALIVE"
            )
        pubkey = validate_peer_public_key(peer_public_key)
        normalized_keepalive = validate_keepalive_interval(keepalive_interval)
        return (
            f"interface {wg} wireguard peer {pubkey} "
            f"keepalive-interval {normalized_keepalive}"
        )
    if operation is WireguardRciOperation.REMOVE_PEER:
        if peer_public_key is None:
            raise WireguardRciError("peer_public_key is required for REMOVE_PEER")
        pubkey = validate_peer_public_key(peer_public_key)
        return f"interface {wg} no wireguard peer {pubkey}"
    if operation is WireguardRciOperation.SET_PRESHARED_KEY:
        if peer_public_key is None or secret is None:
            raise WireguardRciError(
                "peer_public_key and secret are required for SET_PRESHARED_KEY"
            )
        pubkey = validate_peer_public_key(peer_public_key)
        normalized_secret = validate_wg_key_shape(secret)
        return f"interface {wg} wireguard peer {pubkey} preshared-key {normalized_secret}"
    if operation is WireguardRciOperation.CLEAR_PRESHARED_KEY:
        if peer_public_key is None:
            raise WireguardRciError("peer_public_key is required for CLEAR_PRESHARED_KEY")
        pubkey = validate_peer_public_key(peer_public_key)
        return f"interface {wg} no wireguard peer {pubkey} preshared-key"
    if operation is WireguardRciOperation.SET_IP_ADDRESS:
        if ipv4_address is None or ipv4_mask is None:
            raise WireguardRciError("ipv4_address and ipv4_mask are required for SET_IP_ADDRESS")
        addr = validate_ipv4_gateway(ipv4_address)
        mask = validate_ipv4_dotted_mask(ipv4_mask)
        return f"interface {wg} ip address {addr} {mask}"
    if operation is WireguardRciOperation.CLEAR_IP_ADDRESS:
        return f"interface {wg} no ip address"
    if operation is WireguardRciOperation.IP_GLOBAL:
        if global_auto:
            return f"interface {wg} ip global auto"
        if global_order is not None:
            order = validate_ip_global_bound(global_order, field="order")
            return f"interface {wg} ip global order {order}"
        if global_priority is None:
            raise WireguardRciError("global_priority or global_auto required for IP_GLOBAL")
        priority = validate_ip_global_bound(global_priority, field="priority")
        return f"interface {wg} ip global {priority}"
    if operation is WireguardRciOperation.CLEAR_IP_GLOBAL:
        return f"interface {wg} no ip global"
    if operation is WireguardRciOperation.SET_TCP_MSS:
        validate_tcp_mss_bound(TCP_MSS_MODE_PMTU)
        return f"interface {wg} ip tcp adjust-mss pmtu"
    if operation is WireguardRciOperation.CLEAR_TCP_MSS:
        return f"interface {wg} no ip tcp adjust-mss"
    raise WireguardRciError(f"operation not allowlisted: {operation}")


def command_redacted_for(
    operation: WireguardRciOperation,
    wg_id: str,
    *,
    asc_args: str | None = None,
    peer_public_key: str | None = None,
    endpoint: str | None = None,
    allow_ips: str | None = None,
    keepalive_interval: int | None = None,
    global_auto: bool = False,
    global_order: int | None = None,
    global_priority: int | None = None,
) -> str:
    """Build a sealed command string safe for error surfaces (secrets never included)."""
    if operation is WireguardRciOperation.SET_PRIVATE_KEY:
        wg = validate_wireguard_id(wg_id)
        return f"interface {wg} wireguard private-key <redacted>"
    if operation is WireguardRciOperation.SET_PRESHARED_KEY:
        wg = validate_wireguard_id(wg_id)
        if peer_public_key is None:
            raise WireguardRciError(
                "peer_public_key is required for SET_PRESHARED_KEY redaction"
            )
        pubkey = validate_peer_public_key(peer_public_key)
        return f"interface {wg} wireguard peer {pubkey} preshared-key <redacted>"
    if operation is WireguardRciOperation.IP_GLOBAL:
        wg = validate_wireguard_id(wg_id)
        return f"interface {wg} ip global <priority>"
    return command_for(
        operation,
        wg_id,
        asc_args=asc_args,
        peer_public_key=peer_public_key,
        endpoint=endpoint,
        allow_ips=allow_ips,
        keepalive_interval=keepalive_interval,
        global_auto=global_auto,
        global_order=global_order,
        global_priority=global_priority,
    )


def sealed_request_for(
    operation: WireguardRciOperation,
    wg_id: str,
    *,
    asc_args: str | None = None,
    secret: str | None = None,
    peer_public_key: str | None = None,
    endpoint: str | None = None,
    allow_ips: str | None = None,
    keepalive_interval: int | None = None,
    ipv4_address: str | None = None,
    ipv4_mask: str | None = None,
    global_auto: bool = False,
    global_order: int | None = None,
    global_priority: int | None = None,
) -> SealedRciWriteRequest:
    body = build_sealed_parse_body(
        command_for(
            operation,
            wg_id,
            asc_args=asc_args,
            secret=secret,
            peer_public_key=peer_public_key,
            endpoint=endpoint,
            allow_ips=allow_ips,
            keepalive_interval=keepalive_interval,
            ipv4_address=ipv4_address,
            ipv4_mask=ipv4_mask,
            global_auto=global_auto,
            global_order=global_order,
            global_priority=global_priority,
        )
    )
    return SealedRciWriteRequest(body=body)


def nested_peer_body_for(
    wg_id: str,
    peer_public_key: str,
    *,
    endpoint: str | None = None,
    allow_ips: str | None = None,
    keepalive_interval: int | None = None,
    preshared_key: str | None = None,
) -> bytes:
    return build_wireguard_nested_peer_body(
        wg_id,
        peer_public_key,
        endpoint=endpoint,
        allow_ips=allow_ips,
        keepalive_interval=keepalive_interval,
        preshared_key=preshared_key,
    )


def sealed_nested_peer_request_for(
    wg_id: str,
    peer_public_key: str,
    *,
    endpoint: str | None = None,
    allow_ips: str | None = None,
    keepalive_interval: int | None = None,
    preshared_key: str | None = None,
) -> SealedRciWriteRequest:
    body = nested_peer_body_for(
        wg_id,
        peer_public_key,
        endpoint=endpoint,
        allow_ips=allow_ips,
        keepalive_interval=keepalive_interval,
        preshared_key=preshared_key,
    )
    return SealedRciWriteRequest(body=body)


def verify_wireguard_response(
    operation: WireguardRciOperation,
    wg_id: str,
    response: Any,
    *,
    asc_args: str | None = None,
    peer_public_key: str | None = None,
    endpoint: str | None = None,
    allow_ips: str | None = None,
    keepalive_interval: int | None = None,
    ipv4_address: str | None = None,
    ipv4_mask: str | None = None,
    global_auto: bool = False,
    global_order: int | None = None,
    global_priority: int | None = None,
) -> WireguardRciResult:
    wg = validate_wireguard_id(wg_id)
    normalized_asc: str | None = None
    normalized_peer: str | None = None
    normalized_endpoint: str | None = None
    normalized_allow_ips: str | None = None
    normalized_keepalive: int | None = None
    normalized_address: str | None = None
    normalized_mask: str | None = None
    normalized_global_auto: bool | None = None
    normalized_global_order: int | None = None
    normalized_global_priority: int | None = None
    if operation is WireguardRciOperation.SET_ASC:
        if asc_args is None:
            raise WireguardRciError("asc_args is required for SET_ASC verification")
        normalized_asc = validate_asc_args(asc_args)
    if operation in (
        WireguardRciOperation.ADD_PEER,
        WireguardRciOperation.SET_PEER_ENDPOINT,
        WireguardRciOperation.SET_PEER_ALLOW_IPS,
        WireguardRciOperation.SET_PEER_KEEPALIVE,
        WireguardRciOperation.REMOVE_PEER,
        WireguardRciOperation.SET_PRESHARED_KEY,
        WireguardRciOperation.CLEAR_PRESHARED_KEY,
    ):
        if peer_public_key is None:
            raise WireguardRciError("peer_public_key is required for peer operation verification")
        normalized_peer = validate_peer_public_key(peer_public_key)
    if operation is WireguardRciOperation.SET_PEER_ENDPOINT:
        if endpoint is None:
            raise WireguardRciError("endpoint is required for SET_PEER_ENDPOINT verification")
        normalized_endpoint = validate_peer_endpoint(endpoint)
    if operation is WireguardRciOperation.SET_PEER_ALLOW_IPS:
        if allow_ips is None:
            raise WireguardRciError("allow_ips is required for SET_PEER_ALLOW_IPS verification")
        ipv4, mask = validate_peer_allow_ips(allow_ips)
        normalized_allow_ips = f"{ipv4} {mask}"
    if operation is WireguardRciOperation.SET_PEER_KEEPALIVE:
        if keepalive_interval is None:
            raise WireguardRciError(
                "keepalive_interval is required for SET_PEER_KEEPALIVE verification"
            )
        normalized_keepalive = validate_keepalive_interval(keepalive_interval)
    if operation is WireguardRciOperation.SET_IP_ADDRESS:
        if ipv4_address is None or ipv4_mask is None:
            raise WireguardRciError(
                "ipv4_address and ipv4_mask are required for SET_IP_ADDRESS verification"
            )
        normalized_address = validate_ipv4_gateway(ipv4_address)
        normalized_mask = validate_ipv4_dotted_mask(ipv4_mask)
    if operation is WireguardRciOperation.IP_GLOBAL:
        normalized_global_auto = global_auto or None
        if global_order is not None:
            normalized_global_order = validate_ip_global_bound(global_order, field="order")
        if global_priority is not None:
            normalized_global_priority = validate_ip_global_bound(
                global_priority, field="priority"
            )
    entries, prompt = collect_rci_status_and_prompt(response)
    normalized_prompt = normalize_rci_prompt(prompt) if prompt else ""
    if not entries:
        raise WireguardRciError("no RCI parse status returned")
    if not is_allowlisted_rci_prompt(prompt, allowed=_ALLOWED_PROMPTS):
        raise WireguardRciError("RCI parse prompt missing or not allowlisted")
    if any(entry.status == _ERROR_STATUS_KIND for entry in entries):
        raise WireguardRciError("RCI parse reported an error status")
    if not all(entry.status in _SUCCESS_STATUS_KINDS for entry in entries):
        raise WireguardRciError("RCI parse returned an unexpected status kind")
    return WireguardRciResult(
        operation=operation,
        wg_id=wg,
        asc_args=normalized_asc,
        ack_matched=True,
        prompt=normalized_prompt,
        status_entries=tuple(entries),
        peer_public_key=normalized_peer,
        peer_endpoint=normalized_endpoint,
        peer_allow_ips=normalized_allow_ips,
        peer_keepalive_interval=normalized_keepalive,
        ipv4_address=normalized_address,
        ipv4_mask=normalized_mask,
        global_auto=normalized_global_auto,
        global_order=normalized_global_order,
        global_priority=normalized_global_priority,
    )


def verify_wireguard_nested_peer_response(
    wg_id: str,
    response: Any,
    *,
    peer_public_key: str,
    endpoint: str | None = None,
    allow_ips: str | None = None,
    keepalive_interval: int | None = None,
) -> WireguardRciResult:
    wg = validate_wireguard_id(wg_id)
    normalized_peer = validate_peer_public_key(peer_public_key)
    normalized_endpoint: str | None = None
    normalized_allow_ips: str | None = None
    normalized_keepalive: int | None = None
    if endpoint is not None:
        normalized_endpoint = validate_peer_endpoint(endpoint)
    if allow_ips is not None:
        normalized_allow_ips = normalize_nested_peer_allow_ips(allow_ips)
    if keepalive_interval is not None:
        normalized_keepalive = validate_keepalive_interval(keepalive_interval)
    entries, prompt = collect_rci_status_and_prompt(response)
    normalized_prompt = normalize_rci_prompt(prompt) if prompt else ""
    if not entries:
        raise WireguardRciError("no RCI nested peer status returned")
    if prompt and not is_allowlisted_rci_prompt(prompt, allowed=_ALLOWED_PROMPTS):
        raise WireguardRciError("RCI nested peer prompt not allowlisted")
    if any(entry.status == _ERROR_STATUS_KIND for entry in entries):
        raise WireguardRciError("RCI nested peer reported an error status")
    if not all(entry.status in _SUCCESS_STATUS_KINDS for entry in entries):
        raise WireguardRciError("RCI nested peer returned an unexpected status kind")
    return WireguardRciResult(
        operation=WireguardRciOperation.UPSERT_PEER_NESTED,
        wg_id=wg,
        asc_args=None,
        ack_matched=True,
        prompt=normalized_prompt,
        status_entries=tuple(entries),
        peer_public_key=normalized_peer,
        peer_endpoint=normalized_endpoint,
        peer_allow_ips=normalized_allow_ips,
        peer_keepalive_interval=normalized_keepalive,
    )


def execute_wireguard_rci(
    transport: RciSealedWriteTransport,
    operation: WireguardRciOperation,
    wg_id: str,
    *,
    asc_args: str | None = None,
    secret: str | None = None,
    peer_public_key: str | None = None,
    endpoint: str | None = None,
    allow_ips: str | None = None,
    keepalive_interval: int | None = None,
    ipv4_address: str | None = None,
    ipv4_mask: str | None = None,
    global_auto: bool = False,
    global_order: int | None = None,
    global_priority: int | None = None,
) -> WireguardRciResult:
    request = sealed_request_for(
        operation,
        wg_id,
        asc_args=asc_args,
        secret=secret,
        peer_public_key=peer_public_key,
        endpoint=endpoint,
        allow_ips=allow_ips,
        keepalive_interval=keepalive_interval,
        ipv4_address=ipv4_address,
        ipv4_mask=ipv4_mask,
        global_auto=global_auto,
        global_order=global_order,
        global_priority=global_priority,
    )
    response = transport.execute_sealed_rci_write(request)
    return verify_wireguard_response(
        operation,
        wg_id,
        response,
        asc_args=asc_args,
        peer_public_key=peer_public_key,
        endpoint=endpoint,
        allow_ips=allow_ips,
        keepalive_interval=keepalive_interval,
        ipv4_address=ipv4_address,
        ipv4_mask=ipv4_mask,
        global_auto=global_auto,
        global_order=global_order,
        global_priority=global_priority,
    )


def execute_wireguard_nested_peer_rci(
    transport: RciSealedWriteTransport,
    wg_id: str,
    peer_public_key: str,
    *,
    endpoint: str | None = None,
    allow_ips: str | None = None,
    keepalive_interval: int | None = None,
    preshared_key: str | None = None,
) -> WireguardRciResult:
    request = sealed_nested_peer_request_for(
        wg_id,
        peer_public_key,
        endpoint=endpoint,
        allow_ips=allow_ips,
        keepalive_interval=keepalive_interval,
        preshared_key=preshared_key,
    )
    response = transport.execute_sealed_rci_write(request)
    return verify_wireguard_nested_peer_response(
        wg_id,
        response,
        peer_public_key=peer_public_key,
        endpoint=endpoint,
        allow_ips=allow_ips,
        keepalive_interval=keepalive_interval,
    )


def wireguard_create_interface(
    transport: RciSealedWriteTransport,
    wg_id: str,
) -> WireguardRciResult:
    return execute_wireguard_rci(transport, WireguardRciOperation.CREATE_INTERFACE, wg_id)


def wireguard_remove_interface(
    transport: RciSealedWriteTransport,
    wg_id: str,
) -> WireguardRciResult:
    return execute_wireguard_rci(transport, WireguardRciOperation.REMOVE_INTERFACE, wg_id)


def wireguard_set_asc(
    transport: RciSealedWriteTransport,
    wg_id: str,
    asc_args: str,
) -> WireguardRciResult:
    return execute_wireguard_rci(
        transport,
        WireguardRciOperation.SET_ASC,
        wg_id,
        asc_args=asc_args,
    )


__all__ = [
    "WireguardRciError",
    "WireguardRciOperation",
    "WireguardRciResult",
    "command_for",
    "command_redacted_for",
    "execute_wireguard_nested_peer_rci",
    "execute_wireguard_rci",
    "nested_peer_body_for",
    "parse_interface_address_cidr",
    "sealed_nested_peer_request_for",
    "sealed_request_for",
    "verify_wireguard_nested_peer_response",
    "verify_wireguard_response",
    "wireguard_create_interface",
    "wireguard_remove_interface",
    "wireguard_set_asc",
]
