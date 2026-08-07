"""Vendor-neutral network intent value objects (M2 offline preset)."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, TypeVar

CANONICAL_ZONE_IDS: frozenset[str] = frozenset({"Guest", "Promo", "Staff", "AdminServer"})

SECRET_SHAPED_KEYS: frozenset[str] = frozenset(
    {
        "password",
        "passphrase",
        "psk",
        "pre_shared_key",
        "secret",
        "private_key",
        "session",
        "token",
        "api_key",
    }
)

_WIREGUARD_TEST_ID_RE = re.compile(r"^Wireguard[5-9]$")

WIREGUARD_SECRET_SHAPED_KEYS: frozenset[str] = frozenset(
    {
        "private_key",
        "privatekey",
        "preshared_key",
        "preshared",
        "pre_shared",
        "passphrase",
        "obfs_key",
    }
    | SECRET_SHAPED_KEYS
)

_FQDN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


class ZoneId(StrEnum):
    GUEST = "Guest"
    PROMO = "Promo"
    STAFF = "Staff"
    ADMIN_SERVER = "AdminServer"


class UplinkMode(StrEnum):
    ETHERNET = "Ethernet"
    WIFI_WAN = "WifiWan"
    LOCAL_ONLY = "LocalOnly"
    LTE = "Lte"


class Ipv6Posture(StrEnum):
    DISABLED = "Disabled"
    OBSERVE_ONLY = "ObserveOnly"
    MANAGED = "Managed"


class CaptivePortalMode(StrEnum):
    DISABLED = "Disabled"
    ENABLED = "Enabled"


class WifiWpaMode(StrEnum):
    WPA2 = "WPA2"
    WPA3 = "WPA3"
    WPA2_WPA3_MIXED = "WPA2_WPA3_MIXED"


class WifiBand(StrEnum):
    BAND_2_4GHZ = "BAND_2_4GHZ"  # -> WifiMaster0
    BAND_5GHZ = "BAND_5GHZ"  # -> WifiMaster1


class WireguardPeerRciShape(StrEnum):
    PATH_STYLE = "path_style"
    NESTED_RCI = "nested_rci"


class FirewallAction(StrEnum):
    ALLOW = "Allow"
    DENY = "Deny"


class FirewallDestinationFamily(StrEnum):
    ORDER_PAGE = "OrderPage"
    DNS = "Dns"
    DHCP = "Dhcp"
    MANAGEMENT = "Management"
    INTERNET = "Internet"
    LOCAL_ZONE = "LocalZone"


GUEST_ALLOWED_ALLOW_FAMILIES: frozenset[FirewallDestinationFamily] = frozenset(
    {
        FirewallDestinationFamily.ORDER_PAGE,
        FirewallDestinationFamily.DNS,
        FirewallDestinationFamily.DHCP,
    }
)


class RackAssetRole(StrEnum):
    HUB = "Hub"
    PRINTER = "Printer"
    PLOTTER = "Plotter"
    SWITCH = "Switch"
    ROUTER = "Router"


class FindingSeverity(StrEnum):
    INFO = "Info"
    WARNING = "Warning"
    ERROR = "Error"


class BlockingFor(StrEnum):
    VALIDATION = "validation"
    APPLY_FRAGMENT = "apply_fragment"
    WRITE = "write"


@dataclass(frozen=True, slots=True)
class IntentValidationError(ValueError):
    code: str
    message: str
    field: str | None = None

    def __str__(self) -> str:
        return self.message


def canonical_digest(payload: dict[str, Any]) -> str:
    raw = canonical_dumps(payload)
    return "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


def canonical_dumps(obj: Any) -> str:
    """Deterministic JSON for P2 digests (UTF-8, sorted keys, no whitespace)."""
    _reject_non_json_types(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _reject_non_json_types(obj: Any) -> None:
    if obj is None or isinstance(obj, (bool, int, str)):
        return
    if isinstance(obj, float):
        if not (obj == obj and abs(obj) != float("inf")):
            raise ValueError("non-finite float rejected in canonical JSON")
        return
    if isinstance(obj, list):
        for item in obj:
            _reject_non_json_types(item)
        return
    if isinstance(obj, dict):
        for key, value in obj.items():
            if not isinstance(key, str):
                raise ValueError("canonical JSON dict keys must be strings")
            _reject_non_json_types(value)
        return
    raise ValueError(f"unsupported type for canonical JSON: {type(obj).__name__}")


def digest_canonical(domain: str, obj: Any) -> str:
    """Domain-separated sha256 digest: rc-p2:<name>:v1| + canonical bytes."""
    if not domain or ":" in domain:
        raise ValueError("invalid canonical domain name")
    prefix = f"rc-p2:{domain}:v1|"
    canonical_bytes = canonical_dumps(obj).encode("utf-8")
    digest = hashlib.sha256(prefix.encode("utf-8") + canonical_bytes).hexdigest()
    return f"sha256:{digest}"


def _normalize_intent_key(key: str) -> str:
    return key.lower().replace("-", "_")


def _reject_unknown_keys(data: dict[str, Any], allowed: frozenset[str], *, context: str) -> None:
    for key in data:
        normalized = _normalize_intent_key(key)
        if normalized in SECRET_SHAPED_KEYS and key != "credential_ref_id":
            raise IntentValidationError(
                "secret_shaped_field",
                f"{context}: secret-shaped field rejected",
                field=context,
            )
    unknown = set(data.keys()) - allowed
    if unknown:
        raise IntentValidationError(
            "unknown_fields",
            f"{context}: unrecognized field(s)",
            field=context,
        )


def _reject_wireguard_secret_keys(data: dict[str, Any], *, context: str) -> None:
    for key in data:
        normalized = _normalize_intent_key(key)
        if normalized in WIREGUARD_SECRET_SHAPED_KEYS:
            raise IntentValidationError(
                "secret_shaped_field",
                f"{context}: secret-shaped field rejected",
                field=context,
            )


def normalize_fqdn(value: str, *, field: str = "local_fqdn") -> str:
    normalized = value.strip().lower().rstrip(".")
    if not normalized or not _FQDN_RE.match(normalized):
        raise IntentValidationError(
            "invalid_fqdn",
            "invalid FQDN format",
            field=field,
        )
    return normalized


@dataclass(frozen=True, slots=True)
class WireguardIntent:
    wg_id: str
    enabled: bool
    asc_args: tuple[int, ...] | None = None
    private_key_credential_ref_id: str | None = None
    preshared_key_credential_ref_id: str | None = None
    peer_public_key: str | None = None
    peer_endpoint: str | None = None
    peer_allow_ips: str | None = None
    peer_keepalive_interval: int | None = None
    peer_rci_shape: WireguardPeerRciShape = WireguardPeerRciShape.NESTED_RCI
    interface_address: str | None = None
    ip_global_priority: int | None = None
    ip_global_auto: bool = False
    tcp_mss_pmtu: bool = False

    def to_canonical(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "wg_id": self.wg_id,
            "enabled": self.enabled,
        }
        if self.asc_args is not None:
            payload["asc_args"] = list(self.asc_args)
        if self.private_key_credential_ref_id is not None:
            payload["private_key_credential_ref_id"] = self.private_key_credential_ref_id
        if self.preshared_key_credential_ref_id is not None:
            payload["preshared_key_credential_ref_id"] = self.preshared_key_credential_ref_id
        if self.peer_public_key is not None:
            payload["peer_public_key"] = self.peer_public_key
        if self.peer_endpoint is not None:
            payload["peer_endpoint"] = self.peer_endpoint
        if self.peer_allow_ips is not None:
            payload["peer_allow_ips"] = self.peer_allow_ips
        if self.peer_keepalive_interval is not None:
            payload["peer_keepalive_interval"] = self.peer_keepalive_interval
        if self.peer_rci_shape is not WireguardPeerRciShape.NESTED_RCI:
            payload["peer_rci_shape"] = self.peer_rci_shape.value
        if self.interface_address is not None:
            payload["interface_address"] = self.interface_address
        if self.ip_global_auto:
            payload["ip_global_auto"] = True
        if self.ip_global_priority is not None:
            payload["ip_global_priority"] = self.ip_global_priority
        if self.tcp_mss_pmtu:
            payload["tcp_mss_pmtu"] = True
        return payload

    @property
    def has_secret_ops(self) -> bool:
        return bool(
            self.private_key_credential_ref_id
            or self.preshared_key_credential_ref_id
            or self.peer_public_key
        )


@dataclass(frozen=True, slots=True)
class WifiIntent:
    ssid: str
    enabled: bool
    credential_ref_id: str | None
    captive_portal: CaptivePortalMode
    guest_isolation: bool
    wpa_mode: WifiWpaMode = WifiWpaMode.WPA2
    band: WifiBand = WifiBand.BAND_2_4GHZ

    def to_canonical(self) -> dict[str, Any]:
        return {
            "ssid": self.ssid,
            "enabled": self.enabled,
            "credential_ref_id": self.credential_ref_id,
            "captive_portal": self.captive_portal.value,
            "guest_isolation": self.guest_isolation,
            "wpa_mode": self.wpa_mode.value,
            "band": self.band.value,
        }


@dataclass(frozen=True, slots=True)
class DhcpReservation:
    mac_address: str
    ipv4_address: str

    def to_canonical(self) -> dict[str, Any]:
        return {
            "mac_address": self.mac_address.lower(),
            "ipv4_address": self.ipv4_address,
        }


@dataclass(frozen=True, slots=True)
class DhcpIntent:
    pool_start: str
    pool_end: str
    lease_seconds: int
    reservations: tuple[DhcpReservation, ...]

    def to_canonical(self) -> dict[str, Any]:
        return {
            "pool_start": self.pool_start,
            "pool_end": self.pool_end,
            "lease_seconds": self.lease_seconds,
            "reservations": [r.to_canonical() for r in self.reservations],
        }


@dataclass(frozen=True, slots=True)
class DnsIntent:
    local_fqdn: str
    upstream_resolvers: tuple[str, ...]

    def to_canonical(self) -> dict[str, Any]:
        return {
            "local_fqdn": self.local_fqdn,
            "upstream_resolvers": list(self.upstream_resolvers),
        }


@dataclass(frozen=True, slots=True)
class FirewallRule:
    action: FirewallAction
    destination_family: FirewallDestinationFamily
    ordinal: int

    def to_canonical(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "destination_family": self.destination_family.value,
            "ordinal": self.ordinal,
        }


@dataclass(frozen=True, slots=True)
class FirewallIntent:
    rules: tuple[FirewallRule, ...]

    def to_canonical(self) -> dict[str, Any]:
        return {"rules": [r.to_canonical() for r in self.rules]}


@dataclass(frozen=True, slots=True)
class NetworkZoneIntent:
    zone_id: ZoneId
    vlan_id: int
    ipv4_cidr: str
    ipv6_posture: Ipv6Posture
    management_allowed: bool
    dhcp: DhcpIntent
    dns: DnsIntent
    wifi: WifiIntent | None
    firewall: FirewallIntent

    def to_canonical(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "zone_id": self.zone_id.value,
            "vlan_id": self.vlan_id,
            "ipv4_cidr": self.ipv4_cidr,
            "ipv6_posture": self.ipv6_posture.value,
            "management_allowed": self.management_allowed,
            "dhcp": self.dhcp.to_canonical(),
            "dns": self.dns.to_canonical(),
            "firewall": self.firewall.to_canonical(),
        }
        if self.wifi is not None:
            payload["wifi"] = self.wifi.to_canonical()
        return payload


_UPLINK_ALLOWED_KEYS: frozenset[str] = frozenset(
    {
        "mode",
        "ssid",
        "band",
        "credential_ref_id",
        "bssid",
        "priority",
        "captive_portal_client",
    }
)
_UPLINK_PRIORITY_MIN = 0
_UPLINK_PRIORITY_MAX = 255


@dataclass(frozen=True, slots=True)
class UplinkIntent:
    mode: UplinkMode
    ssid: str | None = None
    band: WifiBand | None = None
    credential_ref_id: str | None = None
    bssid: str | None = None
    priority: int = 100
    captive_portal_client: bool = False

    def to_canonical(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"mode": self.mode.value}
        if self.ssid is not None:
            payload["ssid"] = self.ssid
        if self.band is not None:
            payload["band"] = self.band.value
        if self.credential_ref_id is not None:
            payload["credential_ref_id"] = self.credential_ref_id
        if self.bssid is not None:
            payload["bssid"] = self.bssid
        if self.priority != 100:
            payload["priority"] = self.priority
        if self.captive_portal_client:
            payload["captive_portal_client"] = True
        return payload


def uplink_preference_key(intent: UplinkIntent) -> tuple[int, str]:
    """Lower priority number = higher preference when comparing uplink intents."""
    return (intent.priority, intent.mode.value)


@dataclass(frozen=True, slots=True)
class RackAssetIntent:
    role: RackAssetRole
    display_name: str
    recommendation: str | None

    def to_canonical(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "role": self.role.value,
            "display_name": self.display_name,
        }
        if self.recommendation is not None:
            payload["recommendation"] = self.recommendation
        return payload


@dataclass(frozen=True, slots=True)
class ReadinessFinding:
    code: str
    severity: FindingSeverity
    blocking_for: BlockingFor
    summary_redacted: str
    family: str | None = None

    def to_public(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity.value,
            "blocking_for": self.blocking_for.value,
            "summary_redacted": self.summary_redacted,
            "family": self.family,
        }


_E = TypeVar("_E", bound=StrEnum)


def _intent_field(context: str, field: str) -> str:
    return f"{context}.{field}" if context else field


def _require_present(data: dict[str, Any], field: str, *, context: str) -> None:
    if field not in data:
        raise IntentValidationError(
            f"{field}_missing",
            f"{context}: {field} is required; omitting it silently changes device state",
            field=_intent_field(context, field),
        )


def _parse_wifi_enum(
    value: Any,
    enum_cls: type[_E],
    *,
    field: str,
    context: str,
) -> _E:
    try:
        return enum_cls(str(value))
    except ValueError as exc:
        raise IntentValidationError(
            f"invalid_{field}",
            f"{context}: invalid {field}",
            field=_intent_field(context, field),
        ) from exc


def _parse_asc_args_list(raw: Any, *, context: str) -> tuple[int, ...] | None:
    from router_control.adapters.netcraze.allowlist import validate_asc_args

    if raw is None:
        return None
    if not isinstance(raw, list):
        raise IntentValidationError("invalid_asc_args", f"{context}: asc_args must be array")
    if not raw:
        return None
    values: list[int] = []
    for idx, item in enumerate(raw):
        if not isinstance(item, int) or isinstance(item, bool):
            raise IntentValidationError(
                "invalid_asc_args",
                f"{context}: asc_args[{idx}] must be non-negative integer",
            )
        if item < 0:
            raise IntentValidationError(
                "invalid_asc_args",
                f"{context}: asc_args[{idx}] must be non-negative",
            )
        values.append(item)
    length = len(values)
    if length not in (9, 16):
        raise IntentValidationError(
            "invalid_asc_args",
            f"{context}: asc_args must contain exactly 9 or 16 integers",
        )
    try:
        validate_asc_args(" ".join(str(value) for value in values))
    except ValueError as exc:
        raise IntentValidationError("invalid_asc_args", f"{context}: {exc}") from exc
    return tuple(values)


def _parse_wireguard(data: dict[str, Any]) -> WireguardIntent:
    from router_control.adapters.netcraze.allowlist import validate_peer_allow_ips_list

    context = "wireguard"
    _reject_wireguard_secret_keys(data, context=context)
    _reject_unknown_keys(
        data,
        frozenset(
            {
                "wg_id",
                "asc_args",
                "enabled",
                "private_key_credential_ref_id",
                "preshared_key_credential_ref_id",
                "peer_public_key",
                "peer_endpoint",
                "peer_allow_ips",
                "peer_keepalive_interval",
                "peer_rci_shape",
                "interface_address",
                "ip_global_priority",
                "ip_global_auto",
                "tcp_mss_pmtu",
            }
        ),
        context=context,
    )
    wg_id = str(data["wg_id"]).strip()
    if not _WIREGUARD_TEST_ID_RE.fullmatch(wg_id):
        raise IntentValidationError(
            "invalid_wg_id",
            f"{context}: wg_id must be Wireguard5–Wireguard9",
        )
    asc_args = _parse_asc_args_list(data.get("asc_args"), context=context)

    private_key_ref = data.get("private_key_credential_ref_id")
    psk_ref = data.get("preshared_key_credential_ref_id")
    peer_public_key = data.get("peer_public_key")
    peer_endpoint = data.get("peer_endpoint")
    peer_allow_ips = data.get("peer_allow_ips")
    peer_keepalive = data.get("peer_keepalive_interval")

    for field_name, value in (
        ("private_key_credential_ref_id", private_key_ref),
        ("preshared_key_credential_ref_id", psk_ref),
        ("peer_public_key", peer_public_key),
        ("peer_endpoint", peer_endpoint),
        ("peer_allow_ips", peer_allow_ips),
    ):
        if value is not None and not isinstance(value, str):
            raise IntentValidationError(
                "invalid_field_type",
                f"{context}: {field_name} must be string",
            )

    keepalive_value: int | None = None
    if peer_keepalive is not None:
        if not isinstance(peer_keepalive, int) or isinstance(peer_keepalive, bool):
            raise IntentValidationError(
                "invalid_keepalive",
                f"{context}: peer_keepalive_interval must be integer",
            )
        if peer_keepalive < 3 or peer_keepalive > 3600:
            raise IntentValidationError(
                "invalid_keepalive",
                f"{context}: peer_keepalive_interval must be 3..3600",
            )
        keepalive_value = peer_keepalive

    has_peer_fields = any(
        value is not None
        for value in (peer_public_key, peer_endpoint, peer_allow_ips, keepalive_value, psk_ref)
    )
    if has_peer_fields and not private_key_ref:
        raise IntentValidationError(
            "private_key_ref_required",
            f"{context}: private_key_credential_ref_id required for peer/secret ops",
        )
    if psk_ref and not peer_public_key:
        raise IntentValidationError(
            "peer_public_key_required",
            f"{context}: peer_public_key required when preshared_key_credential_ref_id set",
        )
    if (peer_endpoint or peer_allow_ips or keepalive_value is not None) and not peer_public_key:
        raise IntentValidationError(
            "peer_public_key_required",
            f"{context}: peer_public_key required for peer config fields",
        )

    if peer_allow_ips:
        try:
            validate_peer_allow_ips_list(str(peer_allow_ips).strip())
        except ValueError as exc:
            raise IntentValidationError("invalid_peer_allow_ips", f"{context}: {exc}") from exc

    interface_address_raw = data.get("interface_address")
    interface_address: str | None = None
    if interface_address_raw is not None:
        if not isinstance(interface_address_raw, str):
            raise IntentValidationError(
                "invalid_field_type",
                f"{context}: interface_address must be string",
            )
        interface_address = str(interface_address_raw).strip() or None

    ip_global_auto = bool(data.get("ip_global_auto", False))
    if not isinstance(data.get("ip_global_auto", False), bool) and "ip_global_auto" in data:
        raise IntentValidationError(
            "invalid_field_type",
            f"{context}: ip_global_auto must be boolean",
        )

    ip_global_priority_raw = data.get("ip_global_priority")
    ip_global_priority: int | None = None
    if ip_global_priority_raw is not None:
        if not isinstance(ip_global_priority_raw, int) or isinstance(ip_global_priority_raw, bool):
            raise IntentValidationError(
                "invalid_field_type",
                f"{context}: ip_global_priority must be integer",
            )
        if ip_global_priority_raw < 0 or ip_global_priority_raw > 65535:
            raise IntentValidationError(
                "invalid_ip_global_priority",
                f"{context}: ip_global_priority must be 0..65535",
            )
        ip_global_priority = ip_global_priority_raw

    if ip_global_auto and ip_global_priority is not None:
        raise IntentValidationError(
            "invalid_ip_global",
            f"{context}: ip_global_auto and ip_global_priority are mutually exclusive",
        )

    tcp_mss_pmtu = bool(data.get("tcp_mss_pmtu", False))
    if not isinstance(data.get("tcp_mss_pmtu", False), bool) and "tcp_mss_pmtu" in data:
        raise IntentValidationError(
            "invalid_field_type",
            f"{context}: tcp_mss_pmtu must be boolean",
        )

    # Default nested_rci: only device-verified peer transport on NC-1812 (path_style REJECTED live).
    peer_rci_shape_raw = data.get("peer_rci_shape", WireguardPeerRciShape.NESTED_RCI.value)
    if peer_rci_shape_raw is None:
        peer_rci_shape_raw = WireguardPeerRciShape.NESTED_RCI.value
    try:
        peer_rci_shape = WireguardPeerRciShape(str(peer_rci_shape_raw))
    except ValueError as exc:
        raise IntentValidationError(
            "invalid_peer_rci_shape",
            f"{context}: peer_rci_shape must be path_style or nested_rci",
        ) from exc
    if peer_rci_shape is WireguardPeerRciShape.PATH_STYLE:
        raise IntentValidationError(
            "peer_rci_shape_unsupported",
            f"{context}: peer_rci_shape=path_style is REJECTED on NC-1812 5.01.C.1.0-0; "
            "use nested_rci (device-verified write accepted 2026-07-24)",
        )

    _require_present(data, "enabled", context=context)
    if not isinstance(data["enabled"], bool):
        raise IntentValidationError(
            "invalid_enabled",
            f"{context}: enabled must be boolean",
        )

    return WireguardIntent(
        wg_id=wg_id,
        enabled=bool(data["enabled"]),
        asc_args=asc_args,
        private_key_credential_ref_id=str(private_key_ref) if private_key_ref else None,
        preshared_key_credential_ref_id=str(psk_ref) if psk_ref else None,
        peer_public_key=str(peer_public_key).strip() if peer_public_key else None,
        peer_endpoint=str(peer_endpoint).strip() if peer_endpoint else None,
        peer_allow_ips=str(peer_allow_ips).strip() if peer_allow_ips else None,
        peer_keepalive_interval=keepalive_value,
        peer_rci_shape=peer_rci_shape,
        interface_address=interface_address,
        ip_global_priority=ip_global_priority,
        ip_global_auto=ip_global_auto,
        tcp_mss_pmtu=tcp_mss_pmtu,
    )


def parse_network_intent(kind: str, data: dict[str, Any]) -> WireguardIntent:
    """Parse a standalone network intent document by kind string."""
    if not isinstance(data, dict):
        raise IntentValidationError("invalid_document", "intent must be object")
    kind_norm = _normalize_intent_key(kind)
    if kind_norm in ("wireguard", "awg"):
        return _parse_wireguard(data)
    raise IntentValidationError("unknown_kind", "unsupported intent kind")


def _parse_wifi(data: dict[str, Any] | None, *, zone_id: ZoneId) -> WifiIntent | None:
    if data is None:
        return None
    context = f"wifi.{zone_id.value}"
    _reject_unknown_keys(
        data,
        frozenset(
            {
                "ssid",
                "enabled",
                "credential_ref_id",
                "captive_portal",
                "guest_isolation",
                "wpa_mode",
                "band",
            }
        ),
        context=context,
    )
    enabled = bool(data["enabled"])
    cred = data.get("credential_ref_id")
    if enabled and zone_id != ZoneId.GUEST and not cred:
        raise IntentValidationError(
            "wifi_credential_required",
            f"{zone_id.value}: enabled Wi-Fi requires credential_ref_id",
        )
    if cred is not None and not isinstance(cred, str):
        raise IntentValidationError("invalid_credential_ref", "credential_ref_id must be string")
    _require_present(data, "wpa_mode", context=context)
    _require_present(data, "band", context=context)
    _require_present(data, "guest_isolation", context=context)
    wpa_mode = _parse_wifi_enum(
        data["wpa_mode"],
        WifiWpaMode,
        field="wpa_mode",
        context=context,
    )
    band = _parse_wifi_enum(
        data["band"],
        WifiBand,
        field="band",
        context=context,
    )
    guest_isolation_raw = data["guest_isolation"]
    if not isinstance(guest_isolation_raw, bool):
        raise IntentValidationError(
            "invalid_guest_isolation",
            f"{context}: guest_isolation must be boolean",
        )
    # Safe default: Disabled until Coova-Chilli compiler exists (SCENARIO_PORTABLE §4).
    captive_portal_raw = data.get("captive_portal", CaptivePortalMode.DISABLED.value)
    return WifiIntent(
        ssid=str(data["ssid"]),
        enabled=enabled,
        credential_ref_id=str(cred) if cred else None,
        captive_portal=CaptivePortalMode(str(captive_portal_raw)),
        guest_isolation=guest_isolation_raw,
        wpa_mode=wpa_mode,
        band=band,
    )


def _parse_dhcp(data: dict[str, Any], *, context: str) -> DhcpIntent:
    _reject_unknown_keys(
        data,
        frozenset({"pool_start", "pool_end", "lease_seconds", "reservations"}),
        context=context,
    )
    reservations: list[DhcpReservation] = []
    for idx, item in enumerate(data.get("reservations") or []):
        if not isinstance(item, dict):
            raise IntentValidationError(
                "invalid_reservation",
                f"{context}: reservation {idx} invalid",
            )
        _reject_unknown_keys(
            item,
            frozenset({"mac_address", "ipv4_address"}),
            context=f"{context}.reservation[{idx}]",
        )
        reservations.append(
            DhcpReservation(
                mac_address=str(item["mac_address"]),
                ipv4_address=str(item["ipv4_address"]),
            )
        )
    return DhcpIntent(
        pool_start=str(data["pool_start"]),
        pool_end=str(data["pool_end"]),
        lease_seconds=int(data["lease_seconds"]),
        reservations=tuple(reservations),
    )


def _parse_dns(data: dict[str, Any], *, context: str) -> DnsIntent:
    _reject_unknown_keys(
        data,
        frozenset({"local_fqdn", "upstream_resolvers"}),
        context=context,
    )
    fqdn = normalize_fqdn(str(data["local_fqdn"]))
    resolvers = tuple(str(r) for r in (data.get("upstream_resolvers") or []))
    return DnsIntent(local_fqdn=fqdn, upstream_resolvers=resolvers)


def _parse_firewall(data: dict[str, Any], *, context: str) -> FirewallIntent:
    _reject_unknown_keys(data, frozenset({"rules"}), context=context)
    rules: list[FirewallRule] = []
    for idx, item in enumerate(data.get("rules") or []):
        if not isinstance(item, dict):
            raise IntentValidationError("invalid_firewall_rule", f"{context}: rule {idx} invalid")
        _reject_unknown_keys(
            item,
            frozenset({"action", "destination_family", "ordinal"}),
            context=f"{context}.rule[{idx}]",
        )
        rules.append(
            FirewallRule(
                action=FirewallAction(str(item["action"])),
                destination_family=FirewallDestinationFamily(str(item["destination_family"])),
                ordinal=int(item["ordinal"]),
            )
        )
    return FirewallIntent(rules=tuple(sorted(rules, key=lambda r: r.ordinal)))


def _parse_zone(data: dict[str, Any]) -> NetworkZoneIntent:
    _reject_unknown_keys(
        data,
        frozenset(
            {
                "zone_id",
                "vlan_id",
                "ipv4_cidr",
                "ipv6_posture",
                "management_allowed",
                "dhcp",
                "dns",
                "wifi",
                "firewall",
            }
        ),
        context="zone",
    )
    zone_id = ZoneId(str(data["zone_id"]))
    if "ipv6_posture" not in data:
        raise IntentValidationError(
            "ipv6_posture_missing",
            f"zone.{zone_id.value}: ipv6_posture required",
        )
    ipv6 = Ipv6Posture(str(data["ipv6_posture"]))
    return NetworkZoneIntent(
        zone_id=zone_id,
        vlan_id=int(data["vlan_id"]),
        ipv4_cidr=str(data["ipv4_cidr"]),
        ipv6_posture=ipv6,
        management_allowed=bool(data["management_allowed"]),
        dhcp=_parse_dhcp(data["dhcp"], context=f"zone.{zone_id.value}.dhcp"),
        dns=_parse_dns(data["dns"], context=f"zone.{zone_id.value}.dns"),
        wifi=_parse_wifi(data.get("wifi"), zone_id=zone_id),
        firewall=_parse_firewall(data["firewall"], context=f"zone.{zone_id.value}.firewall"),
    )


def _parse_uplink_priority(raw: Any, *, context: str) -> int:
    if raw is None:
        return 100
    if not isinstance(raw, int) or isinstance(raw, bool):
        raise IntentValidationError(
            "invalid_priority",
            f"{context}: priority must be integer",
        )
    if raw < _UPLINK_PRIORITY_MIN or raw > _UPLINK_PRIORITY_MAX:
        raise IntentValidationError(
            "invalid_priority",
            f"{context}: priority must be {_UPLINK_PRIORITY_MIN}..{_UPLINK_PRIORITY_MAX}",
        )
    return raw


def _parse_uplink_bool(
    raw: Any,
    *,
    field: str,
    context: str,
    default: bool = False,
) -> bool:
    if raw is None:
        return default
    if not isinstance(raw, bool):
        raise IntentValidationError(
            f"invalid_{field}",
            f"{context}: {field} must be boolean",
        )
    return raw


def _parse_uplink(data: dict[str, Any]) -> UplinkIntent:
    context = "uplink"
    _reject_unknown_keys(data, _UPLINK_ALLOWED_KEYS, context=context)
    mode = UplinkMode(str(data["mode"]))
    priority = _parse_uplink_priority(data.get("priority"), context=context)
    captive_portal_client = _parse_uplink_bool(
        data.get("captive_portal_client"),
        field="captive_portal_client",
        context=context,
    )

    ssid_raw = data.get("ssid")
    band_raw = data.get("band")
    cred_raw = data.get("credential_ref_id")
    bssid_raw = data.get("bssid")
    wifi_fields_present = any(v is not None for v in (ssid_raw, band_raw, cred_raw, bssid_raw))

    if mode == UplinkMode.WIFI_WAN:
        if not ssid_raw or not str(ssid_raw).strip():
            raise IntentValidationError(
                "wifi_wan_ssid_required",
                f"{context}: WifiWan requires non-empty ssid",
            )
        if not cred_raw or not str(cred_raw).strip():
            raise IntentValidationError(
                "wifi_wan_credential_required",
                f"{context}: WifiWan requires credential_ref_id",
            )
        if not isinstance(cred_raw, str):
            raise IntentValidationError(
                "invalid_credential_ref",
                f"{context}: credential_ref_id must be string",
            )
        from router_control.adapters.netcraze.allowlist import validate_ssid

        try:
            ssid = validate_ssid(str(ssid_raw))
        except ValueError as exc:
            raise IntentValidationError("invalid_ssid", f"{context}: {exc}") from exc
        band = _parse_wifi_enum(
            band_raw if band_raw is not None else WifiBand.BAND_2_4GHZ.value,
            WifiBand,
            field="band",
            context=context,
        )
        bssid: str | None = None
        if bssid_raw is not None:
            if not isinstance(bssid_raw, str):
                raise IntentValidationError(
                    "invalid_bssid",
                    f"{context}: bssid must be string",
                )
            from router_control.adapters.netcraze.dhcp_rci import validate_mac_address

            try:
                bssid = validate_mac_address(str(bssid_raw))
            except ValueError as exc:
                raise IntentValidationError("invalid_bssid", f"{context}: {exc}") from exc
        return UplinkIntent(
            mode=mode,
            ssid=ssid,
            band=band,
            credential_ref_id=str(cred_raw).strip(),
            bssid=bssid,
            priority=priority,
            captive_portal_client=captive_portal_client,
        )

    if wifi_fields_present:
        raise IntentValidationError(
            "uplink_wifi_fields_misuse",
            f"{context}: ssid/band/credential_ref_id/bssid only allowed for WifiWan mode",
        )
    return UplinkIntent(
        mode=mode,
        priority=priority,
        captive_portal_client=captive_portal_client,
    )


def _parse_rack_asset(data: dict[str, Any], *, idx: int) -> RackAssetIntent:
    _reject_unknown_keys(
        data,
        frozenset({"role", "display_name", "recommendation"}),
        context=f"rack_assets[{idx}]",
    )
    rec = data.get("recommendation")
    return RackAssetIntent(
        role=RackAssetRole(str(data["role"])),
        display_name=str(data["display_name"]),
        recommendation=str(rec) if rec is not None else None,
    )


@dataclass(frozen=True, slots=True)
class EventPresetDocument:
    name: str
    uplink: UplinkIntent
    zones: tuple[NetworkZoneIntent, ...]
    rack_assets: tuple[RackAssetIntent, ...]
    local_order_url: str
    router_owns_l3: bool = True

    def to_canonical(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "uplink": self.uplink.to_canonical(),
            "zones": [z.to_canonical() for z in sorted(self.zones, key=lambda z: z.zone_id.value)],
            "rack_assets": [a.to_canonical() for a in self.rack_assets],
            "local_order_url": self.local_order_url,
            "router_owns_l3": self.router_owns_l3,
        }

    @property
    def canonical_digest(self) -> str:
        return canonical_digest(self.to_canonical())


def parse_event_preset_document(data: dict[str, Any]) -> EventPresetDocument:
    try:
        return _parse_event_preset_document_impl(data)
    except IntentValidationError:
        raise
    except KeyError as exc:
        raise IntentValidationError(
            "missing_field", f"missing required field: {exc!s}"
        ) from exc
    except ValueError as exc:
        raise IntentValidationError("invalid_value", "invalid value") from exc
    except (AttributeError, TypeError) as exc:
        raise IntentValidationError("invalid_shape", "invalid shape") from exc


def _parse_event_preset_document_impl(data: dict[str, Any]) -> EventPresetDocument:
    if not isinstance(data, dict):
        raise IntentValidationError("invalid_document", "document must be object")
    _reject_unknown_keys(
        data,
        frozenset({"name", "uplink", "zones", "rack_assets", "local_order_url", "router_owns_l3"}),
        context="document",
    )
    zones_raw = data.get("zones")
    if not isinstance(zones_raw, list):
        raise IntentValidationError("invalid_zones", "zones must be array")
    zones = tuple(_parse_zone(z) for z in zones_raw)
    rack_raw = data.get("rack_assets") or []
    if not isinstance(rack_raw, list):
        raise IntentValidationError("invalid_rack_assets", "rack_assets must be array")
    assets = tuple(_parse_rack_asset(a, idx=i) for i, a in enumerate(rack_raw))
    return EventPresetDocument(
        name=str(data["name"]),
        uplink=_parse_uplink(data["uplink"]),
        zones=zones,
        rack_assets=assets,
        local_order_url=str(data["local_order_url"]),
        router_owns_l3=bool(data.get("router_owns_l3", True)),
    )


def _ipv4_in_network(ip: str, network: ipaddress.IPv4Network) -> bool:
    return ipaddress.IPv4Address(ip) in network


def _validate_dhcp_pool(
    zone: NetworkZoneIntent,
    network: ipaddress.IPv4Network,
    findings: list[ReadinessFinding],
) -> None:
    pool_start = ipaddress.IPv4Address(zone.dhcp.pool_start)
    pool_end = ipaddress.IPv4Address(zone.dhcp.pool_end)
    if pool_start > pool_end:
        findings.append(
            ReadinessFinding(
                code="dhcp_pool_inverted",
                severity=FindingSeverity.ERROR,
                blocking_for=BlockingFor.VALIDATION,
                summary_redacted=f"{zone.zone_id.value}: DHCP pool start after end",
            )
        )
    special = {network.network_address, network.broadcast_address}
    gateway = network.network_address + 1
    special.add(gateway)
    for ip in (pool_start, pool_end):
        if ip not in network:
            findings.append(
                ReadinessFinding(
                    code="dhcp_pool_outside_subnet",
                    severity=FindingSeverity.ERROR,
                    blocking_for=BlockingFor.VALIDATION,
                    summary_redacted=f"{zone.zone_id.value}: DHCP pool outside subnet",
                )
            )
        if ip in special:
            findings.append(
                ReadinessFinding(
                    code="dhcp_pool_special_address",
                    severity=FindingSeverity.ERROR,
                    blocking_for=BlockingFor.VALIDATION,
                    summary_redacted=f"{zone.zone_id.value}: DHCP pool uses special address",
                )
            )
    seen_ips: set[str] = set()
    seen_macs: set[str] = set()
    for res in zone.dhcp.reservations:
        ip = ipaddress.IPv4Address(res.ipv4_address)
        if ip not in network:
            findings.append(
                ReadinessFinding(
                    code="reservation_outside_subnet",
                    severity=FindingSeverity.ERROR,
                    blocking_for=BlockingFor.VALIDATION,
                    summary_redacted=f"{zone.zone_id.value}: reservation outside subnet",
                )
            )
        if ip in special:
            findings.append(
                ReadinessFinding(
                    code="reservation_special_address",
                    severity=FindingSeverity.ERROR,
                    blocking_for=BlockingFor.VALIDATION,
                    summary_redacted=f"{zone.zone_id.value}: reservation uses special address",
                )
            )
        if res.ipv4_address in seen_ips:
            findings.append(
                ReadinessFinding(
                    code="reservation_duplicate_ip",
                    severity=FindingSeverity.ERROR,
                    blocking_for=BlockingFor.VALIDATION,
                    summary_redacted=f"{zone.zone_id.value}: duplicate reservation IP",
                )
            )
        mac = res.mac_address.lower()
        if mac in seen_macs:
            findings.append(
                ReadinessFinding(
                    code="reservation_duplicate_mac",
                    severity=FindingSeverity.ERROR,
                    blocking_for=BlockingFor.VALIDATION,
                    summary_redacted=f"{zone.zone_id.value}: duplicate reservation MAC",
                )
            )
        seen_ips.add(res.ipv4_address)
        seen_macs.add(mac)
        if not (pool_start <= ip <= pool_end):
            findings.append(
                ReadinessFinding(
                    code="reservation_outside_pool",
                    severity=FindingSeverity.ERROR,
                    blocking_for=BlockingFor.VALIDATION,
                    summary_redacted=f"{zone.zone_id.value}: reservation outside pool",
                )
            )


def validate_zone_invariants(document: EventPresetDocument) -> list[ReadinessFinding]:
    findings: list[ReadinessFinding] = []
    zone_ids = [z.zone_id for z in document.zones]
    if len(zone_ids) != 4:
        findings.append(
            ReadinessFinding(
                code="zone_count_invalid",
                severity=FindingSeverity.ERROR,
                blocking_for=BlockingFor.VALIDATION,
                summary_redacted=f"expected 4 zones, got {len(zone_ids)}",
            )
        )
    if len(set(zone_ids)) != len(zone_ids):
        findings.append(
            ReadinessFinding(
                code="zone_duplicate",
                severity=FindingSeverity.ERROR,
                blocking_for=BlockingFor.VALIDATION,
                summary_redacted="duplicate zone_id rejected",
            )
        )
    missing = CANONICAL_ZONE_IDS - {z.value for z in zone_ids}
    if missing:
        findings.append(
            ReadinessFinding(
                code="zone_missing",
                severity=FindingSeverity.ERROR,
                blocking_for=BlockingFor.VALIDATION,
                summary_redacted=f"missing zones: {sorted(missing)}",
            )
        )
    extra = {z.value for z in zone_ids} - CANONICAL_ZONE_IDS
    if extra:
        findings.append(
            ReadinessFinding(
                code="zone_unknown",
                severity=FindingSeverity.ERROR,
                blocking_for=BlockingFor.VALIDATION,
                summary_redacted=f"unknown zones: {sorted(extra)}",
            )
        )

    vlans: dict[int, str] = {}
    networks: list[tuple[str, ipaddress.IPv4Network]] = []
    for zone in document.zones:
        if zone.vlan_id in vlans:
            findings.append(
                ReadinessFinding(
                    code="vlan_overlap",
                    severity=FindingSeverity.ERROR,
                    blocking_for=BlockingFor.VALIDATION,
                    summary_redacted=(
                        f"VLAN {zone.vlan_id} reused by {vlans[zone.vlan_id]}"
                        f" and {zone.zone_id.value}"
                    ),
                )
            )
        vlans[zone.vlan_id] = zone.zone_id.value
        try:
            net = ipaddress.IPv4Network(zone.ipv4_cidr, strict=False)
        except ValueError:
            findings.append(
                ReadinessFinding(
                    code="invalid_cidr",
                    severity=FindingSeverity.ERROR,
                    blocking_for=BlockingFor.VALIDATION,
                    summary_redacted=f"{zone.zone_id.value}: invalid ipv4_cidr",
                )
            )
            continue
        networks.append((zone.zone_id.value, net))
        _validate_dhcp_pool(zone, net, findings)

        if zone.zone_id == ZoneId.ADMIN_SERVER:
            if not zone.management_allowed:
                findings.append(
                    ReadinessFinding(
                        code="admin_management_required",
                        severity=FindingSeverity.ERROR,
                        blocking_for=BlockingFor.VALIDATION,
                        summary_redacted="AdminServer must allow management",
                    )
                )
        elif zone.management_allowed:
            findings.append(
                ReadinessFinding(
                    code="management_outside_admin",
                    severity=FindingSeverity.ERROR,
                    blocking_for=BlockingFor.VALIDATION,
                    summary_redacted=f"{zone.zone_id.value}: management not allowed",
                )
            )

        mgmt_rules = [
            r
            for r in zone.firewall.rules
            if r.destination_family == FirewallDestinationFamily.MANAGEMENT
            and r.action == FirewallAction.ALLOW
        ]
        if zone.zone_id != ZoneId.ADMIN_SERVER and mgmt_rules:
            findings.append(
                ReadinessFinding(
                    code="management_firewall_leak",
                    severity=FindingSeverity.ERROR,
                    blocking_for=BlockingFor.VALIDATION,
                    summary_redacted=f"{zone.zone_id.value}: management firewall allow rejected",
                )
            )

        if zone.zone_id == ZoneId.GUEST:
            order_allows = [
                r
                for r in zone.firewall.rules
                if r.destination_family == FirewallDestinationFamily.ORDER_PAGE
                and r.action == FirewallAction.ALLOW
            ]
            if zone.wifi and zone.wifi.enabled:
                if not order_allows:
                    findings.append(
                        ReadinessFinding(
                            code="guest_wifi_without_order_page",
                            severity=FindingSeverity.ERROR,
                            blocking_for=BlockingFor.VALIDATION,
                            summary_redacted="Guest Wi-Fi enabled requires OrderPage allow",
                        )
                    )
                if not zone.wifi.guest_isolation:
                    findings.append(
                        ReadinessFinding(
                            code="guest_isolation_required",
                            severity=FindingSeverity.ERROR,
                            blocking_for=BlockingFor.VALIDATION,
                            summary_redacted="Guest Wi-Fi requires client isolation",
                        )
                    )
            disallowed_guest_allows = [
                r
                for r in zone.firewall.rules
                if r.action == FirewallAction.ALLOW
                and r.destination_family not in GUEST_ALLOWED_ALLOW_FAMILIES
            ]
            if disallowed_guest_allows:
                findings.append(
                    ReadinessFinding(
                        code="guest_not_order_page_only",
                        severity=FindingSeverity.ERROR,
                        blocking_for=BlockingFor.VALIDATION,
                        summary_redacted=(
                            "Guest firewall ALLOW limited to OrderPage, DNS, and DHCP"
                        ),
                    )
                )

    for i, (name_a, net_a) in enumerate(networks):
        for name_b, net_b in networks[i + 1 :]:
            if net_a.overlaps(net_b):
                findings.append(
                    ReadinessFinding(
                        code="subnet_overlap",
                        severity=FindingSeverity.ERROR,
                        blocking_for=BlockingFor.VALIDATION,
                        summary_redacted=f"subnet overlap between {name_a} and {name_b}",
                    )
                )

    if document.uplink.mode == UplinkMode.LTE:
        findings.append(
            ReadinessFinding(
                code="uplink_lte_deferred",
                severity=FindingSeverity.WARNING,
                blocking_for=BlockingFor.APPLY_FRAGMENT,
                summary_redacted="LTE uplink deferred; blocks apply fragment",
                family="uplink",
            )
        )

    if document.uplink.captive_portal_client:
        findings.append(
            ReadinessFinding(
                code="uplink_captive_portal_client_unsupported",
                severity=FindingSeverity.WARNING,
                blocking_for=BlockingFor.APPLY_FRAGMENT,
                summary_redacted=(
                    "Uplink captive-portal client mode not supported yet "
                    "(distinct from host Coova-Chilli captive portal)"
                ),
                family="uplink",
            )
        )

    if not document.router_owns_l3:
        findings.append(
            ReadinessFinding(
                code="unmanaged_ownership_inferred",
                severity=FindingSeverity.ERROR,
                blocking_for=BlockingFor.VALIDATION,
                summary_redacted="router_owns_l3 must be true; unmanaged ownership not inferred",
            )
        )

    hub_roles = [a for a in document.rack_assets if a.role == RackAssetRole.HUB]
    router_roles = [a for a in document.rack_assets if a.role == RackAssetRole.ROUTER]
    if not hub_roles or not router_roles:
        findings.append(
            ReadinessFinding(
                code="rack_missing_core_roles",
                severity=FindingSeverity.ERROR,
                blocking_for=BlockingFor.VALIDATION,
                summary_redacted="rack must include Hub and Router assets",
            )
        )

    return findings


def validation_blocking(findings: list[ReadinessFinding]) -> bool:
    return any(
        f.severity == FindingSeverity.ERROR and f.blocking_for == BlockingFor.VALIDATION
        for f in findings
    )


@dataclass(frozen=True, slots=True)
class TopologyGatewayBinding:
    zone_id: str
    ipv4_gateway: str

    def to_canonical(self) -> dict[str, Any]:
        return {"zone_id": self.zone_id, "ipv4_gateway": self.ipv4_gateway}


@dataclass(frozen=True, slots=True)
class TopologyBinding:
    """Explicit port/radio/gateway bindings — no silent .1 inference."""

    gateways: tuple[TopologyGatewayBinding, ...]
    ports: tuple[str, ...] = ()
    radios: tuple[str, ...] = ()

    def to_canonical(self) -> dict[str, Any]:
        return {
            "gateways": [g.to_canonical() for g in self.gateways],
            "ports": list(self.ports),
            "radios": list(self.radios),
        }


def gateway_for_cidr(cidr: str) -> str:
    """Explicit gateway from CIDR — caller must persist; never silent default."""
    network = ipaddress.IPv4Network(cidr, strict=False)
    return str(network.network_address + 1)
