"""Frozen allowlist of read-only and sealed write RCI commands for Gate A transport."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
from dataclasses import dataclass
from enum import StrEnum

LAB_CLASS_EXPENDABLE = "expendable_development_router"
_ROUTER_CONTROL_LAB_CLASS_ENV = "ROUTER_CONTROL_LAB_CLASS"


class HttpMethod(StrEnum):
    GET = "GET"
    POST = "POST"


@dataclass(frozen=True, slots=True)
class ReadCommand:
    name: str
    method: HttpMethod
    path: str


@dataclass(frozen=True, slots=True)
class WriteAllowlistEntry:
    method: HttpMethod
    path: str
    body_sha256: str


SHOW_SYSTEM = ReadCommand("show_system", HttpMethod.GET, "/rci/show/system")
COMPONENTS_LIST = ReadCommand("components_list", HttpMethod.POST, "/rci/components/list")
COMPONENTS_LIST_STATUS = ReadCommand(
    "components_list_status", HttpMethod.GET, "/rci/components/list"
)
SHOW_IDENTIFICATION = ReadCommand(
    "show_identification", HttpMethod.GET, "/rci/show/identification"
)
SHOW_VERSION = ReadCommand("show_version", HttpMethod.GET, "/rci/show/version")

ALLOWLIST: frozenset[ReadCommand] = frozenset(
    {SHOW_SYSTEM, COMPONENTS_LIST, SHOW_IDENTIFICATION, SHOW_VERSION}
)

MAX_CONTINUATION_ROUNDS = 5
DEFAULT_CONTINUATION_BUDGET_SECONDS = 30.0

SHOW_INTERFACE = ReadCommand("show_interface", HttpMethod.GET, "/rci/show/interface")
SHOW_RC_INTERFACE = ReadCommand("show_rc_interface", HttpMethod.GET, "/rci/show/rc/interface")
SHOW_IP_ROUTE = ReadCommand("show_ip_route", HttpMethod.GET, "/rci/show/ip/route")
SHOW_IP_POLICY = ReadCommand("show_ip_policy", HttpMethod.GET, "/rci/show/ip/policy")
SHOW_IP_NAME_SERVER = ReadCommand(
    "show_ip_name_server", HttpMethod.GET, "/rci/show/ip/name-server"
)
SHOW_IP_SSH = ReadCommand("show_ip_ssh", HttpMethod.GET, "/rci/ip/ssh")
SHOW_IP_HTTP = ReadCommand("show_ip_http", HttpMethod.GET, "/rci/ip/http")

DISCOVERY_ALLOWLIST: frozenset[ReadCommand] = frozenset({SHOW_INTERFACE, SHOW_IP_ROUTE})

# VPN connection-policy readback (help-verified show only; rejected forms refused offline).
VPN_POLICY_READ_ALLOWLIST: frozenset[ReadCommand] = frozenset(
    {SHOW_IP_POLICY, SHOW_IP_NAME_SERVER}
)

_REJECTED_VPN_POLICY_SHOW_COMMANDS = frozenset(
    {
        "show rc ip policy",
        "show ip name-servers",
        "show name-server",
        "show hotspot",
    }
)

# Station configured/runtime readback (non-certifying; separate from topology discovery).
STATION_READ_ALLOWLIST: frozenset[ReadCommand] = frozenset(
    {SHOW_INTERFACE, SHOW_RC_INTERFACE}
)

BOOTSTRAP_DISCOVERY_ALLOWLIST: frozenset[ReadCommand] = frozenset(
    {
        SHOW_SYSTEM,
        COMPONENTS_LIST,
        COMPONENTS_LIST_STATUS,
        SHOW_IDENTIFICATION,
        SHOW_VERSION,
        SHOW_INTERFACE,
        SHOW_IP_SSH,
        SHOW_IP_HTTP,
    }
)

DEFAULT_DISCOVERY_MAX_BYTES = 2 * 1024 * 1024

RCI_WRITE_PATH = "/rci/"

_INTERFACE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
# Sealed Wi-Fi station uplink ids (wifi_station_validation.ALLOWED_WIFI_STATION_IDS).
_WIFI_STATION_INTERFACE_ID_RE = re.compile(r"^WifiMaster[01]/WifiStation0$")
_INTERFACE_PARSE_COMMAND_RE = re.compile(
    r"^interface [A-Za-z0-9][A-Za-z0-9._-]{0,63} (?:up|down)$"
)
# Wi-Fi AP sealed write template on WifiMaster0|1.
# Observed hardware inventory: NC-1812 firmware 5.01.C.1.0-0 (READ-ONLY 2026-07-31) —
# AccessPoint0..6 per radio only; AP7/8/9 not present on device.
# Default (non-expendable): AccessPoint3–6 only — rejects AccessPoint0/1/2 and AP7+.
# Expendable lab (`ROUTER_CONTROL_LAB_CLASS=expendable_development_router`): AccessPoint0–6.
# Allows up|down|no ssid|ssid <bounded>|WPA-PSK|encryption verbs; no other prefixes.
# Body may contain SECRET (psk) → body_sha256 varies per secret; template matches
# structure not digest. Do not weaken existing ssid/up/down checks.
WIFI_AP_INDEX_MAX = 6
WIFI_AP_INDEX_DEFAULT_MIN = 3
WIFI_AP_INDEX_EXPENDABLE_MIN = 0
_WIFI_SSID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
_WIFI_WPA_PSK_CHARSET = r"[A-Za-z0-9._:+@%/=~^|!?&*()\[\]{}#,<>\-]"
_WIFI_WPA_PSK_RE = re.compile(rf"^{_WIFI_WPA_PSK_CHARSET}{{8,63}}$")


def is_expendable_lab_class() -> bool:
    """True when ``ROUTER_CONTROL_LAB_CLASS=expendable_development_router``."""
    return os.environ.get(_ROUTER_CONTROL_LAB_CLASS_ENV, "").strip() == LAB_CLASS_EXPENDABLE


def wifi_ap_index_min() -> int:
    """Inclusive lower bound for allowlisted AccessPoint index on this lab class."""
    return (
        WIFI_AP_INDEX_EXPENDABLE_MIN
        if is_expendable_lab_class()
        else WIFI_AP_INDEX_DEFAULT_MIN
    )


def wifi_ap_index_max() -> int:
    """Inclusive upper bound from observed hardware inventory (AccessPoint0..6)."""
    return WIFI_AP_INDEX_MAX


def _wifi_ap_index_class() -> str:
    lo = wifi_ap_index_min()
    hi = wifi_ap_index_max()
    if lo == hi:
        return str(lo)
    return f"[{lo}-{hi}]"


def _wifi_ap_id_re() -> re.Pattern[str]:
    return re.compile(rf"^WifiMaster[01]/AccessPoint{_wifi_ap_index_class()}$")


def _wifi_ap_parse_command_re() -> re.Pattern[str]:
    idx = _wifi_ap_index_class()
    return re.compile(
        rf"^interface WifiMaster[01]/AccessPoint{idx} "
        r"(?:"
        r"up|down|no ssid|ssid [A-Za-z0-9][A-Za-z0-9._-]{0,31}|"
        r"authentication wpa-psk [A-Za-z0-9._:+@%/=~^|!?&*()\[\]{}#,<>\-]{8,63}|"
        r"no authentication wpa-psk|"
        r"encryption enable|no encryption enable|"
        r"encryption wpa2|no encryption wpa2|"
        r"encryption wpa3|no encryption wpa3"
        r")$"
    )
# WireGuard sealed write template.
# Default (non-expendable): Wireguard5–9 only.
# Expendable lab (`ROUTER_CONTROL_LAB_CLASS=expendable_development_router`): Wireguard0–9.
# Allows: create/remove, asc (9 or 16 ints), private-key set/clear, bare peer create/remove,
# path-style peer endpoint/allow-ips/keepalive-interval (one CLI line per RCI parse request),
# peer preshared-key set/clear, ip address set/clear, ip global auto|order|priority, no ip global.
# Secret key material matched by base64 SHAPE only (43–44 chars); digest varies per secret.
# up|down already covered by generic interface template — do not duplicate.
# ASC-9 documented order: jc jmin jmax s1 s2 h1 h2 h3 h4 (see probe help + OPERATOR_AWG_DISCOVERY).
# Positions 0–4 (jc,jmin,jmax,s1,s2): 0..99999 — prior uniform 5-digit cap for small params.
# Positions 5–8 (h1–h4): 0..UINT32_MAX — AmneziaWG header magic is 32-bit unsigned.
# Arity 16 (allowlist shape only; product planner soft-rejects): each token 0..UINT32_MAX.
_ASC_SMALL_PARAM_MAX = 99_999
_ASC_UINT32_MAX = 4_294_967_295
_ASC9_ARITY = 9
_ASC16_ARITY = 16
_WIREGUARD_ASC_ARGS_SHAPE_RE = re.compile(
    r"^(?:[0-9]+ ){8}[0-9]+$|^(?:[0-9]+ ){15}[0-9]+$"
)
_WG_KEY_SHAPE = r"[A-Za-z0-9+/=_-]{43,44}"
_WG_ENDPOINT_SHAPE = r"[A-Za-z0-9._:-]{1,253}:[0-9]{1,5}"
_WG_IPV4_SHAPE = r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}"
_WG_MASK_SHAPE = rf"(?:{_WG_IPV4_SHAPE}|[0-9]{{1,3}})"
_WG_KEEPALIVE_SHAPE = r"[0-9]{1,4}"


def _wireguard_index_class() -> str:
    return "[0-9]" if is_expendable_lab_class() else "[5-9]"


def _wireguard_id_re() -> re.Pattern[str]:
    return re.compile(rf"^Wireguard{_wireguard_index_class()}$")


def _wg_peer_endpoint_arm() -> str:
    idx = _wireguard_index_class()
    return (
        rf"interface Wireguard{idx} wireguard peer {_WG_KEY_SHAPE} "
        rf"endpoint {_WG_ENDPOINT_SHAPE}"
    )


def _wg_peer_allow_ips_arm() -> str:
    idx = _wireguard_index_class()
    return (
        rf"interface Wireguard{idx} wireguard peer {_WG_KEY_SHAPE} "
        rf"allow-ips {_WG_IPV4_SHAPE} {_WG_MASK_SHAPE}"
    )


def _wg_peer_keepalive_arm() -> str:
    idx = _wireguard_index_class()
    return (
        rf"interface Wireguard{idx} wireguard peer {_WG_KEY_SHAPE} "
        rf"keepalive-interval {_WG_KEEPALIVE_SHAPE}"
    )


def _wireguard_parse_command_re() -> re.Pattern[str]:
    idx = _wireguard_index_class()
    return re.compile(
        rf"^(?:"
        rf"interface Wireguard{idx}"
        rf"|no interface Wireguard{idx}"
        rf"|interface Wireguard{idx} wireguard asc (?:[0-9]+ ){{8}}[0-9]+"
        rf"|interface Wireguard{idx} wireguard asc (?:[0-9]+ ){{15}}[0-9]+"
        rf"|interface Wireguard{idx} wireguard private-key {_WG_KEY_SHAPE}"
        rf"|interface Wireguard{idx} no wireguard private-key"
        rf"|interface Wireguard{idx} wireguard peer {_WG_KEY_SHAPE}"
        rf"|{_wg_peer_endpoint_arm()}"
        rf"|{_wg_peer_allow_ips_arm()}"
        rf"|{_wg_peer_keepalive_arm()}"
        rf"|interface Wireguard{idx} no wireguard peer {_WG_KEY_SHAPE}"
        rf"|interface Wireguard{idx} wireguard peer {_WG_KEY_SHAPE} preshared-key {_WG_KEY_SHAPE}"
        rf"|interface Wireguard{idx} no wireguard peer {_WG_KEY_SHAPE} preshared-key"
        rf"|interface Wireguard{idx} ip address {_WG_IPV4_SHAPE} {_WG_MASK_SHAPE}"
        rf"|interface Wireguard{idx} no ip address"
        rf"|interface Wireguard{idx} ip global auto"
        rf"|interface Wireguard{idx} ip global order [0-9]{{1,5}}"
        rf"|interface Wireguard{idx} ip global [0-9]{{1,5}}"
        rf"|interface Wireguard{idx} no ip global"
        rf"|interface Wireguard{idx} ip tcp adjust-mss pmtu"
        rf"|interface Wireguard{idx} no ip tcp adjust-mss"
        rf")$"
    )


def body_sha256(body: bytes) -> str:
    return f"sha256:{hashlib.sha256(body).hexdigest()}"


def build_sealed_parse_body(cli_command: str) -> bytes:
    """Serialize a single sealed CLI command to the fixed RCI parse POST body."""
    command = cli_command.strip()
    if not command:
        raise ValueError("empty sealed parse command")
    return json.dumps([{"parse": command}]).encode("utf-8")


_FAIL_SAFE_ARM_BODY_SHA256 = body_sha256(
    build_sealed_parse_body("system configuration fail-safe timer reboot 60")
)
_FAIL_SAFE_DISARM_BODY_SHA256 = body_sha256(
    build_sealed_parse_body("no system configuration fail-safe timer")
)
_SYSTEM_SAVE_BODY_SHA256 = body_sha256(build_sealed_parse_body("system configuration save"))
_SYSTEM_REBOOT_BODY_SHA256 = body_sha256(build_sealed_parse_body("system reboot"))

WRITE_ALLOWLIST: frozenset[WriteAllowlistEntry] = frozenset(
    {
        WriteAllowlistEntry(HttpMethod.POST, RCI_WRITE_PATH, _FAIL_SAFE_ARM_BODY_SHA256),
        WriteAllowlistEntry(HttpMethod.POST, RCI_WRITE_PATH, _FAIL_SAFE_DISARM_BODY_SHA256),
        WriteAllowlistEntry(HttpMethod.POST, RCI_WRITE_PATH, _SYSTEM_SAVE_BODY_SHA256),
        WriteAllowlistEntry(HttpMethod.POST, RCI_WRITE_PATH, _SYSTEM_REBOOT_BODY_SHA256),
    }
)

_FIXED_WRITE_BODY_SHA256S: frozenset[str] = frozenset(
    entry.body_sha256 for entry in WRITE_ALLOWLIST
)


def is_allowlisted(method: str, path: str) -> bool:
    normalized_path = path if path.startswith("/") else f"/{path}"
    for command in ALLOWLIST:
        if command.method == method and command.path == normalized_path:
            return True
    return False


def is_discovery_allowlisted(method: str, path: str) -> bool:
    normalized_path = path if path.startswith("/") else f"/{path}"
    for command in DISCOVERY_ALLOWLIST:
        if command.method == method and command.path == normalized_path:
            return True
    return False


def is_station_read_allowlisted(method: str, path: str) -> bool:
    normalized_path = path if path.startswith("/") else f"/{path}"
    for command in STATION_READ_ALLOWLIST:
        if command.method == method and command.path == normalized_path:
            return True
    return False


def is_bootstrap_discovery_allowlisted(method: str, path: str) -> bool:
    normalized_path = path if path.startswith("/") else f"/{path}"
    for command in BOOTSTRAP_DISCOVERY_ALLOWLIST:
        if command.method == method and command.path == normalized_path:
            return True
    return False


def is_vpn_policy_read_allowlisted(method: str, path: str) -> bool:
    normalized_path = path if path.startswith("/") else f"/{path}"
    for command in VPN_POLICY_READ_ALLOWLIST:
        if command.method == method and command.path == normalized_path:
            return True
    return False


def refuse_rejected_vpn_policy_show_command(command: str) -> None:
    """Refuse firmware-rejected VPN policy show commands (:87,:230-233 §7)."""
    normalized = command.strip().lower()
    if normalized in _REJECTED_VPN_POLICY_SHOW_COMMANDS:
        raise ValueError(
            f"show command rejected and not allowlisted: {command!r} "
            "(OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md:87,:230-233 §7)"
        )


def validate_vpn_policy_read_command(command: str) -> ReadCommand:
    """Map help-verified show command to ReadCommand or fail-closed."""
    normalized = command.strip().lower()
    refuse_rejected_vpn_policy_show_command(command)
    if normalized == "show ip policy":
        return SHOW_IP_POLICY
    if normalized == "show ip name-server":
        return SHOW_IP_NAME_SERVER
    raise ValueError(f"vpn policy read command not allowlisted: {command!r}")


def validate_interface_id(interface_id: str) -> str:
    """Return normalized bounded interface id or raise ValueError."""
    normalized = interface_id.strip()
    if not normalized or len(normalized) > 64:
        raise ValueError("interface id length out of bounds")
    if _WIFI_STATION_INTERFACE_ID_RE.fullmatch(normalized):
        return normalized
    if not _INTERFACE_ID_RE.fullmatch(normalized):
        raise ValueError("interface id contains disallowed characters")
    return normalized


def validate_wifi_ap_id(ap_id: str) -> str:
    """Return normalized Wi-Fi AP id or raise ValueError.

    Default: WifiMaster0|1 + AccessPoint3–6 (rejects AccessPoint0/1/2 and AP7+).
    Expendable lab class: WifiMaster0|1 + AccessPoint0–6.
    """
    normalized = ap_id.strip()
    if not normalized:
        raise ValueError("wifi ap id is empty")
    if not _wifi_ap_id_re().fullmatch(normalized):
        raise ValueError("wifi ap id is not an allowlisted test access point")
    return normalized


def validate_ssid(ssid: str) -> str:
    """Return normalized bounded SSID or raise ValueError."""
    normalized = ssid.strip()
    if not normalized:
        raise ValueError("ssid is empty")
    if not _WIFI_SSID_RE.fullmatch(normalized):
        raise ValueError("ssid contains disallowed characters or length")
    return normalized


def validate_wpa_psk(psk: str) -> str:
    """Return normalized bounded WPA-PSK or raise ValueError.

    ASCII 8–63 chars; charset excludes whitespace, control, JSON-breaking,
    and shell-metacharacters (space, quote, semicolon, backtick, newline, $, backslash).
    """
    normalized = psk.strip()
    if not normalized:
        raise ValueError("wpa psk is empty")
    if not _WIFI_WPA_PSK_RE.fullmatch(normalized):
        raise ValueError("wpa psk contains disallowed characters or length")
    return normalized


def is_interface_parse_body(body: bytes) -> bool:
    """True when body is a sealed interface up/down parse template."""
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    if not isinstance(payload, list) or len(payload) != 1:
        return False
    entry = payload[0]
    if not isinstance(entry, dict) or set(entry.keys()) != {"parse"}:
        return False
    command = entry.get("parse")
    if not isinstance(command, str):
        return False
    return _INTERFACE_PARSE_COMMAND_RE.fullmatch(command.strip()) is not None


def is_wifi_ap_parse_body(body: bytes) -> bool:
    """True when body is a sealed Wi-Fi AP up/down/ssid/WPA/encryption parse template."""
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    if not isinstance(payload, list) or len(payload) != 1:
        return False
    entry = payload[0]
    if not isinstance(entry, dict) or set(entry.keys()) != {"parse"}:
        return False
    command = entry.get("parse")
    if not isinstance(command, str):
        return False
    return _wifi_ap_parse_command_re().fullmatch(command.strip()) is not None


def _validate_wifi_station_command_tail(tail: str) -> bool:
    """Semantic validation for Wi-Fi station sealed parse tail (station id already checked)."""
    if tail in {
        "up",
        "down",
        "no ssid",
        "no authentication wpa-psk",
        "encryption enable",
        "no encryption enable",
        "encryption wpa2",
        "no encryption wpa2",
        "ip address dhcp",
        "no ip address dhcp",
        "no ip address",
    }:
        return True
    ssid_prefix = "ssid "
    if tail.startswith(ssid_prefix):
        remainder = tail[len(ssid_prefix) :]
        if remainder != remainder.lstrip():
            return False
        try:
            validate_ssid(remainder)
        except ValueError:
            return False
        return True
    psk_prefix = "authentication wpa-psk "
    if tail.startswith(psk_prefix):
        remainder = tail[len(psk_prefix) :]
        if remainder != remainder.lstrip():
            return False
        try:
            validate_wpa_psk(remainder)
        except ValueError:
            return False
        return True
    global_prefix = "ip global "
    if tail.startswith(global_prefix):
        remainder = tail[len(global_prefix) :]
        if remainder == "auto" or remainder.startswith("order "):
            return False
        if not re.fullmatch(r"[0-9]{1,5}", remainder):
            return False
        if len(remainder) > 1 and remainder[0] == "0":
            return False
        from router_control.adapters.netcraze.vpn_policy_rci import validate_ip_global_bound

        try:
            validate_ip_global_bound(int(remainder), field="priority")
        except ValueError:
            return False
        return True
    return False


def _ndns_name_token_re() -> str:
    return r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"


def _ndns_domain_alternation() -> str:
    from router_control.application.keendns_planner import KEENDNS_ALLOWED_DOMAINS

    return "|".join(re.escape(domain) for domain in sorted(KEENDNS_ALLOWED_DOMAINS))


def _ndns_book_command_re() -> re.Pattern[str]:
    name = _ndns_name_token_re()
    domain = _ndns_domain_alternation()
    return re.compile(rf"^ndns book-name {name} ({domain}) (auto|cloud|direct)$")


def _ndns_drop_command_re() -> re.Pattern[str]:
    name = _ndns_name_token_re()
    domain = _ndns_domain_alternation()
    return re.compile(rf"^ndns drop-name {name} ({domain})$")


def is_ndns_parse_body(body: bytes) -> bool:
    """True when body is a sealed ndns book-name or drop-name parse template (exact fullmatch)."""
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    if not isinstance(payload, list) or len(payload) != 1:
        return False
    entry = payload[0]
    if not isinstance(entry, dict) or set(entry.keys()) != {"parse"}:
        return False
    command = entry.get("parse")
    if not isinstance(command, str):
        return False
    stripped = command.strip()
    return (
        _ndns_book_command_re().fullmatch(stripped) is not None
        or _ndns_drop_command_re().fullmatch(stripped) is not None
    )


def is_wifi_station_parse_body(body: bytes) -> bool:
    """True when body is a sealed Wi-Fi station first-slice write parse template."""
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    if not isinstance(payload, list) or len(payload) != 1:
        return False
    entry = payload[0]
    if not isinstance(entry, dict) or set(entry.keys()) != {"parse"}:
        return False
    command = entry.get("parse")
    if not isinstance(command, str):
        return False
    stripped = command.strip()
    prefix = "interface "
    if not stripped.startswith(prefix):
        return False
    rest = stripped[len(prefix) :]
    space_idx = rest.find(" ")
    if space_idx < 0:
        return False
    station_id = rest[:space_idx]
    tail = rest[space_idx + 1 :]
    from router_control.adapters.netcraze.wifi_station_validation import validate_wifi_station_id

    try:
        validate_wifi_station_id(station_id)
    except ValueError:
        return False
    return _validate_wifi_station_command_tail(tail)


def validate_wireguard_id(wg_id: str) -> str:
    """Return normalized WireGuard interface id or raise ValueError.

    Default: Wireguard5–9 (throwaway test interfaces). Rejects Wireguard0–4.
    Expendable lab class: Wireguard0–9.
    """
    normalized = wg_id.strip()
    if not normalized:
        raise ValueError("wireguard id is empty")
    if not _wireguard_id_re().fullmatch(normalized):
        raise ValueError("wireguard id is not an allowlisted test interface")
    return normalized


_WIREGUARD_NAME_PROBE_SEPARATORS_RE = re.compile(r"[-_.\s]+")
_WG_SHORT_INTERFACE_NAME_RE = re.compile(r"^wg\d+$")


def normalize_wireguard_name_probe(name: str) -> str:
    """Casefold and strip separator chars for wireguard-like interface detection."""
    return _WIREGUARD_NAME_PROBE_SEPARATORS_RE.sub("", name.casefold())


def is_wireguard_like_interface_name(interface_id: str) -> bool:
    """True when normalized name starts with ``wireguard`` or matches ``wg`` + digits."""
    normalized = normalize_wireguard_name_probe(interface_id.strip())
    if normalized.startswith("wireguard"):
        return True
    return _WG_SHORT_INTERFACE_NAME_RE.fullmatch(normalized) is not None


def is_canonical_wireguard_interface_id(interface_id: str) -> bool:
    """True only when ``validate_wireguard_id`` accepts the interface id."""
    try:
        validate_wireguard_id(interface_id)
    except ValueError:
        return False
    return True


_WG_KEY_RE = re.compile(rf"^{_WG_KEY_SHAPE}$")
_WG_ENDPOINT_RE = re.compile(rf"^{_WG_ENDPOINT_SHAPE}$")
_WG_IPV4_RE = re.compile(rf"^{_WG_IPV4_SHAPE}$")
_WG_MASK_RE = re.compile(rf"^{_WG_MASK_SHAPE}$")


def validate_wg_key_shape(key: str) -> str:
    """Return normalized WireGuard key base64 SHAPE or raise ValueError.

    Matches charset+length only (43–44 chars); does not log or store the value.
    """
    normalized = key.strip()
    if not normalized:
        raise ValueError("wireguard key is empty")
    if not _WG_KEY_RE.fullmatch(normalized):
        raise ValueError("wireguard key shape invalid")
    return normalized


def validate_peer_public_key(pubkey: str) -> str:
    """Return normalized peer public-key SHAPE or raise ValueError."""
    return validate_wg_key_shape(pubkey)


def validate_peer_endpoint(endpoint: str) -> str:
    """Return normalized host:port endpoint or raise ValueError."""
    normalized = endpoint.strip()
    if not normalized:
        raise ValueError("peer endpoint is empty")
    if not _WG_ENDPOINT_RE.fullmatch(normalized):
        raise ValueError("peer endpoint shape invalid")
    host, _, port_text = normalized.rpartition(":")
    if not host or not port_text.isdigit():
        raise ValueError("peer endpoint must be host:port")
    port = int(port_text)
    if port < 1 or port > 65535:
        raise ValueError("peer endpoint port out of range")
    return normalized


def _peer_allow_ips_host_part(entry: str) -> str:
    normalized = entry.strip()
    if "/" in normalized:
        return normalized.partition("/")[0].strip()
    parts = normalized.split()
    if parts:
        return parts[0].strip()
    return normalized


def _is_ipv6_peer_allow_ips_entry(entry: str) -> bool:
    host = _peer_allow_ips_host_part(entry)
    return bool(host) and ":" in host


def validate_peer_allow_ips(allow_ips: str) -> tuple[str, str]:
    """Parse allow-ips as 'ipv4 mask' or 'ipv4/prefix' → (ipv4, mask)."""
    normalized = allow_ips.strip()
    if not normalized:
        raise ValueError("peer allow_ips is empty")
    if _is_ipv6_peer_allow_ips_entry(normalized):
        raise ValueError(f"peer allow_ips IPv6 entry unsupported: {normalized!r}")
    if "/" in normalized:
        ipv4, _, prefix_text = normalized.partition("/")
        ipv4 = ipv4.strip()
        prefix_text = prefix_text.strip()
        if not prefix_text.isdigit():
            raise ValueError("peer allow_ips CIDR prefix invalid")
        prefix = int(prefix_text)
        if prefix < 0 or prefix > 32:
            raise ValueError("peer allow_ips CIDR prefix out of range")
        if not _WG_IPV4_RE.fullmatch(ipv4):
            raise ValueError("peer allow_ips ipv4 invalid")
        return ipv4, str(prefix)
    parts = normalized.split()
    if len(parts) != 2:
        raise ValueError("peer allow_ips must be 'ipv4 mask' or 'ipv4/prefix'")
    ipv4, mask = parts[0].strip(), parts[1].strip()
    if not _WG_IPV4_RE.fullmatch(ipv4):
        raise ValueError("peer allow_ips ipv4 invalid")
    if mask.isdigit():
        prefix = int(mask)
        if prefix < 0 or prefix > 32:
            raise ValueError("peer allow_ips mask out of range")
        return ipv4, mask
    if not _WG_MASK_RE.fullmatch(mask):
        raise ValueError("peer allow_ips mask invalid")
    return ipv4, mask


def validate_keepalive_interval(value: int) -> int:
    """Return validated keepalive interval (3..3600) or raise ValueError."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError("keepalive interval must be integer")
    if value < 3 or value > 3600:
        raise ValueError("keepalive interval must be 3..3600")
    return value


def _asc_token_max_for_position(position: int, *, arity: int) -> int:
    if arity == _ASC16_ARITY:
        return _ASC_UINT32_MAX
    if position <= 4:
        return _ASC_SMALL_PARAM_MAX
    return _ASC_UINT32_MAX


def _validate_asc_tokens(tokens: list[str]) -> None:
    """Fail-closed per-position bounds for ASC token list (shared by validate + sealed parse)."""
    arity = len(tokens)
    if arity not in (_ASC9_ARITY, _ASC16_ARITY):
        raise ValueError("asc args must be exactly 9 or 16 non-negative integers")
    for position, token in enumerate(tokens):
        if not token or not token.isdigit():
            raise ValueError("asc args must be exactly 9 or 16 non-negative integers")
        value = int(token)
        token_max = _asc_token_max_for_position(position, arity=arity)
        if value > token_max:
            raise ValueError("asc args must be exactly 9 or 16 non-negative integers")


def validate_asc_args(asc_args: str) -> str:
    """Return normalized asc args or raise ValueError.

    Requires EXACTLY 9 or EXACTLY 16 space-separated decimal tokens (strict ``[0-9]+``,
    no sign/whitespace inside tokens). Per-position bounds: jc..s2 → 0..99999; h1..h4 →
    0..4294967295; arity-16 allowlist tokens → 0..4294967295 each.
    """
    normalized = asc_args.strip()
    if not normalized:
        raise ValueError("asc args is empty")
    if "  " in normalized:
        raise ValueError("asc args must be exactly 9 or 16 non-negative integers")
    if not _WIREGUARD_ASC_ARGS_SHAPE_RE.fullmatch(normalized):
        raise ValueError("asc args must be exactly 9 or 16 non-negative integers")
    tokens = normalized.split(" ")
    if any(not part for part in tokens):
        raise ValueError("asc args must be exactly 9 or 16 non-negative integers")
    _validate_asc_tokens(tokens)
    return normalized


def is_wireguard_parse_body(body: bytes) -> bool:
    """True when body is a sealed WireGuard create/remove/asc parse template."""
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    if not isinstance(payload, list) or len(payload) != 1:
        return False
    entry = payload[0]
    if not isinstance(entry, dict) or set(entry.keys()) != {"parse"}:
        return False
    command = entry.get("parse")
    if not isinstance(command, str):
        return False
    stripped = command.strip()
    if _wireguard_parse_command_re().fullmatch(stripped) is None:
        return False
    asc_prefix = " wireguard asc "
    asc_idx = stripped.find(asc_prefix)
    if asc_idx >= 0:
        asc_args = stripped[asc_idx + len(asc_prefix) :]
        try:
            validate_asc_args(asc_args)
        except ValueError:
            return False
    if " ip address " in stripped and "no ip address" not in stripped:
        from router_control.adapters.netcraze.rci_validation import RciValidationError
        from router_control.adapters.netcraze.vlan_rci import (
            validate_ipv4_dotted_mask,
            validate_ipv4_gateway,
        )

        tokens = stripped.split(" ")
        addr = tokens[-2]
        mask = tokens[-1]
        try:
            validate_ipv4_gateway(addr)
            validate_ipv4_dotted_mask(mask)
        except (RciValidationError, ValueError):
            return False
    if " ip global " in stripped and "no ip global" not in stripped:
        order_suffix = " ip global order "
        if order_suffix in stripped:
            from router_control.adapters.netcraze.vpn_policy_rci import validate_ip_global_bound

            order_idx = stripped.rfind(order_suffix)
            digits = stripped[order_idx + len(order_suffix) :]
            try:
                validate_ip_global_bound(int(digits), field="order")
            except ValueError:
                return False
        elif not stripped.endswith(" ip global auto"):
            from router_control.adapters.netcraze.vpn_policy_rci import validate_ip_global_bound

            global_suffix = " ip global "
            global_idx = stripped.rfind(global_suffix)
            digits = stripped[global_idx + len(global_suffix) :]
            try:
                validate_ip_global_bound(int(digits), field="priority")
            except ValueError:
                return False
    if " ip tcp adjust-mss " in stripped and "no ip tcp adjust-mss" not in stripped:
        from router_control.adapters.netcraze.tcp_mss_validation import validate_tcp_mss_bound

        mss_suffix = " ip tcp adjust-mss "
        mss_idx = stripped.rfind(mss_suffix)
        mode = stripped[mss_idx + len(mss_suffix) :]
        try:
            validate_tcp_mss_bound(mode)
        except ValueError:
            return False
    return True


_NESTED_PEER_OBJECT_KEYS = frozenset(
    {"key", "endpoint", "allow-ips", "keepalive-interval", "preshared-key"}
)


def _dotted_netmask_for_nested(ipv4: str, mask: str) -> str:
    """Convert numeric/CIDR prefix to dotted IPv4 netmask for nested RCI peer body."""
    if mask.isdigit():
        prefix = int(mask)
        return str(ipaddress.IPv4Network(f"{ipv4}/{prefix}", strict=False).netmask)
    return mask


def validate_peer_allow_ips_list(allow_ips: str) -> str:
    """Validate comma-separated allow-ips; refuse IPv6 entries by name (never silent drop)."""
    normalized = allow_ips.strip()
    if not normalized:
        raise ValueError("peer allow_ips is empty")
    parts = [part.strip() for part in normalized.split(",") if part.strip()]
    if not parts:
        raise ValueError("peer allow_ips is empty")
    for part in parts:
        if _is_ipv6_peer_allow_ips_entry(part):
            raise ValueError(f"peer allow_ips IPv6 entry unsupported: {part!r}")
        validate_peer_allow_ips(part)
    return normalized


def _nested_allow_ips_entries(allow_ips: str) -> list[dict[str, str]]:
    """Parse one or more comma-separated allow-ips specs into nested array entries."""
    validate_peer_allow_ips_list(allow_ips)
    entries: list[dict[str, str]] = []
    for part in allow_ips.split(","):
        normalized = part.strip()
        if not normalized:
            continue
        ipv4, mask = validate_peer_allow_ips(normalized)
        entries.append(
            {
                "address": ipv4,
                "mask": _dotted_netmask_for_nested(ipv4, mask),
            }
        )
    if not entries:
        raise ValueError("peer allow_ips is empty")
    return entries


def normalize_nested_peer_allow_ips(allow_ips: str) -> str:
    """Parse comma-separated allow-ips into a stable WireguardRciResult string.

    Each spec is validated via ``validate_peer_allow_ips``; masks are normalized
    to dotted IPv4 netmasks to match nested RCI body ``allow-ips`` array entries.
    Returns comma-joined ``'ipv4 mask'`` pairs.
    """
    entries = _nested_allow_ips_entries(allow_ips)
    return ",".join(f"{entry['address']} {entry['mask']}" for entry in entries)


def _validate_nested_allow_ips_entry(entry: object) -> bool:
    if not isinstance(entry, dict) or set(entry.keys()) != {"address", "mask"}:
        return False
    address = entry.get("address")
    mask = entry.get("mask")
    if not isinstance(address, str) or not isinstance(mask, str):
        return False
    if not _WG_IPV4_RE.fullmatch(address.strip()):
        return False
    if mask.isdigit() or not _WG_MASK_RE.fullmatch(mask.strip()):
        return False
    if not _WG_IPV4_RE.fullmatch(mask.strip()):
        return False
    return True


def _validate_nested_peer_object(peer_obj: dict[str, object]) -> bool:
    if set(peer_obj.keys()) - _NESTED_PEER_OBJECT_KEYS:
        return False
    raw_key = peer_obj.get("key")
    if not isinstance(raw_key, str) or _WG_KEY_RE.fullmatch(raw_key.strip()) is None:
        return False
    for key, value in peer_obj.items():
        if key == "key":
            continue
        if key == "endpoint":
            if not isinstance(value, dict) or set(value.keys()) != {"address"}:
                return False
            address = value.get("address")
            if not isinstance(address, str):
                return False
            try:
                validate_peer_endpoint(address)
            except ValueError:
                return False
        elif key == "allow-ips":
            if not isinstance(value, list) or not value:
                return False
            if not all(_validate_nested_allow_ips_entry(item) for item in value):
                return False
        elif key == "keepalive-interval":
            if not isinstance(value, dict) or set(value.keys()) != {"interval"}:
                return False
            interval = value.get("interval")
            if not isinstance(interval, int) or isinstance(interval, bool):
                return False
            try:
                validate_keepalive_interval(interval)
            except ValueError:
                return False
        elif key == "preshared-key":
            if not isinstance(value, str):
                return False
            try:
                validate_wg_key_shape(value)
            except ValueError:
                return False
        else:
            return False
    return True


def is_wireguard_nested_peer_body(body: bytes) -> bool:
    """True when body is a sealed nested WireGuard peer resource write template.

    Keenetic nested peer writes use ``peer`` as an array of objects with a ``key``
    field (ivansible/ndm-wireguard show-rc template; read≈write).
    """
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    if not isinstance(payload, dict) or set(payload.keys()) != {"interface"}:
        return False
    interface = payload["interface"]
    if not isinstance(interface, dict) or len(interface) != 1:
        return False
    wg_id, wg_body = next(iter(interface.items()))
    if not isinstance(wg_id, str) or _wireguard_id_re().fullmatch(wg_id.strip()) is None:
        return False
    if not isinstance(wg_body, dict) or set(wg_body.keys()) != {"wireguard"}:
        return False
    wireguard = wg_body["wireguard"]
    if not isinstance(wireguard, dict) or set(wireguard.keys()) != {"peer"}:
        return False
    peer = wireguard["peer"]
    if not isinstance(peer, list) or len(peer) != 1:
        return False
    peer_obj = peer[0]
    if not isinstance(peer_obj, dict):
        return False
    return _validate_nested_peer_object(peer_obj)


def build_wireguard_nested_peer_body(
    wg_id: str,
    peer_public_key: str,
    *,
    endpoint: str | None = None,
    allow_ips: str | None = None,
    keepalive_interval: int | None = None,
    preshared_key: str | None = None,
) -> bytes:
    """Serialize a sealed nested WireGuard peer upsert body for POST /rci/.

    Emits ``peer`` as a single-element array with ``key`` = pubkey and nested
    resource objects (endpoint/allow-ips/keepalive-interval) per Keenetic RCI shape.
    """
    wg = validate_wireguard_id(wg_id)
    pubkey = validate_peer_public_key(peer_public_key)
    peer_obj: dict[str, object] = {"key": pubkey}
    if endpoint is not None:
        peer_obj["endpoint"] = {"address": validate_peer_endpoint(endpoint)}
    if allow_ips is not None:
        peer_obj["allow-ips"] = _nested_allow_ips_entries(allow_ips)
    if keepalive_interval is not None:
        peer_obj["keepalive-interval"] = {
            "interval": validate_keepalive_interval(keepalive_interval)
        }
    if preshared_key is not None:
        peer_obj["preshared-key"] = validate_wg_key_shape(preshared_key)
    payload = {
        "interface": {
            wg: {
                "wireguard": {
                    "peer": [peer_obj],
                }
            }
        }
    }
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def is_write_allowlisted(method: str, path: str, body: bytes) -> bool:
    """Fail-closed write gate: fixed digest, sealed interface, Wi-Fi AP, or WireGuard template."""
    normalized_path = path if path.startswith("/") else f"/{path}"
    if method != HttpMethod.POST or normalized_path != RCI_WRITE_PATH:
        return False
    digest = body_sha256(body)
    if digest in _FIXED_WRITE_BODY_SHA256S:
        return True
    return (
        is_interface_parse_body(body)
        or is_wifi_ap_parse_body(body)
        or is_wifi_station_parse_body(body)
        or is_wireguard_parse_body(body)
        or is_wireguard_nested_peer_body(body)
        or (is_ndns_parse_body(body) and is_expendable_lab_class())
    )


__all__ = [
    "LAB_CLASS_EXPENDABLE",
    "ALLOWLIST",
    "BOOTSTRAP_DISCOVERY_ALLOWLIST",
    "COMPONENTS_LIST",
    "COMPONENTS_LIST_STATUS",
    "DEFAULT_CONTINUATION_BUDGET_SECONDS",
    "DEFAULT_DISCOVERY_MAX_BYTES",
    "DISCOVERY_ALLOWLIST",
    "HttpMethod",
    "MAX_CONTINUATION_ROUNDS",
    "RCI_WRITE_PATH",
    "ReadCommand",
    "SHOW_IDENTIFICATION",
    "SHOW_INTERFACE",
    "SHOW_RC_INTERFACE",
    "SHOW_IP_HTTP",
    "SHOW_IP_NAME_SERVER",
    "SHOW_IP_POLICY",
    "SHOW_IP_ROUTE",
    "SHOW_IP_SSH",
    "SHOW_SYSTEM",
    "SHOW_VERSION",
    "STATION_READ_ALLOWLIST",
    "VPN_POLICY_READ_ALLOWLIST",
    "WRITE_ALLOWLIST",
    "WriteAllowlistEntry",
    "body_sha256",
    "build_sealed_parse_body",
    "build_wireguard_nested_peer_body",
    "is_allowlisted",
    "is_bootstrap_discovery_allowlisted",
    "is_discovery_allowlisted",
    "is_station_read_allowlisted",
    "is_vpn_policy_read_allowlisted",
    "is_expendable_lab_class",
    "refuse_rejected_vpn_policy_show_command",
    "validate_vpn_policy_read_command",
    "is_interface_parse_body",
    "is_ndns_parse_body",
    "is_wifi_ap_parse_body",
    "is_wifi_station_parse_body",
    "is_wireguard_nested_peer_body",
    "is_wireguard_parse_body",
    "is_write_allowlisted",
    "validate_asc_args",
    "validate_interface_id",
    "normalize_nested_peer_allow_ips",
    "validate_keepalive_interval",
    "validate_peer_allow_ips",
    "validate_peer_allow_ips_list",
    "validate_peer_endpoint",
    "validate_peer_public_key",
    "validate_ssid",
    "validate_wifi_ap_id",
    "validate_wg_key_shape",
    "WIFI_AP_INDEX_DEFAULT_MIN",
    "WIFI_AP_INDEX_EXPENDABLE_MIN",
    "WIFI_AP_INDEX_MAX",
    "wifi_ap_index_max",
    "wifi_ap_index_min",
    "is_canonical_wireguard_interface_id",
    "is_wireguard_like_interface_name",
    "normalize_wireguard_name_probe",
    "validate_wireguard_id",
    "validate_wpa_psk",
]
