"""Anchor-based grammar doc citations — resilient to line-number drift."""

# Registry table lines are intentionally long (evidence paths + anchor keys).
# ruff: noqa: E501

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

_HEADING_RE = re.compile(r"^(#+)\s+(.*)$")
_DOC_REF_IN_NOTES_RE = re.compile(r"(docs/[^\s#]+\.md#[\w-]+)")

UNCONFIRMED_SOURCE_MARKER = "grammar source not fixed (источник не зафиксирован)"

_WIFI_DOC = "docs/OPERATOR_WIFI_DISCOVERY.md"
_STATION_DOC = _WIFI_DOC
_WG_DOC = "docs/OPERATOR_AWG_DISCOVERY.md"
_WG_APPLY_DOC = "docs/OPERATOR_AWG_APPLY.md"
_VPN_DOC = "docs/OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md"
_KEENDNS_DOC = "docs/OPERATOR_KEENDNS_DISCOVERY.md"


@dataclass(frozen=True, slots=True)
class GrammarDocRef:
    """Markdown section anchor + snippet that must appear in that section."""

    path: str
    anchor: str
    snippet: str

    def format(self) -> str:
        return f"{self.path}#{self.anchor}"


@dataclass(frozen=True, slots=True)
class GrammarOpRegistryEntry:
    family: str
    operation: str
    ref: GrammarDocRef | None = None
    unconfirmed: bool = False
    default_evidence: str | None = None
    snippet_override: str | None = None


_WIFI_SSID_SECTION = GrammarDocRef(
    _WIFI_DOC,
    "on-device-write-shape-verification-2026-07-24",
    "interface WifiMaster0/AccessPoint3 ssid",
)
_WIFI_WPA_SECTION = GrammarDocRef(
    _WIFI_DOC,
    "wpa-encryption-verification-2026-07-24",
    "authentication wpa-psk",
)
_WIFI_WPA3_SECTION = GrammarDocRef(
    _WIFI_DOC,
    "4-wifiintent-mapping-offline-product-model-2026-07-24",
    "encryption wpa3",
)
_STATION_SECTION = GrammarDocRef(
    _STATION_DOC,
    "2c-wifi-station-wisp-client-grammar-device-confirmed-first-association-bounded-2026-07-31",
    "interface {station} ssid",
)
_WG_DEVICE_SECTION = GrammarDocRef(
    _WG_DOC,
    "on-device-write-shape-verification-2026-07-24-prior-physical-unit-superseded-rebind-2026-07-31",
    "interface Wireguard<N>",
)
_WG_NESTED_PEER_SECTION = GrammarDocRef(
    _WG_APPLY_DOC,
    "additive-nested-rci-peer-shape-default-device-verified-write-accepted-2026-07-24",
    "wireguard_upsert_peer_nested",
)
_WG_PATH_PEER_SECTION = GrammarDocRef(
    _WG_APPLY_DOC,
    "sealed-path-style-peer-grammar-offline-compiler",
    "wireguard private-key",
)
_VPN_HELP_SECTION = GrammarDocRef(
    _VPN_DOC,
    "2b-read-only-observed-grammar-verified-from-help",
    "ip policy {name}",
)
_KEENDNS_CLI_SECTION = GrammarDocRef(
    _KEENDNS_DOC,
    "cli-ndns-command-group",
    "ndns book-name",
)


def heading_to_anchor(heading: str) -> str:
    """GitHub-compatible markdown heading slug."""
    slug = heading.strip().lower()
    slug = re.sub(r"[^\w\s-]", "", slug)
    slug = re.sub(r"\s+", "-", slug)
    return slug


def section_text_for_anchor(doc: str, anchor: str) -> str:
    """Return markdown section body starting at the heading whose slug matches anchor."""
    lines = doc.splitlines()
    target = anchor.lower()
    start: int | None = None
    start_level = 0
    for index, line in enumerate(lines):
        match = _HEADING_RE.match(line)
        if not match:
            continue
        level = len(match.group(1))
        slug = heading_to_anchor(match.group(2))
        if slug == target:
            start = index
            start_level = level
            break
    if start is None:
        return ""
    end = len(lines)
    for index in range(start + 1, len(lines)):
        match = _HEADING_RE.match(lines[index])
        if match and len(match.group(1)) <= start_level:
            end = index
            break
    return "\n".join(lines[start:end])


def verify_grammar_doc_ref(ref: GrammarDocRef, *, root: Path | None = None) -> bool:
    root = root or REPO_ROOT
    text = (root / ref.path).read_text(encoding="utf-8")
    section = section_text_for_anchor(text, ref.anchor)
    return bool(section) and ref.snippet in section


def cite(ref: GrammarDocRef) -> str:
    return ref.format()


def _entry(
    family: str,
    operation: str,
    *,
    ref: GrammarDocRef | None = None,
    unconfirmed: bool = False,
    default_evidence: str | None = None,
    snippet_override: str | None = None,
) -> GrammarOpRegistryEntry:
    return GrammarOpRegistryEntry(
        family=family,
        operation=operation,
        ref=ref,
        unconfirmed=unconfirmed,
        default_evidence=default_evidence,
        snippet_override=snippet_override,
    )


def _build_registry() -> dict[tuple[str, str], GrammarOpRegistryEntry]:
    wifi_ap = "wifi_ap"
    wifi_station = "wifi_station"
    wireguard = "wireguard"
    vpn_policy = "vpn_policy"
    keendns = "keendns"
    dhcp = "dhcp"
    dns = "dns"
    firewall = "firewall"
    vlan = "vlan"

    entries: list[GrammarOpRegistryEntry] = [
        _entry(wifi_ap, "wifi_ap_set_ssid", ref=_WIFI_SSID_SECTION, default_evidence="wifi-writeshape-verify-192.168.2.1-20260724.json"),
        _entry(wifi_ap, "wifi_ap_clear_ssid", ref=_WIFI_SSID_SECTION, snippet_override="no ssid", default_evidence="wifi-writeshape-verify-192.168.2.1-20260724.json"),
        _entry(wifi_ap, "wifi_ap_up", ref=_WIFI_SSID_SECTION, snippet_override="AccessPoint3 up", default_evidence="wifi-writeshape-verify-192.168.2.1-20260724.json"),
        _entry(wifi_ap, "wifi_ap_down", ref=_WIFI_WPA_SECTION, snippet_override="AccessPoint3 down", default_evidence="wifi-wpa-writeshape-verify-192.168.2.1-20260724.json"),
        _entry(wifi_ap, "wifi_ap_set_wpa_psk", ref=_WIFI_WPA_SECTION, default_evidence="wifi-wpa-writeshape-verify-192.168.2.1-20260724.json"),
        _entry(wifi_ap, "wifi_ap_clear_wpa_psk", ref=_WIFI_WPA_SECTION, snippet_override="no authentication wpa-psk", default_evidence="wifi-wpa-writeshape-verify-192.168.2.1-20260724.json"),
        _entry(wifi_ap, "wifi_ap_encryption_enable", ref=_WIFI_WPA_SECTION, snippet_override="encryption enable", default_evidence="wifi-wpa-writeshape-verify-192.168.2.1-20260724.json"),
        _entry(wifi_ap, "wifi_ap_encryption_disable", ref=_WIFI_WPA_SECTION, snippet_override="no encryption enable", default_evidence="wifi-wpa-writeshape-verify-192.168.2.1-20260724.json"),
        _entry(wifi_ap, "wifi_ap_encryption_wpa2", ref=_WIFI_WPA_SECTION, snippet_override="encryption wpa2", default_evidence="wifi-wpa-writeshape-verify-192.168.2.1-20260724.json"),
        _entry(wifi_ap, "wifi_ap_encryption_wpa2_clear", ref=_WIFI_WPA_SECTION, snippet_override="no encryption wpa2", default_evidence="wifi-wpa-writeshape-verify-192.168.2.1-20260724.json"),
        _entry(wifi_ap, "wifi_ap_encryption_wpa3", ref=_WIFI_WPA3_SECTION, default_evidence="wifi-wpa3-live-reverify-192.168.2.1-20260724.json"),
        _entry(
            wifi_ap,
            "wifi_ap_encryption_wpa3_clear",
            unconfirmed=True,
            default_evidence="wifi-wpa3-live-reverify-192.168.2.1-20260724.json",
        ),
        _entry(wifi_station, "wifi_station_set_ssid", ref=_STATION_SECTION, default_evidence="station-wisp-grammar-probe-20260731.json"),
        _entry(wifi_station, "wifi_station_clear_ssid", ref=_STATION_SECTION, snippet_override="no ssid", default_evidence="station-wisp-grammar-probe-20260731.json"),
        _entry(wifi_station, "wifi_station_set_wpa_psk", ref=_STATION_SECTION, snippet_override="authentication wpa-psk", default_evidence="station-wisp-grammar-probe-20260731.json"),
        _entry(wifi_station, "wifi_station_clear_wpa_psk", ref=_STATION_SECTION, snippet_override="no authentication wpa-psk", default_evidence="station-wisp-grammar-probe-20260731.json"),
        _entry(wifi_station, "wifi_station_encryption_enable", ref=_STATION_SECTION, snippet_override="encryption enable", default_evidence="station-wisp-grammar-probe-20260731.json"),
        _entry(wifi_station, "wifi_station_encryption_disable", ref=_STATION_SECTION, snippet_override="no encryption enable", default_evidence="station-wisp-grammar-probe-20260731.json"),
        _entry(wifi_station, "wifi_station_encryption_wpa2", ref=_STATION_SECTION, snippet_override="encryption wpa2", default_evidence="station-wisp-grammar-probe-20260731.json"),
        _entry(wifi_station, "wifi_station_encryption_wpa2_clear", ref=_STATION_SECTION, snippet_override="no encryption wpa2", default_evidence="station-wisp-grammar-probe-20260731.json"),
        _entry(wifi_station, "wifi_station_ip_address_dhcp", ref=_STATION_SECTION, snippet_override="ip address dhcp", default_evidence="station-wisp-grammar-probe-20260731.json"),
        _entry(wifi_station, "wifi_station_clear_ip_address_dhcp", ref=_STATION_SECTION, snippet_override="ip address dhcp", default_evidence="station-wisp-grammar-probe-20260731.json"),
        _entry(wifi_station, "wifi_station_clear_ip_address", ref=_STATION_SECTION, snippet_override="ip address dhcp", default_evidence="station-wisp-grammar-probe-20260731.json"),
        _entry(wifi_station, "wifi_station_up", ref=_STATION_SECTION, snippet_override="Up / down", default_evidence="station-wisp-grammar-probe-20260731.json"),
        _entry(wifi_station, "wifi_station_down", ref=_STATION_SECTION, snippet_override="Up / down", default_evidence="station-wisp-grammar-probe-20260731.json"),
        _entry(wifi_station, "wifi_station_ip_global", ref=_STATION_SECTION, snippet_override="ip global", default_evidence="station-wisp-upstream-uplink-first-association-20260731.json"),
        _entry(wifi_station, "wifi_station_set_bssid", unconfirmed=True),
        _entry(wifi_station, "wifi_station_standby_enable", unconfirmed=True),
        _entry(wifi_station, "wifi_station_standby_timeout", unconfirmed=True),
        _entry(wireguard, "wireguard_create_interface", ref=_WG_DEVICE_SECTION, default_evidence="awg-writeshape-verify-192.168.2.1-20260724.json"),
        _entry(wireguard, "wireguard_remove_interface", ref=_WG_DEVICE_SECTION, snippet_override="no interface Wireguard", default_evidence="awg-writeshape-verify-192.168.2.1-20260724.json"),
        _entry(wireguard, "wireguard_set_asc", ref=_WG_DEVICE_SECTION, snippet_override="wireguard asc", default_evidence="awg-writeshape-verify-192.168.2.1-20260724.json"),
        _entry(wireguard, "wireguard_set_private_key", ref=_WG_PATH_PEER_SECTION, default_evidence="awg-private-key-live-reverify-192.168.2.1-20260724.json"),
        _entry(wireguard, "wireguard_set_ip_address", unconfirmed=True),
        _entry(wireguard, "wireguard_clear_ip_address", unconfirmed=True),
        _entry(wireguard, "wireguard_ip_global", unconfirmed=True),
        _entry(wireguard, "wireguard_clear_ip_global", unconfirmed=True),
        _entry(wireguard, "wireguard_set_tcp_mss", unconfirmed=True),
        _entry(wireguard, "wireguard_clear_tcp_mss", unconfirmed=True),
        _entry(wireguard, "wireguard_upsert_peer_nested", ref=_WG_NESTED_PEER_SECTION, default_evidence="awg-peer-nested-rci-live-reverify-192.168.2.1-20260724.json"),
        _entry(wireguard, "wireguard_remove_peer", unconfirmed=True),
        _entry(wireguard, "wireguard_clear_private_key", unconfirmed=True),
        _entry(wireguard, "interface_up", unconfirmed=True),
        _entry(wireguard, "interface_down", unconfirmed=True),
        _entry(vpn_policy, "vpn_policy_create", ref=_VPN_HELP_SECTION),
        _entry(vpn_policy, "vpn_policy_remove", ref=_VPN_HELP_SECTION, snippet_override="no ip policy {name}"),
        _entry(vpn_policy, "vpn_policy_ip_global", ref=_VPN_HELP_SECTION, snippet_override="ip global"),
        _entry(vpn_policy, "vpn_policy_ip_global_teardown_unverified", unconfirmed=True),
        _entry(vpn_policy, "vpn_policy_set_name_server", ref=_VPN_HELP_SECTION, snippet_override="ip name-server"),
        _entry(vpn_policy, "vpn_policy_clear_name_server", unconfirmed=True),
        _entry(keendns, "keendns_book_name", ref=_KEENDNS_CLI_SECTION, unconfirmed=True),
        _entry(
            keendns,
            "keendns_drop_name",
            ref=_KEENDNS_CLI_SECTION,
            snippet_override="ndns drop-name",
            unconfirmed=True,
        ),
    ]

    offline_ops = {
        dhcp: (
            "dhcp_set_pool",
            "dhcp_clear_pool",
            "dhcp_set_lease",
            "dhcp_bind_host",
            "dhcp_unbind_host",
        ),
        dns: (
            "dns_set_static_host",
            "dns_clear_static_host",
            "dns_set_upstream",
            "dns_clear_upstream",
        ),
        firewall: ("firewall_add_rule", "firewall_remove_rule"),
        vlan: (
            "vlan_create_bridge",
            "vlan_remove_bridge",
            "vlan_set_ip_address",
            "vlan_clear_ip_address",
            "vlan_set_security_level",
            "vlan_clear_security_level",
            "vlan_up",
            "vlan_down",
        ),
    }
    for family, ops in offline_ops.items():
        for operation in ops:
            entries.append(_entry(family, operation, unconfirmed=True))

    return {(entry.family, entry.operation): entry for entry in entries}


GRAMMAR_OP_REGISTRY: dict[tuple[str, str], GrammarOpRegistryEntry] = _build_registry()


def registry_entry(family: str, operation: str) -> GrammarOpRegistryEntry:
    key = (family, operation)
    if key not in GRAMMAR_OP_REGISTRY:
        raise KeyError(f"no grammar registry entry for {family}/{operation}")
    return GRAMMAR_OP_REGISTRY[key]


def iter_registry_entries() -> Iterator[GrammarOpRegistryEntry]:
    yield from GRAMMAR_OP_REGISTRY.values()


def effective_ref(entry: GrammarOpRegistryEntry) -> GrammarDocRef | None:
    if entry.ref is None:
        return None
    if entry.snippet_override:
        return GrammarDocRef(entry.ref.path, entry.ref.anchor, entry.snippet_override)
    return entry.ref


def build_planner_op_notes(
    family: str,
    operation: str,
    *,
    sealed_template: str,
    evidence: str | None = None,
    snippet_override: str | None = None,
    extra: tuple[str, ...] = (),
    negation: bool = False,
    verification_kind: str | None = None,
) -> tuple[str, ...]:
    """Build per-op grammar citation notes from the central registry."""
    entry = registry_entry(family, operation)
    notes: list[str] = [f"sealed template {sealed_template}"]
    if entry.unconfirmed or entry.ref is None:
        notes.append(f"offline_unverified; {UNCONFIRMED_SOURCE_MARKER}")
        if evidence or entry.default_evidence:
            notes.append(
                f"evidence {evidence or entry.default_evidence}; not doc line-cited"
            )
    else:
        ref = effective_ref(entry)
        if ref is None:
            raise ValueError(f"registry entry {family}/{operation} missing ref")
        if snippet_override:
            ref = GrammarDocRef(ref.path, ref.anchor, snippet_override)
        kind = verification_kind or ("device-verified negation" if negation else "device-verified")
        ev = evidence or entry.default_evidence
        ev_suffix = f"; evidence {ev}" if ev else ""
        notes.append(f"{kind} ({cite(ref)}{ev_suffix})")
    return tuple(notes) + extra


def extract_doc_ref_from_notes(notes: tuple[str, ...] | list[str]) -> str | None:
    joined = " ".join(notes)
    match = _DOC_REF_IN_NOTES_RE.search(joined)
    return match.group(1) if match else None


def notes_mark_unconfirmed(notes: tuple[str, ...] | list[str]) -> bool:
    return UNCONFIRMED_SOURCE_MARKER in " ".join(notes)


__all__ = [
    "GRAMMAR_OP_REGISTRY",
    "GrammarDocRef",
    "GrammarOpRegistryEntry",
    "UNCONFIRMED_SOURCE_MARKER",
    "build_planner_op_notes",
    "cite",
    "effective_ref",
    "extract_doc_ref_from_notes",
    "heading_to_anchor",
    "iter_registry_entries",
    "notes_mark_unconfirmed",
    "registry_entry",
    "section_text_for_anchor",
    "verify_grammar_doc_ref",
    "_WIFI_SSID_SECTION",
    "_WIFI_WPA_SECTION",
]
