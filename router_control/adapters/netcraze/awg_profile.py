"""Local-only AmneziaWG profile parser — enumerated fields, DPAPI secret refs."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from router_control.adapters.netcraze.allowlist import (
    validate_asc_args,
    validate_peer_allow_ips_list,
)
from router_control.ports.vault import CredentialVaultPort

_SECTION_RE = re.compile(r"^\s*\[(Interface|Peer)\]\s*$", re.IGNORECASE)
_KV_RE = re.compile(r"^\s*([A-Za-z0-9]+)\s*=\s*(.*)\s*$")

ALLOWED_INTERFACE_KEYS: frozenset[str] = frozenset(
    {
        "PrivateKey",
        "Address",
        "DNS",
        "Jc",
        "Jmin",
        "Jmax",
        "S1",
        "S2",
        "S3",
        "S4",
        "I1",
        "I2",
        "I3",
        "I4",
        "I5",
        "H1",
        "H2",
        "H3",
        "H4",
    }
)
ALLOWED_PEER_KEYS: frozenset[str] = frozenset(
    {
        "PublicKey",
        "PresharedKey",
        "Endpoint",
        "AllowedIPs",
        "PersistentKeepalive",
    }
)
ALLOWED_KEYS: frozenset[str] = ALLOWED_INTERFACE_KEYS | ALLOWED_PEER_KEYS

REQUIRED_INTERFACE_KEYS: frozenset[str] = frozenset({"PrivateKey", "Address"})
REQUIRED_PEER_KEYS: frozenset[str] = frozenset({"PublicKey", "Endpoint", "AllowedIPs"})
PEER_KEEPALIVE_MIN = 3
PEER_KEEPALIVE_MAX = 3600

VAULT_KIND_PRIVATE_KEY = "awg_private_key"
VAULT_KIND_PRESHARED_KEY = "awg_preshared_key"

# Documented ASC-9 order: jc jmin jmax s1 s2 h1 h2 h3 h4
ASC9_FIELD_ORDER: tuple[str, ...] = ("Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4")
AWG2X_FIELD_NAMES: frozenset[str] = frozenset({"S3", "S4", "I1", "I2", "I3", "I4", "I5"})
AWG2X_ASC_COMPILE_MESSAGE = (
    "AmneziaWG 2.x extended obfuscation (S3/S4/I1-I5) is not device-verified; "
    "ASC-9 compile requires exactly Jc,Jmin,Jmax,S1,S2,H1-H4 with no S3/S4/I1-I5"
)
DUALSTACK_IPV6_OPERATOR_NOTE = (
    "Маршруты IPv6 из профиля не применены. Туннель работает только по IPv4."
)


class AwgProfileError(Exception):
    """Profile parse or validation failure."""


@dataclass(frozen=True, slots=True)
class CredentialRefRole:
    role: str
    credential_ref_id: str
    kind: str


@dataclass(frozen=True, slots=True)
class ParsedAwgProfile:
    """Sanitized parse result — field names, asc9 obfuscation ints, credential refs only."""

    interface_field_names: tuple[str, ...]
    peer_field_names: tuple[str, ...]
    credential_refs: tuple[CredentialRefRole, ...]
    endpoint_configured: bool
    interface_address_present: bool
    awg_param_names: tuple[str, ...]
    profile_digest: str
    asc9_args: tuple[int, ...] | None
    interface_address: str | None = None
    peer_public_key: str | None = None
    peer_endpoint: str | None = None
    peer_allow_ips: str | None = None
    peer_keepalive_interval: int | None = None
    unsupported_fields: tuple[str, ...] = ()
    operator_notes: tuple[str, ...] = ()

    def sanitized_dict(self) -> dict[str, Any]:
        """Certification/evidence-safe payload — no peer routing endpoints or keys."""
        payload: dict[str, Any] = {
            "interface_field_names": list(self.interface_field_names),
            "peer_field_names": list(self.peer_field_names),
            "credential_refs": [
                {
                    "role": ref.role,
                    "credential_ref_id": ref.credential_ref_id,
                    "kind": ref.kind,
                }
                for ref in self.credential_refs
            ],
            "endpoint_configured": self.endpoint_configured,
            "interface_address_present": self.interface_address_present,
            "awg_param_names": list(self.awg_param_names),
            "profile_digest": self.profile_digest,
        }
        if self.asc9_args is not None:
            payload["asc9_args"] = list(self.asc9_args)
        return payload

    def sanitized_dict_for_apply(self) -> dict[str, Any]:
        """Parse-preview / WireguardIntentFields — adds non-secret peer routing metadata."""
        payload = self.sanitized_dict()
        if self.peer_public_key is not None:
            payload["peer_public_key"] = self.peer_public_key
        if self.peer_endpoint is not None:
            payload["peer_endpoint"] = self.peer_endpoint
        if self.peer_allow_ips is not None:
            payload["peer_allow_ips"] = self.peer_allow_ips
        if self.peer_keepalive_interval is not None:
            payload["peer_keepalive_interval"] = self.peer_keepalive_interval
        if self.interface_address is not None:
            payload["interface_address"] = self.interface_address
        if self.unsupported_fields:
            payload["unsupported_fields"] = list(self.unsupported_fields)
        if self.operator_notes:
            payload["operator_notes"] = list(self.operator_notes)
        return payload


def awg2x_asc_compile_error() -> str:
    """Human-readable reason ASC-9 compile is blocked when AWG 2.x fields are present."""
    return AWG2X_ASC_COMPILE_MESSAGE


def require_asc9_args_for_compile(profile: ParsedAwgProfile) -> tuple[int, ...]:
    """Return validated ASC-9 tuple for WireguardIntent/planner or raise AwgProfileError."""
    if profile.asc9_args is not None:
        return profile.asc9_args
    if any(name in profile.awg_param_names for name in AWG2X_FIELD_NAMES):
        raise AwgProfileError(AWG2X_ASC_COMPILE_MESSAGE)
    raise AwgProfileError(
        "ASC-9 obfuscation parameters incomplete (need Jc,Jmin,Jmax,S1,S2,H1-H4)"
    )


def _digest_text(text: str) -> str:
    return f"sha256:{hashlib.sha256(text.encode('utf-8')).hexdigest()}"


def _extract_asc9_args(interface: dict[str, str]) -> tuple[int, ...] | None:
    if any(key in interface for key in AWG2X_FIELD_NAMES):
        return None
    if not all(key in interface for key in ASC9_FIELD_ORDER):
        return None
    values: list[int] = []
    for key in ASC9_FIELD_ORDER:
        raw = interface[key].strip()
        if not raw.isdigit():
            raise AwgProfileError(f"invalid obfuscation integer for {key}")
        values.append(int(raw))
    asc_str = " ".join(str(value) for value in values)
    try:
        validate_asc_args(asc_str)
    except ValueError as exc:
        raise AwgProfileError(str(exc)) from exc
    return tuple(values)


def _parse_sections(text: str) -> tuple[dict[str, str], dict[str, str]]:
    current: str | None = None
    interface: dict[str, str] = {}
    peers: list[dict[str, str]] = []
    peer: dict[str, str] | None = None
    interface_section_seen = False

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        section_match = _SECTION_RE.match(line)
        if section_match:
            section = section_match.group(1).lower()
            if section == "interface":
                if interface_section_seen:
                    raise AwgProfileError("duplicate [Interface] section")
                interface_section_seen = True
                current = "interface"
                continue
            if section == "peer":
                if peer is not None:
                    peers.append(peer)
                peer = {}
                current = "peer"
                continue
            raise AwgProfileError(f"unsupported section: [{section_match.group(1)}]")
        kv_match = _KV_RE.match(line)
        if not kv_match:
            raise AwgProfileError("malformed profile line")
        key, value = kv_match.group(1), kv_match.group(2).strip()
        if current == "interface":
            if key in interface:
                raise AwgProfileError(f"duplicate interface field: {key}")
            interface[key] = value
        elif current == "peer" and peer is not None:
            if key in peer:
                raise AwgProfileError(f"duplicate peer field: {key}")
            peer[key] = value
        else:
            raise AwgProfileError("key/value outside [Interface] or [Peer] section")

    if peer is not None:
        peers.append(peer)

    if not interface:
        raise AwgProfileError("missing [Interface] section")
    if len(peers) != 1:
        raise AwgProfileError("exactly one [Peer] section required")
    return interface, peers[0]


def _validate_keys(section: str, mapping: dict[str, str], allowed: frozenset[str]) -> None:
    for key in mapping:
        if key not in allowed:
            raise AwgProfileError(f"unknown {section} field: {key}")


def _require_non_empty(mapping: dict[str, str], key: str) -> None:
    if not str(mapping.get(key, "")).strip():
        raise AwgProfileError(f"missing or empty required field: {key}")


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


def _partition_peer_allow_ips(raw: str) -> tuple[str, bool]:
    """Split AllowedIPs into IPv4 CSV (order preserved) and dropped_ipv6 flag."""
    normalized = raw.strip()
    if not normalized:
        raise AwgProfileError("peer allow_ips is empty")
    parts = [part.strip() for part in normalized.split(",") if part.strip()]
    if not parts:
        raise AwgProfileError("peer allow_ips is empty")
    ipv4_parts: list[str] = []
    dropped_ipv6 = False
    for part in parts:
        if _is_ipv6_peer_allow_ips_entry(part):
            dropped_ipv6 = True
        else:
            ipv4_parts.append(part)
    if not ipv4_parts:
        raise AwgProfileError("peer allow_ips has no usable IPv4 entry")
    ipv4_csv = ", ".join(ipv4_parts)
    try:
        validate_peer_allow_ips_list(ipv4_csv)
    except ValueError as exc:
        raise AwgProfileError(str(exc)) from exc
    return ipv4_csv, dropped_ipv6


def _parse_peer_keepalive_interval(peer: dict[str, str]) -> int | None:
    if "PersistentKeepalive" not in peer:
        return None
    raw = peer["PersistentKeepalive"].strip()
    if not raw.isdigit():
        raise AwgProfileError(
            f"invalid PersistentKeepalive: must be integer "
            f"{PEER_KEEPALIVE_MIN}..{PEER_KEEPALIVE_MAX}"
        )
    value = int(raw)
    if value < PEER_KEEPALIVE_MIN or value > PEER_KEEPALIVE_MAX:
        raise AwgProfileError(
            f"invalid PersistentKeepalive: must be integer "
            f"{PEER_KEEPALIVE_MIN}..{PEER_KEEPALIVE_MAX}"
        )
    return value


def parse_awg_profile_text(
    text: str,
    *,
    vault: CredentialVaultPort,
) -> ParsedAwgProfile:
    """Parse profile text locally; store secrets via vault; return sanitized struct."""
    interface, peer = _parse_sections(text)
    _validate_keys("interface", interface, ALLOWED_INTERFACE_KEYS)
    _validate_keys("peer", peer, ALLOWED_PEER_KEYS)

    for key in REQUIRED_INTERFACE_KEYS:
        _require_non_empty(interface, key)
    for key in REQUIRED_PEER_KEYS:
        _require_non_empty(peer, key)

    peer_allow_ips, dropped_ipv6 = _partition_peer_allow_ips(peer["AllowedIPs"])
    unsupported_fields: tuple[str, ...] = ()
    operator_notes: tuple[str, ...] = ()
    if dropped_ipv6:
        unsupported_fields = ("AllowedIPs",)
        operator_notes = (DUALSTACK_IPV6_OPERATOR_NOTE,)

    credential_refs: list[CredentialRefRole] = []
    private_handle = vault.create(kind=VAULT_KIND_PRIVATE_KEY, secret=interface["PrivateKey"])
    credential_refs.append(
        CredentialRefRole(
            role="PrivateKey",
            credential_ref_id=private_handle.credential_ref_id,
            kind=private_handle.kind,
        )
    )
    try:
        if "PresharedKey" in peer and str(peer["PresharedKey"]).strip():
            psk_handle = vault.create(kind=VAULT_KIND_PRESHARED_KEY, secret=peer["PresharedKey"])
            credential_refs.append(
                CredentialRefRole(
                    role="PresharedKey",
                    credential_ref_id=psk_handle.credential_ref_id,
                    kind=psk_handle.kind,
                )
            )
    except Exception:
        vault.delete(private_handle.credential_ref_id)
        raise

    awg_keys = set(ASC9_FIELD_ORDER) | AWG2X_FIELD_NAMES
    awg_names = tuple(sorted(key for key in interface if key in awg_keys))
    interface_names = tuple(sorted(interface.keys()))
    peer_names = tuple(sorted(peer.keys()))
    asc9_args = _extract_asc9_args(interface)

    profile_digest = _digest_text(text)

    peer_public_key = peer.get("PublicKey", "").strip() or None
    peer_endpoint = peer.get("Endpoint", "").strip() or None
    peer_keepalive_interval = _parse_peer_keepalive_interval(peer)
    interface_address = interface.get("Address", "").strip() or None

    return ParsedAwgProfile(
        interface_field_names=interface_names,
        peer_field_names=peer_names,
        credential_refs=tuple(credential_refs),
        endpoint_configured=bool(peer_endpoint),
        interface_address_present=bool(str(interface.get("Address", "")).strip()),
        awg_param_names=awg_names,
        profile_digest=profile_digest,
        asc9_args=asc9_args,
        interface_address=interface_address,
        peer_public_key=peer_public_key,
        peer_endpoint=peer_endpoint,
        peer_allow_ips=peer_allow_ips,
        peer_keepalive_interval=peer_keepalive_interval,
        unsupported_fields=unsupported_fields,
        operator_notes=operator_notes,
    )


def parse_awg_profile_path(
    path: Path | str,
    *,
    vault: CredentialVaultPort,
) -> ParsedAwgProfile:
    profile_path = Path(path)
    if not profile_path.is_file():
        raise AwgProfileError(f"profile not found: {profile_path}")
    return parse_awg_profile_text(profile_path.read_text(encoding="utf-8"), vault=vault)


__all__ = [
    "ALLOWED_KEYS",
    "ASC9_FIELD_ORDER",
    "AWG2X_ASC_COMPILE_MESSAGE",
    "AWG2X_FIELD_NAMES",
    "DUALSTACK_IPV6_OPERATOR_NOTE",
    "AwgProfileError",
    "CredentialRefRole",
    "ParsedAwgProfile",
    "awg2x_asc_compile_error",
    "parse_awg_profile_path",
    "parse_awg_profile_text",
    "require_asc9_args_for_compile",
]
