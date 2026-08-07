"""Redaction helpers for Gate A evidence and logs."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from typing import Any

# Real SSH/RCI output may append erase-to-EOL after prompt or body (``\x1b[K``).
# Normalized in ``rci_prompt.normalize_rci_prompt``; reuse for CLI parsers.
_SSH_CLI_ERASE_LINE_SUFFIX = "\x1b[K"


def strip_ssh_cli_ansi_artifacts(text: str) -> str:
    """Remove known ANSI artefacts from SSH CLI text before sealed-branch matching.

    Device SSH/RCI appends erase-to-EOL (``\\x1b[K``) as a **line suffix** after prompt
    or body text (see ``rci_prompt.normalize_rci_prompt``). Mid-string sequences
    are intentionally preserved so forged sealed phrases cannot be assembled.

    CRLF (``\\r\\n``) is normalized before line splitting; lone ``\\r`` without ``\\n``
    is not treated as a line break (mid-string ``\\r`` forgery invariant).
    """
    if not text:
        return text
    suffix_len = len(_SSH_CLI_ERASE_LINE_SUFFIX)
    stripped_lines: list[str] = []
    for line in text.replace("\r\n", "\n").split("\n"):
        if line.endswith("\r"):
            line = line[:-1]
        while line.endswith(_SSH_CLI_ERASE_LINE_SUFFIX):
            line = line[:-suffix_len]
        stripped_lines.append(line)
    return "\n".join(stripped_lines)

_REDACT_KEYS = frozenset(

    {

        "password",

        "username",

        "user",

        "authorization",

        "cookie",

        "set-cookie",

        "serial",

        "servicetag",

        "service_tag",

        "mac",

        "macaddr",

        "mac_address",

        "session",

        "session_cookie",

        "token",

        "secret",

        "challenge",

        "realm",

        "x-ndm-challenge",

        "x-ndm-realm",

        "www-authenticate",

        "ha1",

        "hostname",

        "domain",

    }

)

# Wi-Fi / WireGuard / AmneziaWG secret field names vary by probe and firmware surface.
# Defense-in-depth: shared sanitize must redact these even when probe-local stopgaps exist.
# WireGuard apply readback uses show interface only (NOT show rc); private-key /
# preshared-key in observed peer blocks must still redact via fragments below.
# Substring match on normalized keys (strip/lower, hyphen→underscore). Fragments target
# credential material only — bare "key" or "_key" is intentionally omitted to avoid
# over-redacting public-key, wireguard-public-key, and ssh-host-key identifiers.
_WIFI_WG_SECRET_KEY_FRAGMENTS = frozenset(
    {
        "passphrase",
        "preshared",  # preshared-key → preshared_key
        "pre_shared",  # pre-shared-key → pre_shared_key
        "private_key",  # private-key; does not match public_key
        "privatekey",  # PrivateKey camelCase; does not match publickey
        "psk",  # psk, wpa-psk, wpa_psk
        "wpa_psk",  # explicit wpa_psk spelling
        "sae",  # sae, authentication-sae, authentication_sae
        "authentication_sae",  # explicit authentication_sae spelling
        "obfs_key",  # obfs-key
        "obfskey",  # ObfsKey-style
    }
)


_SERIAL_MAC_PATTERN = re.compile(

    r"([0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}|"

    r"[0-9A-Fa-f]{12,}|"

    r"SERIAL[_-]?REDACTED)",

    re.IGNORECASE,

)

_REDACTED_CLI_PLACEHOLDER = "<redacted>"

_WPA_PSK_CLI_RE = re.compile(r"(?i)(authentication\s+wpa-psk)\s+\S+")
_WPA_PSK_TRAILING_CLI_RE = re.compile(r"(?i)(?<!\w)(wpa-psk)\s+\S+")
_WG_PRIVATE_KEY_CLI_RE = re.compile(r"(?i)(wireguard\s+private-key)\s+\S+")
_WG_PRESHARED_KEY_CLI_RE = re.compile(r"(?i)(preshared-key)\s+\S+")


def redact_sealed_cli_command(command: str) -> str:
    """Redact secret tail values from a sealed single-line RCI CLI command."""
    text = command.strip()
    if not text:
        return text
    text = _WPA_PSK_CLI_RE.sub(rf"\1 {_REDACTED_CLI_PLACEHOLDER}", text)
    text = _WPA_PSK_TRAILING_CLI_RE.sub(rf"\1 {_REDACTED_CLI_PLACEHOLDER}", text)
    text = _WG_PRIVATE_KEY_CLI_RE.sub(rf"\1 {_REDACTED_CLI_PLACEHOLDER}", text)
    text = _WG_PRESHARED_KEY_CLI_RE.sub(rf"\1 {_REDACTED_CLI_PLACEHOLDER}", text)
    return text


def redact_sealed_nested_body(body: dict[str, Any]) -> dict[str, Any]:
    """Redact secret fields in nested WireGuard peer bodies; preserve public keys."""
    result: dict[str, Any] = json.loads(json.dumps(body))

    def _walk(obj: Any) -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                normalized = key.strip().lower().replace("-", "_")
                if normalized in {
                    "preshared_key",
                    "private_key",
                    "privatekey",
                    "psk",
                    "passphrase",
                    "password",
                    "pre_shared_key",
                    "wpa_psk",
                }:
                    obj[key] = "REDACTED"
                else:
                    _walk(value)
        elif isinstance(obj, list):
            for item in obj:
                _walk(item)

    _walk(result)
    return result


def redact_key(key: str) -> bool:

    normalized = key.strip().lower().replace("-", "_")

    if normalized == "credential_ref_id" or normalized.endswith("_credential_ref_id"):
        return False

    normalized_keys = {item.replace("-", "_") for item in _REDACT_KEYS}

    return (

        normalized in normalized_keys

        or "password" in normalized

        or "secret" in normalized

        or "challenge" in normalized

        or "realm" in normalized

        or "token" in normalized

        or any(fragment in normalized for fragment in _WIFI_WG_SECRET_KEY_FRAGMENTS)

    )





def sanitize_value(value: Any, *, parent_key: str | None = None) -> Any:

    if isinstance(value, dict):

        return sanitize_mapping(value)

    if isinstance(value, list):

        return [sanitize_value(item, parent_key=parent_key) for item in value]

    if isinstance(value, str):

        if value.startswith(("sha256:", "digest:")):

            return value

        if parent_key is not None:
            normalized_key = parent_key.strip().lower().replace("-", "_")
            if normalized_key.endswith("public_key") or normalized_key in {
                "public_key",
                "peer_public_key",
            }:
                return value

        if _SERIAL_MAC_PATTERN.search(value):

            return "REDACTED"

        return value

    return value





def sanitize_mapping(mapping: dict[str, Any]) -> dict[str, Any]:

    sanitized: dict[str, Any] = {}

    for key, value in mapping.items():

        if redact_key(key):

            sanitized[key] = "REDACTED"

        else:

            sanitized[key] = sanitize_value(value, parent_key=str(key))

    return sanitized





def hash_interface_id(raw_id: str) -> str:
    """Stable redacted digest for logical interface identifiers."""
    normalized = raw_id.strip()
    if not normalized:
        return "sha256:" + hashlib.sha256(b"<empty>").hexdigest()
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


_RFC1918_V4 = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)
_ULA_V6 = ipaddress.IPv6Network("fc00::/7")


def _is_rfc1918_or_ula(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    if isinstance(network, ipaddress.IPv4Network):
        return any(network.subnet_of(block) for block in _RFC1918_V4)
    if isinstance(network, ipaddress.IPv6Network):
        return network.subnet_of(_ULA_V6)
    return False


def classify_private_prefix(cidr: str) -> str | None:
    """Return normalized RFC1918/ULA network prefix CIDR or None if public/invalid."""
    candidate = cidr.strip()
    if not candidate:
        return None
    try:
        network = ipaddress.ip_network(candidate, strict=False)
    except ValueError:
        return None
    if not _is_rfc1918_or_ula(network):
        return None
    return str(network)


_STRUCTURE_ALLOWLISTED_FIELDS = frozenset(
    {
        "type",
        "link",
        "connected",
        "state",
        "up",
        "traits",
        "address",
        "addresses",
        "ip",
        "mask",
        "prefix",
        "prefix-length",
        "network",
        "gateway",
        "defaultgw",
        "security-level",
        "role",
        "bridge",
        "segment",
        "uplink",
        "parent",
        "via",
        "interface",
        "member",
        "members",
        "port",
        "mtu",
    }
)

_STRUCTURE_MAX_DEPTH = 3
_STRUCTURE_MAX_ENTRIES = 32
_STRUCTURE_MAX_OUTPUT_BYTES = 8192


def _structure_json_type(value: object) -> str:
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    if isinstance(value, str):
        return "string"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return "number"
    if value is None:
        return "null"
    return "unknown"


def _structure_hash_key(raw_key: str) -> str:
    normalized = raw_key.strip()
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def _structure_secret_category(key: str) -> str | None:
    # Allowlist always wins: an audited field NAME never gets a secret category,
    # even if it would otherwise match a sensitive-name heuristic below.
    if key in _STRUCTURE_ALLOWLISTED_FIELDS:
        return None
    normalized = key.strip().lower().replace("-", "_")
    if redact_key(key):
        if "password" in normalized:
            return "password"
        if "secret" in normalized:
            return "secret"
        if "token" in normalized:
            return "token"
        if "mac" in normalized:
            return "mac"
        if "hostname" in normalized or "domain" in normalized:
            return "address"
        return "secret"
    if normalized in {"id", "uuid", "guid", "name"}:
        return "identifier"
    if normalized in {"ipv4", "ipv6", "dns"}:
        return "address"
    if normalized in {"ssid", "essid"}:
        return "ssid"
    if normalized in {"description", "desc", "comment"}:
        return "description"
    return None


def _cap_structure_lists(result: dict[str, Any]) -> None:
    result["dynamic_top_key_hashes"] = sorted(result["dynamic_top_key_hashes"])[
        :_STRUCTURE_MAX_ENTRIES
    ]
    result["secret_field_categories"] = result["secret_field_categories"][
        :_STRUCTURE_MAX_ENTRIES
    ]
    result["field_samples"] = result["field_samples"][:_STRUCTURE_MAX_ENTRIES]
    for sample in result["field_samples"]:
        if "dynamic_key_hashes" in sample:
            sample["dynamic_key_hashes"] = sorted(sample["dynamic_key_hashes"])[
                :_STRUCTURE_MAX_ENTRIES
            ]


def _enforce_structure_output_bound(result: dict[str, Any]) -> dict[str, Any]:
    _cap_structure_lists(result)
    encoded = json.dumps(result, sort_keys=True, separators=(",", ":"))
    if len(encoded) <= _STRUCTURE_MAX_OUTPUT_BYTES:
        return result

    trimmed = dict(result)
    trimmed["truncated"] = True
    _cap_structure_lists(trimmed)

    while (
        len(json.dumps(trimmed, sort_keys=True, separators=(",", ":")))
        > _STRUCTURE_MAX_OUTPUT_BYTES
    ):
        reduced = False
        if trimmed["field_samples"]:
            trimmed["field_samples"] = trimmed["field_samples"][:-1]
            reduced = True
        elif trimmed["dynamic_top_key_hashes"]:
            trimmed["dynamic_top_key_hashes"] = trimmed["dynamic_top_key_hashes"][:-1]
            reduced = True
        elif trimmed["secret_field_categories"]:
            trimmed["secret_field_categories"] = trimmed["secret_field_categories"][:-1]
            reduced = True
        else:
            for sample in reversed(trimmed["field_samples"]):
                dynamic_hashes = sample.get("dynamic_key_hashes")
                if dynamic_hashes:
                    sample["dynamic_key_hashes"] = dynamic_hashes[:-1]
                    reduced = True
                    break
        if not reduced:
            break

    return trimmed


def describe_structure(payload: object) -> dict[str, Any]:
    """Emit a bounded structural fingerprint for a JSON object (no raw values)."""
    if not isinstance(payload, dict):
        raise ValueError("describe_structure requires a JSON object")

    state = {"entries": 0, "truncated": False}
    histogram: dict[str, int] = {}
    dynamic_top_key_hashes: list[str] = []
    secret_fields: dict[str, dict[str, str]] = {}
    field_samples: list[dict[str, Any]] = []

    def bump_type(value: object) -> None:
        kind = _structure_json_type(value)
        histogram[kind] = histogram.get(kind, 0) + 1

    def mark_truncated() -> None:
        state["truncated"] = True

    def consume_walk_entry() -> bool:
        if state["entries"] >= _STRUCTURE_MAX_ENTRIES:
            mark_truncated()
            return False
        state["entries"] += 1
        return True

    def append_capped(target: list[Any], item: Any) -> bool:
        if len(target) >= _STRUCTURE_MAX_ENTRIES:
            mark_truncated()
            return False
        target.append(item)
        return True

    def record_secret(key: str) -> bool:
        if len(secret_fields) >= _STRUCTURE_MAX_ENTRIES:
            mark_truncated()
            return False
        category = _structure_secret_category(key)
        if category is None:
            category = "secret"
        key_hash = _structure_hash_key(key)
        secret_fields[key_hash] = {"category": category, "key_hash": key_hash}
        return True

    def append_field_sample(sample: dict[str, Any]) -> None:
        if len(field_samples) >= _STRUCTURE_MAX_ENTRIES:
            mark_truncated()
            return
        field_samples.append(sample)

    def path_segment(key: str) -> str:
        if key in _STRUCTURE_ALLOWLISTED_FIELDS:
            return key
        return _structure_hash_key(key)

    def walk(value: object, *, depth: int, path: str) -> None:
        if not consume_walk_entry():
            return
        bump_type(value)
        if depth >= _STRUCTURE_MAX_DEPTH:
            if depth == _STRUCTURE_MAX_DEPTH and isinstance(value, (dict, list)):
                mark_truncated()
            return
        if isinstance(value, dict):
            allowlisted: dict[str, str] = {}
            dynamic_hashes: list[str] = []
            for key, child in value.items():
                secret = _structure_secret_category(key)
                if secret is not None:
                    if not record_secret(key):
                        break
                    continue
                child_path = f"{path}.{path_segment(key)}" if path else path_segment(key)
                if key in _STRUCTURE_ALLOWLISTED_FIELDS:
                    allowlisted[key] = _structure_json_type(child)
                    walk(child, depth=depth + 1, path=child_path)
                    if state["entries"] >= _STRUCTURE_MAX_ENTRIES:
                        mark_truncated()
                        break
                else:
                    if not append_capped(dynamic_hashes, _structure_hash_key(key)):
                        break
                    walk(child, depth=depth + 1, path=child_path)
                    if state["entries"] >= _STRUCTURE_MAX_ENTRIES:
                        mark_truncated()
                        break
            if allowlisted or dynamic_hashes:
                sample: dict[str, Any] = {"path": path or "<root>", "container_type": "object"}
                if allowlisted:
                    sample["allowlisted_fields"] = [
                        {"name": name, "type": field_type}
                        for name, field_type in sorted(allowlisted.items())
                    ]
                if dynamic_hashes:
                    sample["dynamic_key_hashes"] = sorted(dynamic_hashes)
                append_field_sample(sample)
            return
        if isinstance(value, list):
            element_histogram: dict[str, int] = {}
            merged_fields: dict[str, str] = {}
            sample_count = 0
            for item in value:
                kind = _structure_json_type(item)
                element_histogram[kind] = element_histogram.get(kind, 0) + 1
                if sample_count < 3 and isinstance(item, dict):
                    sample_count += 1
                    for key, child in item.items():
                        secret = _structure_secret_category(key)
                        if secret is not None:
                            if not record_secret(key):
                                break
                            continue
                        if key in _STRUCTURE_ALLOWLISTED_FIELDS:
                            merged_fields[key] = _structure_json_type(child)
                if state["entries"] < _STRUCTURE_MAX_ENTRIES:
                    walk(item, depth=depth + 1, path=path)
                else:
                    mark_truncated()
                    break
            sample = {
                "path": path or "<root>",
                "container_type": "array",
                "count": len(value),
                "element_type_histogram": element_histogram,
            }
            if merged_fields:
                sample["allowlisted_fields"] = [
                    {"name": name, "type": field_type}
                    for name, field_type in sorted(merged_fields.items())
                ]
            append_field_sample(sample)

    for top_key in payload:
        if top_key in _STRUCTURE_ALLOWLISTED_FIELDS:
            continue
        if not append_capped(dynamic_top_key_hashes, _structure_hash_key(top_key)):
            break

    walk(payload, depth=0, path="")

    result: dict[str, Any] = {
        "top_type": "object",
        "top_count": len(payload),
        "value_type_histogram": dict(sorted(histogram.items())),
        "dynamic_top_key_hashes": sorted(dynamic_top_key_hashes),
        "secret_field_categories": sorted(
            secret_fields.values(),
            key=lambda item: item["key_hash"],
        ),
        "field_samples": field_samples,
        "truncated": state["truncated"],
    }

    return _enforce_structure_output_bound(result)


def describe_list_structure(payload: object) -> dict[str, Any]:
    """Emit a bounded structural fingerprint for a JSON array root (no raw values)."""
    if not isinstance(payload, list):
        raise ValueError("describe_list_structure requires a JSON array")

    state = {"entries": 0, "truncated": False}
    histogram: dict[str, int] = {}
    secret_fields: dict[str, dict[str, str]] = {}
    field_samples: list[dict[str, Any]] = []

    root_element_histogram: dict[str, int] = {}
    for item in payload:
        kind = _structure_json_type(item)
        root_element_histogram[kind] = root_element_histogram.get(kind, 0) + 1

    def bump_type(value: object) -> None:
        kind = _structure_json_type(value)
        histogram[kind] = histogram.get(kind, 0) + 1

    def mark_truncated() -> None:
        state["truncated"] = True

    def consume_walk_entry() -> bool:
        if state["entries"] >= _STRUCTURE_MAX_ENTRIES:
            mark_truncated()
            return False
        state["entries"] += 1
        return True

    def append_capped(target: list[Any], item: Any) -> bool:
        if len(target) >= _STRUCTURE_MAX_ENTRIES:
            mark_truncated()
            return False
        target.append(item)
        return True

    def record_secret(key: str) -> bool:
        if len(secret_fields) >= _STRUCTURE_MAX_ENTRIES:
            mark_truncated()
            return False
        category = _structure_secret_category(key)
        if category is None:
            category = "secret"
        key_hash = _structure_hash_key(key)
        secret_fields[key_hash] = {"category": category, "key_hash": key_hash}
        return True

    def append_field_sample(sample: dict[str, Any]) -> None:
        if len(field_samples) >= _STRUCTURE_MAX_ENTRIES:
            mark_truncated()
            return
        field_samples.append(sample)

    def path_segment(key: str) -> str:
        if key in _STRUCTURE_ALLOWLISTED_FIELDS:
            return key
        return _structure_hash_key(key)

    def indexed_child_path(parent_path: str, index: int) -> str:
        segment = f"[{index}]"
        return f"{parent_path}{segment}" if parent_path else segment

    def walk(value: object, *, depth: int, path: str) -> None:
        if not consume_walk_entry():
            return
        bump_type(value)
        if depth >= _STRUCTURE_MAX_DEPTH:
            if depth == _STRUCTURE_MAX_DEPTH and isinstance(value, (dict, list)):
                mark_truncated()
            return
        if isinstance(value, dict):
            allowlisted: dict[str, str] = {}
            dynamic_hashes: list[str] = []
            for key, child in value.items():
                secret = _structure_secret_category(key)
                if secret is not None:
                    if not record_secret(key):
                        break
                    continue
                child_path = f"{path}.{path_segment(key)}" if path else path_segment(key)
                if key in _STRUCTURE_ALLOWLISTED_FIELDS:
                    allowlisted[key] = _structure_json_type(child)
                    walk(child, depth=depth + 1, path=child_path)
                    if state["entries"] >= _STRUCTURE_MAX_ENTRIES:
                        mark_truncated()
                        break
                else:
                    if not append_capped(dynamic_hashes, _structure_hash_key(key)):
                        break
                    walk(child, depth=depth + 1, path=child_path)
                    if state["entries"] >= _STRUCTURE_MAX_ENTRIES:
                        mark_truncated()
                        break
            if allowlisted or dynamic_hashes:
                sample: dict[str, Any] = {"path": path or "<root>", "container_type": "object"}
                if allowlisted:
                    sample["allowlisted_fields"] = [
                        {"name": name, "type": field_type}
                        for name, field_type in sorted(allowlisted.items())
                    ]
                if dynamic_hashes:
                    sample["dynamic_key_hashes"] = sorted(dynamic_hashes)
                append_field_sample(sample)
            return
        if isinstance(value, list):
            element_histogram: dict[str, int] = {}
            for item in value:
                kind = _structure_json_type(item)
                element_histogram[kind] = element_histogram.get(kind, 0) + 1
            merged_fields: dict[str, str] = {}
            sample_count = 0
            for idx, item in enumerate(value):
                if sample_count < 3 and isinstance(item, dict):
                    sample_count += 1
                    for key, child in item.items():
                        secret = _structure_secret_category(key)
                        if secret is not None:
                            if not record_secret(key):
                                break
                            continue
                        if key in _STRUCTURE_ALLOWLISTED_FIELDS:
                            merged_fields[key] = _structure_json_type(child)
                child_path = indexed_child_path(path, idx)
                if state["entries"] < _STRUCTURE_MAX_ENTRIES:
                    walk(item, depth=depth + 1, path=child_path)
                else:
                    mark_truncated()
                    break
            sample = {
                "path": path or "<root>",
                "container_type": "array",
                "count": len(value),
                "element_type_histogram": element_histogram,
            }
            if merged_fields:
                sample["allowlisted_fields"] = [
                    {"name": name, "type": field_type}
                    for name, field_type in sorted(merged_fields.items())
                ]
            append_field_sample(sample)

    walk(payload, depth=0, path="")

    result: dict[str, Any] = {
        "top_type": "array",
        "top_count": len(payload),
        "element_type_histogram": dict(sorted(root_element_histogram.items())),
        "value_type_histogram": dict(sorted(histogram.items())),
        "dynamic_top_key_hashes": [],
        "secret_field_categories": sorted(
            secret_fields.values(),
            key=lambda item: item["key_hash"],
        ),
        "field_samples": field_samples,
        "truncated": state["truncated"],
    }

    return _enforce_structure_output_bound(result)


def build_gate_a_evidence(
    *,
    model: str,
    title: str | None,
    firmware_version: str,
    build: str | None,
    update_channel: str | None,
    component_set_digest: str,
    device_fingerprint_digest: str,
    evidence_recorded_at: str,
    transport_security: str | None = None,
    https_check: str | None = None,
    gate_a_certification_eligible: bool = False,
    certification_eligible: bool = False,
    ssh_host_key_algorithm: str | None = None,
    ssh_host_key_fingerprint_sha256: str | None = None,
    fingerprint_status: str,
    identity_shape: str,
    identity_complete: bool,
    model_source: str,
    update_channel_source: str,
    build_source: str,
    region: str | None = None,
    region_source: str = "unknown",
    physical_identifier_source: str,
    firmware_sources_agreement: bool | None = None,
    model_disagreement: bool = False,
    firmware_display_title: str | None = None,
    model_display: str | None = None,
    model_display_source: str = "unknown",
    sandbox: str | None = None,
    sandbox_source: str = "unknown",
    bsp_build: str | None = None,
    bsp_build_source: str = "unknown",
) -> dict[str, Any]:

    payload: dict[str, Any] = {

        "model": model,

        "firmware_version": firmware_version,

        "component_set_digest": component_set_digest,

        "device_fingerprint": device_fingerprint_digest,

        "evidence_recorded_at": evidence_recorded_at,

        "gate_a_certification_eligible": gate_a_certification_eligible,

        "certification_eligible": certification_eligible,

        "fingerprint_status": fingerprint_status,

        "identity_shape": identity_shape,

        "identity_complete": identity_complete,

        "model_source": model_source,

        "update_channel_source": update_channel_source,

        "build_source": build_source,

        "physical_identifier_source": physical_identifier_source,
        "model_disagreement": model_disagreement,
    }
    if firmware_sources_agreement is not None:
        payload["firmware_sources_agreement"] = firmware_sources_agreement
    if region_source != "unknown":
        payload["region_source"] = region_source

    if title:

        payload["title"] = title

    if firmware_display_title:

        payload["firmware_display_title"] = firmware_display_title

    if model_display:
        payload["model_display"] = model_display
        if model_display_source != "unknown":
            payload["model_display_source"] = model_display_source
    if build:
        payload["build"] = build
    if bsp_build:
        payload["bsp_build"] = bsp_build
        if bsp_build_source != "unknown":
            payload["bsp_build_source"] = bsp_build_source
    if sandbox:
        payload["sandbox"] = sandbox
        if sandbox_source != "unknown":
            payload["sandbox_source"] = sandbox_source
    if region:
        payload["region"] = region
    if update_channel:
        payload["update_channel"] = update_channel

    if transport_security is not None:

        payload["transport_security"] = transport_security

    if https_check is not None:

        payload["https_check"] = https_check

    if ssh_host_key_algorithm:
        payload["ssh_host_key_algorithm"] = ssh_host_key_algorithm

    if ssh_host_key_fingerprint_sha256:
        payload["ssh_host_key_fingerprint_sha256"] = ssh_host_key_fingerprint_sha256

    return sanitize_mapping(payload)

