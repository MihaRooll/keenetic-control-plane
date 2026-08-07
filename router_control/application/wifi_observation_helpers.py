"""Shared Wi-Fi interface readback parsing and idempotent compare helpers."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal, cast

from router_control.adapters.netcraze.sanitize import sanitize_mapping
from router_control.domain.network_intents import WifiBand, WifiWpaMode

ComparisonResult = Literal["match", "differs", "unknown"]

# auth-type/security-level intentionally excluded — not association or WPA indicators
# (use encryption + link/connected/state/ssid; site-survey uses mode/channel/rssi).
_INTERFACE_FIELD_KEYS = frozenset({"ssid", "encryption", "state", "up"})
_LINK_KEYS = frozenset({"link", "connected", "broadcast", "broadcasting"})
_SECRET_FIELD_KEYS = frozenset(
    {"psk", "passphrase", "wpa_psk", "pre_shared_key", "password", "key"}
)
# Note: walk uses broad "key" for derive_key_configured heuristics only; show-rc ingest
# redaction uses sanitize_mapping/redact_key (narrower — "key" alone is not redacted there).
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)(psk|passphrase|password|pre[_-]?shared[_-]?key|wpa[_-]?psk)\s*[=:]\s*\S+"
)
_AUTH_WPA_PSK_RE = re.compile(r"(?i)(authentication\s+wpa-psk)\s+\S+")
_SECRET_SPACE_DELIMITED_RE = re.compile(r"(?i)(?<!\S)(wpa-psk|psk|passphrase)\s+\S+")
_WG_PRIVATE_KEY_RE = re.compile(r"(?i)(wireguard\s+private-key)\s+\S+")
_WG_PRESHARED_KEY_RE = re.compile(r"(?i)(preshared-key)\s+\S+")

# Fail-closed secret indicators for error/audit text (not show-rc partial scrub).
_ERROR_MESSAGE_REDACTED = "[REDACTED:error_message]"
_SECRET_ERROR_FIELD_NAMES = (
    "preshared_key",
    "presharedkey",
    "pre_shared_key",
    "pre_shared",
    "preshared",
    "private_key",
    "privatekey",
    "private-key",
    "wpa_psk",
    "wpa-psk",
    "passphrase",
    "password",
    "credential",
    "secret",
    "ssid",
    "psk",
    "key",
    "passwd",
    "пароль",
)
_SECRET_ERROR_FIELDS_ALT = "|".join(
    re.escape(name) for name in sorted(_SECRET_ERROR_FIELD_NAMES, key=len, reverse=True)
)
_SECRET_ERROR_FIELD_ASSIGNMENT_RE = re.compile(
    rf"(?i)(?:{_SECRET_ERROR_FIELDS_ALT})\s*[=:\t]\s*\S"
)
_SECRET_ERROR_JSON_KEY_RE = re.compile(
    rf"""(?i)["'](?:{_SECRET_ERROR_FIELDS_ALT})["']\s*:"""
)
_SECRET_ERROR_URL_ENCODED_ASSIGNMENT_RE = re.compile(
    rf"(?i)(?:{_SECRET_ERROR_FIELDS_ALT})%3[dD]"
)
_SECRET_ERROR_DOUBLE_URL_ENCODED_ASSIGNMENT_RE = re.compile(
    rf"(?i)(?:{_SECRET_ERROR_FIELDS_ALT}|passwd|pass%20word|пароль)%253[dD]"
)
_SECRET_ERROR_URL_ENCODED_JSON_KEY_RE = re.compile(
    rf"(?i)%22(?:{_SECRET_ERROR_FIELDS_ALT})%22(?:%3[aA]|:)\s*"
)
_SECRET_ERROR_WG_LEXICON_RE = re.compile(
    r"(?i)(?:wireguard\s+private-key|preshared-key)\s+\S"
)
_SECRET_ERROR_WPA_PSK_SPACE_RE = re.compile(r"(?i)(?:authentication\s+)?wpa-psk\s+\S")
_SECRET_ERROR_PSK_SPACE_RE = re.compile(r"(?i)(?<![_\w])psk\s+\S{8,}")
_SECRET_ERROR_PASSWORD_PROSE_RE = re.compile(
    r"(?i)\bpassword\b(?:\s+(?:is|was|are|were)\s+\S|\s*[=:\t]\s*\S)"
)
_SECRET_ERROR_PASSPHRASE_RE = re.compile(r"(?i)\bpassphrase\b['\s=:\t]")
_SECRET_ERROR_PRIVATE_KEY_RE = re.compile(r"(?i)\bprivate[_-]?key\b\s*[=:\t]\s*\S")
_SECRET_ERROR_CREDENTIAL_VALUE_RE = re.compile(
    r"(?i)(?<![_\w])credential(?![_\w]|_ref)\s*[=:\t]\s*\S"
)
_SECRET_ERROR_SECRET_ASSIGNMENT_RE = re.compile(r"(?i)\bsecret\b\s*[=:\t]\s*\S")
_SECRET_ERROR_AUTHORIZATION_BEARER_RE = re.compile(
    r"(?i)\bauthorization\s*:\s*bearer\s+\S{8,}"
)
_SECRET_ERROR_PEM_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"
)
_LEXICAL_SECRET_INDICATOR_RES: tuple[re.Pattern[str], ...] = (
    _SECRET_ERROR_FIELD_ASSIGNMENT_RE,
    _SECRET_ERROR_JSON_KEY_RE,
    _SECRET_ERROR_URL_ENCODED_ASSIGNMENT_RE,
    _SECRET_ERROR_DOUBLE_URL_ENCODED_ASSIGNMENT_RE,
    _SECRET_ERROR_URL_ENCODED_JSON_KEY_RE,
    _SECRET_ERROR_WG_LEXICON_RE,
    _SECRET_ERROR_WPA_PSK_SPACE_RE,
    _SECRET_ERROR_PSK_SPACE_RE,
    _SECRET_ERROR_PASSWORD_PROSE_RE,
    _SECRET_ERROR_PASSPHRASE_RE,
    _SECRET_ERROR_PRIVATE_KEY_RE,
    _SECRET_ERROR_CREDENTIAL_VALUE_RE,
    _SECRET_ERROR_SECRET_ASSIGNMENT_RE,
    _SECRET_ERROR_AUTHORIZATION_BEARER_RE,
    _SECRET_ERROR_PEM_PRIVATE_KEY_RE,
)
# Structural second barrier: high-entropy / PEM-like material without field-name lexicon.
# ``=`` excluded so ``field=value`` pairs are not one glued high-entropy token (F-3).
_CANDIDATE_SECRET_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/_-]{32,})(?![A-Za-z0-9+/=_-])"
)
# OpenSSH-style host-key digests: mask only plausible fingerprint tail (F-1 bypass).
_SHA256_FINGERPRINT_TAIL_RE = re.compile(r"SHA256:([A-Za-z0-9+/=]+)")
_MAX_SHA256_FINGERPRINT_B64_LEN = 43
# Module paths: bounded segments so lowercase secret suffixes cannot extend the mask.
_MODULE_PATH_MASK_RE = re.compile(
    r"\b(?:[a-z_][a-z0-9_]{0,48}/)+[a-z_][a-z0-9_]{0,48}\b"
)
_SAFE_DIAGNOSTIC_TOKEN_RES: tuple[re.Pattern[str], ...] = (
    re.compile(r"^SHA256:[A-Za-z0-9+/=]+$"),
    re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        re.IGNORECASE,
    ),
    re.compile(r"^(req_|corr_|cred_|credref:)[a-z0-9_-]+$", re.IGNORECASE),
    re.compile(r"^WifiMaster\d+/AccessPoint\d+$"),
    re.compile(r"^Wireguard\d+$"),
    re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", re.IGNORECASE),
    re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$"),
    re.compile(r"^[a-z_][a-z0-9_]*(?:/[a-z_][a-z0-9_]*)+$"),
)
# Operator-safe structured codes (stable; no secret-bearing prose).
ERROR_CODE_CREDENTIAL_REF_REQUIRED = "planner.credential_ref_required"
ERROR_CODE_SSID_REQUIRED = "planner.ssid_required"
ERROR_CODE_CREDENTIAL_RESOLUTION_FAILED = "service.credential_resolution_failed"
ERROR_CODE_OP_DISPATCH_FAILED = "service.op_dispatch_failed"
ERROR_CODE_READBACK_FAILED = "service.readback_failed"
ERROR_CODE_UNSUPPORTED_OPERATION = "service.unsupported_operation"
ERROR_CODE_NO_APPLY_OPS = "planner.no_apply_ops"
ERROR_CODE_GUEST_ISOLATION_UNSUPPORTED = "planner.guest_isolation_unsupported"
ERROR_CODE_CAPTIVE_PORTAL_UNSUPPORTED = "planner.captive_portal_unsupported"
ERROR_CODE_STATION_PRIORITY_REQUIRES_IP_GLOBAL = "planner.station_priority_requires_ip_global"


def walk_for_keys(obj: Any, keys: frozenset[str]) -> dict[str, Any]:
    found: dict[str, Any] = {}
    if isinstance(obj, dict):
        for key, value in obj.items():
            normalized = str(key).lower().replace("-", "_")
            if normalized in keys and normalized not in found:
                found[normalized] = value
            child = walk_for_keys(value, keys)
            for child_key, child_value in child.items():
                found.setdefault(child_key, child_value)
    elif isinstance(obj, list):
        for item in obj:
            child = walk_for_keys(item, keys)
            for child_key, child_value in child.items():
                found.setdefault(child_key, child_value)
    return found


def extract_interface_fields(raw: Any) -> dict[str, Any]:
    found = walk_for_keys(raw, _INTERFACE_FIELD_KEYS | _LINK_KEYS)
    return {key: found[key] for key in sorted(found)}


def sanitize_observed_fields(observed: dict[str, Any]) -> dict[str, object]:
    sanitized = sanitize_mapping(dict(observed))
    return {str(key): value for key, value in sanitized.items()}


def encryption_value_enabled(value: Any) -> bool:
    if value in (False, None, "", 0):
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        text = value.strip().lower()
        if text in {"no", "false", "disabled", "0", "off", "none"}:
            return False
        return bool(text)
    return bool(value)


def encryption_indicates_wpa3(encryption: Any) -> bool:
    if encryption is None:
        return False
    if isinstance(encryption, dict):
        for key, value in encryption.items():
            if not encryption_value_enabled(value):
                continue
            key_text = str(key).lower()
            if "wpa3" in key_text:
                return True
            if isinstance(value, str) and "wpa3" in value.lower():
                return True
        return False
    text = str(encryption).lower()
    return "wpa3" in text and "no" not in text


def encryption_indicates_wpa2(encryption: Any) -> bool:
    if encryption is None:
        return False
    if isinstance(encryption, dict):
        for key, value in encryption.items():
            if not encryption_value_enabled(value):
                continue
            key_text = str(key).lower()
            if "wpa2" in key_text:
                return True
            if isinstance(value, str) and "wpa2" in value.lower():
                return True
        return False
    text = str(encryption).lower()
    return "wpa2" in text and "no" not in text


def encryption_matches_mode(encryption: Any, wpa_mode: WifiWpaMode) -> bool:
    if wpa_mode == WifiWpaMode.WPA2:
        return encryption_indicates_wpa2(encryption)
    if wpa_mode == WifiWpaMode.WPA3:
        return encryption_indicates_wpa3(encryption)
    if wpa_mode == WifiWpaMode.WPA2_WPA3_MIXED:
        return encryption_indicates_wpa2(encryption) and encryption_indicates_wpa3(encryption)
    return False


def encryption_empty(encryption: Any) -> bool:
    if encryption is None:
        return True
    if isinstance(encryption, dict):
        return not any(value not in (False, None, "", 0, {}, []) for value in encryption.values())
    text = str(encryption).strip().lower()
    return text in ("", "none", "disabled", "{}")


_NON_MATCHABLE_WPA_MODES = frozenset({"unknown", "not_configured", "unrecognized"})

_OPEN_DISABLED_SCALAR_VALUES = frozenset({"disabled", "none"})


def _scalar_is_disabled_none(value: Any) -> bool:
    """True only for explicit ``disabled`` / ``none`` string tokens (not empty/0/False)."""
    if not isinstance(value, str):
        return False
    return value.strip().lower() in _OPEN_DISABLED_SCALAR_VALUES


def encryption_indicates_open(encryption: Any) -> bool:
    """True when encryption readback clearly indicates an open/disabled neighbour network."""
    if encryption is None:
        return False
    if encryption_indicates_wpa2(encryption) or encryption_indicates_wpa3(encryption):
        return False
    if isinstance(encryption, dict):
        mode_val = encryption.get("encryption-mode")
        if mode_val is None:
            mode_val = encryption.get("encryption_mode")
        has_enc_key = "encryption" in encryption
        has_mode_key = "encryption-mode" in encryption or "encryption_mode" in encryption
        if has_enc_key and has_mode_key:
            enc_val = encryption.get("encryption")
            return _scalar_is_disabled_none(enc_val) and _scalar_is_disabled_none(mode_val)
        return False
    if isinstance(encryption, str):
        return _scalar_is_disabled_none(encryption)
    return False


def map_encryption_to_wpa_mode(encryption: Any) -> str:
    if encryption is None or encryption_empty(encryption):
        return "not_configured"
    has_wpa2 = encryption_indicates_wpa2(encryption)
    has_wpa3 = encryption_indicates_wpa3(encryption)
    if has_wpa2 and has_wpa3:
        return WifiWpaMode.WPA2_WPA3_MIXED.value
    if has_wpa2:
        return WifiWpaMode.WPA2.value
    if has_wpa3:
        return WifiWpaMode.WPA3.value
    return "unrecognized"


def map_encryption_to_survey_wpa_mode(encryption: Any) -> str:
    """Map neighbour site-survey encryption to per-row ``wpa_mode`` (includes ``open``)."""
    if encryption_indicates_open(encryption):
        return "open"
    if encryption_empty(encryption):
        return "not_configured"
    has_wpa2 = encryption_indicates_wpa2(encryption)
    has_wpa3 = encryption_indicates_wpa3(encryption)
    if has_wpa2 and has_wpa3:
        return WifiWpaMode.WPA2_WPA3_MIXED.value
    if has_wpa2:
        return WifiWpaMode.WPA2.value
    if has_wpa3:
        return WifiWpaMode.WPA3.value
    return "unrecognized"


def state_is_up(state: Any) -> bool:
    if isinstance(state, bool):
        return state
    if state is None:
        return False
    text = str(state).strip().lower()
    return text in {"up", "enabled", "true", "1"}


def state_is_down(state: Any) -> bool:
    if isinstance(state, bool):
        return not state
    if state is None:
        return True
    text = str(state).strip().lower()
    return text in {"down", "disabled", "false", "0", ""}


def parse_up_down_flag(value: Any) -> bool | None:
    """Admin/link up-down vocabulary (``link``, ``connected``, ``state``, ``up``).

    Recognizes bool and str tokens: ``up``/``down``, ``enabled``/``disabled``,
    ``true``/``false``, string ``"1"``/``"0"``. Does **not** recognize ``yes``/``no``/
    ``on``/``off`` (broadcast vocabulary — see ``parse_broadcast_flag``). Bare int/
    float/other containers → ``None`` (no device evidence for numeric link). Empty/
    whitespace-only strings → ``None`` (unknown, not down).
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if not text:
        return None
    if text in {"up", "enabled", "true", "1"}:
        return True
    if text in {"down", "disabled", "false", "0"}:
        return False
    return None


_parse_up_down_flag = parse_up_down_flag


def resolve_enabled_or_up(state: Any, up_flag: Any) -> bool | None:
    """Return enabled/up when recognized; None when absent or unrecognized."""
    if state is None and up_flag is None:
        return None
    state_known = parse_up_down_flag(state)
    up_known = parse_up_down_flag(up_flag)
    if state_known is None and up_known is None:
        return None
    if state_known is True or up_known is True:
        return True
    if state_known is False and up_known is False:
        return False
    if state_known is not None:
        return state_known
    return up_known


def sanitize_show_rc_interface_raw(raw: Any) -> Any:
    """Scrub PSK/private-key material from show-rc interface payloads at ingest."""
    if raw is None:
        return None
    if isinstance(raw, str):
        return scrub_encryption_scalar(raw)
    if isinstance(raw, dict):
        sanitized = sanitize_mapping(dict(raw))
        scrubbed = scrub_encryption_value(sanitized)
        return scrubbed if scrubbed is not None else sanitized
    if isinstance(raw, list):
        return [sanitize_show_rc_interface_raw(item) for item in raw]
    if isinstance(raw, tuple):
        return tuple(sanitize_show_rc_interface_raw(item) for item in raw)
    return raw


def _normalize_error_message_for_detection(message: str) -> str:
    """Collapse transport splits so cross-line and abbreviated field names still match."""
    collapsed = re.sub(r"[\r\n\t]+", " ", message)
    collapsed = re.sub(r"(?i)\bpass\s+word\b", "password", collapsed)
    return collapsed


def _is_safe_diagnostic_token(token: str) -> bool:
    return any(pattern.match(token) for pattern in _SAFE_DIAGNOSTIC_TOKEN_RES)


def _token_looks_like_secret_material(token: str) -> bool:
    """Structural heuristic: long high-entropy tokens likely carrying secret bytes."""
    if len(token) < 32:
        return False
    if _is_safe_diagnostic_token(token):
        return False
    allowed = sum(1 for char in token if char.isalnum() or char in "+/=_-")
    if allowed / len(token) < 0.85:
        return False
    char_classes = sum(
        [
            any(char.islower() for char in token),
            any(char.isupper() for char in token),
            any(char.isdigit() for char in token),
            any(char in "+/=_-" for char in token),
        ]
    )
    if char_classes >= 2 and len(token) >= 40:
        return True
    return len(token) >= 48


def _mask_sha256_fingerprints(message: str) -> str:
    """Mask only plausible SHA256 fingerprint tails; leave overlong glued secrets scannable."""

    def _repl(match: re.Match[str]) -> str:
        tail = match.group(1)
        if len(tail) <= _MAX_SHA256_FINGERPRINT_B64_LEN:
            return "SHA256:[FINGERPRINT]"
        return match.group(0)

    return _SHA256_FINGERPRINT_TAIL_RE.sub(_repl, message)


def _mask_safe_structural_regions(message: str) -> str:
    """Mask public digests and module paths before entropy scan."""
    masked = _mask_sha256_fingerprints(message)
    return _MODULE_PATH_MASK_RE.sub("[MODULE-PATH]", masked)


def _iter_structural_secret_candidates(blob: str) -> tuple[str, ...]:
    """Yield token fragments to check; split ``field=value`` glues (F-3)."""
    seen: set[str] = set()
    ordered: list[str] = []
    for match in _CANDIDATE_SECRET_TOKEN_RE.finditer(blob):
        token = match.group(1)
        for fragment in (token, *token.split("=")):
            if not fragment or fragment in seen:
                continue
            seen.add(fragment)
            ordered.append(fragment)
    return tuple(ordered)


def _message_contains_structural_secret_material(message: str, normalized: str) -> bool:
    if _SECRET_ERROR_PEM_PRIVATE_KEY_RE.search(message):
        return True
    if _SECRET_ERROR_AUTHORIZATION_BEARER_RE.search(normalized):
        return True
    for blob in (_mask_safe_structural_regions(message), _mask_safe_structural_regions(normalized)):
        for token in _iter_structural_secret_candidates(blob):
            if _token_looks_like_secret_material(token):
                return True
    return False


def _message_contains_lexical_secret_indicator(normalized: str) -> bool:
    return any(pattern.search(normalized) for pattern in _LEXICAL_SECRET_INDICATOR_RES)


def error_message_contains_secret_indicator(message: str) -> bool:
    """Return True when error/audit text shows lexical or structural secret material."""
    if not message:
        return False
    normalized = _normalize_error_message_for_detection(message)
    if _message_contains_structural_secret_material(message, normalized):
        return True
    return _message_contains_lexical_secret_indicator(normalized)


def scrub_error_message(message: str) -> str:
    """Fail-closed scrub for exception/diagnostic text bound for audit or HTTP errors.

    Two barriers: (1) lexical field/device indicators on normalized text;
    (2) structural PEM/Bearer/high-entropy tokens independent of field names.
    When any barrier triggers the entire message is replaced with a stable
    placeholder. Non-secret diagnostics pass through unchanged. Show-rc ingest
    keeps partial substring scrub via ``scrub_encryption_scalar`` (separate path).
    """
    if error_message_contains_secret_indicator(message):
        return _ERROR_MESSAGE_REDACTED
    return message


def sanitize_station_readback_dict(payload: dict[str, object]) -> dict[str, object]:
    """Final pass: keyed redaction + encryption scalar scrub on readback DTO fields."""
    sanitized = sanitize_mapping(dict(payload))
    result: dict[str, object] = {}
    for key, value in sanitized.items():
        if isinstance(value, str):
            result[str(key)] = scrub_encryption_scalar(value)
        else:
            result[str(key)] = value
    return result


def scrub_encryption_scalar(value: str) -> str:
    """Scrub secret substrings from scalar encryption readback strings."""
    result = _SECRET_ASSIGNMENT_RE.sub(r"\1=REDACTED", value)
    result = _AUTH_WPA_PSK_RE.sub(r"\1 REDACTED", result)
    result = _SECRET_SPACE_DELIMITED_RE.sub(r"\1 REDACTED", result)
    result = _WG_PRIVATE_KEY_RE.sub(r"\1 REDACTED", result)
    return _WG_PRESHARED_KEY_RE.sub(r"\1 REDACTED", result)


def scrub_encryption_value(value: Any) -> object | None:
    """Recursively scrub encryption readback containers; preserve keyed sanitize_mapping."""
    if value is None:
        return None
    if isinstance(value, str):
        return scrub_encryption_scalar(value)
    if isinstance(value, dict):
        sanitized = sanitize_mapping(dict(value))
        return _scrub_encryption_nested(sanitized)
    if isinstance(value, list):
        return [_scrub_encryption_nested_item(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_scrub_encryption_nested_item(item) for item in value)
    return cast(object, value)


def _scrub_encryption_nested_item(item: Any) -> object:
    if isinstance(item, (str, dict, list, tuple)):
        scrubbed = scrub_encryption_value(item)
        return scrubbed if scrubbed is not None else item
    return item


def _scrub_encryption_nested(mapping: dict[str, Any]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, val in mapping.items():
        if isinstance(val, (str, dict, list, tuple)):
            scrubbed = scrub_encryption_value(val)
            result[str(key)] = scrubbed if scrubbed is not None else val
        else:
            result[str(key)] = val
    return result


def ssid_present(ssid: Any) -> bool:
    if ssid is None:
        return False
    return bool(str(ssid).strip())


def band_label_from_ap_id(ap_id: str) -> str:
    if ap_id.startswith("WifiMaster0/"):
        return "2.4GHz"
    if ap_id.startswith("WifiMaster1/"):
        return "5GHz"
    return "unknown"


def band_label_from_intent(band: WifiBand) -> str:
    if band == WifiBand.BAND_2_4GHZ:
        return "2.4GHz"
    if band == WifiBand.BAND_5GHZ:
        return "5GHz"
    return "unknown"


def parse_broadcast_flag(value: Any) -> bool | None:
    """Broadcast/broadcasting vocabulary — supplementary to ``link``.

    Recognizes bool and str tokens: ``true``/``false``, ``yes``/``no``, ``on``/``off``,
    ``up``/``down``, string ``"1"``/``"0"``. Does **not** recognize ``enabled``/
    ``disabled`` (admin/link vocabulary — see ``parse_up_down_flag``). Bare int/float/
    other containers and empty strings → ``None``.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if not text:
        return None
    if text in {"true", "1", "yes", "on", "up"}:
        return True
    if text in {"false", "0", "no", "off", "down"}:
        return False
    return None


_parse_broadcast_flag = parse_broadcast_flag


def resolve_link_up(fields: dict[str, Any]) -> bool | None:
    """On-wire link signal from ``link`` only — never from broadcast/connected/state."""
    if "link" not in fields:
        return None
    return parse_up_down_flag(fields["link"])


def resolve_broadcast(fields: dict[str, Any]) -> bool | None:
    """Broadcast/broadcasting flag — supplementary; never substitutes ``link_up``."""
    if "broadcast" in fields:
        return parse_broadcast_flag(fields["broadcast"])
    if "broadcasting" in fields:
        return parse_broadcast_flag(fields["broadcasting"])
    return None


def resolve_on_air_signal(fields: dict[str, Any]) -> bool | None:
    """On-air verdict: ``link_up`` from ``link`` only; link/broadcast conflict → unknown."""
    link = resolve_link_up(fields)
    broadcast = resolve_broadcast(fields)
    if link is not None and broadcast is not None and link != broadcast:
        return None
    return link


def resolve_device_connected(fields: dict[str, Any]) -> bool | None:
    """Opaque device connected flag; not equivalent to on-air/broadcasting."""
    if "connected" not in fields:
        return None
    return parse_up_down_flag(fields["connected"])


def derive_key_configured(raw: Any, sanitized_fields: dict[str, object]) -> bool | None:
    raw_secrets = walk_for_keys(raw, _SECRET_FIELD_KEYS)
    for value in raw_secrets.values():
        if value not in (None, "", False, 0):
            return True
    for key, value in sanitized_fields.items():
        normalized = str(key).lower().replace("-", "_")
        secret_fragments = ("psk", "passphrase", "pre_shared", "wpa_psk")
        if any(fragment in normalized for fragment in secret_fragments):
            if value == "REDACTED":
                return True
            if value not in (None, "", False, 0):
                return True
    return None


def derive_dhcp_client_configured(raw: Any) -> bool | None:
    """Return whether show-rc reports ``ip address dhcp`` on the station interface.

    ``show interface`` runtime ``summary.ipv4`` reflects acquisition state, not
    configured DHCP client (see docs/OPERATOR_WIFI_DISCOVERY.md §2c — admin up
    may leave summary.ipv4 pending/disabled). Only show-rc ``address dhcp`` is
    used for compensation baseline.
    """
    if raw is None:
        return None
    candidates = walk_for_keys(
        raw,
        frozenset({"address dhcp", "address_dhcp", "dhcp"}),
    )
    for key, value in candidates.items():
        normalized_key = str(key).lower().replace("-", "_").replace(" ", "_")
        if "dhcp" not in normalized_key:
            continue
        if "address" not in normalized_key and normalized_key != "dhcp":
            continue
        if value in (True, "yes", "true", "1", 1):
            return True
        if value in (False, "no", "false", "0", 0, "", None):
            return False
    return None


def compare_ssid_field(
    observed_ssid: str | None,
    expected_ssid: str,
    *,
    readable: bool,
) -> ComparisonResult:
    if not readable or observed_ssid is None:
        return "unknown"
    if not ssid_present(observed_ssid):
        return "unknown"
    return "match" if str(observed_ssid) == expected_ssid else "differs"


def compare_encryption_field(
    expected_mode: WifiWpaMode,
    *,
    readable: bool,
    mapped_mode: str,
) -> ComparisonResult:
    if not readable or mapped_mode in _NON_MATCHABLE_WPA_MODES:
        return "unknown"
    return "match" if mapped_mode == expected_mode.value else "differs"


def compare_enabled_field(
    observed_up: bool | None,
    expected_enabled: bool,
    *,
    readable: bool,
) -> ComparisonResult:
    if not readable or observed_up is None:
        return "unknown"
    return "match" if observed_up == expected_enabled else "differs"


def compare_band_field(
    observed_band: str,
    expected_band: WifiBand,
    *,
    readable: bool,
) -> ComparisonResult:
    if not readable or observed_band == "unknown":
        return "unknown"
    return "match" if observed_band == band_label_from_intent(expected_band) else "differs"


@dataclass(frozen=True, slots=True)
class WifiStationInterfaceReadback:
    """Split station readback: configured (show rc) vs associated (show interface)."""

    configured_ssid: str | None
    configured_encryption: str | None
    configured_dhcp_client: bool | None
    associated_ssid: str | None
    associated_ssid_field_present: bool
    associated_encryption: str | None
    state: str | None

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "configured_ssid": self.configured_ssid,
            "configured_encryption": self.configured_encryption,
            "configured_dhcp_client": self.configured_dhcp_client,
            "associated_ssid": self.associated_ssid,
            "associated_ssid_field_present": self.associated_ssid_field_present,
            "associated_encryption": self.associated_encryption,
            "state": self.state,
        }
        if self.associated_ssid_field_present and not ssid_present(self.associated_ssid):
            payload["associated_network"] = "none"
        elif ssid_present(self.associated_ssid):
            payload["associated_network"] = "present"
        else:
            payload["associated_network"] = "unknown"
        return sanitize_station_readback_dict(payload)


def _scalar_field_value(raw: Any, key: str) -> Any | None:
    fields = extract_interface_fields(raw)
    normalized = key.lower().replace("-", "_")
    for field_key, value in fields.items():
        if field_key.lower().replace("-", "_") == normalized:
            return value
    walked = walk_for_keys(raw, frozenset({normalized}))
    return walked.get(normalized)


def parse_station_associated_ssid(runtime_raw: Any) -> tuple[str | None, bool]:
    """Return (associated_ssid, field_present). Empty field while up = no association."""
    fields = extract_interface_fields(runtime_raw)
    if "ssid" not in fields:
        walked = walk_for_keys(runtime_raw, frozenset({"ssid"}))
        if "ssid" not in walked:
            return None, False
        raw_ssid = walked["ssid"]
    else:
        raw_ssid = fields["ssid"]
    if raw_ssid is None:
        return None, True
    text = str(raw_ssid).strip()
    if not text:
        return None, True
    return text, True


def parse_station_configured_ssid(configured_raw: Any) -> str | None:
    """Configured SSID from ``show rc interface`` (not runtime association)."""
    raw_ssid = _scalar_field_value(configured_raw, "ssid")
    if raw_ssid is None:
        return None
    text = str(raw_ssid).strip()
    return text or None


def parse_station_interface_readback(
    configured_raw: Any,
    runtime_raw: Any,
) -> WifiStationInterfaceReadback:
    configured_sanitized = sanitize_show_rc_interface_raw(configured_raw)
    configured_ssid = parse_station_configured_ssid(configured_sanitized)
    configured_encryption_raw = _scalar_field_value(configured_sanitized, "encryption")
    configured_encryption = (
        None
        if configured_encryption_raw is None
        else scrub_encryption_scalar(str(configured_encryption_raw).strip()) or None
    )
    configured_dhcp_client = derive_dhcp_client_configured(configured_sanitized)
    associated_ssid, associated_field_present = parse_station_associated_ssid(runtime_raw)
    runtime_fields = extract_interface_fields(runtime_raw)
    associated_encryption_raw = runtime_fields.get("encryption")
    associated_encryption = (
        None
        if associated_encryption_raw is None
        else str(associated_encryption_raw).strip() or None
    )
    state_raw = runtime_fields.get("state")
    state = None if state_raw is None else str(state_raw).strip() or None
    return WifiStationInterfaceReadback(
        configured_ssid=configured_ssid,
        configured_encryption=configured_encryption,
        configured_dhcp_client=configured_dhcp_client,
        associated_ssid=associated_ssid,
        associated_ssid_field_present=associated_field_present,
        associated_encryption=associated_encryption,
        state=state,
    )
