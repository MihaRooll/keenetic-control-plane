"""Typed, sealed RCI Wi-Fi station (WISP client) operations."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from router_control.adapters.netcraze.allowlist import (
    build_sealed_parse_body,
    validate_ssid,
    validate_wpa_psk,
)
from router_control.adapters.netcraze.dhcp_rci import validate_mac_address
from router_control.adapters.netcraze.fail_safe_rci import (
    FailSafeStatusEntry,
    RciSealedWriteTransport,
    collect_rci_status_and_prompt,
)
from router_control.adapters.netcraze.rci_prompt import (
    RCI_PROMPT_CONFIG,
    is_allowlisted_rci_prompt,
    normalize_rci_prompt,
)
from router_control.adapters.netcraze.transport import SealedRciWriteRequest
from router_control.adapters.netcraze.wifi_station_validation import validate_wifi_station_id

_ALLOWED_PROMPTS = frozenset({RCI_PROMPT_CONFIG})
_SUCCESS_STATUS_KINDS = frozenset({"message", "warning"})
_ERROR_STATUS_KIND = "error"
_ALLOWED_SECURITY_LEVELS = frozenset({"public", "private", "protected"})

_AUTH_TOKENS = frozenset(
    {"permission", "denied", "unauthorized", "forbidden", "authentication failed"}
)
_NOT_FOUND_TOKENS = frozenset(
    {"not found", "no such", "does not exist", "unknown interface", "invalid interface"}
)
_GRAMMAR_TOKENS = frozenset(
    {
        "unknown command",
        "incomplete",
        "syntax",
        "invalid command",
        "parse error",
        "unexpected token",
    }
)
_TRANSPORT_EXCEPTIONS = (TimeoutError, ConnectionError, OSError)


class WifiStationRciErrorCategory(StrEnum):
    UNSUPPORTED_GRAMMAR = "unsupported_grammar"
    REJECTED_BY_ROUTER = "rejected_by_router"
    AUTH_OR_PERMISSION = "auth_or_permission"
    RESOURCE_NOT_FOUND = "resource_not_found"
    TRANSPORT_OR_TIMEOUT = "transport_or_timeout"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class WifiStationRciFailureDetails:
    category: WifiStationRciErrorCategory
    sanitized_message: str
    operation: str
    command_redacted: str


class WifiStationRciError(Exception):
    """RCI Wi-Fi station operation failed or returned an unverifiable ack."""

    def __init__(
        self,
        message: str,
        *,
        details: WifiStationRciFailureDetails | None = None,
    ) -> None:
        super().__init__(message)
        self.details = details


class WifiStationRciOperation(StrEnum):
    SET_SSID = "wifi_station_set_ssid"
    CLEAR_SSID = "wifi_station_clear_ssid"
    UP = "wifi_station_up"
    DOWN = "wifi_station_down"
    SET_WPA_PSK = "wifi_station_set_wpa_psk"
    CLEAR_WPA_PSK = "wifi_station_clear_wpa_psk"
    ENCRYPTION_ENABLE = "wifi_station_encryption_enable"
    ENCRYPTION_WPA2 = "wifi_station_encryption_wpa2"
    ENCRYPTION_WPA3 = "wifi_station_encryption_wpa3"
    ENCRYPTION_WPA2_CLEAR = "wifi_station_encryption_wpa2_clear"
    ENCRYPTION_WPA3_CLEAR = "wifi_station_encryption_wpa3_clear"
    ENCRYPTION_DISABLE = "wifi_station_encryption_disable"
    SET_BSSID = "wifi_station_set_bssid"
    SET_SECURITY_LEVEL = "wifi_station_set_security_level"
    STANDBY_ENABLE = "wifi_station_standby_enable"
    STANDBY_TIMEOUT = "wifi_station_standby_timeout"
    IP_GLOBAL = "wifi_station_ip_global"
    IP_ADDRESS_DHCP = "wifi_station_ip_address_dhcp"
    CLEAR_IP_ADDRESS_DHCP = "wifi_station_clear_ip_address_dhcp"
    CLEAR_IP_ADDRESS = "wifi_station_clear_ip_address"
    PMF = "wifi_station_pmf"
    PMF_FORCE = "wifi_station_pmf_force"


@dataclass(frozen=True, slots=True)
class WifiStationRciResult:
    operation: WifiStationRciOperation
    station_id: str
    ssid: str | None
    ack_matched: bool
    prompt: str
    status_entries: tuple[FailSafeStatusEntry, ...]

    def sanitized_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "operation": self.operation.value,
            "station_id": self.station_id,
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
        if self.ssid is not None:
            payload["ssid"] = self.ssid
        return payload


def _validate_security_level(level: str) -> str:
    normalized = level.strip().lower()
    if normalized not in _ALLOWED_SECURITY_LEVELS:
        raise ValueError(f"security level not allowlisted: {level!r}")
    return normalized


def _validate_priority(priority: int) -> int:
    if isinstance(priority, bool) or not isinstance(priority, int):
        raise ValueError("priority must be an integer")
    if priority < 0 or priority > 65535:
        raise ValueError("priority must be in range 0..65535")
    return priority


def _validate_standby_timeout(seconds: int) -> int:
    if isinstance(seconds, bool) or not isinstance(seconds, int):
        raise ValueError("standby timeout must be an integer")
    if seconds < 1 or seconds > 86400:
        raise ValueError("standby timeout must be in range 1..86400")
    return seconds


def command_for(
    operation: WifiStationRciOperation,
    station_id: str,
    *,
    ssid: str | None = None,
    psk: str | None = None,
    bssid: str | None = None,
    security_level: str | None = None,
    priority: int | None = None,
    global_order: int | None = None,
    global_auto: bool = False,
    standby_timeout: int | None = None,
) -> str:
    station = validate_wifi_station_id(station_id)
    if operation is WifiStationRciOperation.SET_SSID:
        if ssid is None:
            raise WifiStationRciError("ssid is required for SET_SSID")
        normalized_ssid = validate_ssid(ssid)
        return f"interface {station} ssid {normalized_ssid}"
    if operation is WifiStationRciOperation.CLEAR_SSID:
        return f"interface {station} no ssid"
    if operation is WifiStationRciOperation.UP:
        return f"interface {station} up"
    if operation is WifiStationRciOperation.DOWN:
        return f"interface {station} down"
    if operation is WifiStationRciOperation.SET_WPA_PSK:
        if psk is None:
            raise WifiStationRciError("psk is required for SET_WPA_PSK")
        normalized_psk = validate_wpa_psk(psk)
        return f"interface {station} authentication wpa-psk {normalized_psk}"
    if operation is WifiStationRciOperation.CLEAR_WPA_PSK:
        return f"interface {station} no authentication wpa-psk"
    if operation is WifiStationRciOperation.ENCRYPTION_ENABLE:
        return f"interface {station} encryption enable"
    if operation is WifiStationRciOperation.ENCRYPTION_DISABLE:
        return f"interface {station} no encryption enable"
    if operation is WifiStationRciOperation.ENCRYPTION_WPA2:
        return f"interface {station} encryption wpa2"
    if operation is WifiStationRciOperation.ENCRYPTION_WPA2_CLEAR:
        return f"interface {station} no encryption wpa2"
    if operation is WifiStationRciOperation.ENCRYPTION_WPA3:
        return f"interface {station} encryption wpa3"
    if operation is WifiStationRciOperation.ENCRYPTION_WPA3_CLEAR:
        return f"interface {station} no encryption wpa3"
    if operation is WifiStationRciOperation.SET_BSSID:
        if bssid is None:
            raise WifiStationRciError("bssid is required for SET_BSSID")
        normalized_bssid = validate_mac_address(bssid)
        return f"interface {station} mac bssid {normalized_bssid}"
    if operation is WifiStationRciOperation.SET_SECURITY_LEVEL:
        if security_level is None:
            raise WifiStationRciError("security_level is required for SET_SECURITY_LEVEL")
        level = _validate_security_level(security_level)
        return f"interface {station} security-level {level}"
    if operation is WifiStationRciOperation.STANDBY_ENABLE:
        return f"interface {station} standby enable"
    if operation is WifiStationRciOperation.STANDBY_TIMEOUT:
        if standby_timeout is None:
            raise WifiStationRciError("standby_timeout is required for STANDBY_TIMEOUT")
        timeout = _validate_standby_timeout(standby_timeout)
        return f"interface {station} standby timeout {timeout}"
    if operation is WifiStationRciOperation.IP_GLOBAL:
        if global_auto:
            return f"interface {station} ip global auto"
        if global_order is not None:
            order = _validate_priority(global_order)
            return f"interface {station} ip global order {order}"
        if priority is None:
            raise WifiStationRciError("priority is required for IP_GLOBAL")
        validated_priority = _validate_priority(priority)
        return f"interface {station} ip global {validated_priority}"
    if operation is WifiStationRciOperation.IP_ADDRESS_DHCP:
        return f"interface {station} ip address dhcp"
    if operation is WifiStationRciOperation.CLEAR_IP_ADDRESS_DHCP:
        return f"interface {station} no ip address dhcp"
    if operation is WifiStationRciOperation.CLEAR_IP_ADDRESS:
        return f"interface {station} no ip address"
    if operation is WifiStationRciOperation.PMF:
        return f"interface {station} pmf"
    if operation is WifiStationRciOperation.PMF_FORCE:
        return f"interface {station} pmf force"
    raise WifiStationRciError(f"operation not allowlisted: {operation}")


def command_redacted_for(
    operation: WifiStationRciOperation,
    station_id: str,
    *,
    ssid: str | None = None,
    bssid: str | None = None,
    security_level: str | None = None,
    priority: int | None = None,
    global_order: int | None = None,
    global_auto: bool = False,
    standby_timeout: int | None = None,
) -> str:
    """Build a sealed command string safe for error surfaces (PSK never included)."""
    if operation is WifiStationRciOperation.SET_WPA_PSK:
        station = validate_wifi_station_id(station_id)
        return f"interface {station} authentication wpa-psk <redacted>"
    if operation is WifiStationRciOperation.IP_GLOBAL:
        station = validate_wifi_station_id(station_id)
        return f"interface {station} ip global <priority>"
    if operation is WifiStationRciOperation.SET_BSSID:
        station = validate_wifi_station_id(station_id)
        return f"interface {station} mac bssid <bssid>"
    if operation is WifiStationRciOperation.SET_SECURITY_LEVEL:
        station = validate_wifi_station_id(station_id)
        return f"interface {station} security-level <level>"
    if operation is WifiStationRciOperation.STANDBY_TIMEOUT:
        station = validate_wifi_station_id(station_id)
        return f"interface {station} standby timeout <seconds>"
    return command_for(
        operation,
        station_id,
        ssid=ssid,
        bssid=bssid,
        security_level=security_level,
        priority=priority,
        global_order=global_order,
        global_auto=global_auto,
        standby_timeout=standby_timeout,
    )


def _tokenize_evidence(*parts: str) -> str:
    return " ".join(part.strip().lower() for part in parts if part).strip()


def _matches_any(text: str, tokens: frozenset[str]) -> bool:
    return any(token in text for token in tokens)


_AUTH_WHOLE_WORD = re.compile(
    r"\b(?:permission\s+denied|access\s+denied|unauthorized|forbidden)\b",
    re.IGNORECASE,
)

_WPA_PSK_AUTH_MESSAGE = re.compile(
    r"authentication\s+wpa-psk\s+\S+",
    re.IGNORECASE,
)
_WPA_PSK_TRAILING_SECRET = re.compile(
    r"(?<!\w)wpa-psk\s+\S+",
    re.IGNORECASE,
)


def _sanitize_router_status_message(message: str) -> str:
    text = message.strip()
    if not text:
        return text
    text = _WPA_PSK_AUTH_MESSAGE.sub("authentication wpa-psk <redacted>", text)
    text = _WPA_PSK_TRAILING_SECRET.sub("wpa-psk <redacted>", text)
    return text


def _matches_auth_or_permission(text: str) -> bool:
    if _AUTH_WHOLE_WORD.search(text):
        return True
    return _matches_any(text, _AUTH_TOKENS)


def classify_wifi_station_rci_failure(
    *,
    operation: WifiStationRciOperation,
    station_id: str,
    ssid: str | None = None,
    status_entries: tuple[FailSafeStatusEntry, ...] | None = None,
    prompt: str | None = None,
    exc: BaseException | None = None,
    fallback_message: str = "RCI Wi-Fi station operation failed",
) -> WifiStationRciFailureDetails:
    command_redacted = command_redacted_for(operation, station_id, ssid=ssid)
    op_name = operation.value

    if exc is not None and isinstance(exc, _TRANSPORT_EXCEPTIONS):
        return WifiStationRciFailureDetails(
            category=WifiStationRciErrorCategory.TRANSPORT_OR_TIMEOUT,
            sanitized_message=exc.__class__.__name__,
            operation=op_name,
            command_redacted=command_redacted,
        )

    if status_entries:
        error_entries = [entry for entry in status_entries if entry.status == _ERROR_STATUS_KIND]
        if error_entries:
            entry = error_entries[0]
            evidence = _tokenize_evidence(entry.ident, entry.code, entry.message)
            if _matches_any(evidence, _GRAMMAR_TOKENS):
                category = WifiStationRciErrorCategory.UNSUPPORTED_GRAMMAR
            elif _matches_any(evidence, _NOT_FOUND_TOKENS):
                category = WifiStationRciErrorCategory.RESOURCE_NOT_FOUND
            elif _matches_auth_or_permission(evidence):
                category = WifiStationRciErrorCategory.AUTH_OR_PERMISSION
            else:
                category = WifiStationRciErrorCategory.REJECTED_BY_ROUTER
            raw_message = entry.message.strip() or entry.ident.strip() or fallback_message
            message = _sanitize_router_status_message(raw_message)
            return WifiStationRciFailureDetails(
                category=category,
                sanitized_message=message,
                operation=op_name,
                command_redacted=command_redacted,
            )

    if not status_entries or not is_allowlisted_rci_prompt(
        prompt,
        allowed=_ALLOWED_PROMPTS,
        collapse_config_if=True,
    ):
        message = fallback_message
        if exc is not None:
            message = exc.__class__.__name__
        return WifiStationRciFailureDetails(
            category=WifiStationRciErrorCategory.UNKNOWN,
            sanitized_message=message,
            operation=op_name,
            command_redacted=command_redacted,
        )

    return WifiStationRciFailureDetails(
        category=WifiStationRciErrorCategory.UNKNOWN,
        sanitized_message=fallback_message,
        operation=op_name,
        command_redacted=command_redacted,
    )


_OPERATION_ACK_SUBSTRINGS: dict[WifiStationRciOperation, tuple[str, ...]] = {
    WifiStationRciOperation.SET_SSID: ("ssid saved",),
    WifiStationRciOperation.CLEAR_SSID: ("ssid reset",),
    WifiStationRciOperation.SET_WPA_PSK: ("wpa psk set",),
    WifiStationRciOperation.CLEAR_WPA_PSK: ("wpa psk removed",),
    WifiStationRciOperation.ENCRYPTION_ENABLE: ("wireless encryption enabled",),
    WifiStationRciOperation.ENCRYPTION_DISABLE: ("wireless encryption disabled",),
    WifiStationRciOperation.ENCRYPTION_WPA2: ("wpa2 algorithms enabled",),
    WifiStationRciOperation.ENCRYPTION_WPA2_CLEAR: ("wpa2 algorithms disabled",),
    WifiStationRciOperation.UP: ("interface is up",),
    WifiStationRciOperation.DOWN: ("interface is down",),
    WifiStationRciOperation.IP_ADDRESS_DHCP: ("started dhcp client",),
    WifiStationRciOperation.CLEAR_IP_ADDRESS_DHCP: ("stopped dhcp client",),
    WifiStationRciOperation.CLEAR_IP_ADDRESS: ("ip address cleared",),
    # Device-exercised L3 ack 2026-08-05: ident Network::Interface::L3Base; message
    # quotes the station iface and contains "global priority is {N}." — do not hardcode
    # priority value in matcher; station_id binding enforced in _matches_operation_ack.
    WifiStationRciOperation.IP_GLOBAL: ("global priority is",),
}

# Unexercised ops: only Core::Configurator Done (interface-enter pattern).
_CONFIGURATOR_DONE_ACK = ("configurator: done",)
_UNEXERCISED_OPERATION_ACK_SUBSTRINGS: dict[WifiStationRciOperation, tuple[str, ...]] = {
    WifiStationRciOperation.SET_BSSID: _CONFIGURATOR_DONE_ACK,
    WifiStationRciOperation.STANDBY_ENABLE: _CONFIGURATOR_DONE_ACK,
    WifiStationRciOperation.STANDBY_TIMEOUT: _CONFIGURATOR_DONE_ACK,
    WifiStationRciOperation.SET_SECURITY_LEVEL: _CONFIGURATOR_DONE_ACK,
    WifiStationRciOperation.ENCRYPTION_WPA3: _CONFIGURATOR_DONE_ACK,
    WifiStationRciOperation.ENCRYPTION_WPA3_CLEAR: _CONFIGURATOR_DONE_ACK,
    WifiStationRciOperation.PMF: _CONFIGURATOR_DONE_ACK,
    WifiStationRciOperation.PMF_FORCE: _CONFIGURATOR_DONE_ACK,
}


def _entry_evidence_text(entry: FailSafeStatusEntry) -> str:
    return _tokenize_evidence(entry.ident, entry.code, entry.message)


def _entries_match_required_substrings(
    entries: tuple[FailSafeStatusEntry, ...],
    required: tuple[str, ...],
) -> bool:
    for entry in entries:
        evidence = _entry_evidence_text(entry)
        if all(substring in evidence for substring in required):
            return True
    return False


def _matches_operation_ack(
    operation: WifiStationRciOperation,
    entries: tuple[FailSafeStatusEntry, ...],
    *,
    station_id: str | None = None,
) -> bool:
    confirmed = _OPERATION_ACK_SUBSTRINGS.get(operation)
    if confirmed is not None:
        required = confirmed
        if operation is WifiStationRciOperation.IP_GLOBAL:
            if station_id is None:
                return False
            required = (*confirmed, station_id.strip().lower())
        return _entries_match_required_substrings(entries, required)
    unexercised = _UNEXERCISED_OPERATION_ACK_SUBSTRINGS.get(operation)
    if unexercised is not None:
        return _entries_match_required_substrings(entries, unexercised)
    return False


def _raise_classified(
    operation: WifiStationRciOperation,
    station_id: str,
    *,
    ssid: str | None = None,
    status_entries: tuple[FailSafeStatusEntry, ...] | None = None,
    prompt: str | None = None,
    fallback_message: str,
) -> None:
    details = classify_wifi_station_rci_failure(
        operation=operation,
        station_id=station_id,
        ssid=ssid,
        status_entries=status_entries,
        prompt=prompt,
        fallback_message=fallback_message,
    )
    raise WifiStationRciError(fallback_message, details=details)


def sealed_request_for(
    operation: WifiStationRciOperation,
    station_id: str,
    *,
    ssid: str | None = None,
    psk: str | None = None,
    bssid: str | None = None,
    security_level: str | None = None,
    priority: int | None = None,
    global_order: int | None = None,
    global_auto: bool = False,
    standby_timeout: int | None = None,
) -> SealedRciWriteRequest:
    body = build_sealed_parse_body(
        command_for(
            operation,
            station_id,
            ssid=ssid,
            psk=psk,
            bssid=bssid,
            security_level=security_level,
            priority=priority,
            global_order=global_order,
            global_auto=global_auto,
            standby_timeout=standby_timeout,
        )
    )
    return SealedRciWriteRequest(body=body)


def verify_wifi_station_response(
    operation: WifiStationRciOperation,
    station_id: str,
    response: Any,
    *,
    ssid: str | None = None,
) -> WifiStationRciResult:
    station = validate_wifi_station_id(station_id)
    normalized_ssid: str | None = None
    if operation is WifiStationRciOperation.SET_SSID:
        if ssid is None:
            raise WifiStationRciError("ssid is required for SET_SSID verification")
        normalized_ssid = validate_ssid(ssid)
    entries, prompt = collect_rci_status_and_prompt(response)
    status_tuple = tuple(entries)
    normalized_prompt = normalize_rci_prompt(prompt, collapse_config_if=True) if prompt else ""
    if not entries:
        _raise_classified(
            operation,
            station,
            ssid=normalized_ssid,
            status_entries=status_tuple,
            prompt=normalized_prompt or prompt,
            fallback_message="no RCI parse status returned",
        )
    if not is_allowlisted_rci_prompt(
        prompt,
        allowed=_ALLOWED_PROMPTS,
        collapse_config_if=True,
    ):
        _raise_classified(
            operation,
            station,
            ssid=normalized_ssid,
            status_entries=status_tuple,
            prompt=normalized_prompt or prompt,
            fallback_message="RCI parse prompt missing or not allowlisted",
        )
    if any(entry.status == _ERROR_STATUS_KIND for entry in entries):
        _raise_classified(
            operation,
            station,
            ssid=normalized_ssid,
            status_entries=status_tuple,
            prompt=normalized_prompt,
            fallback_message="RCI parse reported an error status",
        )
    if not all(entry.status in _SUCCESS_STATUS_KINDS for entry in entries):
        _raise_classified(
            operation,
            station,
            ssid=normalized_ssid,
            status_entries=status_tuple,
            prompt=normalized_prompt,
            fallback_message="RCI parse returned an unexpected status kind",
        )
    if not _matches_operation_ack(operation, status_tuple, station_id=station):
        _raise_classified(
            operation,
            station,
            ssid=normalized_ssid,
            status_entries=status_tuple,
            prompt=normalized_prompt,
            fallback_message="RCI parse ack does not match device-confirmed pattern",
        )
    return WifiStationRciResult(
        operation=operation,
        station_id=station,
        ssid=normalized_ssid,
        ack_matched=True,
        prompt=normalized_prompt,
        status_entries=tuple(entries),
    )


def execute_wifi_station_rci(
    transport: RciSealedWriteTransport,
    operation: WifiStationRciOperation,
    station_id: str,
    *,
    ssid: str | None = None,
    psk: str | None = None,
    bssid: str | None = None,
    security_level: str | None = None,
    priority: int | None = None,
    global_order: int | None = None,
    global_auto: bool = False,
    standby_timeout: int | None = None,
) -> WifiStationRciResult:
    request = sealed_request_for(
        operation,
        station_id,
        ssid=ssid,
        psk=psk,
        bssid=bssid,
        security_level=security_level,
        priority=priority,
        global_order=global_order,
        global_auto=global_auto,
        standby_timeout=standby_timeout,
    )
    try:
        response = transport.execute_sealed_rci_write(request)
    except WifiStationRciError:
        raise
    except _TRANSPORT_EXCEPTIONS as exc:
        details = classify_wifi_station_rci_failure(
            operation=operation,
            station_id=station_id,
            ssid=ssid,
            exc=exc,
            fallback_message="transport error during RCI write",
        )
        raise WifiStationRciError("transport error during RCI write", details=details) from exc
    except Exception as exc:
        details = classify_wifi_station_rci_failure(
            operation=operation,
            station_id=station_id,
            ssid=ssid,
            exc=exc,
            fallback_message="unexpected error during RCI write",
        )
        raise WifiStationRciError("unexpected error during RCI write", details=details) from exc
    return verify_wifi_station_response(operation, station_id, response, ssid=ssid)


__all__ = [
    "WifiStationRciError",
    "WifiStationRciErrorCategory",
    "WifiStationRciFailureDetails",
    "WifiStationRciOperation",
    "WifiStationRciResult",
    "classify_wifi_station_rci_failure",
    "command_for",
    "command_redacted_for",
    "execute_wifi_station_rci",
    "sealed_request_for",
    "validate_wifi_station_id",
    "verify_wifi_station_response",
]
