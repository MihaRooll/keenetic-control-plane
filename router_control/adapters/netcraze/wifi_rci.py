"""Typed, sealed RCI Wi-Fi access-point up/down/ssid/WPA operations."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from router_control.adapters.netcraze.allowlist import (
    build_sealed_parse_body,
    validate_ssid,
    validate_wifi_ap_id,
    validate_wpa_psk,
)
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

_ALLOWED_PROMPTS = frozenset({RCI_PROMPT_CONFIG})
_SUCCESS_STATUS_KINDS = frozenset({"message", "warning"})
_ERROR_STATUS_KIND = "error"

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


class WifiApRciErrorCategory(StrEnum):
    UNSUPPORTED_GRAMMAR = "unsupported_grammar"
    REJECTED_BY_ROUTER = "rejected_by_router"
    AUTH_OR_PERMISSION = "auth_or_permission"
    RESOURCE_NOT_FOUND = "resource_not_found"
    TRANSPORT_OR_TIMEOUT = "transport_or_timeout"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class WifiApRciFailureDetails:
    category: WifiApRciErrorCategory
    sanitized_message: str
    operation: str
    command_redacted: str


class WifiApRciError(Exception):
    """RCI Wi-Fi AP operation failed or returned an unverifiable ack."""

    def __init__(
        self,
        message: str,
        *,
        details: WifiApRciFailureDetails | None = None,
    ) -> None:
        super().__init__(message)
        self.details = details


class WifiApRciOperation(StrEnum):
    SET_SSID = "wifi_ap_set_ssid"
    CLEAR_SSID = "wifi_ap_clear_ssid"
    UP = "wifi_ap_up"
    DOWN = "wifi_ap_down"
    SET_WPA_PSK = "wifi_ap_set_wpa_psk"
    CLEAR_WPA_PSK = "wifi_ap_clear_wpa_psk"
    ENCRYPTION_ENABLE = "wifi_ap_encryption_enable"
    ENCRYPTION_WPA2 = "wifi_ap_encryption_wpa2"
    ENCRYPTION_WPA2_CLEAR = "wifi_ap_encryption_wpa2_clear"
    ENCRYPTION_WPA3 = "wifi_ap_encryption_wpa3"
    ENCRYPTION_WPA3_CLEAR = "wifi_ap_encryption_wpa3_clear"
    ENCRYPTION_DISABLE = "wifi_ap_encryption_disable"


@dataclass(frozen=True, slots=True)
class WifiApRciResult:
    operation: WifiApRciOperation
    ap_id: str
    ssid: str | None
    ack_matched: bool
    prompt: str
    status_entries: tuple[FailSafeStatusEntry, ...]

    def sanitized_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "operation": self.operation.value,
            "ap_id": self.ap_id,
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


def command_for(
    operation: WifiApRciOperation,
    ap_id: str,
    ssid: str | None = None,
    psk: str | None = None,
) -> str:
    ap = validate_wifi_ap_id(ap_id)
    if operation is WifiApRciOperation.SET_SSID:
        if ssid is None:
            raise WifiApRciError("ssid is required for SET_SSID")
        normalized_ssid = validate_ssid(ssid)
        return f"interface {ap} ssid {normalized_ssid}"
    if operation is WifiApRciOperation.CLEAR_SSID:
        return f"interface {ap} no ssid"
    if operation is WifiApRciOperation.UP:
        return f"interface {ap} up"
    if operation is WifiApRciOperation.DOWN:
        return f"interface {ap} down"
    if operation is WifiApRciOperation.SET_WPA_PSK:
        if psk is None:
            raise WifiApRciError("psk is required for SET_WPA_PSK")
        normalized_psk = validate_wpa_psk(psk)
        return f"interface {ap} authentication wpa-psk {normalized_psk}"
    if operation is WifiApRciOperation.CLEAR_WPA_PSK:
        return f"interface {ap} no authentication wpa-psk"
    if operation is WifiApRciOperation.ENCRYPTION_ENABLE:
        return f"interface {ap} encryption enable"
    if operation is WifiApRciOperation.ENCRYPTION_DISABLE:
        return f"interface {ap} no encryption enable"
    if operation is WifiApRciOperation.ENCRYPTION_WPA2:
        return f"interface {ap} encryption wpa2"
    if operation is WifiApRciOperation.ENCRYPTION_WPA2_CLEAR:
        return f"interface {ap} no encryption wpa2"
    if operation is WifiApRciOperation.ENCRYPTION_WPA3:
        return f"interface {ap} encryption wpa3"
    if operation is WifiApRciOperation.ENCRYPTION_WPA3_CLEAR:
        return f"interface {ap} no encryption wpa3"
    raise WifiApRciError(f"operation not allowlisted: {operation}")


def command_redacted_for(
    operation: WifiApRciOperation,
    ap_id: str,
    ssid: str | None = None,
) -> str:
    """Build a sealed command string safe for error surfaces (PSK never included)."""
    if operation is WifiApRciOperation.SET_WPA_PSK:
        ap = validate_wifi_ap_id(ap_id)
        return f"interface {ap} authentication wpa-psk <redacted>"
    return command_for(operation, ap_id, ssid=ssid)


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
    """Fail-closed scrub of router status text before operator/API surfaces."""
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


def classify_wifi_ap_rci_failure(
    *,
    operation: WifiApRciOperation,
    ap_id: str,
    ssid: str | None = None,
    status_entries: tuple[FailSafeStatusEntry, ...] | None = None,
    prompt: str | None = None,
    exc: BaseException | None = None,
    fallback_message: str = "RCI Wi-Fi operation failed",
) -> WifiApRciFailureDetails:
    """Evidence-only classifier; unmatched signals fail-closed to ``unknown``."""
    command_redacted = command_redacted_for(operation, ap_id, ssid=ssid)
    op_name = operation.value

    if exc is not None and isinstance(exc, _TRANSPORT_EXCEPTIONS):
        return WifiApRciFailureDetails(
            category=WifiApRciErrorCategory.TRANSPORT_OR_TIMEOUT,
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
                category = WifiApRciErrorCategory.UNSUPPORTED_GRAMMAR
            elif _matches_any(evidence, _NOT_FOUND_TOKENS):
                category = WifiApRciErrorCategory.RESOURCE_NOT_FOUND
            elif _matches_auth_or_permission(evidence):
                category = WifiApRciErrorCategory.AUTH_OR_PERMISSION
            else:
                category = WifiApRciErrorCategory.REJECTED_BY_ROUTER
            raw_message = entry.message.strip() or entry.ident.strip() or fallback_message
            message = _sanitize_router_status_message(raw_message)
            return WifiApRciFailureDetails(
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
        return WifiApRciFailureDetails(
            category=WifiApRciErrorCategory.UNKNOWN,
            sanitized_message=message,
            operation=op_name,
            command_redacted=command_redacted,
        )

    return WifiApRciFailureDetails(
        category=WifiApRciErrorCategory.UNKNOWN,
        sanitized_message=fallback_message,
        operation=op_name,
        command_redacted=command_redacted,
    )


def _raise_classified(
    operation: WifiApRciOperation,
    ap_id: str,
    *,
    ssid: str | None = None,
    status_entries: tuple[FailSafeStatusEntry, ...] | None = None,
    prompt: str | None = None,
    fallback_message: str,
) -> None:
    details = classify_wifi_ap_rci_failure(
        operation=operation,
        ap_id=ap_id,
        ssid=ssid,
        status_entries=status_entries,
        prompt=prompt,
        fallback_message=fallback_message,
    )
    raise WifiApRciError(fallback_message, details=details)


def sealed_request_for(
    operation: WifiApRciOperation,
    ap_id: str,
    ssid: str | None = None,
    psk: str | None = None,
) -> SealedRciWriteRequest:
    body = build_sealed_parse_body(command_for(operation, ap_id, ssid=ssid, psk=psk))
    return SealedRciWriteRequest(body=body)


def verify_wifi_ap_response(
    operation: WifiApRciOperation,
    ap_id: str,
    response: Any,
    ssid: str | None = None,
) -> WifiApRciResult:
    ap = validate_wifi_ap_id(ap_id)
    normalized_ssid: str | None = None
    if operation is WifiApRciOperation.SET_SSID:
        if ssid is None:
            raise WifiApRciError("ssid is required for SET_SSID verification")
        normalized_ssid = validate_ssid(ssid)
    entries, prompt = collect_rci_status_and_prompt(response)
    status_tuple = tuple(entries)
    normalized_prompt = normalize_rci_prompt(prompt, collapse_config_if=True) if prompt else ""
    if not entries:
        _raise_classified(
            operation,
            ap,
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
            ap,
            ssid=normalized_ssid,
            status_entries=status_tuple,
            prompt=normalized_prompt or prompt,
            fallback_message="RCI parse prompt missing or not allowlisted",
        )
    if any(entry.status == _ERROR_STATUS_KIND for entry in entries):
        _raise_classified(
            operation,
            ap,
            ssid=normalized_ssid,
            status_entries=status_tuple,
            prompt=normalized_prompt,
            fallback_message="RCI parse reported an error status",
        )
    if not all(entry.status in _SUCCESS_STATUS_KINDS for entry in entries):
        _raise_classified(
            operation,
            ap,
            ssid=normalized_ssid,
            status_entries=status_tuple,
            prompt=normalized_prompt,
            fallback_message="RCI parse returned an unexpected status kind",
        )
    return WifiApRciResult(
        operation=operation,
        ap_id=ap,
        ssid=normalized_ssid,
        ack_matched=True,
        prompt=normalized_prompt,
        status_entries=tuple(entries),
    )


def execute_wifi_ap_rci(
    transport: RciSealedWriteTransport,
    operation: WifiApRciOperation,
    ap_id: str,
    ssid: str | None = None,
    psk: str | None = None,
) -> WifiApRciResult:
    request = sealed_request_for(operation, ap_id, ssid=ssid, psk=psk)
    try:
        response = transport.execute_sealed_rci_write(request)
    except WifiApRciError:
        raise
    except _TRANSPORT_EXCEPTIONS as exc:
        details = classify_wifi_ap_rci_failure(
            operation=operation,
            ap_id=ap_id,
            ssid=ssid,
            exc=exc,
            fallback_message="transport error during RCI write",
        )
        raise WifiApRciError("transport error during RCI write", details=details) from exc
    except Exception as exc:
        details = classify_wifi_ap_rci_failure(
            operation=operation,
            ap_id=ap_id,
            ssid=ssid,
            exc=exc,
            fallback_message="unexpected error during RCI write",
        )
        raise WifiApRciError("unexpected error during RCI write", details=details) from exc
    return verify_wifi_ap_response(operation, ap_id, response, ssid=ssid)


def wifi_ap_up(transport: RciSealedWriteTransport, ap_id: str) -> WifiApRciResult:
    return execute_wifi_ap_rci(transport, WifiApRciOperation.UP, ap_id)


def wifi_ap_down(transport: RciSealedWriteTransport, ap_id: str) -> WifiApRciResult:
    return execute_wifi_ap_rci(transport, WifiApRciOperation.DOWN, ap_id)


def wifi_ap_set_ssid(
    transport: RciSealedWriteTransport,
    ap_id: str,
    ssid: str,
) -> WifiApRciResult:
    return execute_wifi_ap_rci(transport, WifiApRciOperation.SET_SSID, ap_id, ssid=ssid)


def wifi_ap_clear_ssid(transport: RciSealedWriteTransport, ap_id: str) -> WifiApRciResult:
    return execute_wifi_ap_rci(transport, WifiApRciOperation.CLEAR_SSID, ap_id)


def wifi_ap_set_wpa_psk(
    transport: RciSealedWriteTransport,
    ap_id: str,
    psk: str,
) -> WifiApRciResult:
    return execute_wifi_ap_rci(transport, WifiApRciOperation.SET_WPA_PSK, ap_id, psk=psk)


def wifi_ap_clear_wpa_psk(transport: RciSealedWriteTransport, ap_id: str) -> WifiApRciResult:
    return execute_wifi_ap_rci(transport, WifiApRciOperation.CLEAR_WPA_PSK, ap_id)


def wifi_ap_encryption_enable(
    transport: RciSealedWriteTransport,
    ap_id: str,
) -> WifiApRciResult:
    return execute_wifi_ap_rci(transport, WifiApRciOperation.ENCRYPTION_ENABLE, ap_id)


def wifi_ap_encryption_disable(
    transport: RciSealedWriteTransport,
    ap_id: str,
) -> WifiApRciResult:
    return execute_wifi_ap_rci(transport, WifiApRciOperation.ENCRYPTION_DISABLE, ap_id)


def wifi_ap_encryption_wpa2(transport: RciSealedWriteTransport, ap_id: str) -> WifiApRciResult:
    return execute_wifi_ap_rci(transport, WifiApRciOperation.ENCRYPTION_WPA2, ap_id)


def wifi_ap_encryption_wpa2_clear(
    transport: RciSealedWriteTransport,
    ap_id: str,
) -> WifiApRciResult:
    return execute_wifi_ap_rci(transport, WifiApRciOperation.ENCRYPTION_WPA2_CLEAR, ap_id)


def wifi_ap_encryption_wpa3(transport: RciSealedWriteTransport, ap_id: str) -> WifiApRciResult:
    return execute_wifi_ap_rci(transport, WifiApRciOperation.ENCRYPTION_WPA3, ap_id)


def wifi_ap_encryption_wpa3_clear(
    transport: RciSealedWriteTransport,
    ap_id: str,
) -> WifiApRciResult:
    return execute_wifi_ap_rci(transport, WifiApRciOperation.ENCRYPTION_WPA3_CLEAR, ap_id)


__all__ = [
    "WifiApRciError",
    "WifiApRciErrorCategory",
    "WifiApRciFailureDetails",
    "WifiApRciOperation",
    "WifiApRciResult",
    "classify_wifi_ap_rci_failure",
    "command_for",
    "command_redacted_for",
    "execute_wifi_ap_rci",
    "sealed_request_for",
    "verify_wifi_ap_response",
    "wifi_ap_clear_ssid",
    "wifi_ap_clear_wpa_psk",
    "wifi_ap_down",
    "wifi_ap_encryption_disable",
    "wifi_ap_encryption_enable",
    "wifi_ap_encryption_wpa2",
    "wifi_ap_encryption_wpa2_clear",
    "wifi_ap_encryption_wpa3",
    "wifi_ap_encryption_wpa3_clear",
    "wifi_ap_set_ssid",
    "wifi_ap_set_wpa_psk",
    "wifi_ap_up",
]
