"""Read-only router internet status observation via RCI ``show internet status``."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Literal, Protocol

from router_control.adapters.netcraze.site_survey import unwrap_rci_parse_dict
from router_control.application.wifi_observation_helpers import (
    parse_station_associated_ssid,
    walk_for_keys,
)

_INTERNET_STATUS_COMMAND = "show internet status"
_BOOL_FIELD_KEYS = frozenset(
    {
        "internet",
        "reliable",
        "gateway_accessible",
        "gateway",
        "dns_accessible",
        "dns",
        "captive_accessible",
    }
)
_META_FIELD_KEYS = frozenset({"checked", "interface"})

ReadStatusLiteral = Literal["ok", "failed", "unsupported"]


class InternetStatusTransport(Protocol):
    def execute_rci_parse(self, cli_command: str) -> Any: ...


def _parse_yes_no(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"yes", "true", "1"}:
        return True
    if text in {"no", "false", "0"}:
        return False
    return None


def _coerce_bool(value: Any) -> bool | None:
    parsed = _parse_yes_no(value)
    if parsed is not None:
        return parsed
    if isinstance(value, bool):
        return value
    return None


def _pick_bool(found: dict[str, Any], primary: str, *fallbacks: str) -> bool | None:
    for key in (primary, *fallbacks):
        if key not in found:
            continue
        result = _coerce_bool(found[key])
        if result is not None:
            return result
    return None


def _format_checked_at(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _format_gateway_interface(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _is_wifi_station_gateway_interface(value: str | None) -> bool:
    if not value:
        return False
    text = value.strip()
    return "WifiStation" in text or text.startswith("WifiMaster")


@dataclass(frozen=True, slots=True)
class InternetStatusObservation:
    internet: bool | None
    reliable: bool | None
    gateway_accessible: bool | None
    dns_accessible: bool | None
    captive_accessible: bool | None
    gateway_interface: str | None
    gateway_ssid: str | None
    checked_at: str | None
    read_status: ReadStatusLiteral

    def to_dict(self) -> dict[str, object]:
        return {
            "internet": self.internet,
            "reliable": self.reliable,
            "gateway_accessible": self.gateway_accessible,
            "dns_accessible": self.dns_accessible,
            "captive_accessible": self.captive_accessible,
            "gateway_interface": self.gateway_interface,
            "gateway_ssid": self.gateway_ssid,
            "checked_at": self.checked_at,
            "read_status": self.read_status,
        }


def failed_internet_status_observation() -> InternetStatusObservation:
    return InternetStatusObservation(
        internet=None,
        reliable=None,
        gateway_accessible=None,
        dns_accessible=None,
        captive_accessible=None,
        gateway_interface=None,
        gateway_ssid=None,
        checked_at=None,
        read_status="failed",
    )


def parse_internet_status_payload(raw: Any) -> InternetStatusObservation:
    unwrapped = unwrap_rci_parse_dict(raw)
    payload = unwrapped if unwrapped is not None else (raw if isinstance(raw, dict) else None)
    if payload is None:
        return failed_internet_status_observation()
    found = walk_for_keys(payload, _BOOL_FIELD_KEYS | _META_FIELD_KEYS)
    return InternetStatusObservation(
        internet=_pick_bool(found, "internet"),
        reliable=_pick_bool(found, "reliable"),
        gateway_accessible=_pick_bool(found, "gateway_accessible", "gateway"),
        dns_accessible=_pick_bool(found, "dns_accessible", "dns"),
        captive_accessible=_pick_bool(found, "captive_accessible"),
        gateway_interface=_format_gateway_interface(found.get("interface")),
        gateway_ssid=None,
        checked_at=_format_checked_at(found.get("checked")),
        read_status="ok",
    )


def run_internet_status_observe(*, transport: InternetStatusTransport) -> InternetStatusObservation:
    try:
        raw = transport.execute_rci_parse(_INTERNET_STATUS_COMMAND)
    except Exception:
        return failed_internet_status_observation()
    observation = parse_internet_status_payload(raw)
    gateway = observation.gateway_interface
    if not gateway or not _is_wifi_station_gateway_interface(gateway):
        return observation
    gateway_ssid: str | None = None
    try:
        runtime_raw = transport.execute_rci_parse(f"show interface {gateway}")
        associated_ssid, _field_present = parse_station_associated_ssid(runtime_raw)
        gateway_ssid = associated_ssid
    except Exception:
        gateway_ssid = None
    if gateway_ssid is None:
        return observation
    return replace(observation, gateway_ssid=gateway_ssid)
