"""Read-only observed Wi-Fi AP state service (offline-testable; no PSK exposure)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from router_control.adapters.netcraze.allowlist import (
    validate_wifi_ap_id,
    wifi_ap_index_max,
    wifi_ap_index_min,
)
from router_control.adapters.netcraze.sanitize import sanitize_mapping
from router_control.application.wifi_observation_helpers import (
    band_label_from_ap_id,
    compare_band_field,
    compare_enabled_field,
    compare_encryption_field,
    compare_ssid_field,
    derive_key_configured,
    extract_interface_fields,
    map_encryption_to_wpa_mode,
    resolve_device_connected,
    resolve_enabled_or_up,
    resolve_link_up,
    sanitize_observed_fields,
    scrub_encryption_value,
)
from router_control.domain.network_intents import WifiIntent


class WifiObservedTransport(Protocol):
    def execute_rci_parse(self, cli_command: str) -> Any: ...


class WifiObservedStateError(ValueError):
    """Fail-closed Wi-Fi observed-state error."""


@dataclass(frozen=True, slots=True)
class ObservedWifiApState:
    ap_id: str
    band: str
    ssid: str | None
    enabled_or_up: bool | None
    link_up: bool | None
    device_connected: bool | None
    wpa_mode: str
    encryption_raw: object | None
    key_configured: bool | None
    readable: bool

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "ap_id": self.ap_id,
            "band": self.band,
            "ssid": self.ssid,
            "enabled_or_up": self.enabled_or_up,
            "link_up": self.link_up,
            "device_connected": self.device_connected,
            "wpa_mode": self.wpa_mode,
            "encryption_raw": self.encryption_raw,
            "key_configured": self.key_configured,
            "readable": self.readable,
        }
        return sanitize_mapping(payload)


@dataclass(frozen=True, slots=True)
class ObservedWifiStateReport:
    access_points: tuple[ObservedWifiApState, ...]
    comparisons: dict[str, dict[str, str]] | None
    certification_eligible: bool
    transport_security: str
    https_check: str
    offline_verified_only: bool

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "access_points": [ap.to_dict() for ap in self.access_points],
            "certification_eligible": self.certification_eligible,
            "transport_security": self.transport_security,
            "https_check": self.https_check,
            "offline_verified_only": self.offline_verified_only,
        }
        if self.comparisons is not None:
            payload["comparisons"] = self.comparisons
        return sanitize_mapping(payload)


def default_allowlisted_ap_ids() -> list[str]:
    ap_ids: list[str] = []
    for master in ("WifiMaster0", "WifiMaster1"):
        for index in range(wifi_ap_index_min(), wifi_ap_index_max() + 1):
            ap_ids.append(f"{master}/AccessPoint{index}")
    return ap_ids


def _validate_ap_ids(ap_ids: list[str]) -> list[str]:
    if not ap_ids:
        raise WifiObservedStateError("ap_ids must not be empty")
    normalized: list[str] = []
    for ap_id in ap_ids:
        try:
            normalized.append(validate_wifi_ap_id(ap_id))
        except ValueError as exc:
            raise WifiObservedStateError(str(exc)) from exc
    return normalized


def _sanitize_encryption_raw(encryption: Any) -> object | None:
    return scrub_encryption_value(encryption)


def read_observed_ap_state(
    transport: WifiObservedTransport,
    ap_id: str,
) -> ObservedWifiApState:
    validated = validate_wifi_ap_id(ap_id)
    command = f"show interface {validated}"
    try:
        raw = transport.execute_rci_parse(command)
    except Exception:
        return ObservedWifiApState(
            ap_id=validated,
            band=band_label_from_ap_id(validated),
            ssid=None,
            enabled_or_up=None,
            link_up=None,
            device_connected=None,
            wpa_mode="unknown",
            encryption_raw=None,
            key_configured=None,
            readable=False,
        )

    if raw is None:
        return ObservedWifiApState(
            ap_id=validated,
            band=band_label_from_ap_id(validated),
            ssid=None,
            enabled_or_up=None,
            link_up=None,
            device_connected=None,
            wpa_mode="unknown",
            encryption_raw=None,
            key_configured=None,
            readable=False,
        )

    fields = extract_interface_fields(raw)
    if not fields:
        return ObservedWifiApState(
            ap_id=validated,
            band=band_label_from_ap_id(validated),
            ssid=None,
            enabled_or_up=None,
            link_up=None,
            device_connected=None,
            wpa_mode="unknown",
            encryption_raw=None,
            key_configured=None,
            readable=False,
        )

    sanitized = sanitize_observed_fields(fields)
    encryption = fields.get("encryption")
    ssid_value = fields.get("ssid")
    ssid_text = str(ssid_value) if ssid_value is not None else None
    state = fields.get("state")
    up_flag = fields.get("up")
    enabled_or_up = resolve_enabled_or_up(state, up_flag)

    return ObservedWifiApState(
        ap_id=validated,
        band=band_label_from_ap_id(validated),
        ssid=ssid_text,
        enabled_or_up=enabled_or_up,
        link_up=resolve_link_up(fields),
        device_connected=resolve_device_connected(fields),
        wpa_mode=map_encryption_to_wpa_mode(encryption),
        encryption_raw=_sanitize_encryption_raw(encryption),
        key_configured=derive_key_configured(raw, sanitized),
        readable=True,
    )


def compare_observed_to_desired(
    observed: ObservedWifiApState,
    desired: WifiIntent,
) -> dict[str, str]:
    return {
        "ssid": compare_ssid_field(observed.ssid, desired.ssid, readable=observed.readable),
        "wpa_mode": compare_encryption_field(
            desired.wpa_mode,
            readable=observed.readable,
            mapped_mode=observed.wpa_mode,
        ),
        "enabled": compare_enabled_field(
            observed.enabled_or_up,
            desired.enabled,
            readable=observed.readable,
        ),
        "band": compare_band_field(
            observed.band,
            desired.band,
            readable=observed.readable,
        ),
    }


def run_wifi_observed_state(
    *,
    transport: WifiObservedTransport,
    ap_ids: list[str] | None = None,
    desired_by_ap: dict[str, WifiIntent] | None = None,
    transport_security: str = "fixture",
    https_check: str = "not_certified",
) -> ObservedWifiStateReport:
    target_ids = _validate_ap_ids(list(ap_ids or default_allowlisted_ap_ids()))
    access_points = tuple(read_observed_ap_state(transport, ap_id) for ap_id in target_ids)
    comparisons: dict[str, dict[str, str]] | None = None
    if desired_by_ap:
        comparisons = {}
        for ap_state in access_points:
            desired = desired_by_ap.get(ap_state.ap_id)
            if desired is None:
                continue
            comparisons[ap_state.ap_id] = compare_observed_to_desired(ap_state, desired)
    return ObservedWifiStateReport(
        access_points=access_points,
        comparisons=comparisons,
        certification_eligible=False,
        transport_security=transport_security,
        https_check=https_check,
        offline_verified_only=True,
    )
