"""Host-persisted remembered Wi-Fi uplink — credential_ref only, no plaintext secrets."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from router_control.application.wifi_station_apply_planner import station_id_for_band
from router_control.domain.network_intents import WifiBand
from router_control.persistence.store import _UNSET, PersistenceStore
from router_control.ports.clock import ClockPort

_WIFI_APS_PSK_KIND = "WifiApPsk"
_SSID_MAX_LEN = 32
_VALID_BANDS = frozenset({WifiBand.BAND_2_4GHZ.value, WifiBand.BAND_5GHZ.value})


class RememberedUplinkValidationError(ValueError):
    def __init__(self, message: str, *, code: str, field: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.field = field


def _validate_ssid(value: str) -> str:
    stripped = value.strip()
    if not stripped:
        raise RememberedUplinkValidationError(
            "SSID must not be empty when uplink is active",
            code="remembered_uplink.validation_failed",
            field="ssid",
        )
    if stripped != value:
        raise RememberedUplinkValidationError(
            "SSID must not have leading or trailing spaces",
            code="remembered_uplink.validation_failed",
            field="ssid",
        )
    if len(stripped) > _SSID_MAX_LEN:
        raise RememberedUplinkValidationError(
            f"SSID must not exceed {_SSID_MAX_LEN} characters",
            code="remembered_uplink.validation_failed",
            field="ssid",
        )
    return stripped


def _band_from_value(value: str) -> WifiBand:
    try:
        return WifiBand(value)
    except ValueError as exc:
        raise RememberedUplinkValidationError(
            f"unsupported band: {value}",
            code="remembered_uplink.validation_failed",
            field="band",
        ) from exc


@dataclass
class RememberedUplinkService:
    store: PersistenceStore
    clock: ClockPort

    def get_remembered(self) -> dict[str, Any]:
        row = self.store.get_remembered_uplink()
        stored_ref = row.get("credential_ref_id")
        configured, effective_ref = self._resolve_credential_ref(
            str(stored_ref) if stored_ref else None
        )
        if not configured and (bool(row.get("desired_active")) or stored_ref):
            row = self.store.upsert_remembered_uplink(
                credential_ref_id=None,
                desired_active=False,
                now=self.clock.now(),
            )
            effective_ref = None
            configured = False
        band = str(row["band"])
        station_id = row.get("station_id")
        if not station_id and band in _VALID_BANDS:
            station_id = station_id_for_band(_band_from_value(band))
        return {
            "router_id": row.get("router_id"),
            "mode": row["mode"],
            "ssid": row["ssid"],
            "band": band,
            "station_id": station_id,
            "credential_ref_id": effective_ref,
            "credential_configured": configured,
            "desired_active": bool(row["desired_active"]),
            "updated_at": row["updated_at"],
        }

    def update_remembered(
        self,
        *,
        router_id: str | None | object = _UNSET,
        ssid: str | None = None,
        band: str | None = None,
        station_id: str | None | object = _UNSET,
        credential_ref_id: str | None | object = _UNSET,
        desired_active: bool | None = None,
    ) -> dict[str, Any]:
        resolved_ssid: str | None = None
        if ssid is not None:
            resolved_ssid = _validate_ssid(ssid)
        resolved_band: str | None = None
        resolved_station: str | None | object = station_id
        if band is not None:
            if band not in _VALID_BANDS:
                raise RememberedUplinkValidationError(
                    f"unsupported band: {band}",
                    code="remembered_uplink.validation_failed",
                    field="band",
                )
            resolved_band = band
            if station_id is _UNSET:
                resolved_station = station_id_for_band(_band_from_value(band))
        if credential_ref_id is not _UNSET and credential_ref_id is not None:
            ref_id = str(credential_ref_id).strip()
            if not ref_id:
                raise RememberedUplinkValidationError(
                    "credential ref must not be blank",
                    code="remembered_uplink.validation_failed",
                    field="credential_ref_id",
                )
            configured, _ = self._resolve_credential_ref(ref_id)
            if not configured:
                raise RememberedUplinkValidationError(
                    "credential ref is missing, revoked, or not WifiApPsk",
                    code="remembered_uplink.invalid_credential_ref",
                    field="credential_ref_id",
                )
            credential_ref_id = ref_id
        current = self.get_remembered()
        will_be_active = (
            desired_active if desired_active is not None else current["desired_active"]
        )
        next_ssid = resolved_ssid if resolved_ssid is not None else str(current["ssid"])
        if will_be_active and not next_ssid.strip():
            raise RememberedUplinkValidationError(
                "SSID required when desired_active is true",
                code="remembered_uplink.validation_failed",
                field="ssid",
            )
        next_router_id = (
            router_id if router_id is not _UNSET else current["router_id"]
        )
        if will_be_active and not next_router_id:
            raise RememberedUplinkValidationError(
                "router_id required when desired_active is true",
                code="remembered_uplink.validation_failed",
                field="router_id",
            )
        if credential_ref_id is _UNSET:
            will_be_configured = current["credential_configured"]
        elif credential_ref_id is None:
            will_be_configured = False
        else:
            will_be_configured = True
        if will_be_active and not will_be_configured:
            raise RememberedUplinkValidationError(
                "credential required when desired_active is true",
                code="remembered_uplink.validation_failed",
                field="credential_ref_id",
            )
        self.store.upsert_remembered_uplink(
            router_id=router_id,
            ssid=resolved_ssid,
            band=resolved_band,
            station_id=resolved_station,
            credential_ref_id=credential_ref_id,
            desired_active=desired_active,
            now=self.clock.now(),
        )
        return self.get_remembered()

    def forget_remembered(self) -> dict[str, Any]:
        self.store.reset_remembered_uplink(now=self.clock.now())
        return self.get_remembered()

    def _resolve_credential_ref(self, ref_id: str | None) -> tuple[bool, str | None]:
        if not ref_id:
            return False, None
        row = self.store.get_credential_ref(ref_id)
        if row is None:
            return False, None
        kind = str(row["kind"])
        revoked_at = row["revoked_at"]
        if kind != _WIFI_APS_PSK_KIND or revoked_at is not None:
            return False, None
        return True, ref_id
