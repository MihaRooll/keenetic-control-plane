"""Standing network preferences — host-persisted staff/guest Wi‑Fi defaults."""



from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from router_control.persistence.errors import NotFoundError, PreconditionFailed
from router_control.persistence.store import _UNSET, PersistenceStore
from router_control.ports.clock import ClockPort

_WIFI_APS_PSK_KIND = "WifiApPsk"

_STAFF_SSID_MAX_LEN = 32

_GUEST_SSID_MAX_LEN = 32

_WIFI_AP_ID_RE = re.compile(r"^WifiMaster[01]/AccessPoint[0-6]$")





class StandingNetworkPreferencesValidationError(ValueError):

    def __init__(self, message: str, *, code: str, field: str | None = None) -> None:

        super().__init__(message)

        self.code = code

        self.field = field





def _validate_ssid(value: str, *, field: str) -> str:

    stripped = value.strip()

    if not stripped:

        raise StandingNetworkPreferencesValidationError(

            "SSID must not be empty",

            code="standing.validation_failed",

            field=field,

        )

    if stripped != value:

        raise StandingNetworkPreferencesValidationError(

            "SSID must not have leading or trailing spaces",

            code="standing.validation_failed",

            field=field,

        )

    max_len = _STAFF_SSID_MAX_LEN if field == "staff_ssid" else _GUEST_SSID_MAX_LEN

    if len(stripped) > max_len:

        raise StandingNetworkPreferencesValidationError(

            f"SSID must not exceed {max_len} characters",

            code="standing.validation_failed",

            field=field,

        )

    return stripped





def _validate_ap_id(value: str, *, field: str) -> str:

    stripped = value.strip()

    if stripped != value:

        raise StandingNetworkPreferencesValidationError(

            "AP id must not have leading or trailing spaces",

            code="standing.validation_failed",

            field=field,

        )

    if not _WIFI_AP_ID_RE.fullmatch(stripped):

        raise StandingNetworkPreferencesValidationError(

            "AP id must match WifiMaster[01]/AccessPoint[0-6]",

            code="standing.validation_failed",

            field=field,

        )

    return stripped





def _validate_ap_roles_no_overlap(
    *,
    staff_ap_id: str | None,
    guest_ap_id: str | None,
) -> None:
    if staff_ap_id is not None and guest_ap_id is not None and staff_ap_id == guest_ap_id:
        raise StandingNetworkPreferencesValidationError(
            "staff and guest AP roles must not use the same access point",
            code="standing.ap_role_overlap",
            field=None,
        )





@dataclass

class StandingNetworkPreferencesService:

    store: PersistenceStore

    clock: ClockPort



    def get_preferences(self) -> dict[str, Any]:

        try:

            row = self.store.get_standing_network_preferences()

        except NotFoundError:

            self.store.seed_standing_network_preferences_defaults()

            row = self.store.get_standing_network_preferences()

        stored_ref = row.get("staff_password_credential_ref_id")

        configured, effective_ref = self._resolve_staff_password_ref(

            str(stored_ref) if stored_ref else None

        )

        if stored_ref and not configured:

            self.store.clear_standing_staff_password_ref_if_matches(

                str(stored_ref),

                now=self.clock.now(),

            )

            row = self.store.get_standing_network_preferences()

            configured, effective_ref = self._resolve_staff_password_ref(

                str(row["staff_password_credential_ref_id"])

                if row.get("staff_password_credential_ref_id")

                else None

            )

        return {

            "staff_ssid": row["staff_ssid"],

            "guest_default_ssid": row["guest_default_ssid"],

            "staff_password_credential_ref_id": effective_ref,

            "staff_password_configured": configured,

            "guest_default_enabled": False,

            "staff_ap_id": row["staff_ap_id"],

            "guest_ap_id": row["guest_ap_id"],

            "updated_at": row["updated_at"],

        }



    def update_preferences(

        self,

        *,

        staff_ssid: str | None = None,

        staff_password_credential_ref_id: str | None | object = _UNSET,

        guest_default_ssid: str | None = None,

        staff_ap_id: str | None | object = _UNSET,

        guest_ap_id: str | None | object = _UNSET,

    ) -> dict[str, Any]:

        resolved_staff: str | None = None

        if staff_ssid is not None:

            resolved_staff = _validate_ssid(staff_ssid, field="staff_ssid")

        resolved_guest: str | None = None

        if guest_default_ssid is not None:

            resolved_guest = _validate_ssid(guest_default_ssid, field="guest_default_ssid")

        if staff_password_credential_ref_id is not _UNSET:

            if staff_password_credential_ref_id is not None:

                ref_id = str(staff_password_credential_ref_id).strip()

                if not ref_id:

                    raise StandingNetworkPreferencesValidationError(

                        "credential ref must not be blank",

                        code="standing.validation_failed",

                        field="staff_password_credential_ref_id",

                    )

                configured, _ = self._resolve_staff_password_ref(ref_id)

                if not configured:

                    raise StandingNetworkPreferencesValidationError(

                        "credential ref is missing, revoked, or not WifiApPsk",

                        code="standing.invalid_credential_ref",

                        field="staff_password_credential_ref_id",

                    )

                staff_password_credential_ref_id = ref_id

        resolved_staff_ap_id: str | None | object = staff_ap_id

        if staff_ap_id is not _UNSET and staff_ap_id is not None:

            resolved_staff_ap_id = _validate_ap_id(str(staff_ap_id), field="staff_ap_id")

        resolved_guest_ap_id: str | None | object = guest_ap_id

        if guest_ap_id is not _UNSET and guest_ap_id is not None:

            resolved_guest_ap_id = _validate_ap_id(str(guest_ap_id), field="guest_ap_id")

        current = self.get_preferences()
        effective_staff_ap_id = (
            current["staff_ap_id"]
            if staff_ap_id is _UNSET
            else resolved_staff_ap_id
        )
        effective_guest_ap_id = (
            current["guest_ap_id"]
            if guest_ap_id is _UNSET
            else resolved_guest_ap_id
        )
        _validate_ap_roles_no_overlap(
            staff_ap_id=effective_staff_ap_id,
            guest_ap_id=effective_guest_ap_id,
        )

        try:
            self.store.upsert_standing_network_preferences(

                staff_ssid=resolved_staff,

                staff_password_credential_ref_id=staff_password_credential_ref_id,

                guest_default_ssid=resolved_guest,

                staff_ap_id=resolved_staff_ap_id,

                guest_ap_id=resolved_guest_ap_id,

                now=self.clock.now(),

            )
        except PreconditionFailed as exc:
            raise StandingNetworkPreferencesValidationError(
                "staff and guest AP roles must not use the same access point",
                code="standing.ap_role_overlap",
                field=None,
            ) from exc

        return self.get_preferences()



    def _resolve_staff_password_ref(

        self, ref_id: str | None

    ) -> tuple[bool, str | None]:

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

