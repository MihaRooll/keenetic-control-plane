"""Offline event preset plan preview — redacted, no router I/O."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from router_control.domain.event_preset import EventPresetDocument, ValidationStatus
from router_control.domain.network_intents import (
    BlockingFor,
    FindingSeverity,
    ReadinessFinding,
    UplinkMode,
)


@dataclass
class PresetPlannerService:
    gate_b_not_write_certified: bool = True
    gate_c_closed: bool = True
    gate_d_closed: bool = True
    awg_supported: bool = False
    routes_supported: bool = False
    lte_supported: bool = False

    def build_plan_preview(
        self,
        *,
        document: EventPresetDocument,
        validation_status: ValidationStatus,
    ) -> dict[str, Any]:
        families: list[dict[str, Any]] = []
        families.append(self._lan_family(document, validation_status))
        families.append(self._uplink_family(document))
        families.append(self._wifi_family(document))
        families.append(self._certification_family())
        return {
            "write_ready": False,
            "validation_status": validation_status.value,
            "families": families,
        }

    def _lan_family(
        self, document: EventPresetDocument, validation_status: ValidationStatus
    ) -> dict[str, Any]:
        items = [
            {
                "zone_id": z.zone_id.value,
                "vlan_id": z.vlan_id,
                "ipv4_cidr": z.ipv4_cidr,
                "ipv6_posture": z.ipv6_posture.value,
            }
            for z in document.zones
        ]
        support = "supported" if validation_status != ValidationStatus.INVALID else "unsupported"
        return {
            "family": "lan_zones",
            "support": support,
            "items": items,
        }

    def _uplink_family(self, document: EventPresetDocument) -> dict[str, Any]:
        mode = document.uplink.mode
        if mode == UplinkMode.LTE:
            return {
                "family": "uplink",
                "support": "deferred",
                "certification_blocker": "lte_not_implemented",
                "items": [{"mode": mode.value}],
            }
        if mode == UplinkMode.WIFI_WAN:
            uplink = document.uplink
            item: dict[str, Any] = {
                "mode": mode.value,
                "priority": uplink.priority,
            }
            if uplink.ssid:
                item["ssid_redacted"] = "[present]"
            if uplink.band is not None:
                item["band"] = uplink.band.value
            if uplink.credential_ref_id:
                item["credential_ref_id"] = uplink.credential_ref_id
            if uplink.bssid:
                item["bssid"] = uplink.bssid
            if uplink.captive_portal_client:
                item["captive_portal_client"] = True
            return {
                "family": "uplink",
                "support": "unsupported",
                "certification_blocker": "wifi_wan_not_certified",
                "items": [item],
            }
        uplink = document.uplink
        item = {"mode": mode.value}
        if uplink.priority != 100:
            item["priority"] = uplink.priority
        if uplink.captive_portal_client:
            item["captive_portal_client"] = True
            return {
                "family": "uplink",
                "support": "unsupported",
                "certification_blocker": "uplink_captive_portal_client_unsupported",
                "items": [item],
            }
        return {
            "family": "uplink",
            "support": "supported",
            "items": [item],
        }

    def _wifi_family(self, document: EventPresetDocument) -> dict[str, Any]:
        items = []
        for zone in document.zones:
            if zone.wifi is None:
                continue
            items.append(
                {
                    "zone_id": zone.zone_id.value,
                    "ssid": zone.wifi.ssid,
                    "enabled": zone.wifi.enabled,
                    "credential_ref_id": zone.wifi.credential_ref_id,
                    "captive_portal": zone.wifi.captive_portal.value,
                    "wpa_mode": zone.wifi.wpa_mode.value,
                    "band": zone.wifi.band.value,
                }
            )
        return {"family": "wifi", "support": "supported", "items": items}

    def _certification_family(self) -> dict[str, Any]:
        blockers: list[str] = []
        if self.gate_b_not_write_certified:
            blockers.append("gate_b_not_write_certified")
        if self.gate_c_closed:
            blockers.append("gate_c_closed")
        if self.gate_d_closed:
            blockers.append("gate_d_closed")
        if not self.awg_supported:
            blockers.append("awg_not_implemented")
        if not self.routes_supported:
            blockers.append("routes_not_implemented")
        items = [{"blocker": b} for b in blockers]
        support = "unsupported" if blockers else "supported"
        payload: dict[str, Any] = {
            "family": "certification_apply",
            "support": support,
            "items": items,
        }
        if blockers:
            payload["certification_blocker"] = blockers[0]
        return payload

    def plan_blocker_findings(self) -> list[ReadinessFinding]:
        findings: list[ReadinessFinding] = []
        if not self.awg_supported:
            findings.append(
                ReadinessFinding(
                    code="awg_apply_deferred",
                    severity=FindingSeverity.WARNING,
                    blocking_for=BlockingFor.APPLY_FRAGMENT,
                    summary_redacted="AWG apply fragment blocked until Gate B WriteCertified",
                    family="awg",
                )
            )
        if not self.routes_supported:
            findings.append(
                ReadinessFinding(
                    code="routes_apply_deferred",
                    severity=FindingSeverity.WARNING,
                    blocking_for=BlockingFor.APPLY_FRAGMENT,
                    summary_redacted="Route apply fragment blocked until benchmark certified",
                    family="routes",
                )
            )
        if not self.lte_supported:
            findings.append(
                ReadinessFinding(
                    code="lte_apply_deferred",
                    severity=FindingSeverity.WARNING,
                    blocking_for=BlockingFor.APPLY_FRAGMENT,
                    summary_redacted="LTE uplink deferred",
                    family="uplink",
                )
            )
        if self.gate_b_not_write_certified:
            findings.append(
                ReadinessFinding(
                    code="gate_b_write_blocked",
                    severity=FindingSeverity.ERROR,
                    blocking_for=BlockingFor.WRITE,
                    summary_redacted="Gate B not WriteCertified; writes blocked",
                    family="certification",
                )
            )
        return findings
