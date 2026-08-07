"""Event preset domain — immutable revisions and validation status (M2)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from router_control.domain.network_intents import (
    BlockingFor,
    CaptivePortalMode,
    DhcpIntent,
    DnsIntent,
    EventPresetDocument,
    FindingSeverity,
    FirewallAction,
    FirewallDestinationFamily,
    FirewallIntent,
    FirewallRule,
    Ipv6Posture,
    NetworkZoneIntent,
    RackAssetIntent,
    RackAssetRole,
    ReadinessFinding,
    UplinkIntent,
    UplinkMode,
    WifiBand,
    WifiIntent,
    WifiWpaMode,
    ZoneId,
    canonical_digest,
    parse_event_preset_document,
    validate_zone_invariants,
    validation_blocking,
)

__all__ = [
    "EventPresetDocument",
    "EventPresetRevision",
    "ValidationStatus",
    "build_safe_default_document",
    "derive_readiness_status",
    "document_from_dict",
    "document_to_revision_fields",
    "etag_for_preset",
    "etag_for_preset_revision",
    "validate_document",
]


def _ensure_utc(value: datetime, name: str) -> datetime:
    if value.tzinfo is None:
        raise ValueError(f"{name} must be timezone-aware UTC")
    offset = value.utcoffset()
    if offset is None or offset != timedelta(0):
        raise ValueError(f"{name} must use UTC timezone")
    return value.astimezone(UTC)


class ValidationStatus(StrEnum):
    DRAFT = "Draft"
    VALID_OFFLINE = "ValidOffline"
    INVALID = "Invalid"
    READY_FOR_READ_ONLY_ASSESSMENT = "ReadyForReadOnlyAssessment"


def _guest_firewall() -> FirewallIntent:
    return FirewallIntent(
        rules=(
            FirewallRule(
                action=FirewallAction.ALLOW,
                destination_family=FirewallDestinationFamily.ORDER_PAGE,
                ordinal=0,
            ),
            FirewallRule(
                action=FirewallAction.ALLOW,
                destination_family=FirewallDestinationFamily.DNS,
                ordinal=1,
            ),
            FirewallRule(
                action=FirewallAction.ALLOW,
                destination_family=FirewallDestinationFamily.DHCP,
                ordinal=2,
            ),
            FirewallRule(
                action=FirewallAction.DENY,
                destination_family=FirewallDestinationFamily.MANAGEMENT,
                ordinal=3,
            ),
            FirewallRule(
                action=FirewallAction.DENY,
                destination_family=FirewallDestinationFamily.INTERNET,
                ordinal=4,
            ),
        )
    )


def _staff_promo_firewall() -> FirewallIntent:
    return FirewallIntent(
        rules=(
            FirewallRule(
                action=FirewallAction.DENY,
                destination_family=FirewallDestinationFamily.MANAGEMENT,
                ordinal=0,
            ),
            FirewallRule(
                action=FirewallAction.ALLOW,
                destination_family=FirewallDestinationFamily.LOCAL_ZONE,
                ordinal=1,
            ),
            FirewallRule(
                action=FirewallAction.ALLOW,
                destination_family=FirewallDestinationFamily.INTERNET,
                ordinal=2,
            ),
        )
    )


def _admin_firewall() -> FirewallIntent:
    return FirewallIntent(
        rules=(
            FirewallRule(
                action=FirewallAction.ALLOW,
                destination_family=FirewallDestinationFamily.MANAGEMENT,
                ordinal=0,
            ),
            FirewallRule(
                action=FirewallAction.ALLOW,
                destination_family=FirewallDestinationFamily.LOCAL_ZONE,
                ordinal=1,
            ),
            FirewallRule(
                action=FirewallAction.ALLOW,
                destination_family=FirewallDestinationFamily.INTERNET,
                ordinal=2,
            ),
        )
    )


def _zone_dhcp(cidr: str, start: str, end: str) -> DhcpIntent:
    return DhcpIntent(
        pool_start=start,
        pool_end=end,
        lease_seconds=3600,
        reservations=(),
    )


def _zone_dns(fqdn: str) -> DnsIntent:
    return DnsIntent(local_fqdn=fqdn, upstream_resolvers=())


def build_safe_default_document(*, name: str = "Safe Default Booth") -> EventPresetDocument:
    """AC-8 safe default: four zones, Guest Wi-Fi off, private Staff/Promo, Admin wired."""
    return EventPresetDocument(
        name=name,
        uplink=UplinkIntent(mode=UplinkMode.ETHERNET),
        local_order_url="https://orders.booth.local/",
        router_owns_l3=True,
        rack_assets=(
            RackAssetIntent(
                role=RackAssetRole.ROUTER,
                display_name="Event Router",
                recommendation="sole L3/DHCP/DNS/firewall/AP owner",
            ),
            RackAssetIntent(
                role=RackAssetRole.HUB,
                display_name="Production Hub",
                recommendation="application/control only; not L3 owner",
            ),
            RackAssetIntent(
                role=RackAssetRole.SWITCH,
                display_name="Managed L2 Switch",
                recommendation="managed L2 with UPS recommended",
            ),
            RackAssetIntent(
                role=RackAssetRole.PRINTER,
                display_name="Label Printer",
                recommendation=None,
            ),
        ),
        zones=(
            NetworkZoneIntent(
                zone_id=ZoneId.GUEST,
                vlan_id=10,
                ipv4_cidr="10.10.10.0/24",
                ipv6_posture=Ipv6Posture.DISABLED,
                management_allowed=False,
                dhcp=_zone_dhcp("10.10.10.0/24", "10.10.10.50", "10.10.10.200"),
                dns=_zone_dns("guest.booth.local"),
                wifi=WifiIntent(
                    ssid="Guest",
                    enabled=False,
                    credential_ref_id=None,
                    captive_portal=CaptivePortalMode.DISABLED,
                    guest_isolation=True,
                    wpa_mode=WifiWpaMode.WPA2,
                    band=WifiBand.BAND_2_4GHZ,
                ),
                firewall=_guest_firewall(),
            ),
            NetworkZoneIntent(
                zone_id=ZoneId.PROMO,
                vlan_id=20,
                ipv4_cidr="10.10.20.0/24",
                ipv6_posture=Ipv6Posture.DISABLED,
                management_allowed=False,
                dhcp=_zone_dhcp("10.10.20.0/24", "10.10.20.50", "10.10.20.200"),
                dns=_zone_dns("promo.booth.local"),
                wifi=WifiIntent(
                    ssid="Promo-Private",
                    enabled=True,
                    credential_ref_id="credref:promo-wifi",
                    captive_portal=CaptivePortalMode.DISABLED,
                    guest_isolation=False,
                    wpa_mode=WifiWpaMode.WPA2,
                    band=WifiBand.BAND_2_4GHZ,
                ),
                firewall=_staff_promo_firewall(),
            ),
            NetworkZoneIntent(
                zone_id=ZoneId.STAFF,
                vlan_id=30,
                ipv4_cidr="10.10.30.0/24",
                ipv6_posture=Ipv6Posture.DISABLED,
                management_allowed=False,
                dhcp=_zone_dhcp("10.10.30.0/24", "10.10.30.50", "10.10.30.200"),
                dns=_zone_dns("staff.booth.local"),
                wifi=WifiIntent(
                    ssid="Staff-Private",
                    enabled=True,
                    credential_ref_id="credref:staff-wifi",
                    captive_portal=CaptivePortalMode.DISABLED,
                    guest_isolation=False,
                    wpa_mode=WifiWpaMode.WPA2,
                    band=WifiBand.BAND_2_4GHZ,
                ),
                firewall=_staff_promo_firewall(),
            ),
            NetworkZoneIntent(
                zone_id=ZoneId.ADMIN_SERVER,
                vlan_id=40,
                ipv4_cidr="10.10.40.0/24",
                ipv6_posture=Ipv6Posture.DISABLED,
                management_allowed=True,
                dhcp=_zone_dhcp("10.10.40.0/24", "10.10.40.50", "10.10.40.200"),
                dns=_zone_dns("admin.booth.local"),
                wifi=None,
                firewall=_admin_firewall(),
            ),
        ),
    )


def validate_document(
    document: EventPresetDocument,
) -> tuple[ValidationStatus, list[ReadinessFinding]]:
    findings = validate_zone_invariants(document)
    if validation_blocking(findings):
        return ValidationStatus.INVALID, findings
    return ValidationStatus.VALID_OFFLINE, findings


def derive_readiness_status(
    validation_status: ValidationStatus,
    extra_findings: list[ReadinessFinding],
) -> ValidationStatus:
    combined = list(extra_findings)
    if validation_status == ValidationStatus.INVALID:
        return ValidationStatus.INVALID
    if validation_blocking(combined):
        return ValidationStatus.INVALID
    ro_blockers = [
        f
        for f in combined
        if f.blocking_for in (BlockingFor.VALIDATION, BlockingFor.APPLY_FRAGMENT)
        and f.severity in (FindingSeverity.ERROR, FindingSeverity.WARNING)
    ]
    if validation_status == ValidationStatus.VALID_OFFLINE and not any(
        f.severity == FindingSeverity.ERROR for f in ro_blockers
    ):
        return ValidationStatus.READY_FOR_READ_ONLY_ASSESSMENT
    return validation_status


@dataclass(frozen=True, slots=True)
class EventPresetRevision:
    revision_id: str
    preset_id: str
    revision_number: int
    canonical_document: dict[str, Any]
    canonical_digest: str
    validation_status: ValidationStatus
    summary_redacted: str | None
    created_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "created_at", _ensure_utc(self.created_at, "created_at"))
        if self.revision_number < 1:
            raise ValueError("revision_number must be >= 1")


@dataclass(frozen=True, slots=True)
class EventPreset:
    preset_id: str
    site_id: str
    name: str
    version: int
    current_revision_id: str | None
    published_revision_id: str | None
    created_at: datetime
    updated_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "created_at", _ensure_utc(self.created_at, "created_at"))
        object.__setattr__(self, "updated_at", _ensure_utc(self.updated_at, "updated_at"))
        if self.version < 1:
            raise ValueError("version must be >= 1")


def etag_for_preset(preset_id: str, version: int, current_digest: str | None) -> str:
    digest = current_digest or "none"
    return f'"{preset_id}:{version}:{digest}"'


def etag_for_preset_revision(revision_id: str, canonical_digest: str) -> str:
    return f'"{revision_id}:{canonical_digest}"'


def document_from_dict(data: dict[str, Any]) -> EventPresetDocument:
    return parse_event_preset_document(data)


def document_to_revision_fields(document: EventPresetDocument) -> tuple[dict[str, Any], str]:
    canonical = document.to_canonical()
    return canonical, canonical_digest(canonical)
