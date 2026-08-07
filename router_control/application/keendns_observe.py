"""KeenDNS/CrazeDNS read-only status classification (injected raw only; no network I/O)."""

from __future__ import annotations

from typing import Any, Literal

from router_control.adapters.netcraze.ndns_probe import (
    NDNS_DOCS_SOURCED_ALTERNATE_LABELS,
    NDNS_SEALED_COMPONENT_ID,
    ComponentsParseStatus,
    ndns_component_present,
    parse_components_inventory,
    parse_get_booked,
    parse_show_ndns,
)

FeatureAvailability = Literal["unavailable", "disabled", "unknown"]
NameReservation = Literal["reserved", "not_reserved", "unknown"]
AccessMode = Literal["auto", "cloud", "direct", "unknown"]

_DISCOVERY_DOC = "docs/OPERATOR_KEENDNS_DISCOVERY.md"


def classify_keendns_status(
    *,
    components_raw: str | None = None,
    ndns_show_raw: str | None = None,
    get_booked_raw: str | None = None,
) -> dict[str, Any]:
    """Classify KeenDNS feature state from injected probe fields; empty → all unknown."""
    notes: list[str] = [
        "classification from injected raw only; no live probe in this deliverable (D-1)",
        f"show/ndns and get-booked shapes not device-observed in lab ({_DISCOVERY_DOC} §2)",
        (
            f"component presence uses sealed id {NDNS_SEALED_COMPONENT_ID!r} only; "
            f"docs alternate labels {sorted(NDNS_DOCS_SOURCED_ALTERNATE_LABELS)!r} "
            "not used for classify (D-4)"
        ),
    ]

    if not any(field for field in (components_raw, ndns_show_raw, get_booked_raw)):
        return {
            "feature_availability": "unknown",
            "name_reservation": "unknown",
            "access_mode": "unknown",
            "notes": notes + ["empty body → all unknown (D-3/D-4/D-5)"],
        }

    components = parse_components_inventory(components_raw)
    show = parse_show_ndns(ndns_show_raw)
    booked = parse_get_booked(get_booked_raw)

    feature: FeatureAvailability = "unknown"
    components_status = components.get("parse_status")
    component_ids = components.get("component_ids")
    if components_status == ComponentsParseStatus.OK.value:
        present = ndns_component_present(component_ids)
        if present is False:
            feature = "unavailable"
            notes.append(
                f"components parse OK and sealed id {NDNS_SEALED_COMPONENT_ID!r} absent "
                f"({_DISCOVERY_DOC} §4; fixture component id)"
            )
        elif present is True:
            notes.append(
                f"components parse OK and sealed id {NDNS_SEALED_COMPONENT_ID!r} present "
                f"(feature availability beyond component install not device-confirmed)"
            )
    elif components_raw:
        notes.append("components inventory unparsed or unfamiliar → feature_availability unknown")

    # D-5: no sealed disabled sample in repo — never emit disabled from empty/unparsed.
    name_reservation: NameReservation = "unknown"
    if booked.get("parse_status") != "unknown":
        notes.append(
            "get-booked output present but no sealed reservation parse shape "
            f"({_DISCOVERY_DOC} §3)"
        )

    access_mode: AccessMode = "unknown"
    if show.get("parse_status") != "unknown":
        notes.append(
            "show ndns output present but no sealed access-mode parse shape "
            f"({_DISCOVERY_DOC} §3)"
        )

    return {
        "feature_availability": feature,
        "name_reservation": name_reservation,
        "access_mode": access_mode,
        "notes": notes,
    }


__all__ = [
    "AccessMode",
    "FeatureAvailability",
    "NameReservation",
    "classify_keendns_status",
]
