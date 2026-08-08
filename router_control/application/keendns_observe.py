"""KeenDNS/CrazeDNS read-only status classification and live observe."""

from __future__ import annotations

from typing import Any, Literal, Protocol

from router_control.adapters.netcraze.ndns_probe import (
    GET_BOOKED_COMMAND,
    NDNS_DOCS_SOURCED_ALTERNATE_LABELS,
    NDNS_SEALED_COMPONENT_ID,
    SHOW_ACME_COMMAND,
    SHOW_NDNS_COMMAND,
    AcmeShowParseStatus,
    ComponentsParseStatus,
    NdnsBookedParseStatus,
    NdnsShowParseStatus,
    ndns_component_present,
    parse_components_inventory,
    parse_get_booked,
    parse_show_acme,
    parse_show_ndns,
)

FeatureAvailability = Literal["unavailable", "disabled", "unknown"]
NameReservation = Literal["reserved", "not_reserved", "unknown"]
AccessMode = Literal["auto", "cloud", "direct", "unknown"]

_DISCOVERY_DOC = "docs/OPERATOR_KEENDNS_DISCOVERY.md"


class KeenDnsObserveTransport(Protocol):
    def execute_rci_parse(self, cli_command: str) -> Any: ...


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
                "(feature availability beyond component install not device-confirmed)"
            )
    elif components_raw:
        notes.append("components inventory unparsed or unfamiliar → feature_availability unknown")

    # D-5: no sealed disabled sample in repo — never emit disabled from empty/unparsed.
    name_reservation: NameReservation = "unknown"
    show_status = show.get("parse_status")
    if show_status == NdnsShowParseStatus.OK.value:
        name_reservation = "reserved"
        notes.append(
            f"show ndns sealed parse: personal name/domain present ({_DISCOVERY_DOC} §3)"
        )
    elif show_status == NdnsShowParseStatus.NOT_RESERVED.value:
        name_reservation = "not_reserved"
        notes.append(
            f"show ndns sealed parse: empty personal name/domain ({_DISCOVERY_DOC} §3)"
        )
    elif show.get("parse_status") != "unknown":
        notes.append(
            "show ndns output present but no sealed reservation parse shape "
            f"({_DISCOVERY_DOC} §3)"
        )

    booked_status = booked.get("parse_status")
    if booked_status == NdnsBookedParseStatus.OK.value:
        if name_reservation == "unknown":
            name_reservation = "reserved"
        notes.append(f"get-booked sealed parse returned booked FQDN ({_DISCOVERY_DOC} §3)")
    elif booked_status == NdnsBookedParseStatus.NOT_RESERVED.value:
        if name_reservation == "unknown":
            name_reservation = "not_reserved"
        notes.append(
            f"get-booked indicates no cloud booking — not treated as FQDN ({_DISCOVERY_DOC} §3)"
        )
    elif get_booked_raw and booked_status not in ("unknown",):
        notes.append(
            "get-booked output present but no sealed reservation parse shape "
            f"({_DISCOVERY_DOC} §3)"
        )

    access_mode: AccessMode = "unknown"
    sealed_access = show.get("access_mode")
    if isinstance(sealed_access, str) and sealed_access in {"auto", "cloud", "direct"}:
        access_mode = sealed_access  # type: ignore[assignment]
        notes.append(f"show ndns access mode from sealed sample ({_DISCOVERY_DOC} §3)")
    elif show_status not in (NdnsShowParseStatus.UNKNOWN.value,):
        notes.append(
            "show ndns output present but access-mode not sealed "
            f"({_DISCOVERY_DOC} §3)"
        )

    return {
        "feature_availability": feature,
        "name_reservation": name_reservation,
        "access_mode": access_mode,
        "notes": notes,
    }


def _compose_booked_fqdn(name: str | None, domain: str | None) -> str | None:
    if name and domain:
        return f"{name}.{domain}"
    return None


def run_keendns_observe(*, transport: KeenDnsObserveTransport) -> dict[str, Any]:
    """Read-only live observe: show acme + show ndns (+ optional get-booked honesty)."""
    notes: list[str] = [
        "live read-only observe via show acme + show ndns",
        f"sealed shapes per {_DISCOVERY_DOC} §3",
    ]

    try:
        acme_raw = transport.execute_rci_parse(SHOW_ACME_COMMAND)
    except Exception as exc:
        notes.append(f"show acme transport error: {exc!s}")
        acme_raw = None

    try:
        ndns_raw = transport.execute_rci_parse(SHOW_NDNS_COMMAND)
    except Exception as exc:
        notes.append(f"show ndns transport error: {exc!s}")
        ndns_raw = None

    booked_raw: Any | None = None
    try:
        booked_raw = transport.execute_rci_parse(GET_BOOKED_COMMAND)
    except Exception as exc:
        notes.append(f"get-booked optional probe skipped or failed: {exc!s}")

    acme = parse_show_acme(acme_raw)
    show = parse_show_ndns(ndns_raw)
    booked = parse_get_booked(booked_raw)

    default_fqdn: str | None = None
    ssl_valid: bool | None = None
    if acme.get("parse_status") == AcmeShowParseStatus.OK.value:
        default_domain = acme.get("default_domain")
        if isinstance(default_domain, str) and default_domain.strip():
            default_fqdn = default_domain.strip().lower()
        cert = acme.get("default_domain_certificate_valid")
        if isinstance(cert, bool):
            ssl_valid = cert
    elif acme.get("parse_status") != AcmeShowParseStatus.UNKNOWN.value:
        notes.append("show acme present but default-domain not sealed-parseable")

    booked_name = show.get("name") if isinstance(show.get("name"), str) else None
    booked_domain = show.get("domain") if isinstance(show.get("domain"), str) else None
    booked_fqdn = _compose_booked_fqdn(booked_name, booked_domain)

    if booked_fqdn is None and booked.get("parse_status") == NdnsBookedParseStatus.OK.value:
        candidate = booked.get("booked_fqdn")
        if isinstance(candidate, str) and candidate.strip():
            booked_fqdn = candidate.strip().lower()

    name_reservation: NameReservation = "unknown"
    show_status = show.get("parse_status")
    if show_status == NdnsShowParseStatus.OK.value or booked_fqdn:
        name_reservation = "reserved"
    elif show_status == NdnsShowParseStatus.NOT_RESERVED.value:
        name_reservation = "not_reserved"
    elif booked.get("parse_status") == NdnsBookedParseStatus.NOT_RESERVED.value:
        name_reservation = "not_reserved"

    access_mode: AccessMode = "unknown"
    sealed_access = show.get("access_mode")
    if isinstance(sealed_access, str) and sealed_access in {"auto", "cloud", "direct"}:
        access_mode = sealed_access  # type: ignore[assignment]

    if default_fqdn is None:
        notes.append("default automatic CrazeDNS FQDN not read — never invented")

    return {
        "default_fqdn": default_fqdn,
        "ssl_valid": ssl_valid,
        "booked_name": booked_name,
        "booked_domain": booked_domain,
        "booked_fqdn": booked_fqdn,
        "access_mode": access_mode,
        "name_reservation": name_reservation,
        "notes": notes,
        "certification_eligible": False,
    }


__all__ = [
    "AccessMode",
    "FeatureAvailability",
    "KeenDnsObserveTransport",
    "NameReservation",
    "classify_keendns_status",
    "run_keendns_observe",
]
