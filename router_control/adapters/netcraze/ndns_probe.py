"""Read-only parsers for KeenDNS/CrazeDNS observe probes (docs-sourced shapes only)."""

from __future__ import annotations

import json
from enum import StrEnum
from typing import Any

from router_control.adapters.netcraze.sanitize import strip_ssh_cli_ansi_artifacts
from router_control.adapters.netcraze.site_survey import unwrap_rci_parse_dict

PARSER_VERSION_COMPONENTS = "ndns-components-v1"
PARSER_VERSION_SHOW = "ndns-show-v2"
PARSER_VERSION_BOOKED = "ndns-booked-v2"
PARSER_VERSION_ACME = "ndns-acme-v1"

# Sealed component id from bootstrap fixture (see tests/fixtures/netcraze/).
NDNS_SEALED_COMPONENT_ID = "ndns"

# Docs-sourced alternate labels — OPERATOR_KEENDNS_DISCOVERY.md §4.
NDNS_DOCS_SOURCED_ALTERNATE_LABELS = frozenset({"keendns", "crazedns"})

# Candidate read command metadata (not added to global allowlist this cycle — D-13).
SHOW_NDNS_COMMAND = "show ndns"
SHOW_ACME_COMMAND = "show acme"
GET_BOOKED_COMMAND = "ndns get-booked"

_NO_BOOKING_MARKERS = frozenset(
    {
        "no booking",
        "no booking found",
        "not booked",
    }
)


class ComponentsParseStatus(StrEnum):
    OK = "ok"
    UNKNOWN = "unknown"
    UNPARSED = "unparsed"


class NdnsShowParseStatus(StrEnum):
    OK = "ok"
    NOT_RESERVED = "not_reserved"
    UNKNOWN = "unknown"
    UNPARSED = "unparsed"


class NdnsBookedParseStatus(StrEnum):
    OK = "ok"
    NOT_RESERVED = "not_reserved"
    UNKNOWN = "unknown"
    UNPARSED = "unparsed"


class AcmeShowParseStatus(StrEnum):
    OK = "ok"
    UNKNOWN = "unknown"
    UNPARSED = "unparsed"


def _normalize_raw(raw: str | bytes) -> str:
    if isinstance(raw, bytes):
        text = raw.decode("utf-8", errors="replace")
    else:
        text = raw
    return strip_ssh_cli_ansi_artifacts(text.strip())


def _kebab_to_snake(key: str) -> str:
    return key.replace("-", "_")


def _normalize_access_mode(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if not text:
        return None
    if text in {"auto", "cloud", "direct"}:
        return text
    return None


def _normalize_domain_label(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    return text or None


def _coerce_bool(value: Any) -> bool | None:
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


def _component_ids_from_map(component_map: dict[str, Any]) -> tuple[str, ...]:
    return tuple(sorted(k for k in component_map if isinstance(k, str) and k))


def _parse_components_payload(data: Any) -> dict[str, Any]:
    if isinstance(data, dict):
        component_map = data.get("component")
        if isinstance(component_map, dict):
            ids = _component_ids_from_map(component_map)
            if not ids:
                return {
                    "parser_version": PARSER_VERSION_COMPONENTS,
                    "parse_status": ComponentsParseStatus.UNKNOWN.value,
                    "component_ids": None,
                    "notes": (
                        "component map present but empty "
                        "(OPERATOR_KEENDNS_DISCOVERY.md §4)",
                    ),
                }
            return {
                "parser_version": PARSER_VERSION_COMPONENTS,
                "parse_status": ComponentsParseStatus.OK.value,
                "component_ids": ids,
            }
        components_list = data.get("components")
        if isinstance(components_list, list):
            ids_list: list[str] = []
            for item in components_list:
                if isinstance(item, dict) and isinstance(item.get("id"), str) and item["id"]:
                    ids_list.append(item["id"])
            if ids_list:
                return {
                    "parser_version": PARSER_VERSION_COMPONENTS,
                    "parse_status": ComponentsParseStatus.OK.value,
                    "component_ids": tuple(sorted(set(ids_list))),
                }
    if isinstance(data, list):
        ids_list = []
        for item in data:
            if isinstance(item, dict) and isinstance(item.get("id"), str) and item["id"]:
                ids_list.append(item["id"])
        if ids_list:
            return {
                "parser_version": PARSER_VERSION_COMPONENTS,
                "parse_status": ComponentsParseStatus.OK.value,
                "component_ids": tuple(sorted(set(ids_list))),
            }
    return {
        "parser_version": PARSER_VERSION_COMPONENTS,
        "parse_status": ComponentsParseStatus.UNPARSED.value,
        "component_ids": None,
        "notes": (
            "unrecognized components inventory shape; sealed bootstrap JSON only "
            "(OPERATOR_KEENDNS_DISCOVERY.md §4)",
        ),
    }


def parse_components_inventory(raw: str | bytes | dict[str, Any] | None) -> dict[str, Any]:
    """Parse components inventory; bootstrap dict or JSON string."""
    if raw is None:
        return {
            "parser_version": PARSER_VERSION_COMPONENTS,
            "parse_status": ComponentsParseStatus.UNKNOWN.value,
            "component_ids": None,
        }
    if isinstance(raw, dict):
        return _parse_components_payload(raw)
    text = _normalize_raw(raw)
    if not text:
        return {
            "parser_version": PARSER_VERSION_COMPONENTS,
            "parse_status": ComponentsParseStatus.UNKNOWN.value,
            "component_ids": None,
        }
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return {
            "parser_version": PARSER_VERSION_COMPONENTS,
            "parse_status": ComponentsParseStatus.UNPARSED.value,
            "component_ids": None,
            "notes": (
                "components_raw is not valid JSON bootstrap shape "
                "(OPERATOR_KEENDNS_DISCOVERY.md §4)",
            ),
        }
    return _parse_components_payload(payload)


def _unwrap_payload(raw: str | bytes | dict[str, Any] | list[Any] | None) -> dict[str, Any] | None:
    if raw is None:
        return None
    if isinstance(raw, (dict, list)):
        unwrapped = unwrap_rci_parse_dict(raw)
        if unwrapped is not None:
            return unwrapped
        return raw if isinstance(raw, dict) else None
    text = _normalize_raw(raw)
    if not text:
        return None
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    unwrapped = unwrap_rci_parse_dict(payload)
    if unwrapped is not None:
        return unwrapped
    return payload if isinstance(payload, dict) else None


def _extract_acme_block(payload: dict[str, Any] | None) -> dict[str, Any] | None:
    if payload is None:
        return None
    acme = payload.get("acme")
    if isinstance(acme, dict):
        return acme
    return None


def parse_show_acme(raw: str | bytes | dict[str, Any] | list[Any] | None) -> dict[str, Any]:
    """Parse ``show acme`` output; sealed default-domain sample only."""
    if raw is None:
        return {
            "parser_version": PARSER_VERSION_ACME,
            "parse_status": AcmeShowParseStatus.UNKNOWN.value,
            "command": SHOW_ACME_COMMAND,
            "default_domain": None,
            "default_domain_certificate_valid": None,
        }

    payload = _unwrap_payload(raw)
    acme = _extract_acme_block(payload)
    if acme is None:
        if isinstance(raw, (str, bytes)) and _normalize_raw(raw):
            return {
                "parser_version": PARSER_VERSION_ACME,
                "parse_status": AcmeShowParseStatus.UNPARSED.value,
                "command": SHOW_ACME_COMMAND,
                "default_domain": None,
                "default_domain_certificate_valid": None,
                "notes": (
                    "non-empty show acme output has no sealed acme block "
                    "(OPERATOR_KEENDNS_DISCOVERY.md §3)",
                ),
            }
        return {
            "parser_version": PARSER_VERSION_ACME,
            "parse_status": AcmeShowParseStatus.UNKNOWN.value,
            "command": SHOW_ACME_COMMAND,
            "default_domain": None,
            "default_domain_certificate_valid": None,
        }

    default_domain = _normalize_domain_label(
        acme.get("default-domain", acme.get("default_domain"))
    )
    cert_valid = _coerce_bool(
        acme.get(
            "default-domain-certificate-valid",
            acme.get("default_domain_certificate_valid"),
        )
    )

    if not default_domain:
        return {
            "parser_version": PARSER_VERSION_ACME,
            "parse_status": AcmeShowParseStatus.UNKNOWN.value,
            "command": SHOW_ACME_COMMAND,
            "default_domain": None,
            "default_domain_certificate_valid": cert_valid,
            "notes": (
                "show acme acme block present but default-domain empty "
                "(OPERATOR_KEENDNS_DISCOVERY.md §3; sealed live sample has FQDN)"
            ),
        }

    return {
        "parser_version": PARSER_VERSION_ACME,
        "parse_status": AcmeShowParseStatus.OK.value,
        "command": SHOW_ACME_COMMAND,
        "default_domain": default_domain,
        "default_domain_certificate_valid": cert_valid,
    }


def parse_show_ndns(raw: str | bytes | dict[str, Any] | list[Any] | None) -> dict[str, Any]:
    """Parse ``show ndns`` output; sealed empty personal name/domain sample."""
    base_unknown = {
        "parser_version": PARSER_VERSION_SHOW,
        "parse_status": NdnsShowParseStatus.UNKNOWN.value,
        "command": SHOW_NDNS_COMMAND,
        "name": None,
        "domain": None,
        "access_mode": None,
    }
    if raw is None:
        return base_unknown

    payload = _unwrap_payload(raw)
    if payload is None:
        if isinstance(raw, (str, bytes)) and _normalize_raw(raw):
            return {
                **base_unknown,
                "parse_status": NdnsShowParseStatus.UNPARSED.value,
                "notes": (
                    "non-empty show ndns output is not sealed JSON/RCI shape "
                    "(OPERATOR_KEENDNS_DISCOVERY.md §3)",
                ),
            }
        return base_unknown

    name = _normalize_domain_label(payload.get("name"))
    domain = _normalize_domain_label(payload.get("domain"))
    access_mode = _normalize_access_mode(payload.get("access"))

    if not name and not domain:
        return {
            "parser_version": PARSER_VERSION_SHOW,
            "parse_status": NdnsShowParseStatus.NOT_RESERVED.value,
            "command": SHOW_NDNS_COMMAND,
            "name": None,
            "domain": None,
            "access_mode": access_mode,
            "notes": (
                "sealed live show ndns sample has empty personal name/domain "
                "(OPERATOR_KEENDNS_DISCOVERY.md §3)"
            ),
        }

    if name and domain:
        return {
            "parser_version": PARSER_VERSION_SHOW,
            "parse_status": NdnsShowParseStatus.OK.value,
            "command": SHOW_NDNS_COMMAND,
            "name": name,
            "domain": domain,
            "access_mode": access_mode,
        }

    return {
        **base_unknown,
        "parse_status": NdnsShowParseStatus.UNPARSED.value,
        "name": name,
        "domain": domain,
        "access_mode": access_mode,
        "notes": (
            "show ndns has partial name/domain — not a sealed reservation shape "
            "(OPERATOR_KEENDNS_DISCOVERY.md §3)"
        ),
    }


def _looks_like_no_booking(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in _NO_BOOKING_MARKERS)


def _looks_like_fqdn(text: str) -> bool:
    stripped = text.strip()
    if not stripped or " " in stripped:
        return False
    if _looks_like_no_booking(stripped):
        return False
    return "." in stripped and not stripped.startswith(".")


def parse_get_booked(raw: str | bytes | dict[str, Any] | list[Any] | None) -> dict[str, Any]:
    """Parse ``ndns get-booked`` output; continued/cloud no-booking is not an FQDN."""
    base_unknown = {
        "parser_version": PARSER_VERSION_BOOKED,
        "parse_status": NdnsBookedParseStatus.UNKNOWN.value,
        "command": GET_BOOKED_COMMAND,
        "booked_fqdn": None,
        "continued": None,
    }
    if raw is None:
        return base_unknown

    if isinstance(raw, dict):
        continued = raw.get("continued")
        if continued is True:
            message = raw.get("message")
            if isinstance(message, str) and _looks_like_no_booking(message):
                return {
                    **base_unknown,
                    "parse_status": NdnsBookedParseStatus.NOT_RESERVED.value,
                    "continued": True,
                    "notes": (
                        "get-booked continued with no-booking message — not an FQDN "
                        "(OPERATOR_KEENDNS_DISCOVERY.md §3)"
                    ),
                }
        booked = raw.get("booked") or raw.get("fqdn") or raw.get("name")
        if isinstance(booked, str) and _looks_like_fqdn(booked):
            return {
                "parser_version": PARSER_VERSION_BOOKED,
                "parse_status": NdnsBookedParseStatus.OK.value,
                "command": GET_BOOKED_COMMAND,
                "booked_fqdn": booked.strip().lower(),
                "continued": continued if isinstance(continued, bool) else None,
            }

    payload = _unwrap_payload(raw)
    if payload is not None:
        message = payload.get("message")
        if isinstance(message, str) and _looks_like_no_booking(message):
            return {
                **base_unknown,
                "parse_status": NdnsBookedParseStatus.NOT_RESERVED.value,
                "continued": payload.get("continued") if isinstance(payload.get("continued"), bool) else None,
                "notes": (
                    "get-booked parse message indicates no booking — not an FQDN "
                    "(OPERATOR_KEENDNS_DISCOVERY.md §3)"
                ),
            }
        for key in ("booked", "fqdn", "domain", "name"):
            candidate = payload.get(key)
            if isinstance(candidate, str) and _looks_like_fqdn(candidate):
                return {
                    "parser_version": PARSER_VERSION_BOOKED,
                    "parse_status": NdnsBookedParseStatus.OK.value,
                    "command": GET_BOOKED_COMMAND,
                    "booked_fqdn": candidate.strip().lower(),
                    "continued": payload.get("continued") if isinstance(payload.get("continued"), bool) else None,
                }

    text = _normalize_raw(raw) if isinstance(raw, (str, bytes)) else ""
    if not text:
        return base_unknown
    if _looks_like_no_booking(text):
        return {
            **base_unknown,
            "parse_status": NdnsBookedParseStatus.NOT_RESERVED.value,
            "notes": (
                "get-booked text indicates no booking — not an FQDN "
                "(OPERATOR_KEENDNS_DISCOVERY.md §3)"
            ),
        }
    if _looks_like_fqdn(text):
        return {
            "parser_version": PARSER_VERSION_BOOKED,
            "parse_status": NdnsBookedParseStatus.OK.value,
            "command": GET_BOOKED_COMMAND,
            "booked_fqdn": text.strip().lower(),
        }
    return {
        **base_unknown,
        "parse_status": NdnsBookedParseStatus.UNPARSED.value,
        "notes": (
            "non-empty get-booked output has no sealed reservation shape "
            "(OPERATOR_KEENDNS_DISCOVERY.md §3)"
        ),
    }


def ndns_component_present(component_ids: tuple[str, ...] | None) -> bool | None:
    """Return True/False when inventory parse succeeded; None when unknown."""
    if component_ids is None:
        return None
    return NDNS_SEALED_COMPONENT_ID in component_ids


__all__ = [
    "GET_BOOKED_COMMAND",
    "NDNS_DOCS_SOURCED_ALTERNATE_LABELS",
    "NDNS_SEALED_COMPONENT_ID",
    "PARSER_VERSION_ACME",
    "PARSER_VERSION_BOOKED",
    "PARSER_VERSION_COMPONENTS",
    "PARSER_VERSION_SHOW",
    "SHOW_ACME_COMMAND",
    "SHOW_NDNS_COMMAND",
    "AcmeShowParseStatus",
    "ComponentsParseStatus",
    "NdnsBookedParseStatus",
    "NdnsShowParseStatus",
    "ndns_component_present",
    "parse_components_inventory",
    "parse_get_booked",
    "parse_show_acme",
    "parse_show_ndns",
]
