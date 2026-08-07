"""Read-only parsers for KeenDNS/CrazeDNS observe probes (docs-sourced shapes only)."""

from __future__ import annotations

import json
from enum import StrEnum
from typing import Any

from router_control.adapters.netcraze.sanitize import strip_ssh_cli_ansi_artifacts

PARSER_VERSION_COMPONENTS = "ndns-components-v1"
PARSER_VERSION_SHOW = "ndns-show-v1"
PARSER_VERSION_BOOKED = "ndns-booked-v1"

# Sealed component id from bootstrap fixture (see tests/fixtures/netcraze/).
NDNS_SEALED_COMPONENT_ID = "ndns"

# Docs-sourced alternate labels — OPERATOR_KEENDNS_DISCOVERY.md §4.
NDNS_DOCS_SOURCED_ALTERNATE_LABELS = frozenset({"keendns", "crazedns"})

# Candidate read command metadata (not added to global allowlist this cycle — D-13).
SHOW_NDNS_COMMAND = "show ndns"
GET_BOOKED_COMMAND = "ndns get-booked"


class ComponentsParseStatus(StrEnum):
    OK = "ok"
    UNKNOWN = "unknown"
    UNPARSED = "unparsed"


class NdnsShowParseStatus(StrEnum):
    UNKNOWN = "unknown"
    UNPARSED = "unparsed"


class NdnsBookedParseStatus(StrEnum):
    UNKNOWN = "unknown"
    UNPARSED = "unparsed"


def _normalize_raw(raw: str | bytes) -> str:
    if isinstance(raw, bytes):
        text = raw.decode("utf-8", errors="replace")
    else:
        text = raw
    return strip_ssh_cli_ansi_artifacts(text.strip())


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


def parse_show_ndns(raw: str | bytes | None) -> dict[str, Any]:
    """Parse ``show ndns`` output; no device-observed sample → unknown/unparsed only."""
    if raw is None:
        return {
            "parser_version": PARSER_VERSION_SHOW,
            "parse_status": NdnsShowParseStatus.UNKNOWN.value,
            "command": SHOW_NDNS_COMMAND,
        }
    text = _normalize_raw(raw)
    if not text:
        return {
            "parser_version": PARSER_VERSION_SHOW,
            "parse_status": NdnsShowParseStatus.UNKNOWN.value,
            "command": SHOW_NDNS_COMMAND,
        }
    return {
        "parser_version": PARSER_VERSION_SHOW,
        "parse_status": NdnsShowParseStatus.UNPARSED.value,
        "command": SHOW_NDNS_COMMAND,
        "notes": (
            "non-empty show ndns output has no sealed device sample "
            "(OPERATOR_KEENDNS_DISCOVERY.md §3; not device-observed in lab)",
        ),
    }


def parse_get_booked(raw: str | bytes | None) -> dict[str, Any]:
    """Parse ``ndns get-booked`` output; no device-observed sample → unknown/unparsed only."""
    if raw is None:
        return {
            "parser_version": PARSER_VERSION_BOOKED,
            "parse_status": NdnsBookedParseStatus.UNKNOWN.value,
            "command": GET_BOOKED_COMMAND,
        }
    text = _normalize_raw(raw)
    if not text:
        return {
            "parser_version": PARSER_VERSION_BOOKED,
            "parse_status": NdnsBookedParseStatus.UNKNOWN.value,
            "command": GET_BOOKED_COMMAND,
        }
    return {
        "parser_version": PARSER_VERSION_BOOKED,
        "parse_status": NdnsBookedParseStatus.UNPARSED.value,
        "command": GET_BOOKED_COMMAND,
        "notes": (
            "non-empty get-booked output has no sealed device sample "
            "(OPERATOR_KEENDNS_DISCOVERY.md §3; not device-observed in lab)",
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
    "PARSER_VERSION_BOOKED",
    "PARSER_VERSION_COMPONENTS",
    "PARSER_VERSION_SHOW",
    "SHOW_NDNS_COMMAND",
    "ComponentsParseStatus",
    "NdnsBookedParseStatus",
    "NdnsShowParseStatus",
    "ndns_component_present",
    "parse_components_inventory",
    "parse_get_booked",
    "parse_show_ndns",
]
