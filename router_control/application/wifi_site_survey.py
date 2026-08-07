"""Read-only Wi-Fi site-survey service (offline-testable; neighbour privacy)."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Protocol

from router_control.adapters.netcraze.site_survey import (
    SiteSurveyParseResult,
    SiteSurveyRadio,
    extract_rci_ap_cell,
    parse_site_survey_ap_cell,
    parse_site_survey_output,
    site_survey_command_for,
    validate_site_survey_radio,
)
from router_control.application.wifi_observation_helpers import (
    map_encryption_to_survey_wpa_mode,
    scrub_encryption_value,
)

_LOGGER = logging.getLogger(__name__)


class SiteSurveyTransport(Protocol):
    def execute_site_survey(self, command: str) -> Any: ...


class WifiSiteSurveyError(ValueError):
    """Fail-closed Wi-Fi site-survey error."""


@dataclass(frozen=True, slots=True)
class SiteSurveyReport:
    radio: str
    command: str
    networks: tuple[dict[str, object], ...]
    network_count: int
    per_network_security_present: bool
    findings: tuple[str, ...]
    skipped_row_count: int
    certification_eligible: bool
    transport_security: str
    offline_verified_only: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "radio": self.radio,
            "command": self.command,
            "networks": list(self.networks),
            "network_count": self.network_count,
            "per_network_security_present": self.per_network_security_present,
            "findings": list(self.findings),
            "skipped_row_count": self.skipped_row_count,
            "certification_eligible": self.certification_eligible,
            "transport_security": self.transport_security,
            "offline_verified_only": self.offline_verified_only,
        }


def coerce_survey_text(raw: Any) -> str:
    """Coerce transport payload to tabular text (legacy CLI / show wrappers)."""
    if isinstance(raw, str):
        return raw
    if isinstance(raw, dict):
        for key in ("text", "output", "message", "data"):
            value = raw.get(key)
            if isinstance(value, str):
                return value
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                show = item.get("show")
                if isinstance(show, dict):
                    for value in show.values():
                        if isinstance(value, str):
                            return value
                status = item.get("status")
                if isinstance(status, list):
                    for entry in status:
                        if isinstance(entry, dict):
                            message = entry.get("message")
                            if isinstance(message, str):
                                return message
    try:
        return json.dumps(raw)
    except TypeError:
        return str(raw)


def _parse_survey_payload(
    raw: Any,
    *,
    radio: SiteSurveyRadio,
) -> SiteSurveyParseResult:
    ap_cell, is_parse_shaped = extract_rci_ap_cell(raw)
    if is_parse_shaped:
        if ap_cell is None:
            command = site_survey_command_for(radio)
            return SiteSurveyParseResult(
                radio=radio,
                command=command,
                networks=(),
                per_network_security_present=False,
                findings=("site_survey_malformed",),
            )
        return parse_site_survey_ap_cell(
            ap_cell,
            radio=radio,
            sanitize_encryption=scrub_encryption_value,
            map_wpa_mode=map_encryption_to_survey_wpa_mode,
        )

    text = coerce_survey_text(raw)
    return parse_site_survey_output(text, radio=radio)


def run_wifi_site_survey(
    *,
    transport: SiteSurveyTransport,
    radio: SiteSurveyRadio | str,
    transport_security: str = "fixture",
) -> SiteSurveyReport:
    resolved_radio = (
        radio if isinstance(radio, SiteSurveyRadio) else validate_site_survey_radio(str(radio))
    )
    command = site_survey_command_for(resolved_radio)
    try:
        raw = transport.execute_site_survey(command)
    except Exception as exc:
        raise WifiSiteSurveyError(
            f"site-survey transport failed: {exc.__class__.__name__}"
        ) from exc

    parsed: SiteSurveyParseResult = _parse_survey_payload(raw, radio=resolved_radio)
    network_dicts = tuple(network.to_dict() for network in parsed.networks)
    _LOGGER.info(
        "wifi site-survey completed radio=%s network_count=%d skipped_row_count=%d findings=%s",
        resolved_radio.value,
        len(network_dicts),
        parsed.skipped_row_count,
        list(parsed.findings),
    )
    return SiteSurveyReport(
        radio=resolved_radio.value,
        command=parsed.command,
        networks=network_dicts,
        network_count=len(network_dicts),
        per_network_security_present=parsed.per_network_security_present,
        findings=parsed.findings,
        skipped_row_count=parsed.skipped_row_count,
        certification_eligible=False,
        transport_security=transport_security,
        offline_verified_only=True,
    )


__all__ = [
    "SiteSurveyReport",
    "SiteSurveyTransport",
    "WifiSiteSurveyError",
    "coerce_survey_text",
    "run_wifi_site_survey",
]
