"""Parse read-only Wi-Fi site-survey CLI text and RCI JSON (WifiMaster0/1 only)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
_REQUIRED_HEADER_COLUMNS = frozenset({"SSID", "MAC", "Ch", "Mode", "Q"})
_HEADER_TOKENS = _REQUIRED_HEADER_COLUMNS
_HEADER_CANONICAL: dict[str, str] = {
    "ssid": "SSID",
    "mac": "MAC",
    "ch": "Ch",
    "mode": "Mode",
    "q": "Q",
}


class SiteSurveyRadio(StrEnum):
    WIFI_MASTER_0 = "WifiMaster0"
    WIFI_MASTER_1 = "WifiMaster1"


class SiteSurveyParseError(ValueError):
    """Fail-closed site-survey parse error."""


@dataclass(frozen=True, slots=True)
class SiteSurveyNetwork:
    ssid: str
    bssid: str
    channel: int
    mode: str
    signal_quality: int
    hidden: bool = False
    rssi: int | None = None
    bandwidth: int | None = None
    wpa_mode: str = "unknown"
    encryption_raw: object | None = None

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "ssid": self.ssid,
            "bssid": self.bssid,
            "channel": self.channel,
            "mode": self.mode,
            "signal_quality": self.signal_quality,
            "hidden": self.hidden,
            "wpa_mode": self.wpa_mode,
        }
        if self.rssi is not None:
            payload["rssi"] = self.rssi
        if self.bandwidth is not None:
            payload["bandwidth"] = self.bandwidth
        if self.encryption_raw is not None:
            payload["encryption_raw"] = self.encryption_raw
        return payload


@dataclass(frozen=True, slots=True)
class SiteSurveyParseResult:
    radio: SiteSurveyRadio
    command: str
    networks: tuple[SiteSurveyNetwork, ...]
    per_network_security_present: bool
    findings: tuple[str, ...]
    skipped_row_count: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "radio": self.radio.value,
            "command": self.command,
            "networks": [network.to_dict() for network in self.networks],
            "per_network_security_present": self.per_network_security_present,
            "findings": list(self.findings),
            "skipped_row_count": self.skipped_row_count,
        }


def validate_site_survey_radio(raw: str) -> SiteSurveyRadio:
    normalized = raw.strip()
    try:
        return SiteSurveyRadio(normalized)
    except ValueError as exc:
        raise SiteSurveyParseError(
            f"radio must be WifiMaster0 or WifiMaster1, got {raw!r}"
        ) from exc


def site_survey_command_for(radio: SiteSurveyRadio) -> str:
    return f"show site-survey {radio.value}"


def unwrap_rci_parse_dict(raw: Any) -> dict[str, Any] | None:
    """Extract a ``parse`` dict from a tight RCI wrapper (list-or-dict)."""
    if isinstance(raw, dict):
        parse = raw.get("parse")
        if isinstance(parse, dict):
            return parse
        return None
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict):
                continue
            parse = item.get("parse")
            if isinstance(parse, dict):
                return parse
    return None


def extract_rci_ap_cell(raw: Any) -> tuple[list[Any] | None, bool]:
    """Return ``(ap_cell, is_parse_shaped)``.

    When ``is_parse_shaped`` is True the payload is RCI ``parse``-shaped:
    - ``ap_cell`` is a list (possibly empty) on success — items may be non-dict
    - ``ap_cell`` is ``None`` when ``parse`` exists but ``ap_cell`` is missing or not a list
    When ``is_parse_shaped`` is False, caller should fall back to tabular text coercion.
    """
    parse_dict = unwrap_rci_parse_dict(raw)
    if parse_dict is None:
        return None, False
    ap_cell = parse_dict.get("ap_cell")
    if ap_cell is None:
        return None, True
    if not isinstance(ap_cell, list):
        return None, True
    return ap_cell, True


def _parse_channel(raw: Any) -> int:
    try:
        channel = int(str(raw).strip())
    except (TypeError, ValueError) as exc:
        raise SiteSurveyParseError(f"invalid channel: {raw!r}") from exc
    if channel < 1 or channel > 196:
        raise SiteSurveyParseError(f"channel out of range: {channel}")
    return channel


def _parse_signal_quality(raw: Any) -> int:
    try:
        quality = int(str(raw).strip())
    except (TypeError, ValueError) as exc:
        raise SiteSurveyParseError(f"invalid signal quality: {raw!r}") from exc
    if quality < 0 or quality > 100:
        raise SiteSurveyParseError(f"signal quality out of range: {quality}")
    return quality


def _parse_optional_int(raw: Any) -> int | None:
    if raw is None:
        return None
    try:
        return int(str(raw).strip())
    except (TypeError, ValueError):
        return None


def _row_encryption_fields(row: dict[str, Any]) -> object | None:
    encryption = row.get("encryption")
    encryption_mode = row.get("encryption-mode")
    if encryption_mode is None:
        encryption_mode = row.get("encryption_mode")
    if encryption is None and encryption_mode is None:
        return None
    if encryption is not None and encryption_mode is not None:
        return {"encryption": encryption, "encryption-mode": encryption_mode}
    return encryption if encryption is not None else encryption_mode


def _is_header_line(line: str) -> bool:
    return _parse_header_columns(line) is not None


def _parse_header_columns(line: str) -> dict[str, int] | None:
    """Map required tabular header columns to token indices; None when unrecognized."""
    tokens = line.split()
    lowered = {token.lower() for token in tokens}
    if not set(_HEADER_CANONICAL.keys()).issubset(lowered):
        return None
    col_map: dict[str, int] = {}
    for idx, token in enumerate(tokens):
        canonical = _HEADER_CANONICAL.get(token.lower())
        if canonical is None:
            continue
        if canonical in col_map:
            return None
        col_map[canonical] = idx
    if set(col_map.keys()) != _REQUIRED_HEADER_COLUMNS:
        return None
    return col_map


def _parse_data_line(line: str, col_map: dict[str, int]) -> SiteSurveyNetwork:
    parts = line.split()
    ordered = sorted(col_map.items(), key=lambda item: item[1])
    last_three = [name for name, _ in ordered[-3:]]
    if set(last_three) != {"Ch", "Mode", "Q"}:
        raise SiteSurveyParseError(f"unrecognized site-survey header order: {line!r}")
    if len(parts) < len(_REQUIRED_HEADER_COLUMNS):
        raise SiteSurveyParseError(f"malformed site-survey row: {line!r}")

    signal_quality = _parse_signal_quality(parts[-1])
    mode = parts[-2]
    channel = _parse_channel(parts[-3])
    body = parts[:-3]

    mac_pos: int | None = None
    for idx, token in enumerate(body):
        if _MAC_RE.fullmatch(token):
            if mac_pos is not None:
                raise SiteSurveyParseError(f"ambiguous MAC in site-survey row: {line!r}")
            mac_pos = idx
    if mac_pos is None:
        raise SiteSurveyParseError(f"invalid bssid in row: {line!r}")

    bssid = body[mac_pos]
    if col_map["SSID"] < col_map["MAC"]:
        ssid = " ".join(body[:mac_pos]).strip()
    else:
        ssid = " ".join(body[mac_pos + 1 :]).strip()

    hidden = not ssid
    return SiteSurveyNetwork(
        ssid=ssid,
        bssid=bssid.lower(),
        channel=channel,
        mode=mode,
        signal_quality=signal_quality,
        hidden=hidden,
    )


def _parse_ieee_mode(row: dict[str, Any]) -> str:
    if "ieee" not in row:
        raise SiteSurveyParseError("missing ieee in ap_cell row")
    ieee = row["ieee"]
    if not isinstance(ieee, str):
        raise SiteSurveyParseError(f"invalid ieee in ap_cell row: {ieee!r}")
    mode = ieee.strip()
    if not mode:
        raise SiteSurveyParseError("empty ieee in ap_cell row")
    return mode


def parse_site_survey_ap_cell_row(
    row: dict[str, Any],
    *,
    sanitize_encryption: Any,
    map_wpa_mode: Any,
) -> SiteSurveyNetwork:
    """Parse one RCI ``ap_cell`` row (live key names: essid, address, ieee, …)."""
    if "essid" not in row:
        raise SiteSurveyParseError("missing essid in ap_cell row")
    essid_raw = row["essid"]
    if essid_raw is None:
        raise SiteSurveyParseError("null essid in ap_cell row")
    ssid = str(essid_raw)
    hidden = ssid == ""

    address = row.get("address")
    if not isinstance(address, str) or not _MAC_RE.fullmatch(address):
        raise SiteSurveyParseError(f"invalid address in ap_cell row: {address!r}")

    mode = _parse_ieee_mode(row)

    channel = _parse_channel(row.get("channel"))
    signal_quality = _parse_signal_quality(row.get("quality"))

    rssi = _parse_optional_int(row.get("rssi"))
    bandwidth = _parse_optional_int(row.get("bandwidth"))

    encryption = _row_encryption_fields(row)
    if encryption is None:
        wpa_mode = "unknown"
        encryption_raw = None
    else:
        encryption_raw = sanitize_encryption(encryption)
        mapped = map_wpa_mode(encryption)
        wpa_mode = mapped if mapped != "not_configured" else "unrecognized"

    return SiteSurveyNetwork(
        ssid=ssid,
        bssid=address.lower(),
        channel=channel,
        mode=mode,
        signal_quality=signal_quality,
        hidden=hidden,
        rssi=rssi,
        bandwidth=bandwidth,
        wpa_mode=wpa_mode,
        encryption_raw=encryption_raw,
    )


def parse_site_survey_ap_cell(
    ap_cell: list[Any],
    *,
    radio: SiteSurveyRadio,
    sanitize_encryption: Any,
    map_wpa_mode: Any,
) -> SiteSurveyParseResult:
    """Parse RCI ``parse.ap_cell`` rows into typed networks."""
    command = site_survey_command_for(radio)
    if not ap_cell:
        return SiteSurveyParseResult(
            radio=radio,
            command=command,
            networks=(),
            per_network_security_present=False,
            findings=("site_survey_empty",),
            skipped_row_count=0,
        )

    networks: list[SiteSurveyNetwork] = []
    skipped = 0
    has_security_data = False
    for item in ap_cell:
        if not isinstance(item, dict):
            skipped += 1
            continue
        try:
            network = parse_site_survey_ap_cell_row(
                item,
                sanitize_encryption=sanitize_encryption,
                map_wpa_mode=map_wpa_mode,
            )
        except SiteSurveyParseError:
            skipped += 1
            continue
        networks.append(network)
        if _row_encryption_fields(item) is not None:
            has_security_data = True

    findings: tuple[str, ...] = ()
    if skipped > 0:
        findings = ("site_survey_rows_skipped",)

    return SiteSurveyParseResult(
        radio=radio,
        command=command,
        networks=tuple(networks),
        per_network_security_present=has_security_data,
        findings=findings,
        skipped_row_count=skipped,
    )


def parse_site_survey_output(
    text: str,
    *,
    radio: SiteSurveyRadio,
) -> SiteSurveyParseResult:
    """Parse tabular site-survey text into typed rows (security always unknown)."""
    command = site_survey_command_for(radio)
    if not text or not text.strip():
        return SiteSurveyParseResult(
            radio=radio,
            command=command,
            networks=(),
            per_network_security_present=False,
            findings=("site_survey_empty",),
        )

    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    if not lines:
        return SiteSurveyParseResult(
            radio=radio,
            command=command,
            networks=(),
            per_network_security_present=False,
            findings=("site_survey_empty",),
        )

    header_idx: int | None = None
    header_columns: dict[str, int] | None = None
    for idx, line in enumerate(lines):
        col_map = _parse_header_columns(line)
        if col_map is not None:
            header_idx = idx
            header_columns = col_map
            break

    if header_idx is None or header_columns is None:
        return SiteSurveyParseResult(
            radio=radio,
            command=command,
            networks=(),
            per_network_security_present=False,
            findings=("site_survey_malformed",),
        )

    networks: list[SiteSurveyNetwork] = []
    skipped = 0
    for line in lines[header_idx + 1 :]:
        if line.startswith("-") or _is_header_line(line):
            continue
        try:
            networks.append(_parse_data_line(line, header_columns))
        except SiteSurveyParseError:
            skipped += 1

    findings: tuple[str, ...] = ()
    if skipped > 0:
        findings = ("site_survey_rows_skipped",)

    return SiteSurveyParseResult(
        radio=radio,
        command=command,
        networks=tuple(networks),
        per_network_security_present=False,
        findings=findings,
        skipped_row_count=skipped,
    )


__all__ = [
    "SiteSurveyNetwork",
    "SiteSurveyParseError",
    "SiteSurveyParseResult",
    "SiteSurveyRadio",
    "extract_rci_ap_cell",
    "parse_site_survey_ap_cell",
    "parse_site_survey_ap_cell_row",
    "parse_site_survey_output",
    "site_survey_command_for",
    "unwrap_rci_parse_dict",
    "validate_site_survey_radio",
]
