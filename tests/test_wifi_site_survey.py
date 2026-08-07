"""Offline tests for site-survey parser."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest
from router_control.adapters.netcraze.site_survey import (
    SiteSurveyParseError,
    SiteSurveyRadio,
    extract_rci_ap_cell,
    parse_site_survey_ap_cell,
    parse_site_survey_ap_cell_row,
    parse_site_survey_output,
    site_survey_command_for,
    validate_site_survey_radio,
)
from router_control.application.wifi_observation_helpers import (
    encryption_indicates_open,
    map_encryption_to_survey_wpa_mode,
    map_encryption_to_wpa_mode,
    scrub_encryption_value,
)
from router_control.application.wifi_site_survey import (
    _parse_survey_payload,
    run_wifi_site_survey,
)

_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "netcraze"


def _load_json(name: str) -> object:
    return json.loads((_FIXTURES / name).read_text(encoding="utf-8"))


def test_site_survey_command_only_allowlisted_radios() -> None:
    assert site_survey_command_for(SiteSurveyRadio.WIFI_MASTER_0) == "show site-survey WifiMaster0"
    assert site_survey_command_for(SiteSurveyRadio.WIFI_MASTER_1) == "show site-survey WifiMaster1"


def test_validate_site_survey_radio_rejects_passthrough() -> None:
    with pytest.raises(SiteSurveyParseError, match="WifiMaster0 or WifiMaster1"):
        validate_site_survey_radio("WifiMaster2")


def test_parse_synthetic_fixture_wifi_master0() -> None:
    text = (_FIXTURES / "site_survey_wifi_master0.txt").read_text(encoding="utf-8")
    result = parse_site_survey_output(text, radio=SiteSurveyRadio.WIFI_MASTER_0)
    assert result.per_network_security_present is False
    assert "security_type" not in result.to_dict()
    assert len(result.networks) == 2
    assert result.networks[0].ssid == "SYNTH-SSID-Alpha"
    assert result.networks[0].bssid == "aa:bb:cc:dd:ee:01"
    assert result.networks[0].channel == 6
    assert result.networks[0].mode == "n"
    assert result.networks[0].signal_quality == 85


def test_parse_empty_survey_degraded_not_exception() -> None:
    result = parse_site_survey_output("", radio=SiteSurveyRadio.WIFI_MASTER_0)
    assert result.networks == ()
    assert result.findings == ("site_survey_empty",)


def test_parse_malformed_row_skipped_not_cleared() -> None:
    text = "SSID MAC Ch Mode Q\nbroken row\n"
    result = parse_site_survey_output(text, radio=SiteSurveyRadio.WIFI_MASTER_1)
    assert result.networks == ()
    assert result.skipped_row_count == 1
    assert result.findings == ("site_survey_rows_skipped",)


def test_parse_missing_header_degraded() -> None:
    result = parse_site_survey_output("no header here\n", radio=SiteSurveyRadio.WIFI_MASTER_0)
    assert result.networks == ()
    assert result.findings == ("site_survey_malformed",)


def test_parse_tabular_extra_column_uses_header_not_tail_positions() -> None:
    text = (
        "SSID MAC Band Ch Mode Q\n"
        "SYNTH-SSID-Alpha aa:bb:cc:dd:ee:01 40 6 n 85\n"
    )
    result = parse_site_survey_output(text, radio=SiteSurveyRadio.WIFI_MASTER_0)
    assert len(result.networks) == 1
    assert result.networks[0].ssid == "SYNTH-SSID-Alpha"
    assert result.networks[0].bssid == "aa:bb:cc:dd:ee:01"
    assert result.networks[0].channel == 6
    assert result.networks[0].mode == "n"
    assert result.networks[0].signal_quality == 85


def test_parse_tabular_header_case_insensitive() -> None:
    text = (
        "ssid mac ch mode q\n"
        "SYNTH-SSID-Beta aa:bb:cc:dd:ee:03 6 n 80\n"
    )
    result = parse_site_survey_output(text, radio=SiteSurveyRadio.WIFI_MASTER_0)
    assert len(result.networks) == 1
    assert result.networks[0].ssid == "SYNTH-SSID-Beta"
    assert result.networks[0].channel == 6
    assert result.networks[0].signal_quality == 80


def test_parse_tabular_reordered_header_columns() -> None:
    text = (
        "MAC SSID Ch Mode Q\n"
        "aa:bb:cc:dd:ee:02 Venue WiFi 11 ac 72\n"
    )
    result = parse_site_survey_output(text, radio=SiteSurveyRadio.WIFI_MASTER_1)
    assert len(result.networks) == 1
    assert result.networks[0].ssid == "Venue WiFi"
    assert result.networks[0].bssid == "aa:bb:cc:dd:ee:02"
    assert result.networks[0].channel == 11


def test_parse_tabular_missing_required_column_is_malformed() -> None:
    text = "SSID MAC Ch Mode\nSYNTH-SSID-Alpha aa:bb:cc:dd:ee:01 6 n\n"
    result = parse_site_survey_output(text, radio=SiteSurveyRadio.WIFI_MASTER_0)
    assert result.networks == ()
    assert result.findings == ("site_survey_malformed",)


def test_parse_tabular_duplicate_header_column_is_malformed() -> None:
    text = "SSID MAC MAC Ch Mode Q\nSYNTH-SSID-Alpha aa:bb:cc:dd:ee:01 6 n 85\n"
    result = parse_site_survey_output(text, radio=SiteSurveyRadio.WIFI_MASTER_0)
    assert result.networks == ()
    assert result.findings == ("site_survey_malformed",)


def test_parse_rci_live_shape_all_rows() -> None:
    raw = _load_json("site_survey_rci_wifi_master0.json")
    ap_cell, is_parse = extract_rci_ap_cell(raw)
    assert is_parse is True
    assert ap_cell is not None
    result = parse_site_survey_ap_cell(
        ap_cell,
        radio=SiteSurveyRadio.WIFI_MASTER_0,
        sanitize_encryption=scrub_encryption_value,
        map_wpa_mode=map_encryption_to_wpa_mode,
    )
    assert result.per_network_security_present is True
    assert len(result.networks) == 3
    assert result.skipped_row_count == 0

    alpha = result.networks[0]
    assert alpha.ssid == "SYNTH-SSID-Alpha"
    assert alpha.bssid == "aa:bb:cc:dd:ee:01"
    assert alpha.channel == 6
    assert alpha.mode == "11b/g/n/ax/be"
    assert alpha.signal_quality == 85
    assert alpha.rssi == -42
    assert alpha.bandwidth == 40
    assert alpha.hidden is False
    assert alpha.wpa_mode == "WPA2"
    assert alpha.encryption_raw is not None

    hidden = result.networks[1]
    assert hidden.ssid == ""
    assert hidden.hidden is True
    assert hidden.mode == "11a/n/ac/ax/be"
    assert hidden.wpa_mode == "WPA3"

    no_sec = result.networks[2]
    assert no_sec.ssid == "SYNTH-SSID-NoSec"
    assert no_sec.wpa_mode == "unknown"
    assert no_sec.encryption_raw is None


def test_parse_rci_skipped_row_count() -> None:
    raw = _load_json("site_survey_rci_skipped_row.json")
    parsed = _parse_survey_payload(raw, radio=SiteSurveyRadio.WIFI_MASTER_1)
    assert len(parsed.networks) == 1
    assert parsed.networks[0].ssid == "SYNTH-SSID-Good"
    assert parsed.skipped_row_count == 1
    assert parsed.findings == ("site_survey_rows_skipped",)


def test_parse_rci_empty_ap_cell_clean_no_networks() -> None:
    raw = _load_json("site_survey_rci_empty_ap_cell.json")
    parsed = _parse_survey_payload(raw, radio=SiteSurveyRadio.WIFI_MASTER_0)
    assert parsed.networks == ()
    assert parsed.findings == ("site_survey_empty",)
    assert parsed.per_network_security_present is False


def test_parse_rci_all_non_dict_ap_cell_not_empty() -> None:
    raw = _load_json("site_survey_rci_all_non_dict_ap_cell.json")
    parsed = _parse_survey_payload(raw, radio=SiteSurveyRadio.WIFI_MASTER_0)
    assert parsed.networks == ()
    assert parsed.skipped_row_count == 3
    assert parsed.findings == ("site_survey_rows_skipped",)
    assert "site_survey_empty" not in parsed.findings
    assert parsed.per_network_security_present is False


def test_parse_rci_mixed_dict_and_non_dict_rows() -> None:
    raw = _load_json("site_survey_rci_mixed_non_dict_ap_cell.json")
    parsed = _parse_survey_payload(raw, radio=SiteSurveyRadio.WIFI_MASTER_0)
    assert len(parsed.networks) == 2
    assert parsed.skipped_row_count == 1
    assert parsed.findings == ("site_survey_rows_skipped",)
    assert parsed.per_network_security_present is True


def test_parse_rci_null_ieee_skipped() -> None:
    row = {
        "essid": "SYNTH-SSID-Bad",
        "address": "aa:bb:cc:dd:ee:40",
        "channel": 6,
        "quality": 50,
        "ieee": None,
    }
    with pytest.raises(SiteSurveyParseError, match="invalid ieee"):
        parse_site_survey_ap_cell_row(
            row,
            sanitize_encryption=scrub_encryption_value,
            map_wpa_mode=map_encryption_to_wpa_mode,
        )


def test_parse_rci_ieee_used_not_bss_mode_key() -> None:
    row = {
        "essid": "SYNTH-SSID-ModeCheck",
        "address": "aa:bb:cc:dd:ee:50",
        "channel": 36,
        "quality": 88,
        "mode": "Master",
        "ieee": "11b/g/n/ax/be",
        "encryption": "wpa2",
        "encryption-mode": "psk",
    }
    network = parse_site_survey_ap_cell_row(
        row,
        sanitize_encryption=scrub_encryption_value,
        map_wpa_mode=map_encryption_to_wpa_mode,
    )
    assert network.mode == "11b/g/n/ax/be"
    assert network.mode != "Master"


def test_parse_rci_no_encryption_rows_per_network_security_present_false() -> None:
    raw = _load_json("site_survey_rci_no_encryption_rows.json")
    parsed = _parse_survey_payload(raw, radio=SiteSurveyRadio.WIFI_MASTER_0)
    assert len(parsed.networks) == 1
    assert parsed.networks[0].wpa_mode == "unknown"
    assert parsed.per_network_security_present is False


def test_parse_rci_malformed_ap_cell_fail_closed() -> None:
    raw = _load_json("site_survey_rci_malformed_ap_cell.json")
    parsed = _parse_survey_payload(raw, radio=SiteSurveyRadio.WIFI_MASTER_0)
    assert parsed.networks == ()
    assert parsed.findings == ("site_survey_malformed",)


class _JsonTransport:
    def __init__(self, payload: object) -> None:
        self.payload = payload

    def execute_site_survey(self, command: str) -> object:
        return self.payload


def test_service_rci_path_per_network_security_present_when_encryption_present() -> None:
    raw = _load_json("site_survey_rci_wifi_master0.json")
    report = run_wifi_site_survey(
        transport=_JsonTransport(raw),
        radio=SiteSurveyRadio.WIFI_MASTER_0,
    )
    assert report.per_network_security_present is True
    assert report.network_count == 3
    assert report.skipped_row_count == 0


def test_service_logs_counts_not_rows(caplog: pytest.LogCaptureFixture) -> None:
    raw = _load_json("site_survey_rci_wifi_master0.json")
    caplog.set_level(logging.INFO, logger="router_control.application.wifi_site_survey")
    run_wifi_site_survey(
        transport=_JsonTransport(raw),
        radio=SiteSurveyRadio.WIFI_MASTER_0,
    )
    log_text = caplog.text
    assert "SYNTH-SSID-Alpha" not in log_text
    assert "aa:bb:cc:dd:ee:01" not in log_text
    assert "network_count=3" in log_text


def test_parse_rci_open_encryption_disabled_mode_none() -> None:
    raw = _load_json("site_survey_rci_open_unrecognized.json")
    parsed = _parse_survey_payload(raw, radio=SiteSurveyRadio.WIFI_MASTER_0)
    assert parsed.per_network_security_present is True
    assert "security_type" not in parsed.to_dict()
    assert len(parsed.networks) == 2

    open_net = parsed.networks[0]
    assert open_net.ssid == "SYNTH-SSID-Open"
    assert open_net.wpa_mode == "open"
    assert open_net.wpa_mode not in ("WPA2", "WPA3", "WPA2_WPA3_MIXED", "unrecognized")
    assert isinstance(open_net.encryption_raw, dict)
    assert open_net.encryption_raw == {
        "encryption": "disabled",
        "encryption-mode": "none",
    }

    unmapped = parsed.networks[1]
    assert unmapped.ssid == "SYNTH-SSID-Unmapped"
    assert unmapped.wpa_mode == "unrecognized"
    assert unmapped.wpa_mode not in ("WPA2", "WPA3", "WPA2_WPA3_MIXED", "open")


def test_parse_rci_open_row_direct() -> None:
    row = {
        "essid": "SYNTH-SSID-OpenDirect",
        "address": "aa:bb:cc:dd:ee:12",
        "channel": 1,
        "quality": 65,
        "ieee": "11b/g/n",
        "encryption": "disabled",
        "encryption-mode": "none",
    }
    network = parse_site_survey_ap_cell_row(
        row,
        sanitize_encryption=scrub_encryption_value,
        map_wpa_mode=map_encryption_to_survey_wpa_mode,
    )
    assert network.wpa_mode == "open"
    assert isinstance(network.encryption_raw, dict)


def test_site_survey_report_no_security_type_key() -> None:
    raw = _load_json("site_survey_rci_wifi_master0.json")
    report = run_wifi_site_survey(
        transport=_JsonTransport(raw),
        radio=SiteSurveyRadio.WIFI_MASTER_0,
    )
    payload = report.to_dict()
    assert "security_type" not in payload
    assert "security_type_known" not in payload
    assert "per_network_security_present" in payload
    assert payload["per_network_security_present"] is True
    assert all("wpa_mode" in net for net in payload["networks"])


@pytest.mark.parametrize(
    ("encryption", "expected_mode"),
    [
        ({"encryption": "disabled", "encryption-mode": "none"}, "open"),
        ("disabled", "open"),
        ("none", "open"),
        ({"encryption": "", "encryption-mode": "none"}, "unrecognized"),
        ({"encryption": 0, "encryption-mode": "none"}, "unrecognized"),
        (False, "unrecognized"),
        ({}, "not_configured"),
        ("", "not_configured"),
        ({"encryption": "vendor-cipher-x9", "encryption-mode": "opaque"}, "unrecognized"),
        ({"encryption": "disabled"}, "unrecognized"),
    ],
)
def test_survey_wpa_mode_open_only_for_clear_disabled_none(
    encryption: object,
    expected_mode: str,
) -> None:
    assert map_encryption_to_survey_wpa_mode(encryption) == expected_mode
    if expected_mode == "open":
        assert encryption_indicates_open(encryption)
    else:
        assert not encryption_indicates_open(encryption)


def test_survey_open_row_empty_encryption_string_not_open() -> None:
    row = {
        "essid": "SYNTH-SSID-Ambiguous",
        "address": "aa:bb:cc:dd:ee:20",
        "channel": 3,
        "quality": 50,
        "ieee": "11b/g/n",
        "encryption": "",
        "encryption-mode": "none",
    }
    network = parse_site_survey_ap_cell_row(
        row,
        sanitize_encryption=scrub_encryption_value,
        map_wpa_mode=map_encryption_to_survey_wpa_mode,
    )
    assert network.wpa_mode == "unrecognized"
    assert network.wpa_mode != "open"
