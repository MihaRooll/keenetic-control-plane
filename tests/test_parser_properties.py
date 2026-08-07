"""Property-based robustness tests for Netcraze CLI/JSON parsers and validators."""

from __future__ import annotations

import re
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from router_control.adapters.netcraze.allowlist import (
    validate_interface_id,
    validate_ssid,
    validate_wifi_ap_id,
    validate_wireguard_id,
)
from router_control.adapters.netcraze.awg_profile import AwgProfileError, parse_awg_profile_text
from router_control.adapters.netcraze.route_topology_probe import (
    RouteTopologyProbeError,
    parse_default_routes,
)
from router_control.adapters.netcraze.sanitize import strip_ssh_cli_ansi_artifacts
from router_control.adapters.netcraze.site_survey import (
    SiteSurveyParseError,
    SiteSurveyRadio,
    parse_site_survey_ap_cell,
    parse_site_survey_output,
)
from router_control.adapters.netcraze.topology_probe import (
    TopologyProbeError,
    parse_topology_interfaces,
)
from router_control.adapters.netcraze.vpn_policy_probe import (
    parse_show_ip_name_server,
    parse_show_ip_policy,
)
from router_control.adapters.secrets.memory import MemoryVault

_PROP = settings(max_examples=25, deadline=None)
_CRITICAL_PROP = settings(max_examples=100, deadline=None)

_EMPTY_NAME_SERVER = "Server list is empty."
_FORBIDDEN_INTERFACE_CHARS = re.compile(r"[^A-Za-z0-9._/\-]")
_SEALED_STATION_IDS = frozenset({"WifiMaster0/WifiStation0", "WifiMaster1/WifiStation0"})

_cli_input = st.one_of(
    st.text(max_size=4096),
    st.binary(max_size=4096),
    st.text(max_size=4096).map(lambda s: s + "\x1b[K"),
    st.text(max_size=512).map(lambda s: s.replace("\n", "\r\n")),
)

_json_scalar = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(),
    st.floats(allow_nan=False, allow_infinity=False),
    st.text(max_size=256),
)

_json_value = st.recursive(
    _json_scalar,
    lambda children: st.one_of(
        st.lists(children, max_size=8),
        st.dictionaries(st.text(min_size=1, max_size=16), children, max_size=8),
    ),
    max_leaves=24,
)


def _sanitize_encryption(value: object) -> object:
    return value


def _map_wpa_mode(_value: object) -> str:
    return "unknown"


@given(raw=_cli_input)
@_CRITICAL_PROP
def test_vpn_policy_parsers_never_raise_unexpected(raw: str | bytes) -> None:
    policy = parse_show_ip_policy(raw)
    name_server = parse_show_ip_name_server(raw)
    assert isinstance(policy, dict)
    assert isinstance(name_server, dict)
    assert policy.keys() >= {"parse_status"}
    assert name_server.keys() >= {"parse_status"}
    assert policy["parse_status"] in {
        "zero_policies",
        "unknown",
        "unparsed",
    }
    assert name_server["parse_status"] in {"empty", "unknown", "unparsed"}
    if "policy_count" in policy and policy["policy_count"] is not None:
        assert isinstance(policy["policy_count"], int)
        assert policy["policy_count"] >= 0
    if "name_servers" in name_server and name_server["name_servers"] is not None:
        assert isinstance(name_server["name_servers"], list)
        assert all(isinstance(item, str) for item in name_server["name_servers"])


@given(raw=_cli_input)
@_PROP
def test_vpn_policy_garbage_never_claims_sealed_counts(raw: str | bytes) -> None:
    if isinstance(raw, bytes):
        text = raw.decode("utf-8", errors="replace").strip()
    else:
        text = strip_ssh_cli_ansi_artifacts(raw.strip())
    policy = parse_show_ip_policy(raw)
    if text:
        assert policy["parse_status"] != "zero_policies"
        assert policy.get("policy_count") is None
    else:
        assert policy["parse_status"] == "zero_policies"
        assert policy.get("policy_count") == 0

    ns = parse_show_ip_name_server(raw)
    if text == _EMPTY_NAME_SERVER:
        assert ns["parse_status"] == "empty"
        assert ns.get("name_servers") == []
    elif not text:
        assert ns["parse_status"] == "unknown"
        assert ns.get("name_servers") is None
    else:
        assert ns["parse_status"] == "unparsed"
        assert ns.get("name_servers") is None


@given(payload=_json_value)
@_CRITICAL_PROP
def test_topology_parser_fail_closed_or_structured(payload: object) -> None:
    try:
        interfaces = parse_topology_interfaces(payload)
    except TopologyProbeError:
        return
    assert isinstance(interfaces, tuple)
    for iface in interfaces:
        assert iface.interface_id_hash.startswith("sha256:")


@given(payload=_json_value)
@_CRITICAL_PROP
def test_default_route_parser_fail_closed_or_empty(payload: object) -> None:
    try:
        routes = parse_default_routes(payload)
    except RouteTopologyProbeError:
        return
    assert isinstance(routes, tuple)
    for route in routes:
        assert route.interface_id_hash.startswith("sha256:")
        assert route.route_type == "unicast"
        assert route.route_state == "active"


@given(text=st.text(max_size=4096))
@_PROP
def test_site_survey_text_parser_never_raises(text: str) -> None:
    result = parse_site_survey_output(text, radio=SiteSurveyRadio.WIFI_MASTER_0)
    assert result.radio == SiteSurveyRadio.WIFI_MASTER_0
    assert isinstance(result.networks, tuple)


@given(rows=st.lists(st.one_of(_json_value, st.dictionaries(st.text(), _json_value)), max_size=16))
@_PROP
def test_site_survey_ap_cell_skips_bad_rows(rows: list[Any]) -> None:
    result = parse_site_survey_ap_cell(
        rows,
        radio=SiteSurveyRadio.WIFI_MASTER_1,
        sanitize_encryption=_sanitize_encryption,
        map_wpa_mode=_map_wpa_mode,
    )
    assert result.skipped_row_count + len(result.networks) <= len(rows)


@given(garbage=st.text(min_size=1, max_size=512))
@_PROP
def test_awg_profile_garbage_raises_profile_error(garbage: str) -> None:
    vault = MemoryVault()
    with pytest.raises(AwgProfileError):
        parse_awg_profile_text(garbage, vault=vault)


@given(raw=st.text(min_size=1, max_size=128))
@_CRITICAL_PROP
def test_interface_id_rejects_forbidden_chars(raw: str) -> None:
    if raw.strip() in _SEALED_STATION_IDS:
        return
    if _FORBIDDEN_INTERFACE_CHARS.search(raw.strip()):
        with pytest.raises(ValueError):
            validate_interface_id(raw)


@given(raw=st.text(min_size=1, max_size=128))
@_CRITICAL_PROP
def test_wifi_ap_id_rejects_forbidden_chars(raw: str) -> None:
    if _FORBIDDEN_INTERFACE_CHARS.search(raw.strip()):
        with pytest.raises(ValueError):
            validate_wifi_ap_id(raw)


@given(raw=st.text(min_size=1, max_size=128))
@_CRITICAL_PROP
def test_wireguard_id_rejects_forbidden_chars(raw: str) -> None:
    if _FORBIDDEN_INTERFACE_CHARS.search(raw.strip()):
        with pytest.raises(ValueError):
            validate_wireguard_id(raw)


@given(raw=st.text(min_size=1, max_size=64))
@_CRITICAL_PROP
def test_ssid_rejects_forbidden_chars(raw: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}", raw.strip()):
        with pytest.raises(ValueError):
            validate_ssid(raw)


@given(text=st.text(max_size=4096))
@_PROP
def test_strip_ssh_cli_ansi_idempotent(text: str) -> None:
    once = strip_ssh_cli_ansi_artifacts(text)
    twice = strip_ssh_cli_ansi_artifacts(once)
    assert once == twice


@given(text=st.text(max_size=4096))
@_PROP
def test_strip_ssh_cli_ansi_never_lengthens(text: str) -> None:
    stripped = strip_ssh_cli_ansi_artifacts(text)
    assert len(stripped) <= len(text)


@given(text=st.text(max_size=2048))
@_PROP
def test_strip_ssh_cli_ansi_crlf_and_suffix_stable(text: str) -> None:
    mutated = text.replace("\n", "\r\n") + "\x1b[K"
    stripped = strip_ssh_cli_ansi_artifacts(mutated)
    assert isinstance(stripped, str)
    assert "\x1b[K" not in stripped or not stripped.endswith("\x1b[K")


def test_site_survey_row_parser_raises_only_parse_error() -> None:
    from router_control.adapters.netcraze.site_survey import parse_site_survey_ap_cell_row

    with pytest.raises(SiteSurveyParseError):
        parse_site_survey_ap_cell_row(
            {"essid": "x"},
            sanitize_encryption=_sanitize_encryption,
            map_wpa_mode=_map_wpa_mode,
        )
