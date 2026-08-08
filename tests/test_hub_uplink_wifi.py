"""Поведенческие контракты модели и экрана «Интернет» LOCAL HUB (uplink Wi‑Fi)."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
HUB = REPO_ROOT / "router_control_host" / "web" / "hub"
UPLINK_MODEL_JS = HUB / "features" / "uplink-wifi-model.js"
DIAGNOSTICS_MODEL_JS = HUB / "features" / "diagnostics-model.js"
UPLINK_SCREEN_JS = HUB / "screens" / "internet-uplink.js"
SCREENS_INDEX_JS = HUB / "screens" / "index.js"
SESSION_JS = HUB / "core" / "session.js"

NODE_SKIP_ENV = "HUB_TESTS_ALLOW_SKIP_NODE"
REALISTIC_FINGERPRINT = "SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY"
CYRILLIC = re.compile(r"[А-Яа-яЁё]")


def _require_node() -> str:
    node = shutil.which("node")
    if node is None:
        if os.environ.get(NODE_SKIP_ENV) == "1":
            pytest.skip(f"node not available ({NODE_SKIP_ENV}=1)")
        pytest.fail(
            "node is required for hub uplink wifi tests; install Node.js or set "
            f"{NODE_SKIP_ENV}=1 to allow skip",
        )
    return node


def _run_node_harness(script: str, tmp_path: Path, label: str) -> object:
    node = _require_node()
    tmp_path.mkdir(parents=True, exist_ok=True)
    harness_path = tmp_path / f"{label}.mjs"
    harness_path.write_text(script, encoding="utf-8")
    proc = subprocess.run(
        [node, str(harness_path)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    if proc.returncode != 0:
        pytest.fail(
            f"node harness {label} failed:\nstdout={proc.stdout}\nstderr={proc.stderr}",
        )
    return json.loads(proc.stdout.strip())


def _run_export(tmp_path: Path, *, label: str, script_body: str) -> object:
    script = f"const mod = await import({json.dumps(UPLINK_MODEL_JS.as_uri())});\n{script_body}"
    return _run_node_harness(script, tmp_path, label)


def _full_session() -> dict[str, object]:
    return {
        "routerId": "router-lab-1",
        "routerHost": "10.0.0.1",
        "liveReady": True,
        "hostKeyConfirmed": True,
        "usernameAvailable": True,
        "wifiLive": {
            "host": "10.0.0.1",
            "username": "admin",
            "credentialRefId": "cred-ref-1",
            "sshHostKeySha256": REALISTIC_FINGERPRINT,
        },
        "sourceAddress": "192.168.2.144",
    }


def test_uplink_wifi_band_radio_mapping(tmp_path: Path) -> None:
    """WifiMaster0↔BAND_2_4GHZ, WifiMaster1↔BAND_5GHZ."""
    result = _run_export(
        tmp_path,
        label="band-radio",
        script_body="""
console.log(JSON.stringify({
  m0: mod.bandFromRadio('WifiMaster0'),
  m1: mod.bandFromRadio('WifiMaster1'),
  b24: mod.radioFromBand('BAND_2_4GHZ'),
  b5: mod.radioFromBand('BAND_5GHZ'),
  label24: mod.bandLabelRu('BAND_2_4GHZ'),
  label5: mod.bandLabelRu('BAND_5GHZ'),
}));
""",
    )
    assert result["m0"] == "BAND_2_4GHZ"
    assert result["m1"] == "BAND_5GHZ"
    assert result["b24"] == "WifiMaster0"
    assert result["b5"] == "WifiMaster1"
    assert "2,4" in result["label24"]
    assert "5" in result["label5"]


def test_uplink_wifi_site_survey_body_includes_live_fields(tmp_path: Path) -> None:
    """POST /wifi/site-survey body: radio + live params, host 10.0.0.1 not 192.168.2.1."""
    session = _full_session()
    result = _run_export(
        tmp_path,
        label="survey-body",
        script_body=f"""
const session = {json.dumps(session)};
console.log(JSON.stringify({{
  m0: mod.buildSiteSurveyBody(session, 'WifiMaster0'),
  m1: mod.buildSiteSurveyBody(session, 'WifiMaster1'),
}}));
""",
    )
    for key in ("m0", "m1"):
        body = result[key]
        assert body["radio"] in ("WifiMaster0", "WifiMaster1")
        assert body["host"] == "10.0.0.1"
        assert body["username"] == "admin"
        assert body["router_credential_ref_id"] == "cred-ref-1"
        assert body["ssh_host_key_sha256"] == REALISTIC_FINGERPRINT
        assert body["source_address"] == "192.168.2.144"
        assert body["router_id"] == "router-lab-1"
        assert body["host"] != "192.168.2.1"


# WifiStationPreviewBody (wifi_station_preview_routes.py)
WIFI_STATION_PREVIEW_ALLOWED_KEYS = frozenset(
    {"mode", "ssid", "band", "credential_ref_id", "bssid", "priority", "auth_mode"},
)

# WifiStationIntentFields + WifiLiveConnectionFields (wifi_station_apply_routes.py)
WIFI_STATION_INTENT_KEYS = frozenset(
    {"mode", "ssid", "band", "credential_ref_id", "bssid", "priority", "auth_mode"},
)
WIFI_LIVE_CONNECTION_KEYS = frozenset(
    {
        "host",
        "username",
        "router_credential_ref_id",
        "ssh_host_key_sha256",
        "source_address",
        "router_id",
    },
)
WIFI_STATION_TEARDOWN_ALLOWED_KEYS = (
    WIFI_STATION_INTENT_KEYS
    | WIFI_LIVE_CONNECTION_KEYS
    | {"confirm_live_teardown", "confirm_live_apply"}
)
WIFI_STATION_APPLY_ALLOWED_KEYS = (
    WIFI_STATION_INTENT_KEYS
    | WIFI_LIVE_CONNECTION_KEYS
    | {"confirm_live_apply", "compensate_on_failure", "idempotent", "uplink_settle_seconds"}
)


def test_uplink_wifi_station_preview_apply_teardown_bodies(tmp_path: Path) -> None:
    """Request builders for preview/apply/teardown match backend pydantic schemas."""
    session = _full_session()
    result = _run_export(
        tmp_path,
        label="station-bodies",
        script_body=f"""
const session = {json.dumps(session)};
const preview = mod.buildStationPreviewBody({{
  ssid: 'Venue-Net',
  band: 'BAND_5GHZ',
  credentialRefId: 'cred-uplink-1',
}});
const apply = mod.buildStationApplyBody({{ previewBody: preview, session }});
const teardown = mod.buildStationTeardownBody({{
  ssid: 'Venue-Net',
  band: 'BAND_5GHZ',
  credentialRefId: 'cred-uplink-1',
  session,
}});
console.log(JSON.stringify({{ preview, apply, teardown }}));
""",
    )
    preview = result["preview"]
    assert preview["mode"] == "WifiWan"
    assert preview["ssid"] == "Venue-Net"
    assert preview["band"] == "BAND_5GHZ"
    assert preview["credential_ref_id"] == "cred-uplink-1"
    assert preview["priority"] == 100
    assert "compensate_on_failure" not in preview
    assert "idempotent" not in preview
    assert set(preview.keys()) <= WIFI_STATION_PREVIEW_ALLOWED_KEYS

    apply = result["apply"]
    assert apply["confirm_live_apply"] is True
    assert apply["compensate_on_failure"] is True
    assert apply["idempotent"] is True
    assert apply["uplink_settle_seconds"] == 25
    assert apply["host"] == "10.0.0.1"
    assert set(apply.keys()) <= WIFI_STATION_APPLY_ALLOWED_KEYS

    teardown = result["teardown"]
    assert teardown["confirm_live_teardown"] is True
    assert teardown["mode"] == "WifiWan"
    assert teardown["ssid"] == "Venue-Net"
    assert "compensate_on_failure" not in teardown
    assert "idempotent" not in teardown
    assert set(teardown.keys()) <= WIFI_STATION_TEARDOWN_ALLOWED_KEYS


@pytest.mark.parametrize(
    ("response", "expect_success", "expect_state"),
    [
        (
            {
                "overall": "applied",
                "uplink_verification_status": "uplink_verified_bounded",
            },
            True,
            "SUCCESS",
        ),
        (
            {
                "overall": "applied",
                "uplink_verification_status": "uplink_dispatched_unverified",
            },
            False,
            "WARNING",
        ),
        (
            {
                "overall": "applied",
                "uplink_verification_status": "uplink_associated_no_global",
            },
            False,
            "WARNING",
        ),
        (
            {
                "overall": "failed",
                "uplink_verification_status": "uplink_failed",
            },
            False,
            "ERROR",
        ),
    ],
)
def test_uplink_wifi_parse_apply_verdict_honesty(
    tmp_path: Path,
    response: dict[str, object],
    expect_success: bool,
    expect_state: str,
) -> None:
    """Success только applied + uplink_verified_bounded."""
    payload = json.dumps(response, ensure_ascii=False)
    result = _run_export(
        tmp_path,
        label="parse-apply",
        script_body=f"""
console.log(JSON.stringify(mod.parseUplinkApplyVerdict({payload}, {{ intent: 'apply' }})));
""",
    )
    assert result["success"] is expect_success
    assert result["hubState"] == expect_state


def test_uplink_wifi_parse_teardown_verdict_applied_success(tmp_path: Path) -> None:
    """Teardown: overall=applied → success без uplink_verified_bounded."""
    result = _run_export(
        tmp_path,
        label="parse-teardown",
        script_body="""
console.log(JSON.stringify(mod.parseUplinkApplyVerdict({
  overall: 'applied',
  uplink_verification_status: 'uplink_dispatched_unverified',
}, { intent: 'teardown' })));
""",
    )
    assert result["success"] is True
    assert result["hubState"] == "SUCCESS"


def test_uplink_wifi_mutation_readiness_requires_live_params(tmp_path: Path) -> None:
    """Без live params мутация запрещена."""
    result = _run_export(
        tmp_path,
        label="readiness",
        script_body="""
console.log(JSON.stringify({
  empty: mod.evaluateUplinkWifiMutationReadiness({}, null),
  fake: mod.evaluateUplinkWifiMutationReadiness({}, 'fake'),
}));
""",
    )
    assert result["empty"]["allowed"] is False
    assert result["fake"]["allowed"] is False
    assert result["fake"]["mock"] is True


def test_uplink_wifi_form_validation_blocks_open_and_short_password(tmp_path: Path) -> None:
    """OPEN сеть и короткий пароль блокируются в UI."""
    result = _run_export(
        tmp_path,
        label="validate",
        script_body="""
console.log(JSON.stringify({
  open: mod.validateUplinkWifiForm({
    ssid: 'FreeWiFi',
    password: 'long-enough',
    openNetwork: true,
  }),
  short: mod.validateUplinkWifiForm({ ssid: 'Net', password: 'short' }),
  ok: mod.validateUplinkWifiForm({ ssid: 'Net', password: 'long-enough-8' }),
}));
""",
    )
    assert result["open"]["valid"] is False
    assert result["short"]["valid"] is False
    assert result["ok"]["valid"] is True


def test_uplink_wifi_notes_simple_russian_no_jargon() -> None:
    """Константы UI — простой русский, без Uplink/Station/AccessPoint."""
    source = UPLINK_MODEL_JS.read_text(encoding="utf-8")
    for const in (
        "UPLINK_WIFI_DISTINCTION_NOTE",
        "UPLINK_WIFI_SCAN_NOTE",
        "UPLINK_WIFI_PASSWORD_FIELD_NOTE",
    ):
        match = re.search(rf"export const {const}\s*=\s*\n?\s*'([^']+)'", source)
        assert match is not None, const
        text = match.group(1)
        assert CYRILLIC.search(text)
        for forbidden in ("Uplink", "Station", "AccessPoint", "WISP", "WifiWan"):
            assert forbidden not in text


def test_uplink_wifi_screen_registered_in_menu() -> None:
    """AC-1: экран в menuScreens между connection и staff-wifi."""
    source = SCREENS_INDEX_JS.read_text(encoding="utf-8")
    assert "internet-uplink" in source
    assert "internetUplink" in source
    menu_match = re.search(r"export const menuScreens = \[([\s\S]*?)\];", source)
    assert menu_match is not None
    menu_block = menu_match.group(1)
    connection_pos = menu_block.index("connection")
    uplink_pos = menu_block.index("internetUplink")
    staff_pos = menu_block.index("staffWifi")
    assert connection_pos < uplink_pos < staff_pos


def test_uplink_wifi_screen_meta_and_risk_modal() -> None:
    """meta.id/title и buildRiskModalBody (не buildWifiRiskModalBody)."""
    source = UPLINK_SCREEN_JS.read_text(encoding="utf-8")
    assert "id: 'internet-uplink'" in source
    assert "title: 'Интернет'" in source
    assert "iconName: 'connection'" in source
    assert "buildRiskModalBody" in source
    assert "buildWifiRiskModalBody" not in source
    assert "parseUplinkApplyVerdict" in source
    assert "parseWifiApplyVerdict" not in source


def test_uplink_wifi_scan_surveys_both_radios(tmp_path: Path) -> None:
    """scanUplinkWifiNetworks: dual-radio POST to WifiMaster0 and WifiMaster1."""
    session = _full_session()
    result = _run_export(
        tmp_path,
        label="scan-dual-radio",
        script_body=f"""
const session = {json.dumps(session)};
const captured = [];
globalThis.fetch = async (url, init = {{}}) => {{
  const urlStr = String(url);
  if (urlStr.includes('192.168.2.1')) {{
    throw new Error('forbidden fetch target');
  }}
  let body = {{}};
  if (init?.body) {{
    body = JSON.parse(String(init.body));
  }}
  captured.push({{
    url: urlStr,
    method: init?.method ?? 'GET',
    body,
  }});
  if (!urlStr.includes('wifi/site-survey')) {{
    throw new Error(`unexpected fetch: ${{urlStr}}`);
  }}
  const radio = body.radio;
  const networks = radio === 'WifiMaster0'
    ? [{{ ssid: 'Alpha-24', wpa_mode: 'WPA2', rssi: 55 }}]
    : [{{ ssid: 'Beta-5', wpa_mode: 'WPA2', rssi: 70 }}];
  return {{
    ok: true,
    status: 200,
    headers: {{ get: () => 'application/json' }},
    json: async () => ({{ networks }}),
    text: async () => JSON.stringify({{ networks }}),
  }};
}};

const merged = await mod.scanUplinkWifiNetworks(session);
console.log(JSON.stringify({{
  captured,
  mergedCount: merged.length,
  ssids: merged.map((n) => n.ssid),
  bands: merged.map((n) => n.band),
  surveyRadios: captured.map((c) => c.body.radio),
  surveyHosts: captured.map((c) => c.body.host),
  surveyMethods: captured.map((c) => c.method),
}}));
""",
    )
    assert result["mergedCount"] == 2
    assert set(result["surveyRadios"]) == {"WifiMaster0", "WifiMaster1"}
    assert len(result["captured"]) == 2
    assert all(method == "POST" for method in result["surveyMethods"])
    assert all(host == "10.0.0.1" for host in result["surveyHosts"])
    assert "Beta-5" in result["ssids"]
    assert "Alpha-24" in result["ssids"]


def test_uplink_wifi_preview_http_body_matches_schema(tmp_path: Path) -> None:
    """previewUplinkWifiConnection sends only preview fields (no live connection params)."""
    session = _full_session()
    result = _run_export(
        tmp_path,
        label="preview-http",
        script_body=f"""
const session = {json.dumps(session)};
const previewBody = mod.buildStationPreviewBody({{
  ssid: 'Venue-Net',
  band: 'BAND_5GHZ',
  credentialRefId: 'cred-uplink-1',
}});
let capturedBody = null;
globalThis.fetch = async (url, init = {{}}) => {{
  const urlStr = String(url);
  if (urlStr.includes('192.168.2.1')) {{
    throw new Error('forbidden fetch target');
  }}
  if (init?.body) {{
    capturedBody = JSON.parse(String(init.body));
  }}
  if (!urlStr.includes('wifi/station/preview')) {{
    throw new Error(`unexpected fetch: ${{urlStr}}`);
  }}
  return {{
    ok: true,
    status: 200,
    headers: {{ get: () => 'application/json' }},
    json: async () => ({{ overall: 'preview_ok' }}),
    text: async () => JSON.stringify({{ overall: 'preview_ok' }}),
  }};
}};

await mod.previewUplinkWifiConnection({{ previewBody, session }});
console.log(JSON.stringify({{ capturedBody }}));
""",
    )
    body = result["capturedBody"]
    assert body is not None
    assert body["mode"] == "WifiWan"
    assert body["ssid"] == "Venue-Net"
    assert body["credential_ref_id"] == "cred-uplink-1"
    assert "host" not in body
    assert "router_credential_ref_id" not in body
    assert set(body.keys()) <= WIFI_STATION_PREVIEW_ALLOWED_KEYS


def test_uplink_wifi_apply_http_body_matches_schema(tmp_path: Path) -> None:
    """applyUplinkWifiConnection HTTP body includes live fields within apply schema."""
    session = _full_session()
    result = _run_export(
        tmp_path,
        label="apply-http",
        script_body=f"""
const session = {json.dumps(session)};
const previewBody = mod.buildStationPreviewBody({{
  ssid: 'Venue-Net',
  band: 'BAND_5GHZ',
  credentialRefId: 'cred-uplink-1',
}});
let capturedBody = null;
globalThis.fetch = async (url, init = {{}}) => {{
  const urlStr = String(url);
  if (urlStr.includes('192.168.2.1')) {{
    throw new Error('forbidden fetch target');
  }}
  if (init?.body) {{
    capturedBody = JSON.parse(String(init.body));
  }}
  if (!urlStr.includes('wifi/station/apply')) {{
    throw new Error(`unexpected fetch: ${{urlStr}}`);
  }}
  return {{
    ok: true,
    status: 200,
    headers: {{ get: () => 'application/json' }},
    json: async () => ({{ overall: 'applied' }}),
    text: async () => JSON.stringify({{ overall: 'applied' }}),
  }};
}};

await mod.applyUplinkWifiConnection({{ previewBody, session }});
console.log(JSON.stringify({{ capturedBody }}));
""",
    )
    body = result["capturedBody"]
    assert body is not None
    assert body["confirm_live_apply"] is True
    assert body["host"] == "10.0.0.1"
    assert body["username"] == "admin"
    assert body["router_credential_ref_id"] == "cred-ref-1"
    assert body["ssh_host_key_sha256"] == REALISTIC_FINGERPRINT
    assert body["source_address"] == "192.168.2.144"
    assert body["router_id"] == "router-lab-1"
    assert set(body.keys()) <= WIFI_STATION_APPLY_ALLOWED_KEYS


def test_uplink_wifi_teardown_http_body_matches_schema(tmp_path: Path) -> None:
    """teardownUplinkWifiConnection HTTP body includes live fields within teardown schema."""
    session = _full_session()
    result = _run_export(
        tmp_path,
        label="teardown-http",
        script_body=f"""
const session = {json.dumps(session)};
let capturedBody = null;
globalThis.fetch = async (url, init = {{}}) => {{
  const urlStr = String(url);
  if (urlStr.includes('192.168.2.1')) {{
    throw new Error('forbidden fetch target');
  }}
  if (init?.body) {{
    capturedBody = JSON.parse(String(init.body));
  }}
  if (!urlStr.includes('wifi/station/teardown')) {{
    throw new Error(`unexpected fetch: ${{urlStr}}`);
  }}
  return {{
    ok: true,
    status: 200,
    headers: {{ get: () => 'application/json' }},
    json: async () => ({{ overall: 'applied' }}),
    text: async () => JSON.stringify({{ overall: 'applied' }}),
  }};
}};

await mod.teardownUplinkWifiConnection({{
  ssid: 'Venue-Net',
  band: 'BAND_5GHZ',
  credentialRefId: 'cred-uplink-1',
  session,
}});
console.log(JSON.stringify({{ capturedBody }}));
""",
    )
    body = result["capturedBody"]
    assert body is not None
    assert body["confirm_live_teardown"] is True
    assert body["host"] == "10.0.0.1"
    assert body["username"] == "admin"
    assert body["router_credential_ref_id"] == "cred-ref-1"
    assert set(body.keys()) <= WIFI_STATION_TEARDOWN_ALLOWED_KEYS


def test_uplink_wifi_merge_survey_deduplicates_by_ssid_band(tmp_path: Path) -> None:
    """mergeSurveyNetworks дедуплицирует по ssid+band."""
    result = _run_export(
        tmp_path,
        label="merge",
        script_body="""
const merged = mod.mergeSurveyNetworks([
  { radio: 'WifiMaster0', networks: [{ ssid: 'Alpha', wpa_mode: 'WPA2', rssi: 50 }] },
  { radio: 'WifiMaster0', networks: [{ ssid: 'Alpha', wpa_mode: 'WPA2', rssi: 40 }] },
  { radio: 'WifiMaster1', networks: [{ ssid: 'Beta', wpa_mode: 'WPA2', rssi: 70 }] },
]);
console.log(JSON.stringify({
  count: merged.length,
  ssids: merged.map((n) => n.ssid),
  bands: merged.map((n) => n.band),
}));
""",
    )
    assert result["count"] == 2
    assert result["ssids"] == ["Beta", "Alpha"]
    assert result["bands"] == ["BAND_5GHZ", "BAND_2_4GHZ"]


INTERNET_SOURCE_BLOCK_JS = HUB / "features" / "internet-source-block.js"


def _run_block_export(tmp_path: Path, *, label: str, script_body: str) -> object:
    script = (
        f"const mod = await import({json.dumps(INTERNET_SOURCE_BLOCK_JS.as_uri())});\n"
        f"{script_body}"
    )
    return _run_node_harness(script, tmp_path, label)


def test_describe_internet_source_unknown_until_read(tmp_path: Path) -> None:
    """AC-1: «источник неизвестен» пока нет успешного observe."""
    result = _run_block_export(
        tmp_path,
        label="source-unknown",
        script_body="""
console.log(JSON.stringify({
  nullObs: mod.describeInternetSource(null),
  failed: mod.describeInternetSource({ read_status: 'failed' }),
}));
""",
    )
    assert result["nullObs"]["label"] == "источник неизвестен"
    assert result["failed"]["label"] == "источник неизвестен"


def test_describe_internet_source_wifi_wired_vpn(tmp_path: Path) -> None:
    """describeInternetSource: Wi‑Fi / провод / VPN по gateway_interface."""
    result = _run_block_export(
        tmp_path,
        label="source-kinds",
        script_body="""
console.log(JSON.stringify({
  wifi: mod.describeInternetSource({
    read_status: 'ok',
    gateway_interface: 'WifiMaster1/WifiStation0',
  }),
  wired: mod.describeInternetSource({
    read_status: 'ok',
    gateway_interface: 'GigabitEthernet0',
  }),
  vpn: mod.describeInternetSource({
    read_status: 'ok',
    gateway_interface: 'Wireguard5',
  }),
}));
""",
    )
    assert result["wifi"]["kind"] == "wifi"
    assert result["wifi"]["label"] == "Wi‑Fi"
    assert result["wired"]["kind"] == "wired"
    assert "Провод" in result["wired"]["label"]
    assert result["vpn"]["kind"] == "vpn"


def test_describe_internet_source_wifi_prefers_gateway_ssid(tmp_path: Path) -> None:
    """gateway_ssid present → quoted SSID detail; absent → raw interface fallback."""
    result = _run_block_export(
        tmp_path,
        label="source-wifi-ssid",
        script_body="""
console.log(JSON.stringify({
  withSsid: mod.describeInternetSource({
    read_status: 'ok',
    gateway_interface: 'WifiMaster1/WifiStation0',
    gateway_ssid: 'Cafe-Upstream',
  }),
  withoutSsid: mod.describeInternetSource({
    read_status: 'ok',
    gateway_interface: 'WifiMaster1/WifiStation0',
  }),
  emptySsid: mod.describeInternetSource({
    read_status: 'ok',
    gateway_interface: 'WifiMaster1/WifiStation0',
    gateway_ssid: '   ',
  }),
}));
""",
    )
    assert result["withSsid"]["detail"] == "«Cafe-Upstream»"
    assert result["withoutSsid"]["detail"] == "WifiMaster1/WifiStation0"
    assert result["emptySsid"]["detail"] == "WifiMaster1/WifiStation0"


def test_normalize_router_internet_observe_passes_through_gateway_ssid(tmp_path: Path) -> None:
    """Regression: normalizeRouterInternetObserve must not drop gateway_ssid.

    Root-cause of a real bug found live 2026-08-07: the raw API response from
    POST /internet-status/observe already carried gateway_ssid, but this
    normalizer (the actual path used by the «Интернет» screen) whitelisted
    fields without it, silently downgrading the UI to the raw technical
    interface id even though describeInternetSource() itself (tested in
    isolation elsewhere in this file) correctly prefers the SSID when present.
    """
    script = (
        f"const mod = await import({json.dumps(DIAGNOSTICS_MODEL_JS.as_uri())});\n"
        "console.log(JSON.stringify({\n"
        "  withSsid: mod.normalizeRouterInternetObserve({\n"
        "    read_status: 'ok',\n"
        "    internet: true,\n"
        "    gateway_interface: 'WifiMaster1/WifiStation0',\n"
        "    gateway_ssid: 'Netcraze-7619',\n"
        "  }),\n"
        "  withoutSsid: mod.normalizeRouterInternetObserve({\n"
        "    read_status: 'ok',\n"
        "    gateway_interface: 'Wireguard9',\n"
        "  }),\n"
        "  nonStringSsidIgnored: mod.normalizeRouterInternetObserve({\n"
        "    read_status: 'ok',\n"
        "    gateway_ssid: 42,\n"
        "  }),\n"
        "}));\n"
    )
    result = _run_node_harness(script, tmp_path, "normalize-observe-ssid")
    assert result["withSsid"]["gateway_ssid"] == "Netcraze-7619"
    assert result["withoutSsid"]["gateway_ssid"] is None
    assert result["nonStringSsidIgnored"]["gateway_ssid"] is None


def test_describe_remembered_uplink_separate_from_live(tmp_path: Path) -> None:
    """AC-1: запомненное — отдельная строка, не live gateway."""
    result = _run_block_export(
        tmp_path,
        label="remembered-line",
        script_body="""
console.log(JSON.stringify({
  inactive: mod.describeRememberedUplink({ desired_active: false, ssid: 'X' }),
  active: mod.describeRememberedUplink({
    desired_active: true,
    ssid: 'Cafe',
    band: 'BAND_2_4GHZ',
    credential_configured: true,
  }),
}));
""",
    )
    assert result["inactive"] is None
    assert "Запомнено" in result["active"]
    assert "Cafe" in result["active"]


def test_persist_remembered_uplink_put_body_uses_credential_ref_only(
    tmp_path: Path,
) -> None:
    """AC-6: PUT remembered-uplink — только credential_ref_id, без password."""
    result = _run_export(
        tmp_path,
        label="remembered-put",
        script_body="""
let captured = null;
globalThis.fetch = async (url, init = {}) => {
  if (init?.body) captured = JSON.parse(String(init.body));
  return {
    ok: true,
    status: 200,
    headers: { get: () => 'application/json' },
    json: async () => ({ desired_active: true }),
    text: async () => '{}',
  };
};
await mod.persistRememberedUplinkAfterApply({
  routerId: 'router-1',
  ssid: 'Net',
  band: 'BAND_5GHZ',
  credentialRefId: 'cred-ref-only',
});
console.log(JSON.stringify({ captured }));
""",
    )
    body = result["captured"]
    assert body is not None
    assert body["credential_ref_id"] == "cred-ref-only"
    assert body["desired_active"] is True
    assert "password" not in body


def test_internet_uplink_screen_uses_source_block() -> None:
    """AC-4/AC-5: экран монтирует mountInternetSourceAffordance."""
    source = UPLINK_SCREEN_JS.read_text(encoding="utf-8")
    assert "mountInternetSourceAffordance" in source
    assert "internet-source-block.js" in source
    assert "fetchRouterInternetObserve" in source
    assert "fetchRememberedUplink" in source
    assert "persistRememberedUplinkAfterApply" in source
    assert "rebuildSlot" in source
    assert "20–30 секунд" in source


def test_internet_uplink_run_mutation_toast_tone_from_hub_state() -> None:
    """Apply toast tone uses getStateDescriptor(hubState) when !success."""
    source = UPLINK_SCREEN_JS.read_text(encoding="utf-8")
    assert "getStateDescriptor" in source
    run_mutation_start = source.find("async function runMutation(")
    assert run_mutation_start != -1
    run_mutation_region = source[run_mutation_start : run_mutation_start + 3000]
    assert "getStateDescriptor(lastVerdict.hubState).tone" in run_mutation_region
    assert "Object.values(HubState).includes(lastVerdict.hubState)" in run_mutation_region
    assert "tone: lastVerdict.success ? 'success' : 'warning'" not in run_mutation_region


def test_internet_uplink_connect_persist_failure_shows_warning_with_retry() -> None:
    """Connect path: persist failure warns + operationRetry, not silent swallow."""
    source = UPLINK_SCREEN_JS.read_text(encoding="utf-8")
    connect_start = source.find("if (succeeded && action === 'connect')")
    assert connect_start != -1
    connect_region = source[connect_start : connect_start + 2800]
    assert "persistRememberedUplinkAfterApply" in connect_region
    assert "operationError = error" in connect_region
    assert "operationRetry = async () =>" in connect_region
    assert "tone: 'warning'" in connect_region
    assert "Не удалось сохранить автоподключение" in connect_region
    assert "Нажмите «Повторить»" in connect_region
    assert "remembered persistence failure must not mask apply verdict" not in connect_region


def test_internet_uplink_teardown_persist_failure_shows_warning_with_retry() -> None:
    """Teardown path: deactivate failure warns + operationRetry (mirror contract)."""
    source = UPLINK_SCREEN_JS.read_text(encoding="utf-8")
    teardown_start = source.find("if (succeeded && action === 'teardown')")
    assert teardown_start != -1
    teardown_region = source[teardown_start : teardown_start + 2200]
    assert "deactivateRememberedUplink" in teardown_region
    assert "operationError = error" in teardown_region
    assert "operationRetry = async () =>" in teardown_region
    assert "Не удалось отключить автоподключение" in teardown_region
    assert "Нажмите «Повторить»" in teardown_region


def _extract_subscribe_connectivity_callback(source: str) -> str:
    marker = "subscribeConnectivity((online) => {"
    start = source.find(marker)
    assert start != -1, "subscribeConnectivity callback missing"
    brace = source.find("{", start + len(marker) - 1)
    depth = 0
    j = brace
    while j < len(source):
        if source[j] == "{":
            depth += 1
        elif source[j] == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1 : j]
        j += 1
    raise AssertionError("subscribeConnectivity callback body not closed")


def test_uplink_risk_modal_cancel_offline_stale_revokes_prepared_credential() -> None:
    """hub-offline-abort-followups: prepared credential revoked on cancel/offline/stale."""
    source = UPLINK_SCREEN_JS.read_text(encoding="utf-8")
    assert "function cancelPreparedMutation()" in source
    assert "function cancelPreparedMutation() {\n    revokePendingCredential();\n  }" in source
    risk_start = source.find("function openRiskModal(action, changeLines, onConfirm)")
    assert risk_start != -1
    risk_body = source[risk_start : risk_start + 3500]
    assert "if (!confirmed) {" in risk_body
    assert "cancelPreparedMutation();" in risk_body
    offline_confirm = risk_body.split("if (offline)", 1)[1]
    assert "cancelPreparedMutation();" in offline_confirm.split("await onConfirm", 1)[0]
    stale_confirm = risk_body.split("if (!uplinkIntentMatchesCurrent(intentSnapshot, current))", 1)[1]
    assert "cancelPreparedMutation();" in stale_confirm.split("await onConfirm", 1)[0]


def test_uplink_connectivity_offline_aborts_and_revokes_prepared_credential() -> None:
    """hub-offline-abort-followups: offline arm revokes prepared credential and aborts flows."""
    source = UPLINK_SCREEN_JS.read_text(encoding="utf-8")
    callback = _extract_subscribe_connectivity_callback(source)
    offline_arm_start = callback.find("if (!online)")
    assert offline_arm_start != -1
    offline_arm = callback[offline_arm_start:]
    offline_return = offline_arm.find("renderAll()")
    offline_block = offline_arm[: offline_return]
    assert "cancelPreparedMutation()" in offline_block
    assert "prepareAbort?.abort()" in offline_block
    assert "mutateAbort?.abort()" in offline_block
