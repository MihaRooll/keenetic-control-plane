"""DOM-harness tests for UI honesty defects (toast paths, manifest tips, a11y, copy)."""

from __future__ import annotations

import json

import pytest

from tests.test_config_ui import WEB, _run_ui_dom_runtime

MANIFEST_PATH = WEB / "ui-field-manifest.json"

VERIFY_MISMATCH_WIFI = {
    "overall": "verify_mismatch",
    "on_air_verification_status": "on_air_unverified",
}

VERIFY_MISMATCH_STATION = {
    "overall": "verify_mismatch",
    "uplink_verification_status": "uplink_dispatched_unverified",
}

VERIFY_MISMATCH_AWG = {
    "overall": "verify_mismatch",
    "tunnel_verification_status": "tunnel_unverified",
}

_FLUSH_ASYNC = """
async function flushUiAsync() {
  await new Promise((r) => setImmediate(r));
  await new Promise((r) => setImmediate(r));
}
"""


def _async_dom_script(body: str) -> str:
    return f"""
(async () => {{
{body}
}})().catch((err) => {{
  console.error(err && err.stack ? err.stack : String(err));
  process.exit(1);
}});
"""

_SETUP_STUB = """
uiExports.resetToastCaptureForTest();
uiExports.setApiFetchStubForTest(async (path, options) => {
  const action = globalThis.__TEST_APPLY_RESPONSE__;
  if (!action || !action[path]) {
    throw new Error("unexpected apiFetch path: " + path);
  }
  return { data: action[path], status: 200 };
});
"""


def _minimal_wifi_manifest() -> dict:
    full = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    fields = full["families"]["wifi_ap"]["fields"]
    ssid = next(f for f in fields if f["name"] == "ssid")
    return {
        "families": {
            "wifi_ap": {
                "fields": [ssid],
            },
        },
    }


def _load_manifest_in_dom_script() -> str:
    return r"""
const manifestPath = process.argv[1].replace(/app\.js$/, "ui-field-manifest.json");
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
uiExports.setFieldManifestForTest(manifest);
"""


def _full_manifest_json() -> str:
    return json.dumps(
        json.loads(MANIFEST_PATH.read_text(encoding="utf-8")),
        ensure_ascii=False,
    )


def _prepare_wifi_apply_dom() -> str:
    return """
document.body.appendChild(ui.panel);
ui.ui.advancedDetails.open = true;
document.getElementById("wifi-apply-ssid").value = "Test-SSID";
document.getElementById("wifi-apply-ap-id").value = "WifiMaster0/AccessPoint3";
document.getElementById("wifi-apply-wpa-mode").value = "WPA2";
document.getElementById("wifi-apply-confirm").checked = true;
"""


def _prepare_awg_apply_dom() -> str:
    return """
document.body.appendChild(ui.panel);
ui.ui.advancedDetails.open = true;
document.getElementById("awg-apply-wg-id").value = "Wireguard5";
document.getElementById("awg-apply-peer-pubkey").value = "peerPubKeyBase64==";
document.getElementById("awg-apply-confirm").checked = true;
"""


def _prepare_station_apply_dom() -> str:
    return """
document.body.appendChild(harness.form);
document.getElementById("uplink-station-confirm").checked = true;
"""


def _prepare_uplink_ap_dom() -> str:
    return """
document.body.appendChild(harness.panel);
document.getElementById("uplink-ap-ssid").value = "Staff-Field";
document.getElementById("uplink-ap-confirm").checked = true;
"""


def _assert_toast_not_success(toast_text: str) -> None:
    prefix_only = toast_text.split(" — ")[0]
    lower = prefix_only.lower()
    assert "VERIFY MISMATCH" in toast_text, toast_text
    assert "dispatched" not in lower, toast_text
    assert ": applied" not in lower, toast_text
    assert "verified on-air" not in lower, toast_text


@pytest.mark.parametrize(
    (
        "path_id",
        "harness_builder",
        "prepare_dom",
        "btn_testid",
        "api_path",
        "response_data",
        "toast_action",
    ),
    [
        (
            "P-wifi-apply",
            "buildWifiApplyActionHarness",
            _prepare_wifi_apply_dom(),
            "wifi-apply-action-btn",
            "/wifi/apply",
            VERIFY_MISMATCH_WIFI,
            "Apply",
        ),
        (
            "P-wifi-teardown",
            "buildWifiApplyActionHarness",
            _prepare_wifi_apply_dom(),
            "wifi-teardown-action-btn",
            "/wifi/teardown",
            VERIFY_MISMATCH_WIFI,
            "Teardown",
        ),
        (
            "P-awg-apply",
            "buildAwgApplyActionHarness",
            _prepare_awg_apply_dom(),
            "awg-apply-action-btn",
            "/wireguard/apply",
            VERIFY_MISMATCH_AWG,
            "Apply",
        ),
        (
            "P-awg-teardown",
            "buildAwgApplyActionHarness",
            _prepare_awg_apply_dom(),
            "awg-teardown-action-btn",
            "/wireguard/teardown",
            VERIFY_MISMATCH_AWG,
            "Teardown",
        ),
        (
            "P-station-apply",
            "buildStationApplyActionHarness",
            _prepare_station_apply_dom(),
            "station-apply-action-btn",
            "/wifi/station/apply",
            VERIFY_MISMATCH_STATION,
            "Apply",
        ),
        (
            "P-station-teardown",
            "buildStationApplyActionHarness",
            _prepare_station_apply_dom(),
            "station-teardown-action-btn",
            "/wifi/station/teardown",
            VERIFY_MISMATCH_STATION,
            "Teardown",
        ),
        (
            "P-uplink-ap-apply",
            "buildUplinkApApplyActionHarness",
            _prepare_uplink_ap_dom(),
            "uplink-ap-apply-action-btn",
            "/wifi/apply",
            VERIFY_MISMATCH_WIFI,
            "Apply",
        ),
    ],
)
def test_ui_apply_toast_path_binding_via_click_handlers(
    path_id: str,
    harness_builder: str,
    prepare_dom: str,
    btn_testid: str,
    api_path: str,
    response_data: dict,
    toast_action: str,
) -> None:
    """Click handlers must route apply responses through APPLY_TOAST_PATHS registry."""
    response_json = json.dumps(response_data)
    action_json = json.dumps(toast_action)
    script = _async_dom_script(f"""
{_FLUSH_ASYNC}
{_load_manifest_in_dom_script()}
{_SETUP_STUB}
globalThis.__TEST_APPLY_RESPONSE__ = {{ {json.dumps(api_path)}: {response_json} }};
const ui = uiExports.{harness_builder}({{ expendable: false }});
const harness = ui;
{prepare_dom}
const btn = dom.queryByTestId({json.dumps(btn_testid)}, document.body);
if (!btn) throw new Error("button not found: " + {json.dumps(btn_testid)});
btn.click();
await flushUiAsync();
const toasts = uiExports.getCapturedToastsForTest();
let expectedFromRegistry = null;
const pathId = {json.dumps(path_id)};
const action = {action_json};
if (pathId === "P-uplink-ap-apply") {{
  expectedFromRegistry = uiExports.buildUplinkApApplyToast({response_json});
}} else if (pathId.startsWith("P-wifi")) {{
  expectedFromRegistry = uiExports.formatWifiApplyToast({response_json}, action);
}} else if (pathId.startsWith("P-awg")) {{
  expectedFromRegistry = uiExports.formatAwgApplyToast({response_json}, action);
}} else if (pathId.startsWith("P-station")) {{
  expectedFromRegistry = uiExports.formatStationApplyToast({response_json}, action);
}}
console.log(JSON.stringify({{
  path_id: pathId,
  toasts,
  last_toast: toasts.length ? toasts[toasts.length - 1] : null,
  registry_has_path: !!uiExports.APPLY_TOAST_PATHS[pathId],
  expected_from_registry: expectedFromRegistry,
  handler_used_registry:
    toasts.length && expectedFromRegistry
      ? toasts[toasts.length - 1] === expectedFromRegistry
      : false,
}}));
""")
    result = _run_ui_dom_runtime(script)
    assert result["registry_has_path"] is True, result
    assert result["last_toast"], result
    _assert_toast_not_success(str(result["last_toast"]))
    assert result["handler_used_registry"] is True, result


def test_ui_apply_toast_path_binding_breaks_on_false_success_toast() -> None:
    """Red test: mutating APPLY_TOAST_PATHS to a false-success toast must fail binding."""
    response_json = json.dumps(VERIFY_MISMATCH_WIFI)
    script = _async_dom_script(f"""
{_FLUSH_ASYNC}
{_load_manifest_in_dom_script()}
{_SETUP_STUB}
globalThis.__TEST_APPLY_RESPONSE__ = {{ "/wifi/apply": {response_json} }};
const original = uiExports.APPLY_TOAST_PATHS["P-wifi-apply"].toastFromResponse;
uiExports.APPLY_TOAST_PATHS["P-wifi-apply"].toastFromResponse = function() {{
  globalThis.__ROUTER_CONTROL_TOAST_CAPTURE__.push("AP apply OK");
}};
const ui = uiExports.buildWifiApplyActionHarness({{ expendable: false }});
document.body.appendChild(ui.panel);
ui.ui.advancedDetails.open = true;
document.getElementById("wifi-apply-ssid").value = "Test-SSID";
document.getElementById("wifi-apply-ap-id").value = "WifiMaster0/AccessPoint3";
document.getElementById("wifi-apply-wpa-mode").value = "WPA2";
document.getElementById("wifi-apply-confirm").checked = true;
const btn = dom.queryByTestId("wifi-apply-action-btn", document.body);
btn.click();
await flushUiAsync();
const toasts = uiExports.getCapturedToastsForTest();
const honest = uiExports.formatWifiApplyToast({response_json}, "Apply");
console.log(JSON.stringify({{
  last_toast: toasts.length ? toasts[toasts.length - 1] : null,
  honest_expected: honest,
  binding_ok:
    toasts.length
    && toasts[toasts.length - 1] === honest,
  looks_false_success:
    toasts.length
    && toasts[toasts.length - 1] === "AP apply OK",
}}));
uiExports.APPLY_TOAST_PATHS["P-wifi-apply"].toastFromResponse = original;
""")
    result = _run_ui_dom_runtime(script)
    assert result["binding_ok"] is False, result
    assert result["looks_false_success"] is True, result


def test_ui_wifi_control_aria_describedby_links_tooltip() -> None:
    manifest = _minimal_wifi_manifest()
    script = f"""
uiExports.setFieldManifestForTest({json.dumps(manifest, ensure_ascii=False)});
const ui = uiExports.buildWifiApplyFormSurface({{ expendable: false }});
document.body.appendChild(ui.panel);
const control = document.getElementById("wifi-apply-ssid");
const tooltipId = control ? control.getAttribute("aria-describedby") : null;
const tooltip = tooltipId ? document.getElementById(tooltipId) : null;
const trigger = dom.queryByTestId("wifi-apply-ssid-tooltip", ui.form);
console.log(JSON.stringify({{
  control_has_describedby: !!tooltipId,
  tooltip_exists: !!tooltip,
  trigger_no_describedby: trigger ? !trigger.getAttribute("aria-describedby") : false,
  trigger_aria_label_ok: trigger ? trigger.getAttribute("aria-label") === "Подсказка" : false,
}}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["control_has_describedby"] is True
    assert result["tooltip_exists"] is True
    assert result["trigger_no_describedby"] is True
    assert result["trigger_aria_label_ok"] is True


def test_ui_manifest_tooltip_matches_json_for_wifi_ssid() -> None:
    manifest = _minimal_wifi_manifest()
    expected = manifest["families"]["wifi_ap"]["fields"][0]["tooltip"]
    script = f"""
uiExports.setFieldManifestForTest({json.dumps(manifest, ensure_ascii=False)});
const ui = uiExports.buildWifiApplyFormSurface({{ expendable: false }});
document.body.appendChild(ui.panel);
const tooltipId = document.getElementById("wifi-apply-ssid").getAttribute("aria-describedby");
const tooltip = document.getElementById(tooltipId);
console.log(JSON.stringify({{
  text: tooltip ? tooltip.textContent : null,
  expected: {json.dumps(expected, ensure_ascii=False)},
}}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["text"] == result["expected"]
    assert "SSID" in str(result["text"])


def test_ui_manifest_unavailable_fail_closed_tooltip() -> None:
    script = r"""
uiExports.setFieldManifestForTest(null, "unavailable");
const ui = uiExports.buildWifiApplyFormSurface({ expendable: false });
document.body.appendChild(ui.panel);
const tooltipId = document.getElementById("wifi-apply-ssid").getAttribute("aria-describedby");
const tooltip = document.getElementById(tooltipId);
console.log(JSON.stringify({
  text: tooltip ? tooltip.textContent : null,
  state: uiExports.getFieldManifestState(),
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["state"] == "unavailable"
    assert result["text"] and "манифеста" in result["text"]


def test_ui_manifest_defaults_applied_to_wifi_controls() -> None:
    script = f"""
{_load_manifest_in_dom_script()}
const ui = uiExports.buildWifiApplyFormSurface({{ expendable: false }});
document.body.appendChild(ui.panel);
ui.advancedDetails.open = true;
const enabled = document.getElementById("wifi-apply-enabled");
const compensate = document.getElementById("wifi-apply-compensate");
const idempotent = document.getElementById("wifi-apply-idempotent");
const captive = document.getElementById("wifi-apply-captive");
const guest = document.getElementById("wifi-apply-guest-isolation");
console.log(JSON.stringify({{
  enabled_checked: enabled ? enabled.checked : null,
  compensate_checked: compensate ? compensate.checked : null,
  idempotent_checked: idempotent ? idempotent.checked : null,
  captive_value: captive ? captive.value : null,
  guest_checked: guest ? guest.checked : null,
}}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["enabled_checked"] is False
    assert result["compensate_checked"] is True
    assert result["idempotent_checked"] is False
    assert result["captive_value"] == "Disabled"
    assert result["guest_checked"] is False


def test_ui_manifest_defaults_applied_to_awg_peer_rci_shape() -> None:
    script = f"""
{_load_manifest_in_dom_script()}
const ui = uiExports.buildAwgApplyFormSurface({{ expendable: false }});
document.body.appendChild(ui.panel);
ui.advancedDetails.open = true;
const shape = document.getElementById("awg-apply-peer-rci-shape");
const enabled = document.getElementById("awg-apply-enabled");
const tooltipId = shape ? shape.getAttribute("aria-describedby") : null;
console.log(JSON.stringify({{
  shape_value: shape ? shape.value : null,
  enabled_checked: enabled ? enabled.checked : null,
  has_tooltip: !!tooltipId,
}}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["shape_value"] == "nested_rci"
    assert result["enabled_checked"] is False
    assert result["has_tooltip"] is True


def test_ui_copy_honesty_vpn_rci_deploy_source() -> None:
    """Secondary static grep; primary honesty is DOM in test_ui_remaining_surfaces."""
    source = (WEB / "app.js").read_text(encoding="utf-8")
    assert "VPN/WG parse preview (vault only)" in source
    assert "VPN catalog import" in source
    assert "/vpn-profiles/import" in source
    assert "not device apply" in source
    assert "RCI FAKE ack (not device)" in source
    assert "SQLite synthetic ack" in source
    assert "Job queued (SQLite plan queue, not device apply)" in source
    assert "AP apply dispatched" not in source


def test_ui_toast_apply_family_result_red_green() -> None:
    """Red→green: format helpers must match prefix + honesty composition."""
    data = VERIFY_MISMATCH_WIFI
    script = f"""
const data = {json.dumps(data)};
const formatted = uiExports.formatWifiApplyToast(data, "Apply");
const prefix = uiExports.wifiApplyToastPrefix(data, "Apply");
const honesty = uiExports.wifiApplyHonestySummary(data);
const composed = prefix + (honesty ? " — " + honesty : "");
console.log(JSON.stringify({{
  formatted,
  composed,
  has_verify_mismatch: formatted.includes("VERIFY MISMATCH"),
  equals_composed: formatted === composed,
}}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["has_verify_mismatch"] is True
    assert result["equals_composed"] is True


@pytest.mark.parametrize(
    ("data", "must_contain", "must_not_contain"),
    [
        (
            {"on_air_verification_status": "on_air_verified"},
            ["unknown", "overall missing"],
            ["on-air verified (link up)", "NOT verified", "verified on-air"],
        ),
        (
            {
                "overall": "dispatched_offline",
                "on_air_verification_status": "on_air_verified",
            },
            ["unknown", "overall dispatched_offline"],
            ["on-air verified (link up)", "verified on-air", "NOT verified"],
        ),
        (
            None,
            ["unknown", "no result"],
            ["verified on-air", "on-air verified"],
        ),
    ],
    ids=["H1-no-overall", "H2-unknown-overall", "H3-null-data"],
)
def test_ui_wifi_apply_toast_honesty_three_states_via_dom(
    data: dict | None,
    must_contain: list[str],
    must_not_contain: list[str],
) -> None:
    """AC-H1..H3: primary verdict must not contradict secondary on-air honesty."""
    data_json = "null" if data is None else json.dumps(data)
    script = f"""
const formatted = uiExports.formatWifiApplyToast({data_json}, "Apply");
const prefix = uiExports.wifiApplyToastPrefix({data_json}, "Apply");
const honesty = uiExports.wifiApplyHonestySummary({data_json});
console.log(JSON.stringify({{
  formatted,
  prefix,
  honesty,
}}));
"""
    result = _run_ui_dom_runtime(script)
    formatted = str(result["formatted"])
    for needle in must_contain:
        assert needle in formatted, (needle, result)
    for forbidden in must_not_contain:
        assert forbidden not in formatted, (forbidden, result)
    if data is None:
        assert formatted == str(result["prefix"])
        assert result["honesty"] == ""
    else:
        assert " — " in formatted or not result["honesty"]


def test_ui_wifi_apply_toast_success_path_unchanged() -> None:
    """Success: overall=applied + on_air_verified stays verified on-air."""
    script = r"""
const data = { overall: "applied", on_air_verification_status: "on_air_verified" };
const formatted = uiExports.formatWifiApplyToast(data, "Apply");
console.log(JSON.stringify({ formatted }));
"""
    result = _run_ui_dom_runtime(script)
    assert "Apply verified on-air" in str(result["formatted"])
    assert "on-air verified (link up)" in str(result["formatted"])


def test_ui_dom_has_misleading_apply_success_exempt_requires_applied_overall() -> None:
    """domHasMisleadingApplySuccessText must not exempt on_air_verified without overall=applied."""
    script = r"""
const withoutApplied = uiExports.domHasMisleadingApplySuccessText(
  { on_air_verification_status: "on_air_verified" },
  "on-air verified (link up)",
);
const withApplied = uiExports.domHasMisleadingApplySuccessText(
  { overall: "applied", on_air_verification_status: "on_air_verified" },
  "on-air verified (link up)",
);
console.log(JSON.stringify({ withoutApplied, withApplied }));
"""
    result = _run_ui_dom_runtime(script)
    assert result["withoutApplied"] is True
    assert result["withApplied"] is False


def test_ui_station_apply_toast_honesty_uplink_gated_on_applied() -> None:
    """AC-H4: uplink_verified_bounded must not substitute success when overall not applied."""
    script = r"""
const data = { uplink_verification_status: "uplink_verified_bounded" };
const formatted = uiExports.formatStationApplyToast(data, "Apply");
const honesty = uiExports.stationApplyHonestySummary(data);
console.log(JSON.stringify({ formatted, honesty }));
"""
    result = _run_ui_dom_runtime(script)
    formatted = str(result["formatted"])
    assert "unknown" in formatted.lower()
    assert "overall missing" in formatted or "overall unknown" in formatted
    assert "uplink verified bounded" not in formatted
    assert "secondary — overall not applied" in formatted
    assert "uplink=uplink_verified_bounded" in formatted


def test_ui_station_apply_toast_success_path_uplink_verified_unchanged() -> None:
    """Success: overall=applied + uplink_verified_bounded keeps positive uplink secondary."""
    script = r"""
const data = {
  overall: "applied",
  uplink_verification_status: "uplink_verified_bounded",
};
const formatted = uiExports.formatStationApplyToast(data, "Apply");
console.log(JSON.stringify({ formatted }));
"""
    result = _run_ui_dom_runtime(script)
    formatted = str(result["formatted"])
    assert "verified bounded" in formatted
    assert "uplink verified bounded" in formatted
    assert "secondary — overall not applied" not in formatted


@pytest.mark.parametrize(
    ("data", "must_contain", "must_not_contain"),
    [
        (
            {
                "overall": "failed",
                "configuration_verification_status": "device_accepted_configuration",
                "tunnel_verification_status": "tunnel_healthy",
            },
            ["FAILED", "secondary — overall not applied"],
            ["configuration applied", "tunnel healthy (peer handshake"],
        ),
        (
            {
                "overall": "verify_mismatch",
                "configuration_verification_status": "device_accepted_configuration",
                "tunnel_verification_status": "tunnel_healthy",
            },
            ["VERIFY MISMATCH", "secondary — overall not applied"],
            ["configuration applied", "tunnel healthy (peer handshake"],
        ),
    ],
    ids=["H5-failed-overall", "H5-verify-mismatch-overall"],
)
def test_ui_awg_apply_toast_honesty_gated_on_applied(
    data: dict,
    must_contain: list[str],
    must_not_contain: list[str],
) -> None:
    """AC-H5: positive config/tunnel secondary gated on overall=applied."""
    script = f"""
const formatted = uiExports.formatAwgApplyToast({json.dumps(data)}, "Apply");
const honesty = uiExports.awgApplyHonestySummary({json.dumps(data)});
console.log(JSON.stringify({{ formatted, honesty }}));
"""
    result = _run_ui_dom_runtime(script)
    formatted = str(result["formatted"])
    for needle in must_contain:
        assert needle in formatted, (needle, result)
    for forbidden in must_not_contain:
        assert forbidden not in formatted, (forbidden, result)


def test_ui_awg_apply_toast_success_path_config_tunnel_unchanged() -> None:
    """Success: overall=applied keeps positive configuration and tunnel secondary."""
    script = r"""
const data = {
  overall: "applied",
  configuration_verification_status: "device_accepted_configuration",
  tunnel_verification_status: "tunnel_healthy",
};
const formatted = uiExports.formatAwgApplyToast(data, "Apply");
console.log(JSON.stringify({ formatted }));
"""
    result = _run_ui_dom_runtime(script)
    formatted = str(result["formatted"])
    assert "configuration applied" in formatted
    assert "tunnel healthy (peer handshake" in formatted
    assert "secondary — overall not applied" not in formatted
