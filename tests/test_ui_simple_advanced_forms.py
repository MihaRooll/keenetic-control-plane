"""DOM-harness tests for simple-by-default + advanced settings (P1–P3)."""

from __future__ import annotations

import json

from tests.test_config_ui import WEB, _run_ui_dom_runtime


def test_wifi_simple_fields_and_advanced_testids() -> None:
    script = r"""
const ui = uiExports.buildWifiApplyFormSurface({ expendable: false });
document.body.appendChild(ui.panel);
const advanced = dom.queryByTestId("wifi-apply-advanced-settings", ui.form);
const simpleIds = ["wifi-apply-ssid", "wifi-apply-psk-cred-ref", "wifi-apply-band"];
const advancedIds = [
  "wifi-apply-ap-id",
  "wifi-apply-wpa-mode",
  "wifi-apply-enabled",
  "wifi-apply-guest-isolation",
  "wifi-apply-captive",
  "wifi-apply-router-id",
  "wifi-apply-compensate",
  "wifi-apply-idempotent",
  "wifi-apply-host",
  "wifi-apply-username",
  "wifi-apply-router-cred-ref",
  "wifi-apply-ssh-pin",
  "wifi-apply-source-address",
  "wifi-apply-confirm",
];
const simplePresent = simpleIds.every((id) => !!document.getElementById(id));
const advancedPresent = advancedIds.every((id) => !!document.getElementById(id));
const guestHonesty = dom.queryByTestId("wifi-apply-guest-isolation-honesty", ui.form);
const captiveHonesty = dom.queryByTestId("wifi-apply-captive-honesty", ui.form);
console.log(JSON.stringify({
  simplePresent,
  advancedPresent,
  has_advanced_details: !!advanced,
  guest_honesty: guestHonesty ? guestHonesty.textContent : "",
  captive_honesty: captiveHonesty ? captiveHonesty.textContent : "",
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["simplePresent"] is True
    assert result["advancedPresent"] is True
    assert result["has_advanced_details"] is True
    assert "422 wifi.guest_isolation_unsupported" in str(result["guest_honesty"])
    assert "422 wifi.captive_portal_unsupported" in str(result["captive_honesty"])
    assert "zero ops" not in str(result["guest_honesty"]).lower()
    assert "zero ops" not in str(result["captive_honesty"]).lower()


def test_wifi_apply_payload_includes_live_connection_fields() -> None:
    script = r"""
const ui = uiExports.buildWifiApplyFormSurface({ expendable: false });
document.body.appendChild(ui.panel);
ui.advancedDetails.open = true;
const fills = {
  "wifi-apply-username": "lab-admin",
  "wifi-apply-router-cred-ref": "credref:router-mgmt",
  "wifi-apply-ssh-pin": "SHA256:abc123",
  "wifi-apply-source-address": "192.168.2.10",
};
for (const [id, val] of Object.entries(fills)) {
  const el = document.getElementById(id);
  if (el) el.value = val;
}
const payload = ui.readPayload(false);
console.log(JSON.stringify({
  payload_username: payload.username,
  payload_router_cred: payload.router_credential_ref_id,
  payload_pin: payload.ssh_host_key_sha256,
  payload_source: payload.source_address,
  keys: Object.keys(payload).sort(),
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["payload_username"] == "lab-admin"
    assert result["payload_router_cred"] == "credref:router-mgmt"
    assert result["payload_pin"] == "SHA256:abc123"
    assert result["payload_source"] == "192.168.2.10"
    for key in ("username", "router_credential_ref_id", "ssh_host_key_sha256", "source_address"):
        assert key in result["keys"]


def test_wifi_tooltip_aria_and_keyboard() -> None:
    manifest = json.loads((WEB / "ui-field-manifest.json").read_text(encoding="utf-8"))
    wifi_fields = manifest["families"]["wifi_ap"]["fields"]
    names = ("ssid", "credential_ref_id", "band")
    minimal = {
        "families": {
            "wifi_ap": {
                "fields": [f for f in wifi_fields if f["name"] in names],
            },
        },
    }
    manifest_json = json.dumps(minimal, ensure_ascii=False)
    script = f"""
uiExports.setFieldManifestForTest({manifest_json});
const ui = uiExports.buildWifiApplyFormSurface({{ expendable: false }});
document.body.appendChild(ui.panel);
const control = document.getElementById("wifi-apply-ssid");
const tooltipId = control ? control.getAttribute("aria-describedby") : null;
const tooltip = tooltipId ? document.getElementById(tooltipId) : null;
const trigger = dom.queryByTestId("wifi-apply-ssid-tooltip", ui.form);
if (trigger) trigger.focus();
const visibleOnFocus = tooltip && !tooltip.getAttribute("hidden");
if (trigger) trigger.click();
const visibleOnClick = tooltip && !tooltip.getAttribute("hidden");
if (trigger) trigger.click();
const hiddenOnSecondClick = tooltip && tooltip.getAttribute("hidden") != null;
if (trigger) {{
  trigger.focus();
  trigger.click();
}}
if (trigger) trigger.keydown("Escape");
const hiddenOnEscape = tooltip && tooltip.getAttribute("hidden") != null;
console.log(JSON.stringify({{
  has_control_describedby: !!tooltipId,
  has_trigger: !!trigger,
  role_tooltip: tooltip ? tooltip.getAttribute("role") : null,
  visible_on_focus: !!visibleOnFocus,
  visible_on_click: !!visibleOnClick,
  hidden_on_second_click: !!hiddenOnSecondClick,
  hidden_on_escape: !!hiddenOnEscape,
}}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["has_control_describedby"] is True
    assert result["has_trigger"] is True
    assert result["role_tooltip"] == "tooltip"
    assert result["visible_on_focus"] is True
    assert result["visible_on_click"] is True
    assert result["hidden_on_second_click"] is True
    assert result["hidden_on_escape"] is True


def test_awg_simple_advanced_and_path_style_honesty() -> None:
    script = r"""
const ui = uiExports.buildAwgApplyFormSurface({ expendable: false });
document.body.appendChild(ui.panel);
const closed = dom.collectVisibleText(ui.form);
ui.advancedDetails.open = true;
const open = dom.collectVisibleText(ui.form);
const shapeSelect = document.getElementById("awg-apply-peer-rci-shape");
let pathDisabled = false;
for (const child of shapeSelect.children || []) {
  if (child.tagName === "OPTION" && child.attributes.value === "path_style") {
    pathDisabled = child.getAttribute("disabled") != null;
  }
}
const payload = ui.readPayload(false);
console.log(JSON.stringify({
  closed_hides_asc: !closed.includes("ASC args"),
  open_shows_asc: open.includes("ASC args"),
  closed_shows_confirm: closed.includes("Подтверждаю live apply"),
  path_style_disabled: pathDisabled,
  payload_has_wg: !!payload.wg_id,
  payload_shape: payload.peer_rci_shape,
  has_router_id_field: !!document.getElementById("awg-apply-router-id"),
  no_compensate_field: !document.getElementById("awg-apply-compensate"),
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["closed_hides_asc"] is True
    assert result["open_shows_asc"] is True
    assert result["closed_shows_confirm"] is True
    assert result["path_style_disabled"] is True
    assert result["payload_has_wg"] is True
    assert result["payload_shape"] == "nested_rci"
    assert result["has_router_id_field"] is True
    assert result["no_compensate_field"] is True


def test_awg_apply_payload_includes_advanced_and_live_fields() -> None:
    script = r"""
const ui = uiExports.buildAwgApplyFormSurface({ expendable: false });
document.body.appendChild(ui.panel);
ui.advancedDetails.open = true;
const fills = {
  "awg-apply-asc-args": "1 2 3 4 5 6 7 8 9",
  "awg-apply-peer-pubkey": "peerPubKeyBase64==",
  "awg-apply-peer-endpoint": "vpn.example.com:51820",
  "awg-apply-peer-allow-ips": "10.0.0.0/24",
  "awg-apply-peer-keepalive": "25",
  "awg-apply-handshake-settle": "20",
  "awg-apply-username": "awg-admin",
  "awg-apply-router-cred-ref": "credref:awg-router",
  "awg-apply-ssh-pin": "SHA256:awgpin",
  "awg-apply-source-address": "192.168.2.11",
  "awg-apply-host": "192.168.2.1",
};
for (const [id, val] of Object.entries(fills)) {
  const el = document.getElementById(id);
  if (el) el.value = val;
}
const payload = ui.readPayload(true);
console.log(JSON.stringify({
  asc_args: payload.asc_args,
  peer_public_key: payload.peer_public_key,
  peer_endpoint: payload.peer_endpoint,
  peer_allow_ips: payload.peer_allow_ips,
  peer_keepalive_interval: payload.peer_keepalive_interval,
  handshake_settle_seconds: payload.handshake_settle_seconds,
  username: payload.username,
  router_credential_ref_id: payload.router_credential_ref_id,
  ssh_host_key_sha256: payload.ssh_host_key_sha256,
  source_address: payload.source_address,
  host: payload.host,
  confirm_live_apply: payload.confirm_live_apply,
  keys: Object.keys(payload).sort(),
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["asc_args"] == [1, 2, 3, 4, 5, 6, 7, 8, 9]
    assert result["peer_public_key"] == "peerPubKeyBase64=="
    assert result["peer_endpoint"] == "vpn.example.com:51820"
    assert result["peer_allow_ips"] == "10.0.0.0/24"
    assert result["peer_keepalive_interval"] == 25
    assert result["handshake_settle_seconds"] == 20
    assert result["username"] == "awg-admin"
    assert result["router_credential_ref_id"] == "credref:awg-router"
    assert result["ssh_host_key_sha256"] == "SHA256:awgpin"
    assert result["source_address"] == "192.168.2.11"
    assert result["host"] == "192.168.2.1"
    assert result["confirm_live_apply"] is False
    for key in (
        "asc_args",
        "peer_public_key",
        "peer_endpoint",
        "peer_allow_ips",
        "peer_keepalive_interval",
        "handshake_settle_seconds",
        "username",
        "router_credential_ref_id",
        "ssh_host_key_sha256",
        "source_address",
        "host",
    ):
        assert key in result["keys"]


def test_station_apply_form_all_body_fields() -> None:
    script = r"""
const ui = uiExports.buildUplinkStationApplyFormSurface();
document.body.appendChild(ui.form);
const intent = {
  ssid: "Venue-Net",
  band: "BAND_5GHZ",
  credential_ref_id: "credref:test",
  bssid: "aa:bb:cc:dd:ee:ff",
};
ui.updateIntentSummary(intent);
const bssidEl = document.getElementById("uplink-station-bssid");
if (bssidEl) bssidEl.value = intent.bssid;
ui.advancedDetails.open = true;
const settleEl = document.getElementById("uplink-station-settle");
if (settleEl) settleEl.value = "25";
const liveFills = {
  "uplink-station-username": "sta-admin",
  "uplink-station-ssh-pin": "SHA256:stapin",
  "uplink-station-source-address": "192.168.2.12",
};
for (const [id, val] of Object.entries(liveFills)) {
  const el = document.getElementById(id);
  if (el) el.value = val;
}
const payload = uiExports.readUplinkStationApplyPayloadFromDom(false, intent);
const fieldIds = [
  "uplink-station-mode",
  "uplink-station-priority",
  "uplink-station-auth-mode",
  "uplink-station-bssid",
  "uplink-station-settle",
  "uplink-station-router-id",
  "uplink-station-compensate",
  "uplink-station-idempotent",
  "uplink-station-host",
  "uplink-station-username",
  "uplink-station-router-cred-ref",
  "uplink-station-ssh-pin",
  "uplink-station-source-address",
  "uplink-station-confirm",
];
const openHonestyEl = dom.queryByTestId("uplink-station-auth-open-honesty", ui.form);
console.log(JSON.stringify({
  all_fields: fieldIds.every((id) => !!document.getElementById(id)),
  payload_keys: Object.keys(payload).sort(),
  auth_mode: payload.auth_mode,
  mode: payload.mode,
  uplink_settle_seconds: payload.uplink_settle_seconds,
  username: payload.username,
  ssh_host_key_sha256: payload.ssh_host_key_sha256,
  source_address: payload.source_address,
  open_honesty: openHonestyEl ? openHonestyEl.textContent : "",
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["all_fields"] is True
    for key in (
        "mode",
        "ssid",
        "band",
        "credential_ref_id",
        "priority",
        "auth_mode",
        "bssid",
        "uplink_settle_seconds",
        "username",
        "ssh_host_key_sha256",
        "source_address",
        "compensate_on_failure",
        "idempotent",
    ):
        assert key in result["payload_keys"]
    assert result["auth_mode"] == "wpa2_psk"
    assert result["mode"] == "WifiWan"
    assert result["uplink_settle_seconds"] == 25
    assert result["username"] == "sta-admin"
    assert result["ssh_host_key_sha256"] == "SHA256:stapin"
    assert result["source_address"] == "192.168.2.12"
    assert "open-network authentication grammar" in str(result["open_honesty"])


def test_harness_attribute_selector_and_dataset() -> None:
    script = r"""
const ui = uiExports.buildWifiApplyFormSurface({ expendable: false });
document.body.appendChild(ui.panel);
const byTestId = dom.queryByTestId("wifi-apply-ssid", ui.form);
console.log(JSON.stringify({
  found: !!byTestId,
  testid_attr: byTestId ? byTestId.getAttribute("data-testid") : null,
  dataset_testid: byTestId ? byTestId.dataset.testid : null,
  active_after_focus: (() => {
    if (!byTestId) return false;
    byTestId.focus();
    return document.activeElement === byTestId;
  })(),
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["found"] is True
    assert result["testid_attr"] == "wifi-apply-ssid"
    assert result["dataset_testid"] == "wifi-apply-ssid"
    assert result["active_after_focus"] is True


def test_harness_query_by_testid_rejects_wrong_dom() -> None:
    """Self-contained: queryByTestId must not match when data-testid is wrong."""
    script = r"""
const decoy = document.createElement("div");
decoy.setAttribute("data-testid", "wifi-apply-advanced-settings-BROKEN");
document.body.appendChild(decoy);
const ui = uiExports.buildWifiApplyFormSurface({ expendable: false });
document.body.appendChild(ui.panel);
const advanced = dom.queryByTestId("wifi-apply-advanced-settings", ui.form);
const decoyHit = dom.queryByTestId("wifi-apply-advanced-settings", decoy);
console.log(JSON.stringify({
  advanced_found: !!advanced,
  decoy_is_not_match: decoyHit === decoy,
  advanced_dataset: advanced ? advanced.dataset.testid : null,
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["advanced_found"] is True
    assert result["decoy_is_not_match"] is False
    assert result["advanced_dataset"] == "wifi-apply-advanced-settings"


def test_wifi_advanced_red_green_guard_testid() -> None:
    """Guard: breaking data-testid on advanced block must fail this assertion.

    Red command (mutation proof): in app.js change
    ``testId: "wifi-apply-advanced-settings"`` → ``"wifi-apply-advanced-settings-BROKEN"``,
    then run pytest on this test (see test name in module).
    Expected: ``AssertionError: assert False is True`` on ``advanced_found``.
    Restore testId and re-run for green.
    """
    script = r"""
const ui = uiExports.buildWifiApplyFormSurface({ expendable: false });
document.body.appendChild(ui.panel);
const advanced = dom.queryByTestId("wifi-apply-advanced-settings", ui.form);
console.log(JSON.stringify({
  advanced_found: !!advanced,
  advanced_testid: advanced ? advanced.dataset.testid : null,
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["advanced_found"] is True
    assert result["advanced_testid"] == "wifi-apply-advanced-settings"
