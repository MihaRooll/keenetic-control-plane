"""DOM-harness tests for remaining operator UI surfaces (VPN import, RCI, add-router)."""

from __future__ import annotations

import json

from tests.test_config_ui import WEB, _load_manifest_in_dom_script, _run_ui_dom_runtime

_FLUSH_ASYNC = r"""
async function flushUiAsync() {
  await new Promise((resolve) => setTimeout(resolve, 0));
}
"""

_FETCH_MANIFEST_MOCK = r"""
function installManifestFetchMock() {
  const manifestPath = process.argv[1].replace(/app\.js$/, "ui-field-manifest.json");
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  globalThis.fetch = async (url) => {
    if (String(url).includes("ui-field-manifest.json")) {
      return { ok: true, json: async () => manifest };
    }
    throw new Error("unexpected fetch: " + url);
  };
}
"""


def test_vpn_import_simple_advanced_fields_and_defaults() -> None:
    script = f"""
(async () => {{
{_FETCH_MANIFEST_MOCK}
installManifestFetchMock();
uiExports.setFieldManifestForTest(null, "pending");
await uiExports.loadFieldManifest();
const ui = uiExports.buildVpnImportFormSurface();
document.body.appendChild(ui.panel);
const simpleIds = [
  "vpn-import-display-name",
  "vpn-import-vpn-kind",
  "vpn-import-profile-document",
  "vpn-import-profile-text",
];
    const advanced = dom.queryByTestId("vpn-import-advanced-settings", ui.form);
    const payload = ui.readPayload(false);
    const closedText = dom.collectVisibleText(ui.form);
    ui.advancedDetails.open = true;
    const advancedIds = ["vpn-import-private-key", "vpn-import-preshared-key"];
    console.log(JSON.stringify({{
      simplePresent: simpleIds.every((id) => !!document.getElementById(id)),
      advancedPresent: advancedIds.every((id) => !!document.getElementById(id)),
      has_advanced: !!advanced,
      vpn_kind_default: payload.vpn_kind,
      secrets_hidden_closed: !closedText.includes("Private key"),
      manifest_loaded: uiExports.getFieldManifestState() === "loaded",
      has_vpn_kind_tooltip: !!dom.queryByTestId("vpn-import-vpn-kind-tooltip", ui.form),
    }}));
}})().catch((err) => {{ console.error(err); process.exit(1); }});
"""
    result = _run_ui_dom_runtime(script)
    assert result["simplePresent"] is True
    assert result["advancedPresent"] is True
    assert result["has_advanced"] is True
    assert result["vpn_kind_default"] == "AmneziaWG"
    assert result["secrets_hidden_closed"] is True
    assert result["manifest_loaded"] is True
    assert result["has_vpn_kind_tooltip"] is True


def test_vpn_import_loads_manifest_via_fetch_without_pre_inject() -> None:
    """F-1: cold path awaits loadFieldManifest before form build."""
    script = f"""
(async () => {{
{_FETCH_MANIFEST_MOCK}
installManifestFetchMock();
uiExports.setFieldManifestForTest(null, "pending");
await uiExports.loadFieldManifest();
const ui = uiExports.buildVpnImportFormSurface();
document.body.appendChild(ui.form);
const kindEl = document.getElementById("vpn-import-vpn-kind");
console.log(JSON.stringify({{
  manifest_loaded: uiExports.getFieldManifestState() === "loaded",
  vpn_kind_default: kindEl ? kindEl.value : null,
  has_tooltip: !!dom.queryByTestId("vpn-import-vpn-kind-tooltip", ui.form),
}}));
}})().catch((err) => {{ console.error(err); process.exit(1); }});
"""
    result = _run_ui_dom_runtime(script)
    assert result["manifest_loaded"] is True
    assert result["vpn_kind_default"] == "AmneziaWG"
    assert result["has_tooltip"] is True


def test_wizard_draft_loads_manifest_via_fetch_without_pre_inject() -> None:
    """F-2: add-router wizard forms get manifest defaults after loadFieldManifest."""
    script = f"""
(async () => {{
{_FETCH_MANIFEST_MOCK}
installManifestFetchMock();
uiExports.setFieldManifestForTest(null, "pending");
await uiExports.loadFieldManifest();
const ui = uiExports.buildWizardDraftFormSurface();
document.body.appendChild(ui.form);
const insecure = document.getElementById("wizard-insecure-http");
console.log(JSON.stringify({{
  manifest_loaded: uiExports.getFieldManifestState() === "loaded",
  insecure_unchecked: insecure ? !insecure.checked : null,
  has_host_tooltip: !!dom.queryByTestId("wizard-host-tooltip", ui.form),
}}));
}})().catch((err) => {{ console.error(err); process.exit(1); }});
"""
    result = _run_ui_dom_runtime(script)
    assert result["manifest_loaded"] is True
    assert result["insecure_unchecked"] is True
    assert result["has_host_tooltip"] is True


def test_vpn_import_honesty_copy_visible_in_dom() -> None:
    script = r"""
const ui = uiExports.buildVpnImportFormSurface();
document.body.appendChild(ui.panel);
const visibleText = dom.collectVisibleText(ui.panel);
console.log(JSON.stringify({
  not_device_apply:
    visibleText.includes("НЕ import/apply")
    || visibleText.includes("not device apply")
    || visibleText.includes("≠ device apply"),
  catalog_only:
    visibleText.includes("SQLite/vault") || visibleText.includes("Catalog import"),
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["not_device_apply"] is True
    assert result["catalog_only"] is True


def test_vpn_import_form_method_post_defense() -> None:
    script = r"""
const ui = uiExports.buildVpnImportFormSurface();
console.log(JSON.stringify({ method: ui.form.getAttribute("method") }));
"""
    result = _run_ui_dom_runtime(script)
    assert result["method"] == "post"


def test_vpn_import_password_fields_omit_name_and_clear_on_submit() -> None:
    marker = "RC-VPN-IMPORT-SECRET-MARKER-9f3a"
    script = f"""
(async () => {{
{_FLUSH_ASYNC}
uiExports.setApiFetchStubForTest(async () => ({{
  data: {{ profile_id: "prof_test", display_name: "T", vpn_kind: "AmneziaWG" }},
}}));
uiExports.resetToastCaptureForTest();
const ui = uiExports.buildVpnImportFormSurface();
document.body.appendChild(ui.panel);
ui.advancedDetails.open = true;
document.getElementById("vpn-import-display-name").value = "Lab VPN";
document.getElementById("vpn-import-profile-document").value =
  '{{"interface":{{"listen_port":51820}}}}';
document.getElementById("vpn-import-private-key").value = {json.dumps(marker)};
document.getElementById("vpn-import-preshared-key").value = "psk-marker";
const pk = document.getElementById("vpn-import-private-key");
const psk = document.getElementById("vpn-import-preshared-key");
const pkHasName = !!(pk && pk.attributes && pk.attributes.name);
const pskHasName = !!(psk && psk.attributes && psk.attributes.name);
const btn = dom.queryByTestId("vpn-import-submit", ui.panel);
btn.click();
await flushUiAsync();
const resultText = ui.resultBox.textContent || "";
const toasts = uiExports.getCapturedToastsForTest();
console.log(JSON.stringify({{
  pkHasName,
  pskHasName,
  pk_cleared: pk && pk.value === "",
  psk_cleared: psk && psk.value === "",
  result_has_marker: resultText.includes({json.dumps(marker)}),
  toast_has_marker: toasts.some((t) => t.includes({json.dumps(marker)})),
  toast_honest: toasts.some((t) => t.includes("not device apply")),
  toast_has_profile: toasts.some((t) => t.includes("prof_test")),
}}));
}})().catch((err) => {{ console.error(err); process.exit(1); }});
"""
    result = _run_ui_dom_runtime(script)
    assert result["pkHasName"] is False
    assert result["pskHasName"] is False
    assert result["pk_cleared"] is True
    assert result["psk_cleared"] is True
    assert result["result_has_marker"] is False
    assert result["toast_has_marker"] is False
    assert result["toast_honest"] is True
    assert result["toast_has_profile"] is True


def test_vpn_import_payload_includes_backend_fields() -> None:
    script = r"""
const ui = uiExports.buildVpnImportFormSurface();
document.body.appendChild(ui.panel);
ui.advancedDetails.open = true;
document.getElementById("vpn-import-display-name").value = "Import me";
document.getElementById("vpn-import-vpn-kind").value = "AmneziaWG";
document.getElementById("vpn-import-profile-document").value =
  '{"interface":{"listen_port":51820}}';
document.getElementById("vpn-import-private-key").value = "pk";
document.getElementById("vpn-import-preshared-key").value = "psk";
const payload = ui.readPayload(true);
console.log(JSON.stringify({
  keys: Object.keys(payload).sort(),
  display_name: payload.display_name,
  has_profile_document: typeof payload.profile_document === "object",
  has_private_key: payload.private_key === "pk",
  has_psk: payload.preshared_key === "psk",
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["display_name"] == "Import me"
    assert result["has_profile_document"] is True
    assert result["has_private_key"] is True
    assert result["has_psk"] is True
    for key in ("display_name", "vpn_kind", "profile_document", "private_key", "preshared_key"):
        assert key in result["keys"]


def test_rci_mutation_interface_id_in_advanced_and_honesty_copy() -> None:
    script = r"""
const ui = uiExports.buildRciMutationFormSurface({});
document.body.appendChild(ui.panel);
const closed = dom.collectVisibleText(ui.panel);
ui.advancedDetails.open = true;
const open = dom.collectVisibleText(ui.form);
const iface = document.getElementById("rci-interface-id");
console.log(JSON.stringify({
  closed_hides_iface: !closed.includes("Interface ID"),
  open_shows_iface: open.includes("Interface ID"),
  has_iface_testid: !!(iface && iface.getAttribute("data-testid") === "rci-interface-id"),
  honesty_fake: closed.includes("NOT live device RCI"),
  confirm_present: !!document.getElementById("rci-mutation-confirm"),
  confirm_honesty_dom: !!dom.queryByTestId("rci-mutation-confirm-honesty", ui.form),
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["closed_hides_iface"] is True
    assert result["open_shows_iface"] is True
    assert result["has_iface_testid"] is True
    assert result["honesty_fake"] is True
    assert result["confirm_present"] is True
    assert result["confirm_honesty_dom"] is True


def test_rci_operation_manifest_tooltip_dom() -> None:
    script = f"""
{_load_manifest_in_dom_script()}
const ui = uiExports.buildRciMutationFormSurface({{}});
document.body.appendChild(ui.form);
const op = document.getElementById("rci-operation");
const tooltip = dom.queryByTestId("rci-operation-tooltip", ui.form);
const payload = ui.readPayload();
console.log(JSON.stringify({{
  has_operation_select: !!op,
  has_tooltip: !!tooltip,
  aria_describedby: op ? op.getAttribute("aria-describedby") : null,
  operation_default: payload.operation,
  select_value: op ? op.value : null,
  has_honesty: !!dom.queryByTestId("rci-operation-honesty", ui.form),
}}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["has_operation_select"] is True
    assert result["has_tooltip"] is True
    assert result["aria_describedby"] is not None
    assert result["operation_default"] == "fail_safe_arm"
    assert result["select_value"] == "fail_safe_arm"
    assert result["has_honesty"] is True


def test_rci_mutation_resolves_path_and_body_from_manifest() -> None:
    script = f"""
{_load_manifest_in_dom_script()}
const payload = {{
  router_id: "rtr_test",
  operation: "fail_safe_arm",
  interface_id: "",
  confirm_rci_mutation: true,
}};
const resolved = uiExports.resolveRciMutationRequest(payload);
const ifacePayload = {{
  router_id: "rtr_test",
  operation: "interface_up",
  interface_id: "GigabitEthernet0",
  confirm_rci_mutation: true,
}};
const ifaceResolved = uiExports.resolveRciMutationRequest(ifacePayload);
const missingIface = uiExports.resolveRciMutationRequest({{
  router_id: "rtr_test",
  operation: "interface_down",
  interface_id: "",
  confirm_rci_mutation: true,
}});
console.log(JSON.stringify({{
  path: resolved.path,
  body_operation: resolved.body ? resolved.body.operation : null,
  iface_path: ifaceResolved.path,
  iface_body: ifaceResolved.body,
  missing_iface_error: missingIface.error || null,
}}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["path"] == "/routers/rtr_test/rci/fail-safe/arm"
    assert result["body_operation"] == "arm_timer_reboot_60"
    assert result["iface_path"] == "/routers/rtr_test/rci/interface"
    assert result["iface_body"]["operation"] == "interface_up"
    assert result["iface_body"]["interface_id"] == "GigabitEthernet0"
    assert "interface_id" in (result["missing_iface_error"] or "")


def test_rci_operation_invalid_manifest_body_enum_yields_empty_select() -> None:
    """F-9 red guard: harness must not mask invalid select value with first option."""
    script = f"""
{_load_manifest_in_dom_script()}
const ui = uiExports.buildRciMutationFormSurface({{}});
document.body.appendChild(ui.form);
const op = document.getElementById("rci-operation");
op.value = "arm_timer_reboot_60";
const payload = ui.readPayload();
console.log(JSON.stringify({{
  select_value: op.value,
  payload_operation: payload.operation,
}}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["select_value"] == ""
    assert result["payload_operation"] == ""


def test_wizard_draft_allow_insecure_http_default_false_in_advanced() -> None:
    script = f"""
{_load_manifest_in_dom_script()}
const ui = uiExports.buildWizardDraftFormSurface();
document.body.appendChild(ui.form);
const closed = dom.collectVisibleText(ui.form);
const insecure = document.getElementById("wizard-insecure-http");
const payload = ui.readPayload(false);
console.log(JSON.stringify({{
  closed_hides_insecure: !closed.includes("HTTP"),
  insecure_unchecked: insecure ? !insecure.checked : null,
  payload_false: payload.allow_insecure_http === false,
  has_advanced: !!dom.queryByTestId("wizard-draft-advanced-settings", ui.form),
}}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["closed_hides_insecure"] is True
    assert result["insecure_unchecked"] is True
    assert result["payload_false"] is True
    assert result["has_advanced"] is True


def test_wizard_draft_source_address_in_payload() -> None:
    script = r"""
const ui = uiExports.buildWizardDraftFormSurface();
document.body.appendChild(ui.form);
ui.advancedDetails.open = true;
document.getElementById("wizard-source-address").value = "192.168.2.10";
const payload = ui.readPayload(false);
console.log(JSON.stringify({ source_address: payload.source_address }));
"""
    result = _run_ui_dom_runtime(script)
    assert result["source_address"] == "192.168.2.10"


def test_wizard_confirm_allow_overwrite_default_false_in_advanced() -> None:
    script = f"""
{_load_manifest_in_dom_script()}
const ui = uiExports.buildWizardHostKeyConfirmFormSurface();
document.body.appendChild(ui.form);
const closed = dom.collectVisibleText(ui.form);
ui.advancedDetails.open = true;
const overwrite = document.getElementById("wizard-allow-overwrite");
const payload = ui.readPayload();
const danger = dom.queryByTestId("wizard-allow-overwrite-danger", ui.form);
console.log(JSON.stringify({{
  closed_hides_overwrite: !closed.includes("перезапись"),
  overwrite_unchecked: overwrite ? !overwrite.checked : null,
  payload_false: payload.allow_overwrite === false,
  has_danger_note: !!danger,
}}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["closed_hides_overwrite"] is True
    assert result["overwrite_unchecked"] is True
    assert result["payload_false"] is True
    assert result["has_danger_note"] is True


def test_wizard_learn_post_body_includes_source_address() -> None:
    script = r"""
const body = uiExports.buildWizardSshHostKeyLearnBody({
  host: "192.168.2.1",
  port: "22",
  sourceAddress: "192.168.2.10",
});
console.log(JSON.stringify(body));
"""
    result = _run_ui_dom_runtime(script)
    assert result["host"] == "192.168.2.1"
    assert result["port"] == 22
    assert result["source_address"] == "192.168.2.10"


def test_wizard_confirm_post_body_includes_allow_overwrite() -> None:
    script = r"""
const body = uiExports.buildWizardSshHostKeyConfirmBody({
  fingerprint_sha256: "SHA256:abc",
  algorithm: "ssh-ed25519",
  allow_overwrite: true,
});
console.log(JSON.stringify(body));
"""
    result = _run_ui_dom_runtime(script)
    assert result["fingerprint_sha256"] == "SHA256:abc"
    assert result["algorithm"] == "ssh-ed25519"
    assert result["allow_overwrite"] is True


def test_vpn_import_broken_testid_guard_red_observation() -> None:
    """Guard: missing submit testid should fail DOM lookup (red→green anchor)."""
    script = r"""
const ui = uiExports.buildVpnImportFormSurface();
document.body.appendChild(ui.panel);
const btn = dom.queryByTestId("vpn-import-submit-NOT-REAL", ui.panel);
console.log(JSON.stringify({ btn_found: !!btn }));
"""
    result = _run_ui_dom_runtime(script)
    assert result["btn_found"] is False


def test_site_survey_live_params_in_advanced() -> None:
    script = f"""
{_load_manifest_in_dom_script()}
const ui = uiExports.buildSiteSurveyFormSurface();
document.body.appendChild(ui.form);
const closed = dom.collectVisibleText(ui.form);
ui.advancedDetails.open = true;
const advancedIds = [
  "uplink-scan-host",
  "uplink-scan-username",
  "uplink-scan-router-cred-ref",
  "uplink-scan-ssh-pin",
  "uplink-scan-source-address",
];
console.log(JSON.stringify({{
  closed_hides_host: !closed.includes("Host"),
  advanced_present: advancedIds.every((id) => !!document.getElementById(id)),
  has_advanced: !!dom.queryByTestId("uplink-scan-advanced-settings", ui.form),
  payload_has_host: (() => {{
    document.getElementById("uplink-scan-host").value = "192.168.2.1";
    return ui.readSurveyBodyForRadio("WifiMaster0").host === "192.168.2.1";
  }})(),
}}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["closed_hides_host"] is True
    assert result["advanced_present"] is True
    assert result["has_advanced"] is True
    assert result["payload_has_host"] is True


def test_wifi_observed_form_live_params_and_honest_null_toast() -> None:
    script = r"""
const ui = uiExports.buildWifiObservedFormSurface({
  showCompare: true,
  apRangeStart: 3,
  apRangeEnd: 3,
});
document.body.appendChild(ui.form);
ui.advancedDetails.open = true;
document.getElementById("wifi-status-host").value = "192.168.2.1";
const payload = ui.readPayload();
const nullToast = uiExports.formatWifiObservedSessionToast(null);
console.log(JSON.stringify({
  has_host: !!document.getElementById("wifi-status-host"),
  payload_host: payload.host,
  null_toast_unknown: nullToast.includes("unknown"),
  not_bare_refresh: nullToast !== "Observed state refreshed",
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["has_host"] is True
    assert result["payload_host"] == "192.168.2.1"
    assert result["null_toast_unknown"] is True
    assert result["not_bare_refresh"] is True


def test_traffic_discovery_human_fields_not_sole_json() -> None:
    script = f"""
{_load_manifest_in_dom_script()}
const ui = uiExports.buildTrafficDiscoveryFormSurface();
document.body.appendChild(ui.panel);
const closed = dom.collectVisibleText(ui.form);
ui.advancedDetails.open = true;
document.getElementById("traffic-evidence-dst").value = "10.0.0.1";
document.getElementById("traffic-evidence-proto").value = "tcp";
document.getElementById("traffic-route-prefix").value = "10.0.0.0/24";
document.getElementById("traffic-router-id").value = "rtr_test";
document.getElementById("traffic-confidence").value = "0.8";
document.getElementById("traffic-observation-id").value = "tobs_test";
const obsPayload = ui.readObservationPayload();
const propPayload = ui.readProposalPayload();
console.log(JSON.stringify({{
  closed_shows_dst: closed.includes("Evidence destination") || closed.includes("destination"),
  closed_hides_json: !closed.includes("Evidence JSON"),
  obs_evidence: obsPayload.evidence,
  prop_route: propPayload.route_intent,
  has_advanced: !!dom.queryByTestId("traffic-discovery-advanced-settings", ui.form),
  has_confidence_tooltip: !!dom.queryByTestId("traffic-confidence-tooltip", ui.form),
}}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["obs_evidence"] == {"dst": "10.0.0.1", "proto": "tcp"}
    assert result["prop_route"] == {"prefix": "10.0.0.0/24"}
    assert result["has_advanced"] is True


def test_commissioning_create_form_mode_and_async() -> None:
    script = f"""
{_load_manifest_in_dom_script()}
const ui = uiExports.buildCommissioningCreateFormSurface("rtr_default", "fake");
document.body.appendChild(ui.form);
const payload = uiExports.readCommissioningCreatePayloadFromDom("fake");
console.log(JSON.stringify({{
  has_mode: !!document.getElementById("commissioning-mode"),
  has_async: !!document.getElementById("commissioning-assess-async"),
  has_router_tooltip: !!dom.queryByTestId("commissioning-router-id-tooltip", ui.form),
  payload_mode: payload.mode,
  payload_router: payload.router_id,
}}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["has_mode"] is True
    assert result["has_async"] is True
    assert result["has_router_tooltip"] is True
    assert result["payload_router"] == "rtr_default"


def test_preset_deploy_risk_get_put_buttons_in_source() -> None:
    """Deploy surface: risk_acknowledged, GET deployment-revision, PUT desired-revision."""
    source = (WEB / "app.js").read_text(encoding="utf-8")
    deploy = source.split("Deployment Confirm/Apply (FAKE)")[1].split(
        "async function renderOperations"
    )[0]
    assert "deploy-risk-acknowledged" in deploy
    assert "risk_acknowledged: readRiskAcknowledged()" in deploy
    assert "deploy-get-deployment-revision-btn" in deploy
    assert "/deployment-revisions/" in deploy
    assert "deploy-put-desired-revision-btn" in deploy
    assert 'method: "PUT"' in deploy
    assert "/desired-revision" in deploy
