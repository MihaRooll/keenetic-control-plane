"""UI smoke for #config router settings view."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie

REPO_ROOT = Path(__file__).resolve().parents[1]
WEB = REPO_ROOT / "router_control_host" / "web"


@pytest.fixture
def authed_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    app = create_app(db_path=tmp_path / "config-ui.sqlite3", enable_worker=False)
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield client


def test_config_ui_nav_link_in_html(authed_client) -> None:
    html = authed_client.get("/settings/router-control").text
    assert 'href="#config"' in html
    assert 'data-view="config"' in html
    assert "Настройки роутера" in html


def test_config_ui_logout_control_in_html(authed_client) -> None:
    html = authed_client.get("/settings/router-control").text
    assert 'action="/logout"' in html
    assert 'method="post"' in html.lower()
    assert "Выйти" in html


def test_config_ui_app_js_contract() -> None:
    source = (WEB / "app.js").read_text(encoding="utf-8")
    assert 'case "config":' in source
    assert 'renderConfig(root)' in source
    assert '"/observed-interfaces"' in source
    assert "Каталог/preset Apply заблокирован: Gate B не WriteCertified" in source
    assert "Bounded Wi-Fi/AWG test Apply ниже доступны" in source
    assert "KeenDNS недоступен в этой сборке" in source
    assert "innerHTML" not in source


def test_config_ui_app_js_node_syntax() -> None:
    js_path = WEB / "app.js"
    node = shutil.which("node")
    if node is None:
        pytest.skip("node not available")
    result = subprocess.run(
        [node, "--check", str(js_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr or result.stdout


def test_config_ui_styles_present(authed_client) -> None:
    css = authed_client.get("/settings/router-control/assets/styles.css").text
    assert ".config-section" in css
    assert ".config-apply-banner" in css
    assert ".config-wifi-apply-form" in css
    assert ".logout-form" in css


def _wifi_apply_form_source() -> str:
    source = (WEB / "app.js").read_text(encoding="utf-8")
    return source.split("function buildWifiApplyFormSurface")[1].split(
        "function parseAwgAscArgs"
    )[0]


def _awg_apply_form_source() -> str:
    source = (WEB / "app.js").read_text(encoding="utf-8")
    return source.split("function buildAwgApplyFormSurface")[1].split(
        "function readUplinkStationApplyPayloadFromDom"
    )[0]


def _awg_apply_handler_source() -> str:
    source = (WEB / "app.js").read_text(encoding="utf-8")
    return source.split("const awgApplyUi = buildAwgApplyFormSurface")[1].split(
        "const trafficPanel"
    )[0]


def _wifi_apply_handler_source() -> str:
    source = (WEB / "app.js").read_text(encoding="utf-8")
    return source.split("const wifiApplyUi = buildWifiApplyFormSurface")[1].split(
        "const wifiStatusPanel"
    )[0]


def test_config_ui_wifi_apply_section() -> None:
    source = (WEB / "app.js").read_text(encoding="utf-8")
    html = (WEB / "index.html").read_text(encoding="utf-8")
    wifi_form = _wifi_apply_form_source()
    wifi_handlers = _wifi_apply_handler_source()
    wifi_execute = source.split("async function executeWifiApplyClick")[1].split(
        "async function executeAwgApplyClick"
    )[0]
    wifi_section = wifi_form + wifi_handlers + wifi_execute
    assert '"/wifi/preview"' in wifi_section
    assert '"/wifi/apply"' in wifi_section
    assert '"/wifi/teardown"' in wifi_section
    assert "WifiMaster0" in wifi_section
    assert "/AccessPoint" in wifi_section
    assert "confirm_live_apply" in wifi_section
    assert "credential_ref_id" in wifi_section
    assert "buildAdvancedSettingsBlock" in source
    assert "wifi-apply-advanced-settings" in wifi_form
    assert "Дополнительные настройки" in wifi_section
    assert "wifi-apply-compensate" in wifi_form
    assert "wifi-apply-idempotent" in wifi_form
    assert "wifi-apply-router-id" in wifi_form
    assert "HONESTY_WIFI_GUEST_ISOLATION" in source
    assert "wifi-apply-guest-isolation-honesty" in wifi_form
    assert 'name="psk"' not in source
    assert 'name="psk"' not in html
    assert "plaintext PSK" in wifi_section or "credential_ref_id" in wifi_section
    assert 'id="wifi-apply-enabled"' in wifi_section or '"wifi-apply-enabled"' in wifi_section
    assert "wifi-apply-enabled" in wifi_section
    payload_reader = source.split("function readWifiApplyPayloadFromDom")[1].split(
        "function wifiApplyHonestySummary"
    )[0]
    assert "enabled: !!(enabledEl && enabledEl.checked)" in payload_reader
    assert "enabled: true" not in payload_reader
    assert "authentication wpa-psk" in wifi_section
    assert "encryption wpa3" in wifi_section
    assert "не authentication sae" in wifi_section
    assert "device-verified" in wifi_section
    assert "pending live verification" not in wifi_section
    assert "SAE grammar" not in wifi_section
    assert "AccessPoint3" in wifi_section
    assert "isExpendableLabClass()" in source
    ap_range = source.split("function wifiApIndexRange")[1].split(
        "function readWifiApplyPayloadFromDom"
    )[0]
    assert "apRangeStart: expendable ? 0 : 3" in ap_range
    assert "apRangeEnd: 6" in ap_range
    assert "for (let n = apRangeStart" in wifi_section
    assert "n <= apRangeEnd" in wifi_section
    assert "Production AP0/1/2 запрещены" in wifi_section
    assert "Expendable lab: AccessPoint0" in wifi_section
    assert '"AccessPoint0"' not in wifi_section
    assert '"AccessPoint7"' not in wifi_section
    assert '"AccessPoint8"' not in wifi_section
    assert '"AccessPoint9"' not in wifi_section


def test_config_ui_wifi_apply_honesty() -> None:
    source = (WEB / "app.js").read_text(encoding="utf-8")
    honesty_section = source.split("function wifiApplyHonestySummary")[1].split(
        "function buildWifiApplyFormSurface"
    )[0]
    wifi_handlers = _wifi_apply_handler_source()
    wifi_execute = source.split("async function executeWifiApplyClick")[1].split(
        "async function executeAwgApplyClick"
    )[0]
    assert "function wifiApplyHonestySummary" in source
    assert "on_air_verification_status" in honesty_section
    assert "on_air_verified" in honesty_section
    assert "on_air_admin_only" in honesty_section
    assert "NOT on-air — admin up only (NOT success)" in honesty_section
    assert "on_air_unverified" in honesty_section
    assert "on_air_still_broadcasting" in honesty_section
    honesty_block = honesty_section
    assert 'parts.push("on-air verified (link up)")' in honesty_block
    assert "NOT success" in honesty_block
    assert 'APPLY_TOAST_PATHS["P-wifi-apply"].toastFromResponse(data)' in wifi_execute
    assert "executeWifiApplyClick(readWifiApplyPayload, renderWifiApplyResult)" in wifi_handlers
    assert "executeWifiTeardownClick(readWifiApplyPayload, renderWifiApplyResult)" in wifi_handlers


def test_config_ui_wifi_draft_honesty() -> None:
    source = (WEB / "app.js").read_text(encoding="utf-8")
    draft_section = source.split("Wi-Fi / DNS — локальный черновик")[1].split(
        "Wi-Fi Apply (test AP)"
    )[0]
    assert "не участвуют в запросах" in draft_section
    assert "только preview в UI, не отправляется на сервер" in draft_section


def test_config_ui_wifi_observed_section() -> None:
    source = (WEB / "app.js").read_text(encoding="utf-8")
    status_section = source.split("Wi-Fi Status (observed)")[1].split("AWG Apply")[0]
    assert "Wi-Fi Status (observed)" in source
    assert '"/wifi/observed-state"' in status_section
    assert "Could not read Wi-Fi state" in status_section
    assert "match" in status_section
    assert "differs" in status_section
    assert "unknown" in status_section
    assert "offline-verified only" in status_section
    assert "formatWifiObservedSessionToast" in status_section
    assert "buildWifiObservedFormSurface" in status_section
    assert "ssh_tunnel_pinned" in source
    assert "live read-only session" in source
    assert "fixture/offline" in source
    assert "config-wifi-observed" in status_section
    assert "config-wifi-observed-unreadable" in status_section
    assert "Refresh observed state" in status_section
    assert "Link up" in status_section


def test_config_ui_awg_apply_section() -> None:
    source = (WEB / "app.js").read_text(encoding="utf-8")
    awg_form = _awg_apply_form_source()
    awg_handlers = _awg_apply_handler_source()
    awg_execute = source.split("async function executeAwgApplyClick")[1].split(
        "async function executeStationApplyClick"
    )[0]
    awg_teardown_execute = source.split("async function executeAwgTeardownClick")[1].split(
        "async function executeStationApplyClick"
    )[0]
    awg_section = awg_form + awg_handlers + awg_execute + awg_teardown_execute
    assert "AWG Apply (test interface)" in source
    assert '"/wireguard/preview"' in awg_section
    assert '"/wireguard/apply"' in awg_section
    assert '"/wireguard/teardown"' in awg_section
    assert "Wireguard5" in awg_form
    assert "Wireguard9" in awg_form
    assert "confirm_live_apply" in awg_section
    assert 'name="private-key"' not in awg_section
    assert (
        'id="awg-apply-peer-rci-shape"' in awg_form
        or '"awg-apply-peer-rci-shape"' in awg_form
    )
    assert "path_style" in awg_form
    assert "nested RCI (default — device-verified (write accepted) 2026-07-24)" in awg_form
    assert "path-style (legacy — peer write REJECTED on 5.01.C.1.0-0)" in awg_form
    assert "nested_rci" in awg_section
    assert "peer_rci_shape" in awg_section
    payload_reader = source.split("function readAwgApplyPayloadFromDom")[1].split(
        "function buildAwgApplyFormSurface"
    )[0]
    assert "peer_rci_shape: peerRciShapeVal" in payload_reader
    assert 'peer_rci_shape: base.peer_rci_shape || "nested_rci"' in awg_teardown_execute
    assert "path-style (default — peer not device-verified)" not in awg_section
    assert "experimental — offline only, not device-verified" not in awg_section
    assert "path-style (device-verified)" not in awg_section
    assert (
        "payload.private_key_credential_ref_id = base.private_key_credential_ref_id"
        in awg_teardown_execute
    )
    assert "payload.peer_public_key = base.peer_public_key" in awg_teardown_execute
    assert "wgRangeStart = expendable ? 0 : 5" in awg_form
    assert "for (let n = wgRangeStart" in awg_form
    assert "Wireguard5–Wireguard9" in awg_form
    assert "Wireguard interfaces 0–9" in awg_form
    assert '"Wireguard0"' not in awg_form
    assert "config-awg-apply-honesty" in awg_form
    assert "awg-apply-advanced-settings" in awg_form
    assert "tunnel_never_handshaked" in awg_form
    assert "tunnel_healthy" in awg_form
    assert "DEVICE-CONFIRMED" in awg_form
    assert "interface Address NOT configured" in awg_form
    assert "tunnel_no_peer" in awg_form
    assert "tunnel_unverified" in awg_form
    apply_toast_paths = source.split("const APPLY_TOAST_PATHS")[1].split(
        "async function executeWifiApplyClick"
    )[0]
    assert "awgApplyHonestySummary" in apply_toast_paths
    assert "configuration applied" in awg_form
    awg_honesty = source.split("function awgApplyHonestySummary")[1].split(
        "function buildWifiApplyFormSurface"
    )[0]
    assert "tunnel NOT verified" in awg_honesty
    assert "не «online via vpn»" in awg_form.lower()
    assert "wireguard.status:up" in awg_form.lower()
    assert "online via vpn" not in awg_honesty.lower()
    assert "working vpn" in awg_honesty.lower()
    assert 'parts.push("interface up (admin)")' in awg_honesty
    assert "interface_present_down" in awg_honesty
    assert "tunnel never handshaked" in awg_honesty.lower()
    assert "DEVICE-CONFIRMED" in awg_honesty
    assert "interface Address NOT configured" in awg_honesty
    assert "awg-apply-handshake-settle" in awg_form
    assert "handshake_settle_seconds" in awg_section


def test_config_ui_awg_apply_styles(authed_client) -> None:
    css = authed_client.get("/settings/router-control/assets/styles.css").text
    assert ".config-awg-apply-form" in css
    assert ".config-advanced-settings" in css


def test_config_ui_traffic_discovery_section() -> None:
    source = (WEB / "app.js").read_text(encoding="utf-8")
    traffic_section = source.split("TrafficDiscovery (proposals-only)")[1].split("KeenDNS")[0]
    assert "TrafficDiscovery (proposals-only)" in source
    assert "config-traffic-discovery" in traffic_section
    assert '"/traffic/observations"' in traffic_section
    assert '"/traffic/proposals"' in traffic_section
    assert "/traffic/proposals/" in traffic_section
    assert "proposals-only" in traffic_section
    assert "auto-apply" in traffic_section.lower()
    assert "auto-apply blocked" in traffic_section.lower() or "Auto-apply" in traffic_section
    assert "apply на роутер" in traffic_section or "недоступен" in traffic_section
    assert "Record observation" in traffic_section
    assert "Create proposal" in traffic_section
    assert "Get proposal" in traffic_section
    assert "evidence_digest" not in traffic_section or "digest only" in traffic_section


def test_config_ui_traffic_discovery_styles(authed_client) -> None:
    css = authed_client.get("/settings/router-control/assets/styles.css").text
    assert ".config-traffic-discovery-form" in css
    assert ".config-traffic-discovery-safety" in css


def test_config_ui_deploy_apply_section() -> None:
    source = (WEB / "app.js").read_text(encoding="utf-8")
    deploy_section = source.split("Deployment Confirm/Apply (FAKE)")[1].split(
        "async function renderOperations"
    )[0]
    assert "Deployment Confirm/Apply (FAKE)" in source
    assert "FAKE mode only" in deploy_section
    assert "fake-gated" in deploy_section
    assert "config-deploy-apply-form" in deploy_section
    assert 'id="deploy-router-id"' in deploy_section or '"deploy-router-id"' in deploy_section
    pub_id_ok = (
        'id="deploy-published-preset-id"' in deploy_section
        or '"deploy-published-preset-id"' in deploy_section
    )
    assert pub_id_ok
    assert 'id="deploy-plan-id"' in deploy_section or '"deploy-plan-id"' in deploy_section
    assert "/deployment-revisions" in deploy_section
    assert "/readiness" in deploy_section
    assert "/desired-revisions" in deploy_section
    assert '"/plans"' in deploy_section or "/plans/" in deploy_section
    assert "/confirm" in deploy_section
    assert "/apply" in deploy_section
    assert "/backup-artifact" in deploy_section
    assert "storage locator" in deploy_section or "metadata only" in deploy_section
    assert "intent_json" not in deploy_section
    assert "private_key" not in deploy_section
    assert "preshared_key" not in deploy_section
    assert "management_password" not in deploy_section


def test_config_ui_deploy_apply_styles(authed_client) -> None:
    css = authed_client.get("/settings/router-control/assets/styles.css").text
    assert ".config-deploy-apply-form" in css
    assert ".config-deploy-apply-safety" in css


def test_config_ui_credentials_panel() -> None:
    source = (WEB / "app.js").read_text(encoding="utf-8")
    assert "Credential refs (vault metadata)" in source
    assert "config-credentials-form" in source
    assert "/credentials" in source
    assert "/revoke" in source
    assert 'method: "PUT"' in source
    assert "DPAPI" in source
    assert "one-shot" in source
    assert "cred-enroll-value" in source
    assert 'valueEl.value = ""' in source
    cred_start = source.index("config-credentials-form")
    cred_section = source[cred_start : cred_start + 5500]
    assert "credForm.addEventListener(\"submit\"" in cred_section
    assert "ev.preventDefault()" in cred_section
    assert "runCredentialEnroll()" in cred_section
    assert "omitName: true" in cred_section
    assert 'appendFormField(credForm, "enroll_value"' in cred_section
    enroll_field = cred_section.split('appendFormField(credForm, "enroll_value"')[1].split(");")[0]
    assert "name:" not in enroll_field and 'name="' not in enroll_field


def test_config_ui_vpn_import_panel() -> None:
    source = (WEB / "app.js").read_text(encoding="utf-8")
    assert "VPN/WG parse preview" in source
    assert "config-vpn-import-form" in source
    assert '"/vpn-profiles/parse-preview"' in source
    assert "profile_text" in source
    assert "sanitized" in source.lower()
    assert "vpn-import-profile-text" in source
    assert 'textEl.value = ""' in source
    assert "AWG Apply" in source
    vpn_start = source.index("config-vpn-import-form")
    vpn_section = source[vpn_start : vpn_start + 2500]
    assert "vpnImportForm.addEventListener(\"submit\"" in vpn_section
    assert "ev.preventDefault()" in vpn_section


def test_config_ui_vpn_policy_preview_panel() -> None:
    source = (WEB / "app.js").read_text(encoding="utf-8")
    assert "VPN policy-routing preview" in source
    assert "config-vpn-policy-preview-form" in source
    assert '"/vpn/policy-routing/preview"' in source
    assert "help_verified_grammar_unapplied" in source
    assert "NO APPLY" in source
    assert "unknowns" in source
    assert "vpnPolicyDescribeOp" in source
    assert "citation:" in source
    policy_start = source.index("config-vpn-policy-preview-form")
    policy_section = source[policy_start : policy_start + 9000]
    assert "verification_status" in policy_section
    assert "NOT device-verified" in policy_section
    assert "apply_ops" in policy_section
    assert "teardown_ops" in policy_section
    submit_block = source[policy_start : policy_start + 12000]
    assert "form.addEventListener(\"submit\"" in submit_block
    assert "ev.preventDefault()" in policy_section


def test_config_ui_network_family_preview_panels() -> None:
    source = (WEB / "app.js").read_text(encoding="utf-8")
    for family, path in (
        ("VLAN preview", '"/vlan/preview"'),
        ("DHCP preview", '"/dhcp/preview"'),
        ("DNS preview", '"/dns/preview"'),
        ("Firewall preview", '"/firewall/preview"'),
    ):
        assert family in source
        assert path in source
    assert "config-vlan-preview-form" in source
    assert "config-dhcp-preview-form" in source
    assert "config-dns-preview-form" in source
    assert "config-firewall-preview-form" in source
    assert "offline_unverified" in source
    assert "NOT device-certified" in source
    assert "NO APPLY" in source
    assert "reverse order for rollback" in source
    assert "networkFamilyPreviewErrorHuman" in source
    assert "Preview not run yet." in source


def test_config_ui_network_family_preview_styles(authed_client) -> None:
    css = authed_client.get("/settings/router-control/assets/styles.css").text
    assert ".config-network-family-preview-safety" in css
    assert ".config-vlan-preview-form" in css
    assert ".config-firewall-preview-result" in css


def test_ui_runtime_network_family_preview_offline_unverified() -> None:
    """Executable: offline_unverified warning + apply_ops order + teardown rollback note."""
    script = """
const box = document.createElement("pre");
const data = {
  verification_status: "offline_unverified",
  bridge_id: "Bridge3",
  zone_id: "staff",
  vlan_id: 20,
  ipv4_cidr: "10.20.0.0/24",
  ipv4_gateway: "10.20.0.1",
  apply_ops: [
    { operation: "vlan_create_bridge", bridge_id: "Bridge3" },
    { operation: "vlan_set_ip_address", bridge_id: "Bridge3", ipv4_gateway: "10.20.0.1" },
    { operation: "vlan_up", bridge_id: "Bridge3" },
  ],
  teardown_ops: [
    { operation: "vlan_down", bridge_id: "Bridge3" },
    { operation: "vlan_clear_ip_address", bridge_id: "Bridge3" },
    { operation: "vlan_remove_bridge", bridge_id: "Bridge3" },
  ],
  notes: [],
};
uiExports.renderNetworkFamilyPreviewResult(box, data, [
  { key: "bridge_id", label: "bridge_id" },
  { key: "zone_id", label: "zone_id" },
  { key: "vlan_id", label: "vlan_id" },
]);
const out = box.textContent;
console.log(JSON.stringify({
  has_offline_warning: out.includes("offline_unverified") && out.includes("NOT device-verified"),
  has_no_apply: out.includes("NO APPLY"),
  apply_order_ok:
    out.indexOf("vlan_create_bridge") < out.indexOf("vlan_set_ip_address")
    && out.indexOf("vlan_set_ip_address") < out.indexOf("vlan_up"),
  teardown_reverse_note: out.includes("reverse order for rollback"),
  not_run_before: uiExports.NETWORK_FAMILY_PREVIEW_NOT_RUN === "Preview not run yet.",
}));
"""
    result = _run_app_js_ui_checks(script)
    assert result["has_offline_warning"] is True
    assert result["has_no_apply"] is True
    assert result["apply_order_ok"] is True
    assert result["teardown_reverse_note"] is True
    assert result["not_run_before"] is True


def test_ui_runtime_network_family_preview_error_human() -> None:
    script = """
const msg = uiExports.networkFamilyPreviewErrorHuman(
  "dhcp.preview_failed",
  "zone id not allowlisted: 'Guest;drop table'",
);
console.log(JSON.stringify({
  human: msg,
  has_code_label: msg.startsWith("DHCP preview failed:"),
  has_server_message: msg.includes("zone id not allowlisted"),
}));
"""
    result = _run_app_js_ui_checks(script)
    assert result["has_code_label"] is True
    assert result["has_server_message"] is True


def test_config_ui_rci_mutation_panel() -> None:
    source = (WEB / "app.js").read_text(encoding="utf-8")
    rci_start = source.index("function buildRciMutationFormSurface")
    rci_end = source.index("function readWizardDraftPayloadFromDom", rci_start)
    section = source[rci_start:rci_end]
    assert "Sealed RCI mutations (FAKE)" in source
    assert "buildRciOperationOptionsFromManifest" in source
    assert "resolveRciMutationRequest" in section
    assert "rci-mutation-confirm" in section
    assert "sealed" in section.lower()
    assert "form.addEventListener(\"submit\"" in section
    assert "SQLite synthetic ack" in section
    assert "ev.preventDefault()" in section
    lower = section.lower()
    assert "raw rci" not in lower
    assert "passthrough" not in lower
    assert "rci command" not in lower
    assert "rci-mutation-advanced-settings" in section


def test_config_ui_new_panel_styles(authed_client) -> None:
    css = authed_client.get("/settings/router-control/assets/styles.css").text
    assert ".config-credentials-form" in css
    assert ".config-vpn-import-form" in css
    assert ".config-vpn-policy-preview-form" in css
    assert ".config-vlan-preview-form" in css
    assert ".config-network-family-preview-safety" in css
    assert ".config-rci-mutation-form" in css


def test_add_router_wizard_nav_link_in_html(authed_client) -> None:
    html = authed_client.get("/settings/router-control").text
    assert 'href="#add-router"' in html
    assert 'data-view="add-router"' in html
    assert "Добавить роутер" in html


def test_add_router_wizard_app_js_contract() -> None:
    source = (WEB / "app.js").read_text(encoding="utf-8")
    assert 'case "add-router":' in source
    assert "renderAddRouter" in source
    assert "/lab/wizard-draft-router" in source
    assert "/lab/bootstrap-discovery" in source
    assert "/ssh-host-key/learn" in source
    assert "/ssh-host-key/confirm" in source
    assert "WIZARD_FINDING_MESSAGES" in source
    assert "ssh_component_missing" in source
    assert "components_inventory_unavailable" in source
    assert "wizardComponentsInventorySummary" in source
    assert "wizardSshComponentFact" in source
    assert "список усечён" in source
    assert "неизвестно" in source.split("wizardSshComponentFact")[1].split("function")[0]
    assert "Компоненты:" in source
    wizard_start = source.index("async function renderAddRouter")
    wizard_section = source[wizard_start : wizard_start + 14000]
    assert "allow_overwrite" in wizard_section
    assert "wizard-allow-overwrite" in wizard_section
    assert "buildWizardDraftFormSurface" in source
    assert "buildWizardHostKeyConfirmFormSurface" in source
    assert "Gate A не открыт" in source
    assert "Wi‑Fi" in source or "Wi-Fi" in source
    assert "management_password" not in source
    assert "wizard-secret" in source
    draft_fn = source.split("function buildWizardDraftFormSurface")[1].split(
        "function readWizardHostKeyConfirmPayloadFromDom"
    )[0]
    assert "omitName: true" in draft_fn
    assert "secretEl.value = \"\"" in wizard_section
    assert "ev.preventDefault()" in wizard_section
    assert "firmware_version_changes" in source
    assert "draftIdempotencyKey" in wizard_section
    assert "draftSucceeded" in wizard_section
    assert "ensureWizardDraft" in wizard_section
    assert "runBootstrapDiscovery" in wizard_section
    assert "Повторить обнаружение" in wizard_section
    assert 'method: "post"' in draft_fn or "method: 'post'" in draft_fn
    assert "renderWizardTransportHonesty" in source
    assert "certification_eligible=false" in source
    assert "более старую версию" in source
    assert "совпадает" in source
    downgrade_section = source.split("более старую версию")[1].split(
        "effects.firmware_version_changes === false"
    )[0]
    assert "совпадает" not in downgrade_section
    ssh_msg = source.split("ssh_component_missing:")[1].split("ssh_disabled:")[0]
    assert "автоматически" in ssh_msg
    assert "затем выполните" not in ssh_msg
    submit_block = wizard_section.split('form.addEventListener("submit"')[1].split("});")[0]
    assert "ev.preventDefault()" in submit_block
    assert "if (!state.draftSucceeded)" in submit_block
    assert "ensureWizardDraft" in submit_block
    assert 'apiFetch("/lab/wizard-draft-router"' in wizard_section
    assert "draftFingerprint" in wizard_section
    assert "invalidateWizardDraft" in wizard_section
    assert "onDraftIdentityFieldChange" in wizard_section
    assert submit_block.index("draftIdempotencyKey") < submit_block.index("await")
    assert "submit.disabled = true" in submit_block
    assert "submit.disabled = false" in submit_block
    retry_block = wizard_section.split("Повторить обнаружение")[1].split(
        "nextBtn.addEventListener"
    )[0]
    assert "runBootstrapDiscovery" in retry_block
    assert "/lab/wizard-draft-router" not in retry_block
    assert "ensureWizardDraft" not in retry_block
    draft_fn = source.split("function buildWizardDraftFormSurface")[1].split(
        "function readWizardHostKeyConfirmPayloadFromDom"
    )[0]
    secret_field = draft_fn.split('fieldTooltipOpts("wizard_draft", "secret"')[1].split(");")[0]
    assert "omitName: true" in secret_field
    assert "name:" not in secret_field and 'name="' not in secret_field


def test_add_router_wizard_styles(authed_client) -> None:
    css = authed_client.get("/settings/router-control/assets/styles.css").text
    assert ".wizard-progress" in css
    assert ".wizard-handoff" in css
    assert ".wizard-form" in css


def test_uplink_nav_link_in_html(authed_client) -> None:
    html = authed_client.get("/settings/router-control").text
    assert 'href="#uplink"' in html
    assert 'data-view="uplink"' in html
    assert "Uplink" in html


def test_uplink_app_js_contract() -> None:
    source = (WEB / "app.js").read_text(encoding="utf-8")
    assert 'case "uplink":' in source
    assert "renderUplink" in source
    uplink_start = source.index("async function renderUplink")
    uplink_helpers = source[source.index("function uplinkDisplaySsid") : uplink_start]
    assert "stationApplyHonestySummary" in uplink_helpers
    assert "renderStationApplyPlanSummary" in uplink_helpers
    uplink_section = source[uplink_start : uplink_start + 45000]
    station_execute = source.split("async function executeStationApplyClick")[1].split(
        "async function executeStationTeardownClick"
    )[0]
    assert '"/wifi/site-survey"' in uplink_section
    assert '"/wifi/station/preview"' in uplink_section
    assert '"/wifi/station/apply"' in station_execute
    station_teardown_execute = source.split("async function executeStationTeardownClick")[1].split(
        "async function executeUplinkApApplyClick",
    )[0]
    assert '"/wifi/station/teardown"' in station_teardown_execute
    assert '"/wifi/observed-state"' in uplink_section
    assert '"/wifi/preview"' in uplink_section
    assert '"/wifi/apply"' in source.split("async function executeUplinkApApplyClick")[1].split(
        "function buildWifiApplyActionHarness"
    )[0]
    assert "/routers/" in uplink_section
    assert 'method: "PUT"' in uplink_section
    assert (
        "not hardware-verified" in uplink_section
        or "не hardware-verified" in uplink_section
        or "uplink не verified" in uplink_section
        or "uplink_verified_bounded" in uplink_section
        or "device_accepted_grammar" in uplink_section
    )
    preview_block = uplink_section.split("3. Preview join + station apply/teardown")[1].split(
        "4. Own SSID"
    )[0]
    assert "grammar_verification_status" in preview_block
    assert "planned_uplink_verification_level" in preview_block
    assert "NOT runtime uplink_verification_status" in preview_block
    assert "uplink_dispatched_unverified" in preview_block
    assert "uplink_dispatched_unverified" in uplink_helpers
    assert "uplink_settle_seconds" in preview_block
    assert "20–30" in preview_block or "20-30" in preview_block
    assert "оборвать текущий uplink" in preview_block
    assert "Apply station join" in preview_block
    assert "Teardown station" in preview_block
    station_form = source.split("function buildUplinkStationApplyFormSurface")[1].split(
        "function buildCredentialEnrollTestSurface"
    )[0]
    assert "uplink-station-confirm" in station_form
    assert (
        "stationApplyHonestySummary" in preview_block
        or "stationApplyHonestySummary(data)" in preview_block
        or "stationApplyHonestySummary" in uplink_helpers
    )
    assert "renderStationApplyPlanSummary" in preview_block
    assert (
        "device_accepted_grammar" in preview_block
        or "grammar_verification_status" in preview_block
    )
    assert "planned_uplink_verified_bounded" in preview_block
    preview_output_block = preview_block.split("async function runUplinkPreview")[1].split(
        "const previewBtn"
    )[0]
    assert "planned_uplink_verification_level" in preview_output_block
    assert "uplink_dispatched_unverified" not in preview_output_block
    assert "uplink_verified_bounded" not in preview_output_block
    assert 'text(previewBtn, "Connect' not in preview_block
    assert "Connect/Apply" not in preview_block
    assert "DHCP client path" not in source
    assert "device-exercised on station" in uplink_helpers or "20" in uplink_helpers
    assert "open-network authentication grammar" in uplink_section
    security_label_block = source[
        source.index("function uplinkSecurityLabel") : source.index("function uplinkDisplaySsid")
    ]
    assert 'mode === "open"' in security_label_block
    assert 'return "open"' in security_label_block
    assert "per_network_security_present" in uplink_section
    pick_handler = uplink_section.split("pickBtn.addEventListener")[1]
    pick_open_block = pick_handler.split("selectTd.appendChild")[0]
    assert 'net.wpa_mode === "open"' in pick_open_block
    assert "openNetworkEl.checked = isOpenRow" in pick_open_block
    assert "updateOpenUi()" in pick_open_block
    assert "openUnsupportedEl.hidden = !isOpen" in uplink_section
    assert "skipped_row_count" in uplink_section
    assert "Hidden" in uplink_helpers
    assert "unknown" in uplink_section
    assert "confirm_live_apply" in uplink_section
    assert "link_up" in uplink_section
    assert "device_connected" in uplink_section
    assert "not on-air" in uplink_section
    status_block = uplink_section.split("function renderUplinkStatusRows")[1].split(
        "statusRefreshBtn"
    )[0]
    assert "Venue uplink" in status_block or "uplink-status-venue" in status_block or (
        "renderUplinkStationReadbackInto" in uplink_section
    )
    assert "rebroadcast" in status_block
    assert (
        "join не применён" in status_block
        or "join not applied" in status_block
        or "uplink_verification_status" in status_block
        or "station apply/teardown" in status_block
        or "bounded association" in status_block
        or "renderUplinkStationReadbackInto" in uplink_section
    )
    assert (
        "AP link_up не заимствуется" in status_block
        or "uplink-readback" in uplink_section
        or "renderUplinkStationReadbackInto" in uplink_section
    )
    assert "sample.link_up" not in status_block
    assert "previewJoinBtn.hidden" in uplink_section or "previewJoinBtn.disabled" in uplink_section
    assert "omitName: true" in uplink_section
    assert "ev.preventDefault()" in uplink_section
    assert 'valueEl.value = ""' in uplink_section
    enroll_split = uplink_section.split('appendFormField(credForm, "enroll_value"')[1]
    enroll_field = enroll_split.split(");")[0]
    assert "name:" not in enroll_field and 'name="' not in enroll_field


def test_uplink_readback_status_table_contract() -> None:
    """Structural UI contract: readback table wired to apply response, not comment strings."""
    source = (WEB / "app.js").read_text(encoding="utf-8")

    assert "function classifyUplinkSignalEvidence(" in source
    assert "function renderUplinkStationReadbackInto(" in source
    assert "function isUplinkReadbackSecretKey(" in source
    assert "function sanitizeUplinkReadbackDisplayValue(" in source

    helpers_start = source.index("const UPLINK_READBACK_SECRET_KEYS")
    helpers_end = source.index("function renderStationApplyPlanSummary")
    helpers_block = source[helpers_start:helpers_end]
    assert "associated_ssid" in helpers_block
    assert "configured_ssid" in helpers_block
    assert "appendUplinkReadbackEvidenceRow" in helpers_block
    assert "uplink-evidence-badge-" in helpers_block
    assert "classifyUplinkSignalEvidence" in helpers_block

    uplink_start = source.index("async function renderUplink")
    uplink_section = source[uplink_start : uplink_start + 52000]

    apply_block = source.split("async function executeStationApplyClick")[1].split(
        "async function executeStationTeardownClick"
    )[0]
    assert "renderStationApplyResult" not in apply_block
    assert 'APPLY_TOAST_PATHS["P-station-apply"].toastFromResponse(data)' in apply_block
    assert "executeStationApplyClick({" in uplink_section

    result_fn = uplink_section.split("function renderStationApplyResult(data)")[1].split(
        "async function runUplinkPreview"
    )[0]
    assert "data.uplink_readback" in result_fn
    assert "data.verdict_explanation" in result_fn
    assert "renderUplinkStationReadbackInto(" in result_fn
    assert "lastStationObserve" in result_fn

    readback_fn = source.split("function renderUplinkStationReadbackInto(")[1].split(
        "function renderStationApplyPlanSummary"
    )[0]
    assert "uplink-readback-no-data" in readback_fn
    assert "station join не применён" in readback_fn or "не применён" in readback_fn
    assert "Отвергнут" in helpers_block
    assert "Засчитан" in helpers_block
    assert "sanitizeUplinkReadbackDisplayValue" in helpers_block
    assert "upstream SSID" in helpers_block or "значение скрыто" in helpers_block

    assert "uplink_verification_status" in readback_fn


def test_uplink_readback_status_table_styles(authed_client) -> None:
    css = authed_client.get("/settings/router-control/assets/styles.css").text
    assert ".uplink-evidence-badge-rejected" in css
    assert ".uplink-evidence-badge-counted" in css
    assert ".uplink-readback-no-data" in css or ".uplink-readback-empty" in css


def test_uplink_readback_status_table_red_green() -> None:
    """Guard: contract requires structural wiring — arbitrary comment must not satisfy."""
    source = (WEB / "app.js").read_text(encoding="utf-8")
    assert "function renderUplinkStationReadbackInto(" in source
    assert "data.uplink_readback" not in "// uplink_readback placeholder only"


def test_uplink_styles_present(authed_client) -> None:
    css = authed_client.get("/settings/router-control/assets/styles.css").text
    assert ".uplink-section" in css
    assert ".uplink-scan-form" in css
    assert ".uplink-ap-apply-form" in css
    assert ".uplink-station-apply-form" in css
    assert ".uplink-status-venue-table" in css or ".uplink-status-ap-table" in css


def test_config_ui_verdict_explanation_contract() -> None:
    source = (WEB / "app.js").read_text(encoding="utf-8")
    assert "renderVerdictExplanationInto" in source
    assert "renderApplyResultWithVerdict" in source
    assert "verdictRejectionHumanLabel" in source
    assert "verdict-explanation-rejected" in source
    assert "verdict-explanation-details" in source
    assert "connected_with_link_down" in source
    assert "connected=true при link=down" in source
    assert "txbytes_without_rxbytes" in source
    assert "txbytes > 0 при rxbytes=0" in source
    assert "Отвергнутые обманчивые сигналы" in source
    assert "Подробнее: объяснение вердикта" in source
    wifi_form = _wifi_apply_form_source()
    wifi_handlers = _wifi_apply_handler_source()
    awg_form = _awg_apply_form_source()
    awg_handlers = _awg_apply_handler_source()
    awg_section = awg_form + awg_handlers
    uplink_start = source.index("async function renderUplink")
    uplink_section = source[uplink_start : uplink_start + 46000]
    assert "renderApplyResultWithVerdict" in wifi_form
    assert "renderApplyResultWithVerdict" in awg_section
    assert "renderApplyResultWithVerdict" in uplink_section
    assert "verdictExplanationBox" in wifi_form
    assert "wifiApplyUi.renderResult" in wifi_handlers
    assert "awgApplyUi.renderResult" in awg_handlers or "renderAwgApplyResult" in awg_handlers
    assert "verdictExplanationBox" in awg_form
    assert "stationVerdictExplanationBox" in uplink_section


def test_config_ui_verdict_explanation_styles(authed_client) -> None:
    css = authed_client.get("/settings/router-control/assets/styles.css").text
    assert ".verdict-explanation-rejected" in css
    assert ".verdict-explanation-details" in css


_UPSTREAM_SSID_UI_MARKER = "RC-UPSTREAM-SSID-UI-MARKER-e5f6a7b8"


_UPSTREAM_SSID_UI_MARKER = "RC-UPSTREAM-SSID-UI-MARKER-e5f6a7b8"
_CREDENTIAL_SECRET_UI_MARKER = "RC-CREDENTIAL-SECRET-UI-MARKER-c1d2e3f4"
UI_DOM_HARNESS = REPO_ROOT / "tests" / "support" / "ui_dom_harness.js"


def _load_manifest_in_dom_script() -> str:
    return r"""
const manifestPath = process.argv[1].replace(/app\.js$/, "ui-field-manifest.json");
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
uiExports.setFieldManifestForTest(manifest);
"""


def _run_ui_dom_runtime(script_body: str) -> dict[str, object]:
    """Execute app.js against the richer offline DOM harness (Node)."""
    node = shutil.which("node")
    if node is None:
        pytest.skip("node not available")
    app_js = WEB / "app.js"
    harness_js = UI_DOM_HARNESS.read_text(encoding="utf-8")
    harness = (
        harness_js
        + r"""
const fs = require("fs");
const source = fs.readFileSync(process.argv[1], "utf8");
const dom = createUiDomHarness();
globalThis.document = dom.document;
globalThis.window = dom.window;
globalThis.localStorage = dom.localStorage;
globalThis.location = { hash: "#config" };
globalThis.crypto = { randomUUID: () => "00000000-0000-4000-8000-000000000001" };
globalThis.__ROUTER_CONTROL_UI_TEST__ = true;
eval(source);
const uiExports = globalThis.__ROUTER_CONTROL_UI_TEST__;
if (!uiExports || typeof uiExports !== "object") {
  throw new Error("UI test exports missing");
}
"""
        + script_body
    )
    proc = subprocess.run(
        [node, "-e", harness, str(app_js)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    if proc.returncode != 0:
        pytest.fail(
            "node UI DOM runtime failed:\n"
            f"stdout={proc.stdout}\nstderr={proc.stderr}",
        )
    return json.loads(proc.stdout.strip())


def _wifi_apply_manifest_ui_defaults() -> dict[str, object]:
    """Defaults the UI must mirror from ui-field-manifest.json when manifest is loaded."""
    manifest = json.loads((WEB / "ui-field-manifest.json").read_text(encoding="utf-8"))
    by_name = {
        field["name"]: field.get("default")
        for field in manifest["families"]["wifi_ap"]["fields"]
    }

    def _bool_default(name: str) -> bool:
        val = by_name.get(name)
        return bool(val) if val is not None else False

    return {
        "band": by_name.get("band") or "BAND_2_4GHZ",
        "wpa_mode": by_name.get("wpa_mode") or "WPA2",
        "guest_isolation": _bool_default("guest_isolation"),
        "captive_portal": by_name.get("captive_portal") or "Disabled",
        "enabled": _bool_default("enabled"),
        "credential_ref_id": by_name.get("credential_ref_id"),
        "confirm_live_apply": _bool_default("confirm_live_apply"),
        "compensate_on_failure": _bool_default("compensate_on_failure"),
        "idempotent": _bool_default("idempotent"),
    }


def _wifi_apply_model_ui_defaults() -> dict[str, object]:
    """Defaults the UI must mirror for WifiApplyBody-controlled fields."""
    from router_control.domain.network_intents import CaptivePortalMode, WifiBand, WifiWpaMode
    from router_control_host.wifi_apply_routes import WifiApplyBody

    body_fields = WifiApplyBody.model_fields
    return {
        "band": WifiBand.BAND_2_4GHZ.value,
        "wpa_mode": WifiWpaMode.WPA2.value,
        "guest_isolation": False,
        "captive_portal": CaptivePortalMode.DISABLED.value,
        "enabled": True,
        "credential_ref_id": body_fields["credential_ref_id"].default,
        "confirm_live_apply": body_fields["confirm_live_apply"].default,
        "compensate_on_failure": body_fields["compensate_on_failure"].default,
        "idempotent": body_fields["idempotent"].default,
    }


def _run_app_js_ui_checks(script_body: str) -> dict[str, object]:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node not available")
    app_js = WEB / "app.js"
    harness = r"""
const fs = require("fs");
const source = fs.readFileSync(process.argv[1], "utf8");
globalThis.__ROUTER_CONTROL_UI_TEST__ = true;
globalThis.document = {
  createElement(tag) {
    const node = {
      tagName: String(tag).toUpperCase(),
      className: "",
      textContent: "",
      children: [],
      appendChild(c) { this.children.push(c); return c; },
      setAttribute() {},
      removeAttribute() {},
      classList: { toggle() {}, add() {}, remove() {} },
      get firstChild() { return this.children[0] || null; },
      removeChild(c) {
        const idx = this.children.indexOf(c);
        if (idx >= 0) this.children.splice(idx, 1);
      },
    };
    return node;
  },
};
globalThis.location = { hash: "#dashboard" };
globalThis.crypto = { randomUUID: () => "00000000-0000-4000-8000-000000000001" };
globalThis.window = globalThis;
eval(source);
const uiExports = globalThis.__ROUTER_CONTROL_UI_TEST__;
if (!uiExports || typeof uiExports !== "object") {
  throw new Error("UI test exports missing");
}
""" + script_body
    proc = subprocess.run(
        [node, "-e", harness, str(app_js)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    if proc.returncode != 0:
        pytest.fail(
            "node UI harness failed:\n"
            f"stdout={proc.stdout}\nstderr={proc.stderr}",
        )
    return json.loads(proc.stdout.strip())


def test_ui_runtime_apply_result_redacts_upstream_ssid_from_dom_dump() -> None:
    marker = _UPSTREAM_SSID_UI_MARKER
    script = f"""
const marker = {json.dumps(marker)};
const payload = {{
  overall: "applied",
  uplink_verification_status: "uplink_verified_bounded",
  uplink_readback: {{
    configured_ssid: marker,
    associated_ssid: marker,
    associated_ssid_field_present: true,
    associated_ssid_matches_intent: true,
  }},
  verdict_explanation: {{
    signals_read: [{{ signal: "associated_ssid_matches_intent", value: true }}],
    signals_missing: [],
    signals_rejected: [],
  }},
}};
const box = document.createElement("pre");
uiExports.renderApplyResultWithVerdict(null, box, payload);
const sanitized = uiExports.sanitizeApplyResultForDisplay(payload);
console.log(JSON.stringify({{
  marker_in_box: box.textContent.includes(marker),
  marker_in_sanitized: JSON.stringify(sanitized).includes(marker),
  box_has_redacted: box.textContent.includes("[REDACTED]"),
}}));
"""
    result = _run_app_js_ui_checks(script)
    assert result["marker_in_box"] is False
    assert result["marker_in_sanitized"] is False
    assert result["box_has_redacted"] is True


def test_ui_runtime_awg_toast_not_success_when_tunnel_unverified() -> None:
    script = """
const prefix = uiExports.awgApplyToastPrefix({
    overall: "applied",
    tunnel_verification_status: "tunnel_unverified",
}, "Apply");
console.log(JSON.stringify({
    prefix,
    looks_like_success: prefix === "Apply: applied" || prefix.startsWith("Apply: applied"),
}));
"""
    result = _run_app_js_ui_checks(script)
    assert result["looks_like_success"] is False
    assert "NOT verified" in str(result["prefix"])


def test_ui_runtime_apply_toast_overall_before_verdict() -> None:
    """Terminal overall failure must lead toast prefix — verdict is secondary (honesty summary)."""
    script = """
const cases = [
  {
    fn: "wifiApplyToastPrefix",
    data: { overall: "failed", on_air_verification_status: "on_air_unverified" },
    action: "Apply",
    expect: "Apply FAILED",
  },
  {
    fn: "wifiApplyToastPrefix",
    data: { overall: "verify_mismatch", on_air_verification_status: "on_air_unverified" },
    action: "Teardown",
    expect: "Teardown VERIFY MISMATCH",
  },
  {
    fn: "awgApplyToastPrefix",
    data: { overall: "failed", tunnel_verification_status: "tunnel_unverified" },
    action: "Apply",
    expect: "Apply FAILED",
  },
  {
    fn: "awgApplyToastPrefix",
    data: { overall: "verify_mismatch", tunnel_verification_status: "tunnel_unverified" },
    action: "Teardown",
    expect: "Teardown VERIFY MISMATCH",
  },
  {
    fn: "stationApplyToastPrefix",
    data: { overall: "failed", uplink_verification_status: "uplink_dispatched_unverified" },
    action: "Apply",
    expect: "Apply FAILED",
  },
  {
    fn: "wifiApplyToastPrefix",
    data: { overall: "applied", on_air_verification_status: "on_air_unverified" },
    action: "Apply",
    expect: "Apply NOT verified",
  },
  {
    fn: "awgApplyToastPrefix",
    data: { overall: "rolled_back", tunnel_verification_status: "tunnel_unverified" },
    action: "Apply",
    expect: "Apply ROLLED BACK",
  },
];
const results = cases.map((c) => ({
  fn: c.fn,
  overall: c.data.overall,
  verdict:
    c.data.on_air_verification_status
    || c.data.tunnel_verification_status
    || c.data.uplink_verification_status
    || null,
  prefix: uiExports[c.fn](c.data, c.action),
  expect: c.expect,
  ok: uiExports[c.fn](c.data, c.action) === c.expect,
}));
console.log(JSON.stringify({ results, all_ok: results.every((r) => r.ok) }));
"""
    result = _run_app_js_ui_checks(script)
    assert result["all_ok"] is True, result["results"]


def test_ui_runtime_apply_toast_full_matrix_no_false_success() -> None:
    """Every overall×verdict combo: only positive verdicts may read as success."""
    script = r"""
const OVERALLS = [
  "applied",
  "failed",
  "verify_mismatch",
  "rolled_back",
  "dispatched_offline",
  "unsupported_pending_verification",
];
const FAMILIES = [
  {
    fn: "stationApplyToastPrefix",
    field: "uplink_verification_status",
    verdicts: [
      null,
      "uplink_verified_bounded",
      "uplink_dispatched_unverified",
      "uplink_associated_no_global",
      "uplink_failed",
    ],
    positive: { uplink_verified_bounded: "Apply verified bounded" },
    failures: { uplink_failed: "Apply FAILED" },
    defaultNonSuccess: "Apply NOT verified",
  },
  {
    fn: "wifiApplyToastPrefix",
    field: "on_air_verification_status",
    verdicts: [
      null,
      "on_air_verified",
      "on_air_admin_only",
      "on_air_unverified",
      "on_air_still_broadcasting",
    ],
    positive: { on_air_verified: "Apply verified on-air" },
    failures: { on_air_still_broadcasting: "Apply FAILED" },
    defaultNonSuccess: "Apply NOT verified",
  },
  {
    fn: "awgApplyToastPrefix",
    field: "tunnel_verification_status",
    verdicts: [
      null,
      "tunnel_healthy",
      "tunnel_unverified",
      "tunnel_no_peer",
      "tunnel_never_handshaked",
    ],
    positive: { tunnel_healthy: "Apply verified tunnel" },
    failures: { tunnel_never_handshaked: "Apply FAILED tunnel" },
    defaultNonSuccess: "Apply NOT verified",
  },
];
const TERMINAL_OVERALL = {
  failed: "Apply FAILED",
  verify_mismatch: "Apply VERIFY MISMATCH",
  rolled_back: "Apply ROLLED BACK",
  unsupported_pending_verification: "Apply UNSUPPORTED",
};
function looksLikeSuccess(prefix) {
  if (!prefix || typeof prefix !== "string") return false;
  if (prefix.includes(": applied")) return true;
  if (prefix.includes(": done")) return true;
  if (prefix.endsWith(" NOT on-air")) return true;
  if (prefix.includes(" verified ")) return true;
  return false;
}
const rows = [];
for (const family of FAMILIES) {
  for (const overall of OVERALLS) {
    for (const verdict of family.verdicts) {
      const data = { overall };
      if (verdict != null) data[family.field] = verdict;
      const prefix = uiExports[family.fn](data, "Apply");
      let expect;
      if (TERMINAL_OVERALL[overall]) {
        expect = TERMINAL_OVERALL[overall];
      } else if (overall === "applied" && verdict && family.positive[verdict]) {
        expect = family.positive[verdict];
      } else if (overall === "applied" && verdict && family.failures[verdict]) {
        expect = family.failures[verdict];
      } else if (overall === "applied") {
        expect = family.defaultNonSuccess;
      } else {
        expect = "Apply unknown (overall " + overall + ")";
      }
      const ok = prefix === expect;
      const falseSuccess = !ok && looksLikeSuccess(prefix);
      rows.push({
        family: family.fn,
        overall,
        verdict,
        prefix,
        expect,
        ok,
        falseSuccess,
      });
    }
  }
}
console.log(JSON.stringify({
  rows,
  all_ok: rows.every((r) => r.ok),
  any_false_success: rows.some((r) => r.falseSuccess),
}));
"""
    result = _run_app_js_ui_checks(script)
    assert result["all_ok"] is True, result["rows"]
    assert result["any_false_success"] is False


def test_ui_runtime_station_applied_without_verdict_not_success() -> None:
    script = """
const prefix = uiExports.stationApplyToastPrefix({ overall: "applied" }, "Apply");
console.log(JSON.stringify({
  prefix,
  ok: prefix === "Apply NOT verified",
  looks_like_success: prefix === "Apply: applied",
}));
"""
    result = _run_app_js_ui_checks(script)
    assert result["ok"] is True
    assert result["looks_like_success"] is False


def test_ui_runtime_f7_positive_verdict_without_overall_not_success() -> None:
    script = """
const prefix = uiExports.wifiApplyToastPrefix({
  on_air_verification_status: "on_air_verified",
}, "Apply");
console.log(JSON.stringify({
  prefix,
  ok: prefix === "Apply unknown (overall missing)",
  was_false_success: prefix === "Apply verified on-air",
  not_not_verified: prefix !== "Apply NOT verified",
}));
"""
    result = _run_app_js_ui_checks(script)
    assert result["ok"] is True
    assert result["was_false_success"] is False
    assert result["not_not_verified"] is True


def test_ui_runtime_f7_dispatched_offline_plus_positive_verdict_not_success() -> None:
    script = """
const prefix = uiExports.wifiApplyToastPrefix({
  overall: "dispatched_offline",
  on_air_verification_status: "on_air_verified",
}, "Apply");
console.log(JSON.stringify({
  prefix,
  ok: prefix === "Apply unknown (overall dispatched_offline)",
  was_false_success: prefix === "Apply verified on-air",
  not_not_verified: prefix !== "Apply NOT verified",
}));
"""
    result = _run_app_js_ui_checks(script)
    assert result["ok"] is True
    assert result["was_false_success"] is False
    assert result["not_not_verified"] is True


def test_ui_runtime_wifi_still_broadcasting_reads_as_failure() -> None:
    script = """
const prefix = uiExports.wifiApplyToastPrefix({
  overall: "applied",
  on_air_verification_status: "on_air_still_broadcasting",
}, "Teardown");
console.log(JSON.stringify({
  prefix,
  ok: prefix === "Teardown FAILED",
  was_soft: prefix === "Teardown NOT on-air",
}));
"""
    result = _run_app_js_ui_checks(script)
    assert result["ok"] is True
    assert result["was_soft"] is False


def test_ui_dom_wifi_apply_panel_renders_expected_controls() -> None:
    script = r"""
const ui = uiExports.buildWifiApplyFormSurface({ expendable: false });
document.body.appendChild(ui.panel);
const ids = [
  "wifi-apply-ap-id",
  "wifi-apply-ssid",
  "wifi-apply-band",
  "wifi-apply-wpa-mode",
  "wifi-apply-psk-cred-ref",
  "wifi-apply-guest-isolation",
  "wifi-apply-confirm",
];
const present = ids.map((id) => ({ id, found: !!document.getElementById(id) }));
console.log(JSON.stringify({
  present,
  all_found: present.every((row) => row.found),
  has_form_class: ui.form.className.includes("config-wifi-apply-form"),
  tree_depth_ok: JSON.stringify(dom.collectDomTree(ui.form)).includes("wifi-apply-ssid"),
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["all_found"] is True, result["present"]
    assert result["has_form_class"] is True
    assert result["tree_depth_ok"] is True


def test_ui_dom_wifi_apply_advanced_hidden_until_expanded() -> None:
    script = r"""
const ui = uiExports.buildWifiApplyFormSurface({ expendable: false });
document.body.appendChild(ui.panel);
const closedText = dom.collectVisibleText(ui.form);
const advancedOpen = ui.advancedDetails.open;
ui.advancedDetails.open = true;
const openText = dom.collectVisibleText(ui.form);
console.log(JSON.stringify({
  advanced_open_initially: advancedOpen,
  closed_has_summary: closedText.includes("Дополнительные настройки"),
  closed_hides_host: !closedText.includes("Router host"),
  closed_hides_confirm: !closedText.includes("Подтверждаю live apply"),
  closed_hides_wpa: !closedText.includes("WPA mode"),
  closed_hides_ap: !closedText.includes("Test AP"),
  open_shows_host: openText.includes("Router host"),
  open_shows_confirm: openText.includes("Подтверждаю live apply"),
  open_shows_wpa: openText.includes("WPA mode"),
  open_shows_ap: openText.includes("Test AP"),
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["advanced_open_initially"] is False
    assert result["closed_has_summary"] is True
    assert result["closed_hides_host"] is True
    assert result["closed_hides_confirm"] is True
    assert result["closed_hides_wpa"] is True
    assert result["closed_hides_ap"] is True
    assert result["open_shows_host"] is True
    assert result["open_shows_confirm"] is True
    assert result["open_shows_wpa"] is True
    assert result["open_shows_ap"] is True


def test_ui_dom_wifi_apply_defaults_match_request_model() -> None:
    expected = _wifi_apply_manifest_ui_defaults()
    script = f"""
{_load_manifest_in_dom_script()}
const expected = {json.dumps(expected)};
const ui = uiExports.buildWifiApplyFormSurface({{ expendable: false }});
document.body.appendChild(ui.panel);
const payload = ui.readPayload(true);
const compare = {{
  band: payload.band === expected.band,
  wpa_mode: payload.wpa_mode === expected.wpa_mode,
  guest_isolation: payload.guest_isolation === expected.guest_isolation,
  captive_portal: payload.captive_portal === expected.captive_portal,
  enabled: payload.enabled === expected.enabled,
  credential_ref_id: payload.credential_ref_id === expected.credential_ref_id,
  confirm_live_apply: payload.confirm_live_apply === expected.confirm_live_apply,
  compensate_on_failure: payload.compensate_on_failure === expected.compensate_on_failure,
  idempotent: payload.idempotent === expected.idempotent,
}};
console.log(JSON.stringify({{
  payload,
  expected,
  compare,
  all_ok: Object.values(compare).every(Boolean),
}}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["all_ok"] is True, result


def test_ui_dom_credential_secret_not_in_result_markup() -> None:
    marker = _CREDENTIAL_SECRET_UI_MARKER
    script = f"""
const marker = {json.dumps(marker)};
const surface = uiExports.buildCredentialEnrollTestSurface();
document.body.appendChild(surface.mount);
document.body.appendChild(surface.resultBox);
surface.valueInput.value = marker;
surface.renderEnrollResult({{
  credential_ref_id: "cred_test_001",
  kind: "RouterManagementPassword",
}});
const resultText = surface.resultBox.textContent || "";
const resultVisible = uiExports.collectDomVisibleText(surface.resultBox);
console.log(JSON.stringify({{
  marker_in_result: resultText.includes(marker),
  marker_in_result_visible: resultVisible.includes(marker),
  result_has_ref: resultText.includes("cred_test_001"),
  form_still_holds_secret: surface.valueInput.value === marker,
}}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["marker_in_result"] is False
    assert result["marker_in_result_visible"] is False
    assert result["result_has_ref"] is True
    assert result["form_still_holds_secret"] is True


def test_ui_dom_apply_result_no_false_success_without_positive_verdict() -> None:
    script = r"""
const ui = uiExports.buildWifiApplyFormSurface({ expendable: false });
document.body.appendChild(ui.panel);
const data = {
  overall: "applied",
  on_air_verification_status: "on_air_unverified",
};
ui.renderResult(data);
const visible =
  uiExports.collectDomVisibleText(ui.resultPanel)
  + "\n"
  + uiExports.wifiApplyHonestySummary(data);
console.log(JSON.stringify({
  misleading: uiExports.domHasMisleadingApplySuccessText(data, visible),
  has_not_verified_honesty: visible.includes("on-air NOT verified"),
  toast_prefix: uiExports.wifiApplyToastPrefix(data, "Apply"),
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["misleading"] is False
    assert result["has_not_verified_honesty"] is True
    assert result["toast_prefix"] == "Apply NOT verified"


def test_ui_dom_wifi_apply_advanced_red_green_guard() -> None:
    """Guard: advanced fields must not be visible while details stays closed."""
    script = r"""
const ui = uiExports.buildWifiApplyFormSurface({ expendable: false });
document.body.appendChild(ui.panel);
const blob = dom.collectVisibleText(ui.form);
console.log(JSON.stringify({
  fails_if_confirm_visible_while_closed: blob.includes("Подтверждаю live apply"),
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["fails_if_confirm_visible_while_closed"] is False
