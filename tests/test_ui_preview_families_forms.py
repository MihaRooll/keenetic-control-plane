"""DOM-harness tests for P4 preview families simple/advanced + collections."""

from __future__ import annotations

import json

from tests.test_config_ui import _run_ui_dom_runtime


def _minimal_wifi_manifest_js() -> str:
    return json.dumps(
        {
            "families": {
                "wifi_ap": {
                    "fields": [
                        {
                            "name": "ssid",
                            "tooltip": "Имя беспроводной сети (SSID), 1–32 символа.",
                        },
                        {"name": "credential_ref_id", "tooltip": "Sealed credential."},
                        {"name": "band", "tooltip": "Диапазон Wi‑Fi: 2,4 ГГц или 5 ГГц."},
                    ],
                },
            },
        },
        ensure_ascii=False,
    )


def _minimal_vlan_manifest_js() -> str:
    return json.dumps(
        {
            "families": {
                "vlan": {
                    "fields": [
                        {"name": "bridge_id", "tooltip": "Bridge интерфейс для VLAN subinterface."},
                    ],
                },
            },
        },
        ensure_ascii=False,
    )


def test_vlan_preview_advanced_and_tooltips() -> None:
    manifest_js = _minimal_vlan_manifest_js()
    script = f"""
uiExports.setFieldManifestForTest({manifest_js});
const ui = uiExports.buildVlanPreviewFormSurface();
document.body.appendChild(ui.panel);
const advanced = dom.queryByTestId("vlan-preview-advanced-settings", ui.form);
const gateway = document.getElementById("vlan-preview-ipv4-gateway");
const tooltip = dom.queryByTestId("vlan-preview-bridge-id-tooltip", ui.form);
console.log(JSON.stringify({{
  has_advanced: !!advanced,
  has_gateway: !!gateway,
  has_tooltip: !!tooltip,
  closed_hides_gateway: !dom.collectVisibleText(ui.form).includes("10.20.0.1") || !gateway.value,
}}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["has_advanced"] is True
    assert result["has_gateway"] is True
    assert result["has_tooltip"] is True


def test_dhcp_preview_reservations_collection_payload() -> None:
    script = r"""
const ui = uiExports.buildDhcpPreviewFormSurface();
document.body.appendChild(ui.panel);
ui.advancedDetails.open = true;
document.getElementById("dhcp-preview-zone-id").value = "Guest";
document.getElementById("dhcp-preview-pool-start").value = "10.10.10.50";
document.getElementById("dhcp-preview-pool-end").value = "10.10.10.200";
document.getElementById("dhcp-preview-lease-seconds").value = "3600";
ui.reservationsEditor.addRow({ mac_address: "aa:bb:cc:dd:ee:01", ipv4_address: "10.10.10.60" });
const payload = ui.readPayload();
console.log(JSON.stringify({
  reservations_len: payload.reservations.length,
  mac: payload.reservations[0].mac_address,
  lease: payload.lease_seconds,
  has_collection: !!dom.queryByTestId("dhcp-preview-reservations", ui.form),
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["has_collection"] is True
    assert result["reservations_len"] == 1
    assert result["mac"] == "aa:bb:cc:dd:ee:01"
    assert result["lease"] == 3600


def test_firewall_preview_rules_collection_not_json_field() -> None:
    script = r"""
const ui = uiExports.buildFirewallPreviewFormSurface();
document.body.appendChild(ui.panel);
ui.advancedDetails.open = true;
document.getElementById("firewall-preview-zone-id").value = "Guest";
const payload = ui.readPayload();
const jsonField = document.getElementById("firewall-preview-rules-json");
console.log(JSON.stringify({
  has_rules_editor: !!dom.queryByTestId("firewall-preview-rules", ui.form),
  no_json_field: !jsonField,
  rules_shape: payload.rules[0],
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["has_rules_editor"] is True
    assert result["no_json_field"] is True
    assert result["rules_shape"]["action"] == "Allow"
    assert "destination_family" in result["rules_shape"]


def test_preview_honesty_banners_present() -> None:
    script = r"""
const ui = uiExports.buildVlanPreviewFormSurface();
document.body.appendChild(ui.panel);
const visible = dom.collectVisibleText(ui.panel);
console.log(JSON.stringify({
  offline: visible.includes("offline_unverified"),
  no_apply: visible.includes("NO APPLY"),
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["offline"] is True
    assert result["no_apply"] is True


def test_vpn_policy_preview_name_servers_collection() -> None:
    script = r"""
const ui = uiExports.buildVpnPolicyPreviewFormSurface();
document.body.appendChild(ui.panel);
ui.advancedDetails.open = true;
document.getElementById("vpn-policy-name").value = "test-policy";
document.getElementById("vpn-policy-interface").value = "Wireguard0";
ui.nameServersEditor.addRow({ address: "1.1.1.1", domain: "example.com" });
const payload = ui.readPayload();
console.log(JSON.stringify({
  has_editor: !!dom.queryByTestId("vpn-policy-name-servers", ui.form),
  ns_len: payload.name_servers.length,
  ns_domain: payload.name_servers[0].domain,
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["has_editor"] is True
    assert result["ns_len"] == 1
    assert result["ns_domain"] == "example.com"


def test_vpn_policy_preview_address_configured_false_payload() -> None:
    script = r"""
const ui = uiExports.buildVpnPolicyPreviewFormSurface();
document.body.appendChild(ui.panel);
ui.advancedDetails.open = true;
document.getElementById("vpn-policy-name").value = "test-policy";
document.getElementById("vpn-policy-interface").value = "Wireguard0";
document.getElementById("vpn-policy-address-configured").value = "false";
const payload = ui.readPayload();
console.log(JSON.stringify({
  address_configured: payload.address_configured,
  has_key: Object.prototype.hasOwnProperty.call(payload, "address_configured"),
}));
"""
    result = _run_ui_dom_runtime(script)
    assert result["has_key"] is True
    assert result["address_configured"] is False
