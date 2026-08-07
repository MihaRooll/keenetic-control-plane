"""VPN policy-routing preview host API tests (preview-only; no apply route)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from router_control.adapters.netcraze.vpn_policy_rci import VpnPolicyRciOperation
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie

_DOC_CITATION = "OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md"


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    app = create_app(db_path=tmp_path / "vpn-policy-preview.sqlite3", enable_worker=False)
    from fastapi.testclient import TestClient

    with TestClient(app) as tc:
        tc.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield tc


_PREVIEW_BODY = {
    "policy_name": "vpn-uplink",
    "vpn_interface": "GigabitEthernet1",
    "interface_kind": "other",
    "ip_global": {"priority": 700},
    "name_servers": [{"address": "1.1.1.1"}],
}


def test_vpn_policy_preview_compiles_offline(client) -> None:
    resp = client.post("/api/router-control/v1/vpn/policy-routing/preview", json=_PREVIEW_BODY)
    assert resp.status_code == 200
    body = resp.json()
    assert body["verification_status"] == "help_verified_grammar_unapplied"
    assert body["policy_name"] == "vpn-uplink"
    assert [op["operation"] for op in body["apply_ops"]] == [
        VpnPolicyRciOperation.SET_NAME_SERVER.value,
        VpnPolicyRciOperation.IP_GLOBAL.value,
        VpnPolicyRciOperation.CREATE_POLICY.value,
    ]
    ip_global_op = body["apply_ops"][1]
    assert ip_global_op["interface_id"] == "GigabitEthernet1"
    assert ip_global_op["global_priority"] == 700
    assert any(_DOC_CITATION in note for note in ip_global_op["notes"])
    assert [op["operation"] for op in body["teardown_ops"]] == [
        VpnPolicyRciOperation.REMOVE_POLICY.value,
        VpnPolicyRciOperation.IP_GLOBAL_TEARDOWN_UNVERIFIED.value,
        VpnPolicyRciOperation.CLEAR_NAME_SERVER.value,
    ]


def test_vpn_policy_preview_wg_without_address_422(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")
    resp = client.post(
        "/api/router-control/v1/vpn/policy-routing/preview",
        json={
            "policy_name": "vpn-wg",
            "vpn_interface": "Wireguard0",
            "interface_kind": "wireguard",
            "address_configured": False,
            "ip_global": "auto",
        },
    )
    assert resp.status_code == 422
    body = resp.json()
    assert body["error"]["code"] == "vpn.policy_routing_preview_failed"
    assert "Wireguard0" not in json.dumps(body)


_NON_CANONICAL_WIREGUARD_INTERFACE_NAMES: tuple[str, ...] = (
    "wireguard0",
    "WIREGUARD0",
    "WireGuard0",
    "Wireguard",
    "Wireguard00",
    "Wireguard 0",
    "Wire guard0",
    "Wireguard-0",
    "Wireguard_0",
    "wg0",
    "WG0",
    "Wireguard999999",
    "Wireguard-1",
)


@pytest.mark.parametrize("vpn_interface", _NON_CANONICAL_WIREGUARD_INTERFACE_NAMES)
def test_vpn_policy_preview_non_canonical_wg_name_422(
    client,
    vpn_interface: str,
) -> None:
    resp = client.post(
        "/api/router-control/v1/vpn/policy-routing/preview",
        json={
            "policy_name": "vpn-wg",
            "vpn_interface": vpn_interface,
            "ip_global": "auto",
        },
    )
    assert resp.status_code == 422
    body = resp.json()
    assert body["error"]["code"] == "vpn.policy_routing_preview_failed"
    assert vpn_interface not in json.dumps(body)


def test_vpn_policy_preview_canonical_wireguard0_200(
    client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")
    resp = client.post(
        "/api/router-control/v1/vpn/policy-routing/preview",
        json={
            "policy_name": "vpn-wg",
            "vpn_interface": "Wireguard0",
            "interface_kind": "wireguard",
            "address_configured": True,
            "ip_global": "auto",
        },
    )
    assert resp.status_code == 200
    assert resp.json()["vpn_interface"] == "Wireguard0"


@pytest.mark.parametrize(
    ("ip_global", "expected_substring"),
    [
        ({"priority": True}, "priority"),
        ({"priority": "700"}, "priority"),
        ({"order": True}, "order"),
        ({"order": "600"}, "order"),
        ({"priority": -1}, "priority"),
        ({"priority": 70000}, "priority"),
        ({"order": 70000}, "order"),
    ],
)
def test_vpn_policy_preview_rejects_ip_global_coercion_and_bounds(
    client,
    ip_global: dict[str, object],
    expected_substring: str,
) -> None:
    resp = client.post(
        "/api/router-control/v1/vpn/policy-routing/preview",
        json={**_PREVIEW_BODY, "ip_global": ip_global},
    )
    assert resp.status_code == 422
    payload = resp.json()
    assert "error" in payload
    error = payload["error"]
    assert error["code"] == "request.validation_failed"
    message = error.get("message", "")
    details_text = json.dumps(error.get("details", []))
    combined = f"{message.lower()} {details_text.lower()}"
    assert expected_substring in combined
    body_text = json.dumps(payload)
    if isinstance(ip_global.get("priority"), str):
        assert ip_global["priority"] not in body_text
    if isinstance(ip_global.get("order"), str):
        assert ip_global["order"] not in body_text


def test_vpn_policy_preview_openapi_ip_global_bounds(client) -> None:
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    schema = resp.json()
    priority_schema = schema["components"]["schemas"]["VpnPolicyIpGlobalPriorityBody"]
    assert priority_schema["properties"]["priority"]["minimum"] == 0
    assert priority_schema["properties"]["priority"]["maximum"] == 65535
    order_schema = schema["components"]["schemas"]["VpnPolicyIpGlobalOrderBody"]
    assert order_schema["properties"]["order"]["minimum"] == 0
    assert order_schema["properties"]["order"]["maximum"] == 65535


def test_vpn_policy_preview_rejects_invalid_ip_global_shape(client) -> None:
    resp = client.post(
        "/api/router-control/v1/vpn/policy-routing/preview",
        json={
            **_PREVIEW_BODY,
            "ip_global": {"priority": 700, "extra": 1},
        },
    )
    assert resp.status_code == 422


def test_openapi_has_preview_not_apply(client) -> None:
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    schema = resp.json()
    paths = schema["paths"]
    assert "/api/router-control/v1/vpn/policy-routing/preview" in paths
    assert "/api/router-control/v1/vpn/policy-routing/apply" not in paths
    assert "/api/router-control/v1/vpn/policy-routing/teardown" not in paths
    preview_post = paths["/api/router-control/v1/vpn/policy-routing/preview"]["post"]
    response_schema = preview_post["responses"]["200"]["content"]["application/json"]["schema"]
    if "$ref" in response_schema:
        ref_name = response_schema["$ref"].rsplit("/", 1)[-1]
        response_schema = schema["components"]["schemas"][ref_name]
    assert "verification_status" in response_schema["properties"]

