"""Network family preview host API tests (VLAN/DHCP/DNS/firewall; preview-only; no apply routes)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from router_control.adapters.netcraze.dhcp_rci import DhcpRciOperation
from router_control.adapters.netcraze.dns_rci import DnsRciOperation
from router_control.adapters.netcraze.firewall_rci import FirewallRciOperation
from router_control.adapters.netcraze.vlan_rci import VlanRciOperation
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie

_API = "/api/router-control/v1"

_VLAN_BODY = {
    "bridge_id": "Bridge3",
    "zone_id": "staff",
    "vlan_id": 20,
    "ipv4_cidr": "10.20.0.0/24",
    "ipv4_gateway": "10.20.0.1",
}

_DHCP_BODY = {
    "zone_id": "Guest",
    "pool_start": "10.10.0.100",
    "pool_end": "10.10.0.200",
    "lease_seconds": 86400,
    "reservations": [
        {"mac_address": "aa:bb:cc:00:00:01", "ipv4_address": "10.10.0.50"},
    ],
}

_DNS_BODY = {
    "zone_id": "Guest",
    "local_fqdn": "order.guest.example.com",
    "upstream_resolvers": ["8.8.8.8"],
}

_FIREWALL_BODY = {
    "zone_id": "Guest",
    "rules": [
        {"action": "Allow", "destination_family": "OrderPage", "ordinal": 10},
        {"action": "Allow", "destination_family": "Dns", "ordinal": 20},
    ],
}

_SECRET_FIELD_NAMES = ("password", "psk", "private_key", "preshared_key")

_INJECTION_ZONE_IDS = (
    "Guest;drop table",
    "Guest\ninjected",
    "Guest/`id`",
    "Guest/evil",
    "Guest\u00a0space",
)


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    app = create_app(db_path=tmp_path / "network-family-preview.sqlite3", enable_worker=False)
    from fastapi.testclient import TestClient

    with TestClient(app) as tc:
        tc.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield tc


def test_vlan_preview_compiles_offline(client) -> None:
    resp = client.post(f"{_API}/vlan/preview", json=_VLAN_BODY)
    assert resp.status_code == 200
    body = resp.json()
    assert body["verification_status"] == "offline_unverified"
    assert body["bridge_id"] == "Bridge3"
    assert body["vlan_id"] == 20
    assert [op["operation"] for op in body["apply_ops"]] == [
        VlanRciOperation.CREATE_BRIDGE.value,
        VlanRciOperation.SET_IP_ADDRESS.value,
        VlanRciOperation.UP.value,
    ]
    set_ip = body["apply_ops"][1]
    assert set_ip["ipv4_gateway"] == "10.20.0.1"
    assert set_ip["ipv4_mask"] == "255.255.255.0"
    assert [op["operation"] for op in body["teardown_ops"]] == [
        VlanRciOperation.DOWN.value,
        VlanRciOperation.CLEAR_IP_ADDRESS.value,
        VlanRciOperation.REMOVE_BRIDGE.value,
    ]


def test_dhcp_preview_compiles_offline(client) -> None:
    resp = client.post(f"{_API}/dhcp/preview", json=_DHCP_BODY)
    assert resp.status_code == 200
    body = resp.json()
    assert body["verification_status"] == "offline_unverified"
    assert body["zone_id"] == "Guest"
    assert body["lease_seconds"] == 86400
    assert [op["operation"] for op in body["apply_ops"]] == [
        DhcpRciOperation.SET_POOL.value,
        DhcpRciOperation.SET_LEASE.value,
        DhcpRciOperation.BIND_HOST.value,
    ]
    bind_op = body["apply_ops"][2]
    assert bind_op["mac_address"] == "aa:bb:cc:00:00:01"
    assert bind_op["ipv4_address"] == "10.10.0.50"


def test_dns_preview_compiles_offline(client) -> None:
    resp = client.post(f"{_API}/dns/preview", json=_DNS_BODY)
    assert resp.status_code == 200
    body = resp.json()
    assert body["verification_status"] == "offline_unverified"
    assert body["local_fqdn"] == "order.guest.example.com"
    assert [op["operation"] for op in body["apply_ops"]] == [
        DnsRciOperation.SET_STATIC_HOST.value,
        DnsRciOperation.SET_UPSTREAM.value,
    ]
    assert body["apply_ops"][1]["upstream_resolver"] == "8.8.8.8"


def test_firewall_preview_compiles_offline(client) -> None:
    resp = client.post(f"{_API}/firewall/preview", json=_FIREWALL_BODY)
    assert resp.status_code == 200
    body = resp.json()
    assert body["verification_status"] == "offline_unverified"
    assert [op["operation"] for op in body["apply_ops"]] == [
        FirewallRciOperation.ADD_RULE.value,
        FirewallRciOperation.ADD_RULE.value,
    ]
    assert [op["ordinal"] for op in body["apply_ops"]] == [10, 20]
    assert body["apply_ops"][0]["destination_family"] == "OrderPage"


@pytest.mark.parametrize("zone_id", _INJECTION_ZONE_IDS)
def test_dhcp_preview_rejects_injected_zone_id(client, zone_id: str) -> None:
    resp = client.post(f"{_API}/dhcp/preview", json={**_DHCP_BODY, "zone_id": zone_id})
    assert resp.status_code == 422
    payload = resp.json()
    if "error" in payload:
        assert payload["error"]["code"] == "dhcp.preview_failed"
    else:
        assert payload.get("detail")


def test_vlan_preview_rejects_production_bridge(client) -> None:
    resp = client.post(f"{_API}/vlan/preview", json={**_VLAN_BODY, "bridge_id": "Bridge0"})
    assert resp.status_code == 422
    error = resp.json()["error"]
    assert error["code"] == "vlan.preview_failed"
    assert error["details"][0]["field"] == "bridge_id"
    assert error["details"][0]["reason"] == "not_allowlisted"


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("vlan_id", True),
        ("vlan_id", "20"),
        ("vlan_id", 0),
        ("vlan_id", 4095),
        ("lease_seconds", True),
        ("lease_seconds", "86400"),
        ("lease_seconds", 59),
        ("lease_seconds", 604801),
        ("ordinal", True),
        ("ordinal", "10"),
    ],
)
def test_preview_rejects_numeric_coercion_and_bounds(
    client,
    field: str,
    bad_value: object,
) -> None:
    if field == "vlan_id":
        body = {**_VLAN_BODY, field: bad_value}
        path = f"{_API}/vlan/preview"
    elif field == "lease_seconds":
        body = {**_DHCP_BODY, field: bad_value}
        path = f"{_API}/dhcp/preview"
    else:
        body = {
            **_FIREWALL_BODY,
            "rules": [{**_FIREWALL_BODY["rules"][0], field: bad_value}],
        }
        path = f"{_API}/firewall/preview"
    resp = client.post(path, json=body)
    assert resp.status_code == 422


@pytest.mark.parametrize("secret_field", _SECRET_FIELD_NAMES)
def test_preview_rejects_plaintext_secret_fields(client, secret_field: str) -> None:
    resp = client.post(
        f"{_API}/dhcp/preview",
        json={**_DHCP_BODY, secret_field: "super-secret-value"},
    )
    assert resp.status_code == 422


def test_preview_response_contains_no_secrets(client) -> None:
    resp = client.post(f"{_API}/dhcp/preview", json=_DHCP_BODY)
    assert resp.status_code == 200
    serialized = json.dumps(resp.json()).lower()
    for token in ("password", "psk", "private_key", "preshared", "secret"):
        assert token not in serialized


def test_openapi_has_preview_not_apply(client) -> None:
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    paths = resp.json()["paths"]
    for family in ("vlan", "dhcp", "dns", "firewall"):
        preview_path = f"{_API}/{family}/preview"
        apply_path = f"{_API}/{family}/apply"
        teardown_path = f"{_API}/{family}/teardown"
        assert preview_path in paths
        assert apply_path not in paths
        assert teardown_path not in paths
        preview_post = paths[preview_path]["post"]
        response_schema = preview_post["responses"]["200"]["content"]["application/json"]["schema"]
        if "$ref" in response_schema:
            ref_name = response_schema["$ref"].rsplit("/", 1)[-1]
            response_schema = resp.json()["components"]["schemas"][ref_name]
        assert "verification_status" in response_schema["properties"]
        verdict = response_schema["properties"]["verification_status"]
        assert verdict.get("const") == "offline_unverified" or verdict.get("enum") == [
            "offline_unverified"
        ]


def test_openapi_dhcp_lease_bounds(client) -> None:
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    schema = resp.json()["components"]["schemas"]["DhcpPreviewBody"]
    assert schema["properties"]["lease_seconds"]["minimum"] == 60
    assert schema["properties"]["lease_seconds"]["maximum"] == 604800


def test_openapi_vlan_id_bounds(client) -> None:
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    schema = resp.json()["components"]["schemas"]["VlanPreviewBody"]
    assert schema["properties"]["vlan_id"]["minimum"] == 1
    assert schema["properties"]["vlan_id"]["maximum"] == 4094
