"""Guard: owned operator error paths must not echo user-supplied substrings.

Covered: event-preset validation, network-family preview (vlan/dhcp/dns/firewall),
StarletteHTTPException envelope, Wi-Fi apply/preview/observed-state/site-survey routes,
WireGuard apply/preview/observe routes (HTTP + sealed-apply audit), VPN profile
parse-preview, VPN policy-routing preview.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from router_control.application.wifi_apply_service import WifiApplyServiceError
from router_control.application.wifi_observed_state import WifiObservedStateError
from router_control.application.wifi_site_survey import WifiSiteSurveyError
from router_control.application.wireguard_apply_service import WireguardApplyServiceError
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie
from router_control_host.errors import starlette_http_error_response
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import Request

_CANARY = "SuperSecretPSK-should-not-echo"
_PLAIN_MARKER = "OrdinaryToken-xyzzy-42"
_API = "/api/router-control/v1"

_VLAN_BODY: dict[str, Any] = {
    "bridge_id": "Bridge3",
    "zone_id": "Guest",
    "vlan_id": 20,
    "ipv4_cidr": "10.20.0.0/24",
    "ipv4_gateway": "10.20.0.1",
}

_DHCP_BODY: dict[str, Any] = {
    "zone_id": "Guest",
    "pool_start": "10.10.0.100",
    "pool_end": "10.10.0.200",
    "lease_seconds": 86400,
    "reservations": [],
}

_DNS_BODY: dict[str, Any] = {
    "zone_id": "Guest",
    "local_fqdn": "order.guest.example.com",
    "upstream_resolvers": ["8.8.8.8"],
}

_FIREWALL_BODY: dict[str, Any] = {
    "zone_id": "Guest",
    "rules": [{"action": "Allow", "destination_family": "OrderPage", "ordinal": 10}],
}

_WIFI_PREVIEW_BODY: dict[str, Any] = {
    "ap_id": "WifiMaster0/AccessPoint3",
    "ssid": "Staff-Private",
    "enabled": True,
    "guest_isolation": False,
    "wpa_mode": "WPA2",
    "band": "BAND_2_4GHZ",
}

_WIFI_APPLY_BODY: dict[str, Any] = {
    **_WIFI_PREVIEW_BODY,
    "confirm_live_apply": True,
}

_WIFI_OBSERVED_BODY: dict[str, Any] = {
    "ap_ids": ["WifiMaster0/AccessPoint3"],
}

_WIFI_SITE_SURVEY_BODY: dict[str, Any] = {
    "radio": "WifiMaster0",
}

_WG_PREVIEW_BODY: dict[str, Any] = {
    "wg_id": "Wireguard5",
    "enabled": True,
    "asc_args": [5, 42, 54, 0, 0, 1, 2, 3, 4],
}

_WG_APPLY_BODY: dict[str, Any] = {
    **_WG_PREVIEW_BODY,
    "confirm_live_apply": True,
}

_WG_TEARDOWN_BODY: dict[str, Any] = {
    "wg_id": "Wireguard5",
    "enabled": True,
    "confirm_live_teardown": True,
}

_WG_OBSERVE_BODY: dict[str, Any] = {
    "wg_id": "Wireguard5",
}

_VPN_PARSE_PREVIEW_PROFILE = """
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.0.0.2/32
Jc = 5
Jmin = 50
Jmax = 1000
S1 = 80
S2 = 80
H1 = 0
H2 = 0
H3 = 0
H4 = 0

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""

_VPN_POLICY_PREVIEW_BODY: dict[str, Any] = {
    "policy_name": "vpn-uplink",
    "vpn_interface": "GigabitEthernet1",
    "ip_global": {"priority": 700},
}


def _assert_canary_absent(payload: object) -> None:
    blob = json.dumps(payload)
    assert _CANARY not in blob


def _inject_canary_strings(body: dict[str, Any]) -> dict[str, Any]:
    injected = dict(body)
    for key, value in list(body.items()):
        if isinstance(value, str):
            injected[key] = _CANARY
        elif isinstance(value, list) and value and isinstance(value[0], dict):
            nested = {
                k: (_CANARY if isinstance(v, str) else v)
                for k, v in value[0].items()
            }
            injected[key] = [nested]
    injected[_CANARY] = "extra-unknown-key"
    return injected


def _wifi_canary_preview_body() -> dict[str, Any]:
    return {
        **_WIFI_PREVIEW_BODY,
        "ssid": _CANARY,
        "ap_id": "WifiMaster0/AccessPoint3",
    }


def _wifi_canary_apply_body() -> dict[str, Any]:
    return {
        **_WIFI_APPLY_BODY,
        "ssid": _CANARY,
        "ap_id": "WifiMaster0/AccessPoint3",
    }


def _http_request(path: str = "/wifi/preview") -> Request:
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "path": path,
        "headers": [],
        "query_string": b"",
        "client": ("127.0.0.1", 1),
        "server": ("127.0.0.1", 8787),
        "scheme": "http",
        "root_path": "",
    }
    request = Request(scope)
    request.state.request_id = "req_wifi_handler_no_echo"
    request.state.correlation_id = "corr_wifi_handler_no_echo"
    return request


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")
    app = create_app(db_path=tmp_path / "no-echo-guard.sqlite3", enable_worker=False)
    from fastapi.testclient import TestClient

    with TestClient(app) as tc:
        tc.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield tc


def _assert_plain_marker_absent(payload: object) -> None:
    blob = json.dumps(payload)
    assert _PLAIN_MARKER not in blob


def _assert_structured_details(error: dict[str, Any]) -> None:
    details = error.get("details", [])
    assert details, "expected structured details with field and reason"
    assert details[0].get("field")
    assert details[0].get("reason")


def _assert_structured_details_no_values(error: dict[str, Any]) -> None:
    details = error.get("details", [])
    assert details, "expected structured details with field and reason"
    for item in details:
        assert set(item.keys()) <= {"field", "reason", "expected"}
        for _key, value in item.items():
            if isinstance(value, str):
                assert _PLAIN_MARKER not in value
                assert _CANARY not in value
            assert value != _PLAIN_MARKER
            assert value != _CANARY


@pytest.fixture
def wg_apply_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    app = create_app(db_path=tmp_path / "no-echo-wg-apply.sqlite3", allow_fake_mutations=True)
    from fastapi.testclient import TestClient

    with TestClient(app) as tc:
        tc.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield tc


def _wg_apply_store(client):
    return client.app.state.host.runtime.store


def _latest_wg_audit(client, *, verb: str) -> dict[str, object]:
    events = _wg_apply_store(client).list_audit_events(
        action_prefix=f"sealed_apply.wireguard.{verb}"
    )
    assert events, f"expected sealed_apply.wireguard.{verb} audit event"
    return events[0]


@pytest.mark.parametrize(
    ("path", "base_body"),
    [
        (f"{_API}/vlan/preview", _VLAN_BODY),
        (f"{_API}/dhcp/preview", _DHCP_BODY),
        (f"{_API}/dns/preview", _DNS_BODY),
        (f"{_API}/firewall/preview", _FIREWALL_BODY),
    ],
)
def test_network_family_preview_canary_absent(client, path: str, base_body: dict[str, Any]) -> None:
    resp = client.post(path, json=_inject_canary_strings(base_body))
    assert resp.status_code == 422
    body = resp.json()
    _assert_canary_absent(body)
    assert "error" in body
    assert "detail" not in body


def test_vlan_preview_bridge_id_canary_structural_diagnostics(client) -> None:
    resp = client.post(
        f"{_API}/vlan/preview",
        json={**_VLAN_BODY, "bridge_id": _CANARY},
    )
    assert resp.status_code == 422
    body = resp.json()
    _assert_canary_absent(body)
    error = body["error"]
    assert error["code"] == "vlan.preview_failed"
    assert "bridge_id" in json.dumps(error).lower()
    details = error.get("details", [])
    assert details and details[0].get("reason") == "not_allowlisted"
    assert details[0].get("field") == "bridge_id"


def test_dns_preview_local_fqdn_canary_structural_diagnostics(client) -> None:
    resp = client.post(
        f"{_API}/dns/preview",
        json={**_DNS_BODY, "local_fqdn": _CANARY},
    )
    assert resp.status_code == 422
    body = resp.json()
    _assert_canary_absent(body)
    error = body["error"]
    assert error["code"] == "dns.preview_failed"
    details = error.get("details", [])
    assert details and details[0].get("reason") == "invalid_fqdn"
    assert details[0].get("field") == "local_fqdn"


def test_dhcp_preview_bad_mac_canary_structural_diagnostics(client) -> None:
    resp = client.post(
        f"{_API}/dhcp/preview",
        json={
            **_DHCP_BODY,
            "reservations": [{"mac_address": _CANARY, "ipv4_address": "10.10.0.50"}],
        },
    )
    assert resp.status_code == 422
    body = resp.json()
    _assert_canary_absent(body)
    error = body["error"]
    assert error["code"] == "dhcp.preview_failed"
    details = error.get("details", [])
    assert details and details[0].get("reason") == "invalid_format"
    assert details[0].get("field") == "mac_address"


def test_firewall_preview_zone_id_canary_structural_diagnostics(client) -> None:
    resp = client.post(
        f"{_API}/firewall/preview",
        json={**_FIREWALL_BODY, "zone_id": _CANARY + "!"},
    )
    assert resp.status_code == 422
    body = resp.json()
    _assert_canary_absent(body)
    error = body["error"]
    assert error["code"] == "firewall.preview_failed"
    details = error.get("details", [])
    assert details and details[0].get("reason") == "not_allowlisted"
    assert details[0].get("field") == "zone_id"


def test_wifi_preview_canary_in_ssid_absent(client) -> None:
    resp = client.post(
        f"{_API}/wifi/preview",
        json=_wifi_canary_preview_body(),
    )
    assert resp.status_code in {422, 503}
    body = resp.json()
    _assert_canary_absent(body)


def test_wifi_preview_ap_id_canary_structural_diagnostics(client) -> None:
    resp = client.post(
        f"{_API}/wifi/preview",
        json={**_WIFI_PREVIEW_BODY, "ap_id": _CANARY},
    )
    assert resp.status_code == 422
    body = resp.json()
    _assert_canary_absent(body)
    error = body["error"]
    assert error["code"] == "wifi.ap_forbidden"
    details = error.get("details", [])
    assert details and details[0].get("reason") == "not_allowlisted"
    assert details[0].get("field") == "ap_id"


def test_wifi_apply_canary_in_ssid_absent(client) -> None:
    resp = client.post(
        f"{_API}/wifi/apply",
        json=_wifi_canary_apply_body(),
    )
    assert resp.status_code in {422, 503}
    body = resp.json()
    _assert_canary_absent(body)


def test_wifi_observed_state_canary_absent(client) -> None:
    resp = client.post(
        f"{_API}/wifi/observed-state",
        json={"ap_ids": [_CANARY]},
    )
    assert resp.status_code == 422
    body = resp.json()
    _assert_canary_absent(body)
    assert body["error"]["code"] == "wifi.ap_forbidden"


def test_wifi_site_survey_canary_absent(client) -> None:
    resp = client.post(
        f"{_API}/wifi/site-survey",
        json=_inject_canary_strings(_WIFI_SITE_SURVEY_BODY),
    )
    assert resp.status_code == 422
    body = resp.json()
    _assert_canary_absent(body)


def test_wifi_site_survey_invalid_radio_not_echoed(client) -> None:
    invalid_radio = "WifiMaster2"
    resp = client.post(
        f"{_API}/wifi/site-survey",
        json={"radio": invalid_radio},
    )
    assert resp.status_code == 422
    body = resp.json()
    assert invalid_radio not in json.dumps(body)


def test_wireguard_preview_wg_id_canary_structural_diagnostics(client) -> None:
    resp = client.post(
        f"{_API}/wireguard/preview",
        json={**_WG_PREVIEW_BODY, "wg_id": _CANARY},
    )
    assert resp.status_code == 422
    body = resp.json()
    _assert_canary_absent(body)
    error = body["error"]
    assert error["code"] == "wireguard.wg_forbidden"
    details = error.get("details", [])
    assert details and details[0].get("reason") == "not_allowlisted"
    assert details[0].get("field") == "wg_id"
    _assert_structured_details_no_values(error)


def test_wireguard_apply_service_error_plain_marker_absent(
    wg_apply_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    import router_control_host.wireguard_apply_routes as routes_mod

    def _fail(*_args: object, **_kwargs: object) -> None:
        raise WireguardApplyServiceError(f"apply failed marker={_PLAIN_MARKER}")

    monkeypatch.setattr(routes_mod, "apply_wireguard_intent", _fail)
    resp = wg_apply_client.post(f"{_API}/wireguard/apply", json=_WG_APPLY_BODY)
    assert resp.status_code == 422
    body = resp.json()
    _assert_plain_marker_absent(body)
    assert body["error"]["code"] == "wireguard.apply_failed"


def test_wireguard_apply_audit_failed_plain_marker_absent(
    wg_apply_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    import router_control_host.wireguard_apply_routes as routes_mod

    def _fail(*_args: object, **_kwargs: object) -> None:
        raise WireguardApplyServiceError(f"apply failed marker={_PLAIN_MARKER}")

    monkeypatch.setattr(routes_mod, "apply_wireguard_intent", _fail)
    resp = wg_apply_client.post(f"{_API}/wireguard/apply", json=_WG_APPLY_BODY)
    assert resp.status_code == 422
    summary = json.loads(str(_latest_wg_audit(wg_apply_client, verb="apply")["summary_redacted"]))
    _assert_plain_marker_absent(summary)
    assert "error_message" in summary
    assert _PLAIN_MARKER not in summary["error_message"]


def test_wireguard_teardown_audit_failed_plain_marker_absent(
    wg_apply_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    import router_control_host.wireguard_apply_routes as routes_mod

    def _fail(*_args: object, **_kwargs: object) -> None:
        raise WireguardApplyServiceError(f"teardown failed marker={_PLAIN_MARKER}")

    monkeypatch.setattr(routes_mod, "teardown_wireguard", _fail)
    resp = wg_apply_client.post(f"{_API}/wireguard/teardown", json=_WG_TEARDOWN_BODY)
    assert resp.status_code == 422
    _assert_plain_marker_absent(resp.json())
    audit = _latest_wg_audit(wg_apply_client, verb="teardown")
    summary = json.loads(str(audit["summary_redacted"]))
    _assert_plain_marker_absent(summary)
    assert "error_message" in summary
    assert _PLAIN_MARKER not in summary["error_message"]


def test_vpn_parse_preview_plain_marker_absent(client) -> None:
    profile = _VPN_PARSE_PREVIEW_PROFILE.replace(
        "AllowedIPs = 0.0.0.0/0",
        f"AllowedIPs = 2001:db8::{_PLAIN_MARKER}/128",
    )
    resp = client.post(
        f"{_API}/vpn-profiles/parse-preview",
        json={"profile_text": profile},
    )
    assert resp.status_code == 422
    body = resp.json()
    _assert_plain_marker_absent(body)
    assert body["error"]["code"] == "profile.validation_failed"
    _assert_structured_details_no_values(body["error"])


def test_wireguard_observe_connection_fields_plain_marker_absent(client) -> None:
    resp = client.post(
        f"{_API}/wireguard/observe",
        json={
            **_WG_OBSERVE_BODY,
            "host": _PLAIN_MARKER,
            "username": _PLAIN_MARKER,
        },
    )
    assert resp.status_code == 422
    body = resp.json()
    _assert_plain_marker_absent(body)
    assert body["error"]["code"] == "wireguard.live_connection_incomplete"


def test_wireguard_observe_forbidden_wg_structural_details_only(client) -> None:
    resp = client.post(
        f"{_API}/wireguard/observe",
        json={**_WG_OBSERVE_BODY, "wg_id": _PLAIN_MARKER},
    )
    assert resp.status_code == 422
    body = resp.json()
    _assert_plain_marker_absent(body)
    error = body["error"]
    assert error["code"] == "wireguard.wg_forbidden"
    _assert_structured_details_no_values(error)
    details = error.get("details", [])
    assert details[0].get("field") == "wg_id"
    assert details[0].get("reason") == "not_allowlisted"


def test_vpn_policy_preview_vpn_interface_canary_absent(client) -> None:
    resp = client.post(
        f"{_API}/vpn/policy-routing/preview",
        json={
            "policy_name": "vpn-uplink",
            "vpn_interface": _CANARY,
            "interface_kind": "wireguard",
            "address_configured": False,
            "ip_global": "auto",
        },
    )
    assert resp.status_code == 422
    body = resp.json()
    _assert_canary_absent(body)
    assert body["error"]["code"] == "vpn.policy_routing_preview_failed"


@pytest.mark.parametrize(
    ("handler_import", "handler_name", "exc_factory"),
    [
        (
            "router_control_host.wifi_apply_routes",
            "_ap_validation_error",
            lambda: ValueError(f"ap forbidden: {_CANARY}"),
        ),
        (
            "router_control_host.wifi_apply_routes",
            "_wifi_apply_error",
            lambda: WifiApplyServiceError(f"apply failed with {_CANARY}"),
        ),
        (
            "router_control_host.wifi_observed_routes",
            "_ap_validation_error",
            lambda: ValueError(f"ap forbidden: {_CANARY}"),
        ),
        (
            "router_control_host.wifi_observed_routes",
            "_service_error",
            lambda: WifiObservedStateError(f"observed failed with {_CANARY}"),
        ),
        (
            "router_control_host.wifi_site_survey_routes",
            "_radio_validation_error",
            lambda: ValueError(f"radio invalid: {_CANARY}"),
        ),
        (
            "router_control_host.wifi_site_survey_routes",
            "_service_error",
            lambda: WifiSiteSurveyError(f"survey failed with {_CANARY}"),
        ),
    ],
)
def test_wifi_error_handlers_canary_absent_direct(
    handler_import: str,
    handler_name: str,
    exc_factory: Any,
) -> None:
    import importlib

    module = importlib.import_module(handler_import)
    handler = getattr(module, handler_name)
    request = _http_request()
    response = handler(request, exc_factory())
    body = json.loads(response.body)
    _assert_canary_absent(body)


def test_wifi_live_backup_unavailable_canary_absent() -> None:
    """Резервная копия: ошибка live_backup_unavailable не эхоит canary."""
    from router_control_host.wifi_apply_routes import _live_backup_unavailable_error

    request = _http_request("/wifi/teardown")
    response = _live_backup_unavailable_error(request)
    body = json.loads(response.body)
    _assert_canary_absent(body)
    assert "backup" in body["error"]["code"] or "live_backup" in body["error"]["code"]


def test_wifi_sealed_apply_trail_begin_canary_absent() -> None:
    """Журнал sealed_apply: trail_begin_failed не эхоит canary из исключения."""
    from router_control_host.errors import sealed_apply_trail_begin_error_response

    request = _http_request("/wifi/apply")
    response = sealed_apply_trail_begin_error_response(request, RuntimeError(_CANARY))
    body = json.loads(response.body)
    _assert_canary_absent(body)
    assert body["error"]["code"] == "sealed_apply.trail_begin_failed"


def test_wifi_site_survey_radio_validation_error_no_echo() -> None:
    from router_control_host.wifi_site_survey_routes import _radio_validation_error

    invalid_radio = "WifiMaster2"
    request = _http_request("/wifi/site-survey")
    exc = ValueError(
        f"radio must be WifiMaster0 or WifiMaster1, got {invalid_radio!r}"
    )
    response = _radio_validation_error(request, exc)
    body = json.loads(response.body)
    assert invalid_radio not in json.dumps(body)
    assert body["error"]["code"] == "wifi.site_survey_radio_forbidden"
    details = body["error"].get("details", [])
    assert details and details[0].get("reason") == "invalid_value"
    assert details[0].get("field") == "radio"


def test_preset_revision_unknown_key_canary_absent(client) -> None:
    site_id = client.app.state.host.ensure_default_site()
    create = client.post(
        f"{_API}/sites/{site_id}/event-presets",
        json={"name": "NoEcho Booth"},
        headers={"Idempotency-Key": "no-echo-create"},
    )
    assert create.status_code == 201
    preset = create.json()["preset"]
    doc = client.get(
        f"{_API}/event-presets/{preset['preset_id']}/revisions/"
        f"{preset['current_revision_id']}"
    ).json()["canonical_document"]
    doc[_CANARY] = True
    resp = client.post(
        f"{_API}/event-presets/{preset['preset_id']}/revisions",
        json={"document": doc},
        headers={"Idempotency-Key": "no-echo-rev", "If-Match": preset["etag"]},
    )
    assert resp.status_code == 400
    body = resp.json()
    _assert_canary_absent(body)
    assert body["error"]["code"] == "request.validation_failed"
    assert "unrecognized field" in body["error"]["message"].lower()


def test_preset_revision_invalid_fqdn_canary_absent(client) -> None:
    site_id = client.app.state.host.ensure_default_site()
    create = client.post(
        f"{_API}/sites/{site_id}/event-presets",
        json={"name": "FQDN Booth"},
        headers={"Idempotency-Key": "no-echo-fqdn-create"},
    )
    preset = create.json()["preset"]
    doc = client.get(
        f"{_API}/event-presets/{preset['preset_id']}/revisions/"
        f"{preset['current_revision_id']}"
    ).json()["canonical_document"]
    guest = next(z for z in doc["zones"] if z["zone_id"] == "Guest")
    guest["dns"]["local_fqdn"] = _CANARY
    resp = client.post(
        f"{_API}/event-presets/{preset['preset_id']}/revisions",
        json={"document": doc},
        headers={"Idempotency-Key": "no-echo-fqdn-rev", "If-Match": preset["etag"]},
    )
    assert resp.status_code == 400
    body = resp.json()
    _assert_canary_absent(body)
    assert "invalid fqdn" in body["error"]["message"].lower()
    _assert_structured_details(body["error"])


def test_preset_revision_invalid_wpa_mode_canary_absent(client) -> None:
    site_id = client.app.state.host.ensure_default_site()
    create = client.post(
        f"{_API}/sites/{site_id}/event-presets",
        json={"name": "WPA Booth"},
        headers={"Idempotency-Key": "no-echo-wpa-create"},
    )
    preset = create.json()["preset"]
    doc = client.get(
        f"{_API}/event-presets/{preset['preset_id']}/revisions/"
        f"{preset['current_revision_id']}"
    ).json()["canonical_document"]
    guest = next(z for z in doc["zones"] if z["zone_id"] == "Guest")
    guest["wifi"]["wpa_mode"] = _CANARY
    resp = client.post(
        f"{_API}/event-presets/{preset['preset_id']}/revisions",
        json={"document": doc},
        headers={"Idempotency-Key": "no-echo-wpa-rev", "If-Match": preset["etag"]},
    )
    assert resp.status_code == 400
    body = resp.json()
    _assert_canary_absent(body)
    assert body["error"]["code"] == "request.validation_failed"
    details = body.get("details", []) or body["error"].get("details", [])
    assert details and "wpa_mode" in details[0].get("field", "").lower()
    assert details[0].get("reason") == "invalid_value"


def test_starlette_http_exception_never_echoes_detail() -> None:
    request = _http_request("/missing")
    request.state.request_id = "req_starlette_no_echo"
    request.state.correlation_id = "corr_starlette_no_echo"
    exc = StarletteHTTPException(status_code=404, detail=_CANARY)
    response = starlette_http_error_response(request, exc)
    body = json.loads(response.body)
    _assert_canary_absent(body)
    assert body["error"]["code"] == "resource.not_found"
    assert "detail" not in body


def test_red_green_guard_vlan_preview_echo_would_fail(client) -> None:
    """Document RED state: echoing canary in preview message fails the guard."""
    from router_control_host import network_family_preview_routes as routes

    original = routes._preview_error

    def _echo_preview_error(request, *, code: str, exc: Exception):
        from router_control_host.errors import error_response

        return error_response(
            request,
            status_code=422,
            code=code,
            message=f"bridge id not allowlisted: '{_CANARY}'",
        )

    routes._preview_error = _echo_preview_error  # type: ignore[assignment]
    try:
        resp = client.post(
            f"{_API}/vlan/preview",
            json={**_VLAN_BODY, "bridge_id": _CANARY},
        )
        assert resp.status_code == 422
        with pytest.raises(AssertionError):
            _assert_canary_absent(resp.json())
    finally:
        routes._preview_error = original


def test_red_green_guard_wifi_preview_echo_would_fail() -> None:
    """Document RED state: echoing canary in Wi-Fi preview handler fails the guard."""
    from router_control_host.errors import error_response
    from router_control_host.wifi_apply_routes import _wifi_preview_error

    request = _http_request()
    original_message = "Preview compilation failed"

    def _echo_preview_error(request_arg, exc: Exception):
        _ = exc
        return error_response(
            request_arg,
            status_code=422,
            code="wifi.preview_failed",
            message=f"preview failed: '{_CANARY}'",
        )

    good = _wifi_preview_error(request, RuntimeError(_CANARY))
    _assert_canary_absent(json.loads(good.body))

    bad = _echo_preview_error(request, RuntimeError(_CANARY))
    with pytest.raises(AssertionError):
        _assert_canary_absent(json.loads(bad.body))
    assert original_message not in json.dumps(json.loads(bad.body))


def test_red_green_guard_vpn_parse_preview_echo_would_fail(client) -> None:
    """Document RED state: echoing marker in parse-preview message fails the guard."""
    import router_control_host.routes as routes

    original = routes._awg_profile_validation_error

    def _echo_validation_error(request, exc):
        from router_control_host.errors import error_response

        return error_response(
            request,
            status_code=422,
            code="profile.validation_failed",
            message=f"profile invalid: {_PLAIN_MARKER}",
        )

    routes._awg_profile_validation_error = _echo_validation_error  # type: ignore[assignment]
    try:
        profile = _VPN_PARSE_PREVIEW_PROFILE.replace(
            "AllowedIPs = 0.0.0.0/0",
            f"AllowedIPs = 2001:db8::{_PLAIN_MARKER}/128",
        )
        resp = client.post(
            f"{_API}/vpn-profiles/parse-preview",
            json={"profile_text": profile},
        )
        assert resp.status_code == 422
        with pytest.raises(AssertionError):
            _assert_plain_marker_absent(resp.json())
    finally:
        routes._awg_profile_validation_error = original


def test_red_green_guard_wireguard_apply_echo_would_fail(
    wg_apply_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Document RED state: echoing marker in apply_failed message fails the guard."""
    import router_control_host.wireguard_apply_routes as routes_mod

    def _fail(*_args: object, **_kwargs: object) -> None:
        raise WireguardApplyServiceError(f"marker={_PLAIN_MARKER}")

    original_service_error = routes_mod._service_error

    def _echo_service_error(request, exc):
        from router_control_host.errors import error_response

        return error_response(
            request,
            status_code=422,
            code="wireguard.apply_failed",
            message=f"apply failed: {_PLAIN_MARKER}",
        )

    monkeypatch.setattr(routes_mod, "apply_wireguard_intent", _fail)
    routes_mod._service_error = _echo_service_error  # type: ignore[assignment]
    try:
        resp = wg_apply_client.post(f"{_API}/wireguard/apply", json=_WG_APPLY_BODY)
        assert resp.status_code == 422
        with pytest.raises(AssertionError):
            _assert_plain_marker_absent(resp.json())
    finally:
        routes_mod._service_error = original_service_error


def _fake_probe_runner_class(
    *,
    probe_http: object,
    probe_tls: object,
    probe_internet: object,
) -> type:
    return type(
        "FakeProbeRunner",
        (),
        {
            "probe_http": staticmethod(probe_http),
            "probe_tls": staticmethod(probe_tls),
            "probe_internet": staticmethod(probe_internet),
        },
    )


def test_host_http_probe_failure_canary_absent(client) -> None:
    from router_control_host.host_probes import HostHttpProbeResult

    def _boom(*, url: str) -> HostHttpProbeResult:
        raise RuntimeError(f"failed for {url}")

    client.app.state.host.host_probe_runner = _fake_probe_runner_class(
        probe_http=_boom,
        probe_tls=_boom,
        probe_internet=_boom,
    )()
    site_id = client.app.state.host.ensure_default_site()
    create = client.post(
        f"{_API}/sites/{site_id}/event-presets",
        json={"name": "Host HTTP NoEcho"},
        headers={"Idempotency-Key": "host-http-no-echo"},
    )
    preset = create.json()["preset"]
    doc = client.get(
        f"{_API}/event-presets/{preset['preset_id']}/revisions/"
        f"{preset['current_revision_id']}"
    ).json()["canonical_document"]
    doc["local_order_url"] = f"http://{_CANARY}:9090/hidden"
    client.post(
        f"{_API}/event-presets/{preset['preset_id']}/revisions",
        json={"document": doc},
        headers={"Idempotency-Key": "host-http-no-echo-rev", "If-Match": preset["etag"]},
    )
    resp = client.post(
        f"{_API}/lab/host-http-probe",
        json={
            "url_ref": "event_preset_local_order_url",
            "preset_id": preset["preset_id"],
        },
    )
    assert resp.status_code == 500
    _assert_canary_absent(resp.json())


def test_host_tls_probe_failure_canary_absent(client) -> None:
    from router_control_host.host_probes import HostTlsProbeResult

    def _boom(*, hostname: str) -> HostTlsProbeResult:
        raise RuntimeError(f"failed for {hostname}")

    client.app.state.host.host_probe_runner = _fake_probe_runner_class(
        probe_http=_boom,
        probe_tls=_boom,
        probe_internet=_boom,
    )()
    site_id = client.app.state.host.ensure_default_site()
    create = client.post(
        f"{_API}/sites/{site_id}/event-presets",
        json={"name": "Host TLS NoEcho"},
        headers={"Idempotency-Key": "host-tls-no-echo"},
    )
    preset = create.json()["preset"]
    doc = client.get(
        f"{_API}/event-presets/{preset['preset_id']}/revisions/"
        f"{preset['current_revision_id']}"
    ).json()["canonical_document"]
    doc["local_order_url"] = f"https://{_CANARY}/"
    client.post(
        f"{_API}/event-presets/{preset['preset_id']}/revisions",
        json={"document": doc},
        headers={"Idempotency-Key": "host-tls-no-echo-rev", "If-Match": preset["etag"]},
    )
    resp = client.post(
        f"{_API}/lab/host-tls-probe",
        json={
            "hostname_ref": "event_preset_local_order_host",
            "preset_id": preset["preset_id"],
        },
    )
    assert resp.status_code == 500
    _assert_canary_absent(resp.json())


def test_host_internet_probe_failure_canary_absent(client) -> None:
    from router_control_host.host_probes import HostInternetProbeResult

    _INTERNET_CANARY = "INTERNET-PROBE-CANARY-MARKER-XYZZY"

    def _boom(*, targets_profile: str) -> HostInternetProbeResult:
        raise RuntimeError(f"failed profile {targets_profile} {_INTERNET_CANARY}")

    client.app.state.host.host_probe_runner = _fake_probe_runner_class(
        probe_http=_boom,
        probe_tls=_boom,
        probe_internet=_boom,
    )()
    resp = client.post(f"{_API}/lab/host-internet-probe", json={})
    assert resp.status_code == 500
    blob = resp.text
    assert _INTERNET_CANARY not in blob
    _assert_canary_absent(resp.json())
