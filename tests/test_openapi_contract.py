"""OpenAPI contract tests — response schemas must expose verdict fields (not decorative {})."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, get_args
from unittest.mock import patch

import pytest
from pydantic import BaseModel
from router_control.adapters.netcraze.allowlist import is_wireguard_nested_peer_body
from router_control.application.wifi_apply_service import WifiApplyVerification
from router_control_host.app import create_app
from router_control_host.apply_response_models import (
    OVERALL_HTTP_SEMANTICS,
    ApplyOverallStatus,
    BootstrapDiscoveryResponse,
    DhcpPreviewResponse,
    DnsPreviewResponse,
    FirewallPreviewResponse,
    RciMutationResponse,
    VlanPreviewResponse,
    VpnPolicyPreviewResponse,
    WifiApplyResponse,
    WifiApplyVerificationResponse,
    WifiObservedStateResponse,
    WifiPreviewResponse,
    WifiSiteSurveyResponse,
    WifiStationApplyResponse,
    WifiStationPreviewResponse,
    WireguardApplyResponse,
    WireguardPreviewResponse,
)
from router_control_host.auth import mint_hub_admin_cookie

_API = "/api/router-control/v1"
_PINNED_OPENAPI_PATH = (
    Path(__file__).resolve().parents[1] / "docs" / "contracts" / "openapi-v0.json"
)
_TEST_AP = "WifiMaster0/AccessPoint3"
_TEST_WG = "Wireguard5"
_ASC_9 = [5, 42, 54, 0, 0, 1, 2, 3, 4]


def _resolve_response_schema(
    openapi: dict[str, Any],
    path: str,
    *,
    method: str = "post",
    status: str = "200",
) -> dict[str, Any]:
    operation = openapi["paths"][path][method]
    schema = operation["responses"][status]["content"]["application/json"]["schema"]
    if "$ref" in schema:
        ref_name = schema["$ref"].rsplit("/", 1)[-1]
        return openapi["components"]["schemas"][ref_name]
    return schema


def _schema_property_names(schema: dict[str, Any]) -> set[str]:
    return set(schema.get("properties", {}))


def _schema_required(schema: dict[str, Any]) -> set[str]:
    return set(schema.get("required", []))


def _canonical_openapi(schema: dict[str, Any]) -> str:
    """Stable JSON serialization — insensitive to key order and whitespace."""
    return json.dumps(schema, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _load_pinned_openapi() -> dict[str, Any]:
    return json.loads(_PINNED_OPENAPI_PATH.read_text(encoding="utf-8"))


def _openapi_diff_paths(
    live: Any,
    pinned: Any,
    *,
    prefix: str = "",
    limit: int = 20,
) -> list[str]:
    diffs: list[str] = []
    if type(live) is not type(pinned):
        return [f"{prefix}: type {type(live).__name__} != {type(pinned).__name__}"]
    if isinstance(live, dict):
        for key in sorted(set(live) | set(pinned)):
            path = f"{prefix}.{key}" if prefix else key
            if key not in live:
                diffs.append(f"missing in live app schema: {path}")
            elif key not in pinned:
                diffs.append(f"extra in live app schema (regenerate openapi-v0.json): {path}")
            else:
                diffs.extend(_openapi_diff_paths(live[key], pinned[key], prefix=path))
    elif isinstance(live, list):
        if len(live) != len(pinned):
            diffs.append(f"{prefix}: list length {len(live)} != {len(pinned)}")
        for index, (left, right) in enumerate(zip(live, pinned, strict=False)):
            diffs.extend(_openapi_diff_paths(left, right, prefix=f"{prefix}[{index}]"))
    elif live != pinned:
        diffs.append(f"{prefix}: {live!r} != {pinned!r}")
    return diffs[:limit]


def _assert_required_model_fields_in_body(model: type[BaseModel], body: dict[str, Any]) -> None:
    for field_name, field_info in model.model_fields.items():
        if field_info.is_required() and field_name not in body:
            raise AssertionError(
                f"{model.__name__} declares required field {field_name!r} "
                f"missing from live response keys {sorted(body)}"
            )


def _wifi_intent_payload(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "ap_id": _TEST_AP,
        "ssid": "Staff-Private",
        "enabled": True,
        "credential_ref_id": "credref:staff-wifi",
        "captive_portal": "Disabled",
        "guest_isolation": False,
        "wpa_mode": "WPA2",
        "band": "BAND_2_4GHZ",
    }
    base.update(overrides)
    return base


def _wireguard_intent_payload(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "wg_id": _TEST_WG,
        "enabled": True,
        "asc_args": _ASC_9,
    }
    base.update(overrides)
    return base


def _station_apply_payload(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "mode": "WifiWan",
        "ssid": "Venue-Guest",
        "band": "BAND_2_4GHZ",
        "credential_ref_id": "credref:venue-wifi",
        "confirm_live_apply": True,
    }
    base.update(overrides)
    return base


def _bootstrap_sample_report() -> dict[str, object]:
    return {
        "certification_eligible": False,
        "transport_security": "insecure_http",
        "https_check": "not_certified",
        "model": "NC-1812",
        "firmware_version": "4.03.C.6.4-16",
        "firmware_digest": "sha256:abc",
        "fingerprint_digest": "sha256:def",
        "component_set_digest": "sha256:ghi",
        "ssh_component_installed": False,
        "ssh_access_enabled": False,
        "wifi_access_points": [{"interface_id_hash": "sha256:ap0", "link_up": True}],
        "findings": ["firmware_below_verified_baseline"],
        "components_inventory": {
            "entries": [{"id": "ndm", "installed": True}],
            "total_observed": 3,
            "truncated": False,
            "source_shape": "component_map",
        },
        "ssh_component_determination": {
            "lookup": "component.ssh",
            "matched": False,
            "outcome": "key_absent",
        },
        "component_change_side_effects": {
            "firmware_rebuild": False,
            "automatic_reboot": False,
            "management_downtime": False,
        },
    }


@dataclass(frozen=True)
class _ResponseModelCase:
    route_id: str
    path: str
    model: type[BaseModel]
    invoke: Callable[..., Any]
    setup: Callable[..., None] | None = None


@pytest.fixture
def openapi_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    app = create_app(db_path=tmp_path / "openapi-contract.sqlite3", allow_fake_mutations=True)
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield client


@pytest.fixture
def enrolled_openapi_client(openapi_client, request: pytest.FixtureRequest):
    enroll = openapi_client.post(
        f"{_API}/routers",
        json={
            "display_name": "OpenAPI Contract Router",
            "vendor": "Netcraze",
            "model": "NC-1812",
            "endpoint": {"kind": "management_https", "host": "10.0.0.1", "port": 443},
            "management_password": "test-secret",
        },
        headers={"Idempotency-Key": f"openapi-contract-{request.node.name}"},
    )
    assert enroll.status_code == 202
    openapi_client.test_router_id = enroll.json()["router_id"]
    return openapi_client


@pytest.fixture
def openapi_schema(openapi_client) -> dict[str, Any]:
    resp = openapi_client.get("/openapi.json")
    assert resp.status_code == 200
    return resp.json()


def test_pinned_openapi_matches_live_app(openapi_schema: dict[str, Any]) -> None:
    """F-5 guard: committed docs/contracts/openapi-v0.json must match live app.openapi()."""
    pinned = _load_pinned_openapi()
    live_canonical = _canonical_openapi(openapi_schema)
    pinned_canonical = _canonical_openapi(pinned)
    if live_canonical == pinned_canonical:
        return
    diffs = _openapi_diff_paths(openapi_schema, pinned)
    detail = "\n".join(diffs[:20])
    raise AssertionError(
        "Live /openapi.json diverges from docs/contracts/openapi-v0.json; "
        f"run py -3.11 scripts/export-openapi.py. First diffs:\n{detail}"
    )


_PREVIEW_RESPONSE_MODELS = (
    DhcpPreviewResponse,
    DnsPreviewResponse,
    FirewallPreviewResponse,
    VlanPreviewResponse,
    VpnPolicyPreviewResponse,
)


@pytest.mark.parametrize("model", _PREVIEW_RESPONSE_MODELS, ids=lambda m: m.__name__)
def test_preview_response_models_live_in_apply_response_models(
    model: type[BaseModel],
) -> None:
    """Consolidation guard: preview response models must not drift back into route modules."""
    assert model.__module__ == "router_control_host.apply_response_models"


def test_openapi_export_is_idempotent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Response-model refactors must not change OpenAPI — double export must be byte-identical."""
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    app = create_app(db_path=tmp_path / "openapi-idempotent.sqlite3", allow_fake_mutations=True)
    first = _canonical_openapi(app.openapi())
    second = _canonical_openapi(app.openapi())
    assert first == second


def test_wifi_apply_verification_model_matches_service_to_dict() -> None:
    service_fields = {
        field.name for field in WifiApplyVerification.__dataclass_fields__.values()
    }
    model_fields = set(WifiApplyVerificationResponse.model_fields)
    assert service_fields == model_fields
    sample = WifiApplyVerification(
        ssid_ok=True,
        encryption_ok=True,
        admin_up_ok=True,
        on_air_ok=None,
        observed={"ssid": "Staff-Private"},
    )
    parsed = WifiApplyVerificationResponse.model_validate(sample.to_dict())
    assert parsed.admin_up_ok is True
    assert parsed.on_air_ok is None


@pytest.mark.parametrize(
    ("path", "verdict_field"),
    [
        (f"{_API}/wireguard/apply", "tunnel_verification_status"),
        (f"{_API}/wireguard/teardown", "tunnel_verification_status"),
        (f"{_API}/wifi/station/apply", "uplink_verification_status"),
        (f"{_API}/wifi/station/teardown", "uplink_verification_status"),
        (f"{_API}/wifi/station/preview", "planned_uplink_verification_level"),
        (f"{_API}/wifi/apply", "on_air_verification_status"),
        (f"{_API}/wifi/teardown", "on_air_verification_status"),
    ],
)
def test_openapi_verdict_field_in_schema(
    openapi_schema: dict[str, Any],
    path: str,
    verdict_field: str,
) -> None:
    schema = _resolve_response_schema(openapi_schema, path)
    assert schema != {}, f"{path} 200 response must not be empty schema"
    props = _schema_property_names(schema)
    assert verdict_field in props, f"{path} OpenAPI must document {verdict_field}"
    required = _schema_required(schema)
    assert verdict_field in required, f"{path} OpenAPI must require {verdict_field}"


@pytest.mark.parametrize(
    "path",
    [
        f"{_API}/wireguard/apply",
        f"{_API}/wireguard/teardown",
        f"{_API}/wifi/station/apply",
        f"{_API}/wifi/station/teardown",
        f"{_API}/wifi/apply",
        f"{_API}/wifi/teardown",
    ],
)
def test_openapi_verdict_explanation_required(openapi_schema: dict[str, Any], path: str) -> None:
    schema = _resolve_response_schema(openapi_schema, path)
    props = _schema_property_names(schema)
    assert "verdict_explanation" in props, f"{path} must document verdict_explanation"
    assert "verdict_explanation" in _schema_required(schema)
    explanation = openapi_schema["components"]["schemas"]["VerdictExplanationResponse"]
    assert "signals_read" in explanation["properties"]
    assert "signals_missing" in explanation["properties"]
    assert "signals_rejected" in explanation["properties"]


def test_openapi_wifi_verification_nested_fields_match_model(
    openapi_schema: dict[str, Any],
) -> None:
    verification = openapi_schema["components"]["schemas"]["WifiApplyVerificationResponse"]
    nested_props = _schema_property_names(verification)
    model_props = set(WifiApplyVerificationResponse.model_fields)
    assert nested_props == model_props
    assert "admin_up_ok" in nested_props
    assert "on_air_ok" in nested_props
    assert "up_ok" not in nested_props
    required = _schema_required(verification)
    assert required == {"ssid_ok", "encryption_ok", "admin_up_ok", "observed"}
    assert "on_air_ok" not in required


_APPLY_OVERALL_VALUES = frozenset(get_args(ApplyOverallStatus))


@pytest.mark.parametrize(
    "path",
    [
        f"{_API}/wireguard/apply",
        f"{_API}/wireguard/teardown",
        f"{_API}/wifi/station/apply",
        f"{_API}/wifi/station/teardown",
        f"{_API}/wifi/apply",
        f"{_API}/wifi/teardown",
    ],
)
def test_openapi_apply_overall_is_literal_enum(
    openapi_schema: dict[str, Any],
    path: str,
) -> None:
    schema = _resolve_response_schema(openapi_schema, path)
    overall = schema["properties"]["overall"]
    assert "enum" in overall, f"{path} overall must be a closed enum"
    assert frozenset(overall["enum"]) == _APPLY_OVERALL_VALUES
    description = overall.get("description", "")
    assert "HTTP status" in description or "HTTP 200" in description
    assert OVERALL_HTTP_SEMANTICS.split(".")[0] in description


def test_openapi_apply_overall_contract_fails_when_enum_value_removed(
    openapi_schema: dict[str, Any],
) -> None:
    """Red→green guard: dropping rolled_back from ApplyOverallStatus empties contract parity."""
    schema = _resolve_response_schema(openapi_schema, f"{_API}/wifi/apply")
    overall_enum = set(schema["properties"]["overall"]["enum"])
    model_values = set(get_args(ApplyOverallStatus))
    assert overall_enum == model_values
    without_rolled_back = model_values - {"rolled_back"}
    assert "rolled_back" in overall_enum
    assert "rolled_back" not in without_rolled_back


def test_openapi_wireguard_tunnel_verdict_is_literal_enum(
    openapi_schema: dict[str, Any],
) -> None:
    schema = _resolve_response_schema(openapi_schema, f"{_API}/wireguard/apply")
    tunnel = schema["properties"]["tunnel_verification_status"]
    assert "enum" in tunnel
    assert set(tunnel["enum"]) == {
        "tunnel_no_peer",
        "tunnel_never_handshaked",
        "tunnel_healthy",
        "tunnel_unverified",
    }


def test_openapi_station_uplink_verdict_is_literal_enum(
    openapi_schema: dict[str, Any],
) -> None:
    schema = _resolve_response_schema(openapi_schema, f"{_API}/wifi/station/apply")
    uplink = schema["properties"]["uplink_verification_status"]
    assert "enum" in uplink
    assert set(uplink["enum"]) == {
        "uplink_dispatched_unverified",
        "uplink_associated_no_global",
        "uplink_verified_bounded",
        "uplink_failed",
    }


def test_openapi_wifi_on_air_verdict_is_literal_enum(
    openapi_schema: dict[str, Any],
) -> None:
    schema = _resolve_response_schema(openapi_schema, f"{_API}/wifi/apply")
    on_air = schema["properties"]["on_air_verification_status"]
    assert "enum" in on_air
    assert set(on_air["enum"]) == {
        "on_air_verified",
        "on_air_admin_only",
        "on_air_unverified",
        "on_air_still_broadcasting",
    }


def test_openapi_station_planned_uplink_level_distinct_from_runtime(
    openapi_schema: dict[str, Any],
) -> None:
    """Plan compile-time label must not share runtime uplink enum values."""
    preview_schema = _resolve_response_schema(openapi_schema, f"{_API}/wifi/station/preview")
    apply_schema = _resolve_response_schema(openapi_schema, f"{_API}/wifi/station/apply")
    planned = preview_schema["properties"]["planned_uplink_verification_level"]
    runtime = apply_schema["properties"]["uplink_verification_status"]
    assert "enum" in planned or "const" in planned
    planned_values = set(planned.get("enum", [planned["const"]]))
    runtime_values = set(runtime["enum"])
    assert planned_values.isdisjoint(runtime_values), (
        f"plan/runtime uplink verdict values must not overlap: {planned_values & runtime_values}"
    )
    assert planned_values == {"planned_uplink_verified_bounded"}


def _extract_literal_enum_values(prop_schema: dict[str, Any]) -> set[str]:
    """Resolve enum/const from direct schema or nullable anyOf wrapper."""
    if "enum" in prop_schema:
        return set(prop_schema["enum"])
    if "const" in prop_schema:
        return {prop_schema["const"]}
    if "anyOf" in prop_schema:
        values: set[str] = set()
        for branch in prop_schema["anyOf"]:
            if branch.get("type") == "null":
                continue
            values |= _extract_literal_enum_values(branch)
        return values
    raise AssertionError(f"schema has no enum/const/anyOf: {prop_schema!r}")


def test_openapi_wireguard_configuration_verdict_is_literal_enum(
    openapi_schema: dict[str, Any],
) -> None:
    schema = _resolve_response_schema(openapi_schema, f"{_API}/wireguard/apply")
    configuration = schema["properties"]["configuration_verification_status"]
    assert _extract_literal_enum_values(configuration) == {"device_accepted_configuration"}


def test_openapi_wireguard_interface_verdict_is_literal_enum(
    openapi_schema: dict[str, Any],
) -> None:
    schema = _resolve_response_schema(openapi_schema, f"{_API}/wireguard/apply")
    interface = schema["properties"]["interface_verification_status"]
    assert _extract_literal_enum_values(interface) == {
        "interface_present_up",
        "interface_present_down",
        "interface_not_up",
        "interface_id_mismatch",
        "interface_absent",
        "interface_still_present",
    }


def test_openapi_wireguard_interface_address_verdict_is_literal_enum(
    openapi_schema: dict[str, Any],
) -> None:
    schema = _resolve_response_schema(openapi_schema, f"{_API}/wireguard/apply")
    address = schema["properties"]["interface_address_verification_status"]
    assert _extract_literal_enum_values(address) == {
        "interface_address_not_configured",
        "address_configured_unverified",
        "address_readback_confirmed",
    }


def test_openapi_verdict_contract_fails_when_model_field_removed(
    openapi_schema: dict[str, Any],
) -> None:
    """Red→green guard: dropping tunnel_verification_status from the model empties the contract."""
    schema = _resolve_response_schema(openapi_schema, f"{_API}/wireguard/apply")
    fields = set(WireguardApplyResponse.model_fields)
    assert "tunnel_verification_status" in fields
    without_verdict = fields - {"tunnel_verification_status"}
    assert "tunnel_verification_status" not in without_verdict
    assert "tunnel_verification_status" in _schema_property_names(schema)


def _response_model_cases() -> list[_ResponseModelCase]:
    def _wifi_setup(c: Any) -> None:
        transport = _ApiFakeWifiTransport()
        c.app.state.host.wifi_apply_transport_factory = lambda: transport
        c.app.state.host.wifi_apply_credential_resolver = lambda _ref: "test-psk-placeholder"
        transport.readback_sequence = [
            {
                "interface": {
                    "ssid": "Staff-Private",
                    "encryption": {"wpa2": True, "enabled": True},
                    "state": "up",
                    "up": True,
                }
            }
        ]

    def _wireguard_setup(c: Any) -> None:
        transport = _ApiFakeWireguardTransport()
        c.app.state.host.wireguard_apply_transport_factory = lambda: transport
        transport.readback_sequence = [
            {
                "interface": {
                    "id": _TEST_WG,
                    "state": "up",
                    "up": True,
                    "type": "Wireguard",
                }
            }
        ]

    def _station_setup(c: Any) -> None:
        transport = _ApiFakeStationTransport()
        c.app.state.host.wifi_station_apply_transport_factory = lambda: transport
        c.app.state.host.wifi_station_apply_credential_resolver = (
            lambda _ref: "test-psk-placeholder"
        )

    return [
        _ResponseModelCase(
            "wifi-site-survey",
            f"{_API}/wifi/site-survey",
            WifiSiteSurveyResponse,
            lambda c: c.post(f"{_API}/wifi/site-survey", json={"radio": "WifiMaster0"}),
        ),
        _ResponseModelCase(
            "wifi-station-apply",
            f"{_API}/wifi/station/apply",
            WifiStationApplyResponse,
            lambda c: c.post(f"{_API}/wifi/station/apply", json=_station_apply_payload()),
            setup=_station_setup,
        ),
        _ResponseModelCase(
            "wifi-station-teardown",
            f"{_API}/wifi/station/teardown",
            WifiStationApplyResponse,
            lambda c: c.post(
                f"{_API}/wifi/station/teardown",
                json=_station_apply_payload(confirm_live_apply=False, confirm_live_teardown=True),
            ),
            setup=_station_setup,
        ),
        _ResponseModelCase(
            "wifi-observed-state",
            f"{_API}/wifi/observed-state",
            WifiObservedStateResponse,
            lambda c: c.post(f"{_API}/wifi/observed-state", json={}),
        ),
        _ResponseModelCase(
            "wifi-preview",
            f"{_API}/wifi/preview",
            WifiPreviewResponse,
            lambda c: c.post(f"{_API}/wifi/preview", json=_wifi_intent_payload()),
            setup=_wifi_setup,
        ),
        _ResponseModelCase(
            "wifi-apply",
            f"{_API}/wifi/apply",
            WifiApplyResponse,
            lambda c: c.post(
                f"{_API}/wifi/apply",
                json=_wifi_intent_payload(confirm_live_apply=True),
            ),
            setup=_wifi_setup,
        ),
        _ResponseModelCase(
            "wifi-teardown",
            f"{_API}/wifi/teardown",
            WifiApplyResponse,
            lambda c: c.post(
                f"{_API}/wifi/teardown",
                json={
                    "ap_id": _TEST_AP,
                    "wpa_mode": "WPA2",
                    "confirm_live_teardown": True,
                },
            ),
            setup=_wifi_setup,
        ),
        _ResponseModelCase(
            "vpn-policy-preview",
            f"{_API}/vpn/policy-routing/preview",
            VpnPolicyPreviewResponse,
            lambda c: c.post(
                f"{_API}/vpn/policy-routing/preview",
                json={
                    "policy_name": "vpn-uplink",
                    "vpn_interface": "GigabitEthernet1",
                    "interface_kind": "other",
                    "ip_global": {"priority": 700},
                    "name_servers": [{"address": "1.1.1.1"}],
                },
            ),
        ),
        _ResponseModelCase(
            "vlan-preview",
            f"{_API}/vlan/preview",
            VlanPreviewResponse,
            lambda c: c.post(
                f"{_API}/vlan/preview",
                json={
                    "bridge_id": "Bridge3",
                    "zone_id": "staff",
                    "vlan_id": 20,
                    "ipv4_cidr": "10.20.0.0/24",
                    "ipv4_gateway": "10.20.0.1",
                },
            ),
        ),
        _ResponseModelCase(
            "dhcp-preview",
            f"{_API}/dhcp/preview",
            DhcpPreviewResponse,
            lambda c: c.post(
                f"{_API}/dhcp/preview",
                json={
                    "zone_id": "Guest",
                    "pool_start": "10.10.0.100",
                    "pool_end": "10.10.0.200",
                    "lease_seconds": 86400,
                    "reservations": [],
                },
            ),
        ),
        _ResponseModelCase(
            "dns-preview",
            f"{_API}/dns/preview",
            DnsPreviewResponse,
            lambda c: c.post(
                f"{_API}/dns/preview",
                json={
                    "zone_id": "Guest",
                    "local_fqdn": "order.guest.example.com",
                    "upstream_resolvers": ["8.8.8.8"],
                },
            ),
        ),
        _ResponseModelCase(
            "firewall-preview",
            f"{_API}/firewall/preview",
            FirewallPreviewResponse,
            lambda c: c.post(
                f"{_API}/firewall/preview",
                json={
                    "zone_id": "Guest",
                    "rules": [
                        {
                            "action": "Allow",
                            "destination_family": "Dns",
                            "ordinal": 10,
                        },
                    ],
                },
            ),
        ),
        _ResponseModelCase(
            "wireguard-preview",
            f"{_API}/wireguard/preview",
            WireguardPreviewResponse,
            lambda c: c.post(f"{_API}/wireguard/preview", json=_wireguard_intent_payload()),
        ),
        _ResponseModelCase(
            "wireguard-apply",
            f"{_API}/wireguard/apply",
            WireguardApplyResponse,
            lambda c: c.post(
                f"{_API}/wireguard/apply",
                json=_wireguard_intent_payload(confirm_live_apply=True),
            ),
            setup=_wireguard_setup,
        ),
        _ResponseModelCase(
            "wireguard-teardown",
            f"{_API}/wireguard/teardown",
            WireguardApplyResponse,
            lambda c: c.post(
                f"{_API}/wireguard/teardown",
                json=_wireguard_intent_payload(confirm_live_teardown=True),
            ),
            setup=_wireguard_setup,
        ),
        _ResponseModelCase(
            "bootstrap-discovery",
            f"{_API}/lab/bootstrap-discovery",
            BootstrapDiscoveryResponse,
            lambda c: c.post(
                f"{_API}/lab/bootstrap-discovery",
                json={
                    "host": "http://192.168.2.1",
                    "username": "admin",
                    "credential_ref_id": "cred_test",
                    "allow_insecure_http": True,
                },
            ),
        ),
        _ResponseModelCase(
            "rci-fail-safe-arm",
            f"{_API}/routers/{{router_id}}/rci/fail-safe/arm",
            RciMutationResponse,
            lambda c: c.post(
                f"{_API}/routers/{c.test_router_id}/rci/fail-safe/arm",
                json={"operation": "arm_timer_reboot_60"},
                headers={"Idempotency-Key": "openapi-rci-arm"},
            ),
        ),
        _ResponseModelCase(
            "rci-fail-safe-disarm",
            f"{_API}/routers/{{router_id}}/rci/fail-safe/disarm",
            RciMutationResponse,
            lambda c: c.post(
                f"{_API}/routers/{c.test_router_id}/rci/fail-safe/disarm",
                json={"operation": "disarm_timer"},
                headers={"Idempotency-Key": "openapi-rci-disarm"},
            ),
        ),
        _ResponseModelCase(
            "rci-interface-up",
            f"{_API}/routers/{{router_id}}/rci/interface",
            RciMutationResponse,
            lambda c: c.post(
                f"{_API}/routers/{c.test_router_id}/rci/interface",
                json={"operation": "interface_up", "interface_id": "Bridge0"},
                headers={"Idempotency-Key": "openapi-rci-if-up"},
            ),
        ),
        _ResponseModelCase(
            "rci-system-save",
            f"{_API}/routers/{{router_id}}/rci/system/configuration-save",
            RciMutationResponse,
            lambda c: c.post(
                f"{_API}/routers/{c.test_router_id}/rci/system/configuration-save",
                json={"operation": "configuration_save"},
                headers={"Idempotency-Key": "openapi-rci-save"},
            ),
        ),
        _ResponseModelCase(
            "rci-system-reboot",
            f"{_API}/routers/{{router_id}}/rci/system/reboot",
            RciMutationResponse,
            lambda c: c.post(
                f"{_API}/routers/{c.test_router_id}/rci/system/reboot",
                json={"operation": "reboot"},
                headers={"Idempotency-Key": "openapi-rci-reboot"},
            ),
        ),
        _ResponseModelCase(
            "wifi-station-preview",
            f"{_API}/wifi/station/preview",
            WifiStationPreviewResponse,
            lambda c: c.post(
                f"{_API}/wifi/station/preview",
                json={
                    "mode": "WifiWan",
                    "ssid": "Venue-Guest",
                    "band": "BAND_2_4GHZ",
                    "credential_ref_id": "credref:venue-wifi",
                },
            ),
        ),
    ]


@pytest.mark.parametrize(
    "case",
    _response_model_cases(),
    ids=lambda case: case.route_id,
)
def test_response_model_routes_validate_live_body(
    case: _ResponseModelCase,
    enrolled_openapi_client,
) -> None:
    if case.setup is not None:
        case.setup(enrolled_openapi_client)
    if case.route_id == "bootstrap-discovery":
        with patch(
            "router_control_host.bootstrap_discovery_routes.run_bootstrap_discovery",
            return_value=_bootstrap_sample_report(),
        ):
            resp = case.invoke(enrolled_openapi_client)
    else:
        resp = case.invoke(enrolled_openapi_client)
    assert resp.status_code == 200, f"{case.route_id}: {resp.text}"
    body = resp.json()
    _assert_required_model_fields_in_body(case.model, body)
    case.model.model_validate(body)


def test_live_response_validates_against_wireguard_apply_model(openapi_client) -> None:
    """Actual JSONResponse body must validate against the documented model (no silent drift)."""
    transport = _ApiFakeWireguardTransport()
    openapi_client.app.state.host.wireguard_apply_transport_factory = lambda: transport
    transport.readback_sequence = [
        {
            "interface": {
                "id": "Wireguard5",
                "state": "up",
                "up": True,
                "type": "Wireguard",
            }
        }
    ]
    resp = openapi_client.post(
        f"{_API}/wireguard/apply",
        json={"wg_id": "Wireguard5", "enabled": True, "confirm_live_apply": True},
    )
    assert resp.status_code == 200
    body = resp.json()
    parsed = WireguardApplyResponse.model_validate(body)
    assert parsed.tunnel_verification_status == body["tunnel_verification_status"]
    assert parsed.tunnel_verification_status == "tunnel_no_peer"


def test_live_response_validates_against_station_apply_model(openapi_client) -> None:
    transport = _ApiFakeStationTransport()
    openapi_client.app.state.host.wifi_station_apply_transport_factory = lambda: transport
    openapi_client.app.state.host.wifi_station_apply_credential_resolver = (
        lambda _ref: "test-psk-placeholder"
    )
    resp = openapi_client.post(
        f"{_API}/wifi/station/apply",
        json={
            "mode": "WifiWan",
            "ssid": "Venue-Guest",
            "band": "BAND_2_4GHZ",
            "credential_ref_id": "credref:venue-wifi",
            "confirm_live_apply": True,
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    parsed = WifiStationApplyResponse.model_validate(body)
    assert parsed.uplink_verification_status == body["uplink_verification_status"]
    assert parsed.uplink_verification_status == "uplink_dispatched_unverified"


def test_openapi_no_secrets_in_wireguard_apply_schema(
    openapi_schema: dict[str, Any],
) -> None:
    schema = _resolve_response_schema(openapi_schema, f"{_API}/wireguard/apply")
    serialized = str(schema).lower()
    for forbidden in ("private_key", "preshared", "password", "psk"):
        assert forbidden not in serialized


class _ApiFakeWifiTransport:
    def __init__(self) -> None:
        self.readback_sequence: list[Any] = []
        self._pre_apply_read_done = False

    def execute_sealed_rci_write(self, request: Any) -> Any:
        return _ok_envelope()

    def execute_rci_parse(self, cli_command: str) -> Any:
        if cli_command.startswith("show interface") and not self._pre_apply_read_done:
            self._pre_apply_read_done = True
            if len(self.readback_sequence) == 1:
                return {
                    "interface": {
                        "ssid": "",
                        "encryption": {},
                        "state": "down",
                        "up": False,
                    }
                }
        if self.readback_sequence:
            return self.readback_sequence.pop(0)
        return {
            "interface": {
                "ssid": "",
                "encryption": {},
                "state": "down",
                "up": False,
            }
        }


class _ApiFakeWireguardTransport:
    def __init__(self) -> None:
        self.readback_sequence: list[Any] = []
        self._pre_apply_read_done = False

    def execute_sealed_rci_write(self, request: Any) -> Any:
        body_bytes = request.body
        if is_wireguard_nested_peer_body(body_bytes):
            return _ok_envelope()
        return _ok_envelope()

    def execute_rci_parse(self, cli_command: str) -> Any:
        if cli_command.startswith("show interface") and not self._pre_apply_read_done:
            self._pre_apply_read_done = True
            if len(self.readback_sequence) == 1:
                return {"interface": {}}
        if self.readback_sequence:
            return self.readback_sequence.pop(0)
        return {"interface": {}}


class _ApiFakeStationTransport:
    wifi_station_offline_only = True

    def execute_sealed_rci_write(self, request: Any) -> Any:
        return _ok_envelope()


def _ok_envelope() -> list[dict[str, Any]]:
    return [
        {
            "parse": {
                "prompt": "(config)",
                "status": [
                    {
                        "status": "message",
                        "code": "8979152",
                        "ident": "Core::Interface",
                        "message": "synthetic ack",
                    }
                ],
            }
        }
    ]
