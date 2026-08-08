"""KeenDNS/CrazeDNS preview host API tests (status + preview only; no apply route)."""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie

_API = "/api/router-control/v1"
_DOC_CITATION = "OPERATOR_KEENDNS_DISCOVERY.md"
_FIXTURE = Path("tests/fixtures/netcraze/bootstrap_components_real_device_shape.json")


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    app = create_app(db_path=tmp_path / "keendns-preview.sqlite3", enable_worker=False)
    from fastapi.testclient import TestClient

    with TestClient(app) as tc:
        tc.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield tc


_PREVIEW_BODY = {
    "intent_kind": "book",
    "name": "sample-name",
    "domain": "keenetic.link",
    "mode": "auto",
}


def test_keendns_status_empty_unknown(client) -> None:
    resp = client.post(f"{_API}/keendns/status", json={})
    assert resp.status_code == 200
    body = resp.json()
    assert body["feature_availability"] == "unknown"
    assert body["name_reservation"] == "unknown"
    assert body["access_mode"] == "unknown"
    assert body["feature_availability"] != "disabled"


def test_keendns_status_unavailable_without_ndns(client) -> None:
    payload = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    component_map = dict(payload["component"])
    component_map.pop("ndns")
    payload["component"] = component_map
    resp = client.post(
        f"{_API}/keendns/status",
        json={"components_raw": json.dumps(payload)},
    )
    assert resp.status_code == 200
    assert resp.json()["feature_availability"] == "unavailable"


def test_keendns_status_unfamiliar_unknown(client) -> None:
    resp = client.post(
        f"{_API}/keendns/status",
        json={"components_raw": "not-json", "ndns_show_raw": "foo bar"},
    )
    assert resp.status_code == 200
    assert resp.json()["feature_availability"] == "unknown"


def test_keendns_preview_compiles_offline(client) -> None:
    resp = client.post(f"{_API}/keendns/preview", json=_PREVIEW_BODY)
    assert resp.status_code == 200
    body = resp.json()
    assert body["verification_status"] == "documentation_sourced_unconfirmed"
    assert body["preview_ops"][0]["command_text"] == "ndns book-name sample-name keenetic.link auto"
    assert any(_DOC_CITATION in note for note in body["preview_ops"][0]["notes"])


def test_keendns_preview_book_requires_mode(client) -> None:
    resp = client.post(
        f"{_API}/keendns/preview",
        json={"intent_kind": "book", "name": "n", "domain": "keenetic.link"},
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "keendns.preview_failed"


def test_openapi_has_preview_and_apply(client) -> None:
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    paths = resp.json()["paths"]
    assert f"{_API}/keendns/preview" in paths
    assert f"{_API}/keendns/status" in paths
    assert f"{_API}/keendns/apply" in paths
    assert f"{_API}/keendns/teardown" not in paths
    preview_post = paths[f"{_API}/keendns/preview"]["post"]
    response_schema = preview_post["responses"]["200"]["content"]["application/json"]["schema"]
    if "$ref" in response_schema:
        ref_name = response_schema["$ref"].rsplit("/", 1)[-1]
        response_schema = resp.json()["components"]["schemas"][ref_name]
    verdict = response_schema["properties"]["verification_status"]
    assert verdict.get("const") == "documentation_sourced_unconfirmed" or verdict.get("enum") == [
        "documentation_sourced_unconfirmed"
    ]


def test_no_apply_keendns_service_export() -> None:
    module = importlib.import_module("router_control.application.keendns_preview_service")
    assert not hasattr(module, "apply_keendns")
    assert not hasattr(module, "execute_sealed_rci_write")


def test_keendns_observe_fake_adapter(client) -> None:
    resp = client.post(
        f"{_API}/keendns/observe",
        json={},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["default_fqdn"] is None
    assert body["ssl_valid"] is None
    assert body["name_reservation"] == "not_reserved"
    assert body["access_mode"] == "unknown"
    assert body["certification_eligible"] is False


def test_keendns_status_empty_still_no_io(client) -> None:
    resp = client.post(f"{_API}/keendns/status", json={})
    assert resp.status_code == 200
    body = resp.json()
    assert body["feature_availability"] == "unknown"
    assert body["name_reservation"] == "unknown"
    assert body["access_mode"] == "unknown"


def test_openapi_has_observe_route(client) -> None:
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    paths = resp.json()["paths"]
    assert f"{_API}/keendns/observe" in paths


def test_keendns_preview_service_has_no_execute_import() -> None:
    path = Path("router_control/application/keendns_preview_service.py")
    source = path.read_text(encoding="utf-8")
    assert "SealedRciWriteRequest" not in source
    assert "from router_control.adapters.netcraze.transport" not in source
