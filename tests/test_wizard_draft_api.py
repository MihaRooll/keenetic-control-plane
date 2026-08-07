"""Wizard draft router API — Gate A closed OK, no secret leak."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie


@pytest.fixture
def app_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")
    application = create_app(db_path=tmp_path / "wizard-draft.sqlite3", allow_fake_mutations=False)
    return application


@pytest.fixture
def client(app_env):
    from fastapi.testclient import TestClient

    with TestClient(app_env) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield c


def _draft_body(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "host": "192.168.2.1",
        "username": "admin",
        "secret": "lab-wizard-secret-value",
        "allow_insecure_http": True,
    }
    body.update(overrides)
    return body


def test_wizard_draft_requires_auth(app_env) -> None:
    from fastapi.testclient import TestClient

    with TestClient(app_env) as c:
        response = c.post(
            "/api/router-control/v1/lab/wizard-draft-router",
            json=_draft_body(),
            headers={"Idempotency-Key": "wiz-auth-1"},
        )
    assert response.status_code == 401


def test_wizard_draft_rejects_extra_fields(client) -> None:
    response = client.post(
        "/api/router-control/v1/lab/wizard-draft-router",
        json={**_draft_body(), "management_password": "must-not-accept"},
        headers={"Idempotency-Key": "wiz-extra-1"},
    )
    assert response.status_code == 422


def test_wizard_draft_requires_idempotency_key(client) -> None:
    response = client.post(
        "/api/router-control/v1/lab/wizard-draft-router",
        json=_draft_body(),
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "request.validation_failed"


def test_wizard_draft_rejects_oversized_idempotency_key(client) -> None:
    response = client.post(
        "/api/router-control/v1/lab/wizard-draft-router",
        json=_draft_body(),
        headers={"Idempotency-Key": "x" * 129},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "request.validation_failed"


def test_wizard_draft_success_gate_a_closed(client, app_env) -> None:
    app_env.gate_a_certification = None
    response = client.post(
        "/api/router-control/v1/lab/wizard-draft-router",
        json=_draft_body(),
        headers={"Idempotency-Key": "wiz-success-1"},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["router_id"].startswith("rtr_")
    assert body["credential_ref_id"].startswith("cred_")
    assert body["certification_eligible"] is False
    assert body["gate_a_status"] == "closed"
    assert "Wi-Fi" in body["handoff_note"] or "Wi" in body["handoff_note"]


def test_wizard_draft_response_has_no_secrets(client, caplog) -> None:
    import logging

    from router_control_host.wizard_draft_routes import (
        WizardDraftRouterBody,
        _wizard_draft_digest,
    )

    caplog.set_level(logging.DEBUG)
    secret_value = "lab-wizard-secret-value"
    draft_payload = _draft_body(secret=secret_value)
    response = client.post(
        "/api/router-control/v1/lab/wizard-draft-router",
        json=draft_payload,
        headers={"Idempotency-Key": "wiz-nosecret-1"},
    )
    assert response.status_code == 201
    body = response.json()
    serialized = json.dumps(body)
    assert secret_value not in serialized
    assert "password" not in serialized.lower()
    assert secret_value not in caplog.text

    vault = client.app.state.host.runtime.vault
    cred_id = body["credential_ref_id"]
    assert vault.use(cred_id) == secret_value

    store = client.app.state.host.runtime.store
    body_dict = WizardDraftRouterBody(**draft_payload).model_dump(mode="json")
    digest = _wizard_draft_digest(body_dict)
    record = store.peek_idempotency(
        operation_kind="enroll",
        idempotency_key="wiz-nosecret-1",
        request_digest=digest,
        router_id=None,
    )
    assert record is not None
    stored = json.loads(record.response_ref or "{}")
    stored_blob = json.dumps(stored)
    assert secret_value not in stored_blob


def test_wizard_draft_idempotent_replay(client) -> None:
    key = "wiz-replay-1"
    first = client.post(
        "/api/router-control/v1/lab/wizard-draft-router",
        json=_draft_body(),
        headers={"Idempotency-Key": key},
    )
    second = client.post(
        "/api/router-control/v1/lab/wizard-draft-router",
        json=_draft_body(),
        headers={"Idempotency-Key": key},
    )
    assert first.status_code == 201
    assert second.status_code == 201
    assert first.json()["router_id"] == second.json()["router_id"]
