"""API tests for POST /vpn-profiles/parse-preview — vault parse, sanitized response only."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from router_control.adapters.netcraze.awg_profile import (
    DUALSTACK_IPV6_OPERATOR_NOTE,
    parse_awg_profile_text,
)
from router_control.adapters.secrets.memory import MemoryVault
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie

SAMPLE_PROFILE = """
[Interface]
PrivateKey = EXAMPLE_PRIVATE_KEY_PLACEHOLDER_AAAAAAAAAAAAAAAAAAAAAAAA
Address = 10.0.0.2/32
DNS = 1.1.1.1
Jc = 5
Jmin = 50
Jmax = 1000
S1 = 80
S2 = 80

[Peer]
PublicKey = EXAMPLE_PUBLIC_KEY_PLACEHOLDER_BBBBBBBBBBBBBBBBBBBBBBBBBBBB
PresharedKey = EXAMPLE_PSK_PLACEHOLDER_CCCCCCCCCCCCCCCCCCCCCCCCCCCC
Endpoint = EXAMPLE_ENDPOINT:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""

SECRET_SENTINELS = (
    "EXAMPLE_PRIVATE_KEY_PLACEHOLDER",
    "EXAMPLE_PSK_PLACEHOLDER",
)


@pytest.fixture
def authed_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    app = create_app(db_path=tmp_path / "vpn-import-api.sqlite3", enable_worker=False)
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield client


def test_parse_preview_requires_auth(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    app = create_app(db_path=tmp_path / "vpn-import-unauth.sqlite3", enable_worker=False)
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        resp = client.post(
            "/api/router-control/v1/vpn-profiles/parse-preview",
            json={"profile_text": SAMPLE_PROFILE},
        )
    assert resp.status_code == 401


def test_parse_preview_extra_forbid(authed_client) -> None:
    resp = authed_client.post(
        "/api/router-control/v1/vpn-profiles/parse-preview",
        json={"profile_text": SAMPLE_PROFILE, "unexpected": True},
    )
    assert resp.status_code == 422


def test_parse_preview_sanitized_no_secret_echo(authed_client) -> None:
    resp = authed_client.post(
        "/api/router-control/v1/vpn-profiles/parse-preview",
        json={"profile_text": SAMPLE_PROFILE},
    )
    assert resp.status_code == 200
    body = resp.json()
    text = resp.text
    assert "profile_text" not in body
    assert "PrivateKey" in body["interface_field_names"]
    assert body["endpoint_configured"] is True
    assert len(body["credential_refs"]) >= 1
    for ref in body["credential_refs"]:
        assert "credential_ref_id" in ref
        assert ref["credential_ref_id"].startswith("cred_")
    for sentinel in SECRET_SENTINELS:
        assert sentinel not in text
    assert body["peer_public_key"] == "EXAMPLE_PUBLIC_KEY_PLACEHOLDER_BBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    assert body["peer_endpoint"] == "EXAMPLE_ENDPOINT:51820"
    assert body["peer_allow_ips"] == "0.0.0.0/0"
    assert body["peer_keepalive_interval"] == 25


def test_parse_preview_peer_fields_absent_from_certification_sanitized(authed_client) -> None:
    """parse-preview returns peer routing fields; certification sanitized_dict must not."""
    resp = authed_client.post(
        "/api/router-control/v1/vpn-profiles/parse-preview",
        json={"profile_text": SAMPLE_PROFILE},
    )
    assert resp.status_code == 200
    preview = resp.json()
    assert preview["peer_endpoint"] == "EXAMPLE_ENDPOINT:51820"

    vault = MemoryVault()
    parsed = parse_awg_profile_text(SAMPLE_PROFILE, vault=vault)
    evidence = parsed.sanitized_dict()
    assert "peer_endpoint" not in evidence
    assert "peer_public_key" not in evidence
    assert "peer_allow_ips" not in evidence
    assert "EXAMPLE_ENDPOINT" not in json.dumps(evidence)


def test_parse_preview_invalid_profile(authed_client) -> None:
    resp = authed_client.post(
        "/api/router-control/v1/vpn-profiles/parse-preview",
        json={"profile_text": "[Interface]\nAddress = 10.0.0.1/32\n"},
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "profile.validation_failed"


DUAL_STACK_PROFILE = SAMPLE_PROFILE.replace(
    "AllowedIPs = 0.0.0.0/0", "AllowedIPs = 0.0.0.0/0, ::/0"
)
_PLAIN_MARKER = "ECHO_PLAIN_MARKER_DO_NOT_ECHO_12345"


def test_parse_preview_dual_stack_allowed_ips(authed_client) -> None:
    resp = authed_client.post(
        "/api/router-control/v1/vpn-profiles/parse-preview",
        json={"profile_text": DUAL_STACK_PROFILE},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["peer_allow_ips"] == "0.0.0.0/0"
    assert body["unsupported_fields"] == ["AllowedIPs"]
    assert body["operator_notes"] == [DUALSTACK_IPV6_OPERATOR_NOTE]
    assert "::/0" not in resp.text


def test_parse_preview_dual_stack_no_echo_marker_in_ipv6(authed_client) -> None:
    profile = DUAL_STACK_PROFILE.replace(
        "::/0",
        f"2001:db8::{_PLAIN_MARKER}/128",
    )
    resp = authed_client.post(
        "/api/router-control/v1/vpn-profiles/parse-preview",
        json={"profile_text": profile},
    )
    assert resp.status_code == 200
    assert _PLAIN_MARKER not in resp.text
    body = resp.json()
    assert body["peer_allow_ips"] == "0.0.0.0/0"
    assert body["unsupported_fields"] == ["AllowedIPs"]


def test_parse_preview_ipv6_only_allowed_ips_422(authed_client) -> None:
    profile = SAMPLE_PROFILE.replace("AllowedIPs = 0.0.0.0/0", "AllowedIPs = ::/0")
    resp = authed_client.post(
        "/api/router-control/v1/vpn-profiles/parse-preview",
        json={"profile_text": profile},
    )
    assert resp.status_code == 422
    body = resp.json()
    assert body["error"]["code"] == "profile.validation_failed"
    details = body["error"].get("details", [])
    assert any(d.get("field") == "AllowedIPs" for d in details)
    assert "::/0" not in resp.text


def test_import_dual_stack_allowed_ips(authed_client) -> None:
    resp = authed_client.post(
        "/api/router-control/v1/vpn-profiles/import",
        json={
            "display_name": "dual-stack-test",
            "vpn_kind": "AmneziaWG",
            "profile_text": DUAL_STACK_PROFILE,
            "wg_id": "Wireguard5",
        },
        headers={"Idempotency-Key": "dual-stack-import-1"},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["validation_status"] == "Valid"
    assert body["unsupported_fields"] == ["AllowedIPs"]
    assert body["operator_notes"] == [DUALSTACK_IPV6_OPERATOR_NOTE]
    assert body["wireguard_intent_fields"]["peer_allow_ips"] == "0.0.0.0/0"
    assert "::/0" not in resp.text


def test_import_ipv6_only_allowed_ips_422(authed_client) -> None:
    profile = SAMPLE_PROFILE.replace("AllowedIPs = 0.0.0.0/0", "AllowedIPs = ::/0")
    resp = authed_client.post(
        "/api/router-control/v1/vpn-profiles/import",
        json={
            "display_name": "ipv6-only-test",
            "vpn_kind": "AmneziaWG",
            "profile_text": profile,
            "wg_id": "Wireguard5",
        },
        headers={"Idempotency-Key": "ipv6-only-import-1"},
    )
    assert resp.status_code == 422
    body = resp.json()
    assert body["error"]["code"] == "profile.validation_failed"
    details = body["error"].get("details", [])
    assert any(d.get("field") == "AllowedIPs" for d in details)
