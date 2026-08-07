"""UI security headers, CSP, traversal, secret vocabulary."""

from __future__ import annotations

import json
import re
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie
from router_control_host.ui_routes import CSP_VALUE

REPO_ROOT = Path(__file__).resolve().parents[1]
WEB = REPO_ROOT / "router_control_host" / "web"

_UPSTREAM_SSID_MARKER = "RC-UPSTREAM-SSID-LEAK-TEST-a1b2c3d4"
_OFFLINE_PSK_PLACEHOLDER = "test-psk-placeholder-for-station"


@pytest.fixture
def authed_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    app = create_app(db_path=tmp_path / "ui-sec.sqlite3", enable_worker=False)
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield client


def _assert_security_headers(r) -> None:
    assert r.headers.get("Content-Security-Policy") == CSP_VALUE
    assert r.headers.get("Referrer-Policy") == "no-referrer"
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"


def test_csp_on_html(authed_client) -> None:
    r = authed_client.get("/settings/router-control")
    assert r.status_code == 200
    _assert_security_headers(r)
    assert "unsafe-inline" not in r.headers.get("Content-Security-Policy", "")


def test_csp_on_assets(authed_client) -> None:
    for asset in ("styles.css", "app.js"):
        r = authed_client.get(f"/settings/router-control/assets/{asset}")
        assert r.status_code == 200
        _assert_security_headers(r)


def test_path_traversal_blocked(authed_client) -> None:
    for path in (
        "/settings/router-control/assets/../index.html",
        "/settings/router-control/assets/..%2findex.html",
        "/settings/router-control/assets/styles.css%00.js",
    ):
        r = authed_client.get(path)
        assert r.status_code in (400, 404), path


def test_ui_traversal_in_prefix_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    from fastapi.testclient import TestClient

    app = create_app(db_path=tmp_path / "ui-trav.sqlite3", enable_worker=False)
    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        r = client.get("/settings/router-control/../etc/passwd")
    assert r.status_code in (400, 404)


# API contract field names for credential references — not secret values.
_SAFE_CREDENTIAL_REF_TOKENS = (
    "private_key_credential_ref_id",
    "preshared_key_credential_ref_id",
)


def _text_without_safe_credential_ref_ids(text: str) -> str:
    masked = text.lower()
    for token in _SAFE_CREDENTIAL_REF_TOKENS:
        masked = masked.replace(token, "")
    return masked


def _strip_app_js_secret_denylist_blocks(text: str) -> str:
    """Remove intentional secret-key denylist literals from static analysis."""
    stripped = text
    for pattern in (
        r"const UPLINK_READBACK_SECRET_KEYS = new Set\(\[[\s\S]*?\]\);",
        r"function isUplinkReadbackSecretKey\([\s\S]*?\n\}",
        r"function sanitizeUplinkReadbackDisplayValue\([\s\S]*?\n\}",
        r"function redactApplyResultSecrets\([\s\S]*?\n\}",
        r"function sanitizeApplyResultForDisplay\([\s\S]*?\n\}",
    ):
        stripped = re.sub(pattern, "", stripped)
    return stripped


def test_static_assets_no_secret_vocabulary(authed_client) -> None:
    forbidden = [
        "private_key",
        "preshared_key",
        "management_password",
        "hub_admin_password",
        "never-echo",
    ]
    obfuscation_markers = [
        '["management", "password"]',
        "['management', 'password']",
    ]
    for path in ("/settings/router-control", "/settings/router-control/assets/app.js"):
        r = authed_client.get(path)
        body = r.text
        if path.endswith("app.js"):
            body = _strip_app_js_secret_denylist_blocks(body)
        lower = _text_without_safe_credential_ref_ids(body)
        for word in forbidden:
            assert word not in lower, f"{word} found in {path}"
        for marker in obfuscation_markers:
            assert marker not in r.text, f"obfuscation marker {marker!r} found in {path}"


def test_static_assets_secret_denylist_still_present(authed_client) -> None:
    """Denylist helpers must remain in app.js — only excluded from vocabulary scan."""
    r = authed_client.get("/settings/router-control/assets/app.js")
    assert r.status_code == 200
    assert "UPLINK_READBACK_SECRET_KEYS" in r.text
    assert "function isUplinkReadbackSecretKey(" in r.text
    assert "function sanitizeApplyResultForDisplay(" in r.text


def test_login_page_csp_no_unsafe_inline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    app = create_app(db_path=tmp_path / "login-csp.sqlite3", enable_worker=False)
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        r = client.get("/login")
    assert r.status_code == 200
    csp = r.headers.get("Content-Security-Policy", "")
    assert "style-src 'self'" in csp
    assert "unsafe-inline" not in csp


def test_no_login_form_in_ui(authed_client) -> None:
    """Management shell must not embed a password/login form."""
    r = authed_client.get("/settings/router-control")
    assert 'type="password"' not in r.text
    assert 'action="/login"' not in r.text
    assert 'name="password"' not in r.text


def test_wizard_secret_field_not_in_url_or_storage() -> None:
    """Static source checks on wizard JS — NOT a runtime DOM guarantee.

    Asserts the add-router wizard path avoids named password fields, storage APIs,
    and URL query usage, and that the step-0 submit handler calls preventDefault
    before apiFetch to wizard-draft. Does not execute the browser or intercept
    network at runtime.
    """
    app_js = Path(__file__).resolve().parents[1] / "router_control_host" / "web" / "app.js"
    source = app_js.read_text(encoding="utf-8")
    wizard_start = source.index("async function renderAddRouter")
    wizard_section = source[wizard_start : wizard_start + 14000]
    assert "localStorage.setItem" not in wizard_section
    assert "localStorage.getItem" not in wizard_section
    assert "sessionStorage" not in wizard_section
    assert "location.search" not in wizard_section
    assert "secretEl.value = \"\"" in wizard_section
    assert 'name="secret"' not in wizard_section
    assert "management_password" not in wizard_section.lower()
    submit_block = wizard_section.split('form.addEventListener("submit"')[1].split("});")[0]
    assert "ev.preventDefault()" in submit_block
    assert "ensureWizardDraft" in submit_block
    draft_fn = source.split("function buildWizardDraftFormSurface")[1].split(
        "function readWizardHostKeyConfirmPayloadFromDom"
    )[0]
    secret_field = draft_fn.split('fieldTooltipOpts("wizard_draft", "secret"')[1].split(");")[0]
    assert "omitName: true" in secret_field
    assert "name:" not in secret_field and 'name="' not in secret_field


def test_uplink_password_field_not_in_url_or_storage() -> None:
    """Static checks on uplink credential enroll path (not runtime DOM)."""
    app_js = Path(__file__).resolve().parents[1] / "router_control_host" / "web" / "app.js"
    source = app_js.read_text(encoding="utf-8")
    uplink_start = source.index("async function renderUplink")
    uplink_section = source[uplink_start : uplink_start + 22000]
    assert "localStorage.setItem" not in uplink_section
    assert "sessionStorage" not in uplink_section
    assert "location.search" not in uplink_section
    assert 'name="enroll_value"' not in uplink_section
    assert "uplink-enroll-value" in uplink_section
    cred_block = uplink_section.split("uplink-credential-form")[1].split("uplink-preview")[0]
    assert "credForm.addEventListener(\"submit\"" in cred_block
    assert "ev.preventDefault()" in cred_block
    assert "omitName: true" in cred_block
    assert 'valueEl.value = ""' in cred_block
    enroll_split = uplink_section.split('appendFormField(credForm, "enroll_value"')[1]
    enroll_field = enroll_split.split(");")[0]
    assert "name:" not in enroll_field and 'name="' not in enroll_field


def _associated_readback(*, ssid: str) -> dict[str, Any]:
    return {
        "configured_ssid": ssid,
        "configured_encryption": "wpa2",
        "associated_ssid": ssid,
        "associated_ssid_field_present": True,
        "associated_encryption": "wpa2",
        "state": "up",
        "associated_network": "present",
    }


class _UiSecFakeStationLiveTransport:
    wifi_station_live_dispatch = True
    wifi_station_offline_only = False  # type: ignore[misc, assignment]

    def __init__(self, *, readback: dict[str, Any]) -> None:
        self.readback = readback
        self.write_commands: list[str] = []
        self.parse_commands: list[str] = []
        self.sleep_calls: list[float] = []

    def execute_sealed_rci_write(self, request: Any) -> Any:
        from router_control.adapters.netcraze.transport import SealedRciWriteRequest

        assert isinstance(request, SealedRciWriteRequest)
        body = json.loads(request.body.decode("utf-8"))
        self.write_commands.append(str(body[0]["parse"]))
        text = request.body.decode("utf-8", errors="replace").lower()
        if " ip global " in text:
            return [
                {
                    "parse": {
                        "prompt": "(config)",
                        "status": [
                            {
                                "status": "message",
                                "code": "72744991",
                                "ident": "Network::Interface::L3Base",
                                "message": '"WifiMaster0/WifiStation0": global priority is 100.',
                            }
                        ],
                    }
                }
            ]
        message = "synthetic ack"
        for fragment, ack_message in (
            (" no authentication wpa-psk", "WPA PSK removed."),
            (" no encryption wpa2", "WPA2 algorithms disabled."),
            (" no encryption enable", "wireless encryption disabled."),
            (" no ssid", "SSID reset."),
            (" ssid ", "SSID saved."),
            (" encryption enable", "wireless encryption enabled."),
            (" encryption wpa2", "WPA2 algorithms enabled."),
            (" authentication wpa-psk", "WPA PSK set."),
            (" ip address dhcp", "Started DHCP client on station."),
            (" up", "interface is up."),
            (" down", "interface is down."),
        ):
            if fragment in text:
                message = ack_message
                break
        return [
            {
                "parse": {
                    "prompt": "(config)",
                    "status": [
                        {
                            "status": "message",
                            "code": "8979152",
                            "ident": "Network::Interface",
                            "message": message,
                        }
                    ],
                }
            }
        ]

    def execute_rci_parse(self, cli_command: str) -> Any:
        self.parse_commands.append(cli_command)
        if cli_command.startswith("show rc interface"):
            return {"ssid": self.readback.get("configured_ssid", ""), "encryption": "wpa2"}
        if cli_command.startswith("show interface"):
            return {
                "ssid": self.readback.get("associated_ssid", ""),
                "encryption": "wpa2",
                "state": self.readback.get("state", "up"),
            }
        if cli_command == "show internet status":
            return {"internet": "yes", "gateway": "yes", "dns": "yes"}
        raise AssertionError(f"unexpected parse command: {cli_command}")


def test_wifi_station_apply_to_dict_redacts_upstream_ssid() -> None:
    from router_control.application.wifi_station_apply_service import WifiStationApplyResult

    result = WifiStationApplyResult(
        overall="applied",
        station_id="WifiMaster0/WifiStation0",
        verification_status="device_accepted_grammar",
        grammar_verification_status="device_accepted_grammar",
        uplink_verification_status="uplink_verified_bounded",
        steps=(),
        errors=(),
        logs=(),
        uplink_readback=_associated_readback(ssid=_UPSTREAM_SSID_MARKER),
    )
    serialized = json.dumps(result.to_dict())
    assert _UPSTREAM_SSID_MARKER not in serialized
    assert "REDACTED" in serialized


def test_wifi_station_apply_http_response_no_upstream_ssid_leak(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Full apply→HTTP path: upstream SSID marker must not appear anywhere in response."""
    from router_control.adapters.netcraze.certification import GateACertification
    from router_control.adapters.netcraze.startup_backup import StartupBackupMetadata
    from router_control_host.wifi_live_transport import WifiLiveSession

    _VALID_SSH_HOST_KEY_SHA256 = "SHA256:" + "a" * 43
    _FINGERPRINT_DIGEST = "sha256:" + "b" * 64
    _COMPONENT_DIGEST = "sha256:" + "d" * 64
    now = datetime.now(UTC)

    gate_a = GateACertification(
        status="open",
        certification="ReadOnlyCertified",
        approved_scope="SLICE-4-readonly",
        model="NC-1812",
        model_display="Ultra (NC-1812)",
        firmware_version="5.01.C.1.0-0",
        firmware_display="5.1.1",
        ndm_build="0-b592e619a0",
        bsp_build="0-f371d30955",
        update_channel="Main",
        region="EA",
        component_set_digest=_COMPONENT_DIGEST,
        device_fingerprint_digest=_FINGERPRINT_DIGEST,
        physical_id_source="show.identification_digest",
        transport="ssh_tunnel",
        ssh_host_key_algorithm="ssh-ed25519",
        ssh_host_key_fingerprint_sha256=_VALID_SSH_HOST_KEY_SHA256,
        certification_eligible=True,
        evidence_recorded_at=now,
        evidence_path="data/artifacts/gate-a-probe.json",
        expires_at=now + timedelta(days=90),
        revocation_policy="human",
        gates_b_closed=True,
        gates_c_closed=True,
        gates_d_closed=True,
    )

    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    monkeypatch.setattr(
        "router_control_host.wifi_station_apply_routes.is_win32_live_capable",
        lambda: True,
    )
    app = create_app(db_path=tmp_path / "ui-ssid-leak.sqlite3", allow_fake_mutations=True)
    app.state.host.gate_a_certification = gate_a
    session_transport = _UiSecFakeStationLiveTransport(
        readback=_associated_readback(ssid=_UPSTREAM_SSID_MARKER),
    )

    @contextmanager
    def _mock_live(**_kwargs: object):
        tunnel = MagicMock()
        yield WifiLiveSession(transport=session_transport, tunnel=tunnel)

    def _mock_backup(**_kwargs: object) -> StartupBackupMetadata:
        return StartupBackupMetadata(
            artifact_type="startup_config_backup",
            endpoint="/ci/startup-config.txt",
            content_sha256="deadbeef" * 8,
            size_bytes=128,
            encrypted_locator="data/backups/startup-test.enc",
            metadata_locator="data/backups/startup-test.meta.json",
            recorded_at=now.isoformat(),
            transport_security="ssh_tunnel_pinned",
            host="192.168.2.1",
            device_fingerprint_digest=_FINGERPRINT_DIGEST,
            ssh_host_key_fingerprint_sha256=_VALID_SSH_HOST_KEY_SHA256,
            ssh_host_key_algorithm="ssh-ed25519",
        )

    monkeypatch.setattr(
        "router_control_host.wifi_station_apply_routes.open_wifi_live_session",
        _mock_live,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_station_apply_routes.backup_startup_config",
        _mock_backup,
    )
    app.state.host.wifi_station_apply_credential_resolver = (
        lambda _ref: _OFFLINE_PSK_PLACEHOLDER
    )

    from fastapi.testclient import TestClient

    payload = {
        "mode": "WifiWan",
        "ssid": "Venue-Guest",
        "band": "BAND_2_4GHZ",
        "credential_ref_id": "credref:venue-wifi",
        "priority": 40,
        "confirm_live_apply": True,
        "host": "192.168.2.1",
        "username": "admin",
        "router_credential_ref_id": "credref:router-admin",
        "ssh_host_key_sha256": _VALID_SSH_HOST_KEY_SHA256,
        "source_address": "192.168.2.10",
        "uplink_settle_seconds": 25,
    }
    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        resp = client.post("/api/router-control/v1/wifi/station/apply", json=payload)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body.get("overall") in {"applied", "verify_mismatch"}, body
    body_blob = json.dumps(body)
    assert _UPSTREAM_SSID_MARKER not in body_blob
    assert _OFFLINE_PSK_PLACEHOLDER not in body_blob
    readback = body.get("uplink_readback")
    assert readback is not None, body
    assert readback.get("configured_ssid") == "REDACTED"
    assert readback.get("associated_ssid") == "REDACTED"
