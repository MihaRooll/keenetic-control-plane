"""Bootstrap discovery service — findings, sanitization, NC-1812 fixture."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from router_control.adapters.netcraze.allowlist import (
    COMPONENTS_LIST,
    MAX_CONTINUATION_ROUNDS,
    SHOW_IDENTIFICATION,
    SHOW_INTERFACE,
    SHOW_IP_HTTP,
    SHOW_IP_SSH,
    SHOW_SYSTEM,
    SHOW_VERSION,
)
from router_control.adapters.netcraze.transport import HttpExchange, TransportError
from router_control.adapters.secrets.memory import MemoryVault
from router_control.application.bootstrap_discovery import (
    FINDING_COMPONENT_CHANGE_TRIGGERS_FIRMWARE_UPGRADE,
    FINDING_COMPONENTS_INVENTORY_UNAVAILABLE,
    FINDING_COMPONENTS_LISTING_TIMEOUT,
    FINDING_FIRMWARE_BELOW_BASELINE,
    FINDING_FIRMWARE_MAJOR_VERSION_JUMP,
    FINDING_SSH_COMPONENT_MISSING,
    FINDING_SSH_DISABLED,
    FINDING_SSH_STATE_UNKNOWN,
    FINDING_UPDATE_CHANNEL_NOT_STABLE,
    FINDING_UPDATE_CHANNEL_UNKNOWN,
    FINDING_WIFI_INVENTORY_UNAVAILABLE,
    VERIFIED_FIRMWARE_BASELINE,
    BootstrapDiscoveryError,
    _build_components_inventory,
    _derive_ssh_component_determination,
    _parse_management_http_summary,
    _parse_ssh_access_enabled,
    _resolve_ssh_component_state,
    _ssh_component_installed,
    run_bootstrap_discovery,
)

_SECRET_SENTINELS = (
    "password",
    "private_key",
    "preshared",
    "serial",
    "mac",
    "ssid",
    "startup-config",
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "netcraze"


def _load(name: str) -> object:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@dataclass
class MockHttpClient:
    responses: list[HttpExchange] = field(default_factory=list)
    calls: list[tuple[str, str]] = field(default_factory=list)

    def request(
        self,
        *,
        host: str,
        port: int,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes | None,
        connect_timeout: float,
        read_timeout: float,
        ssl_context: object | None,
    ) -> HttpExchange:
        self.calls.append((method, path))
        if not self.responses:
            raise TransportError("no mock responses left")
        return self.responses.pop(0)

    def request_limited(
        self,
        *,
        host: str,
        port: int,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes | None,
        connect_timeout: float,
        read_timeout: float,
        ssl_context: object | None,
        max_bytes: int,
    ) -> HttpExchange:
        return self.request(
            host=host,
            port=port,
            method=method,
            path=path,
            headers=headers,
            body=body,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
            ssl_context=ssl_context,
        )


def _json_exchange(payload: object) -> HttpExchange:
    return HttpExchange(
        status=200,
        headers={"content-type": "application/json"},
        body=json.dumps(payload).encode("utf-8"),
    )


def _not_found_exchange() -> HttpExchange:
    return HttpExchange(status=404, headers={}, body=b"")


def _bootstrap_client(*, ssh_present: bool = False) -> MockHttpClient:
    ssh_response = (
        _json_exchange(_load("bootstrap_nc1812_ip_ssh.json"))
        if ssh_present
        else _not_found_exchange()
    )
    return MockHttpClient(
        responses=[
            _json_exchange(_load("bootstrap_nc1812_system.json")),
            _json_exchange(_load("bootstrap_nc1812_components.json")),
            _json_exchange(_load("bootstrap_nc1812_identification.json")),
            _json_exchange(_load("bootstrap_nc1812_version.json")),
            _json_exchange(_load("bootstrap_nc1812_interface.json")),
            ssh_response,
            _json_exchange(_load("bootstrap_nc1812_ip_http.json")),
        ]
    )


@pytest.fixture
def expendable_lab(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")


def test_nc1812_fixture_findings_and_identity(expendable_lab: None) -> None:
    vault = MemoryVault()
    handle = vault.create(kind="RouterManagementPassword", secret="lab-password")
    report = run_bootstrap_discovery(
        host="http://192.168.2.1",
        username="admin",
        credential_ref_id=handle.credential_ref_id,
        vault=vault,
        allow_insecure_http=True,
        http_client=_bootstrap_client(),
    )
    assert report["certification_eligible"] is False
    assert report["transport_security"] == "insecure_http"
    assert report["https_check"] == "not_certified"
    assert report["model"] == "NC-1812"
    assert report["firmware_version"] == "4.03.C.6.4-16"
    assert set(report["findings"]) == {
        FINDING_FIRMWARE_BELOW_BASELINE,
        FINDING_SSH_COMPONENT_MISSING,
    }
    assert FINDING_SSH_DISABLED not in report["findings"]
    assert FINDING_SSH_STATE_UNKNOWN not in report["findings"]
    assert FINDING_WIFI_INVENTORY_UNAVAILABLE not in report["findings"]
    assert len(report["wifi_access_points"]) == 14
    link_up_count = sum(1 for ap in report["wifi_access_points"] if ap.get("link_up") is True)
    assert link_up_count == 2
    assert all(ap.get("connected") is True for ap in report["wifi_access_points"])
    assert report["management_http"] == {"security_level": "private"}
    assert report["ssh_component_installed"] is False
    assert report["ssh_access_enabled"] is None
    assert report["sandbox"] == "stable"
    assert report["update_channel"] == "Main"
    assert report["channel_firmware_version"] == "4.03.C.6.4-16"
    assert report["component_change_would_upgrade_firmware"] is False
    assert report["component_change_crosses_major_version"] is False
    assert report["update_channel_is_stable"] is True
    assert report["component_change_side_effects"] == {
        "firmware_rebuild": True,
        "automatic_reboot": True,
        "management_downtime": True,
        "firmware_version_changes": False,
    }
    assert FINDING_UPDATE_CHANNEL_UNKNOWN not in report["findings"]
    assert FINDING_UPDATE_CHANNEL_NOT_STABLE not in report["findings"]
    inventory = report["components_inventory"]
    assert inventory["source_shape"] == "component_map"
    assert inventory["total_observed"] == 3
    assert inventory["truncated"] is False
    assert len(inventory["entries"]) == 3
    entry_ids = {e["id"] for e in inventory["entries"]}
    assert entry_ids == {"cloudcontrol", "ndm", "webui"}
    for entry in inventory["entries"]:
        assert set(entry.keys()) <= {"id", "installed", "version", "available"}
    assert report["ssh_component_determination"] == {
        "lookup": "component.ssh",
        "matched": False,
        "outcome": "key_absent",
    }
    assert FINDING_COMPONENTS_INVENTORY_UNAVAILABLE not in report["findings"]


def test_ssh_component_installed_false_when_installed_flag_false() -> None:
    components = {"component": {"ssh": {"installed": False}}}
    assert _ssh_component_installed(components) is False


def test_ssh_public_security_level_means_enabled() -> None:
    assert _parse_ssh_access_enabled({"security-level": "public"}) is True
    assert _parse_ssh_access_enabled({"security-level": "private"}) is True
    assert _parse_ssh_access_enabled({"security-level": "disabled"}) is False
    assert _parse_ssh_access_enabled({}) is False


def test_ssh_installed_public_does_not_emit_ssh_disabled(expendable_lab: None) -> None:
    components = _load("bootstrap_nc1812_components.json")
    assert isinstance(components, dict)
    component_map = dict(components["component"])
    component_map["ssh"] = {"installed": True}
    components = {**components, "component": component_map}
    client = MockHttpClient(
        responses=[
            _json_exchange(_load("bootstrap_nc1812_system.json")),
            _json_exchange(components),
            _json_exchange(_load("bootstrap_nc1812_identification.json")),
            _json_exchange(_load("bootstrap_nc1812_version.json")),
            _json_exchange(_load("bootstrap_nc1812_interface.json")),
            _json_exchange({"security-level": "public", "port": 22}),
            _json_exchange(_load("bootstrap_nc1812_ip_http.json")),
        ]
    )
    vault = MemoryVault()
    handle = vault.create(kind="RouterManagementPassword", secret="lab-password")
    report = run_bootstrap_discovery(
        host="http://192.168.2.1",
        username="admin",
        credential_ref_id=handle.credential_ref_id,
        vault=vault,
        allow_insecure_http=True,
        http_client=client,
    )
    assert report["ssh_component_installed"] is True
    assert report["ssh_access_enabled"] is True
    assert FINDING_SSH_DISABLED not in report["findings"]
    assert FINDING_SSH_COMPONENT_MISSING not in report["findings"]
    ssh_entry = next(
        e for e in report["components_inventory"]["entries"] if e["id"] == "ssh"
    )
    assert ssh_entry["installed"] is True
    assert report["ssh_component_determination"]["outcome"] == "matched_true"
    assert report["ssh_component_determination"]["matched"] is True
    assert report["ssh_component_determination"]["determination_shape"] == "explicit_installed"


def test_ssh_installed_false_emits_component_missing(expendable_lab: None) -> None:
    components = _load("bootstrap_nc1812_components.json")
    assert isinstance(components, dict)
    component_map = dict(components["component"])
    component_map["ssh"] = {"installed": False}
    components = {**components, "component": component_map}
    client = MockHttpClient(
        responses=[
            _json_exchange(_load("bootstrap_nc1812_system.json")),
            _json_exchange(components),
            _json_exchange(_load("bootstrap_nc1812_identification.json")),
            _json_exchange(_load("bootstrap_nc1812_version.json")),
            _json_exchange(_load("bootstrap_nc1812_interface.json")),
            _json_exchange({}),
            _json_exchange(_load("bootstrap_nc1812_ip_http.json")),
        ]
    )
    vault = MemoryVault()
    handle = vault.create(kind="RouterManagementPassword", secret="lab-password")
    report = run_bootstrap_discovery(
        host="http://192.168.2.1",
        username="admin",
        credential_ref_id=handle.credential_ref_id,
        vault=vault,
        allow_insecure_http=True,
        http_client=client,
    )
    assert report["ssh_component_installed"] is False
    assert FINDING_SSH_COMPONENT_MISSING in report["findings"]


def test_serialized_output_has_no_secret_lexicon(expendable_lab: None) -> None:
    vault = MemoryVault()
    handle = vault.create(kind="RouterManagementPassword", secret="super-secret-lab-password")
    report = run_bootstrap_discovery(
        host="http://192.168.2.1",
        username="admin",
        credential_ref_id=handle.credential_ref_id,
        vault=vault,
        allow_insecure_http=True,
        http_client=_bootstrap_client(),
    )
    serialized = json.dumps(report)
    for token in _SECRET_SENTINELS:
        assert token not in serialized.lower()
    assert "super-secret-lab-password" not in serialized
    assert "SYNTH-SERIAL" not in serialized
    assert "SYNTH-SERVICE" not in serialized
    assert "SENTINEL-SSID" not in serialized
    assert "DE:AD:BE:EF" not in serialized


def test_wifi_access_points_use_hashed_ids(expendable_lab: None) -> None:
    vault = MemoryVault()
    handle = vault.create(kind="RouterManagementPassword", secret="lab-password")
    report = run_bootstrap_discovery(
        host="http://192.168.2.1",
        username="admin",
        credential_ref_id=handle.credential_ref_id,
        vault=vault,
        allow_insecure_http=True,
        http_client=_bootstrap_client(),
    )
    for ap in report["wifi_access_points"]:
        assert "interface_id_hash" in ap
        assert ap["interface_id_hash"].startswith("sha256:")
        assert "ssid" not in ap
        assert "mac" not in ap


def test_policy_refuses_without_expendable_lab(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ROUTER_CONTROL_LAB_CLASS", raising=False)
    vault = MemoryVault()
    handle = vault.create(kind="RouterManagementPassword", secret="lab-password")
    with pytest.raises(BootstrapDiscoveryError, match="expendable lab class"):
        run_bootstrap_discovery(
            host="http://192.168.2.1",
            username="admin",
            credential_ref_id=handle.credential_ref_id,
            vault=vault,
            allow_insecure_http=True,
            http_client=_bootstrap_client(),
        )


def test_policy_refuses_non_private_host(expendable_lab: None) -> None:
    vault = MemoryVault()
    handle = vault.create(kind="RouterManagementPassword", secret="lab-password")
    with pytest.raises(BootstrapDiscoveryError, match="private management host"):
        run_bootstrap_discovery(
            host="http://8.8.8.8",
            username="admin",
            credential_ref_id=handle.credential_ref_id,
            vault=vault,
            allow_insecure_http=True,
            http_client=_bootstrap_client(),
        )


def test_verified_baseline_constant_matches_gate_a_ssot() -> None:
    assert VERIFIED_FIRMWARE_BASELINE == "5.01.C.1.0-0"


def test_bootstrap_fetch_sequence_is_fixed(expendable_lab: None) -> None:
    client = _bootstrap_client()
    vault = MemoryVault()
    handle = vault.create(kind="RouterManagementPassword", secret="lab-password")
    run_bootstrap_discovery(
        host="http://192.168.2.1",
        username="admin",
        credential_ref_id=handle.credential_ref_id,
        vault=vault,
        allow_insecure_http=True,
        http_client=client,
    )
    assert client.calls == [
        (SHOW_SYSTEM.method, SHOW_SYSTEM.path),
        (COMPONENTS_LIST.method, COMPONENTS_LIST.path),
        (SHOW_IDENTIFICATION.method, SHOW_IDENTIFICATION.path),
        (SHOW_VERSION.method, SHOW_VERSION.path),
        (SHOW_INTERFACE.method, SHOW_INTERFACE.path),
        (SHOW_IP_SSH.method, SHOW_IP_SSH.path),
        (SHOW_IP_HTTP.method, SHOW_IP_HTTP.path),
    ]


def test_ssh_404_degrades_to_finding_not_hard_error(expendable_lab: None) -> None:
    vault = MemoryVault()
    handle = vault.create(kind="RouterManagementPassword", secret="lab-password")
    report = run_bootstrap_discovery(
        host="http://192.168.2.1",
        username="admin",
        credential_ref_id=handle.credential_ref_id,
        vault=vault,
        allow_insecure_http=True,
        http_client=_bootstrap_client(),
    )
    assert FINDING_SSH_COMPONENT_MISSING in report["findings"]
    assert report["ssh_access_enabled"] is None


def test_http_404_degrades_without_extra_finding(expendable_lab: None) -> None:
    client = MockHttpClient(
        responses=[
            _json_exchange(_load("bootstrap_nc1812_system.json")),
            _json_exchange(_load("bootstrap_nc1812_components.json")),
            _json_exchange(_load("bootstrap_nc1812_identification.json")),
            _json_exchange(_load("bootstrap_nc1812_version.json")),
            _json_exchange(_load("bootstrap_nc1812_interface.json")),
            _not_found_exchange(),
            _not_found_exchange(),
        ]
    )
    vault = MemoryVault()
    handle = vault.create(kind="RouterManagementPassword", secret="lab-password")
    report = run_bootstrap_discovery(
        host="http://192.168.2.1",
        username="admin",
        credential_ref_id=handle.credential_ref_id,
        vault=vault,
        allow_insecure_http=True,
        http_client=client,
    )
    assert FINDING_SSH_COMPONENT_MISSING in report["findings"]
    assert "management_http" not in report
    assert len(report["findings"]) == 2


def test_auth_failure_on_optional_read_is_hard_error(expendable_lab: None) -> None:
    challenge = 'Digest realm="x", nonce="abc123", qop="auth"'
    client = MockHttpClient(
        responses=[
            _json_exchange(_load("bootstrap_nc1812_system.json")),
            _json_exchange(_load("bootstrap_nc1812_components.json")),
            _json_exchange(_load("bootstrap_nc1812_identification.json")),
            _json_exchange(_load("bootstrap_nc1812_version.json")),
            _json_exchange(_load("bootstrap_nc1812_interface.json")),
            HttpExchange(status=401, headers={"www-authenticate": challenge}, body=b""),
            HttpExchange(status=401, headers={}, body=b""),
        ]
    )
    vault = MemoryVault()
    handle = vault.create(kind="RouterManagementPassword", secret="lab-password")
    with pytest.raises(BootstrapDiscoveryError, match="authentication failed"):
        run_bootstrap_discovery(
            host="http://192.168.2.1",
            username="admin",
            credential_ref_id=handle.credential_ref_id,
            vault=vault,
            allow_insecure_http=True,
            http_client=client,
        )


def test_transport_failure_on_required_read_is_hard_error(expendable_lab: None) -> None:
    client = MockHttpClient(
        responses=[
            HttpExchange(status=500, headers={}, body=b"internal error"),
        ]
    )
    vault = MemoryVault()
    handle = vault.create(kind="RouterManagementPassword", secret="lab-password")
    with pytest.raises(BootstrapDiscoveryError, match="HTTP 500"):
        run_bootstrap_discovery(
            host="http://192.168.2.1",
            username="admin",
            credential_ref_id=handle.credential_ref_id,
            vault=vault,
            allow_insecure_http=True,
            http_client=client,
        )


def test_parse_management_http_nested_shape() -> None:
    nested = _load("bootstrap_nc1812_ip_http.json")
    assert _parse_management_http_summary(nested) == {"security_level": "private"}


def test_parse_management_http_flat_shape() -> None:
    flat = _load("bootstrap_nc1812_ip_http_flat.json")
    assert _parse_management_http_summary(flat) == {
        "port": 80,
        "security_level": "private",
        "listen": True,
    }


def test_parse_management_http_garbage_degrades() -> None:
    assert _parse_management_http_summary("not-a-dict") is None
    assert _parse_management_http_summary({"security-level": {"garbage": 1}}) is None
    assert _parse_management_http_summary({"port": "not-int"}) is None


def test_parse_management_http_nested_non_true_marker_does_not_invent_level() -> None:
    assert _parse_management_http_summary({"security-level": {"private": None}}) is None
    assert _parse_management_http_summary({"security-level": {"private": 1}}) is None
    assert _parse_management_http_summary({"security-level": {"private": {}}}) is None


def test_transport_timeout_maps_to_bootstrap_discovery_error(expendable_lab: None) -> None:
    from router_control.adapters.netcraze.errors import TransportTimeout

    class TimeoutClient:
        def request(self, **_kwargs: object) -> HttpExchange:
            raise TransportTimeout("read timeout")

        def request_limited(self, **_kwargs: object) -> HttpExchange:
            raise TransportTimeout("read timeout")

    vault = MemoryVault()
    handle = vault.create(kind="RouterManagementPassword", secret="lab-password")
    with pytest.raises(BootstrapDiscoveryError, match="read timeout"):
        run_bootstrap_discovery(
            host="http://192.168.2.1",
            username="admin",
            credential_ref_id=handle.credential_ref_id,
            vault=vault,
            allow_insecure_http=True,
            http_client=TimeoutClient(),
        )


def test_credential_resolution_error_names_ref(expendable_lab: None) -> None:
    vault = MemoryVault()
    with pytest.raises(
        BootstrapDiscoveryError,
        match="credential resolution failed for credential_ref_id=cred_missing",
    ):
        run_bootstrap_discovery(
            host="http://192.168.2.1",
            username="admin",
            credential_ref_id="cred_missing",
            vault=vault,
            allow_insecure_http=True,
            http_client=_bootstrap_client(),
        )


def test_ssh_present_branch_no_component_missing(expendable_lab: None) -> None:
    components = _load("bootstrap_nc1812_components.json")
    assert isinstance(components, dict)
    component_map = dict(components["component"])
    component_map["ssh"] = {"installed": True}
    components = {**components, "component": component_map}
    client = MockHttpClient(
        responses=[
            _json_exchange(_load("bootstrap_nc1812_system.json")),
            _json_exchange(components),
            _json_exchange(_load("bootstrap_nc1812_identification.json")),
            _json_exchange(_load("bootstrap_nc1812_version.json")),
            _json_exchange(_load("bootstrap_nc1812_interface.json")),
            _json_exchange(_load("bootstrap_nc1812_ip_ssh.json")),
            _json_exchange(_load("bootstrap_nc1812_ip_http.json")),
        ]
    )
    vault = MemoryVault()
    handle = vault.create(kind="RouterManagementPassword", secret="lab-password")
    report = run_bootstrap_discovery(
        host="http://192.168.2.1",
        username="admin",
        credential_ref_id=handle.credential_ref_id,
        vault=vault,
        allow_insecure_http=True,
        http_client=client,
    )
    assert FINDING_SSH_COMPONENT_MISSING not in report["findings"]
    assert report["ssh_component_installed"] is True
    assert report["ssh_access_enabled"] is True


def _components_with_channel(
    *,
    sandbox: str | None = "stable",
    channel_firmware: str = "4.03.C.6.4-16",
) -> dict[str, object]:
    base = _load("bootstrap_nc1812_components.json")
    assert isinstance(base, dict)
    payload = dict(base)
    if sandbox is None:
        payload.pop("sandbox", None)
    else:
        payload["sandbox"] = sandbox
    firmware = dict(payload["firmware"])
    firmware["version"] = channel_firmware
    payload["firmware"] = firmware
    return payload


def test_stable_same_major_newer_triggers_upgrade_without_major_jump(
    expendable_lab: None,
) -> None:
    components = _components_with_channel(channel_firmware="4.03.C.7.0-0")
    client = MockHttpClient(
        responses=[
            _json_exchange(_load("bootstrap_nc1812_system.json")),
            _json_exchange(components),
            _json_exchange(_load("bootstrap_nc1812_identification.json")),
            _json_exchange(_load("bootstrap_nc1812_version.json")),
            _json_exchange(_load("bootstrap_nc1812_interface.json")),
            _not_found_exchange(),
            _json_exchange(_load("bootstrap_nc1812_ip_http.json")),
        ]
    )
    vault = MemoryVault()
    handle = vault.create(kind="RouterManagementPassword", secret="lab-password")
    report = run_bootstrap_discovery(
        host="http://192.168.2.1",
        username="admin",
        credential_ref_id=handle.credential_ref_id,
        vault=vault,
        allow_insecure_http=True,
        http_client=client,
    )
    assert report["component_change_would_upgrade_firmware"] is True
    assert report["component_change_crosses_major_version"] is False
    assert report["component_change_side_effects"]["firmware_version_changes"] is True
    assert FINDING_COMPONENT_CHANGE_TRIGGERS_FIRMWARE_UPGRADE in report["findings"]
    assert FINDING_FIRMWARE_MAJOR_VERSION_JUMP not in report["findings"]


def test_channel_major_jump_finding(expendable_lab: None) -> None:
    components = _components_with_channel(channel_firmware="5.01.C.1.0-0")
    client = MockHttpClient(
        responses=[
            _json_exchange(_load("bootstrap_nc1812_system.json")),
            _json_exchange(components),
            _json_exchange(_load("bootstrap_nc1812_identification.json")),
            _json_exchange(_load("bootstrap_nc1812_version.json")),
            _json_exchange(_load("bootstrap_nc1812_interface.json")),
            _not_found_exchange(),
            _json_exchange(_load("bootstrap_nc1812_ip_http.json")),
        ]
    )
    vault = MemoryVault()
    handle = vault.create(kind="RouterManagementPassword", secret="lab-password")
    report = run_bootstrap_discovery(
        host="http://192.168.2.1",
        username="admin",
        credential_ref_id=handle.credential_ref_id,
        vault=vault,
        allow_insecure_http=True,
        http_client=client,
    )
    assert report["component_change_would_upgrade_firmware"] is True
    assert report["component_change_crosses_major_version"] is True
    assert report["component_change_side_effects"]["firmware_version_changes"] is True
    assert FINDING_FIRMWARE_MAJOR_VERSION_JUMP in report["findings"]


def test_preview_sandbox_not_stable(expendable_lab: None) -> None:
    components = _components_with_channel(sandbox="preview")
    client = MockHttpClient(
        responses=[
            _json_exchange(_load("bootstrap_nc1812_system.json")),
            _json_exchange(components),
            _json_exchange(_load("bootstrap_nc1812_identification.json")),
            _json_exchange(_load("bootstrap_nc1812_version.json")),
            _json_exchange(_load("bootstrap_nc1812_interface.json")),
            _not_found_exchange(),
            _json_exchange(_load("bootstrap_nc1812_ip_http.json")),
        ]
    )
    vault = MemoryVault()
    handle = vault.create(kind="RouterManagementPassword", secret="lab-password")
    report = run_bootstrap_discovery(
        host="http://192.168.2.1",
        username="admin",
        credential_ref_id=handle.credential_ref_id,
        vault=vault,
        allow_insecure_http=True,
        http_client=client,
    )
    assert report["update_channel"] == "preview"
    assert report["update_channel_is_stable"] is False
    assert FINDING_UPDATE_CHANNEL_NOT_STABLE in report["findings"]


def test_missing_sandbox_unknown_channel(expendable_lab: None) -> None:
    components = _components_with_channel(sandbox=None)
    client = MockHttpClient(
        responses=[
            _json_exchange(_load("bootstrap_nc1812_system.json")),
            _json_exchange(components),
            _json_exchange(_load("bootstrap_nc1812_identification.json")),
            _json_exchange(_load("bootstrap_nc1812_version.json")),
            _json_exchange(_load("bootstrap_nc1812_interface.json")),
            _not_found_exchange(),
            _json_exchange(_load("bootstrap_nc1812_ip_http.json")),
        ]
    )
    vault = MemoryVault()
    handle = vault.create(kind="RouterManagementPassword", secret="lab-password")
    report = run_bootstrap_discovery(
        host="http://192.168.2.1",
        username="admin",
        credential_ref_id=handle.credential_ref_id,
        vault=vault,
        allow_insecure_http=True,
        http_client=client,
    )
    assert "sandbox" not in report
    assert "update_channel" not in report
    assert "channel_firmware_version" not in report
    assert FINDING_UPDATE_CHANNEL_UNKNOWN in report["findings"]
    assert report["component_change_side_effects"]["firmware_version_changes"] is None


def test_components_without_firmware_version_does_not_fabricate_target(
    expendable_lab: None,
) -> None:
    components = _components_with_channel(sandbox="stable")
    assert isinstance(components, dict)
    firmware = dict(components["firmware"])
    firmware.pop("version", None)
    components = {**components, "firmware": firmware}
    client = MockHttpClient(
        responses=[
            _json_exchange(_load("bootstrap_nc1812_system.json")),
            _json_exchange(components),
            _json_exchange(_load("bootstrap_nc1812_identification.json")),
            _json_exchange(_load("bootstrap_nc1812_version.json")),
            _json_exchange(_load("bootstrap_nc1812_interface.json")),
            _not_found_exchange(),
            _json_exchange(_load("bootstrap_nc1812_ip_http.json")),
        ]
    )
    vault = MemoryVault()
    handle = vault.create(kind="RouterManagementPassword", secret="lab-password")
    with pytest.raises(BootstrapDiscoveryError):
        run_bootstrap_discovery(
            host="http://192.168.2.1",
            username="admin",
            credential_ref_id=handle.credential_ref_id,
            vault=vault,
            allow_insecure_http=True,
            http_client=client,
        )


def test_components_listing_timeout_soft_degrades(expendable_lab: None) -> None:
    continued = _json_exchange({"continued": True})
    client = MockHttpClient(
        responses=[
            _json_exchange(_load("bootstrap_nc1812_system.json")),
            *([continued] * (1 + MAX_CONTINUATION_ROUNDS)),
            _json_exchange(_load("bootstrap_nc1812_identification.json")),
            _json_exchange(_load("bootstrap_nc1812_version.json")),
            _json_exchange(_load("bootstrap_nc1812_interface.json")),
            _json_exchange(_load("bootstrap_nc1812_ip_ssh.json")),
            _json_exchange(_load("bootstrap_nc1812_ip_http.json")),
        ]
    )
    vault = MemoryVault()
    handle = vault.create(kind="RouterManagementPassword", secret="lab-password")
    report = run_bootstrap_discovery(
        host="http://192.168.2.1",
        username="admin",
        credential_ref_id=handle.credential_ref_id,
        vault=vault,
        allow_insecure_http=True,
        http_client=client,
    )
    assert report["model"] == "NC-1812"
    assert report["firmware_version"] == "4.03.C.6.4-16"
    assert FINDING_COMPONENTS_LISTING_TIMEOUT in report["findings"]
    assert FINDING_COMPONENTS_INVENTORY_UNAVAILABLE in report["findings"]
    assert FINDING_SSH_COMPONENT_MISSING not in report["findings"]
    assert FINDING_SSH_STATE_UNKNOWN in report["findings"]
    assert report["ssh_component_installed"] is None
    assert report["ssh_access_enabled"] is True
    assert report["components_inventory"]["source_shape"] == "unavailable"
    assert report["ssh_component_determination"]["outcome"] == "inventory_unavailable"
    assert "channel_firmware_version" not in report
    assert "update_channel" not in report
    components_calls = [
        call for call in client.calls if call[1] == "/rci/components/list"
    ]
    assert components_calls[0] == ("POST", "/rci/components/list")
    assert len([c for c in components_calls if c[0] == "GET"]) <= MAX_CONTINUATION_ROUNDS


def test_major_jump_without_upgrade_when_channel_older(expendable_lab: None) -> None:
    version = dict(_load("bootstrap_nc1812_version.json"))
    version["version"] = "5.01.C.1.0-0"
    version["release"] = "5.01.C.1.0-0"
    components = _components_with_channel(channel_firmware="4.03.C.6.4-16")
    client = MockHttpClient(
        responses=[
            _json_exchange(_load("bootstrap_nc1812_system.json")),
            _json_exchange(components),
            _json_exchange(_load("bootstrap_nc1812_identification.json")),
            _json_exchange(version),
            _json_exchange(_load("bootstrap_nc1812_interface.json")),
            _not_found_exchange(),
            _json_exchange(_load("bootstrap_nc1812_ip_http.json")),
        ]
    )
    vault = MemoryVault()
    handle = vault.create(kind="RouterManagementPassword", secret="lab-password")
    report = run_bootstrap_discovery(
        host="http://192.168.2.1",
        username="admin",
        credential_ref_id=handle.credential_ref_id,
        vault=vault,
        allow_insecure_http=True,
        http_client=client,
    )
    assert report["component_change_would_upgrade_firmware"] is False
    assert report["component_change_crosses_major_version"] is True
    assert report["component_change_side_effects"]["firmware_version_changes"] is True
    assert FINDING_FIRMWARE_MAJOR_VERSION_JUMP in report["findings"]
    assert FINDING_COMPONENT_CHANGE_TRIGGERS_FIRMWARE_UPGRADE not in report["findings"]


def _bootstrap_client_with_components(components: object) -> MockHttpClient:
    return MockHttpClient(
        responses=[
            _json_exchange(_load("bootstrap_nc1812_system.json")),
            _json_exchange(components),
            _json_exchange(_load("bootstrap_nc1812_identification.json")),
            _json_exchange(_load("bootstrap_nc1812_version.json")),
            _json_exchange(_load("bootstrap_nc1812_interface.json")),
            _not_found_exchange(),
            _json_exchange(_load("bootstrap_nc1812_ip_http.json")),
        ]
    )


def test_nested_unexpected_ssh_key_shape_still_reports_inventory(
    expendable_lab: None,
) -> None:
    components = _load("bootstrap_components_nested_ssh_key.json")
    vault = MemoryVault()
    handle = vault.create(kind="RouterManagementPassword", secret="lab-password")
    report = run_bootstrap_discovery(
        host="http://192.168.2.1",
        username="admin",
        credential_ref_id=handle.credential_ref_id,
        vault=vault,
        allow_insecure_http=True,
        http_client=_bootstrap_client_with_components(components),
    )
    assert report["ssh_component_installed"] is False
    assert report["ssh_component_determination"]["outcome"] == "key_absent"
    assert report["ssh_component_determination"]["matched"] is False
    assert FINDING_SSH_COMPONENT_MISSING in report["findings"]
    assert FINDING_COMPONENTS_INVENTORY_UNAVAILABLE not in report["findings"]
    entry_ids = {e["id"] for e in report["components_inventory"]["entries"]}
    assert entry_ids == {"ndm", "ssh-server"}


def test_oversized_component_map_is_capped(expendable_lab: None) -> None:
    base = _load("bootstrap_nc1812_components.json")
    assert isinstance(base, dict)
    component_map = {f"pkg{i:03d}": {"installed": True} for i in range(70)}
    components = {**base, "component": component_map}
    vault = MemoryVault()
    handle = vault.create(kind="RouterManagementPassword", secret="lab-password")
    report = run_bootstrap_discovery(
        host="http://192.168.2.1",
        username="admin",
        credential_ref_id=handle.credential_ref_id,
        vault=vault,
        allow_insecure_http=True,
        http_client=_bootstrap_client_with_components(components),
    )
    inventory = report["components_inventory"]
    assert inventory["total_observed"] == 70
    assert inventory["truncated"] is True
    assert len(inventory["entries"]) == 64
    assert inventory["source_shape"] == "component_map"


def test_component_inventory_redacts_secret_like_meta(expendable_lab: None) -> None:
    components = _load("bootstrap_components_with_secrets.json")
    vault = MemoryVault()
    handle = vault.create(kind="RouterManagementPassword", secret="lab-password")
    report = run_bootstrap_discovery(
        host="http://192.168.2.1",
        username="admin",
        credential_ref_id=handle.credential_ref_id,
        vault=vault,
        allow_insecure_http=True,
        http_client=_bootstrap_client_with_components(components),
    )
    serialized = json.dumps(report)
    assert "SYNTH-SERIAL" not in serialized
    assert "DE:AD:BE:EF" not in serialized
    assert "SECRET-LICENCE" not in serialized
    assert "AA:BB:CC:DD:EE:FF" not in serialized
    entry_ids = {e["id"] for e in report["components_inventory"]["entries"]}
    assert "AA:BB:CC:DD:EE:FF" not in entry_ids
    ndm = next(e for e in report["components_inventory"]["entries"] if e["id"] == "ndm")
    assert "serial" not in ndm
    assert "mac" not in ndm
    assert "licence" not in ndm


def test_ssh_installed_matched_false_determination(expendable_lab: None) -> None:
    components = _load("bootstrap_nc1812_components.json")
    assert isinstance(components, dict)
    component_map = dict(components["component"])
    component_map["ssh"] = {"installed": False}
    payload = {**components, "component": component_map}
    vault = MemoryVault()
    handle = vault.create(kind="RouterManagementPassword", secret="lab-password")
    report = run_bootstrap_discovery(
        host="http://192.168.2.1",
        username="admin",
        credential_ref_id=handle.credential_ref_id,
        vault=vault,
        allow_insecure_http=True,
        http_client=_bootstrap_client_with_components(payload),
    )
    assert report["ssh_component_installed"] is False
    assert report["ssh_component_determination"] == {
        "lookup": "component.ssh",
        "matched": True,
        "outcome": "matched_false",
        "determination_shape": "explicit_installed",
    }


def test_build_components_inventory_empty_map() -> None:
    inventory = _build_components_inventory({"component": {}}, components_listing_timeout=False)
    assert inventory["source_shape"] == "empty"
    assert inventory["total_observed"] == 0
    determination = _derive_ssh_component_determination(
        {"component": {}},
        components_listing_timeout=False,
        inventory=inventory,
    )
    assert determination["outcome"] == "inventory_unavailable"
    assert determination["outcome"] != "key_absent"


def test_empty_inventory_integration_never_key_absent() -> None:
    raw = {"component": {}}
    inventory = _build_components_inventory(raw, components_listing_timeout=False)
    determination = _derive_ssh_component_determination(
        raw,
        components_listing_timeout=False,
        inventory=inventory,
    )
    installed = _ssh_component_installed(raw, inventory=inventory)
    assert inventory["source_shape"] == "empty"
    assert determination["outcome"] == "inventory_unavailable"
    assert determination["outcome"] != "key_absent"
    assert installed is None


def test_real_device_shape_ssh_installed_via_presence() -> None:
    components = _load("bootstrap_components_real_device_shape.json")
    assert isinstance(components, dict)
    inventory = _build_components_inventory(components, components_listing_timeout=False)
    installed, det = _resolve_ssh_component_state(
        components,
        components_listing_timeout=False,
        inventory=inventory,
    )
    assert installed is True
    assert det["outcome"] == "matched_true"
    assert det["matched"] is True
    assert det["determination_shape"] == "presence_in_map"
    assert det["lookup"] == "component.ssh"
    assert inventory["source_shape"] == "component_map"
    assert inventory["total_observed"] == 39
    assert inventory["truncated"] is False
    ssh_entry = next(e for e in inventory["entries"] if e["id"] == "ssh")
    assert ssh_entry == {"id": "ssh", "version": "2022.82-7"}
    assert "installed" not in ssh_entry


def test_real_device_ssh_shape_e2e_presence_no_missing(expendable_lab: None) -> None:
    base = _load("bootstrap_nc1812_components.json")
    assert isinstance(base, dict)
    component_map = dict(base["component"])
    component_map["ssh"] = {"version": "2022.82-7"}
    components = {**base, "component": component_map}
    vault = MemoryVault()
    handle = vault.create(kind="RouterManagementPassword", secret="lab-password")
    report = run_bootstrap_discovery(
        host="http://192.168.2.1",
        username="admin",
        credential_ref_id=handle.credential_ref_id,
        vault=vault,
        allow_insecure_http=True,
        http_client=_bootstrap_client_with_components(components),
    )
    assert report["ssh_component_installed"] is True
    assert FINDING_SSH_COMPONENT_MISSING not in report["findings"]
    assert FINDING_SSH_STATE_UNKNOWN in report["findings"]
    assert report["ssh_access_enabled"] is None
    det = report["ssh_component_determination"]
    assert det["outcome"] == "matched_true"
    assert det["determination_shape"] == "presence_in_map"
    ssh_entry = next(e for e in report["components_inventory"]["entries"] if e["id"] == "ssh")
    assert ssh_entry == {"id": "ssh", "version": "2022.82-7"}


def test_ssh_garbage_meta_shape_unusable(expendable_lab: None) -> None:
    base = _load("bootstrap_nc1812_components.json")
    assert isinstance(base, dict)
    component_map = dict(base["component"])
    component_map["ssh"] = "not-a-dict"
    components = {**base, "component": component_map}
    vault = MemoryVault()
    handle = vault.create(kind="RouterManagementPassword", secret="lab-password")
    report = run_bootstrap_discovery(
        host="http://192.168.2.1",
        username="admin",
        credential_ref_id=handle.credential_ref_id,
        vault=vault,
        allow_insecure_http=True,
        http_client=_bootstrap_client_with_components(components),
    )
    assert report["ssh_component_installed"] is None
    assert report["ssh_component_determination"]["outcome"] == "shape_unusable"
    assert report["ssh_component_determination"]["matched"] is False
    assert FINDING_SSH_STATE_UNKNOWN in report["findings"]
    assert FINDING_SSH_COMPONENT_MISSING not in report["findings"]
    assert report["model"] == "NC-1812"


def test_truncation_force_includes_ssh(expendable_lab: None) -> None:
    base = _load("bootstrap_nc1812_components.json")
    assert isinstance(base, dict)
    component_map = {f"pkg{i:03d}": {"installed": True} for i in range(65)}
    component_map["ssh"] = {"version": "2022.82-7"}
    components = {**base, "component": component_map}
    vault = MemoryVault()
    handle = vault.create(kind="RouterManagementPassword", secret="lab-password")
    report = run_bootstrap_discovery(
        host="http://192.168.2.1",
        username="admin",
        credential_ref_id=handle.credential_ref_id,
        vault=vault,
        allow_insecure_http=True,
        http_client=_bootstrap_client_with_components(components),
    )
    inventory = report["components_inventory"]
    assert inventory["total_observed"] == 66
    assert inventory["truncated"] is True
    assert len(inventory["entries"]) == 64
    entry_ids = {e["id"] for e in inventory["entries"]}
    assert "ssh" in entry_ids


def test_hostile_version_token_omitted_from_inventory(expendable_lab: None) -> None:
    components = _load("bootstrap_components_with_secrets.json")
    vault = MemoryVault()
    handle = vault.create(kind="RouterManagementPassword", secret="lab-password")
    report = run_bootstrap_discovery(
        host="http://192.168.2.1",
        username="admin",
        credential_ref_id=handle.credential_ref_id,
        vault=vault,
        allow_insecure_http=True,
        http_client=_bootstrap_client_with_components(components),
    )
    webui = next(e for e in report["components_inventory"]["entries"] if e["id"] == "webui")
    assert "version" not in webui
    assert "licence" not in webui
    serialized = json.dumps(report)
    assert "SECRET-LICENCE" not in serialized


def _wifi_ap_entry(**fields: object) -> dict[str, object]:
    base: dict[str, object] = {
        "type": "AccessPoint",
        "role": "lan",
    }
    base.update(fields)
    return base


@pytest.mark.parametrize(
    ("fields", "expected_link_up", "expected_connected"),
    [
        ({"link": "down", "connected": True}, False, True),
        ({"connected": True}, None, True),
        ({"link": "up", "connected": False}, True, False),
        ({}, None, None),
    ],
    ids=[
        "connected_true_link_down",
        "connected_only_without_link",
        "link_up_connected_false",
        "both_absent",
    ],
)
def test_bootstrap_wifi_ap_link_connected_honesty(
    fields: dict[str, object],
    expected_link_up: bool | None,
    expected_connected: bool | None,
) -> None:
    from router_control.application.bootstrap_discovery import _sanitize_wifi_ap_entry

    sanitized = _sanitize_wifi_ap_entry("WifiMaster0/AccessPoint3", _wifi_ap_entry(**fields))
    assert sanitized is not None
    if expected_link_up is None:
        assert "link_up" not in sanitized
    else:
        assert sanitized.get("link_up") is expected_link_up
    if expected_connected is None:
        assert "connected" not in sanitized
    else:
        assert sanitized.get("connected") is expected_connected
