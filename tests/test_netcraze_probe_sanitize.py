"""Gate A probe evidence sanitization tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from router_control.adapters.netcraze.adapter import NetcrazeReadOnlyAdapter
from router_control.adapters.netcraze.identity import parse_identity
from router_control.adapters.netcraze.sanitize import describe_structure, sanitize_mapping
from router_control.adapters.netcraze.transport import NetcrazeTransport
from router_control.domain.ids import RouterId

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "netcraze"


class FixedClock:
    def now(self) -> datetime:
        return datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC)


class RecordingTransport:
    def __init__(
        self,
        system: object,
        components: object,
        *,
        identification: object | None = None,
        version: object | None = None,
        transport_security_label: str = "https",
        https_check_label: str = "not_certified",
        gate_a_certification_eligible: bool = False,
    ) -> None:
        self._system = system
        self._components = components
        self._identification = identification if identification is not None else {}
        self._version = version if version is not None else {}
        self.fetch_calls: list[str] = []
        self.transport_security_label = transport_security_label
        self.https_check_label = https_check_label
        self.gate_a_certification_eligible = gate_a_certification_eligible

    def read_json(self, command, body=None):  # type: ignore[no-untyped-def]
        from router_control.adapters.netcraze.allowlist import (
            COMPONENTS_LIST,
            SHOW_IDENTIFICATION,
            SHOW_SYSTEM,
            SHOW_VERSION,
        )

        self.fetch_calls.append(command.name)
        if command is SHOW_SYSTEM:
            return self._system
        if command is COMPONENTS_LIST:
            return self._components
        if command is SHOW_IDENTIFICATION:
            return self._identification
        if command is SHOW_VERSION:
            return self._version
        raise AssertionError("unexpected command")


def test_public_system_redacts_serial_and_mac() -> None:
    system = json.loads((FIXTURES / "system.json").read_text(encoding="utf-8"))
    components = json.loads((FIXTURES / "components_list.json").read_text(encoding="utf-8"))
    parsed = parse_identity(system, components)
    public = parsed.public_system
    assert public.get("serial") == "REDACTED"
    assert public.get("mac") == "REDACTED"
    assert "SERIAL_REDACTED" not in json.dumps(public)


def test_gate_a_evidence_has_no_secrets() -> None:
    system = json.loads((FIXTURES / "system.json").read_text(encoding="utf-8"))
    components = json.loads((FIXTURES / "components_list.json").read_text(encoding="utf-8"))
    adapter = NetcrazeReadOnlyAdapter(
        router_id=RouterId("router-lab-001"),
        transport=NetcrazeTransport(
            host="192.168.1.1",
            username="lab-user",
            password="lab-password",
        ),
        clock=FixedClock(),
    )
    adapter.transport = RecordingTransport(system, components)  # type: ignore[assignment]
    evidence = adapter.probe_gate_a_evidence()
    blob = json.dumps(evidence)
    forbidden_tokens = (
        "lab-user",
        "lab-password",
        "SERIAL_REDACTED",
        "MAC_REDACTED",
        "Authorization",
    )
    for forbidden in forbidden_tokens:
        assert forbidden not in blob
    assert evidence["firmware_version"] == "5.01"
    assert str(evidence["device_fingerprint"]).startswith("sha256:")
    assert evidence["transport_security"] == "https"
    assert evidence["https_check"] == "not_certified"
    assert evidence["gate_a_certification_eligible"] is False
    assert evidence["certification_eligible"] is False
    assert evidence["identity_shape"] == "legacy"
    assert evidence["identity_complete"] is True
    assert evidence["fingerprint_status"] == "stable"
    assert evidence["model_source"] == "rci_system"
    assert evidence["physical_identifier_source"] == "rci_system"
    assert adapter.transport.fetch_calls == [
        "show_system",
        "components_list",
        "show_identification",
        "show_version",
    ]


def test_insecure_http_evidence_is_non_certifying() -> None:
    adapter = NetcrazeReadOnlyAdapter(
        router_id=RouterId("router-lab-001"),
        transport=NetcrazeTransport(
            host="192.168.1.1",
            username="lab-user",
            password="lab-password",
            use_tls=False,
        ),
        clock=FixedClock(),
    )
    system = json.loads((FIXTURES / "system.json").read_text(encoding="utf-8"))
    components = json.loads((FIXTURES / "components_list.json").read_text(encoding="utf-8"))
    adapter.transport = RecordingTransport(
        system,
        components,
        transport_security_label="insecure_http",
    )  # type: ignore[assignment]
    evidence = adapter.probe_gate_a_evidence()
    assert evidence["transport_security"] == "insecure_http"
    assert evidence["https_check"] == "not_certified"
    assert evidence["gate_a_certification_eligible"] is False
    assert evidence["certification_eligible"] is False
    assert "synth" not in json.dumps(evidence).lower()


def test_observed_shape_evidence_non_certifying_without_telemetry_leak() -> None:
    system = json.loads((FIXTURES / "system_telemetry_only.json").read_text(encoding="utf-8"))
    components = json.loads((FIXTURES / "components_observed.json").read_text(encoding="utf-8"))
    adapter = NetcrazeReadOnlyAdapter(
        router_id=RouterId("router-lab-001"),
        transport=NetcrazeTransport(
            host="192.168.1.1",
            username="lab-user",
            password="lab-password",
            use_tls=False,
        ),
        clock=FixedClock(),
    )
    adapter.transport = RecordingTransport(
        system,
        components,
        transport_security_label="insecure_http",
    )  # type: ignore[assignment]
    evidence = adapter.probe_gate_a_evidence()
    blob = json.dumps(evidence)
    assert evidence["firmware_version"] == "5.01.C.1.0-0"
    assert evidence["firmware_display_title"] == "5.1.1"
    assert "title" not in evidence
    assert evidence.get("title") != evidence["firmware_display_title"]
    assert evidence["model"] == "unknown"
    assert evidence["model_source"] == "unknown"
    assert evidence["update_channel_source"] == "unknown"
    assert evidence["build_source"] == "unknown"
    assert evidence["physical_identifier_source"] == "missing"
    assert evidence["identity_shape"] == "observed"
    assert evidence["identity_complete"] is False
    assert evidence["fingerprint_status"] == "provisional"
    assert evidence["certification_eligible"] is False
    assert evidence["gate_a_certification_eligible"] is False
    assert evidence["transport_security"] == "insecure_http"
    for forbidden in (
        "FAKE-HOSTNAME-LEAK",
        "fake.example-leak",
        "lab-user",
        "lab-password",
        "SHOULD-NOT-APPEAR",
    ):
        assert forbidden not in blob


def test_observed_shape_without_hints_succeeds_non_certified() -> None:
    system = json.loads((FIXTURES / "system_telemetry_only.json").read_text(encoding="utf-8"))
    components = json.loads((FIXTURES / "components_observed.json").read_text(encoding="utf-8"))
    adapter = NetcrazeReadOnlyAdapter(
        router_id=RouterId("router-lab-001"),
        transport=NetcrazeTransport(host="192.168.1.1", username="u", password="p"),
        clock=FixedClock(),
    )
    adapter.transport = RecordingTransport(system, components)  # type: ignore[assignment]
    evidence = adapter.probe_gate_a_evidence()
    assert evidence["model"] == "unknown"
    assert evidence["model_source"] == "unknown"
    assert evidence["update_channel_source"] == "unknown"
    assert evidence["identity_complete"] is False
    assert evidence["certification_eligible"] is False


_PLACEHOLDER = "PLACEHOLDER_SECRET_VALUE"


_WIFI_WG_SECRET_KEYS = (
    "psk",
    "passphrase",
    "preshared-key",
    "pre-shared-key",
    "private-key",
    "privatekey",
    "PrivateKey",
    "wpa-psk",
    "wpa_psk",
    "sae",
    "authentication-sae",
    "authentication_sae",
    "obfs-key",
    "ObfsKey",
    "PresharedKey",
)

_WIFI_WG_BENIGN_KEYS = (
    "public-key",
    "wireguard-public-key",
    "ssh-host-key",
    "keepalive-interval",
    "wpa-mode",
    "encryption",
    "ssid",
)


@pytest.mark.parametrize("key", _WIFI_WG_SECRET_KEYS)
def test_sanitize_mapping_redacts_wifi_wg_secret_keys(key: str) -> None:
    payload = sanitize_mapping({key: _PLACEHOLDER})
    assert payload[key] == "REDACTED"


@pytest.mark.parametrize("key", _WIFI_WG_BENIGN_KEYS)
def test_sanitize_mapping_preserves_wifi_wg_benign_keys(key: str) -> None:
    payload = sanitize_mapping({key: _PLACEHOLDER})
    assert payload[key] == _PLACEHOLDER


def test_describe_structure_classifies_wifi_wg_secrets() -> None:
    structure = describe_structure(
        {
            "psk": _PLACEHOLDER,
            "public-key": _PLACEHOLDER,
            "ssid": "PLACEHOLDER_SSID",
        }
    )
    categories = {item["category"] for item in structure["secret_field_categories"]}
    assert "secret" in categories
    blob = json.dumps(structure)
    assert _PLACEHOLDER not in blob
    assert "PLACEHOLDER_SSID" not in blob


def test_sanitize_mapping_preserves_credential_ref_id_keys() -> None:
    payload = sanitize_mapping(
        {
            "private_key_credential_ref_id": "credref:awg-private",
            "preshared_key_credential_ref_id": "credref:awg-psk",
            "credential_ref_id": "credref:generic",
            "private-key": _PLACEHOLDER,
            "public-key": _PLACEHOLDER,
            "endpoint": "vpn.example.com:51820",
        }
    )
    assert payload["private_key_credential_ref_id"] == "credref:awg-private"
    assert payload["preshared_key_credential_ref_id"] == "credref:awg-psk"
    assert payload["credential_ref_id"] == "credref:generic"
    assert payload["private-key"] == "REDACTED"
    assert payload["public-key"] == _PLACEHOLDER
    assert payload["endpoint"] == "vpn.example.com:51820"


def test_sanitize_mapping_redacts_sensitive_keys() -> None:
    payload = sanitize_mapping(
        {
            "username": "admin",
            "password": "secret",
            "model": "NC-1812",
            "nested": {"serial": "ABC"},
            "session_cookie": "name=value",
            "x-ndm-challenge": "token-value",
        }
    )
    assert payload["username"] == "REDACTED"
    assert payload["password"] == "REDACTED"
    assert payload["nested"]["serial"] == "REDACTED"
    assert payload["session_cookie"] == "REDACTED"
    assert payload["x-ndm-challenge"] == "REDACTED"


def _load(name: str) -> object:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_observed_complete_identity_still_non_certifying() -> None:
    system = _load("system_telemetry_only.json")
    components = _load("components_observed.json")
    adapter = NetcrazeReadOnlyAdapter(
        router_id=RouterId("router-lab-001"),
        transport=NetcrazeTransport(
            host="192.168.1.1",
            username="lab-user",
            password="lab-password",
            use_tls=False,
        ),
        clock=FixedClock(),
    )
    adapter.transport = RecordingTransport(
        system,
        components,
        identification=_load("identification_both_ids.json"),
        version=_load("version_match.json"),
        transport_security_label="insecure_http",
    )  # type: ignore[assignment]
    evidence = adapter.probe_gate_a_evidence()
    blob = json.dumps(evidence)
    assert evidence["identity_complete"] is True
    assert evidence["fingerprint_status"] == "stable"
    assert evidence["model"] == "NC-1812"
    assert evidence["model_source"] == "rci_version"
    assert evidence["model_display"] == "Netcraze Ultra NC-1812"
    assert evidence["build"] == "SYNTH-NDM-BUILD-100"
    assert evidence["build_source"] == "rci_version_ndm_exact"
    assert evidence["bsp_build"] == "SYNTH-BSP-BUILD-200"
    assert evidence["sandbox"] == "stable"
    assert evidence["update_channel"] == "Main"
    assert evidence["update_channel_source"] == "rci_version_sandbox_ui_map"
    assert evidence["physical_identifier_source"] == "show.identification_digest"
    assert evidence["certification_eligible"] is False
    assert evidence["gate_a_certification_eligible"] is False
    for forbidden in ("SYNTH-SERIAL-ABC123", "SYNTH-STAG-XYZ789", "serial_digest"):
        assert forbidden not in blob


def test_evidence_exposes_no_physical_digests() -> None:
    system = _load("system_telemetry_only.json")
    components = _load("components_observed.json")
    adapter = NetcrazeReadOnlyAdapter(
        router_id=RouterId("router-lab-001"),
        transport=NetcrazeTransport(host="192.168.1.1", username="u", password="p"),
        clock=FixedClock(),
    )
    adapter.transport = RecordingTransport(
        system,
        components,
        identification=_load("identification_both_ids.json"),
        version=_load("version_match.json"),
    )  # type: ignore[assignment]
    evidence = adapter.probe_gate_a_evidence()
    blob = json.dumps(evidence)
    assert "serial_digest" not in blob
    assert "servicetag_digest" not in blob
    assert str(evidence["device_fingerprint"]).startswith("sha256:")
