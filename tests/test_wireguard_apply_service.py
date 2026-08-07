"""Offline tests for WireGuard apply service (injected fake transport)."""

from __future__ import annotations

import json
from typing import Any

import pytest
import router_control.application.wireguard_apply_service as wg_apply_service
from router_control.adapters.netcraze.allowlist import is_wireguard_nested_peer_body
from router_control.adapters.netcraze.sanitize import (
    redact_sealed_cli_command,
    redact_sealed_nested_body,
)
from router_control.application.wireguard_apply_service import (
    WG_PEER_LAST_HANDSHAKE_NEVER,
    WireguardApplyServiceError,
    apply_wireguard_intent,
    observe_tunnel_health,
    preview_wireguard_apply,
    teardown_wireguard,
)
from router_control.domain.network_intents import WireguardIntent, WireguardPeerRciShape

_ASC_9 = (5, 42, 54, 0, 0, 1, 2, 3, 4)
_ASC_16 = (5, 42, 54, 0, 0, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0)
_TEST_WG = "Wireguard5"
_FORBIDDEN_WG = "Wireguard0"
_PLACEHOLDER_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
_PLACEHOLDER_PEER = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
_IFACE_PUBLIC_KEY_LIVE = "83K4OikWbv9nmhQuhvCVjgc+kmZs410m/8hdyXOQVWU="
_REAL_PEER_PUBLIC_KEY_LIVE = "Oq6wuNSfv44nSkw3d3zfIqzda3ZZQlogDvY3nCLq/vM="
_ALT_PEER_PUBLIC_KEY = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="
_PRIVATE_KEY_REF = "credref:awg-private-test"
_PSK_REF = "credref:awg-psk-test"


def _fake_credential_resolver(ref_id: str) -> str:
    if ref_id == _PRIVATE_KEY_REF:
        return _PLACEHOLDER_KEY
    if ref_id == _PSK_REF:
        return "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="
    raise AssertionError(f"unexpected credential ref: {ref_id}")


def _intent(**overrides: object) -> WireguardIntent:
    base = {
        "wg_id": _TEST_WG,
        "enabled": True,
        "asc_args": _ASC_9,
    }
    base.update(overrides)
    return WireguardIntent(**base)  # type: ignore[arg-type]


def _ok_envelope(*, prompt: str = "(config)") -> list[dict[str, Any]]:
    return [
        {
            "parse": {
                "prompt": prompt,
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


def _real_live_peer_shape_readback(*, wg_id: str = _TEST_WG, txbytes: int = 148) -> dict[str, Any]:
    """Live NC-1812 shape: iface wireguard.public-key + peer[] with bool online."""
    return {
        "interface": {
            "id": wg_id,
            "state": "up",
            "link": "down",
            "type": "Wireguard",
            "wireguard": {
                "public-key": _IFACE_PUBLIC_KEY_LIVE,
                "listen-port": 44365,
                "status": "up",
                "peer": [
                    {
                        "public-key": _REAL_PEER_PUBLIC_KEY_LIVE,
                        "via": "WifiMaster1/WifiStation0",
                        "rxbytes": 0,
                        "txbytes": txbytes,
                        "last-handshake": WG_PEER_LAST_HANDSHAKE_NEVER,
                        "online": False,
                        "enabled": True,
                    }
                ],
            },
        }
    }


def _multi_peer_readback(*, match_key: str = _REAL_PEER_PUBLIC_KEY_LIVE) -> dict[str, Any]:
    return {
        "interface": {
            "id": _TEST_WG,
            "state": "up",
            "type": "Wireguard",
            "wireguard": {
                "public-key": _IFACE_PUBLIC_KEY_LIVE,
                "peer": [
                    {
                        "public-key": _ALT_PEER_PUBLIC_KEY,
                        "last-handshake": 1_700_000_000,
                        "online": "yes",
                        "rxbytes": 999,
                        "txbytes": 1,
                    },
                    {
                        "public-key": match_key,
                        "last-handshake": WG_PEER_LAST_HANDSHAKE_NEVER,
                        "online": "no",
                        "rxbytes": 0,
                        "txbytes": 50,
                    },
                ],
            },
        }
    }


def _iface_public_key_only_readback() -> dict[str, Any]:
    """Regression: iface wireguard.public-key without peer[] must not become peer."""
    return {
        "interface": {
            "id": _TEST_WG,
            "state": "up",
            "type": "Wireguard",
            "wireguard": {
                "public-key": _IFACE_PUBLIC_KEY_LIVE,
                "status": "up",
            },
        }
    }


def _empty_peer_array_readback() -> dict[str, Any]:
    return {
        "interface": {
            "id": _TEST_WG,
            "state": "up",
            "type": "Wireguard",
            "wireguard": {
                "public-key": _IFACE_PUBLIC_KEY_LIVE,
                "peer": [],
            },
        }
    }


def _applied_readback(wg_id: str = _TEST_WG) -> dict[str, Any]:
    return {
        "interface": {
            "id": wg_id,
            "state": "up",
            "up": True,
            "type": "Wireguard",
        }
    }


def _down_readback(wg_id: str = _TEST_WG) -> dict[str, Any]:
    return {
        "interface": {
            "id": wg_id,
            "state": "down",
            "up": False,
            "type": "Wireguard",
        }
    }


def _baseline_readback() -> dict[str, Any]:
    return {"interface": {}}


def _foreign_interface_pre_readback(*, wg_id: str = "Wireguard4") -> dict[str, Any]:
    """Pre-apply readback for a different WG interface (target baseline unknown — fail-closed)."""
    return {
        "interface": {
            "id": wg_id,
            "state": "up",
            "wireguard": {
                "public-key": _IFACE_PUBLIC_KEY_LIVE,
                "peer": [
                    {
                        "public-key": _PLACEHOLDER_PEER,
                        "last-handshake": WG_PEER_LAST_HANDSHAKE_NEVER,
                        "online": False,
                        "rxbytes": 0,
                        "txbytes": 0,
                    }
                ],
            },
        }
    }


def _dead_peer_readback(*, wg_id: str = _TEST_WG, txbytes: int = 5000) -> dict[str, Any]:
    """Observed dead-peer shape: status up + rising txbytes but INT_MAX handshake."""
    return {
        "interface": {
            "id": wg_id,
            "state": "up",
            "up": True,
            "type": "Wireguard",
            "wireguard": {
                "status": "up",
                "peer": [
                    {
                        "public-key": _PLACEHOLDER_PEER,
                        "last-handshake": WG_PEER_LAST_HANDSHAKE_NEVER,
                        "online": "no",
                        "rxbytes": 0,
                        "txbytes": txbytes,
                        "enabled": "yes",
                    }
                ],
            },
        }
    }


def _healthy_peer_readback_synthesised(*, wg_id: str = _TEST_WG) -> dict[str, Any]:
    """Synthesised healthy peer fields — NOT live-confirmed on device."""
    return {
        "interface": {
            "id": wg_id,
            "state": "up",
            "up": True,
            "wireguard": {
                "status": "up",
                "peer": [
                    {
                        "public-key": _PLACEHOLDER_PEER,
                        "last-handshake": 1_700_000_000,
                        "online": "yes",
                        "rxbytes": 1024,
                        "txbytes": 2048,
                    }
                ],
            },
        }
    }


def _ambiguous_zero_handshake_readback(
    *, wg_id: str = _TEST_WG, txbytes: int = 5000, rxbytes: int = 92
) -> dict[str, Any]:
    """Ambiguous zero last-handshake: parseable online/rx but unconfirmed LH counter."""
    return {
        "interface": {
            "id": wg_id,
            "state": "up",
            "up": True,
            "type": "Wireguard",
            "wireguard": {
                "status": "up",
                "peer": [
                    {
                        "public-key": _PLACEHOLDER_PEER,
                        "last-handshake": 0,
                        "online": "yes",
                        "rxbytes": rxbytes,
                        "txbytes": txbytes,
                        "enabled": "yes",
                    }
                ],
            },
        }
    }


def _missing_peer_fields_readback(*, wg_id: str = _TEST_WG) -> dict[str, Any]:
    return {
        "interface": {
            "id": wg_id,
            "state": "up",
            "wireguard": {
                "peer": [
                    {
                        "public-key": _PLACEHOLDER_PEER,
                    }
                ],
            },
        }
    }


def _extract_observed(
    raw: dict[str, Any],
    *,
    match_peer_public_key: str | None = None,
) -> dict[str, Any]:
    from router_control.application.wireguard_apply_service import _extract_show_interface_observed

    return _extract_show_interface_observed(
        raw,
        match_peer_public_key=match_peer_public_key,
    )


class FakeWireguardApplyTransport:
    def __init__(
        self,
        *,
        write_response: Any | None = None,
        readback_sequence: list[Any] | None = None,
        show_interface_readback_sequence: list[Any] | None = None,
        fail_on_command: str | None = None,
        readback_raises: BaseException | None = None,
        pre_read_raises: BaseException | None = None,
    ) -> None:
        self.write_response = write_response if write_response is not None else _ok_envelope()
        self.readback_sequence = list(readback_sequence or [])
        self.show_interface_readback_sequence = list(show_interface_readback_sequence or [])
        self.fail_on_command = fail_on_command
        self.readback_raises = readback_raises
        self.pre_read_raises = pre_read_raises
        self.write_commands: list[str] = []
        self.nested_write_bodies: list[dict[str, Any]] = []
        self.parse_commands: list[str] = []
        self._show_interface_parse_count = 0

    def execute_sealed_rci_write(self, request: Any) -> Any:
        body_bytes = request.body
        if is_wireguard_nested_peer_body(body_bytes):
            nested = json.loads(body_bytes.decode("utf-8"))
            self.nested_write_bodies.append(redact_sealed_nested_body(nested))
            return self.write_response
        body = json.loads(body_bytes.decode("utf-8"))
        command = str(body[0]["parse"])
        self.write_commands.append(redact_sealed_cli_command(command))
        if self.fail_on_command is not None and command == self.fail_on_command:
            return [
                {
                    "parse": {
                        "prompt": "(config)",
                        "status": [
                            {
                                "status": "error",
                                "code": "1",
                                "ident": "Core::Interface",
                                "message": "synthetic failure",
                            }
                        ],
                    }
                }
            ]
        if command == f"interface {_TEST_WG}":
            return _ok_envelope(prompt="(config-if)")
        return self.write_response

    def execute_rci_parse(self, cli_command: str) -> Any:
        self.parse_commands.append(cli_command)
        if cli_command.startswith("show interface "):
            if (
                self.pre_read_raises is not None
                and self._show_interface_parse_count == 0
            ):
                self._show_interface_parse_count += 1
                raise self.pre_read_raises
            if (
                self.readback_raises is not None
                and self._show_interface_parse_count > 0
            ):
                raise self.readback_raises
            if self.show_interface_readback_sequence:
                idx = self._show_interface_parse_count
                self._show_interface_parse_count += 1
                if idx < len(self.show_interface_readback_sequence):
                    return self.show_interface_readback_sequence[idx]
            if self.readback_sequence and self._show_interface_parse_count > 0:
                self._show_interface_parse_count += 1
                return self.readback_sequence.pop(0)
            if self.readback_sequence and self._show_interface_parse_count == 0:
                self._show_interface_parse_count += 1
                return _baseline_readback()
            self._show_interface_parse_count += 1
            return _baseline_readback()
        if self.readback_raises is not None:
            raise self.readback_raises
        if self.readback_sequence:
            return self.readback_sequence.pop(0)
        return _baseline_readback()


def test_preview_returns_plan_without_dispatch() -> None:
    plan = preview_wireguard_apply(_intent())
    assert plan["verification_status"] == "device_verified_asc9"
    assert len(plan["apply_ops"]) == 3
    serialized = json.dumps(plan)
    assert "private" not in serialized.lower()
    assert "peer_public_key" not in serialized


def test_apply_success_dispatches_ops_and_verifies() -> None:
    transport = FakeWireguardApplyTransport(readback_sequence=[_applied_readback()])
    result = apply_wireguard_intent(
        intent=_intent(), transport=transport, credential_resolver=_fake_credential_resolver
    )
    assert result.overall == "applied"
    assert len(result.steps) == 3
    assert all(step.ok for step in result.steps)
    assert result.verification is not None
    assert result.verification.id_ok is True
    assert result.verification.up_ok is True
    assert result.to_dict()["verification_status"] == "device_verified_asc9"
    assert result.configuration_verification_status == "device_accepted_configuration"
    assert result.interface_verification_status == "interface_present_up"
    assert result.tunnel_verification_status == "tunnel_no_peer"


def test_apply_honesty_three_notions_tunnel_never_verified() -> None:
    transport = FakeWireguardApplyTransport(readback_sequence=[_applied_readback()])
    result = apply_wireguard_intent(
        intent=_intent(), transport=transport, credential_resolver=_fake_credential_resolver
    )
    payload = result.to_dict()
    assert payload["configuration_verification_status"] == "device_accepted_configuration"
    assert payload["interface_verification_status"] == "interface_present_up"
    assert payload["tunnel_verification_status"] == "tunnel_no_peer"
    assert payload["tunnel_verification_status"] != "tunnel_verified"
    assert payload["tunnel_verification_status"] != "tunnel_up"
    assert payload["tunnel_verification_status"] != "tunnel_healthy"


def test_apply_enabled_true_interface_down_interface_not_up() -> None:
    transport = FakeWireguardApplyTransport(readback_sequence=[_down_readback()])
    result = apply_wireguard_intent(
        intent=_intent(enabled=True),
        transport=transport,
        credential_resolver=_fake_credential_resolver,
    )
    assert result.overall == "verify_mismatch"
    assert result.verification is not None
    assert result.verification.id_ok is True
    assert result.verification.up_ok is False
    assert result.interface_verification_status == "interface_not_up"
    assert result.tunnel_verification_status == "tunnel_no_peer"


def test_apply_enabled_false_interface_down_honest_present_down() -> None:
    transport = FakeWireguardApplyTransport(readback_sequence=[_down_readback()])
    result = apply_wireguard_intent(
        intent=_intent(enabled=False),
        transport=transport,
        credential_resolver=_fake_credential_resolver,
    )
    assert result.overall == "applied"
    assert result.interface_verification_status == "interface_present_down"
    assert result.interface_verification_status != "interface_present_up"


def test_apply_verify_mismatch_honest_interface_failure_tunnel_unverified() -> None:
    transport = FakeWireguardApplyTransport(
        readback_sequence=[_applied_readback(wg_id="Wireguard6")]
    )
    result = apply_wireguard_intent(
        intent=_intent(), transport=transport, credential_resolver=_fake_credential_resolver
    )
    assert result.overall == "verify_mismatch"
    assert result.configuration_verification_status == "device_accepted_configuration"
    assert result.interface_verification_status == "interface_id_mismatch"
    assert result.tunnel_verification_status == "tunnel_no_peer"


def test_apply_op_error_stops_with_failed() -> None:
    transport = FakeWireguardApplyTransport(
        show_interface_readback_sequence=[
            _foreign_interface_pre_readback(),
            _applied_readback(),
        ],
        fail_on_command="interface Wireguard5 wireguard asc 5 42 54 0 0 1 2 3 4",
    )
    result = apply_wireguard_intent(
        intent=_intent(), transport=transport, credential_resolver=_fake_credential_resolver
    )
    assert result.overall == "failed"
    assert any(not step.ok for step in result.steps)
    assert result.verification is None
    assert result.configuration_verification_status is None
    assert result.tunnel_verification_status == "tunnel_unverified"
    assert result.rollback is not None
    assert result.rollback.outcome == "partial"
    assert "wireguard_remove_interface" not in result.rollback.ops
    uncovered = {item.op: item.reason for item in result.rollback.uncovered_ops}
    assert "wireguard_create_interface" in uncovered
    assert "pre-apply state unknown" in uncovered["wireguard_create_interface"]
    assert len(transport.write_commands) == 2


def test_apply_verify_mismatch() -> None:
    transport = FakeWireguardApplyTransport(
        readback_sequence=[_applied_readback(wg_id="Wireguard6")]
    )
    result = apply_wireguard_intent(
        intent=_intent(), transport=transport, credential_resolver=_fake_credential_resolver
    )
    assert result.overall == "verify_mismatch"
    assert result.verification is not None
    assert result.verification.id_ok is False
    assert result.tunnel_verification_status == "tunnel_no_peer"


def test_observe_tunnel_health_dead_peer_never_handshaked_not_healthy() -> None:
    observed = _extract_observed(_dead_peer_readback())
    assert observe_tunnel_health(observed) == "tunnel_never_handshaked"
    assert observe_tunnel_health(observed) != "tunnel_healthy"
    assert observed.get("state") == "up"
    assert observed.get("up") is True
    assert observed.get("peer_txbytes") == 5000
    assert observed.get("peer_last_handshake") == WG_PEER_LAST_HANDSHAKE_NEVER


def test_observe_tunnel_health_int_max_is_never_not_timestamp() -> None:
    observed = _extract_observed(_dead_peer_readback())
    assert observed["peer_last_handshake"] == 2147483647
    assert observe_tunnel_health(observed) == "tunnel_never_handshaked"


def test_observe_tunnel_health_int_max_with_online_yes_rx_never_healthy() -> None:
    """INT_MAX sentinel wins before healthy — reorder regression guard."""
    raw = _dead_peer_readback()
    raw["interface"]["wireguard"]["peer"][0]["online"] = "yes"
    raw["interface"]["wireguard"]["peer"][0]["rxbytes"] = 4096
    observed = _extract_observed(raw)
    assert observed["peer_last_handshake"] == WG_PEER_LAST_HANDSHAKE_NEVER
    assert observed["peer_online"] == "yes"
    assert observed["peer_rxbytes"] == 4096
    assert observe_tunnel_health(observed) == "tunnel_never_handshaked"
    assert observe_tunnel_health(observed) != "tunnel_healthy"


def test_parse_yes_no_peer_online_rejects_up_token() -> None:
    from router_control.application.wireguard_apply_service import _parse_yes_no

    assert _parse_yes_no("yes") is True
    assert _parse_yes_no("no") is False
    assert _parse_yes_no(True) is True
    assert _parse_yes_no(False) is False
    assert _parse_yes_no("up") is None
    assert _parse_yes_no("down") is None
    assert _parse_yes_no("maybe") is None


def test_observe_tunnel_health_bool_online_healthy_and_not_healthy() -> None:
    healthy_raw = _healthy_peer_readback_synthesised()
    healthy_raw["interface"]["wireguard"]["peer"][0]["online"] = True
    healthy_observed = _extract_observed(healthy_raw)
    assert observe_tunnel_health(healthy_observed) == "tunnel_healthy"

    dead_raw = _real_live_peer_shape_readback()
    dead_observed = _extract_observed(dead_raw)
    assert observe_tunnel_health(dead_observed) == "tunnel_never_handshaked"


def test_real_live_peer_shape_extracts_peer_not_iface_public_key() -> None:
    observed = _extract_observed(_real_live_peer_shape_readback())
    assert observed["peer_public_key"] == _REAL_PEER_PUBLIC_KEY_LIVE
    assert observed["peer_public_key"] != _IFACE_PUBLIC_KEY_LIVE
    assert observed["peer_online"] is False
    assert observe_tunnel_health(observed) == "tunnel_never_handshaked"


def test_iface_public_key_without_peer_array_not_treated_as_peer() -> None:
    observed = _extract_observed(_iface_public_key_only_readback())
    assert "peer_public_key" not in observed
    assert _IFACE_PUBLIC_KEY_LIVE not in observed.values()
    verdict = observe_tunnel_health(observed)
    assert verdict == "tunnel_no_peer"
    assert verdict != "tunnel_healthy"
    assert verdict != "tunnel_unverified"


def test_empty_peer_array_no_peer() -> None:
    observed = _extract_observed(_empty_peer_array_readback())
    assert "peer_public_key" not in observed
    assert observe_tunnel_health(observed) == "tunnel_no_peer"


def test_multi_peer_selects_configured_public_key() -> None:
    observed = _extract_observed(
        _multi_peer_readback(),
        match_peer_public_key=_REAL_PEER_PUBLIC_KEY_LIVE,
    )
    assert observed["peer_public_key"] == _REAL_PEER_PUBLIC_KEY_LIVE
    assert observe_tunnel_health(observed) == "tunnel_never_handshaked"


def test_multi_peer_without_match_uses_first_peer() -> None:
    observed = _extract_observed(_multi_peer_readback())
    assert observed["peer_public_key"] == _ALT_PEER_PUBLIC_KEY
    assert observe_tunnel_health(observed) == "tunnel_healthy"


def test_extract_observed_accepts_match_peer_public_key_kwarg() -> None:
    from router_control.application.wireguard_apply_service import _extract_show_interface_observed

    observed = _extract_show_interface_observed(
        _multi_peer_readback(),
        match_peer_public_key=_REAL_PEER_PUBLIC_KEY_LIVE,
    )
    assert observed["peer_public_key"] == _REAL_PEER_PUBLIC_KEY_LIVE


def test_observe_tunnel_health_synthesised_healthy_device_confirmed() -> None:
    """Healthy branch from show interface peer fields — DEVICE-CONFIRMED 2026-07-31."""
    observed = _extract_observed(_healthy_peer_readback_synthesised())
    assert observe_tunnel_health(observed) == "tunnel_healthy"


def test_observe_tunnel_health_no_peer() -> None:
    observed = _extract_observed(_applied_readback())
    assert observe_tunnel_health(observed) == "tunnel_no_peer"


def test_observe_tunnel_health_missing_fields_unverified() -> None:
    observed = _extract_observed(_missing_peer_fields_readback())
    assert observe_tunnel_health(observed) == "tunnel_unverified"
    assert observe_tunnel_health(observed) != "tunnel_healthy"


def test_apply_default_settle_caps_never_handshaked_to_unverified() -> None:
    """Zero settle must not emit false tunnel_never_handshaked (device needs ~20-30s)."""
    transport = FakeWireguardApplyTransport(readback_sequence=[_dead_peer_readback()])
    result = apply_wireguard_intent(
        intent=_intent(), transport=transport, credential_resolver=_fake_credential_resolver
    )
    assert result.overall == "applied"
    assert result.tunnel_verification_status == "tunnel_unverified"
    assert observe_tunnel_health(_extract_observed(_dead_peer_readback())) == (
        "tunnel_never_handshaked"
    )


def test_apply_dead_peer_with_settle_keeps_never_handshaked() -> None:
    transport = FakeWireguardApplyTransport(
        show_interface_readback_sequence=[
            _baseline_readback(),
            _dead_peer_readback(txbytes=100),
            _dead_peer_readback(txbytes=200),
        ]
    )
    result = apply_wireguard_intent(
        intent=_intent(),
        transport=transport,
        credential_resolver=_fake_credential_resolver,
        handshake_settle_seconds=25,
    )
    assert result.overall == "applied"
    assert result.tunnel_verification_status == "tunnel_never_handshaked"


def test_observe_tunnel_health_unknown_handshake_string_unverified() -> None:
    raw = _dead_peer_readback()
    raw["interface"]["wireguard"]["peer"][0]["last-handshake"] = "never"
    observed = _extract_observed(raw)
    assert observe_tunnel_health(observed) == "tunnel_unverified"
    assert observe_tunnel_health(observed) != "tunnel_never_handshaked"


def test_observe_tunnel_handshake_zero_unverified_not_never() -> None:
    """Zero has no confirmed firmware semantics — must not infer never_handshaked."""
    raw = _dead_peer_readback()
    raw["interface"]["wireguard"]["peer"][0]["last-handshake"] = 0
    observed = _extract_observed(raw)
    assert observe_tunnel_health(observed) == "tunnel_unverified"
    assert observe_tunnel_health(observed) != "tunnel_never_handshaked"


def test_observe_tunnel_handshake_negative_unverified_not_never() -> None:
    """Negative handshake values are unconfirmed — must not infer never_handshaked."""
    raw = _dead_peer_readback()
    raw["interface"]["wireguard"]["peer"][0]["last-handshake"] = -1
    observed = _extract_observed(raw)
    assert observe_tunnel_health(observed) == "tunnel_unverified"
    assert observe_tunnel_health(observed) != "tunnel_never_handshaked"


def test_observe_tunnel_health_positive_timestamp_dead_peer_never_handshaked() -> None:
    """Positive non-sentinel timestamp + dead-peer counters → never_handshaked."""
    raw = _dead_peer_readback()
    raw["interface"]["wireguard"]["peer"][0]["last-handshake"] = 999_999_999
    raw["interface"]["wireguard"]["peer"][0]["online"] = "no"
    raw["interface"]["wireguard"]["peer"][0]["rxbytes"] = 0
    observed = _extract_observed(raw)
    assert observe_tunnel_health(observed) == "tunnel_never_handshaked"


def test_apply_healthy_peer_synthesised() -> None:
    transport = FakeWireguardApplyTransport(
        readback_sequence=[_healthy_peer_readback_synthesised()]
    )
    result = apply_wireguard_intent(
        intent=_intent(), transport=transport, credential_resolver=_fake_credential_resolver
    )
    assert result.overall == "applied"
    assert result.tunnel_verification_status == "tunnel_healthy"


def test_apply_observed_scrubs_private_key_not_public_key() -> None:
    raw = _dead_peer_readback()
    raw["interface"]["wireguard"]["peer"][0]["private-key"] = _PLACEHOLDER_KEY
    transport = FakeWireguardApplyTransport(readback_sequence=[raw])
    result = apply_wireguard_intent(
        intent=_intent(), transport=transport, credential_resolver=_fake_credential_resolver
    )
    assert result.verification is not None
    observed = result.verification.observed
    assert "REDACTED" in json.dumps(observed)
    assert _PLACEHOLDER_KEY not in json.dumps(observed)
    assert observed.get("peer_public_key") == _PLACEHOLDER_PEER


def test_apply_handshake_settle_recheck(monkeypatch: pytest.MonkeyPatch) -> None:
    sleeps: list[float] = []

    def _fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    monkeypatch.setattr(wg_apply_service.time, "sleep", _fake_sleep)
    transport = FakeWireguardApplyTransport(
        show_interface_readback_sequence=[
            _baseline_readback(),
            _dead_peer_readback(txbytes=100),
            _healthy_peer_readback_synthesised(),
        ]
    )
    result = apply_wireguard_intent(
        intent=_intent(),
        transport=transport,
        credential_resolver=_fake_credential_resolver,
        handshake_settle_seconds=25,
    )
    assert result.overall == "applied"
    assert result.tunnel_verification_status == "tunnel_healthy"
    assert sleeps == [25.0]
    assert transport._show_interface_parse_count == 3
    assert any("recheck" in line for line in result.logs)
    assert result.verification is not None
    observed = result.verification.observed
    assert observed.get("peer_last_handshake") != WG_PEER_LAST_HANDSHAKE_NEVER
    assert observe_tunnel_health(dict(observed)) == "tunnel_healthy"


def test_apply_settle_recheck_internal_consistency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """D1: final observation embedded in verification matches tunnel_healthy verdict."""
    monkeypatch.setattr(wg_apply_service.time, "sleep", lambda _seconds: None)
    transport = FakeWireguardApplyTransport(
        show_interface_readback_sequence=[
            _dead_peer_readback(txbytes=100),
            _healthy_peer_readback_synthesised(),
        ]
    )
    result = apply_wireguard_intent(
        intent=_intent(),
        transport=transport,
        credential_resolver=_fake_credential_resolver,
        handshake_settle_seconds=25,
    )
    assert result.tunnel_verification_status == "tunnel_healthy"
    assert result.verification is not None
    embedded_status = observe_tunnel_health(dict(result.verification.observed))
    assert embedded_status == result.tunnel_verification_status
    payload = result.to_dict()
    assert payload["tunnel_verification_status"] == "tunnel_healthy"
    assert observe_tunnel_health(dict(payload["verification"]["observed"])) == "tunnel_healthy"


def test_apply_interface_address_not_configured_signal() -> None:
    transport = FakeWireguardApplyTransport(
        readback_sequence=[_healthy_peer_readback_synthesised()]
    )
    result = apply_wireguard_intent(
        intent=_intent(), transport=transport, credential_resolver=_fake_credential_resolver
    )
    assert result.interface_address_verification_status == "interface_address_not_configured"
    assert result.to_dict()["interface_address_verification_status"] == (
        "interface_address_not_configured"
    )


def test_apply_handshake_settle_recheck_ambiguous_zero_becomes_healthy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sleeps: list[float] = []

    def _fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    monkeypatch.setattr(wg_apply_service.time, "sleep", _fake_sleep)
    first_readback = _ambiguous_zero_handshake_readback(txbytes=100)
    observed = _extract_observed(first_readback)
    assert observe_tunnel_health(observed) == "tunnel_unverified"
    assert observe_tunnel_health(observed) != "tunnel_never_handshaked"
    transport = FakeWireguardApplyTransport(
        show_interface_readback_sequence=[
            _baseline_readback(),
            first_readback,
            _healthy_peer_readback_synthesised(),
        ]
    )
    result = apply_wireguard_intent(
        intent=_intent(),
        transport=transport,
        credential_resolver=_fake_credential_resolver,
        handshake_settle_seconds=25,
    )
    assert result.overall == "applied"
    assert result.tunnel_verification_status == "tunnel_healthy"
    assert sleeps == [25.0]
    assert transport._show_interface_parse_count == 3
    assert any("ambiguous last-handshake" in line for line in result.logs)
    assert any("recheck" in line for line in result.logs)


def test_apply_handshake_settle_recheck_ambiguous_zero_stays_unverified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sleeps: list[float] = []

    def _fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    monkeypatch.setattr(wg_apply_service.time, "sleep", _fake_sleep)
    transport = FakeWireguardApplyTransport(
        show_interface_readback_sequence=[
            _baseline_readback(),
            _ambiguous_zero_handshake_readback(txbytes=100),
            _ambiguous_zero_handshake_readback(txbytes=200),
        ]
    )
    result = apply_wireguard_intent(
        intent=_intent(),
        transport=transport,
        credential_resolver=_fake_credential_resolver,
        handshake_settle_seconds=25,
    )
    assert result.overall == "applied"
    assert result.tunnel_verification_status == "tunnel_unverified"
    assert sleeps == [25.0]
    assert transport._show_interface_parse_count == 3
    assert any("recheck" in line for line in result.logs)


def test_apply_handshake_settle_skips_recheck_missing_handshake_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sleeps: list[float] = []

    def _fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    monkeypatch.setattr(wg_apply_service.time, "sleep", _fake_sleep)
    transport = FakeWireguardApplyTransport(
        show_interface_readback_sequence=[
            _baseline_readback(),
            _missing_peer_fields_readback(),
        ]
    )
    result = apply_wireguard_intent(
        intent=_intent(),
        transport=transport,
        credential_resolver=_fake_credential_resolver,
        handshake_settle_seconds=25,
    )
    assert result.tunnel_verification_status == "tunnel_unverified"
    assert sleeps == []
    assert transport._show_interface_parse_count == 2
    assert not any("recheck" in line for line in result.logs)


def test_apply_handshake_settle_skips_recheck_unparseable_handshake_string(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sleeps: list[float] = []

    def _fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    monkeypatch.setattr(wg_apply_service.time, "sleep", _fake_sleep)
    raw = _dead_peer_readback()
    raw["interface"]["wireguard"]["peer"][0]["last-handshake"] = "never"
    transport = FakeWireguardApplyTransport(
        show_interface_readback_sequence=[
            _baseline_readback(),
            raw,
        ]
    )
    result = apply_wireguard_intent(
        intent=_intent(),
        transport=transport,
        credential_resolver=_fake_credential_resolver,
        handshake_settle_seconds=25,
    )
    assert result.tunnel_verification_status == "tunnel_unverified"
    assert sleeps == []
    assert transport._show_interface_parse_count == 2
    assert not any("recheck" in line for line in result.logs)


def test_apply_handshake_settle_skips_recheck_ambiguous_zero_missing_online_rx(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F-1 gate: LH=0 unconfirmed but online/rx omitted → no settle recheck."""
    sleeps: list[float] = []

    def _fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    monkeypatch.setattr(wg_apply_service.time, "sleep", _fake_sleep)
    raw = _ambiguous_zero_handshake_readback(txbytes=100)
    peer = raw["interface"]["wireguard"]["peer"][0]
    peer.pop("online", None)
    peer.pop("rxbytes", None)
    transport = FakeWireguardApplyTransport(
        show_interface_readback_sequence=[
            _baseline_readback(),
            raw,
        ]
    )
    result = apply_wireguard_intent(
        intent=_intent(),
        transport=transport,
        credential_resolver=_fake_credential_resolver,
        handshake_settle_seconds=25,
    )
    assert result.tunnel_verification_status == "tunnel_unverified"
    assert sleeps == []
    assert transport._show_interface_parse_count == 2
    assert not any("recheck" in line for line in result.logs)


def test_apply_handshake_settle_clamped_and_never_handshaked_not_overall_failed() -> None:
    transport = FakeWireguardApplyTransport(
        show_interface_readback_sequence=[
            _baseline_readback(),
            _dead_peer_readback(txbytes=100),
            _dead_peer_readback(txbytes=200),
        ]
    )
    result = apply_wireguard_intent(
        intent=_intent(),
        transport=transport,
        credential_resolver=_fake_credential_resolver,
        handshake_settle_seconds=5,
    )
    assert result.overall == "applied"
    assert result.tunnel_verification_status == "tunnel_never_handshaked"
    assert transport._show_interface_parse_count == 3


def test_teardown_clear_private_key_quirk_end_state_success() -> None:
    transport = FakeWireguardApplyTransport(
        readback_sequence=[_baseline_readback()],
        fail_on_command=f"interface {_TEST_WG} no wireguard private-key",
    )
    intent = _intent(
        private_key_credential_ref_id=_PRIVATE_KEY_REF,
        peer_public_key=_PLACEHOLDER_PEER,
        asc_args=None,
    )
    result = teardown_wireguard(
        wg_id=_TEST_WG,
        transport=transport,
        credential_resolver=_fake_credential_resolver,
        intent=intent,
    )
    assert result.overall == "applied"
    assert result.interface_verification_status == "interface_absent"
    clear_step = next(
        step for step in result.steps if step.op == "wireguard_clear_private_key"
    )
    assert clear_step.ok is False
    assert "WireguardRciError" in clear_step.error


def test_teardown_genuine_removal_failure_overall_failed() -> None:
    transport = FakeWireguardApplyTransport(
        show_interface_readback_sequence=[_applied_readback()],
        fail_on_command=f"no interface {_TEST_WG}",
    )
    result = teardown_wireguard(
        wg_id=_TEST_WG,
        transport=transport,
        credential_resolver=_fake_credential_resolver,
    )
    assert result.overall == "failed"
    assert result.interface_verification_status == "interface_still_present"
    remove_step = next(
        step for step in result.steps if step.op == "wireguard_remove_interface"
    )
    assert remove_step.ok is False


def test_teardown_baseline_verify() -> None:
    transport = FakeWireguardApplyTransport(readback_sequence=[_baseline_readback()])
    result = teardown_wireguard(
        wg_id=_TEST_WG,
        transport=transport,
        credential_resolver=_fake_credential_resolver,
    )
    assert result.overall == "applied"
    assert len(result.steps) == 2
    assert result.verification is not None
    assert result.verification.id_ok is True
    assert result.tunnel_verification_status == "tunnel_unverified"
    assert result.interface_verification_status == "interface_absent"


def test_forbidden_wg_rejected_at_service() -> None:
    with pytest.raises(WireguardApplyServiceError, match="allowlisted"):
        preview_wireguard_apply(_intent(wg_id=_FORBIDDEN_WG))


def test_16_arg_unsupported_pending_verification() -> None:
    result = apply_wireguard_intent(
        intent=_intent(asc_args=_ASC_16),
        transport=FakeWireguardApplyTransport(),
        credential_resolver=_fake_credential_resolver,
    )
    assert result.overall == "unsupported_pending_verification"
    assert result.steps == ()


def test_backup_callback_invoked() -> None:
    calls: list[str] = []
    transport = FakeWireguardApplyTransport(readback_sequence=[_applied_readback()])

    def backup() -> None:
        calls.append("backup")

    apply_wireguard_intent(
        intent=_intent(),
        transport=transport,
        credential_resolver=_fake_credential_resolver,
        backup_callback=backup,
    )
    assert calls == ["backup"]


def test_dispatch_uses_sealed_ops_only() -> None:
    transport = FakeWireguardApplyTransport(readback_sequence=[_applied_readback()])
    apply_wireguard_intent(
        intent=_intent(),
        transport=transport,
        credential_resolver=_fake_credential_resolver,
    )
    assert any("wireguard asc" in cmd for cmd in transport.write_commands)
    assert any(cmd.endswith(" up") for cmd in transport.write_commands)
    assert not any("private-key" in cmd for cmd in transport.write_commands)


def test_secret_placeholder_only_in_transport_writes() -> None:
    intent = _intent(
        private_key_credential_ref_id=_PRIVATE_KEY_REF,
        peer_public_key=_PLACEHOLDER_PEER,
        peer_endpoint="vpn.example.com:51820",
        peer_allow_ips="10.0.0.0/24",
        peer_keepalive_interval=25,
        preshared_key_credential_ref_id=_PSK_REF,
        asc_args=None,
        peer_rci_shape=WireguardPeerRciShape.NESTED_RCI,
    )
    transport = FakeWireguardApplyTransport(readback_sequence=[_applied_readback()])
    result = apply_wireguard_intent(
        intent=intent,
        transport=transport,
        credential_resolver=_fake_credential_resolver,
    )
    assert result.overall == "applied"
    plan = preview_wireguard_apply(intent)
    plan_json = json.dumps(plan)
    result_json = json.dumps(result.to_dict())
    logs_blob = json.dumps(list(result.logs))
    assert result.to_dict()["verification_status"] == "pending_live_verification"
    assert result.to_dict()["verification_notes"]
    for blob in (plan_json, result_json, logs_blob):
        assert _PLACEHOLDER_KEY not in blob
        assert "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=" not in blob
    assert len(transport.nested_write_bodies) == 1
    assert not any(
        cmd == f"interface {_TEST_WG} wireguard peer {_PLACEHOLDER_PEER}"
        for cmd in transport.write_commands
    )
    assert any("secret not logged" in line for line in result.logs)


def test_path_style_intent_unsupported_without_dispatch() -> None:
    intent = _intent(
        asc_args=None,
        private_key_credential_ref_id=_PRIVATE_KEY_REF,
        peer_public_key=_PLACEHOLDER_PEER,
        peer_endpoint="vpn.example.com:51820",
        peer_rci_shape=WireguardPeerRciShape.PATH_STYLE,
    )
    plan = preview_wireguard_apply(intent)
    assert plan["verification_status"] == "unsupported"
    assert plan["apply_ops"] == []
    transport = FakeWireguardApplyTransport(readback_sequence=[_applied_readback()])
    result = apply_wireguard_intent(
        intent=intent,
        transport=transport,
        credential_resolver=_fake_credential_resolver,
    )
    assert result.overall == "failed"
    assert not transport.write_commands
    assert not transport.nested_write_bodies


def test_nested_rci_dispatch_resolves_psk_via_credential_ref() -> None:
    intent = _intent(
        private_key_credential_ref_id=_PRIVATE_KEY_REF,
        peer_public_key=_PLACEHOLDER_PEER,
        peer_endpoint="vpn.example.com:51820",
        preshared_key_credential_ref_id=_PSK_REF,
        asc_args=None,
        peer_rci_shape=WireguardPeerRciShape.NESTED_RCI,
    )
    transport = FakeWireguardApplyTransport(readback_sequence=[_applied_readback()])
    result = apply_wireguard_intent(
        intent=intent,
        transport=transport,
        credential_resolver=_fake_credential_resolver,
    )
    assert result.overall == "applied"
    assert len(transport.nested_write_bodies) == 1
    peer_obj = transport.nested_write_bodies[0]["interface"][_TEST_WG]["wireguard"]["peer"][0]
    assert peer_obj["key"] == _PLACEHOLDER_PEER
    assert peer_obj["endpoint"] == {"address": "vpn.example.com:51820"}
    assert peer_obj["preshared-key"] == "REDACTED"
    assert not any(" wireguard peer " in cmd for cmd in transport.write_commands)
    plan = preview_wireguard_apply(intent)
    plan_json = json.dumps(plan)
    result_json = json.dumps(result.to_dict())
    logs_blob = json.dumps(list(result.logs))
    for blob in (plan_json, result_json, logs_blob):
        assert _PLACEHOLDER_KEY not in blob
        assert "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=" not in blob
    nested_op = next(
        op for op in plan["apply_ops"] if op["operation"] == "wireguard_upsert_peer_nested"
    )
    assert nested_op["peer_rci_shape"] == "nested_rci"
    assert nested_op["credential_ref_id"] == _PSK_REF


def test_teardown_ops_order() -> None:
    transport = FakeWireguardApplyTransport(readback_sequence=[_baseline_readback()])
    teardown_wireguard(
        wg_id=_TEST_WG,
        transport=transport,
        credential_resolver=_fake_credential_resolver,
    )
    assert transport.write_commands[0].endswith(" down")
    assert transport.write_commands[1].startswith("no interface")


def test_teardown_continues_after_down_failure() -> None:
    transport = FakeWireguardApplyTransport(
        readback_sequence=[_baseline_readback()],
        fail_on_command=f"interface {_TEST_WG} down",
    )
    result = teardown_wireguard(
        wg_id=_TEST_WG,
        transport=transport,
        credential_resolver=_fake_credential_resolver,
    )
    assert result.overall == "failed"
    assert result.overall != "applied"
    assert any(cmd.startswith("no interface") for cmd in transport.write_commands)
    down_step = next(step for step in result.steps if step.op == "interface_down")
    assert down_step.ok is False
    assert result.verification is not None
    assert result.errors[0].startswith("InterfaceRciError:")


def test_teardown_aggregates_dispatch_and_readback_errors() -> None:
    class TeardownReadbackFailTransport(FakeWireguardApplyTransport):
        def execute_rci_parse(self, cli_command: str) -> Any:
            if cli_command.startswith("show interface "):
                raise RuntimeError("synthetic readback failure")
            return super().execute_rci_parse(cli_command)

    transport = TeardownReadbackFailTransport(
        fail_on_command=f"interface {_TEST_WG} down",
    )
    result = teardown_wireguard(
        wg_id=_TEST_WG,
        transport=transport,
        credential_resolver=_fake_credential_resolver,
    )
    assert result.overall == "failed"
    assert result.verification is None
    assert result.errors[0].startswith("InterfaceRciError:")
    assert result.errors[1] == "service.readback_failed"
    assert len(result.steps) == 2
    assert any(cmd.startswith("no interface") for cmd in transport.write_commands)


def test_apply_readback_failed_reports_interface_address_not_configured() -> None:
    transport = FakeWireguardApplyTransport(
        readback_raises=RuntimeError("synthetic readback failure"),
    )
    result = apply_wireguard_intent(
        intent=_intent(
            peer_public_key=_PLACEHOLDER_PEER,
            peer_allow_ips="0.0.0.0/0",
            private_key_credential_ref_id=_PRIVATE_KEY_REF,
        ),
        transport=transport,
        credential_resolver=_fake_credential_resolver,
    )
    assert result.overall == "failed"
    assert result.interface_address_verification_status == "interface_address_not_configured"
    assert result.rollback is not None
    assert result.rollback.outcome == "partial"
    assert any(item.op == "wireguard_set_asc" for item in result.rollback.uncovered_ops)
    assert result.to_dict()["interface_address_verification_status"] == (
        "interface_address_not_configured"
    )


def test_traffic_routing_intent_logs_address_limitation_on_success() -> None:
    transport = FakeWireguardApplyTransport(
        readback_sequence=[_healthy_peer_readback_synthesised()]
    )
    result = apply_wireguard_intent(
        intent=_intent(
            peer_public_key=_PLACEHOLDER_PEER,
            peer_allow_ips="10.0.0.0/8",
            peer_endpoint="203.0.113.1:51820",
            private_key_credential_ref_id=_PRIVATE_KEY_REF,
        ),
        transport=transport,
        credential_resolver=_fake_credential_resolver,
    )
    assert result.overall == "applied"
    assert result.interface_address_verification_status == "interface_address_not_configured"
    assert any("traffic-routing intent" in log for log in result.logs)
    assert any("interface Address NOT configured" in log for log in result.logs)


def test_partial_dispatch_failure_triggers_fail_closed_rollback() -> None:
    transport = FakeWireguardApplyTransport(
        show_interface_readback_sequence=[
            _foreign_interface_pre_readback(),
            _applied_readback(),
        ],
        fail_on_command=f"interface {_TEST_WG} up",
    )
    result = apply_wireguard_intent(
        intent=_intent(asc_args=None),
        transport=transport,
        credential_resolver=_fake_credential_resolver,
    )
    assert result.overall == "failed"
    assert result.rollback is not None
    assert result.rollback.attempted is True
    assert result.rollback.outcome == "partial"
    assert "wireguard_remove_interface" not in result.rollback.ops
    uncovered = {item.op: item.reason for item in result.rollback.uncovered_ops}
    assert "pre-apply state unknown" in uncovered["wireguard_create_interface"]
    assert result.errors[0].startswith("InterfaceRciError:")


def test_rollback_failure_preserves_dispatch_and_rollback_errors() -> None:
    up_fail = f"interface {_TEST_WG} up"
    rollback_remove_fail = f"no interface {_TEST_WG}"

    class PartialRollbackTransport(FakeWireguardApplyTransport):
        def execute_sealed_rci_write(self, request: Any) -> Any:
            body_bytes = request.body
            if is_wireguard_nested_peer_body(body_bytes):
                nested = json.loads(body_bytes.decode("utf-8"))
                self.nested_write_bodies.append(redact_sealed_nested_body(nested))
                return self.write_response
            body = json.loads(body_bytes.decode("utf-8"))
            command = str(body[0]["parse"])
            self.write_commands.append(redact_sealed_cli_command(command))
            if command in {up_fail, rollback_remove_fail}:
                return [
                    {
                        "parse": {
                            "prompt": "(config)",
                            "status": [
                                {
                                    "status": "error",
                                    "code": "1",
                                    "ident": "Core::Interface",
                                    "message": "synthetic failure",
                                }
                            ],
                        }
                    }
                ]
            if command == f"interface {_TEST_WG}":
                return _ok_envelope(prompt="(config-if)")
            return self.write_response

    transport = PartialRollbackTransport(
        show_interface_readback_sequence=[
            _foreign_interface_pre_readback(),
            _applied_readback(),
        ],
    )
    result = apply_wireguard_intent(
        intent=_intent(asc_args=None),
        transport=transport,
        credential_resolver=_fake_credential_resolver,
    )
    assert result.overall == "failed"
    assert result.errors[0].startswith("InterfaceRciError:")
    assert result.rollback_errors == ()
    assert result.rollback is not None
    assert result.rollback.outcome == "partial"
    assert rollback_remove_fail not in transport.write_commands
    uncovered = {item.op: item.reason for item in result.rollback.uncovered_ops}
    assert "pre-apply state unknown" in uncovered["wireguard_create_interface"]


def test_tunnel_unverified_does_not_compensate() -> None:
    transport = FakeWireguardApplyTransport(readback_sequence=[_applied_readback()])
    result = apply_wireguard_intent(
        intent=_intent(),
        transport=transport,
        credential_resolver=_fake_credential_resolver,
    )
    assert result.overall == "applied"
    assert result.tunnel_verification_status == "tunnel_no_peer"
    assert result.rollback is not None
    assert result.rollback.attempted is False
    assert result.rollback.outcome == "not_attempted"


def test_uncovered_set_asc_reported_on_rollback() -> None:
    transport = FakeWireguardApplyTransport(
        fail_on_command=f"interface {_TEST_WG} up",
    )
    result = apply_wireguard_intent(
        intent=_intent(),
        transport=transport,
        credential_resolver=_fake_credential_resolver,
    )
    assert result.rollback is not None
    assert result.rollback.outcome == "partial"
    uncovered = {item.op: item.reason for item in result.rollback.uncovered_ops}
    assert "wireguard_set_asc" in uncovered
    assert "no sealed negation grammar" in uncovered["wireguard_set_asc"]
    assert result.overall == "failed"


def test_compensate_opt_out_keeps_failed_without_rollback() -> None:
    transport = FakeWireguardApplyTransport(
        fail_on_command=f"interface {_TEST_WG} up",
    )
    result = apply_wireguard_intent(
        intent=_intent(asc_args=None),
        transport=transport,
        credential_resolver=_fake_credential_resolver,
        compensate_on_failure=False,
    )
    assert result.overall == "failed"
    assert result.rollback is not None
    assert result.rollback.attempted is False


def test_readback_failure_after_dispatch_triggers_rollback() -> None:
    transport = FakeWireguardApplyTransport(
        show_interface_readback_sequence=[_foreign_interface_pre_readback()],
        readback_raises=RuntimeError("readback failed"),
    )
    result = apply_wireguard_intent(
        intent=_intent(asc_args=None),
        transport=transport,
        credential_resolver=_fake_credential_resolver,
    )
    assert result.overall == "failed"
    assert result.errors == ("service.readback_failed",)
    assert result.rollback is not None
    assert result.rollback.outcome == "partial"
    assert "wireguard_remove_interface" not in result.rollback.ops
    uncovered = {item.op: item.reason for item in result.rollback.uncovered_ops}
    assert "pre-apply state unknown" in uncovered["wireguard_create_interface"]


def test_rollback_empty_pre_apply_baseline_is_fail_closed() -> None:
    transport = FakeWireguardApplyTransport(
        show_interface_readback_sequence=[_baseline_readback(), _applied_readback()],
        fail_on_command=f"interface {_TEST_WG} up",
    )
    result = apply_wireguard_intent(
        intent=_intent(asc_args=None),
        transport=transport,
        credential_resolver=_fake_credential_resolver,
    )
    assert result.rollback is not None
    assert "wireguard_remove_interface" not in result.rollback.ops
    uncovered = {item.op: item.reason for item in result.rollback.uncovered_ops}
    assert "wireguard_create_interface" in uncovered
    assert "pre-apply state unknown" in uncovered["wireguard_create_interface"]
    assert "wireguard_remove_interface" not in transport.write_commands


def test_rollback_skipped_when_pre_apply_state_unknown() -> None:
    transport = FakeWireguardApplyTransport(
        show_interface_readback_sequence=[_applied_readback(), _applied_readback()],
        fail_on_command=f"interface {_TEST_WG} up",
    )
    result = apply_wireguard_intent(
        intent=_intent(asc_args=None),
        transport=transport,
        credential_resolver=_fake_credential_resolver,
    )
    assert result.rollback is not None
    assert "wireguard_remove_interface" not in result.rollback.ops
    uncovered = {item.op: item.reason for item in result.rollback.uncovered_ops}
    assert "wireguard_create_interface" in uncovered
    assert "pre-existing" in uncovered["wireguard_create_interface"]


def test_rollback_skipped_when_pre_apply_read_fails() -> None:
    transport = FakeWireguardApplyTransport(
        fail_on_command=f"interface {_TEST_WG} up",
        pre_read_raises=RuntimeError("pre read failed"),
    )
    result = apply_wireguard_intent(
        intent=_intent(asc_args=None),
        transport=transport,
        credential_resolver=_fake_credential_resolver,
    )
    assert result.rollback is not None
    assert result.rollback.ops == ()
    uncovered = {item.op: item.reason for item in result.rollback.uncovered_ops}
    assert "wireguard_create_interface" in uncovered
    assert "pre-apply state unknown" in uncovered["wireguard_create_interface"]
    assert "wireguard_remove_interface" not in transport.write_commands


class _RaiseOnIpAddressTransport(FakeWireguardApplyTransport):
    def execute_sealed_rci_write(self, request: Any) -> Any:
        body = json.loads(request.body.decode("utf-8"))
        command = str(body[0]["parse"])
        if "ip address" in command:
            raise RuntimeError("synthetic SET_IP_ADDRESS transport failure")
        return super().execute_sealed_rci_write(request)


class _RaiseOnIpGlobalTransport(FakeWireguardApplyTransport):
    def execute_sealed_rci_write(self, request: Any) -> Any:
        body = json.loads(request.body.decode("utf-8"))
        command = str(body[0]["parse"])
        if "ip global" in command:
            raise RuntimeError("synthetic IP_GLOBAL transport failure")
        return super().execute_sealed_rci_write(request)


class _RaiseOnTcpMssTransport(FakeWireguardApplyTransport):
    def execute_sealed_rci_write(self, request: Any) -> Any:
        body = json.loads(request.body.decode("utf-8"))
        command = str(body[0]["parse"])
        if "adjust-mss" in command:
            raise RuntimeError("synthetic SET_TCP_MSS transport failure")
        return super().execute_sealed_rci_write(request)


class _RaiseOnPrivateKeyTransport(FakeWireguardApplyTransport):
    def execute_sealed_rci_write(self, request: Any) -> Any:
        body = json.loads(request.body.decode("utf-8"))
        command = str(body[0]["parse"])
        if "private-key" in command:
            raise RuntimeError("secret material must not leak")
        return super().execute_sealed_rci_write(request)


def test_dispatch_set_ip_address_failure_logs_exception_detail() -> None:
    transport = _RaiseOnIpAddressTransport(readback_sequence=[_baseline_readback()])
    result = apply_wireguard_intent(
        intent=_intent(
            interface_address="10.0.0.2/32",
            peer_public_key=_PLACEHOLDER_PEER,
            private_key_credential_ref_id=_PRIVATE_KEY_REF,
            asc_args=None,
        ),
        transport=transport,
        credential_resolver=_fake_credential_resolver,
    )
    address_step = next(
        step for step in result.steps if step.op == "wireguard_set_ip_address"
    )
    assert "RuntimeError" in address_step.error
    assert "synthetic SET_IP_ADDRESS transport failure" in address_step.error
    assert any("RuntimeError" in log for log in result.logs)
    assert _PLACEHOLDER_KEY not in " ".join(result.logs)


def test_dispatch_ip_global_failure_logs_exception_detail() -> None:
    transport = _RaiseOnIpGlobalTransport(readback_sequence=[_baseline_readback()])
    result = apply_wireguard_intent(
        intent=_intent(
            ip_global_priority=700,
            private_key_credential_ref_id=_PRIVATE_KEY_REF,
            asc_args=None,
        ),
        transport=transport,
        credential_resolver=_fake_credential_resolver,
    )
    ip_global_step = next(
        step for step in result.steps if step.op == "wireguard_ip_global"
    )
    assert "RuntimeError" in ip_global_step.error
    assert "synthetic IP_GLOBAL transport failure" in ip_global_step.error
    assert any("RuntimeError" in log for log in result.logs)
    assert _PLACEHOLDER_KEY not in " ".join(result.logs)


def test_dispatch_tcp_mss_failure_logs_exception_detail() -> None:
    transport = _RaiseOnTcpMssTransport(readback_sequence=[_baseline_readback()])
    result = apply_wireguard_intent(
        intent=_intent(
            tcp_mss_pmtu=True,
            asc_args=None,
        ),
        transport=transport,
        credential_resolver=_fake_credential_resolver,
    )
    tcp_mss_step = next(
        step for step in result.steps if step.op == "wireguard_set_tcp_mss"
    )
    assert "RuntimeError" in tcp_mss_step.error
    assert "synthetic SET_TCP_MSS transport failure" in tcp_mss_step.error
    assert any("RuntimeError" in log for log in result.logs)


def test_dispatch_secret_op_failure_stays_opaque() -> None:
    transport = _RaiseOnPrivateKeyTransport(readback_sequence=[_baseline_readback()])
    result = apply_wireguard_intent(
        intent=_intent(
            private_key_credential_ref_id=_PRIVATE_KEY_REF,
            peer_public_key=_PLACEHOLDER_PEER,
            asc_args=None,
        ),
        transport=transport,
        credential_resolver=_fake_credential_resolver,
    )
    private_step = next(
        step for step in result.steps if step.op == "wireguard_set_private_key"
    )
    assert private_step.error == "service.op_dispatch_failed"
    assert "secret material must not leak" not in " ".join(result.logs)
    assert _PLACEHOLDER_KEY not in " ".join(result.logs)
