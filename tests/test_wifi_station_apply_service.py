"""Offline tests for Wi-Fi station apply service (preview + fail-closed apply)."""



from __future__ import annotations

import json
from typing import Any

import pytest
from router_control.adapters.netcraze.transport import SealedRciWriteRequest
from router_control.adapters.netcraze.wifi_station_rci import WifiStationRciOperation
from router_control.application.wifi_station_apply_planner import WifiStationPlannerOptions
from router_control.application.wifi_station_apply_service import (
    WifiStationApplyServiceError,
    apply_wifi_station_intent,
    preview_wifi_station_apply,
    readback_wifi_station_state,
    teardown_wifi_station,
)
from router_control.domain.network_intents import UplinkIntent, UplinkMode, WifiBand


def _wifi_wan_intent() -> UplinkIntent:

    return UplinkIntent(

        mode=UplinkMode.WIFI_WAN,

        ssid="Venue-Guest",

        band=WifiBand.BAND_2_4GHZ,

        credential_ref_id="credref:venue-wifi",

        priority=100,

    )





def _ack_envelope(message: str, *, prompt: str = "(config)") -> list[dict[str, Any]]:

    return [

        {

            "parse": {

                "prompt": prompt,

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





_ACK_BY_FRAGMENT: tuple[tuple[str, str], ...] = (
    (" no authentication wpa-psk", "WPA PSK removed."),
    (" no encryption wpa2", "WPA2 algorithms disabled."),
    (" no encryption enable", "wireless encryption disabled."),
    (" no ssid", "SSID reset."),
    (" no ip address dhcp", "Stopped DHCP client on station."),
    (" no ip address", "IP address cleared."),
    (" ssid ", "SSID saved."),
    (" encryption enable", "wireless encryption enabled."),
    (" encryption wpa2", "WPA2 algorithms enabled."),
    (" authentication wpa-psk", "WPA PSK set."),
    (" ip global ", '"WifiMaster0/WifiStation0": global priority is 100.'),
    (" ip address dhcp", "Started DHCP client on station."),
    (" up", "interface is up."),
    (" down", "interface is down."),
)


def _ip_global_ack_envelope(
    *,
    station: str = "WifiMaster0/WifiStation0",
    priority: int = 100,
) -> list[dict[str, Any]]:
    return [
        {
            "parse": {
                "prompt": "(config)",
                "status": [
                    {
                        "status": "message",
                        "code": "72744991",
                        "ident": "Network::Interface::L3Base",
                        "message": f'"{station}": global priority is {priority}.',
                    }
                ],
            }
        }
    ]


def _response_for_body(body: bytes) -> list[dict[str, Any]]:
    text = body.decode("utf-8", errors="replace").lower()
    if " ip global " in text:
        return _ip_global_ack_envelope()
    for fragment, message in _ACK_BY_FRAGMENT:
        if fragment in text:
            return _ack_envelope(message)
    raise AssertionError(f"no test ack mapping for sealed body fragment: {text!r}")





class FakeWifiStationApplyTransport:

    wifi_station_offline_only = True



    def __init__(self, *, write_response: Any | None = None) -> None:

        self.write_response = write_response

        self.write_calls: list[SealedRciWriteRequest] = []



    def execute_sealed_rci_write(self, request: SealedRciWriteRequest) -> Any:

        self.write_calls.append(request)

        if self.write_response is not None:

            return self.write_response

        return _response_for_body(request.body)





class RejectFirstOpTransport(FakeWifiStationApplyTransport):

    def execute_sealed_rci_write(self, request: SealedRciWriteRequest) -> Any:

        self.write_calls.append(request)

        if len(self.write_calls) == 1:

            return _ack_envelope("syntax error: rejected", prompt="(config)")

        return _response_for_body(request.body)





class FailOnWriteNumbersTransport(FakeWifiStationApplyTransport):
    """Fail on selected 1-based write indices (apply + rollback share the counter)."""

    def __init__(self, *, fail_on_writes: frozenset[int]) -> None:
        super().__init__()
        self.fail_on_writes = fail_on_writes
        self.write_count = 0

    def execute_sealed_rci_write(self, request: SealedRciWriteRequest) -> Any:
        self.write_count += 1
        self.write_calls.append(request)
        if self.write_count in self.fail_on_writes:
            return _ack_envelope("syntax error: rejected", prompt="(config)")
        return _response_for_body(request.body)





class UnmarkedTransport:

    def execute_sealed_rci_write(self, request: SealedRciWriteRequest) -> Any:

        raise AssertionError("execute_sealed_rci_write must not be called without offline marker")





class FalseMarkerTransport(UnmarkedTransport):

    wifi_station_offline_only = False





class FakeReadbackTransport:

    def __init__(self, configured: Any, runtime: Any) -> None:

        self.configured = configured

        self.runtime = runtime

        self.commands: list[str] = []



    def execute_rci_parse(self, cli_command: str) -> Any:

        self.commands.append(cli_command)

        if cli_command.startswith("show rc interface"):

            return self.configured

        if cli_command.startswith("show interface"):

            return self.runtime

        raise AssertionError(f"unexpected read command: {cli_command}")





def test_preview_wifi_station_apply_is_deterministic() -> None:

    intent = _wifi_wan_intent()

    preview_a = preview_wifi_station_apply(intent)

    preview_b = preview_wifi_station_apply(intent)

    assert preview_a == preview_b

    assert preview_a["station_id"] == "WifiMaster0/WifiStation0"

    assert preview_a["grammar_verification_status"] == "device_accepted_grammar"

    assert preview_a["planned_uplink_verification_level"] == "planned_uplink_verified_bounded"

    assert preview_a["verification_status"] == "device_accepted_grammar"

    assert "configured_ssid" in preview_a["readback_rule"]

    assert [op["operation"] for op in preview_a["apply_ops"]] == [

        WifiStationRciOperation.SET_SSID.value,

        WifiStationRciOperation.ENCRYPTION_ENABLE.value,

        WifiStationRciOperation.ENCRYPTION_WPA2.value,

        WifiStationRciOperation.SET_WPA_PSK.value,

        WifiStationRciOperation.UP.value,

    ]





_MSG_LIVE_DISABLED = "live Wi-Fi station apply dispatch is disabled"





def test_apply_without_transport_is_fail_closed() -> None:

    with pytest.raises(WifiStationApplyServiceError, match=_MSG_LIVE_DISABLED):

        apply_wifi_station_intent(intent=_wifi_wan_intent(), transport=None)





def test_apply_without_offline_guard_is_fail_closed() -> None:

    with pytest.raises(WifiStationApplyServiceError, match=_MSG_LIVE_DISABLED):

        apply_wifi_station_intent(

            intent=_wifi_wan_intent(),

            transport=UnmarkedTransport(),  # type: ignore[arg-type]

            credential_resolver=lambda _ref: "unused",

        )





def test_apply_with_false_offline_marker_is_fail_closed() -> None:

    with pytest.raises(WifiStationApplyServiceError, match=_MSG_LIVE_DISABLED):

        apply_wifi_station_intent(

            intent=_wifi_wan_intent(),

            transport=FalseMarkerTransport(),  # type: ignore[arg-type]

            credential_resolver=lambda _ref: "unused",

        )





def test_apply_offline_grammar_accepted_dispatched() -> None:

    transport = FakeWifiStationApplyTransport()

    result = apply_wifi_station_intent(

        intent=_wifi_wan_intent(),

        transport=transport,

        credential_resolver=lambda ref: "synthetic-psk-for-tests-only" if ref else "",

    )

    assert result.overall == "dispatched_offline"

    assert result.grammar_verification_status == "device_accepted_grammar"

    assert result.uplink_verification_status == "uplink_dispatched_unverified"

    assert len(result.steps) == 5

    assert all(step.ok for step in result.steps)

    assert len(transport.write_calls) == 5





def test_teardown_continue_on_error_does_not_abort_remainder() -> None:

    transport = RejectFirstOpTransport()

    result = teardown_wifi_station(

        intent=_wifi_wan_intent(),

        transport=transport,

        credential_resolver=lambda _ref: "unused",

        options=WifiStationPlannerOptions(include_encryption_wpa2=True),

    )

    assert result.steps[0].ok is False
    assert result.steps[0].op == WifiStationRciOperation.DOWN.value
    assert result.steps[1].op == WifiStationRciOperation.CLEAR_WPA_PSK.value
    assert result.steps[1].ok is True
    assert result.steps[2].op == WifiStationRciOperation.ENCRYPTION_WPA2_CLEAR.value
    assert result.steps[2].ok is True
    assert result.steps[3].op == WifiStationRciOperation.ENCRYPTION_DISABLE.value
    assert result.steps[3].ok is True
    assert result.steps[4].op == WifiStationRciOperation.CLEAR_SSID.value
    assert result.steps[4].ok is True
    assert len(result.steps) == 5
    assert result.errors


def test_teardown_offline_non_default_priority_compiles() -> None:
    transport = FakeWifiStationApplyTransport()
    intent = UplinkIntent(
        mode=UplinkMode.WIFI_WAN,
        ssid="Venue-Guest",
        band=WifiBand.BAND_2_4GHZ,
        credential_ref_id="credref:venue-wifi",
        priority=600,
    )
    result = teardown_wifi_station(
        intent=intent,
        transport=transport,
        credential_resolver=lambda _ref: "unused",
    )
    assert result.overall == "dispatched_offline"
    assert result.steps[0].op == WifiStationRciOperation.DOWN.value
    assert all(step.ok for step in result.steps)





def test_readback_split_configured_vs_associated() -> None:

    configured = {"ssid": "RC-LAB-NOSUCHNET-d78c3d57", "encryption": "wpa2"}

    runtime_up_no_assoc = {"ssid": "", "encryption": "wpa2", "state": "up"}

    transport = FakeReadbackTransport(configured, runtime_up_no_assoc)

    readback = readback_wifi_station_state(transport, "WifiMaster0/WifiStation0")

    assert readback["configured_ssid"] == "RC-LAB-NOSUCHNET-d78c3d57"

    assert readback["associated_ssid"] is None

    assert readback["associated_ssid_field_present"] is True

    assert readback["associated_network"] == "none"

    assert "show rc interface" in transport.commands[0]

    assert transport.commands[1].startswith("show interface")





def test_preview_has_no_psk_literals() -> None:

    preview = preview_wifi_station_apply(_wifi_wan_intent())

    serialized = json.dumps(preview)

    assert "synthetic-psk" not in serialized.lower()

    assert "wpa-psk test" not in serialized.lower()


class LiveDispatchTransport(FakeWifiStationApplyTransport):
    wifi_station_offline_only = False  # type: ignore[misc, assignment]
    wifi_station_live_dispatch = True

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self.parse_commands: list[str] = []
        self.runtime_readback: dict[str, object] = {
            "ssid": "Venue-Guest",
            "encryption": "wpa2",
            "state": "up",
        }
        self.configured_readback: dict[str, object] = {
            "ssid": "Venue-Guest",
            "encryption": "wpa2",
        }
        self.internet_status: dict[str, object] = {
            "internet": "yes",
            "gateway": "yes",
            "dns": "yes",
        }

    def execute_rci_parse(self, cli_command: str) -> Any:
        self.parse_commands.append(cli_command)
        if cli_command.startswith("show rc interface"):
            return self.configured_readback
        if cli_command.startswith("show interface"):
            return self.runtime_readback
        if cli_command == "show internet status":
            return self.internet_status
        raise AssertionError(f"unexpected parse: {cli_command}")


class SequencingLiveDispatchTransport(LiveDispatchTransport):
    def __init__(
        self,
        *,
        internet_status_sequence: list[dict[str, object]] | None = None,
        **kwargs: object,
    ) -> None:
        super().__init__(**kwargs)
        self.internet_status_sequence = list(internet_status_sequence or [])
        self._internet_status_call_count = 0

    def execute_rci_parse(self, cli_command: str) -> Any:
        if cli_command == "show internet status":
            self.parse_commands.append(cli_command)
            if self.internet_status_sequence:
                idx = self._internet_status_call_count
                self._internet_status_call_count += 1
                if idx < len(self.internet_status_sequence):
                    return self.internet_status_sequence[idx]
                return self.internet_status_sequence[-1]
            return self.internet_status
        return super().execute_rci_parse(cli_command)


class SequencingRuntimeReadbackTransport(SequencingLiveDispatchTransport):
    def __init__(
        self,
        *,
        runtime_readback_sequence: list[dict[str, object]] | None = None,
        **kwargs: object,
    ) -> None:
        super().__init__(**kwargs)
        self.runtime_readback_sequence = list(runtime_readback_sequence or [])
        self._runtime_show_call_count = 0

    def execute_rci_parse(self, cli_command: str) -> Any:
        if cli_command.startswith("show interface"):
            self.parse_commands.append(cli_command)
            if self.runtime_readback_sequence:
                idx = self._runtime_show_call_count
                self._runtime_show_call_count += 1
                if idx < len(self.runtime_readback_sequence):
                    return self.runtime_readback_sequence[idx]
                return self.runtime_readback_sequence[-1]
            return self.runtime_readback
        return super().execute_rci_parse(cli_command)


class FailFirstObserveReadbackTransport(LiveDispatchTransport):
    """Fail the first post-settle station readback; later observe attempts succeed."""

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._fail_next_show_rc = True

    def execute_rci_parse(self, cli_command: str) -> Any:
        if cli_command.startswith("show rc interface") and self._fail_next_show_rc:
            self._fail_next_show_rc = False
            raise RuntimeError("simulated post-settle station readback failure")
        return super().execute_rci_parse(cli_command)


def test_observe_uplink_settle_before_first_readback_ordering() -> None:
    observe_order: list[str] = []
    transport = LiveDispatchTransport()
    original_parse = transport.execute_rci_parse

    def tracked_parse(cli_command: str) -> Any:
        if cli_command.startswith("show interface") or cli_command == "show internet status":
            observe_order.append(f"observe:{cli_command.split()[0]}")
        return original_parse(cli_command)

    transport.execute_rci_parse = tracked_parse  # type: ignore[method-assign]

    apply_wifi_station_intent(
        intent=_wifi_wan_intent(),
        transport=transport,  # type: ignore[arg-type]
        credential_resolver=lambda _ref: "synthetic-psk-for-tests-only",
        live_dispatch=True,
        compensate_on_failure=False,
        uplink_settle_seconds=25,
        sleep_fn=lambda _seconds: observe_order.append("sleep"),
    )
    assert observe_order[:1] == ["sleep"]
    assert observe_order.index("sleep") < next(
        i for i, item in enumerate(observe_order) if item.startswith("observe:")
    )


def test_live_dispatch_applies_uplink_observe() -> None:
    sleep_calls: list[float] = []
    transport = LiveDispatchTransport()
    result = apply_wifi_station_intent(
        intent=_wifi_wan_intent(),
        transport=transport,  # type: ignore[arg-type]
        credential_resolver=lambda _ref: "synthetic-psk-for-tests-only",
        live_dispatch=True,
        uplink_settle_seconds=22,
        sleep_fn=lambda seconds: sleep_calls.append(seconds),
    )
    assert sleep_calls == [22.0]
    assert result.overall == "applied"
    assert result.uplink_verification_status == "uplink_verified_bounded"
    assert "show internet status" in transport.parse_commands


def test_live_dispatch_settle_zero_never_verified_bounded() -> None:
    transport = LiveDispatchTransport()
    result = apply_wifi_station_intent(
        intent=_wifi_wan_intent(),
        transport=transport,  # type: ignore[arg-type]
        credential_resolver=lambda _ref: "synthetic-psk-for-tests-only",
        live_dispatch=True,
        compensate_on_failure=False,
        uplink_settle_seconds=0,
        sleep_fn=lambda _seconds: None,
    )
    assert result.uplink_verification_status == "uplink_dispatched_unverified"
    assert result.overall == "verify_mismatch"
    assert result.uplink_settle_seconds is None
    assert result.rollback is not None
    assert result.rollback.attempted is False


def test_live_dispatch_associated_no_global_does_not_compensate() -> None:
    sleep_calls: list[float] = []
    transport = LiveDispatchTransport()
    transport.internet_status = {}
    result = apply_wifi_station_intent(
        intent=_wifi_wan_intent(),
        transport=transport,  # type: ignore[arg-type]
        credential_resolver=lambda _ref: "synthetic-psk-for-tests-only",
        live_dispatch=True,
        compensate_on_failure=True,
        uplink_settle_seconds=25,
        sleep_fn=lambda seconds: sleep_calls.append(seconds),
    )
    assert sleep_calls == [25.0]
    assert result.uplink_verification_status == "uplink_associated_no_global"
    assert result.overall == "verify_mismatch"
    assert result.rollback is not None
    assert result.rollback.attempted is False
    logs_text = "\n".join(result.logs)
    assert "uplink_associated_no_global after settle readback" in logs_text
    assert "uplink recheck unchanged: uplink_associated_no_global" in logs_text
    assert transport.parse_commands.count("show internet status") == 2


def test_live_dispatch_settle_first_verified_no_recheck() -> None:
    sleep_calls: list[float] = []
    transport = LiveDispatchTransport()
    result = apply_wifi_station_intent(
        intent=_wifi_wan_intent(),
        transport=transport,  # type: ignore[arg-type]
        credential_resolver=lambda _ref: "synthetic-psk-for-tests-only",
        live_dispatch=True,
        compensate_on_failure=False,
        uplink_settle_seconds=25,
        sleep_fn=lambda seconds: sleep_calls.append(seconds),
    )
    assert sleep_calls == [25.0]
    assert result.uplink_verification_status == "uplink_verified_bounded"
    assert result.overall == "applied"
    logs_text = "\n".join(result.logs)
    assert "uplink recheck" not in logs_text
    assert transport.parse_commands.count("show internet status") == 1


def test_live_dispatch_uplink_failed_premature_recheck_becomes_verified() -> None:
    sleep_calls: list[float] = []
    transport = SequencingRuntimeReadbackTransport(
        runtime_readback_sequence=[
            {"ssid": "", "encryption": "wpa2", "state": "up"},
            {"ssid": "Venue-Guest", "encryption": "wpa2", "state": "up"},
        ]
    )
    result = apply_wifi_station_intent(
        intent=_wifi_wan_intent(),
        transport=transport,  # type: ignore[arg-type]
        credential_resolver=lambda _ref: "synthetic-psk-for-tests-only",
        live_dispatch=True,
        compensate_on_failure=False,
        uplink_settle_seconds=25,
        sleep_fn=lambda seconds: sleep_calls.append(seconds),
    )
    assert sleep_calls == [25.0]
    assert result.uplink_verification_status == "uplink_verified_bounded"
    assert result.overall == "applied"
    logs_text = "\n".join(result.logs)
    assert (
        "uplink_failed after settle readback; "
        "one uplink recheck without additional wait"
    ) in logs_text
    assert "uplink recheck verdict: uplink_failed -> uplink_verified_bounded" in logs_text
    assert transport.parse_commands.count("show internet status") == 2


def test_live_dispatch_no_global_recheck_becomes_verified() -> None:
    sleep_calls: list[float] = []
    transport = SequencingLiveDispatchTransport(
        internet_status_sequence=[
            {},
            {"internet": "yes", "gateway": "yes", "dns": "yes"},
        ]
    )
    result = apply_wifi_station_intent(
        intent=_wifi_wan_intent(),
        transport=transport,  # type: ignore[arg-type]
        credential_resolver=lambda _ref: "synthetic-psk-for-tests-only",
        live_dispatch=True,
        uplink_settle_seconds=25,
        sleep_fn=lambda seconds: sleep_calls.append(seconds),
    )
    assert sleep_calls == [25.0]
    assert result.uplink_verification_status == "uplink_verified_bounded"
    assert result.overall == "applied"
    logs_text = "\n".join(result.logs)
    assert "uplink_associated_no_global after settle readback" in logs_text
    assert (
        "uplink recheck verdict: uplink_associated_no_global -> uplink_verified_bounded"
        in logs_text
    )
    assert transport.parse_commands.count("show internet status") == 2


def test_live_dispatch_unverified_readback_failure_recheck_becomes_verified() -> None:
    sleep_calls: list[float] = []
    transport = FailFirstObserveReadbackTransport()
    result = apply_wifi_station_intent(
        intent=_wifi_wan_intent(),
        transport=transport,  # type: ignore[arg-type]
        credential_resolver=lambda _ref: "synthetic-psk-for-tests-only",
        live_dispatch=True,
        compensate_on_failure=False,
        uplink_settle_seconds=25,
        sleep_fn=lambda seconds: sleep_calls.append(seconds),
    )
    assert sleep_calls == [25.0]
    assert result.uplink_verification_status == "uplink_verified_bounded"
    assert result.overall == "applied"
    logs_text = "\n".join(result.logs)
    assert (
        "uplink_dispatched_unverified after settle readback; "
        "one uplink recheck without additional wait"
    ) in logs_text
    assert (
        "uplink recheck verdict: uplink_dispatched_unverified -> uplink_verified_bounded"
        in logs_text
    )
    assert transport.parse_commands.count("show internet status") == 1


def test_live_dispatch_settle_zero_no_recheck_on_no_global() -> None:
    sleep_calls: list[float] = []
    transport = SequencingLiveDispatchTransport(
        internet_status_sequence=[
            {},
            {"internet": "yes", "gateway": "yes", "dns": "yes"},
        ]
    )
    result = apply_wifi_station_intent(
        intent=_wifi_wan_intent(),
        transport=transport,  # type: ignore[arg-type]
        credential_resolver=lambda _ref: "synthetic-psk-for-tests-only",
        live_dispatch=True,
        compensate_on_failure=False,
        uplink_settle_seconds=0,
        sleep_fn=lambda seconds: sleep_calls.append(seconds),
    )
    assert sleep_calls == []
    assert result.uplink_verification_status == "uplink_associated_no_global"
    assert result.overall == "verify_mismatch"
    assert transport.parse_commands.count("show internet status") == 1
    logs_text = "\n".join(result.logs)
    assert "uplink settle skipped (0s); observe without wait" in logs_text
    assert "uplink recheck" not in logs_text


def test_live_dispatch_settle_zero_no_recheck_on_failed() -> None:
    sleep_calls: list[float] = []
    transport = LiveDispatchTransport()
    transport.runtime_readback = {"ssid": "", "encryption": "wpa2", "state": "up"}
    result = apply_wifi_station_intent(
        intent=_wifi_wan_intent(),
        transport=transport,  # type: ignore[arg-type]
        credential_resolver=lambda _ref: "synthetic-psk-for-tests-only",
        live_dispatch=True,
        compensate_on_failure=False,
        uplink_settle_seconds=0,
        sleep_fn=lambda seconds: sleep_calls.append(seconds),
    )
    assert sleep_calls == []
    assert result.uplink_verification_status == "uplink_failed"
    assert result.overall == "verify_mismatch"
    assert transport.parse_commands.count("show internet status") == 1
    logs_text = "\n".join(result.logs)
    assert "uplink settle skipped (0s); observe without wait" in logs_text
    assert "uplink recheck" not in logs_text


def test_live_dispatch_backup_callback_before_first_write() -> None:
    order: list[str] = []
    transport = LiveDispatchTransport()

    def backup_callback() -> None:
        order.append("backup")

    original_write = transport.execute_sealed_rci_write

    def tracked_write(request: SealedRciWriteRequest) -> Any:
        order.append("write")
        return original_write(request)

    transport.execute_sealed_rci_write = tracked_write  # type: ignore[method-assign]

    apply_wifi_station_intent(
        intent=_wifi_wan_intent(),
        transport=transport,  # type: ignore[arg-type]
        credential_resolver=lambda _ref: "synthetic-psk-for-tests-only",
        live_dispatch=True,
        backup_callback=backup_callback,
        uplink_settle_seconds=25,
        sleep_fn=lambda _seconds: None,
    )
    assert order.index("backup") < order.index("write")


def test_live_dispatch_uplink_failed_compensates() -> None:
    transport = LiveDispatchTransport()
    transport.runtime_readback = {"ssid": "", "encryption": "wpa2", "state": "up"}
    result = apply_wifi_station_intent(
        intent=_wifi_wan_intent(),
        transport=transport,  # type: ignore[arg-type]
        credential_resolver=lambda _ref: "synthetic-psk-for-tests-only",
        live_dispatch=True,
        compensate_on_failure=True,
        uplink_settle_seconds=25,
        sleep_fn=lambda _seconds: None,
    )
    assert result.uplink_verification_status == "uplink_failed"
    assert result.overall == "verify_mismatch"
    assert result.rollback is not None
    assert result.rollback.attempted is True
    assert result.rollback.outcome == "partial"
    assert any(
        item.op == WifiStationRciOperation.IP_GLOBAL.value for item in result.rollback.uncovered_ops
    )


def test_live_dispatch_failure_uplink_unverified() -> None:
    transport = RejectFirstOpTransport()
    transport.wifi_station_offline_only = False  # type: ignore[misc, assignment]
    transport.wifi_station_live_dispatch = True  # type: ignore[attr-defined]
    result = apply_wifi_station_intent(
        intent=_wifi_wan_intent(),
        transport=transport,  # type: ignore[arg-type]
        credential_resolver=lambda _ref: "synthetic-psk-for-tests-only",
        live_dispatch=True,
        compensate_on_failure=True,
        uplink_settle_seconds=0,
        sleep_fn=lambda _seconds: None,
    )
    assert result.overall in {"failed", "rolled_back"}
    assert result.uplink_verification_status == "uplink_dispatched_unverified"
    assert result.uplink_verification_status != "uplink_verified_bounded"
    assert result.errors
    assert any("WifiStationRciError" in err for err in result.errors)
    assert "service.op_dispatch_failed" not in result.errors
    failed_step = next(step for step in result.steps if not step.ok)
    assert failed_step.error is not None
    assert "WifiStationRciError" in failed_step.error
    assert "synthetic-psk" not in failed_step.error.lower()
    assert result.rollback is not None
    assert result.rollback.attempted is True


def test_mid_sequence_failure_compensate_preserves_dispatch_errors() -> None:
    transport = FailOnWriteNumbersTransport(fail_on_writes=frozenset({3, 4, 5, 6, 7}))
    result = apply_wifi_station_intent(
        intent=_wifi_wan_intent(),
        transport=transport,  # type: ignore[arg-type]
        credential_resolver=lambda _ref: "synthetic-psk-for-tests-only",
        compensate_on_failure=True,
    )
    assert result.errors
    assert any("WifiStationRciError" in err for err in result.errors)
    assert "service.op_dispatch_failed" not in result.errors
    assert result.rollback is not None
    assert result.rollback.attempted is True
    assert result.rollback.outcome in {"failed", "partial"}
    assert result.overall == "failed"


def test_non_secret_dispatch_failure_surfaces_informative_detail() -> None:
    transport = RejectFirstOpTransport()
    result = apply_wifi_station_intent(
        intent=_wifi_wan_intent(),
        transport=transport,  # type: ignore[arg-type]
        credential_resolver=lambda _ref: "synthetic-psk-for-tests-only",
        compensate_on_failure=False,
    )
    failed_step = result.steps[0]
    assert failed_step.ok is False
    assert failed_step.op == WifiStationRciOperation.SET_SSID.value
    assert failed_step.error is not None
    assert "WifiStationRciError" in failed_step.error
    assert "device-confirmed pattern" in failed_step.error
    assert result.errors
    assert any("WifiStationRciError" in err for err in result.errors)
    logs_text = "\n".join(result.logs)
    assert "WifiStationRciError" in logs_text
    assert "synthetic-psk" not in logs_text.lower()
    assert "synthetic-psk" not in json.dumps(result.errors).lower()


def test_secret_dispatch_failure_stays_opaque() -> None:
    transport = FailOnWriteNumbersTransport(fail_on_writes=frozenset({4}))
    result = apply_wifi_station_intent(
        intent=_wifi_wan_intent(),
        transport=transport,  # type: ignore[arg-type]
        credential_resolver=lambda _ref: "synthetic-psk-for-tests-only",
        compensate_on_failure=False,
    )
    psk_step = next(
        step for step in result.steps if step.op == WifiStationRciOperation.SET_WPA_PSK.value
    )
    assert psk_step.ok is False
    assert psk_step.error == "service.op_dispatch_failed"
    assert "service.op_dispatch_failed" in result.errors
    assert "synthetic-psk" not in json.dumps(result.errors).lower()
    logs_text = "\n".join(result.logs)
    assert "synthetic-psk" not in logs_text.lower()
    assert "dispatch failed for wifi_station_set_wpa_psk: service.op_dispatch_failed" in logs_text


def test_idempotent_live_never_skips_psk_op() -> None:
    transport = LiveDispatchTransport()
    transport.configured_readback = {"ssid": "Venue-Guest", "encryption": "wpa2"}
    transport.runtime_readback = {"ssid": "Venue-Guest", "encryption": "wpa2", "state": "up"}
    result = apply_wifi_station_intent(
        intent=_wifi_wan_intent(),
        transport=transport,  # type: ignore[arg-type]
        credential_resolver=lambda _ref: "synthetic-psk-for-tests-only",
        live_dispatch=True,
        idempotent=True,
        uplink_settle_seconds=0,
        sleep_fn=lambda _seconds: None,
    )
    psk_steps = [
        step for step in result.steps if step.op == WifiStationRciOperation.SET_WPA_PSK.value
    ]
    assert len(psk_steps) == 1
    assert psk_steps[0].ok is True


def test_ip_global_uncovered_in_rollback_response() -> None:
    transport = LiveDispatchTransport()
    transport.runtime_readback = {"ssid": "", "encryption": "wpa2", "state": "up"}
    result = apply_wifi_station_intent(
        intent=_wifi_wan_intent(),
        transport=transport,  # type: ignore[arg-type]
        credential_resolver=lambda _ref: "synthetic-psk-for-tests-only",
        options=WifiStationPlannerOptions(include_ip_global=True),
        live_dispatch=True,
        compensate_on_failure=True,
        uplink_settle_seconds=25,
        sleep_fn=lambda _seconds: None,
    )
    assert result.uplink_verification_status == "uplink_failed"
    assert result.rollback is not None
    assert result.rollback.attempted is True
    uncovered = {item.op: item.reason for item in result.rollback.uncovered_ops}
    assert WifiStationRciOperation.IP_GLOBAL.value in uncovered
    assert "no sealed negation grammar" in uncovered[WifiStationRciOperation.IP_GLOBAL.value]
    assert result.rollback.outcome == "partial"


def test_non_allowlist_station_id_compile_fails() -> None:
    from router_control.application.wifi_station_apply_planner import (
        compile_uplink_intent_to_station_ops,
    )

    with pytest.raises(ValueError, match="not allowlisted"):
        compile_uplink_intent_to_station_ops(
            _wifi_wan_intent(),
            station_id="WifiMaster1/WifiStation1",
        )

