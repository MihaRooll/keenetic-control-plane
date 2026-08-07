"""Offline WireGuard intent → sealed op compiler tests."""

from __future__ import annotations

import json

import pytest
from router_control.adapters.netcraze.interface_rci import InterfaceRciOperation
from router_control.adapters.netcraze.wireguard_rci import WireguardRciOperation
from router_control.application.wireguard_apply_planner import (
    _PRESHARED_KEY_UNVERIFIED_NOTE,
    _PRIVATE_KEY_PARTIAL_VERIFIED_NOTE,
    _SECRET_UNVERIFIED_NOTE,
    WG_HANDSHAKE_SETTLE_SECONDS_MAX,
    WG_HANDSHAKE_SETTLE_SECONDS_MIN,
    WireguardApplyPlannerError,
    compile_wireguard_intent_to_ops,
    intent_implies_traffic_routing,
)
from router_control.domain.network_intents import WireguardIntent, WireguardPeerRciShape

_PLACEHOLDER_PEER = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
_PRIVATE_KEY_REF = "credref:awg-private-test"
_ASC_9 = (5, 42, 54, 0, 0, 1, 2, 3, 4)
_ASC_16 = (5, 42, 54, 0, 0, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0)

_APPLY_OPS_ENABLED = (
    WireguardRciOperation.CREATE_INTERFACE,
    WireguardRciOperation.SET_ASC,
    InterfaceRciOperation.UP,
)

_TEARDOWN_OPS = (
    InterfaceRciOperation.DOWN,
    WireguardRciOperation.REMOVE_INTERFACE,
)


def _intent(**overrides: object) -> WireguardIntent:
    base = {
        "wg_id": "Wireguard5",
        "enabled": True,
        "asc_args": _ASC_9,
    }
    base.update(overrides)
    return WireguardIntent(**base)  # type: ignore[arg-type]


def test_handshake_settle_constants_match_ip_global_band() -> None:
    assert WG_HANDSHAKE_SETTLE_SECONDS_MIN == 20
    assert WG_HANDSHAKE_SETTLE_SECONDS_MAX == 30


def test_intent_implies_traffic_routing_from_allow_ips() -> None:
    assert intent_implies_traffic_routing(_intent(peer_allow_ips="10.0.0.0/8"))
    assert not intent_implies_traffic_routing(_intent())
    assert not intent_implies_traffic_routing(_intent(peer_allow_ips="   "))
    assert not intent_implies_traffic_routing(_intent(peer_allow_ips=None))


def test_planner_notes_include_interface_address_configuration() -> None:
    plan = compile_wireguard_intent_to_ops(_intent())
    assert any("SET_IP_ADDRESS" in note or "interface Address compiles" in note for note in plan.notes)


def test_wireguard_rci_has_interface_address_operations() -> None:
    op_values = {op.value for op in WireguardRciOperation}
    assert WireguardRciOperation.SET_IP_ADDRESS.value in op_values
    assert WireguardRciOperation.IP_GLOBAL.value in op_values


def test_clamp_handshake_settle_seconds() -> None:
    from router_control.application.wireguard_apply_planner import clamp_handshake_settle_seconds

    assert clamp_handshake_settle_seconds(0) == 0.0
    assert clamp_handshake_settle_seconds(-1) == 0.0
    assert clamp_handshake_settle_seconds(5) == 20.0
    assert clamp_handshake_settle_seconds(25) == 25.0
    assert clamp_handshake_settle_seconds(100) == 30.0


def test_asc9_full_apply_and_teardown_sequence() -> None:
    plan = compile_wireguard_intent_to_ops(_intent())
    assert plan.verification_status == "device_verified_asc9"
    assert [op.operation for op in plan.apply_ops] == [op.value for op in _APPLY_OPS_ENABLED]
    assert [op.operation for op in plan.teardown_ops] == [op.value for op in _TEARDOWN_OPS]
    assert any("show interface peer fields only" in note for note in plan.notes)
    assert any("NOT read show rc" in note for note in plan.notes)
    assert plan.apply_ops[1].asc_args == "5 42 54 0 0 1 2 3 4"
    assert all(op.wg_id == "Wireguard5" for op in plan.apply_ops)


def test_create_only_when_disabled_without_asc() -> None:
    plan = compile_wireguard_intent_to_ops(
        WireguardIntent(wg_id="Wireguard6", enabled=False, asc_args=None)
    )
    assert plan.verification_status == "device_verified_asc9"
    assert len(plan.apply_ops) == 1
    assert plan.apply_ops[0].operation == WireguardRciOperation.CREATE_INTERFACE.value
    assert len(plan.teardown_ops) == 2


def test_create_and_up_without_asc() -> None:
    plan = compile_wireguard_intent_to_ops(
        WireguardIntent(wg_id="Wireguard7", enabled=True, asc_args=None)
    )
    assert [op.operation for op in plan.apply_ops] == [
        WireguardRciOperation.CREATE_INTERFACE.value,
        InterfaceRciOperation.UP.value,
    ]


@pytest.mark.parametrize("wg_id", ["Wireguard0", "Wireguard4", "Wireguard10", "Bridge0"])
def test_rejects_non_test_interfaces(wg_id: str) -> None:
    with pytest.raises(ValueError, match="allowlisted"):
        compile_wireguard_intent_to_ops(_intent(wg_id=wg_id))


def test_accepts_wireguard0_in_expendable_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")
    plan = compile_wireguard_intent_to_ops(_intent(wg_id="Wireguard0"), wg_id="Wireguard0")
    assert plan.apply_ops
    assert plan.teardown_ops


def test_16_arg_flagged_unsupported_pending_verification() -> None:
    plan = compile_wireguard_intent_to_ops(_intent(asc_args=_ASC_16))
    assert plan.verification_status == "unsupported_pending_verification"
    assert plan.apply_ops == ()
    assert plan.teardown_ops == ()
    assert any("NOT-DEVICE-VERIFIED" in note for note in plan.notes)


def test_wg_id_mismatch_fails_closed() -> None:
    with pytest.raises(WireguardApplyPlannerError, match="does not match"):
        compile_wireguard_intent_to_ops(_intent(), wg_id="Wireguard6")


def test_negative_asc_args_rejected_by_planner() -> None:
    negative = list(_ASC_9)
    negative[2] = -1
    with pytest.raises(WireguardApplyPlannerError, match="non-negative"):
        compile_wireguard_intent_to_ops(_intent(asc_args=tuple(negative)))


def test_secret_ops_compile_pending_live_verification() -> None:
    intent = _intent(
        asc_args=None,
        private_key_credential_ref_id=_PRIVATE_KEY_REF,
        peer_public_key=_PLACEHOLDER_PEER,
        peer_endpoint="vpn.example.com:51820",
        peer_allow_ips="10.0.0.0/24",
        peer_keepalive_interval=25,
    )
    plan = compile_wireguard_intent_to_ops(intent)
    assert plan.verification_status == "pending_live_verification"
    op_names = [op.operation for op in plan.apply_ops]
    assert op_names[0] == WireguardRciOperation.CREATE_INTERFACE.value
    assert WireguardRciOperation.SET_PRIVATE_KEY.value in op_names
    assert WireguardRciOperation.UPSERT_PEER_NESTED.value in op_names
    assert WireguardRciOperation.ADD_PEER.value not in op_names
    nested = next(
        op
        for op in plan.apply_ops
        if op.operation == WireguardRciOperation.UPSERT_PEER_NESTED.value
    )
    assert nested.peer_endpoint == "vpn.example.com:51820"
    assert nested.peer_allow_ips == "10.0.0.0/24"
    assert nested.peer_keepalive_interval == 25
    for op in plan.apply_ops:
        assert getattr(op, "secret", None) is None
        serialized = json.dumps(
            {
                "operation": op.operation,
                "credential_ref_id": op.credential_ref_id,
                "peer_public_key": op.peer_public_key,
            }
        )
        assert "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" not in serialized
    assert any("path-style" in note for note in plan.notes)


def test_private_key_op_partial_device_verified_note() -> None:
    intent = _intent(
        asc_args=None,
        private_key_credential_ref_id=_PRIVATE_KEY_REF,
        peer_public_key=_PLACEHOLDER_PEER,
        peer_endpoint="vpn.example.com:51820",
        preshared_key_credential_ref_id="cred_test_psk_ref",
    )
    plan = compile_wireguard_intent_to_ops(intent)
    assert plan.verification_status == "pending_live_verification"

    private_key_op = next(
        op
        for op in plan.apply_ops
        if op.operation == WireguardRciOperation.SET_PRIVATE_KEY.value
    )
    assert _PRIVATE_KEY_PARTIAL_VERIFIED_NOTE in private_key_op.notes
    assert _SECRET_UNVERIFIED_NOTE not in private_key_op.notes
    assert "end-to-end tunnel" not in _PRIVATE_KEY_PARTIAL_VERIFIED_NOTE.lower()

    nested_peer = next(
        op
        for op in plan.apply_ops
        if op.operation == WireguardRciOperation.UPSERT_PEER_NESTED.value
    )
    assert nested_peer.credential_ref_id == "cred_test_psk_ref"
    assert _PRESHARED_KEY_UNVERIFIED_NOTE in nested_peer.notes

    clear_private_key_op = next(
        op
        for op in plan.teardown_ops
        if op.operation == WireguardRciOperation.CLEAR_PRIVATE_KEY.value
    )
    assert _SECRET_UNVERIFIED_NOTE in clear_private_key_op.notes
    assert _PRIVATE_KEY_PARTIAL_VERIFIED_NOTE not in clear_private_key_op.notes


def test_default_nested_rci_when_peer_rci_shape_omitted() -> None:
    intent = _intent(
        asc_args=None,
        private_key_credential_ref_id=_PRIVATE_KEY_REF,
        peer_public_key=_PLACEHOLDER_PEER,
        peer_endpoint="vpn.example.com:51820",
    )
    plan = compile_wireguard_intent_to_ops(intent)
    op_names = [op.operation for op in plan.apply_ops]
    assert WireguardRciOperation.UPSERT_PEER_NESTED.value in op_names
    assert WireguardRciOperation.ADD_PEER.value not in op_names
    assert all(
        op.peer_rci_shape in (None, WireguardPeerRciShape.NESTED_RCI.value)
        for op in plan.apply_ops
        if op.peer_public_key is not None or op.operation.endswith("peer")
    )


def test_explicit_path_style_rejected_unsupported() -> None:
    intent = _intent(
        asc_args=None,
        private_key_credential_ref_id=_PRIVATE_KEY_REF,
        peer_public_key=_PLACEHOLDER_PEER,
        peer_endpoint="vpn.example.com:51820",
        peer_rci_shape=WireguardPeerRciShape.PATH_STYLE,
    )
    plan = compile_wireguard_intent_to_ops(intent)
    assert plan.verification_status == "unsupported"
    assert plan.apply_ops == ()
    assert plan.teardown_ops == ()
    assert any("REJECTED" in note for note in plan.notes)


def test_apply_ops_rejects_path_style_direct_call() -> None:
    """Fail-closed: internal _apply_ops must not emit path-style peer ops."""
    from router_control.application.wireguard_apply_planner import _apply_ops

    intent = _intent(
        asc_args=None,
        private_key_credential_ref_id=_PRIVATE_KEY_REF,
        peer_public_key=_PLACEHOLDER_PEER,
        peer_endpoint="vpn.example.com:51820",
        peer_rci_shape=WireguardPeerRciShape.PATH_STYLE,
    )
    with pytest.raises(WireguardApplyPlannerError, match="path_style"):
        _apply_ops(intent, "Wireguard5")


def test_tunnel_observe_note_device_confirmed_not_pending_live() -> None:
    plan = compile_wireguard_intent_to_ops(_intent())
    tunnel_notes = [note for note in plan.notes if "Tunnel health" in note]
    assert tunnel_notes
    combined = " ".join(tunnel_notes)
    assert "DEVICE-CONFIRMED" in combined
    assert "pending_live_verification" not in combined.lower()
    assert "NOT device-confirmed" not in combined
    all_notes = " ".join(plan.notes)
    assert "interface Address compiles" in all_notes
    assert "NOT device-proven egress" in all_notes
    assert "end-to-end tunnel" not in all_notes.lower()


def test_ipv6_peer_allow_ips_refused_by_planner() -> None:
    intent = _intent(
        asc_args=None,
        private_key_credential_ref_id=_PRIVATE_KEY_REF,
        peer_public_key=_PLACEHOLDER_PEER,
        peer_endpoint="vpn.example.com:51820",
        peer_allow_ips="0.0.0.0/0, ::/0",
    )
    with pytest.raises(WireguardApplyPlannerError, match=r"::/0"):
        compile_wireguard_intent_to_ops(intent)


def test_nested_rci_emits_single_upsert_op() -> None:
    intent = _intent(
        asc_args=None,
        private_key_credential_ref_id=_PRIVATE_KEY_REF,
        preshared_key_credential_ref_id="cred_test_psk_ref",
        peer_public_key=_PLACEHOLDER_PEER,
        peer_endpoint="vpn.example.com:51820",
        peer_allow_ips="10.0.0.0/24",
        peer_keepalive_interval=25,
        peer_rci_shape=WireguardPeerRciShape.NESTED_RCI,
    )
    plan = compile_wireguard_intent_to_ops(intent)
    peer_ops = [
        op
        for op in plan.apply_ops
        if op.operation
        in (
            WireguardRciOperation.ADD_PEER.value,
            WireguardRciOperation.SET_PEER_ENDPOINT.value,
            WireguardRciOperation.SET_PEER_ALLOW_IPS.value,
            WireguardRciOperation.SET_PEER_KEEPALIVE.value,
            WireguardRciOperation.SET_PRESHARED_KEY.value,
            WireguardRciOperation.UPSERT_PEER_NESTED.value,
        )
    ]
    assert len(peer_ops) == 1
    nested = peer_ops[0]
    assert nested.operation == WireguardRciOperation.UPSERT_PEER_NESTED.value
    assert nested.peer_rci_shape == WireguardPeerRciShape.NESTED_RCI.value
    assert nested.credential_ref_id == "cred_test_psk_ref"
    assert nested.peer_endpoint == "vpn.example.com:51820"
    assert any("peer[] array" in note for note in nested.notes)
    assert _PRESHARED_KEY_UNVERIFIED_NOTE in nested.notes
    assert _SECRET_UNVERIFIED_NOTE not in nested.notes
    assert WireguardRciOperation.SET_PRIVATE_KEY.value in [op.operation for op in plan.apply_ops]


def test_compensate_ops_for_succeeded_wireguard_apply_reverse_order() -> None:
    from router_control.adapters.netcraze.interface_rci import InterfaceRciOperation
    from router_control.application.wireguard_apply_planner import (
        compensate_ops_for_succeeded_wireguard_apply,
        uncovered_compensate_ops_for_succeeded_wireguard_apply,
    )

    intent = WireguardIntent(
        wg_id="Wireguard5",
        enabled=True,
        asc_args=(5, 42, 54, 0, 0, 1, 2, 3, 4),
        private_key_credential_ref_id="credref:test",
        peer_public_key="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
    )
    plan = compile_wireguard_intent_to_ops(intent)
    succeeded = (
        WireguardRciOperation.CREATE_INTERFACE.value,
        WireguardRciOperation.SET_PRIVATE_KEY.value,
        WireguardRciOperation.UPSERT_PEER_NESTED.value,
        WireguardRciOperation.SET_ASC.value,
        InterfaceRciOperation.UP.value,
    )
    compensate = compensate_ops_for_succeeded_wireguard_apply(plan.apply_ops, succeeded)
    assert [op.operation for op in compensate] == [
        InterfaceRciOperation.DOWN.value,
        WireguardRciOperation.REMOVE_PEER.value,
        WireguardRciOperation.CLEAR_PRIVATE_KEY.value,
        WireguardRciOperation.REMOVE_INTERFACE.value,
    ]
    uncovered = uncovered_compensate_ops_for_succeeded_wireguard_apply(plan.apply_ops, succeeded)
    assert uncovered == (("wireguard_set_asc", "no sealed negation grammar (unverified)"),)


def test_compensate_skips_remove_when_interface_pre_existed() -> None:
    from router_control.adapters.netcraze.interface_rci import InterfaceRciOperation
    from router_control.adapters.netcraze.wireguard_rci import WireguardRciOperation
    from router_control.application.wireguard_apply_planner import (
        WireguardApplyPreState,
        compensate_ops_for_succeeded_wireguard_apply,
        uncovered_compensate_ops_for_succeeded_wireguard_apply,
    )

    intent = WireguardIntent(wg_id="Wireguard5", enabled=True, asc_args=None)
    plan = compile_wireguard_intent_to_ops(intent)
    succeeded = (WireguardRciOperation.CREATE_INTERFACE.value, InterfaceRciOperation.UP.value)
    pre_state = WireguardApplyPreState(known=True, interface_existed=True, was_admin_up=False)
    compensate = compensate_ops_for_succeeded_wireguard_apply(
        plan.apply_ops, succeeded, pre_state=pre_state
    )
    assert [op.operation for op in compensate] == [InterfaceRciOperation.DOWN.value]
    uncovered = dict(
        uncovered_compensate_ops_for_succeeded_wireguard_apply(
            plan.apply_ops, succeeded, pre_state=pre_state
        )
    )
    assert "wireguard_create_interface" in uncovered
    assert "pre-existing" in uncovered["wireguard_create_interface"]


def test_compensate_unknown_pre_state_is_fail_closed() -> None:
    from router_control.adapters.netcraze.wireguard_rci import WireguardRciOperation
    from router_control.application.wireguard_apply_planner import (
        WireguardApplyPreState,
        compensate_ops_for_succeeded_wireguard_apply,
        uncovered_compensate_ops_for_succeeded_wireguard_apply,
    )

    intent = WireguardIntent(wg_id="Wireguard5", enabled=False, asc_args=None)
    plan = compile_wireguard_intent_to_ops(intent)
    succeeded = (WireguardRciOperation.CREATE_INTERFACE.value,)
    pre_state = WireguardApplyPreState(known=False)
    assert compensate_ops_for_succeeded_wireguard_apply(
        plan.apply_ops, succeeded, pre_state=pre_state
    ) == ()
    uncovered = dict(
        uncovered_compensate_ops_for_succeeded_wireguard_apply(
            plan.apply_ops, succeeded, pre_state=pre_state
        )
    )
    assert "pre-apply state unknown" in uncovered["wireguard_create_interface"]


def test_derive_pre_state_wrong_interface_is_unknown_fail_closed() -> None:
    from router_control.adapters.netcraze.wireguard_rci import WireguardRciOperation
    from router_control.application.wireguard_apply_planner import (
        compensate_ops_for_succeeded_wireguard_apply,
        derive_wireguard_pre_state,
        uncovered_compensate_ops_for_succeeded_wireguard_apply,
    )
    from router_control.domain.network_intents import WireguardIntent

    observed = {
        "id": "Wireguard4",
        "state": "up",
        "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
        "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    }
    pre_state = derive_wireguard_pre_state(observed, wg_id="Wireguard5")
    assert pre_state.known is False

    intent = WireguardIntent(wg_id="Wireguard5", enabled=True, asc_args=None)
    plan = compile_wireguard_intent_to_ops(intent)
    succeeded = (WireguardRciOperation.CREATE_INTERFACE.value,)
    compensate = compensate_ops_for_succeeded_wireguard_apply(
        plan.apply_ops, succeeded, pre_state=pre_state
    )
    assert compensate == ()
    uncovered = dict(
        uncovered_compensate_ops_for_succeeded_wireguard_apply(
            plan.apply_ops, succeeded, pre_state=pre_state
        )
    )
    assert "pre-apply state unknown" in uncovered[WireguardRciOperation.CREATE_INTERFACE.value]


def test_derive_pre_state_empty_observed_is_unknown() -> None:
    from router_control.application.wireguard_apply_planner import derive_wireguard_pre_state

    pre_state = derive_wireguard_pre_state({}, wg_id="Wireguard5")
    assert pre_state.known is False


def test_derive_pre_state_missing_public_key_is_unknown_not_absent() -> None:
    from router_control.adapters.netcraze.wireguard_rci import WireguardRciOperation
    from router_control.application.wireguard_apply_planner import (
        compensate_ops_for_succeeded_wireguard_apply,
        derive_wireguard_pre_state,
        uncovered_compensate_ops_for_succeeded_wireguard_apply,
    )

    observed = {"id": "Wireguard5", "state": "up"}
    pre_state = derive_wireguard_pre_state(observed, wg_id="Wireguard5")
    assert pre_state.had_private_key is None

    intent = WireguardIntent(wg_id="Wireguard5", enabled=True, asc_args=None)
    plan = compile_wireguard_intent_to_ops(intent)
    succeeded = (WireguardRciOperation.SET_PRIVATE_KEY.value,)
    compensate = compensate_ops_for_succeeded_wireguard_apply(
        plan.apply_ops, succeeded, pre_state=pre_state
    )
    assert WireguardRciOperation.CLEAR_PRIVATE_KEY.value not in [
        op.operation for op in compensate
    ]
    uncovered = dict(
        uncovered_compensate_ops_for_succeeded_wireguard_apply(
            plan.apply_ops, succeeded, pre_state=pre_state
        )
    )
    assert "private-key state unknown" in uncovered[WireguardRciOperation.SET_PRIVATE_KEY.value]


def test_compensate_blocks_down_when_admin_up_unknown() -> None:
    from router_control.adapters.netcraze.interface_rci import InterfaceRciOperation
    from router_control.application.wireguard_apply_planner import (
        WireguardApplyPreState,
        compensate_ops_for_succeeded_wireguard_apply,
        uncovered_compensate_ops_for_succeeded_wireguard_apply,
    )

    intent = WireguardIntent(wg_id="Wireguard5", enabled=True, asc_args=None)
    plan = compile_wireguard_intent_to_ops(intent)
    succeeded = (InterfaceRciOperation.UP.value,)
    pre_state = WireguardApplyPreState(
        known=True,
        interface_existed=False,
        was_admin_up=None,
    )
    compensate = compensate_ops_for_succeeded_wireguard_apply(
        plan.apply_ops, succeeded, pre_state=pre_state
    )
    assert compensate == ()
    uncovered = dict(
        uncovered_compensate_ops_for_succeeded_wireguard_apply(
            plan.apply_ops, succeeded, pre_state=pre_state
        )
    )
    assert "admin-up state unknown" in uncovered[InterfaceRciOperation.UP.value]


def test_planner_emits_set_tcp_mss_before_up() -> None:
    from router_control.application.wireguard_apply_planner import (
        _TCP_MSS_UNVERIFIED_CLEAR_NOTE,
        compensate_ops_for_succeeded_wireguard_apply,
    )

    intent = WireguardIntent(
        wg_id="Wireguard5",
        enabled=True,
        asc_args=_ASC_9,
        tcp_mss_pmtu=True,
    )
    plan = compile_wireguard_intent_to_ops(intent)
    ops = [op.operation for op in plan.apply_ops]
    assert WireguardRciOperation.SET_TCP_MSS.value in ops
    assert ops.index(WireguardRciOperation.SET_TCP_MSS.value) < ops.index(
        InterfaceRciOperation.UP.value
    )
    teardown_ops = [op.operation for op in plan.teardown_ops]
    assert WireguardRciOperation.CLEAR_TCP_MSS.value in teardown_ops
    clear_tcp = next(
        op for op in plan.teardown_ops if op.operation == WireguardRciOperation.CLEAR_TCP_MSS.value
    )
    assert _TCP_MSS_UNVERIFIED_CLEAR_NOTE in clear_tcp.notes

    succeeded = (
        WireguardRciOperation.CREATE_INTERFACE.value,
        WireguardRciOperation.SET_ASC.value,
        WireguardRciOperation.SET_TCP_MSS.value,
        InterfaceRciOperation.UP.value,
    )
    compensate = compensate_ops_for_succeeded_wireguard_apply(plan.apply_ops, succeeded)
    assert WireguardRciOperation.CLEAR_TCP_MSS.value in [op.operation for op in compensate]
