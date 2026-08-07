"""VPN policy-routing planner tests (AC-D3)."""

from __future__ import annotations

import pytest
from router_control.adapters.netcraze.vpn_policy_rci import VpnPolicyRciOperation, command_for
from router_control.application.vpn_policy_routing_planner import (
    VpnPolicyRoutingPlannerError,
    compile_vpn_policy_routing_intent,
)
from router_control.application.vpn_policy_routing_service import preview_vpn_policy_routing


def _non_wg_intent(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "policy_name": "vpn-uplink",
        "vpn_interface": "GigabitEthernet1",
        "interface_kind": "other",
        "ip_global": {"priority": 700},
        "name_servers": [{"address": "1.1.1.1"}],
    }
    base.update(overrides)
    return base


def test_planner_happy_path_non_wg() -> None:
    plan = compile_vpn_policy_routing_intent(_non_wg_intent())
    assert plan.verification_status == "help_verified_grammar_unapplied"
    assert [op.operation for op in plan.apply_ops] == [
        VpnPolicyRciOperation.SET_NAME_SERVER.value,
        VpnPolicyRciOperation.IP_GLOBAL.value,
        VpnPolicyRciOperation.CREATE_POLICY.value,
    ]
    cli = command_for(
        VpnPolicyRciOperation.IP_GLOBAL,
        interface_id=plan.vpn_interface,
        global_priority=700,
    )
    assert cli == "interface GigabitEthernet1 ip global 700"


def test_planner_wg_without_address_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")
    with pytest.raises(VpnPolicyRoutingPlannerError) as exc_info:
        compile_vpn_policy_routing_intent(
            {
                "policy_name": "vpn-wg",
                "vpn_interface": "Wireguard0",
                "interface_kind": "wireguard",
                "address_configured": False,
                "ip_global": "auto",
            }
        )
    message = str(exc_info.value)
    assert "Address is NOT configured" in message
    assert "no sealed" in message


def test_planner_wg0_refuses_without_address_when_lab_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wireguard0 must refuse on name pattern alone — not via write allowlist."""
    monkeypatch.delenv("ROUTER_CONTROL_LAB_CLASS", raising=False)
    with pytest.raises(VpnPolicyRoutingPlannerError) as exc_info:
        compile_vpn_policy_routing_intent(
            {
                "policy_name": "vpn-wg",
                "vpn_interface": "Wireguard0",
                "ip_global": "auto",
            }
        )
    message = str(exc_info.value)
    assert "canonical WireguardN" in message or "Address is NOT configured" in message
    assert "refusing non-canonical" in message or "no sealed" in message


def test_planner_unknowns_include_section_five_questions() -> None:
    plan = compile_vpn_policy_routing_intent(_non_wg_intent())
    joined = "\n".join(plan.unknowns)
    assert "single connection" in joined
    assert "without permit global" in joined
    assert "ipv6/route" in joined.lower() or "ipv6" in joined
    assert "WireGuard interface ip global" in joined or "WireGuard" in joined
    assert ":200" in joined
    assert ":201" in joined
    assert ":202" in joined
    assert ":203" in joined


def test_planner_wg_unknown_cites_section_five_four_and_interface() -> None:
    plan = compile_vpn_policy_routing_intent(
        {
            "policy_name": "vpn-wg",
            "vpn_interface": "Wireguard5",
            "interface_kind": "wireguard",
            "address_configured": True,
            "ip_global": "auto",
        }
    )
    wg_unknowns = [
        u
        for u in plan.unknowns
        if "Wireguard5" in u and "WG ip global unconfirmed" in u
    ]
    assert len(wg_unknowns) == 1
    assert ":203" in wg_unknowns[0]
    assert "§5.4" in wg_unknowns[0]


def test_planner_rejects_invalid_name_server_domain() -> None:
    with pytest.raises(ValueError, match="invalid name-server domain"):
        compile_vpn_policy_routing_intent(
            _non_wg_intent(name_servers=[{"address": "1.1.1.1", "domain": "not a fqdn!!!"}])
        )


def test_planner_rejects_bool_ip_global_order() -> None:
    with pytest.raises(VpnPolicyRoutingPlannerError) as exc_info:
        compile_vpn_policy_routing_intent(_non_wg_intent(ip_global={"order": True}))
    assert "ip global order must be integer" in str(exc_info.value)


def test_planner_rejects_negative_ip_global_priority() -> None:
    with pytest.raises(VpnPolicyRoutingPlannerError) as exc_info:
        compile_vpn_policy_routing_intent(_non_wg_intent(ip_global={"priority": -1}))
    message = str(exc_info.value)
    assert "ip global priority must be in range 0..65535" in message
    assert "wifi_station_rci" in message


def test_planner_rejects_ip_global_priority_above_sealed_max() -> None:
    with pytest.raises(VpnPolicyRoutingPlannerError) as exc_info:
        compile_vpn_policy_routing_intent(_non_wg_intent(ip_global={"priority": 100_000}))
    message = str(exc_info.value)
    assert "ip global priority must be in range 0..65535" in message
    assert "wifi_station_rci" in message


def test_planner_rejects_ip_global_order_out_of_range() -> None:
    with pytest.raises(VpnPolicyRoutingPlannerError) as exc_info:
        compile_vpn_policy_routing_intent(_non_wg_intent(ip_global={"order": 70000}))
    message = str(exc_info.value)
    assert "ip global order must be in range 0..65535" in message


_DOC_CITATION = (
    "docs/OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md"
    "#2b-read-only-observed-grammar-verified-from-help"
)
_UNCONFIRMED_MARKER = "grammar source not fixed (источник не зафиксирован)"

_GRAMMAR_CITATION_EXPECTATIONS: tuple[tuple[str, str], ...] = (
    (VpnPolicyRciOperation.SET_NAME_SERVER.value, _DOC_CITATION),
    (VpnPolicyRciOperation.IP_GLOBAL.value, _DOC_CITATION),
    (VpnPolicyRciOperation.CREATE_POLICY.value, _DOC_CITATION),
    (VpnPolicyRciOperation.REMOVE_POLICY.value, _DOC_CITATION),
    (
        VpnPolicyRciOperation.IP_GLOBAL_TEARDOWN_UNVERIFIED.value,
        _UNCONFIRMED_MARKER,
    ),
    (VpnPolicyRciOperation.CLEAR_NAME_SERVER.value, _UNCONFIRMED_MARKER),
)


def test_planner_ops_notes_include_grammar_source_citations() -> None:
    plan = compile_vpn_policy_routing_intent(
        _non_wg_intent(
            name_servers=[
                {"address": "1.1.1.1"},
                {"address": "8.8.8.8", "domain": "example.com"},
            ]
        )
    )
    ops_by_kind = {op.operation: op for op in (*plan.apply_ops, *plan.teardown_ops)}
    for operation, expected_citation in _GRAMMAR_CITATION_EXPECTATIONS:
        assert operation in ops_by_kind, f"missing op {operation}"
        notes_text = " ".join(ops_by_kind[operation].notes)
        assert expected_citation in notes_text, (
            f"{operation} notes missing citation {expected_citation!r}: {notes_text!r}"
        )


def test_teardown_is_reverse_of_apply() -> None:
    plan = compile_vpn_policy_routing_intent(
        _non_wg_intent(
            name_servers=[
                {"address": "1.1.1.1"},
                {"address": "8.8.8.8", "domain": "example.com"},
            ]
        )
    )
    assert [op.operation for op in plan.teardown_ops] == [
        VpnPolicyRciOperation.REMOVE_POLICY.value,
        VpnPolicyRciOperation.IP_GLOBAL_TEARDOWN_UNVERIFIED.value,
        VpnPolicyRciOperation.CLEAR_NAME_SERVER.value,
        VpnPolicyRciOperation.CLEAR_NAME_SERVER.value,
    ]
    assert plan.teardown_ops[-2].name_server_address == "8.8.8.8"
    assert plan.teardown_ops[-1].name_server_address == "1.1.1.1"


def test_preview_service_verification_status() -> None:
    preview = preview_vpn_policy_routing(_non_wg_intent())
    assert preview["verification_status"] == "help_verified_grammar_unapplied"
    assert [op["operation"] for op in preview["apply_ops"]] == [
        VpnPolicyRciOperation.SET_NAME_SERVER.value,
        VpnPolicyRciOperation.IP_GLOBAL.value,
        VpnPolicyRciOperation.CREATE_POLICY.value,
    ]
    ip_global_op = preview["apply_ops"][1]
    assert ip_global_op["interface_id"] == "GigabitEthernet1"
    assert ip_global_op["global_priority"] == 700
    assert any(_DOC_CITATION in note for note in ip_global_op["notes"])
    assert [op["operation"] for op in preview["teardown_ops"]] == [
        VpnPolicyRciOperation.REMOVE_POLICY.value,
        VpnPolicyRciOperation.IP_GLOBAL_TEARDOWN_UNVERIFIED.value,
        VpnPolicyRciOperation.CLEAR_NAME_SERVER.value,
    ]
    assert preview["unknowns"]


_NON_CANONICAL_WIREGUARD_INTERFACE_NAMES: tuple[str, ...] = (
    "wireguard0",
    "WIREGUARD0",
    "WireGuard0",
    "Wireguard",
    "Wireguard00",
    "Wireguard 0",
    "Wire guard0",
    "Wireguard-0",
    "Wireguard_0",
    "wg0",
    "WG0",
    "Wireguard999999",
    "Wireguard-1",
)


@pytest.mark.parametrize("vpn_interface", _NON_CANONICAL_WIREGUARD_INTERFACE_NAMES)
def test_planner_refuses_non_canonical_wireguard_interface_names(
    vpn_interface: str,
) -> None:
    with pytest.raises(VpnPolicyRoutingPlannerError) as exc_info:
        compile_vpn_policy_routing_intent(
            {
                "policy_name": "vpn-wg",
                "vpn_interface": vpn_interface,
                "ip_global": "auto",
            }
        )
    message = str(exc_info.value)
    assert "canonical WireguardN" in message
    assert vpn_interface in message


def test_planner_canonical_wireguard0_passes_with_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")
    plan = compile_vpn_policy_routing_intent(
        {
            "policy_name": "vpn-wg",
            "vpn_interface": "Wireguard0",
            "interface_kind": "wireguard",
            "address_configured": True,
            "ip_global": "auto",
        }
    )
    assert plan.vpn_interface == "Wireguard0"


def test_planner_wireguard_like_outcomes_table(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Document expected planner outcomes for adversarial interface-name probes."""
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")

    def compile_minimal(vpn_interface: str) -> str:
        try:
            compile_vpn_policy_routing_intent(
                {
                    "policy_name": "vpn-wg",
                    "vpn_interface": vpn_interface,
                    "ip_global": "auto",
                }
            )
            return "plan_ok"
        except VpnPolicyRoutingPlannerError as exc:
            msg = str(exc)
            if "canonical WireguardN" in msg:
                return "refuse_non_canonical"
            if "Address is NOT configured" in msg:
                return "refuse_address_not_configured"
            return f"planner_error:{msg[:40]}"
        except ValueError as exc:
            return f"value_error:{exc}"

    expectations: dict[str, str] = {
        "wireguard0": "refuse_non_canonical",
        "WIREGUARD0": "refuse_non_canonical",
        "WireGuard0": "refuse_non_canonical",
        "Wireguard": "refuse_non_canonical",
        "Wireguard00": "refuse_non_canonical",
        "Wireguard 0": "refuse_non_canonical",
        "Wireguard0 ": "refuse_address_not_configured",
        "Wireguard0\n": "refuse_address_not_configured",
        "Wire guard0": "refuse_non_canonical",
        "W1reguard0": "plan_ok",
        "Wireguard-0": "refuse_non_canonical",
        "Wireguard_0": "refuse_non_canonical",
        "wg0": "refuse_non_canonical",
        "WG0": "refuse_non_canonical",
        "Wir\u0435guard0": "value_error:interface id contains disallowed characters",
        "GigabitEthernet1Wireguard0": "plan_ok",
        "Wireguard999999": "refuse_non_canonical",
        "Wireguard-1": "refuse_non_canonical",
        "Wireguard0\x00": "refuse_non_canonical",
        "-Wireguard0": "refuse_non_canonical",
        "Wireguard\t0": "refuse_non_canonical",
    }
    for name, expected in expectations.items():
        assert compile_minimal(name) == expected, f"{name!r} -> {compile_minimal(name)!r}"


def test_planner_wireguard_like_charset_refusal_precedence() -> None:
    """Wireguard-like names refuse on canonical WireguardN before charset validation.

    Semantically actionable refusal for adversarial wireguard spellings (-Wireguard0,
    Wireguard<TAB>0). Non-wireguard-like homoglyphs (Cyrillic е) still hit charset check.
    """
    for vpn_interface in ("-Wireguard0", "Wireguard\t0"):
        with pytest.raises(VpnPolicyRoutingPlannerError) as exc_info:
            compile_vpn_policy_routing_intent(
                {
                    "policy_name": "vpn-wg",
                    "vpn_interface": vpn_interface,
                    "ip_global": "auto",
                }
            )
        message = str(exc_info.value)
        assert "canonical WireguardN" in message
        assert "disallowed characters" not in message

    with pytest.raises(ValueError, match="interface id contains disallowed characters"):
        compile_vpn_policy_routing_intent(
            {
                "policy_name": "vpn-wg",
                "vpn_interface": "Wir\u0435guard0",
                "ip_global": "auto",
            }
        )


def test_vpn_policy_rci_rejects_ip_global_priority_above_sealed_max() -> None:
    with pytest.raises(ValueError) as exc_info:
        command_for(
            VpnPolicyRciOperation.IP_GLOBAL,
            interface_id="GigabitEthernet1",
            global_priority=70000,
        )
    message = str(exc_info.value)
    assert "ip global priority must be in range 0..65535" in message
    assert "wifi_station_rci" in message


def test_ip_global_is_uncovered_for_compensation() -> None:
    from router_control.adapters.netcraze.vpn_policy_probe import VpnPolicyParseStatus
    from router_control.application.vpn_policy_routing_planner import (
        compensate_ops_for_succeeded_vpn_policy_apply,
        derive_vpn_policy_pre_state,
        uncovered_compensate_ops_for_succeeded_vpn_policy_apply,
    )

    plan = compile_vpn_policy_routing_intent(_non_wg_intent())
    succeeded = (VpnPolicyRciOperation.IP_GLOBAL.value,)
    pre_state = derive_vpn_policy_pre_state(
        policy_parse_status=VpnPolicyParseStatus.ZERO_POLICIES.value,
        name_server_parse_status=VpnPolicyParseStatus.EMPTY.value,
    )
    assert compensate_ops_for_succeeded_vpn_policy_apply(
        plan.apply_ops, succeeded, pre_state=pre_state
    ) == ()
    uncovered = dict(
        uncovered_compensate_ops_for_succeeded_vpn_policy_apply(
            plan.apply_ops, succeeded, pre_state=pre_state
        )
    )
    assert (
        uncovered[VpnPolicyRciOperation.IP_GLOBAL.value]
        == "no sealed negation grammar (unverified)"
    )


def test_derive_pre_state_empty_probe_classifications() -> None:
    from router_control.adapters.netcraze.vpn_policy_probe import VpnPolicyParseStatus
    from router_control.application.vpn_policy_routing_planner import derive_vpn_policy_pre_state

    pre_state = derive_vpn_policy_pre_state(
        policy_parse_status=VpnPolicyParseStatus.ZERO_POLICIES.value,
        name_server_parse_status=VpnPolicyParseStatus.EMPTY.value,
    )
    assert pre_state.known is True
    assert pre_state.policy_existed is False
    assert pre_state.had_name_servers is False
    assert pre_state.had_ip_global is None


def test_derive_pre_state_unknown_probe_status_is_not_known() -> None:
    from router_control.adapters.netcraze.vpn_policy_probe import VpnPolicyParseStatus
    from router_control.application.vpn_policy_routing_planner import derive_vpn_policy_pre_state

    pre_state = derive_vpn_policy_pre_state(
        policy_parse_status=VpnPolicyParseStatus.UNKNOWN.value,
        name_server_parse_status=VpnPolicyParseStatus.UNKNOWN.value,
    )
    assert pre_state.known is False


def test_compensate_duplicate_name_servers_preserves_addresses() -> None:
    from router_control.adapters.netcraze.vpn_policy_probe import VpnPolicyParseStatus
    from router_control.application.vpn_policy_routing_planner import (
        compensate_ops_for_succeeded_vpn_policy_apply,
        derive_vpn_policy_pre_state,
    )

    plan = compile_vpn_policy_routing_intent(
        _non_wg_intent(
            name_servers=[
                {"address": "8.8.8.8"},
                {"address": "1.1.1.1"},
            ]
        )
    )
    name_server_ops = [
        op
        for op in plan.apply_ops
        if op.operation == VpnPolicyRciOperation.SET_NAME_SERVER.value
    ]
    succeeded = tuple(op.operation for op in name_server_ops)
    pre_state = derive_vpn_policy_pre_state(
        policy_parse_status=VpnPolicyParseStatus.ZERO_POLICIES.value,
        name_server_parse_status=VpnPolicyParseStatus.EMPTY.value,
    )
    compensate = compensate_ops_for_succeeded_vpn_policy_apply(
        plan.apply_ops, succeeded, pre_state=pre_state
    )
    assert [op.operation for op in compensate] == [
        VpnPolicyRciOperation.CLEAR_NAME_SERVER.value,
        VpnPolicyRciOperation.CLEAR_NAME_SERVER.value,
    ]
    assert [op.name_server_address for op in compensate] == ["1.1.1.1", "8.8.8.8"]


def test_compensate_first_name_server_only_on_fail_stop() -> None:
    from router_control.adapters.netcraze.vpn_policy_probe import VpnPolicyParseStatus
    from router_control.application.vpn_policy_routing_planner import (
        compensate_ops_for_succeeded_vpn_policy_apply,
        derive_vpn_policy_pre_state,
    )

    plan = compile_vpn_policy_routing_intent(
        _non_wg_intent(
            name_servers=[
                {"address": "8.8.8.8"},
                {"address": "1.1.1.1"},
            ]
        )
    )
    name_server_ops = tuple(
        op
        for op in plan.apply_ops
        if op.operation == VpnPolicyRciOperation.SET_NAME_SERVER.value
    )
    succeeded = (VpnPolicyRciOperation.SET_NAME_SERVER.value,)
    pre_state = derive_vpn_policy_pre_state(
        policy_parse_status=VpnPolicyParseStatus.ZERO_POLICIES.value,
        name_server_parse_status=VpnPolicyParseStatus.EMPTY.value,
    )
    compensate = compensate_ops_for_succeeded_vpn_policy_apply(
        name_server_ops, succeeded, pre_state=pre_state
    )
    assert len(compensate) == 1
    assert compensate[0].operation == VpnPolicyRciOperation.CLEAR_NAME_SERVER.value
    assert compensate[0].name_server_address == "8.8.8.8"
