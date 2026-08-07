"""Cross-cutting invariants for network-family security scaffold."""

from __future__ import annotations

import pytest
from router_control.adapters.netcraze.dhcp_rci import DhcpRciOperation
from router_control.adapters.netcraze.transport import SealedRciWriteRequest
from router_control.adapters.netcraze.vpn_policy_rci import VpnPolicyRciOperation
from router_control.application.apply_types import ApplyOverallStatus, ApplyRollbackOutcome
from router_control.application.dhcp_apply_planner import (
    DhcpApplyPreState,
    derive_dhcp_pre_state,
    uncovered_compensate_ops_for_succeeded_dhcp_apply,
)
from router_control.application.dhcp_apply_service import (
    DhcpApplyServiceError,
    apply_dhcp_intent,
)
from router_control.application.dns_apply_planner import derive_dns_pre_state
from router_control.application.firewall_apply_planner import derive_firewall_pre_state
from router_control.application.vlan_apply_planner import derive_vlan_pre_state
from router_control.application.vlan_apply_service import (
    VlanApplyServiceError,
    apply_vlan_intent,
)
from router_control.application.vpn_policy_routing_planner import derive_vpn_policy_pre_state
from router_control.application.vpn_policy_routing_service import (
    VpnPolicyRoutingServiceError,
    apply_vpn_policy_routing_intent,
)


def test_all_families_derive_unknown_without_sealed_parsers() -> None:
    assert derive_vlan_pre_state({"any": "observation"}).known is False
    assert derive_dhcp_pre_state({"any": "observation"}).known is False
    assert derive_dns_pre_state({"any": "observation"}).known is False
    assert derive_firewall_pre_state({"any": "observation"}).known is False
    assert derive_vpn_policy_pre_state().known is False


def test_uncovered_ops_are_honest_not_silent() -> None:
    from router_control.application.dhcp_apply_planner import compile_dhcp_intent_to_ops

    plan = compile_dhcp_intent_to_ops(
        {
            "zone_id": "Guest",
            "pool_start": "10.10.0.100",
            "pool_end": "10.10.0.200",
            "lease_seconds": 86400,
            "reservations": [],
        }
    )
    succeeded = (DhcpRciOperation.SET_LEASE.value,)
    uncovered = uncovered_compensate_ops_for_succeeded_dhcp_apply(
        plan.apply_ops,
        succeeded,
        pre_state=DhcpApplyPreState(known=True, pool_existed=False, had_lease=False),
    )
    assert uncovered == ((DhcpRciOperation.SET_LEASE.value, "no sealed lease-clear op"),)


class _OfflineMarkerTransport:
    vlan_offline_only = True
    dhcp_offline_only = True
    vpn_policy_offline_only = True

    def execute_sealed_rci_write(self, request: SealedRciWriteRequest) -> list[dict[str, object]]:
        raise AssertionError("dispatch must not run without explicit offline test transport")


def test_live_apply_still_fail_closed_without_transport() -> None:
    with pytest.raises(VlanApplyServiceError, match="live VLAN apply dispatch is disabled"):
        apply_vlan_intent(
            intent={
                "zone_id": "staff",
                "vlan_id": 20,
                "ipv4_cidr": "10.20.0.0/24",
                "ipv4_gateway": "10.20.0.1",
            },
            bridge_id="Bridge3",
            transport=None,
        )
    with pytest.raises(DhcpApplyServiceError, match="live DHCP apply dispatch is disabled"):
        apply_dhcp_intent(
            intent={
                "zone_id": "Guest",
                "pool_start": "10.10.0.100",
                "pool_end": "10.10.0.200",
                "lease_seconds": 86400,
                "reservations": [],
            },
            transport=None,
        )
    with pytest.raises(
        VpnPolicyRoutingServiceError,
        match="live VPN policy apply dispatch is disabled",
    ):
        apply_vpn_policy_routing_intent(
            intent={
                "policy_name": "vpn-uplink",
                "vpn_interface": "GigabitEthernet1",
                "interface_kind": "other",
                "ip_global": {"priority": 700},
            },
            transport=None,
        )


def test_apply_status_literals_are_closed_sets() -> None:
    from typing import get_args

    assert "rolled_back" in get_args(ApplyOverallStatus)
    assert "partial" in get_args(ApplyRollbackOutcome)


def test_vpn_ip_global_not_mapped_to_teardown_unverified_for_compensation() -> None:
    from router_control.application.vpn_policy_routing_planner import (
        compensate_ops_for_succeeded_vpn_policy_apply,
        compile_vpn_policy_routing_intent,
    )

    plan = compile_vpn_policy_routing_intent(
        {
            "policy_name": "vpn-uplink",
            "vpn_interface": "GigabitEthernet1",
            "interface_kind": "other",
            "ip_global": {"priority": 700},
        }
    )
    compensate = compensate_ops_for_succeeded_vpn_policy_apply(
        plan.apply_ops,
        (VpnPolicyRciOperation.IP_GLOBAL.value,),
        pre_state=derive_vpn_policy_pre_state(),
    )
    assert all(
        op.operation != VpnPolicyRciOperation.IP_GLOBAL_TEARDOWN_UNVERIFIED.value
        for op in compensate
    )
