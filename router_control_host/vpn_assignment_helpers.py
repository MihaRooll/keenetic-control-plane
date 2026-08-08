"""Re-export shared VPN tunnel-assignment helpers from application layer."""

from router_control.application.vpn_assignment_helpers import (
    assignment_policy_metadata,
    coerce_peer_rci_shape,
    merge_teardown_metadata,
    resolve_assignment_wg_id,
    wireguard_intent_from_metadata_dict,
)

__all__ = [
    "assignment_policy_metadata",
    "coerce_peer_rci_shape",
    "merge_teardown_metadata",
    "resolve_assignment_wg_id",
    "wireguard_intent_from_metadata_dict",
]
