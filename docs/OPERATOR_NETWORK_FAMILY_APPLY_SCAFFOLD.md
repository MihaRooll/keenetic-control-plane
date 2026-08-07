# Network-family apply security scaffold (offline; mechanics-ready, apply disabled)

## For agents

| Topic | Rule |
|---|---|
| Scope | VLAN, DHCP, DNS, firewall, VPN policy-routing — **preview + offline service scaffold only** |
| HTTP | **No** `/apply` or `/teardown` routes for these families; OpenAPI must stay preview-only |
| Live dispatch | Fail-closed without `*_offline_only` transport marker; no composition wiring |
| PreState | `derive_*_pre_state` without sealed family parser → `known=False`; never invent True/False from raw dicts |
| VPN probe | Only documented empty `show ip policy` → `policy_existed=False`; empty name-server → `had_name_servers=False`; else field `None` + fail-closed |
| Compensation | Paired teardown ops only (see table); blocked when pre-existing or unknown |
| Uncovered | `dhcp_set_lease` (no sealed lease-clear); `vpn_policy_ip_global` (no sealed negation; do **not** map to `IP_GLOBAL_TEARDOWN_UNVERIFIED`) |
| Services | `compensate_on_failure=False` default; optional `store` + `SealedApplyTrailParams` → `begin/guard/finish` trail hooks |
| verification_status | VLAN/DHCP/DNS/firewall: `offline_unverified`; VPN: `help_verified_grammar_unapplied` — **not** device-verified |

## Field determinability

| Family | Field | Determinable? | Evidence | Unknown behavior |
|---|---|---|---|---|
| vlan | bridge_existed | No | No sealed Bridge show parser | `known=False` or field `None`; block destructive compensate |
| vlan | had_ip | No | No family IP readback model | same |
| vlan | was_admin_up | No | Generic show interface not bound to VLAN apply | same |
| dhcp | pool_existed | No | No show ip dhcp parser | same |
| dhcp | had_lease | No | No lease readback | same |
| dhcp | had_reservations | No | No bind inventory parser | same |
| dns | had_static_host | No | No ip host inventory parser | same |
| dns | had_upstreams | No | Non-empty name-server shapes unparsed for local DNS | same |
| firewall | had_rules | No | No access-list show parser; ordinal collision risk | same |
| vpn_policy | policy_existed | Partial | Documented empty `show ip policy` → `False` | Non-empty/unknown → `None`; block remove if unknown/pre-existing |
| vpn_policy | had_name_servers | Partial | Documented empty `show ip name-server` → `False` | Else `None`; block clear if unknown/pre-existing |
| vpn_policy | had_ip_global | No | No sealed read form for global binding | Always unknown; `ip_global` compensate uncovered |

## Compensation map (confirmed pairs only)

| Family | Apply op | Compensate op |
|---|---|---|
| vlan | create_bridge | remove_bridge |
| vlan | set_ip_address | clear_ip_address |
| vlan | up | down |
| dhcp | set_pool | clear_pool |
| dhcp | bind_host | unbind_host |
| dns | set_static_host | clear_static_host |
| dns | set_upstream | clear_upstream |
| firewall | add_rule | remove_rule |
| vpn_policy | create | remove |
| vpn_policy | set_name_server | clear_name_server |

## Uncovered ops (explicit, not silently mapped)

| Op | Reason |
|---|---|
| `dhcp_set_lease` | no sealed lease-clear op |
| `vpn_policy_ip_global` | no sealed negation grammar (unverified) |

## Mechanics note

PreState, compensation APIs, typed `ApplyOverallStatus` / `ApplyRollbackOutcome`, and sealed-trail hook points exist in application services so future Gate B live apply can reuse the same paths. **`compensate_on_failure` defaults off**; HTTP apply remains absent until explicit certification and route work.

## Related

- Sealed Wi‑Fi / WireGuard apply (device-verified families): existing planners/services
- Preview HTTP: `tests/test_network_family_preview_api.py`, `tests/test_vpn_policy_preview_api.py`
- Property invariants: `tests/test_planner_properties.py`
