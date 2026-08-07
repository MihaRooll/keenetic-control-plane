# ADR-005: Local-first commissioning roadmap

- Status: Accepted
- Date: 2026-07-22
- Supersedes: [ADR-004](0004-product-capability-scope.md) **§Capability order only** (execution ordering / milestone DAG)
- Scope: commissioning milestone order, parallel deferred lanes, M1–M3 bounds

## Context

ADR-004 fixed product scope, certified target, VPN policy, route scale, TrafficDiscovery
proposals, Hub non-blocking, and strangler cutover. Its **Capability order** section
placed AmneziaWG write certification and managed routes **before** TrafficDiscovery,
NetworkPolicy, local DNS/readiness, durable worker, planner, and combined LAN rehearsal.

Phase 1 SLICE-6 AWG trial (2026-07-21) closed **completed_failed**
(`certification_failed_all_candidates_handshake`). WriteCertified was **not** claimed;
write shapes remain unregistered. Treating AWG/routes as critical-path predecessors blocks
local-first commissioning work that does not require router writes.

Event booth architecture also requires explicit ownership: **NC-1812** is the sole
L3/DHCP/DNS/firewall/AP policy owner; **Hub PC** is application/control plane only.
A managed L2 switch and UPS are recommended so Hub–printer L2 adjacency survives router
reboot; the router remains the network SPOF for Wi-Fi/DHCP/DNS.

## Decision

### Milestone DAG (normative execution order)

```text
M0 docs rebaseline (this ADR + ROADMAP sync) ──► complete 2026-07-22
         │
         ▼
M1 read-only commissioning MVP ──► M2 offline event preset/readiness ──► M3 durable worker
         │                              │                                    │
         └──────────────┬───────────────┴────────────────────────────────────┘
                        ▼
                   M4 recovery substrate
                        │
                        ▼
         M5 independent per-family certification (AWG, routes, … parallel families)
                        │
                        ▼
                   M6 combined commissioning rehearsal
                        │
                        ▼
                   M7 Hub module_3.0 integration
                        │
                        ▼
                   M8 signed central pull (later)
```

### Parallel deferred lanes (not predecessors of M1–M4 or M6)

These lanes may proceed only under their own human gates and evidence packages.
They **do not** block M1–M3 offline/read-only implementation:

- **AWG write certification** — post failed B/C trial; shape discovery + new human packet
  before any WriteCertified claim or lab re-open ([`gate-b-awg-certification-result.json`](../gate-b-awg-certification-result.json)).
- **Managed routes** — benchmark and Gate B per-family evidence when authorized.
- **LTE / SIM uplink** — out of M1–M3 scope until separately certified.

TrafficDiscovery proposals (SLICE-8 offline) are **not** blocked behind routes for
readiness/commissioning modeling; auto-apply remains gated by policy and write certification.

### M1–M3 bounds (authorized offline/read-only code only)

| Milestone | In scope | Explicitly out |
|-----------|----------|----------------|
| **M1** | Read-only commissioning MVP; enroll/preflight/identity using existing Gate A RO only | Router writes; new gate opens |
| **M2** | Offline event preset + readiness modeling | Live mutations; Hub UI |
| **M3** | Durable worker / job durability offline | Signed pull; Hub `module_3.0`; generic/raw RCI; frontend claim |

Shared constraints for M1–M3:

- No router writes.
- Live I/O only existing Gate A read-only tuple.
- No signed central pull implementation.
- No Hub `module_3.0` integration.
- No UI frontend claim.
- No generic/raw RCI endpoint.

### ADR-004 decisions retained unchanged

ADR-004 remains authoritative for: certified target tuple, VPN AmneziaWG-only scope,
fail-closed unknown capability, route-scale benchmark policy, TrafficDiscovery as
proposals-only bounded context, event four-zone preset, Hub failure isolation, and
strangler cutover rules. Only **§Capability order** is superseded by this ADR and
[`ROADMAP.md`](../contracts/ROADMAP.md).

### Network ownership (architecture fact)

- **NC-1812**: sole owner of L3 routing, DHCP, DNS, firewall, and AP/Wi-Fi policy on the event LAN.
- **Hub PC**: application/control plane (orders, board, printing, Router Control API); not a network policy authority.
- **Managed L2 switch + UPS** (recommended): preserve Hub–printer and other fixed L2 adjacency during router reboot.
- **Explicit limitation**: router remains network SPOF for Wi-Fi, DHCP, and DNS until a separately approved design says otherwise.

## Consequences

- [`ROADMAP.md`](../contracts/ROADMAP.md) is the normative milestone contract; SLICE history remains as completed evidence, not current critical path.
- STATUS `next_task` advances to M1; AWG shape discovery is a parallel deferred lane note, not M1 predecessor.
- Agents must not claim AWG/routes/LTE block M1–M3 offline work.
- WriteCertified and Gate B/C re-open still require sanitized evidence and explicit human approval.

## Rejected alternatives

- Keep AWG→routes→TrafficDiscovery linear order as critical path after failed AWG trial.
- Block commissioning/readiness on WriteCertified AWG.
- Treat Hub PC as DHCP/DNS/firewall owner for the event LAN.

## Compliance

Decision is satisfied when:

- ADR-004 §Capability order is marked superseded with pointer here;
- ROADMAP lists M0–M8 with entry/exit/evidence/stop per milestone;
- STATUS records 2026-07-22 M1–M3 offline/read-only authorization;
- Gate A ReadOnlyCertified tuple and B/C/D trial facts are preserved unchanged;
- No doc claims all gates closed, Gate A is next, or Netcraze adapter is future-only.
