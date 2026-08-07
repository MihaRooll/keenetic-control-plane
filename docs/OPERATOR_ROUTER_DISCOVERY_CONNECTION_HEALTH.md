## For agents

| Item | Value |
|---|---|
| Purpose | Read-only backend for simple-mode UI: bounded router discovery + connection health summary |
| Routes | `POST /api/router-control/v1/lab/router-discovery`, `POST /api/router-control/v1/lab/connection-health` |
| Certifying | **Never** — both responses always `certification_eligible: false`; do not open Gate A/B/C/D |
| Network | Discovery candidates from local default gateway(s), one conventional first-host (`.1`) per active IPv4 interface **without** a default route, and enrolled endpoint hosts; **no** subnet scan, no free-form probe lists |
| Host routing table | **Windows hub:** default gateway(s) via `Get-NetRoute`; active IPv4 interfaces via `Get-NetIPConfiguration` (`router_control_host/host_route_table.py`); non-Windows returns empty sets (fail-soft) |
| Health green | **All five** facts must be `true`: `reachable`, `host_key_match`, `tuple_match`, `credentials_present`, `evidence_fresh` — null is not healthy |
| Probe ports | **Live host:** soft SSH health probe wired when Gate A open (`build_soft_readonly_health_probe_fn`); discovery `probe=true` uses soft identity adapter (`build_soft_candidate_identity_probe`) over the same health probe. **Fake/offline:** probe absent → yellow `reachability_unknown` (not 422). Discovery `probe=true` without injected port → **422** `probe not configured`. |
| SSOT | API shapes: [`docs/contracts/API_CONTRACT.md`](contracts/API_CONTRACT.md) §7.9.2–7.9.3 |

## Operator summary

### Router discovery

Use when the operator needs “what router might be on this network?” without running the Add-router bootstrap flow.

- Sources: Wi‑Fi/default **gateway** from the hub PC routing table (Windows: live `Get-NetRoute`; other OS: gateway source empty) + **one conventional subnet first-host** (network+1, typically `.1` on /24) per active local IPv4 interface that has **no** default route through it (Windows: `Get-NetIPConfiguration`; other OS: empty) + routers already enrolled in the project database.
- `candidate_origin`: `default_gateway`, `local_subnet_gateway`, or `known_endpoint`.
- Each candidate reports `identity_state`: **known match** (live probe tuple match only), **known mismatch**, or **unknown** (never coerced from missing data).
- Local enrollment + stored pin matching Gate A tuple is **unknown** with `enrollment_match_identity_unverified` until `probe=true` succeeds — not `known_match`.
- Soft-excluded hosts (public gateway, loopback) appear in top-level `excluded_candidates[]` with `reason_code`; they are never probed or listed in `candidates[]`.
- Unknown/mismatch candidates require credentials before writes and never authorize writes from this endpoint.
- Optional `probe=true` runs identity probe **only** for bounded candidates with resolvable credentials **and** a stored SSH host-key pin (or Gate A pin); unenrolled default gateway and local_subnet_gateway candidates are skipped (audit via `probed_hosts`).

### Connection health

Use for a traffic-light summary before deeper wizard steps.

| Status | Meaning (simplified) |
|---|---|
| Green | Reachable, pinned host key matches, identity tuple matches Gate A evidence, credentials resolvable, Gate A evidence fresh |
| Yellow | Reachable but missing/stale/non-critical unknown facts (e.g. stale Gate A opening window, probe unavailable → `reachability_unknown`) |
| Red | Unreachable, host-key mismatch, identity mismatch, or missing credentials |

This endpoint is **read-only** and does not authorize configuration writes.

## Verification checklist (agents)

- [ ] `pytest tests/test_router_discovery.py tests/test_connection_health.py`
- [ ] Worst-case tests prove red→green transitions per fact dimension
- [ ] Bounds test proves probe set never exceeds declared candidates
- [ ] No live network in unit tests (socket monkeypatch / injectable fakes)

## Manifest fields (for UI agent — do not edit manifest here)

| Family | Field | simple/advanced | Route |
|---|---|---|---|
| router_discovery | `include_default_gateway` | simple | `/lab/router-discovery` |
| router_discovery | `include_known_endpoints` | simple | `/lab/router-discovery` |
| router_discovery | `preferred_source_address` | advanced | `/lab/router-discovery` |
| router_discovery | `probe` | advanced | `/lab/router-discovery` |
| connection_health | `router_id` | simple | `/lab/connection-health` |
| connection_health | `host` | simple | `/lab/connection-health` |
| connection_health | `source_address` | advanced | `/lab/connection-health` |
| connection_health | `credential_ref_id` | simple | `/lab/connection-health` |
| connection_health | `ssh_host_key_sha256` | advanced | `/lab/connection-health` |
| connection_health | `probe` | advanced | `/lab/connection-health` |
