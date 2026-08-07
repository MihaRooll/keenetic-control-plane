# Implementation roadmap contract

## For agents

| Check | Action |
|---|---|
| Phase | **P3 shared typed executor complete** (2026-07-22; offline/default-deny; Certified registry empty; **not live-ready**); both fail-safe trials **completed_failed**; **2026-08-05:** first handshake + traffic via tunnel **device-verified** (§M-24..§M-27); station apply **live** (§M-34); **current `next_task`:** `local-hub-vpn-real-peer-autoconnect-continuation` — [`STATUS.yaml`](../STATUS.yaml); active handoff [`SESSION_HANDOFF_REAL_ROUTER_2026-08-02.md`](../SESSION_HANDOFF_REAL_ROUTER_2026-08-02.md) |
| Gates | **A** **ReadOnlyCertified** (authorized rebind **2026-07-31** rebind #2 post-WG; evidence `data/artifacts/gate-a-probe-post-wireguard-install-192.168.2.1-20260731.json`; rebind #1 `gate-a-probe-newrouter-…` **SUPERSEDED**); **NOT** WriteCertified; **B** `completed_failed` / `not_write_certified`; **C** closed `completed_failed`; **D** closed — **WriteCertified not claimed**; `write_shapes_registered` remains **false** |
| Ordering SSOT | Milestone DAG **M0→M8** per [ADR-0005](../adrs/0005-local-first-commissioning-roadmap.md); supersedes ADR-004 §Capability order only |
| Deferred lanes | AWG write certification, managed routes, LTE/SIM, **portable rack / WISP client uplink** — **parallel**, not predecessors of M1–M3; **dedicated NC-1812 HW validation program** authorized for Gate A RO + offline prep — **non-expendable / out-of-envelope** live mutations still require fresh exact **T4** per campaign; **expendable** bounded autonomous work when `ROUTER_CONTROL_LAB_CLASS=expendable_development_router` and live device matches recorded tuple — [`DEDICATED_ROUTER_LAB_POLICY.md`](../DEDICATED_ROUTER_LAB_POLICY.md) §1a (**NOT** WriteCertified; Gates B/C/D unchanged) |
| M1–M3 bounds | No router writes; live I/O Gate A RO only; no signed pull; no Hub `module_3.0`; **LOCAL HUB PWA + prototype UI exist** (`router_control_host/web/`); bounded live apply paths **device-verified** for VPN handshake/traffic and station (§M-24..§M-35); no generic/raw RCI |
| Authorization | User authorization 2026-07-22: M1–M3 offline/read-only code only — see [`STATUS.yaml`](../STATUS.yaml) and [`AI_HANDOFF.md`](AI_HANDOFF.md) |
| Hub isolation | Router Control failure must not block kiosk, board, printing, or Hub startup ([`ARCHITECTURE.md`](../ARCHITECTURE.md)) |
| Trace | [`RCI_POLICY.md`](RCI_POLICY.md), [`HARDWARE_GATES.md`](HARDWARE_GATES.md), [`PERSISTENCE_CONTRACT.md`](PERSISTENCE_CONTRACT.md), [`API_CONTRACT.md`](API_CONTRACT.md), [`TEST_STRATEGY.md`](TEST_STRATEGY.md), [`SCENARIOS.md`](SCENARIOS.md) |

---

## 1. Purpose and scope

This document is the **normative implementation roadmap** between Phase 0b contracts and production commissioning. It defines the **local-first milestone DAG** (M0–M8), entry/exit/evidence/stop conditions, and **parallel deferred lanes** (AWG, routes, LTE).

**Ordering authority:** [ADR-0005](../adrs/0005-local-first-commissioning-roadmap.md) supersedes [ADR-004](../adrs/0004-product-capability-scope.md) §Capability order only. ADR-004 certified target, VPN scope, fail-closed writes, route benchmark, TrafficDiscovery proposals, Hub non-blocking, and cutover rules remain binding.

**Completed foundation (historical, not current critical path):** Phase 0b closed; SLICE-1 portable core; offline mega SLICE-2/3/5/8; SLICE-4 Gate A read-only adapter; SLICE-6 AWG trial closed failed (2026-07-21) — see [`gate-b-awg-certification-result.json`](../gate-b-awg-certification-result.json).

**Global entry gate (M1+ code):** M0 complete in [`STATUS.yaml`](../STATUS.yaml) **and** recorded M1–M3 offline/read-only authorization **and** applicable slice/milestone scope in STATUS. Live observe requires Gate **A** open; writes require Gates **B/C/D** per family — currently fail-closed.

---

## 2. Milestone DAG (M0–M8)

```text
M0 docs rebaseline ──► M1 RO commissioning MVP ──► M2 event preset/readiness ──► M3 durable worker
                              │                           │                              │
                              └─────────────┬─────────────┴──────────────────────────────┘
                                            ▼
                                     M4 recovery substrate
                                            ▼
                          M5 per-family certification (parallel families inside milestone)
                                            ▼
                                     M6 combined LAN rehearsal
                                            ▼
                                     M7 Hub module_3.0 integration
                                            ▼
                                     M8 signed central pull (later)

Parallel deferred (not blocking M1–M4/M6):
  • Dedicated NC-1812 HW validation program (Gate A RO + offline prep/docs only until P1–P3 verify green; live mutations require P1–P3 + fresh exact T4 per campaign)
  • AWG write lane (post failed B/C trial)
  • Managed routes lane
  • LTE / SIM uplink lane
```

### M0 — Local-first roadmap rebaseline (docs only)

| Field | Content |
|---|---|
| **Entry** | Principal approval of rebaseline plan; preserve gate evidence |
| **Exit** | ADR-0005 accepted; ROADMAP/STATUS/project-state/docs-map synced; stale AWG-linear navigation removed |
| **Evidence** | This file + ADR-0005 + STATUS `current_phase: m0-local-first-roadmap-rebaseline` complete |
| **Stop** | Do not change product Python in M0; do not open write gates |

### M1 — Read-only commissioning MVP

| Field | Content |
|---|---|
| **Status** | **Complete** (2026-07-22) |
| **Entry** | M0 complete; M1–M3 offline authorization recorded; Gate **A** ReadOnlyCertified tuple unchanged |
| **Exit** | Commissioning MVP: enroll/preflight/identity/readiness paths on fake + optional Gate A RO; offline tests green |
| **Evidence** | TEST lanes 1–2 + optional lane 4 (Gate A RO); no write dispatch |
| **Stop** | Any router write attempt; opening Gate B/C/D; claiming WriteCertified |
| **Out of scope** | Router writes; new gate opens; Hub embed; signed pull; UI frontend |

### M2 — Offline event preset / readiness

| Field | Content |
|---|---|
| **Status** | **Complete** (2026-07-22) |
| **Entry** | M1 exit; same authorization bounds |
| **Exit** | Event preset and readiness modeling offline; four-zone intent documented in domain/application without live mutation |
| **Evidence** | Fake/recorded tests; SCN-EVT trace where applicable; no live writes |
| **Stop** | Live NetworkPolicy apply; Hub UI claims |
| **Out of scope** | Live mutations; Hub `module_3.0`; signed pull |

### M3 — Durable worker / job durability ✅ complete (2026-07-22)

| Field | Content |
|---|---|
| **Entry** | M2 exit; persistence contract satisfied |
| **Exit** | Worker claim/lease/fencing/recovery offline; per-router serialization demonstrated |
| **Evidence** | `router_control.application.worker`, `tests/test_worker_*.py`; PERSISTENCE §4.5 renew/complete |
| **Stop** | Long router I/O inside SQLite txn; signed central pull; generic/raw RCI |
| **Out of scope** | Signed pull; Hub module_3.0; frontend; live writes |

### UI presentation — prototype management surface ✅ complete (2026-07-22)

| Field | Content |
|---|---|
| **Entry** | M3 exit; principal-approved UI auth/CSP/buildless SPA architecture |
| **Exit** | Buildless SPA `/settings/router-control` on prototype host; M1–M3 views; hub_admin gate; theme/a11y |
| **Evidence** | `router_control_host/web/*`, `tests/test_ui_*.py`; [`OPERATOR_UI.md`](../OPERATOR_UI.md) |
| **Stop** | Hub `module_3.0` embed claims; Apply when Gate B not WriteCertified; secrets in DOM |
| **Out of scope** | Hub integration; live commissioning writes; npm/CDN/framework build |

### M4 — Recovery substrate ✅ complete (2026-07-22)

| Field | Content |
|---|---|
| **Status** | **Complete** (2026-07-22) |
| **Entry** | M3 exit |
| **Exit** | RecoveryRequired / compensation paths specified and tested offline — **not live-ready** |
| **Evidence** | SCN-JOB-* recovery rows; persistence fault injection |
| **Stop** | Blind retry without identity/read-back |

### M5 — Independent per-family certification

| Field | Content |
|---|---|
| **Status** | **Offline framework complete** (2026-07-22); live campaigns pending |
| **Entry** | M4 exit; explicit human gate per capability family |
| **Exit (offline slice)** | Per-family catalog (`fail_safe`, `vlan`, `dhcp`, `dns`, `wifi`, `firewall`, `amneziawg`, `routes`); empty/default-deny shape registries; evidence manifest schema; read discovery catalog; offline planner/runner/CLI — **no dispatch** |
| **Exit (live slice)** | Sanitized Gate B (+ C lab when applicable) evidence per family; **WriteCertified** only with STATUS update |
| **Evidence** | `router_control/adapters/netcraze/certification_framework.py`, `docs/netcraze-source-catalog.json`, `docs/schemas/netcraze-evidence-manifest.schema.json`, `scripts/plan-gate-b-family.py`; HARDWARE_GATES checklists |
| **Stop** | Inventing RCI shapes; conflating trial authorization with WriteCertified; planner/runner dispatch |
| **First live campaign** | **Fail-safe discovery/certification Human Gate** (exact T4 packet required) |
| **Note** | AWG lane resumes here as **one family** — not a predecessor of M1–M4 |

### M6 — Combined commissioning rehearsal

| Field | Content |
|---|---|
| **Entry** | M5 families required for rehearsal scope certified or explicitly simulated |
| **Exit** | End-to-end LAN rehearsal script offline + optional RO observe; rollback documented |
| **Evidence** | SCN-CUT-* / commissioning checklist; no silent production cutover |
| **Stop** | Production Gate D without rehearsal evidence |

### M7 — Hub `module_3.0` integration

| Field | Content |
|---|---|
| **Entry** | Prototype parity on M1–M6 scope; Hub maintainer approval |
| **Exit** | Mechanical embed; shared listener; failure isolation verified |
| **Evidence** | ARCHITECTURE §9; integration tests on fake adapter |
| **Stop** | Blocking Hub startup on RC failure |

### M8 — Signed central pull (later)

| Field | Content |
|---|---|
| **Entry** | Separate authorization; M7 optional depending on deployment |
| **Exit** | Signed pull protocol implemented and tested |
| **Evidence** | Security review + contract amendment |
| **Stop** | Unsigned or ad-hoc remote control plane |

---

## 3. Parallel deferred lanes

These lanes run **only** under their own human gates. They do **not** block M1–M3.

| Lane | Status (2026-07-22) | Next when pursued |
|---|---|---|
| **Dedicated NC-1812 HW validation** | Program authorized 2026-07-22; Gate A RO + offline prep in scope | **Non-expendable / out-of-envelope** live mutations require fresh exact **T4** Human Gate per campaign; **expendable** bounded autonomous envelope per [`DEDICATED_ROUTER_LAB_POLICY.md`](../DEDICATED_ROUTER_LAB_POLICY.md) §1a when lab_class + live tuple match — **NOT** WriteCertified; program auth ≠ standing write approval |
| **AWG writes** | Trial **completed_failed**; shapes unregistered | Sanitized shape discovery + new human packet ([`OPERATOR_GATE_B_C_AWG.md`](../OPERATOR_GATE_B_C_AWG.md)) |
| **Managed routes** | Not benchmarked; Gate B not WriteCertified | M5 family certification when authorized |
| **LTE / SIM uplink** | Out of v1 commissioning scope | Separate compatibility lane |
| **Portable rack / WISP client uplink** | Domain `UplinkIntent` extended (2026-07-31); bounded grammar probe **device-confirmed** offline (`device_accepted_grammar`); first association **bounded persisted** (`uplink_verified_bounded`, 5 GHz WPA2); planner **unsupported** / `wifi_wan_not_certified`; HTTP `POST /wifi/station/apply` + `/wifi/station/teardown` **device-verified live 2026-08-05** (§M-34) | See §3.2 — broader association scenarios **T4-gated** |

### 3.2 Portable rack / WISP client uplink (parallel deferred)

Honest gap lane for field-technician portable equipment rack — venue Wi‑Fi client, wired fallback, planned cellular. **Does not** open Gate A/B/C/D or claim WriteCertified. Scenario SSOT: [`SCENARIO_PORTABLE_EQUIPMENT_RACK.md`](../SCENARIO_PORTABLE_EQUIPMENT_RACK.md).

**Hazards (read before station code):**

| Hazard | Impact |
|---|---|
| Management cut-off | Station misconfig isolates router management |
| Same-band AP+station coupling | Rebroadcast + client on one radio may fail (unverified) |
| Evil-twin / SSID spoof | Without `bssid` pin, wrong AP association risk |
| Venue DNS / captive hijack | Breaks VPN, order page, or Hub reachability |
| No kill-switch / unresolved policy grammar | Vendor `ip policy permit global` probe **rejected** (`no such command: global`); kill-switch **unresolved**; no policy-routing in repo; VPN drop may leak — see [`OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md`](../OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md) |
| Connectivity ↔ component download | WireGuard/AmneziaWG install needs NDSS/internet; venue Wi‑Fi needs station + upstream credentials; `component unavailable` ≠ unsupported — pre-provision before field ship |
| Gate A STALE | *(Historical — superseded 2026-07-31 authorized rebind; Gate A ReadOnlyCertified.)* |

**Ordered work items:**

| # | Work item | Lane | Depends on |
|---|---|---|---|
| 1 | `UplinkIntent` WifiWan parse/validate + captive_portal_client marker + priority | **offline-buildable** | Done (2026-07-31 foundation) |
| 2 | Scenario doc + gap register + ROADMAP hazards | **offline-buildable** | Done (2026-07-31 foundation) |
| 3 | Planner/readiness blockers (`wifi_wan_not_certified`, captive client finding) | **offline-buildable** | Done (2026-07-31 foundation) |
| 4 | Device recon — Wi‑Fi station RCI grammar (sanitized evidence only) | **offline-buildable** (bounded probe 2026-07-31) | Done — evidence `station-wisp-grammar-probe-20260731.json`; first association **bounded persisted** |
| 5 | Sealed station uplink ops + allowlist (if evidence supports) | **offline-buildable** (grammar compile + ack verify) | #4; live dispatch **T4-gated** + Gate B family cert |
| 6 | Captive portal **client** automation (distinct from host Coova-Chilli) | **live/T4-gated** | #4–5 + unknown vendor behavior |
| 7 | Multi-uplink failover / policy-routing (optional) | **blocked** — design on open questions | Help grammar captured 2026-07-31; vendor `permit global` probe **rejected**; kill-switch **unresolved**; see [`OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md`](../OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md) §5 |
| 8 | LTE / USB modem uplink | **live/T4-gated** | USB stack **installed** on current unit (2026-07-31); physical modem + live path; operation not device-verified |
| 9 | WG component pre-provision / connectivity | **deployment-order (field guidance)** | **Resolved on current lab unit** (WG installed 2026-07-31); field rack may still ship offline — pre-provision before ship or restore WAN first; see scenario §5 |

### 3.1 Module scope honesty — offline-incomplete / live-gated verticals

Honest completeness relative to full event-booth apply (not bounded test-AP sealed apply):

| Vertical | Code truth | Offline-buildable? | Live / T4 gate |
|---|---|---|---|
| **VLAN / DHCP / DNS / firewall** | `deployment_planner.py` compiles plan items; **VLAN/DHCP/DNS/firewall:** sealed offline `{family}_apply_planner.py` + `{family}_apply_service.py` + `{family}_rci.py` (preview/build; `verification_status=offline_unverified`; **not** Gate B / WriteCertified; **HTTP preview routes delivered 2026-08-01** — `/vlan/preview`, `/dhcp/preview`, `/dns/preview`, `/firewall/preview`; **UI preview panels wired 2026-08-01**; **NOT device-verified**; no apply routes) | Yes — all four sealed offline executors + preview API tests | Gate B family certification + T4 per family; apply HTTP routes |
| **LTE uplink** | `preset_planner.py` ~L67–69 `lte_apply_deferred`; `network_intents.py` ~L1071–1074 | Yes — planner/uplink modeling | **T4-gated** when live |
| **Captive portal** | Domain field accepted; `captive_portal=Enabled` **rejected at compile** — HTTP **422** `wifi.captive_portal_unsupported` (default `Disabled` = noop); same rule for `guest_isolation=true` → `wifi.guest_isolation_unsupported` | Readiness/docs offline | Coova-Chilli install+reboot = **T4** (live) |
| **KeenDNS / CrazeDNS** | No backend; UI unavailable | Discovery/docs only | External/cloud **T4** |
| **TrafficDiscovery** | `composition.py` composes service; proposals-only; **HTTP routes delivered** — `POST /traffic/observations`, `POST /traffic/proposals`, `GET /traffic/proposals/{proposal_id}` (`traffic_discovery_routes.py`; registered in `app.py`); **UI panel on `#config` delivered 2026-08-01**; `auto_apply_blocked=true` | Yes — API routes + UI panel + SQLite persistence | Router auto-apply writes **T4** |
| **Sealed apply reliability (wifi/station/wg)** | `sealed_apply_runs` mid-flight trail + sealed apply audit; state-aware compensating rollback; 503 `sealed_apply.trail_begin_failed`; **no** auto resume/rollback — **NOT device-verified** (2026-08-01) | Yes — persistence + apply services + tests | Live HTTP verification optional; Gates B/C/D unchanged |
| **Preset AWG/routes fragments** | `preset_planner.py` `awg_not_implemented` / `*_apply_deferred` when Gate B blocks | Readiness offline | **Not** the same as sealed `/wifi/*` + `/wireguard/*` — see [`DOMAIN_MODEL.md`](../DOMAIN_MODEL.md) dual-path note |

Bounded sealed Wi-Fi/AWG apply on test APs may be live under per-campaign T4 while rows above remain incomplete for preset/deployment apply.

### 3.3 Full operator web UI — next major phase (2026-08-01)

**Status:** **`operator-web-ui-full-coverage` substantially delivered** (2026-08-01); LOCAL HUB PWA is primary operator surface. **Current continuation:** [`STATUS.yaml`](../STATUS.yaml) `next_task` `local-hub-vpn-real-peer-autoconnect-continuation`. Prototype presentation UI (M1–M3 views, bounded `#config` apply panels, eight LOCAL HUB screens + main menu) is **complete** for current operator spec wave.

| Principle | Requirement |
|---|---|
| **Simple by default** | Happy-path forms show only minimum inputs (example: create Wi-Fi → SSID + password + band; sealed planner/service derives ops, allowlists, confirm gates, live connection params) |
| **Full on demand** | **Advanced settings** expander on every capability screen reveals **all** supported parameters (no hidden backend-only knobs) |
| **Guidance** | Tooltips on **every** field: purpose, safe default, device-verified vs offline-only / pending verification |
| **Coverage rule** | If planners/services/API expose a configurable parameter for a family, UI must surface it (default or advanced) |
| **Verification** | Autonomous UI contract tests (`tests/test_config_ui.py` JS matrix; extend per family); optional browser-verify for layout — **NOT device-verified** until live campaigns |
| **Gates** | Does **not** open Gates B/C/D; does **not** claim WriteCertified; broad catalog/preset Apply remains blocked until Gate B |

**Parallel deferred (unchanged):** VPN routing live apply (preview offline; kill-switch unresolved); network-family apply HTTP routes; Gate B / `write_shapes_registered`.

Operator runbook anchor: [`OPERATOR_UI.md`](../OPERATOR_UI.md). Router-config vertical: [`OPERATOR_ROUTER_CONFIG_UI.md`](../OPERATOR_ROUTER_CONFIG_UI.md).

---

## 4. Global prohibitions (all milestones)

| Rule | Enforcement |
|---|---|
| Unknown identity, firmware, capability, or profile | **Fail closed** — no write dispatch ([`HARDWARE_GATES.md`](HARDWARE_GATES.md) §5) |
| Closed applicable gate | Live observe without A → **403**; write dispatch → **403** `gate.mutation_forbidden` |
| Secrets in repo/docs/fixtures/logs | Forbidden — DPAPI opaque refs only |
| Invented RCI JSON bodies | Forbidden — recorded evidence binds sanitized manifests only |
| Hub failure isolation | RC degraded/disabled must not block Hub core services |
| Certification claims | No milestone may claim WriteCertified without gate evidence package |

---

## 5. Gate ladder reference (independent switches)

| Gate | Opens | Does **not** imply |
|---|---|---|
| **A** | Live read-only observe/preflight | Write certification, B/C/D, AWG support |
| **B** | Per-family automated write dispatch | Lab window (C), production (D), full product certification |
| **C** | Time-boxed lab mutations | Event production writes |
| **D** | Production enablement on enrolled router | Retroactive certification of A/B/C evidence |

Current posture: **A ReadOnlyCertified** (authorized rebind **2026-07-31** rebind #2 post-WG; evidence `data/artifacts/gate-a-probe-post-wireguard-install-192.168.2.1-20260731.json`; rebind #1 `gate-a-probe-newrouter-…` **SUPERSEDED**); **NOT** WriteCertified; **B** completed_failed / not WriteCertified; **C/D closed**; `write_shapes_registered` remains **false**. See [`HARDWARE_GATES.md`](HARDWARE_GATES.md) and [`DEDICATED_ROUTER_LAB_POLICY.md`](../DEDICATED_ROUTER_LAB_POLICY.md).

---

## 6. Historical SLICE completion (reference only)

The following SLICE IDs are **completed evidence**, mapped into the foundation above. They are **not** the current execution order (see M0–M8).

| SLICE | Status | Maps to |
|---|---|---|
| SLICE-1 | Complete | Foundation / M1 fake paths |
| SLICE-2 | Complete | Persistence / M3 |
| SLICE-3 | Complete | `router_control_host` / M1 API surface |
| SLICE-4 | Complete | Gate A RO adapter / M1 live RO |
| SLICE-5 | Complete | Vault / M1 credentials |
| SLICE-6 | Closed failed | AWG deferred lane (not M1 blocker) |
| SLICE-7 | Not started | Routes deferred lane |
| SLICE-8 | Complete (proposals only) | TrafficDiscovery offline / M2 readiness input |
| SLICE-9 | Not started | NetworkPolicy / M2–M6 |
| SLICE-10 | Not started | Hub / **M7** |
| SLICE-11 | Not started | Cutover / **M6** |

---

## 7. Links

- Milestone ordering ADR: [`adrs/0005-local-first-commissioning-roadmap.md`](../adrs/0005-local-first-commissioning-roadmap.md)
- AI agent cold-start: [`AI_HANDOFF.md`](AI_HANDOFF.md)
- Hardware gates: [`HARDWARE_GATES.md`](HARDWARE_GATES.md)
- Project status: [`STATUS.yaml`](../STATUS.yaml)
- Architecture ownership: [`ARCHITECTURE.md`](../ARCHITECTURE.md)
