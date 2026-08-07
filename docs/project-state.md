# Project state

> Living snapshot for agents and humans. Update when phase or priorities change.

## For agents

**When to read:** every session start (via hook summary); before planning slices; with `/setup-project-environment`.

**Apply:** align work to `phase` and `next_checks`; run doctor if stale.

**SSOT:** `docs/STATUS.yaml` is the authoritative machine-readable state (phase, deliverables, blockers, next task). This file is a non-competing projection for harness hooks and quick session context — if they diverge, follow `STATUS.yaml`.

<!-- project-docs-sync: phase=p3-shared-netcraze-executor updated=2026-08-07T16:35:00+03:00 -->

---

## phase

P3 topology safety closure complete (2026-07-23); **expendable lab envelope 2026-07-30** adds `lab_class: expendable_development_router`; Gate A **ReadOnlyCertified** (authorized rebind **2026-07-31**). **2026-08-05 (§M-24..§M-35):** first real WG handshake; `SET_IP_ADDRESS` + `wireguard_ip_global` device-accepted; traffic via tunnel reversible; station 14 ops allowlisted + **7/7 live apply**; main menu R-9; MSS applied (captive efficacy NOT proven). **2026-08-06 (§M-47..§M-51):** test-DB isolation Main-confirmed; staff/guest R-3..R-6 resumed, migration 16 applied live on the operator's real database, main-menu role assignment ЖИВЬЁМ (not just КОД ГОТОВ), `#/staff-wifi`/`#/guest-wifi` confirmed still session-only; two integration-readiness UX packages closed (connection-wizard SSH error handling, VPN screen tunnel-picker default + jargon); 598 leftover scratch files removed from repo root; new `docs/OPERATOR_HUB_MODULE_INTEGRATION_READINESS.md` crosswalk against `ARCHITECTURE.md` §10 for the (still unauthorized, `module_3.0` not present in this workspace) M7 milestone. **Current `next_task`:** see `STATUS.yaml` `next_task.day_10_morning_2_status_2026_08_07` (latest) and `.action` (LEAD). Gates A ReadOnlyCertified; B completed_failed; C/D closed — **not WriteCertified**; `write_shapes_registered` false. **2026-08-07 (§M-53..§M-55):** Gate A same-tuple freshness recertification is now fully automated (Windows Scheduled Task via `schtasks.exe` + a live-host background reload watchdog so an already-running process self-heals without a restart) — closes the recurring manual-daily-recert chore; a real intermittent first-attempt SSH connect failure to the router (concurrent live sessions during Overview page load colliding with the router's own SSH daemon) is fixed with an automatic single retry on transient connect/handshake errors only (`SshTransientConnectionError`), never on identity/auth failures; the Overview screen now shows the actual connected Wi-Fi SSID (best-effort, same already-open transport) instead of a raw technical interface id, and routine router polling was reduced from a 60s full refresh to a 5-minute full refresh plus a 60s host-only (no router SSH) internet-reachability heartbeat that escalates to an early full refresh only on a confirmed true→false transition. A general SSH-concurrency lock across all live router sessions was deliberately NOT built (flagged as a Minimum-T3 "concurrency/race correctness" decision requiring separate Sol approval, not silently expanded from the narrower T1 retry fix). **2026-08-07 day (§M-56):** the already-built Wi-Fi uplink auto-reconnect watchdog (`uplink_watchdog_service.py`) is now enabled on the live host AND made router-load-safe: a cheap host-side internet-reachability probe (same DNS+TCP check already used by the Overview heartbeat, zero router SSH) runs first each poll cycle, escalating to the router-side SSH check only when that cheap probe reports trouble or is inconclusive — matching the operator's explicit "monitor without hitting the router; only check the router when something looks wrong" architecture request. Live-verified: watchdog running=true on the restarted host, host-probe wiring functional (`internet_reachable: true`), zero regressions on Overview. Not yet closed: no remembered Wi-Fi network exists in the live database (`desired_active=0`), so the full "real disconnect → watchdog reconnects" scenario remains unproven — same honest gap as before, now on a safer implementation. **2026-08-07 day, continuation (§M-57):** operator turned VPN off and asked to properly set up the Wi-Fi connection; the router's real Wi-Fi uplink (`Netcraze-7619`, 5GHz) is now marked remembered (`desired_active=true`, reusing an existing non-revoked credential_ref from §M-24, no password re-entry, no live reapply), so the watchdog is no longer a no-op. While verifying this, found and fixed a real bug: a shared frontend normalizer (`diagnostics-model.js::normalizeRouterInternetObserve`) was silently dropping the `gateway_ssid` field between fetch and render on both Overview and 'Интернет' screens — the §M-55 unit test only covered the render function in isolation with a hand-built object and missed it. Fixed with a one-line whitelist addition plus a new regression test targeting the normalizer itself; live-confirmed the 'Интернет' screen now genuinely shows the real connected SSID against an actual Wi-Fi gateway — the first true end-to-end proof, not just data-layer. **2026-08-07 day, continuation (§M-58):** Overview main screen redesigned as a compact status-card grid (router/internet, staff network, guest network, VPN, domain, entry pages) per an operator-supplied reference screenshot, delegated to `operational-orchestrator` (T2) as explicitly requested — all card data reuses already-existing model fields, nothing fabricated, and the reference's "recent events" list was explicitly ruled out of scope (no backend audit-log API exists). Main personally re-verified the diff, tests, and CACHE_VERSION bump rather than trusting the subagent report; a pixel-level screenshot check failed due to a browser-extension backend disconnect (environment issue, not a code finding) — operator should glance at the live page once. **Parallel deferred:** VPN named policy / kill-switch live apply; network-family apply routes blocked; Wi-Fi auto-reconnect watchdog full live-proof (real disconnect scenario); R-10 full tactile animation acceptance; heartbeat-escalation-on-real-outage not yet exercised against an actual live disconnect.

## milestones

| Milestone | Status | Notes |
|-----------|--------|-------|
| Phase 0a architecture evidence | done | Frozen in baseline commit `c15ef56` |
| Harness bootstrapped (Essential) | done | On-disk Essential; stale local plugin 0.1.0 disabled |
| Phase 0b contracts | done | Wave 7 closeout complete; eight STATUS deliverable IDs + supporting artifacts ([`contracts/`](contracts/)) |
| Phase 1 / SLICE-1 (portable core + FakeRouterAdapter) | done | `router_control` package, fake-only tests, stdlib-only runtime (2026-07-21) |
| Phase 1 offline mega (SLICE-2/3/5/8) | done | Persistence, FastAPI host, vault, TrafficDiscovery proposals-only (2026-07-21) |
| Phase 1 / SLICE-4 (Gate A read-only host) | done | Gate A **re-certified** ReadOnlyCertified exact post-change tuple (2026-07-21; return-home source-bound refresh 2026-07-23) |
| Phase 1 / SLICE-6 (Gate B/C AWG trial) | complete (failed) | Trial closed 2026-07-21: certification_failed_all_candidates_handshake; **not WriteCertified** |
| M0 local-first roadmap rebaseline | done | ADR-0005 + ROADMAP M0–M8 DAG; M1–M3 offline authorization (2026-07-22) |
| M1 read-only commissioning MVP | done | CommissioningRun API, migration 2, fake + Gate A RO assess (2026-07-22) |
| M2 event preset / readiness | done | Four-zone intent, migration 3, preset API, planner/readiness (2026-07-22) |
| M3 durable worker / runtime | done | DurableWorker, heartbeat lease, typed handlers, async M1/M2 202 (2026-07-22) |
| Prototype management UI | done | Buildless SPA `/settings/router-control`; hub_admin gate; M1–M3 views; not Hub integration (2026-07-22) |
| Prototype UI auth bootstrap | done | Standalone login/session/logout, root redirect, favicon — [`SESSION_HANDOFF_UI_AUTH_2026-07-22.md`](SESSION_HANDOFF_UI_AUTH_2026-07-22.md) (2026-07-22) |
| Prototype UI auth runtime rework | done | v2 token iat/exp, domain-separated signing, exact same-origin, POST-only logout, login.css (2026-07-22) |
| Prototype UI auth Origin:null closure | done | Standalone loopback profile, Host/ASGI pin, Origin:null, login throttle, run-prototype-host.ps1 (2026-07-22) |
| M4 recovery substrate | done | Offline/fake complete; **not live-ready** for router mutation campaigns (2026-07-22) |
| M5 certification framework (offline/default-deny) | done | Per-family catalog, empty shape registries, evidence manifests, offline planner/CLI — no dispatch (2026-07-22) |
| P1-B live dispatch substrate | **complete** (2026-07-22) | Poll continuation, effect SM, DPAPI artifacts, safety session — offline/not live-ready |
| P2 immutable deployment model | **complete** (2026-07-22) | Offline/fake immutable deployment path; **not live-ready** — [`contracts/ROADMAP.md`](contracts/ROADMAP.md) |
| P3 shared executor | **complete** (2026-07-22) | SharedTypedOperationExecutor offline/default-deny; promotion pipeline; empty Certified registry; not live-ready |
| P1-A persistence foundation | **complete** (2026-07-22) | Migration 4 substrate verified — [`contracts/PERSISTENCE_CONTRACT.md`](contracts/PERSISTENCE_CONTRACT.md) |
| Fail-safe live campaign | **completed_failed** (2026-07-23) | Both trials consumed: `fail-safe-20260723T110000Z` (`ssh_dispatch_failed_before_verified_ack`; VPN absent) and prior `fail-safe-20260723T094500Z`; not WriteCertified; no replay — [`OPERATOR_GATE_FAIL_SAFE.md`](OPERATOR_GATE_FAIL_SAFE.md) |
| Dedicated NC-1812 HW validation | authorized parallel lane | Program 2026-07-22; Gate A RO + offline prep; feeds M5 after M4 — [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) |
| Gate A recert 2.1 (source-bound) | done | Return-home evidence `24c6df7e…` on `192.168.2.10`; same tuple; prior `232bc5ca` historical (2026-07-23) |
| VPN import + AWG parser 1.5 | done | `import-vpn-profile.py`, 10/10 profiles in vault, S3/S4/I1–I5 extensions (2026-07-23) |
| Sealed interface/save RCI operator CLIs | done (offline) | Validate-default CLIs + tests + [`OPERATOR_RCI_TYPED_OPS.md`](OPERATOR_RCI_TYPED_OPS.md) (2026-07-23); live still T4 |
| Router Control integration facade | done | `RouterControlConfig` + `build_runtime`, [`INTEGRATION.md`](INTEGRATION.md), offline tests (2026-07-23) |
| Router config UI vertical slice 1 | done | `#config` view, import-vpn-profile CLI, observed-interfaces RO API — [`OPERATOR_ROUTER_CONFIG_UI.md`](OPERATOR_ROUTER_CONFIG_UI.md); Apply blocked (2026-07-23) |
| Wi-Fi Apply UI + live wiring | done (offline) | `#config` Wi-Fi Apply section + per-request live transport from body params; bounded test AP + confirm; backup on live apply; WriteCertified NOT claimed (2026-07-24) |
| Wi-Fi live E2E (web + device) | done | Human-approved T4 2026-07-24: WPA2 on `WifiMaster0/AccessPoint3`; full web auth→apply→teardown; evidence `wifi-wpa-writeshape-verify-192.168.2.1-20260724.json`; not WriteCertified |
| AWG live core verify | done | Human-approved T4 2026-07-24: create/asc-9/up/teardown on `Wireguard5`; asc-16 rejected; evidence `awg-wireguard5-live-verify-192.168.2.1-20260724.json` |
| VPN AWG apply/verify vertical | done (offline) | WireguardIntent + planner/service + API + UI AWG Apply; honesty split on apply result (`configuration_verification_status`, `interface_verification_status`, `tunnel_verification_status` 4-state from `show interface` peer fields); [`OPERATOR_AWG_APPLY.md`](OPERATOR_AWG_APPLY.md) (first real handshake + traffic via tunnel **device-verified** 2026-08-05 §M-24..§M-27; kill-switch/named policy still open) |
| WPA3 + WPA2/WPA3-mixed live verify | done | Human-approved T4 2026-07-24: grammar `authentication wpa-psk` + `encryption wpa3` (+ wpa2 mixed); evidence `wifi-wpa3-live-reverify-…json`, `wifi-wpa2wpa3-mixed-live-verify-…json`; not WriteCertified |
| AWG secret tunnel ops | partial live | Offline-ready; overall `pending_live_verification`; **private-key transport partially device-verified** live (re-confirmed 2026-07-24); **nested_rci peer write re-confirmed** (2nd campaign 2026-07-24); PSK write-acked on nested upsert, effect not independently confirmed; peer-field readback still pending; path-style peer **REJECTED**; evidence `awg-secret-tunnel-wireguard5-live-probe-192.168.2.1-20260724.json`, `awg-peer-nested-rci-live-reverify-192.168.2.1-20260724.json`, `awg-peer-nested-rci-psk-live-192.168.2.1-20260724.json`; NOT fully device-verified / NOT WriteCertified |
| AWG peer nested-RCI transport | **device-verified write ACCEPTED (corrected shape)** | Additive `peer_rci_shape=nested_rci` (default flipped 2026-07-24); body corrected to array/`key` nested objects; live re-verify **ACCEPTED** on NC-1812 5.01.C.1.0-0 (ack matched + interface applied/up); evidence `data/artifacts/awg-peer-nested-rci-live-reverify-192.168.2.1-20260724.json`; path-style peer **REJECTED** live; **NOT** tunnel connectivity / WriteCertified; `write_shapes_registered` false |

## deferred_verticals (module scope honesty)

Verticals below are **incomplete** relative to full event-booth commissioning. Each row marks whether work can proceed **offline-buildable** or requires **live/T4-gated** evidence.

| Vertical | Current state | Build lane | Live / gate |
|---|---|---|---|
| **VLAN / DHCP / DNS / firewall** | `deployment_planner.py` compiles typed plan items; sealed offline `{family}_apply_planner.py` + `{family}_apply_service.py` + `{family}_rci.py` (preview/build; `verification_status=offline_unverified`; **not** Gate B / WriteCertified); **HTTP preview routes delivered 2026-08-01** — `POST /vlan/preview`, `/dhcp/preview`, `/dns/preview`, `/firewall/preview` — **NOT device-verified**; no apply routes | **offline-buildable** (executors + preview API tests exist) | Gate B family certification + **T4** per family for live dispatch + apply HTTP routes |
| **LTE uplink** | Domain field accepted; `preset_planner.py` ~L67–69 emits `lte_apply_deferred`; `network_intents.py` ~L1071–1074 | **offline-buildable later** | **live/T4-gated** when pursued |
| **Portable rack / WifiWan client** | `UplinkIntent` extended; **offline** `wifi_station_apply_planner` + site-survey API (2026-07-31); bounded grammar probe **device-confirmed**; first upstream association **uplink_verified_bounded + PERSISTED**; HTTP station apply/teardown **device-verified live 2026-08-05** (§M-34: 7/7 ops); **`tunnel_healthy` + traffic via tunnel** (§M-27); offline VPN policy-routing **preview only** (2026-08-01); preset planner **unsupported** / `wifi_wan_not_certified`; scenario [`SCENARIO_PORTABLE_EQUIPMENT_RACK.md`](SCENARIO_PORTABLE_EQUIPMENT_RACK.md) | **offline-buildable** (compiler + read API + ack verify + preview + UI) | **Parallel deferred:** VPN named policy / kill-switch live apply (kill-switch unresolved; no apply route) |
| **Captive portal** | Domain `captive_portal` field accepted; `Enabled` **rejected** at compile (HTTP **422** `wifi.captive_portal_unsupported`); default `Disabled` noop; readiness requires Disabled for safe default | Discovery/docs offline | Coova-Chilli install+reboot = escalated **T4** (live) |
| **KeenDNS / CrazeDNS** | Status/preview RO (2026-08-01); **offline apply shipped** — `POST /keendns/apply`, UI «Опубликовать», planner/allowlist (`verification_status=offline_unverified`; **not** WriteCertified); Human Gate **APPROVED standing 2026-08-08** on expendable — [`OPERATOR_KEENDNS_DISCOVERY.md`](OPERATOR_KEENDNS_DISCOVERY.md) | **offline-buildable** (apply API + UI confirm path) | Live cloud registration **not device-proven**; Gate packet **APPROVED** — [`HUMAN_GATE_KEENDNS_CLOUD_BOOKING_20260801.md`](HUMAN_GATE_KEENDNS_CLOUD_BOOKING_20260801.md); do not re-ask |
| **TrafficDiscovery** | `TrafficDiscoveryService` composed in `composition.py`; proposals-only; **HTTP routes delivered** — `POST /traffic/observations`, `POST /traffic/proposals`, `GET /traffic/proposals/{proposal_id}` (`traffic_discovery_routes.py`; registered in `app.py`); **UI panel on `#config`**; `auto_apply_blocked=true` | **offline-buildable** (API + UI + SQLite persistence) | Auto-apply remains policy-blocked; router writes **T4** |
| **Preset AWG / routes apply fragments** | `preset_planner.py` emits `awg_not_implemented` / `awg_apply_deferred` / `routes_apply_deferred` when Gate B not WriteCertified | Readiness/planner offline | **Separate** from sealed `/wifi/*` + `/wireguard/*` bounded apply (see [`DOMAIN_MODEL.md`](DOMAIN_MODEL.md) dual-path note) |

See also [`contracts/ROADMAP.md`](contracts/ROADMAP.md) §3.1 and [`SESSION_HANDOFF_REAL_ROUTER_2026-08-02.md`](SESSION_HANDOFF_REAL_ROUTER_2026-08-02.md) (active narrative; historical methods: [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md); prior unit: [`SESSION_HANDOFF_REAL_ROUTER_2026-07-24.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-24.md) §14 historical).

## next_checks

- [x] Atomically open Phase 0b in `docs/STATUS.yaml` and this file
- [x] Run `scripts\project-doctor.ps1` on this machine
- [x] Disable stale `cursor-project-harness` 0.1.0 (Essential sufficient; need 0.5.0 to re-enable)
- [x] Write Phase 0b Wave 1–7 contracts and closeout
- [x] Obtain explicit human approval for Phase 1 / SLICE-1 (`implementation_transition_gate`, 2026-07-21)
- [x] Implement SLICE-1: portable core, FakeRouterAdapter, fake-only tests
- [x] Overnight autonomy authorized offline mega (SLICE-2/3/5/8)
- [x] Implement offline mega: persistence, host, vault, traffic proposals
- [x] Implement SLICE-4 read-only Netcraze adapter code + CLIs + Gate A open host integration (2026-07-21)
- [x] Main: AWG Gate B/C lab runner — trial completed_failed; evidence [`gate-b-awg-certification-result.json`](gate-b-awg-certification-result.json)
- [x] M0: local-first roadmap rebaseline (ADR-0005, ROADMAP, STATUS, docs-map) — 2026-07-22
- [x] M1: read-only commissioning MVP (offline/RO; Gate A only) — 2026-07-22
- [x] M2: event preset / readiness (offline/RO) — 2026-07-22
- [x] M3: durable worker loop (offline/RO) — authorized 2026-07-22
- [x] Prototype UI auth bootstrap: standalone login/session, root, favicon — [`SESSION_HANDOFF_UI_AUTH_2026-07-22.md`](SESSION_HANDOFF_UI_AUTH_2026-07-22.md)
- [x] Prototype UI auth runtime rework: v2 token, same-origin login/logout, login.css (2026-07-22)
- [x] P3 topology safety closure: sealed CLI prehash, digest-bound execute prerequisite, LiveMutationPolicy default-deny, P2 unbound reject, source_address bind — 2026-07-23
- [x] NC-1812 topology read discovery (non-certifying, offline fixtures + CLI) — 2026-07-23
- [x] NC-1812 default-route read discovery (non-certifying, offline fixtures + CLI) — 2026-07-23
- [x] Real-router session handoff persisted — [`SESSION_HANDOFF_REAL_ROUTER_2026-08-02.md`](SESSION_HANDOFF_REAL_ROUTER_2026-08-02.md) (2026-08-02 active narrative; historical methods: [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md))
- [x] Offline SSH exec-channel typed RO discovery harness (non-certifying, offline validate default) — [`OPERATOR_SSH_CLI_DISCOVERY.md`](OPERATOR_SSH_CLI_DISCOVERY.md) (2026-07-23)
- [x] Offline AWG/WireGuard RCI write-shape RO discovery harness (validate-default plan + gated `--live-probe`) — [`OPERATOR_AWG_DISCOVERY.md`](OPERATOR_AWG_DISCOVERY.md) (2026-07-23)
- [x] **AWG live RO shape discovery** on lab router (`--live-probe` executed 2026-07-23) — artifact `data/artifacts/awg-shape-192.168.2.1-20260723.json`; candidate write-shape documented (documentation-sourced, NOT certified)
- [x] **Wi-Fi discovery doc** — [`OPERATOR_WIFI_DISCOVERY.md`](OPERATOR_WIFI_DISCOVERY.md); RO evidence from shared 32-interface inventory; candidate write-shape + WifiIntent offline product model (2026-07-24)
- [x] **T4 packets executed** (2026-07-24) — [`T4_GATE_PACKET_AWG_WRITESHAPE_VERIFY_2026-07-23.md`](T4_GATE_PACKET_AWG_WRITESHAPE_VERIFY_2026-07-23.md), [`T4_GATE_PACKET_WIFI_WRITESHAPE_VERIFY_2026-07-23.md`](T4_GATE_PACKET_WIFI_WRITESHAPE_VERIFY_2026-07-23.md); evidence `wifi-writeshape-verify-192.168.2.1-20260724.json`, `wifi-wpa-writeshape-verify-192.168.2.1-20260724.json`, `awg-writeshape-verify-192.168.2.1-20260724.json`
- [x] **Sealed Wi-Fi write ops + live verify** — `wifi_rci.py` + `scripts/wifi-rci-op.py`; bounded test AP; WPA2 device-verified 2026-07-24
- [x] **Sealed AWG write ops + live core verify** — `wireguard_rci.py` + `scripts/wireguard-rci-op.py`; create/asc-9/remove on Wireguard5; asc-16 rejected
- [x] **Wi-Fi web E2E** — auth → preview → apply → verify → teardown via UI + API; [`OPERATOR_WIFI_APPLY.md`](OPERATOR_WIFI_APPLY.md)
- [x] **WPA3 + WPA2/WPA3-mixed live verify** — device-verified 2026-07-24 on `AccessPoint3`; grammar correction applied; evidence `wifi-wpa3-live-reverify-192.168.2.1-20260724.json`, `wifi-wpa2wpa3-mixed-live-verify-192.168.2.1-20260724.json`
- [x] **VPN AWG apply/verify vertical (offline)** — WireguardIntent + planner/service + API + UI; [`OPERATOR_AWG_APPLY.md`](OPERATOR_AWG_APPLY.md)
- [x] **AWG secret tunnel ops (offline)** — sealed private-key/peer/preshared-key; private-key **partial** live confirm (re-confirmed 2026-07-24); nested_rci peer write **ACCEPTED** live re-verify 2026-07-24; path-style peer **REJECTED**
- [x] **AWG peer nested-RCI transport (offline code + live re-verify)** — additive `peer_rci_shape=nested_rci` (default flipped 2026-07-24); corrected array/`key` shape **ACCEPTED** live 2026-07-24; evidence `awg-peer-nested-rci-live-reverify-192.168.2.1-20260724.json`; `write_shapes_registered` remains false; NOT WriteCertified / NOT tunnel connectivity
- [x] **Gate A parser-false-drift recert** — post-parser-fix probe matches recorded tuple (`drifted_fields=0`); **NOT a rebind** — evidence `gate-a-probe-post-parser-fix-20260801.json` sha256 f3dd1c…; defective probe `gate-a-probe-campaign-20260801.json`; human gate `HUMAN_GATE_GATE_A_IDENTITY_DRIFT_20260801.md`
- [x] **Guest Wi‑Fi AP3 live campaign** — `WifiMaster0/AccessPoint3`; `on_air_verified`; save=false; guest isolation unsupported (422) — evidence `guest-wifi-live-campaign-20260802.json`
- [x] **Lab connectivity → WG component install** — resolved 2026-07-31 after uplink restored; WireGuard component installed; identity-drift rebind recorded — see [`STATUS.yaml`](STATUS.yaml) reviews `nc1812_wg_component_installed_20260731`, `nc1812_gate_a_identity_drift_rebind_post_wg_20260731`
- [x] **Station uplink first association + persist** — `uplink_verified_bounded` on `WifiMaster1/WifiStation0`; config saved; survived reboot — evidence `station-wisp-upstream-uplink-first-association-20260731.json`
- [x] **Tunnel dead-peer live-confirm** — revalidate-live `tunnel_never_handshaked` device-confirmed — evidence `wg-tunnel-health-dead-peer-revalidate-live-20260731.json`
- [x] **Offline session 2026-08-01** — source_address propagation; station HTTP apply/teardown; VPN policy-routing preview; network-family preview HTTP; teardown Gate A backup; typed OpenAPI verdict models; verdict_explanation; unified link_up; UI panels; BREAKING error code prefixes — **NOT device-verified**
- [x] **Offline reliability substrate 2026-08-01** — sealed_apply_runs trail + audit (schema **v12**); compensating rollback (wifi/station/wg); **network-family security scaffold** (PreState/compensation/trail hooks; HTTP preview-only); device-output parsers; schema secret scan; closed literals; grammar_doc_refs; planner/parser/UI property tests — **NOT device-verified**; verify baseline green — pytest **3196** passed / **2** skipped (exit **0**); ruff exit **0**
- [ ] **Full operator web UI** (`operator-web-ui-full-coverage`) — simple-by-default + Advanced settings + tooltips + all supported parameters + UI contract tests; **NOT delivered**
- [ ] **Network-family apply routes** (VLAN/DHCP/DNS/firewall) — preview-only delivered; apply + Gate B blocked
- [ ] **VPN named connection policy / kill-switch live apply** — BLOCKED (offline preview delivered; kill-switch `permit global` unresolved; default-route via `ip global` **device-verified** §M-27)
- [x] **Live station HTTP apply verification** — **device-verified 2026-08-05** (§M-34: 14 allowlisted, 7/7 live apply, internet via station)
- [x] **Default-route parser v1.3** — live validated via station uplink path (bare 0.0.0.0/0 without type/state)
- [ ] **Deferred T3:** non-expendable production-AP allowlist widen — BLOCKED (expendable class resolves via `ROUTER_CONTROL_LAB_CLASS`)
- [ ] **Deferred:** Gate B / `write_shapes_registered` formalization — registries remain empty
- [ ] Hub module_3.0 mechanical integration — follow [`INTEGRATION.md`](INTEGRATION.md) facade + API contract mount pattern
- [x] Operator source-bound Gate A reprobe on new network (`192.168.2.1` / `192.168.2.10`) + Gate A SSOT evidence constants updated — 2026-07-23
- [x] **Per-feature live discovery + sealed ops cycle (Wi-Fi + AWG core)** — RO discovery done; sealed ops delivered; live T4 executed 2026-07-24 on **prior unit** bounded test AP — [`SESSION_HANDOFF_REAL_ROUTER_2026-07-24.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-24.md) §10; post-rebind status [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md)
- [x] Direct-array route parser (`/rci/show/ip/route` bare top-level list; shape from `default-route-shape-192.168.2.1-20260723.json`) — **`default-route-v1.2`** offline (DiscoveryRead/non-certifying) — 2026-07-23
- [x] **Captive portal discovery doc** — [`OPERATOR_CAPTIVE_PORTAL_DISCOVERY.md`](OPERATOR_CAPTIVE_PORTAL_DISCOVERY.md); greenfield; Coova-Chilli; component install+config = T4 (documentation-sourced, NOT device-certified)
- [x] **KeenDNS/CrazeDNS discovery doc** — [`OPERATOR_KEENDNS_DISCOVERY.md`](OPERATOR_KEENDNS_DISCOVERY.md); greenfield; cloud booking = T4/external (documentation-sourced, NOT device-certified)
- [ ] **Deferred T4:** captive-portal (Coova-Chilli install+reboot) and KeenDNS/CrazeDNS (cloud/external) — candidate shapes documented only
- [ ] **Deferred T4:** extended AWG asc I1–I5 encoding probe — 16-int asc rejected on device; plan-only harness `scripts/probe-nc1812-awg-asc-encoding.py`
- [ ] Gate B certification / `write_shapes_registered` formalization — deferred; AWG+Wi-Fi T4 campaigns executed but not WriteCertified
- [x] Live read-only SSH CLI channel discovery — **superseded** (RCI canonical, 2026-07-23); offline harness in [`OPERATOR_SSH_CLI_DISCOVERY.md`](OPERATOR_SSH_CLI_DISCOVERY.md); no longer active `next_task`

## toolchain_notes

- Doctor advisory: `pwsh` missing; Windows PowerShell 5.1 runs harness hooks — do not install `pwsh` only for exit 0.
- Target runtime: Python 3.11; optional host deps via `pip install -e ".[dev,host]"`; SSH tunnel probe requires `pip install -e ".[hardware]"` (Paramiko).
- Windows Python 3.11 verified (2026-07-20): `py.exe -3.11 --version` → Python 3.11.9.
- Dev host: `uvicorn router_control_host.app:app --reload` (FakeAdapter default; `RC_ADAPTER_MODE=live` + Gate A open for read-only observe; Gate B/C fail_safe **completed_failed** — trials `fail-safe-20260723T110000Z` + prior `fail-safe-20260723T094500Z` consumed; **not WriteCertified**; registries empty; Gate D closed; set `HUB_ADMIN_PASSWORD` for Ready).
- Offline mega verify (2026-07-21): `pytest`, `ruff`, `mypy`, docs-validate on `router_control` + `router_control_host` + `tests`.
