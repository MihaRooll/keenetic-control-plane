# Dedicated development router — lab policy

## For agents

| Check | Action |
|---|---|
| Ownership | Currently connected lab router at **`192.168.2.1`** is **project-owned** dedicated development/laboratory hardware, purchased solely for Router Control development and certification |
| Lab class | **`lab_class: expendable_development_router`** (authorized **2026-07-30**) — operator-owned throwaway test unit; factory-reset acceptable; **no** production traffic; **no** third-party users; see §1a |
| Dependency | **No** production or customer dependency on this device; controlled config churn/reboots/restores acceptable on **expendable** class — **not** a claim of zero lab risk |
| HW target | **Preferred** hardware validation target for comprehensive module validation (Gate A RO, fixtures, certification packets) — **not** imitation-only |
| Program vs action | **Program authorization** (2026-07-22) ≠ **action approval** — see §2 |
| Gate A | **ReadOnlyCertified** (authorized rebind **2026-07-31**); routine read-only observe on **exact recorded tuple** |
| Offline in-scope | Offline harnesses, recorded fixtures, plans, backup/restore tooling, certification packet prep — **in scope** without new T4 |
| Live mutations | **Non-expendable:** in-envelope bounded reversible verification → **standing authorized** (2026-07-24); carve-outs → explicit per-action confirmation. **Expendable (`expendable_development_router`):** wider autonomous envelope (2026-07-30) — save, reboot, install, firmware, factory reset, all APs/WG, SSH enable; see §1a |
| Gates unchanged | Does **not** open B/C/D; does **not** claim WriteCertified; does **not** certify unknown RCI/firmware/capabilities; Gate **D** production-only **closed** |
| Milestone order | **P3 topology safety closure complete** (2026-07-23); Gate A **ReadOnlyCertified** after authorized rebind **2026-07-31** (complete). **WireGuard component installed 2026-07-31** (`wireguard`; digest change with host key unchanged); tunnel health 4-state from `show interface` (NOT `show rc`); **dead-peer + `tunnel_healthy` DEVICE-CONFIRMED** (2026-07-31); **2026-08-05 (§M-24..§M-27):** first real handshake; `SET_IP_ADDRESS` + `wireguard_ip_global` device-accepted; traffic via tunnel reversible — kill-switch/named policy/IPv6 still open. **Current `next_task`:** read [`STATUS.yaml`](STATUS.yaml) (`local-hub-vpn-real-peer-autoconnect-continuation` at time of writing) — do not hardcode id here. **Parallel deferred:** VPN named connection policy / kill-switch live apply (offline preview only; kill-switch `permit global` **unresolved**). Gates B/C/D unchanged; not WriteCertified. |
| SSOT | [`STATUS.yaml`](STATUS.yaml) `approvals.dedicated_development_router_lab`; gates block unchanged |

**User authorization evidence:** 2026-07-22 (English SSOT in STATUS; brief Russian intent summary below — **not** standing write approval). **Expendable lab class:** 2026-07-30 (widened autonomous envelope on throwaway test router; factory-reset OK).

**Russian intent (summary):** выделенный lab router куплен только под разработку Router Control. **2026-07-24:** bounded reversible live verification (non-expendable envelope) — standing authorized. **2026-07-30:** `expendable_development_router` — расширенный автономный envelope (save/reboot/install/firmware/reset, все AP включая AP0–2 и WifiMaster1, все WG); authorized Gate A rebind с evidence; Gate A **ReadOnlyCertified** после rebind **2026-07-31**. **2026-08-08:** KeenDNS/CrazeDNS cloud book/drop/update — standing на expendable; **не переспрашивать**. Non-expendable carve-outs — explicit per-action go. «Разрешаю всё» / «на все даю добро» = applicable envelope only (не WriteCertified / не B/C/D).

---

## 1a. Lab class: `expendable_development_router` (2026-07-30)

**Granted by human operator 2026-07-30.** Applies only to devices marked in [`STATUS.yaml`](STATUS.yaml) `approvals.dedicated_development_router_lab.lab_class: expendable_development_router`.

| Property | Requirement |
|---|---|
| Ownership | Operator-owned **throwaway** test router for Router Control lab only |
| Production traffic | **None** — no production SSIDs, no customer workloads, no third-party users |
| Factory reset | **Acceptable** — device may be reset/replaced during development |
| Scope | Standing authorization is **scoped to expendable class**; non-expendable lab devices retain stricter 2026-07-24 envelope + carve-outs |

### Authorized envelope — expendable class ONLY (autonomous — no per-action human confirmation)

When **`ROUTER_CONTROL_LAB_CLASS=expendable_development_router`** (or STATUS marks device expendable) **and** Gate A tuple matches live device (after authorized rebind when stale):

| Category | Authorized autonomously |
|---|---|
| Persist | **`system configuration save`** / persisting configuration |
| Lifecycle | **Reboot**; **factory reset** |
| Components | **Component/package install** (SSH server, Coova-Chilli, WireGuard/AmneziaWG, etc.) — requires **vendor/update channel reachability** (NDSS/internet); `Components::Lister component "<name>" is unavailable` on offline router often means **no connectivity / stale catalogue**, not unsupported hardware (see 2026-07-31 WG connectivity blocker) |
| Firmware | **Firmware update/downgrade** |
| Wi‑Fi | **`WifiMaster0/1` + `AccessPoint0`–`6`** per observed hardware inventory (firmware `5.01.C.1.0-0`; AP7/8/9 not present) — no production SSID exists on expendable unit |
| WireGuard | **ALL** WireGuard interfaces (not limited to `Wireguard5`–`9`) |
| Management | Enabling management services needed for control (e.g. **SSH**) |
| KeenDNS / CrazeDNS cloud | **Standing authorized 2026-08-08** — live `ndns book-name` / `drop-name` / `get-update` and `ndns` component install when absent; Gate A tuple must match; template defaults `promo` + `netcraze.pro` + `mode=auto` (UI may override). Agents **must not re-ask**. Packet: [`HUMAN_GATE_KEENDNS_CLOUD_BOOKING_20260801.md`](HUMAN_GATE_KEENDNS_CLOUD_BOOKING_20260801.md) (**APPROVED**) |
| Gate A rebind | **Authorized rebind** — see §1b; **silent rebind forbidden** |
| Evidence | Sanitized packages to **`data/artifacts/`**; throwaway secrets via **`credential_ref` only** |
| Bootstrap discovery | **Non-certifying** read-only HTTP bootstrap for Add-router wizard — `POST /api/router-control/v1/lab/bootstrap-discovery`; narrow allowlist incl. bounded `components/list` POST→GET poll; surfaces update channel, channel target firmware, upgrade/major-jump findings, informational side effects (rebuild+reboot+downtime); **`certification_eligible: false` always**; does **not** open Gate A or install/commit components; see [`OPERATOR_GATE_A.md`](OPERATOR_GATE_A.md) §18 |

**Absolute (all lab classes):** no secrets in repo; evidence honesty; do **not** open Gate **B/C/D**; do **not** claim **WriteCertified**; do **not** set **`write_shapes_registered=true`**.

### Non-expendable envelope (unchanged 2026-07-24)

Devices **without** expendable class retain the bounded reversible envelope and carve-outs documented in § standing authorization below.

---

## 1b. Gate A rebind — authorized vs silent (expendable only)

| Term | Meaning |
|---|---|
| **Silent rebind** | Updating SSOT tuple/evidence **without** recorded observed values, artifact path, and dated rebind event — **FORBIDDEN** (all classes) |
| **Authorized rebind** | On **`expendable_development_router` ONLY**: agent MAY run pinned Gate A probe and update certified tuple **autonomously** when **all** hold: (a) records **observed** tuple + evidence artifact path under `data/artifacts/`; (b) **never fabricates** firmware, host-key, or digest values; (c) logs rebind as **explicit dated event** in STATUS/reviews |
| **Fail-closed writes** | Live writes **FAIL-CLOSED** when live device ≠ currently recorded tuple |

Non-expendable devices: Gate A re-certification after tuple drift still requires operator §6 copy-paste human approval ([`OPERATOR_GATE_A.md`](OPERATOR_GATE_A.md)).

### Physical device replacement — rebind completed (2026-07-31)

**Historical discovery (2026-07-30)** on management host **`192.168.2.1`**: ICMP reachable; TCP 80/443 open; TCP 22 refused; identity uncharacterized. Prior tuple marked stale pending re-certification.

**Authorized rebind completed 2026-07-31** on expendable class — **two same-day rebinds:** (1) morning — physical device replacement, evidence `data/artifacts/gate-a-probe-newrouter-192.168.2.1-20260731.json` (**superseded**); (2) afternoon — WireGuard install identity drift, evidence `data/artifacts/gate-a-probe-post-wireguard-install-192.168.2.1-20260731.json`; Gate A **ReadOnlyCertified**; prior host-key pin SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM superseded (historical only). Certified tuple set by this rebind is UNCHANGED since — subsequent freshness-only recertifications moved only the evidence pointer, never the tuple; **current SSOT evidence pointer:** [`STATUS.yaml`](STATUS.yaml) `gates.A.evidence` / [`gate-a-certification.json`](gate-a-certification.json) → `data/artifacts/gate-a-probe-main-verify-20260805-evening.json`.

---

## Standing bounded live-verification authorization (2026-07-24) — non-expendable default

**Granted by human operator 2026-07-24.** Applies to **non-expendable** lab devices. **Expendable** class uses §1a envelope instead (2026-07-30 supersedes carve-outs listed below for expendable only).

### Authorized envelope (autonomous — no per-campaign blocking gate)

Agents **MAY** perform bounded, reversible live verification autonomously when **all** of the following hold:

| Requirement | Detail |
|---|---|
| Identity preflight | **Exact certified tuple** + SSH host-key pin — **FAIL-CLOSED** on any mismatch: model **NC-1812**; firmware **5.01.C.1.0-0**; host-key **SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY** (current Gate A pin; prior pin SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM superseded 2026-07-31 — historical only); source-address **`192.168.2.10`** |
| Bounded test resources **ONLY** | WireGuard **`Wireguard5`–`Wireguard9`**; Wi‑Fi **`WifiMaster0/AccessPoint3`–`AccessPoint6`** only (2.4 GHz band on this tuple — **`WifiMaster1` not** in envelope) |
| Pre-change backup | Encrypted startup-config backup to **`data/backups/`** before first mutation in a session/campaign |
| Write pattern | Minimal reversible writes → readback verify → rollback/teardown |
| No persist | **NO** `system configuration save` — changes must **not** be persisted |
| Secrets | Throwaway secrets via **`credential_ref` only** (never plaintext); deleted after teardown |
| Evidence | Sanitized packages to **`data/artifacts/`** (no secrets) |

**Routine bounded verification loop** (e.g. Wi‑Fi/AWG apply + teardown on bounded test interfaces) is **standing authorized**. Per-campaign T4 Human Gate Packets for in-envelope work become **records/evidence**, not a blocking human gate.

**Does not:** open Gate **B/C/D**; claim **WriteCertified**; set **`write_shapes_registered=true`**; widen allowlists beyond the bounded set.

### Carve-outs — hard STOP retained (explicit per-action human confirmation required)

Even under standing authorization, the following remain a **hard STOP** — each requires **explicit per-action** human confirmation (not covered by «разрешаю всё»):

- Production APs **`AccessPoint0/1/2`**, or **any** write to interfaces/resources **outside** the bounded ranges; **allowlist widening** beyond the bounded set
- **`system configuration save`** / persisting configuration
- **Reboot**; **component/package install** (e.g. captive portal Coova-Chilli); **factory reset**; **firmware changes**
- **External/cloud configuration** (KeenDNS/CrazeDNS) — **non-expendable only**; on expendable class covered by §1a standing KeenDNS approval **2026-08-08**
- **Opening Gate B/C/D**, claiming **WriteCertified**, or setting **`write_shapes_registered=true`** — formal evidence/registration process required, not a single accepted probe
- **Any operation** that is irreversible or whose rollback is **not** guaranteed

**Operator scope clarification:** «разрешаю всё» / «на все даю добро» authorizes the **applicable envelope** (§ standing non-expendable / §1a expendable including standing KeenDNS 2026-08-08). It does **NOT** authorize opening Gates B/C/D, WriteCertified claims, or non-expendable carve-outs outside that envelope.

---

## 1. Device ownership and purpose

The **currently connected Netcraze Ultra NC-1812** attached to this project's laboratory network is:

- **Project-owned** dedicated development/laboratory router hardware.
- Purchased **solely** for Router Control development, hardware validation, and gate certification work.
- **Not** serving production traffic, customer workloads, or event-booth production tuple during lab campaigns unless a separate Gate **D** Human Gate explicitly authorizes production enablement (Gate **D** remains **closed**).

This ownership fact is distinct from **event LAN network ownership** ([`CANONICAL.md`](CANONICAL.md) §8): on a deployed event LAN the NC-1812 remains L3/DHCP/DNS policy owner; here we state **lab device ownership** — who may use the hardware for Router Control validation without implying production blast-radius immunity for undefined writes.

The NC-1812 is the **preferred hardware target** for comprehensive Router Control module validation (read-only observe, recorded evidence, certification trials). Fake and recorded lanes remain mandatory; hardware validation is **not** an imitation-only shortcut.

Exact identity/firmware tuple and sanitized digests: [`STATUS.yaml`](STATUS.yaml) `gates.A` only — do not add raw device identifiers to this document.

---

## 2. Program authorization vs action approval (normative)

| Dimension | Program authorization (2026-07-22) | Action approval |
|---|---|---|
| What it is | Recorded intent that dedicated-lab HW validation is **in scope** for the project | **In-envelope bounded reversible verification:** standing authorized (2026-07-24) — autonomous within envelope; per-campaign packets = evidence. **Carve-outs:** explicit per-action human confirmation |
| Standing writes | **Not** granted for undefined writes or carve-outs | **In-envelope** bounded reversible loop: standing authorized. **Outside envelope:** each action requires explicit human go |
| Gate opens | **Does not** open B/C/D or claim WriteCertified | Standing authorization does **not** open gates; carve-out gate opens require formal process + explicit confirmation |
| Gate A RO | Allowed on exact tuple under existing ReadOnlyCertified certification | Re-certification after tuple drift still requires operator checklist |
| Offline work | Harnesses, fixtures, plans, backup tooling, cert packet prep | N/A (no live I/O) |
| Evidence | STATUS `approvals.dedicated_development_router_lab` | Sanitized packages + STATUS gate updates when gates actually open |

**Checklist — before live hardware work:**

- [ ] Read [`STATUS.yaml`](STATUS.yaml) gates A/B/C/D — factual posture unchanged by this policy alone
- [ ] Classify work: **offline prep** (program OK) vs **in-envelope bounded reversible live verify** (standing authorized 2026-07-24) vs **carve-out live mutation** (explicit per-action confirmation required)
- [ ] For in-envelope verification: follow standing authorization envelope (identity preflight, bounded resources, backup, no save, credential_ref, evidence)
- [ ] For carve-outs: Human Gate Packet / explicit per-action confirmation includes all elements in §4
- [ ] Do **not** treat user program intent as approval for undefined writes

---

## 3. Authorized under program (no new T4 for these)

Without a new T4 Human Gate, agents and operators may:

| Activity | Boundaries |
|---|---|
| Gate **A** read-only observe/probe/re-certification | Exact certified tuple only; [`OPERATOR_GATE_A.md`](OPERATOR_GATE_A.md); stale/drift → fail-closed |
| Offline harness implementation | Tests, fake adapter, prototype **`router_control_host`** / FakeAdapter offline host only — **not** Hub `module_3.0` integration; no live writes |
| Recorded sanitized fixtures | Redacted transcripts; no secrets; old-device fixtures never certify NC-1812 alone |
| Plans and certification packet preparation | Shapes, checklists, runbooks — **no invented RCI bodies** on live path |
| Backup/restore **tooling** and encrypted backup **prep** | Pre-change backup CLI under Gate A evidence rules; backup alone does not open B/C/D |
| Documentation and STATUS-aligned gate narratives | Factual gates only |

---

## 4. Requires explicit per-action human confirmation (carve-outs — **non-expendable only**)

The following require **explicit per-action** human confirmation on **non-expendable** lab devices — **not** covered by standing bounded live-verification authorization (2026-07-24). On **`expendable_development_router`**, items covered by §1a autonomous envelope proceed **without** per-action confirmation; §1a defers here for expendable class.

**Non-expendable carve-outs:**

- Production APs **`AccessPoint0/1/2`** or **any** write outside bounded test resources (`AccessPoint3`–`6`, `Wireguard5`–`9`)
- **Allowlist widening** beyond non-expendable bounded set
- **`system configuration save`** / persisting configuration
- **Reboot** for test or recovery (when not already covered by an authorized window)
- **Component install** or removal (e.g. captive portal Coova-Chilli)
- **Factory reset** or destructive restore
- **Firmware changes**
- **External/cloud configuration** (KeenDNS/CrazeDNS) — **non-expendable only**; expendable class: standing authorized **2026-08-08** ([`HUMAN_GATE_KEENDNS_CLOUD_BOOKING_20260801.md`](HUMAN_GATE_KEENDNS_CLOUD_BOOKING_20260801.md)) — **do not re-ask**
- Capability **write trial** or WriteCertified pursuit (Gate **B** / **C** as applicable) — **all classes**
- **Opening Gate B/C/D**, claiming **WriteCertified**, or setting **`write_shapes_registered=true`** — **all classes**
- **Any operation** that is irreversible or whose rollback is **not** guaranteed — **non-expendable**; expendable factory reset/reboot covered by §1a with evidence discipline

**Required Human Gate Packet elements:**

| Element | Requirement |
|---|---|
| Scope | Exact commands/window **or** typed capability family; no generic/raw RCI |
| Identity | Pre-flight identity/tuple check against enrolled `RouterId` and STATUS `gates.A.tuple` |
| Backup | Pre-change encrypted startup-config backup (pinned SSH; DPAPI artifact) |
| Fail-safe / rollback | Documented compensation path; Fail-safe Configuration where disruptive |
| Gate **C** | Time-bounded laboratory window when lab mutations apply |
| Post-test | Restore/evidence capture; sanitized artifact; STATUS update only when gate actually changes |
| WriteCertified | **Never** implied by program authorization or failed trial closeout |

Re-open Gate **B/C** AWG or other families: [`OPERATOR_GATE_B_C_AWG.md`](OPERATOR_GATE_B_C_AWG.md) — trial **completed_failed**; **not** WriteCertified.

---

## 5. Explicit non-claims

This policy **does not**:

- Grant **standing approval** for undefined writes or non-expendable carve-outs beyond the applicable envelope (§ standing non-expendable / §1a expendable)
- **Open** Gate **B**, Gate **C**, or Gate **D** (in-envelope verification is **not** a gate open)
- **Claim** WriteCertified for any capability family or set **`write_shapes_registered=true`**
- **Certify** unknown RCI shapes, firmware fields, or capabilities not evidenced in gate packages
- Open **Gate D** (production-only; remains **closed**)
- Imply **M4** remains the **next** milestone (M4 delivered 2026-07-22; **P3 topology safety closure complete** 2026-07-23; Gate A authorized rebind **complete 2026-07-31** — two same-day rebinds; WG component **installed**; **`tunnel_healthy` DEVICE-CONFIRMED** 2026-07-31; **2026-08-05:** handshake + traffic via tunnel device-verified (§M-24..§M-27) — kill-switch/named policy still open; **current `next_task`** — read [`STATUS.yaml`](STATUS.yaml), do not hardcode its id here; **parallel deferred** VPN named policy / kill-switch live apply — kill-switch `permit global` unresolved — [`OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md`](OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md))
- Authorize Hub `module_3.0` integration or signed central pull

**Non-expendable:** controlled lab config churn within the **standing bounded reversible envelope** only — envelope rollback means **config-level teardown/remove-interface**, **not** reboot, factory restore, component install, or firmware change; those remain **non-expendable carve-outs** requiring explicit per-action confirmation.

**Expendable (`expendable_development_router`):** save, reboot, factory reset, component install, and firmware change are **in §1a autonomous envelope** (2026-07-30) — not carve-outs — **when vendor channel is reachable**. **Current expendable lab unit (2026-07-31):** wireguard component **already installed** — the offline-install circular dependency is **resolved here** but remains a **field-rack shipping lesson** (component install on an offline router with WAN down / NDSS unreachable fails with `component unavailable`; restore uplink or pre-provision before ship). This removes **production/customer blast-radius** claims for expendable throwaway units; it does **not** eliminate operational risk for undefined commands or non-expendable carve-out actions.

---

## 6. Milestone ordering

| Priority | Item |
|---|---|
| **Next (critical path)** | Current `next_task` in [`STATUS.yaml`](STATUS.yaml) (id changes over time — read it, don't hardcode): as of 2026-08-02 night, the "LOCAL HUB" PWA redesign (`Привью интерфейса/` mockups + brief) is the main priority, driven by an Opus-5-led `operational-orchestrator`; `app.js` split, live-connection-params gaps, and remaining simple-by-default/Advanced/tooltips coverage fold INTO that redesign rather than preceding it |
| **Parallel deferred (lab hardware)** | **VPN named connection policy / kill-switch live apply** on current rebind unit (`tunnel_healthy` **DEVICE-CONFIRMED**; traffic via `ip global` priority **device-verified reversible** §M-27; kill-switch `permit global` unresolved); Wi-Fi/AWG module validation under expendable envelope |
| **Offline framework (delivered)** | Per-family certification catalog, empty shape registries, evidence manifest schema, read discovery, offline planner/CLI — unconditional no-dispatch; **P3** shared executor + explicit `source_address` bind for overlapping-subnet safety |
| **Parallel lane (expendable envelope + offline prep)** | **`expendable_development_router`** envelope authorized 2026-07-30; Wi‑Fi/AWG module work under expendable class after rebind; offline fixtures/prep; **non-expendable carve-outs** still require explicit per-action confirmation |
| **Requires M5 live evidence + process** | Broad standing or multi-family WriteCertified campaigns — expendable envelope does **not** bypass M5 per-family certification or WriteCertified claims |
| **Not advanced** | Hub `module_3.0` integration (M7); production Gate **D** |

**Clarification:** **Non-expendable in-envelope** bounded reversible live verification (Wi‑Fi/AWG apply+teardown on bounded test interfaces) is **standing authorized** (2026-07-24). **Expendable** class uses §1a wider autonomous envelope (2026-07-30). **Non-expendable carve-outs** — production AP widen, save, reboot, install, reset, external/cloud, Gate B/C/D opens, WriteCertified — require **explicit per-action** human confirmation. **WriteCertified** claims require M5 per-family live evidence plus explicit STATUS update. Offline planner/runner/CLI refuse dispatch unconditionally for unregistered shapes.

---

## 7a. Dual-router lab topology observation (2026-07-23, non-certifying)

Local operator observation on overlapping `192.168.1.0/24` (Windows default route may prefer Wi‑Fi):

| Path | Source | Target gateway | Port 22 (SSH) | Port 80 (HTTP) |
|---|---|---|---|---|
| Ethernet (`Ethernet 3` / Liga3) | `192.168.1.144` | `192.168.1.1` | reachable | reachable |
| Wi‑Fi | `192.168.1.119` | `192.168.1.1` | timeout | reachable |

**Non-claims:** port probes alone do **not** establish NC-1812 identity. Before treating any target as the certified NC-1812 tuple, require **Gate A identity match** + **host-key pin** alignment with [`gate-a-certification.json`](gate-a-certification.json).

**Gate A (current lab, post-rebind 2026-07-31, freshness-recertified through 2026-08-05):** use `--host 192.168.2.1 --source-address 192.168.2.10` on hardware CLIs — see [`OPERATOR_GATE_A.md`](OPERATOR_GATE_A.md) and §7a migration subsection below. **Authorized rebind complete 2026-07-31** (ReadOnlyCertified); tuple UNCHANGED since — current SSOT evidence pointer `data/artifacts/gate-a-probe-main-verify-20260805-evening.json` (source **`192.168.2.10`**; fifth consecutive freshness-only recertification, drifted_fields=0) — see [`STATUS.yaml`](STATUS.yaml) `gates.A.evidence` for the exact pointer, never hardcode a filename here as permanent; superseded pre-WG evidence `gate-a-probe-newrouter-192.168.2.1-20260731.json`; silent rebind forbidden. **Historical (pre-migration):** `--source-address 192.168.1.144` on overlapping `192.168.1.0/24`; return-home artifacts `gate-a-return-home-20260723.json` and `gate-a-return-home-192.168.2.1-20260723.json` — **superseded** (not current SSOT). Evidence may record exact local source IP and `source_address_class` (`private_ipv4_literal` / `private_ipv6_literal`); never MAC/serial/hardware interface IDs. Prior same-tuple evidence remains historical — not revoked. Dual NIC still requires source binding on every live observe despite non-overlapping subnets; **future live mutations** additionally require **`proven_wan_isolated`** from non-certifying topology discovery (`scripts/probe-nc1812-topology.py`) **or** physical uplink disconnect per P3 topology safety. Topology and **default-route** discovery reads are **not** Gate A certifying reads — Gate A four-read allowlist unchanged. **`scripts/probe-nc1812-default-route.py`** (GET `/rci/show/ip/route`, DiscoveryRead) emits default-route structural evidence only; `multiple_default_routes` / `ambiguous` / unknown shape block T4 uplink claims; optional topology correlation by hashed interface IDs never alone promotes `proven_wan_isolated`.

### Physical uplink disconnect (2026-07-23, operator action)

| Item | Observation |
|---|---|
| Action | Operator **physically disconnected** working-router ↔ test-router uplink cable |
| Read-only delta | One **GigabitEthernet+Port** observed **up → down** |
| Logical classification | Remains **ambiguous / non-certifying** — topology parser does not alone certify WAN isolation |
| Pre-T4 alternative | Physical disconnect **satisfies** P3 isolation requirement **while cable stays disconnected** (see [`SESSION_HANDOFF_REAL_ROUTER_2026-07-23.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-23.md)) |

### Network migration 2026-07-23: test router on 192.168.2.0/24

| Item | Observation |
|---|---|
| Test router management | `192.168.2.1` on dedicated lab LAN `192.168.2.0/24` |
| Host Ethernet source bind | **`192.168.2.10`** — mandatory `--source-address` on all live observe CLIs |
| Home working router | `192.168.1.1` via Wi‑Fi on `192.168.1.0/24` — **subnet overlap with test LAN removed** |
| Source bind still required | Dual NIC on host (Ethernet to test router + Wi‑Fi to home router) — overlapping subnets gone does **not** remove source-bind requirement |
| Gate A SSOT | Tuple set by identity-drift rebind **2026-07-31** afternoon (source **`192.168.2.10`**), UNCHANGED since; current evidence pointer `data/artifacts/gate-a-probe-main-verify-20260805-evening.json` (2026-08-05 fifth freshness-only recertification, proactive) — see [`STATUS.yaml`](STATUS.yaml) / [`gate-a-certification.json`](gate-a-certification.json) for the authoritative pointer; superseded `gate-a-probe-newrouter-…` (physical replacement rebind #1 same day) and return-home artifacts **historical**; silent rebind forbidden |

Active session handoff: [`SESSION_HANDOFF_REAL_ROUTER_2026-08-02.md`](SESSION_HANDOFF_REAL_ROUTER_2026-08-02.md) (narrative companion; policy SSOT remains this doc + [`STATUS.yaml`](STATUS.yaml); historical methods companion: [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md)).

---

## 7. Gate posture (factual — unchanged by this policy)

| Gate | Status | Notes |
|---|---|---|
| **A** | Open **ReadOnlyCertified** | Authorized rebind 2026-07-31 on expendable class; new physical unit at 192.168.2.1; Gates B/C/D unchanged |
| **B** | completed_failed | Fail-safe trials `fail-safe-20260723T110000Z` (current) + `fail-safe-20260723T094500Z` (`previous_trial`); historical CertificationTrialAuthorized, not WriteCertified; AWG trial also completed_failed |
| **C** | closed completed_failed | Both fail-safe lab windows closed; second window `11:00–12:00Z` closed `2026-07-23T11:41:34Z` |
| **D** | closed | Production-only |

Details: [`HARDWARE_GATES.md`](contracts/HARDWARE_GATES.md), [`STATUS.yaml`](STATUS.yaml) `gates`.

---

## 8. Links

- Status SSOT: [`STATUS.yaml`](STATUS.yaml)
- Hardware gates: [`HARDWARE_GATES.md`](contracts/HARDWARE_GATES.md)
- Gate A operator: [`OPERATOR_GATE_A.md`](OPERATOR_GATE_A.md)
- Gate B/C AWG operator: [`OPERATOR_GATE_B_C_AWG.md`](OPERATOR_GATE_B_C_AWG.md)
- Fail-safe operator: [`OPERATOR_GATE_FAIL_SAFE.md`](OPERATOR_GATE_FAIL_SAFE.md)
- Roadmap: [`ROADMAP.md`](contracts/ROADMAP.md)
- AI cold-start: [`AI_HANDOFF.md`](contracts/AI_HANDOFF.md)
- Test lanes: [`TEST_STRATEGY.md`](contracts/TEST_STRATEGY.md)
