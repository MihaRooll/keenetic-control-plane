# Human Gate Packet — KeenDNS/CrazeDNS cloud booking (external write)

## For agents

| Fact | Value |
|---|---|
| Status | **APPROVED — standing (2026-08-08)** |
| Decision | Operator explicit: «На все даю добро» / do not re-ask permission (chat 2026-08-08) |
| Effect right now | Agents **MUST NOT** stop to re-ask for KeenDNS/CrazeDNS cloud book/drop/update permission on the **expendable** lab router when Gate A tuple matches. Proceed to implement and (when code exists) dispatch under § standing defaults + evidence discipline. |
| Scope | **`lab_class: expendable_development_router` only** — exact Gate A tuple; fail-closed on identity drift |
| Standing defaults (template) | `name=promo`, `domain=netcraze.pro`, `mode=auto` — operator may change in UI; do not invent other production names |
| Prepared by | KeenDNS RO + sealed preview deliverable, 2026-08-01; approval recorded 2026-08-08 |
| Gate A / B / C / D | Gate A remains `open` / `ReadOnlyCertified`; B `completed_failed`; C/D **closed**; `write_shapes_registered` **false**; **WriteCertified not claimed** |
| Also still forbidden | Secrets in repo; silent Gate A rebind; opening B/C/D; production Gate D; non-expendable cloud writes without a separate packet |

**Do not** treat this packet as still OPEN. Discovery docs alone were never approval — **this dated approval is**.

Living SSOT cross-links: [`STATUS.yaml`](STATUS.yaml) `approvals.keendns_cloud_booking_expendable`, [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) §1a.

---

## 1. Authorized actions (expendable lab — standing)

| Order | Action | Classification |
|---|---|---|
| 1 (RO) | `show ndns` / `ndns get-booked` / components inventory read | Gate A RO when allowlisted |
| 2 (external) | `ndns book-name <name> <domain> <auto\|cloud\|direct>` | **Standing authorized** on expendable + matching tuple |
| 3 (external rollback) | `ndns drop-name <name> <domain>` | **Standing authorized** (separate explicit product action / teardown path) |
| 4 (external refresh) | `ndns get-update [<access>]` | **Standing authorized** when needed after book |
| 5 (component) | Install Cloud services agent + KeenDNS/CrazeDNS (`ndns`) if absent | Covered by expendable §1a component install + this standing |

**Not authorized by this packet:** claiming WriteCertified; setting `write_shapes_registered=true`; opening Gates B/C/D; cloud writes on **non-expendable** devices.

Local HTTPS prep (`ip http ssl enable` + `security-level public ssl` + `save`) remains separate (expendable save/HTTPS may use §1a — not required for cloud book itself).

Example standing-default command (template):

```text
ndns book-name promo netcraze.pro auto
```

Source grammar: [`OPERATOR_KEENDNS_DISCOVERY.md`](OPERATOR_KEENDNS_DISCOVERY.md) §3 — still docs-sourced until live-certified shapes exist; dispatch may proceed under this approval with fail-closed unknown capability.

---

## 2. Exact commands in order (candidate — documentation-sourced)

1. **Observe (RO):** `show ndns` — mapping `GET /rci/show/ndns`.
2. **Observe (RO):** `ndns get-booked` — list booked names.
3. **External write:** `ndns book-name {name} {domain} {auto|cloud|direct}`.
4. **Rollback:** `ndns drop-name {name} {domain}`.
5. **Refresh:** `ndns get-update` — optional access arg docs-silent.

Prefer sealed typed ops over raw parse when implemented.

---

## 3. Data egress and account

| Data | Leaves device? | Destination | Account |
|---|---|---|---|
| Domain name + mode (`book-name`) | **Yes** (when executed) | Keenetic/Netcraze **cloud** | Operator accepted egress 2026-08-08 |
| Device identity binding | Likely (license / service_tag class) | Cloud | Observed in Gate A identity reads — **not a vault field name** |
| Transfer codes (optional) | **Yes** if supplied | Cloud | One-time secret — **never store in repo** |

---

## 4. Prerequisites (agents satisfy autonomously when possible)

- `ndns` component present or install under expendable envelope.
- Domain accept-list on live target (Netcraze: `netcraze.pro`, `netcraze.link`, `netcraze.club`, `crazedns.ru`; Keenetic generics as listed in discovery).
- Gate A tuple matches live device — else fail-closed.
- Evidence: sanitized artifacts under `data/artifacts/`; no secrets in repo.

---

## 5. Risks (accepted by operator 2026-08-08)

| Risk | Notes |
|---|---|
| Cloud registration under wrong account | Operator accepted standing approval for this lab unit |
| Name collision | Prefer `ndns check-name` when RO available; template `promo` may already be taken — fail honestly |
| Mode mismatch | Default `auto`; change only from UI/intent |
| Partial rollback | `drop-name` is separate action |
| Component absent | Install under expendable envelope or fail-closed with honest UI |

---

## 6. Rollback completeness

| Action | Rollback path | Completeness |
|---|---|---|
| `book-name` | `ndns drop-name {name} {domain}` | **Partial** — depends on cloud accepting drop |
| `get-update` | None sealed | Cloud-side refresh only |

---

## 7. Checklist — operator decision recorded 2026-08-08

- [x] Operator owns or controls the target Keenetic/Netcraze cloud account for this lab device
- [x] `ndns` component present **or** install via expendable T4/component envelope approved
- [x] Standing default triple `{promo, netcraze.pro, auto}` accepted as template (UI may override)
- [x] Domain accept-list to be verified on live target before first book (agent duty — not a re-ask)
- [x] Accept external data egress to vendor cloud
- [x] Rollback plan understood (`drop-name` is separate explicit action)
- [x] Gate A tuple must match live device (fail-closed on drift — unchanged)
- [x] This Human Gate packet **explicitly approved** — agents **must not re-ask**

---

## 8. Source citations + unconfirmed markers

| Item | Status |
|---|---|
| CLI `ndns` command group | **DOCUMENTATION-SOURCED** — Keenetic CLI Reference OS 5.0 §3.92; [`OPERATOR_KEENDNS_DISCOVERY.md`](OPERATOR_KEENDNS_DISCOVERY.md) §3 |
| `show ndns` / `get-booked` response shapes | **NOT device-observed in lab** (as of approval date) — observe live before relying on parsers |
| RCI JSON write body for book/drop | **Docs-silent / LOW–MEDIUM** — prefer sealed typed ops |
| Preview `verification_status` | Was `documentation_sourced_unconfirmed`; apply path may still report honesty until live-certified |
| Interactive account login via CLI | **Docs-silent** |

---

## 9. Related references

- [`OPERATOR_KEENDNS_DISCOVERY.md`](OPERATOR_KEENDNS_DISCOVERY.md) — candidate write-shape classification
- [`OPERATOR_SIMPLE_MODE.md`](OPERATOR_SIMPLE_MODE.md) — simple-mode domain step
- [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) §1a — expendable envelope includes standing KeenDNS
- [`docs/contracts/API_CONTRACT.md`](contracts/API_CONTRACT.md) — update when apply route lands
- [`STATUS.yaml`](STATUS.yaml) `approvals.keendns_cloud_booking_expendable`
