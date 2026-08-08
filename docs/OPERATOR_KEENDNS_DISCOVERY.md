# Operator runbook — NC-1812 greenfield KeenDNS/CrazeDNS write-shape discovery

## For agents

| Topic | Rule |
|---|---|
| When to read | Before planning KeenDNS/CrazeDNS domain registration, remote-access write-shape classification, or ndns RCI modeling on NC-1812 |
| Scope | Greenfield KeenDNS/CrazeDNS discovery — documentation-sourced candidate write-shape only; **no** live cloud booking |
| Status | DOCUMENTATION-SOURCED candidate — **NOT** device-certified; does **not** set `write_shapes_registered=true`; does **not** imply WriteCertified |
| Gates | A open ReadOnlyCertified (unchanged); B `completed_failed`; C/D **closed**; **not WriteCertified**; `write_shapes_registered` remains **false** |
| Next | External/cloud write on **expendable lab** = **standing authorized 2026-08-08** — `POST /keendns/apply` shipped offline; live RO on expendable lab next. Non-expendable cloud write still needs a separate packet. WriteCertified / `write_shapes_registered` remain false until certified. **Overview Domain card goal (compact name+publish):** [`OPERATOR_DOMAIN_OVERVIEW_GOAL.md`](OPERATOR_DOMAIN_OVERVIEW_GOAL.md) — living operator ask + command surface; do not re-grow clutter. |

---

## 1. Purpose

Per-feature discovery for the **KeenDNS domain** (Keenetic branding; on Netcraze Ultra NC-1812 branded **CrazeDNS**) write-shape classification. This document records a **documentation-sourced** candidate shape — it does **not** register write shapes, claim WriteCertified, or open Gates B/C/D.

Discovery is **classification only** — it does **not** infer cloud account state, certificate lifecycle, or write safety beyond existing Gate A ReadOnlyCertified scope.

---

## 2. Current codebase state

**RO + preview + apply (offline)** — classify, preview, and confirm-gated apply shipped; live cloud booking **not** device-proven; **not WriteCertified**:

| Item | State |
|---|---|
| UI `#config` KeenDNS section | Expert stub «в разработке» unchanged ([`OPERATOR_ROUTER_CONFIG_UI.md`](OPERATOR_ROUTER_CONFIG_UI.md)) |
| Simple-mode step 5 | **Status + preview + apply** via `POST /keendns/status`, `/keendns/preview`, `/keendns/apply` ([`OPERATOR_SIMPLE_MODE.md`](OPERATOR_SIMPLE_MODE.md)) |
| Domain model / entity / intent | Preview + apply intent (`book`/`drop`); classify in `keendns_observe.py` + parsers in `ndns_probe.py` |
| Parser / typed op / WRITE_ALLOWLIST | Probe parsers + preview planner + `is_ndns_parse_body` OR arm; apply service dispatches sealed book/drop |
| Cloud booking (`book-name` / `drop-name` / `get-update`) | **`book-name`/`drop-name` apply HTTP shipped** (2026-08-08 cycle); `get-update` **not** allowlisted; live lab RO pending |
| Live RO ndns capture | **None** in current lab session |
| WriteCertified / `write_shapes_registered` | **NOT claimed**; remains **false** |

---

## 3. Candidate write-shape (documentation-sourced, NOT certified)

> **Status:** DOCUMENTATION-SOURCED — **NOT** device-certified. Does **not** set `write_shapes_registered=true`. Does **not** imply WriteCertified.

### CLI `ndns` command group

| Command | Role |
|---|---|
| `ndns check-name <name>` | Check name availability |
| `ndns book-name <name> <domain> <auto\|cloud\|direct> [ipv6 cloud \| transfer-code]` | Register/update domain mode |
| `ndns drop-name <name> <domain>` | Release domain registration |
| `ndns get-booked` | List booked names |
| `ndns get-update [<access>]` | Trigger cloud update / refresh |
| `show ndns` | Show current ndns state |

**Modes:** `auto` | `cloud` | `direct`

**Keenetic domains (generic):** `keenetic.pro`, `keenetic.name`, `keenetic.link`

**Netcraze Ultra NC-1812 CrazeDNS domains:** `netcraze.pro`, `netcraze.link`, `netcraze.club`, `crazedns.ru` — **device-verify exact accept-list** on target tuple before any T4 campaign.

Example (auto mode — cloud-side setting, docs-sourced):

```text
ndns book-name sample_name keenetic.link auto
```

### Local remote HTTPS prep (device-stored — distinct from cloud booking)

For Direct-access remote HTTPS to the router web UI (when public WAN IP available):

```text
ip http ssl enable
ip http security-level public ssl
system configuration save
```

Cloud booking commands (`book-name`, `drop-name`, `get-update`) do **not** require `system configuration save` — configuration is stored on the cloud server, not locally.

---

## 4. External/cloud + T4 (CRITICAL)

| Command class | Storage | Project classification |
|---|---|---|
| `ndns book-name` | Keenetic/Netcraze **cloud** | **Standing authorized** on expendable lab (2026-08-08) — do not re-ask; non-expendable still needs separate packet |
| `ndns drop-name` | Cloud | **Standing authorized** on expendable (2026-08-08) |
| `ndns get-update` | Cloud | **Standing authorized** on expendable (2026-08-08) |
| `ndns check-name` / `show ndns` / `get-booked` | Read/observe | Gate A RO scope when allowlisted |
| `ip http ssl enable` + `security-level public ssl` + `system configuration save` | Local device config | **T4** live mutation |

**Prerequisites (documentation-sourced):**

- **Cloud services agent + KeenDNS/CrazeDNS component** — install = **T4** if absent (`Cloud services agent and CrazeDNS` in NDMS component list).
- Device↔cloud identity uses **license / service_tag** (observed in Gate A identity reads — not a secret field name for vault).
- Whether interactive Keenetic Account login is required via CLI is **docs-silent**.

**Expendable lab:** Human Gate **APPROVED standing 2026-08-08** — discovery docs alone were never approval; the dated packet + `STATUS.yaml` `approvals.keendns_cloud_booking_expendable` are. Agents **must not re-ask**.

---

## 5. RCI model + reads

| Operation | Inferred mapping | Confidence |
|---|---|---|
| Observe ndns state | `GET /rci/show/ndns` ↔ `show ndns` | **HIGH** for read mapping |
| Book / drop / update | `/rci/ndns/...` or `POST /rci/` `{"parse":"ndns book-name ..."}` | **LOW–MEDIUM** — exact JSON body **docs-silent** |
| Nested JSON write | Docs-silent | **LOW** |

Prefer sealed typed ops over raw parse when T3+ implementation exists.

---

## 6. SECRET fields

| Field | Notes |
|---|---|
| Cloud/session tokens | **Docs-silent** — never invent, log, or store in repo |
| ACME private key | Stored on device after SSL provisioning — **never touch or log** |
| Transfer codes | Optional `book-name` argument — treat as one-time secret if present |

---

## 7. Deferred (T3) + gates

| Work item | Tier |
|---|---|
| Domain model + sealed ndns op + WRITE_ALLOWLIST | **T3** — data-model + security boundary |
| Cloud booking (`book-name` / `drop-name` / `get-update`) | **Standing authorized** on expendable (2026-08-08); apply shipped offline (`POST /keendns/apply`); live RO on expendable next; non-expendable needs separate packet |
| Component install (Cloud services agent + CrazeDNS) | Expendable §1a + standing KeenDNS approval |

Gates A/B/C/D remain **unchanged** by this discovery document. `write_shapes_registered` remains **false**. WriteCertified **NOT** claimed.

---

## 8. Sources

- [Keenetic — KeenDNS service](https://help.keenetic.com/hc/en-us/articles/360000400919-KeenDNS-service)
- [Keenetic — Automatic access type selection in KeenDNS](https://support.keenetic.com/starter/kn-1112/en/35112-automatic-access-type-selection-in-dns.html)
- [Netcraze NC-1812 — CrazeDNS frequently asked questions](https://support.netcraze.ru/ultra/nc-1812/en/36404-dns-frequently-asked-questions.html)
- Keenetic CLI Reference OS 5.0 (KN-1011) — `ndns` command group (§3.92)
- [Keenetic — Remote access to the web interface](https://help.keenetic.com/hc/en-us/articles/360003145220-Remote-access-to-the-web-interface)
- [Netcraze NC-1812 — Automatic access type selection in CrazeDNS](https://support.netcraze.ru/ultra/nc-1812/en/35112-automatic-access-type-selection-in-dns.html)

---

## Related references

- [`OPERATOR_AWG_DISCOVERY.md`](OPERATOR_AWG_DISCOVERY.md) — parallel per-feature discovery pattern
- [`OPERATOR_WIFI_DISCOVERY.md`](OPERATOR_WIFI_DISCOVERY.md) — Wi-Fi candidate shape (feature 2 of 4)
- [`OPERATOR_ROUTER_CONFIG_UI.md`](OPERATOR_ROUTER_CONFIG_UI.md) — UI KeenDNS stub
- [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) §1a — expendable standing KeenDNS 2026-08-08
- [`STATUS.yaml`](STATUS.yaml) — gates unchanged; WriteCertified NOT claimed
