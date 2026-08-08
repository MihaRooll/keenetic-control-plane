# Domain Overview card — living goal & KeenDNS link

## For agents

| Topic | Rule |
|---|---|
| When to read | **Before any** Overview Domain / KeenDNS UI change; cold-start when `next_task` or operator asks about «Домен» |
| Operator ask (2026-08-08) | Card is too big — throw away extras; keep only: pick default or custom name (within allowed suffixes) + publish domain. Settings live on the router. |
| Product bar | R-8 in [`OPERATOR_SIMPLE_MAIN_MENU_SPEC.md`](OPERATOR_SIMPLE_MAIN_MENU_SPEC.md) + R-9 (no clutter on main screen) |
| Cloud booking | **APPROVED standing 2026-08-08** — [`HUMAN_GATE_KEENDNS_CLOUD_BOOKING_20260801.md`](HUMAN_GATE_KEENDNS_CLOUD_BOOKING_20260801.md), `STATUS.yaml` `approvals.keendns_cloud_booking_expendable`. **Do not re-ask.** Defaults: `promo` / `netcraze.pro` / `mode=auto` |
| Honesty | Never paint «облако зарегистрировано» / readiness green from dispatch alone. Toast = dispatch honesty only (M-6) |
| Discovery SSOT | [`OPERATOR_KEENDNS_DISCOVERY.md`](OPERATOR_KEENDNS_DISCOVERY.md) — CLI candidates, gates, secrets |
| WriteCertified | **false** — do not claim |

---

## 1. Goal (do not forget)

### 1a. Operator ask 2026-08-08 (wave 2 — **current**)

CrazeDNS on the router already has:

1. **Automatic / default device name** — e.g. long-hash.`netcraze.io` with SSL («Доменное имя Netcraze» in Web UI).  
   **Must be shown by querying the router** (`show acme` / `show ndns` / sealed RCI) — **never** hardcode a FQDN pasted in chat.
2. **Personal booked name** — operator picks own label + accept-list suffix (`promo.netcraze.pro`, …) and publishes via `ndns book-name …`.  
   Vendor note: HTTP proxy to home apps needs a **personal** booked name; the automatic `.io` name alone is not enough for that.

Overview must:

| Surface | Behavior |
|---|---|
| Default FQDN | Live RO from router → display ( + SSL hint **only if sealed**) |
| Custom publish | Name + suffix + «Опубликовать» → confirm → `POST /keendns/apply` (`mode=auto`) |

### 1b. Compact card (wave 1 — done)

On Overview step **4 · Домен** keep chrome thin:

1. See / edit a **name** (default `promo` or own DNS label).
2. Pick an allowed **suffix** (default `netcraze.pro`).
3. Press **«Опубликовать»** → **one** UI confirm → module books on the router.

Everything else (event checklist, «Проверить домен», «Открыть черновик», long honesty essays) stays off Overview. Advanced on `#/domain`.

---

## 2. Problems / traps

| Problem | Why it hurts | Fix direction |
|---|---|---|
| Overview card too tall | Operator loses R-9; looks like a form dump | Single compact card: name + suffix + publish (+ optional short FQDN) |
| HTML `hidden` on `.hub-domain__btn-row` | Author CSS `display:flex` overrides UA `[hidden]` → starter button still visible | Do **not** mount starter/draft nodes for `variant=overview` |
| Dual layout (status card + «Имя для черновика») | Duplicate notes, two titles | Merge into one Overview surface |
| Event checklist on Domain card | Not required for publish | Cut from Overview |
| `keendns/status` returns empty → always «unknown» | Badge «Облако не проверяется» is honest but noisy | Optional one-line after publish; no fake verify |
| `domainCloudVerified` always false | Readiness domain segment never greens | Do **not** green from `overall=applied` alone until sealed cloud verify |
| Stale docs (M-5 «только заявка», IMPLEMENTATION_STATUS human-gate-only) | Agents re-ask or rebuild gates | Prefer STATUS + this doc + HUMAN_GATE standing |
| Default starter `promo` often **taken** in cloud | Operator sees generic router failure toast | Parse apply `logs[]` / device message → «имя занято» + suggest another label |
| Live cloud registration **not** device-proven | R-8 still `КОД ГОТОВ`, not `ЖИВЬЁМ` | Live book + observe `show ndns` / `get-booked` next honesty step |

---

## 3. How we talk to the router (commands)

Branding: Keenetic **KeenDNS** ≡ Netcraze **CrazeDNS**. Cloud config is **not** stored in local startup-config (no `system configuration save` for book/drop).

### 3.1 Commands we dispatch today

| CLI | Product path | Notes |
|---|---|---|
| `ndns book-name <name> <domain> <auto\|cloud\|direct>` | `POST /keendns/apply` `intent_kind=book` → sealed parse | Overview publish uses **`auto`** |
| `ndns drop-name <name> <domain>` | Apply API exists; Overview **must not** expose drop | Full screen may later |

Allowlisted / planned in code: `router_control/application/keendns_planner.py`, `adapters/netcraze/allowlist.py`.

### 3.2 Commands authorized but not wired (or RO-only)

| CLI | Status |
|---|---|
| `ndns get-update` | Standing authorized on expendable; **not** in allowlist/planner |
| `ndns check-name <name>` | Docs; UI honestly says availability unknown |
| `show acme` / `GET /rci/show/acme` | **Live sealed 2026-08-08:** `default-domain` = automatic device FQDN (`*.netcraze.io`); `default-domain-certificate-valid` = SSL hint; fixture `tests/fixtures/netcraze/show-acme-default-domain-v1.json` |
| `show ndns` / `GET /rci/show/ndns` | Live sealed: empty `name`/`domain` when no personal book; filled after `book-name` |
| `ndns get-booked` | Live: may return `continued` then cloud error «No booking found…» when none booked — do not treat as personal FQDN |
| `ndns book-name` / `drop-name` apply | Live: first RCI parse ack may be `parse.continued` only — apply re-dispatches same sealed body (bounded poll) before fail-closed |

### 3.3 External evidence (vendor manuals)

- CrazeDNS auto mode CLI: `ndns book-name {name} {domain} auto` — [Netcraze support 35112](https://support.netcraze.ru/speedster/nc-3013/en/35112-automatic-access-type-selection-in-dns.html)
- KeenDNS service overview: [Keenetic support 15882](https://support.keenetic.com/starter/kn-1112/en/15882-dns-service.html)
- Success sample: `Ndns::Client: Booked "sample_name.keenetic.link"` — booking is cloud-side; setting need not be saved locally

### 3.4 Accept-list suffixes (docs-sourced)

`keenetic.pro` \| `keenetic.name` \| `keenetic.link` \| `netcraze.pro` \| `netcraze.link` \| `netcraze.club` \| `crazedns.ru`

---

## 4. Product HTTP surface (already shipped)

| Endpoint | Role |
|---|---|
| `POST /keendns/status` | Classify from injected/empty observe when live params absent — `{}` → unknown |
| `POST /keendns/observe` | Live RO: `show acme` default FQDN + SSL hint + `show ndns` personal fields; Overview when session has complete live connection |
| `POST /keendns/preview` | Offline plan |
| `POST /keendns/apply` | Live book/drop under Gate A + expendable + tuple match + confirm |

Flow:

```text
name + suffix → confirm modal → POST /keendns/apply
  { intent_kind: book, name, domain, mode: auto, confirm_live_apply: true, … }
→ sealed `ndns book-name … auto`
→ toast = dispatch honesty (NOT cloud-proven)
```

---

## 5. Overview UI cut list (target)

**Keep on Overview**

- Step «4 · Домен» chrome (badge + title)
- Name field (prefilled default)
- Suffix select
- Primary **«Опубликовать»**
- Optional: compact FQDN preview (`name.suffix`)
- Optional: one short post-dispatch honesty line

**Remove from Overview** (remain on `#/domain` if needed)

- Event selected / not selected tiles
- «Проверить домен»
- «Открыть черновик»
- «Все настройки домена» as loud CTA (quiet link OK if one line)
- «Подставить стартовое имя» if default already applied on load
- Long starter / availability / duplicate draft essays
- Hardcoded «Облако не проверяется» badge as primary chrome (or demote)
- Second card titled «Имя для черновика»

---

## 6. Code map (owned for compact card)

| Area | Path |
|---|---|
| Overview mount | `router_control_host/web/hub/screens/overview.js` — `mountDomainSimplePublishAffordance({ variant: 'overview' })` |
| Legacy status card (dead export) | `…/features/overview-card-grid.js` (`buildDomainStatusCard`) — **not** Overview path |
| Simple publish widget | `…/features/domain-simple-publish.js` |
| Model / defaults / apply | `…/features/domain-model.js` |
| Full screen (advanced) | `…/screens/domain.js` |
| Hub tests | `tests/test_hub_domain*.py`, overview domain tests |

`CACHE_VERSION` bump required on hub JS change (Main: UTF-8 Python, not PowerShell `Set-Content`).

---

## 7. Acceptance checklist

### Wave 1 (compact card) — done

- [x] Overview Domain fits one compact card: name + suffix + publish
- [x] Default `promo` + `netcraze.pro` still works without extra clicks
- [x] One UI confirm then `POST /keendns/apply` (no re-ask of standing human gate)
- [x] No fake «published in cloud» / readiness green
- [x] Quiet path to `#/domain` for advanced only
- [x] This doc + docs-map updated; validators green
- [x] Hub tests for domain/overview still pass; `CACHE_VERSION` bumped

### Wave 2 (default domain from router + custom book) — **current**

- [x] Living goal recorded here + cross-links (`OPERATOR_KEENDNS_DISCOVERY`, main-menu R-8, docs-map, STATUS pointer)
- [x] Live RO capture: **`show acme`** → `default-domain` / SSL validity; `show ndns` empty until personal book; fixture `tests/fixtures/netcraze/show-acme-default-domain-v1.json` (**never** hardcode FQDN in UI)
- [x] Parsers extract default/automatic FQDN (+ SSL only if sealed) and booked personal names
- [x] Hub can request live observe (wifi-style connection fields); empty inject path stays honest `unknown`
- [x] Overview shows **queried** default domain; keep name/suffix/«Опубликовать» for personal book
- [x] Custom book still `POST /keendns/apply` `mode=auto`; toast = dispatch honesty only
- [x] Tests + `CACHE_VERSION` bump; docs validators green
- [x] Live cloud book + observe proven 2026-08-08 (expendable): `POST /keendns/observe` returns automatic `*.netcraze.io` + SSL; apply drop/book with **continued poll** booked `rc39d9d0.netcraze.pro` (artifacts under `data/artifacts/keendns-*-20260808.json`). Standing template `promo` may be **taken** — UI must allow another label.
- [x] Trap fixed: first RCI ack is often `parse.continued=true` — apply polls same sealed body up to 20 rounds (`_KEENDNS_CONTINUATION_MAX_ROUNDS`)

---

## 8. Next honesty steps (after wave 2 observe)

1. Live book on expendable → evidence artifact → flip R-8 toward `ЖИВЬЁМ` only with real cloud observe.
2. Wire `get-update` if product needs refresh after WAN change.
3. Refresh stale M-5 / IMPLEMENTATION_STATUS human-gate-only wording.
4. HTTP-proxy / 4th-level app publish (vendor: needs personal booked name) — separate product slice after observe+book.

---

## 9. Changelog

| Date | Note |
|---|---|
| 2026-08-08 | **Wave 2 shipped live:** `show acme`→default FQDN; `POST /keendns/observe`; Overview displays queried domain; apply continued-poll; live book `rc39d9d0.netcraze.pro` |
| 2026-08-08 | **Wave 2 goal locked:** show automatic CrazeDNS name via live router query; keep personal `book-name` publish; never hardcode chat FQDN |
| 2026-08-08 | Compact Overview card shipped: single surface (name + suffix + Опубликовать); dual status+draft cards removed |
| 2026-08-08 | Created from operator ask «карточка слишком большая» + autonomous KeenDNS research; standing cloud booking unchanged |
