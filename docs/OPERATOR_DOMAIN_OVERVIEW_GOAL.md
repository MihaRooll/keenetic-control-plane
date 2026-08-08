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

On Overview step **4 · Домен** the operator needs:

1. See / edit a **name** (default `promo` or own DNS label).
2. Pick an allowed **suffix** (default `netcraze.pro`).
3. Press **«Опубликовать»** → **one** UI confirm → module books on the router (`POST /keendns/apply`).

Everything else (event checklist, «Проверить домен», «Открыть черновик», long honesty essays, duplicate draft notes, dual status+publish cards) is **out of Overview**. Keep advanced / diagnostics on `#/domain`.

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
| `show ndns` / `ndns get-booked` | Parsers exist; status API does **not** live-probe yet |

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
| `POST /keendns/status` | Classify from injected/empty observe — Overview today gets `{}` → unknown |
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

## 7. Acceptance checklist (this wave)

- [x] Overview Domain fits one compact card: name + suffix + publish
- [x] Default `promo` + `netcraze.pro` still works without extra clicks
- [x] One UI confirm then `POST /keendns/apply` (no re-ask of standing human gate)
- [x] No fake «published in cloud» / readiness green
- [x] Quiet path to `#/domain` for advanced only
- [x] This doc + docs-map updated; validators green
- [x] Hub tests for domain/overview still pass; `CACHE_VERSION` bumped

---

## 8. Next honesty steps (not this UI cut)

1. Live RO: `show ndns` / `get-booked` into status so Overview can show booked name without lying.
2. Live book on expendable → evidence artifact → flip R-8 toward `ЖИВЬЁМ` only with real cloud observe.
3. Wire `get-update` if product needs refresh after WAN change.
4. Refresh stale M-5 / IMPLEMENTATION_STATUS human-gate-only wording.

---

## 9. Changelog

| Date | Note |
|---|---|
| 2026-08-08 | Compact Overview card shipped: single surface (name + suffix + Опубликовать); dual status+draft cards removed |
| 2026-08-08 | Created from operator ask «карточка слишком большая» + autonomous KeenDNS research; standing cloud booking unchanged |
