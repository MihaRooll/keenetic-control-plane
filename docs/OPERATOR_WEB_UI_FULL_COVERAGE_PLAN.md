# Full operator web UI — autonomous implementation plan

## For agents

**When to read:** implementing [`STATUS.yaml`](STATUS.yaml) `next_task` `operator-web-ui-full-coverage`; extending `#config` / `#uplink`; adding progressive disclosure, tooltips, or UI contract tests.

**Apply:** docs-only plan (2026-08-01). **Do not** claim device-verified, WriteCertified, or open Gates B/C/D from UI work. **Do not** invent HTTP fields — SSOT is Pydantic request bodies in `router_control_host/*_routes.py` and exported [`docs/contracts/openapi-v0.json`](contracts/openapi-v0.json).

**Do not:** rewrite the SPA from scratch in one step; drop honesty toast/verdict logic; duplicate field defaults in UI strings; add `/apply` routes for preview-only families; bypass `confirm_live_apply` / credential vault flow.

**Related (read before coding):**

| Doc | Role |
|-----|------|
| [`OPERATOR_UI.md`](OPERATOR_UI.md) | SPA routes, auth, CSP, gates |
| [`OPERATOR_SIMPLE_MODE.md`](OPERATOR_SIMPLE_MODE.md) | Default `#simple` wizard, connection-health link tri-state, router-discovery autodetect, mode switcher |
| [`OPERATOR_ROUTER_CONFIG_UI.md`](OPERATOR_ROUTER_CONFIG_UI.md) | `#config` panels inventory |
| [`contracts/ROADMAP.md`](contracts/ROADMAP.md) §3.3 | Phase principles |
| [`OPERATOR_NETWORK_FAMILY_APPLY_SCAFFOLD.md`](OPERATOR_NETWORK_FAMILY_APPLY_SCAFFOLD.md) | Preview-only network families |
| [`OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md`](OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md) | VPN policy-routing grammar |
| [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) | Expendable allowlists (AP/WG ids) |

**Code anchors:**

| Area | Path |
|------|------|
| Monolith SPA | `router_control_host/web/app.js` (large monolith; approximate size — verify locally, e.g. `(Get-Content …).Count` or `wc -l`) |
| Styles SSOT | `router_control_host/web/assets/styles.css` |
| Shell HTML | `router_control_host/web/index.html` |
| UI contract tests | `tests/test_config_ui.py` (approximate line count — verify locally before citing) |
| OpenAPI export | `scripts/export-openapi.py` → `docs/contracts/openapi-v0.json` |
| Request models | `router_control_host/wifi_apply_routes.py`, `wireguard_apply_routes.py`, `wifi_station_preview_routes.py`, `wifi_station_apply_routes.py`, `network_family_preview_routes.py`, `vpn_policy_preview_routes.py`, `rci_mutation_routes.py` |

---

## 1. Scope — what “full coverage” means

**In scope:** every field on every HTTP request body the prototype host exposes for router configuration, plus honest UX for capabilities that are preview-only, gate-blocked, or firmware-rejected.

**Families (verified against route modules):**

| Family | Preview route | Apply/teardown route | Request model(s) |
|--------|---------------|----------------------|------------------|
| Wi‑Fi AP | `POST /wifi/preview` | `POST /wifi/apply`, `/wifi/teardown` | `WifiPreviewBody`, `WifiApplyBody`, `WifiTeardownBody` — `wifi_apply_routes.py` |
| Wi‑Fi station | `POST /wifi/station/preview` | `POST /wifi/station/apply`, `/wifi/station/teardown` | `WifiStationPreviewBody`, `WifiStationApplyBody` — `wifi_station_*_routes.py` |
| WireGuard/AWG | `POST /wireguard/preview` | `POST /wireguard/apply`, `/wireguard/teardown` | `WireguardPreviewBody`, `WireguardApplyBody` — `wireguard_apply_routes.py` |
| VLAN | `POST /vlan/preview` | **none** | `VlanPreviewBody` — `network_family_preview_routes.py` |
| DHCP | `POST /dhcp/preview` | **none** | `DhcpPreviewBody`, `DhcpReservationBody` |
| DNS | `POST /dns/preview` | **none** | `DnsPreviewBody` |
| Firewall | `POST /firewall/preview` | **none** | `FirewallPreviewBody`, `FirewallRuleBody` |
| VPN policy-routing | `POST /vpn/policy-routing/preview` | **none** | `VpnPolicyPreviewBody` — `vpn_policy_preview_routes.py` |
| Sealed RCI (typed) | — | `POST /rci/*` (fake-gated) | `FailSafeArmBody`, `InterfaceMutationBody`, etc. — `rci_mutation_routes.py` |

**Auxiliary surfaces (not “parameter families” but must stay honest):**

| Surface | View | APIs |
|---------|------|------|
| Credential vault enroll | `#config` | `PUT /routers/{id}/credentials` |
| VPN `.conf` parse-preview | `#config` | `POST /vpn-profiles/parse-preview` |
| VPN catalog import | `#config`, `#vpn` | `POST /vpn-profiles/import` (catalog only — not device apply) |
| Wi‑Fi observed state | `#config` | `POST /wifi/observed-state` |
| Site survey | `#uplink` | `POST /wifi/site-survey` |
| Add-router wizard | `#add-router` | `/lab/wizard-draft-router`, `/lab/bootstrap-discovery`, SSH host-key learn/confirm |
| Event preset validate/plan | `#config` | `POST /event-presets/{id}/validate`, `.../plan-preview` |
| TrafficDiscovery | `#config` | proposals-only (no router apply) |
| Deployment Confirm/Apply | operations | fake-gated catalog path |

**Surface closure status (2026-08-01 cycle 2):**

| Surface | Status | Notes |
|---------|--------|-------|
| VPN catalog import | **closed** | `#config` + `#vpn`; manifest load; simple/advanced; catalog honesty |
| Sealed RCI (FAKE) | **closed** | operation tooltip + confirm honesty note; fake transport copy |
| Add-router wizard | **closed** | manifest load; learn `source_address`; confirm `allow_overwrite` |
| TrafficDiscovery | **closed** | human evidence/route fields + Advanced JSON fallback; manifest tooltips |
| Commissioning UI | **closed** | mode field, readiness-checks read, optional async assess; Apply disabled |
| Presets deploy Confirm/Apply | **closed** | `risk_acknowledged`, GET deployment-revision, PUT desired-revision |
| Site survey (`#uplink`) | **closed** | `buildSiteSurveyFormSurface`; live ×5 advanced; honest survey toast |
| Wi‑Fi observed (`#config` / `#uplink` step 5) | **closed** | `buildWifiObservedFormSurface`; live ×5; null toast unknown |
| `#settings` | **N/A** | theme/gates/logout — no field manifest |

**Explicitly out of scope for this phase:** live apply for VLAN/DHCP/DNS/firewall/VPN policy-routing; Gate B catalog/preset Apply; KeenDNS backend (stub stays); device-verified claims from UI green states.

---

## 2. Decision — increment (наращивать), not rewrite

### 2.1 Option A — rewrite SPA

| Pro | Con |
|-----|-----|
| Clean module tree from day one | **High regression risk** for honesty logic already proven in production use |
| No legacy flat layout | ~6246 lines of battle-tested verdict/toast/redaction code to re-prove |
| | Existing `tests/test_config_ui.py` matrix (~50+ tests) becomes stale wholesale |
| | Autonomous agent cannot land one safe PR; violates “small verifiable steps” |

### 2.2 Option B — incremental refactor (chosen)

| Pro | Con |
|-----|-----|
| Preserves `wifiApplyToastPrefix`, `renderApplyResultWithVerdict`, upstream-SSID redaction, expendable allowlists | Monolith remains until late extraction phases |
| Node harness (`__ROUTER_CONTROL_UI_TEST__`) keeps working while extracting | Temporary dual patterns during migration |
| Each phase ships user-visible UX + passes existing tests | Requires discipline: extract, don’t fork honesty |
| Matches agent workflow: one family / one primitive per PR | |

### 2.3 Decision

**Incrementally refactor `router_control_host/web/app.js`**, extracting shared primitives first, then per-family modules, **without changing honesty semantics**. Treat rewrite as **forbidden** until parity tests cover extracted modules and a dedicated migration step explicitly retires the monolith tail.

**First extraction targets (order matters):**

1. Honesty helpers (already exported under `globalThis.__ROUTER_CONTROL_UI_TEST__` at `app.js` ~6558)
2. Field manifest loader (see §4)
3. `renderSimpleAdvancedForm(manifest, family)` progressive-disclosure builder
4. Per-family renderers (`wifiApForm.js`, …) imported by `app.js`

---

## 3. Model — simple by default, full on demand

### 3.1 Progressive disclosure pattern

Every capability screen uses the same DOM contract (CSP-safe: `createElement` + `textContent` only):

```text
<section data-family="wifi-ap" class="config-family">
  <h2>…human title…</h2>
  <p class="field-hint family-honesty-banner">…capability-level honesty…</p>
  <form class="config-simple-form">…minimum fields…</form>
  <details class="config-advanced" data-testid="advanced-settings">
    <summary>Дополнительные настройки</summary>
    <div class="config-advanced-fields">…all remaining model fields…</div>
  </details>
  <div class="config-actions">Preview | Apply | Teardown (if applicable)</div>
  <div class="config-results">…renderApplyResultWithVerdict…</div>
</section>
```

**Rules:**

- Simple form **must** produce a valid request body when combined with manifest defaults (§4).
- Advanced panel exposes **every** model field not in simple set (coverage rule from ROADMAP §3.3).
- Fields with server-side rejection (e.g. `path_style` peer RCI) appear in advanced but **disabled** with firmware-rejection copy — not hidden silently.
- Live connection block (`host`, `username`, `router_credential_ref_id`, `ssh_host_key_sha256`, `source_address`, optional `router_id`) stays in advanced for apply families; never auto-filled silently.
- `ap_id` / `wg_id` selectors stay **explicit** (dropdown) — never auto-pick silently (policy + expendable allowlist in `isExpendableLabClass()`).

### 3.2 Family → simple path → advanced → default source

| Family | Simple path (operator-facing) | Advanced (all other model fields) | Default / SSOT source |
|--------|--------------------------------|-----------------------------------|------------------------|
| **Wi‑Fi AP** | SSID; PSK via credential enroll → `credential_ref_id`; band (2.4 / 5 GHz) | `ap_id`; `enabled`; `wpa_mode`; `guest_isolation`; `captive_portal`; live connection fields; `confirm_live_apply` / teardown confirm; teardown `wpa_mode` | **OpenAPI** `default` where present (`captive_portal`: `Disabled`). **Required fields without schema default** — simple-path conventions (single SSOT file, §4): `enabled=true`, `guest_isolation=false`, `wpa_mode=WPA2`, first legal `ap_id` in allowlist **pre-selected in dropdown but visible**. Current behavior reference: `app.js` Wi‑Fi Apply block ~2875–3150 |
| **Wi‑Fi station** | Site survey → pick network; enroll PSK → ref; confirm apply | `bssid`; `band`; `priority`; `auth_mode`; `mode` (fixed `WifiWan`); live connection; confirm flags | OpenAPI: `band=BAND_2_4GHZ`, `priority=100`, `mode=WifiWan`. Server default when `auth_mode` omitted: `WPA2_PSK` (`wifi_station_preview_routes.py` ~54). **Open network** — not in simple path (422, §5) |
| **WireGuard** | Choose `wg_id`; import `.conf` **or** peer public key + endpoint + allow-ips; private key via credential ref | `enabled`; `asc_args` (9 ints); `preshared_key_credential_ref_id`; `peer_keepalive_interval`; `peer_rci_shape`; `handshake_settle_seconds`; live connection; confirm | OpenAPI: `peer_rci_shape=nested_rci`, `handshake_settle_seconds=0`. Simple convention: `enabled=true`. **16-arg ASC** — show disabled “unsupported_pending_verification” (planner message, not UI invention) |
| **VLAN preview** | `bridge_id`, `zone_id`, `vlan_id`, `ipv4_cidr`, `ipv4_gateway` (all required — no shorter happy path) | — (all fields already required) | No optional defaults in `VlanPreviewBody`; honesty banner: preview-only |
| **DHCP preview** | `zone_id`, `pool_start`, `pool_end`, `lease_seconds`; empty `reservations` | `reservations[]` rows | `lease_seconds` bounds from model (`60`–`604800`); no schema default — simple path uses documented convention constant in manifest (e.g. `86400`) **generated once**, not hardcoded in UI |
| **DNS preview** | `zone_id`, `local_fqdn`, one upstream resolver | additional upstreams | `upstream_resolvers` min length 1 |
| **Firewall preview** | `zone_id`; one rule (`action`, `destination_family`, `ordinal`) | additional rules | `ordinal` ≥ 0 |
| **VPN policy-routing preview** | `policy_name`, `vpn_interface`, `ip_global=auto` | `interface_kind`, `address_configured`, `ip_global` priority/order variant, `name_servers[]` | `ip_global` default literal `"auto"` when simple |
| **VPN catalog import** | `display_name`, `vpn_kind`, `profile_document` JSON; optional `profile_text` hint | write-only `private_key`, `preshared_key` (`password`, cleared after submit) | `vpn_kind=AmneziaWG`; **catalog import ≠ device apply** |
| **Sealed RCI (fake)** | `router_id`, operation select, confirm | `interface_id` for up/down | **Succeeded = SQLite fake ack**, not device |
| **Add-router wizard** | host, username, secret, display_name | port, `allow_insecure_http` (**default false**), `source_address` (learn), confirm `allow_overwrite` (**default false**) | manifest `wizard_draft` / `ssh_host_key` |

**Credential flow (cross-cutting):** simple paths never accept plaintext secrets in apply bodies. Pattern: inline “Сохранить пароль” → `PUT .../credentials` → use returned `credential_ref_id` in apply payload (existing `#config` credentials panel + uplink enroll).

---

## 4. Default SSOT — prevent UI/model drift

### 4.1 Problem

Many intent fields are **required in OpenAPI without `default`** (`enabled`, `guest_isolation`, `wpa_mode`, `band`, …). UI currently hardcodes fallbacks in `app.js` (e.g. `wpa_mode: wpaEl.value || "WPA2"` ~3050), which will drift from models.

### 4.2 Solution (mandatory for implementation)

Introduce **`router_control_host/web/ui-field-manifest.json`** (generated, committed):

| Manifest key | Source |
|--------------|--------|
| `fields[].name`, `required`, `type`, `enum`, `min`/`max` | Pydantic → OpenAPI (`scripts/export-openapi.py`) |
| `fields[].default` | OpenAPI `default` when present |
| `fields[].simple` | boolean — in simple path |
| `fields[].advanced_only` | boolean |
| `fields[].disabled_reason` | optional — firmware/gate rejection |
| `fields[].tooltip` | OpenAPI `description` + linked operator doc anchor |

**Generator (implementation task):** `scripts/export-ui-field-manifest.py` reading live FastAPI models or `openapi-v0.json`; test `tests/test_ui_field_manifest.py` asserts manifest matches OpenAPI component schemas for each family.

**UI rule:** `buildPayloadFromForm(manifest, family)` is the **only** place defaults merge into JSON bodies. **Forbidden:** string literal defaults in form submit handlers except manifest lookup.

**UI loader (2026-08-01):** `app.js` fetches `/settings/router-control/assets/ui-field-manifest.json` on `#config`, `#uplink`, `#vpn`, and `#add-router` view render (`await loadFieldManifest()` before form build); `fieldTooltipOpts(family, name)` drives tooltips **and** merges manifest `default` into form control state (boolean checked, enum/string/number value); unavailable manifest → `#global-banner` + fail-closed tips. Apply toast honesty is path-bound via `APPLY_TOAST_PATHS` + click-handler harness tests in `tests/test_ui_honesty_defects.py`.

### 4.3 Tooltips (§4 overlap)

| Layer | Content | Drift control |
|-------|---------|---------------|
| **Schema tooltips** | Field purpose, bounds, enum values | From OpenAPI / Pydantic `Field(description=…)` — extend descriptions in route models where missing |
| **Policy tooltips** | device-verified vs offline-only vs rejected | Static keys in manifest referencing doc paths (`OPERATOR_WIFI_APPLY.md`, `OPERATOR_NETWORK_FAMILY_APPLY_SCAFFOLD.md`) |
| **Runtime tooltips** | allowlist ranges (AP3–6 vs AP0–6) | Computed from `isExpendableLabClass()` + manifest `allowlist` block |

**Rendering:** CSP-safe hover/focus tooltips without `innerHTML`:

- Prefer `<button type="button" class="field-tooltip-trigger" aria-label="Подсказка" aria-controls="tip-id">?</button>` + `<span id="tip-id" role="tooltip" class="field-tooltip">…</span>`; **`aria-describedby` on the form control** (input/select/checkbox), not on the trigger.
- Do **not** use native `title=` alone — insufficient for accessibility tests and multi-line text.

---

## 5. Showing non-applicable capabilities

Use **four distinct UX states** — never conflate copy:

| State | Operator meaning | UI pattern | Example |
|-------|------------------|------------|---------|
| **A — Preview only** | Grammar compiled offline; **no HTTP apply** exists | Primary action = **Preview**; Apply button **absent** (not disabled grey); banner `verification_status=offline_unverified` / `help_verified_grammar_unapplied` | VLAN/DHCP/DNS/firewall/VPN policy panels |
| **B — Gate blocked now** | Family may exist later; blocked by WriteCertified / catalog gate | Control **disabled** + banner cites gate; bounded exceptions listed separately | Catalog/preset Apply banner (~OPERATOR_ROUTER_CONFIG_UI §11) |
| **C — Firmware / grammar rejected** | Must not be offered as viable choice | Field **visible** in advanced, **disabled**, rejection reason | AWG `path_style`; station `auth_mode=OPEN` (422 `_MSG_OPEN_UNSUPPORTED`) |
| **D — Not implemented** | No backend route / stub | Section stub, no fake Apply | KeenDNS |

**Copy templates (Russian, human-first):**

- A: «Только предпросмотр — применение на роутер недоступно (грамматика не подтверждена на устройстве).»
- B: «Применение каталога заблокировано: Gate B не WriteCertified. Ограниченные тестовые Apply ниже — отдельное подтверждение.»
- C: «Вариант отвергнут прошивкой — недоступен для выбора.»
- D: «Функция недоступна в этой сборке.»

**Honesty:** preview success ≠ router configured; live apply success only via §7 invariants.

---

## 6. Autonomous UI verification

### 6.1 What exists today (keep and extend)

| Layer | Mechanism | Covers | Gap |
|-------|-----------|--------|-----|
| **Static contract** | `tests/test_config_ui.py` string/structure asserts on `app.js` / CSS / HTML | API paths, forbidden `innerHTML`, honesty strings, panel IDs | No DOM layout; breaks on harmless renames unless updated |
| **Syntax** | `node --check app.js` | Parse errors | — |
| **Runtime logic harness** | Node `eval(app.js)` with `__ROUTER_CONTROL_UI_TEST__=true`; exported functions (`_run_app_js_ui_checks` ~772) | Toast prefixes, SSID redaction, verdict rendering | Only exported functions; not full navigation |
| **HTTP integration** | FastAPI `TestClient` in same file | Shell routes, auth cookie | Not browser |

### 6.2 Browser automation — honest assessment

| Approach | Value | Cost / risk | Recommendation |
|----------|-------|-------------|----------------|
| **Extend Node harness** | High — autonomous, CI-friendly, no new deps | Must export more pure functions (`buildPayloadFromForm`, `isFieldDisabled`) | **Primary** — do first |
| **Cursor Browser MCP** (`.cursor/skills/browser-verify`) | Layout smoke, `#config` navigation, tooltip visibility | Needs loopback host + Human Gate for login; **not stable CI**; Cloud Agents often cannot reach localhost | **Optional** post-phase manual/agent smoke; not acceptance gate |
| **Playwright/Puppeteer in pytest** | Real DOM E2E | New dependency, flaky CI, auth/cookie setup, duplicates harness | **Defer** unless Node harness cannot cover progressive disclosure |

**Browser MCP integration (if used):**

1. Start host via `scripts/run-prototype-host.ps1` (Human Gate: operator password).
2. Navigate `/login` → POST login → `#config`.
3. Snapshot: `details[data-testid="advanced-settings"]` closed by default; open → field count matches manifest.
4. **Never** store credentials in repo or test fixtures.

### 6.3 Verification roadmap for agents

| Check | Command / test |
|-------|----------------|
| UI contract matrix | `py -3.11 -m pytest tests/test_config_ui.py -q` |
| Manifest ↔ OpenAPI | `tests/test_ui_field_manifest.py` (to add) |
| Node syntax | `node --check router_control_host/web/app.js` |
| Runtime honesty | extend `_run_app_js_ui_checks` per new toast/builder |
| Docs | `scripts/validate-project-docs.ps1`; `scripts/project-docs.py audit` |

---

## 7. Honesty invariants — checkable rules

| ID | Invariant | Verify automatically |
|----|-----------|----------------------|
| H-01 | No plaintext PSK/key/password fields in apply bodies or DOM (`name="psk"`, `private-key`, …) | Static: `test_config_ui.py` wifi/awg sections; grep CI gate |
| H-02 | Upstream SSID / secrets never in result DOM | Runtime: `test_ui_runtime_apply_result_redacts_upstream_ssid_from_dom_dump` |
| H-03 | Success toast **only** when `overall=applied` **and** family verdict positive (`on_air_verified`, `tunnel_healthy`, `uplink_verified_bounded`) | Runtime: `test_ui_runtime_awg_toast_not_success_when_tunnel_unverified` + siblings |
| H-04 | Terminal `overall` failure (`FAILED`, `ROLLED BACK`, `UNSUPPORTED`, …) wins in toast prefix before soft verdict | Static + runtime on `applyFamilyToastPrefix` |
| H-05 | `confirm_live_apply` / `confirm_live_teardown` required for live apply families | Static: payload includes flag; API test rejects `false` |
| H-06 | Preview-only families: **no** Apply button, explicit `NO APPLY` / preview banner | Static: network-family + VPN policy tests |
| H-07 | No `innerHTML` / inline `element.style` | Static: `'innerHTML' not in source` |
| H-08 | Rendering via `textContent` / `createElement` only | Static + CSP headers test in host tests |
| H-09 | Broad catalog Apply remains blocked when Gate B not WriteCertified | Static banner strings + disabled deploy apply |
| H-10 | Rejected firmware options disabled with rejection copy (not silent drop) | Static: `path_style` REJECTED label; open network blocked message |
| H-11 | `ap_id` / `wg_id` chosen explicitly from allowlist UI (no silent default in payload without visible selection) | Static: dropdown build loops; manifest test for allowlist range |
| H-12 | `verdict_explanation` collapsible on apply results | Static: `renderApplyResultWithVerdict`, CSS `.verdict-explanation-details` |
| H-13 | Credential enroll: `omitName`, clear value after submit, `preventDefault` | Static: credentials panel tests |
| H-14 | Defaults in payloads match manifest / OpenAPI — no duplicate literals in submit handlers | `test_ui_field_manifest.py` + refactor grep gate (`enabled: true` forbidden outside manifest loader) |
| H-15 | Do not claim device-verified / WriteCertified in UI labels unless citing evidence doc + still showing NOT verified for live apply | Static scan for forbidden phrases in success paths |

---

## 8. Implementation phases (each independently verifiable)

| Phase | Deliverable | Visible user value | Verify |
|-------|-------------|-------------------|--------|
| **P0 — Manifest** | `export-ui-field-manifest.py` + `ui-field-manifest.json` + tests | None (infra) | new pytest + OpenAPI diff |
| **P1 — Primitives** | `details` advanced pattern, tooltip component, `buildPayloadFromForm`, CSS | Wi‑Fi AP: 3-field simple view + «Дополнительные настройки» | `test_config_ui.py` updated; Wi‑Fi tests green | **done 2026-08-01** |
| **P2 — Station uplink** | `#uplink` progressive disclosure; scan→join flow unchanged logically | Technician uplink simplified | uplink section tests + runtime harness | **done 2026-08-01** |
| **P3 — WireGuard** | Import + simple peer path; advanced ASC/shape/settle | AWG setup simplified | awg section tests | **done 2026-08-01** |
| **P4 — Preview families** | Unified preview-only template (state A); DHCP reservations advanced | Consistent preview UX | **done 2026-08-01** — `buildVlanPreviewFormSurface` … + collection row editors; `tests/test_ui_preview_families_forms.py` |
| **P5 — Module extraction** | Split `app.js` into ES modules under `web/families/`; `app.js` imports | Maintainability | full `test_config_ui.py` + `node --check` |
| **P6 — Harness expansion** | Export payload builder + disable logic to `__ROUTER_CONTROL_UI_TEST__` | Stronger autonomous checks | new runtime tests |
| **P7 — Optional browser smoke** | Documented Browser MCP checklist in `OPERATOR_UI.md` cross-link | Visual confidence | manual/agent; not CI gate |

**Phase ordering rule:** never disable existing tests; add new asserts before removing old flat UI.

**First visible win:** **P1** — operator opens `#config` Wi‑Fi Apply and sees only SSID + credential ref + band; everything else behind «Дополнительные настройки».

---

## 9. Agent execution checklist

- [x] Read this plan + ROADMAP §3.3 + OPERATOR_ROUTER_CONFIG_UI
- [x] Run baseline: `py -3.11 -m pytest tests/test_config_ui.py -q`
- [x] **P1–P3 (2026-08-01):** Wi‑Fi AP / station / AWG simple-by-default + advanced + tooltips + harness tests — see `tests/test_ui_simple_advanced_forms.py`
- [x] **P4 (2026-08-01):** VLAN/DHCP/DNS/firewall/VPN-policy preview panels — simple/advanced + tooltips + structured collection row editors (not sole JSON); honesty `offline_unverified` / `help_verified_grammar_unapplied` preserved — see `tests/test_ui_preview_families_forms.py`
- [x] **Event-preset editor (2026-08-01):** `#presets` editor aligned with domain (`AdminServer`, uplink enums, firewall `rules[]`, `canonical_document` load); UI→domain guard — `tests/test_ui_event_preset_form_domain.py`
- [x] **P0 manifest (UI consumption 2026-08-01):** runtime loader + manifest-backed tooltips + fail-closed banner; generator/tests remain parallel track (`ui-field-manifest.json`, `test_ui_field_manifest.py`)
- [ ] **P5–P7** — preset editor progressive disclosure extensions, commissioning UI, optional browser smoke
- [ ] Do not touch gate status in `STATUS.yaml`
- [ ] No live router writes during UI-only work
- [x] Russian operator copy; English SSOT doc anchors unchanged

---

## 10. Docs Impact Record (seed)

```yaml
contract_id: operator-web-ui-full-coverage-plan
docs_paths_touched:
  - docs/OPERATOR_WEB_UI_FULL_COVERAGE_PLAN.md
docs_map_entries_updated:
  - docs/OPERATOR_WEB_UI_FULL_COVERAGE_PLAN.md
validator_run: yes
validator_exit_code: 0
notes: Agent-facing implementation plan for next_task operator-web-ui-full-coverage; docs-only seed 2026-08-01
```

---

## Changelog

| Date | Change |
|------|--------|
| 2026-08-01 | Initial plan — recon verified against app.js (~6246 lines), route models, test_config_ui.py harness |
