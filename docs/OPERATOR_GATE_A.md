# Gate A — runbook для оператора (Netcraze Ultra NC-1812)

## For agents

| Правило | Действие |
|---|---|
| Gate A | **Human-only open recorded in STATUS.yaml.** Gate A **ReadOnlyCertified** (authorized rebind **2026-07-31** on expendable class). Agents may implement typed Gate A loader/host integration when approved; do not open without explicit operator checklist + sanitized tuple |
| Dedicated lab | Project-owned lab router; **`lab_class: expendable_development_router`** (2026-07-30) — see [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) §1a; non-expendable retains 2026-07-24 envelope |
| Gates A–D | Gate **A** **ReadOnlyCertified** (authorized rebind 2026-07-31); Gate **B** **completed_failed** (not WriteCertified); nested [`gate-a-certification.json`](gate-a-certification.json) lists B/C/D **closed**; Gates **C/D** remain **closed** in STATUS |
| Live I/O | Live observe (`RC_ADAPTER_MODE=live`) requires Gate A open + typed certification; otherwise **403** `gate.a_closed` |
| Secrets | **Запрещено** класть в repo/chat: passwords, private keys, preshared keys, raw sessions, startup-config |
| Firmware | Raw string **`5.01.C.1.0-0`** from `components/firmware.version`; display title **`5.1.1`** from `firmware.title` — **не** нормализовать raw в display |
| Observed identity | Lab NC-1812 HTTP-only path uses **components map** shape; `show/system` telemetry **ignored** for identity/evidence; canonical `model` = RCI `show.version.hw_id`; `model_display` from version display fields; `update_channel` from exact `sandbox: stable` → `Main` (`rci_version_sandbox_ui_map`); operator hints optional/omitted when RCI supplies identity/channel — backward-compatible only when supplied (token set must exactly equal `{hw_id}`) |
| Physical IDs | Gate A adds GET `/rci/show/identification` + GET `/rci/show/version` (frontend bundle trace: `show.identification`, `show.version`); raw serial/servicetag hashed and discarded; evidence source `show.identification_digest` only — no digest values |
| После approve / SLICE-4 | Read-only adapter/probe **code** may land while Gate A stays **CLOSED** in `STATUS.yaml`; live probe and gate open require human checklist + sanitized tuple (§6) |
| Interactive auth | Operator-supplied live evidence on NC-1812 firmware **5.1.1** shows `x-ndw2-interactive` with internal `/auth` sequence: RCI challenge supplies **cookie name only**; first fixed `GET /auth` is **401** with `X-NDM-Realm`, `X-NDM-Challenge`, and exactly one matching `Set-Cookie`; code corrected offline (2026-07-21, second correction) — **re-probe required** before any certification claim |
| Insecure HTTP | Local lab HTTP on port 80 observed; HTTPS on 443 timed out. Plain HTTP requires exact `--allow-insecure-http` / `-AllowInsecureHttp` on **private** hosts only; artifacts record `transport_security: insecure_http`, `https_check: not_certified`, `gate_a_certification_eligible: false`, `certification_eligible: false` — **never** certifying even when `identity_complete: true` and `fingerprint_status: stable` |
| Bootstrap discovery (non-certifying) | **`POST /api/router-control/v1/lab/bootstrap-discovery`** — Add-router wizard brick 1; opt-in plain HTTP over narrow bootstrap allowlist (identity, components **POST+GET poll**, interface, `/rci/ip/ssh`, `/rci/ip/http`); surfaces update channel, channel target firmware, upgrade/major-jump assessments, and informational component-change side effects (**read-only** — no install/commit); requires **`ROUTER_CONTROL_LAB_CLASS=expendable_development_router`** + private host + `credential_ref_id`; optional reads **404** (e.g. SSH component absent) → **200** + findings; `components/list` timeout → **200** + `components_listing_timeout`; host vault resolves **`credential_ref_id`** via DPAPI on Windows **independent of `RC_ADAPTER_MODE`** (`RC_VAULT=memory` for isolation); response always **`certification_eligible: false`**; usable while Gate A **stale/closed**; never opens Gate A or performs writes; offline-verified fixtures + expendable NC-1812 **4.03.C.6.4-16** shapes (2026-07) — not device-certified |
| Pinned SSH tunnel | Optional certifying path: `--ssh-tunnel` / `-SshTunnel` with required `--ssh-host-key-sha256` / `-SshHostKeySha256 SHA256:...` (from `ssh-keygen -l -E sha256` on router host key). RCI runs over local forward to the same verified SSH management address at port 80; artifact records `transport_security: ssh_tunnel`, `https_check: ssh_host_key_pinned`, public fingerprint digest + algorithm — **no** raw host key or password. When `identity_complete: true`, `gate_a_certification_eligible` and `certification_eligible` may be **true** in artifact; human §6 checklist + STATUS.yaml open still required before live observe |
| Overlapping-subnet source bind | When lab PC has multiple NIC paths (Ethernet to test router + Wi‑Fi to home router), **mandatory** `--source-address` / `-SourceAddress` with literal private local IP on hardware CLIs (`probe-gate-a`, `probe-nc1812-topology`, `probe-nc1812-default-route`, `backup-router-startup`, fail-safe/AWG execute). On **`probe-gate-a`**, **`probe-nc1812-topology`**, and **`probe-nc1812-default-route`**, `--source-address` **requires** pinned SSH (`--ssh-tunnel` + `--ssh-host-key-sha256` on Gate A; `--ssh-host-key-sha256` on topology/default-route) — plain HTTP cannot bind outbound source; CLI exits before vault if SSH tunnel/pin is omitted. **Current lab:** test router **`192.168.2.1`**, Ethernet source **`192.168.2.10`** — see [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) §7a. **Current Gate A SSOT evidence:** `data/artifacts/gate-a-probe-post-parser-fix-20260801.json` (sha256 **f3dd1c328edb6546925e6f19cb0e2f62bc213e66942975508feebe8304e187d2**; algorithm **`component-set-v2`**; freshness recert **2026-08-01** — **NOT a rebind**; source **`192.168.2.10`**). **Previous evidence (same tuple):** `gate-a-probe-post-wireguard-install-192.168.2.1-20260731.json` (post-WG identity-drift rebind **2026-07-31**). **Defective probe (old parse — do not use as current):** `gate-a-probe-campaign-20260801.json`. **Superseded:** `gate-a-probe-newrouter-192.168.2.1-20260731.json` (physical replacement rebind #1 same day). **Historical:** overlapping `192.168.1.0/24` bind **`192.168.1.144`** → `192.168.1.1`; evidence `gate-a-return-home-20260723.json` — **superseded**; silent rebind forbidden. Identity + host-key pin required before NC-1812 claims — port reachability alone is insufficient. **Future live mutations** additionally require **`proven_wan_isolated`** topology classification from non-certifying `probe-nc1812-topology` **or** physical uplink disconnect — source binding alone does not open B/C/D; default-route correlation does **not** substitute for topology WAN isolation proof |
| Topology discovery (non-certifying) | **`scripts/probe-nc1812-topology.py`** — sealed GET `/rci/show/interface` on **separate DiscoveryRead allowlist** (not Gate A four-read); artifact `certification_eligible: false`; offline `--fixture` mode for tests; live requires aligned Gate A tuple + pin + mandatory `--source-address`. **Observed keyed parser v2.3** (`parser_version: topology-interface-v2.3`; v2.2 artifacts remain readable for correlation) accepts map-keyed interface bundles (root-direct or `interface` mapping wrapper): ignores non-candidate root children (scalars, mappings without link/connected/state keys); strips sensitive/drop keys from valid candidates before parse/output; **`link_up` from `link` only via shared `parse_up_down_flag`** — never from `connected`/`state`; `connected` is independent opaque flag via same up/down parser; present-but-unparseable link → `link_up: null` + uncertainty (interface **not** dropped); malformed optional consumed fields omit that fact and emit **sorted uncertainty field names only** (never values/hashes); positive prefix/bridge/segment/uplink overlap may still classify `lan_to_lan_or_overlap` under uncertainty; any interface uncertainty blocks `proven_wan_isolated`; keyed WAN proof requires **`link_up: true`** (not `connected` alone); v1 list wrapper unchanged (`topology-interface-v1`). Classification (`proven_wan_isolated` / `lan_to_lan_or_overlap` / `ambiguous`) is **safety evidence only — not certification**; Gates A–D unchanged |
| Default-route discovery (non-certifying) | **`scripts/probe-nc1812-default-route.py`** — sealed GET `/rci/show/ip/route` on **DiscoveryRead allowlist** (Gate A four-read frozen); parser **`default-route-v1.3`** accepts v1 dict `{"route":[entries…]}` and **observed outer list wrapper** `[ [entries…] ]` (root list length exactly 1 whose sole item is the route-entry list; **`[[]]`** → `no_default_route`); any other nesting/mixed outer types fail-closed; emits **default-route/uplink structural evidence only** — hashed outbound interface IDs, gateway **private network class** (never host), safe metric/type/state enums; non-default routes dropped; classification `one_default_route` / `multiple_default_routes` / `no_default_route` / `ambiguous`; **`multiple_default_routes` / `ambiguous` / `no_default_route` / unknown shape block T4 uplink claims**; artifact always `certification_eligible: false`; optional **`--topology-artifact`** correlates hashed default outbound to **link-up** non-LAN interface hashes from sanitized topology (v2.3 or readable v2.2 artifacts — **bool `link_up: true` only**, never `connected` alone or artifact `parser_version` downgrade) — **never alone promotes `proven_wan_isolated`**; optional **`--shape-out`** on parse fail (see **Default-route shape fingerprint** row); live requires aligned Gate A + pin + `--source-address` + DPAPI |
| Topology shape fingerprint (parse fail) | **Two-step discovery:** (1) Gate A identity tuple via `probe-gate-a`; (2) topology DiscoveryRead via `probe-nc1812-topology`. When parser rejects payload shape (`TopologyProbeError`, exit **4**), optional **`--shape-out`** writes a **structural-only** JSON artifact (`certification_eligible: false`, `parser_error_class`, bounded `structure`, `structure_canonical_digest`, `raw_payload_sha256`, operator `source_address`, tuple/evidence digests) — **no raw values/IDs/addresses/MAC/SSID/secrets**. Default CLI without `--shape-out` unchanged. Gates A–D statuses unchanged |
| Default-route shape fingerprint (parse fail) | When **`default-route-v1.2`** parser rejects payload (`RouteTopologyProbeError`, exit **4**), optional **`--shape-out`** on `probe-nc1812-default-route` writes the same non-certifying envelope as topology shape artifacts. **List-root payloads** (observed outer wrapper and other array roots) emit a bounded **container-only** structural fingerprint: `top_type: array`, actual `top_count`, root `element_type_histogram`, ordinal-safe path indices (`[0]`, `[0][1]`, …), nested container type/count/histograms, allowlisted route field **names + JSON types only** (`destination`/`metric` stay hashed dynamic keys); secret field names categorized/hashed; bounds entries≤32 / depth≤3 / output bytes≤8192; `structure_canonical_digest` + `raw_payload_sha256` only — **never raw values/lengths/IDs/IPs/domains**. Dict-root unknown shapes reuse dict `describe_structure`. Gates A–D unchanged |
| Topology **field-name discovery** stage (2026-07-23) | `structure` field samples now name only an **audited closed allowlist of non-secret field NAMES** (`type,link,connected,state,up,traits,address,addresses,ip,mask,prefix,prefix-length,network,gateway,defaultgw,security-level,role,bridge,segment,uplink,parent,via,interface,member,members,port,mtu`) with **JSON type/container shape/count only — never the scalar value or string length**. Any name outside this list stays a `sha256:` hash or a `secret_field_categories` category (`password`/`secret`/`token`/`mac`/`identifier`/`ssid`/`description`/`dns`-as-`address`); map-keyed dynamic interface top keys (interface identifiers) are **always** hashed, never named literally. Still **non-certifying**; Gates A–D unchanged |
| Startup backup (pre-component) | **Operator-only** encrypted backup via fixed `GET /ci/startup-config.txt` over **pinned SSH tunnel** only; DPAPI `.dpapi` + sanitized metadata under `data/backups/` — **does not** install components, reboot, or open Gates B/C/D |
| SSOT | [`STATUS.yaml`](STATUS.yaml), [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md), [`HARDWARE_GATES.md`](contracts/HARDWARE_GATES.md), [`API_CONTRACT.md`](contracts/API_CONTRACT.md) §10.1; active handoff [`SESSION_HANDOFF_REAL_ROUTER_2026-08-02.md`](SESSION_HANDOFF_REAL_ROUTER_2026-08-02.md) |

---

## 1. Назначение

Этот runbook описывает, как **локальный оператор** на Windows готовит лабораторию, собирает sanitized identity tuple для **Netcraze Ultra NC-1812**, проходит checklist Gate A ([`HARDWARE_GATES.md`](contracts/HARDWARE_GATES.md) §6.1) и отправляет **copy-paste** сообщение для открытия Gate A. Документ не открывает gates автоматически.

**Gate A** разрешает только **read-only** RCI transport / identity / observe. Gates **B/C/D** (writes, lab window, production) остаются закрытыми.

---

## 2. Prerequisites (лаборатория)

| Требование | Проверка |
|---|---|
| Windows PC в зоне **Admin/Server** | Hub или dev-host доступен только оператору |
| Роутер NC-1812 в lab-сети | Management HTTPS/RCI endpoint известен (host/port) |
| `HUB_ADMIN_PASSWORD` задан | `GET /api/router-control/v1/status` → **200** `Ready`, не **503** |
| Offline host smoke (опционально) | `scripts/verify-offline.ps1` exit 0 без роутера |
| Backup lab state | Отдельный lab router; не event production tuple |

Сеть: Guest/Promo **не** должны иметь доступ к Router Control API или RCI.

---

## 3. Доступ к UI роутера и RCI с Windows

1. Подключите admin PC к lab LAN (не Guest Wi‑Fi).
2. Узнайте management IP роутера (DHCP reservation или наклейка; **не** публикуйте в shared docs).
3. Откройте локальный HTTPS UI роутера в browser (сертификат — по lab policy; self-signed допустим с явным trust только на admin PC). **Operator note (2026-07-21):** on lab NC-1812 firmware 5.1.1, HTTPS to port 443 timed out; HTTP on port 80 responded with `x-ndw2-interactive` challenge — use insecure-HTTP probe path below only after code re-probe; do not treat as Gate A certified.
4. RCI/management API — тот же host/port; auth scheme selected from `WWW-Authenticate` (`x-ndw2-interactive` with internal `/auth` sequence, or Digest for proxy use per legacy evidence); **пароль не копировать в chat**.
5. Для dev-host API: `uvicorn router_control_host.app:app` + cookie `hub_admin` после login flow prototype (см. [`SECURITY_OPS.md`](contracts/SECURITY_OPS.md)).

Проверка reachability (без secrets):

```powershell
# Пример: TCP reachability management port (замените host/port)
Test-NetConnection -ComputerName 192.168.x.x -Port 443
```

---

## 4. Sanitized identity tuple (обязательные поля)

Соберите **только** redacted metadata для certification package ([`HARDWARE_GATES.md`](contracts/HARDWARE_GATES.md) §1):

| Поле | Пример формата | Примечание |
|---|---|---|
| `model` | `NC-1812` | Canonical hardware ID from RCI `show.version.hw_id` (`model_source: rci_version`); absent → `unknown` |
| `model_display` | `Netcraze Ultra NC-1812` | Display metadata from `show.version` `model`/`device`/`description` only (`model_display_source: rci_version_display`); excluded from fingerprint |
| `firmware_version` | `5.01.C.1.0-0` | **Raw string** from `components/firmware.version` — не `5.1.1` |
| `firmware_display_title` | `5.1.1` | Display metadata from `firmware.title` only |
| `build` | RCI NDM exact | From nested `show.version.ndm.exact` (`build_source: rci_version_ndm_exact`); required for `identity_complete`; flat `build` is legacy display fallback only (`build_source: rci_version`); absent → unknown |
| `bsp_build` | optional RCI value | From nested `show.version.bsp.exact` (`bsp_build_source: rci_version_bsp_exact`); never substitutes NDM build |
| `sandbox` | `stable` or unknown | Raw `show.version.sandbox` preserved (`sandbox_source: rci_version`); exact `stable` maps to `update_channel: Main` |
| `region` | RCI value or unknown | From `show.version` `region` only (`region_source: rci_version`); never used as update channel |
| `update_channel` | `Main` | From exact `sandbox: stable` (`update_channel_source: rci_version_sandbox_ui_map`); optional operator hint fallback (`operator_ui_hint`) when sandbox unmapped |
| `physical_identifier_source` | `missing` or `show.identification_digest` | Digest source label only — no serial/servicetag values in artifact |
| `firmware_sources_agreement` | `true`/`false`/absent | When both `version` and `release` present: each nonblank and must agree with each other and components raw firmware; single field compared to components when only one present |
| `component_set_digest` | `sha256:…` | Sorted installed component IDs under algorithm **`component-set-v2`**. **MODE A** (any component entry has `installed` key): truthy `installed` counts — bool, version-like string (e.g. `5.01.C.1.0-0`), `yes`/`true`/`1`/`installed`; `installed: false`/null/0 → excluded; entries **without** `installed` key are catalogue stubs → **excluded** even when `version` is present. **MODE B** (no entry has `installed` key): 2026-07-31 semantics — non-empty `version` → installed; `available`-only → excluded; unrecognized metadata → parse fail-closed. Future probe field: `installed_component_ids` (sorted IDs, capped) may be emitted separately. **Honesty:** Recorded Gate A `component_set_digest` (e.g. `sha256:23bd35bc…`) already matches independent recompute of sorted **`entries_with_installed_key`** under **`component-set-v2`**. On dual-population responses, defective pre-v2 parse hashed **catalogue stubs** (entries without `installed` key) — producing drift digests (e.g. `sha256:479a368c…`) with unchanged host-key/firmware. After this parse fix, a correct dual-pop re-probe should **align** with the recorded digest rather than resemble a device swap. Never silent-rewrite tuple; if mismatch persists after correct re-probe, authorized rebind only. |
| `device_fingerprint` | redacted digest | Observed shape digest; excludes hostname/domain/runtime |
| `fingerprint_status` | `provisional` or `stable` | **`provisional`** while RCI identity claims incomplete (missing both physical digests, `hw_id`, NDM build, firmware agreement, or token/hwid disagreement); **`stable`** only when complete — **neither status alone certifies Gate A** |
| `identity_complete` | `true`/`false` | **`true`** when observed-shape RCI claims are complete (`hw_id`, both serial/servicetag digests, matching optional `identification.hwid`, NDM build via `ndm.exact`, firmware agreement, no token/hwid disagreement) — **independent of transport certification** |
| `certification_eligible` | `false` | Always **`false`** on insecure HTTP and until Gate A checklist + human approval; **`identity_complete: true` on insecure HTTP does not set this to `true`** — `gate_a_certification_eligible` and `https_check: not_certified` remain **`false`** |
| `evidence_recorded_at` | UTC ISO8601 | |
| `evidence_locator` | internal path | Не в public repo |

**Transport vs identity:** `identity_complete` and `fingerprint_status` reflect **RCI identity claims only** — not TLS/HTTPS certification. Insecure HTTP may yield `identity_complete: true` and `fingerprint_status: stable` while `certification_eligible`, `gate_a_certification_eligible`, and `https_check` remain non-certifying; pinned SSH + §6.1 checklist + human STATUS.yaml open are required before Gate A ReadOnlyCertified live observe.

Identity read должен быть согласован с enrolled fingerprint policy ([`DOMAIN_MODEL.md`](DOMAIN_MODEL.md)).

---

## 5. Checklist Gate A — RCI transport (§6.1)

Скопируйте и отметьте в lab log (redacted transcripts):

- [ ] Authenticated encrypted transport: local HTTPS with certificate validation **or** host-key-pinned SSH tunnel to verified router management RCI HTTP (see §4.1)
- [ ] Interactive or Digest auth challenge and session establishment recorded (redacted); interactive uses bounded GET/POST/GET `/auth` only — RCI `session_cookie` is **name-only**; first internal `GET /auth` must be **401** with challenge headers and one matching `Set-Cookie`
- [ ] Identity read matches enrolled fingerprint
- [ ] Command-level error normalization captured
- [ ] 401 re-auth behavior (single retry) captured or marked unknown
- [ ] `"continued": true` polling captured or marked not observed
- [ ] Timeout behavior documented

Пакет evidence: redacted transcripts, checklist, adapter version — **без** passwords/keys/sessions/startup-config ([`HARDWARE_GATES.md`](contracts/HARDWARE_GATES.md) §2).

---

## 6. Copy-paste шаблон для chat (открытие Gate A)

**Отправляет только человек-оператор.** Агент не подставляет secrets.

```
Human Gate A open request — Netcraze Ultra NC-1812

I confirm lab prerequisites and HARDWARE_GATES.md §6.1 checklist completed (redacted evidence stored internally).

Certification tuple (sanitized):
- model: NC-1812 (rci_version hw_id)
- model_display: Netcraze Ultra NC-1812 (rci_version_display)
- firmware_version: 5.01.C.1.0-0
- firmware_display_title: 5.1.1
- build: <ndm.exact or unknown>
- sandbox: stable
- update_channel: Main (rci_version_sandbox_ui_map)
- component_set_digest: sha256:<redacted>
- device_fingerprint: digest:<redacted> (fingerprint_status: stable or provisional)
- identity_complete: true or false
- certification_eligible: false
- evidence_recorded_at: <UTC ISO8601>
- evidence_locator: <internal only>

Scope: Gate A read-only only (observe/enroll/preflight identity legs).
Gates B/C/D remain CLOSED. No startup-config, passwords, keys, or sessions attached.

Approve opening Gate A for this exact tuple in STATUS/hardware config.
```

---

## 7. Что НЕ вставлять в chat / repo

| Запрещено | Причина |
|---|---|
| Router management password | Write-only vault |
| VPN private keys / preshared keys | SECURITY_OPS |
| Raw RCI session cookies / tokens | Session hijack risk |
| Full startup-config dumps | High leak risk |
| Real serial/MAC in public artifacts | Redact to digest |

---

## 8. Что делает агент после human approval

1. Ждёт **явного** human message с checklist + tuple (шаблон §6).
2. **Не** открывает Gate A сам — только implementer по отдельному approved contract обновляет gate state **если** human explicitly approved.
3. SLICE-4 read-only adapter/probe code may exist **before** Gate A open; gates stay CLOSED until operator completes §6.1 + human §6 approval for the **exact** tuple.
4. Продолжает fail-closed для B/C/D и всех writes.
5. Обновляет docs atomically (`STATUS`, `project-state`, `docs-map`) только в рамках approved task.

---

## 9. Что остаётся заблокированным (B / C / D)

| Gate | После открытия A |
|---|---|
| **B** — write certification per family | **Closed** — no automated write dispatch |
| **C** — lab mutation window | **Closed** — no lab mutations |
| **D** — production enablement | **Closed** — no event production writes |
| `POST .../apply` (live) | **403** `gate.mutation_forbidden` until B/C/D satisfied |
| AWG apply on hardware | Requires Gate B + lab/prod gates |

---

## 10. Optional: offline host smoke (без роутера)

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\verify-offline.ps1
```

Ожидание: pytest, ruff, mypy, docs validator — exit 0. Это **не** заменяет Gate A evidence.

Экспорт OpenAPI (contract artifact):

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\export-openapi.ps1
```

---

## 11. Troubleshooting

| Симптом | Вероятная причина | Действие |
|---|---|---|
| `503 security.configuration_blocked` | Пустой `HUB_ADMIN_PASSWORD` | Задать password; перезапустить host |
| `403 gate.a_closed` при `RC_ADAPTER_MODE=live` | Gate A closed (expected) | Normal until human Gate A open |
| `202` enroll/preflight в fake mode | L2 fake persist intent | **Не** считать live observe успешным |
| Identity mismatch | Wrong network/router | Stop; re-verify fingerprint |
| `503 feature.degraded` на mutations | Host `feature_state=Degraded` | Fix worker/DB; GET `/status` still 200 |
| Auth bypass suspicion | Alternate path forms | Host normalizes API prefix paths; report if 401 missing |

---

---

## 13. DPAPI credential enrollment (Windows)

Interactive enrollment stores the router RCI password in **Windows DPAPI CurrentUser** vault under `data/secrets/` (gitignored). Metadata records host, username, and `credential_ref` only — **never** the password.

**Current lab (2026-07-23 migration):**

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\store-router-credential.ps1 -RouterHost 192.168.2.1 -Username <lab-user>
```

Equivalent Python entry:

```powershell
py.exe -3.11 scripts\store-router-credential.py --host 192.168.2.1 --username <lab-user>
```

**Historical (pre-migration overlapping LAN):** replace host with `192.168.1.1`.

Prompt: `Router password:` via getpass (not argv/env). Output: `credential_ref_id` and next probe hint only.

Optional metadata path: `--meta-out data/secrets/meta/router-credential-meta.json` (default).

---

## 14. Gate A probe CLI (sanitized evidence)

After enrollment, operator (or approved Main live step) runs read-only probe against **private** lab host. Artifact lands under `data/artifacts/` (gitignored). No username/password/serial/MAC/session tokens in artifact.

**Primary — current lab (authorized rebind 2026-07-31; freshness recert 2026-08-01 post-parser-fix — NOT a rebind):** test router `192.168.2.1`, Ethernet source `192.168.2.10`. Current Gate A SSOT evidence: `data/artifacts/gate-a-probe-post-parser-fix-20260801.json` (ReadOnlyCertified; sha256 f3dd1c328edb6546925e6f19cb0e2f62bc213e66942975508feebe8304e187d2; host-key pin `SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY`). Previous same-tuple evidence: `gate-a-probe-post-wireguard-install-192.168.2.1-20260731.json`. Re-probe only when tuple drift or authorized rebind — **not** a silent SSOT update. Host tooling validates artifact **sha256** and **24h freshness** — arbitrary substitute files fail.

```powershell
py.exe -3.11 scripts\probe-gate-a.py --host 192.168.2.1 --credential-ref <cred_...> --username <lab-user> --ssh-tunnel --ssh-host-key-sha256 SHA256:<pin-from-ssh-keygen> --source-address 192.168.2.10
```

PowerShell equivalent:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\probe-gate-a.ps1 -RouterHost 192.168.2.1 -CredentialRef <cred_...> -Username <lab-user> -SshTunnel -SshHostKeySha256 SHA256:<pin-from-ssh-keygen> -SourceAddress 192.168.2.10
```

Install hardware extra first: `pip install -e ".[hardware]"`. Obtain pin from router: `ssh-keygen -l -E sha256 -f <hostkey.pub>` (use `SHA256:...` digest only — never commit real lab pin).

**Historical (pre-migration overlapping `192.168.1.0/24`):** host `192.168.1.1`, source `192.168.1.144` — **superseded**; recorded only in historical evidence `gate-a-return-home-20260723.json` (not current Gate A SSOT).

```powershell
py.exe -3.11 scripts\probe-gate-a.py --host 192.168.1.1 --credential-ref <cred_...> --username <lab-user> --ssh-tunnel --ssh-host-key-sha256 SHA256:<pin-from-ssh-keygen> --source-address 192.168.1.144
```

**Insecure HTTP (private lab only; non-certifying evidence):** required when HTTPS is unreachable and SSH pin path is not used. RCI supplies canonical `hw_id`, NDM build, and channel mapping; hints optional for backward compatibility only.

```powershell
py.exe -3.11 scripts\probe-gate-a.py --host http://192.168.2.1:80 --credential-ref <cred_...> --username <lab-user> --allow-insecure-http
```

**Historical insecure HTTP:** replace host with `http://192.168.1.1:80`.

| Flag | Purpose |
|---|---|
| `--allow-non-private` / `-AllowNonPrivate` | Lab edge case only; default denies public IPs |
| `--allow-insecure-http` / `-AllowInsecureHttp` | Plain HTTP to **private** hosts only; artifact is permanently non-certifying |
| `--ssh-tunnel` / `-SshTunnel` | Host-key-pinned SSH local forward to verified router management RCI HTTP; requires `--ssh-host-key-sha256` |
| `--ssh-host-key-sha256` / `-SshHostKeySha256` | Pinned SSH host key SHA256 digest (`SHA256:...`); verified before password auth |
| `--source-address` / `-SourceAddress` | Literal private local IPv4/IPv6 outbound bind on **SSH tunnel only** (overlapping-subnet labs); requires `--ssh-tunnel` + host-key pin — not valid on plain HTTP probe |
| `--expected-model` / `-ExpectedModel` | Optional backward-compatible hint; omit when RCI `hw_id` present; when supplied, token set must be exactly `{hw_id}` (empty/partial/case-variant/competing => incomplete) |
| `--update-channel` / `-UpdateChannel` | Optional fallback when `sandbox` is not exactly `stable` |
| `--artifact-out` | Override evidence JSON path |
| `--secrets-root` | DPAPI root (default `data/secrets`) |

Insecure observed-shape artifacts include `transport_security: insecure_http`, `https_check: not_certified`, `gate_a_certification_eligible: false`, `certification_eligible: false`, and (when physical/build/firmware agreement incomplete) `fingerprint_status: provisional`, `identity_complete: false`. Even when `identity_complete: true` after enriched probe, **certification remains false** on insecure HTTP. **Gate A remains CLOSED** until operator completes §6.1 checklist, live evidence is reviewed after **re-probe** with corrected transport and physical-identity parser, and human sends §6 approval for the exact identity/firmware tuple.

---

## 16. Encrypted startup-config backup (pre-component install)

**Scope:** operator prepares a **DPAPI-encrypted** startup-config artifact **before** risky component install or firmware work. This implementation **does not** install components, reboot the router, or open Gates **B/C/D**.

| Rule | Detail |
|---|---|
| Endpoint | Fixed **`GET /ci/startup-config.txt` only** — no generic paths, raw RCI, running-config, logs, or self-test |
| Transport | **Pinned SSH tunnel required** (`--ssh-host-key-sha256` / `-SshHostKeySha256`); uses existing DPAPI credential ref + username |
| Secrets | Password via DPAPI vault only (interactive enrollment §13); **no** password argv/env; plaintext memory-only during fetch |
| Size bound | Max **4 MiB**; non-200, empty, or oversize → **no artifact** written |
| Artifacts | Encrypted `*.dpapi` + sanitized `*.meta.json` under `data/backups/` (gitignored); stdout prints locator paths + content hash only |
| Gates | Gates **B/C/D remain CLOSED**; backup alone does not authorize writes |

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\backup-router-startup.ps1 `
  -RouterHost 192.168.2.1 `
  -CredentialRef <cred_...> `
  -Username <lab-user> `
  -SshHostKeySha256 SHA256:<pin-from-ssh-keygen> `
  -SourceAddress 192.168.2.10
```

Python equivalent:

```powershell
py.exe -3.11 scripts\backup-router-startup.py `
  --host 192.168.2.1 `
  --credential-ref <cred_...> `
  --username <lab-user> `
  --ssh-host-key-sha256 SHA256:<pin-from-ssh-keygen> `
  --source-address 192.168.2.10
```

**Historical (pre-migration):** host `192.168.1.1`, source `192.168.1.144` (omit `-SourceAddress` / `--source-address` only if single-path — not current lab).

Backup output is fixed to repository `data/backups/`; the CLI has no output-root override. Optional: `--secrets-root`, `--allow-non-private` (lab edge cases). Before vault or network access, the CLI requires the typed Gate A certification, matching STATUS/evidence, device fingerprint digest, and the same actual pinned SSH host-key digest/algorithm. **Never** attach plaintext startup-config, passwords, or session material to chat/repo.

---

## 17. Gate A re-certification after tuple drift (component install or physical replacement)

When a lab component install/removal changes the installed component set, or when the **physical device is replaced**, the prior Gate A tuple becomes **stale or revoked** — live observe and writes fail closed until re-probe and re-certification for the **new exact digests**.

**Path selection:**

| Scenario | Re-certification path |
|---|---|
| **Expendable class** (`expendable_development_router`) | **Authorized rebind** (§17a) — autonomous pinned probe + evidence + dated STATUS update |
| **Non-expendable** | Human §6 copy-paste approval required |
| **Gate A rebind (2026-07-31 completed)** | Expendable → §17b completed authorized rebind; non-expendable → human §6 |

### 17a. Authorized rebind vs silent rebind (expendable class only)

| Term | Rule |
|---|---|
| **Silent rebind** | Updating SSOT tuple/evidence without recorded observed values, artifact path, and dated rebind event — **FORBIDDEN** (all classes) |
| **Authorized rebind** | On **`expendable_development_router`** ONLY ([`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) §1b): agent MAY run pinned Gate A probe (§14) and update `gate-a-certification.json` + `STATUS.yaml` **autonomously** when: (a) observed tuple + evidence artifact path recorded; (b) values **never fabricated**; (c) rebind logged as explicit dated event |
| **Non-expendable** | Human §6 copy-paste approval still required |
| **Writes while tuple drift** | Live writes **FAIL-CLOSED** when live device ≠ recorded tuple |

### 17b. Physical device replacement — authorized rebind completed (2026-07-31)

**Historical discovery (2026-07-30):** read-only discovery on **`192.168.2.1`**: ICMP reachable; TCP 80/443 open (NDMS Web Panel); TCP 22 refused (host-key unscanned); identity **uncharacterized**. Prior tuple (NC-1812 / 5.01.C.1.0-0 / host-key SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM) marked stale pending re-certification.

**Authorized rebind completed 2026-07-31** on **`expendable_development_router`** — **two same-day rebinds:** (1) morning physical device replacement — SSH service was stopped, enabled via telnet CLI (`service ssh` + `system configuration save`) before certifying probe; evidence `gate-a-probe-newrouter-192.168.2.1-20260731.json` sha256 `ce76e7ec…` (**superseded**); (2) afternoon post-WG identity drift — evidence `gate-a-probe-post-wireguard-install-192.168.2.1-20260731.json` sha256 `86bbcb58…` (**previous_evidence** as of 2026-08-01 freshness recert). Secondary observed RSA-2048 host key SHA256:LrVOhAyxJqo3kRdAmXxZN0SIZtvbaUk6XMmqzBWtDXs noted but **NOT pinned** (probe pinned ed25519 SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY); Gate A **ReadOnlyCertified** ONLY; Gates B/C/D unchanged; WriteCertified NOT claimed.

### 17c. Parser-false-drift freshness recert (2026-08-01 — NOT a rebind)

**2026-08-01** live reprobe under **defective v1 parse** produced apparent digest drift (`gate-a-probe-campaign-20260801.json`) while host-key and firmware stayed unchanged — **≠** physical device swap. Root cause: dual-population `components/list` — **`entries_with_installed_key`=40**, **`parser_counts_installed`=54**, **`overlap=[]`** (`component-install-marker-truth-20260801.json`); pre-v2 digest hashed catalogue stubs. Recorded Gate A digest already matched sorted installed-key set under **`component-set-v2`**.

**Freshness recert (NOT rebind):** post-parser-fix pinned probe `gate-a-probe-post-parser-fix-20260801.json` (sha256 **f3dd1c328edb6546925e6f19cb0e2f62bc213e66942975508feebe8304e187d2**; **`drifted_fields=0`**); certified tuple **byte-identical**. Human packet: [`HUMAN_GATE_GATE_A_IDENTITY_DRIFT_20260801.md`](HUMAN_GATE_GATE_A_IDENTITY_DRIFT_20260801.md). See **L-21** in [`ENGINEERING_LESSONS.md`](ENGINEERING_LESSONS.md). Host tooling validates probe artifact **sha256** — substituting arbitrary files (including the defective campaign probe) **fails**; stale evidence (>24h) **blocks** live tooling until fresh reprobe.

| Step | Expendable class (`expendable_development_router`) | Non-expendable |
|---|---|---|
| 1 | Optional encrypted startup-config backup (§16) before disruptive work | Same |
| 2 | Run pinned-SSH Gate A probe (§14); artifact under `data/artifacts/` | Same |
| 3 | Record **observed** tuple + evidence artifact path; **never fabricate** values | Same |
| 4 | **Authorized rebind:** update `gate-a-certification.json`, `STATUS.yaml`, docs atomically with **dated rebind event** | Operator confirms health; human sends §6-style approval for **new** sanitized tuple; then implementer updates SSOT |
| 5 | Live writes permitted only after recorded tuple matches live device | Same fail-closed rule |

Rules:

- Prior tuple and pre-change backup remain **historical**; backup metadata only in docs (no locator, IP, or content hash).
- Exact component presence is not a Gate A certification claim; Gate B preflight must freshly re-observe it.
- Gates **B/C/D stay CLOSED**; component install alone does not open write gates.
- Do not relabel the pre-change backup as current-tuple baseline.

---

## 18. Component install semantics (Add-router wizard / bootstrap context)

**Purpose:** Before any future component write path, bootstrap discovery surfaces what a Keenetic **component install** implies so the Add-router wizard can warn the operator.

### Documented (vendor CLI / operator research — offline SSOT)

| Step | Semantics |
|---|---|
| `components list` | Read-only inventory; may return `"continued": true` → poll until final payload with `sandbox`, `firmware`, `component` (bootstrap: POST once, then bounded GET poll — see [`API_CONTRACT.md`](contracts/API_CONTRACT.md) §7.9) |
| `components install <name>` | Schedules component install |
| `components commit` | Applies pending component changes |
| **Side effect** | Install + commit **rebuild KeeneticOS to the latest build on the device update channel** and trigger an **automatic reboot** (management downtime). Rebuild is a **process** effect and occurs even when channel target equals installed firmware — see `firmware_version_changes` in bootstrap discovery side-effects |

Bootstrap discovery exposes these as **informational** `component_change_side_effects` (including `firmware_version_changes` separate from rebuild/reboot/downtime) and channel/target assessments — **not** write authorization.

**Institutional memory (offline-verified, 2026-07-31):** A derived boolean `ssh_component_installed` alone was insufficient to settle a real browser-agent vs API dispute about whether SSH was listed in `components/list`. Bootstrap discovery now emits **`components_inventory`** (sanitized capped list) plus **`ssh_component_determination`** (how the boolean was derived) so operators and agents can verify claims without trusting a single flag. Wizard step 2 shows compact count + SSH fact only — not a full component browser.

**Institutional memory (live expendable lab, 2026-07-31):** On the current dedicated development router, `components/list` returns per-component entries as **`{id, version}` only** — no `installed` boolean. Treating `component.ssh.installed` as the sole lookup produced a **false negative** (`ssh_component_missing` while SSH was present). Correct semantics: **key presence in the component map means installed** when `installed` is absent; explicit `installed: true|false` still wins when present. `ssh_component_determination.determination_shape` records which rule applied (`presence_in_map` vs `explicit_installed`). Empty or timed-out inventory yields `inventory_unavailable` — never `key_absent`.

### UNVERIFIED (do not claim in code/tests/docs as live-proven)

| Item | Status |
|---|---|
| Exact RCI HTTP body for `components commit` | **UNVERIFIED** — CLI research only; no live commit probe in v0 |
| Channel target `firmware.version` shape on all firmware branches | **Offline-verified** on NC-1812 **4.03.C.6.4-16** fixture only |
| Continued GET poll on all KeeneticOS versions | **Offline-verified** protocol shape; live timing bounds not device-certified |

**Safety:** Bootstrap discovery remains **read-only**; Gates **A–D** unchanged; plain HTTP **`certification_eligible: false` always**. Future install/commit APIs require separate hardware gate + operator approval.

---

## 19. READ-ONLY OBSERVED — route, uplink, USB (2026-07-31)

Secondary institutional facts from Gate A ReadOnlyCertified rebind (`NC-1812`, firmware `5.01.C.1.0-0`). Wi‑Fi AP/station inventory detail: [`OPERATOR_WIFI_DISCOVERY.md`](OPERATOR_WIFI_DISCOVERY.md) §2b.

| Topic | Observation |
|---|---|
| Default route read path | **`show ip route`** — use this path; **`show ipv4 route`** is **not** the observed working read |
| Uplink priority fields | **`global`** + **`priority`** observed; **`standby`** **NOT** observed on this tuple |
| USB modem interfaces | Components **`usb`**, **`usbmodem`**, **`usblte`**, **`usbqmi`**, **`usbnet`** **confirmed installed** on current rebind unit (2026-07-31) — cellular/USB-modem uplink needs **no** component download; **no** USB modem interface objects in `show interface` inventory **without** physical modem plugged in; modem operation **NOT** device-verified |
| WireGuard component | **`wireguard` installed** on current rebind unit (2026-07-31 afternoon) after connectivity restored; authorized Gate A identity-drift rebind #2 moved digests to `sha256:23bd35bc…` / `sha256:c34adec…`. **Historical (phase-1, pre-uplink):** component absent; `install wireguard` → `Components::Lister … unavailable` — connectivity blocker, **not** hardware limitation (prior unit had WG component + live write evidence) |

**No write grammar added.** Station join/uplink write paths remain **UNKNOWN** / T4-gated.

---

## 20. Automated same-tuple freshness recertification (2026-08-06)

**Purpose:** the opening-freshness window (`opening_freshness_hours`, default **24**) had required a human/agent to manually re-run §14's probe roughly once a day, purely to refresh the evidence pointer when the tuple had NOT changed. This section adds automation for that exact repeated case only — it does **not** relax fail-closed behaviour, and it never touches the certification file when the newly probed tuple differs from the certified one in any field, or when `certification_eligible`/`identity_complete` are not both `true`.

| Rule | Detail |
|---|---|
| Scope | **Same-tuple freshness refresh ONLY.** Any drift → certification file left completely untouched, non-zero exit, human/Main must review (silent rebind remains forbidden — this automation cannot bypass that) |
| Core script | `scripts/gate_a_freshness_lib.py` — pure library (`is_due`, `evaluate_and_apply`, `diff_tuple_fields`); no disk writes except via `write_config`, which is only ever called from the CLI, never from the pure evaluation function |
| CLI | `scripts/recertify-gate-a-freshness.py` / `.ps1` — wraps the existing §14 probe CLI (`probe-gate-a.py`) via subprocess; no new SSH/DPAPI logic; defaults match the current lab tuple (host `192.168.2.1`, username `admin`, `credential_ref cred_69280efb9361ca2911e99d383f0ce474`, pin `SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY`, source `192.168.2.10`) |
| Manual run | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\recertify-gate-a-freshness.ps1 -Force` — probes now regardless of the due-check; drop `-Force` to only act when within `-RefreshMarginHours` (default 12h) of the deadline; add `-DryRun` to probe+evaluate without writing |
| Exit codes | `0` = recertified or not-due (no-op); `2` = probe subprocess failed; `3` = drift/ineligible detected (file untouched — read stderr for the diffed field names); `4` = config load error |
| Scheduling | `scripts/install-gate-a-freshness-task.ps1` registers **two** Windows Scheduled Tasks via `schtasks.exe /rl LIMITED` (default names `RouterControl-GateA-FreshnessAuto-Interval` at `/sc HOURLY /mo 4`, and `-Logon` — `/sc ONLOGON`, or `/sc MINUTE /mo 30` fallback when `ONLOGON` itself needs elevation on the host) running under the current Windows user; `scripts/uninstall-gate-a-freshness-task.ps1` removes both. **Important:** the `ScheduledTasks` PowerShell module (`Register-ScheduledTask`) requires an **elevated** session on this class of machine even for a task that runs as the current non-admin user — `schtasks.exe` does not have that requirement, which is why the install script uses it |
| Logs | `data/artifacts/gate-a-recert-automation.log` (one line per CLI invocation: `not_due` / `recertified proactive=...` / `drift_detected: <fields>` / `probe_failed: ...`) and `data/artifacts/gate-a-recert-task.log` (raw stdout+stderr from unattended scheduled runs) — both gitignored, no secrets |
| Why this still needs a logged-in session | The Task Scheduler tasks only fire while the configured Windows user is logged on — this matches the pre-existing constraint that the DPAPI `CurrentUser`-scoped credential vault (§13) can only be decrypted inside that same user's interactive session; there is no headless/SYSTEM path for this vault by design |
| Offline tests | `tests/test_gate_a_freshness_automation.py` — 7 tests, fully offline (no router/DPAPI/network), including a round-trip through the real `router_control.adapters.netcraze.certification.load_gate_a_certification` proving an automated same-tuple refresh genuinely reopens Gate A |
| Full narrative | `.cursor/plans/main-decisions-local-hub.md` §M-53 (live proof, three real bugs found+fixed during setup, exact commands run) |
| **Live host must also reload, not just the file** | An **already-running** `router_control_host` process caches `try_load_gate_a_certification()` **once** at startup on `HostState.gate_a_certification`, and every write-gating route (`wifi_apply_routes.py`, `wireguard_apply_routes.py`, `wifi_station_apply_routes.py`, `vpn_catalog_status_routes.py`) and the connection-health check read that SAME cached object — keeping the on-disk file fresh (this section) is necessary but **not sufficient** on its own for a long-lived host process |
| Live-reload watchdog | `router_control/application/gate_a_refresh_watchdog.py` — background asyncio task (pattern mirrors `vpn_watchdog_service.py`) that reloads the cert from disk every `GATE_A_REFRESH_POLL_SECONDS` (env, default `120`, floor `30`) and swaps `host.gate_a_certification` in place; **enabled by default** (`GATE_A_REFRESH_WATCHDOG_ENABLED`, unlike the opt-in VPN watchdog) since it is read-only and side-effect-free; on any reload failure it leaves the last-known-good certification untouched, never nulls it. Wired in `app.py`'s `lifespan()`, only started when `adapter_mode == "live"` and a cert was loaded at startup |
| One-time catch-up | A host process that was already running BEFORE this watchdog was deployed still needs one manual restart to start benefiting from it; every restart after that is self-sufficient — the watchdog then keeps that same process's in-memory certification in sync with the scheduled-task-refreshed file indefinitely, with no further restarts needed for freshness alone |

---

## 15. Links (scripts)

- Hardware gates: [`contracts/HARDWARE_GATES.md`](contracts/HARDWARE_GATES.md)
- API gates: [`contracts/API_CONTRACT.md`](contracts/API_CONTRACT.md) §10
- Status SSOT: [`STATUS.yaml`](STATUS.yaml)
- Test lanes: [`contracts/TEST_STRATEGY.md`](contracts/TEST_STRATEGY.md)
- OpenAPI artifact: [`contracts/openapi-v0.json`](contracts/openapi-v0.json)
