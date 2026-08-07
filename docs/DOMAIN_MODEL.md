# Доменная модель Router Control

## Назначение и границы

Этот документ фиксирует vendor-neutral модель управления роутерами. Имена сущностей и полей приведены на английском; пояснения и правила — на русском. Модель не содержит Keenetic/RCI JSON, CLI-команд, FastAPI-типа запросов или деталей конкретного имени интерфейса.

Router Control хранит намерение оператора, подтверждённые наблюдения и историю применения раздельно. Он не считает текущий IP-адрес, hostname, default gateway или имя интерфейса идентичностью устройства. Normative REST surface — [`contracts/API_CONTRACT.md`](contracts/API_CONTRACT.md).

Контексты первого цикла:

- `RouterInventory` — роутеры, площадки, endpoints, capabilities и observations;
- `CredentialVault` — ссылки на локально защищённые секреты;
- `VpnLifecycle` — каталог VPN-профилей и назначения на роутеры;
- `Provisioning` — desired revisions, plans, apply и verify;
- `JobsAudit` — durable operations/jobs/steps, idempotency и audit; persistence schema — [`contracts/PERSISTENCE_CONTRACT.md`](contracts/PERSISTENCE_CONTRACT.md);
- `Commissioning` — read-only commissioning runs и readiness checks (M1); fake + optional Gate A RO assess; never `Commissioned`/`WriteCertified`;
- `EventPreset` — offline four-zone intent catalog (M2): immutable revisions, validation/readiness, planner preview; `write_ready=false` always; CredentialRef-only Wi-Fi;
- **P2 immutable deployment (2026-07-22, offline/fake):** `PublishedPreset` → `RouterDeploymentRevision` → `DesiredRevision` (deployment-bound) → session-bound `ChangePlan` → Confirm/Apply fake path; family certification snapshots; managed ownership deltas; atomic verify-success bundle; **not live-ready**;
- `RoutingPolicy` и `TrafficDiscovery` — зарезервированы; TrafficDiscovery proposals (SLICE-8 offline) не блокируются AWG/routes для M1–M3 readiness ([ADR-0005](adrs/0005-local-first-commissioning-roadmap.md)).

Milestone порядок исполнения — [`contracts/ROADMAP.md`](contracts/ROADMAP.md) M0–M8; не путать с historical SLICE numbering.

## Идентичность и общие типы

Все aggregate roots получают случайный стабильный ID (UUID/ULID или эквивалентный opaque string), создаваемый Router Control и не переиспользуемый после удаления.

| Тип | Смысл |
|---|---|
| `SiteId` | Стабильная идентичность площадки/Hub deployment |
| `RouterId` | Стабильная идентичность enrolled роутера |
| `ProfileId` | Стабильная идентичность импортированного VPN-профиля |
| `AssignmentId` | Идентичность назначения профиля роутеру |
| `RevisionId` | Идентичность immutable desired revision |
| `ResourceId` | Локальная идентичность ownership record |
| `PlanId` | Идентичность immutable плана |
| `OperationId`, `JobId`, `StepId` | Идентичности пользовательской операции, исполнения и шага |
| `ArtifactId`, `AuditEventId` | Идентичности артефакта и события |

`RouterId` не выводится только из IP или MAC. При enrollment фиксируются доступные аппаратные признаки (`serial`, базовый MAC, model и vendor fingerprint), а их последующее несовпадение блокирует writes и требует явного re-enrollment. Endpoint можно менять без смены `RouterId`.

Имена интерфейсов (`Wireguard0`, `Wireguard1`), route indices и vendor object names — наблюдаемые locator-ы. Они могут входить в `external_locator`, но не становятся ID доменной сущности.

Время хранится в UTC. Любое решение, основанное на observation, указывает `observed_at`, `valid_until` и источник.

## Основные сущности

### `Site`

Логическая площадка, на которой работает Hub.

- `site_id`, `display_name`, `timezone`;
- `created_at`, `updated_at`;
- набор связанных `Router`.

Схема multi-router-ready с первого дня: каждый router-scoped объект содержит `router_id`, даже если UI v1 показывает один роутер.

### `Router`

Enrolled устройство, которым может управлять система.

- `router_id`, `site_id`, `display_name`;
- `vendor`, `model`, `hardware_revision`;
- подтверждённые identity claims и их fingerprint;
- один или несколько изменяемых management endpoints;
- `credential_ref_id`;
- lifecycle status: `PendingEnrollment | Enrolled | IdentityMismatch | Disabled`;
- ссылка на последнюю capability/observation и текущие revision markers.

Endpoint, IP, hostname и default gateway — адреса доступа, а не identity. Перед каждой mutation adapter повторно проверяет identity.

### `RouterCapability`

Timestamped snapshot возможностей конкретного `Router`.

- `capability_id`, `router_id`;
- firmware/component versions;
- поддерживаемые read/write функции, safe configuration, VPN kinds и ограничения;
- `observed_at`, `valid_until`, `source`;
- `certification_status`: `Unknown | ReadOnlyCertified | WriteCertified | Unsupported`.

Переходы и gates: [`contracts/HARDWARE_GATES.md`](contracts/HARDWARE_GATES.md). Gate A → `ReadOnlyCertified`; Gate B per family → `WriteCertified`; negative evidence → `Unsupported`; expiry/revocation → downgrade toward `Unknown`. Отсутствующая, просроченная или неподтверждённая capability приводит к fail-closed для write.

### `CredentialRef`

Opaque ссылка на секрет в `CredentialVault`.

- `credential_ref_id`, `router_id`, `kind`;
- `provider` (локально — `DPAPI.CurrentUser`);
- непрозрачный provider locator;
- `created_at`, `rotated_at`, `revoked_at`.

**Secret-kind vocabulary** (без DDL): `router_management_password`, `router_session_envelope`, `awg_private_key`, `awg_preshared_key`, `backup_encryption_key`, `hub_enrollment_key` — см. [`contracts/SECURITY_OPS.md`](contracts/SECURITY_OPS.md).

Домен не получает функцию «прочитать секрет для UI». Plaintext password, RCI session, AWG private key и recovery material запрещены в API DTO, SQLite payload, logs, plans, jobs, audit и diagnostics. На удаление/ротацию ссылающихся credentials действуют явные lifecycle checks.

### `VpnProfileArtifact`

Импортированный и провалидированный VPN-профиль как артефакт каталога.

- `profile_id`, `display_name`, `vpn_kind` (`AmneziaWG` в v1);
- версия parser/schema;
- redacted metadata и digest исходного нормализованного содержимого;
- ссылки на encrypted secret parts через `CredentialRef`/secret store;
- validation status и список unsupported fields;
- `created_at`, `superseded_at`.

Импорт не означает применение. Unsupported fields дают validation error, а не молчаливое отбрасывание. Каталог не ограничен одним профилем.

### `TunnelAssignment`

Намерение использовать `VpnProfileArtifact` на конкретном `Router`.

- `assignment_id`, `router_id`, `profile_id`;
- стабильный logical role, например `primary-event-vpn`;
- desired activation state и policy metadata;
- observed vendor locator, если он найден;
- `created_at`, `retired_at`.

Ограничение «на роутере один active AWG assignment» — policy v1, а не универсальный invariant домена. Имя `Wireguard0` не является `AssignmentId`.

### `RouterObservation`

Immutable timestamped read-back состояния роутера.

- `observation_id`, `router_id`;
- identity fingerprint и capability reference;
- нормализованный state snapshot/digest;
- resource version/ETag;
- `observed_at`, `valid_until`, collection status и redacted error;
- источник и adapter version.

Observation является `fresh`, только если успешно завершена, identity совпадает и `now <= valid_until`. После TTL она `stale`: её можно показывать с предупреждением, но нельзя использовать как основание нового mutation plan. Новое наблюдение не перезаписывает историю.

### `DesiredRevision`

Immutable снимок полного управляемого намерения для одного `Router`.

- `revision_id`, `router_id`, монотонный `revision_number`;
- canonical desired document/digest;
- `parent_revision_id`;
- actor/reason и `created_at`;
- `based_on_observation_id`.

Редактирование создаёт новую revision. Existing revision не изменяется. Клиент получает ETag текущей desired revision и при mutation передаёт `If-Match`; несовпадение возвращает conflict/precondition failure и не создаёт план. HTTP semantics — [`contracts/API_CONTRACT.md`](contracts/API_CONTRACT.md) §3, §7.4.

### `ManagedResource`

Ownership record для объекта, которым владеет Router Control.

- `resource_id`, `router_id`;
- `resource_kind` и стабильный logical key;
- `owner`/`manager` (`router-control`);
- desired revision, создавшая или усыновившая ресурс;
- observed vendor locator и fingerprint;
- lifecycle: `Planned | Present | Missing | Retired`;
- `last_observation_id`, timestamps.

Наличие похожего имени или конфигурации не доказывает ownership. Ресурс становится managed только после успешного создания Router Control либо явного подтверждённого adoption. Удалять, переименовывать и заменять можно только managed resources.

### `ChangePlan`

Immutable redacted diff между `DesiredRevision` и fresh `RouterObservation`.

- `plan_id`, `router_id`, `revision_id`, `observation_id`;
- digest expected desired и observed resource version/ETag;
- ordered high-level changes и postconditions;
- risk classification, backup requirement, safe-configuration requirement;
- expiry, actor, `created_at`, confirmation state.

Plan не содержит raw RCI-команд или секретов. **Confirm** привязывает plan digest, expiry и actor session — не password re-entry ([`contracts/SECURITY_OPS.md`](contracts/SECURITY_OPS.md)). Confirm не делает stale plan актуальным: перед запуском сверяются identity, desired revision, observation version, digest и expiry. Любое расхождение требует нового observation и plan. Operator scenarios: [`contracts/SCENARIOS.md`](contracts/SCENARIOS.md); implementation sequence: [`contracts/ROADMAP.md`](contracts/ROADMAP.md).

### `Operation`, `Job`, `Step`

`Operation` — пользовательское намерение и API-visible lifecycle; `Job` — одна durable попытка исполнения; `Step` — checkpointed единица работы.

- `Operation`: `operation_id`, `router_id`, kind, actor, `plan_id`, `idempotency_record_id`, aggregate status, timestamps;
- `Job`: `job_id`, `operation_id`, `router_id`, attempt, status, lease owner/until, heartbeat, recovery decision, timestamps;
- `Step`: `step_id`, `job_id`, ordinal, kind, status, checkpoint, attempts, timestamps, redacted error.

Базовый reconcile lifecycle:

`Pending → Planning → Applying → Verifying → Converged | Drifted | Failed | RecoveryRequired`.

Execution lifecycle детальнее различает `Queued`, `Leased`, `Running`, `Succeeded`, `Failed`, `Cancelled`, `Lost` и `RecoveryRequired`. Terminal status не возвращается в running.

Шаги проектируются идемпотентными в **едином порядке** ([`contracts/RCI_POLICY.md`](contracts/RCI_POLICY.md)):

`preflight` → `identity-check` → `observe` → `backup` → `plan-preconditions` → `Confirm` → `begin-fail-safe-configuration` → `apply` → `read-back` → `verify` → `save` | `compensate`.

Legacy step names `begin-safe-configuration` эквивалентны **Fail-safe Configuration** (primary term; vendor alias Safe Configuration). Checkpoint сохраняется после подтверждённого результата шага, а не до него. Неизвестный исход внешней mutation после crash нельзя автоматически считать failed или повторять вслепую: сначала выполняется read-back и выбирается resume, compensate либо `RecoveryRequired`.

Одновременно может исполняться не более одного mutation job на `RouterId`. Read-only jobs допустимы параллельно, если не нарушают active safe-configuration session. Lease и атомарный claim обеспечивают правило между workers/processes; in-process lock сам по себе недостаточен.

**M3 runtime (2026-07-22):** `DurableWorker` maintains at most **one** dedicated heartbeat activity (0|1 thread) per active claim, renewing `lease_until_epoch` during long handlers; `renew_lease` / `complete_job` are fence-guarded store methods; typed handler registry rejects unknown/live mutation kinds before external I/O.

**Prototype UI (2026-07-22):** operator surfaces for M1–M3 aggregates are presentation-only on `router_control_host` (`/settings/router-control`); domain invariants unchanged — no secret read port, Apply disabled when write gates closed ([`OPERATOR_UI.md`](OPERATOR_UI.md)).

### `IdempotencyRecord`

Durable привязка mutation request к результату.

- `idempotency_record_id`, scope/actor, `router_id`, operation kind;
- `idempotency_key`;
- canonical request digest;
- связанный `operation_id`;
- status, response reference, `created_at`, `expires_at`.

Уникальность задаётся как минимум по `(scope, router_id, operation_kind, idempotency_key)`. Повтор с тем же digest возвращает исходную operation/response; тот же key с другим digest — conflict. Record создаётся атомарно с `Operation`. SQLite layout и retention — [`contracts/PERSISTENCE_CONTRACT.md`](contracts/PERSISTENCE_CONTRACT.md) §6.

### `AuditEvent`

Append-only событие безопасности и управления.

- `audit_event_id`, `occurred_at`;
- actor type/id, request/correlation IDs;
- `router_id`, `operation_id`, `job_id`, `plan_id`;
- action, outcome, risk/danger level;
- redacted summary и digest исходного запроса;
- artifact references и версии Hub/adapter.

Audit event не обновляется и не служит mutable job state. Секреты и неотредактированные конфиги в него не попадают. Append-only store и atomic creation with operations — [`contracts/PERSISTENCE_CONTRACT.md`](contracts/PERSISTENCE_CONTRACT.md) §7–8.

### `CommissioningRun`

Durable read-only readiness assessment для одного `Site`/`Router` (M1). Zero router writes; never переводит систему в `Commissioned` или `WriteCertified`.

- `run_id`, `site_id`, `router_id`, `mode` (`fake` | `live`);
- `state`, optimistic `version`, `correlation_id`;
- redacted `summary_redacted`, `report_digest`, `assessed_at`;
- `created_at`, `updated_at`.

**States:** `Draft` → `Observing` → `Assessing` → terminal (`ReadyReadOnly` | `Blocked` | `Failed` | `Cancelled`).

| From | Legal targets |
|---|---|
| `Draft` | `Observing`, `Cancelled` |
| `Observing` | `Assessing`, `Blocked`, `Failed`, `Cancelled` |
| `Assessing` | `ReadyReadOnly`, `Blocked`, `Failed`, `Cancelled` |
| `ReadyReadOnly` | `Cancelled` |

Terminal для cancel: `Blocked`, `Failed`, `Cancelled`. `ReadyReadOnly` **не** terminal для cancel — operator may cancel a read-only-ready run.

`ReadyReadOnly` означает read-only readiness; write gates (B/C/D) могут оставаться closed — это отражается в `write_blockers`, а не блокирует RO terminal. Invariants: `never_commissioned`, `never_write_certified`, `write_ready=false` на API surface.

Assess idempotent и crash-safe: interrupted `Assessing` resume без illegal transition; partial checks очищаются при resume.

### `ReadinessCheck`

Append-only результат одной проверки внутри `CommissioningRun`.

- `check_id`, `run_id`, `check_kind`, `ordinal`, `attempt`;
- `outcome`: `Passed` | `Failed` | `Blocked` | `Skipped`;
- `blocking`, `write_related`;
- redacted `summary_redacted`, optional `evidence_digest`;
- `created_at`.

**Check kinds (M1):** `site_router_linkage`, `enroll_status`, `observation_fresh`, `gate_a_open`, `identity_tuple_match` (RO-blocking); `gate_b_not_write_certified`, `gate_c_closed`, `gate_d_closed` (write-related blockers, non-blocking for RO terminal).

RO-blocking checks с `Failed`/`Blocked` → run terminal `Failed`/`Blocked`. Write-related checks never block `ReadyReadOnly`; они попадают в report `write_blockers`.

### `EventPreset` / `EventPresetRevision` (M2)

Offline catalog event-booth network intent. Zero router writes; `write_ready=false` always on API surface.

**`EventPreset`:**

- `preset_id`, `site_id`, `name`, optimistic `version`;
- `current_revision_id`, optional `published_revision_id`;
- `created_at`, `updated_at`.

**`EventPresetRevision` (immutable after insert):**

- `revision_id`, `preset_id`, `revision_number`;
- `canonical_document` (Guest/Promo/Staff/AdminServer zones, uplink, rack assets, local order URL);
- `canonical_digest` (excludes timestamps/secrets);
- `validation_status`: `Draft` | `ValidOffline` | `Invalid` | `ReadyForReadOnlyAssessment`;
- redacted `summary_redacted`, `created_at`.

**Intent VOs (vendor-neutral):** `NetworkZoneIntent`, `UplinkIntent` (Ethernet/WifiWan/LocalOnly/Lte; WifiWan optional `ssid`, `band`, `credential_ref_id`, `bssid`, `priority`; distinct `captive_portal_client` — see portable rack scenario), `WifiIntent` (CredentialRef-only passphrase; optional `wpa_mode` + `band`; host `captive_portal` distinct from uplink client marker), `WireguardIntent` (bounded test `wg_id`; optional 9-int `asc_args`; `enabled` → generic interface up/down), `DhcpIntent`, `DnsIntent`, `FirewallIntent`, `RackAssetIntent`, `ReadinessFinding`.

**UplinkIntent (2026-07-31, portable rack foundation — offline only):**

| Field | Type / default | Notes |
|---|---|---|
| `mode` | `UplinkMode` | `Ethernet`, `WifiWan`, `LocalOnly`, `Lte` (deferred) |
| `ssid`, `band`, `credential_ref_id`, `bssid` | required when `mode=WifiWan`; **forbidden** on other modes | When `mode=WifiWan`: non-empty `ssid` + `credential_ref_id` required; `band` defaults `BAND_2_4GHZ`; optional `bssid` validated as MAC; CredentialRef-only — no plaintext PSK |
| `priority` | int, default `100` | Lower = higher preference (modeling only; no failover compiler) |
| `captive_portal_client` | bool, default `false` | **Client** direction (venue portal) — distinct from `WifiIntent.captive_portal` (host Coova-Chilli); readiness `uplink_captive_portal_client_unsupported` |

Planner: `WifiWan` remains `support: unsupported` / `certification_blocker: wifi_wan_not_certified` even when fully specified. Scenario: [`SCENARIO_PORTABLE_EQUIPMENT_RACK.md`](SCENARIO_PORTABLE_EQUIPMENT_RACK.md).

**WifiIntent (2026-07-24, offline product model):**

| Field | Type / default | Notes |
|---|---|---|
| `ssid`, `enabled`, `credential_ref_id`, `captive_portal`, `guest_isolation` | existing | CredentialRef-only; no plaintext PSK |
| `wpa_mode` | `WifiWpaMode`, default `WPA2` | `WPA3` compiles full sealed sequence with `verification_status=device_verified_wpa2` (same literal as WPA2) — WPA3-Personal uses `authentication wpa-psk` + `encryption wpa3` (Keenetic CLI Reference KN-1812 / KeeneticOS 5.0; no `authentication sae`); device-verified on NC-1812 5.01.C.1.0-0 (2026-07-24); evidence `data/artifacts/wifi-wpa3-live-reverify-192.168.2.1-20260724.json`. `WPA2_WPA3_MIXED` compiles with `verification_status=device_verified_wpa2` — grammar `authentication wpa-psk` + `encryption wpa2` + `encryption wpa3`; readback `wpa2,wpa3`; device-verified on NC-1812 5.01.C.1.0-0 (2026-07-24); evidence `data/artifacts/wifi-wpa2wpa3-mixed-live-verify-192.168.2.1-20260724.json` |
| `band` | `WifiBand`, default `BAND_2_4GHZ` | Maps to `WifiMaster0`; `BAND_5GHZ` → `WifiMaster1`; compiler enforces against `ap_id` |

Offline compiler: `router_control/application/wifi_apply_planner.py` (`compile_wifi_intent_to_ops`) emits ordered sealed op descriptors for WPA2, WPA3-Personal, and WPA2+WPA3 mixed (all device-verified); no live dispatch claim; WriteCertified NOT claimed; `write_shapes_registered` remains false.

**WireguardIntent (2026-07-24, offline product model):**

| Field | Type / default | Notes |
|---|---|---|
| `wg_id` | string | Must be `Wireguard5`–`Wireguard9` (test interfaces only) |
| `enabled` | bool | Maps to generic sealed `interface up|down` after WG ops |
| `asc_args` | optional tuple of 9 or 16 ints | 9-int bounds: jc..s2 0..99999, h1..h4 0..4294967295 (`validate_asc_args` SSOT); 9-int → device-verified apply path (small test values live-verified 2026-07-24 only); 16-int → planner `unsupported_pending_verification` |
| `private_key_credential_ref_id` | optional string | Vault ref (`awg_private_key` kind); resolved only at dispatch |
| `preshared_key_credential_ref_id` | optional string | Vault ref (`awg_preshared_key` kind); requires `peer_public_key` |
| `peer_public_key` | optional string | Non-secret WireGuard peer public key (base64 shape) |
| `peer_endpoint` | optional string | Non-secret `host:port` |
| `peer_allow_ips` | optional string | Non-secret CIDR, `ipv4 mask` (dotted IPv4 or numeric prefix), or `ipv4/prefix` |
| `peer_keepalive_interval` | optional int 3..3600 | Non-secret keepalive |
| `peer_rci_shape` | optional enum, default `nested_rci` | Only **`nested_rci`** accepted at runtime; explicit **`path_style`** → **422** `peer_rci_shape_unsupported` (path-style peer grammar **REJECTED** live 2026-07-24; sealed offline templates retained for historical reference) |

Secret/peer ops compile with overall `verification_status=pending_live_verification` (nested JSON resource write when `nested_rci` — **device-verified write ACCEPTED** on NC-1812 5.01.C.1.0-0 2026-07-24 re-verify; evidence `data/artifacts/awg-peer-nested-rci-live-reverify-192.168.2.1-20260724.json`; path-style peer grammar when `path_style` — **REJECTED** live 2026-07-24). **Private-key transport is partially device-verified** (NC-1812 live probe 2026-07-24). Preshared-key remains pending; **tunnel observe path** (`tunnel_verification_status` dead-peer + healthy) **DEVICE-CONFIRMED** 2026-07-31, first real handshake 2026-08-05 (§M-24..§M-26); **`SET_IP_ADDRESS` + `wireguard_ip_global` DEVICE-VERIFIED** (§M-24/M-27); default-route via tunnel **reversible** — distinct from planner secret axis; **do not** claim kill-switch/named policy, WriteCertified, or `write_shapes_registered=true`. IPv6 allow-ips **explicitly refused** offline. Raw `private_key` / `psk` body fields rejected.

Offline compiler: `router_control/application/wireguard_apply_planner.py` (`compile_wireguard_intent_to_ops`); sealed WG ops via `wireguard_rci`; secrets via `credential_ref_id` only at dispatch; up/down via `interface_rci`; WriteCertified NOT claimed.

**Invariants:** exactly four canonical zones; AdminServer sole management zone; Guest order-page-only + client isolation when Wi-Fi enabled; subnet/VLAN/pool/reservation overlap rejected; IPv6 posture explicit; unknown fields rejected; missing AWG/routes/LTE or Gates B/C/D block apply/write fragments only — not sound LAN `ValidOffline`.

### Sealed bounded apply vs preset certification pipeline (dual path)

Two **intentionally separate** apply worlds exist today. Do **not** read `preset_planner` markers such as `awg_not_implemented` / `awg_apply_deferred` as «AWG apply does not exist».

| Path | Role | Key modules | HTTP / dispatch |
|---|---|---|---|
| **(a) Sealed bounded apply** | Lab/test-AP Wi-Fi + AWG + VLAN/DHCP/DNS/firewall offline sealed executors under bounded allowlists | `router_control/application/wifi_apply_planner.py`, `wifi_apply_service.py` (Wi-Fi apply adds offline compensating rollback, router error taxonomy, idempotent re-apply — **not** new device-verified); `wireguard_apply_planner.py`, `wireguard_apply_service.py`; `vlan_apply_planner.py`, `vlan_apply_service.py`; `dhcp_apply_planner.py`, `dhcp_apply_service.py`; `dns_apply_planner.py`, `dns_apply_service.py`; `firewall_apply_planner.py`, `firewall_apply_service.py`; sealed ops in `wifi_rci.py` / `wireguard_rci.py` / `vlan_rci.py` / `dhcp_rci.py` / `dns_rci.py` / `firewall_rci.py` | POST `/api/router-control/v1/wifi/preview\|apply\|teardown` and `/wireguard/preview\|apply\|teardown`; VLAN/DHCP/DNS/firewall **preview-only** HTTP (`/vlan/preview`, `/dhcp/preview`, `/dns/preview`, `/firewall/preview`; `verification_status=offline_unverified`; no apply routes); per-campaign T4 + confirm for live Wi-Fi/AWG; VLAN/DHCP/DNS/firewall **not** Gate B certified / **not** WriteCertified |
| **(b) Preset / deployment certification pipeline** | M2 event-preset readiness + immutable deployment plan compilation gated on Gate B / WriteCertified | `router_control/application/preset_planner.py` (readiness blockers: `awg_not_implemented`, `awg_apply_deferred`, `routes_apply_deferred`, `lte_apply_deferred` when `awg_supported` / gate flags block); `router_control/application/deployment_planner.py` (compiles VLAN/DHCP/DNS/firewall plan items — all four have sealed offline executors in path (a); preset apply still gated on Gate B / WriteCertified) | Preset API persists intent only; full preset apply fragments remain blocked until family certification — **orthogonal** to sealed `/wifi/*` and `/wireguard/*` |

Sealed bounded apply may proceed under human-approved per-campaign T4 on bounded test resources while preset apply fragments still emit `*_deferred` / `*_not_implemented` because Gate B is **not** WriteCertified and `write_shapes_registered` remains **false**.

**Grammar doc citations (2026-08-01):** every sealed planner op notes grammar via `router_control/application/grammar_doc_refs.py` (`GRAMMAR_OP_REGISTRY`; anchor `#snippet` verified offline). Ops without a confirmed discovery source carry `grammar source not fixed (источник не зафиксирован)` in notes — property-tested (`tests/test_planner_properties.py::test_all_compiled_ops_grammar_doc_refs_resolve_or_mark_unconfirmed`). Station DHCP compensation baseline reads `address dhcp` from `show rc interface` only (not runtime `summary.ipv4`); unknown → fail-closed skip.

**Network-family security scaffold (2026-08-01):** VLAN/DHCP/DNS/firewall/VPN policy planners expose PreState + compensation maps mirroring sealed Wi‑Fi/WG mechanics (`docs/OPERATOR_NETWORK_FAMILY_APPLY_SCAFFOLD.md`). Application services add typed rollback outcomes and optional `sealed_apply_runs` trail hook points; **`compensate_on_failure` defaults off**; HTTP remains preview-only for these families (no `/apply` or `/teardown` routes). Uncovered: `dhcp_set_lease`, `vpn_policy_ip_global`.

### BackupArtifact

Проверяемый артефакт для восстановления перед mutation.

- `artifact_id`, `router_id`, `operation_id`;
- kind, storage locator, content digest, size;
- identity fingerprint, source observation/revision;
- encryption/redaction metadata;
- `created_at`, retention и verification status.

Перед продолжением опасной mutation backup должен быть непустым, hash-verified и принадлежать ожидаемому роутеру. Metadata хранится в SQLite, bytes — в защищённом artifact storage.

## Desired, observed и applied

Для каждого `Router` различаются три указателя:

- `desired_revision_id` — последняя принятая оператором цель;
- `observed_revision`/ETag — версия последнего fresh read-back, не обещание соответствия цели;
- `applied_revision_id` — revision, чьи postconditions подтверждены повторным read-back.

`applied_revision_id` обновляется только после успешного `Verifying`. Успех отправки команды или HTTP 200 от роутера недостаточен.

Состояние:

- `Converged`: fresh observation удовлетворяет desired revision и applied marker ей соответствует;
- `Pending`: desired новее applied, но apply ещё не завершён;
- `Drifted`: fresh observation противоречит applied/desired для managed resources;
- `Unknown`: observation отсутствует, stale или identity/capability не подтверждены;
- `Failed`: job завершился известной ошибкой без неопределённого внешнего результата;
- `RecoveryRequired`: безопасное автоматическое решение после сбоя невозможно.

ETag для desired state строится из стабильной revision identity/digest. ETag observation отражает конкретную observed resource version. API `If-Match` защищает от lost update, но не заменяет транзакционную проверку plan preconditions непосредственно перед lease/apply. Revision pointers и verify-only `applied_revision_id` — [`contracts/PERSISTENCE_CONTRACT.md`](contracts/PERSISTENCE_CONTRACT.md) §3–4.

## Managed merge и drift

Planner сравнивает desired с полным observed inventory, но формирует mutations только для:

1. уже известных `ManagedResource`;
2. новых ресурсов из desired, которым будет назначен ownership record;
3. явно adopted ресурсов после отдельного подтверждения.

Unknown/unmanaged resources сохраняются без изменений, даже если они похожи, конфликтуют по имени или отсутствуют в desired. Такой конфликт останавливает plan либо требует другого locator/adoption; он не разрешается удалением чужого объекта. `prune=false` — default.

Drift классифицируется:

- `ManagedMissing` — managed ресурс исчез;
- `ManagedChanged` — управляемые поля изменены вне Router Control;
- `LocatorChanged` — vendor locator изменился, identity ресурса требует подтверждения;
- `UnmanagedConflict` — неизвестный ресурс мешает desired;
- `ObservationStale` — достоверное сравнение невозможно.

Reconcile исправляет только managed drift. Политика ownership важнее совпадения имени, IP или интерфейса.

## Later: `RouteSet` и `TrafficObservation`

Эти сущности резервируются для последующих фаз и не входят в API v0.

`RouteSet` — versioned logical collection публичных destination prefixes/rules, связанная с `RouterId` и logical tunnel role. Она имеет собственный digest, provenance, limits и managed-resource mapping. Private/RFC1918, CGNAT, link-local, multicast и иные запрещённые destinations отклоняются до plan.

`TrafficObservation` — immutable evidence о трафике с timestamp, TTL, confidence и redacted process/application attribution. Она может породить `RouteProposal`, но не изменяет `RouteSet` и не запускает apply напрямую. Auto-apply возможен только для отдельно определённой trusted policy.

## Инварианты

1. Stable ID отделён от endpoint, IP, hostname и vendor interface name.
2. Любая mutation привязана к `RouterId`, fresh identity-checked observation, immutable desired revision и confirmed non-stale plan.
3. Unknown capability/firmware запрещает writes.
4. Unknown resources сохраняются; destructive reconciliation разрешён только для доказанно managed resources.
5. `applied_revision_id` меняется только после read-back и postcondition verification.
6. Mutation jobs сериализуются per `RouterId`; claims, leases и checkpoints durable.
7. Crash с неизвестным внешним исходом ведёт к read-back/recovery, а не к слепому повтору.
8. Idempotency key с другим request digest всегда conflict.
9. Secrets отсутствуют в plans, payloads, audit, logs, diagnostics и обычных artifacts.
10. Route/capture entities не получают скрытого write path до своих фаз и safety gates.
