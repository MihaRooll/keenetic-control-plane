# Доменная модель Router Control

## Назначение и границы

Этот документ фиксирует vendor-neutral модель управления роутерами. Имена сущностей и полей приведены на английском; пояснения и правила — на русском. Модель не содержит Keenetic/RCI JSON, CLI-команд, FastAPI-типа запросов или деталей конкретного имени интерфейса.

Router Control хранит намерение оператора, подтверждённые наблюдения и историю применения раздельно. Он не считает текущий IP-адрес, hostname, default gateway или имя интерфейса идентичностью устройства.

Контексты первого цикла:

- `RouterInventory` — роутеры, площадки, endpoints, capabilities и observations;
- `CredentialVault` — ссылки на локально защищённые секреты;
- `VpnLifecycle` — каталог VPN-профилей и назначения на роутеры;
- `Provisioning` — desired revisions, plans, apply и verify;
- `JobsAudit` — durable operations/jobs/steps, idempotency и audit;
- `RoutingPolicy` и `TrafficDiscovery` — зарезервированы на последующие фазы.

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

Редактирование создаёт новую revision. Existing revision не изменяется. Клиент получает ETag текущей desired revision и при mutation передаёт `If-Match`; несовпадение возвращает conflict/precondition failure и не создаёт план.

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

Plan не содержит raw RCI-команд или секретов. **Confirm** привязывает plan digest, expiry и actor session — не password re-entry ([`contracts/SECURITY_OPS.md`](contracts/SECURITY_OPS.md)). Confirm не делает stale plan актуальным: перед запуском сверяются identity, desired revision, observation version, digest и expiry. Любое расхождение требует нового observation и plan.

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

### `IdempotencyRecord`

Durable привязка mutation request к результату.

- `idempotency_record_id`, scope/actor, `router_id`, operation kind;
- `idempotency_key`;
- canonical request digest;
- связанный `operation_id`;
- status, response reference, `created_at`, `expires_at`.

Уникальность задаётся как минимум по `(scope, router_id, operation_kind, idempotency_key)`. Повтор с тем же digest возвращает исходную operation/response; тот же key с другим digest — conflict. Record создаётся атомарно с `Operation`.

### `AuditEvent`

Append-only событие безопасности и управления.

- `audit_event_id`, `occurred_at`;
- actor type/id, request/correlation IDs;
- `router_id`, `operation_id`, `job_id`, `plan_id`;
- action, outcome, risk/danger level;
- redacted summary и digest исходного запроса;
- artifact references и версии Hub/adapter.

Audit event не обновляется и не служит mutable job state. Секреты и неотредактированные конфиги в него не попадают.

### `BackupArtifact`

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

ETag для desired state строится из стабильной revision identity/digest. ETag observation отражает конкретную observed resource version. API `If-Match` защищает от lost update, но не заменяет транзакционную проверку plan preconditions непосредственно перед lease/apply.

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
