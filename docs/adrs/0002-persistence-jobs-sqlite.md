# ADR-002: SQLite persistence и durable jobs

- Status: Accepted
- Date: 2026-07-19
- Decision owners: Router Control
- Scope: persistence, migrations, jobs, recovery, idempotency, audit

## Контекст

Router Control должен переживать restart/crash Hub во время изменения сетевого устройства. Потеря очереди, ownership records, desired revision или результата уже выполненного шага может привести к повторной destructive mutation либо к удалению чужой конфигурации.

Целевой Hub `module_3.0` уже использует полезные SQLite-паттерны:

- отдельные database files с независимым `PRAGMA user_version`;
- contiguous append-only migration chain;
- backup существующей базы перед первой pending migration;
- транзакцию на migration и idempotent no-op для актуальной схемы;
- repository connections с `sqlite3.Row`;
- `BEGIN IMMEDIATE` для атомарного claim;
- условные status transitions как optimistic lock;
- durable idempotency keys, leases, attempt counters и append-only audit;
- metadata артефактов в SQLite, bytes на диске.

`app/services/merch/state.py` показывает atomic JSON sidecars через temp file, `fsync` и `os.replace`, но этот подход не принимается как authoritative state Router Control: несколько связанных aggregates, constraints, claims и crash recovery требуют одной транзакционной базы.

Router Control разрабатывается отдельно, затем переносится в Hub. Его schema lifecycle не должен зависеть от `studio.sqlite3`, cutting jobs или порядка запуска других bounded contexts.

## Решение

### Отдельная база

Authoritative state хранится в отдельном файле:

`data/router_control.sqlite3`

Router Control не добавляет таблицы в `studio.sqlite3` и не использует JSON-файлы как database/outbox/job log. Отдельный файл даёт независимые migrations, backup/restore, degradation и retention. Повреждение или отключение Router Control не должно блокировать kiosk, board, printing либо startup Hub.

SQLite является единственным authoritative persistence store для domain state, ownership, desired/observed/applied markers, jobs, idempotency и audit.

JSON и CONF разрешены только как:

- import/export interchange;
- versioned redacted snapshot внутри явно определённого поля/артефакта;
- hashed backup/diagnostic artifact;
- wire representation API.

JSON sidecar не является источником истины. Core relationships, IDs, statuses, revisions, lease fields и timestamps хранятся структурированно и индексируются; произвольный JSON не заменяет schema evolution.

### Multi-router-ready с первого дня

Даже при single-router UI v1 схема не содержит singleton row и не предполагает «текущий роутер». Все router-scoped таблицы имеют `router_id`; uniqueness и indexes учитывают его. Jobs, idempotency, ownership, artifacts и audit допускают несколько роутеров и несколько площадок без будущего преобразования primary keys.

Site и Router имеют стабильные opaque IDs. Endpoint IP, hostname, default gateway и имя интерфейса хранятся как изменяемые attributes/locators и не используются как primary key.

### Секреты

SQLite хранит только `CredentialRef` и metadata secret lifecycle:

- opaque reference ID;
- `router_id`, purpose/kind;
- provider identifier;
- opaque provider locator;
- timestamps ротации/revocation.

Локальный provider — Windows DPAPI `CurrentUser` под постоянным Windows-user Hub. Passwords, AWG private keys, raw profiles, RCI sessions и DPAPI plaintext/ciphertext blobs не помещаются в обычные domain/job/audit JSON fields. Secret material хранится за `CredentialVault`; database records позволяют только resolve для внутренней операции, rotate и revoke.

Server recovery/envelope encryption является отдельным future contract. Наличие database backup само по себе не обещает восстановление DPAPI secrets под другим Windows user или на другом компьютере.

## Логическая схема и ответственности таблиц

Это контракт ответственности, а не SQL DDL. Точные типы, foreign keys и indexes будут зафиксированы в Phase 0b/реализации migrations.

### Inventory и capabilities

- `sites` — stable `site_id`, display metadata, lifecycle timestamps.
- `routers` — stable `router_id`, `site_id`, identity fingerprint/claims, lifecycle, desired/applied pointers; без IP-as-ID.
- `router_endpoints` — изменяемые management addresses, priority, last success/failure; несколько endpoint на router.
- `router_capabilities` — immutable timestamped capability snapshots, firmware/components, certification, validity TTL.
- `credential_refs` — только opaque DPAPI-backed references и lifecycle metadata.

### VPN и desired state

- `vpn_profile_artifacts` — profile identity, kind, parser version, redacted metadata, digest, validation status; secret parts только по refs.
- `tunnel_assignments` — logical assignment между router/profile, desired activation и observed vendor locator.
- `desired_revisions` — immutable, monotonic per-router revisions, parent, canonical digest, actor/reason.
- `router_revision_state` — current desired pointer, verified applied pointer и last observation marker; update applied выполняется в verify transaction.

### Observations, ownership и planning

- `router_observations` — immutable read-back header: timestamps, TTL, identity/capability refs, ETag/resource version, digest, collection status.
- `observation_resources` — нормализованные observed resources либо versioned redacted snapshot references; позволяют diff без полного startup-config на hot path.
- `managed_resources` — ownership record: router, kind, logical key, vendor locator/fingerprint, creating revision, lifecycle.
- `change_plans` — immutable plan header: desired revision, observation, expected ETags/digests, expiry, confirmation and risk metadata.
- `change_plan_items` — ordered redacted high-level changes, pre/postconditions, ownership impact; без raw commands/secrets.

### Operations и durable execution

- `operations` — API-visible пользовательское намерение, router, plan, actor, aggregate status, correlation.
- `jobs` — execution attempts, `router_id`, lease owner/until, heartbeat, attempt, recovery state, cancel request, terminal outcome.
- `job_steps` — ordered steps, status, attempts, checkpoint, start/finish, redacted error и result/artifact refs.
- `router_mutation_locks` — durable per-router serialization fence/lease либо эквивалентная атомарная уникальность active mutation.
- `idempotency_records` — scope + router + operation kind + key, request digest, operation/response reference, status и expiry.

`Operation` не переисполняется как новый пользовательский запрос; при recovery создаётся/возобновляется `Job` attempt по явно определённому правилу. История предыдущих attempts сохраняется.

### Audit и artifacts

- `audit_events` — append-only actor/action/outcome timeline, redacted payload и request digest, correlation refs.
- `backup_artifacts` — router backup metadata, digest, size, identity fingerprint, verification/retention и storage locator.
- `artifacts` — metadata прочих plan/job/diagnostic artifacts; большие bytes находятся вне SQLite в защищённом artifact directory.

Audit rows не обновляются и не являются job state. Artifact bytes публикуются атомарно: запись во временный файл, flush/fsync, проверка digest/size, atomic replace в final path; metadata становится видимой только после успешной публикации bytes.

### Later

- `route_sets`, `route_set_entries`, `route_resource_bindings` — versioned managed routing policy; создаются только в routes phase.
- `traffic_observations`, `route_proposals` — timestamped evidence/TTL/confidence и proposals; создаются только в TrafficDiscovery phase.

Эти таблицы резервируют multi-router keys, но не открывают write path в API v0.

## Revisions, concurrency и ETag

`DesiredRevision` immutable. Новое намерение создаёт следующий per-router revision в одной transaction и условно меняет current pointer. API ETag соответствует revision identity/digest; `If-Match` проверяется внутри той же transaction, чтобы исключить lost update.

`RouterObservation` immutable и имеет `observed_at`/`valid_until`. Stale observation остаётся историей, но не может быть основанием mutation plan. Plan хранит exact desired revision, observation ID, observed ETag/resource version и digests.

При claim/apply worker повторно и транзакционно проверяет:

1. plan подтверждён и не истёк;
2. desired pointer всё ещё указывает на ожидаемую revision;
3. observation ещё fresh;
4. identity/capability остаются допустимыми;
5. per-router mutation lease получена.

Если внешний router state мог измениться после observation, перед первой mutation выполняется повторный read-back/precondition check. Stale plan не «освежается» заменой одного поля — создаётся новый plan.

`applied_revision_id` изменяется только в transaction завершения verify, после успешного read-back и postconditions. Отправленная команда, завершённый apply step или HTTP 200 не считаются applied.

## Durable jobs и сериализация

### Claim и lease

Worker atomарно выбирает claimable job и переводит его из `Queued` в `Leased` в короткой `BEGIN IMMEDIATE` transaction. Update содержит expected current status; только один contender получает row. Lease имеет:

- уникальный `lease_owner`;
- `lease_until`;
- heartbeat/renew timestamp;
- monotonic `attempt`;
- fencing token или эквивалентную проверку attempt во всех последующих writes.

Одновременно разрешён максимум один active mutation job на `router_id`. Это enforced базой через lock row/conditional transaction, а не только `threading.RLock`. Read-only jobs могут выполняться параллельно, если нет конфликта с safe-configuration lifecycle.

Long router I/O не выполняется внутри SQLite transaction. Transaction фиксирует intent/checkpoint, освобождается, затем adapter выполняет I/O; результат записывается отдельной conditional transaction с проверкой lease/fence.

### Checkpoints

Каждый `job_step` имеет deterministic kind/ordinal и переходы:

`Pending → Running → Succeeded | Failed | CompensationRequired | RecoveryRequired`.

Checkpoint фиксируется только после подтверждённого результата. Result содержит redacted facts, observation/artifact refs и external correlation, но не secret/raw command. Успешный step не повторяется, если postcondition всё ещё доказуема.

Минимальная цепочка mutation:

`preflight → identity-check → observe → backup → plan-preconditions → begin-safe-configuration → apply → read-back → verify → commit → audit`.

При failure после begin/apply запускаются explicit compensation steps. Router Safe Configuration/commit-confirm остаётся обязательной внешней страховкой для disruptive writes; SQLite transaction не может сделать router mutation атомарной.

### Startup recovery и expired leases

На startup recovery worker:

1. оставляет terminal jobs неизменными;
2. возвращает безопасные `Queued` jobs в claimable pool;
3. находит `Leased/Running` jobs с expired lease;
4. помечает attempt `Lost` и классифицирует последний checkpoint;
5. если внешней mutation ещё не было — создаёт resume attempt;
6. если mutation могла произойти — сначала выполняет identity check и read-back;
7. продолжает verify/commit, запускает compensation либо устанавливает `RecoveryRequired`.

Timeout/crash после отправки router command означает unknown outcome, а не автоматический failure. Слепой повтор запрещён. Late report от старого worker отклоняется expected-status/fencing check.

Cancel для `Queued` job терминален сразу. Для in-flight job это durable `cancel_requested`; worker останавливается только на безопасной границе, затем verify/compensate. Cancel не отменяет уже произошедшую внешнюю mutation.

## Idempotency

Все mutation API требуют `Idempotency-Key`. В transaction создания operation:

- canonical request получает digest;
- создаётся уникальный `idempotency_record`;
- создаются `Operation` и initial `Job`;
- записывается audit event.

Повтор с тем же key и digest возвращает существующую operation/terminal response. Повтор с тем же key и другим digest возвращает conflict. Idempotency records не удаляются, пока возможен retry клиента или recovery job; retention задаётся отдельно и не может обгонять audit/operation retention.

Идемпотентность HTTP request не равна идемпотентности adapter step. Каждый apply step также имеет read-before-write, deterministic logical resource key и postcondition.

## Migrations и backups

Router Control использует собственную contiguous migration chain, начиная с version 1, и собственный `PRAGMA user_version`.

Правила:

1. Shipped migration никогда не редактируется и не перенумеровывается; изменение добавляется новой version.
2. Chain проверяется на contiguous versions до открытия write path.
3. Если pending migrations нет, startup — idempotent no-op без backup.
4. Перед первой pending migration существующей непустой базы создаётся consistent verified backup.
5. Каждая migration и изменение `user_version` выполняются в одной transaction; ошибка приводит к rollback этой migration и блокирует Router Control startup.
6. По умолчанию migrations additive. Destructive rebuild требует отдельного tested migration, достаточного disk-space check и restore drill.
7. Несовместимая future schema version приводит к fail-closed Router Control, но не к downgrade и не к блокировке остальных Hub services.

Backup не создаётся простым копированием открытого WAL-backed файла. Используется SQLite online backup API (или закрытая checkpointed database) во временный путь. После завершения выполняются integrity/quick check, size/digest verification и fsync; только затем temp file атомарно переименовывается в timestamped final backup. До успешной публикации backup migrations не начинаются.

Backup metadata включает source schema version, timestamp, digest и размер. Retention не удаляет последний проверенный pre-migration backup. Restore выполняется offline/при остановленном Router Control через temp restore + integrity check + atomic replace; автоматический silent rollback schema запрещён.

## Connection и transaction policy

- Foreign keys включаются на каждом connection.
- Busy timeout ограничен и измерим; бесконечные retries запрещены.
- WAL допустим для concurrency, но checkpoint/backup учитывают `-wal`/`-shm`; policy проверяется тестами на Windows.
- Repository methods используют parameter binding и короткие transactions.
- Write transitions всегда содержат expected state/version либо иной optimistic concurrency guard.
- DB timestamps задаются одним UTC clock abstraction для тестируемого lease/recovery.
- Application-level lock может снижать contention, но correctness обеспечивается SQLite constraints/transactions.
- Corruption, disk-full и permission errors переводят Router Control в degraded/disabled и пишут redacted operational event; другие Hub contexts продолжают работу.

## Retention

- Desired revisions, ownership и applied markers сохраняются, пока router enrolled и пока нужны для audit/recovery.
- Последнее fresh observation и observations, на которые ссылаются active plans/jobs, не удаляются; более старые snapshots могут compaction по policy.
- Operations/jobs/steps и idempotency records не удаляются до окончания recovery/retry window.
- Audit append-only и имеет отдельную длительную retention/export policy.
- Backup/artifact bytes удаляются только после проверки ссылок и retention; сначала удаляется/помечается metadata transaction, затем bytes через recoverable cleanup flow.

## Рассмотренные альтернативы

### Использовать `data/studio.sqlite3`

Отклонено. Общий migration counter и failure domain связывают Router Control с orders/stations и усложняют независимый перенос, backup и disable.

### JSON state files/sidecars

Отклонено как authoritative store. Atomic replace защищает один файл от partial write, но не даёт relational constraints, atomic claim, cross-aggregate transaction, leases и конкурентный `If-Match`. JSON остаётся interchange/artifact format.

### In-memory queue

Отклонено. Restart теряет apply checkpoints и создаёт риск повторной mutation.

### Внешняя job system/DB server

Отложено. Для локального Windows Hub это повышает deployment/operations cost. Multi-router schema и lease protocol позволяют позднее заменить repository без изменения domain contracts.

## Последствия

Положительные:

- crash-safe desired/ownership/job state;
- независимый lifecycle Router Control;
- знакомые `module_3.0` migration/claim patterns;
- безопасная per-router serialization;
- готовность к нескольким routers без schema rewrite;
- JSON не становится скрытой второй базой.

Отрицательные:

- нужны явные recovery state machine, retention и artifact cleanup;
- SQLite не делает внешние router changes транзакционными;
- DPAPI `CurrentUser` усложняет перенос backup на другой Hub/user;
- online backup, WAL и Windows crash cases требуют отдельных тестов.

## Критерии проверки решения

1. Повторный запуск migrations не меняет актуальную базу.
2. Fault injection на каждой migration оставляет предыдущую version читаемой и backup проверяемым.
3. Два workers не могут claim два mutation jobs одного `RouterId`.
4. Expired lease и late stale worker report не приводят к двойному apply.
5. Crash до/после каждого step восстанавливается через checkpoint/read-back либо заканчивается `RecoveryRequired`.
6. Concurrent desired update с устаревшим `If-Match` отклоняется.
7. Stale observation/plan не запускает mutation.
8. Unknown managed outcome не повторяется без read-back.
9. Поиск по database, jobs, audit и artifacts не обнаруживает plaintext secrets.
10. Повреждение/недоступность `router_control.sqlite3` не мешает startup остальных сервисов Hub.
