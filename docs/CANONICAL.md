# Router Control: canonical facts

Этот документ фиксирует code-truth legacy-контура и решения, которые нельзя незаметно менять при создании `router_control`. Имена сущностей, API и компонентов приведены на английском; пояснения — на русском.

## 1. Приоритет источников

При конфликте источников действует порядок:

1. текущий исполняемый код;
2. наблюдение над конкретным роутером с датой;
3. утверждённые архитектурные решения Phase 0;
4. эксплуатационные документы;
5. старые сценарии, имена интерфейсов и endpoint — только historical fixtures.

Документ не содержит паролей, private keys, preshared keys, serial/MAC и иных секретов.

## 2. Code-truth: auto-push, а не collect-only

Текущий основной путь GUI выполняет **защищённый real-time auto-push**:

- `TrafficMonitorGui/MainWindow.xaml.cs`, `StartMonitoringProcess()` безусловно вызывает `AppendCommonKeeneticArgs(..., enableDeltaPush: true, ...)`.
- `AppendCommonKeeneticArgs()` при `enableDeltaPush: true` добавляет `-EnableKeeneticPush`; HTTP выбран по умолчанию, если оператор явно не указал SSH identity file.
- `StartMonitoringProcess()` также передаёт `-KeeneticProfileAccumulate`, поэтому сбор профиля продолжается параллельно с push.
- `Monitor-CursorNetwork.ps1`, main loop вызывает `Push-KeeneticDeltaRoutes -Enabled:([bool]$EnableKeeneticPush)`.
- `Push-KeeneticDeltaRoutes()` отправляет каждый новый public IPv4 `/24` не более одного раза за сессию, используя `KeeneticPushedNets`; при HTTP сначала подгружает уже существующие routes из `Get-KeeneticRouteCidrsHttp()`.

Следовательно, фразы «маршруты не отправляются» в `MainWindow.xaml.cs` (`AddToSelectedApps()`, `SelectedAppItem_PropertyChanged()`) описывают только действие выбора приложения, но вводят в заблуждение относительно последующего Start. Нижний исторический список в `Project_Context_For_AI.md`, где сказано, что программа переведена в collect-only, также устарел. Разделы 1 и 5 того же файла согласуются с executable code и правильно называют auto-push текущим режимом.

Collect-only остаётся фактическим fallback:

- без `-EnableKeeneticPush` сам PowerShell monitor только собирает artifacts;
- при active PC full-tunnel VPN `Push-KeeneticDeltaRoutes()` делает pause, но сбор и profile accumulation продолжаются;
- initial HTTP connection failure не завершает monitor: main path позже пытается reconnect;
- `DryRun` не изменяет роутер;
- manual `Ensure-*` scripts остаются отдельным способом досинхронизации.

Это описание только legacy behavior. В целевом `router_control` TrafficDiscovery создаёт `RouteProposal`; default — proposal/confirm, а auto-apply разрешён только явно trusted policy.

## 3. Router reality и deployment history

### Historical observed reality — 2026-07-19

- Физически текущий target — новый **Netcraze Ultra NC-1812**.
- На момент наблюдения **WireGuard/AmneziaWG на нём не настроен**.
- Локально наблюдалась raw version string `5.01`; exact NDMS release, build, channel и installed component set ещё не подтверждены.
- Поддержка нужных RCI commands, components и AmneziaWG на установленной версии ещё не сертифицирована.
- До capability certification любые writes должны быть заблокированы. Phase 0 не изменяет живой роутер.

### Sanitized lab observations — 2026-07-21 (historical non-certifying: insecure HTTP)

**Historical only** — early operator probe over plain LAN HTTP (gates **CLOSED** at observation time; **не** certification claim):

- Raw firmware string from `components/firmware.version`: **`5.01.C.1.0-0`** (canonical); display title **`5.1.1`** from `firmware.title`.
- `show/system` on lab HTTP path carries telemetry only; identity claims ignore it for observed shape.
- Frontend bundle trace (sanitized loaded NDMS web UI, 2026-07-21) maps dotted tokens **`show.identification`** → GET `/rci/show/identification` and **`show.version`** → GET `/rci/show/version`. Parser and allowlist design validated offline; insecure HTTP remains non-certifying (`certification_eligible: false`).
- Plain LAN HTTP and unpinned SSH are non-certifying transport paths.

Shared identity/parser rules (also apply to certifying path):

- Gate A frozen allowlist (exactly four RCI reads): GET `/rci/show/system`, POST `/rci/components/list`, GET `/rci/show/identification`, GET `/rci/show/version`. Raw serial/servicetag hashed at parser boundary; evidence exposes `physical_identifier_source: show.identification_digest` only (no digest values).
- Canonical observed `model` = exact `show.version.hw_id`; optional `show.identification.hwid` must exact-match when present; display `model`/`device`/`description` are metadata only (`model_display`). Operator hint: absent/blank => no token disagreement; when supplied, extracted token set must exactly equal `{hw_id}` (empty, partial, case variant, or competing tokens => incomplete). RCI display metadata may omit tokens; present tokens must exactly match `{hw_id}`.
- NDM build from nested `show.version.ndm.exact` (`build_source: rci_version_ndm_exact`) required for `identity_complete`; flat `build` is legacy display fallback only (`build_source: rci_version`); BSP exact separate; components raw firmware remains canonical; when both `version` and `release` are present they must agree with each other and components firmware; exact `sandbox: stable` maps to update channel `Main`.
- Firmware source disagreement or token/hwid disagreement leaves identity incomplete/provisional.

### Dedicated lab device ownership — 2026-07-22

- The currently connected **Netcraze Ultra NC-1812** is **project-owned** dedicated development/laboratory hardware purchased solely for Router Control development and certification; no production or customer dependency; preferred hardware validation target ([`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md)).
- **Lab device ownership** is distinct from **network ownership** (§8 event LAN L3/DHCP/DNS policy owner on deployed event LAN).

### Gate A ReadOnlyCertified — 2026-07-31 (current authorized rebind tuple)

**Same-day rebind sequence on expendable class:** rebind **#1** (morning) — physical device replacement; rebind **#2** (afternoon) — WireGuard component install identity drift (image rebuild moved both digests; host-key and firmware unchanged).

Current tuple from pinned-SSH probe evidence `data/artifacts/gate-a-probe-post-wireguard-install-192.168.2.1-20260731.json` (`2026-07-31T17:56:29+00:00`; `source_address: 192.168.2.10`) — exact tuple in [`STATUS.yaml`](STATUS.yaml) and [`gate-a-certification.json`](gate-a-certification.json):

- **Target:** Netcraze Ultra **NC-1812**; firmware **`5.01.C.1.0-0`**, display **`5.1.1`**, NDM build **`0-b592e619a0`**, BSP **`0-f371d30955`**, channel **Main**, region **EA**.
- **Digests:** `component_set_digest` **sha256:23bd35bc1bcbf8523495ff7fb37ef2ded597ce9d07b9c1c968ae1f9e4aa4de80**; `device_fingerprint_digest` **sha256:c34adec44383c0dc1f31833bb6d7885a8e9af454722af0c6bfba3761ac71e6fd**.
- **Superseded (pre-WG, same day):** evidence `gate-a-probe-newrouter-192.168.2.1-20260731.json`; digests **sha256:91145a8284d142729b93bb0fd549312134dd669ef7b07f4d2207d2b6a22dd83b** / **sha256:13885245280ae4301f27d7ef03ab7cdaf1b51367943216b62f5c81590973e021**.
- **Component claims:** Gate A evidence certifies the component-set digest only. Exact component presence must be freshly re-observed during Gate B preflight and is not a Gate A certification claim.
- **Transport:** authenticated encryption via host-key-pinned SSH tunnel (`transport: ssh_tunnel`, `ssh_host_key_algorithm: ssh-ed25519`, pin **SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY**); prior pin **SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM** superseded (historical only).
- **Gate posture:** Gate **A** open **ReadOnlyCertified** for the new exact tuple; Gate **B** completed_failed (not WriteCertified); Gates **C/D** closed — ungated live mutations forbidden.
- **Lab topology:** test router **`192.168.2.1`**; mandatory `--source-address 192.168.2.10` on hardware CLIs; future live mutations additionally require WAN isolation or physical uplink disconnect.
- **Host integration:** live host enroll/preflight remains bound to typed Gate A config + DPAPI credential ref when `RC_ADAPTER_MODE=live`.

Это current reality для NC-1812 dedicated lab device.

### Historical Gate A ReadOnlyCertified — 2026-07-21 (superseded post-change tuple)

After an encrypted pre-change startup backup, a user-approved component install changed the installed-component set. The router then rebooted and a pinned-SSH read-only re-probe supplied a tuple later superseded by the 2026-07-31 authorized rebind (initial post-change evidence 2026-07-21T17:15:29+00:00; **return-home source-bound recertification** on **2026-07-23** with same digests — evidence `2026-07-23T05:17:43.764839+00:00`, `source_address: 192.168.1.144` — **historical only**):

- **Target:** Netcraze Ultra **NC-1812**; same raw firmware **`5.01.C.1.0-0`**, display **`5.1.1`**, NDM/BSP builds, channel **Main**, region **EA**; superseded component-set **`sha256:de72a7af…`** and fingerprint **`sha256:eb58946c…`**; superseded host-key pin **SHA256:lU1D6ChV…**.
- **Dual-homed lab topology (historical):** overlapping `192.168.1.0/24` paths required explicit `--source-address 192.168.1.144`; network migrated to `192.168.2.0/24` (2026-07-23) before physical device replacement (2026-07-30).
- **Prior tuple:** pre-install ReadOnlyCertified tuple **revoked** (historical only); encrypted pre-change startup backup retained as ignored local DPAPI baseline (metadata only — no locator or content hash in docs).
- Certifying path may also use HTTPS with certificate validation to the same verified management host; plain LAN HTTP remains historical/non-certifying only.

Superseded by §3 *Gate A ReadOnlyCertified — 2026-07-31*; do not treat as current SSOT.

### Historical Gate A tuple — 2026-07-21 (pre-change)

Prior ReadOnlyCertified tuple opened earlier on 2026-07-21 was **revoked** when a user-approved install changed the installed component set. Superseded digests are recorded only in STATUS `gates.A.previous_tuple` and `gate-a-certification.json` `previous_certifications` — not inherited for live observe. Encrypted pre-change startup backup succeeded before install and remains an ignored local baseline for rollback planning; it does **not** re-open Gate A for the old tuple.

### Historical FI deployment fixture

Старое рабочее развёртывание имело один active interface с system name `Wireguard0`, UI description `AWG client_1`, FI profile и static `/24` routes на этот интерфейс; экспериментальный `Wireguard1` должен был быть disabled/empty. Hostname endpoint старого профиля на роутере разрешался как `0.0.0.0`, поэтому применялся заранее разрешённый IP endpoint.

Конкретные FI/DE endpoints, tunnel address, `Wireguard0`, `Wireguard1`, descriptions и число routes — только historical fixtures для recorded tests. Они не являются current NC-1812 state, router identity или domain defaults.

## 4. Locked domain invariants

1. `RouterId` — stable identity. IP, hostname, default gateway, `Wireguard0` и UI description identity не являются.
2. Перед mutation identity проверяется по model + serial/MAC/fingerprint; wrong network, gateway или fingerprint означает hard abort.
3. Domain/API не содержит Keenetic JSON или raw RCI commands. RCI полностью скрыт за `RouterAdapter`.
4. Unknown firmware или unknown capability fail closed для writes.
5. Целевой route inventory не должен зависеть от полного `show/running-config`. Legacy `show/ip/route`, точные response shapes и доступность targeted read должны быть подтверждены на certification tuple NC-1812.
6. Target transport обязан нормализовать auth expiry и command-level errors независимо от HTTP status. Конкретное поведение 401/re-auth на NC-1812 остаётся certification hypothesis.
7. Target transport должен уметь обработать asynchronous continuation, если она наблюдается. Поле `"continued": true` и polling semantics остаются certification hypotheses до recorded fixture NC-1812.
8. Read-only operations могут выполняться параллельно; mutation jobs сериализуются per `RouterId`.
9. Managed merge: изменяются и удаляются только resources с ownership record Router Control. Unmanaged resources не prune.
10. Desired revisions immutable; observed state timestamped и становится stale после TTL.
11. `applied_revision` меняется только после read-back и postcondition verification.
12. Reconcile lifecycle: `Pending → Planning → Applying → Verifying → Converged | Drifted | Failed | RecoveryRequired`.
13. Profile catalog не ограничен; assignment моделируется отдельно от profile artifact.
14. Private/RFC1918, CGNAT, link-local, loopback, multicast/reserved destinations запрещены в VPN `RouteSet`.
15. Domain endpoint `0.0.0.0` — validation error либо отдельный явно approved resolved-IP variant; silent success запрещён.
16. Router failure/degraded/disabled не блокирует Hub kiosk/board/printing startup.
17. Capture/TrafficDiscovery не пишет routes напрямую: evidence → `RouteProposal`; default apply требует operator flow.
18. Browser/iPad никогда не получает router password, VPN private key, raw RCI session или startup-config.

## 5. Locked mutation and safety invariants

Каждая опасная операция соблюдает единый protocol:

1. enroll/fingerprint;
2. capability + current-state read;
3. непустой backup artifact с hash и router identity;
4. immutable redacted `ChangePlan`;
5. plan-preconditions → normal operator `Confirm` (plan digest + expiry + session binding — [`contracts/SECURITY_OPS.md`](contracts/SECURITY_OPS.md));
6. mandatory **Fail-safe Configuration** (vendor alias **Safe Configuration**) для VPN, Wi-Fi, VLAN и firewall writes; это global safety mode, а не транзакционный commit-confirm;
7. минимальные idempotent steps;
8. read-back и functional verification, включая AWG handshake/application reachability;
9. startup configuration save только после успешной verification;
10. при failure — best-effort compensation, а при потере всех management sessions — Fail-safe timeout/reboot rollback к последней saved startup configuration.

Rollback является compensating operation, а не транзакционной атомарностью. Терминология: **Fail-safe Configuration** — primary name в Router Control contracts; **Safe Configuration** — accepted vendor/UI alias ([`contracts/RCI_POLICY.md`](contracts/RCI_POLICY.md)). Все mutation requests используют `Idempotency-Key`; plan связан с observed resource version и digest, stale plan отклоняется.

Firmware/components в v1 — только detect + operator instructions. Auto-install и auto-update запрещены.

## 6. First-deployment policy, не domain invariant

- Первый certified target: `Netcraze Ultra NC-1812`.
- **Historical (2026-07-19):** lab observation recorded raw version string **`5.01`** only — exact NDMS release, build, channel и installed component set **не** были подтверждены (см. §3 *Historical observed reality — 2026-07-19*).
- **Historical (2026-07-21, non-certifying):** insecure HTTP probe recorded raw firmware **`5.01.C.1.0-0`** and display **`5.1.1`** — **без** certification claim (см. §3 *Sanitized lab observations — historical*).
- **Historical (2026-07-21, ReadOnlyCertified, post-change):** pinned-SSH Gate A tuple after encrypted pre-change backup, user-approved component install, reboot, and re-probe; superseded digests and host-key pin — prior tuple revoked (см. §3 *Historical Gate A ReadOnlyCertified — 2026-07-21*).
- **Current (2026-07-31, ReadOnlyCertified, authorized rebind):** two same-day rebinds on expendable class — (1) physical device replacement morning; (2) post-WG identity drift afternoon; current evidence `gate-a-probe-post-wireguard-install-192.168.2.1-20260731.json`; prior tuples in `previous_certifications` only (см. §3 *Gate A ReadOnlyCertified — 2026-07-31* and STATUS `gates.A`).
- VPN v1: только `AmneziaWG`; unsupported/unknown profile fields fail closed.
- На одном router в первом deployment preset разрешён ровно один active AWG assignment.
- Управление выполняет только local operator.
- Internal route stress target — 5000. Netcraze публикует лимит 1024 строк для batch import, но не общий active-route limit; production ceiling задаётся только hardware benchmark gate.
- UI размещается только в защищённом блоке существующего Hub `/settings`.

`Wireguard0` не входит в эту policy: это historical system name. Adapter обязан discover и использовать фактический system interface ID, а UI caption хранить отдельно.

## 7. Legacy safety facts, которые надо сохранить

### Public `/24` filter

`Monitor-CursorNetwork.ps1/Test-IsPublicIpv4DotZero()` и `Ensure-Keenetic-Routes-FromProfile.ps1/Test-IsPublicIpv4Cidr24()` исключают private, CGNAT, loopback, link-local и multicast/reserved ranges. Legacy discovery агрегирует IPv4 до `/24`. Целевой domain сохраняет запрет специальных destinations, но prefix policy должна быть явной, а не зашитой в parser.

### PC VPN pause

`Monitor-CursorNetwork.ps1/Get-PcVpnState()` считает full-tunnel вероятным, если default-route adapter похож на VPN либо router недоступен. `Push-KeeneticDeltaRoutes()` ставит push на pause и автоматически resumes позже. Это useful safety heuristic, но не доказательство router identity и не замена preflight.

### PowerShell 5.1 ASCII logs

GUI запускает `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`. Legacy `Monitor-CursorNetwork.ps1` читается Windows PowerShell 5.1, поэтому console `Write-Host`/`Write-Warning` messages в этом UTF-8-without-BOM файле должны оставаться ASCII. Artifact encoding — отдельный контракт: legacy CSV/JSON/log helpers пишут UTF-8 BOM.

### `show/running-config` timeout

Полный config на старом роутере с тысячами routes часто превышал timeout. `KeeneticHttpClient` имеет общий 10-second `HttpClient.Timeout`; `Keenetic-VpnProfileTools.ps1/Invoke-KeeneticRaw()` использует 15 seconds. Legacy `BackupRoutesAsync()` и `Backup-KeeneticRoutes()` читают `show/running-config`, поэтому их route backup может завершиться ошибкой. `Export-Active-Keenetic-Routes.ps1` правильно использует `show/ip/route`; это canonical route-inventory pattern. Startup-config backup остаётся отдельной high-risk operation, не hot-path read.

### Endpoint hostname resolving to `0.0.0.0`

Исторически hostname FI profile на старом router дал remote endpoint `0.0.0.0`; рабочим обходом был заранее разрешённый IP. Новая реализация не должна молча подменять hostname: resolution result фиксируется как observation, `0.0.0.0` отклоняется, а IP variant требует явного approval и audit.

### System interface names

RCI commands требуют system ID (`Wireguard0` в старом fixture), а не UI caption (`AWG client_1`). `KeeneticHttpClient.GetInterfacesAsync()`/`ParseInterfacesJson()` различает ID и description. `KeeneticRouteInterfaceHelper.ResolveForNewRoutes()` сейчас всегда возвращает `Wireguard0`; эту model-specific hard-code нельзя переносить.

### Credentials and secrets

- Legacy GUI хранит router password отдельным DPAPI `CurrentUser` blob через `SettingsStore.SavePassword()`/`LoadPassword()`.
- PowerShell tools принимают plain parameter, process/user environment variable `KEENETIC_SSH_PASSWORD` или тот же DPAPI blob. Plain command-line/environment transport — legacy compatibility, не target design.
- Target local vault: opaque `CredentialRef` + DPAPI `CurrentUser` под постоянным Windows user Hub; secret write/rotate/delete без read-back через API.
- Private keys и passwords не попадают в settings JSON, job payload, audit, plan diff, logs, diagnostics или backup metadata.
- Автоматическое server recovery возможно только для криптографически enrolled Hub с per-Hub envelope; fleet-wide operator key недостаточен. При замене router генерируются новые VPN keys, старые отзываются.

## 8. Locked platform boundaries

- Реализация — переносимый Python package `router_control`; domain не импортирует FastAPI.
- Канонический дом проекта и prototype — репозиторий `keenetic-control-plane`; FastAPI dev-host **`router_control_host`** exists (`/api/router-control/v1`, FakeAdapter+SQLite default; `RC_ADAPTER_MODE=live` + Gate A open → pinned SSH read-only observe; Gate B **completed_failed**; Gates C/D **closed**). `ScanCursorIP` — legacy behavioral evidence. Target integration — Python 3.11 FastAPI Hub `module_3.0`.
- После integration API prefix `/api/router-control/v1/*` работает на common listener и защищён existing `hub_admin` fail closed.
- Если Router Control enabled, пустой `HUB_ADMIN_PASSWORD` — startup security error именно для Router Control.
- Persistence — отдельный `data/router_control.sqlite3`; JSON/CONF только import/export и hashed artifacts.
- Durable jobs, steps, leases, idempotency records и append-only audit переживают process restart.
- Four future network zones: Guest, Promo, Staff, Admin/Server. Guest получает только локальную HTTPS order page; доступ к Admin/Router Control блокируется.
- **P3 topology safety closure (2026-07-23, complete, offline/default-deny):** adapter/executor share one `CertifiedOperationRegistry`; Gate D missing/`None` denies; hardware CLIs accept `--source-address` (mandatory on fail-safe/AWG execute); **fail-safe trials** `fail-safe-20260723T094500Z` and retry `fail-safe-20260723T110000Z` both consumed **completed_failed** (same `sealed_cli_dispatch` failure class; VPN absent on second; root cause unproven; not WriteCertified); **offline SSH CLI channel discovery harness delivered** (2026-07-23); **expendable lab (2026-07-31):** **`tunnel_healthy` DEVICE-CONFIRMED** (evidence `data/artifacts/wg-awg-real-tunnel-attempt-20260731.json`); **2026-08-05 (§M-24..§M-27):** first real handshake; `SET_IP_ADDRESS` + `wireguard_ip_global` device-accepted; traffic via tunnel reversible with higher NDMS `ip global` priority — kill-switch/named policy/IPv6 still open; **`next_task` id:** `local-hub-vpn-real-peer-autoconnect-continuation` per [`STATUS.yaml`](STATUS.yaml); **parallel deferred:** VPN named connection policy / kill-switch **live apply** (offline preview only; kill-switch `permit global` **unresolved**); registries empty; Gate B **completed_failed**; Gates C/D **closed**; WriteCertified **NOT** claimed.
- **P1-B live dispatch substrate (2026-07-22, complete):** MutationExecutor wires effect SM (initiate-once + poll continuation), safety session, boot marker, evidence (`runtime_applied` / `startup_saved`), DPAPI durable artifact path (offline tests), process mutex held through I/O — **offline/fake only**; live dispatch remains `MutationForbidden`; no exactly-once claim.
- **Network ownership:** NC-1812 — sole L3/DHCP/DNS/firewall/AP policy owner on event LAN; Hub PC — application/control plane only; managed L2 switch + UPS recommended for Hub–printer L2 during router reboot; router remains network SPOF for Wi-Fi/DHCP/DNS (explicit). **Lab device ownership** (project-owned dedicated development router for Router Control validation) is a separate fact — see [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md).
- Milestone ordering: ADR-0005 local-first commissioning DAG (M0–M8); ADR-004 §Capability order superseded for execution ordering only.
- HTTPS deployment: per-Hub public FQDN, DNS-01 certificate, local DNS и Caddy. Offline window: 1–3 дня.

## 9. Что ещё не доказано

После Gate A ReadOnlyCertified на **текущем** expendable lab unit (authorized rebind **2026-07-31**; evidence `data/artifacts/gate-a-probe-post-wireguard-install-192.168.2.1-20260731.json`; host-key SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY) identity, firmware, build, channel и digest installed component set подтверждены для **read-only observe**; **`tunnel_healthy` DEVICE-CONFIRMED** (2026-07-31) и **first real handshake + traffic via tunnel** (2026-08-05, §M-24..§M-27) — **не** означает WriteCertified или полную routing policy (kill-switch/named policy/IPv6 still open; captive via tunnel unproven). Exact component presence не является Gate A claim и должна быть заново проверена в Gate B preflight. Для **writes** остаются неизвестными: полная AWG compatibility и lossless AmneziaWG mapping, Fail-safe Configuration commands и practical route ceiling на NC-1812. NDMS 5.1 документирует import advanced ASC parameters, но это не доказывает write-safe совместимость raw **`5.01.C.1.0-0`**. Эти gaps запрещают writes; `write_shapes_registered` остаётся **false**; Gate B **completed_failed**; Gates C/D **closed**; старые Keenetic responses и historical `5.01`-only observation (2026-07-19) не считаются доказательством write compatibility.
