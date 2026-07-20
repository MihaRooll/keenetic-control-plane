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

### Current observed reality — 2026-07-19

- Физически текущий target — новый **Netcraze Ultra NC-1812**.
- На момент наблюдения **WireGuard/AmneziaWG на нём не настроен**.
- Локально наблюдалась raw version string `5.01`; exact NDMS release, build, channel и installed component set ещё не подтверждены.
- Поддержка нужных RCI commands, components и AmneziaWG на установленной версии ещё не сертифицирована.
- До capability certification любые writes должны быть заблокированы. Phase 0 не изменяет живой роутер.

Это current reality, а не продолжение состояния старого устройства.

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

- Первый certified target: `Netcraze Ultra NC-1812`; raw version `5.01` остаётся unclassified до identity snapshot.
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
- Канонический дом проекта и будущего prototype — репозиторий `keenetic-control-plane`; отдельный FastAPI dev-host ещё не создан. `ScanCursorIP` используется только как legacy behavioral evidence. Target integration — существующий Python 3.11 FastAPI Hub `module_3.0`.
- После integration API prefix `/api/router-control/v1/*` работает на common listener и защищён existing `hub_admin` fail closed.
- Если Router Control enabled, пустой `HUB_ADMIN_PASSWORD` — startup security error именно для Router Control.
- Persistence — отдельный `data/router_control.sqlite3`; JSON/CONF только import/export и hashed artifacts.
- Durable jobs, steps, leases, idempotency records и append-only audit переживают process restart.
- Four future network zones: Guest, Promo, Staff, Admin/Server. Guest получает только локальную HTTPS order page; доступ к Admin/Router Control блокируется.
- HTTPS deployment: per-Hub public FQDN, DNS-01 certificate, local DNS и Caddy. Offline window: 1–3 дня.

## 9. Что ещё не доказано

До live read-only certification на NC-1812 неизвестны точные firmware build/channel, installed components, полная AWG compatibility, RCI response/auth shapes, Fail-safe Configuration commands и practical route ceiling. NDMS 5.1 документирует import advanced ASC parameters, но это не доказывает совместимость raw `5.01` или lossless AmneziaWG mapping. Эти gaps запрещают writes; старые Keenetic responses не считаются доказательством совместимости.
