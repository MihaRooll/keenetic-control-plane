# Legacy map

Классификация отвечает на вопрос «как использовать legacy при создании `router_control`», а не оценивает качество файла целиком.

| Class | Значение |
|---|---|
| **Port** | Перенести поведение в новый component, переписав под target contracts. |
| **Golden behavior** | Сохранить наблюдаемую семантику и покрыть characterization tests; код буквально не копировать. |
| **Prototype-only** | Допустимо как лабораторный инструмент до parity/cutover, но не как production foundation. |
| **Do-not-reuse** | Исторический/сгенерированный/опасно привязанный artifact; не включать в новую реализацию. |
| **Anti-pattern** | Поведение противоречит locked safety/architecture invariants и должно быть явно исключено. |

Один файл может содержать полезный behavior и опасный mechanism. В таблице указан основной class, а исключения названы в reason.

## Основной executable contour

| Existing file / symbol | Class | Reason | Future component |
|---|---|---|---|
| `TrafficMonitorGui/MainWindow.xaml.cs` — process selection, `TryBuildWatchTargets()` | **Port** | Полезная модель выбора process name/path и profile binding. WPF lifecycle и запуск child PowerShell не переносятся. | `TrafficDiscovery.ProcessSelector`, Hub `/settings` UI |
| `MainWindow.xaml.cs/StartMonitoringProcess()` | **Golden behavior** | Доказывает current auto-push + profile accumulation и VPN-safe narrative. В target auto-push заменяется proposal/trusted-policy contract. | `TrafficDiscovery`, `RouteProposalService` |
| `MainWindow.xaml.cs/ApplySelectedVpnProfileAsync()` | **Prototype-only** | Есть confirm, router lock, pre-backup, apply и verify, но нет immutable plan, identity/fingerprint, Safe Configuration, durable job и compensation. | `ProvisioningPlanner`, `MutationJobRunner` |
| `MainWindow.xaml.cs/ApplyRoutesForAppAsync()`, `RemoveRoutesForAppAsync()` | **Anti-pattern** | Direct mutation + unconditional save; отсутствуют ownership, diff/plan, Safe Configuration, read-back failure handling и managed-only prune. | `RouteSetPlanner`, `RouteReconciler` |
| `TrafficMonitorGui/KeeneticHttpHelper.cs` — auth, one re-auth, interface/route reads | **Port** | Нужна эквивалентная transport semantics: challenge auth, cookies, one 401 retry, parsing fixtures. Добавить command-level errors, synchronized auth и `"continued"` polling. | `NetcrazeRciTransport`, `NetcrazeAdapter` |
| `KeeneticHttpHelper.cs/AddRoutesAsync()`, `RemoveRoutesAsync()`, `SaveConfigAsync()` | **Prototype-only** | Подтверждает RCI body shapes старого устройства, но доверяет HTTP success и не реализует safe mutation protocol. | recorded fixtures для `NetcrazeAdapter`; writes — только через `MutationJobRunner` |
| `KeeneticHttpHelper.cs/BackupRoutesAsync()` | **Anti-pattern** | Route backup зависит от тяжёлого `show/running-config` при 10-second timeout. Это уже наблюдалось как ненадёжное на больших tables. | `BackupArtifactService`; route inventory через `show/ip/route`, startup backup отдельно |
| `KeeneticHttpHelper.cs/ApplyVpnProfileAsync()` | **Prototype-only** | Fail-closed для missing interface и удаляет old peers перед apply, но может оставить partial state и сразу save без Safe Configuration/functional verify. | `VpnPlanner`, `AwgProvisioner`, compensation steps |
| `KeeneticHttpHelper.cs/TestRouteRoundtripAsync()` | **Prototype-only** | Использует documentation CIDR и делает add/read/remove, но mutation небезопасна для неизвестного router и не сохраняет/восстанавливает full baseline. | hardware capability certification test |
| `TrafficMonitorGui/VpnProfileModels.cs` — parser/status model | **Port** | Полезно различает Supported/DetectedUnsupported/Invalid, WG/AWG/ASC2 и fail-closed missing fields. Нельзя переносить raw secrets в domain DTO/logs. | `VpnProfileParser`, `VpnProfileValidator`, encrypted artifact store |
| `VpnProfileModels.cs` — single peer and field assumptions | **Prototype-only** | Это legacy parser capability, не универсальная domain model. V1 принимает только сертифицированный AWG subset; unknown fields fail closed. | `AwgV1ProfileSchema` |
| `TrafficMonitorGui/SettingsStore.cs` | **Golden behavior** | DPAPI `CurrentUser` и отдельный password blob — правильное направление. API не должен возвращать plaintext. | `DpapiSecretStore`, opaque `CredentialRef` |
| `TrafficMonitorGui/KeeneticRouteInterfaceHelper.cs` | **Do-not-reuse** | Всегда возвращает historical `Wireguard0` и игнорирует selection. System name — observed vendor detail, не identity/default. | `RouterInventory`, adapter-discovered `InterfaceId` |
| `TrafficMonitorGui/RouterIpHelper.cs` и default-gateway discovery | **Prototype-only** | Может помочь UX discovery, но gateway/IP недостаточны для identity и mutation authorization. | enrollment candidate discovery; обязательный fingerprint verification |
| `TrafficMonitorGui/AppTests.cs` | **Port** | Characterization examples полезны как исходные fixtures, но ожидания с `Wireguard0` должны стать historical tests, не defaults. | unit/fixture tests `router_control` |

## Traffic monitoring and route discovery

| Existing file / symbol | Class | Reason | Future component |
|---|---|---|---|
| `Monitor-CursorNetwork.ps1` — TCP collection, process re-resolution, atomic artifacts | **Port** | Это основа discovery behavior: process restart handling, event/unique IP aggregation, timestamps UTC, atomic output. | `TrafficDiscovery` Python bounded context |
| `Monitor-CursorNetwork.ps1/Resolve-SeedDomainMap()`, `Build-DomainCandidate()` | **Golden behavior** | Правильно помечает DNS/PTR evidence как ambiguous, а не как доказанную app ownership. | `DomainEvidenceEnricher` |
| `Monitor-CursorNetwork.ps1/Test-IsPublicIpv4DotZero()` | **Golden behavior** | Запрещает private/CGNAT/loopback/link-local/multicast routes. Перенести как typed destination policy с полными IP range tests. | `RouteDestinationPolicy` |
| `Monitor-CursorNetwork.ps1/Get-PcVpnState()`, `Push-KeeneticDeltaRoutes()` pause/resume | **Golden behavior** | Сбор продолжается при PC VPN, router push ставится на pause. Router unreachability остаётся heuristic, не identity proof. | `PreflightService`, `TrafficDiscovery` |
| `Monitor-CursorNetwork.ps1/Push-KeeneticDeltaRoutes()` direct push | **Anti-pattern** | Discovery напрямую меняет router без plan/confirm/ownership/durable job/Safe Configuration. В target default только proposal; auto-apply — trusted policy. | `RouteProposalService` → `RouteSetPlanner` |
| `Monitor-CursorNetwork.ps1` ASCII console messages under PS 5.1 | **Golden behavior** | Для legacy файла сообщения должны быть ASCII; UTF-8 BOM artifacts сохраняются. Это compatibility constraint strangler-контура. | legacy adapter tests; Python logging после cutover не наследует ограничение |
| `Monitor-CursorNetwork.ps1` SSH/plink/plain environment credential paths | **Do-not-reuse** | Password в environment/command invocation и optional `accept-new` host key не соответствуют target vault/trust boundaries. | `CredentialVault`, authenticated RCI transport |
| `Monitor-CursorNetwork.ps1` copies in `publish/` and `bin/` | **Do-not-reuse** | Generated/stale deployment copies; source of truth — root script до cutover. | build artifacts only |

## VPN and RCI PowerShell tools

| Existing file / symbol | Class | Reason | Future component |
|---|---|---|---|
| `Keenetic-VpnProfileTools.ps1/Parse-VpnProfileFile()` | **Port** | Хороший independent characterization source для WG/AWG/ASC2 recognition и required fields. | `VpnProfileParser` tests |
| `Keenetic-VpnProfileTools.ps1/Convert-VpnProfileToKeeneticInterfaceBody()` | **Prototype-only** | Полезная запись старого RCI payload shape, но vendor JSON не должен проникать в domain и совместимость NC-1812 не доказана. | `NetcrazeAdapter` recorded fixtures |
| `Keenetic-VpnProfileTools.ps1/Connect-KeeneticVpnTools()`, `Invoke-KeeneticRciTools()` | **Port** | Сохранить challenge auth и single 401 re-auth semantics. Реализация дублируется с C# и не умеет continued polling/command errors. | единый `NetcrazeRciTransport` |
| `Keenetic-VpnProfileTools.ps1/Backup-KeeneticRoutes()` | **Anti-pattern** | Читает полный running/startup config и считает route backup incomplete при timeout; непригодно для hot path. | `BackupArtifactService` |
| `Keenetic-VpnProfileTools.ps1/Apply-KeeneticWireGuardProfile()` | **Prototype-only** | Полезны checks existing interface и dry-run payload, но delete-old-peer → apply → optional save не имеет atomicity/Safe Configuration/compensation. | `AwgProvisioner` job steps |
| `Keenetic-VpnProfileTools.ps1/Get-KeeneticPasswordForTools()` | **Prototype-only** | DPAPI CurrentUser полезен; plain parameter и environment fallback оставить только legacy CLI. | `DpapiSecretStore` |
| copies `Keenetic-VpnProfileTools.ps1` in `publish/` and `bin/` | **Do-not-reuse** | Generated copies могут расходиться с root source. | build artifacts only |

## Route ensure, inventory and recovery

| Existing file / symbol | Class | Reason | Future component |
|---|---|---|---|
| `Export-Active-Keenetic-Routes.ps1` | **Golden behavior** | Использует лёгкий `show/ip/route`, фильтрует по interface и создаёт reviewable artifact без running-config. | `RouteInventoryReader`, route backup exporter |
| `Ensure-Keenetic-Routes-FromProfile.ps1` | **Golden behavior** | Public `/24` filtering — обязательное safety behavior. Сам direct apply не переносить. | `RouteDestinationPolicy`, import adapter |
| `Ensure-Keenetic-Routes-List.ps1` | **Prototype-only** | Полезны missing-before/read-back/missing-after и small batches; нет identity, ownership, plan, idempotency record, command-error checks или Safe Configuration. | `RouteSetPlanner`, `RouteReconciler`, `MutationJobRunner` |
| `Ensure-Keenetic-Routes-FromSummary.ps1` | **Anti-pattern** | В отличие от FromProfile не применяет public/special filter и может принять небезопасный summary; direct save. | запрещённый import path; только validated `RouteProposal` |
| `Check-Keenetic-Routes-List.ps1` | **Port** | Read-only desired-vs-observed comparison полезен для diff и verification. | `RouteSetPlanner`, `VerificationService` |
| `Restore-Keenetic-Routes-FromFile.ps1` | **Prototype-only** | Reviewable restore artifact полезен для drills, но hard-coded interface reporting и direct writes не дают safe rollback. | `RestoreJob`, compensation drill |
| `Move-Keenetic-Routes-FromFile.ps1`, `Switch-Keenetic-Routes-Interface.ps1` | **Anti-pattern** | Массовое перемещение routes между system names без managed ownership и immutable plan может затронуть unmanaged resources. | managed `RouteSet` reassignment plan |
| `Get-Keenetic-VPN-Status.ps1` | **Prototype-only** | Быстрый read-only diagnostic, но hard-coded `Wireguard0/1` и старый response shape. | `RouterInventory`, `TunnelObservation` |
| `Diagnose-Network-Path.ps1` | **Port** | Default route/router reachability/public egress полезны для preflight evidence. | `PreflightService` |
| `Diagnose-Cursor-Region.ps1` | **Prototype-only** | Исторический incident diagnostic с hard-coded route/interface assumptions; не часть Router Control domain. | operator diagnostics plugin/artifact |

## Historical deployment and switching scripts

| Existing file / symbol | Class | Reason | Future component |
|---|---|---|---|
| `Project_Context_For_AI.md` | **Golden behavior** | Источник deployment history, timeout, endpoint resolution, ASCII PS 5.1 и auto-push chronology. Содержит внутренние противоречия; executable code имеет приоритет. | historical fixtures + operations notes |
| `KeeneticOS-CLI-reference.md` | **Prototype-only** | Полезная vendor research note, но примеры `Wireguard0` и команды не доказывают NC-1812 capability. | `NetcrazeAdapter` research/fixture references |
| `Enable-Both-VPN-Profiles.ps1` | **Anti-pattern** | Намеренно поднимает два tunnels; исторически это создало противоречивое routing state и нарушает first-deployment single-active policy. | не переносить; negative scenario test |
| `Create-Keenetic-Wireguard1-Old.ps1` | **Do-not-reuse** | Одноразовый эксперимент создания второго interface со старыми secrets/profile assumptions. | negative fixture only, без secrets |
| `Restore-Old-Single-Router-Profile.ps1` | **Prototype-only** | Документирует useful compensation intent, но жёстко привязан к старым files/interface names и выполняет direct writes. | `VpnRollbackPlan` |
| `Set-VPN-Profile-Names.ps1` | **Do-not-reuse** | Меняет historical UI captions; captions не identity. | optional managed display metadata |
| `Switch-VPN-Keenet-Roll.cmd`, `Switch-VPN-RockBlack-DE.cmd`, `Use-AWG-NEW-DE.cmd`, `Use-AWG-OLD-Roll.cmd`, `VPN-Status.cmd` | **Do-not-reuse** | One-off wrappers с historical paths/names/endpoints; не являются API или repeatable jobs. | Hub plan/job UI |
| historical profile files and endpoint/address values | **Do-not-reuse** | Могут содержать secrets и относятся к старому router/FI deployment. Нельзя помещать в docs, tests или repository. | sanitized recorded fixtures с documentation CIDRs |

## Build and UI support

| Existing file / symbol | Class | Reason | Future component |
|---|---|---|---|
| `TrafficMonitorGui/README.md` | **Golden behavior** | Подтверждает current executable auto-push и operational safeguards, но old router state — historical fixture. | strangler runbook |
| `Rebuild-Clean.ps1` | **Prototype-only** | Нужен только для поддержки legacy WPF executable до cutover. | legacy release process |
| `TrafficMonitorGui/publish/**`, `TrafficMonitorGui/bin/**`, `TrafficMonitorGui/obj/**` | **Do-not-reuse** | Generated outputs/caches, не architecture evidence и не source. | исключить из Python package |
| WPF XAML/windows/theme/icon/process presentation code | **Do-not-reuse** | Target UI — protected block existing Hub `/settings`, не отдельное desktop application. | vanilla Hub settings UI |

## Обязательные characterization tests перед cutover

1. Current GUI Start действительно передаёт `-EnableKeeneticPush` и `-KeeneticProfileAccumulate`.
2. Active PC VPN приводит к pause router writes, но не останавливает collection.
3. Private/CGNAT/loopback/link-local/multicast destinations не попадают в `RouteProposal`.
4. DNS/PTR enrichment остаётся evidence с ambiguity, а не authoritative mapping.
5. Challenge auth выполняет не более одной re-auth после 401.
6. Route inventory использует `show/ip/route`; hot path не вызывает `show/running-config`.
7. Profile parser fail closed на missing/unknown AWG fields и multiple peers.
8. System interface ID и UI description не смешиваются; `Wireguard0` используется только в historical fixture.
9. Ни один fixture/log/plan/job/audit не содержит password, private key или preshared key.
10. Live NC-1812 writes остаются disabled до отдельной capability certification.
