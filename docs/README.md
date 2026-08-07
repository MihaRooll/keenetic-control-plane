# Router Control

Router Control — модуль локального управления роутером **Netcraze Ultra NC-1812** для выездного event booth. Offline mega (SLICE-2/3/5/8) доставил persistence, FastAPI host, vault и TrafficDiscovery proposals-only; живой роутер по-прежнему не изменяется без открытых hardware gates.

## Текущий статус

**Phase 0a / 0b — complete.** **Phase 1 offline mega + SLICE-4 Gate A — complete** (2026-07-21; post-WG identity-drift rebind **2026-07-31**). Gate **A** open ReadOnlyCertified; Gate **B** `completed_failed`; Gates **C/D** closed. **M0–M5 + P1–P3 — complete** (2026-07-22..2026-07-23). **Prototype management UI — complete** (2026-07-22). **2026-08-01 offline-only sessions (NOT device-verified):** VPN policy-routing preview; network-family preview HTTP; station apply/teardown HTTP + UI panels; offline reliability substrate (schema v12). **Next task:** [`STATUS.yaml`](STATUS.yaml) `next_task` (`local-hub-vpn-real-peer-autoconnect-continuation`) — VPN handshake + traffic via tunnel **device-verified** (§M-24..§M-27); station apply **live** (§M-34). **Parallel deferred:** VPN named policy / kill-switch live apply (offline preview only; kill-switch `permit global` **unresolved**; **`SET_IP_ADDRESS` + `wireguard_ip_global` DEVICE-VERIFIED** §M-24/M-27). Active handoff: [`SESSION_HANDOFF_REAL_ROUTER_2026-08-02.md`](SESSION_HANDOFF_REAL_ROUTER_2026-08-02.md) (historical methods companion: [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md)).

Этот репозиторий — текущий дом проекта и будущего лабораторного prototype. Целевая интеграция — существующий Python 3.11 / FastAPI Hub `module_3.0`, но только после проверки ядра и hardware gates. `ScanCursorIP` остаётся legacy behavioral evidence и рабочим strangler-контуром до достижения parity и отдельного решения о cutover; новую реализацию там не создаём.

## Порядок чтения

Новый участник или AI agent читает документацию в таком порядке (совпадает с [`AGENTS.md`](../AGENTS.md)):

1. [`README.md`](../README.md) — назначение, статус и ограничения.
2. [`STATUS.yaml`](STATUS.yaml) — машиночитаемая phase, deliverables, blockers и next task.
3. [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) — dedicated NC-1812 lab ownership; expendable autonomous envelope vs non-expendable carve-outs; Gate A RO.
4. [`CANONICAL.md`](CANONICAL.md) — canonical facts, safety invariants и legacy evidence.
5. [`contracts/README.md`](contracts/README.md) — contracts program и Wave navigation.
6. [`contracts/AI_HANDOFF.md`](contracts/AI_HANDOFF.md) — cold-start extensions, SSOT, task template.
7. [`SESSION_HANDOFF_REAL_ROUTER_2026-08-02.md`](SESSION_HANDOFF_REAL_ROUTER_2026-08-02.md) — **current** real-router session narrative (post-rebind unit; capability banner for superseded VPN claims — see STATUS §M-24+).
   - **Recommended (methodology):** [`ENGINEERING_LESSONS.md`](ENGINEERING_LESSONS.md) — transferable lab judgement, offline-reliability traps, agent-delegation lessons (L-1..L-20, D-1..D-5); companion to handoff assumption traps; does **not** override POLICY/STATUS.
   - **Recommended (UI / next major phase):** [`OPERATOR_UI.md`](OPERATOR_UI.md), [`OPERATOR_ROUTER_CONFIG_UI.md`](OPERATOR_ROUTER_CONFIG_UI.md), [`OPERATOR_WEB_UI_FULL_COVERAGE_PLAN.md`](OPERATOR_WEB_UI_FULL_COVERAGE_PLAN.md), [`contracts/ROADMAP.md`](contracts/ROADMAP.md) §3.3 — prototype UI today; **`operator-web-ui-full-coverage`** (`STATUS.yaml` `next_task`: simple-by-default + Advanced settings + tooltips + all supported parameters).
8. Task-specific contracts as needed (e.g. [`OPERATOR_NETWORK_FAMILY_APPLY_SCAFFOLD.md`](OPERATOR_NETWORK_FAMILY_APPLY_SCAFFOLD.md) for VLAN/DHCP/DNS/firewall preview scaffold; [`OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md`](OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md) for VPN policy-routing).
9. [`project-state.md`](project-state.md) — non-competing harness projection.

**New chat orchestrator prompt:** [`NEW_CHAT_ORCHESTRATOR_PROMPT_2026-08-02.md`](NEW_CHAT_ORCHESTRATOR_PROMPT_2026-08-02.md) — living paste block for autonomous continuation; refresh baseline blocks before copy.

## Дополнительная навигация Phase 0a

По задаче — после обязательного cold start:

- [`VISION.md`](VISION.md) — event scenario, пользователи, зоны и границы продукта.
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — bounded contexts, trust boundaries и путь prototype → Hub.
- [`DOMAIN_MODEL.md`](DOMAIN_MODEL.md) — entities, revisions, desired/observed state, ownership и invariants.
- [`LEGACY_MAP.md`](LEGACY_MAP.md) — что переносить из C#/PowerShell, что считать golden behavior и что не переиспользовать.
- [`COMPATIBILITY.md`](COMPATIBILITY.md) — firmware/capability matrix и hardware certification gates.
- [`OPERATOR_GATE_A.md`](OPERATOR_GATE_A.md) — completed Gate A operator runbook (ReadOnlyCertified lab tuple).
- [`OPERATOR_GATE_FAIL_SAFE.md`](OPERATOR_GATE_FAIL_SAFE.md) — fail-safe timer discovery runner; both trials closed **completed_failed** (historical).
- [`SESSION_HANDOFF_REAL_ROUTER_2026-07-24.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-24.md) — **historical** prior-unit handoff (methods archive; superseded by 2026-07-31).
- [`SESSION_HANDOFF_UI_AUTH_2026-07-22.md`](SESSION_HANDOFF_UI_AUTH_2026-07-22.md) — UI auth bootstrap closeout (delivered 2026-07-22; **historical handoff** — do not paste §10).
- ADR:
  - [`adrs/0001-python-package-fastapi-host.md`](adrs/0001-python-package-fastapi-host.md)
  - [`adrs/0002-persistence-jobs-sqlite.md`](adrs/0002-persistence-jobs-sqlite.md)
  - [`adrs/0003-security-auth-secrets.md`](adrs/0003-security-auth-secrets.md)
  - [`adrs/0004-product-capability-scope.md`](adrs/0004-product-capability-scope.md)
  - [`adrs/0005-local-first-commissioning-roadmap.md`](adrs/0005-local-first-commissioning-roadmap.md)

## Зафиксированное направление

- Domain core создаётся как переносимый Python package `router_control` без зависимости от FastAPI.
- Prototype получает отдельный FastAPI dev-host; позже package механически встраивается в lifecycle и dependency wiring `module_3.0`.
- In Hub API будет жить на общем listener под `/api/router-control/v1/*` ([`contracts/API_CONTRACT.md`](contracts/API_CONTRACT.md)), а UI — только в защищённом блоке существующего `/settings`.
- Router Control использует отдельную SQLite database `data/router_control.sqlite3`; JSON допускается для import/export и redacted artifacts, но не как основное state storage.
- Первая VPN capability — только **AmneziaWG**. Unknown firmware, capability или profile field запрещает write operation.
- Любое изменение роутера проходит unified lifecycle: preflight → identity → observe → backup → plan-preconditions → Confirm → Fail-safe Configuration → apply → read-back → verify → save/compensate ([`contracts/RCI_POLICY.md`](contracts/RCI_POLICY.md)).
- Mutation jobs сериализуются по стабильному `RouterId`; модуль изменяет или удаляет только ресурсы с собственной ownership record.
- Degraded/disabled Router Control не должен блокировать kiosk, order board, printing или запуск Hub.

Полный продуктовый сценарий и explicit non-goals описаны в [`VISION.md`](VISION.md).

## Границы Phase 0a

Phase 0a создаёт только architecture evidence: code-truth, domain model, security/trust boundaries, compatibility unknowns, integration contract и ADR. На этой phase запрещены:

- реализация package, API или UI;
- подключение к живому NC-1812 и любые router mutations;
- утверждение поддержки firmware/AWG без laboratory evidence;
- перенос в `module_3.0`;
- размещение passwords, private keys, session data или иных secrets в документации.

Phase 0a/0b closed. Foundation complete (offline mega, SLICE-4 Gate A RO, SLICE-6 AWG trial closed failed). **M0–M5 + P1–P3 complete.** **2026-08-01 offline-only sessions (NOT device-verified).** **Next major phase:** full operator web UI — [`STATUS.yaml`](STATUS.yaml) `next_task` (`operator-web-ui-full-coverage`). **Parallel deferred:** VPN routing live apply (offline preview only; kill-switch unresolved). Active handoff: [`SESSION_HANDOFF_REAL_ROUTER_2026-08-02.md`](SESSION_HANDOFF_REAL_ROUTER_2026-08-02.md) (historical methods companion: [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md)).

## Harness и living docs

Cursor harness (Essential) bootstrapped from cursor-project-toolkit. Дополнительная навигация:

| Документ | Назначение |
|----------|------------|
| [`project-state.md`](project-state.md) | Живая проекция phase/next checks для hooks (SSOT — [`STATUS.yaml`](STATUS.yaml)) |
| [`docs-map.json`](docs-map.json) | Индекс документации; обновлять при изменении listed docs |
| [`living-documentation.md`](living-documentation.md) | Правила living docs и docs-map |
| [`papercuts.md`](papercuts.md) | Workflow friction log (`.papercuts.jsonl`) |
| [`project-environment.md`](project-environment.md) | Doctor/setup surfaces |
| [`docs-map-schema.md`](docs-map-schema.md) | Схема `docs-map.json` |
| [`NEW_CHAT_ORCHESTRATOR_PROMPT_2026-08-02.md`](NEW_CHAT_ORCHESTRATOR_PROMPT_2026-08-02.md) | Готовый промт для нового чата (orchestrator paste; обновлять baseline перед копированием) |
