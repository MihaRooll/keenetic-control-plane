# Router Control

Router Control — самостоятельный проект локальной control plane для безопасного управления роутером **Netcraze Ultra NC-1812** в составе выездного event booth. Проект должен дать оператору проверяемые inventory, plans, durable jobs и audit, не превращая сетевой модуль в точку отказа для заказов, production board и печати.

Этот репозиторий — канонический дом Router Control и будущего прототипа. `ScanCursorIP` используется только как legacy behavioral evidence и strangler-контур; новая реализация не должна создаваться там.

## Статус

**Phase 0a / 0b — complete.** **M0–M5 + P1–P3 — complete** (2026-07-22..2026-07-23). Gate **A** open ReadOnlyCertified; Gate **B** `completed_failed` (not WriteCertified); Gates **C/D** closed. **2026-08-05 device-verified (expendable lab):** first real WireGuard handshake; interface Address + `wireguard_ip_global`; client traffic via tunnel reversibly; station allowlist 14 + 7/7 live; dual-stack AllowedIPs import; MSS apply/clear; VPN catalog live status + remove; main menu recomposed; VPN three-state UI + routing live; browser MCP usable (§M-41) — detail in [`.cursor/plans/main-decisions-local-hub.md`](.cursor/plans/main-decisions-local-hub.md) §M-24..§M-46. **Honesty gaps:** MSS ≠ captive portal; Wi‑Fi auto-reconnect watchdog not live-proven; guest entry pages need HW; animation acceptance (R-10) not human-done; rockblack peer no reply; kill-switch/named policy not built; R-3..R-6 blocked behind human gate. Gate A current evidence: see [`docs/STATUS.yaml`](docs/STATUS.yaml) `gates.A.evidence` (2026-08-05 fifth freshness recert — `gate-a-probe-main-verify-20260805-evening.json`, same tuple, NOT a rebind). **Next:** [`docs/STATUS.yaml`](docs/STATUS.yaml) `next_task` (`night_6_status_2026_08_05` / `evening_5_browser_2026_08_05`). WriteCertified **NOT** claimed; `write_shapes_registered` false. Active handoff: [`docs/SESSION_HANDOFF_REAL_ROUTER_2026-08-02.md`](docs/SESSION_HANDOFF_REAL_ROUTER_2026-08-02.md) + decisions hub §M-24+ (historical methods: [`docs/SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](docs/SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md)).

Packages: `router_control` (domain + persistence + vault + traffic + Netcraze RO adapter) and `router_control_host` (FastAPI `/api/router-control/v1` + UI `/settings/router-control` + session bootstrap). Run host: `uvicorn router_control_host.app:app` (set `HUB_ADMIN_PASSWORD`; open `/` or `/login` in browser) or `scripts/run-prototype-host.ps1` (DPAPI + standalone profile). Operator UI runbook: [`docs/OPERATOR_UI.md`](docs/OPERATOR_UI.md). **New chat:** copy-paste orchestrator prompt — [`docs/NEW_CHAT_ORCHESTRATOR_PROMPT_2026-08-06.md`](docs/NEW_CHAT_ORCHESTRATOR_PROMPT_2026-08-06.md) (refresh baseline blocks before copy). **Browser MCP (`cursor-ide-browser`) is usable** for UI verification per §M-41.

## Архитектура в двух словах

- Переносимое Python 3.11 ядро `router_control` отделено от FastAPI (`router_control_host`) и vendor RCI.
- Prototype FastAPI dev-host живёт в этом репозитории под тем же prefix, что и будущий Hub.
- Состояние — `data/router_control.sqlite3`; secrets — opaque `CredentialRef` + Memory/DPAPI vault (no plaintext API).
- Любая mutation должна пройти unified lifecycle: preflight → identity → observe → backup → plan-preconditions → Confirm → Fail-safe Configuration → apply → read-back → verify → save/compensate ([`docs/contracts/RCI_POLICY.md`](docs/contracts/RCI_POLICY.md)).
- Unknown firmware, capability или profile field блокируют writes.
- Router Control изменяет только ресурсы с подтверждённым ownership.
- Legacy WPF/PowerShell остаётся источником проверяемого поведения до parity и явного cutover.

## Порядок чтения

Перед любой работой прочитайте по порядку (совпадает с [`AGENTS.md`](AGENTS.md)):

1. [`README.md`](README.md) — назначение, статус и ограничения.
2. [`docs/STATUS.yaml`](docs/STATUS.yaml) — машиночитаемая phase, deliverables, blockers и next task.
3. [`docs/DEDICATED_ROUTER_LAB_POLICY.md`](docs/DEDICATED_ROUTER_LAB_POLICY.md) — dedicated NC-1812 lab ownership; expendable autonomous envelope vs non-expendable carve-outs; Gate A RO.
4. [`docs/CANONICAL.md`](docs/CANONICAL.md) — canonical facts, safety invariants и legacy evidence.
5. [`docs/contracts/README.md`](docs/contracts/README.md) — contracts program и Wave navigation.
6. [`docs/contracts/AI_HANDOFF.md`](docs/contracts/AI_HANDOFF.md) — cold-start extensions, SSOT, task template.
7. [`docs/SESSION_HANDOFF_REAL_ROUTER_2026-08-02.md`](docs/SESSION_HANDOFF_REAL_ROUTER_2026-08-02.md) — **current** real-router session narrative (2026-08-01/02 live session). Human gate packets (links only): [`docs/HUMAN_GATE_GATE_A_IDENTITY_DRIFT_20260801.md`](docs/HUMAN_GATE_GATE_A_IDENTITY_DRIFT_20260801.md), [`docs/HUMAN_GATE_KEENDNS_CLOUD_BOOKING_20260801.md`](docs/HUMAN_GATE_KEENDNS_CLOUD_BOOKING_20260801.md). Historical methods companion: [`docs/SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](docs/SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md).
   - **Recommended (methodology):** [`docs/ENGINEERING_LESSONS.md`](docs/ENGINEERING_LESSONS.md)
   - **Required (main screen SSOT):** [`docs/OPERATOR_SIMPLE_MAIN_MENU_SPEC.md`](docs/OPERATOR_SIMPLE_MAIN_MENU_SPEC.md)
   - **Recommended (UI):** [`docs/OPERATOR_UI.md`](docs/OPERATOR_UI.md), [`docs/OPERATOR_ROUTER_CONFIG_UI.md`](docs/OPERATOR_ROUTER_CONFIG_UI.md) — prototype runbooks; [`docs/OPERATOR_WEB_UI_FULL_COVERAGE_PLAN.md`](docs/OPERATOR_WEB_UI_FULL_COVERAGE_PLAN.md) — deferred plan, **not** current `next_task`; [`docs/contracts/ROADMAP.md`](docs/contracts/ROADMAP.md) §3.3
8. Task-specific contracts as needed (e.g. [`docs/OPERATOR_NETWORK_FAMILY_APPLY_SCAFFOLD.md`](docs/OPERATOR_NETWORK_FAMILY_APPLY_SCAFFOLD.md), [`docs/OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md`](docs/OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md)).
9. [`docs/project-state.md`](docs/project-state.md) — non-competing harness projection.

**New chat orchestrator prompt:** [`docs/NEW_CHAT_ORCHESTRATOR_PROMPT_2026-08-06.md`](docs/NEW_CHAT_ORCHESTRATOR_PROMPT_2026-08-06.md) — paste block for autonomous continuation; **current truth** is [`docs/STATUS.yaml`](docs/STATUS.yaml) `next_task` (`night_6_status_2026_08_05`, `evening_5_browser_2026_08_05`) and [`.cursor/plans/main-decisions-local-hub.md`](.cursor/plans/main-decisions-local-hub.md) §M-24..§M-46 — read those before the paste block. Staff/guest resume: [`docs/HUMAN_GATE_STAFF_GUEST_MAIN_MENU_20260805.md`](docs/HUMAN_GATE_STAFF_GUEST_MAIN_MENU_20260805.md). Historical: [`docs/NEW_CHAT_ORCHESTRATOR_PROMPT_2026-08-05.md`](docs/NEW_CHAT_ORCHESTRATOR_PROMPT_2026-08-05.md).

**Дополнительно по задаче:** [`docs/VISION.md`](docs/VISION.md), [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), [`docs/DOMAIN_MODEL.md`](docs/DOMAIN_MODEL.md), [`docs/LEGACY_MAP.md`](docs/LEGACY_MAP.md), [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md), [`docs/adrs/`](docs/adrs/), [`docs/README.md`](docs/README.md) (полная навигация Phase 0a).

## Будущая интеграция

После fake, recorded и hardware certification gates переносимое ядро планируется механически встроить в существующий Python 3.11 / FastAPI Hub `module_3.0`: API на общем listener под `/api/router-control/v1/*` ([`docs/contracts/API_CONTRACT.md`](docs/contracts/API_CONTRACT.md)), UI — только в защищённом блоке `/settings` (prototype SPA already at `/settings/router-control` on dev-host), lifecycle — через существующие bootstrap/dependencies/lifespan patterns.

Руководство по facade и bootstrap для стороннего сервиса: [`docs/INTEGRATION.md`](docs/INTEGRATION.md).

Интеграция в `module_3.0` выполняется позже, а не в Phase 0b и не на текущем переносе документации.

## Ограничения текущего этапа

- **M1–M3** authorized as offline/read-only code only (2026-07-22). **Dedicated lab program** (2026-07-22): project-owned NC-1812 HW validation in scope; Gate A RO + offline prep OK. **Expendable lab class** (`expendable_development_router`, 2026-07-30): bounded autonomous envelope (save, reboot, component install, WireGuard, bounded Wi‑Fi APs, etc.) when live device matches recorded tuple — see [`docs/DEDICATED_ROUTER_LAB_POLICY.md`](docs/DEDICATED_ROUTER_LAB_POLICY.md) §1a. **Non-expendable carve-outs** and undefined writes still require explicit per-action confirmation.
- Live observe allowed only under Gate **A** open **ReadOnlyCertified** exact tuple; Gate **B** **completed_failed** (not WriteCertified); Gates **C/D** closed for writes.
- В репозитории запрещены passwords, private keys, raw sessions, startup-config и другие secrets.
- AWG write certification is a **parallel deferred lane** (trial completed_failed 2026-07-21) — not an M1 predecessor.

Полная навигация по Phase 0a находится в [`docs/README.md`](docs/README.md).
