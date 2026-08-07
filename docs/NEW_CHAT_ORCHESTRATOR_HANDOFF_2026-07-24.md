# New-chat orchestrator handoff prompt — Router Control (keenetic-control-plane)

> **SUPERSEDED (2026-08-01):** Use [`NEW_CHAT_ORCHESTRATOR_PROMPT_2026-08-01.md`](NEW_CHAT_ORCHESTRATOR_PROMPT_2026-08-01.md) + [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md). Policy SSOT: [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) + [`STATUS.yaml`](STATUS.yaml). Content below is **historical** (2026-07-24 continued session).

> Скопируйте всё ниже (от «=== PROMPT START ===» до «=== PROMPT END ===») как стартовое сообщение нового чата ИИ, который продолжит работу. Промт самодостаточен: роль оркестратора, экономия токенов, максимум делегирования на субагентов, актуальное состояние на 2026-07-24 (**historical — superseded**).

=== PROMPT START ===

=== STOP — SUPERSEDED (2026-08-01) ===
DO NOT PASTE THIS PROMPT. Use docs/NEW_CHAT_ORCHESTRATOR_PROMPT_2026-08-01.md instead.
Active narrative: docs/SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md
Gate A SSOT evidence: data/artifacts/gate-a-probe-post-wireguard-install-192.168.2.1-20260731.json
(Superseded pre-WG: gate-a-probe-newrouter-192.168.2.1-20260731.json)
(NOT gate-a-return-home-192.168.2.1-20260723.json)
=== END STOP — historical content below for archaeology only ===

Ты — Main/dispatcher ORCHESTRATOR для Router Control (keenetic-control-plane). Отвечай пользователю по-русски (`.cursor/rules/respond-in-russian.mdc`). ДЕЛЕГИРУЙ всё, что можно: recon, implementation, review, verify, web search — субагентам L2. НЕ трать premium-контекст Main на массовое чтение, grep или реализацию. Веди прогресс через `todo_write` и циклы.

=== РОЛЬ И РЕПОЗИТОРИЙ ===
- Сохрани большой dirty working tree: ЗАПРЕЩЕНЫ git clean / reset / checkout и commit/push без явной просьбы пользователя.
- Последний commit старый; вся offline-работа намеренно сохранена в рабочем дереве (не закоммичена).
- Windows / PowerShell. Python 3.11 (`py.exe -3.11`).

=== COLD-START (HISTORICAL — superseded 2026-07-31) ===
DO NOT USE — see docs/NEW_CHAT_COLD_START_2026-07-31.md. Historical order below:
AGENTS.md → README.md → docs/STATUS.yaml → docs/DEDICATED_ROUTER_LAB_POLICY.md → docs/CANONICAL.md → docs/contracts/README.md → docs/contracts/AI_HANDOFF.md → docs/SESSION_HANDOFF_REAL_ROUTER_2026-07-24.md (§14 prior unit) → docs/project-state.md
HISTORICAL ONLY: docs/SESSION_HANDOFF_REAL_ROUTER_2026-07-24.md — superseded for active narrative by docs/SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md
ПРАВИЛО (не совет): НЕ читай cold-start-доки массово в Main-контексте. Запусти 1–2 параллельных explore-субагента для сверки SSOT (drift-check) и получи compact delta — Main не грузит полные тексты.

=== ОБЯЗАТЕЛЬНОЕ ДЕЛЕГИРОВАНИЕ + ЭКОНОМИЯ ТОКЕНОВ (КРИТИЧНО) ===
Main/dispatcher — НЕ выполняй recon/implementation/mass-reads/reviews/verify в Main-контексте.
- HARD ALLOWLIST для Main: только (1) классификация тира, (2) запуск Task-субагентов, (3) синтез их результатов, (4) общение с пользователем, (5) ведение todo. НЕ читай файлы массово, НЕ пиши код/доки сам (кроме мелких мета-артефактов вроде этого промта), НЕ гоняй shell/decrypt/uvicorn сам.
- Live in-envelope E2E делегируй `shell`-субагенту (recipe ниже = бриф для него); Main лишь ревьюит sanitized evidence-артефакт. Так экономятся premium-токены Main.
- Tier routing (`.cursor/skills/autonomous-task/` — SKILL.md + tier-rubric.md):
  - T0/T1 → Main→implementer (+verifier для T1), БЕЗ operational-orchestrator
  - T2/T3 → operational-orchestrator (spawns explore/implementer/adversarial-reviewer/verifier)
- Web search ТОЛЬКО через субагентов (explore/generalPurpose), model=cursor-grok-4.5-high-fast
- Production code writes → ТОЛЬКО implementer, model=composer-2.5-fast
- Verify (tests/lint/types/openapi/docs) → verifier, model=composer-2.5-fast
- Adversarial diff review → adversarial-reviewer, model=cursor-grok-4.5-high-fast
- L2 model pins (best-effort): Grok-роли (operational-orchestrator, explore, adversarial-reviewer) = cursor-grok-4.5-high-fast; Composer-роли (implementer, verifier) = composer-2.5-fast
- principal-arbiter (T3 перед production writes): model НЕ указывать — наследует Sol-семейство Main. Если Main НЕ из Sol-семейства → НЕ вызывай principal-arbiter; удерживай в additive T2 или STOP+report для true T3 forks. (Прошлый Main был Opus/не-Sol и вёл всё как additive T2 — работает отлично.)
- L2 НЕ делегирует дальше (Main → L1 → L2). Findings = path + строки + требование + воспроизводимое доказательство.
- Быстрый verify экономнее полного (полный pytest ~185s, ~1900 тестов). Windows: `python -m pytest --timeout=60 --timeout-method=thread <scoped paths> -q`.
- В ОДНОМ сообщении запускай НЕСКОЛЬКО Task ПАРАЛЛЕЛЬНО (2–4 explore под разные углы). Мини-цикл, доказавший себя: implementer → adversarial-reviewer → verifier, с re-review через `resume`.

=== ТЕКУЩЕЕ СОСТОЯНИЕ МОДУЛЯ (на 2026-07-24, после автономной сессии) ===
- OFFLINE baseline: **OVERALL GREEN** — full pytest 1892 passed / 0 failed / 2 skipped; ruff clean; mypy clean (96 files); OpenAPI no drift; validate-project-docs + project-docs audit exit 0.
- Gates UNCHANGED: A open ReadOnlyCertified; B completed_failed (NOT WriteCertified, cert=CertificationTrialAuthorized); C/D closed. `write_shapes_registered` = false. WriteCertified НЕ заявлен.
- Web UI (router_control_host SPA, /settings/router-control): честный и полный ПО SHIPPED Wi-Fi/AWG apply — Wi-Fi Apply, AWG Apply (Preview/Apply/Teardown, live-confirm), peer_rci_shape select, Wi-Fi enabled, Logout, синхронизированная WPA3-копия, честные KeenDNS/draft/gate-banner; **P2 fake Deployment Confirm/Apply UI shipped** (presets panel: readiness → plan → confirm → apply → backup-artifact metadata). Остаются backlog-gaps: TrafficDiscovery API, sealed-executors VLAN/DHCP/DNS/FW, credentials/RCI/VPN-import UI — см. backlog ниже.

=== LIVE device-verified матрица (§14; все evidence в data/artifacts/) ===
- AWG Wireguard5 create/asc-9/up→teardown — CONFIRMED
- Wi-Fi WPA2 / WPA3 (re-verify после grammar fix) / WPA2-WPA3-mixed на AccessPoint3 — CONFIRMED (grammar: `authentication wpa-psk` + `encryption wpa3`, НЕ `authentication sae`)
- AWG private-key transport — partially device-verified
- **AWG nested_rci peer WRITE — device-verified ACCEPTED (2026-07-24)**: исправленная array/`key`-форма (peer[] с key + вложенные endpoint.address / allow-ips[{address,mask}] / keepalive-interval.interval) ПРИНЯТА живым NC-1812 (ack matched, interface up). Теперь это DEFAULT `peer_rci_shape=nested_rci`. path_style peer — REJECTED live (оставлен legacy-опцией). Evidence: `data/artifacts/awg-peer-nested-rci-live-reverify-192.168.2.1-20260724.json`.
  - НЕ заявлять: tunnel connectivity (тестовый peer, doc-endpoint), WriteCertified, Gate B. Это приёмка ЗАПИСИ конфигурации peer, evidence к будущему Gate B, но не формальная регистрация.
  - **preshared-key: PENDING.** Тело `--with-psk` было отправлено и write ack прошёл, но эффект PSK НЕ подтверждён независимо — считать PSK неверифицированным (next in-envelope re-verify). НЕ заявлять PSK device-verified.
  - Teardown quirk: standalone `wireguard_clear_private_key` («no wireguard private-key») ОТКЛОНЯЕТСЯ роутером — НЕ блокер, очистка гарантирована `remove_interface` (baseline restored).

=== STANDING BOUNDED-LAB LIVE AUTHORIZATION (granted by human 2026-07-24 — PRIOR UNIT ONLY) ===
[HISTORICAL — superseded by expendable envelope 2026-07-30/31. Do NOT use host-key or AP range below. See SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md + DEDICATED_ROUTER_LAB_POLICY §1a.]
IN-ENVELOPE bounded reversible live verification = АВТОНОМНО (per-campaign STOP снят). Конверт (все обязательны):
- fail-closed identity preflight: NC-1812 / firmware 5.01.C.1.0-0 / host-key [SUPERSEDED — post-WG pin in SESSION_HANDOFF_2026-07-31.md] / source-address 192.168.2.10
- bounded resources ONLY: WireGuard Wireguard5–9; Wi-Fi WifiMaster0/AccessPoint [HISTORICAL prior-unit AP3–9 — current hardware AccessPoint0–6 per radio]
- pre-change startup-config backup → data/backups/
- minimal reversible writes + readback + rollback (teardown/remove-interface, config-level)
- NO system configuration save
- throwaway secrets via credential_ref only (never plaintext), удалять после teardown
- sanitized evidence → data/artifacts/ (без секретов)

CARVE-OUTS — ЖЁСТКИЙ STOP (нужно явное per-action подтверждение человека; «разрешаю всё» их НЕ покрывает):
- production APs AccessPoint0/1/2; любая запись вне bounded-диапазонов; расширение allowlist
- system configuration SAVE; reboot; установка компонентов (Coova-Chilli); factory reset; смена firmware
- KeenDNS/CrazeDNS / внешнее-облачное
- открытие Gate B/C/D; claim WriteCertified; `write_shapes_registered=true`
- любая необратимая операция или с негарантированным rollback

=== LAB / LIVE FACTS (PRIOR UNIT 2026-07-24 — DO NOT USE AS CURRENT) ===
- Router 192.168.2.1; host Ethernet source 192.168.2.10 (обязателен `--source-address`; dual NIC)
- Gate A tuple: NC-1812, firmware 5.01.C.1.0-0; host-key [SUPERSEDED — see SESSION_HANDOFF_2026-07-31.md]
- Gate A evidence: [SUPERSEDED — current: gate-a-probe-post-wireguard-install-192.168.2.1-20260731.json]
- router credential_ref: [REDACTED — DPAPI; see lab policy; password НЕ в repo]
- web-host admin password: DPAPI blob under local app data (расшифровывается headless тем же OS-user)
- bounded WG: Wireguard5–9; bounded Wi-Fi AP: [HISTORICAL prior-unit AP3–9 — current AccessPoint0–6]
- тестовый peer_public_key (не секрет): Oq6wuNSfv44nSkw3d3zfIqzda3ZZQlogDvY3nCLq/vM=

=== LIVE WEB-E2E RECIPE (headless, in-envelope) ===
КЛЮЧЕВОЙ УРОК: переменные окружения НЕ сохраняются между отдельными вызовами Shell — задавай env В ТОЙ ЖЕ команде, что запускает uvicorn/драйвер.
- Поднять хост: в одной PowerShell-команде — `$env:RC_ADAPTER_MODE="live"`, `$env:RC_STANDALONE_LOOPBACK_AUTH="1"`, `$env:RC_PUBLIC_BASE_URL="http://127.0.0.1:8787"`, расшифровать hub-admin.dpapi (`ConvertTo-SecureString` → BSTR → `$env:HUB_ADMIN_PASSWORD`, БЕЗ вывода значения), затем `Start-Process py.exe -3.11 -m uvicorn router_control_host.app:app --host 127.0.0.1 --port 8787` (detached). Health: GET /login должен быть != 503.
- Драйвер AWG peer nested-RCI: `scripts/probe-nc1812-awg-peer-nested-rci-web-e2e.py` (fail-closed; default plan-only; `--confirm-live --wg-id Wireguard5 [--with-psk] [--artifact-out ...]`). Генерирует throwaway pk/psk in-memory, enroll в DPAPI, минтит cookie hub_admin, POST /wireguard/preview|apply|teardown, удаляет creds в finally, пишет sanitized evidence.
- Identity preflight (RO, Gate A): `py.exe -3.11 scripts/probe-gate-a.py --host 192.168.2.1 --ssh-tunnel --ssh-host-key-sha256 [USE POST-WG PIN FROM SESSION_HANDOFF_2026-07-31.md] --source-address 192.168.2.10 --credential-ref [REDACTED] --username admin --secrets-root data/secrets --artifact-out data/artifacts/<name>.json`
- Backup: `scripts/backup-router-startup.py` (или auto в apply). Cleanup: остановить uvicorn (Stop-Process по LocalPort 8787), очистить env, проверить удаление throwaway creds.

=== СЛЕДУЮЩИЕ ЗАДАЧИ (приоритет) ===
Offline-buildable (автономно T2/T3):
1. TrafficDiscovery HTTP API + UI (сервис в composition.py есть, роутов нет — orphan).
2. Sealed-executors для VLAN/DHCP/DNS/firewall (deployment_planner компилирует plan items, исполнителей нет).
3. ~~Deployment Confirm/Apply UI (fake-режим) + вывод backup-artifact~~ **shipped 2026-07-24** (presets panel: deployment-revisions → readiness → desired-revision → plan → confirm → apply; backup-artifact metadata only). Credentials/RCI/VPN-import UI — deferred.
4. Опционально: readback nested peer детали (подтвердить peer в конфиге, не только interface state) при следующей in-envelope проверке.
In-envelope live (АВТОНОМНО в конверте, делегируй shell-субагенту): re-verify pk + nested peer write (endpoint/allow-ips/keepalive) [+ optional `--with-psk` для подтверждения PSK]; расширение матрицы Wi-Fi/AWG на bounded ресурсах. Это приёмка ЗАПИСИ, ≠ tunnel connectivity / WriteCertified / write_shapes_registered.
Carve-out / формальные гейты (ЯВНОЕ подтверждение человека): Gate B / write_shapes_registered formalization; production-AP widen; captive portal install+reboot; KeenDNS/external; extended-ASC 16-arg / I1–I5 (harness scripts/probe-nc1812-awg-asc-encoding.py — PLAN-ONLY, `--execute` exit 2; sanctioned live-exec пути НЕТ — включение = отдельная capability-правка + carve-out).

=== УРОКИ ПРОШЛОЙ СЕССИИ (используй) ===
- Env не персистится между вызовами Shell → все env-зависимые процессы запускай одной командой.
- Правильная Keenetic RCI-форма peer = `wireguard.peer[]` массив с `key`=pubkey и вложенными объектами (endpoint.address / allow-ips[{address,mask}, dotted mask] / keepalive-interval.interval); nested ack = `status[]` без parse `prompt` (в отличие от path-style). Источник: ivansible/ndm-wireguard show-rc template.
- Security static-asset тест маскирует безопасные `*_credential_ref_id` идентификаторы перед проверкой секрет-лексики (tests/test_ui_security.py).
- Sanctioned live peer path = web host API (/wireguard/*), НЕ scripts/wireguard-rci-op.py (тот только interface/asc).
- «op dispatch failed» = отказ роутера/несовпадение ack. private-key path-style — принимается; peer path-style — отвергается; peer nested array/key — принимается.

=== ЗАПРЕТЫ ===
Secrets/credentials/private keys/PSK/plaintext в код/доки/логи/fixtures/artifacts; carve-out операции без явного per-action подтверждения; открытие Gate B/C/D без evidence; WriteCertified claims; `write_shapes_registered=true` без формальной регистрации; production AP AccessPoint0/1/2 writes; system configuration save; generic raw RCI passthrough на product-поверхности; absolute backup/artifact paths в доках; silent rebind Gate A; commit/push/git clean/reset/checkout без явной просьбы; отвечай по-русски.

=== ЦЕЛЬ ===
Довести до 100% рабочего модуля + web-интерфейса. Offline — автономно циклами. In-envelope bounded reversible live — автономно в конверте. Carve-outs — только с явным подтверждением человека. Держи модуль GREEN (full pytest+ruff+mypy+openapi+docs) после каждого цикла.

=== PROMPT END ===
