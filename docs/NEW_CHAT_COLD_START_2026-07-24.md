# Cold-start paste prompt for new AI chat (2026-07-24)

> **SUPERSEDED (2026-08-01):** Use [`NEW_CHAT_ORCHESTRATOR_PROMPT_2026-08-01.md`](NEW_CHAT_ORCHESTRATOR_PROMPT_2026-08-01.md). Narrative: [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md). Policy SSOT: [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) + [`STATUS.yaml`](STATUS.yaml).

## For agents

**Purpose:** **HISTORICAL / superseded** — do **not** paste. Use [`NEW_CHAT_ORCHESTRATOR_PROMPT_2026-08-01.md`](NEW_CHAT_ORCHESTRATOR_PROMPT_2026-08-01.md).

**When to use:** Archaeology only — prior-unit 2026-07-24 session context.

**SSOT handoff (historical):** [`SESSION_HANDOFF_REAL_ROUTER_2026-07-24.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-24.md) — prior-unit narrative. **Current unit (2026-07-31):** see [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md) + [`STATUS.yaml`](STATUS.yaml) blocker `wg-component-lab-connectivity-20260731`.

---

## Paste block (copy everything inside the fence)

```
=== STOP — SUPERSEDED (2026-08-01) ===
DO NOT PASTE THIS PROMPT. Use docs/NEW_CHAT_ORCHESTRATOR_PROMPT_2026-08-01.md instead.
Active narrative: docs/SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md
Gate A SSOT evidence: data/artifacts/gate-a-probe-post-wireguard-install-192.168.2.1-20260731.json
(Superseded pre-WG rebind #1: gate-a-probe-newrouter-192.168.2.1-20260731.json)
=== END STOP — historical content below for archaeology only ===

Ты продолжаешь Router Control (keenetic-control-plane) автономно и по-русски.

=== РОЛЬ И РЕПОЗИТОРИЙ ===
- Отвечай пользователю по-русски (.cursor/rules/respond-in-russian.mdc).
- Сохрани большой dirty working tree: ЗАПРЕЩЕНЫ git clean / reset / checkout и commit/push без явной просьбы пользователя.
- Последний commit: 2026-07-21; uncommitted work намеренно сохранён.

=== COLD-START (HISTORICAL — superseded 2026-07-31) ===
DO NOT USE — see docs/NEW_CHAT_COLD_START_2026-07-31.md. Historical order below:
AGENTS.md → README.md → docs/STATUS.yaml → docs/DEDICATED_ROUTER_LAB_POLICY.md → docs/CANONICAL.md → docs/contracts/README.md → docs/contracts/AI_HANDOFF.md → docs/SESSION_HANDOFF_REAL_ROUTER_2026-07-24.md → docs/project-state.md
HISTORICAL ONLY (prior unit): handoff 2026-07-24; Gate A evidence gate-a-return-home-192.168.2.1-20260723.json — SUPERSEDED by gate-a-probe-post-wireguard-install-192.168.2.1-20260731.json (rebind #1 newrouter also SUPERSEDED)

=== ОБЯЗАТЕЛЬНОЕ ДЕЛЕГИРОВАНИЕ + ЭКОНОМИЯ ТОКЕНОВ (КРИТИЧНО) ===
Ты — Main/dispatcher. НЕ трать премиум-контекст Main на рутину чтения больших файлов, массовый grep или реализацию.
- Маршрут по tier (см. .cursor/skills/autonomous-task/ — SKILL.md + tier-rubric.md): T0/T1 — Main→implementer (T1 добавляет verifier), БЕЗ orchestrator; T2/T3 — operational-orchestrator (он сам запускает explore/implementer/adversarial-reviewer/verifier). Смысл делегирования: НЕ выполняй recon/реализацию/ревью/verify в Main-контексте — но выбирай агента по tier, не 'оркестратор на всё'.
- В ОДНОМ сообщении запускай НЕСКОЛЬКО Task ПАРАЛЛЕЛЬНО (2–4 explore под разные углы).
- Разведка/поиск/веб → explore или generalPurpose, model=cursor-grok-4.5-high-fast (веб ТОЛЬКО через субагентов).
- Многофайловая координация (T2/T3) → operational-orchestrator, model=cursor-grok-4.5-high-fast (он сам запускает explore/implementer/adversarial-reviewer/verifier).
- Запись в production-код → ТОЛЬКО implementer, model=composer-2.5-fast.
- Проверки (тесты/линт/типы/openapi/docs) → verifier, model=composer-2.5-fast.
- Независимое ревью диффа → adversarial-reviewer, model=cursor-grok-4.5-high-fast.
- principal-arbiter (T3 перед production-записью): model НЕ указывать — наследует Sol-семейство Main. Если Main НЕ из Sol-семейства → Sol недоступна → НЕ вызывай principal-arbiter; удерживай работу в аддитивных T2-границах и фиксируй ограничение; для настоящих T3-архитектурных развилок — STOP+report и жди EXPLICIT human sign-off.
- L2 НЕ делегирует дальше (Main → L1 → L2). Findings = path + строки + требование + воспроизводимое доказательство.
- Быстрый verify экономнее полного (полный pytest ~200s, 1700+ тестов). На Windows: pytest --timeout=60 --timeout-method=thread.

=== ТЕКУЩЕЕ СОСТОЯНИЕ (2026-07-24 session closeout) ===
Offline доставлено и verifier passed:
- Route parser default-route-v1.2; sanitize.py hardened (Wi-Fi/WG secret fields).
- Sealed write ops: wifi_rci.py (SSID/WPA/encryption/up/down; [HISTORICAL prior-unit AccessPoint3–9 — current hardware AccessPoint0–6 per radio]); wireguard_rci.py (create/asc/remove; Wireguard[5-9]); CLIs scripts/wifi-rci-op.py, scripts/wireguard-rci-op.py.
- Wi-Fi product model: WifiIntent wpa_mode + band; wifi_apply_planner; wifi_apply_service + POST /wifi/preview|apply|teardown; UI Wi-Fi Apply (test AP).
- Verify: pytest 1702 passed / 2 skipped; ruff/mypy/docs validators exit 0; NO commits since 2026-07-21.

Live device-verified NC-1812 (human-approved T4; full rollback; NO system configuration save):
- Wi-Fi WifiMaster0/AccessPoint3: ssid/up/down + WPA2; teardown to baseline.
- AWG Wireguard5: create; asc 9-arg OK; asc 16-arg REJECTED (I1-I5 unresolved); remove.
- FULL E2E WEB: auth → preview → apply(confirm) → backup + sealed ops + readback → teardown → baseline. Evidence: data/artifacts/wifi-web-e2e-verify-192.168.2.1-20260724.json. PSK never logged.

Gates UNCHANGED: A open ReadOnlyCertified; B completed_failed (NOT WriteCertified); C/D closed. write_shapes_registered остаётся false (реестры shape пусты; это не поле в STATUS.gates). WriteCertified NOT claimed. Wi-Fi apply = narrow bounded-test-AP exception, NOT broad WriteCertified.

=== LAB / LIVE FACTS (PRIOR UNIT 2026-07-24 — DO NOT USE AS CURRENT) ===
[HISTORICAL — superseded by expendable envelope 2026-07-30/31. See SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md + DEDICATED_ROUTER_LAB_POLICY §1a.]
- Test router: 192.168.2.1; host Ethernet source: 192.168.2.10 (mandatory --source-address on all live CLIs; dual NIC).
- Home working router: 192.168.1.1 via Wi-Fi (192.168.1.0/24) — parallel path.
- Gate A tuple: NC-1812, firmware 5.01.C.1.0-0; host-key [SUPERSEDED — post-WG pin in SESSION_HANDOFF_2026-07-31.md]
- Gate A SSOT evidence: [SUPERSEDED — current: gate-a-probe-post-wireguard-install-192.168.2.1-20260731.json]
- credential_ref: [REDACTED — DPAPI; see lab policy; password NOT in repo]
- WireGuard component: [HISTORICAL prior-unit claim — current unit: wireguard component installed 2026-07-31]
- Bounded test AP for writes: [HISTORICAL prior-unit AP3 only — current hardware AccessPoint0–6 per radio; see lab policy]

=== SAFE LIVE-TESTING PATTERN + T4 ===
sealed op + review → identity preflight (tuple + host-key + source 192.168.2.10) → pre-change backup (data/backups/) → minimal reversible write on bounded test AP → readback verify → rollback → NO system configuration save → sanitized evidence (data/artifacts/).
Every live mutation requires exact per-campaign T4 Human Gate Packet + explicit human approval. Program authorization ≠ standing write approval.
DPAPI credentials valid only under the OS user who enrolled them.

=== WEB SERVER (prototype host) ===
Recommended (DPAPI launcher, standalone loopback profile):
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/run-prototype-host.ps1
  # init first time: ... -Action init
  # binds 127.0.0.1:8787; sets RC_STANDALONE_LOOPBACK_AUTH=1, RC_PUBLIC_BASE_URL=http://127.0.0.1:8787

Manual alternative:
  $env:HUB_ADMIN_PASSWORD = "<your-operator-password>"
  $env:RC_STANDALONE_LOOPBACK_AUTH = "1"
  $env:RC_PUBLIC_BASE_URL = "http://127.0.0.1:8787"
  uvicorn router_control_host.app:app --host 127.0.0.1 --port 8787

Live adapter: RC_ADAPTER_MODE=live (Gate A RO observe; bounded test-AP apply under T4).
Auth: POST /login with hub_admin password → cookie hub_admin → /settings/router-control → #config → Wi-Fi Apply (test AP).
API: POST /api/router-control/v1/wifi/preview|apply|teardown with confirm_live_apply/confirm_live_teardown + connection params (host, username, router_credential_ref_id, ssh_host_key_sha256, source_address) + credential_ref_id for PSK (never plaintext psk).
See docs/OPERATOR_UI.md and docs/OPERATOR_WIFI_APPLY.md.

=== СЛЕДУЮЩИЕ ЗАДАЧИ (приоритет + tier) ===
1. Production-AP apply (widen allowlist) — T3 + per-campaign T4.
2. WPA3 live-verify — T4 (unsupported_pending_verification today).
3. AWG secret tunnel ops (private-key/peer/preshared-key) — T3 + T4.
4. Gate B / write_shapes_registered formalization — deferred.
5. Captive portal (Coova-Chilli install+reboot) — escalated T4.
6. KeenDNS/CrazeDNS (cloud/external) — T4.
7. Extended AWG asc I1-I5 encoding probe — 16-int rejected on device.
8. VPN AWG apply/verify UI vertical — mirror Wi-Fi; offline first, live T4.

Offline code/tests/docs автономно в T2. Live WRITE = STOP для human approval.

=== ЗАПРЕТЫ ===
Secrets/credentials/private keys/PSK/plaintext в код/доки/логи/fixtures/artifacts; generic raw RCI passthrough на product-поверхности; router writes без exact T4; открытие Gates B/C/D без evidence; WriteCertified claims; write_shapes_registered=true без формальной регистрации; absolute backup paths в доках; silent rebind Gate A; commit/push/git clean/reset/checkout без явной просьбы; production AP AccessPoint0/1/2 writes; system configuration save без T4.
```

---

## Docs Impact Record

| Field | Value |
|---|---|
| contract_id | nc1812-session-fixation-and-newchat-prompt-20260724 |
| paths | docs/NEW_CHAT_COLD_START_2026-07-24.md |
| notes | Paste-ready cold-start; supersedes SESSION_HANDOFF 2026-07-23 §12 for new chats |
