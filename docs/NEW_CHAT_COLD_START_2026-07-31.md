# Cold-start paste prompt for new AI chat (2026-07-31)

> **SUPERSEDED (2026-08-01):** Use [`NEW_CHAT_ORCHESTRATOR_PROMPT_2026-08-01.md`](NEW_CHAT_ORCHESTRATOR_PROMPT_2026-08-01.md). Narrative: [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md). Policy SSOT: [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) + [`STATUS.yaml`](STATUS.yaml).

## For agents

**Purpose:** **HISTORICAL / superseded** — do **not** paste. Use [`NEW_CHAT_ORCHESTRATOR_PROMPT_2026-08-01.md`](NEW_CHAT_ORCHESTRATOR_PROMPT_2026-08-01.md).

**When to use:** Archaeology only — short cold-start paste from 2026-07-31 session closeout.

**SSOT:** Living policy = [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) + [`STATUS.yaml`](STATUS.yaml). **Narrative companion** = [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md). Supersedes [`NEW_CHAT_COLD_START_2026-07-24b.md`](NEW_CHAT_COLD_START_2026-07-24b.md) and related 2026-07-24 paste prompts; **superseded by** [`NEW_CHAT_ORCHESTRATOR_PROMPT_2026-08-01.md`](NEW_CHAT_ORCHESTRATOR_PROMPT_2026-08-01.md).

---

## Paste block (copy everything inside the fence)

```
=== STOP — SUPERSEDED (2026-08-01) ===
DO NOT PASTE THIS PROMPT. Use docs/NEW_CHAT_ORCHESTRATOR_PROMPT_2026-08-01.md instead.
Active narrative: docs/SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md
=== END STOP — historical content below for archaeology only ===

=== PROMPT START ===

Ты продолжаешь Router Control (keenetic-control-plane). Отвечай по-русски (.cursor/rules/respond-in-russian.mdc). Сохрани dirty working tree — без git clean/reset/checkout/commit/push без явной просьбы.

COLD-START (строгий порядок из AGENTS.md):
README.md → docs/STATUS.yaml → docs/DEDICATED_ROUTER_LAB_POLICY.md → docs/CANONICAL.md → docs/contracts/README.md → docs/contracts/AI_HANDOFF.md → docs/SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md → docs/ENGINEERING_LESSONS.md (recommended methodology; judgement traps — не device-fact SSOT) → docs/project-state.md
(AGENTS.md — инструкции агентам; читай первым если новая сессия)

ПРИОРИТЕТ SSOT: docs/STATUS.yaml + docs/DEDICATED_ROUTER_LAB_POLICY.md — политика/lab class/gates/next_task.
Narrative companion (methods/traps/status/end state): docs/SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md — НЕ переопределяет POLICY/STATUS.

Текущий lab unit (post-rebind 2026-07-31, verified end state):
- NC-1812 @ 192.168.2.1; source-bind 192.168.2.10 обязателен
- Gate A ReadOnlyCertified; evidence data/artifacts/gate-a-probe-post-wireguard-install-192.168.2.1-20260731.json (rebind #2 post-WG; rebind #1 morning = physical replacement; superseded: gate-a-probe-newrouter-192.168.2.1-20260731.json)
- Host-key pin SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY
- lab_class expendable_development_router (POLICY §1a)
- Station uplink DEVICE-VERIFIED + PERSISTED (WifiMaster1/WifiStation0, 5 GHz WPA2, ip global 600, config saved, survived reboot) — uplink_verified_bounded, NOT generally "supported"
- WG component installed (wireguard; no Amnezia); NO Wireguard* iface currently
- Tunnel dead-peer + **tunnel_healthy DEVICE-CONFIRMED** (2026-07-31); routing/kill-switch/Address/IPv6 **NOT done**
- Live: online via station uplink + default route; wired ISP global 700 but link DOWN
- Open items: open-network; captive-portal; kill-switch/permit global (**unresolved**); standby; VPN routing live apply (offline preview only); live station HTTP apply verification
- WriteCertified НЕ заявлен; write_shapes_registered false; Gates B/C/D закрыты

Абсолютно: без secrets в repo/chat; live device ≠ recorded tuple → fail-closed writes.

=== PROMPT END ===
```

---

## Docs Impact Record

| Field | Value |
|---|---|
| contract_id | session-handoff-endstate-20260731; engineering-lessons-doc (cycle 2 paste wiring) |
| paths | docs/NEW_CHAT_COLD_START_2026-07-31.md |
| notes | End-state paste; removed in-flight station campaign warning; points to 2026-07-31 handoff; cycle 2 adds `docs/ENGINEERING_LESSONS.md` in operative cold-start chain — see [`ENGINEERING_LESSONS.md`](ENGINEERING_LESSONS.md) Docs Impact Record |
