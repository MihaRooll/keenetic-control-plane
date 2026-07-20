---
name: autonomous-task
description: Автономно выполнить правку, баг, модуль или крупную фичу: выбрать T0–T4, нужных Grok/Composer/Sol субагентов, реализовать, проверить и вернуть evidence. Использовать автоматически для change/build/fix и запросов «сделай», «исправь», «реализуй».
---

# Autonomous task

Один пользовательский запрос → один bounded workflow. Main остаётся dispatcher и финальным владельцем результата.

## Сначала

1. Прочитай [tier-rubric.md](tier-rubric.md): сначала T4 overrides, затем Minimum T3, затем **самый низкий** T0–T2.
2. Создай Task Contract по [contracts.md](contracts.md): Goal, AC, owned paths, verify commands, forbidden operations.
3. Не спрашивай approval для T0–T3, если нет material ambiguity. T4 → Human Gate Packet и stop.

## Routing

| Tier | Путь |
|------|------|
| T0 | Main → `implementer` → Main запускает verify commands |
| T1 | Main → `implementer` → Main запускает `verifier` |
| T2 | Main → `operational-orchestrator` → Explore → plan → implementer → `adversarial-reviewer` → verifier |
| T3 | T2 + `principal-arbiter` approve **до** implementer |
| T4 | Human Gate Packet; без implementer до approval |

Main запускает T0/T1 agents напрямую. Для T2/T3 передай `operational-orchestrator` полный Task Contract; он запускает только L2 workers из таблицы. Composer никогда не запускает reviewer/verifier.

## State machine

T0–T3: `CONTRACT → [PLAN] → [PRINCIPAL] → IMPLEMENT → [REVIEW] → VERIFY → terminal`

T4: `CONTRACT → HUMAN → HUMAN_PENDING`; reject → BLOCKED. После approve: action-only выполняет Main; code-only идёт через reviewed T2; hybrid = reviewed code → Main exact action → verify.

- T0/T1 пропускают PLAN/PRINCIPAL/REVIEW.
- T2 пишет plan в `.cursor/plans/`.
- T3: Sol reject → revise packet; максимум 2 попытки, затем BLOCKED.
- T4: HUMAN_PENDING до явного решения; packet creation не означает approval, external/destructive action остаётся у Main.
- Review/verify rework: общий максимум 3 цикла; цикл 3 чинит только blocker.
- L2 agents не делегируют. Production writer один.

## Spawn packets

Каждый prompt субагенту содержит:

- `contract_id`, tier, phase;
- Goal + AC IDs;
- owned/forbidden paths;
- verify commands;
- ожидаемый return schema из [contracts.md](contracts.md);
- явный запрет расширять scope или делегировать дальше.

Для `adversarial-reviewer` не передавай reasoning автора: Task Contract + plan + diff/evidence достаточно.

## Evidence and completion

- Doc/user-facing change → Docs Impact Record ([contracts.md](contracts.md) §8): paths, map entries, validator yes/no.
- Finding без `path + lines + requirement_ref + evidence` отклони.
- Sol получает только Principal Packet: без raw logs, file dumps и tool JSON.
- `done` допустим только если Verification Record: все AC=`pass`, все exit codes=`0`, blockers=`0`.
- Main возвращает короткий Final Report: изменения, файлы, команды/exit codes, циклы, остаточные риски.

## Safety

- T4 hard overrides: production deploy, push/publish, payments, secrets, data loss, irreversible migration, destructive/external mutation.
- Не commit/push/deploy, если пользователь отдельно не просил.
- Model pins и auto-routing могут fallback/skip в normal chat; зафиксируй это как limitation, а не скрывай.
