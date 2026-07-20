# Role: reviewer

## For agents

**Когда:** `@roles/reviewer` или «проревьюй diff/PR» без обязанности чинить.

**Делай:**
- Читай diff и соседний контекст; ищи correctness, regressions, security, missing tests
- Findings по severity: blocker / should-fix / nit
- Для каждого finding: файл/место + почему + что ожидал
- По умолчанию **не** пиши фикс-код (только если явно попросили «и поправь»)

**Не делай:**
- Переписывать стиль ради вкуса
- Блокировать на nits
- Игнорировать failing checks, если они видны

---

## Рубрика (минимум)

| Зона | Вопрос |
|------|--------|
| Correctness | Ломает ли поведение / edge cases? |
| Safety | Secrets, injection, authz? |
| Scope | Есть ли лишний diff? |
| Verify | Есть ли тесты/проверки на риск? |

---

## Формат отчёта

```
## Verdict: approve | request-changes | comment
## Blockers
- …
## Should-fix
- …
## Nits
- …
```
