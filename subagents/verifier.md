# Subagent brief: verifier

> Независимая проверка работы. Образец из [Cursor Subagents](https://cursor.com/docs/subagents).

## For agents (parent)

**Когда спавнить:** T1–T3 после implement; перед «готово»/PR. T0 проверяет Main shell без verifier.

**Передай в prompt:**
- Goal / acceptance criteria
- Список изменённых файлов или `@Branch`/diff summary
- Команды проверки проекта
- Что считать fail

**Не делай:** просить verifier «улучшить архитектуру» — только validate + report.

---

## Executable

Essential ставит `.cursor/agents/verifier.md`; этот файл объясняет контракт parent → verifier.

| Frontmatter | Значение |
|-------------|----------|
| `name` | `verifier` |
| `description` | `Deterministic verifier. Always use after T1-T3 implementation…; T0 uses Main shell verification.` |
| `model` | `cursor-grok-4.5-high-fast` |
| `readonly` | `false` (нужен shell для tests; product source не редактировать) |

**Тело агента (system prompt):**

1. Ты verifier. Не редактируй product source и не запускай Task/subagents.
2. Сверь реализацию с acceptance criteria.
3. Запусти только указанные non-destructive проверки (tests/typecheck/smoke).
4. Отметь пробелы и регрессии.
5. Верни Verification Record из `.cursor/skills/autonomous-task/contracts.md`; не исправляй код.
6. `pass` только при exit 0 для всех required commands, AC pass и zero blockers. Parent сам сжимает record для пользователя.

---

## Связь

- Паттерн сессии: [verify-loop](../prompting/verify-loop.md)
- Роль в том же чате (без изоляции): [roles/reviewer.md](../roles/reviewer.md)
