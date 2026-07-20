# prompting/ — паттерны работы с агентом

> **AI-first.** Не community prompt dump. Политика ingest: `docs/prompts-chat-verdict.md` (toolkit only).

## For agents

**Когда читать:** старт нетривиальной задачи; пользователь просит «промпт» / «как сформулировать»; наполнение этой папки.

**Применяй:**
- Бери **паттерн** (таблица/чеклист) → встрой в сообщение или plan
- Ориентиры: [`docs/cursor-agent-best-practices.md`](../docs/cursor-agent-best-practices.md), [`docs/cursor-primitives.md`](../docs/cursor-primitives.md)
- Новый материал → только если проходит фильтр ingest из `prompts-chat-verdict` (повторяемый, agent/dev, сжимается без «Act as…»)
- Official starters: `docs/claude-code-prompt-library.md` (toolkit only; паттерны > полный каталог)
- Change/build/fix workflow → `.cursor/skills/autonomous-task` (T0–T4 routing); patterns ниже — его building blocks

**Не делай:** bulk с prompts.chat / Awesome*; длинные persona-эссе; дублировать official Cursor docs целиком.

---

## Индекс паттернов

| Файл | Когда | Bootstrap |
|------|--------|-----------|
| [plan-then-build.md](plan-then-build.md) | Сложная фича, неочевидный scope | Essential |
| [context-hygiene.md](context-hygiene.md) | Новый чат / шумный контекст / смена задачи | Essential |
| [verify-loop.md](verify-loop.md) | После правок кода — до «готово» | Essential |
| `constraint-first.md` | Жёсткие запреты, API/UX/security рамки | Full |
| [lean-prompts-autonomy.md](lean-prompts-autonomy.md) | Короткие промпты + границы автономии (OpenAI) | Essential |
| `agent-loops.md` | Design loops (stop condition + caps) | Full |

---

## Как добавить паттерн

1. Один файл = один паттерн; имя = латинский kebab
2. Сверху `## For agents` (когда / применяй / не делай)
3. Таблицы + чеклист; < ~80 строк
4. Обновить этот индекс
5. Если нужно в продуктах по умолчанию — добавить путь в Essential list в `scripts/bootstrap-into-project.ps1`
