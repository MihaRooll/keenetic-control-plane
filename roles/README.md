# roles/ — краткие роли для @-mention

> **AI-first.** Роль = узкий brief поведения в текущем чате. Не замена rules/skills.

## For agents

**Когда читать:** пользователь `@roles/…` или просит «будь ревьюером / реализуй / выжми docs».

**Применяй:**
- Прочитай brief роли → держи scope роли до смены роли/чата
- Роль ≠ subagent: тот же контекст чата; для изоляции → [`subagents/`](../subagents/README.md) + [Cursor Subagents](https://cursor.com/docs/subagents)
- `roles/implementer.md` — persona текущего чата; `.cursor/agents/implementer.md` — отдельный Composer subagent автономного workflow
- Процедуры со скриптами → skill, не роль

**Не делай:** раздувать роль в persona-эссе; смешивать implement + harsh review в одном проходе без запроса.

---

## Индекс

| Файл | Роль | Когда | Bootstrap |
|------|------|-------|-----------|
| [implementer.md](implementer.md) | implementer | Сделать изменение по согласованному scope | Essential |
| [reviewer.md](reviewer.md) | reviewer | Проверка diff/PR, без лишних правок | Essential |
| `docs-distiller.md` | docs-distiller | AI-first выжимка в `docs/` | Full |

Имена файлов — латиница. Описания в brief — кратко, по-русски ок.
