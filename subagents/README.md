# subagents/ — briefs для делегирования

> **AI-first.** Официально: [Cursor Subagents](https://cursor.com/docs/subagents). Карта plugins: `docs/cursor-team-kit.md`, `docs/cursor-official-plugins.md` (toolkit only).

## For agents

**Когда читать:** нужен отдельный контекст; параллель; независимая верификация; пользователь просит subagent / Task.

**Применяй:**
- Built-in (авто): **Explore**, **Bash**, **Browser** — не дублируй их плагинами
- Custom: файлы в `.cursor/agents/*.md` (YAML frontmatter + prompt) — см. official docs
- Essential уже ставит executable agents: `operational-orchestrator`, `implementer`, `adversarial-reviewer`, `verifier`, `principal-arbiter`
- Parent **передаёт весь нужный контекст** в prompt: у subagent нет истории чата
- Простая one-shot процедура → **skill**, не subagent

**Не делай:** выдумывать несуществующие plugin API; плодить subagent для «changelog/format»; путать с [`roles/`](../roles/README.md) (роль = тот же чат).

---

## Briefs в этой папке

| Файл | Назначение | Bootstrap |
|------|------------|-----------|
| [verifier.md](verifier.md) | Проверка «сделано ли» + тесты | Essential |
| `explorer.md` | Исследование кодовой базы → краткий отчёт | Full |
| `parallel-worker.md` | Параллельный кусок работы | Full |

Executable source: `.cursor/agents/`; файлы здесь — briefs/объяснения. Создание вручную: `/create-subagent` или по [доке](https://cursor.com/docs/subagents).

---

## Subagent vs Skill vs Role

| Нужно | Что |
|-------|-----|
| Изоляция контекста / parallel | Subagent |
| Повторяемый workflow + scripts | Skill |
| Сменить тон в том же чате | Role (`roles/`) |
