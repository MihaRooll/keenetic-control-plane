# Cursor primitives: Rules, Skills, AGENTS.md (выжимка)

> **AI-first.** Источники: SRC-006 — [Rules](https://cursor.com/docs/rules) · [Skills](https://cursor.com/docs/skills).

## For agents

**Когда читать:** создание/правка `.cursor/rules`, skills, `AGENTS.md`; решение «rule или skill».

**Применяй:**
- Повторяющийся стандарт / запрет → **Rule** (коротко, actionable)
- Процедура «как сделать X» со шагами/скриптами → **Skill** (`SKILL.md`)
- Простые инструкции без frontmatter → **AGENTS.md** (root + nested)
- Prefer pointer на canonical file, не копипаст
- Rule `< 500` lines; большие — дробить
- Skill: сильный `description` (для discovery); детали в `references/` (progressive load)
- **В этом репо `description` — на русском** (меню `/`); `name` — латиница. См. [skills-russian-descriptions.md](skills-russian-descriptions.md)
- `alwaysApply: true` только для действительно глобального

**Не делай:** `.md` в `.cursor/rules` без `.mdc` (игнорируется); style guide целиком; дублировать linter/common CLI knowledge; английский `description` у project skills toolkit.

---

## Rules — типы и apply

| Тип | Когда |
|-----|--------|
| Project | `.cursor/rules/*.mdc` в репо |
| User | Customize → глобально (Agent chat, не Cmd/Ctrl+K) |
| Team | Dashboard (Team/Enterprise); precedence выше |
| AGENTS.md | Plain markdown alternative |

### Frontmatter → поведение

| alwaysApply | description | globs | Результат |
|-------------|-------------|-------|-----------|
| true | — | — | Всегда |
| false | — | заданы | Auto при файлах в контексте |
| false | задан | нет | Agent тянет по релевантности |
| false | нет | нет | Только `@rule` вручную |

Precedence при конфликте: **Team → Project → User**.

Создание: `/create-rule` или Customize → Rules. Импорт с GitHub → `.cursor/rules/imported/`.

Nested `AGENTS.md` в подпапках: более специфичные инструкции побеждают при работе в той зоне.

---

## Skills — формат

Пути discovery:

| Path | Scope |
|------|--------|
| `.cursor/skills/`, `.agents/skills/` | Project |
| `~/.cursor/skills/`, `~/.agents/skills/` | User |
| `.claude/skills/`, `.codex/skills/` (+ home) | Compat |

Структура: `skill-name/SKILL.md` (+ optional `scripts/`, `references/`, `assets/`).  
`name` в frontmatter = имя папки. Nested folder skills в monorepo авто-скоупятся к своей директории.

| Field | Назначение | Язык в этом репо |
|-------|------------|------------------|
| `name` | id (= имя папки) | латиница kebab-case |
| `description` | когда применять; текст в меню `/` | **русский** |
| `paths` | glob-скоуп к файлам | — |
| `disable-model-invocation` | только через `/skill-name` | — |

Миграция: `/migrate-to-skills` (dynamic rules без globs + slash commands → skills).  
Always-on / glob rules **не** мигрируются автоматически.

Built-in skills (фрагмент полезных): `/create-rule`, `/create-skill`, `/create-subagent`, `/create-hook`, `/babysit`, `/split-to-prs`, `/review`, `/loop`, `/migrate-to-skills`.

Стандарт: [agentskills.io](https://agentskills.io).

---

## Decision table

| Нужно | Куда |
|-------|------|
| «Всегда typecheck после правок» | Rule `alwaysApply` или частый glob |
| «Как деплоить staging» | Skill + scripts |
| «В frontend/ свои конвенции» | Nested AGENTS.md или rule с globs |
| «Редкая ручная процедура» | Skill с `disable-model-invocation: true` |
| Упаковать для команды | Plugin (`create-plugin`) |

---

## Источник

https://cursor.com/docs/rules · https://cursor.com/docs/skills · SRC-006
