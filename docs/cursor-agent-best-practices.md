# Cursor: agent best practices (выжимка)

> **AI-first.** Источник: SRC-005 — [Best practices for coding with agents](https://cursor.com/blog/agent-best-practices).

## For agents

**Когда читать:** любая нетривиальная задача в Cursor; настройка workflow проекта.

**Применяй:**
- Явный запрос «сначала только план» → **Plan Mode** (`Shift+Tab`): research → вопросы → план → approve → код
- T4 change/build/fix → Human Gate Packet в autonomous-task, не UI Plan Mode
- Change/build/fix → `autonomous-task`: T0/T1 без plan artifact; T2/T3 internal reviewed plan → код → verify без routine approval
- Планы сохраняй в `.cursor/plans/` (resume + контекст для следующих агентов)
- Если результат мимо — **revert + уточнить план**, не латать длинной перепиской
- Контекст: агент сам ищет файлы; `@file` только если точно знаешь; не засоряй irrelevant файлами
- Новый чат при смене задачи / путанице агента; тот же чат — при итерации одной фичи
- Прошлую работу подтягивай через `@Past Chats` / `@Branch`, не копипастой всего треда
- **Rules** = короткое always-on; **Skills** = on-demand workflows
- После серии правок — typecheck/tests; для багов с воспроизведением — Debug Mode + детальный repro

**Не делай:** гигантские rules со style guide; пихать весь репо в контекст; продолжать «мёртвый» длинный чат.

---

## Harness = 3 части

| Часть | Что |
|-------|-----|
| Instructions | System prompt + rules |
| Tools | Edit, search, terminal, … |
| Model | Выбор модели под задачу |

Cursor тюнит harness под каждую frontier-модель — промпты «как для Claude» не обязаны одинаково работать на всех.

---

## Plan Mode

1. Research codebase  
2. Clarifying questions  
3. План с путями файлов  
4. Ждать approval  

Plans = editable Markdown. Save to workspace → `.cursor/plans/`.

Это UI Plan Mode. Workspace `.cursor/plans/` также используется как internal artifact автономного T2/T3 workflow, но не означает human approval. Быстрые правки — без plan; change/build/fix T0–T3 следует `autonomous-task`.

---

## Context hygiene

| Ситуация | Действие |
|----------|----------|
| Знаешь файл | `@` его |
| Не знаешь | Опиши задачу — агент найдёт |
| Смена фичи / агент тупит | New chat |
| Нужен прошлый контекст | `@Past Chats` |
| Ориентация по ветке | `@Branch` |

Длинные треды → noise после summarization → падает фокус.

---

## Rules vs Skills

| | Rules | Skills |
|--|-------|--------|
| Когда в контексте | Часто / always / по globs | Когда релевантны или `/skill` |
| Содержимое | Команды проекта, паттерны, ссылки на canonical files | Workflows, scripts, domain playbooks |
| Антипаттерн | Весь style guide, редкие edge cases | Дублировать always-on в skill |

Правило: добавь rule только после **повторяющейся** ошибки агента. Ссылайся на файлы `@…`, не копируй код.

Пример полезного rule-содержимого: `npm run typecheck`, куда класть API routes, pointer на `components/Button.tsx`.

---

## Паттерны workflow

| Паттерн | Суть |
|---------|------|
| TDD | Сначала тесты по I/O; явно сказать «TDD — без моков несуществующего» |
| Grind loop | Hook на `stop` → `followup_message` пока нет DONE / зелёных тестов |
| Parallel | Worktrees / несколько моделей; cloud agents для делегирования |
| Review | Во время генерации + Agent review + Bugbot на PR |
| Debug Mode | Подробный repro → инструментация → гипотезы |

---

## Чеклист сессии

- [ ] Нужен Plan Mode?  
- [ ] Контекст минимален и релевантен?  
- [ ] Rules не раздуты? Нужный skill есть?  
- [ ] После кода: typecheck / tests  
- [ ] Повторяющаяся ошибка → обновить rule/skill  

---

## Источник

https://cursor.com/blog/agent-best-practices · SRC-005
