# lean-prompts-autonomy

> Паттерн из OpenAI GPT-5.6 guidance (SRC-012). Для Cursor-агентов и product prompts.

## For agents

**Когда:** раздутые rules/skills; агент слишком часто спрашивает; или наоборот ломает scope; миграция на более сильную модель.

**Применяй:**
1. Одна инструкция — один раз (в AGENTS или одном rule)
2. Режь повтор examples/tools; оставляй то, что чинит измеренный gap
3. Явная политика autonomy (шаблон ниже)
4. Goal + hard constraints + success criteria; не микрошаги без нужды
5. «Be concise» — только если реально нужно; иначе модель и так короче

**Не делай:** копипастить «ask first / do not mutate» в каждый файл; «think step by step» на reasoning-моделях.

---

## Autonomy template (вставь в AGENTS / task)

```
For answer/explain/review/diagnose/plan: inspect and report. Do not implement unless asked.

For change/build/fix: do in-scope local edits + non-destructive validation without asking.

Require confirmation for: external writes, destructive actions, purchases, material scope expansion.
```

Safe local: read, logs, in-scope edit, tests.

Для change/build/fix применяй [`autonomous-task`](../.cursor/skills/autonomous-task/SKILL.md): T0/T1 идут без plan artifact, T2/T3 используют internal reviewed plan без routine approval; T4/destructive/external writes human-gated. Это не UI Plan Mode.

---

## Lean checklist

- [ ] Нет дубля одного правила в 3 местах
- [ ] Tools/skills в контексте только нужные
- [ ] Success criteria ясны
- [ ] Approval только на внешнее/разрушительное

---

## См. также

- OpenAI GPT-5.6 guidance: `docs/openai-gpt56-model-guidance.md` (toolkit only)
- [plan-then-build.md](plan-then-build.md) · `constraint-first.md` (Full bootstrap only)
