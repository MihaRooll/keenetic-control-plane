# plan-then-build

> Паттерн: сначала план, потом код. См. Plan Mode в [`docs/cursor-agent-best-practices.md`](../docs/cursor-agent-best-practices.md).

## For agents

**Когда:** нетривиальная фича; >2–3 файлов; неочевидные trade-offs; пользователь не дал точный diff-plan.

**Применяй:**
1. Research (поиск в репо) → уточняющие вопросы при дырах
2. План: цели, файлы, шаги, риски, out-of-scope
3. Если пользователь просил только plan — жди approval (UI Plan Mode / явный OK)
4. Если пользователь просил change/build/fix: `autonomous-task` ведёт T0/T1 без plan artifact, а T2/T3 — через internal reviewed plan без routine approval; T4 ждёт человека
5. Если мимо — revert/уточнить план, не латать длинной перепиской

**Не делай:** писать код при materially ambiguous scope; путать workspace `.cursor/plans/` artifact с UI Plan Mode; «план» без путей файлов.

---

## Когда можно без плана

| Ситуация | План? |
|----------|-------|
| Однотипная правка 1 файла | Нет |
| Баг с ясным repro + местом | Опционально короткий |
| Новая фича / рефактор / API | Да |
| Неясные требования | Да + вопросы |

Для автономного change/build/fix план T2/T3 согласуется внутренним review pipeline. Approval человека нужен для T4/destructive/external writes или явного запроса «сначала план».

---

## Шаблон плана (минимум)

- **Goal** — 1 предложение
- **Files** — пути create/edit
- **Steps** — упорядоченный список
- **Verify** — команды/чеклист (см. [verify-loop.md](verify-loop.md))
- **Out of scope** — что не трогаем

Сохраняй в `.cursor/plans/` если нужен resume между сессиями.

---

## Чеклист

- [ ] Вопросы заданы (или scope ясен)
- [ ] План с путями файлов
- [ ] Approval получен для UI Plan Mode; T4 использует отдельный Human Gate Packet; иначе internal plan reviewed
- [ ] Реализация = план; отклонения зафиксированы
