---
name: maintain-project-docs
description: Обновить living docs и docs-map.json после правки документации или user-facing поверхности; проверить validator. Когда меняли docs/, AGENTS, README, onboarding или просят «обнови docs-map».
---

# maintain-project-docs

## Когда

- Material change в `docs/`, `AGENTS.md`, onboarding, user-facing copy
- Новый doc без записи в `docs/docs-map.json`
- После bootstrap — первичное заполнение map

## Шаги

1. Прочитай `docs/living-documentation.md` и `docs/docs-map-schema.md` (workspace root; в plugin/Essential — product `docs/`).
2. Открой `docs/docs-map.json`. Если файла нет:
   - скопируй из `templates/docs-map.json` когда шаблон есть в продукте/toolkit;
   - иначе создай **минимальный inline map** (version 1, entries только на существующие paths, без broken `../../` links):

```json
{
  "version": 1,
  "entries": [],
  "rules": { "update_on_change": true, "validate_on_commit": false }
}
```

3. **Docs Impact checklist:**
   - [ ] Каждый изменённый doc имеет entry (`path`, `title`, `status`, `owners`)
   - [ ] Новые docs добавлены в `entries`
   - [ ] Deprecated docs → `status: deprecated`
   - [ ] `planned` только пока файл не создан; после seed/bootstrap → `active`
   - [ ] Теги отражают область (`day-0`, `api`, `onboarding`, …)
4. Запусти validator:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\validate-project-docs.ps1
```

5. Запусти расширенный audit (links, unmapped, sync-marker):

```powershell
py -3.11 scripts\project-docs.py audit --project-root .
```

6. Если marker устарел относительно `docs/STATUS.yaml`:

```powershell
py -3.11 scripts\project-docs.py sync-marker --project-root . --write
```

7. Для change/build через `autonomous-task` — приложи **Docs Impact Record**:

```powershell
py -3.11 scripts\project-docs.py impact --project-root . --contract-id TASK --paths path1 path2 --map-entries docs/foo.md --validator-run yes --validator-exit-code 0 --notes "..."
```

(см. `.cursor/skills/autonomous-task/contracts.md` §8)

## Не делай

- Не затирай богатый существующий map без явной просьбы
- Не добавляй entries на несуществующие paths (кроме `status: planned`)
- Не включай secrets в docs
- Не используй `../../docs/` — только workspace-root `docs/...`

## См.

- `docs/project-integrations.md`
- Rule: `.cursor/rules/project-docs-lifecycle.mdc`
