---
name: review-papercuts
description: Разобрать backlog papercuts (жалобы агентов) и предложить/внести фиксы в docs, rules, tooling. Когда просят papercuts, жалобы агента, «что ломается в workflow».
---

# Разбор papercuts (review-papercuts)

## Когда использовать

- «покажи papercuts», «что бесит агента», triage friction
- После серии сессий — починить повторяющиеся cuts

## Шаги

1. Сначала попробуй реальный CLI: `papercuts list --format md`.
2. Если нет в PATH — shim репо:
   `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/papercuts.ps1 list -Format md`
3. Не выдумывай лог. Если файла нет / пусто — так и скажи.
3. Сгруппируй по `--tag` / повторяющемуся тексту.
4. Для каждого top cut предложи fix:
   - docs → править `docs/` / `AGENTS.md`
   - tooling → script, `.gitignore`, cwd note
   - rule/skill → короткий rule или skill
5. После фикса: `papercuts resolve <id>` (можно несколько).
6. Не коммить секреты из evidence.

## См. также

- `docs/papercuts.md`
- `AGENTS.md` → секция Papercuts
