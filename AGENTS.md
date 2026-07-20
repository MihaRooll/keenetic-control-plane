# Router Control: инструкции для агентов

## Cold start

Перед любой работой прочитайте по порядку:

1. `README.md`
2. `docs/STATUS.yaml`
3. `docs/CANONICAL.md`
4. `docs/contracts/README.md`
5. `docs/contracts/AI_HANDOFF.md` — cold-start extensions, SSOT, task template
6. Task-specific contracts as needed
7. `docs/project-state.md` (non-competing harness projection)

## Обязательные правила

- Соблюдайте текущую phase из `docs/STATUS.yaml`; не начинайте deliverables следующей phase заранее.
- Этот репозиторий — canonical project/prototype home. `ScanCursorIP` — только legacy behavioral evidence.
- Не утверждайте, что implementation, package, API или UI существуют, пока они фактически не созданы.
- Не выполняйте writes на реальном роутере без явно открытого hardware mutation gate для точного identity/firmware/capability tuple.
- Не добавляйте passwords, private keys, preshared keys, raw sessions, startup-config, credentials или другие secrets в код, документацию, fixtures, logs и artifacts.
- Unknown identity, firmware, capability или profile field означает fail-closed для writes.
- Не создавайте commit и не выполняйте push, если пользователь явно этого не запросил.
- Не изменяйте `.git` internals.

<!-- cursor-project-toolkit-harness -->

## Toolkit harness (papercuts / patterns)

Bootstrapped from **cursor-project-toolkit** (product Essential). Project rules above still win.

- Product harness rules: `.cursor/rules/product-core.mdc` (with `project-docs-lifecycle.mdc` for doc changes).
- Living docs index: `docs/docs-map.json`; schema in `docs/docs-map-schema.md`; update via `/maintain-project-docs`.
- Session projection: `docs/project-state.md` (non-competing with `docs/STATUS.yaml` SSOT).
- Failed shells may auto-log to `.papercuts.jsonl` via `.cursor/hooks`; details in `docs/papercuts.md`.
- Manual: `scripts/papercuts.ps1 add "<friction + fix>" -Tag tooling` (Windows: `$env:HOME = $env:USERPROFILE` if needed).
- Review: `/review-papercuts` or `papercuts list --format md`.
- Patterns: `prompting/`, `roles/`, `subagents/` when relevant.
- Change/build/fix: apply `.cursor/skills/autonomous-task` automatically; T0–T3 proceed autonomously, T4/destructive/external writes stop for human approval.
- Optional: `/add-plugin cursor-team-kit`; local `cursor-project-harness` installs via toolkit `scripts/install-harness-plugin.ps1`, not `/add-plugin`.

<!-- /cursor-project-toolkit-harness -->
