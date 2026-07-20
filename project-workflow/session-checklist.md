# Session checklist (DoD)

> AI-first. Use at end of a toolkit or product session.

## Before coding

- [ ] Change/build/fix? `autonomous-task`: T0–T3 internal plan as needed; T4 Human Gate; UI Plan Mode only for plan-only
- [ ] Read `AGENTS.md` + relevant `docs/` (not whole archive)
- [ ] Right product skill? (`autonomous-task`, `review-papercuts`)

## During

- [ ] Prefer search over stuffing `@` files
- [ ] New chat if task switched or agent confused
- [ ] After edits: sanity-check links / index tables
- [ ] Hit friction? `papercuts add "…" --tag …` (if CLI installed) — then continue

## Before done

- [ ] If this repo has `SOURCES.md` and new external material → SRC + docs + index
- [ ] If process repeated twice → rule or skill (compound)
- [ ] New/edited skill → `description` на русском (`docs/skills-russian-descriptions.md`)
- [ ] If harness validator scripts exist and harness/.ps1 changed → run parse + validator + smoke
- [ ] If editing toolkit bootstrap → Essential still product-only
- [ ] No secrets staged
- [ ] Commit/push/PR only if user asked; use this product's own ship workflow

## Optional plugins

- [ ] `cursor-team-kit` for CI/PR/deslop
- [ ] `continual-learning` for AGENTS.md memory updates
