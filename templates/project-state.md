# Project state

> Living snapshot for agents and humans. Update when phase or priorities change.

## For agents

**When to read:** every session start (via hook summary); before planning slices; with `/setup-project-environment`.

**Apply:** align work to `phase` and `next_checks`; run doctor if stale.

**SSOT:** `docs/STATUS.yaml` is the authoritative machine-readable state (phase, deliverables, blockers, next task). This file is a non-competing projection for harness hooks and quick session context — if they diverge, follow `STATUS.yaml`.

<!-- project-docs-sync: phase=PLACEHOLDER updated=PLACEHOLDER -->

---

## phase

Describe current phase in human-readable form.

## milestones

| Milestone | Status | Notes |
|-----------|--------|-------|
| Bootstrap | pending | Seed from templates |

## next_checks

- [ ] Align `docs/STATUS.yaml` and this file
- [ ] Run `scripts\project-doctor.ps1`
- [ ] Run `scripts\validate-project-docs.ps1`

## toolchain_notes

- Target runtime: Python 3.11
- Validate docs: `scripts\validate-project-docs.ps1` and `scripts\project-docs.py audit`
