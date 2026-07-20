# Project state

> Living snapshot for agents and humans. Update when phase or priorities change.

## For agents

**When to read:** every session start (via hook summary); before planning slices; with `/setup-project-environment`.

**Apply:** align work to `phase` and `next_checks`; run doctor if stale.

**SSOT:** `docs/STATUS.yaml` is the authoritative machine-readable state (phase, deliverables, blockers, next task). This file is a non-competing projection for harness hooks and quick session context — if they diverge, follow `STATUS.yaml`.

---

## phase

phase-0b-contracts

## milestones

| Milestone | Status | Notes |
|-----------|--------|-------|
| Phase 0a architecture evidence | done | Frozen in baseline commit `c15ef56` |
| Harness bootstrapped (Essential) | done | On-disk Essential; stale local plugin 0.1.0 disabled |
| Phase 0b contracts | in progress | API, RCI policy, persistence, security/ops, test strategy, scenarios, roadmap, AI handoff |
| Implementation / prototype code | pending | Blocked until Phase 0b complete; prepare Python 3.11 before code |

## next_checks

- [x] Atomically open Phase 0b in `docs/STATUS.yaml` and this file
- [x] Run `scripts\project-doctor.ps1` on this machine
- [x] Disable stale `cursor-project-harness` 0.1.0 (Essential sufficient; need 0.5.0 to re-enable)
- [ ] Write Phase 0b contract docs only — no package/API/UI, no router mutations
- [ ] Prepare Python 3.11 before implementation (not required for contracts)

## toolchain_notes

- Doctor advisory: `pwsh` missing; Windows PowerShell 5.1 runs harness hooks — do not install `pwsh` only for exit 0.
- Target runtime for later implementation: Python 3.11 / FastAPI Hub.
- Local plugin renamed to `cursor-project-harness.disabled-0.1.0` under `%USERPROFILE%\.cursor\plugins\local`.
