# Project state

> Living snapshot for agents and humans. Update when phase or priorities change.

## For agents

**When to read:** every session start (via hook summary); before planning slices; with `/setup-project-environment`.

**Apply:** align work to `phase` and `next_checks`; run doctor if stale.

**SSOT:** `docs/STATUS.yaml` is the authoritative machine-readable state (phase, deliverables, blockers, next task). This file is a non-competing projection for harness hooks and quick session context — if they diverge, follow `STATUS.yaml`.

---

## phase

phase-0a-complete

## milestones

| Milestone | Status | Notes |
|-----------|--------|-------|
| Phase 0a architecture evidence | done | See `docs/STATUS.yaml` deliverables |
| Harness bootstrapped (Essential) | done | cursor-project-toolkit Essential surface |
| Phase 0b contracts | pending | Open formally in STATUS.yaml + this file, then contracts only |
| Implementation / prototype code | pending | Blocked until Phase 0b complete |

## next_checks

- [ ] Atomically open Phase 0b in `docs/STATUS.yaml` and this file
- [x] Run `scripts\project-doctor.ps1` on this machine
- [ ] Prepare Python 3.11 before implementation (not required for Phase 0b contracts)

## toolchain_notes

- Doctor advisory: `pwsh` missing; Windows PowerShell 5.1 runs harness hooks — do not install `pwsh` only for exit 0.
- Target runtime for later implementation: Python 3.11 / FastAPI Hub.
- Local plugin `cursor-project-harness` was 0.1.0 (need 0.5.0); Essential on-disk harness is sufficient — disable stale plugin if present.
