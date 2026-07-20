# Project state

> Living snapshot for agents and humans. Update when phase or priorities change.

## For agents

**When to read:** every session start (via hook summary); before planning slices; with `/setup-project-environment`.

**Apply:** align work to `phase` and `next_checks`; run doctor if stale.

**SSOT:** `docs/STATUS.yaml` is the authoritative machine-readable state (phase, deliverables, blockers, next task). This file is a non-competing projection for harness hooks and quick session context — if they diverge, follow `STATUS.yaml`.

---

## phase

phase-0b-complete

## milestones

| Milestone | Status | Notes |
|-----------|--------|-------|
| Phase 0a architecture evidence | done | Frozen in baseline commit `c15ef56` |
| Harness bootstrapped (Essential) | done | On-disk Essential; stale local plugin 0.1.0 disabled |
| Phase 0b contracts | done | Wave 7 closeout complete; eight STATUS deliverable IDs + supporting artifacts ([`contracts/`](contracts/)) |
| Implementation / prototype code | blocked | Pending `implementation_transition_gate.human_approved=true` and `code_may_start=true` |

## next_checks

- [x] Atomically open Phase 0b in `docs/STATUS.yaml` and this file
- [x] Run `scripts\project-doctor.ps1` on this machine
- [x] Disable stale `cursor-project-harness` 0.1.0 (Essential sufficient; need 0.5.0 to re-enable)
- [x] Write Phase 0b Wave 1 contracts (RCI policy, hardware gates, security/ops) — no package/API/UI, no router mutations
- [x] Write Phase 0b Wave 2 persistence contract — no package/API/UI, no router mutations
- [x] Write Phase 0b Wave 3 HTTP/API contract — no package/API/UI/OpenAPI, no router mutations
- [x] Write Phase 0b Wave 4 test strategy contract — no package/API/UI, no router mutations, no hardware tests
- [x] Write Phase 0b Wave 5 scenarios contract — no package/API/UI, no router mutations, no hardware tests
- [x] Write Phase 0b Wave 6 contract docs (roadmap, AI handoff)
- [x] Wave 7 cross-document review/closeout (Phase 0b exit)
- [ ] Obtain explicit human approval for Phase 1 / SLICE-1 (`implementation_transition_gate`)
- [ ] Prepare Python 3.11 before implementation (blocked until human gate open)

## toolchain_notes

- Doctor advisory: `pwsh` missing; Windows PowerShell 5.1 runs harness hooks — do not install `pwsh` only for exit 0.
- Target runtime for later implementation: Python 3.11 / FastAPI Hub.
- Local plugin renamed to `cursor-project-harness.disabled-0.1.0` under `%USERPROFILE%\.cursor\plugins\local`.
