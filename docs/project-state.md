# Project state

> Living snapshot for agents and humans. Update when phase or priorities change.

## For agents

**When to read:** every session start (via hook summary); before planning slices; with `/setup-project-environment`.

**Apply:** align work to `phase` and `next_checks`; run doctor if stale.

**SSOT:** `docs/STATUS.yaml` is the authoritative machine-readable state (phase, deliverables, blockers, next task). This file is a non-competing projection for harness hooks and quick session context — if they diverge, follow `STATUS.yaml`.

---

## phase

phase-1-slice-2-pending

## milestones

| Milestone | Status | Notes |
|-----------|--------|-------|
| Phase 0a architecture evidence | done | Frozen in baseline commit `c15ef56` |
| Harness bootstrapped (Essential) | done | On-disk Essential; stale local plugin 0.1.0 disabled |
| Phase 0b contracts | done | Wave 7 closeout complete; eight STATUS deliverable IDs + supporting artifacts ([`contracts/`](contracts/)) |
| Phase 1 / SLICE-1 (portable core + FakeRouterAdapter) | done | `router_control` package, fake-only tests, stdlib-only runtime (2026-07-21) |
| Phase 1 / SLICE-2 (persistence / jobs) | pending | Requires separate human approval; `code_may_start=false` until gate expanded |

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
- [x] Obtain explicit human approval for Phase 1 / SLICE-1 (`implementation_transition_gate`, 2026-07-21)
- [x] Implement SLICE-1: portable core, application ports, FakeRouterAdapter, fake-only tests (no FastAPI/SQLite/live/hardware)
- [ ] Obtain separate human approval for SLICE-2 persistence before any SQLite/jobs code
- [ ] Prepare Python 3.11 before SLICE-2 code (Windows `py.exe -3.11` verified 2026-07-20)

## toolchain_notes

- Doctor advisory: `pwsh` missing; Windows PowerShell 5.1 runs harness hooks — do not install `pwsh` only for exit 0.
- Target runtime for later implementation: Python 3.11 / FastAPI Hub.
- Windows Python 3.11 verified (2026-07-20): `py.exe -3.11 --version` → Python 3.11.9; executable under `%LOCALAPPDATA%\Programs\Python\Python311\`.
- WSL: `python3` is 3.12.3; `python3.11` absent — choose Windows Python 3.11 for implementation or install WSL 3.11 only after separate approval.
- Local plugin renamed to `cursor-project-harness.disabled-0.1.0` under `%USERPROFILE%\.cursor\plugins\local`.
- SLICE-1 verify (2026-07-21): `pytest`, `ruff`, `mypy`, `compileall` pass on `router_control` + `tests`.
