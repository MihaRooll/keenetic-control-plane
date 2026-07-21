# Project state

> Living snapshot for agents and humans. Update when phase or priorities change.

## For agents

**When to read:** every session start (via hook summary); before planning slices; with `/setup-project-environment`.

**Apply:** align work to `phase` and `next_checks`; run doctor if stale.

**SSOT:** `docs/STATUS.yaml` is the authoritative machine-readable state (phase, deliverables, blockers, next task). This file is a non-competing projection for harness hooks and quick session context — if they diverge, follow `STATUS.yaml`.

---

## phase

phase-1-offline-mega-complete; next slice-4-gate-a

## milestones

| Milestone | Status | Notes |
|-----------|--------|-------|
| Phase 0a architecture evidence | done | Frozen in baseline commit `c15ef56` |
| Harness bootstrapped (Essential) | done | On-disk Essential; stale local plugin 0.1.0 disabled |
| Phase 0b contracts | done | Wave 7 closeout complete; eight STATUS deliverable IDs + supporting artifacts ([`contracts/`](contracts/)) |
| Phase 1 / SLICE-1 (portable core + FakeRouterAdapter) | done | `router_control` package, fake-only tests, stdlib-only runtime (2026-07-21) |
| Phase 1 offline mega (SLICE-2/3/5/8) | done | Persistence, FastAPI host, vault, TrafficDiscovery proposals-only; hardware A–D closed (2026-07-21) |
| Phase 1 / SLICE-4 (Gate A read-only) | pending | Requires separate hardware Gate A open |

## next_checks

- [x] Atomically open Phase 0b in `docs/STATUS.yaml` and this file
- [x] Run `scripts\project-doctor.ps1` on this machine
- [x] Disable stale `cursor-project-harness` 0.1.0 (Essential sufficient; need 0.5.0 to re-enable)
- [x] Write Phase 0b Wave 1–7 contracts and closeout
- [x] Obtain explicit human approval for Phase 1 / SLICE-1 (`implementation_transition_gate`, 2026-07-21)
- [x] Implement SLICE-1: portable core, FakeRouterAdapter, fake-only tests
- [x] Overnight autonomy authorized offline mega (SLICE-2/3/5/8); hardware A–D closed
- [x] Implement offline mega: persistence, host, vault, traffic proposals
- [ ] Obtain separate Gate A open before SLICE-4 live read-only adapter

## toolchain_notes

- Doctor advisory: `pwsh` missing; Windows PowerShell 5.1 runs harness hooks — do not install `pwsh` only for exit 0.
- Target runtime: Python 3.11; optional host deps via `pip install -e ".[dev,host]"`.
- Windows Python 3.11 verified (2026-07-20): `py.exe -3.11 --version` → Python 3.11.9.
- Dev host: `uvicorn router_control_host.app:app --reload` (gates closed; set `HUB_ADMIN_PASSWORD` for Ready).
- Offline mega verify (2026-07-21): `pytest`, `ruff`, `mypy`, docs-validate on `router_control` + `router_control_host` + `tests`.
