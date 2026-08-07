# Human gate — staff/guest networks on the main menu (2026-08-05)

> **AI-first.** Two `principal-arbiter` attempts are spent. The process now requires a human decision before this package moves. Nothing here is a request to bypass a gate; it is the packet the gate asks for.

## For agents

**When to read:** before touching `main-menu-staff-guest-networks`, `standing_network_preferences`, or migration 16.

| Fact | State |
|---|---|
| Arbiter attempts used | **2 of 2** — no third attempt is permitted |
| Verdict | reject, twice; the **substance was approved**, the process claim was not |
| Gate | **CLOSED — resumed, shipped, and live-confirmed** (§M-48, §M-50, 2026-08-06). Historical narrative below (attempts, rejections, resume order) kept for record; do not re-open |
| Schema code (current) | `CURRENT_USER_VERSION = 16`; `_MIGRATION_16` adds nullable `staff_ap_id`/`guest_ap_id` to `standing_network_preferences` — the exact shape the arbiter approved |
| Operator live database (current) | `user_version = 16` — migration applied live 2026-08-06 morning (§M-50), auto-backup created first, no data loss, Main-witnessed via `browser_navigate` reload + direct DB read |
| Backend remnants | none outside the approved shape in `store.py`, `standing_network_preferences.py`, `standing_network_preferences_routes.py` |
| Frontend | main-menu widget (`overview-simple-networks.js`) reads/writes the persisted preference; `#/staff-wifi`/`#/guest-wifi` independently confirmed **still session-only**, untouched — Main verified live, not just by test |

## What the operator asked for

R-3 … R-6 in [`OPERATOR_SIMPLE_MAIN_MENU_SPEC.md`](OPERATOR_SIMPLE_MAIN_MENU_SPEC.md): from the main menu alone, with no trip into settings, the operator assigns which access point is the staff network and which is the guest one, sees and changes the staff SSID and password and the guest name, with staff on by default and guest off, and the same values on every project so promo staff do not reconnect repeatedly.

## Why it is blocked

The blocking issue is **not** the design. Across two reviews the arbiter approved the substance:

- `standing_network_preferences` is the right home for the role assignment; a separate table is not justified.
- Two nullable columns via a **new** migration 16 is the right shape; `NULL` sufficiently means "unassigned"; no tri-state needed.
- Lost test coverage may be remediated forward with stronger assertions, provided adversarial review confirms nothing was weakened.

What was rejected, in order:

1. **Attempt 1 — approval came after the writes.** The L1 orchestrator classified the task T3 itself, called its own arbiter (which, spawned from a Sonnet parent, inherits a non-Sol model), recorded its own approval and started implementing. Migration 16 had already landed when Main noticed. **Root cause was Main's omission**: the standing "for T3 prepare a plan only, Main assembles the Principal Packet" instruction was absent from that particular task prompt.
2. **Attempt 1 substance — the identifier validator was wrong.** It used `^WifiMaster[01]/AccessPoint[3-6]$`, but `3-6` is an *authorization window* for one lab class (`WIFI_AP_INDEX_DEFAULT_MIN = 3` in `allowlist.py:116`, switched at runtime by `is_expendable_lab_class()`), not the domain of valid identifiers (`WIFI_AP_INDEX_MAX = 6`, `allowlist.py:115`). Encoding it in a settings column conflates "what exists" with "what we are allowed to write". Corrected design: validate the canonical shape `^WifiMaster[01]/AccessPoint[0-6]$` at the persistence boundary and leave device eligibility to `validate_wifi_ap_id()` (`allowlist.py:362`), which every live write path already calls.
3. **Attempt 1 — migration tests were missing.** Now specified as five concrete cases rather than a promise: upgrade `v15 → v16` on a **populated** row, fresh database, singleton self-heal with the new columns, reopen-and-fingerprint after upgrade, and fail-closed on out-of-band version drift without mutating the file.
4. **Attempt 2 — the packet claimed a clean pre-write baseline that was not true.** Schema and backend were genuinely reverted, but four front-end files kept the rejected decision's code. The arbiter caught the discrepancy from the plan file itself. Fair.

## The remaining discrepancy, precisely

**Historical snapshot (Attempt 2, packet-write time).** Reverted and verified clean at that point: `migrations.py` (no `_MIGRATION_16`, version 15), `store.py`, `standing_network_preferences.py`, `standing_network_preferences_routes.py`, and the operator's live database. Four front-end files **still carried** the rejected decision's code when the arbiter caught the discrepancy:

- `router_control_host/web/hub/features/overview-simple-networks.js`
- `router_control_host/web/hub/features/staff-wifi-model.js`
- `router_control_host/web/hub/features/guest-wifi-model.js`
- `router_control_host/web/hub/features/wifi-ap-model.js`

That code was **inert** even then: the GET no longer returned the fields so hydration never fired, and a PUT carrying a role got 422 which the existing non-blocking `catch` swallowed. Inert was not the same as harmless — it was dead weight that read as a working feature. That is why Attempt 2 was rejected.

**Current state (per §M-47, 2026-08-06).** The four files above were cleaned afterward; the live tree no longer carries the rejected decision's code. **Operator resume order step (1) — clean first — is done.** Schema/backend baseline above remains unchanged.

**Resume order step (2) — isolation — is now Main-confirmed, not merely landed.** Main personally ran `py -3.11 -m pytest tests/test_db_path_isolation.py tests/test_migrations.py tests/test_migrations_crash_atomic.py tests/test_persistence.py tests/test_host_authority.py tests/test_hub_staff_wifi.py -q` → **180 passed, exit 0**, then re-checked `data/router_control.sqlite3` by read-only connection and confirmed `PRAGMA user_version` stayed `15` with its original six columns after the run — the exact property the whole package exists to guarantee. **Resume order step (3) — resuming the T3 substance itself — may now proceed.**

**Resume order step (3) — done in code, per §M-48 (2026-08-06 night).** Migration 16, the canonical-shape validator, all five named migration tests, the API tests, and the main-menu role-assignment UI landed and passed a full-suite verifier run (4942 passed, 2 skipped, exit 0). `#/staff-wifi`/`#/guest-wifi` confirmed unmodified — still session-only, exactly as this gate required. Main personally read the validator and migration code (matches the design below verbatim) and separately confirmed on an isolated fake instance that an AP-role assignment made through the new widget survives a page reload. **Honest gap: this is `КОД ГОТОВ`, not `ЖИВЬЁМ`.** The operator's live host (port 8787) is still running the pre-migration code in memory; its on-disk database is still read-only-confirmed at `PRAGMA user_version = 15`. Restarting that host will apply migration 16 to the operator's real database automatically — the mechanism is now tested (auto-backup, fingerprint check, fail-closed on drift), but Main deliberately did not restart the live host unattended overnight, given this is the third live-database incident in this project's history. That restart + live confirmation is the one remaining step, for the operator or a future session to do deliberately, not silently.

## A prerequisite the arbiter made binding

Migration 16 must not be exercised until **test-database isolation** is **Main-proven** (not merely landed). **Historical root cause (§M-45):** a test run silently migrated the operator's live database because `ROUTER_CONTROL_DB_PATH` was set in two test harnesses and read nowhere in production code, while the default path was hardcoded in two places. Main repaired the drift with a fingerprint-verified surgical downgrade — no data lost. **Mitigation, confirmed by Main personally (§M-47):** `resolve_db_path()` refuses the production default while a test session is active, detected two ways — `PYTEST_CURRENT_TEST` per-test, and `ROUTER_CONTROL_TEST_SESSION` set at `tests/conftest.py` import time, which closes the exact fixture-scope gap Main raised (collection-time code, session/module-scoped fixtures). 180 targeted tests pass and the operator's database was read-only-verified unchanged (`user_version = 15`) immediately after. **This gate is satisfied.** Host-level tests and migration 16 may now proceed.

## Operator decision — granted 2026-08-05

The operator was asked and answered directly. **Approved, in this order:**

1. **Clean first.** Remove the rejected decision's inert code from the four front-end files so the tree genuinely matches a pre-write baseline. This is also exactly the reconciliation the arbiter made binding on resumption.
2. **Isolation before schema.** The operator agreed isolation must be **Main-proven** **before** anything exercises migration 16 (the package has since landed + adversarial-passed; the remaining gate is Main's personal confirm, not re-implementation). His reasoning, and it is the right one: this was the third database incident.
3. **Then resume** on the substance the arbiter approved across both reviews — `standing_network_preferences` as the home, a new migration 16 with two nullable columns, `NULL` meaning unassigned, the canonical-shape validator `^WifiMaster[01]/AccessPoint[0-6]$` with device eligibility left to `validate_wifi_ap_id()`, the five named migration tests, forward-remediated coverage for the test that was weakened, and an explicit statement in the final report that the dedicated Wi-Fi screens stay session-only.

This human approval is what unblocks the package; the two arbiter attempts stay spent, and **no third arbiter attempt may be made**. If the design changes materially from what is listed above, that is a new decision and needs the operator again, not a fresh arbiter round.

## Related

- Decision log: `.cursor/plans/main-decisions-local-hub.md` §M-44 (the process failure), §M-45 (the database drift), §M-46 (arbiter exhausted, operator resume order, FE cleanup)
- Plan: `.cursor/plans/main-menu-staff-guest-networks.plan.md` (cycle 2, `sol_approved: null`)
- Spec and tracker: [`OPERATOR_SIMPLE_MAIN_MENU_SPEC.md`](OPERATOR_SIMPLE_MAIN_MENU_SPEC.md) R-3 … R-6
