# Engineering lessons — lab methodology and judgement

> **Transferable process SSOT.** Methodological rules distilled from the long **2026-07-31** real-router lab session and the **2026-08-01** offline reliability substrate session. **Not** a device-fact catalogue, capability registry, or gate-status document.

## For agents

| Topic | Rule |
|---|---|
| When to read | Before designing read paths, status vocabularies, tests, or live observe/verify flows; when code "should work" but live behaviour surprises; after cold-start handoff when you need **why** a trap exists, not **what** the current tuple is |
| Scope | Twenty-four transferable judgement rules (L-1..L-24), five agent-delegation lessons (D-1..D-5), compact practical playbook, cross-refs to operator/handoff/policy docs |
| What this is **NOT** | Device-fact SSOT (counts, digests, host keys, evidence paths, capability claims); not a substitute for [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md) §2 assumption traps or [`STATUS.yaml`](STATUS.yaml) |
| Living SSOT for policy | Lab class, expendable envelope, gates, `next_task`, blockers → [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) + [`STATUS.yaml`](STATUS.yaml) only |
| Session narrative | Device-specific methods, evidence filenames, end-state tables → [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md); this doc explains **process**, handoff records **facts** |

---

## Transferable rules

### L-1. Offline-built read paths are hypotheses until they parse real device output once

**Rule:** Treat every offline parser, field mapper, and status classifier as unproven until exercised against at least one sanitized live capture from the target device class.

**Why it paid off:** Multiple read paths looked correct in unit tests but failed on first live wire — tabular site-survey vs empty-200 RCI JSON, observed-state without live-session wiring, tunnel-health reading own pubkey instead of peer array, AP `connected:true` while link down, open Wi-Fi classified as unrecognized, SSH component lookup using wrong field expectation.

**Anti-pattern:** Shipping read endpoints or status copy from fixture-only tests and calling them "device-verified."

**Cross-ref:** Assumption traps and read-path fixes — [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md) §2; operator discovery runbooks — [`OPERATOR_WIFI_DISCOVERY.md`](OPERATOR_WIFI_DISCOVERY.md), [`OPERATOR_AWG_DISCOVERY.md`](OPERATOR_AWG_DISCOVERY.md).

---

### L-2. Fail-closed: missing evidence → unknown; weak signals must not sum to success

**Rule:** When required evidence is absent or ambiguous, return `unknown` / `cannot-determine` — never infer success. Do not aggregate weak partial signals into a positive claim.

**Why it paid off:** Tunnel-health logic initially treated partial peer fields as healthy; only strict invariant checks matched operator-visible dead vs working tunnels.

**Anti-pattern:** "We have some bytes / some field set → probably working."

**Cross-ref:** Tunnel status honesty split — [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md) §1 (WireGuard row); [`OPERATOR_AWG_APPLY.md`](OPERATOR_AWG_APPLY.md).

---

### L-3. Device fields can lie if read literally — observe FAILING state before trusting a field

**Rule:** Before treating a vendor field as a signal, capture both working and broken states; trust only fields whose values **differ** meaningfully between those states. When signals conflict, return **unknown** — never pick the optimistic one.

**Why it paid off:** WireGuard `status: up` on a dead tunnel; monotonic `txbytes` into void (`peer_txbytes_alone_not_evidence`); station `auth-type: none` while associated (**reverse trap** — `none` is **not** proof of open or failed WPA; Keenetic keeps `auth-type none` on working WPA2 uplink — use `encryption`, `link`, `connected`, `state`, `ssid`); AP `connected: true` with `link: down` (`connected_with_link_down`).

**Detection signal:** Negative tests where most fields look healthy but one deceptive field contradicts — e.g. `tests/test_verdict_explanation.py::test_uplink_deceptive_connected_with_link_down_in_explanation`, `tests/test_wifi_apply_service.py::test_apply_admin_up_link_down_verify_mismatch_no_rollback`; enum-coded rejections in `router_control_host/apply_response_models.py` (`connected_with_link_down`, `state_up_with_link_down`, `txbytes_without_rxbytes`, `peer_txbytes_alone_not_evidence`).

**Anti-pattern:** Using a single field (`auth-type`, `connected`, interface admin state, tx-only counters) as proof of security, association, on-air, or egress.

**Cross-ref:** Station and AP trap tables — [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md) §2; [`OPERATOR_WIFI_DISCOVERY.md`](OPERATOR_WIFI_DISCOVERY.md) auth-type trap row; honest observe in [`OPERATOR_WIFI_APPLY.md`](OPERATOR_WIFI_APPLY.md).

---

### L-4. Trust instruments over agent narrative — measurable invariants win

**Rule:** Prefer probe artifacts, digests, parsed fields, and port checks over UI/agent claims ("already installed", "success", panel badges).

**Why it paid off:** Browser automation reported install complete; component-set digest on Gate A probe proved otherwise until the real install landed.

**Anti-pattern:** Closing a task because the web UI or an agent transcript said it worked.

**Cross-ref:** Component vs browser UI row — [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md) §1; Gate A evidence workflow — [`OPERATOR_GATE_A.md`](OPERATOR_GATE_A.md).

---

### L-5. Decorative tests give false confidence — prefer behaviour asserts; prove non-tautology

**Rule:** A security or integration test that cannot fail on regression is worse than no test. Assert observable behaviour; when runtime preconditions cannot be met offline, document that limit explicitly. **Proof obligation:** temporarily break the protection under test and confirm the test fails (red→green).

**Why it paid off:** Substring-in-source UI tests broke on useful refactors without catching regressions; trap tests where a missing signal already prevents a positive verdict tested nothing. Adversarial review found blockers that green CI missed until negative/proof tests landed.

**Detection signal:** Test still passes after you comment out the guard, remove redaction, or drop enforcement — e.g. `tests/test_rci_secret_leak_scanner.py::test_redact_sealed_cli_command_red_green_guard`, `tests/test_planner_properties.py::test_proof_grammar_source_property_is_not_tautological`, `tests/test_config_ui.py::test_uplink_readback_status_table_red_green` (arbitrary comment must not satisfy structural wiring).

**Anti-pattern:** `assert True` patterns, mocks that never exercise failure branches, security tests with no negative case, source-text substring asserts without structural contract.

**Cross-ref:** Code-honesty fixes — [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md) §1; [`contracts/AI_HANDOFF.md`](contracts/AI_HANDOFF.md) verification expectations; [`contracts/TEST_STRATEGY.md`](contracts/TEST_STRATEGY.md).

---

### L-6. Run adversarial review even when tests are green — especially user-facing status copy

**Rule:** After implementation, deliberately attack status strings, URL handling, retry semantics, compensation/rollback paths, and cross-surface consistency (UI vs API vs technician view). Treat green CI as necessary, not sufficient.

**Why it paid off:** Multiple blockers surfaced only when an independent reviewer was tasked to break the change — password echoed in URL query on Enter, firmware downgrade reported as unchanged version, compensating rollback treating absent PSK as proof of our write, `apply_dispatched` taken from checkpoint instead of dispatched-op facts, lease expiring during 20–30s settle waits.

**Detection signal:** Issues found exclusively by adversarial pass, never by unit tests alone; user-visible copy contradicts API enum semantics.

**Anti-pattern:** Stopping at green CI when copy, UX paths, destructive compensation, and audit correlation were not red-teamed.

**Cross-ref:** Session trap catalog — [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md) §2; [`OPERATOR_ROUTER_CONFIG_UI.md`](OPERATOR_ROUTER_CONFIG_UI.md); orchestration policy — [`autonomous-agent-orchestration.md`](autonomous-agent-orchestration.md) (adversarial-reviewer role).

---

### L-7. Honest status vocabularies beat single booleans

**Rule:** Split user-visible status into distinct layers: configuration-accepted vs interface-up vs tunnel-working; grammar-accepted vs uplink-verified; configured vs associated SSID; not-configured vs unrecognized vs unknown; open vs unrecognized security.

**Why it paid off:** Single "success" booleans hid dead tunnels, grammar-only Wi-Fi acks, and survey gaps that operators needed to see separately.

**Anti-pattern:** One `ok: true` or `healthy: true` for multi-stage device workflows.

**Cross-ref:** Honest capability markers — [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md) §1; [`OPERATOR_AWG_APPLY.md`](OPERATOR_AWG_APPLY.md).

---

### L-8. "Accepted by the device" ≠ "works"

**Rule:** Treat grammar acceptance and admin-up as necessary but insufficient; egress, association, encryption, and handshake require separate verification tiers.

**Why it paid off:** Wi-Fi PSK accepted without encryption still failed association (`survey-no-bss`); WireGuard config accepted and interface up while no traffic flowed.

**Anti-pattern:** Promoting `grammar-accepted` or `configuration-accepted` to "device-verified" without bounded end-to-end proof.

**Cross-ref:** Station and WG rows — [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md) §1; [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) (expendable envelope ≠ WriteCertified).

---

### L-9. Model settle windows with bounded wait-and-recheck — never conclude failure from one immediate read

**Rule:** After state-changing operations (routing, DHCP, WireGuard handshake), use bounded poll loops with documented timeouts; distinguish "not yet" from "failed."

**Why it paid off:** Default route and tunnel handshake both needed settle time before trustworthy readback — see handoff settle notes for session-specific durations; immediate polls falsely showed missing route or dead peer.

**Anti-pattern:** Single immediate poll → user-visible failure or false dead-peer.

**Cross-ref:** Default-route and tunnel settle notes — [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md) §1, §9.

---

### L-10. Vendor docs = names to verify, not behaviour to rely on — re-test from a single observation path

**Rule:** Treat documentation and help text as candidate token names; confirm behaviour with live or sanitized captures before encoding product rules.

**Why it paid off:** `permit global` rejected despite vendor kill-switch narrative; scan security type present in RCI but absent in assumptions; **lab observation (not a certified product capability):** plain `wireguard` accepted AmneziaWG-shaped obfuscation params on one unit — re-verify before encoding as product rule.

**Anti-pattern:** Encoding vendor examples or single-session lab observations as certified grammar without device ack/readback.

**Cross-ref:** Routing/VPN policy survey — [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md) §1; [`OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md`](OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md).

---

### L-11. When real input refused, ask if the RULE is wrong — derive bounds from semantics, not one sample

**Rule:** On validation rejection, inspect whether the constraint (regex, digit bound, enum) is incorrect relative to domain semantics — not only whether the sample was malformed.

**Why it paid off:** ASC digit bound conflicted with 32-bit wire encoding until semantics were re-derived.

**Anti-pattern:** Widening validation blindly or rejecting live device output as "user error" without revisiting the rule.

**Cross-ref:** AWG/ASC encoding work — [`OPERATOR_AWG_DISCOVERY.md`](OPERATOR_AWG_DISCOVERY.md); historical asc-9 notes in [`SESSION_HANDOFF_REAL_ROUTER_2026-07-24.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-24.md).

---

### L-12. Never silently discard part of user intent — refuse explicitly and name what was rejected

**Rule:** If the product cannot apply a requested field (e.g., IPv6 allowed-ips), fail with an explicit, named rejection — do not drop silently.

**Why it paid off:** Quiet drops eroded operator trust and hid scope gaps during VPN profile apply.

**Anti-pattern:** Best-effort partial apply without surfacing omitted fields.

**Cross-ref:** Open items (IPv6, Address) — [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md) §1, §10; [`contracts/RCI_POLICY.md`](contracts/RCI_POLICY.md).

---

### L-13. Environment traps: shell persistence, CLI help mode, and SSH framing break naive automation

**Rule:** Launch env-dependent work in the **same** command invocation (env vars do not persist across separate shell calls). For interactive CLI, `cmd?` + Enter may execute the bare command — use partial input + `?` without carriage return, then reset. SSH ANSI after prompt breaks naive string matching.

**Why it paid off:** Repeated false negatives from split-shell env, accidental live execution during help discovery, and prompt parsing failures.

**Anti-pattern:** Assuming Windows/PowerShell session state carries over; treating CLI transcripts like plain text files.

**Cross-ref:** Operator SSH/RCI procedures — [`OPERATOR_SSH_CLI_DISCOVERY.md`](OPERATOR_SSH_CLI_DISCOVERY.md), [`OPERATOR_RCI_TYPED_OPS.md`](OPERATOR_RCI_TYPED_OPS.md); bring-up traps — [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md) §2 (do not restate device-specific commands here).

---

### L-14. Deployment-order dependencies: internet before vendor download — pre-provision before offline rack ships

**Rule:** Component and firmware downloads require upstream internet; internet may require Wi-Fi client association and upstream credentials — plan provisioning **before** shipping a rack that will boot offline.

**Why it paid off:** Circular dependency blocked WG component install until station uplink existed — a product/process lesson, not a one-off glitch.

**Anti-pattern:** Assuming factory-default router can pull packages with no upstream path configured.

**Cross-ref:** Circular-dependency note — [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md) §8; lab policy — [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md). **Product implication only** — no new capability claim.

---

### L-15. After firmware/component change, expect identity drift — plan re-certification; never bypass fail-closed

**Rule:** Treat install/upgrade events as identity-drift triggers. Before any write, obtain **human-approved Gate A re-certification** (authorized rebind per [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md)) — probe, record sanitized evidence, update the recorded tuple through the approved workflow only. **Never** silently rebind or patch tuple/digest/host-key fields without explicit authorization. Do not disable fail-closed checks to "make it work."

**Why it paid off:** WireGuard component install moved digests and required authorized same-day Gate A rebind #2; live device ≠ recorded tuple must stop writes.

**Anti-pattern:** Silent rebind, stale host-key pin, or continuing campaigns on superseded evidence.

**Cross-ref:** Gate A rebind narrative — [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md) §1; [`OPERATOR_GATE_A.md`](OPERATOR_GATE_A.md); [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md); [`contracts/HARDWARE_GATES.md`](contracts/HARDWARE_GATES.md).

---

### L-16. Three states before destructive compensation — unknown ≠ absent ≠ ours

**Rule:** Where a decision leads to rollback, clear, or other destructive compensation, model **three** states: known-present, known-absent, **unknown**. Map unknown to **skip + fail-closed**, never to "we did not set it, so safe to clear."

**Why it paid off:** The costliest offline-session defect: compensating rollback treated missing PSK in pre-apply readback as proof that **we** had set the password, and issued `no authentication wpa-psk` — which would erase a foreign password on a live device.

**Detection signal:** Compensation emits clear/remove ops when baseline read omitted the field; audit shows `PSK state unknown` in uncovered ops instead of destructive clear — `tests/test_wifi_apply_reliability.py::test_compensate_skips_clear_psk_when_pre_readback_omits_psk`, `tests/test_wifi_apply_planner.py::test_derive_pre_state_psk_unknown_when_readback_omits_psk`; `had_psk: bool | None` in `router_control/application/wifi_apply_planner.py` (`WifiApplyPreState`).

**Anti-pattern:** Coercing `None`/missing readback to `False` and proceeding with rollback clears.

**Cross-ref:** Compensation baseline — [`OPERATOR_WIFI_APPLY.md`](OPERATOR_WIFI_APPLY.md); [`contracts/SECURITY_OPS.md`](contracts/SECURITY_OPS.md) sealed apply trail; tags `comp-psk-unknown-fail-closed`.

---

### L-17. Derived audit flags from facts — checkpoints are auxiliary only

**Rule:** Compute product/audit booleans from authoritative fact lists (e.g. non-empty dispatched-op ledger), not from auxiliary checkpoint metadata written mid-flight.

**Why it paid off:** `apply_dispatched` was briefly derivable from checkpoint JSON while `ops_dispatched_redacted` was still empty — audit correlation and recovery could claim dispatch when nothing had actually acked on device.

**Detection signal:** Snapshot shows `apply_dispatched: false` with `checkpoint_apply_dispatched: true` when dispatched list is empty — `tests/test_persistence.py::test_sealed_apply_trail_apply_dispatched_facts_not_checkpoint`; facts-first comment in `router_control/persistence/store.py::build_sealed_apply_trail_snapshot_for_audit`.

**Anti-pattern:** Treating service-layer checkpoint flags as ground truth over durable op lists.

**Cross-ref:** [`contracts/SECURITY_OPS.md`](contracts/SECURITY_OPS.md) trail correlation (2026-08-01 M11); [`contracts/PERSISTENCE_CONTRACT.md`](contracts/PERSISTENCE_CONTRACT.md).

---

### L-18. Secret boundaries need structure, not regex lexicon alone

**Rule:** Regex field-name scrubbers are necessary but insufficient — any new encoding (JSON nesting, PEM blocks, Bearer headers, high-entropy blobs, alternate spellings) bypasses lexicon-only rules. Add **structural** detectors (schema-derived column scan, PEM/Bearer/entropy heuristics) and default-safe behaviour (redact/refuse). Where scrubbing would erase useful diagnostics, prefer **enum-coded** error surfaces over echoing raw device text.

**Why it paid off:** Lexicon-only redaction missed novel secret shapes; over-aggressive scrub removed legitimate debug context until structural codes replaced free-text echoes.

**Detection signal:** New secret shape slips past `_WPA_PSK_CLI_RE`-style patterns but is caught by `secret_scan_table_columns` / structural high-entropy scan — `tests/test_persistence.py::test_secret_scan_columns_match_live_schema`, `tests/test_error_message_secret_scrub.py` (`structural_high_entropy_*`), `router_control/application/wifi_observation_helpers.py::_message_contains_structural_secret_material`; red→green guard in `tests/test_rci_secret_leak_scanner.py::test_redact_sealed_cli_command_red_green_guard`.

**Anti-pattern:** One-regex-fits-all secret policy; returning scrubbed-to-empty error strings with no machine-readable code.

**Cross-ref:** [`contracts/SECURITY_OPS.md`](contracts/SECURITY_OPS.md) audit redaction; [`contracts/RCI_POLICY.md`](contracts/RCI_POLICY.md); OpenAPI verdict literals in `router_control_host/apply_response_models.py`.

---

### L-19. Every safety mechanism needs a worst-case proof test

**Rule:** Timeouts, leases, fail-closed gates, and compensation skips must have tests that exercise the **worst** timing/concurrency path — not only the happy path.

**Why it paid off:** Pre-apply read timeout initially could block the caller indefinitely (worker pool shutdown waiting on hung I/O); sealed-apply lease could expire during bounded 20–30s handshake/settle waits, letting a stale process mark a live apply interrupted.

**Detection signal:** Timeout test asserts caller returns within budget while worker eventually completes — `tests/test_apply_pre_read_timeout.py::test_pre_apply_read_timeout_releases_caller_within_budget`; lease renewed in chunks during settle — `tests/test_persistence.py::test_sealed_apply_lease_survives_settle_wait`, `router_control/application/recovery.py::sleep_preserving_sealed_apply_lease`; finish skipped when lease lost — `tests/test_persistence.py::test_finish_sealed_apply_run_skips_when_lease_lost`.

**Anti-pattern:** Declaring "15s timeout" or "30s lease" without a test where the protected operation outlasts the budget.

**Cross-ref:** [`OPERATOR_AWG_APPLY.md`](OPERATOR_AWG_APPLY.md) handshake settle; pre-apply read in `router_control/application/apply_pre_read.py`.

---

### L-20. Cite docs by section anchor — line numbers rot

**Rule:** Reference operator/contract docs with `path#anchor` (section heading slug) plus expected snippet text; verify anchors with tests. Never cite brittle `file.md:244` line numbers in product code or planner notes.

**Why it paid off:** Line-number citations broke on doc edits and misled operators; false citations are worse than none.

**Detection signal:** Planner note contains `OPERATOR_WIFI_DISCOVERY.md:244` or `:87` — should fail — `tests/test_planner_properties.py::test_wifi_ap_wpa3_clear_note_is_not_false_doc_line_citation`, `test_station_clear_ip_notes_cite_probe_evidence_not_teardown_row`; positive anchor resolution — `test_wifi_ap_grammar_doc_anchor_refs_resolve` via `router_control/application/grammar_doc_refs.py`.

**Anti-pattern:** Hard-coded line numbers in code comments, planner notes, or SSOT cross-refs.

**Cross-ref:** Grammar doc registry — `router_control/application/grammar_doc_refs.py`; [`contracts/TEST_STRATEGY.md`](contracts/TEST_STRATEGY.md).

---

### L-21. Parse-semantics change can look like identity drift — version the digest algorithm

**Rule:** When correcting how installed-component status is parsed, bump and record a named digest algorithm id (`component-set-v2`, etc.). On dual-population responses, defective pre-v2 parse can produce catalogue-stub drift digests while host-key/firmware stay unchanged — **≠** physical device swap. Recorded Gate A digest may already match the correct installed-key set; a correct re-probe after parser fix should align. Never silent-rebind the Gate A tuple; if mismatch persists after correct re-probe, authorized human rebind only.

**Why it paid off:** Defective v1 on dual-population hashed catalogue stubs (drift e.g. `479a368c…`) while recorded Gate A digest (`23bd35bc…`) already matched sorted `entries_with_installed_key` — buggy live reprobe looked like component-set drift on the same unit.

**Anti-pattern:** Rewriting `gate-a-certification.json` or STATUS tuple silently after fixing parse semantics; comparing digests computed under different algorithm ids without naming the algorithm.

**Cross-ref:** Gate A identity drift human gate — `docs/HUMAN_GATE_GATE_A_IDENTITY_DRIFT_20260801.md`.

---

### L-22. Silent metadata loss on the profile path can masquerade as firmware limits

**Rule:** When a parsed field is accepted in an allowlist but dropped before persistence or intent build, treat symptoms (zero handshake bytes, never-initiated traffic) as **pipeline bugs** until a single-variable live experiment falsifies that hypothesis.

**Why it paid off:** `PersistentKeepalive` was allowlisted for months but never reached the device on the profile activation path — every session documented "no handshake" and "Address NOT configured" as separate mysteries until §M-24 changed one variable.

**Anti-pattern:** Documenting "firmware does not support X" when the client never dispatched a built, validated command.

**Cross-ref:** §M-24..§M-26 — `.cursor/plans/main-decisions-local-hub.md`; [`OPERATOR_AWG_APPLY.md`](OPERATOR_AWG_APPLY.md).

---

### L-23. Allowlist absence is not a device ceiling — verify dispatch, not docs consensus

**Rule:** If builder + validator + planner emit a sealed op but live apply fails client-side, inspect `is_write_allowlisted` before blaming NDMS.

**Why it paid off:** Both VPN `ip address`/`ip global` (§M-23) and Wi-Fi station writes (§M-32) were rejected for months with "not supported" narratives; live proof arrived immediately after allowlist registration.

**Anti-pattern:** Escalating to T4/firmware-limit docs when the failure is `AllowlistViolation` before SSH.

**Cross-ref:** §M-23, §M-32 — `.cursor/plans/main-decisions-local-hub.md`; [`OPERATOR_WIFI_DISCOVERY.md`](OPERATOR_WIFI_DISCOVERY.md).

---

### L-24. MSS clamp and captive checks measure different traffic classes — do not conflate fixes

**Rule:** Router-side `captive_accessible` probes use the device's **own** TCP stack; `ip tcp adjust-mss` clamps **forwarded** traffic. Applying MSS and observing unchanged captive status is expected, not failure of the clamp.

**Why it paid off:** §M-30 applied MSS successfully yet `captive_accessible` stayed false — the honest outcome prevented a false "captive fixed" claim.

**Anti-pattern:** Upgrading tunnel health or MSS application to "guest/captive works."

**Cross-ref:** §M-28, §M-30 — `.cursor/plans/main-decisions-local-hub.md`; [`OPERATOR_AWG_APPLY.md`](OPERATOR_AWG_APPLY.md).

---

## Agent delegation lessons (2026-08-01)

Transferable orchestration patterns from the large offline reliability session. Harness policy details live in [`autonomous-agent-orchestration.md`](autonomous-agent-orchestration.md) and [`.cursor/skills/autonomous-task/contracts.md`](../.cursor/skills/autonomous-task/contracts.md).

### D-1. Parallel writers need explicit file ownership — shared artifacts last

**Rule:** When multiple subagents run concurrently, declare `owned_files` per task; treat intermediate red CI in foreign files as normal overlap, not regression. Edit shared surfaces (`docs/docs-map.json`, exported OpenAPI, cross-cutting contracts) **last**, re-read before merge, run final verification only after all branches converge.

**Why it paid off:** Multiple concurrent implementers regularly produced transient red tree states; failures in unowned files were expected mid-flight, not evidence of a broken final state.

**Detection signal:** Agent reports pytest failures in files outside its contract while owned verify commands pass; merge conflicts on map/OpenAPI from parallel doc+code edits.

**Anti-pattern:** Each agent "fixing" the whole tree; editing `docs-map.json` at the start of a parallel batch.

**Cross-ref:** Task Contract `owned_files` — [`.cursor/skills/autonomous-task/contracts.md`](../.cursor/skills/autonomous-task/contracts.md); routing table — [`autonomous-agent-orchestration.md`](autonomous-agent-orchestration.md).

---

### D-2. "Verify yourself — do not take the assignment on faith"

**Rule:** In subagent prompts, explicitly require independent verification of premises stated in the task brief. The assigner's hypothesis may be wrong.

**Why it paid off:** Multiple subagents disproved assumptions baked into their own task descriptions when challenged to verify against code/artifacts first.

**Detection signal:** Subagent report opens with "assignment claimed X; code/evidence shows Y."

**Anti-pattern:** Subagent executes task narrative without checking whether the stated bug/locations still exist.

**Cross-ref:** Evidence protocol — [`autonomous-agent-orchestration.md`](autonomous-agent-orchestration.md) §Evidence protocol.

---

### D-3. Require red→green proof with actual command output

**Rule:** For fixes and new guards, acceptance must include a observed failing run **before** the fix and passing run **after**, with real exit codes/output — not a narrative that tests "should" pass.

**Why it paid off:** Filtered out tests written to match already-green CI without demonstrating they catch the defect class.

**Detection signal:** Verification record lacks failing command output; test added but never demonstrated to fail when protection removed (see L-5 proof obligation).

**Anti-pattern:** "Added test; pytest green" with no break-and-fail demonstration.

**Cross-ref:** Done criteria — [`autonomous-agent-orchestration.md`](autonomous-agent-orchestration.md); proof tests in `tests/test_rci_secret_leak_scanner.py`, `tests/test_planner_properties.py`.

---

### D-4. "If absent, say absent" — do not invent fixes

**Rule:** When evidence, files, or repro steps are missing, report the gap explicitly and stop short of speculative remediation.

**Why it paid off:** Saved cycles that would have "fixed" non-issues or chased stale paths from outdated task briefs.

**Detection signal:** Agent deliverable lists **Not confirmed** / **Not found** sections instead of silent assumptions.

**Anti-pattern:** Plausible-sounding fix with no path/evidence citation.

**Cross-ref:** Fail-closed posture — L-2; honest status vocabularies — L-7.

---

### D-5. Repeat explicit prohibitions per task — they stick

**Rule:** Restate hard bans in every subagent contract (e.g. no live router writes, no secrets in repo, do not touch forbidden paths) even when global rules already exist.

**Why it paid off:** Session reported that restating hard bans in every Task Contract `forbidden` field (e.g. no live router writes) correlated with no out-of-envelope hardware commands — local contract stop alongside global AGENTS.md rules.

**Detection signal:** Audit of subagent shells shows no out-of-envelope hardware commands; `forbidden` list non-empty on every T2/T3 contract.

**Anti-pattern:** Relying on AGENTS.md alone without per-task `forbidden` reinforcement.

**Cross-ref:** [`AGENTS.md`](../AGENTS.md) lab envelope; Task Contract schema — [`.cursor/skills/autonomous-task/contracts.md`](../.cursor/skills/autonomous-task/contracts.md).

---

## Practical playbook

Compact checklist — **facts and current baseline live in cross-referenced docs**, not here.

| Step | Action | See |
|---|---|---|
| 1 | Reach lab safely: wired management path, pin host key, credentials by reference only | [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md), [`OPERATOR_GATE_A.md`](OPERATOR_GATE_A.md), [`contracts/SECURITY_OPS.md`](contracts/SECURITY_OPS.md) |
| 2 | Run verification commands; offline suite must stay green — **match session handoff baseline** (see handoff §8 verify table; do not invent counts) | [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md) §8, [`STATUS.yaml`](STATUS.yaml) |
| 3 | Secrets never in repo; scrub `show rc` and error paths at ingest | [`contracts/SECURITY_OPS.md`](contracts/SECURITY_OPS.md), [`AGENTS.md`](../AGENTS.md) |
| 4 | Backup before first write; tear down to baseline after bounded campaigns | Handoff §8 baseline snapshot, [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) |
| 5 | Write sanitized evidence artifacts; cite them in capability claims — never claim from narrative alone | [`OPERATOR_GATE_A.md`](OPERATOR_GATE_A.md), handoff §1 evidence column |
| 6 | When behaviour surprises, read handoff assumption traps **then** matching L-rule; for multi-agent sessions also scan **D-rules** before parallel edits | Handoff §2, **Transferable rules** and **Agent delegation lessons** above |

---

## Related docs

| Doc | Role |
|---|---|
| [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md) | **Session narrative SSOT** — device facts, evidence, traps, end state |
| [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) | Living lab policy — expendable envelope, rebind rules |
| [`STATUS.yaml`](STATUS.yaml) | Phase, gates, blockers, `next_task` |
| [`OPERATOR_GATE_A.md`](OPERATOR_GATE_A.md) | Gate A probe and source-bind procedures |
| [`OPERATOR_AWG_APPLY.md`](OPERATOR_AWG_APPLY.md) | AWG apply and tunnel status honesty |
| [`OPERATOR_WIFI_APPLY.md`](OPERATOR_WIFI_APPLY.md) | Wi-Fi apply bounded AP path |
| [`contracts/SECURITY_OPS.md`](contracts/SECURITY_OPS.md) | Secrets, scrub, confirm binding |
| [`contracts/HARDWARE_GATES.md`](contracts/HARDWARE_GATES.md) | Gate semantics (read-only reference; do not open B/C/D from this doc) |
| [`contracts/AI_HANDOFF.md`](contracts/AI_HANDOFF.md) | Cold-start extensions and task template |
| [`contracts/TEST_STRATEGY.md`](contracts/TEST_STRATEGY.md) | Test posture, proof/non-tautology expectations |
| [`NEW_CHAT_COLD_START_2026-07-31.md`](NEW_CHAT_COLD_START_2026-07-31.md) | Paste prompt for new chat sessions |
| [`autonomous-agent-orchestration.md`](autonomous-agent-orchestration.md) | Harness routing, adversarial review role, evidence protocol (pairs with **D-rules** above) |

---

## Docs Impact Record

| Field | Value |
|---|---|
| contract_id | engineering-lessons-20260801 |
| paths | docs/ENGINEERING_LESSONS.md, docs/docs-map.json |
| map_entries | docs/ENGINEERING_LESSONS.md — active; tags methodology/lab/cold-start/judgement/ai-first/offline-reliability-0801/agent-delegation |
| validators_required | `scripts/validate-project-docs.ps1`, `py -3.11 scripts/project-docs.py audit --project-root .`, `py -3.11 -m pytest tests/test_project_docs.py -q` |
| notes | Extended L-3/L-5/L-6 with 2026-08-01 code anchors; added L-16..L-20 (compensation tristate, facts-first audit, structural secrets, safety proof tests, anchor citations); added D-1..D-5 agent delegation lessons; no device-fact or gate-status changes |
