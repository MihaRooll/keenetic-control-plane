# Orchestration contracts (normative)

## Constants

- `MAX_REVIEW_CYCLES=3`; cycle 3 reopens blocker findings only.
- `MAX_PRINCIPAL_ATTEMPTS=2`; second reject → `BLOCKED`.
- Premium packets: max 12 invariants and 12 validation steps (each <=200 chars), `scope_summary<=1000`, max 20 `{path, lines, excerpt<=200}` refs.
- Never send raw shell logs, long stack traces, file dumps, or tool JSON to Sol.

All artifacts share one stable `contract_id`.

## 1. Task Contract

```yaml
contract_id: task-slug
tier: T0|T1|T2|T3|T4
goal: testable outcome
acceptance_criteria:
  - id: AC-1
    text: observable result
owned_files: []
verify_commands: []
forbidden: []
```

Writer cannot change acceptance criteria or verification commands.

## 2. Plan (T2+)

Path: `.cursor/plans/<contract_id>.plan.md`.

```yaml
contract_id: task-slug
cycle: 1|2|3
steps:
  - id: S-1
    action: bounded action
    owner: operational-orchestrator|implementer|adversarial-reviewer|verifier|principal-arbiter|explore
sol_approved: true|false|null
```

Persist before first T2/T3 product write. Cycle 3 steps cite blocker finding IDs.

## 3. Principal Packet (T3)

```yaml
contract_id: task-slug
attempt: 1|2
invariants:
  - id: INV-1
    text: must remain true
validation_plan: []
scope_summary: compact summary
owned_files: []
evidence_refs:
  - path: src/file
    lines: 10-20
    excerpt: capped excerpt
```

Sol response:

```yaml
verdict: approve|reject
gaps: []
```

No implementer before `approve`. Reject on attempt 1 → revise once; reject on attempt 2 → BLOCKED.

## 4. Human Gate Packet (T4)

```yaml
contract_id: task-slug
trigger: destructive|external-write|explicit-human
action_summary: requested action
destructive_ops: []
rollback_plan: safe rollback
verify_commands: []
human_decision: null|approve|reject
```

No forbidden mutation before explicit `approve`. After approval, Main owns the exact approved external/destructive action; code-bearing work may enter the reviewed T2 pipeline. Reject → BLOCKED.

## 5. Finding

```yaml
finding_id: F-1
contract_id: task-slug
severity: blocker|should-fix|nit
path: src/file
lines: 10-20
requirement_ref: AC-1|INV-1
evidence: reproducible counterexample
cycle: 1|2|3
status: open|resolved|wontfix
```

Missing `path`, `lines`, `requirement_ref`, or `evidence` → drop finding. Consensus is not evidence.

## 6. Verification Record

```yaml
contract_id: task-slug
cycle: 1|2|3
commands:
  - cmd: exact command
    exit_code: 0
    summary: bounded output
criteria_map:
  - id: AC-1
    status: pass|fail
blockers_open: 0
verdict: pass|fail
```

`pass` iff every required command exits 0, every AC passes, and blockers_open=0.

## 7. Final Report

```yaml
contract_id: task-slug
tier: T0|T1|T2|T3|T4
outcome: done|blocked|human_pending|failed
changes_summary: compact result
files_touched: []
review_cycles_used: 0|1|2|3
principal_attempts_used: 0|1|2
stop_reason: verified_pass|awaiting_human|blocker_exhausted|principal_rejected|human_rejected|verify_fail_exhausted|invalid_task
```

There is no partial completion. Open should-fix/nit may be reported only when all AC and deterministic checks still pass.

## State transitions

```text
CONTRACT -> IMPLEMENT                         T0/T1
CONTRACT -> PLAN -> IMPLEMENT                 T2
CONTRACT -> PLAN -> PRINCIPAL -> IMPLEMENT    T3 approve
PRINCIPAL -> PLAN -> PRINCIPAL                T3 reject on attempt 1
PRINCIPAL -> BLOCKED                          T3 reject on attempt 2
CONTRACT -> HUMAN -> HUMAN_PENDING            T4 awaiting decision
HUMAN_PENDING -> BLOCKED                      T4 explicit human reject
HUMAN_PENDING -> IMPLEMENT                    T4 approve + code-bearing task; Main dispatches reviewed T2 pipeline
HUMAN_PENDING -> EXECUTE -> VERIFY            T4 approve + action-only task; Main executes exact approved action
HUMAN_PENDING -> IMPLEMENT -> REVIEW -> EXECUTE -> VERIFY  T4 approve + code/action hybrid
IMPLEMENT -> VERIFY                           T0/T1
IMPLEMENT -> REVIEW -> VERIFY                 T2/T3/T4-approved-code
REVIEW|VERIFY -> IMPLEMENT                    fixable failure, cycle < 3
VERIFY -> DONE                                strict pass gate
otherwise -> BLOCKED|HUMAN_PENDING|FAILED
```

| Condition | Outcome | stop_reason |
|-----------|---------|-------------|
| Strict verification pass | DONE | `verified_pass` |
| Human decision missing | HUMAN_PENDING | `awaiting_human` |
| Human reject | BLOCKED | `human_rejected` |
| Second principal reject | BLOCKED | `principal_rejected` |
| Cycle 3 has open blocker finding | BLOCKED | `blocker_exhausted` |
| Cycle 3 required command/AC still fails without blocker finding | FAILED | `verify_fail_exhausted` |
| Invalid/unexecutable contract | FAILED | `invalid_task` |

Main creates the Final Report and is the only user-facing completion owner.

## 8. Docs Impact Record

Required when change/build touches docs or user-facing surface (README, onboarding, AGENTS copy):

```yaml
contract_id: task-slug
docs_paths_touched: []
docs_map_entries_updated: []
validator_run: yes|no
validator_exit_code: 0|null
notes: compact optional context
```

- `docs_paths_touched`: every doc/markdown path edited or added
- `docs_map_entries_updated`: `entries[].path` values changed in `docs/docs-map.json`
- `validator_run: yes` expected when map or referenced paths changed; attach exit code
- Omit section only for pure code changes with zero doc/user-facing touch

## Artifact ownership

| Artifact | Creator | Persistence |
|----------|---------|-------------|
| Task Contract | Main | chat/task packet |
| Plan | operational-orchestrator | `.cursor/plans/<contract_id>.plan.md` |
| Principal Packet | operational-orchestrator | compact task packet; no raw log |
| Human Gate Packet | Main | chat until explicit decision |
| Finding | adversarial-reviewer | review return |
| Verification Record | verifier; Main for T0 and T4 action-only | verification return |
| Final Report | Main | user-facing response |
| Docs Impact Record | implementer / Main | task return when docs touched |
