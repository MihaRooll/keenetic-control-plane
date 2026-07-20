# AI agent handoff contract

## For agents

| Check | Action |
|---|---|
| Phase | **Phase 0b complete** — contracts documented and cross-reviewed; **implementation does not exist** |
| SSOT | Read [`STATUS.yaml`](../STATUS.yaml) **before** any claim about deliverables, phase, or gates |
| Code | **No** package, API host, UI, OpenAPI, tests, fixtures, or router mutations until `implementation_transition_gate.human_approved=true` and `code_may_start=true` |
| Gates A–D | **All closed** — live observe and write dispatch fail closed |
| Secrets | Never add passwords, keys, sessions, startup-config, or real device IDs to repo/docs |
| Docs update | Change STATUS + project-state + docs-map + navigation **atomically**; run `scripts/validate-project-docs.ps1` |
| Next task | Explicit human approval for Phase 1 / SLICE-1 — see [`STATUS.yaml`](../STATUS.yaml) `next_task` and `implementation_transition_gate` |
| Trace | All eight STATUS contract deliverables (§8) + [`ROADMAP.md`](ROADMAP.md) implementation sequence; supporting `hardware-gates` and `contracts-index` per [`contracts/README.md`](README.md) |

---

## 1. Cold-start read order

Read in this order at session start (after [`AGENTS.md`](../../AGENTS.md)):

1. [`README.md`](../../README.md) — purpose, boundaries, current phase summary
2. [`docs/STATUS.yaml`](../STATUS.yaml) — **authoritative** phase, deliverables, blockers, next task, `implementation_transition_gate`
3. [`docs/CANONICAL.md`](../CANONICAL.md) — locked legacy facts and domain invariants
4. [`docs/contracts/README.md`](README.md) — contracts program and Wave navigation
5. **This document** — handoff rules, task template, verification expectations
6. Task-specific contracts from §8 as needed
7. [`docs/project-state.md`](../project-state.md) — non-competing harness projection only

Do **not** skip `STATUS.yaml` in favor of README prose or chat history.

---

## 2. SSOT hierarchy

| Priority | Source | Role |
|---|---|---|
| 1 | [`docs/STATUS.yaml`](../STATUS.yaml) | Phase, deliverables completed/pending, blockers, next task, `implementation_transition_gate`, canonical_facts |
| 2 | Phase 0b **contracts** (`docs/contracts/*.md`) | Normative behavior, API, persistence, gates, scenarios, roadmap |
| 3 | Phase 0a docs + ADRs | Architecture evidence; ADRs frozen unless explicitly amended |
| 4 | [`docs/project-state.md`](../project-state.md) | Living projection for hooks — **if diverges from STATUS, follow STATUS** |
| 5 | Chat / plan files | Non-authoritative; verify against STATUS |

**Contracts documented ≠ implementation exists.** Check `STATUS.yaml` `deliverables`, repo tree, and `implementation_transition_gate` before claiming code, package, API, or UI.

---

## 3. Locked invariants (summary)

From [`CANONICAL.md`](../CANONICAL.md) and [`STATUS.yaml`](../STATUS.yaml) `canonical_facts` — do not invent beyond these:

- **Product:** local event booth; first certified router target Netcraze Ultra NC-1812; four zones Guest/Promo/Staff/Admin-Server; Guest gets HTTPS order page only.
- **Identity:** stable `RouterId`; IP/hostname/gateway/interface name are not identity; identity mismatch → hard abort on mutation path.
- **Implementation (future):** Python 3.11 package `router_control`; separate FastAPI dev-host then Hub `module_3.0`; prefix `/api/router-control/v1/*`; UI in `/settings` only.
- **Persistence:** `data/router_control.sqlite3`; JSON import/export/artifacts only.
- **Security:** local operator v1; Confirm after redacted plan; DPAPI `CurrentUser` vault; managed merge ownership only.
- **Mutation lifecycle:** preflight → identity → observe → backup → plan → Confirm → Fail-safe Configuration → apply → read-back → verify → save/compensate ([`RCI_POLICY.md`](RCI_POLICY.md)).
- **Unknown firmware/capability/profile:** fail closed for writes.
- **Failure isolation:** Router Control must not block kiosk, board, printing, or Hub startup.
- **VPN v1:** AmneziaWG only; one active assignment per router in first deployment.
- **Routes:** 5000 is stress goal; production ceiling from lab benchmark only.
- **Legacy:** `ScanCursorIP` is behavioral evidence + strangler fallback until parity and cutover.

---

## 4. Current phase and gates

| Item | Value |
|---|---|
| Phase | **0b** contracts — `status: complete`, `complete: true` (Wave 7 closeout) |
| Wave 7 | **Complete** — cross-document review closed Phase 0b |
| All contract deliverables | Eight STATUS IDs complete; `pending: []` |
| Implementation transition | `implementation_transition_gate.human_approved: false`, `code_may_start: false` — **explicit human approval required** before SLICE-1 |
| Gates A/B/C/D | **All closed** — no live observe/write dispatch |
| Blockers | NC-1812 live certification and firmware tuple — see STATUS `blockers` |

---

## 5. Prohibited operations

Until `implementation_transition_gate.human_approved=true` and `code_may_start=true`:

| Prohibited | Reason |
|---|---|
| Create `router_control` package, `pyproject.toml`, source, tests | Pre-implementation; human gate closed |
| OpenAPI, migrations, fixtures with real device data | No code phase |
| Live router writes or gate opening | Hardware gates closed |
| Hub `module_3.0` integration code | SLICE-10 in roadmap; not now |
| Secrets in docs/code/fixtures/logs | SECURITY_OPS + AGENTS rules |
| Claim certification or open gates in prose | Fail-closed policy |
| Set `implementation_transition_gate.human_approved` or `code_may_start` without human | Human gate |

---

## 6. Task contract template

Use for autonomous work (see `.cursor/skills/autonomous-task/`):

```yaml
contract_id: short-slug
tier: T0|T1|T2|T3|T4
goal: testable outcome
acceptance_criteria:
  - id: AC-1
    text: observable result
owned_files: []          # implementer writes ONLY these
forbidden: []            # explicit exclusions
verify_commands: []      # must exit 0 before done
```

Rules: do not change AC or verify commands; T4/destructive/external writes stop for human approval; findings need path, lines, requirement ref, reproducible evidence.

---

## 7. Owned-path, evidence, review, verify expectations

| Expectation | Rule |
|---|---|
| **Owned paths** | Implementer modifies only `owned_files`; forbidden paths untouched |
| **Evidence** | Commands with exit codes; no model consensus as proof |
| **Review** | Adversarial review on T2+ product writes; blockers must resolve or be waived explicitly |
| **Verify** | All AC pass; required scripts exit 0; `blockers_open: 0` before done |
| **Docs changes** | Update STATUS + project-state + docs-map + nav together; Docs Impact Record when touching docs |
| **Validator** | `pwsh -NoProfile -File scripts/validate-project-docs.ps1` → exit 0 |

---

## 8. Contract catalog (eight STATUS deliverables)

| # | STATUS ID | Contract | Path |
|---|---|---|---|
| 1 | `rci-policy` | RCI policy | [`RCI_POLICY.md`](RCI_POLICY.md) |
| 2 | `security-ops` | Security / operations | [`SECURITY_OPS.md`](SECURITY_OPS.md) |
| 3 | `persistence-contract` | Persistence | [`PERSISTENCE_CONTRACT.md`](PERSISTENCE_CONTRACT.md) |
| 4 | `api-contract` | HTTP/API v0 | [`API_CONTRACT.md`](API_CONTRACT.md) |
| 5 | `test-strategy` | Test strategy | [`TEST_STRATEGY.md`](TEST_STRATEGY.md) |
| 6 | `scenarios` | Operator scenarios | [`SCENARIOS.md`](SCENARIOS.md) |
| 7 | `roadmap` | Implementation roadmap | [`ROADMAP.md`](ROADMAP.md) |
| 8 | `ai-handoff` | AI handoff (this doc) | [`AI_HANDOFF.md`](AI_HANDOFF.md) |

**Supporting (not counted in the eight):** [`HARDWARE_GATES.md`](HARDWARE_GATES.md) (`hardware-gates`); contracts index [`README.md`](README.md) (`contracts-index`).

**Scenario/test trace:** each `SCN-*` maps to API §6, TEST lanes, and contracts — see [`SCENARIOS.md`](SCENARIOS.md) §4 trace matrix and [`TEST_STRATEGY.md`](TEST_STRATEGY.md) §3 coverage matrix.

---

## 9. Atomic documentation updates

When changing listed docs, navigation, or phase status:

1. Edit content files.
2. Update [`docs/STATUS.yaml`](../STATUS.yaml) (`deliverables`, `current_phase`, `next_task`, `links`, exit criteria, `implementation_transition_gate`).
3. Update [`docs/project-state.md`](../project-state.md) milestones and `next_checks`.
4. Update [`docs/docs-map.json`](../docs-map.json) entries for new/changed paths.
5. Sync [`README.md`](../../README.md), [`docs/README.md`](../README.md), [`docs/contracts/README.md`](README.md) as needed.
6. Run `pwsh -NoProfile -File scripts/validate-project-docs.ps1` — must exit **0**.
7. Record Docs Impact Record in task return (see autonomous-task `contracts.md` §8).

Preserve line endings (STATUS.yaml is CRLF). Minimize unrelated churn.

---

## 10. Safe resumption

| Situation | Action |
|---|---|
| New session | Cold-start §1; read STATUS `next_task` |
| Unsure if code exists | List repo; check STATUS `implementation_transition_gate` and deliverables |
| Phase 0b complete | Do **not** start SLICE-1 until human sets `human_approved=true` and `code_may_start=true` |
| Implementation requested | Confirm human gate open in STATUS; else stop with Human Gate Packet |
| Doc drift suspected | Run docs validator; reconcile STATUS over project-state |
| Hardware work | Require explicit gate open for exact tuple; never infer from docs |

**Next owner task:** `phase-1-implementation-human-approval` — obtain explicit human approval before any Phase 1 / SLICE-1 code. `implementation_transition_gate.human_approved` and `code_may_start` remain **false**.

---

## 11. Links

- Project status SSOT: [`STATUS.yaml`](../STATUS.yaml)
- Architecture: [`ARCHITECTURE.md`](../ARCHITECTURE.md)
- Domain model: [`DOMAIN_MODEL.md`](../DOMAIN_MODEL.md)
- Agent entry: [`AGENTS.md`](../../AGENTS.md)
- Contracts index: [`README.md`](README.md)
