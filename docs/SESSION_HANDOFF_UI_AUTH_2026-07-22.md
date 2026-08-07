# Session handoff — prototype UI auth bootstrap (2026-07-22)

**Status: DELIVERED (historical).** For **active** real-router lab context use [`SESSION_HANDOFF_REAL_ROUTER_2026-07-23.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-23.md). This UI handoff remains reference only.



## For agents



| Topic | Rule |

|---|---|

| When to read | Before implementing standalone prototype login/session; before Browser MCP visual smoke; when operator reports 401/404 on dev-host |

| Delivered | M0–M3 offline/read-only + prototype management UI (presentation) + **standalone session bootstrap** — **complete** (2026-07-22) |
| Not delivered | Fresh fail-safe T4 Human Gate campaign — **current next task** (P3 complete) |
| Auth today | `hub_admin:v2` signed cookie via `auth_gate`; UI + API gated; **standalone `/login`** form POST mints cookie; management shell has no password field |
| Operator flow | `GET /` → `/login` or UI; `POST /login` (CSRF provenance) → Set-Cookie; **`POST /logout`** clears session; **`GET /logout` → 405** |
| CSRF provenance | **Origin** (if present, exact match) → **Referer** (if non-empty) → **loopback Fetch Metadata** on absent Origin; **exact `Origin: null`** when standalone profile ON + authority validated + POST login/logout + empty Referer + exact Sec-Fetch-* — see [`OPERATOR_UI.md`](OPERATOR_UI.md) |
| SSOT | [`STATUS.yaml`](STATUS.yaml) `next_task=fail-safe-fresh-t4-campaign` |

| Secrets | Never document real passwords, cookie values, or commands that print tokens/cookies |



---



## 1. Session summary



This handoff closes the **prototype management UI presentation milestone** (buildless SPA at `/settings/router-control`) and the **standalone UI auth bootstrap** delivered **2026-07-22**.



Standalone operators obtain a `hub_admin` session via **`GET /login`** → form **`POST /login`** (Set-Cookie; CSRF provenance: Origin → Referer → loopback Fetch Metadata) and clear it with **`POST /logout`** only. Root landing and local favicon ship with the same host. UI and API gated paths still require a valid signed v2 cookie; empty `HUB_ADMIN_PASSWORD` still yields **503** before **401**.



**Current next task: fresh fail-safe T4 Human Gate campaign** — see [`STATUS.yaml`](STATUS.yaml) `next_task=fail-safe-fresh-t4-campaign` (P3 topology safety closure complete 2026-07-23).



---



## 2. Completed inventory (M0–M3 + UI)



| Milestone | Deliverable | Scope |

|---|---|---|

| M0 | ADR-0005, ROADMAP M0–M8 DAG, docs rebaseline | Docs only |

| M1 | CommissioningRun/ReadinessCheck, migration 2, commissioning API | Offline/read-only; Gate A RO assess only |

| M2 | Four-zone event preset, migration 3, preset API, planner/readiness | Offline; `write_ready=false` always |

| M3 | DurableWorker, lease heartbeat, typed handlers, async M1/M2 202 | Offline/RO/fake only |

| UI | `router_control_host/web/*`, `ui_routes.py`, middleware UI gate | Buildless SPA; M1–M3 views; hub_admin gate; CSP/security headers; **not Hub integration** |



Key UI paths (prototype host):



| Path | Purpose |

|---|---|

| `/settings/router-control` | HTML shell |

| `/settings/router-control/assets/styles.css` | Sole stylesheet (SSOT) |

| `/settings/router-control/assets/app.js` | ES module client |

| `/api/router-control/v1/*` | Existing M1–M3 API (unchanged public shape) |



Gates **unchanged**: A open ReadOnlyCertified; B trial completed_failed (not WriteCertified); C/D closed.



---



## 3. Final verification (UI milestone)



At UI presentation closeout the full offline suite was green:



| Command | Result |

|---|---|

| `py.exe -3.11 -m pytest -q` | **670 passed, 2 skipped** |

| `py.exe -3.11 -m ruff check router_control router_control_host tests scripts` | exit 0 |

| `py.exe -3.11 -m mypy router_control router_control_host` | exit 0 |

| `powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/export-openapi.ps1` | exit 0 |

| `powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/validate-project-docs.ps1` | exit 0 |

| `py.exe -3.11 scripts/project-docs.py audit --project-root .` | exit 0 |



UI-specific tests: `tests/test_ui_host.py`, `tests/test_ui_assets.py`, `tests/test_ui_security.py`, `tests/test_ui_api_contract.py` (synthetic TestClient auth via in-process helpers — not operator browser flow).



---



## 4. Observed standalone operator behavior



### 4.1 Startup (expected configuration step)



Operator sets a real operator password in the process environment (placeholder `<operator-secret>` in docs is **not** a literal password):



```powershell

$env:HUB_ADMIN_PASSWORD = "<your-operator-password>"

uvicorn router_control_host.app:app --host 127.0.0.1 --port 8787

```



Server starts; `HUB_ADMIN_PASSWORD` being set clears the **503** `security.configuration_blocked` path for gated routes.



### 4.2 Browser without `hub_admin` cookie (current)



| Request | Status | Body / notes |

|---|---|---|

| `GET /` | **302** | Redirect to `/login` (unauthenticated) |

| `GET /favicon.ico` | **200** | Local packaged SVG favicon (no CDN/npm) |

| `GET /login` | **200** | Standalone login HTML (public; `no-store`) |

| `GET /settings/router-control` | **401** | JSON envelope `auth.required` — "Valid hub_admin session required" |

| `GET /settings/router-control/assets/styles.css` | **401** | Same gate (assets gated like HTML) |

| `GET /api/router-control/v1/status` | **401** | Same auth order as UI |

| `POST /login` (valid password; Origin exact, or Referer-only, or loopback FM fallback) | **303** | Set-Cookie `hub_admin`; redirect to UI entry |

| `POST /login` (wrong password, foreign Origin, empty `Origin: ""`, or missing provenance on non-loopback) | **401** | No Set-Cookie; generic failure HTML |



### 4.3 Misinterpretation to avoid



Setting `$env:HUB_ADMIN_PASSWORD` **alone does not authenticate the browser**. It only enables the auth gate to accept a **valid signed `hub_admin` cookie**. Without that cookie, 401 on UI/API is **correct and expected**.



Use **`GET /login`** and a provenance-valid **`POST /login`** (Origin exact when sent; else Referer; else loopback Fetch Metadata — see [`OPERATOR_UI.md`](OPERATOR_UI.md)) to mint the cookie; **`POST /logout`** with the same provenance rules clears it; **`GET /logout`** is non-mutating **405**. Do **not** log, paste, or document cookie values or the operator password.



---



## 5. Pre-bootstrap context (historical)



| Factor | Explanation |

|---|---|

| Auth model | Prototype reuses Hub-style `hub_admin` HMAC cookie (`router_control_host/auth.py`); bootstrap now adds HTTP issuance via `session_routes.py` |

| UI plan boundary | Presentation milestone deferred login in management shell; standalone login lives at `/login` ([`OPERATOR_UI.md`](OPERATOR_UI.md)) |

| Hub assumption | Production path still expects Hub `/login`; prototype host now has equivalent standalone bootstrap |

| Routing gaps | Resolved: `/` redirect and `/favicon.ico` shipped with auth bootstrap |



---



## 6. Delivered auth bootstrap (2026-07-22)



| Item | Status |

|---|---|

| Login/session/logout | **Delivered** — same-origin form POST; existing `hub_admin` cookie semantics; fail-closed 401/503 order preserved |

| Root landing | **Delivered** — `/` → `/login` or `/settings/router-control` |

| Favicon | **Delivered** — local `/favicon.ico` |

| UI/API auth boundary | **Preserved** — gated prefixes and middleware order unchanged |

| Tests | **Delivered** — `tests/test_session_routes.py`, `tests/test_host_auth.py`; full offline suite green |

| Visual smoke | Optional — Browser MCP **only after Human Gate** (operator password entry) |



**Out of scope (unchanged):** Hub `module_3.0` integration, router writes, gate opens, live commissioning Apply, npm/CDN build chain.



**Current next task: fresh fail-safe T4 Human Gate campaign** — [`contracts/ROADMAP.md`](contracts/ROADMAP.md); [`STATUS.yaml`](STATUS.yaml) `next_task=fail-safe-fresh-t4-campaign` (P3 complete).



---



## 7. Constraints



- Tier **T3** + `autonomous-task`; principal approval before production writes if auth surface expands beyond signed-cookie bootstrap.

- **Preserve dirty working tree** — do not `git clean`, reset, or discard uncommitted UI/auth work.

- Cold-start: [`AGENTS.md`](../AGENTS.md) → [`STATUS.yaml`](STATUS.yaml) → this doc.

- **No secrets** in repo, docs, fixtures, or command output.

- Gates A/B/C/D and `current_phase` (M3 complete) **unchanged** by auth bootstrap closeout.

- Browser MCP: Human Gate for password entry on `127.0.0.1` — never store credentials in chat or docs.



---



## 8. Verify commands (regression)



```text

py.exe -3.11 -m pytest -q

py.exe -3.11 -m ruff check router_control router_control_host tests scripts

py.exe -3.11 -m mypy router_control router_control_host

powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/validate-project-docs.ps1

py.exe -3.11 scripts/project-docs.py audit --project-root .

```



Optional after Human Gate: Browser MCP navigate authenticated UI shell; screenshot evidence only (no cookie values in artifacts).



---



## 9. Related docs



| Doc | Role |

|---|---|

| [`OPERATOR_UI.md`](OPERATOR_UI.md) | UI runbook; startup warnings |

| [`contracts/SECURITY_OPS.md`](contracts/SECURITY_OPS.md) | Auth decision order |

| [`contracts/AI_HANDOFF.md`](contracts/AI_HANDOFF.md) | Cold-start + next task |

| [`.cursor/plans/prototype-management-ui-20260722.plan.md`](../.cursor/plans/prototype-management-ui-20260722.plan.md) | UI implementation plan (verified pass) |



---



## 10. Historical archive — DO NOT USE for new sessions

> **DO NOT paste this section into a new chat.** Contract `prototype-ui-auth-bootstrap-20260722` is **closed** (IMPLEMENT complete, 2026-07-22). Re-pasting the old auth bootstrap prompt re-opens finished work.

**Current next task:** **fresh fail-safe T4 Human Gate campaign** — [`STATUS.yaml`](STATUS.yaml) `next_task=fail-safe-fresh-t4-campaign`; milestone DAG — [`contracts/ROADMAP.md`](contracts/ROADMAP.md). P3 topology safety closure complete (2026-07-23).

**Cold-start for new sessions:** [`AGENTS.md`](../AGENTS.md) → [`README.md`](../README.md) → [`STATUS.yaml`](STATUS.yaml) → [`contracts/AI_HANDOFF.md`](contracts/AI_HANDOFF.md). Use AI_HANDOFF for the live task contract; this file is **historical closeout only**.

### Delivered (2026-07-22) — reference

| Item | Where |
|---|---|
| Standalone login/session/logout, root redirect, favicon | [`OPERATOR_UI.md`](OPERATOR_UI.md); tests `test_host_auth.py`, `test_session_routes.py` |
| Auth order / security | [`contracts/SECURITY_OPS.md`](contracts/SECURITY_OPS.md) |
| Closeout note | [`STATUS.yaml`](STATUS.yaml) `prototype_ui_auth_bootstrap` |

No executable Task Contract is maintained here. For the current next task, start from ROADMAP + STATUS + AI_HANDOFF — not this handoff.



---



## Docs Impact Record (closeout)

| Field | Value |
|---|---|
| contract_id | prototype-ui-auth-bootstrap-20260722 |
| paths | router_control_host/auth.py, session_routes.py, app.py, web/login.*, web/favicon.svg, tests/test_host_auth.py, tests/test_session_routes.py, docs/STATUS.yaml, docs/OPERATOR_UI.md, docs/SESSION_HANDOFF_UI_AUTH_2026-07-22.md, docs/contracts/AI_HANDOFF.md, docs/contracts/README.md, docs/README.md, docs/project-state.md, docs/docs-map.json, README.md |
| map_entries | docs/OPERATOR_UI.md, docs/SESSION_HANDOFF_UI_AUTH_2026-07-22.md, docs/contracts/AI_HANDOFF.md (titles/tags) |
| validator | scripts/validate-project-docs.ps1 + project-docs.py audit |
| notes | Blocker prototype-ui-auth-bootstrap cleared; P3 complete; next_task fail-safe-fresh-t4-campaign |


