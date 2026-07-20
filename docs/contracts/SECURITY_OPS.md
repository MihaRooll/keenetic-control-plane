# Security and operations contract

## For agents

| Topic | Rule |
|---|---|
| Decision order | Empty/missing `HUB_ADMIN_PASSWORD` when feature enabled → **`SecurityBlocked` → HTTP 503** before any Router Control handler |
| vs Degraded | `SecurityBlocked` = all RC prefix **503**; `Degraded` = limited health/status only, **no mutations** |
| Confirm | Plan digest + expiry + **actor session binding** — not password re-entry |
| Secrets | `CredentialRef` + DPAPI `CurrentUser`; no API plaintext read-back |
| Surfaces | No-secret policy + redaction vectors (placeholders only) |
| Audit | Append-only; no updates/deletes of audit events |
| Replacement | New VPN keys on router replacement; revoke old |
| HTTPS | Zone allow/deny + Hub HTTPS deployment gates; **Hub HTTPS ≠ router RCI transport** |
| Trace | ADR-0003, [`ARCHITECTURE.md`](../ARCHITECTURE.md), [`DOMAIN_MODEL.md`](../DOMAIN_MODEL.md), [`RCI_POLICY.md`](RCI_POLICY.md) |

---

## 1. HTTP auth decision order (`hub_admin`)

For every `/api/router-control/v1` request (including GET):

| Step | Condition | Result |
|---|---|---|
| 1 | Router Control enabled **and** `HUB_ADMIN_PASSWORD` empty/whitespace | **`503`** — `SecurityBlocked`; handler **not** invoked; Hub continues (kiosk/board/printing) |
| 2 | Password configured, invalid/missing `hub_admin` cookie | **`401`** — login required |
| 3 | Valid `hub_admin` session | Proceed to feature policy (disabled/degraded/plan gates) |
| 4 | API key / guest / board / promo tokens | **Never** substitute for `hub_admin` on Router prefix |

Implementation touchpoint: `AdminGateMiddleware` special-case before general fail-open admin gate ([`ARCHITECTURE.md`](../ARCHITECTURE.md) §10, ADR-0003).

## 2. `SecurityBlocked` vs `Degraded`

| State | Router Control API | Hub rest | Mutations |
|---|---|---|---|
| **SecurityBlocked** | All RC routes **`503`** (generic config error) | Continues | **Blocked** |
| **Degraded** | Limited **health/status** endpoints only (contracted in future API doc) | Continues | **Blocked** |
| **Ready** | Full contracted surface | Continues | Allowed only through lifecycle + gates |

`SecurityBlocked` is feature-local: Hub is **not** required to exit startup. Kiosk, order board, and printing remain available.

Mutations are forbidden in both `SecurityBlocked` and `Degraded`. **`SecurityBlocked`** exposes **no** Router Control health handler — all RC prefix routes return **`503`**. **`Degraded`** alone may expose limited, redacted health/status endpoints; those responses must remain bounded and secret-free.

## 3. Operator Confirm binding

**Confirm** authorizes dispatch of an immutable `ChangePlan`. It is **not**:

- re-entry of router password or VPN private key;
- implicit consent by opening settings UI;
- reusable across plans or actors.

Confirm **must** bind:

| Binding | Requirement |
|---|---|
| Plan identity | `plan_id` + content digest |
| Preconditions | Linked `revision_id`, `observation_id`, observation ETag/digest |
| Expiry | `plan.expires_at`; expired plan rejected |
| Actor session | Same authenticated `hub_admin` session that created or explicitly adopted the plan |
| Risk acknowledgment | UI/API records operator Confirm event to audit |

Stale plan after Confirm still rejected at dispatch if identity, observation, or certification changed ([`RCI_POLICY.md`](RCI_POLICY.md) §6).

## 4. `CredentialRef` and DPAPI `CurrentUser`

| Operation | Policy |
|---|---|
| **Create** | Store secret via vault port; return opaque `credential_ref_id` only |
| **Use** | Adapter retrieves secret in-process for RCI/session; never log plaintext |
| **Rotate** | New secret version; update ref; revoke prior after successful verify |
| **Revoke** | Mark ref unusable; block new jobs referencing it |
| **Delete** | Secure delete provider blob; lifecycle checks for in-flight jobs |

Provider: **`DPAPI.CurrentUser`** under stable Windows account running Hub ([`CANONICAL.md`](../CANONICAL.md) §7).

**No API plaintext read-back** — GET credential endpoints return metadata only (`kind`, timestamps, `revoked_at`), never password/key material.

### Secret-kind vocabulary (domain, no DDL)

| `kind` | Material |
|---|---|
| `router_management_password` | RCI/management login |
| `router_session_envelope` | Optional encrypted session material |
| `awg_private_key` | AWG interface private key |
| `awg_preshared_key` | Optional PSK |
| `backup_encryption_key` | Local artifact encryption |
| `hub_enrollment_key` | Per-Hub crypto enrollment (future recovery) |

## 5. No-secret surfaces and redaction

Forbidden in API responses, plan diffs, job payloads, SQLite user-visible fields, logs, diagnostics, audit summaries, and shared fixtures:

- router passwords;
- VPN private keys and preshared keys;
- raw RCI session cookies/tokens;
- startup-config full content;
- serial/MAC in public exports unless operator-only redacted view.

### Redaction policy

- Replace secret substrings with stable placeholders (`[REDACTED:router_password]`, `[REDACTED:awg_private_key]`).
- Structured fields: omit or null secret fields in DTOs; never echo inbound secrets.
- Effective config logs: `SecretStr` / opaque refs only ([`ARCHITECTURE.md`](../ARCHITECTURE.md) §10).

### Example redaction test vectors (synthetic placeholders only)

| Input (test fixture) | Expected output |
|---|---|
| `{"password":"EXAMPLE_ROUTER_PASS_001"}` | `{"password":"[REDACTED:router_password]"}` |
| `PrivateKey=EXAMPLE_AWG_KEY_BASE64_PLACEHOLDER` | `PrivateKey=[REDACTED:awg_private_key]` |
| `Cookie: session=EXAMPLE_SESSION_TOKEN_PLACEHOLDER` | `Cookie: session=[REDACTED:router_session]` |
| Plan diff containing `presharedkey: EXAMPLE_PSK_PLACEHOLDER` | `presharedkey: [REDACTED:awg_preshared_key]` |

Vectors use **fake** values; never copy real operator or router material into tests/docs.

## 6. Append-only audit

`AuditEvent` records ([`DOMAIN_MODEL.md`](../DOMAIN_MODEL.md)):

- actor, action, outcome, correlation IDs;
- `router_id`, `plan_id`, `operation_id`, `job_id` when applicable;
- redacted summary and request digest;
- artifact references.

Audit store is **append-only**: no in-place updates or deletes. Retention/archival may copy forward, not mutate history.

Required events include: enroll, plan create, Confirm, apply start/end, compensate, credential rotate/revoke, gate passage/failure, `SecurityBlocked` transitions.

## 7. Backup, replacement, recovery

| Scenario | Policy |
|---|---|
| **Backup artifacts** | Encrypted at rest where applicable; metadata in SQLite; bytes in protected storage |
| **Router replacement** | Treat as new enrollment or explicit identity ceremony; **generate new VPN keys**; revoke old keys and refs |
| **Hub restore** | DPAPI-bound secrets may be unrecoverable on different user/machine — documented operator recovery path |
| **Fleet recovery** | Requires per-Hub crypto enrollment; fleet-wide operator password insufficient ([`CANONICAL.md`](../CANONICAL.md) §7) |

Replacement never reuses prior AWG private material by default.

## 8. Network zones and HTTPS deployment gates

Four zones: `Guest`, `Promo`, `Staff`, `Admin/Server` ([`ARCHITECTURE.md`](../ARCHITECTURE.md) §4).

| Zone | Router Control / management plane |
|---|---|
| Guest | Deny path to management; HTTPS order page only |
| Promo | Deny Router Control API and router management |
| Staff | Deny management by default |
| Admin/Server | Operator HTTPS + `hub_admin` path |

Zone policy **complements** HTTP auth; source IP/zone is not authentication.

### Hub HTTPS deployment

- Per-Hub public FQDN, DNS-01 certificate, local DNS, Caddy ([`CANONICAL.md`](../CANONICAL.md) §8).
- Production cookies require `Secure`.
- **Hub HTTPS boundary is separate from router RCI transport certification** (Gate A in [`HARDWARE_GATES.md`](HARDWARE_GATES.md)). Valid Hub TLS does not certify local RCI endpoint behavior.

## 9. Links

- RCI lifecycle: [`RCI_POLICY.md`](RCI_POLICY.md)
- Hardware gates: [`HARDWARE_GATES.md`](HARDWARE_GATES.md)
- Index: [`README.md`](README.md)
