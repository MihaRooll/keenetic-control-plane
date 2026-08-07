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
| 0 | Prototype only: `RC_UNSAFE_DISABLE_AUTH=1` **and** standalone loopback profile active **and** request-time `adapter_mode` **exactly** `fake` (missing/unknown/non-string → **not** fake) | **Proceed** — cookie/password not required; **never** substitute in Hub or live adapter |
| 1 | Router Control enabled **and** `HUB_ADMIN_PASSWORD` empty/whitespace | **`503`** — `SecurityBlocked`; handler **not** invoked; Hub continues (kiosk/board/printing) |
| 2 | Password configured, invalid/missing `hub_admin` cookie | **`401`** — login required |
| 3 | Valid `hub_admin` session | Proceed to feature policy (disabled/degraded/plan gates) |
| 4 | API key / guest / board / promo tokens | **Never** substitute for `hub_admin` on Router prefix |

Implementation touchpoint: `AdminGateMiddleware` special-case before general fail-open admin gate ([`ARCHITECTURE.md`](../ARCHITECTURE.md) §10, ADR-0003).

**Prototype unsafe dev auth bypass (2026-08-02):** env-only `RC_UNSAFE_DISABLE_AUTH=1` may skip step 2 on `router_control_host` only when standalone loopback profile is active **and** request-time `adapter_mode` resolves to exactly `fake`. Predicate is **fail-closed**: missing host, absent `adapter_mode` attribute, non-string value, or empty/unknown mode → bypass **denied** (401). Boot arm bit alone is **never** sufficient; sticky arm after runtime adapter mutation or missing/unknown/non-fake `adapter_mode` at request time must **not** bypass auth. ContextVar from middleware carries the computed allow for the request. Live adapter and Hub integration **always** require `hub_admin`. Flag ignored without standalone or on live — loud stderr/log warning. See [`OPERATOR_UI.md`](../OPERATOR_UI.md).

**Prototype UI (2026-07-22):** the same decision order applies to `/settings/router-control` and `/settings/router-control/assets/*` on `router_control_host` (additive middleware branch; API order unchanged). UI responses include strict CSP and frame deny headers ([`OPERATOR_UI.md`](../OPERATOR_UI.md)). Standalone **`GET /login`** form + **`POST /login`** mint `hub_admin:v2` cookie (8h default TTL); **`POST /logout`** clears session (same-origin); management shell has no password field.

**Prototype login throttle (2026-07-22 closure):** in-process sliding window **10 failed credential attempts / 60 seconds** on `POST /login` only; injectable monotonic clock for tests; returns identical generic 401 HTML as bad password; successful login resets counter; origin/authority provenance rejects **must not** call password verification (no timing oracle); `POST /logout` not throttled. Residual risk on loopback remains operator-controlled bind + password choice.

**Prototype standalone loopback authority (2026-07-22):** optional profile `RC_STANDALONE_LOOPBACK_AUTH=1` + canonical `RC_PUBLIC_BASE_URL` (HTTP loopback with explicit port). When ON: Host header exact pin, ASGI server loopback check, reject X-Forwarded-*; exact case-sensitive singleton `Origin: null` accepted on login/logout under Fetch Metadata gates (Cursor Browser). Default OFF preserves TestClient behavior. DPAPI launcher: `scripts/run-prototype-host.ps1` — see [`OPERATOR_UI.md`](../OPERATOR_UI.md).

## 2. `SecurityBlocked` vs `Degraded`

| State | Router Control API | Hub rest | Mutations |
|---|---|---|---|
| **SecurityBlocked** | All RC routes **`503`** (generic config error) | Continues | **Blocked** |
| **Degraded** | Limited **health/status** endpoints only (contracted in [`API_CONTRACT.md`](API_CONTRACT.md) §2) | Continues | **Blocked** |
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

**No API plaintext read-back** — GET credential endpoints return metadata only (`kind`, timestamps, `revoked_at`), never password/key material. Opaque ref columns only in SQLite — [`PERSISTENCE_CONTRACT.md`](PERSISTENCE_CONTRACT.md) §2.5, §7.

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

Audit store is **append-only**: no in-place updates or deletes. Retention/archival may copy forward, not mutate history. SQLite table layout and co-creation with operations — [`PERSISTENCE_CONTRACT.md`](PERSISTENCE_CONTRACT.md) §7–8.

Required events include: enroll, plan create, Confirm, apply start/end, compensate, credential rotate/revoke, gate passage/failure, `SecurityBlocked` transitions, and **sealed apply/teardown** dispatch (`sealed_apply.wifi.*`, `sealed_apply.wifi.station.*`, `sealed_apply.wireguard.*` — redacted intent + step summary + verdict; no resolved secrets).

### Sealed apply audit summary

Each sealed apply/teardown HTTP dispatch **must** append an `audit_events` row when router I/O is attempted (success, service failure, or exception). `summary_redacted` is JSON: `route`, `verb`, redacted `intent`, optional `outcome` (terminal `overall`, `verdict_explanation`, rollback summary — **SSOT for verdict/rollback**), optional `trail` (redacted `sealed_apply_runs` snapshot including `pre_apply_baseline_redacted` and `ops_evidence_redacted` — **SSOT for device acks and pre-apply baseline**), optional redacted `result` (residual fields only; omits `steps`/verdict/rollback when trail/outcome present), optional scrubbed `error_message`, optional `exception_type`. `correlation_id` mirrors the HTTP request. Audit persistence failure **must** log a warning and **must not** fail the apply HTTP response.

**Redacted intent (audit + trail):** credential refs and non-secret operational selectors only — never resolved secrets, never upstream/AP `ssid`, never WireGuard `peer_endpoint` / `asc_args`. Allowed examples:

| Route | Intent fields |
|---|---|
| `wifi` apply | `ap_id`, `enabled`, `captive_portal`, `guest_isolation`, `wpa_mode`, `band`, optional `credential_ref_id` |
| `wifi` teardown | `ap_id`, `wpa_mode` |
| `wifi.station` | `mode`, `band`, `priority`, `auth_mode`, optional `credential_ref_id`, optional `bssid` |
| `wireguard` | `wg_id`, `enabled`, optional `private_key_credential_ref_id`, `preshared_key_credential_ref_id`, `peer_allow_ips`, `peer_keepalive_interval`, `peer_rci_shape` |

**Error redaction (fail-closed, 2026-08-01):** Service-layer `error_message` in audit and operator-facing HTTP errors **must** pass `scrub_error_message`. Unlike show-rc ingest (partial substring scrub via `scrub_encryption_scalar`), error text uses **fail-closed** policy with **two barriers**:

| Barrier | Scope | Bypass resistance |
|---|---|---|
| **Lexical (1st)** | Field assignment (`=`, `:`, tab), JSON keys, single/double URL-encoding, device WireGuard/WPA lexicon, `Authorization: Bearer`, PEM private-key headers, `passwd`/`пароль` | Renaming alone insufficient when delimiter or device lexicon remains |
| **Structural (2nd)** | PEM blocks, Bearer tokens, tokens ≥32 chars with high base64/hex entropy (independent of field names) | Renaming field labels does not hide material shape |

When **either** barrier triggers, the **entire** message is replaced with `[REDACTED:error_message]`. Diagnostic value for secret-bearing failures comes from structured fields (`exception_type`, classified error codes, redacted `intent`, trail snapshot) — not from raw exception text. Uncaught exceptions **must** persist `exception_type` only — arbitrary `str(exc)` is forbidden in audit, logs tied to audit append, and secret-scan surfaces.

**HTTP error surface (2026-08-01):** All operator JSON errors **must** pass through `router_control_host.errors.error_body` (central scrub of `message` + **recursive** string scrub in nested `details` structures). Call sites: `error_response`, `sealed_apply_trail_begin_error_response`, `validation_error_response`, and direct `error_body` in `app.py`, `routes.py`, `ui_routes.py` — scrubbing is centralized in `error_body`; callers need not duplicate.

**Validation / 422 no-echo (2026-08-01):** FastAPI default `RequestValidationError` → `{"detail": exc.errors()}` is **out of policy** — it forwards Pydantic `msg` (often embeds `got '…'`) and `input` (raw user value). Host **must** register `@app.exception_handler(RequestValidationError)` → `validation_error_response` in `router_control_host/errors.py`, which rebuilds structured details with **`loc`**, **`type`**, and safe **`ctx` only** (`expected`, `expected_values`, `ge`, `le`, `gt`, `lt`) — **never** `input`, never raw pydantic `msg`. Top-level code **`request.validation_failed`**; message synthesized from loc + type (+ safe bounds/expected when present). **Union fields (2026-08-01):** when multiple branch failures share one root field, summary **must not** lead with `literal['…']` or PascalCase model tags — prefer the single nested constraint field (`Invalid value for {root}.{nested}: {type} (expected >= N)`) when exactly one branch constraint applies and siblings are structural only; otherwise emit `does not match any allowed form (allowed: …)` built from literal `ctx.expected` and `object with '{field}'` hints from branch locs (excluding `extra_forbidden`). For **`extra_forbidden`** (unknown JSON keys under `extra=forbid`), user-supplied key names **must not** appear in `message` or `details[].loc` — replace with stable **`[unrecognized_field]`** placeholder. Default-safe for new model fields without lexicon updates. Unhandled exceptions **may** return generic `internal.error` via `error_body` without `str(exc)`; must not shadow `HTTPException` / validation handler. Test vectors: `tests/test_validation_error_no_echo.py`, `tests/test_error_message_secret_scrub.py`, `tests/test_vpn_policy_preview_api.py`, `tests/test_rci_secret_leak_scanner.py::test_http_422_validation_surface_no_canary_echo`.

**Operator message synthesis (2026-08-01):** Owned host routes (event-preset validation, network-family preview, Starlette `HTTPException`) **must not** pass `str(exc)` or `exc.detail` into operator `error.message`. Host synthesizes messages from allowlisted reason templates in `synthesize_operator_message` (`unknown_fields`, `invalid_fqdn`, `not_allowlisted`, `out_of_range`, `invalid_format`, `invalid_value`, `preview_failed`) using code-controlled parts only (`field`, `reason`, `expected`, `context`). Structured `details[]` **may** include `{field, reason, expected?}` — **never** a user-supplied `value` or unknown key name. Domain `IntentValidationError` / adapter `RciValidationError` carry `code` + optional `field`; scrub via `error_body` remains a secondary barrier. **Honest residual:** unowned wifi/wg preview routes may still echo exception text until migrated. Test vectors: `tests/test_operator_error_no_echo_guard.py`.

**Lexical refinement (2026-08-01):** Broad “field name + space + word” matching removed for generic labels (`credential`, `password`, `secret`, `ssid`, `psk` in identifier context). Prose like `requires credential_ref_id`, `Device rejected password length`, `secret is required for SET_PRIVATE_KEY` passes when no secret material is present. Device-output patterns (`wpa-psk VALUE`, `wireguard private-key VALUE`, `(?<![_\w])psk VALUE`) retained. `credential_ref_id` / `*_credential_ref_id` never treated as credential value assignment.

**Structured error codes (minimum, 2026-08-01):** Stable codes exported from `wifi_observation_helpers` — planners: `planner.credential_ref_required`, `planner.ssid_required`, `planner.no_apply_ops`; services: `service.credential_resolution_failed`, `service.op_dispatch_failed`, `service.readback_failed`, `service.unsupported_operation`. Apply service `errors[]` and step `error` fields use these codes instead of secret-adjacent prose; HTTP `error.code` remains primary operator signal when message is redacted. Device/router text (`router_message`, adapter exceptions) stays scrubbed at boundary.

**Structural false-positive boundary:** SSH host-key fingerprints (`SHA256:…` with **bounded** base64 tail — appended secret material must not hide behind the digest prefix), UUIDs, `req_`/`corr_`/`cred_`/`credref:` refs, interface paths (`WifiMaster0/AccessPoint3`), MAC addresses, and short tokens (<32 chars) are excluded from entropy redaction. Structural scan **must not** treat `field=value` assignments as one glued token (`=` excluded from candidate charset; RHS checked separately). Tokens ≥48 chars or ≥40 chars with ≥2 character classes (upper/lower/digit/symbol) in error text are treated as secret-shaped. Residual risk: rare diagnostic blobs containing long random strings — prefer structured codes over raw text.

**Audit vs operator boundary:** Both surfaces share the same fail-closed scrubber. Audit additionally omits raw text for uncaught exceptions; operator HTTP responses carry structured `error.code` independent of scrubbed message.

**Secret indicators (non-exhaustive contract list):** `psk`, `preshared`/`pre_shared_key`, `private_key`/`private-key`, `password`, `passphrase`, `passwd`, `пароль`, `key` (assignment/JSON-key forms only — not bare “host key”), `secret`, `credential` (value assignment — not `credential_ref_id`), `ssid` (assignment/value only), `wpa-psk`, WireGuard `private-key`/`preshared-key` lexicon, `Authorization: Bearer`, PEM `PRIVATE KEY` blocks; single and double URL-encoded assignments. Test vectors: `tests/test_error_message_secret_scrub.py`.

**Trail correlation (2026-08-01, M11 recovery evidence):** Every sealed apply audit **must** embed the latest matching `sealed_apply_runs` snapshot keyed by `correlation_id` + `route` + `verb` (not only on failure). Snapshot includes `ops_planned_redacted`, `ops_pending_redacted`, `ops_dispatched_redacted`, `apply_dispatched`, `pre_apply_baseline_redacted`, `ops_evidence_redacted`, `status`. Device ack evidence **must** use bounded redacted step + `device_ack` (status entries or scrubbed show-rc shape via `sanitize_show_rc_interface_raw` / `sanitized_dict`); plaintext PSK from device show-rc **must** be scrubbed before persistence (`tests/test_sealed_apply_crash_durability.py::test_redact_sealed_apply_op_evidence_scrubs_device_plaintext_psk`). **`apply_dispatched` is facts-first** from non-empty `ops_dispatched_redacted`; checkpoint metadata is auxiliary only. Terminal verdict/rollback **must not** be duplicated inside trail mid-flight columns — they live in `outcome_snapshot_redacted` + audit `outcome`.

### Sealed apply mid-flight trail (2026-08-01)

Sync sealed apply/teardown routes (`wifi`, `wifi.station`, `wireguard`) **must** persist a `sealed_apply_runs` row before the first mutating device dispatch; trail begin failure **must** fail-closed (no device I/O; HTTP **503** `sealed_apply.trail_begin_failed`). Per op: record intent in `ops_pending_redacted` **before** device dispatch; move to `ops_dispatched_redacted` only after successful ack; merge redacted `ops_evidence_redacted` into the same intent/progress write (no extra DB row). **M11:** record `pre_apply_baseline_redacted` once after pre-apply read; on terminal finish write `outcome_snapshot_redacted`. Intent/progress writes **must** atomically renew lease with ownership guard. During bounded settle waits before uplink/tunnel readback, apply services **must** renew lease in chunks (`sleep_preserving_sealed_apply_lease` — **fail-closed:** lease renew failure **must** abort the wait and propagate). `finish_sealed_apply_run` **must** require matching `lease_owner` and **must not** overwrite status when lease was lost (e.g. already `Interrupted`). Discovery of unfinished runs is via `PersistenceStore.list_unfinished_sealed_applies()` — **no** v0 HTTP list endpoint. On hub/worker startup, `interrupt_stale_sealed_apply_runs()` **may** mark **expired-lease** orphan `Running` rows `Interrupted` (SQLite only; **no** device I/O; stale when `lease_until_epoch < now` **or** `lease_until_epoch IS NULL` and `started_at` older than default lease TTL; **must not** interrupt runs holding a valid lease). `guard_sealed_apply_trail` **must** terminalize trail on `Exception`, `SystemExit`, and `KeyboardInterrupt`. **Forbidden by default:** automatic resume, compensating rollback, or device writes driven solely by an unfinished trail row. All trail columns **must** remain redacted (credential refs and op names only; never resolved secrets). Pre-apply baseline reads **must** honor transport-aligned timeout without blocking the caller on executor shutdown; abandoned reads hold per-transport I/O lock until completion; **all** RCI parse/write I/O on the same transport instance **must** share that lock (`execute_transport_io`). See [`PERSISTENCE_CONTRACT.md`](PERSISTENCE_CONTRACT.md) §2.28 and §7.1.

**Network-family trail scaffold (2026-08-01):** VLAN/DHCP/DNS/firewall/VPN policy application services include optional `begin/guard/finish` trail hooks for future Gate B HTTP apply (`docs/OPERATOR_NETWORK_FAMILY_APPLY_SCAFFOLD.md`). **No** network-family `/apply` or `/teardown` HTTP routes persist trails today — preview-only HTTP remains the operator surface.

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
- **Gate A certifying RCI transport** requires authenticated encryption: HTTPS with certificate validation **or** host-key-pinned SSH local forward to verified router management RCI HTTP. Plain LAN HTTP and unpinned SSH are lab-only and non-certifying.

### SSH host-key trust (explicit TOFU)

Add-router / lab SSH uses **explicit learn → out-of-band verify → confirm → pin** (`POST …/ssh-host-key/learn` then `POST …/ssh-host-key/confirm`). The learn step opens a pre-auth SSH handshake only to read the server public key; it **never** calls password/auth methods and does not establish a usable tunnel session.

| Policy | Requirement |
|---|---|
| Blind TOFU | **Forbidden** — no Paramiko `AutoAddPolicy`, no silent `accept-new`, no first-connect auto-pin without operator echo |
| Pin storage | Primary `router_endpoints` columns (`ssh_host_key_sha256`, `algorithm`, `pinned_at`, `provenance`) — see [`PERSISTENCE_CONTRACT.md`](PERSISTENCE_CONTRACT.md) §2.3 |
| Pin conflict | Stored pin differing from confirm candidate → **409** `ssh_host_key.pin_conflict`; overwrite only with explicit `allow_overwrite: true` |
| Live transport | `PinnedSshTunnel` remains fail-closed: mismatch raises `SshHostKeyMismatch`; missing pin raises `SshHostKeyMissing` |
| Legacy anti-pattern | Legacy `accept-new` documented as **Do-not-reuse** in [`LEGACY_MAP.md`](../LEGACY_MAP.md) |

Fingerprints are public digests (not secrets) but must be confirmed honestly; provenance records `learned_confirmed` vs `operator_supplied`.

**Offline-verified (2026-07-31):** Brick 3 API/persistence covered by mocked tests only; device SSH component not validated in this change set.

## 9. Links

- HTTP/API surface: [`API_CONTRACT.md`](API_CONTRACT.md)
- Operator scenarios (zone matrix): [`SCENARIOS.md`](SCENARIOS.md) (`SCN-ZONE-*`)
- RCI lifecycle: [`RCI_POLICY.md`](RCI_POLICY.md)
- Hardware gates: [`HARDWARE_GATES.md`](HARDWARE_GATES.md)
- Index: [`README.md`](README.md)
