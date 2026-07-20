# ADR-003: Router Control authentication, trust boundaries, and secrets

- Status: Accepted
- Date: 2026-07-19
- Scope: Router Control v1 and its later integration into `module_3.0`

## Context

Router Control can change the network path by which the operator reaches the
Hub and router. It also handles router credentials and VPN private material.
Those powers must not be exposed to guest devices, worker devices, browser
JavaScript, ordinary SQLite rows, diagnostics, or an unauthenticated Hub
installation.

The target Hub already has one operator authentication pattern:

- `HUB_ADMIN_PASSWORD` is represented as `SecretStr`;
- a successful login issues a short-lived HMAC-signed `hub_admin` token in an
  HttpOnly, SameSite=Lax cookie;
- token signing uses a distinct `hub:` domain prefix and constant-time
  signature comparison;
- `AdminGateMiddleware` protects an explicit set of pages and API prefixes;
- API denial is a JSON `401`, while protected HTML navigation redirects to login;
- a valid Hub-admin cookie also authorizes browser writes through the optional
  API-key middleware.

The current general Hub gate is deliberately opt-in/fail-open when
`HUB_ADMIN_PASSWORD` is empty. That posture is **not sufficient** for Router
Control. Adding the new API prefix only to the existing conditional list would
leave router mutation reachable on an unconfigured Hub.

Windows DPAPI `CurrentUser` normally binds protected data to the same user
credentials and machine. This is appropriate for unattended local use only if
the Hub always runs under a stable Windows account. It is not a portable backup
or fleet recovery mechanism.

## Decision

### 1. Same listener, one operator session, stricter Router Control gate

The development prototype may use a separate FastAPI dev host. At Hub
integration, Router Control is mounted on the **existing FastAPI listener** at:

`/api/router-control/v1/*`

There is no second production management port, no separate Router Control
password, and no new browser scope/token family. The prefix uses the existing
`hub_admin` session and login flow.

The entire prefix is protected at a single middleware/dependency enforcement
point, including GET, preflight, plan, job status, and mutation endpoints. The
rule is fail closed:

1. if Router Control is enabled and `HUB_ADMIN_PASSWORD` is empty or
   whitespace-only, routes remain registered but the feature enters
   `SecurityBlocked`: no worker or mutation starts, and every Router Control
   request receives `503` before its handler runs; Hub startup continues;
2. a request without a valid `hub_admin` cookie receives `401` and no handler
   runs;
3. an API key, station token, Q1 token, board token, guest URL token, or RMM
   credential does not substitute for `hub_admin`;
4. Router Control degraded/disabled status must not prevent the rest of the Hub
   from starting.

The middleware prefix match must cover both `/api/router-control/v1` and its
descendants; tests must prove that slash and path-normalization variants cannot
bypass it. Existing HMAC domain separation, HttpOnly cookie transport, expiry,
constant-time verification, and redacted configuration logging remain in use.
Production HTTPS adds the cookie `Secure` requirement.

### 2. Local operator workflow in v1

Router Control v1 is for a human operator on the protected local Admin/Server
path. Remote management, unattended fleet changes, and autonomous capture-based
writes are outside v1.

Post-v1 remote mutations may be introduced only through the existing RMM
approval queue with an immutable plan, explicit approval and Router Control
audit linkage. A direct remote bypass around the local plan/job engine is not
allowed.

Authentication happens once through the existing Hub login. A valid session is
not asked to re-enter the password for every operation. Authorization to mutate
instead uses:

1. immutable, redacted plan/diff generated from a versioned observation;
2. an ordinary explicit **Confirm** action tied to the plan digest and expiry;
3. an idempotent job that rejects stale observations or changed plans.

Confirmation is not re-authentication. It cannot be replayed for another plan,
and no password is stored in plan, job, audit, URL, or browser storage.

### 3. Local secret storage

Router passwords, VPN private keys, profile secret fields, RCI session material,
and recovery keys are secret values.

Local secret blobs are protected with Windows DPAPI **`CurrentUser`** under the
stable Windows user account that runs the Hub Scheduled Task/service. The
deployment must pin and document that account, load its user profile, and run
install, normal operation, backup validation, and restore validation in that
same identity context. `LocalMachine` scope is not an acceptable fallback.

`data/router_control.sqlite3` stores only opaque `CredentialRef` values and
non-secret metadata needed for lifecycle management. It does not store
plaintext credentials, private keys, DPAPI plaintext, master keys, or a secret
copied into a job payload. The vault owns the mapping from `CredentialRef` to
the protected blob; domain code cannot read a secret back for display.

Secret input is write/rotate/delete only. Decrypted material is retained only
for the operation, unnecessary copies are avoided, references are released
promptly, and mutable buffers are zeroed on a best-effort basis. The
implementation does not claim guaranteed memory erasure in CPython. Rotation
creates a new reference before the old reference
is retired, so crash recovery never requires placing a secret in a durable job.

### 4. Backup, replacement, and future remote recovery

DPAPI `CurrentUser` is intentionally machine/user bound. Copying the SQLite
database or protected blobs to a new PC is not an automatic secret restore.

On a replacement machine:

- router credentials must be re-enrolled locally unless the future recovery
  contract has been used;
- **new VPN key pairs are generated**;
- old peers/keys are revoked after the new tunnel is verified;
- private keys are never migrated merely to preserve identity.

Automatic server-side recovery is a future contract, not a v1 shortcut. It
requires a separate approved ADR and threat model, cryptographic Hub enrollment
and per-Hub envelope encryption:

1. the Hub creates or receives a non-exportable/per-device wrapping identity;
2. the server verifies enrollment and binds recovery ciphertext to that Hub,
   tenant/site, purpose, and key version;
3. each secret uses authenticated encryption with a unique data-encryption key;
4. only the enrolled Hub's wrapping key can unwrap that data key;
5. rotation, revocation, audit, replay protection, and break-glass approval are
   explicit protocol operations.

A fleet-wide symmetric key, operator password, API token, or server database key
alone must never decrypt every Hub. Remote recovery cannot be enabled by merely
uploading DPAPI blobs or exporting a shared key. Until the future contract is
implemented, replacement requires local credential enrollment.

### 5. Network and transport security boundaries

The event network has four distinct zones:

| Zone | Intended principals | Router Control boundary |
|---|---|---|
| Guest | Customer phones; open guest Wi-Fi | May reach only the required local HTTPS order service. No Hub settings, router management, RCI, or other zones. |
| Promo | Kiosk/promo iPads | May reach only required kiosk HTTPS endpoints. No Router Control or Admin/Server reachability. |
| Staff | Authorized worker devices | May reach required board/work services. No router credentials, RCI, or Router Control mutation API. |
| Admin/Server | Hub and explicitly authorized admin device | The only zone allowed to reach Hub settings/Router Control and the router management endpoint. |

These are firewall/VLAN security boundaries, not labels. Their IPv4 and IPv6
negative-path tests are required before deployment. Default inter-zone deny is
maintained; narrow destination/port permits are added only for the stated flows.
Browser possession of a URL does not grant a cross-zone exception.

HTTPS is also a security boundary. Guest QR/signage points to a stable HTTPS
URL. Production traffic terminates at Caddy using a unique per-Hub public FQDN,
DNS-01 certificate, and local DNS mapping, then reaches loopback Uvicorn.
Router Control is same-origin behind this boundary. Direct LAN HTTP, certificate
warning click-through, exposing Uvicorn publicly, or publishing RCI through an
Internet HTTP proxy is not an accepted production mode.

The Hub-to-router RCI transport is a separate local management boundary. Its
exact HTTP/HTTPS endpoint, authentication and validation requirements must be
established by NC-1812 lab certification. Router writes remain blocked until
that selected transport is certified; this ADR does not require the router
itself to provide HTTPS.

The event appliance must remain operational for the accepted offline window of
1–3 days without certificate issuance, remote recovery or external control
plane. Certificate renewal is completed before the event or through the
separately designed management channel.

### 6. No-secret observability contract

The following never contain secrets:

- URLs, query strings, response bodies, HTML, JavaScript, local/session storage;
- SQLite domain tables, plans, diffs, idempotency records, jobs, checkpoints,
  audit events, exception text, logs, metrics, traces, diagnostics, or fixtures;
- startup-configuration artifacts made available to ordinary support tooling;
- screenshots, exported support bundles, or recorded RCI traffic.

Logging may record only reference IDs, operation type, router ID, request ID,
result, and boolean “credential present” state. Headers such as Cookie,
Authorization, API keys, RCI auth, and request/response bodies are excluded.
Redaction is defense in depth; secret-bearing values must not be handed to the
logger in the first place. Sanitized fixtures use generated keys and reserved
documentation addresses.

## Consequences

- Hub integration is mechanically compatible with the existing admin session,
  but Router Control tightens empty-password behavior for its own prefix.
- Operators log in once and confirm a concrete plan without repeated password
  prompts.
- Offline local operation is possible, while copied backups cannot silently
  expose or resurrect credentials on another PC.
- Stable Hub account identity and user-profile loading become deployment and
  restore prerequisites.
- Machine replacement intentionally rotates VPN identity.
- Future recovery requires a separate, reviewable cryptographic protocol.
- Network segmentation and HTTPS must be verified before Router Control writes
  are enabled; application authentication does not compensate for a flat LAN.

## Rejected alternatives

- **Reuse the current fail-open admin gate unchanged:** an empty password would
  expose router control.
- **Require the password for every apply:** encourages password handling in
  browser requests and does not bind approval as strongly as a plan digest.
- **Store encrypted credential columns directly in SQLite:** spreads secret
  lifecycle knowledge and makes accidental query/export leakage more likely;
  SQLite stores `CredentialRef` only.
- **DPAPI `LocalMachine`:** any local account with suitable access has a broader
  decryption path than the stable Hub user requirement.
- **One fleet recovery key:** one compromise becomes fleet-wide decryption.
- **Preserve VPN private keys on replacement:** extends compromise lifetime and
  defeats clean device enrollment.
- **Rely on auth without zones/HTTPS:** leaves credentials and powerful endpoints
  exposed to lateral movement or interception.

## Evidence

- Existing Hub patterns:
  `module_3.0/app/core/admin_auth.py`,
  `module_3.0/app/core/middleware.py`, and
  `module_3.0/app/settings.py` (inspected 2026-07-19).
- Microsoft, [CryptProtectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata):
  same-user credentials and usually the same machine are required without the
  `LOCAL_MACHINE` flag.
- Microsoft, [CryptUnprotectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata):
  decryption performs an integrity check and normally requires the same user.
- Netcraze, [NC-1812 web interface](https://support.netcraze.ru/ultra/nc-1812/en/13520-web-interface.html):
  local management is the default and Internet management is blocked by default.
- Netcraze, [RCI through HTTP Proxy](https://support.netcraze.ru/ultra/nc-1812/en/55035-using-api-methods-through-the-http-proxy-service.html):
  documents the RCI command/API shape; its public HTTP transport is evidence of
  capability, not an approved deployment topology.

