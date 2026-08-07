# Operator runbook — entry pages (guest/staff landing)

## For agents

| Topic | Rule |
|---|---|
| When to read | Before implementing or operating guest/staff entry pages, public zone listener, or diagnostics self-check for entry pages |
| Scope | Operator-authored flat-text landing pages with immutable revisions; separate public ASGI app on `/p/*` only |
| Supported | Draft/publish/unpublish, operator draft preview (auth-gated), in-process self-check, QR + link alternative for guest access |
| Not supported | Captive-portal forced auto-open, logo upload, guest submission persistence, guest reachability proof from operator host |
| Human action | Operator must start `scripts/run-public-entry-zone.ps1` with explicit `RC_PUBLIC_ENTRY_BIND` and add a firewall rule for guest subnet → that port only |

---

## 1. Purpose

Entry pages let the operator publish a simple registration/landing page for guests or staff. Content is flat text only (no HTML from operators). The operator host (`127.0.0.1:8787`) serves management APIs and draft preview; **guests reach pages only through a separate public listener**.

---

## 2. What is supported in v1

| Capability | State |
|---|---|
| Guest and staff audiences (one page each per site) | Supported |
| Draft revisions with validation (`entry.html_not_allowed` for `<`/`>`) | Supported |
| Publish / unpublish pointer swap | Supported |
| Operator draft preview (`GET /entry-pages/{id}/draft-preview`, auth required) | Supported |
| In-process self-check (`POST /entry-pages/{id}/self-check`) | Supported — proves render at operator host only |
| Public zone (`GET /p/{slug}`, CSS asset, form submit accept-only) | Supported when separate listener is running |
| QR code + link for guest access | Supported (hub UI, IMP-3) |
| Form submission persistence | **Not supported** — accept-only, nothing stored |
| Captive portal forced auto-open | **Not supported** — use QR + link |
| Logo upload | **Not supported** |

---

## 3. Architecture

```
Operator host (127.0.0.1:8787)          Public entry zone (LAN address:8790+)
├── /api/.../entry-pages/*  (auth)      ├── GET /p/{slug}
├── /entry-pages/.../draft-preview      ├── GET /p/_assets/entry-page.css
└── (no /p/* routes)                    └── POST /p/{slug}/submit (accept-only)
```

The operator app **does not** mount public routes. The public app **does not** mount API, hub, login, or OpenAPI.

---

## 4. Single human action (operational)

1. Choose a LAN address on the operator PC (not `0.0.0.0`, not `::`).
2. Set `RC_PUBLIC_ENTRY_BIND=<that-address>` and optionally `RC_PUBLIC_ENTRY_PORT` (default `8790`, never `8787`/`8788`).
3. Add a firewall rule allowing **only the guest network subnet** to TCP **that port** on **that address**.
4. Run `powershell -File scripts/run-public-entry-zone.ps1`.
5. Publish the page in the hub; share `http://<bind>:<port>/p/<slug>` or QR.

**Never** expose `127.0.0.1:8787` (operator APIs) to the guest network.

---

## 5. Self-check honesty

`POST /entry-pages/{page_id}/self-check` returns:

- `render_ok`: whether the published revision renders in-process.
- `public_zone_enabled`: `true` if `RC_PUBLIC_ENTRY_BIND` is set in the operator process env; `null` if absent (unknown whether a separate listener runs elsewhere).
- `guest_reachable`: **always `null`** with `guest_reachable_reason: guest_device_check_required`.

Operator preview ≠ guest reachability. Only a check from a guest device can prove the latter.

---

## 6. Security notes

- Public responses use strict CSP (no `script-src`), `X-Frame-Options: DENY`, `Cache-Control: no-store`, `X-Robots-Tag: noindex`.
- Unknown or unpublished slugs return identical 404 bodies (no enumeration).
- Submit accepts only declared form fields; oversized bodies and rate limits are rejected without echoing submitted values.
