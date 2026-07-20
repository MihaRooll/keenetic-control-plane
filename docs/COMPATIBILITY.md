# Router Control compatibility

## Status vocabulary

This document separates product documentation from hardware certification:

- **Verified** — supported by model-specific Netcraze documentation or by an
  explicitly recorded observation. This does not by itself authorize automated
  writes.
- **Lab required** — plausible/documented capability, but the exact NC-1812
  RCI representation, write sequence, persistence, rollback, or scale behavior
  has not passed the live-router certification lane.
- **Unsupported** — outside Router Control v1, even if NDMS can provide the
  capability manually.

Unknown firmware, component sets, fields, or command results fail closed for
writes. Read-only detection may continue and report the unknown value.

## Certified target and firmware identity

The first and only model targeted for certification is **Netcraze Ultra
NC-1812**. Netcraze identifies the product as model index `NC-1812`; its
model-specific support center documents NDMS, configuration backup, HTTPS web
management, and CLI access.

The current deployment observation is written as **`5.01`**. It must be
preserved as an unclassified raw value until a sanitized identity snapshot
records the complete version, update channel, build, installed components,
serial/MAC, and device fingerprint. It must **not** be normalized to **`5.1`**:
official pages currently use forms such as `5.1`, `5.1.0`, and `5.1.1`, while
the Help Center index and latest Main release page are not fully consistent.
Neither source establishes how raw `5.01` maps to a release train.

Certification is keyed by exact model + exact firmware/build + update channel +
component-set digest. A different tuple is detect-only until its compatibility
lane passes.

## Hardware certification gate ladder

Formal gates (Phase 0b opens **none**): [`contracts/HARDWARE_GATES.md`](contracts/HARDWARE_GATES.md).

| Gate | Purpose |
|---|---|
| **A** | Read-only RCI transport + identity certification |
| **B** | Per-capability-family write certification |
| **C** | Explicit laboratory mutation window |
| **D** | Production enablement on event tuple |

`RouterCapability.certification_status` transitions: `Unknown → ReadOnlyCertified → WriteCertified | Unsupported`, with expiry/revocation fail-closed for writes.

## Capability matrix

| Capability | Product/model evidence | Router Control v1 status | Write gate |
|---|---|---|---|
| Segments | **Verified:** model help describes additional local segments, bridges, addressing and DHCP. | Lab required | Discover exact RCI objects; create/read-back; isolation test; reboot and restore. |
| VLANs | **Verified:** VLAN assignment is documented as part of segment and port configuration. | Lab required | Certify tagged/untagged port and bridge fields on the exact firmware. |
| SSIDs | **Verified:** segment help documents wireless settings and multiple access points per band. | Lab required | Certify 2.4/5 GHz bindings, security fields and client reconnect behavior. |
| Firewall | **Verified:** inter-segment isolation is default and explicit permit rules are documented. | Lab required | Certify IPv4 and IPv6 rule order/direction, negative tests, lockout rollback. |
| Local DNS | **Verified:** NDMS 5.0 model notes document DNS-based routing and the model guide requires clients to use the router resolver for it. | Lab required | Certify local host/FQDN records and resolver behavior needed by the Hub; do not infer this from DNS-based routes alone. |
| HTTPS | **Verified:** NC-1812 product/help pages document HTTPS-protected web management. | Lab required for RCI transport; mandatory for user traffic | Prove certificate validation and supported local RCI endpoint. Hub applications use the separately managed HTTPS boundary described in ADR-003. |
| RCI | **Verified:** Netcraze documents JSON GET/POST commands under `/rci`, CLI-like command shape, user access rights, and Digest auth through its HTTP Proxy service. | Lab required | Local HTTPS endpoint, auth challenge/session behavior, command errors, async continuation, timeout, and one synchronized re-auth must be captured. Public HTTP-proxy RCI is not the deployment design. |
| WireGuard | **Verified:** NC-1812 documentation supports the WireGuard component and NDMS 5.0 server UI. | **Unsupported in v1** | Detect/report only; Router Control v1 accepts AmneziaWG profiles only. |
| AmneziaWG (AWG) | NDMS 5.1 release notes confirm WireGuard import with advanced ASC parameters, but do not enumerate the complete accepted field set, call it full AmneziaWG compatibility, or document the RCI object shape. Availability on raw `5.01` is unverified. | **Lab required; v1's only VPN type** | **All AWG writes remain blocked** until every accepted profile field imports without semantic loss and create/switch, read-back, live handshake, application reachability, save, reboot, compensation, and baseline restore pass. Unknown or dropped fields fail closed. |
| Safe Configuration | **Verified:** model help documents fail-safe mode: applied changes remain outside startup configuration until saved; timeout can reboot and restore the saved configuration. | Lab required; mandatory for disruptive writes | Prove activation/status/confirm/rollback over the selected management path and test loss of connectivity. Primary term: **Fail-safe Configuration** ([`contracts/RCI_POLICY.md`](contracts/RCI_POLICY.md)). A best-effort compensating rollback is still required. |
| Routes | **Verified:** model help documents IPv4/IPv6 static routes and NDMS 5.0 DNS-based routes. | Lab required | Only managed routes may be changed. Production ceiling is set by the benchmark gate below. |
| Backups / restore | **Verified:** product and update guidance document saving `startup-config.txt`; firmware/component backup is recommended before risky updates. | Lab required | Validate non-empty artifact, hash and router identity; perform restore + reboot + baseline verification. Backup existence alone is not proof of restorability. |
| Firmware/components | **Verified:** NDMS is modular, and changing components can rebuild/update NDMS and reboot the router. | **Detect-only** | Automated install, removal, channel change, update, downgrade, or firmware restore is unsupported in v1. |

“Verified” in the evidence column means the vendor documents the capability for
NC-1812. Every row marked “Lab required” remains blocked for automated writes
until its gate is recorded against the exact certification tuple.

## AWG certification blocker

AWG-only is a product scope decision, not a claim that AWG write compatibility
already exists. The certification fixture must contain only synthetic keys and
reserved documentation addresses, plus:

1. the exact profile fields accepted from the intended exporter;
2. a field-by-field parse → plan → RCI mapping with rejection of unknown fields;
3. a greenfield import and a switch between two profiles;
4. redacted read-back proving no field was silently omitted or converted;
5. a fresh handshake and application-level reachability through the tunnel;
6. Safe Configuration confirm and timeout rollback paths;
7. save, reboot, health re-check, compensation, and full baseline restore.

Until all seven pass, inventory and preflight may detect AWG-related state, but
plan confirmation cannot dispatch an AWG mutation.

## Route scale benchmark gate

**5,000 routes is an unsupported stress benchmark, not a vendor-supported-limit
promise.** Netcraze documents a 1,024-line limit for static-route batch files,
but does not publish a total active-route capacity for NC-1812. On the
dedicated NC-1812, run separate **100 / 1,000 / 5,000** managed-route trials.
For each size record:

- plan/diff time, peak Hub memory, request count and RCI apply/read-back time;
- startup-configuration save duration and result;
- controlled reboot duration, management recovery time and route count after boot;
- backup size/time and restore duration/result;
- post-restore reboot and proof that the baseline route table returned;
- CPU/memory observations, command errors, timeouts, and Safe Configuration result.

Each trial is baseline → backup → apply → verify → save → reboot → verify →
restore → reboot → verify baseline. The production ceiling is the largest size
that meets the later operations SLO with no loss, truncation, timeout, or
unrecoverable state. It may be lower than 5,000.

## Evidence

Official/model-specific sources, accessed 2026-07-19:

- [Netcraze Ultra NC-1812 product page](https://netcraze.ru/ru/netcraze-ultra)
- [NC-1812 Help Center and release channels](https://support.netcraze.ru/ultra/nc-1812/?lang=en)
- [NDMS 5.0 Main release notes](https://support.netcraze.ru/ultra/nc-1812/en/46907-latest-main-release.html)
- [NDMS 5.1 Preview release notes](https://support.netcraze.ru/ultra/nc-1812/en/46988-latest-preview-release.html)
- [NC-1812 functional limitations](https://support.netcraze.ru/ultra/nc-1812/en/49454-functional-limitations-of-devices.html)
- [Network segments](https://support.netcraze.ru/ultra/nc-1812/en/14628-network-segments.html)
- [Static routing](https://support.netcraze.ru/ultra/nc-1812/en/15880-static-routing.html)
- [DNS-based routes](https://support.netcraze.ru/ultra/nc-1812/en/51150-dns-based-routes.html)
- [WireGuard VPN](https://support.netcraze.ru/ultra/nc-1812/en/16937-wireguard-vpn.html)
- [Fail-safe configuration mode](https://support.netcraze.ru/ultra/nc-1812/en/26242-fail-safe-configuration-mode.html)
- [RCI through the HTTP Proxy service](https://support.netcraze.ru/ultra/nc-1812/en/55035-using-api-methods-through-the-http-proxy-service.html)
- [NDMS component installation/removal](https://support.netcraze.ru/ultra/nc-1812/en/16326-os-components-installation-removal.html)
- [Updating NDMS online](https://support.netcraze.ru/ultra/nc-1812/en/16054-updating-os-online.html)
