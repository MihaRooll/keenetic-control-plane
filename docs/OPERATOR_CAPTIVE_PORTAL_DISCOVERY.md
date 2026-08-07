# Operator runbook — NC-1812 greenfield captive portal write-shape discovery

## For agents

| Topic | Rule |
|---|---|
| When to read | Before planning captive portal write-shape classification, T4 component-install campaigns, or Chilli RCI modeling on NC-1812 |
| Scope | Greenfield captive-portal discovery — documentation-sourced candidate write-shape only; **no** live capture (feature not configured on device) |
| Status | DOCUMENTATION-SOURCED candidate — **NOT** device-certified; does **not** set `write_shapes_registered=true`; does **not** imply WriteCertified |
| Gates | A open ReadOnlyCertified (unchanged); B `completed_failed`; C/D **closed**; **not WriteCertified**; `write_shapes_registered` remains **false** |
| Next | T4 for component install (`components` → `install chilli` → `commit`, rebuild OS → device auto-reboot) + live Chilli config under exact Human Gate Packet |

---

## 1. Purpose

Per-feature discovery for **captive portal RCI write-shape** classification on the Gate A lab tuple (`NC-1812`, firmware `5.01.C.1.0-0`). This document records a **documentation-sourced** candidate shape for Coova-Chilli on KeeneticOS/NDMS — it does **not** register write shapes, claim WriteCertified, or open Gates B/C/D.

Discovery is **classification only** — it does **not** infer write safety, provider reachability, or transport promotion beyond existing Gate A ReadOnlyCertified scope.

---

## 2. Current codebase state

**Greenfield.** Partial domain hint only:

| Item | State |
|---|---|
| `CaptivePortalMode` enum (`Disabled` / `Enabled`) | Present on `WifiIntent` (`router_control/domain/network_intents.py`) |
| RCI captive model / typed op / WRITE_ALLOWLIST | **Absent** |
| `preset_readiness` | Forces `CaptivePortalMode.DISABLED` on Guest zone |
| Live RO capture | **None** — captive portal not configured on dedicated lab device |

Captive portal is **not** an AccessPoint boolean; it requires a separate `Chilli0` interface and (typically) an external UAM/RADIUS provider.

---

## 3. Candidate write-shape (documentation-sourced, NOT certified)

> **Status:** DOCUMENTATION-SOURCED — **NOT** device-certified. Does **not** set `write_shapes_registered=true`. Does **not** imply WriteCertified.

Keenetic/Netcraze captive portal = **Coova-Chilli**. Router Mode only.

### Component install (T4 — out of scope for discovery)

Component must be present before Chilli CLI is available:

```text
components
install chilli
commit
```

`commit` rebuilds NDMS/KeeneticOS and **auto-reboots** the device — treat as **component-install + reboot (T4)** with encrypted pre-change backup and Gate A re-certification afterward.

### Key CLI — `interface Chilli0` with `chilli *` sub-commands

| Command | Role |
|---|---|
| `chilli dhcpif <Bridge1\|Guest>` | Bind captive DHCP to guest bridge (typical: `Bridge1`) |
| `chilli profile <name>` | Provider profile (web UI lists ~20 pre-integrated providers) |
| `chilli uamserver <url>` | UAM server URL (external provider) |
| `chilli uamhomepage <url>` | UAM homepage URL |
| `chilli uamsecret <SECRET>` | UAM shared secret — vault only |
| `chilli uamport` | UAM port (default **3990**) |
| `chilli uamallowed` / `chilli uamdomain` | Walled-garden allow list |
| `chilli radius <s1> [<s2>]` | RADIUS server host(s) |
| `chilli radiussecret <SECRET>` | RADIUS shared secret — vault only |
| `chilli radiusnasid <id>` | RADIUS NAS identifier |
| `chilli radiusauthport` | RADIUS auth port (default **1812**) |
| `chilli radiusacctport` | RADIUS accounting port (default **1813**) |
| `chilli lease` | Client lease seconds (default **3600**, max **259200**) |
| `chilli macauth` | MAC authentication enable |
| `chilli macpasswd <SECRET>` | MAC auth password — vault only |
| `chilli dns` | DNS settings for captive clients |
| `up` / `down` | Enable/disable Chilli interface |

**Documentation note:** official docs describe captive portal as tied to an **external UAM/RADIUS provider**. A simple provider-less splash page is **not** documented.

### Minimal enable sequence (Guest / Bridge1 — documentation-sourced)

```text
interface Chilli0
  chilli dhcpif Bridge1
  chilli profile <provider-profile>
  chilli uamserver <url>
  chilli uamhomepage <url>
  chilli uamsecret <SECRET>
  chilli radius <s1>
  chilli radiussecret <SECRET>
  chilli radiusnasid <id>
  up
system configuration save
```

Replace `<SECRET>`, `<url>`, and provider parameters from the external captive-portal provider account — never embed values in product surfaces or docs.

---

## 4. RCI model (inferred, LOW confidence)

| Operation | Inferred mapping | Confidence |
|---|---|---|
| Write CLI | `POST /rci/` with `{"parse":"<cli>"}` | **LOW–MEDIUM** — prefer sealed typed ops when implemented |
| Nested JSON body | Docs-silent for Chilli subtree | **LOW** |
| Read config | `GET /rci/interface?name=Chilli0` | **LOW** (inferred from interface read pattern) |
| Sessions / status | `show interface Chilli0 chilli` (CLI); RCI show path **docs-silent** | **LOW** |

---

## 5. SECRET fields

| Field | Role |
|---|---|
| `chilli uamsecret` | UAM shared secret — vault-only, never logged |
| `chilli radiussecret` | RADIUS shared secret — vault-only, never logged |
| `chilli macpasswd` | MAC authentication password — vault-only, never logged |
| Runtime login password | End-user captive login — out of router-control vault scope; never logged |

Treat Chilli secrets as **WifiIntent-adjacent** `credential_ref` fields when modeled — values forbidden in docs, fixtures, and artifacts.

---

## 6. Gates / T4

| Action | Tier |
|---|---|
| `components` → `install chilli` → `commit` (OS rebuild + auto-reboot) | **T4** — component install + reboot |
| Live Chilli configuration on device | **T4** — exact Human Gate Packet per campaign |
| External UAM/RADIUS provider reachability | Required for functional captive portal — outside router-control boundary |
| Captive portal as AccessPoint flag | **Invalid** — not a simple Wi-Fi boolean |

Gates A/B/C/D remain **unchanged** by this discovery document. `write_shapes_registered` remains **false**.

---

## 7. Deferred (T3): domain model + sealed op

Modeling captive portal beyond the current `CaptivePortalMode` Enabled/Disabled enum requires:

1. Domain entity / intent fields for Chilli parameters (provider profile, UAM/RADIUS refs, bridge bind).
2. Sealed Chilli write typed operation(s).
3. `WRITE_ALLOWLIST` entries with secret-field redaction.

**Minimum T3** — data-model + security boundary; requires **principal-arbiter (Sol) / human** approval before production writes. Execution blocked until implemented.

---

## 8. Sources

- [Netcraze NC-1812 — Captive portal](https://support.netcraze.ru/ultra/nc-1812/en/15226-captive-portal.html)
- [Keenetic — Captive portal](https://support.keenetic.com/starter/kn-1112/en/15226-captive-portal.html)
- [Netcraze NC-1812 — NDMS component description](https://support.netcraze.ru/ultra/nc-1812/en/16327-os-component-description.html) (Captive portal component)
- Keenetic CLI Reference OS 5.0 (KN-1011) — `interface Chilli0` / `chilli` command group
- [Netcraze NC-1812 — NDMS component installation/removal](https://support.netcraze.ru/ultra/nc-1812/en/16326-os-components-installation-removal.html) (`commit` → rebuild + reboot)
- [Keenetic FAQ — component installation and updating KeeneticOS](https://help.keenetic.com/hc/en-us/articles/360001321080-Frequently-asked-questions-on-component-installation-and-updating-KeeneticOS)

---

## Related references

- [`OPERATOR_WIFI_DISCOVERY.md`](OPERATOR_WIFI_DISCOVERY.md) — Wi-Fi candidate shape; notes Chilli is not an AP flag
- [`OPERATOR_AWG_DISCOVERY.md`](OPERATOR_AWG_DISCOVERY.md) — parallel per-feature discovery pattern
- [`OPERATOR_RCI_TYPED_OPS.md`](OPERATOR_RCI_TYPED_OPS.md) — sealed write CLIs (distinct from greenfield discovery)
- [`STATUS.yaml`](STATUS.yaml) — gates unchanged; WriteCertified NOT claimed
