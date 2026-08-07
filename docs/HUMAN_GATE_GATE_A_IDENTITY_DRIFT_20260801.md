# Human Gate Packet — Gate A identity drift 2026-08-01 (RESOLVED: our defect, not the device)

## For agents

| Fact | Value |
|---|---|
| Status | **RESOLVED — no rebind was performed and none is needed** |
| Root cause | Defect in our own identity parser, **not** a change on the router |
| Device tuple | **Matches the recorded tuple in all nine compared fields** after the parser fix |
| Gate status changed? | **No.** Gate A remains `open` / `ReadOnlyCertified`; B `completed_failed`; C/D `closed` |
| Certified tuple rewritten? | **No.** [`gate-a-certification.json`](gate-a-certification.json) is untouched and was correct all along |
| Remaining open item | Recorded Gate A **evidence is older than the 24 h freshness rule**, so live tooling still fails closed. Refreshing it is a separate, small decision — see §5 |

## 1. What was observed, and what it actually meant

A read-only pinned Gate A probe on 2026-08-01 reported that `component_set_digest` and
`device_fingerprint` differed from the recorded tuple, while model, firmware, NDM/BSP builds,
update channel, region and the SSH host key all matched. Live writes went fail-closed.

Investigation established that **the router had not changed at all**. The digest was being
computed over the wrong set of components.

## 2. The defect

`router_control/adapters/netcraze/identity.py` decided whether a component was installed like
this:

- if the entry carried an `installed` key, its value was pushed through a boolean parser. On
  this firmware that value is a **version string** (`base` → `"5.01.C.1.0-0"`), which matched
  neither the true-set nor the false-set, so the result was "unknown" and the component was
  **excluded**;
- if the entry had **no** `installed` key but did have a `version`, the component was counted
  as **installed** — but on this firmware a bare `version` means "available in the catalogue,
  not installed".

Measured live on the device: 40 entries carried an `installed` marker, 54 entries were counted
as installed by the parser, and **the two sets did not overlap at all**. In other words the
Gate A component digest fingerprinted the vendor's *catalogue* rather than the device's
installed set — so a catalogue refresh on the vendor side moved our device identity with
nothing whatsoever happening on the hardware.

Supporting evidence that this is the whole story: an exhaustive search over every single and
paired add/remove/swap of components failed to reproduce the recorded digest from the observed
set, which is inconsistent with "a component or two changed on the device" and consistent with
"a different set entirely was being hashed".

## 3. Proof that the device is unchanged

After the parser was corrected (`component-set-v2`), a fresh pinned probe was run from
`192.168.2.10` against `192.168.2.1`:

| Field | Result |
|---|---|
| model, firmware_version, ndm_build, bsp_build, update_channel, region | match |
| `component_set_digest` | **match** — `sha256:23bd35bc1bcbf8523495ff7fb37ef2ded597ce9d07b9c1c968ae1f9e4aa4de80` |
| `device_fingerprint` | **match** — `sha256:c34adec44383c0dc1f31833bb6d7885a8e9af454722af0c6bfba3761ac71e6fd` |
| `ssh_host_key_fingerprint_sha256` | match |

Drifted fields: **0 of 9**. Evidence artifact
`data/artifacts/gate-a-probe-post-parser-fix-20260801.json`,
sha256 `f3dd1c328edb6546925e6f19cb0e2f62bc213e66942975508feebe8304e187d2`,
recorded at `2026-08-01T21:28:28.785272+00:00`, source `192.168.2.10`,
digest algorithm `component-set-v2`.

## 4. Why the earlier caution was right

The original packet asked whether to rebind the certified tuple. Rebinding would have written
the catalogue-derived digest `sha256:479a368c…` into the certified record and destroyed the
correct value, while leaving the parser defect in place and un-diagnosed. The correct fix was
in our code, not in the certification record.

Two supporting facts were also established: `wireguard` **is** installed (consistent with the
2026-07-31 campaign), and `chilli` (captive portal) is **not** installed. Under the old parser
both readings were inverted.

## 5. The one decision still outstanding

The recorded Gate A evidence dates from 2026-07-31 and is therefore **stale under the 24 h
freshness rule**, so probes and live tooling still refuse to run
(`Gate A opening freshness expired`). Refreshing it means pointing the evidence fields in
[`STATUS.yaml`](STATUS.yaml) and [`gate-a-certification.json`](gate-a-certification.json) at
the fresh artifact named in §3.

This is **not** a rebind: the certified tuple itself does not change by a single character —
only the evidence pointer, its digest and its timestamp. The prior evidence chain is preserved
as history. The agent did not do this on its own initiative because it touches the Gate A
records, and the standing instruction is to stop when the level is ambiguous.

| Option | Consequence |
|---|---|
| Refresh the evidence pointer to the fresh artifact | Live read and bounded write work becomes possible again; certified tuple unchanged |
| Leave it stale | Everything live stays fail-closed; offline work continues normally |

## 6. What was and was not done to the device

Read-only operations only: two pinned Gate A probes and one allowlisted `components/list`
read. No configuration was written, no backup was needed because nothing was mutated, no
secrets were recorded, and every artifact is sanitized.
