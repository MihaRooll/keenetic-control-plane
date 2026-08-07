# RCI policy contract

## For agents

| Rule | Requirement |
|---|---|
| Boundary | Domain/API **never** expose Keenetic JSON or raw RCI; only vendor-neutral intents via `RouterControlPort` |
| Allowlist | Deny-by-default **capability families** (see §2); literal NC-1812 command shapes **unknown/provisional** until recorded evidence |
| Writes blocked when | Unknown firmware/capability/profile field, identity mismatch, stale/missing evidence, uncertified capability, closed mutation window — see [`HARDWARE_GATES.md`](HARDWARE_GATES.md) |
| Lifecycle | Unified order in §5; **Confirm** before apply; **Fail-safe Configuration** mandatory for disruptive writes — **not** transactional atomicity |
| Serialization | One mutation job per `RouterId`; read-only may parallelize outside active Fail-safe session |
| Evidence | Legacy fixtures from [`LEGACY_MAP.md`](../LEGACY_MAP.md) are old-device behavioral evidence only |
| Milestones | M0–M8 per ADR-0005; **P3 topology safety closure complete** (2026-07-23) — shared Certified registry wiring, Gate D default-deny, explicit `source_address` bind for overlapping-subnet labs; **next major phase:** full operator web UI (`operator-web-ui-full-coverage` per [`STATUS.yaml`](../STATUS.yaml) `next_task`); **parallel deferred:** VPN routing live apply (offline preview only); Gate B **completed_failed**; `write_shapes_registered` false; AWG/routes/LTE parallel deferred |
| Trace | ADR-0002/0004/0005, [`ROADMAP.md`](ROADMAP.md), [`CANONICAL.md`](../CANONICAL.md) |

---

## 1. Vendor-neutral boundary

`NetcrazeRciAdapter` (и будущий transport) — единственное место, где существуют RCI JSON, Digest auth, `"continued"` polling и command-level errors. Domain, application, API DTO, plans, jobs и audit оперируют:

- `RouterId`, fingerprint, capability certification status;
- vendor-neutral mutation intents (например «ensure managed AWG assignment», «apply managed route delta»);
- normalized errors (`IdentityMismatch`, `CapabilityUnknown`, `TransportAuthExpired`, …).

Запрещено:

- raw RCI в SQLite, plan diff, job payload, API response;
- endpoint «send arbitrary RCI»;
- silent mapping legacy KeeneticHttpHelper bodies на NC-1812 без gate B evidence.

**Sealed write redaction (defense-in-depth):** `command_for` / sealed bodies may carry secrets only inside the adapter dispatch path. Operator/API/log/test surfaces use `command_redacted_for` (Wi‑Fi AP/station, WireGuard) and `redact_sealed_cli_command` / `redact_sealed_nested_body` (`sanitize.py`) at fake-transport accumulation and error classification boundaries. `FailSafeStatusEntry.message` and `SealedRciWriteRequest.body` are excluded from `repr`.

## 2. Capability-family allowlist (deny-by-default)

Automated write dispatch разрешён только для **семейств**, прошедших **Gate B** write certification на exact certification tuple (см. [`HARDWARE_GATES.md`](HARDWARE_GATES.md)). До certification семейство остаётся observe-only или blocked.

| Family | Domain scope (vendor-neutral) | Write preconditions |
|---|---|---|
| **observe / identity** | Fingerprint, firmware/components snapshot, targeted reads | Read-only; Gate A for transport; never mutates |
| **wifi** | SSID/security/bindings per managed segment policy | Gate B + Fail-safe + ownership |
| **vlan** | Tagged/untagged port and bridge fields | Gate B + Fail-safe + ownership |
| **firewall** | Inter-segment permit/deny rules | Gate B + Fail-safe + negative tests recorded |
| **AmneziaWG** | Single active AWG assignment v1 | Gate B AWG checklist; unknown profile fields fail closed |
| **routes** | Managed public destinations only | Gate B + route benchmark ceiling |

Семейства вне таблицы — **deny** для automated writes (manual NDMS UI не входит в contract).

Literal RCI object names, field paths и POST bodies для NC-1812 **не фиксируются** этим документом. Они остаются **provisional hypotheses** до sanitized fixtures в evidence package. См. [`COMPATIBILITY.md`](../COMPATIBILITY.md) и [`CANONICAL.md`](../CANONICAL.md) §9.

## 3. Transport, errors, async continuation (certification hypotheses)

Следующие правила — **target adapter contract**; на NC-1812 они подтверждаются только Gate A/B evidence:

| Topic | Target behavior | Evidence status |
|---|---|---|
| Transport | Authenticated encrypted local RCI: HTTPS with certificate validation **or** host-key-pinned SSH tunnel to verified router management HTTP (port 80); Hub HTTPS ≠ router RCI transport ([`ARCHITECTURE.md`](../ARCHITECTURE.md), ADR-003) | Lab required |
| Auth | Digest challenge; session/cookie; **one** synchronized re-auth on 401 | Hypothesis until fixture |
| HTTP vs command errors | Normalize command-level failure независимо от HTTP 200 | Hypothesis |
| Async continuation | Если `"continued": true`, adapter polls до terminal state или timeout | Hypothesis ([`CANONICAL.md`](../CANONICAL.md) §4.7) |
| Timeouts | Bounded; partial response → `TransportIncomplete`, not success | Required design |
| Identity on every mutation | Model + serial/MAC/fingerprint match enrolled `RouterId` | Domain invariant |

Legacy [`LEGACY_MAP.md`](../LEGACY_MAP.md): `KeeneticHttpHelper` и PowerShell tools доказывают **старое** устройство; их JSON shapes — **recorded fixtures для strangler**, не NC-1812 certification.

### Gate A frozen RCI allowlist (Netcraze read-only adapter)

Deny-by-default; exactly **four** bounded reads for Gate A transport (2026-07-21 offline code):

| Method | Path | Frontend bundle trace (dotted token) | Payload policy |
|---|---|---|---|
| GET | `/rci/show/system` | `show.system` | Legacy/telemetry; observed shape ignores for claims |
| POST | `/rci/components/list` | `components.list` | Canonical raw firmware from `firmware.version` |
| GET | `/rci/show/identification` | `show.identification` | Defensive top-level keys only; serial/servicetag hashed at boundary; optional `hwid` (hardware model ID, not unique physical ID); raw cid/mac not parsed |
| GET | `/rci/show/version` | `show.version` | Defensive fields: `hw_id`, display metadata, `release`/`version` (must agree when both present), `sandbox`, `region`, nested `ndm.exact`/`bsp.exact`; canonical model = `hw_id`; NDM build from `ndm.exact` required for completeness; flat `build` display fallback only |

Internal `/auth` remains transport plumbing (not counted in allowlist). Response body schemas for identification/version are **unobserved** until sanitized live fixtures; parser is runtime-defensive. Evidence never exposes raw physical IDs or physical digests — only `physical_identifier_source: show.identification_digest` when present.

**Sealed write shapes (product adapter, fail-closed):** besides fixed fail-safe/system bodies and sealed `[{"parse":"<cli>"}]` templates (interface up/down, Wi-Fi AP, WireGuard path-style — **path-style peer ops compile offline only**; explicit intent `peer_rci_shape=path_style` → **422** `peer_rci_shape_unsupported` at domain/API; path-style peer grammar **REJECTED** live 2026-07-24 on NC-1812 5.01.C.1.0-0), the Netcraze adapter accepts an **additive** bounded nested JSON body for AWG peer upsert: `interface.Wireguard[5-9].wireguard.peer[]` — array of peer objects with required `"key"` (pubkey) and allowlisted nested fields: `endpoint` (`{address}`), `allow-ips` (array of `{address, mask}` with dotted IPv4 netmask), `keepalive-interval` (`{interval}`), `preshared-key` (optional string). Selected by intent `peer_rci_shape=nested_rci` (default since 2026-07-24; only accepted shape at runtime). Shape follows ivansible/ndm-wireguard show-rc write template (read≈write). Nested peer write **device-verified accepted** on NC-1812 5.01.C.1.0-0 (2026-07-24 re-verify; evidence `data/artifacts/awg-peer-nested-rci-live-reverify-192.168.2.1-20260724.json`). No generic/raw RCI passthrough. `write_shapes_registered` remains **false** — evidence toward Gate B, NOT formal registration.

## 4. Identity, capability, freshness, ownership preconditions

Перед созданием или dispatch любого write plan adapter **must** verify:

1. **Identity** — enrolled fingerprint совпадает с live read; mismatch → hard abort, no dispatch ([`DOMAIN_MODEL.md`](../DOMAIN_MODEL.md) `Router`).
2. **Capability** — `RouterCapability.certification_status` ≥ `WriteCertified` для каждого затронутого family; иначе fail closed.
3. **Firmware tuple** — exact model + firmware/build/channel + component-set digest; raw `5.01` остаётся **unclassified** ([`COMPATIBILITY.md`](../COMPATIBILITY.md)).
4. **Freshness** — plan основан на **fresh** `RouterObservation` (`now <= valid_until`, identity OK); stale observation → new observe required.
5. **Ownership** — только `ManagedResource` или явно adopted resources; unmanaged never pruned ([`CANONICAL.md`](../CANONICAL.md) §4.9).
6. **Mutation window** — **Lab path:** Gate C lab window open **and** operator authorization (plus Gate B per family). **Production path:** Gate D satisfied (plus Gate B per family); **does not** require an open Gate C window ([`HARDWARE_GATES.md`](HARDWARE_GATES.md)). **Phase 0b (historical):** all gates closed. **Current posture (2026-07-22):** Gate **A** may be open for read-only observe; write mutations still require Gate **B** WriteCertified per family plus applicable **C**/**D** paths — currently Gate **B** is **completed_failed** (not WriteCertified); Gates **C** and **D** **closed** → **no write dispatch**.

## 5. Unified mutation lifecycle

Единый порядок для опасных операций (VPN, Wi-Fi, VLAN, firewall, routes):

```text
preflight
  → identity-check
  → observe (fresh snapshot + capability reference)
  → backup (non-empty, hash-verified, router-bound artifact)
  → plan-preconditions (desired revision, observation ETag/digest, managed merge diff)
  → Confirm (operator binding — see SECURITY_OPS)
  → begin Fail-safe Configuration (global router safety mode)
  → apply (minimal idempotent steps per family)
  → read-back
  → verify (functional + postconditions)
  → save startup configuration OR compensate
```

**Confirm** — отдельный шаг до apply; не заменяет Fail-safe и не является password re-entry ([`SECURITY_OPS.md`](SECURITY_OPS.md)).

**Fail-safe Configuration** (primary term; alias **Safe Configuration** в vendor docs) — mandatory Netcraze global mode для disruptive writes. Это **не** transactional two-phase commit: applied changes live outside saved startup config until explicit save; timeout may reboot to last saved config ([`CANONICAL.md`](../CANONICAL.md) §5.6–5.10).

On failure after apply: best-effort **compensate**; if all management sessions lost — rely on Fail-safe timeout/reboot rollback. Rollback = compensating operation, not atomicity guarantee.

## 6. Managed merge, stale plans, idempotency

- **Managed merge** — planner изменяет/удаляет только resources с ownership record Router Control; `prune=false` default ([`DOMAIN_MODEL.md`](../DOMAIN_MODEL.md)).
- **Stale plan rejection** — перед lease/apply сверяются: identity, desired `If-Match`/revision, observation version, plan digest, expiry, certification still valid. Любое расхождение → reject, new observe + plan.
- **Idempotency** — каждый mutation request несёт `Idempotency-Key`; duplicate digest returns same operation; same key + different digest → conflict (ADR-0002). SQLite records and retention — [`PERSISTENCE_CONTRACT.md`](PERSISTENCE_CONTRACT.md) §6.
- **Per-RouterId serialization** — не более одного active mutation job; durable lease/claim across workers ([`PERSISTENCE_CONTRACT.md`](PERSISTENCE_CONTRACT.md) §4–5).

## 7. Backup policy

Перед disruptive mutation:

- backup artifact **non-empty**, content hash recorded, bound to router identity fingerprint;
- route inventory hot path — targeted reads (e.g. `show/ip/route` pattern), **not** full `show/running-config` hot path ([`CANONICAL.md`](../CANONICAL.md) §7 (`show/running-config` timeout), [`LEGACY_MAP.md`](../LEGACY_MAP.md));
- startup-config backup — separate high-risk operation with own checklist;
- backup existence alone ≠ restorability; restore rehearsal — Gate B/C evidence.

## 8. Legacy fixture limits

| Source | Allowed use | Forbidden use |
|---|---|---|
| `KeeneticHttpHelper` route/VPN bodies | Characterization tests, strangler oracle | Assume NC-1812 compatibility |
| `Keenetic-VpnProfileTools.ps1` convert | Recorded adapter development | Domain DTO or plan content |
| `Wireguard0` hard-code | Historical fixture ID | Default interface locator |
| Old router HTTP 200 success trust | — | Write success without read-back verify |

## 9. Links

- Test strategy and evidence lanes: [`TEST_STRATEGY.md`](TEST_STRATEGY.md)
- HTTP/API surface: [`API_CONTRACT.md`](API_CONTRACT.md)
- Hardware certification: [`HARDWARE_GATES.md`](HARDWARE_GATES.md)
- Security, Confirm, secrets: [`SECURITY_OPS.md`](SECURITY_OPS.md)
- Index: [`README.md`](README.md)
