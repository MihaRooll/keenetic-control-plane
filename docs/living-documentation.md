# Living documentation

> **AI-first.** Product docs stay current via `docs/docs-map.json`, not a static README index alone.

## For agents

**When to read:** material doc/feature change; bootstrap questions; validator failures; `/maintain-project-docs`.

**Apply:**
- `docs/docs-map.json` is the **living index** — paths, titles, status, owners, tags ([docs-map-schema.md](docs-map-schema.md))
- After material doc or user-facing change → update map entries + run `maintain-project-docs` checklist
- Change/build touching docs → include **Docs Impact Record** in Task Contract return ([contracts.md](../.cursor/skills/autonomous-task/contracts.md))
- Validate: `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\validate-project-docs.ps1`
- Extended audit (links, unmapped surfaces, STATUS sync marker): `py -3.11 scripts\project-docs.py audit --project-root .`
- Sync machine marker only (never rewrite prose): `py -3.11 scripts\project-docs.py sync-marker --project-root . --write`
- Greenfield seeds map **day-0 only** via `new-project.ps1` (skip if file exists with parseable JSON)

**Do not:** overwrite an existing parseable `docs-map.json`; ship without validator when map or referenced paths changed.

---

## Model

```text
docs/docs-map.json     ← index (version, entries, rules)
        │
        ├── entries[].path → must exist on disk (planned: must NOT exist)
        ├── status: active | draft | deprecated | planned
        └── rules.update_on_change → agent expectation
        │
        ▼
maintain-project-docs skill + project-docs-lifecycle rule
        │
        ▼
validate-project-docs.ps1  (schema + path existence)
        │
        ▼
project-docs.py audit  (links, unmapped curated surfaces, sync-marker; advisory in doctor)
```

Unmapped audit scans a **curated** surface list (README, AGENTS, docs/**, templates, project-docs scripts) — not every repo `*.md`.

| Artifact | Role |
|----------|------|
| [docs-map-schema.md](docs-map-schema.md) | Normative field rules |
| `templates/docs-map.json` | Minimal day-0 seed |
| `templates/project-state.md` | Project-state seed with sync marker placeholder |
| `scripts/project-docs.py` | Audit / sync-marker / Docs Impact Record CLI |
| `scripts/project-docs.ps1` | PS5.1 wrapper for project-docs CLI |
| `maintain-project-docs` skill | When/how to update map |
| `project-docs-lifecycle.mdc` | Nudge after doc/feature edits |
| Docs Impact Record | Contract artifact for doc-touching work |

---

## Bootstrap behavior

| Mode | `docs-map.json` | Living docs assets |
|------|-----------------|---------------------|
| Essential | **not** seeded (like product-brief) | `living-documentation.md`, `docs-map-schema.md`, `project-integrations.md`, skill, rule |
| new-project (day-0) | seed from template if absent or empty | same + `docs/docs-map.json` |

Idempotent seed: skip if file exists with any parseable JSON (same policy as product-brief). Unparseable JSON is left untouched (warn only). See [bootstrap-scaffold.md](bootstrap-scaffold.md).

---

## Docs Impact Record

Required shape when change/build touches docs or user-facing surface:

```yaml
contract_id: task-slug
docs_paths_touched: []
docs_map_entries_updated: []
validator_run: yes|no
validator_exit_code: 0|null
notes: compact optional context
```

- `contract_id`: stable task slug shared across orchestration artifacts (see `.cursor/skills/autonomous-task/contracts.md` §8)
- `docs_paths_touched`: every doc/markdown path edited or added
- `docs_map_entries_updated`: `entries[].path` values changed in `docs/docs-map.json`
- `validator_run: yes` expected when map or referenced paths changed; attach exit code

---

## Checklist (material change)

1. Edit doc(s) or user-facing copy
2. Update matching `docs-map.json` entry (status/title/tags)
3. Add entry if new doc
4. Run `validate-project-docs.ps1` (exit 0)
5. Run `project-docs.py audit` (exit 0; use `--strict-unmapped` in CI if desired)
6. Attach Docs Impact Record to task return

---

## Related

- [docs-map-schema.md](docs-map-schema.md)
- [project-integrations.md](project-integrations.md)
- [bootstrap-scaffold.md](bootstrap-scaffold.md)
- [cursor-primitives.md](cursor-primitives.md) — rules/skills/context (`cursor-dynamic-context.md` — Full bootstrap / toolkit only)
