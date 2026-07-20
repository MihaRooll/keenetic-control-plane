# docs-map.json schema

> **AI-first.** Normative rules for `docs/docs-map.json`. Validator: `scripts/validate-project-docs.ps1`.

## For agents

**When to read:** create/edit `docs-map.json`; validator errors; maintain-project-docs skill.

**Apply:** UTF-8 JSON, no BOM; paths relative to repo root, forward slashes OK; every `entries[].path` must exist when validating a project tree **except** `status: planned` (those paths must **not** exist).

**Do not:** invent fields outside this schema; reference paths outside the product repo.

---

## Top-level object

| Field | Type | Required | Rules |
|-------|------|----------|-------|
| `version` | integer | yes | Must be `1` (only supported version) |
| `entries` | array | yes | May be empty; each item = entry object |
| `rules` | object | no | See rules object |

---

## Entry object

| Field | Type | Required | Rules |
|-------|------|----------|-------|
| `path` | string | yes | Relative path; no `..`; must exist on disk unless `status` is `planned` |
| `title` | string | yes | Non-empty, ≤120 chars |
| `status` | string | yes | One of: `active`, `draft`, `deprecated`, `planned` |
| `owners` | array of strings | yes | ≥1 owner; each non-empty, ≤64 chars |
| `tags` | array of strings | no | Each non-empty, ≤32 chars |

**`planned` semantics:** use only while the target file does **not** exist. Validator requires `planned` entries **not** exist on disk; all other statuses require the file to exist.

**Uniqueness:** `path` values must be unique within `entries`.

---

## Rules object

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `update_on_change` | boolean | `true` | Agents should update map when listed docs change |
| `validate_on_commit` | boolean | `false` | Optional CI hook hint (not enforced by harness) |

---

## Minimal valid example

```json
{
  "version": 1,
  "entries": [
    {
      "path": "docs/product-brief.md",
      "title": "Product brief",
      "status": "active",
      "owners": ["team"],
      "tags": ["day-0"]
    }
  ],
  "rules": {
    "update_on_change": true,
    "validate_on_commit": false
  }
}
```

Seed template: `templates/docs-map.json`.

---

## Validator checks

1. JSON parses
2. Required fields and enums per table
3. No duplicate `path`
4. Each `entries[].path`: `planned` → must **not** exist; all other statuses → must exist under project root
5. `-SelfTest` runs fixtures under `tests/project-docs/`

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\validate-project-docs.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\validate-project-docs.ps1 -ProjectRoot C:\work\my-app
```

---

## Related

- [living-documentation.md](living-documentation.md)
- [project-integrations.md](project-integrations.md)
