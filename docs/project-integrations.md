# Project integrations — living docs

> **AI-first.** How products wire living documentation and opt-in MCP after bootstrap.

## For agents

**When to read:** Essential vs day-0 setup; plugin vs on-disk harness; MCP opt-in; memory/Obsidian guides.

**Apply:**
- **Essential bootstrap** copies living-docs **assets** (docs + skill + rule), **not** `docs-map.json`, **not** active MCP, **not** `templates/mcp`
- **new-project** (greenfield) seeds `docs/docs-map.json` from `templates/docs-map.json` only if absent or whitespace-empty; never overwrite any existing parseable (or unparseable) `docs-map.json`
- **Local plugin** (`cursor-project-harness` 0.5.0+) mirrors `maintain-project-docs`, `configure-project-integrations`, `browser-verify`, `setup-project-environment`, `project-docs-lifecycle`
- After material doc/feature change → `/maintain-project-docs` or follow `project-docs-lifecycle` rule
- MCP opt-in → `/configure-project-integrations` (propose/dry-run); implementer applies after confirmation
- Validate docs: `scripts/validate-project-docs.ps1` (shipped Essential + Full) · MCP profiles: `scripts/validate-mcp-profiles.ps1` (**Full** or toolkit only)
- `/configure-project-integrations` and MCP profile templates require **Full bootstrap**, **local plugin**, or **toolkit** — not Essential alone

**Do not:** add active `.cursor/mcp.json` in Essential; ship memory/mcp-security guides or MCP templates in Essential.

---

## Integration matrix (Wave 4)

| Surface | Living docs | Native templates | Strict hooks | Living-eval | Doctor | Stage / state | browser-verify | setup skill | MCP profiles | configure skill | Validator |
|---------|-------------|------------------|--------------|-------------|--------|---------------|----------------|-------------|--------------|-----------------|-----------|
| Essential bootstrap | yes (docs + maintain skill + rule) | no (docs only) | **no** | **no** | yes (`project-doctor.ps1`) | yes (`docs/project-state.md`) | yes (skill) | yes (skill + doctor) | no | **no** (requires Full bootstrap, local plugin, or toolkit) | yes (`validate-project-docs.ps1` on-disk) |
| new-project day-0 | yes | no | no | no | yes (script copied) | yes (seed if absent) | yes | yes | no | no | no |
| Local plugin 0.5.0 | maintain + configure + browser + setup | — | **no** | **no** | — (on-disk script) | — (on-disk state) | yes | yes | — | yes (Cursor-loaded) | — |
| Full bootstrap | all docs + scripts | yes (`templates/cursor`) | yes (`templates/hooks` opt-in) | yes (`tests/living-eval` + `validate-living-evals.ps1`) | yes | yes | yes (skills) | yes | yes (`templates/mcp`) | yes (on-disk skills) | yes (`validate-mcp-profiles.ps1`, `validate-living-evals.ps1`) |
| Toolkit only | all | all templates | templates + evidence skill | manifest + validator | yes | yes | yes | yes | yes | yes | all validators |

**Wave 4 truth:** strict hook templates and living-eval ship in **Full only**; never in Essential, never in plugin. Promotion: `harness-evidence-and-enforcement.md` (Full bootstrap / toolkit) + `/review-harness-evidence` (toolkit-only skill).

## Integration matrix (Wave 3 — reference)

| Surface | Living docs | Native templates | Doctor | Stage / state | browser-verify | setup skill | MCP profiles | configure skill | Validator |
|---------|-------------|------------------|--------|---------------|----------------|-------------|--------------|-----------------|-----------|
| Essential bootstrap | yes (docs + maintain skill + rule) | no (docs only) | yes (`project-doctor.ps1`) | yes (`docs/project-state.md`) | yes (skill) | yes (skill + doctor) | no | no | no |
| new-project day-0 | yes | no | yes (script copied) | yes (seed if absent) | yes | yes | no | no | no |
| Local plugin | maintain + configure + browser + setup | — | — (on-disk script) | — (on-disk state) | yes | yes | — | yes (Cursor-loaded) | — |
| Full bootstrap | all docs + scripts | yes (`templates/cursor`) | yes | yes | yes (skills) | yes | yes (`templates/mcp`) | yes (on-disk skills) | yes (`validate-mcp-profiles.ps1`) |

---

## Integration matrix (Wave 2 — reference)

| Surface | Living docs | Memory / Obsidian | MCP profiles | configure skill | Validator |
|---------|-------------|-------------------|--------------|-----------------|-----------|
| Essential bootstrap | yes (docs + maintain skill + rule) | pointer only (this doc) | no | no | no |
| new-project day-0 | yes | no | no | no | no |
| Local plugin | maintain + configure skills + rules | — | — | yes (Cursor-loaded) | — |
| Full bootstrap | all docs + scripts | yes (Full `docs` copy) | yes (`templates/mcp`) | yes (on-disk skills) | yes (`validate-mcp-profiles.ps1`) |

---

## Essential flow (existing folder)

```powershell
.\scripts\bootstrap-into-project.ps1 -TargetPath C:\work\my-app -Mode Essential
```

Copies: living-docs assets + orchestration surface + Wave3 environment docs/skills/doctor + `validate-project-docs.ps1`. **Absent:** `templates/mcp`, `templates/cursor`, `templates/hooks`, `tests/living-eval`, `validate-living-evals.ps1`, `.cursor/mcp.json`, active native configs, `configure-project-integrations`, `memory-and-obsidian.md`, `mcp-security.md`, `review-harness-evidence` skill, `validate-mcp-profiles.ps1`.

Create `docs/docs-map.json` manually or re-run greenfield `new-project` pattern when starting fresh.

---

## Full / opt-in flow

```powershell
.\scripts\bootstrap-into-project.ps1 -TargetPath C:\work\my-app -Mode Full
```

Adds: full `docs/` (includes `memory-and-obsidian.md`, `mcp-security.md`, `harness-evidence-and-enforcement.md` — Full bootstrap only), `templates/mcp/`, `templates/cursor/`, `templates/hooks/` (strict opt-in), `tests/living-eval/`, `scripts/validate-living-evals.ps1`, `scripts/validate-mcp-profiles.ps1`, all skills including `configure-project-integrations`. Does **not** auto-enable strict hooks — merge `hooks.strict.example.json` only after human signoff.

---

## Greenfield flow

```powershell
.\scripts\new-project.cmd -Name my-app -Goal "цель"
```

After Essential + brief/first-chat → seeds `docs/docs-map.json` and `docs/project-state.md` only if absent or whitespace-empty.

---

## Plugin flow

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\install-harness-plugin.ps1
```

Reload Cursor. Plugin supplies `maintain-project-docs`, `configure-project-integrations`, `browser-verify`, `setup-project-environment`; on-disk map, doctor, state, and MCP templates still live in product repo (Essential/Full bootstrap).

---

## Memory and MCP pointers

| Topic | Guide | Essential | Full |
|-------|-------|-----------|------|
| Authority ladder, Obsidian vault | `memory-and-obsidian.md` | no (pointer here) | yes |
| ReMe opt-in index | `reme-agent-memory.md` | note | yes |
| MCP security, placement, pins | `mcp-security.md` | no | yes |
| Profile templates | `templates/mcp/` | no | yes |
| Integration skill | `/configure-project-integrations` | no | plugin + Full skills |

---

## Related

- [living-documentation.md](living-documentation.md)
- [bootstrap-scaffold.md](bootstrap-scaffold.md)
- Plugin flow: see **Plugin flow** above; full guide `harness-as-cursor-plugin.md` (toolkit only)
