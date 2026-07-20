# Cursor native controls — opt-in templates

> **AI-first.** Permissions, sandbox, CLI, environment, Bugbot, ignore files, Browser tool.

## For agents

**When to read:** user asks to tighten/loosen agent permissions, sandbox, env injection, Bugbot, or indexing scope.

**Apply:**
- Essential bootstrap ships **no active** `permissions.json`, `sandbox.json`, `environment.json`, or `BUGBOT.md`.
- Copy from `templates/cursor/*.example` → project root or `.cursor/` **only after explicit user approval**.
- `environment.json` has **no `$schema`** key in our examples (Cursor-native shape).
- **Runtime secrets** live in env/CI — never committed. **Build secrets** same rule.
- **Browser tool:** local IDE vs Cloud Agents differ; authenticated or untrusted origins → Human Gate before navigation/actions (`/browser-verify`).

**Windows vs WSL2:**
- Controls apply per workspace root; WSL path vs Windows path = different workspaces.
- Hooks/doctor run where Cursor launches them — keep one primary surface per repo clone.

**Do not:** auto-copy examples in Essential/Full bootstrap; store credentials in skills or committed JSON.

---

## Control reference

| Control | Path | Purpose | Essential? |
|---------|------|---------|------------|
| **permissions.json** | `.cursor/permissions.json` | Allow/deny tool patterns | No — opt-in from example |
| **sandbox.json** | `.cursor/sandbox.json` | Shell/network sandbox policy | No — opt-in |
| **cli.json** | `.cursor/cli.json` or project CLI config | CLI agent defaults | No — opt-in |
| **environment.json** | `.cursor/environment.json` | Env vars for agent sessions (names/refs) | No — opt-in; no `$schema` in template |
| **BUGBOT.md** | `.cursor/BUGBOT.md` or repo `BUGBOT.md` | Bugbot/review instructions | No — opt-in |
| **.cursorignore** | `.cursorignore` | Exclude from AI context | User adds as needed |
| **.cursorindexingignore** | `.cursorindexingignore` | Exclude from index only | User adds as needed |
| **Browser tool** | Built-in MCP (Cursor) | Page verify, UI checks | Skill `/browser-verify`; Human Gate on auth/untrusted |

---

## Runtime vs build secrets (never committed)

| Secret type | Allowed in repo | Allowed in environment.json |
|-------------|-----------------|------------------------------|
| Runtime API keys / tokens | **No** | **No** — use `${env:VAR}` refs only |
| Build/deploy tokens | **No** | **No** |
| Public config (NODE_ENV=development) | Docs only | OK as non-secret example |

---

## Opt-in flow

1. Read this doc + [project-environment.md](project-environment.md).
2. Copy needed `templates/cursor/*.example` → drop `.example` suffix; place per Cursor docs.
3. Fill values via env interpolation — never literal secrets.
4. Run `scripts\validate-project-docs.ps1` if docs changed; doctor for env name sanity.

---

## Related

- Examples: `templates/cursor/` (Full bootstrap only)
- Browser verify skill: `.cursor/skills/browser-verify`
- MCP (separate): see [project-integrations.md](project-integrations.md) (Memory and MCP pointers); `mcp-security.md` — Full bootstrap / toolkit only

**Source:** [Cursor permissions](https://cursor.com/docs/agent/permissions) · [Sandbox](https://cursor.com/docs/agent/sandbox) · [Browser](https://cursor.com/docs/agent/browser) · SRC-029/030
