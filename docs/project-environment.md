# Project environment — surfaces and secrets

> **AI-first.** Where agents run, what they touch, and how runtime vs build secrets differ.

## For agents

**When to read:** cross-PC setup, Cloud vs local IDE, where to put secrets, Windows/WSL2 quirks.

**Apply:**
- Classify work by **surface** before choosing tools (Browser MCP, MCP servers, shell, git).
- **Runtime secrets** → env / secret store / CI — never committed.
- **Build secrets** → CI/CD or local `.env` gitignored — never in repo or hook output.
- Run `/setup-project-environment` or `scripts\project-doctor.ps1` before proposing installs or auth flows.
- Windows: `$env:HOME = $env:USERPROFILE` for papercuts; prefer repo cwd for doctor/hooks.

**Do not:** commit `.env`, tokens, or active `.cursor/{permissions,sandbox,environment}.json`; assume Cloud Agents see only repo + configured env.

---

## Surface matrix

| Surface | What agents use | Secrets / runtime vs build | Windows / WSL2 notes |
|---------|-----------------|----------------------------|----------------------|
| **Local IDE** | Rules, skills, hooks, terminal, native Browser MCP, project MCP | Runtime: User/process env, OS keychain via Human Gate. Build: none in repo. | Native Windows paths; hooks run PowerShell 5.1. WSL2: run doctor in same surface you code in. |
| **CLI** | `cursor` / agent CLI, headless scripts | Runtime: CLI config + env refs. Build: CI tokens in pipeline only. | Set HOME on Windows; avoid mixing WSL git with Windows Cursor without path awareness. |
| **Cloud Agents** | Repo snapshot, configured MCP, automation env | Runtime: dashboard-injected env only. Build: N/A in workspace. | No local filesystem; Browser/authenticated flows need Human Gate. |
| **Automation / SDK** | `@cursor/sdk`, GitHub Actions, webhooks | Runtime: automation-scoped secrets. Build: deploy keys in CI vault. | Treat automation memory as poisonable; not general product memory. |
| **SCM** | git, PRs, branches | Never commit secrets; use `.gitignore` for local env files. | `core.autocrlf` / line endings — check `.gitattributes`. |

---

## Runtime vs build secrets

| Kind | Examples | Where | Committed? |
|------|----------|-------|------------|
| **Runtime** | API keys in session, OAuth tokens, PAT in env | Process env, secret manager, CI vars | **Never** |
| **Build** | Signing keys, deploy tokens, npm tokens for publish | CI/CD secret store | **Never** (refs like `${env:VAR}` OK in templates) |
| **Non-secret config** | Node version, package manager, doctor checks | `docs/project-state.md`, repo files | Yes |

---

## Cross-PC checklist

1. Clone/open repo on target machine (Windows or WSL2 — pick one primary surface).
2. `powershell -NoProfile -File scripts\project-doctor.ps1` — advisory if `docs/project-state.md` missing.
3. `/setup-project-environment` — propose toolchain steps; Human Gate before system/auth/external changes.
4. Opt-in native controls from `templates/cursor/*.example` → copy/rename locally; not shipped in Essential.
5. Optional local harness plugin (isolated or default):
   ```powershell
   # Default user profile (Human Gate — writes under %USERPROFILE%\.cursor):
   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\install-harness-plugin.ps1
   # Isolated temp root (no real profile writes):
   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\install-harness-plugin.ps1 -LocalPluginsRoot <isolated-temp>\.cursor\plugins\local
   # Offline proof of both paths (G/P/E/F/D scenarios):
   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\smoke-portability.ps1
   ```
6. Offline portability proof (toolkit clone): `scripts\smoke-portability.ps1` — isolated temp roots, no network; marker `PORTABILITY_SMOKE_PASS`.

**Session context:** bootstrapped `session-start` hook injects exact `phase` and first unchecked `next_checks` from `docs/project-state.md` (≤1200 chars).

---

## Related

- Native controls: [cursor-native-controls.md](cursor-native-controls.md)
- Integrations matrix: [project-integrations.md](project-integrations.md)
- Project phase: [project-state.md](project-state.md)

**Source:** [Cursor docs — Cloud Agents](https://cursor.com/docs/cloud-agent) · [Hooks](https://cursor.com/docs/hooks) · SRC-029
