---
name: setup-project-environment
description: Настройка окружения проекта через doctor → detect PM/toolchain → propose → Human Gate перед system/auth/external → verify; запрет silent install.
---

# setup-project-environment

## Когда

- Новая машина / cross-PC clone
- Doctor WARN по toolchain или missing tools
- Пользователь просит «настрой окружение», Node/Python/package manager

## Шаги

1. Запусти doctor (read-only):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\project-doctor.ps1
```

2. **Detect** package manager / toolchain from repo files (`package.json`, `pnpm-lock.yaml`, `requirements.txt`, `Cargo.toml`, `.nvmrc`, etc.).
3. **Propose** bounded steps — list commands user or implementer will run; explain each.
4. **Human Gate** — STOP before:
   - system-wide installs (choco/winget/apt/brew)
   - auth / OAuth / credential entry
   - external network writes (publish, deploy)
5. После явного OK — implementer или user выполняет шаги; **никаких silent installs** от агента.
6. **Verify** — re-run doctor; update `docs/project-state.md` toolchain_notes if changed.

## Advisory mode

If `docs/project-state.md` missing — doctor may exit non-zero with WARN; bootstrap still OK. Offer to seed from `templates/project-state.md` when present (Full bootstrap) or copy minimal phase block manually.

## Policy (self-contained)

- Doctor prints **curated env summary** only; never dump all env var names; redact secret-shaped names/values.
- Missing optional tools (node, pwsh) → doctor exit **1** advisory; harness/git hard failures → exit **2**.
- Essential bootstrap ships doctor + `docs/project-environment.md` + `docs/project-state.md`; no `templates/cursor/` unless Full.

## Не делай

- `npm install -g`, `winget install`, etc. без explicit human approval
- Не печатай значения env vars matching `*(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)*`
- Не копируй active `permissions.json` / `sandbox.json` / `environment.json` без approval

## Связанное (product paths)

- `docs/project-environment.md` — surfaces matrix (Essential vs Full vs plugin)
- `docs/project-state.md` — phase / next_checks living snapshot
- `templates/cursor/*.example` — opt-in native controls (**Full bootstrap only**)
