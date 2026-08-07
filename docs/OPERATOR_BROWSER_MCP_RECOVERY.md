# Browser MCP recovery runbook (Windows)

> **AI-first.** Read this when the Cursor browser MCP is missing or broken. Fix is scripted and
> idempotent — do not re-derive the patches from memory, run the script.

## For agents

**When to read:** `cursor-ide-browser` is absent from the MCP server list, or `plugin-browse-browser`
tool calls fail with `ENOENT`, `EINVAL`, `EACCES`, `"Not connected"`, or `"error"` server status.
Also read when the operator reports "browser MCP stopped working again" — this has recurred
across Cursor account switches on this machine (operator's working theory; not mechanically
proven that account switching is the trigger, but it is the only variable the operator has
observed changing between working and broken sessions).

**Apply:**
1. Run `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\repair-browser-mcp.ps1 -SelfTest`.
2. Read the output. `OK` + `Self-test PASSED` means the plugin's own daemon and CLI work end to end.
3. If the script printed `ACTION REQUIRED: toggle "plugin-browse-browser" off and on in Settings -> MCP`,
   that one step cannot be automated (see "Why one manual step is unavoidable" below) — ask the
   operator to do it, then verify with a live `browser_status` / `browser_navigate` MCP tool call
   from the agent side, not just the script's self-test (the script only proves the standalone CLI
   works; it does not prove Cursor's MCP client has reconnected).
4. If the script exits non-zero (`FAIL`), do not hand-patch blind — the failures list names exactly
   which snippet was not found, which almost always means the plugin shipped a new version and the
   patch targets in `scripts/repair-browser-mcp.ps1` need updating for the new file layout. Diagnose
   with the same method as §M-49 (below) rather than guessing.
5. If `plugin-browse-browser` is not installed at all, or the script says so, treat
   `cursor-ide-browser` (native) as the first fallback — check whether it is currently registered
   with a direct tool call (see "Fallback order" below) before assuming it is unavailable.

**Do not:**
- Do not re-type the patches from this doc by hand into the plugin cache — use the script so the
  fix is exactly reproducible and self-checking.
- Do not assume killing the MCP server process makes Cursor respawn it automatically — it does not;
  a human toggle or window reload is required every time code changes, confirmed 3 times in one
  session (§M-49).
- Do not treat `browser-use` (the other cached browser plugin, `~/.cursor/plugins/cache/cursor-public/browser-use/`)
  as a drop-in fallback without checking network first — on this machine `pypi.org` does not
  resolve over TCP (DNS resolves, `Test-NetConnection` to port 443 fails), which blocks `uvx` from
  fetching the package. This is a separate, unrelated problem from the browser plugin bugs.

---

## Symptom -> cause -> fix map

| Symptom | Where it shows | Root cause | Fixed by script? |
|---|---|---|---|
| `cursor-ide-browser` missing from `GetMcpTools` catalog | Agent-side MCP discovery | Native Browser MCP registration is per-chat-session/tab, not persistent; can appear and disappear mid-conversation with no visible trigger | No — not a bug to patch, see "Fallback order" |
| `spawn ...\\node_modules\\.bin\\browse ENOENT` | `plugin-browse-browser` any tool call | npm bin-link for vendored `@browserbasehq/browse-cli` dependency was never created (or lost) in the plugin cache | Yes — Fix 1/3 |
| `spawn EINVAL` | Same, after Fix 1/3 applied | Node.js on Windows requires explicit `shell: true` to spawn/execFile a `.cmd` file (tightened after CVE-2024-27980; no longer implicit) | Yes — Fix 2/3 |
| `Connection failed: connect ENOENT ...\\browse-default.sock` | `browser_navigate`/`browser_open`, after Fix 2/3 applied | `browse-cli`'s own daemon listens on a Unix-domain-socket **file path**; Windows needs the `\\.\pipe\` namespace instead, so the daemon dies at startup before creating the file | Yes — Fix 3/3 |
| Server shows `"error"` / tool calls return `{"error":"Not connected"}` | Any tool call, right after a process was killed (by this script or manually) | Cursor's MCP client does not auto-respawn a killed server process | No — requires one manual `Settings -> MCP` toggle or window reload |

Full incident narrative with byte-level evidence (exact `EACCES`/`EPIPE` reproduction, why the naive
named-pipe patch alone is unsafe): `.cursor/plans/main-decisions-local-hub.md` §M-49.

---

## Why one manual step is unavoidable

Every time the plugin's JS code changes (including this repair script's own patches), the *already
running* Node process for `plugin-browse-browser` keeps the old code in memory — it must be killed
and respawned. The script kills it by PID. Cursor's MCP client, however, does not watch for a dead
child process and relaunch it on its own; the next tool call just returns `{"error":"Not connected"}`
and the server catalog shows `"serverStatus":"error"`. The only known way to make Cursor relaunch it
is a human action: toggle the server off/on in `Settings -> MCP`, or a full `Reload Window`. This was
confirmed three separate times in one session — there is no agent-side workaround.

---

## Fallback order (if the script cannot fix `plugin-browse-browser` right now)

1. **`cursor-ide-browser` (native Browser MCP).** Check first with a direct tool call — its presence
   is session-based and can flip on its own (observed appearing and disappearing without any action
   taken, twice in one session, §M-49). If a call like `browser_tabs` / `browser_navigate` succeeds,
   use it; do not assume it is unavailable just because a previous `GetMcpTools` catalog omitted it.
2. **`plugin-browse-browser` after running the repair script + one operator toggle.** The primary,
   most durable option once patched — does not depend on session-based registration.
3. **`browser-use` plugin** (`~/.cursor/plugins/cache/cursor-public/browser-use/`) — cached on disk
   but not registered as an active MCP server on this machine, and its `uvx --python 3.12
   browser-use@latest --cli-mcp` launch command needs to fetch from PyPI at first run, which failed
   here (`pypi.org` TCP connect failure, unrelated network issue). Only pursue this if PyPI
   connectivity is confirmed working and the operator has enabled the plugin in `Settings -> MCP`.

---

## Verification after repair

Do not declare the browser MCP "fixed" from the script's self-test alone — that only proves the
standalone `browse-cli` works, bypassing Cursor's MCP wrapper entirely. After the operator confirms
the manual toggle/reload:

1. Call the actual MCP tool (`browser_status` on `plugin-browse-browser`, or the equivalent on
   whichever server is in use) and confirm no `ENOENT`/`EINVAL`/`EACCES`/`"Not connected"`.
2. Call `browser_navigate` to a real local page and `browser_snapshot`/`browser_get_bounding_box` to
   confirm a real, current DOM tree comes back — not a cached/stale response.
3. Only then resume the original UI verification task (e.g. click-testing a feature).

---

## Related

- Fix script: [`scripts/repair-browser-mcp.ps1`](../scripts/repair-browser-mcp.ps1) — idempotent, safe to re-run any time, `-SelfTest` switch for an end-to-end check.
- Full incident log: [`.cursor/plans/main-decisions-local-hub.md`](../.cursor/plans/main-decisions-local-hub.md) §M-49.
- Skill: [`.cursor/skills/browser-verify/SKILL.md`](../.cursor/skills/browser-verify/SKILL.md) — Human Gate rules for browser use; now also points here for MCP-broken recovery.
- [`docs/cursor-native-controls.md`](cursor-native-controls.md) — Browser tool control reference.
