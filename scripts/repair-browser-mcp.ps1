<#
.SYNOPSIS
  Repairs the plugin-browse-browser MCP server (@browserbasehq/browse-cli wrapper) on Windows.

.DESCRIPTION
  Windows-only Cursor plugin repair. Idempotent - safe to re-run any time, including after a
  Cursor account switch or plugin cache reset, which have been observed (operator report,
  not mechanically confirmed) to correlate with this plugin losing its npm bin-link and/or
  the browser MCP tools disappearing from the session. Full root-cause narrative:
  docs/OPERATOR_BROWSER_MCP_RECOVERY.md and .cursor/plans/main-decisions-local-hub.md section M-49.

  Patches three independent, unrelated Windows incompatibilities:

    1. Missing node_modules/.bin/browse shim - the npm bin-link for the vendored
       @browserbasehq/browse-cli dependency was never created (or was lost) -> ENOENT.
    2. Node.js on Windows requires an explicit `shell: true` option to spawn/execFile a
       `.cmd` file (hardening after CVE-2024-27980; no longer implicit) -> EINVAL.
    3. browse-cli's own local daemon listens on a Unix-domain-socket *file path*, which
       Windows does not support without the `\\.\pipe\` namespace -> `listen EACCES` on the
       daemon side, `connect ENOENT` on the client side. The naive fix (switch to a pipe path)
       is unsafe by itself: browse-cli also probes daemon liveness via
       `fs.promises.access(socketPath)`, which on Windows performs a real `CreateFile` connect
       against the named pipe and can crash the daemon with an unhandled `EPIPE` on the very
       next command. This script disables that probe on win32 (the `process.kill(pid, 0)`
       liveness check alone remains, which is sufficient).

  After patching, if the currently-running MCP server process for this plugin is found, the
  script kills it by PID so Cursor is forced to respawn it with the patched code. Cursor's MCP
  client does NOT auto-respawn a killed server on its own - one manual toggle of
  `plugin-browse-browser` off/on in `Settings -> MCP` (or a full window reload) is required
  after this script reports changes. This is a real Cursor-side limitation, not something this
  script can complete unattended.

.PARAMETER SelfTest
  After patching, exercise the real CLI end-to-end (launches a visible Chrome window):
  open about:blank -> status -> stop. Off by default.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\repair-browser-mcp.ps1

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\repair-browser-mcp.ps1 -SelfTest
#>
[CmdletBinding()]
param(
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'
$script:changed = $false
$script:failures = @()

function Write-Step {
    param([string]$Message)
    Write-Host "[repair-browser-mcp] $Message"
}

function Invoke-TextPatch {
    param(
        [string]$Path,
        [string]$OldSnippet,
        [string]$NewSnippet,
        [string]$Label
    )
    # The target JS/TS files use LF-only line endings; here-strings in this .ps1 file may carry
    # CRLF depending on how the script itself was saved. Normalize both sides to LF before
    # comparing, otherwise Contains()/Replace() silently never match.
    $OldSnippet = $OldSnippet -replace "`r`n", "`n"
    $NewSnippet = $NewSnippet -replace "`r`n", "`n"
    $text = (Get-Content -Raw -LiteralPath $Path) -replace "`r`n", "`n"
    if ($text.Contains($NewSnippet)) {
        Write-Step "$Label - already applied ($Path)"
        return
    }
    if (-not $text.Contains($OldSnippet)) {
        $script:failures += "$Label - expected snippet not found in $Path (plugin version drift? see docs/OPERATOR_BROWSER_MCP_RECOVERY.md)"
        return
    }
    $updated = $text.Replace($OldSnippet, $NewSnippet)
    Set-Content -LiteralPath $Path -Value $updated -NoNewline -Encoding utf8
    Write-Step "$Label - patched ($Path)"
    $script:changed = $true
}

if ($env:OS -ne 'Windows_NT' -and -not $IsWindows) {
    Write-Step 'Not running on Windows - this repair is a no-op on this platform. Exiting 0.'
    exit 0
}

# ---------- Locate plugin cache ----------
$browseCacheRoot = Join-Path $env:USERPROFILE '.cursor\plugins\cache\cursor-public\browse'
if (-not (Test-Path $browseCacheRoot)) {
    Write-Host "[repair-browser-mcp] FAIL: plugin cache not found at $browseCacheRoot - plugin-browse-browser is not installed. Nothing to repair; consider the cursor-ide-browser (native) or browser-use alternatives instead."
    exit 1
}
$pluginRootItem = Get-ChildItem $browseCacheRoot -Directory | Sort-Object Name -Descending | Select-Object -First 1
if (-not $pluginRootItem) {
    Write-Host "[repair-browser-mcp] FAIL: no release directory found under $browseCacheRoot"
    exit 1
}
$pluginRoot = $pluginRootItem.FullName
Write-Step "Plugin root: $pluginRoot"

$binDir = Join-Path $pluginRoot 'node_modules\.bin'
$shimPath = Join-Path $binDir 'browse.cmd'
$wrapperMcp = Join-Path $pluginRoot 'dist\src\mcp-server.js'
$wrapperCli = Join-Path $pluginRoot 'dist\src\cli.js'
$srcMcp = Join-Path $pluginRoot 'src\mcp-server.ts'
$srcCli = Join-Path $pluginRoot 'src\cli.ts'
$vendorIndex = Join-Path $pluginRoot 'node_modules\@browserbasehq\browse-cli\dist\index.js'

foreach ($p in @($wrapperMcp, $wrapperCli, $vendorIndex)) {
    if (-not (Test-Path $p)) {
        Write-Host "[repair-browser-mcp] FAIL: expected file missing: $p - plugin internal layout changed; this script needs updating (see docs/OPERATOR_BROWSER_MCP_RECOVERY.md)."
        exit 1
    }
}

# ---------- Fix 1: missing npm bin shim (ENOENT) ----------
if (-not (Test-Path $shimPath)) {
    New-Item -ItemType Directory -Force -Path $binDir | Out-Null
    $shimLines = @(
        '@ECHO off',
        'SETLOCAL',
        'SET "_dir=%~dp0"',
        'node "%_dir%..\@browserbasehq\browse-cli\dist\index.js" %*'
    )
    Set-Content -LiteralPath $shimPath -Value $shimLines -Encoding ascii
    Write-Step "Fix 1/3 - created missing bin shim: $shimPath"
    $changed = $true
} else {
    Write-Step 'Fix 1/3 - bin shim already present'
}

# ---------- Fix 2: EINVAL - .cmd requires shell:true on Windows (Node, post CVE-2024-27980) ----------
Invoke-TextPatch -Path $wrapperMcp -Label 'Fix 2/3 (mcp-server.js BROWSE_BIN extension)' `
    -OldSnippet 'const BROWSE_BIN = join(PLUGIN_ROOT, ''node_modules'', ''.bin'', ''browse'');' `
    -NewSnippet 'const BROWSE_BIN = join(PLUGIN_ROOT, ''node_modules'', ''.bin'', process.platform === ''win32'' ? ''browse.cmd'' : ''browse'');'

Invoke-TextPatch -Path $wrapperMcp -Label 'Fix 2/3 (mcp-server.js shell:true)' `
    -OldSnippet @'
    const { stdout, stderr } = await execFileAsync(BROWSE_BIN, ['--json', ...args], {
        timeout: 60_000,
        env: process.env,
    });
'@ `
    -NewSnippet @'
    const { stdout, stderr } = await execFileAsync(BROWSE_BIN, ['--json', ...args], {
        timeout: 60_000,
        env: process.env,
        shell: process.platform === 'win32',
    });
'@

Invoke-TextPatch -Path $wrapperCli -Label 'Fix 2/3 (cli.js getBrowseBin extension)' `
    -OldSnippet @'
function getBrowseBin() {
    return join(PLUGIN_ROOT, 'node_modules', '.bin', 'browse');
}
'@ `
    -NewSnippet @'
function getBrowseBin() {
    return join(PLUGIN_ROOT, 'node_modules', '.bin', process.platform === 'win32' ? 'browse.cmd' : 'browse');
}
'@

Invoke-TextPatch -Path $wrapperCli -Label 'Fix 2/3 (cli.js shell:true)' `
    -OldSnippet @'
    const child = spawn(browseBin, args, {
        stdio: 'inherit',
        env: process.env,
    });
'@ `
    -NewSnippet @'
    const child = spawn(browseBin, args, {
        stdio: 'inherit',
        env: process.env,
        shell: process.platform === 'win32',
    });
'@

# Best-effort mirror into the wrapper's TypeScript sources, for consistency if the plugin is
# ever rebuilt from src/. Non-fatal if absent or already diverged - dist/ is what actually runs.
if (Test-Path $srcMcp) {
    Invoke-TextPatch -Path $srcMcp -Label 'Fix 2/3 (mcp-server.ts, best-effort)' `
        -OldSnippet 'const BROWSE_BIN = join(PLUGIN_ROOT, ''node_modules'', ''.bin'', ''browse'');' `
        -NewSnippet 'const BROWSE_BIN = join(PLUGIN_ROOT, ''node_modules'', ''.bin'', process.platform === ''win32'' ? ''browse.cmd'' : ''browse'');'
}
if (Test-Path $srcCli) {
    Invoke-TextPatch -Path $srcCli -Label 'Fix 2/3 (cli.ts, best-effort)' `
        -OldSnippet @'
function getBrowseBin(): string {
  return join(PLUGIN_ROOT, 'node_modules', '.bin', 'browse');
}
'@ `
        -NewSnippet @'
function getBrowseBin(): string {
  return join(PLUGIN_ROOT, 'node_modules', '.bin', process.platform === 'win32' ? 'browse.cmd' : 'browse');
}
'@
}

# ---------- Fix 3: browse-cli daemon Unix-socket incompatibility (EACCES / ENOENT) ----------
Invoke-TextPatch -Path $vendorIndex -Label 'Fix 3/3 (getSocketPath -> Windows named pipe)' `
    -OldSnippet @'
function getSocketPath(session) {
  return path8.join(SOCKET_DIR, `browse-${session}.sock`);
}
'@ `
    -NewSnippet @'
function getSocketPath(session) {
  if (process.platform === "win32") {
    return "\\\\.\\pipe\\browse-" + session;
  }
  return path8.join(SOCKET_DIR, `browse-${session}.sock`);
}
'@

Invoke-TextPatch -Path $vendorIndex -Label 'Fix 3/3 (isDaemonRunning skip fs.access on win32)' `
    -OldSnippet @'
    const pid = parseInt(await import_fs11.promises.readFile(pidFile, "utf-8"));
    process.kill(pid, 0);
    const socketPath = getSocketPath(session);
    await import_fs11.promises.access(socketPath);
    return true;
'@ `
    -NewSnippet @'
    const pid = parseInt(await import_fs11.promises.readFile(pidFile, "utf-8"));
    process.kill(pid, 0);
    if (process.platform !== "win32") {
      const socketPath = getSocketPath(session);
      await import_fs11.promises.access(socketPath);
    }
    return true;
'@

# ---------- Force the running MCP server to pick up patched code ----------
if ($changed) {
    $procs = Get-CimInstance Win32_Process -Filter "Name='node.exe'" |
        Where-Object { $_.CommandLine -like '*mcp-server.js*' -and $_.CommandLine -like '*browse*' }
    if ($procs) {
        foreach ($proc in $procs) {
            Write-Step "Killing stale MCP server process PID $($proc.ProcessId) so it respawns with patched code"
            Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
        }
        Write-Host ''
        Write-Host '[repair-browser-mcp] ACTION REQUIRED: toggle "plugin-browse-browser" off and on in Settings -> MCP' -ForegroundColor Yellow
        Write-Host '[repair-browser-mcp] (or do a full Reload Window) so Cursor respawns the MCP server with the patched code.' -ForegroundColor Yellow
        Write-Host '[repair-browser-mcp] Cursor does not auto-respawn a killed MCP server process - this one step cannot be automated.' -ForegroundColor Yellow
        Write-Host ''
    } else {
        Write-Step 'No running MCP server process found for this plugin - patched code will apply on next start, no manual restart needed.'
    }
} else {
    Write-Step 'No changes needed - all patches already applied.'
}

# ---------- Optional self-test (bypasses the MCP wrapper, exercises the CLI directly) ----------
if ($SelfTest) {
    Write-Step 'Running self-test (opens a visible Chrome window)...'
    Push-Location $pluginRoot
    try {
        $openResult = & $shimPath --json open 'about:blank' 2>&1 | Out-String
        $statusResult = & $shimPath --json status 2>&1 | Out-String
        $stopResult = & $shimPath --json stop 2>&1 | Out-String
        Write-Step "open   -> $($openResult.Trim())"
        Write-Step "status -> $($statusResult.Trim())"
        Write-Step "stop   -> $($stopResult.Trim())"
        if ($openResult -match 'ENOENT' -or $openResult -match 'EINVAL' -or $openResult -match 'EACCES' -or $openResult -match '"success"\s*:\s*false') {
            $failures += "Self-test failed: open returned an error - $($openResult.Trim())"
        } elseif ($statusResult -notmatch '"running"') {
            $failures += "Self-test failed: status did not return expected JSON - $($statusResult.Trim())"
        } else {
            Write-Step 'Self-test PASSED - daemon opened, reported status, and stopped cleanly.'
        }
    } finally {
        Pop-Location
    }
}

# ---------- Summary ----------
Write-Host ''
if ($failures.Count -gt 0) {
    Write-Host '[repair-browser-mcp] FAIL - one or more patches or checks did not succeed:' -ForegroundColor Red
    foreach ($f in $failures) { Write-Host "  - $f" -ForegroundColor Red }
    exit 1
}
Write-Host '[repair-browser-mcp] OK - all checks passed.' -ForegroundColor Green
if ($changed) {
    Write-Host '[repair-browser-mcp] Remember: manual MCP toggle/reload is still required for the running session to pick this up.' -ForegroundColor Yellow
}
exit 0
