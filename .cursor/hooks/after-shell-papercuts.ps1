# Auto-file papercuts on failed shell commands (rate-limited, deduped).
$ErrorActionPreference = "SilentlyContinue"
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
if (-not $env:HOME -and $env:USERPROFILE) { $env:HOME = $env:USERPROFILE }

$raw = [Console]::In.ReadToEnd()
if (-not $raw) { Write-Output "{}"; exit 0 }

try { $evt = $raw | ConvertFrom-Json } catch { Write-Output "{}"; exit 0 }

# Flexible field names across Cursor versions
$exit = $null
foreach ($k in @("exit_code", "exitCode", "status", "exit")) {
    if ($null -ne $evt.$k) { $exit = [int]$evt.$k; break }
}
$cmd = ""
foreach ($k in @("command", "cmd", "shell_command")) {
    if ($evt.$k) { $cmd = [string]$evt.$k; break }
}

# Only failures
if ($null -eq $exit -or $exit -eq 0) { Write-Output "{}"; exit 0 }
if ([string]::IsNullOrWhiteSpace($cmd)) { Write-Output "{}"; exit 0 }

# Skip our own papercuts calls / noise
if ($cmd -match "papercuts(\.exe)?\s" -or $cmd -match "after-shell-papercuts") {
    Write-Output "{}"; exit 0
}

$root = (Get-Location).Path
$stateDir = Join-Path $root ".cursor\hooks\state"
New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
$stateFile = Join-Path $stateDir "papercuts-auto.json"

$maxPerSession = 8
$now = Get-Date
$state = @{ session_day = $now.ToString("yyyy-MM-dd"); count = 0; recent = @() }
if (Test-Path $stateFile) {
    try {
        $loaded = Get-Content $stateFile -Raw -Encoding utf8 | ConvertFrom-Json
        if ($loaded.session_day -eq $state.session_day) {
            $state.count = [int]$loaded.count
            $state.recent = @($loaded.recent)
        }
    } catch { }
}

if ($state.count -ge $maxPerSession) { Write-Output "{}"; exit 0 }

# Dedupe fingerprint (command prefix)
$fp = ($cmd.Trim() -replace "\s+", " ")
if ($fp.Length -gt 160) { $fp = $fp.Substring(0, 160) }
if ($state.recent -contains $fp) { Write-Output "{}"; exit 0 }

$text = "shell exit ${exit}: $fp"
$logFile = Join-Path $root ".papercuts.jsonl"
$filed = $false

$papercuts = Get-Command papercuts.exe -ErrorAction SilentlyContinue
if ($papercuts) {
    & papercuts.exe --file $logFile add $text --tag tooling --severity minor --exit $exit 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { $filed = $true }
}

if (-not $filed) {
    $shimCandidates = @(
        (Join-Path $root "scripts\papercuts.ps1"),
        (Join-Path $PSScriptRoot "papercuts.ps1")
    )
    foreach ($shim in $shimCandidates) {
        if (Test-Path $shim) {
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $shim add $text -Tag tooling -Severity minor | Out-Null
            $filed = $true
            break
        }
    }
}

if ($filed) {
    $state.count = [int]$state.count + 1
    $recent = @($state.recent) + @($fp)
    if ($recent.Count -gt 40) { $recent = $recent[-40..-1] }
    $state.recent = $recent
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($stateFile, ($state | ConvertTo-Json -Compress), $utf8)
    @{ additional_context = "Papercut auto-logged (shell exit ${exit}). Continue the task; do not stop." } | ConvertTo-Json -Compress
} else {
    Write-Output "{}"
}
exit 0
