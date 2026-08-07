<#
.SYNOPSIS
  Register Windows Scheduled Tasks for automated Gate A freshness recertification.
  Uses schtasks.exe (no elevation required for /rl LIMITED current-user tasks).
#>
param(
    [string]$TaskName = "RouterControl-GateA-FreshnessAuto",
    [int]$IntervalHours = 4,
    [string]$ProjectRoot = ""
)

$ErrorActionPreference = "Stop"
$ScriptRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
    $ProjectRoot = (Resolve-Path (Join-Path $ScriptRoot "..")).Path
}

$artifactDir = Join-Path $ProjectRoot "data\artifacts"
New-Item -ItemType Directory -Force -Path $artifactDir | Out-Null

$recertScript = Join-Path $ScriptRoot "recertify-gate-a-freshness.ps1"
$taskLog = Join-Path $artifactDir "gate-a-recert-task.log"
$runnerScript = Join-Path $artifactDir "gate-a-recert-runner.ps1"

# schtasks /tr is limited to 261 characters; keep /tr short via a tiny runner script
# that performs the *>> redirection to gate-a-recert-task.log internally.
@(
    '$ErrorActionPreference = "Continue"'
    "`$Root = '$ProjectRoot'"
    "`$Log = '$taskLog'"
    'New-Item -ItemType Directory -Force -Path (Split-Path $Log) | Out-Null'
    "Push-Location `$Root"
    'try {'
    "    & '$recertScript' *>> `$Log"
    '} finally {'
    '    Pop-Location'
    '}'
) | Set-Content -Path $runnerScript -Encoding UTF8

$taskRun = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$runnerScript`""

function Invoke-SchtasksCreate {
    param(
        [string]$RegisteredName,
        [string[]]$Arguments
    )
    & schtasks.exe @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "schtasks /create failed for '$RegisteredName' (exit $LASTEXITCODE)"
    }
}

function Show-SchtasksDetail {
    param([string]$RegisteredName)
    & schtasks.exe /query /tn $RegisteredName /v /fo LIST
    if ($LASTEXITCODE -ne 0) {
        throw "schtasks /query failed for '$RegisteredName' (exit $LASTEXITCODE)"
    }
}

$logonTask = "$TaskName-Logon"
$intervalTask = "$TaskName-Interval"

& schtasks.exe /create /tn $logonTask /tr $taskRun /sc ONLOGON /rl LIMITED /f
if ($LASTEXITCODE -ne 0) {
    Write-Warning "ONLOGON task registration unavailable without elevation on this host (exit $LASTEXITCODE). Falling back to MINUTE/30 for '$logonTask'."
    Invoke-SchtasksCreate -RegisteredName $logonTask -Arguments @(
        "/create",
        "/tn", $logonTask,
        "/tr", $taskRun,
        "/sc", "MINUTE",
        "/mo", "30",
        "/rl", "LIMITED",
        "/f"
    )
} else {
    Write-Host "Registered '$logonTask' with schedule ONLOGON."
}

Invoke-SchtasksCreate -RegisteredName $intervalTask -Arguments @(
    "/create",
    "/tn", $intervalTask,
    "/tr", $taskRun,
    "/sc", "HOURLY",
    "/mo", "$IntervalHours",
    "/rl", "LIMITED",
    "/f"
)

Write-Host "Registered '$intervalTask' with schedule HOURLY /mo $IntervalHours."
Write-Host ""
Write-Host "--- $logonTask ---"
Show-SchtasksDetail -RegisteredName $logonTask
Write-Host ""
Write-Host "--- $intervalTask ---"
Show-SchtasksDetail -RegisteredName $intervalTask
