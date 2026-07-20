<#
.SYNOPSIS
  Project health check — harness, docs, git, tools, curated env summary (PS 5.1, no module installs).
#>
param(
    [string]$ProjectRoot = ""
)

$ErrorActionPreference = "Continue"
$exitCode = 0
$Utf8 = New-Object System.Text.UTF8Encoding $false

function Get-DoctorProjectRoot {
    param([string]$Explicit)
    if (-not [string]::IsNullOrWhiteSpace($Explicit)) {
        return (Resolve-Path -LiteralPath $Explicit).Path
    }
    if ($env:CURSOR_PROJECT_DIR -and (Test-Path -LiteralPath $env:CURSOR_PROJECT_DIR)) {
        return (Resolve-Path -LiteralPath $env:CURSOR_PROJECT_DIR).Path
    }
    if ($env:CURSOR_SESSION_PROJECT_ROOT -and (Test-Path -LiteralPath $env:CURSOR_SESSION_PROJECT_ROOT)) {
        return (Resolve-Path -LiteralPath $env:CURSOR_SESSION_PROJECT_ROOT).Path
    }
    $scriptDir = $PSScriptRoot
    if ([string]::IsNullOrWhiteSpace($scriptDir)) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
    return (Resolve-Path -LiteralPath (Join-Path $scriptDir "..")).Path
}

function Test-SensitiveEnvName([string]$Name) {
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    $sk = 'sk' + '-'
    $ghp = 'gh' + 'p_'
    $gho = 'gh' + 'o_'
    $xox = 'xox' + '[baprs]-'
    $ai = 'AI' + 'za'
    $pat = '(?i)(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|github_pat_|^' + [regex]::Escape($sk) + '|' + [regex]::Escape($ghp) + '|' + [regex]::Escape($gho) + '|' + $xox + '|' + [regex]::Escape($ai) + ')'
    return ($Name -match $pat)
}

function Write-DoctorLine([string]$Line) {
    Write-Output $Line
}

function Read-TextUtf8([string]$Path) {
    return [System.IO.File]::ReadAllText($Path, $script:Utf8)
}

$root = Get-DoctorProjectRoot -Explicit $ProjectRoot
Write-DoctorLine "=== project-doctor ==="
Write-DoctorLine "root: $root"

$harnessPaths = @(
    ".cursor\hooks\session-start.ps1",
    ".cursor\skills\review-papercuts\SKILL.md",
    ".cursor\rules\product-core.mdc"
)
$harnessOk = $true
foreach ($rel in $harnessPaths) {
    $full = Join-Path $root $rel
    if (Test-Path -LiteralPath $full) {
        Write-DoctorLine "harness: OK $rel"
    } else {
        Write-DoctorLine "harness: MISSING $rel"
        $harnessOk = $false
        $exitCode = 2
    }
}
if ($harnessOk) { Write-DoctorLine "harness: summary OK" }

$mapPath = Join-Path $root "docs\docs-map.json"
if (Test-Path -LiteralPath $mapPath) {
    try {
        $raw = Read-TextUtf8 $mapPath
        $null = $raw | ConvertFrom-Json
        Write-DoctorLine "docs-map: OK parseable"
    } catch {
        Write-DoctorLine "docs-map: FAIL parse"
        $exitCode = 2
    }
} else {
    Write-DoctorLine "docs-map: MISSING (advisory)"
    if ($exitCode -eq 0) { $exitCode = 1 }
}

$statePath = Join-Path $root "docs\project-state.md"
if (Test-Path -LiteralPath $statePath) {
    $stateRaw = Read-TextUtf8 $statePath
    if ([string]::IsNullOrWhiteSpace($stateRaw.Trim())) {
        Write-DoctorLine "project-state: EMPTY (advisory)"
        if ($exitCode -eq 0) { $exitCode = 1 }
    } elseif ($stateRaw -match '(?mi)^##\s*phase\s*\r?\n\s*(.+?)(\r?\n|$)' -or $stateRaw -match '(?mi)^phase:\s*(.+)$') {
        $phaseVal = [string]$matches[1].Trim()
        Write-DoctorLine "project-state: OK phase=$phaseVal"
    } else {
        Write-DoctorLine "project-state: MISSING phase (advisory)"
        if ($exitCode -eq 0) { $exitCode = 1 }
    }
} else {
    Write-DoctorLine "project-state: MISSING (advisory - seed templates/project-state.md)"
    if ($exitCode -eq 0) { $exitCode = 1 }
}

if (Get-Command git -ErrorAction SilentlyContinue) {
    Push-Location -LiteralPath $root
    try {
        $status = & git status --porcelain 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-DoctorLine "git: not a repo or error (advisory)"
            if ($exitCode -eq 0) { $exitCode = 1 }
        } else {
            $count = @($status | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count
            if ($count -eq 0) {
                Write-DoctorLine "git: clean"
            } else {
                Write-DoctorLine "git: dirty ($count entries)"
            }
        }
    } finally {
        Pop-Location
    }
} else {
    Write-DoctorLine "tools: git MISSING"
    $exitCode = 2
}

$missingTools = @()
foreach ($tool in @("node", "pwsh")) {
    if (Get-Command $tool -ErrorAction SilentlyContinue) {
        Write-DoctorLine "tools: $tool OK"
    } else {
        Write-DoctorLine "tools: $tool MISSING"
        $missingTools += $tool
    }
}
if ($missingTools.Count -gt 0 -and $exitCode -eq 0) {
    $exitCode = 1
}

Write-DoctorLine "env: curated summary (secret-shaped names redacted; values never printed)"
$curatedHints = @(
    @{ name = "HOME"; note = "papercuts on Windows" },
    @{ name = "PATH"; note = "toolchain discovery" },
    @{ name = "CURSOR_PROJECT_DIR"; note = "plugin project root" },
    @{ name = "CURSOR_SESSION_PROJECT_ROOT"; note = "session hook override" }
)
foreach ($hint in $curatedHints) {
    $val = [Environment]::GetEnvironmentVariable($hint.name, "Process")
    if (-not [string]::IsNullOrEmpty($val)) {
        Write-DoctorLine ("env: {0}=(set, value hidden) [{1}]" -f $hint.name, $hint.note)
    }
}

$sensitiveSet = 0
$nonSensitiveSet = 0
foreach ($scope in @("Process", "User", "Machine")) {
    try {
        $table = [Environment]::GetEnvironmentVariables($scope)
        foreach ($key in $table.Keys) {
            $name = [string]$key
            if (Test-SensitiveEnvName $name) {
                $sensitiveSet++
            } else {
                $nonSensitiveSet++
            }
        }
    } catch { }
}
Write-DoctorLine "env: sensitive_vars=$sensitiveSet (names redacted)"
Write-DoctorLine "env: other_vars=$nonSensitiveSet (names not enumerated)"

Write-DoctorLine "doctor_exit: $exitCode"
exit $exitCode
