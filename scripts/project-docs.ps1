<#
.SYNOPSIS
  Project documentation lifecycle wrapper (Windows PowerShell 5.1).
.DESCRIPTION
  Delegates to scripts/project-docs.py: audit, sync-marker, impact.
  Accepts PowerShell parameters (-ProjectRoot) and python-style flags
  (--project-root, --strict-unmapped, --write, ...) via remaining arguments.
#>
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet("audit", "sync-marker", "impact")]
    [string]$Command,

    [string]$ProjectRoot = "",

    [switch]$StrictUnmapped,

    [switch]$Write,

    [string]$ContractId = "",

    [string[]]$Paths = @(),

    [string[]]$MapEntries = @(),

    [ValidateSet("yes", "no", "")]
    [string]$ValidatorRun = "",

    [Nullable[int]]$ValidatorExitCode = $null,

    [string]$Notes = "",

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$RemainingArgs = @()
)

$ErrorActionPreference = "Stop"
$ScriptRoot = $PSScriptRoot

$extraPyArgs = @()
$i = 0
while ($i -lt $RemainingArgs.Count) {
    $arg = $RemainingArgs[$i]
    if ($arg -eq "--project-root" -and ($i + 1) -lt $RemainingArgs.Count) {
        $ProjectRoot = $RemainingArgs[$i + 1]
        $i += 2
        continue
    }
    if ($arg -like "--project-root=*") {
        $ProjectRoot = $arg.Substring("--project-root=".Length)
        $i += 1
        continue
    }
    if ($arg -eq "--strict-unmapped") {
        $StrictUnmapped = $true
        $i += 1
        continue
    }
    if ($arg -eq "--write") {
        $Write = $true
        $i += 1
        continue
    }
    $extraPyArgs += $arg
    $i += 1
}

if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
    $ProjectRoot = (Resolve-Path (Join-Path $ScriptRoot "..")).Path
} else {
    $ProjectRoot = (Resolve-Path -LiteralPath $ProjectRoot).Path
}

$pyScript = Join-Path $ScriptRoot "project-docs.py"
$pyArgs = @(
    $pyScript,
    $Command,
    "--project-root",
    $ProjectRoot
)

switch ($Command) {
    "audit" {
        if ($StrictUnmapped) { $pyArgs += "--strict-unmapped" }
    }
    "sync-marker" {
        if ($Write) { $pyArgs += "--write" }
    }
    "impact" {
        if ([string]::IsNullOrWhiteSpace($ContractId)) {
            Write-Error "impact requires -ContractId"
        }
        if ([string]::IsNullOrWhiteSpace($ValidatorRun)) {
            Write-Error "impact requires -ValidatorRun yes|no"
        }
        $pyArgs += @(
            "--contract-id", $ContractId,
            "--validator-run", $ValidatorRun,
            "--notes", $Notes
        )
        if ($Paths.Count -gt 0) {
            $pyArgs += "--paths"
            $pyArgs += $Paths
        }
        if ($MapEntries.Count -gt 0) {
            $pyArgs += "--map-entries"
            $pyArgs += $MapEntries
        }
        if ($null -ne $ValidatorExitCode) {
            $pyArgs += @("--validator-exit-code", [string]$ValidatorExitCode)
        }
    }
}

if ($extraPyArgs.Count -gt 0) {
    $pyArgs += $extraPyArgs
}

Push-Location $ProjectRoot
try {
    & py.exe -3.11 @pyArgs
    $code = $LASTEXITCODE
    if ($null -eq $code) { $code = 0 }
    exit $code
}
finally {
    Pop-Location
}
