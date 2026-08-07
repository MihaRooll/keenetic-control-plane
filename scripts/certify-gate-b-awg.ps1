<#
.SYNOPSIS
  Gate B/C AWG certification CLI wrapper (dry-run default).
#>
param(
    [string]$ProjectRoot = ""
)

$ErrorActionPreference = "Stop"
$ScriptRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
    $ProjectRoot = (Resolve-Path (Join-Path $ScriptRoot "..")).Path
}

$PyScript = Join-Path $ScriptRoot "certify-gate-b-awg.py"
if (-not (Test-Path -LiteralPath $PyScript)) {
    Write-Error "Missing script: $PyScript"
}

Push-Location $ProjectRoot
try {
    & py.exe -3.11 $PyScript @args
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
