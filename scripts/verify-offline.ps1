<#
.SYNOPSIS
  Offline verification bundle: pytest, ruff, mypy, docs validator.
#>
param(
    [string]$ProjectRoot = ""
)

$ErrorActionPreference = "Stop"
$ScriptRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
    $ProjectRoot = (Resolve-Path (Join-Path $ScriptRoot "..")).Path
}

Push-Location $ProjectRoot
try {
    & py.exe -3.11 -m pytest -q
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & py.exe -3.11 -m ruff check router_control router_control_host tests
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & py.exe -3.11 -m mypy router_control
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $ScriptRoot "validate-project-docs.ps1")
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
finally {
    Pop-Location
}

exit 0
