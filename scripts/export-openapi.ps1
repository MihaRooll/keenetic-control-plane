<#
.SYNOPSIS
  Export OpenAPI v0 from FastAPI host to docs/contracts/openapi-v0.json
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
    & py.exe -3.11 (Join-Path $ScriptRoot "export-openapi.py")
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
finally {
    Pop-Location
}

exit 0
