<#
.SYNOPSIS
  Store router RCI credentials in Windows DPAPI vault (interactive getpass).
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$RouterHost,

    [Parameter(Mandatory = $true)]
    [string]$Username,

    [string]$SecretsRoot = "",
    [string]$MetaOut = "",
    [string]$ProjectRoot = ""
)

$ErrorActionPreference = "Stop"
$ScriptRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
    $ProjectRoot = (Resolve-Path (Join-Path $ScriptRoot "..")).Path
}

$pyArgs = @(
    (Join-Path $ScriptRoot "store-router-credential.py"),
    "--host", $RouterHost,
    "--username", $Username
)
if (-not [string]::IsNullOrWhiteSpace($SecretsRoot)) {
    $pyArgs += @("--secrets-root", $SecretsRoot)
}
if (-not [string]::IsNullOrWhiteSpace($MetaOut)) {
    $pyArgs += @("--meta-out", $MetaOut)
}

Push-Location $ProjectRoot
try {
    & py.exe -3.11 @pyArgs
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
finally {
    Pop-Location
}

exit 0
