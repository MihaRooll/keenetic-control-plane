<#
.SYNOPSIS
  Fetch fixed /ci/startup-config.txt over pinned SSH tunnel; store DPAPI-encrypted backup.
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$RouterHost,

    [Parameter(Mandatory = $true)]
    [string]$CredentialRef,

    [Parameter(Mandatory = $true)]
    [string]$Username,

    [Parameter(Mandatory = $true)]
    [string]$SshHostKeySha256,

    [string]$SecretsRoot = "",
    [switch]$AllowNonPrivate,
    [string]$SourceAddress = "",
    [string]$ProjectRoot = ""
)

$ErrorActionPreference = "Stop"
$ScriptRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
    $ProjectRoot = (Resolve-Path (Join-Path $ScriptRoot "..")).Path
}

$pyArgs = @(
    (Join-Path $ScriptRoot "backup-router-startup.py"),
    "--host", $RouterHost,
    "--credential-ref", $CredentialRef,
    "--username", $Username,
    "--ssh-host-key-sha256", $SshHostKeySha256
)
if (-not [string]::IsNullOrWhiteSpace($SecretsRoot)) {
    $pyArgs += @("--secrets-root", $SecretsRoot)
}
if ($AllowNonPrivate) {
    $pyArgs += @("--allow-non-private")
}
if (-not [string]::IsNullOrWhiteSpace($SourceAddress)) {
    $pyArgs += @("--source-address", $SourceAddress)
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
