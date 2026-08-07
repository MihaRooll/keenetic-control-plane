<#
.SYNOPSIS
  Automated same-tuple Gate A freshness recertification (fail-closed on drift).
#>
param(
    [string]$RouterHost = "",
    [string]$Username = "",
    [string]$CredentialRef = "",
    [string]$SshHostKeySha256 = "",
    [string]$SourceAddress = "",
    [string]$SecretsRoot = "",
    [string]$ConfigPath = "",
    [double]$RefreshMarginHours = 0,
    [switch]$Force,
    [switch]$DryRun,
    [string]$ProjectRoot = ""
)

$ErrorActionPreference = "Stop"
$ScriptRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
    $ProjectRoot = (Resolve-Path (Join-Path $ScriptRoot "..")).Path
}

$pyArgs = @(
    (Join-Path $ScriptRoot "recertify-gate-a-freshness.py")
)
if (-not [string]::IsNullOrWhiteSpace($RouterHost)) {
    $pyArgs += @("--host", $RouterHost)
}
if (-not [string]::IsNullOrWhiteSpace($Username)) {
    $pyArgs += @("--username", $Username)
}
if (-not [string]::IsNullOrWhiteSpace($CredentialRef)) {
    $pyArgs += @("--credential-ref", $CredentialRef)
}
if (-not [string]::IsNullOrWhiteSpace($SshHostKeySha256)) {
    $pyArgs += @("--ssh-host-key-sha256", $SshHostKeySha256)
}
if (-not [string]::IsNullOrWhiteSpace($SourceAddress)) {
    $pyArgs += @("--source-address", $SourceAddress)
}
if (-not [string]::IsNullOrWhiteSpace($SecretsRoot)) {
    $pyArgs += @("--secrets-root", $SecretsRoot)
}
if (-not [string]::IsNullOrWhiteSpace($ConfigPath)) {
    $pyArgs += @("--config-path", $ConfigPath)
}
if ($RefreshMarginHours -gt 0) {
    $pyArgs += @("--refresh-margin-hours", $RefreshMarginHours)
}
if ($Force) {
    $pyArgs += @("--force")
}
if ($DryRun) {
    $pyArgs += @("--dry-run")
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
