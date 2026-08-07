<#
.SYNOPSIS
  Gate A read-only Netcraze identity probe (sanitized artifact, no secrets).
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$RouterHost,

    [Parameter(Mandatory = $true)]
    [string]$CredentialRef,

    [Parameter(Mandatory = $true)]
    [string]$Username,

    [string]$SecretsRoot = "",
    [string]$ArtifactOut = "",
    [switch]$AllowNonPrivate,
    [switch]$AllowInsecureHttp,
    [switch]$SshTunnel,
    [string]$SshHostKeySha256 = "",
    [string]$ExpectedModel = "",
    [string]$UpdateChannel = "",
    [string]$SourceAddress = "",
    [string]$ProjectRoot = ""
)

$ErrorActionPreference = "Stop"
$ScriptRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
    $ProjectRoot = (Resolve-Path (Join-Path $ScriptRoot "..")).Path
}

$pyArgs = @(
    (Join-Path $ScriptRoot "probe-gate-a.py"),
    "--host", $RouterHost,
    "--credential-ref", $CredentialRef,
    "--username", $Username
)
if (-not [string]::IsNullOrWhiteSpace($SecretsRoot)) {
    $pyArgs += @("--secrets-root", $SecretsRoot)
}
if (-not [string]::IsNullOrWhiteSpace($ArtifactOut)) {
    $pyArgs += @("--artifact-out", $ArtifactOut)
}
if ($AllowNonPrivate) {
    $pyArgs += @("--allow-non-private")
}
if ($AllowInsecureHttp) {
    $pyArgs += @("--allow-insecure-http")
}
if ($SshTunnel) {
    $pyArgs += @("--ssh-tunnel")
}
if (-not [string]::IsNullOrWhiteSpace($SshHostKeySha256)) {
    $pyArgs += @("--ssh-host-key-sha256", $SshHostKeySha256)
}
if (-not [string]::IsNullOrWhiteSpace($ExpectedModel)) {
    $pyArgs += @("--expected-model", $ExpectedModel)
}
if (-not [string]::IsNullOrWhiteSpace($UpdateChannel)) {
    $pyArgs += @("--update-channel", $UpdateChannel)
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
