<#
.SYNOPSIS
  NC-1812 read-only SSH CLI channel discovery (validate default, live-probe gated).
#>
param(
    [string]$RouterHost = "",
    [string]$CredentialRef = "",
    [string]$Username = "",
    [string]$SshHostKeySha256 = "",
    [string]$SourceAddress = "192.168.2.10",
    [string]$Authorization = "",
    [string]$ArtifactOut = "",
    [string]$SecretsRoot = "",
    [string]$GateAConfig = "",
    [string]$GateAEvidence = "",
    [string]$StatusPath = "",
    [string]$ProbesRoot = "",
    [switch]$AllowNonPrivate,
    [switch]$LiveProbe,
    [string]$ProjectRoot = ""
)

$ErrorActionPreference = "Stop"
$ScriptRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
    $ProjectRoot = (Resolve-Path (Join-Path $ScriptRoot "..")).Path
}

$pyArgs = @((Join-Path $ScriptRoot "probe-nc1812-ssh-cli.py"))
if (-not [string]::IsNullOrWhiteSpace($RouterHost)) {
    $pyArgs += @("--host", $RouterHost)
}
if (-not [string]::IsNullOrWhiteSpace($CredentialRef)) {
    $pyArgs += @("--credential-ref", $CredentialRef)
}
if (-not [string]::IsNullOrWhiteSpace($Username)) {
    $pyArgs += @("--username", $Username)
}
if (-not [string]::IsNullOrWhiteSpace($SshHostKeySha256)) {
    $pyArgs += @("--ssh-host-key-sha256", $SshHostKeySha256)
}
if (-not [string]::IsNullOrWhiteSpace($SourceAddress)) {
    $pyArgs += @("--source-address", $SourceAddress)
}
if (-not [string]::IsNullOrWhiteSpace($Authorization)) {
    $pyArgs += @("--authorization", $Authorization)
}
if (-not [string]::IsNullOrWhiteSpace($ArtifactOut)) {
    $pyArgs += @("--artifact-out", $ArtifactOut)
}
if (-not [string]::IsNullOrWhiteSpace($SecretsRoot)) {
    $pyArgs += @("--secrets-root", $SecretsRoot)
}
if (-not [string]::IsNullOrWhiteSpace($GateAConfig)) {
    $pyArgs += @("--gate-a-config", $GateAConfig)
}
if (-not [string]::IsNullOrWhiteSpace($GateAEvidence)) {
    $pyArgs += @("--gate-a-evidence", $GateAEvidence)
}
if (-not [string]::IsNullOrWhiteSpace($StatusPath)) {
    $pyArgs += @("--status-path", $StatusPath)
}
if (-not [string]::IsNullOrWhiteSpace($ProbesRoot)) {
    $pyArgs += @("--probes-root", $ProbesRoot)
}
if ($AllowNonPrivate) {
    $pyArgs += @("--allow-non-private")
}
if ($LiveProbe) {
    $pyArgs += @("--live-probe")
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
