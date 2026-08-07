# Offline Gate B per-family certification planner — plan/validate/export only.
param(
    [Parameter(Mandatory = $true)]
    [string]$Family,

    [string]$Manifest = "",
    [string]$Catalog = "",
    [string]$FixtureId = "",
    [string]$Export = ""
)

$ErrorActionPreference = "Stop"
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$PyScript = Join-Path $ScriptRoot "plan-gate-b-family.py"

$ArgsList = @("--family", $Family)
if ($Manifest) { $ArgsList += @("--manifest", $Manifest) }
if ($Catalog) { $ArgsList += @("--catalog", $Catalog) }
if ($FixtureId) { $ArgsList += @("--fixture-id", $FixtureId) }
if ($Export) { $ArgsList += @("--export", $Export) }

& py.exe -3.11 $PyScript @ArgsList
exit $LASTEXITCODE
