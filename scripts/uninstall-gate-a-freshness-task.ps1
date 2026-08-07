<#
.SYNOPSIS
  Remove Windows Scheduled Tasks for Gate A freshness recertification.
  Uses schtasks.exe (no elevation required).
#>
param(
    [string]$TaskName = "RouterControl-GateA-FreshnessAuto"
)

$ErrorActionPreference = "Stop"

function Remove-SchtasksIfPresent {
    param([string]$Name)
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    try {
        & schtasks.exe /query /tn $Name *> $null
        $exists = ($LASTEXITCODE -eq 0)
    } finally {
        $ErrorActionPreference = $prevEap
    }
    if ($exists) {
        & schtasks.exe /delete /tn $Name /f
        if ($LASTEXITCODE -ne 0) {
            throw "schtasks /delete failed for '$Name' (exit $LASTEXITCODE)"
        }
        Write-Host "Removed scheduled task $Name"
    } else {
        Write-Host "Scheduled task $Name not found (nothing to remove)"
    }
}

Remove-SchtasksIfPresent -Name "$TaskName-Logon"
Remove-SchtasksIfPresent -Name "$TaskName-Interval"
Remove-SchtasksIfPresent -Name $TaskName
