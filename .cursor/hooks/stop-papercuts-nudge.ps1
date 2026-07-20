# Occasional nudge to triage papercuts (not every stop).
$ErrorActionPreference = "SilentlyContinue"
$raw = [Console]::In.ReadToEnd()
try { $evt = $raw | ConvertFrom-Json } catch { Write-Output "{}"; exit 0 }

$status = [string]$evt.status
$loop = 0
if ($null -ne $evt.loop_count) { $loop = [int]$evt.loop_count }

if ($status -ne "completed" -or $loop -gt 0) { Write-Output "{}"; exit 0 }

$root = (Get-Location).Path
$stateDir = Join-Path $root ".cursor\hooks\state"
New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
$nudgeFile = Join-Path $stateDir "papercuts-nudge.json"
$today = (Get-Date).ToString("yyyy-MM-dd")

if (Test-Path $nudgeFile) {
    try {
        $prev = Get-Content $nudgeFile -Raw -Encoding utf8 | ConvertFrom-Json
        if ($prev.day -eq $today) { Write-Output "{}"; exit 0 }
    } catch { }
}

$log = Join-Path $root ".papercuts.jsonl"
$openHint = "none"
if (Test-Path $log) {
    $env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
    if (-not $env:HOME -and $env:USERPROFILE) { $env:HOME = $env:USERPROFILE }
    $list = & papercuts.exe --file $log list --format md 2>$null
    if ($list -and ($list -join "`n") -match "pc_") {
        $openHint = "open"
    }
}

$utf8 = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText($nudgeFile, (@{ day = $today } | ConvertTo-Json -Compress), $utf8)

if ($openHint -eq "open") {
    @{
        followup_message = "Papercuts: есть открытые жалобы в .papercuts.jsonl. Кратко глянь `papercuts list --format md` (или /review-papercuts). Если сейчас не до triage - ответь одним словом SKIP и остановись."
    } | ConvertTo-Json -Compress
} else {
    Write-Output "{}"
}
exit 0
