# Lightweight papercuts shim (Windows, no Rust required).
# Compatible enough for this toolkit: append-only .papercuts.jsonl
# Prefer real CLI when available: cargo install papercuts
# Usage:
#   pwsh -File scripts/papercuts.ps1 add "text" [--tag area] [--severity minor|major|blocker]
#   pwsh -File scripts/papercuts.ps1 list [--format md]
#   pwsh -File scripts/papercuts.ps1 resolve <id> [<id>...]

param(
    [Parameter(Position = 0)]
    [ValidateSet("add", "list", "resolve", "help")]
    [string]$Command = "help",

    [Parameter(Position = 1, ValueFromRemainingArguments = $true)]
    [string[]]$Rest,

    [string]$Tag = "toolkit",
    [ValidateSet("minor", "major", "blocker")]
    [string]$Severity = "minor",
    [ValidateSet("json", "md")]
    [string]$Format = "json"
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$LogFile = if ($env:PAPERCUTS_FILE) { $env:PAPERCUTS_FILE } else { Join-Path $Root ".papercuts.jsonl" }

function New-CutId {
    $bytes = New-Object byte[] 6
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return "pc_" + [BitConverter]::ToString($bytes).Replace("-", "").ToLowerInvariant()
}

function Write-JsonLine($obj) {
    $dir = Split-Path -Parent $LogFile
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $line = ($obj | ConvertTo-Json -Compress -Depth 6)
    # utf8NoBOM so official papercuts CLI does not skip the line as malformed
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::AppendAllText($LogFile, $line + [Environment]::NewLine, $utf8)
}

function Read-Records {
    if (-not (Test-Path $LogFile)) { return @() }
    $rows = @()
    Get-Content -Path $LogFile -Encoding utf8 | ForEach-Object {
        $t = $_.Trim()
        if (-not $t) { return }
        try { $rows += ($t | ConvertFrom-Json) } catch { }
    }
    return $rows
}

function Get-OpenCuts {
    $rows = Read-Records
    $resolved = @{}
    foreach ($r in $rows) {
        if ($r.kind -eq "resolve" -and $r.id) { $resolved[$r.id] = $true }
    }
    $open = @()
    foreach ($r in $rows) {
        if ($r.kind -eq "cut" -and $r.id -and -not $resolved.ContainsKey($r.id)) {
            $open += $r
        }
    }
    $rank = @{ blocker = 0; major = 1; minor = 2 }
    return $open | Sort-Object { if ($rank.ContainsKey([string]$_.severity)) { $rank[[string]$_.severity] } else { 9 } }, { $_.ts } -Descending
}

switch ($Command) {
    "help" {
        @"
papercuts.ps1 (shim) - no Rust required

  add "text" [--Tag area] [--Severity minor|major|blocker]
  list [--Format json|md]
  resolve <id> [<id>...]

Log: $LogFile
Install real CLI later: cargo install papercuts  (needs working Rust)
"@
        break
    }
    "add" {
        $text = ($Rest -join " ").Trim()
        if (-not $text) { throw "add requires text" }
        $rec = [ordered]@{
            kind     = "cut"
            id       = (New-CutId)
            ts       = (Get-Date).ToUniversalTime().ToString("o")
            agent    = "cursor-toolkit-shim"
            text     = $text
            tags     = @($Tag)
            severity = $Severity
        }
        Write-JsonLine $rec
        @{ ok = $true; data = @{ changed = $true; record = $rec }; meta = @{ shim = $true; file = $LogFile } } | ConvertTo-Json -Compress -Depth 6
        break
    }
    "list" {
        $open = @(Get-OpenCuts)
        if ($Format -eq "md") {
            Write-Output "# Open papercuts ($($open.Count))"
            Write-Output ""
            if ($open.Count -eq 0) { Write-Output "_none_"; break }
            foreach ($c in $open) {
                $tags = if ($c.tags) { ($c.tags -join ", ") } else { "-" }
                Write-Output "- **$($c.id)** [$($c.severity)] ($tags): $($c.text)"
            }
        } else {
            @{ ok = $true; data = @{ cuts = $open }; meta = @{ shim = $true; file = $LogFile } } | ConvertTo-Json -Compress -Depth 6
        }
        break
    }
    "resolve" {
        if (-not $Rest -or $Rest.Count -eq 0) { throw "resolve requires id" }
        $open = @(Get-OpenCuts)
        $resolved = @()
        foreach ($raw in $Rest) {
            $id = $raw.Trim()
            $match = $open | Where-Object { $_.id -eq $id -or $_.id.StartsWith($id) } | Select-Object -First 1
            if (-not $match) { throw "not found: $id" }
            $rec = [ordered]@{
                kind = "resolve"
                id   = $match.id
                ts   = (Get-Date).ToUniversalTime().ToString("o")
            }
            Write-JsonLine $rec
            $resolved += $match.id
        }
        @{ ok = $true; data = @{ resolved = $resolved }; meta = @{ shim = $true; file = $LogFile } } | ConvertTo-Json -Compress -Depth 6
        break
    }
}
