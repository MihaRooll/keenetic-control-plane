<#
.SYNOPSIS
  Validate docs/docs-map.json against docs-map-schema rules (Windows PowerShell 5.1).
#>
param(
    [string]$ProjectRoot = "",

    [switch]$SelfTest
)

$ErrorActionPreference = "Stop"
$ScriptRoot = $PSScriptRoot
$ToolkitRoot = (Resolve-Path (Join-Path $ScriptRoot "..")).Path
$Fail = 0

$ValidStatuses = @("active", "draft", "deprecated", "planned")

function Pass([string]$Message) {
    Write-Host "OK  $Message"
}

function Fail([string]$Message) {
    Write-Host "FAIL $Message"
    $script:Fail++
}

function Assert-True($Condition, [string]$Message) {
    if ($Condition) { Pass $Message } else { Fail $Message }
}

function Test-PathUnderRoot([string]$FullPath, [string]$Root) {
    $full = [System.IO.Path]::GetFullPath($FullPath)
    $root = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    if ($full.Equals($root, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    $prefix = $root + [System.IO.Path]::DirectorySeparatorChar
    return $full.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-IsAbsoluteEntryPath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    if ($Path -match '^[a-zA-Z]:') { return $true }
    if ($Path -match '^\\\\') { return $true }
    if ($Path -match '^/') { return $true }
    return $false
}

function Read-JsonFile([string]$Path) {
    $raw = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
    if ($raw.Length -gt 0 -and [int][char]$raw[0] -eq 0xFEFF) {
        $raw = $raw.Substring(1)
    }
    return ($raw | ConvertFrom-Json)
}

function Test-EntryObject($Entry, [int]$Index, [string]$MapPath) {
    $label = "entry[$Index]"
    if ($null -eq $Entry) {
        Fail "$label is null ($MapPath)"
        return $null
    }
    $path = [string]$Entry.path
    $title = [string]$Entry.title
    $status = [string]$Entry.status

    if ([string]::IsNullOrWhiteSpace($path)) {
        Fail "$label.path required ($MapPath)"
        return $null
    } elseif (Test-IsAbsoluteEntryPath $path) {
        Fail "$label.path must be relative ($MapPath)"
        return $null
    } elseif ($path -match '\.\.') {
        Fail "$label.path must not contain .. ($MapPath)"
        return $null
    }

    if ([string]::IsNullOrWhiteSpace($title)) {
        Fail "$label.title required ($MapPath)"
    } elseif ($title.Length -gt 120) {
        Fail "$label.title too long ($MapPath)"
    }

    if ([string]::IsNullOrWhiteSpace($status)) {
        Fail "$label.status required ($MapPath)"
    } elseif ($ValidStatuses -notcontains $status) {
        Fail "$label.status invalid: $status ($MapPath)"
    }

    $owners = @($Entry.owners)
    if ($owners.Count -lt 1) {
        Fail "$label.owners requires at least one ($MapPath)"
    } else {
        foreach ($o in $owners) {
            $os = [string]$o
            if ([string]::IsNullOrWhiteSpace($os)) {
                Fail "$label.owners contains empty value ($MapPath)"
            } elseif ($os.Length -gt 64) {
                Fail "$label.owners value too long ($MapPath)"
            }
        }
    }

    if ($null -ne $Entry.tags) {
        foreach ($t in @($Entry.tags)) {
            $ts = [string]$t
            if ([string]::IsNullOrWhiteSpace($ts)) {
                Fail "$label.tags contains empty value ($MapPath)"
            } elseif ($ts.Length -gt 32) {
                Fail "$label.tags value too long ($MapPath)"
            }
        }
    }

    return @{
        path   = $path
        status = $status
    }
}

function Test-DocsMap([string]$Root, [string]$MapRelPath) {
    $mapPath = Join-Path $Root $MapRelPath
    if (-not (Test-Path -LiteralPath $mapPath)) {
        Fail "missing map: $MapRelPath"
        return
    }

    $obj = $null
    try {
        $obj = Read-JsonFile $mapPath
    } catch {
        Fail "JSON parse failed: $MapRelPath - $($_.Exception.Message)"
        return
    }

    $version = $obj.version
    if ($null -eq $version) {
        Fail "version required ($MapRelPath)"
    } elseif ([int]$version -ne 1) {
        Fail "version must be 1 ($MapRelPath)"
    }

    if ($null -eq $obj.entries) {
        Fail "entries array required ($MapRelPath)"
        return
    }

    $paths = @{}
    $idx = 0
    foreach ($entry in @($obj.entries)) {
        $entryInfo = Test-EntryObject $entry $idx $MapRelPath
        if ($null -ne $entryInfo -and -not [string]::IsNullOrWhiteSpace($entryInfo.path)) {
            $p = [string]$entryInfo.path
            $estatus = [string]$entryInfo.status
            if ($paths.ContainsKey($p)) {
                Fail "duplicate path: $p ($MapRelPath)"
            } else {
                $paths[$p] = $true
                $candidate = Join-Path $Root ($p -replace '/', '\')
                $exists = Test-Path -LiteralPath $candidate
                if ($estatus -eq "planned") {
                    if ($exists) {
                        Fail "planned entry path already exists; promote to active: $p ($MapRelPath)"
                    }
                } elseif (-not $exists) {
                    Fail "referenced path missing: $p ($MapRelPath)"
                } else {
                    $full = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $candidate).Path)
                    if (-not (Test-PathUnderRoot $full $Root)) {
                        Fail "entry.path escapes project root: $p ($MapRelPath)"
                    }
                }
            }
        }
        $idx++
    }

    if ($null -ne $obj.rules) {
        if ($null -ne $obj.rules.update_on_change) {
            $u = $obj.rules.update_on_change
            if ($u -isnot [bool] -and $u -isnot [System.Management.Automation.SwitchParameter]) {
                $s = [string]$u
                if ($s -notin @("True", "False", "true", "false")) {
                    Fail "rules.update_on_change must be boolean ($MapRelPath)"
                }
            }
        }
        if ($null -ne $obj.rules.validate_on_commit) {
            $v = $obj.rules.validate_on_commit
            if ($v -isnot [bool] -and $v -isnot [System.Management.Automation.SwitchParameter]) {
                $s = [string]$v
                if ($s -notin @("True", "False", "true", "false")) {
                    Fail "rules.validate_on_commit must be boolean ($MapRelPath)"
                }
            }
        }
    }
}

function Invoke-SelfTest {
    Write-Host "=== validate-project-docs self-test ==="
    $fixturesRoot = Join-Path $ToolkitRoot "tests\project-docs\fixtures"
    $assertFail = 0

    $validRoot = Join-Path $fixturesRoot "valid"
    $start = $script:Fail
    Test-DocsMap $validRoot "docs-map.json"
    if ($script:Fail -ne $start) {
        Write-Host "FAIL valid fixture passes"
        $assertFail++
    } else {
        Pass "valid fixture passes"
    }
    $script:Fail = $start

    $badSchemaRoot = Join-Path $fixturesRoot "invalid-schema"
    $start = $script:Fail
    Test-DocsMap $badSchemaRoot "docs-map.json"
    if ($script:Fail -eq $start) {
        Write-Host "FAIL invalid-schema fixture fails"
        $assertFail++
    } else {
        Pass "invalid-schema fixture fails"
    }
    $script:Fail = $start

    $badPathRoot = Join-Path $fixturesRoot "invalid-missing-path"
    $start = $script:Fail
    Test-DocsMap $badPathRoot "docs-map.json"
    if ($script:Fail -eq $start) {
        Write-Host "FAIL invalid-missing-path fixture fails"
        $assertFail++
    } else {
        Pass "invalid-missing-path fixture fails"
    }
    $script:Fail = $start

    $badAbsRoot = Join-Path $fixturesRoot "invalid-absolute-path"
    $start = $script:Fail
    Test-DocsMap $badAbsRoot "docs-map.json"
    if ($script:Fail -eq $start) {
        Write-Host "FAIL invalid-absolute-path fixture fails"
        $assertFail++
    } else {
        Pass "invalid-absolute-path fixture fails"
    }
    $script:Fail = $start

    $bracketRoot = Join-Path $fixturesRoot "valid-bracket-unicode"
    if (Test-Path -LiteralPath (Join-Path $bracketRoot "docs-map.json")) {
        $start = $script:Fail
        Test-DocsMap $bracketRoot "docs-map.json"
        if ($script:Fail -ne $start) {
            Write-Host "FAIL valid-bracket-unicode fixture passes"
            $assertFail++
        } else {
            Pass "valid-bracket-unicode fixture passes"
        }
        $script:Fail = $start
    } else {
        Write-Host "FAIL missing valid-bracket-unicode fixture"
        $assertFail++
    }

    $script:Fail = $assertFail
}

Write-Host "=== Validate project docs ==="

if ($SelfTest) {
    Invoke-SelfTest
} else {
    if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
        $ProjectRoot = (Get-Location).Path
    }
    $ProjectRoot = (Resolve-Path -LiteralPath $ProjectRoot).Path
    Test-DocsMap $ProjectRoot "docs\docs-map.json"
}

Write-Host ""
if ($Fail -eq 0) {
    Write-Host "DOCS_VALIDATE_PASS"
    exit 0
}

Write-Host "DOCS_VALIDATE_FAIL: $Fail finding(s)"
exit 1
