# Ensure Windows HOME for papercuts; optional stage+doctor context (fail-open).
$ErrorActionPreference = "SilentlyContinue"

try {
    [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false
    $OutputEncoding = [Console]::OutputEncoding
} catch { }

if (-not $env:HOME -and $env:USERPROFILE) {
    $env:HOME = $env:USERPROFILE
}

# Capture hook script root at script scope (MyInvocation is null inside nested functions).
$HookScriptRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($HookScriptRoot)) {
    $HookScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
}

function Test-ProjectMarkers {
    param([string]$Dir)
    if ([string]::IsNullOrWhiteSpace($Dir) -or -not (Test-Path -LiteralPath $Dir)) { return $false }
    foreach ($marker in @(".git", "AGENTS.md", "docs\docs-map.json")) {
        if (Test-Path -LiteralPath (Join-Path $Dir $marker)) { return $true }
    }
    return $false
}

function Get-HookProjectRoot {
    if ($env:CURSOR_PROJECT_DIR -and (Test-Path -LiteralPath $env:CURSOR_PROJECT_DIR)) {
        return (Resolve-Path -LiteralPath $env:CURSOR_PROJECT_DIR).Path
    }
    if ($env:CURSOR_SESSION_PROJECT_ROOT -and (Test-Path -LiteralPath $env:CURSOR_SESSION_PROJECT_ROOT)) {
        return (Resolve-Path -LiteralPath $env:CURSOR_SESSION_PROJECT_ROOT).Path
    }
    if (-not [string]::IsNullOrWhiteSpace($script:HookScriptRoot)) {
        $hookCandidate = (Resolve-Path (Join-Path $script:HookScriptRoot "..\..")).Path
        $hooksDir = Join-Path $hookCandidate ".cursor\hooks"
        $selfHook = Join-Path $hooksDir "session-start.ps1"
        if ((Test-Path -LiteralPath $hooksDir) -and (Test-Path -LiteralPath $selfHook)) {
            return $hookCandidate
        }
    }
    try {
        $cwd = (Get-Location).Path
        if (Test-ProjectMarkers $cwd) {
            return $cwd
        }
    } catch { }
    if (-not [string]::IsNullOrWhiteSpace($script:HookScriptRoot)) {
        return (Resolve-Path (Join-Path $script:HookScriptRoot "..\..")).Path
    }
    return (Get-Location).Path
}

function Stop-ProcessTree {
    param([int]$ProcessId)
    if ($ProcessId -le 0) { return }
    try {
        & taskkill.exe /T /F /PID $ProcessId 2>$null | Out-Null
    } catch { }
    try {
        $p = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if ($p -and -not $p.HasExited) { $p.Kill() | Out-Null }
    } catch { }
}

function Read-CaptureFileBounded {
    param(
        [string]$Path,
        [int]$MaxChars = 8192
    )
    if (-not (Test-Path -LiteralPath $Path)) { return "" }
    $stream = $null
    $reader = $null
    try {
        $stream = [System.IO.File]::Open(
            $Path,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::ReadWrite
        )
        $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8)
        $buffer = New-Object char[] 4096
        $sb = New-Object System.Text.StringBuilder
        $remaining = $MaxChars
        while ($remaining -gt 0) {
            $toRead = [Math]::Min($buffer.Length, $remaining)
            $read = $reader.ReadBlock($buffer, 0, $toRead)
            if ($read -le 0) { break }
            [void]$sb.Append($buffer, 0, $read)
            $remaining -= $read
        }
        return $sb.ToString()
    } catch {
        return ""
    } finally {
        if ($null -ne $reader) {
            try { $reader.Dispose() } catch { }
        } elseif ($null -ne $stream) {
            try { $stream.Dispose() } catch { }
        }
    }
}

function Invoke-DoctorChild {
    param(
        [string]$DoctorPath,
        [int]$TimeoutMs = 3000
    )
    $result = @{
        stdout = ""
        stderr = ""
        timedOut = $false
        exitCode = 0
        pid = 0
    }
    $p = $null
    $stdoutFile = $null
    $stderrFile = $null
    try {
        $stdoutFile = Join-Path $env:TEMP ("cptk-doc-out-" + [guid]::NewGuid().ToString("n") + ".txt")
        $stderrFile = Join-Path $env:TEMP ("cptk-doc-err-" + [guid]::NewGuid().ToString("n") + ".txt")

        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "powershell.exe"

        $rootEnv = ""
        $projectRoot = ""
        if ($env:CURSOR_PROJECT_DIR) { $projectRoot = $env:CURSOR_PROJECT_DIR }
        elseif ($env:CURSOR_SESSION_PROJECT_ROOT) { $projectRoot = $env:CURSOR_SESSION_PROJECT_ROOT }
        if (-not [string]::IsNullOrWhiteSpace($projectRoot)) {
            $escRoot = $projectRoot.Replace("'", "''")
            $rootEnv = "`$env:CURSOR_PROJECT_DIR='$escRoot'; `$env:CURSOR_SESSION_PROJECT_ROOT='$escRoot'; "
        }
        $escDoctor = $DoctorPath.Replace("'", "''")
        $escOut = $stdoutFile.Replace("'", "''")
        $escErr = $stderrFile.Replace("'", "''")
        $innerCmd = "${rootEnv}& '$escDoctor' 1>'$escOut' 2>'$escErr'; exit `$LASTEXITCODE"
        $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -Command `"& { $innerCmd }`""
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.RedirectStandardInput = $true
        $psi.CreateNoWindow = $true

        $p = New-Object System.Diagnostics.Process
        $p.StartInfo = $psi
        [void]$p.Start()
        $p.StandardInput.Close()
        $result.pid = $p.Id

        if (-not $p.WaitForExit($TimeoutMs)) {
            $result.timedOut = $true
            Stop-ProcessTree -ProcessId $p.Id
            [void]$p.WaitForExit(500)
            try {
                [void]$p.StandardOutput.ReadToEnd()
                [void]$p.StandardError.ReadToEnd()
            } catch { }
        } elseif ($p.HasExited) {
            try {
                [void]$p.StandardOutput.ReadToEnd()
                [void]$p.StandardError.ReadToEnd()
            } catch { }
            $result.exitCode = $p.ExitCode
            if (Test-Path -LiteralPath $stdoutFile) {
                $result.stdout = Read-CaptureFileBounded -Path $stdoutFile
            }
            if (Test-Path -LiteralPath $stderrFile) {
                $result.stderr = Read-CaptureFileBounded -Path $stderrFile
            }
        }
    } catch {
        $result.stderr = [string]$_.Exception.Message
    } finally {
        if ($null -ne $p -and -not $p.HasExited) {
            Stop-ProcessTree -ProcessId $p.Id
            [void]$p.WaitForExit(500)
        }
        if ($null -ne $p) {
            try { $p.Dispose() } catch { }
        }
        foreach ($captureFile in @($stdoutFile, $stderrFile)) {
            if ($captureFile -and (Test-Path -LiteralPath $captureFile)) {
                Remove-Item -LiteralPath $captureFile -Force -ErrorAction SilentlyContinue
            }
        }
    }
    return $result
}

function Test-SensitiveEnvName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    $sk = 'sk' + '-'
    $ghp = 'gh' + 'p_'
    $gho = 'gh' + 'o_'
    $xox = 'xox' + '[baprs]-'
    $ai = 'AI' + 'za'
    $pat = '(?i)(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|github_pat_|^' + [regex]::Escape($sk) + '|' + [regex]::Escape($ghp) + '|' + [regex]::Escape($gho) + '|' + $xox + '|' + [regex]::Escape($ai) + ')'
    return ($Name -match $pat)
}

function Redact-SecretPatterns {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return "" }
    $redacted = [regex]::Replace($Text, '(?i)(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)\s*[=:]\s*\S+', '$1=[redacted]')
    $redacted = [regex]::Replace($redacted, '(?i)(api[_-]?key|auth[_-]?token)\s*[=:]\s*\S+', '$1=[redacted]')
    $sk = 'sk' + '-'
    $ghp = 'gh' + 'p_'
    $redacted = [regex]::Replace($redacted, ('(?i)\b(' + [regex]::Escape($sk) + '|' + [regex]::Escape($ghp) + '|github_pat_)[^\s''"]+'), '[redacted]')
    return $redacted
}

function Redact-EnvSecretValues {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return "" }
    $redacted = $Text
    foreach ($scope in @("Process", "User", "Machine")) {
        try {
            $table = [Environment]::GetEnvironmentVariables($scope)
            foreach ($key in $table.Keys) {
                $name = [string]$key
                if (Test-SensitiveEnvName $name) {
                    $val = [string]$table[$key]
                    if (-not [string]::IsNullOrEmpty($val)) {
                        $redacted = $redacted.Replace($val, '[redacted]')
                    }
                }
            }
        } catch { }
    }
    return $redacted
}

function Truncate-InjectContext {
    param(
        [string]$Text,
        [int]$MaxLen = 1200
    )
    if ($null -eq $Text) { return "" }
    if ($Text.Length -le $MaxLen) { return $Text }
    return ($Text.Substring(0, $MaxLen - 3) + "...")
}

function Get-NextActionHint {
    param([string]$StatePath)
    if (-not (Test-Path -LiteralPath $StatePath)) { return "" }
    try {
        $content = [System.IO.File]::ReadAllText($StatePath, [System.Text.Encoding]::UTF8)
        if ($content -match '(?msi)^##\s*next_checks\s*\r?\n(.*?)(?=^\s*##\s|\z)') {
            $section = $matches[1]
            if ($section -match '(?m)^\s*-\s*\[\s\]\s*(.+?)\s*$') {
                return "Next: $($matches[1].Trim()). "
            }
        }
        if ($content -match '(?msi)^##\s*next_action\s*\r?\n(.*?)(?=^\s*##\s|\z)') {
            $section = $matches[1]
            foreach ($line in ($section -split '\r?\n')) {
                $t = $line.Trim()
                if (-not [string]::IsNullOrWhiteSpace($t)) {
                    return "Next: $t. "
                }
            }
        }
    } catch { }
    return ""
}

function Get-StageHint {
    param([string]$StatePath)
    if (-not (Test-Path -LiteralPath $StatePath)) { return "" }
    $hint = ""
    try {
        $content = [System.IO.File]::ReadAllText($StatePath, [System.Text.Encoding]::UTF8)
        if ($content -match '(?mi)^##\s*phase\s*\r?\n\s*(.+?)(\r?\n|$)') {
            $hint = "Stage: $($matches[1].Trim()). "
        } elseif ($content -match '(?mi)^phase:\s*(.+)$') {
            $hint = "Stage: $($matches[1].Trim()). "
        }
        $hint += (Get-NextActionHint -StatePath $StatePath)
    } catch { }
    return $hint
}

function Emit-HookJson {
    param([string]$Additional)
    $payload = @{ additional_context = $Additional }
    Write-Output ($payload | ConvertTo-Json -Compress)
}

$root = Get-HookProjectRoot
$doctorPath = if ($env:CURSOR_SESSION_DOCTOR_PATH) { $env:CURSOR_SESSION_DOCTOR_PATH } else { Join-Path $root "scripts\project-doctor.ps1" }
$statePath = Join-Path $root "docs\project-state.md"
$stateTemplate = Join-Path $root "templates\project-state.md"

$baseContext = @(
    "Harness: AI-first docs in docs/; live rules/skills in .cursor/.",
    "Papercuts: failed shells auto-log when possible; or papercuts add with --tag tooling.",
    "Windows: HOME should equal USERPROFILE for papercuts outside quirks."
) -join " "

$additional = $baseContext

$hasDoctor = Test-Path -LiteralPath $doctorPath
$hasStateContext = (Test-Path -LiteralPath $statePath) -or (Test-Path -LiteralPath $stateTemplate)

if ($hasStateContext) {
    try {
        $stageHint = Get-StageHint -StatePath $statePath
        if ([string]::IsNullOrWhiteSpace($stageHint) -and (Test-Path -LiteralPath $stateTemplate)) {
            $stageHint = Get-StageHint -StatePath $stateTemplate
        }
        $doctorBody = ""
        if ($hasDoctor) {
            $doctorResult = Invoke-DoctorChild -DoctorPath $doctorPath -TimeoutMs 3000
            $rawDoctor = ($doctorResult.stdout + " " + $doctorResult.stderr).Trim()
            if ($doctorResult.timedOut) {
                $rawDoctor = "doctor: timeout (>3000ms)"
            }
            $safeDoctor = Redact-SecretPatterns -Text $rawDoctor
            $safeDoctor = Redact-EnvSecretValues -Text $safeDoctor
            $doctorBody = $safeDoctor
        }
        $combined = ($stageHint + $baseContext + " " + $doctorBody).Trim()
        $additional = Truncate-InjectContext -Text $combined -MaxLen 1200
    } catch {
        $additional = $baseContext
    }
}

Emit-HookJson -Additional $additional
exit 0
