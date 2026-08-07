<#
.SYNOPSIS
  Run the Router Control prototype host with DPAPI-protected hub admin password.

.DESCRIPTION
  Stores ciphertext only at %LOCALAPPDATA%\RouterControlDev\hub-admin.dpapi.
  Plaintext exists only in process-scoped $env:HUB_ADMIN_PASSWORD during uvicorn
  and is cleared in finally. Never writes .env or logs the password.

.PARAMETER Action
  start (default) — decrypt and run uvicorn on 127.0.0.1:8787 with standalone profile.
  init — create new DPAPI blob (double hidden prompt).
  rotate — replace DPAPI blob (double hidden prompt).
  clear — delete stored DPAPI blob (explicit invocation only).
#>
param(
    [ValidateSet("start", "init", "rotate", "clear")]
    [string]$Action = "start",

    [string]$ProjectRoot = ""
)

$ErrorActionPreference = "Stop"

function Get-StorePaths {
    $dir = Join-Path $env:LOCALAPPDATA "RouterControlDev"
    $file = Join-Path $dir "hub-admin.dpapi"
    return @{ Directory = $dir; File = $file }
}

function Clear-SensitiveVariable {
    param([System.Security.SecureString]$SecureString)
    if ($null -eq $SecureString) { return }
    $SecureString.Dispose()
}

function Read-MatchingSecurePassword {
    param([string]$Prompt)
    $first = Read-Host -AsSecureString -Prompt $Prompt
    $second = Read-Host -AsSecureString -Prompt "Confirm password"
    $bstrFirst = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($first)
    $bstrSecond = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($second)
    try {
        $plainFirst = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstrFirst)
        $plainSecond = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstrSecond)
        if ($plainFirst -ne $plainSecond) {
            Clear-SensitiveVariable -SecureString $first
            throw "Password confirmation mismatch."
        }
        if ([string]::IsNullOrWhiteSpace($plainFirst)) {
            Clear-SensitiveVariable -SecureString $first
            throw "Password must not be empty."
        }
        return $first
    }
    finally {
        if ($bstrFirst -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstrFirst)
        }
        if ($bstrSecond -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstrSecond)
        }
        Clear-SensitiveVariable -SecureString $second
    }
}

function Save-DpapiBlob {
    param([System.Security.SecureString]$SecurePassword)
    $paths = Get-StorePaths
    if (-not (Test-Path -LiteralPath $paths.Directory)) {
        New-Item -ItemType Directory -Path $paths.Directory -Force | Out-Null
    }
    $cipher = ConvertFrom-SecureString -SecureString $SecurePassword
    Set-Content -LiteralPath $paths.File -Value $cipher -Encoding UTF8 -NoNewline
}

function Remove-DpapiBlob {
    $paths = Get-StorePaths
    if (Test-Path -LiteralPath $paths.File) {
        Remove-Item -LiteralPath $paths.File -Force
    }
}

function Get-DecryptedSecurePassword {
    $paths = Get-StorePaths
    if (-not (Test-Path -LiteralPath $paths.File)) {
        throw "DPAPI store not found. Run with -Action init first."
    }
    $cipher = Get-Content -LiteralPath $paths.File -Raw
    $cipher = $cipher.Trim()
    if ([string]::IsNullOrEmpty($cipher)) {
        throw "DPAPI store is empty or invalid. Run with -Action init first."
    }
    return ConvertTo-SecureString -String $cipher
}

$ScriptRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
    $ProjectRoot = (Resolve-Path (Join-Path $ScriptRoot "..")).Path
}

switch ($Action) {
    "init" {
        $secure = Read-MatchingSecurePassword -Prompt "New hub admin password"
        try {
            Save-DpapiBlob -SecurePassword $secure
            Write-Host "DPAPI store initialized."
        }
        finally {
            Clear-SensitiveVariable -SecureString $secure
        }
        exit 0
    }
    "rotate" {
        $secure = Read-MatchingSecurePassword -Prompt "New hub admin password"
        try {
            Save-DpapiBlob -SecurePassword $secure
            Write-Host "DPAPI store rotated."
        }
        finally {
            Clear-SensitiveVariable -SecureString $secure
        }
        exit 0
    }
    "clear" {
        Remove-DpapiBlob
        Write-Host "DPAPI store cleared."
        exit 0
    }
    "start" {
        $secure = Get-DecryptedSecurePassword
        $bstr = [IntPtr]::Zero
        try {
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
            $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
            $env:HUB_ADMIN_PASSWORD = $plain
            $env:RC_STANDALONE_LOOPBACK_AUTH = "1"
            $env:RC_PUBLIC_BASE_URL = "http://127.0.0.1:8787"

            Push-Location $ProjectRoot
            try {
                & py.exe -3.11 -m uvicorn router_control_host.app:app --host 127.0.0.1 --port 8787
                $exitCode = $LASTEXITCODE
            }
            finally {
                Pop-Location
            }
            if ($null -eq $exitCode) { $exitCode = 0 }
            exit $exitCode
        }
        finally {
            Remove-Item Env:HUB_ADMIN_PASSWORD -ErrorAction SilentlyContinue
            Remove-Item Env:RC_STANDALONE_LOOPBACK_AUTH -ErrorAction SilentlyContinue
            Remove-Item Env:RC_PUBLIC_BASE_URL -ErrorAction SilentlyContinue
            $plain = $null
            if ($bstr -ne [IntPtr]::Zero) {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            }
            Clear-SensitiveVariable -SecureString $secure
        }
    }
}

exit 0
