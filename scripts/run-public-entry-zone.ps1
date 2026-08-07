# Fail-closed launcher for the public guest entry zone (separate listener).
param(
    [string]$Bind = $env:RC_PUBLIC_ENTRY_BIND,
    [int]$Port = 0
)

$ErrorActionPreference = "Stop"

function Fail-Closed([string]$Message) {
    Write-Error $Message
    exit 1
}

if ([string]::IsNullOrWhiteSpace($Bind)) {
    Fail-Closed "RC_PUBLIC_ENTRY_BIND must be set to an explicit LAN address (not empty, not 0.0.0.0, not ::)."
}

$trimmedBind = $Bind.Trim()
if ($trimmedBind -eq "0.0.0.0" -or $trimmedBind -eq "::") {
    Fail-Closed "RC_PUBLIC_ENTRY_BIND must be a specific host address; wildcard bind is refused."
}

if ($Port -le 0) {
    $envPort = $env:RC_PUBLIC_ENTRY_PORT
    if ([string]::IsNullOrWhiteSpace($envPort)) {
        $Port = 8790
    } else {
        $Port = [int]$envPort
    }
}

if ($Port -eq 8787 -or $Port -eq 8788) {
    Fail-Closed "RC_PUBLIC_ENTRY_PORT must not use operator ports 8787 or 8788."
}

if ($Port -lt 8790) {
    Fail-Closed "RC_PUBLIC_ENTRY_PORT must be >= 8790."
}

Write-Host ""
Write-Host "=== Human action required (not performed by this script) ==="
Write-Host "1. Allow inbound TCP $Port on $trimmedBind from the guest network only."
Write-Host "   Example (Windows Defender Firewall, adjust profile/interface as needed):"
Write-Host "   New-NetFirewallRule -DisplayName 'Router Control public entry zone' -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port -RemoteAddress <guest-subnet> -Profile Private"
Write-Host "2. Do NOT expose the operator host (127.0.0.1:8787) to the guest network."
Write-Host "3. Share the guest URL: http://${trimmedBind}:$Port/p/<slug>"
Write-Host "============================================================="
Write-Host ""

$env:RC_PUBLIC_ENTRY_BIND = $trimmedBind
$env:RC_PUBLIC_ENTRY_PORT = "$Port"

Write-Host "Starting public entry zone on ${trimmedBind}:$Port ..."
py -3.11 -m uvicorn router_control_host.public_app:app --host $trimmedBind --port $Port
