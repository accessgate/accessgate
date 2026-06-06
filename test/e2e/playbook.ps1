#!/usr/bin/env pwsh
# E2E smoke playbook for the docker-compose quickstart stack (roadmap #78).
#
# Invoked by `make e2e-docker` AFTER the stack is up. It waits for the proxy to
# report healthy, then asserts the sample policy's allow/deny decisions through
# the proxy:
#
#   GET /anything/allow  -> 200 (allow, proxied to upstream)
#   GET /anything/deny   -> 403 (explicit deny)
#   GET /anything/secret -> 403 (deny-by-default)
#
# Exits non-zero on the first failed assertion so `make e2e-docker` fails the
# build. This script makes no Docker calls itself — lifecycle (up/down) is owned
# by the Makefile target so teardown always runs.

$ErrorActionPreference = 'Stop'

$proxy = $env:PROXY_BASE_URL
if ([string]::IsNullOrWhiteSpace($proxy)) { $proxy = 'http://localhost:8081' }

# Get-StatusCode returns the HTTP status code as an int, or 0 on a transport
# error (connection refused / DNS / timeout). Works on both Windows PowerShell
# 5.1 and PowerShell 7+: 5.1's Invoke-WebRequest throws on 4xx/5xx, so we read
# the status off the thrown WebException's Response (rather than relying on the
# PS7-only -SkipHttpErrorCheck switch).
function Get-StatusCode {
    param([string]$Url, [int]$TimeoutSeconds = 5)
    try {
        $r = Invoke-WebRequest -Uri $Url -Method GET -TimeoutSec $TimeoutSeconds -UseBasicParsing
        return [int]$r.StatusCode
    } catch {
        $resp = $_.Exception.Response
        if ($resp -and $resp.StatusCode) { return [int]$resp.StatusCode }
        return 0
    }
}

function Wait-Healthy {
    param([string]$Url, [int]$TimeoutSeconds = 90)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if ((Get-StatusCode -Url $Url -TimeoutSeconds 3) -eq 200) { return }
        Start-Sleep -Seconds 2
    }
    throw "timed out waiting for $Url to become healthy"
}

function Assert-Status {
    param([string]$Path, [int]$Want)
    $got = Get-StatusCode -Url "$proxy$Path"
    if ($got -ne $Want) {
        throw "FAIL  GET $Path -> $got (want $Want)"
    }
    Write-Host ("PASS  GET {0} -> {1}" -f $Path, $got)
}

Write-Host "[e2e] waiting for proxy health at $proxy/healthz ..."
Wait-Healthy -Url "$proxy/healthz"

Write-Host "[e2e] asserting allow/deny decisions through the proxy ..."
Assert-Status -Path '/anything/allow'  -Want 200
Assert-Status -Path '/anything/deny'   -Want 403
Assert-Status -Path '/anything/secret' -Want 403

Write-Host "[e2e] all assertions passed."
exit 0
