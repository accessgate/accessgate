#!/usr/bin/env pwsh
# Full lifecycle driver for the docker-compose quickstart E2E (roadmap #78),
# invoked by `make e2e-docker`. Owning the whole lifecycle in one script (rather
# than an inline multi-statement -Command) keeps it robust across Windows
# PowerShell 5.1 and PowerShell 7+ and avoids Make/cmd quoting pitfalls.
#
# Steps:
#   1. Seed deployments/docker/.env from .env.example when missing.
#   2. docker compose up -d --build (blocks until healthy via depends_on).
#   3. Run the allow/deny smoke playbook (playbook.ps1).
#   4. ALWAYS docker compose down -v (teardown), then propagate the exit code.
#
# Compose v2 (`docker compose`) is required. Run from the repo root.
$ErrorActionPreference = 'Stop'

$composeFile = 'deployments/docker/docker-compose.yml'
$composeEnv  = 'deployments/docker/.env'
$envExample  = 'deployments/docker/.env.example'
$playbook    = Join-Path $PSScriptRoot 'playbook.ps1'

if (-not (Test-Path $composeEnv)) {
    Copy-Item $envExample $composeEnv
}

Write-Host '[e2e] building and starting the quickstart stack ...'
docker compose -f $composeFile --env-file $composeEnv up -d --build
if ($LASTEXITCODE -ne 0) {
    Write-Error "[e2e] docker compose up failed (exit $LASTEXITCODE)"
    exit $LASTEXITCODE
}

$rc = 1
try {
    & $playbook
    $rc = $LASTEXITCODE
} finally {
    Write-Host '[e2e] tearing down the stack ...'
    docker compose -f $composeFile --env-file $composeEnv down -v | Out-Null
}

exit $rc
