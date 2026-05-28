<#
.SYNOPSIS
    TIP Rollback API — PowerShell Launcher
.DESCRIPTION
    Starts the Flask REST API that allows SOC analysts to view and unblock
    IPs that were blocked by the Policy Enforcer Daemon.

.EXAMPLE
    .\run_api.ps1               # Start on localhost:5050
    .\run_api.ps1 -DryRun       # Start in dry-run (simulate unblocks only)
    .\run_api.ps1 -Port 8080    # Use a custom port

.NOTES
    The API is available at http://localhost:5050 by default.
    Endpoints:
        GET  /health
        GET  /api/blocked
        GET  /api/blocked/<ip>
        POST /api/rollback/<ip>
        POST /api/rollback-all
        GET  /api/audit
#>

param(
    [switch]$DryRun,
    [int]$Port = 5050,
    [string]$Host = "127.0.0.1"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = $PSScriptRoot

function Write-Header($text) {
    $bar = "─" * 65
    Write-Host ""
    Write-Host $bar -ForegroundColor Magenta
    Write-Host "  $text" -ForegroundColor White
    Write-Host $bar -ForegroundColor Magenta
    Write-Host ""
}

function Activate-Venv {
    $venvActivate = Join-Path $ProjectRoot "venv\Scripts\Activate.ps1"
    if (Test-Path $venvActivate) {
        & $venvActivate
    } else {
        Write-Host "  [!] No venv found. Run '.\run.ps1 setup' first." -ForegroundColor Yellow
        exit 1
    }
}

# ── Banner ────────────────────────────────────────────────────────────────────
Write-Header "TIP Rollback API — Week 4"

Write-Host "  URL  : http://${Host}:${Port}" -ForegroundColor Cyan
if ($DryRun) {
    Write-Host "  Mode : DRY-RUN — rollbacks are simulated, no firewall changes" -ForegroundColor Yellow
} else {
    Write-Host "  Mode : LIVE — rollbacks will remove real Windows Firewall rules" -ForegroundColor Green
}
Write-Host ""
Write-Host "  Quick test (run in another terminal):" -ForegroundColor DarkGray
Write-Host "    curl http://localhost:${Port}/health" -ForegroundColor DarkGray
Write-Host "    curl http://localhost:${Port}/api/blocked" -ForegroundColor DarkGray
Write-Host "    curl -X POST http://localhost:${Port}/api/rollback/1.2.3.4" -ForegroundColor DarkGray
Write-Host ""

# ── Activate venv ─────────────────────────────────────────────────────────────
Activate-Venv
Set-Location $ProjectRoot

# ── Build arguments ───────────────────────────────────────────────────────────
$args_list = @("--host", $Host, "--port", $Port)
if ($DryRun) { $args_list += "--dry-run" }

# ── Run ───────────────────────────────────────────────────────────────────────
python -m src.rollback_api @args_list
