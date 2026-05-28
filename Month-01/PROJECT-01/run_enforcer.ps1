<#
.SYNOPSIS
    TIP Policy Enforcer — PowerShell Launcher
.DESCRIPTION
    Starts the Policy Enforcer Daemon which automatically blocks high-risk
    threat indicators using Windows Firewall rules.

.EXAMPLE
    .\run_enforcer.ps1              # Run daemon (requires Admin)
    .\run_enforcer.ps1 -DryRun      # Simulate only — no real firewall changes
    .\run_enforcer.ps1 -Once        # Single cycle and exit
    .\run_enforcer.ps1 -UnblockAll  # Remove all TIP firewall rules
    .\run_enforcer.ps1 -Threshold 80  # Block IPs with risk_score >= 80

.NOTES
    ⚠️  Firewall changes require Administrator privileges.
    Right-click PowerShell → "Run as Administrator" before using real mode.
#>

param(
    [switch]$DryRun,
    [switch]$Once,
    [switch]$UnblockAll,
    [int]$Threshold = 0,
    [int]$Interval = 0
)

$ErrorActionPreference = "Stop"
$ProjectRoot = $PSScriptRoot

# ── Admin check ────────────────────────────────────────────────────────────────
function Test-Admin {
    $current = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    return $current.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

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
Write-Header "TIP Policy Enforcer — Week 3"

if ($UnblockAll) {
    Write-Host "  ⚠️  Mode: UNBLOCK ALL — will remove every TIP firewall rule" -ForegroundColor Red
} elseif ($DryRun) {
    Write-Host "  🔵 Mode: DRY-RUN — simulating only, no real firewall changes" -ForegroundColor Cyan
} elseif ($Once) {
    Write-Host "  🟡 Mode: SINGLE CYCLE — runs once and exits" -ForegroundColor Yellow
} else {
    Write-Host "  🔴 Mode: DAEMON — runs every ${Interval}s until Ctrl+C" -ForegroundColor Green
}
Write-Host ""

# ── Admin warning ─────────────────────────────────────────────────────────────
if (-not $DryRun -and -not (Test-Admin)) {
    Write-Host "  ⚠️  WARNING: PowerShell is NOT running as Administrator." -ForegroundColor Red
    Write-Host "     Windows Firewall rules require elevated privileges." -ForegroundColor Red
    Write-Host "     Either:" -ForegroundColor Yellow
    Write-Host "       1. Right-click PowerShell → Run as Administrator" -ForegroundColor Yellow
    Write-Host "       2. Use -DryRun to simulate without admin rights" -ForegroundColor Yellow
    Write-Host ""
    if (-not $Once) {
        exit 1
    }
}

# ── Activate venv ─────────────────────────────────────────────────────────────
Activate-Venv
Set-Location $ProjectRoot

# ── Build arguments ───────────────────────────────────────────────────────────
$args_list = @()

if ($DryRun)    { $args_list += "--dry-run" }
if ($Once)      { $args_list += "--once" }
if ($UnblockAll){ $args_list += "--unblock-all" }
if ($Threshold -gt 0) { $args_list += "--threshold"; $args_list += $Threshold }
if ($Interval  -gt 0) { $args_list += "--interval";  $args_list += $Interval }

# ── Run ───────────────────────────────────────────────────────────────────────
Write-Host "  Starting enforcer..." -ForegroundColor Cyan
Write-Host ""

python -m src.enforcer @args_list
