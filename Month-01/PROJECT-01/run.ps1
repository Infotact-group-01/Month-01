<#
.SYNOPSIS
    TIP Project — Development Helper Script
.DESCRIPTION
    Common tasks wrapped in a single script for smooth workflow.
.EXAMPLE
    .\run.ps1 setup    # Create venv + install deps
    .\run.ps1 ingest   # Run ingestion pipeline
    .\run.ps1 test     # Run pytest suite
    .\run.ps1 fetch    # Fetch feeds (no DB)
    .\run.ps1 stats    # Show DB statistics
    .\run.ps1 feeds    # List configured feeds
    .\run.ps1 clean    # Remove __pycache__, .pytest_cache
#>

param(
    [Parameter(Position = 0)]
    [ValidateSet("setup", "ingest", "test", "fetch", "stats", "feeds", "clean", "help")]
    [string]$Command = "help"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = $PSScriptRoot

function Write-Header($text) {
    $bar = "─" * 60
    Write-Host ""
    Write-Host $bar -ForegroundColor Magenta
    Write-Host "  $text" -ForegroundColor White
    Write-Host $bar -ForegroundColor Magenta
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

switch ($Command) {

    "setup" {
        Write-Header "Setting up development environment"

        # Create venv if it doesn't exist
        $venvPath = Join-Path $ProjectRoot "venv"
        if (-not (Test-Path $venvPath)) {
            Write-Host "  Creating virtual environment..." -ForegroundColor Cyan
            python -m venv $venvPath
        } else {
            Write-Host "  Virtual environment already exists." -ForegroundColor Green
        }

        # Activate and install deps
        Activate-Venv
        Write-Host "  Installing dependencies..." -ForegroundColor Cyan
        pip install -r (Join-Path $ProjectRoot "requirements.txt") --quiet
        Write-Host "  ✓ Setup complete!" -ForegroundColor Green
    }

    "ingest" {
        Write-Header "Running Ingestion Pipeline"
        Activate-Venv
        Set-Location $ProjectRoot
        python -m src.cli ingest
    }

    "test" {
        Write-Header "Running Test Suite"
        Activate-Venv
        Set-Location $ProjectRoot
        python -m pytest tests/ -v --tb=short
    }

    "fetch" {
        Write-Header "Fetching Feeds (no DB insert)"
        Activate-Venv
        Set-Location $ProjectRoot
        python -m src.cli fetch
    }

    "stats" {
        Write-Header "Database Statistics"
        Activate-Venv
        Set-Location $ProjectRoot
        python -m src.cli stats
    }

    "feeds" {
        Write-Header "Configured Feeds"
        Activate-Venv
        Set-Location $ProjectRoot
        python -m src.cli feeds
    }

    "clean" {
        Write-Header "Cleaning build artifacts"
        $cleaned = 0

        Get-ChildItem -Path $ProjectRoot -Recurse -Directory -Filter "__pycache__" | ForEach-Object {
            Remove-Item $_.FullName -Recurse -Force
            $cleaned++
        }

        $pytestCache = Join-Path $ProjectRoot ".pytest_cache"
        if (Test-Path $pytestCache) {
            Remove-Item $pytestCache -Recurse -Force
            $cleaned++
        }

        Write-Host "  ✓ Cleaned $cleaned artifact(s)." -ForegroundColor Green
    }

    "help" {
        Write-Host ""
        Write-Host "  TIP Project — Development Helper" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  Usage: .\run.ps1 <command>" -ForegroundColor White
        Write-Host ""
        Write-Host "  Commands:" -ForegroundColor White
        Write-Host "    setup    Create venv + install dependencies" -ForegroundColor Gray
        Write-Host "    ingest   Run the full ingestion pipeline" -ForegroundColor Gray
        Write-Host "    test     Run the pytest test suite" -ForegroundColor Gray
        Write-Host "    fetch    Fetch feeds (JSON output, no DB)" -ForegroundColor Gray
        Write-Host "    stats    Show database statistics" -ForegroundColor Gray
        Write-Host "    feeds    List configured feed sources" -ForegroundColor Gray
        Write-Host "    clean    Remove __pycache__ and .pytest_cache" -ForegroundColor Gray
        Write-Host "    help     Show this help message" -ForegroundColor Gray
        Write-Host ""
    }
}
