param(
    [string]$CommitMessage = "Auto-commit: $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
)

# Repository root (assumes script is placed in repo root)
$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

Set-Location $repoRoot

# Stage all changes
git add -A

# Commit (if there are staged changes)
$status = git diff --cached --quiet
if ($LASTEXITCODE -ne 0) {
    git commit -m $CommitMessage
    # Push to origin/main (adjust branch if needed)
    git push origin main
    Write-Host "Commit and push completed at $(Get-Date)" -ForegroundColor Green
} else {
    Write-Host "No changes to commit at $(Get-Date)" -ForegroundColor Yellow
}
