param(
    [switch]$BuildOnly
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$projectPath = Join-Path $repoRoot "winui/PyDDEU.WinUI/PyDDEU.WinUI.csproj"

Push-Location $repoRoot
try {
    Write-Host "== Python bridge health ==" -ForegroundColor Cyan
    python -m pyddeu.winui_bridge --health

    Write-Host "`n== Build WinUI app ==" -ForegroundColor Cyan
    dotnet build $projectPath

    if ($BuildOnly) {
        return
    }

    Write-Host "`n== Launch WinUI app ==" -ForegroundColor Cyan
    dotnet run --project $projectPath
}
finally {
    Pop-Location
}
