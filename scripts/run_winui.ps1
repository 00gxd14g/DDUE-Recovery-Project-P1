[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$BuildOnly,
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$projectPath = Join-Path $repoRoot "winui/PyDDEU.WinUI/PyDDEU.WinUI.csproj"
$venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"
$altVenvPython = Join-Path $repoRoot "venv\Scripts\python.exe"
$pythonCmd = if (Test-Path $venvPython) {
    $venvPython
} elseif (Test-Path $altVenvPython) {
    $altVenvPython
} else {
    "python"
}

Push-Location $repoRoot
try {
    if ($PSCmdlet.ShouldProcess($pythonCmd, "Run Python bridge health check")) {
        Write-Host "== Python bridge health ==" -ForegroundColor Cyan
        & $pythonCmd -m pyddeu.winui_bridge --health
    }

    if ($PSCmdlet.ShouldProcess($projectPath, "Build WinUI app ($Configuration)")) {
        Write-Host "`n== Build WinUI app ==" -ForegroundColor Cyan
        dotnet build $projectPath -c $Configuration
    }

    if ($BuildOnly) {
        return
    }

    if ($PSCmdlet.ShouldProcess($projectPath, "Launch WinUI app ($Configuration)")) {
        Write-Host "`n== Launch WinUI app ==" -ForegroundColor Cyan
        dotnet run --project $projectPath -c $Configuration
    }
}
finally {
    Pop-Location
}
