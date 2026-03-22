[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$BuildOnly,
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$projectPath = Join-Path $repoRoot "winui/PyDDEU.WinUI/PyDDEU.WinUI.csproj"
$targetFramework = "net9.0-windows10.0.19041.0"
$runtimeIdentifier = "win-x64"
$outputDir = Join-Path $repoRoot ("winui/PyDDEU.WinUI\bin\{0}\{1}\{2}" -f $Configuration, $targetFramework, $runtimeIdentifier)
$exePath = Join-Path $outputDir "PyDDEU.WinUI.exe"
$debugLogDir = Join-Path $repoRoot ".logs"
$debugLogPath = Join-Path $debugLogDir "winui-debug-console.log"
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

    if (!(Test-Path $debugLogDir)) {
        New-Item -ItemType Directory -Path $debugLogDir | Out-Null
    }
    if (Test-Path $debugLogPath) {
        Remove-Item $debugLogPath -Force
    }
    $env:PYDDEU_DEBUG_LOG = $debugLogPath

    if ($PSCmdlet.ShouldProcess($exePath, "Launch WinUI app ($Configuration)")) {
        Write-Host "`n== Launch WinUI app ==" -ForegroundColor Cyan
        if (!(Test-Path $exePath)) {
            throw "Built executable not found: $exePath"
        }

        Write-Host "Debug log: $debugLogPath" -ForegroundColor DarkGray
        $proc = Start-Process -FilePath $exePath -WorkingDirectory $outputDir -PassThru

        $script:printedLineCount = 0
        function Write-NewLogLines {
            if (!(Test-Path $debugLogPath)) {
                return
            }
            $lines = @(Get-Content -LiteralPath $debugLogPath -ErrorAction SilentlyContinue)
            if ($script:printedLineCount -gt $lines.Count) {
                $script:printedLineCount = 0
            }
            for ($i = $script:printedLineCount; $i -lt $lines.Count; $i++) {
                Write-Host $lines[$i]
            }
            $script:printedLineCount = $lines.Count
        }

        try {
            while (-not $proc.HasExited) {
                Write-NewLogLines
                Start-Sleep -Milliseconds 300
                $proc.Refresh()
            }
        }
        finally {
            Write-NewLogLines
        }

        Write-Host "`nWinUI process exited with code $($proc.ExitCode)." -ForegroundColor Yellow
        Read-Host "Press Enter to close the debug terminal"
    }
}
finally {
    Pop-Location
}
