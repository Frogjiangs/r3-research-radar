param(
    [int]$Iterations = 300,
    [int]$MaxSeconds = 0,
    [string]$ResumeRunId = ""
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$pythonPath = Join-Path $projectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $pythonPath)) {
    throw "Virtual environment is missing. Run scripts\SETUP.ps1 first."
}

$continuityArguments = @(
    "-m",
    "r3radar",
    "continuity-test",
    "--iterations",
    [string]$Iterations,
    "--max-seconds",
    [string]$MaxSeconds
)
if ($ResumeRunId) {
    $continuityArguments += @("--resume-run-id", $ResumeRunId)
}

Push-Location $projectRoot
try {
    & $pythonPath @continuityArguments
    $continuityExitCode = $LASTEXITCODE
} finally {
    Pop-Location
}
exit $continuityExitCode
