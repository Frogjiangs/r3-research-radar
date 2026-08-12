param(
    [switch]$NoHostedSearch,
    [switch]$SkipAnalysis,
    [ValidateSet("auto", "codex_cli", "llama_cpp")]
    [string]$AnalysisProvider = "auto"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$PythonPath = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $PythonPath)) {
    throw "Run scripts\SETUP.ps1 first."
}
$Arguments = @("-m", "r3radar", "smoke", "--analysis-provider", $AnalysisProvider)
if ($NoHostedSearch) {
    $Arguments += "--no-hosted-search"
}
if ($SkipAnalysis) {
    $Arguments += "--skip-analysis"
}

Push-Location $ProjectRoot
try {
    & $PythonPath @Arguments
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
