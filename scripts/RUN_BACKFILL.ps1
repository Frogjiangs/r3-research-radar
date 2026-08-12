param(
    [switch]$NoHostedSearch,
    [switch]$HostedOnly,
    [ValidateSet("auto", "codex_cli", "llama_cpp")]
    [string]$AnalysisProvider = "auto"
)

$ErrorActionPreference = "Stop"
if ($NoHostedSearch -and $HostedOnly) {
    throw "-NoHostedSearch and -HostedOnly are mutually exclusive."
}
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$PythonPath = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $PythonPath)) {
    throw "Run scripts\SETUP.ps1 first."
}

$Arguments = @("-m", "r3radar", "run", "--analysis-provider", $AnalysisProvider)
if ($NoHostedSearch) {
    $Arguments += "--no-hosted-search"
}
if ($HostedOnly) {
    $Arguments += "--hosted-only"
}

Push-Location $ProjectRoot
try {
    & $PythonPath @Arguments
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
