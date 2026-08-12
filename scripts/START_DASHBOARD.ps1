param(
    [int]$Port = 8765
)

$ErrorActionPreference = "Stop"
$OutputEncoding = [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
if ($Port -lt 1 -or $Port -gt 65535) {
    @{ ok = $false; event = "dashboard_start_failed"; reason = "invalid_port"; port = $Port } |
        ConvertTo-Json -Compress
    exit 1
}
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$PythonPath = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $PythonPath)) {
    @{ ok = $false; event = "dashboard_start_failed"; reason = "python_missing" } |
        ConvertTo-Json -Compress
    exit 1
}

Push-Location $ProjectRoot
try {
    $env:PYTHONUTF8 = "1"
    & $PythonPath -m r3radar dashboard --host 127.0.0.1 --port $Port
    $ExitCode = $LASTEXITCODE
}
catch {
    @{
        ok = $false
        event = "dashboard_start_failed"
        reason = "launcher_exception"
        error = $_.Exception.Message
    } | ConvertTo-Json -Compress
    $ExitCode = 1
}
finally {
    Pop-Location
}
exit $ExitCode
