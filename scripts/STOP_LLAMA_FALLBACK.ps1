$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$WorkspaceRoot = Split-Path -Parent (Split-Path -Parent $ProjectRoot)
$ConfigPath = Join-Path $ProjectRoot "config\r3.v1.json"
$Config = Get-Content -Raw -Encoding UTF8 $ConfigPath | ConvertFrom-Json
$ExpectedExecutable = [IO.Path]::GetFullPath(
    $Config.analysis.llama_cpp.managed_server.executable
)
$ExpectedAlias = [string]$Config.analysis.llama_cpp.model
$ExpectedPort = [int]$Config.analysis.llama_cpp.managed_server.port
$PidPath = Join-Path $WorkspaceRoot "outputs\r3_research_radar\llama_server\server.pid.json"

if (-not (Test-Path -LiteralPath $PidPath)) {
    Write-Output "No managed llama.cpp PID record exists."
    exit 0
}

try {
    $Record = Get-Content -Raw -Encoding UTF8 -LiteralPath $PidPath | ConvertFrom-Json
}
catch {
    throw "Managed PID record is invalid; refusing to stop any process."
}

$ServerPid = [int]$Record.pid
$Process = Get-Process -Id $ServerPid -ErrorAction SilentlyContinue
if ($null -eq $Process) {
    Remove-Item -LiteralPath $PidPath
    Write-Output "Managed llama.cpp process is no longer running."
    exit 0
}

$ActualExecutable = [IO.Path]::GetFullPath($Process.Path)
$ActualStart = $Process.StartTime.ToUniversalTime().ToString("o")
if (
    $ActualExecutable -ine $ExpectedExecutable -or
    $ActualStart -ne [string]$Record.start_time_utc -or
    [string]$Record.model_alias -ne $ExpectedAlias -or
    [int]$Record.port -ne $ExpectedPort
) {
    throw "PID record does not prove ownership; refusing to stop the process."
}

Stop-Process -Id $ServerPid
if (-not $Process.WaitForExit(15000)) {
    throw "llama.cpp did not exit within 15 seconds; PID record was preserved."
}
Remove-Item -LiteralPath $PidPath
Write-Output "Managed llama.cpp fallback stopped."
