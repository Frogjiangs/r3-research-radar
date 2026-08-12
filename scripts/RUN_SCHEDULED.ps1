$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$WorkspaceRoot = Split-Path -Parent (Split-Path -Parent $ProjectRoot)
$LogRoot = Join-Path $WorkspaceRoot "outputs\r3_research_radar\scheduler"
New-Item -ItemType Directory -Force -Path $LogRoot | Out-Null
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogPath = Join-Path $LogRoot ("scheduled_{0}.log" -f $Timestamp)
$RunScript = Join-Path $PSScriptRoot "RUN_BACKFILL.ps1"

try {
    & powershell.exe `
        -NoProfile `
        -NonInteractive `
        -ExecutionPolicy Bypass `
        -File $RunScript *>> $LogPath
    $ExitCode = $LASTEXITCODE
}
catch {
    $_ | Out-String | Add-Content -LiteralPath $LogPath -Encoding UTF8
    $ExitCode = 1
}

("exit_code={0}" -f $ExitCode) | Add-Content -LiteralPath $LogPath -Encoding UTF8
exit $ExitCode
