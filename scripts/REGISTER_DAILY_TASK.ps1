param(
    [string]$TaskName = "R3 Research Radar",
    [string]$DailyAt = "02:00",
    [switch]$Replace
)

$ErrorActionPreference = "Stop"
$RunScript = Join-Path $PSScriptRoot "RUN_SCHEDULED.ps1"
if (-not (Test-Path -LiteralPath $RunScript)) {
    throw "RUN_SCHEDULED.ps1 is missing."
}

$At = [DateTime]::ParseExact($DailyAt, "HH:mm", $null)
$QuotedScript = '"' + $RunScript + '"'
$Action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File $QuotedScript"
$Trigger = New-ScheduledTaskTrigger -Daily -At $At
$Settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Hours 7) `
    -StartWhenAvailable `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -DisallowHardTerminate `
    -MultipleInstances IgnoreNew

$Existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($null -ne $Existing) {
    $ExpectedPath = [IO.Path]::GetFullPath($RunScript)
    $ExistingArguments = [string]$Existing.Actions[0].Arguments
    if ($ExistingArguments -notlike "*$ExpectedPath*") {
        throw "An unrelated scheduled task already uses this name; refusing to replace it."
    }
    if (-not $Replace) {
        throw "The scheduled task already exists. Re-run with -Replace to update it."
    }
}

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $Action `
    -Trigger $Trigger `
    -Settings $Settings `
    -Description "Codex-first R3 cache research radar backfill and incremental resume." `
    -Force
