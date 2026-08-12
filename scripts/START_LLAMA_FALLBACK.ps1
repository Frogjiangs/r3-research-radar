$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$WorkspaceRoot = Split-Path -Parent (Split-Path -Parent $ProjectRoot)
$ConfigPath = Join-Path $ProjectRoot "config\r3.v1.json"
$Config = Get-Content -Raw -Encoding UTF8 $ConfigPath | ConvertFrom-Json
$Server = $Config.analysis.llama_cpp.managed_server
$ExpectedAlias = [string]$Config.analysis.llama_cpp.model
$OutputRoot = Join-Path $WorkspaceRoot "outputs\r3_research_radar\llama_server"
$PidPath = Join-Path $OutputRoot "server.pid.json"
$StdoutPath = Join-Path $OutputRoot "stdout.log"
$StderrPath = Join-Path $OutputRoot "stderr.log"
$ModelsUri = "http://{0}:{1}/v1/models" -f $Server.host, $Server.port

function Get-ModelIds {
    try {
        $Response = Invoke-RestMethod -Uri $ModelsUri -TimeoutSec 3
        return @($Response.data | ForEach-Object { [string]$_.id })
    }
    catch {
        return $null
    }
}

if (-not [bool]$Server.enabled) {
    throw "Managed llama.cpp is disabled in the active configuration."
}
if (-not (Test-Path -LiteralPath $Server.executable)) {
    throw "Configured llama-server executable does not exist."
}
if (-not (Test-Path -LiteralPath $Server.model_path)) {
    throw "Configured GGUF model does not exist."
}

New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null
$Mutex = New-Object System.Threading.Mutex($false, "Local\R3ResearchRadarLlamaStart")
if (-not $Mutex.WaitOne(0)) {
    throw "Another llama.cpp start operation is already in progress."
}

try {
    if (Test-Path -LiteralPath $PidPath) {
        try {
            $Record = Get-Content -Raw -Encoding UTF8 -LiteralPath $PidPath | ConvertFrom-Json
        }
        catch {
            throw "Managed PID record is invalid; refusing to start a second server."
        }
        $Existing = Get-Process -Id ([int]$Record.pid) -ErrorAction SilentlyContinue
        if ($null -ne $Existing) {
            $ActualExecutable = [IO.Path]::GetFullPath($Existing.Path)
            $ExpectedExecutable = [IO.Path]::GetFullPath($Server.executable)
            $ActualStart = $Existing.StartTime.ToUniversalTime().ToString("o")
            if (
                $ActualExecutable -ine $ExpectedExecutable -or
                $ActualStart -ne [string]$Record.start_time_utc -or
                [string]$Record.model_alias -ne $ExpectedAlias -or
                [int]$Record.port -ne [int]$Server.port
            ) {
                throw "PID record does not prove ownership of the running process."
            }
            $Ids = Get-ModelIds
            if ($null -ne $Ids -and $Ids -contains $ExpectedAlias) {
                Write-Output "Managed llama.cpp fallback is already ready."
                exit 0
            }
            throw "The managed llama.cpp process is still starting or unhealthy; refusing a duplicate start."
        }
        Remove-Item -LiteralPath $PidPath
    }

    $ExistingIds = Get-ModelIds
    if ($null -ne $ExistingIds) {
        throw "The configured port is already occupied by an unmanaged or wrong-model service."
    }

    $Arguments = @(
        "--model", ('"' + $Server.model_path + '"'),
        "--alias", $ExpectedAlias,
        "--host", $Server.host,
        "--port", [string]$Server.port,
        "--ctx-size", [string]$Server.context,
        "--batch-size", [string]$Server.batch_size,
        "--n-gpu-layers", "all",
        "--device", ($Server.devices -join ","),
        "--split-mode", $Server.split_mode,
        "--tensor-split", $Server.tensor_split,
        "--parallel", "1",
        "--reasoning", "off",
        "--offline",
        "--no-ui",
        "--log-timestamps"
    )

    $Process = Start-Process `
        -FilePath $Server.executable `
        -ArgumentList $Arguments `
        -WorkingDirectory $ProjectRoot `
        -WindowStyle Hidden `
        -RedirectStandardOutput $StdoutPath `
        -RedirectStandardError $StderrPath `
        -PassThru
    $Process.Refresh()
    $Record = [ordered]@{
        pid = $Process.Id
        start_time_utc = $Process.StartTime.ToUniversalTime().ToString("o")
        executable = [IO.Path]::GetFullPath($Server.executable)
        model_path = [IO.Path]::GetFullPath($Server.model_path)
        model_alias = $ExpectedAlias
        host = [string]$Server.host
        port = [int]$Server.port
        instance_id = [Guid]::NewGuid().ToString()
    }
    $TemporaryPidPath = $PidPath + ".tmp"
    $Record | ConvertTo-Json | Set-Content -LiteralPath $TemporaryPidPath -Encoding UTF8
    Move-Item -LiteralPath $TemporaryPidPath -Destination $PidPath -Force

    $Ready = $false
    for ($Attempt = 0; $Attempt -lt 150; $Attempt++) {
        if ($Process.HasExited) {
            Remove-Item -LiteralPath $PidPath -ErrorAction SilentlyContinue
            throw "llama.cpp exited before becoming ready."
        }
        $Ids = Get-ModelIds
        if ($null -ne $Ids -and $Ids -contains $ExpectedAlias) {
            $Ready = $true
            break
        }
        Start-Sleep -Seconds 2
        $Process.Refresh()
    }
    if (-not $Ready) {
        Stop-Process -Id $Process.Id -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $PidPath -ErrorAction SilentlyContinue
        throw "llama.cpp did not expose the expected model alias within 300 seconds."
    }
    Write-Output ("llama.cpp fallback is ready with PID {0}." -f $Process.Id)
}
finally {
    $Mutex.ReleaseMutex()
    $Mutex.Dispose()
}
