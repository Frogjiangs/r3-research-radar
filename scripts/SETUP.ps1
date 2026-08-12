$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$VenvPath = Join-Path $ProjectRoot ".venv"
$PythonPath = Join-Path $VenvPath "Scripts\python.exe"
$RequirementsLock = Join-Path $ProjectRoot "requirements.lock"
$DistributionPath = Join-Path $VenvPath "r3-distribution"
$DistributionReceipt = Join-Path $VenvPath "r3-distribution-build.json"

function Assert-NativeSuccess {
    param([string]$Step)
    if ($LASTEXITCODE -ne 0) {
        throw "$Step failed with exit code $LASTEXITCODE."
    }
}

if (-not (Test-Path -LiteralPath $PythonPath)) {
    python -m venv $VenvPath
    Assert-NativeSuccess "python -m venv"
}

$PythonMajorMinor = & $PythonPath -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
Assert-NativeSuccess "python version check"
$PythonImplementation = & $PythonPath -c "import platform; print(platform.python_implementation())"
Assert-NativeSuccess "python implementation check"
$PythonPlatform = & $PythonPath -c "import sys; print(sys.platform)"
Assert-NativeSuccess "python platform check"
if (
    $PythonMajorMinor -ne "3.10" -or
    $PythonImplementation -ne "CPython" -or
    $PythonPlatform -ne "win32"
) {
    throw "requirements.lock is accepted only for Windows CPython 3.10; found $PythonImplementation $PythonMajorMinor on $PythonPlatform. Regenerate and re-accept the lock before changing Python."
}

& $PythonPath -m pip install --disable-pip-version-check --require-hashes --only-binary=:all: -r $RequirementsLock
Assert-NativeSuccess "pip install"
& $PythonPath -c "import importlib.metadata as m, sys; sys.exit(0 if any(d.metadata.get('Name') == 'r3-research-radar' for d in m.distributions()) else 1)"
$DistributionInstalled = $LASTEXITCODE -eq 0
if ($DistributionInstalled) {
    & $PythonPath -m pip uninstall --disable-pip-version-check --yes r3-research-radar
    Assert-NativeSuccess "remove previous R3 distribution"
}
& $PythonPath -m pip check
Assert-NativeSuccess "pip check"
$EnvironmentReceipt = Join-Path $VenvPath "r3-environment-verification.json"
& $PythonPath (Join-Path $PSScriptRoot "supply_chain.py") verify-current-environment --lock $RequirementsLock --output $EnvironmentReceipt
Assert-NativeSuccess "exact environment verification"
& $PythonPath (Join-Path $PSScriptRoot "build_distribution.py") --output-dir $DistributionPath --receipt $DistributionReceipt
Assert-NativeSuccess "build and validate R3 distribution"
$Wheel = Get-ChildItem -LiteralPath $DistributionPath -Filter "r3_research_radar-*.whl" -File
if ($Wheel.Count -ne 1) {
    throw "Expected exactly one freshly validated R3 wheel; found $($Wheel.Count)."
}
& $PythonPath -m pip install --disable-pip-version-check --no-deps --no-index --force-reinstall $Wheel[0].FullName
Assert-NativeSuccess "install validated R3 wheel"
& $PythonPath -m pip check
Assert-NativeSuccess "installed distribution pip check"
Push-Location $ProjectRoot
try {
    npm ci --ignore-scripts --no-audit --no-fund
    Assert-NativeSuccess "npm ci"
    & $PythonPath -m r3radar init
    Assert-NativeSuccess "r3radar init"
}
finally {
    Pop-Location
}
