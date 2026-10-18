param(
    [int]$Port = 8080,
    [string]$BindHost = "0.0.0.0",
    [ValidateSet("clean", "tampered")]
    [string]$InitialState = "clean",
    [switch]$NoControl,
    [switch]$SkipTests,
    [switch]$VerifyOnly
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Python = Get-Command python -ErrorAction SilentlyContinue

if (-not $Python) {
    throw "Python 3.10+ was not found. Install Python from https://www.python.org/downloads/ and enable 'Add python.exe to PATH'."
}

& python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)"
if ($LASTEXITCODE -ne 0) {
    throw "Python 3.10+ is required. Current version: $(& python --version 2>&1)"
}

Write-Host "Python: $(& python --version 2>&1)"

if (-not $SkipTests) {
    Push-Location (Join-Path $Root "framework")
    try {
        Write-Host "Running inspector regression tests..."
        python -B -m unittest discover -s tests
        if ($LASTEXITCODE -ne 0) { throw "Inspector regression tests failed." }
    }
    finally {
        Pop-Location
    }

    Write-Host "Running range regression tests..."
    python -B -m unittest discover -s (Join-Path $Root "range\tests")
    if ($LASTEXITCODE -ne 0) { throw "Range regression tests failed." }
}

if ($VerifyOnly) {
    Write-Host "Verification passed. Nothing was started."
    exit 0
}

if (-not $env:LAB_CONTROL_TOKEN) {
    $env:LAB_CONTROL_TOKEN = [System.Guid]::NewGuid().ToString("N")
}

$startArgs = @{
    Port = $Port
    BindHost = $BindHost
    InitialState = $InitialState
}
if ($NoControl) {
    $startArgs.NoControl = $true
}

Write-Host "Starting the lab at http://127.0.0.1:$Port/"
& (Join-Path $Root "range\start.ps1") @startArgs
