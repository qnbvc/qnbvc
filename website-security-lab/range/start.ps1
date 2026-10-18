param(
    [int]$Port = 8080,
    [string]$BindHost = "0.0.0.0",
    [ValidateSet("clean", "tampered")]
    [string]$InitialState = "clean",
    [switch]$NoControl
)

$ErrorActionPreference = "Stop"

if (-not $env:LAB_CONTROL_TOKEN) {
    $env:LAB_CONTROL_TOKEN = [System.Guid]::NewGuid().ToString("N")
}

$env:LAB_INITIAL_STATE = $InitialState
$server = Join-Path $PSScriptRoot "server.py"

Write-Host "Starting synthetic lab on $BindHost`:$Port"
Write-Host "Control token: $env:LAB_CONTROL_TOKEN"
Write-Host "Stop with Ctrl+C."

$controlArgs = @()
if ($NoControl) {
    $controlArgs += "--no-control"
}

python $server --host $BindHost --port $Port --initial-state $InitialState @controlArgs
