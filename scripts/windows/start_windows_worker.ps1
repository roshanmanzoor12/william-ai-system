<#
.SYNOPSIS
    Starts the William/Jarvis Windows Worker using a saved device config.
    This is what install_windows_worker.ps1's auto-start (Scheduled Task or
    Startup shortcut) actually runs at login -- it can also be run directly
    any time to (re)connect manually.

.PARAMETER ConfigPath
    Path to the worker's JSON config file. Defaults to
    %USERPROFILE%\.william\windows_worker.json (written by
    install_windows_worker.ps1).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\windows\start_windows_worker.ps1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = (Join-Path $env:USERPROFILE ".william\windows_worker.json")
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
# scripts/windows/start_windows_worker.ps1 -> repo root is two levels up.
$RepoRoot = Split-Path -Parent (Split-Path -Parent $ScriptDir)
$LogsDir = Join-Path $env:USERPROFILE ".william\logs"
$LogFile = Join-Path $LogsDir ("worker_{0}.log" -f (Get-Date -Format "yyyyMMdd"))

if (-not (Test-Path $ConfigPath)) {
    Write-Host "No worker config found at $ConfigPath -- run install_windows_worker.ps1 first." -ForegroundColor Red
    exit 1
}

New-Item -ItemType Directory -Force -Path $LogsDir | Out-Null

Write-Host "Starting William Windows Worker (config: $ConfigPath)..." -ForegroundColor Cyan

Push-Location $RepoRoot
try {
    python -m apps.worker_nodes.windows.windows_worker --config "$ConfigPath" 2>&1 |
        Tee-Object -FilePath $LogFile -Append
}
finally {
    Pop-Location
}
