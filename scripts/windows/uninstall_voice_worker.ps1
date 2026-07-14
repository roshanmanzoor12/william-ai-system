<#
.SYNOPSIS
    Removes the William/Jarvis Voice Worker's auto-start registration and,
    optionally, its saved device config -- and best-effort notifies the
    backend so the dashboard stops showing this device as enabled.

.PARAMETER RemoveConfig
    Delete the saved device config (%USERPROFILE%\.william\voice_worker.json)
    after uninstalling. If not passed, you will be prompted.

.PARAMETER Disable
    Call POST /voice/device/disable with the saved device token before
    removing the config, so the backend immediately marks the device
    disabled rather than waiting for the heartbeat to go stale. Default:
    enabled (best-effort -- a failure here does not stop the uninstall).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\windows\uninstall_voice_worker.ps1 -RemoveConfig
#>

[CmdletBinding()]
param(
    [switch]$RemoveConfig,

    [Parameter(Mandatory = $false)]
    [bool]$Disable = $true
)

$WilliamHome = Join-Path $env:USERPROFILE ".william"
$ConfigPath = Join-Path $WilliamHome "voice_worker.json"
$StartupShortcut = Join-Path ([Environment]::GetFolderPath("Startup")) "WilliamVoiceWorker.lnk"
$TaskName = "WilliamVoiceWorker"

Write-Host "William Voice Worker -- uninstalling..." -ForegroundColor Cyan

$ExistingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($ExistingTask) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Removed Scheduled Task: $TaskName" -ForegroundColor Green
}
else {
    Write-Host "No Scheduled Task named $TaskName found." -ForegroundColor Yellow
}

if (Test-Path $StartupShortcut) {
    Remove-Item -Path $StartupShortcut -Force
    Write-Host "Removed Startup folder shortcut." -ForegroundColor Green
}

if ($Disable -and (Test-Path $ConfigPath)) {
    try {
        $Config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
        if ($Config.api_base_url -and $Config.device_token) {
            Invoke-RestMethod -Method Post -Uri "$($Config.api_base_url)/voice/device/disable" `
                -Headers @{ Authorization = "Bearer $($Config.device_token)" } | Out-Null
            Write-Host "Backend notified: voice device disabled." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Could not reach the backend to disable the device (continuing anyway): $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

if (-not $RemoveConfig) {
    $Answer = Read-Host "Remove saved device config at $ConfigPath ? [y/N]"
    $RemoveConfig = $Answer -match "^[Yy]"
}

if ($RemoveConfig -and (Test-Path $WilliamHome)) {
    Remove-Item -Path $ConfigPath -Force -ErrorAction SilentlyContinue
    Write-Host "Removed device config." -ForegroundColor Green
}
else {
    Write-Host "Kept device config at $ConfigPath." -ForegroundColor Yellow
}

Write-Host "William Voice Worker uninstalled." -ForegroundColor Green
