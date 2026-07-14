<#
.SYNOPSIS
    Installs and starts the William/Jarvis Voice Worker as a real, reusable
    device connector -- run this ONCE per machine.

.DESCRIPTION
    Redeems a short-lived setup token (from POST /voice/device/setup-token,
    shown in the dashboard's Voice Control "Enable Voice Worker" flow) for a
    durable device token via POST /voice/device/register, saves that device
    token locally, and registers the worker to auto-start at Windows login.
    The setup token itself is never stored -- it is single-use and already
    consumed by the time this script finishes.

    Installing the Voice Worker does NOT by itself change voice mode --
    mode (disabled/push_to_talk/wake_word_admin/...) is a separate choice
    made from the dashboard's Voice Control settings (POST /voice/config).
    If mode is still "disabled" after this script finishes, the worker will
    connect and heartbeat but will not send commands until mode is changed.

.PARAMETER ApiBaseUrl
    Backend API base URL, e.g. http://localhost:8001/api/v1

.PARAMETER SetupToken
    The one-time setup token shown by the dashboard's Enable Voice Worker
    flow. Expires quickly -- run this script before it does.

.PARAMETER DeviceName
    Display name for this device, e.g. "Roshan Windows Laptop".

.PARAMETER AutoStart
    Register a Scheduled Task so the worker starts automatically at login.
    Default: enabled. Pass -AutoStart:$false to skip auto-start setup.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\windows\install_voice_worker.ps1 `
      -ApiBaseUrl "http://localhost:8001/api/v1" -SetupToken "<token>" -DeviceName "Roshan Windows Laptop"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ApiBaseUrl,

    [Parameter(Mandatory = $true)]
    [string]$SetupToken,

    [Parameter(Mandatory = $false)]
    [string]$DeviceName = $env:COMPUTERNAME,

    [Parameter(Mandatory = $false)]
    [bool]$AutoStart = $true
)

$ErrorActionPreference = "Stop"

$ApiBaseUrl = $ApiBaseUrl.TrimEnd("/")
$WilliamHome = Join-Path $env:USERPROFILE ".william"
$LogsDir = Join-Path $WilliamHome "logs"
$ConfigPath = Join-Path $WilliamHome "voice_worker.json"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$StartScript = Join-Path $ScriptDir "start_voice_worker.ps1"
$TaskName = "WilliamVoiceWorker"

Write-Host "William Voice Worker -- installing..." -ForegroundColor Cyan

New-Item -ItemType Directory -Force -Path $WilliamHome | Out-Null
New-Item -ItemType Directory -Force -Path $LogsDir | Out-Null

# Real, current capabilities this installer can honestly claim -- matches
# apps/api/routes/_voice_worker_shared.py::VOICE_WORKER_SUPPORTED_FEATURES.
# local_stt / local_tts / local_microphone_capture are only ever real once
# the matching WILLIAM_STT_PROVIDER / WILLIAM_TTS_PROVIDER /
# WILLIAM_AUDIO_INPUT_PROVIDER env vars are configured -- this script does
# not install or configure those providers, so it does not claim them here.
$SupportedFeatures = @(
    "push_to_talk_text",
    "wake_word_text_detection"
)

$RegisterBody = @{
    setup_token         = $SetupToken
    device_name         = $DeviceName
    device_platform     = "windows"
    supported_features  = $SupportedFeatures
} | ConvertTo-Json

try {
    $RegisterResponse = Invoke-RestMethod -Method Post -Uri "$ApiBaseUrl/voice/device/register" `
        -ContentType "application/json" -Body $RegisterBody
}
catch {
    Write-Host "Registration failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "The setup token may have expired -- generate a new one from Settings > Voice Control and try again." -ForegroundColor Yellow
    exit 1
}

if (-not $RegisterResponse.success) {
    Write-Host "Registration was rejected by the backend: $($RegisterResponse.message)" -ForegroundColor Red
    exit 1
}

$DeviceId = $RegisterResponse.data.device_id
$DeviceToken = $RegisterResponse.data.device_token

$ConfigObject = @{
    api_base_url = $ApiBaseUrl
    device_id    = $DeviceId
    device_token = $DeviceToken
    device_name  = $DeviceName
}
$ConfigObject | ConvertTo-Json | Set-Content -Path $ConfigPath -Encoding UTF8

Write-Host "Device registered: $DeviceId" -ForegroundColor Green
Write-Host "Config saved to $ConfigPath" -ForegroundColor Green

if ($AutoStart) {
    try {
        $Action = New-ScheduledTaskAction -Execute "powershell.exe" `
            -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$StartScript`""
        $Trigger = New-ScheduledTaskTrigger -AtLogOn
        $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

        Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings `
            -Description "William/Jarvis Voice Worker -- starts at login." -Force | Out-Null

        Write-Host "Auto-start registered (Task Scheduler: $TaskName)." -ForegroundColor Green
    }
    catch {
        Write-Host "Could not register a Scheduled Task ($($_.Exception.Message)) -- falling back to Startup folder shortcut." -ForegroundColor Yellow
        try {
            $StartupDir = [Environment]::GetFolderPath("Startup")
            $ShortcutPath = Join-Path $StartupDir "WilliamVoiceWorker.lnk"
            $Shell = New-Object -ComObject WScript.Shell
            $Shortcut = $Shell.CreateShortcut($ShortcutPath)
            $Shortcut.TargetPath = "powershell.exe"
            $Shortcut.Arguments = "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$StartScript`""
            $Shortcut.WorkingDirectory = $ScriptDir
            $Shortcut.Save()
            Write-Host "Auto-start registered (Startup folder shortcut)." -ForegroundColor Green
        }
        catch {
            Write-Host "Could not set up auto-start either way -- run start_voice_worker.ps1 manually after each login." -ForegroundColor Yellow
        }
    }
}
else {
    Write-Host "Auto-start skipped (-AutoStart:`$false). Run start_voice_worker.ps1 manually to connect." -ForegroundColor Yellow
}

Write-Host "Starting worker now..." -ForegroundColor Cyan
Start-Process -FilePath "powershell.exe" `
    -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$StartScript`"" `
    -WindowStyle Hidden

Write-Host "William Voice Worker installed and connected." -ForegroundColor Green
Write-Host "Note: the dashboard cannot keep the microphone always listening by itself -- this installed worker is what listens in the background. Voice runtime mode (push-to-talk/wake word) is set separately in Settings > Voice Control." -ForegroundColor Cyan
