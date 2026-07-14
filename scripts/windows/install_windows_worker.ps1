<#
.SYNOPSIS
    Installs and starts the William/Jarvis Windows Worker as a real,
    reusable device connector -- run this ONCE per machine.

.DESCRIPTION
    Redeems a short-lived setup token (from POST /system/device/setup-token,
    shown in the dashboard's "Enable Windows Worker" flow) for a durable
    device token via POST /system/device/register, saves that device token
    locally, and registers the worker to auto-start at Windows login. The
    setup token itself is never stored -- it is single-use and already
    consumed by the time this script finishes.

.PARAMETER ApiBaseUrl
    Backend API base URL, e.g. http://localhost:8001/api/v1

.PARAMETER SetupToken
    The one-time setup token shown by the dashboard's Enable Windows Worker
    flow. Expires quickly -- run this script before it does.

.PARAMETER DeviceName
    Display name for this device, e.g. "Roshan Windows Laptop".

.PARAMETER AutoStart
    Register a Scheduled Task so the worker starts automatically at login.
    Default: enabled. Pass -AutoStart:$false to skip auto-start setup.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\windows\install_windows_worker.ps1 `
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
$ConfigPath = Join-Path $WilliamHome "windows_worker.json"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$StartScript = Join-Path $ScriptDir "start_windows_worker.ps1"
$TaskName = "WilliamWindowsWorker"

Write-Host "William Windows Worker -- installing..." -ForegroundColor Cyan

New-Item -ItemType Directory -Force -Path $WilliamHome | Out-Null
New-Item -ItemType Directory -Force -Path $LogsDir | Out-Null

$SupportedActions = @(
    "open_microsoft_store",
    "open_chrome",
    "open_vscode",
    "open_notepad",
    "open_explorer",
    "open_folder",
    "open_file",
    "download_generated_file_to_downloads",
    "open_downloads_folder",
    "show_system_info"
)

$RegisterBody = @{
    setup_token        = $SetupToken
    device_name        = $DeviceName
    supported_actions  = $SupportedActions
} | ConvertTo-Json

try {
    $RegisterResponse = Invoke-RestMethod -Method Post -Uri "$ApiBaseUrl/system/device/register" `
        -ContentType "application/json" -Body $RegisterBody
}
catch {
    Write-Host "Registration failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "The setup token may have expired -- generate a new one from Settings > Devices and try again." -ForegroundColor Yellow
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
            -Description "William/Jarvis Windows Worker -- starts at login." -Force | Out-Null

        Write-Host "Auto-start registered (Task Scheduler: $TaskName)." -ForegroundColor Green
    }
    catch {
        Write-Host "Could not register a Scheduled Task ($($_.Exception.Message)) -- falling back to Startup folder shortcut." -ForegroundColor Yellow
        try {
            $StartupDir = [Environment]::GetFolderPath("Startup")
            $ShortcutPath = Join-Path $StartupDir "WilliamWindowsWorker.lnk"
            $Shell = New-Object -ComObject WScript.Shell
            $Shortcut = $Shell.CreateShortcut($ShortcutPath)
            $Shortcut.TargetPath = "powershell.exe"
            $Shortcut.Arguments = "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$StartScript`""
            $Shortcut.WorkingDirectory = $ScriptDir
            $Shortcut.Save()
            Write-Host "Auto-start registered (Startup folder shortcut)." -ForegroundColor Green
        }
        catch {
            Write-Host "Could not set up auto-start either way -- run start_windows_worker.ps1 manually after each login." -ForegroundColor Yellow
        }
    }
}
else {
    Write-Host "Auto-start skipped (-AutoStart:`$false). Run start_windows_worker.ps1 manually to connect." -ForegroundColor Yellow
}

Write-Host "Starting worker now..." -ForegroundColor Cyan
Start-Process -FilePath "powershell.exe" `
    -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$StartScript`"" `
    -WindowStyle Hidden

Write-Host "William Windows Worker installed and connected." -ForegroundColor Green
