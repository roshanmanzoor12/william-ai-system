<#
.SYNOPSIS
    Installs optional local voice dependencies (microphone capture, local
    STT, local TTS, local wake-word detection) into the current Python
    environment -- so the installed Voice Worker can actually listen,
    transcribe, and speak instead of reporting dependency_required.

.DESCRIPTION
    Installs in independent groups so one group's failure never blocks the
    others -- if faster-whisper fails to build, TTS/audio-input/wake-word
    still get installed and reported separately. Prints exactly what it is
    about to install before installing it, verifies each group's imports
    actually work afterward, and lists microphone devices at the end so
    you can immediately confirm a real device is visible.

    This script only installs Python PACKAGES. It does NOT set any
    WILLIAM_*_PROVIDER environment variable -- a package being installed
    is not the same as a provider being chosen (see .env.example and
    apps/worker_nodes/voice/providers/*.py's "configured, not merely
    present" rule). You still choose which providers are active by
    editing your .env yourself.

    faster-whisper and openwakeword both download real model weights on
    first use (not at pip-install time) -- faster-whisper's "base" model
    is roughly 140MB, openwakeword's bundled models are a few MB each.
    Nothing here forces a large model download; WILLIAM_STT_MODEL controls
    which Whisper model size loads (tiny/base/small/medium/large-v3).

.PARAMETER Groups
    Which install groups to run. Default: all. Valid values: base, stt,
    tts, wakeword, fallback, all.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\windows\install_voice_dependencies.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\windows\install_voice_dependencies.ps1 -Groups stt,tts
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("base", "stt", "tts", "wakeword", "fallback", "all")]
    [string[]]$Groups = @("all")
)

$ErrorActionPreference = "Continue"

function Write-Section($title) {
    Write-Host ""
    Write-Host "=== $title ===" -ForegroundColor Cyan
}

function Test-PythonImport($moduleName) {
    python -c "import $moduleName" 2>$null
    return ($LASTEXITCODE -eq 0)
}

function Install-Group($groupName, $packages, $importChecks) {
    Write-Section "$groupName"
    Write-Host "Will install: $($packages -join ', ')" -ForegroundColor Yellow

    $installOk = $true
    foreach ($pkg in $packages) {
        Write-Host "  pip install $pkg ..." -ForegroundColor Gray
        python -m pip install $pkg
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  FAILED to install $pkg (exit code $LASTEXITCODE)." -ForegroundColor Red
            $installOk = $false
        }
    }

    Write-Host "Verifying imports for $groupName ..." -ForegroundColor Gray
    $allImportsOk = $true
    foreach ($check in $importChecks) {
        if (Test-PythonImport $check) {
            Write-Host "  OK   - import $check succeeded" -ForegroundColor Green
        }
        else {
            Write-Host "  MISSING - import $check failed" -ForegroundColor Red
            $allImportsOk = $false
        }
    }

    if ($installOk -and $allImportsOk) {
        Write-Host "$groupName -- ready." -ForegroundColor Green
        return $true
    }
    else {
        Write-Host "$groupName -- one or more packages failed. This provider will keep reporting dependency_required until fixed; other groups are unaffected." -ForegroundColor Yellow
        return $false
    }
}

$runAll = $Groups -contains "all"
$results = @{}

Write-Host "William Voice Dependencies -- installer" -ForegroundColor Cyan
Write-Host "Groups requested: $($Groups -join ', ')" -ForegroundColor Gray
Write-Host "This only installs Python packages -- it does not enable any provider." -ForegroundColor Gray
Write-Host "You still choose active providers via WILLIAM_*_PROVIDER in your .env." -ForegroundColor Gray

Write-Section "Upgrading pip"
python -m pip install --upgrade pip

if ($runAll -or $Groups -contains "base") {
    $results["base (audio input)"] = Install-Group "Base voice (microphone capture)" @("sounddevice", "numpy", "scipy") @("sounddevice", "numpy", "scipy")
}

if ($runAll -or $Groups -contains "stt") {
    Write-Host ""
    Write-Host "faster-whisper: local speech-to-text. The 'base' model (~140MB) downloads on first real use, not now." -ForegroundColor Yellow
    $results["stt (faster-whisper)"] = Install-Group "Local STT (faster-whisper)" @("faster-whisper") @("faster_whisper")
}

if ($runAll -or $Groups -contains "tts") {
    $results["tts (pyttsx3)"] = Install-Group "Local TTS (pyttsx3 / Windows SAPI)" @("pyttsx3", "comtypes", "pywin32") @("pyttsx3", "comtypes")
}

if ($runAll -or $Groups -contains "wakeword") {
    Write-Host ""
    Write-Host "openwakeword: real audio wake-word detection. Downloads small bundled models (a few MB) on first real use." -ForegroundColor Yellow
    $results["wake word (openwakeword)"] = Install-Group "Wake word (openwakeword)" @("openwakeword") @("openwakeword")
}

if ($runAll -or $Groups -contains "fallback") {
    $results["fallback (SpeechRecognition)"] = Install-Group "Optional fallback (SpeechRecognition)" @("SpeechRecognition") @("speech_recognition")
}

Write-Section "Microphone devices"
python -m apps.worker_nodes.voice.voice_worker --list-audio-devices

Write-Section "Summary"
foreach ($key in $results.Keys) {
    $status = if ($results[$key]) { "READY" } else { "NEEDS ATTENTION" }
    $color = if ($results[$key]) { "Green" } else { "Yellow" }
    Write-Host ("  {0,-32} {1}" -f $key, $status) -ForegroundColor $color
}

Write-Host ""
Write-Host "Packages installed. No WILLIAM_*_PROVIDER env var has been changed -- edit your .env to activate the providers you want, then run:" -ForegroundColor Cyan
Write-Host "  powershell -ExecutionPolicy Bypass -File .\scripts\windows\check_voice_dependencies.ps1" -ForegroundColor White
