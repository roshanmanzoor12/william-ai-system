<#
.SYNOPSIS
    Reports exactly what real voice capability is available right now --
    Python version, each optional package's import status, real
    microphone devices, TTS availability, and the current WILLIAM_*
    provider environment variables. Never claims something works without
    actually checking it.

.DESCRIPTION
    Read-only -- installs nothing. Run this after
    install_voice_dependencies.ps1 (or any time) to see the same honest
    status apps/worker_nodes/voice/providers/provider_status.py computes
    for the backend and the Voice Worker.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\windows\check_voice_dependencies.ps1
#>

[CmdletBinding()]
param()

function Write-Section($title) {
    Write-Host ""
    Write-Host "=== $title ===" -ForegroundColor Cyan
}

function Test-PythonImport($moduleName) {
    python -c "import $moduleName" 2>$null
    return ($LASTEXITCODE -eq 0)
}

function Show-Check($label, $ok, $extra = "") {
    if ($ok) {
        Write-Host ("  OK      - {0} {1}" -f $label, $extra) -ForegroundColor Green
    }
    else {
        Write-Host ("  MISSING - {0} {1}" -f $label, $extra) -ForegroundColor Red
    }
}

Write-Host "William Voice Dependencies -- check (read-only, installs nothing)" -ForegroundColor Cyan

Write-Section "Python"
$pyVersion = python --version 2>&1
Write-Host "  $pyVersion"

Write-Section "Packages"
Show-Check "sounddevice (microphone capture)" (Test-PythonImport "sounddevice")
Show-Check "numpy" (Test-PythonImport "numpy")
Show-Check "pyaudio (optional alt. audio backend)" (Test-PythonImport "pyaudio")
Show-Check "speech_recognition (optional fallback)" (Test-PythonImport "speech_recognition")
Show-Check "faster_whisper (local STT)" (Test-PythonImport "faster_whisper")
Show-Check "pyttsx3 (local TTS)" (Test-PythonImport "pyttsx3")
Show-Check "openwakeword (real audio wake word)" (Test-PythonImport "openwakeword")

Write-Section "Microphone devices"
python -m apps.worker_nodes.voice.voice_worker --list-audio-devices

Write-Section "TTS availability"
python -m apps.worker_nodes.voice.voice_worker --test-tts

Write-Section "Current WILLIAM_* provider environment variables"
$envVars = @(
    "WILLIAM_AUDIO_INPUT_PROVIDER", "WILLIAM_AUDIO_DEVICE",
    "WILLIAM_STT_PROVIDER", "WILLIAM_STT_MODEL", "WILLIAM_STT_DEVICE", "WILLIAM_STT_COMPUTE_TYPE", "WILLIAM_STT_BASE_URL",
    "WILLIAM_TTS_PROVIDER", "WILLIAM_TTS_VOICE", "WILLIAM_TTS_RATE", "WILLIAM_TTS_VOLUME", "WILLIAM_TTS_BASE_URL",
    "WILLIAM_WAKE_WORD_PROVIDER", "WILLIAM_WAKE_WORD_PHRASE", "WILLIAM_WAKE_WORD_MODEL",
    "WILLIAM_SPEAKER_RECOGNITION_PROVIDER"
)
foreach ($name in $envVars) {
    $value = [Environment]::GetEnvironmentVariable($name)
    if ([string]::IsNullOrEmpty($value)) {
        Write-Host ("  {0,-36} (not set)" -f $name) -ForegroundColor Yellow
    }
    else {
        Write-Host ("  {0,-36} {1}" -f $name, $value) -ForegroundColor White
    }
}
Write-Host ""
Write-Host "Note: this shows the current shell's environment, not necessarily what a running backend/worker process loaded from .env at its own startup." -ForegroundColor Gray

Write-Section "Aggregate provider status (apps/worker_nodes/voice/providers/provider_status.py)"
python -c "
from apps.worker_nodes.voice.providers import provider_status
import json
print(json.dumps(provider_status.get_full_status(), indent=2))
"
