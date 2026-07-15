"""
apps/worker_nodes/voice/providers/__init__.py

Real voice provider adapters for the Voice Worker: audio input (microphone
capture), STT (speech-to-text), TTS (text-to-speech), wake word (real audio
wake-word detection), and provider_status (the single source of truth for
what's actually available right now).

Every module here follows the same honesty rule as the rest of this
codebase's voice layer (see agents/voice_agent/provider_capabilities.py):
never claim a provider is ready just because a package is importable --
"configured" always additionally requires the matching WILLIAM_*_PROVIDER
env var to be set by the operator. A package being on disk with no env var
set still reports external_dependency_required, with install_guidance
telling the operator what to do next (install the package, or just set the
env var if it's already installed).

Nothing in this package is imported at apps/worker_nodes/voice/voice_worker.py
module load time in a way that would crash the worker if a dependency is
missing -- every import here is optional/lazy, matching this codebase's
established import-safe pattern.
"""
