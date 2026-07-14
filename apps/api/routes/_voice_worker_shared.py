"""
apps/api/routes/_voice_worker_shared.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Dependency-free constants/helpers shared between apps/api/routes/voice.py
and apps/api/routes/voice_device_setup.py -- pulled out into its own module
for exactly the same reason apps/api/routes/_worker_shared.py exists for
the Windows Worker pair (system_worker.py / device_setup.py): voice.py
needs voice_device_setup.py's get_voice_worker_auth_context, and
voice_device_setup.py needs voice.py's dependency-status vocabulary, and
importing directly between the two would be a circular import that Python
resolves order-dependently and silently (whichever module happens to load
first "wins," quietly degrading the other) rather than raising -- worse
than a normal ImportError since nothing crashes to reveal it.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import HTTPException


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def api_success(message: str, data: Optional[Dict[str, Any]] = None, request_id: Optional[str] = None) -> Dict[str, Any]:
    return {
        "success": True,
        "message": message,
        "data": data or {},
        "error": None,
        "metadata": {"request_id": request_id, "timestamp": utc_now().isoformat(), "module": "voice"},
    }


def raise_api_error(
    status_code: int,
    message: str,
    code: str,
    request_id: Optional[str] = None,
    details: Optional[Any] = None,
) -> None:
    raise HTTPException(
        status_code=status_code,
        detail={
            "success": False,
            "message": message,
            "data": {},
            "error": {"code": code, "details": details},
            "metadata": {"request_id": request_id, "timestamp": utc_now().isoformat(), "module": "voice"},
        },
    )


# Real, current capabilities an installed voice worker can honestly claim --
# never invented ones like "real_microphone" unless a provider is actually
# configured (see agents/voice_agent/provider_capabilities.py). This is a
# menu the register-device payload's supported_features is validated
# against, not a promise of what the workspace's providers currently do.
VOICE_WORKER_SUPPORTED_FEATURES = {
    "push_to_talk_text",
    "wake_word_text_detection",
    "local_microphone_capture",
    "local_stt",
    "local_tts",
}


__all__ = [
    "utc_now",
    "api_success",
    "raise_api_error",
    "VOICE_WORKER_SUPPORTED_FEATURES",
]
