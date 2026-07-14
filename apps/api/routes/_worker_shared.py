"""
apps/api/routes/_worker_shared.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Dependency-free constants/helpers shared between apps/api/routes/
system_worker.py and apps/api/routes/device_setup.py. Pulled out into its
own module specifically so those two files can import from each other's
domain (device_setup.py needs WORKER_MVP_ACTIONS; system_worker.py needs
device_setup.py's get_worker_auth_context) without a circular import --
Python only fails that quietly and order-dependently (whichever of the two
happens to be imported first "wins," silently degrading the other), which
is worse than an import error since nothing crashes to reveal it.

Both system_worker.py and device_setup.py still expose api_success/
raise_api_error/utc_now/WORKER_MVP_ACTIONS as names in their own module
namespace (importing them here, not redefining them), so every existing
`from apps.api.routes.system_worker import api_success`-style import
elsewhere in the codebase (e.g. apps/api/routes/capabilities.py) keeps
working unchanged.
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
        "metadata": {"request_id": request_id, "timestamp": utc_now().isoformat(), "module": "system_worker"},
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
            "metadata": {"request_id": request_id, "timestamp": utc_now().isoformat(), "module": "system_worker"},
        },
    )


# Server-side allowlist -- the single source of truth for what a worker is
# ever allowed to be asked to do. Anything outside both sets is rejected
# outright by system_worker.py::classify_worker_action(), regardless of
# what a caller asks for; nothing here ever gets queued just because a
# payload claims it.
WORKER_MVP_ACTIONS = {
    "open_microsoft_store",
    "open_chrome",
    "open_vscode",
    "open_notepad",
    "open_explorer",
    "open_folder",
    "open_file",
    "download_generated_file_to_downloads",
    "open_downloads_folder",
    "show_system_info",
}

# Matches the user-facing risky-action list (delete/shutdown/install/shell/
# messages/calls/financial/passwords) -- none of these are reachable via the
# Phase 1 assistant's windows_device_action flow today (only the MVP set
# above is), but the classification/approval machinery exists now so a
# future phase can add a risky action without inventing this gate from
# scratch.
WORKER_RISKY_ACTIONS = {
    "delete_file",
    "shutdown",
    "restart",
    "install_software",
    "run_shell_command",
    "send_message",
    "place_call",
    "financial_action",
    "enter_password",
    "browser_login_form",
}


__all__ = [
    "utc_now",
    "api_success",
    "raise_api_error",
    "WORKER_MVP_ACTIONS",
    "WORKER_RISKY_ACTIONS",
]
