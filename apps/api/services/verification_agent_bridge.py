"""
apps/api/services/verification_agent_bridge.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Fixes the honestly-documented gap in apps/api/routes/auth.py: the real
agents.verification_agent.verification_agent.VerificationAgent exposes
verify_task(context, task_payload, ...) -- two required arguments, not the
single-dict shape apps/api/routes/auth.py's generic OptionalAgentHook.call()
always invokes (method(payload)). auth.py already names this bridge as its
first import candidate for VERIFICATION_AGENT; this module is that missing
piece, reusing the same context/task_payload split already proven working in
core/verification_bridge.py._send_to_verification_agent().
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger("william.api.services.verification_agent_bridge")


class VerificationAgentBridge:
    """Drop-in VerificationAgent adapter for apps/api/routes/auth.py's
    OptionalAgentHook, whose method_candidates tries `execute_task` first --
    the method name implemented here. Internally calls the real
    VerificationAgent.verify_task(context=, task_payload=, ...) with the
    payload split into its real required shape.
    """

    def __init__(self, settings: Optional[Any] = None) -> None:
        self.settings = settings
        self._verification_agent = None
        self._init_error: Optional[str] = None

        try:
            from agents.verification_agent.verification_agent import VerificationAgent

            self._verification_agent = VerificationAgent()
        except Exception as exc:  # noqa: BLE001 - import-safe by design
            logger.warning("verification_agent_bridge: VerificationAgent unavailable: %s", exc)
            self._init_error = str(exc)

    async def execute_task(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if self._verification_agent is None:
            return {
                "success": False,
                "message": "Verification Agent could not be constructed.",
                "data": {},
                "error": {"code": "VERIFICATION_AGENT_UNAVAILABLE", "detail": self._init_error},
                "metadata": {},
            }

        payload = payload or {}
        from agents.agent_execution_adapter import call_verification_agent

        return await call_verification_agent(
            self._verification_agent,
            context={
                "user_id": payload.get("user_id"),
                "workspace_id": payload.get("workspace_id"),
                "request_id": payload.get("request_id"),
            },
            task_payload={
                "action_type": payload.get("type", "auth_confirmation"),
                "task": payload,
                "completed_result": {
                    "success": payload.get("result") == "success",
                    "data": payload,
                },
            },
        )
