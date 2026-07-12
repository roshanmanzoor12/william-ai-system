"""
agents/agent_execution_adapter.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Common execution interface for calling ANY specialized agent instance safely,
regardless of which internal method name/calling convention it actually
implements.

Root cause this addresses: a live smoke test invoking BaseAgent.execute_task()
directly against all 14 real specialized agent instances showed EVERY ONE of
them crashes -- each with a different signature/attribute mismatch in the
agent's own overrides of BaseAgent's internal hooks (_emit_agent_event,
_log_audit_event, _error_result, etc.), because execute_task() calls those
hooks positionally using BaseAgent's own convention, and most agents'
overrides were written expecting to be called only from that agent's own
code, using that agent's own (different) convention.

Rather than editing every agent's internals to match BaseAgent's exact
internal contract (invasive, high blast-radius across 14 files), this adapter
calls each agent's own REAL, agent-specific task-handling entrypoint directly
(run_task / run / execute, in that confirmed preference order) so each
agent's internal hook calls stay self-consistent with themselves -- and never
routes through the fragile inherited execute_task() pipeline unless nothing
else is available.

Every step here is wrapped so a single broken agent method degrades to a
structured error result instead of crashing the task pipeline.
"""

from __future__ import annotations

import inspect
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("william.agents.agent_execution_adapter")


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


def _normalize_output(raw: Any, agent_name: str, method_name: str) -> Dict[str, Any]:
    if isinstance(raw, dict):
        result = dict(raw)
        result.setdefault("success", True)
        result.setdefault("message", "Agent completed the task.")
        result.setdefault("data", {})
        result.setdefault("error", None)
        result.setdefault("metadata", {})
    else:
        result = {
            "success": True,
            "message": "Agent completed the task.",
            "data": {"result": raw},
            "error": None,
            "metadata": {},
        }

    if not isinstance(result.get("metadata"), dict):
        result["metadata"] = {}
    result["metadata"].setdefault("agent", agent_name)
    result["metadata"].setdefault("dispatched_via", method_name)
    return result


# Confirmed by direct inspection of every specialized agent module:
# - memory_agent.MemoryAgent, security_agent.SecurityAgent: run_task(dict) (sync)
# - system_agent.SystemAgent: handle_task(dict) (async) -- its own real
#   entrypoint name, distinct from every other agent
# - voice_agent.VoiceAgent: arun(dict) (async-native) -- its sync run() calls
#   an internal event-loop bridge that raises "Cannot run sync VoiceAgent
#   method inside an active event loop" when called from async code (which
#   this adapter always is), so arun() must be tried first for this agent
# - verification_agent.VerificationAgent: verify_task(context, task_payload, ...)
#   -- multi-arg, handled by the dedicated call_verification_agent() below,
#   never through this generic list
# - visual_agent.VisualAgent: no generic task-dispatch entrypoint exists at
#   all today (only specific capability methods like analyze_screenshot/
#   analyze_image/analyze_video) -- a genuine, honestly-documented gap; calls
#   through this adapter correctly fall through to AGENT_METHOD_MISSING
#   rather than a fake success
# - every other specialized agent (browser/code/workflow/hologram/call/
#   business/finance/creator) implements run(task) as its real, self-contained
#   entrypoint and calls its OWN internal hooks with ITS OWN (self-consistent)
#   convention from inside run() -- so calling run() directly avoids the
#   base-class contract mismatch entirely.
# "execute_task" and "execute" are kept as last-resort fallbacks for any agent
# that only implements the generic BaseAgent surface.
METHOD_PREFERENCE: List[str] = ["run_task", "handle_task", "arun", "run", "execute", "execute_task"]


async def call_agent(
    agent: Any,
    task: Dict[str, Any],
    *,
    agent_name: str = "unknown",
) -> Dict[str, Any]:
    """Call `agent` with `task` through whichever real entrypoint it implements.

    Tries METHOD_PREFERENCE in order; a TypeError (signature mismatch) on one
    candidate falls through to the next rather than failing the task. Never
    raises -- every failure path returns a normalized structured error result.
    """
    if agent is None:
        return {
            "success": False,
            "message": f"No agent instance available for '{agent_name}'.",
            "data": {"agent_name": agent_name},
            "error": {"code": "AGENT_INSTANCE_UNAVAILABLE"},
            "metadata": {"agent": agent_name},
        }

    last_type_error: Optional[Exception] = None

    for method_name in METHOD_PREFERENCE:
        method = getattr(agent, method_name, None)
        if not callable(method):
            continue

        try:
            raw = method(task)
            raw = await _maybe_await(raw)
            return _normalize_output(raw, agent_name, method_name)

        except TypeError as exc:
            logger.warning(
                "agent_execution_adapter: %s.%s signature mismatch, trying next candidate: %s",
                agent_name,
                method_name,
                exc,
            )
            last_type_error = exc
            continue

        except Exception as exc:  # noqa: BLE001 - never let one agent crash the pipeline
            logger.warning("agent_execution_adapter: %s.%s raised: %s", agent_name, method_name, exc)
            return {
                "success": False,
                "message": f"{agent_name} agent execution failed.",
                "data": {"agent_name": agent_name, "method": method_name},
                "error": {"code": "AGENT_EXECUTION_FAILED", "detail": str(exc)},
                "metadata": {"agent": agent_name, "dispatched_via": method_name},
            }

    return {
        "success": False,
        "message": f"{agent_name} agent has no compatible execution method.",
        "data": {
            "agent_name": agent_name,
            "tried": METHOD_PREFERENCE,
            "last_signature_error": str(last_type_error) if last_type_error else None,
        },
        "error": {"code": "AGENT_METHOD_MISSING"},
        "metadata": {"agent": agent_name},
    }


async def call_verification_agent(
    agent: Any,
    *,
    context: Any,
    task_payload: Dict[str, Any],
    expected_state: Optional[Dict[str, Any]] = None,
    actual_state: Optional[Dict[str, Any]] = None,
    verification_plan: Optional[Dict[str, Any]] = None,
    proof_inputs: Optional[Dict[str, Any]] = None,
    require_security: Optional[bool] = None,
) -> Dict[str, Any]:
    """Dedicated caller for VerificationAgent.verify_task(), whose real
    signature takes `context` and `task_payload` as separate required
    positional/keyword args rather than a single dict -- incompatible with
    the generic single-payload `call_agent()` above."""
    if agent is None:
        return {
            "success": False,
            "message": "No Verification Agent instance available.",
            "data": {},
            "error": {"code": "AGENT_INSTANCE_UNAVAILABLE"},
            "metadata": {"agent": "verification"},
        }

    method = getattr(agent, "verify_task", None)
    if not callable(method):
        return {
            "success": False,
            "message": "Verification Agent has no verify_task method.",
            "data": {},
            "error": {"code": "AGENT_METHOD_MISSING"},
            "metadata": {"agent": "verification"},
        }

    try:
        raw = method(
            context,
            task_payload,
            expected_state=expected_state,
            actual_state=actual_state,
            verification_plan=verification_plan,
            proof_inputs=proof_inputs,
            require_security=require_security,
        )
        raw = await _maybe_await(raw)
        return _normalize_output(raw, "verification", "verify_task")
    except Exception as exc:  # noqa: BLE001
        logger.warning("agent_execution_adapter: verification.verify_task raised: %s", exc)
        return {
            "success": False,
            "message": "Verification Agent execution failed.",
            "data": {},
            "error": {"code": "AGENT_EXECUTION_FAILED", "detail": str(exc)},
            "metadata": {"agent": "verification", "dispatched_via": "verify_task"},
        }
