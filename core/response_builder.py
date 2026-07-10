"""
core/response_builder.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Builds final user-facing progress reports, summaries, errors,
    completion percentages, next steps, dashboard-ready payloads,
    audit-compatible records, memory-compatible summaries, and
    verification-agent-compatible completion payloads.

This file is import-safe and can run even when future William/Jarvis
modules are not created yet.

Architecture Compatibility:
    - Master Agent
    - BaseAgent
    - Agent Registry
    - Agent Router
    - Security Agent
    - Verification Agent
    - Memory Agent
    - Dashboard/API
    - Task Manager
    - Planner
    - SaaS user/workspace isolation
"""

from __future__ import annotations

import logging
import traceback
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union


# =============================================================================
# Safe Optional Imports
# =============================================================================

try:
    from core.context import TaskContext  # type: ignore
except Exception:  # pragma: no cover
    TaskContext = None  # type: ignore


try:
    from core.config import settings  # type: ignore
except Exception:  # pragma: no cover
    settings = None  # type: ignore


# =============================================================================
# Logging
# =============================================================================

logger = logging.getLogger("william.core.response_builder")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)


# =============================================================================
# Enums
# =============================================================================

class ResponseStatus(str, Enum):
    SUCCESS = "success"
    ERROR = "error"
    WARNING = "warning"
    PARTIAL = "partial"
    PENDING = "pending"
    BLOCKED = "blocked"
    VALIDATION_FAILED = "validation_failed"


class ResponseAudience(str, Enum):
    USER = "user"
    DASHBOARD = "dashboard"
    AGENT = "agent"
    API = "api"
    SYSTEM = "system"


class ResponseSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ProgressStage(str, Enum):
    CREATED = "created"
    VALIDATING = "validating"
    SECURITY_CHECK = "security_check"
    ROUTING = "routing"
    PLANNING = "planning"
    EXECUTING = "executing"
    VERIFYING = "verifying"
    SUMMARIZING = "summarizing"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"


# =============================================================================
# Data Structures
# =============================================================================

@dataclass
class ResponseMetadata:
    """
    Metadata attached to every response.

    This keeps dashboard/API/task-history compatible structure.
    """

    user_id: Optional[Union[str, int]] = None
    workspace_id: Optional[Union[str, int]] = None
    task_id: Optional[str] = None
    request_id: Optional[str] = None
    agent_name: Optional[str] = None
    module_name: str = "core"
    file_name: str = "response_builder.py"
    source: str = "ResponseBuilder"
    audience: str = ResponseAudience.USER.value
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    version: str = "1.0.0"
    trace_id: Optional[str] = None
    tags: List[str] = field(default_factory=list)


@dataclass
class ProgressItem:
    """
    Represents a single progress step for user-facing and dashboard progress.
    """

    title: str
    status: str = ResponseStatus.PENDING.value
    percentage: float = 0.0
    message: Optional[str] = None
    stage: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error: Optional[str] = None


@dataclass
class NextStep:
    """
    Represents a recommended next step after task completion.
    """

    title: str
    description: Optional[str] = None
    action_key: Optional[str] = None
    priority: int = 1
    requires_user_action: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ResponsePayload:
    """
    Standard William/Jarvis response object.
    """

    success: bool
    message: str
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Fallback BaseAgent
# =============================================================================

class _FallbackBaseAgent:
    """
    Fallback BaseAgent so this file remains import-safe.

    When real BaseAgent exists, ResponseBuilder can still work with it.
    """

    agent_name = "response_builder"
    agent_type = "core_helper"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.initialized_at = datetime.now(timezone.utc).isoformat()

    def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
        logger.debug("Fallback emit_event: %s | %s", event_name, payload)

    def log_audit(self, payload: Dict[str, Any]) -> None:
        logger.info("Fallback audit log: %s", payload)


try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    BaseAgent = _FallbackBaseAgent  # type: ignore


# =============================================================================
# ResponseBuilder
# =============================================================================

class ResponseBuilder(BaseAgent):
    """
    Builds final structured responses for the William/Jarvis system.

    Main responsibilities:
        - Build success responses
        - Build error responses
        - Build partial completion responses
        - Build progress reports
        - Build module completion summaries
        - Build dashboard/API compatible payloads
        - Prepare verification payloads
        - Prepare memory payloads
        - Emit audit-compatible events
        - Enforce user_id/workspace_id isolation where relevant

    This class does not execute destructive actions.
    It only formats, validates, summarizes, and prepares response payloads.
    """

    agent_name = "response_builder"
    agent_type = "core_helper"
    module_name = "core"

    DEFAULT_COMPLETION_TRACKING = {
        "agent_module": "Core Master Control Files",
        "file_completed": "response_builder.py",
        "completion": 70.0,
        "completed_files": [
            "context.py",
            "config.py",
            "master_agent.py",
            "planner.py",
            "router.py",
            "task_manager.py",
            "response_builder.py",
        ],
        "remaining_files": [
            "safety_bridge.py",
            "verification_bridge.py",
            "memory_bridge.py",
        ],
        "next_recommended_file": "core/safety_bridge.py",
    }

    def __init__(
        self,
        default_audience: str = ResponseAudience.USER.value,
        enable_audit_log: bool = True,
        enable_memory_payload: bool = True,
        enable_verification_payload: bool = True,
        strict_saas_isolation: bool = True,
    ) -> None:
        super().__init__()

        self.default_audience = default_audience
        self.enable_audit_log = enable_audit_log
        self.enable_memory_payload = enable_memory_payload
        self.enable_verification_payload = enable_verification_payload
        self.strict_saas_isolation = strict_saas_isolation

        self.created_at = datetime.now(timezone.utc).isoformat()

    # =========================================================================
    # Public Builders
    # =========================================================================

    def build_success_response(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        context: Optional[Any] = None,
        next_steps: Optional[List[Union[NextStep, Dict[str, Any]]]] = None,
        progress: Optional[List[Union[ProgressItem, Dict[str, Any]]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        audience: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Build a successful user/API/dashboard response.
        """

        valid, validation_error = self._validate_task_context(context)

        if not valid:
            return self._error_result(
                message="Task context validation failed.",
                error_code="CONTEXT_VALIDATION_FAILED",
                details=validation_error,
                context=context,
                audience=audience or self.default_audience,
            )

        response_metadata = self._build_metadata(
            context=context,
            audience=audience or self.default_audience,
            extra=metadata,
        )

        normalized_next_steps = self._normalize_next_steps(next_steps)
        normalized_progress = self._normalize_progress(progress)

        payload_data: Dict[str, Any] = {
            "result": data or {},
            "progress": normalized_progress,
            "next_steps": normalized_next_steps,
            "summary": self._build_summary(
                status=ResponseStatus.SUCCESS.value,
                message=message,
                data=data or {},
                progress=normalized_progress,
            ),
        }

        if self.enable_verification_payload:
            payload_data["verification_payload"] = self._prepare_verification_payload(
                context=context,
                status=ResponseStatus.SUCCESS.value,
                data=payload_data,
            )

        if self.enable_memory_payload:
            payload_data["memory_payload"] = self._prepare_memory_payload(
                context=context,
                message=message,
                data=data or {},
                status=ResponseStatus.SUCCESS.value,
            )

        result = self._safe_result(
            message=message,
            data=payload_data,
            metadata=response_metadata,
        )

        self._emit_agent_event(
            event_name="response.success.created",
            payload=result,
            context=context,
        )

        self._log_audit_event(
            action="build_success_response",
            context=context,
            payload=result,
            severity=ResponseSeverity.LOW.value,
        )

        return result

    def build_error_response(
        self,
        message: str,
        error: Optional[Union[str, Exception, Dict[str, Any]]] = None,
        context: Optional[Any] = None,
        error_code: str = "RESPONSE_ERROR",
        severity: str = ResponseSeverity.MEDIUM.value,
        recoverable: bool = True,
        next_steps: Optional[List[Union[NextStep, Dict[str, Any]]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        audience: Optional[str] = None,
        include_traceback: bool = False,
    ) -> Dict[str, Any]:
        """
        Build a safe, structured error response.
        """

        response_metadata = self._build_metadata(
            context=context,
            audience=audience or self.default_audience,
            extra=metadata,
        )

        error_payload = self._normalize_error(
            error=error,
            error_code=error_code,
            severity=severity,
            recoverable=recoverable,
            include_traceback=include_traceback,
        )

        normalized_next_steps = self._normalize_next_steps(
            next_steps
            or [
                NextStep(
                    title="Review the error details",
                    description="Check the error message and retry after fixing the issue.",
                    action_key="review_error",
                    priority=1,
                    requires_user_action=True,
                )
            ]
        )

        payload_data = {
            "status": ResponseStatus.ERROR.value,
            "next_steps": normalized_next_steps,
            "summary": {
                "status": ResponseStatus.ERROR.value,
                "message": message,
                "error_code": error_code,
                "recoverable": recoverable,
            },
        }

        result = self._error_result(
            message=message,
            error_code=error_code,
            details=error_payload,
            data=payload_data,
            context=context,
            metadata=response_metadata,
            audience=audience or self.default_audience,
        )

        self._emit_agent_event(
            event_name="response.error.created",
            payload=result,
            context=context,
        )

        self._log_audit_event(
            action="build_error_response",
            context=context,
            payload=result,
            severity=severity,
        )

        return result

    def build_partial_response(
        self,
        message: str,
        completed_items: Optional[List[Any]] = None,
        failed_items: Optional[List[Any]] = None,
        pending_items: Optional[List[Any]] = None,
        context: Optional[Any] = None,
        next_steps: Optional[List[Union[NextStep, Dict[str, Any]]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        audience: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Build a partial completion response.
        """

        completed_items = completed_items or []
        failed_items = failed_items or []
        pending_items = pending_items or []

        total = len(completed_items) + len(failed_items) + len(pending_items)
        completion_percentage = 0.0 if total == 0 else round((len(completed_items) / total) * 100, 2)

        progress = [
            ProgressItem(
                title="Completed items",
                status=ResponseStatus.SUCCESS.value,
                percentage=completion_percentage,
                message=f"{len(completed_items)} of {total} items completed.",
                stage=ProgressStage.EXECUTING.value,
                completed_at=datetime.now(timezone.utc).isoformat(),
            )
        ]

        data = {
            "completed_items": completed_items,
            "failed_items": failed_items,
            "pending_items": pending_items,
            "total_items": total,
            "completion_percentage": completion_percentage,
        }

        response_metadata = self._build_metadata(
            context=context,
            audience=audience or self.default_audience,
            extra=metadata,
        )

        result = self._safe_result(
            message=message,
            data={
                "status": ResponseStatus.PARTIAL.value,
                "result": data,
                "progress": self._normalize_progress(progress),
                "next_steps": self._normalize_next_steps(next_steps),
                "summary": self._build_summary(
                    status=ResponseStatus.PARTIAL.value,
                    message=message,
                    data=data,
                    progress=self._normalize_progress(progress),
                ),
            },
            metadata=response_metadata,
        )

        self._emit_agent_event(
            event_name="response.partial.created",
            payload=result,
            context=context,
        )

        self._log_audit_event(
            action="build_partial_response",
            context=context,
            payload=result,
            severity=ResponseSeverity.MEDIUM.value,
        )

        return result

    def build_progress_report(
        self,
        title: str,
        items: List[Union[ProgressItem, Dict[str, Any]]],
        context: Optional[Any] = None,
        message: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        audience: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Build a progress report with calculated completion percentage.
        """

        normalized_items = self._normalize_progress(items)
        completion_percentage = self.calculate_progress_percentage(normalized_items)

        report_message = message or f"{title} is {completion_percentage}% complete."

        response_metadata = self._build_metadata(
            context=context,
            audience=audience or self.default_audience,
            extra=metadata,
        )

        data = {
            "title": title,
            "items": normalized_items,
            "completion_percentage": completion_percentage,
            "status": self._derive_progress_status(normalized_items),
        }

        result = self._safe_result(
            message=report_message,
            data=data,
            metadata=response_metadata,
        )

        self._emit_agent_event(
            event_name="response.progress.created",
            payload=result,
            context=context,
        )

        return result

    def build_module_completion_response(
        self,
        agent_module: Optional[str] = None,
        file_completed: Optional[str] = None,
        completion: Optional[float] = None,
        completed_files: Optional[List[str]] = None,
        remaining_files: Optional[List[str]] = None,
        next_recommended_file: Optional[str] = None,
        context: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Build the exact module completion format required by the William/Jarvis
        all-file prompt workflow.
        """

        tracking = dict(self.DEFAULT_COMPLETION_TRACKING)

        if agent_module is not None:
            tracking["agent_module"] = agent_module

        if file_completed is not None:
            tracking["file_completed"] = file_completed

        if completion is not None:
            tracking["completion"] = float(completion)

        if completed_files is not None:
            tracking["completed_files"] = completed_files

        if remaining_files is not None:
            tracking["remaining_files"] = remaining_files

        if next_recommended_file is not None:
            tracking["next_recommended_file"] = next_recommended_file

        message = (
            f"Agent/Module: {tracking['agent_module']}\n"
            f"File Completed: {tracking['file_completed']}\n"
            f"Completion: {tracking['completion']}%\n"
            f"Completed Files: {tracking['completed_files']}\n"
            f"Remaining Files: {tracking['remaining_files']}\n"
            f"Next Recommended File: {tracking['next_recommended_file']}"
        )

        return self.build_success_response(
            message=message,
            data={
                "completion_tracking": tracking,
                "formatted_completion": message,
            },
            context=context,
            next_steps=[
                NextStep(
                    title=f"Generate {tracking['next_recommended_file']}",
                    description="Continue the Core Master Control Files module by creating the next recommended file.",
                    action_key="generate_next_file",
                    priority=1,
                    requires_user_action=True,
                    metadata={
                        "next_file": tracking["next_recommended_file"],
                    },
                )
            ],
            progress=[
                ProgressItem(
                    title=tracking["file_completed"],
                    status=ResponseStatus.SUCCESS.value,
                    percentage=tracking["completion"],
                    message=f"{tracking['file_completed']} completed successfully.",
                    stage=ProgressStage.COMPLETED.value,
                    completed_at=datetime.now(timezone.utc).isoformat(),
                )
            ],
        )

    def build_dashboard_payload(
        self,
        response: Dict[str, Any],
        widgets: Optional[List[Dict[str, Any]]] = None,
        charts: Optional[List[Dict[str, Any]]] = None,
        table_rows: Optional[List[Dict[str, Any]]] = None,
        context: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Convert any response into dashboard-ready format.
        """

        metadata = self._build_metadata(
            context=context,
            audience=ResponseAudience.DASHBOARD.value,
            extra=response.get("metadata", {}),
        )

        payload = {
            "success": bool(response.get("success", False)),
            "message": response.get("message", ""),
            "dashboard": {
                "widgets": widgets or [],
                "charts": charts or [],
                "table_rows": table_rows or [],
                "raw_response": response,
            },
            "metadata": metadata,
            "error": response.get("error"),
        }

        self._emit_agent_event(
            event_name="response.dashboard.created",
            payload=payload,
            context=context,
        )

        return payload

    def build_api_payload(
        self,
        response: Dict[str, Any],
        status_code: Optional[int] = None,
        context: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Convert response into FastAPI/API-friendly payload.
        """

        success = bool(response.get("success", False))

        if status_code is None:
            status_code = 200 if success else 400

        if response.get("error", {}).get("error_code") == "CONTEXT_VALIDATION_FAILED":
            status_code = 422

        if response.get("error", {}).get("error_code") == "SECURITY_APPROVAL_REQUIRED":
            status_code = 403

        metadata = self._build_metadata(
            context=context,
            audience=ResponseAudience.API.value,
            extra=response.get("metadata", {}),
        )

        return {
            "status_code": status_code,
            "body": {
                "success": success,
                "message": response.get("message", ""),
                "data": response.get("data", {}),
                "error": response.get("error"),
                "metadata": metadata,
            },
        }

    # =========================================================================
    # Progress / Summary Helpers
    # =========================================================================

    def calculate_progress_percentage(
        self,
        items: Optional[List[Union[ProgressItem, Dict[str, Any]]]] = None,
    ) -> float:
        """
        Calculate average progress from progress items.
        """

        if not items:
            return 0.0

        normalized = self._normalize_progress(items)

        if not normalized:
            return 0.0

        total_percentage = 0.0

        for item in normalized:
            try:
                total_percentage += float(item.get("percentage", 0.0))
            except Exception:
                total_percentage += 0.0

        return round(total_percentage / len(normalized), 2)

    def format_user_summary(
        self,
        title: str,
        status: str,
        completion_percentage: Optional[float] = None,
        completed_files: Optional[List[str]] = None,
        remaining_files: Optional[List[str]] = None,
        next_recommended_file: Optional[str] = None,
        notes: Optional[List[str]] = None,
    ) -> str:
        """
        Build a clean user-facing summary string.
        """

        lines = [
            f"{title}",
            f"Status: {status}",
        ]

        if completion_percentage is not None:
            lines.append(f"Completion: {completion_percentage}%")

        if completed_files is not None:
            lines.append(f"Completed Files: {completed_files}")

        if remaining_files is not None:
            lines.append(f"Remaining Files: {remaining_files}")

        if next_recommended_file is not None:
            lines.append(f"Next Recommended File: {next_recommended_file}")

        if notes:
            lines.append("Notes:")
            for note in notes:
                lines.append(f"- {note}")

        return "\n".join(lines)

    def format_error_for_user(
        self,
        error: Union[str, Exception, Dict[str, Any]],
        include_recovery: bool = True,
    ) -> str:
        """
        Create a clean user-facing error message without leaking secrets.
        """

        normalized = self._normalize_error(error)

        message = normalized.get("message", "An unknown error occurred.")
        error_code = normalized.get("error_code", "UNKNOWN_ERROR")

        lines = [
            f"Error: {message}",
            f"Code: {error_code}",
        ]

        if include_recovery:
            lines.append("Next Step: Review the issue, fix the related input/configuration, then retry.")

        return "\n".join(lines)

    # =========================================================================
    # Required Compatibility Hooks
    # =========================================================================

    def _validate_task_context(self, context: Optional[Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Validate SaaS user/workspace context.

        If strict SaaS isolation is enabled and a context is provided,
        user_id and workspace_id must exist.

        This keeps memory, audit, analytics, files, and task history isolated.
        """

        if context is None:
            return True, None

        user_id = self._get_context_value(context, "user_id")
        workspace_id = self._get_context_value(context, "workspace_id")

        if self.strict_saas_isolation:
            missing = []

            if user_id in (None, "", 0):
                missing.append("user_id")

            if workspace_id in (None, "", 0):
                missing.append("workspace_id")

            if missing:
                return False, {
                    "missing_fields": missing,
                    "message": "SaaS isolation requires user_id and workspace_id.",
                }

        return True, None

    def _requires_security_check(
        self,
        action: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Decide whether response building requires Security Agent check.

        Response formatting itself is usually safe.
        However, if the response includes sensitive outputs, financial fields,
        system commands, calls, messages, browser actions, credentials, or
        destructive operation markers, this returns True.
        """

        sensitive_keywords = {
            "password",
            "secret",
            "token",
            "api_key",
            "private_key",
            "credential",
            "delete",
            "payment",
            "transfer",
            "call",
            "send_message",
            "browser_action",
            "system_command",
            "financial_action",
            "destructive",
        }

        action_text = (action or "").lower()

        if any(keyword in action_text for keyword in sensitive_keywords):
            return True

        if not data:
            return False

        flattened = str(data).lower()

        return any(keyword in flattened for keyword in sensitive_keywords)

    def _request_security_approval(
        self,
        context: Optional[Any],
        action: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare a Security Agent approval request.

        This file does not directly perform security decisions.
        It prepares a structured payload that Security Agent can consume.
        """

        return {
            "success": False,
            "message": "Security approval required before continuing.",
            "data": {
                "approval_required": True,
                "security_payload": {
                    "action": action,
                    "data": data or {},
                    "user_id": self._get_context_value(context, "user_id"),
                    "workspace_id": self._get_context_value(context, "workspace_id"),
                    "task_id": self._get_context_value(context, "task_id"),
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "requested_by": self.agent_name,
                },
            },
            "error": {
                "error_code": "SECURITY_APPROVAL_REQUIRED",
                "message": "Sensitive response/action needs Security Agent approval.",
            },
            "metadata": self._build_metadata(context=context),
        }

    def _prepare_verification_payload(
        self,
        context: Optional[Any],
        status: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare payload for Verification Agent.

        Verification Agent can later confirm:
            - task completed
            - output structure valid
            - SaaS isolation respected
            - expected fields exist
        """

        return {
            "verification_type": "response_output_verification",
            "status": status,
            "agent_name": self.agent_name,
            "module_name": self.module_name,
            "user_id": self._get_context_value(context, "user_id"),
            "workspace_id": self._get_context_value(context, "workspace_id"),
            "task_id": self._get_context_value(context, "task_id"),
            "requires_human_review": status in {
                ResponseStatus.ERROR.value,
                ResponseStatus.BLOCKED.value,
                ResponseStatus.PARTIAL.value,
            },
            "data_keys": sorted(list((data or {}).keys())),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

    def _prepare_memory_payload(
        self,
        context: Optional[Any],
        message: str,
        data: Optional[Dict[str, Any]] = None,
        status: str = ResponseStatus.SUCCESS.value,
    ) -> Dict[str, Any]:
        """
        Prepare payload compatible with Memory Agent.

        This does not store memory directly.
        It prepares safe memory context for future Memory Agent processing.
        """

        return {
            "memory_type": "task_response_summary",
            "user_id": self._get_context_value(context, "user_id"),
            "workspace_id": self._get_context_value(context, "workspace_id"),
            "task_id": self._get_context_value(context, "task_id"),
            "summary": message,
            "status": status,
            "important_keys": sorted(list((data or {}).keys())),
            "created_by": self.agent_name,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

    def _emit_agent_event(
        self,
        event_name: str,
        payload: Dict[str, Any],
        context: Optional[Any] = None,
    ) -> None:
        """
        Emit event for registry/router/dashboard listeners.

        Uses BaseAgent.emit_event if available.
        Safe fallback logs only.
        """

        event_payload = {
            "event_name": event_name,
            "agent_name": self.agent_name,
            "module_name": self.module_name,
            "user_id": self._get_context_value(context, "user_id"),
            "workspace_id": self._get_context_value(context, "workspace_id"),
            "task_id": self._get_context_value(context, "task_id"),
            "payload": payload,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        try:
            emit = getattr(super(), "emit_event", None)
            if callable(emit):
                emit(event_name, event_payload)
            else:
                logger.debug("Agent event: %s", event_payload)
        except Exception as exc:
            logger.debug("Failed to emit agent event: %s", exc)

    def _log_audit_event(
        self,
        action: str,
        context: Optional[Any],
        payload: Optional[Dict[str, Any]] = None,
        severity: str = ResponseSeverity.LOW.value,
    ) -> None:
        """
        Log audit-compatible response event.

        This does not persist to a database by itself.
        It calls BaseAgent.log_audit if available, otherwise logs safely.
        """

        if not self.enable_audit_log:
            return

        audit_payload = {
            "action": action,
            "severity": severity,
            "agent_name": self.agent_name,
            "module_name": self.module_name,
            "user_id": self._get_context_value(context, "user_id"),
            "workspace_id": self._get_context_value(context, "workspace_id"),
            "task_id": self._get_context_value(context, "task_id"),
            "payload_summary": self._safe_payload_summary(payload or {}),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        try:
            log_audit = getattr(super(), "log_audit", None)
            if callable(log_audit):
                log_audit(audit_payload)
            else:
                logger.info("Audit event: %s", audit_payload)
        except Exception as exc:
            logger.debug("Failed to log audit event: %s", exc)

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard successful response wrapper.
        """

        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": metadata or self._build_metadata(),
        }

    def _error_result(
        self,
        message: str,
        error_code: str = "ERROR",
        details: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        context: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
        audience: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Standard error response wrapper.
        """

        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": {
                "error_code": error_code,
                "message": message,
                "details": details or {},
            },
            "metadata": metadata
            or self._build_metadata(
                context=context,
                audience=audience or self.default_audience,
            ),
        }

    # =========================================================================
    # Normalizers
    # =========================================================================

    def _normalize_next_steps(
        self,
        next_steps: Optional[List[Union[NextStep, Dict[str, Any]]]],
    ) -> List[Dict[str, Any]]:
        """
        Normalize NextStep dataclasses/dicts into dictionaries.
        """

        if not next_steps:
            return []

        normalized: List[Dict[str, Any]] = []

        for step in next_steps:
            if isinstance(step, NextStep):
                normalized.append(asdict(step))
            elif isinstance(step, dict):
                normalized.append({
                    "title": str(step.get("title", "Next step")),
                    "description": step.get("description"),
                    "action_key": step.get("action_key"),
                    "priority": int(step.get("priority", 1)),
                    "requires_user_action": bool(step.get("requires_user_action", False)),
                    "metadata": dict(step.get("metadata", {})),
                })
            else:
                normalized.append({
                    "title": str(step),
                    "description": None,
                    "action_key": None,
                    "priority": 1,
                    "requires_user_action": True,
                    "metadata": {},
                })

        return sorted(normalized, key=lambda item: item.get("priority", 1))

    def _normalize_progress(
        self,
        progress: Optional[List[Union[ProgressItem, Dict[str, Any]]]],
    ) -> List[Dict[str, Any]]:
        """
        Normalize progress item dataclasses/dicts into dictionaries.
        """

        if not progress:
            return []

        normalized: List[Dict[str, Any]] = []

        for item in progress:
            if isinstance(item, ProgressItem):
                normalized.append(asdict(item))
            elif isinstance(item, dict):
                normalized.append({
                    "title": str(item.get("title", "Progress item")),
                    "status": str(item.get("status", ResponseStatus.PENDING.value)),
                    "percentage": self._clamp_percentage(item.get("percentage", 0.0)),
                    "message": item.get("message"),
                    "stage": item.get("stage"),
                    "started_at": item.get("started_at"),
                    "completed_at": item.get("completed_at"),
                    "error": item.get("error"),
                })
            else:
                normalized.append({
                    "title": str(item),
                    "status": ResponseStatus.PENDING.value,
                    "percentage": 0.0,
                    "message": None,
                    "stage": None,
                    "started_at": None,
                    "completed_at": None,
                    "error": None,
                })

        return normalized

    def _normalize_error(
        self,
        error: Optional[Union[str, Exception, Dict[str, Any]]] = None,
        error_code: str = "ERROR",
        severity: str = ResponseSeverity.MEDIUM.value,
        recoverable: bool = True,
        include_traceback: bool = False,
    ) -> Dict[str, Any]:
        """
        Normalize string/exception/dict errors into safe structured error.
        """

        if error is None:
            return {
                "error_code": error_code,
                "message": "No additional error details provided.",
                "type": "unknown",
                "severity": severity,
                "recoverable": recoverable,
            }

        if isinstance(error, dict):
            safe_error = dict(error)
            safe_error.setdefault("error_code", error_code)
            safe_error.setdefault("severity", severity)
            safe_error.setdefault("recoverable", recoverable)
            safe_error = self._redact_sensitive_values(safe_error)
            return safe_error

        if isinstance(error, Exception):
            payload = {
                "error_code": error_code,
                "message": str(error),
                "type": error.__class__.__name__,
                "severity": severity,
                "recoverable": recoverable,
            }

            if include_traceback:
                payload["traceback"] = traceback.format_exc()

            return self._redact_sensitive_values(payload)

        return {
            "error_code": error_code,
            "message": str(error),
            "type": "string_error",
            "severity": severity,
            "recoverable": recoverable,
        }

    # =========================================================================
    # Internal Formatters
    # =========================================================================

    def _build_metadata(
        self,
        context: Optional[Any] = None,
        audience: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Build metadata from context and optional custom fields.
        """

        metadata = ResponseMetadata(
            user_id=self._get_context_value(context, "user_id"),
            workspace_id=self._get_context_value(context, "workspace_id"),
            task_id=self._get_context_value(context, "task_id"),
            request_id=self._get_context_value(context, "request_id"),
            agent_name=self.agent_name,
            module_name=self.module_name,
            audience=audience or self.default_audience,
            trace_id=self._get_context_value(context, "trace_id"),
        )

        payload = asdict(metadata)

        if extra:
            payload.update(self._redact_sensitive_values(extra))

        return payload

    def _build_summary(
        self,
        status: str,
        message: str,
        data: Dict[str, Any],
        progress: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Build machine-readable and user-friendly response summary.
        """

        progress = progress or []

        return {
            "status": status,
            "message": message,
            "data_keys": sorted(list(data.keys())),
            "progress_percentage": self.calculate_progress_percentage(progress),
            "progress_status": self._derive_progress_status(progress),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def _derive_progress_status(
        self,
        progress: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        """
        Derive global progress status from progress items.
        """

        if not progress:
            return ResponseStatus.PENDING.value

        statuses = {str(item.get("status", "")).lower() for item in progress}

        if ResponseStatus.ERROR.value in statuses:
            return ResponseStatus.ERROR.value

        if ResponseStatus.BLOCKED.value in statuses:
            return ResponseStatus.BLOCKED.value

        if ResponseStatus.PARTIAL.value in statuses:
            return ResponseStatus.PARTIAL.value

        if all(status == ResponseStatus.SUCCESS.value for status in statuses):
            return ResponseStatus.SUCCESS.value

        if ResponseStatus.WARNING.value in statuses:
            return ResponseStatus.WARNING.value

        return ResponseStatus.PENDING.value

    # =========================================================================
    # Context / Safety Utilities
    # =========================================================================

    def _get_context_value(self, context: Optional[Any], key: str) -> Optional[Any]:
        """
        Safely get value from TaskContext, dict, dataclass, or object.
        """

        if context is None:
            return None

        if isinstance(context, dict):
            return context.get(key)

        if hasattr(context, key):
            return getattr(context, key)

        try:
            if hasattr(context, "get"):
                return context.get(key)
        except Exception:
            return None

        return None

    def _safe_payload_summary(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create safe summary for audit logging.
        """

        redacted = self._redact_sensitive_values(payload)

        return {
            "success": redacted.get("success"),
            "message": redacted.get("message"),
            "has_data": bool(redacted.get("data")),
            "has_error": bool(redacted.get("error")),
            "metadata_keys": sorted(list((redacted.get("metadata") or {}).keys())),
        }

    def _redact_sensitive_values(self, value: Any) -> Any:
        """
        Redact secrets/tokens/passwords recursively.
        """

        sensitive_keys = {
            "password",
            "secret",
            "token",
            "access_token",
            "refresh_token",
            "api_key",
            "private_key",
            "credential",
            "authorization",
            "cookie",
        }

        if isinstance(value, dict):
            cleaned = {}
            for key, item in value.items():
                if str(key).lower() in sensitive_keys:
                    cleaned[key] = "[REDACTED]"
                else:
                    cleaned[key] = self._redact_sensitive_values(item)
            return cleaned

        if isinstance(value, list):
            return [self._redact_sensitive_values(item) for item in value]

        if isinstance(value, tuple):
            return tuple(self._redact_sensitive_values(item) for item in value)

        return value

    def _clamp_percentage(self, value: Any) -> float:
        """
        Clamp percentage between 0 and 100.
        """

        try:
            percentage = float(value)
        except Exception:
            percentage = 0.0

        return round(max(0.0, min(100.0, percentage)), 2)

    # =========================================================================
    # Registry / Router Compatibility
    # =========================================================================

    def get_agent_manifest(self) -> Dict[str, Any]:
        """
        Return registry-compatible manifest.
        """

        return {
            "agent_name": self.agent_name,
            "agent_type": self.agent_type,
            "module_name": self.module_name,
            "file_name": "response_builder.py",
            "version": "1.0.0",
            "capabilities": [
                "build_success_response",
                "build_error_response",
                "build_partial_response",
                "build_progress_report",
                "build_module_completion_response",
                "build_dashboard_payload",
                "build_api_payload",
                "calculate_progress_percentage",
                "format_user_summary",
                "format_error_for_user",
            ],
            "requires_security_agent": False,
            "supports_memory_payload": True,
            "supports_verification_payload": True,
            "supports_saas_isolation": True,
            "safe_to_import": True,
        }

    def health_check(self) -> Dict[str, Any]:
        """
        Lightweight health check for dashboard/API.
        """

        return {
            "success": True,
            "message": "ResponseBuilder is healthy.",
            "data": {
                "agent_name": self.agent_name,
                "module_name": self.module_name,
                "created_at": self.created_at,
                "strict_saas_isolation": self.strict_saas_isolation,
                "audit_enabled": self.enable_audit_log,
                "memory_payload_enabled": self.enable_memory_payload,
                "verification_payload_enabled": self.enable_verification_payload,
            },
            "error": None,
            "metadata": self._build_metadata(audience=ResponseAudience.SYSTEM.value),
        }


# =============================================================================
# Convenience Singleton
# =============================================================================

response_builder = ResponseBuilder()


# =============================================================================
# Convenience Functions
# =============================================================================

def build_success_response(
    message: str,
    data: Optional[Dict[str, Any]] = None,
    context: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Convenience function for simple success response.
    """

    return response_builder.build_success_response(
        message=message,
        data=data,
        context=context,
    )


def build_error_response(
    message: str,
    error: Optional[Union[str, Exception, Dict[str, Any]]] = None,
    context: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Convenience function for simple error response.
    """

    return response_builder.build_error_response(
        message=message,
        error=error,
        context=context,
    )


def build_module_completion_response() -> Dict[str, Any]:
    """
    Convenience function for required completion tracking.
    """

    return response_builder.build_module_completion_response()


# =============================================================================
# Local Manual Test
# =============================================================================

if __name__ == "__main__":
    test_context = {
        "user_id": "user_001",
        "workspace_id": "workspace_001",
        "task_id": "task_response_builder_test",
        "request_id": "req_001",
    }

    builder = ResponseBuilder()

    success = builder.build_success_response(
        message="ResponseBuilder test completed successfully.",
        data={
            "file": "core/response_builder.py",
            "status": "ready",
        },
        context=test_context,
        progress=[
            ProgressItem(
                title="Create response builder",
                status=ResponseStatus.SUCCESS.value,
                percentage=100.0,
                message="Response builder created successfully.",
                stage=ProgressStage.COMPLETED.value,
                completed_at=datetime.now(timezone.utc).isoformat(),
            )
        ],
        next_steps=[
            NextStep(
                title="Generate core/safety_bridge.py",
                description="Continue with the next Core Master Control file.",
                action_key="generate_next_file",
                priority=1,
                requires_user_action=True,
            )
        ],
    )

    print(success)

    completion = builder.build_module_completion_response(context=test_context)
    print(completion["data"]["result"]["formatted_completion"])