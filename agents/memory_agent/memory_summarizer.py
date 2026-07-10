"""
agents/memory_agent/memory_summarizer.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Compresses long chats, documents, project updates, notes, and raw text into
    clean memory-ready summaries for the Memory Agent.

Core Responsibilities:
    - Summarize long text safely and deterministically.
    - Extract key facts, decisions, action items, risks, preferences, entities,
      project updates, and memory candidates.
    - Preserve SaaS isolation through user_id and workspace_id validation.
    - Prepare structured Memory Agent payloads.
    - Prepare Verification Agent payloads for completed summarization work.
    - Emit audit/event hooks for Master Agent, Dashboard/API, and Registry use.
    - Remain import-safe even if future William modules are not available yet.

Architecture Connections:
    - Master Agent:
        Can route long chat/doc compression tasks to MemorySummarizer.
    - Memory Agent:
        Uses this file to turn noisy long input into clean structured memory.
    - Security Agent:
        Sensitive/high-privacy summarization requests can be security-checked.
    - Verification Agent:
        Receives verification payloads after summaries are created.
    - Dashboard/API:
        Can call public methods and receive JSON-style structured results.
    - Registry/Loader/Router:
        Exposes clear class name and compatibility metadata.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Import-safe BaseAgent fallback
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for early project stages
    class BaseAgent:  # type: ignore
        """
        Safe fallback BaseAgent.

        This fallback allows the file to import before the final William/Jarvis
        BaseAgent exists. When the real BaseAgent is available, it will be used.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
            self.logger = logging.getLogger(self.agent_name)

        def emit_event(self, *args: Any, **kwargs: Any) -> None:
            return None

        def log_audit(self, *args: Any, **kwargs: Any) -> None:
            return None


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)


# ---------------------------------------------------------------------------
# Enums / Data Structures
# ---------------------------------------------------------------------------

class SummaryInputType(str, Enum):
    CHAT = "chat"
    DOCUMENT = "document"
    PROJECT_UPDATE = "project_update"
    MEETING_NOTES = "meeting_notes"
    TASK_HISTORY = "task_history"
    AGENT_LOG = "agent_log"
    RAW_MEMORY = "raw_memory"
    UNKNOWN = "unknown"


class SummaryStyle(str, Enum):
    CLEAN_MEMORY = "clean_memory"
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    DECISION_LOG = "decision_log"
    ACTION_ITEMS = "action_items"
    COMPACT = "compact"
    DETAILED = "detailed"


class MemoryImportance(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PrivacyLevel(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    PRIVATE = "private"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


@dataclass
class SummaryConfig:
    """
    Runtime configuration for summarization.

    This file intentionally avoids requiring external LLM providers. It uses
    deterministic extractive + rule-based compression by default, while exposing
    a clean interface that can later be connected to an LLM provider by the
    Master Agent or Memory Agent.
    """

    max_input_chars: int = 250_000
    default_target_chars: int = 6_000
    min_target_chars: int = 700
    max_target_chars: int = 20_000
    chunk_size_chars: int = 12_000
    chunk_overlap_chars: int = 800
    max_bullets: int = 30
    max_action_items: int = 25
    max_decisions: int = 25
    max_entities: int = 50
    max_memory_candidates: int = 40
    include_source_hash: bool = True
    include_audit_events: bool = True
    sensitive_keywords: Tuple[str, ...] = (
        "password",
        "secret",
        "api key",
        "token",
        "private key",
        "access key",
        "credential",
        "credit card",
        "bank account",
        "ssn",
        "passport",
        "medical",
        "diagnosis",
        "legal case",
        "lawsuit",
        "confidential",
    )


@dataclass
class TaskContext:
    """
    SaaS-safe task context.

    user_id and workspace_id are required whenever user-specific memory is
    summarized or prepared for storage.
    """

    user_id: str
    workspace_id: str
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    task_id: Optional[str] = None
    agent_id: str = "memory_summarizer"
    source_agent: Optional[str] = None
    session_id: Optional[str] = None
    role: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SummaryRequest:
    """
    Public request object for summarization calls.
    """

    text: str
    context: TaskContext
    input_type: SummaryInputType = SummaryInputType.UNKNOWN
    style: SummaryStyle = SummaryStyle.CLEAN_MEMORY
    target_chars: Optional[int] = None
    title: Optional[str] = None
    source_id: Optional[str] = None
    project_id: Optional[str] = None
    client_id: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    privacy_level: PrivacyLevel = PrivacyLevel.PRIVATE
    importance_hint: Optional[MemoryImportance] = None
    preserve_code_blocks: bool = True
    include_action_items: bool = True
    include_decisions: bool = True
    include_entities: bool = True
    include_memory_candidates: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MemoryCandidate:
    """
    A clean memory candidate that can later be routed by memory_router.py.
    """

    content: str
    category: str
    importance: MemoryImportance
    privacy_level: PrivacyLevel
    confidence: float
    reason: str
    tags: List[str] = field(default_factory=list)


@dataclass
class SummaryResultData:
    """
    Structured summarization output.
    """

    title: str
    summary: str
    compact_summary: str
    key_points: List[str]
    decisions: List[str]
    action_items: List[str]
    risks_or_blockers: List[str]
    entities: List[str]
    memory_candidates: List[Dict[str, Any]]
    source_hash: Optional[str]
    input_type: str
    style: str
    privacy_level: str
    importance: str
    token_estimate: Dict[str, int]
    metadata: Dict[str, Any]


# ---------------------------------------------------------------------------
# MemorySummarizer
# ---------------------------------------------------------------------------

class MemorySummarizer(BaseAgent):
    """
    Compresses long chats/docs/project updates into clean memory.

    This class is deterministic and safe to run without external services. It
    can later be upgraded to call an LLM through a permissioned model gateway,
    but this file itself does not call browsers, system commands, financial
    tools, messages, calls, or destructive operations.

    Public Methods:
        - summarize()
        - summarize_text()
        - summarize_chat()
        - summarize_document()
        - summarize_project_update()
        - summarize_many()
        - build_memory_payload_from_summary()
        - health_check()
        - get_registry_metadata()
    """

    VERSION = "1.0.0"
    AGENT_NAME = "MemorySummarizer"
    AGENT_ID = "memory_summarizer"
    MODULE = "memory_agent"
    FILE_PATH = "agents/memory_agent/memory_summarizer.py"

    def __init__(self, config: Optional[SummaryConfig] = None, **kwargs: Any) -> None:
        super().__init__(
            agent_name=kwargs.get("agent_name", self.AGENT_NAME),
            agent_id=kwargs.get("agent_id", self.AGENT_ID),
        )
        self.config = config or SummaryConfig()
        self.logger = logging.getLogger(self.AGENT_NAME)

    # ------------------------------------------------------------------
    # Required Compatibility Hooks
    # ------------------------------------------------------------------

    def _validate_task_context(
        self,
        context: Union[TaskContext, Dict[str, Any], None],
        *,
        require_user_workspace: bool = True,
    ) -> Tuple[bool, Optional[TaskContext], Optional[str]]:
        """
        Validate SaaS task context.

        This protects against memory/data mixing between users/workspaces.
        """

        if context is None:
            return False, None, "Task context is required."

        if isinstance(context, dict):
            try:
                context = TaskContext(
                    user_id=str(context.get("user_id", "")).strip(),
                    workspace_id=str(context.get("workspace_id", "")).strip(),
                    request_id=str(context.get("request_id") or uuid.uuid4()),
                    task_id=context.get("task_id"),
                    agent_id=str(context.get("agent_id") or self.AGENT_ID),
                    source_agent=context.get("source_agent"),
                    session_id=context.get("session_id"),
                    role=context.get("role"),
                    permissions=list(context.get("permissions") or []),
                    metadata=dict(context.get("metadata") or {}),
                )
            except Exception as exc:
                return False, None, f"Invalid task context format: {exc}"

        if not isinstance(context, TaskContext):
            return False, None, "Task context must be TaskContext or dict."

        if require_user_workspace:
            if not context.user_id or not isinstance(context.user_id, str):
                return False, None, "user_id is required for memory summarization."
            if not context.workspace_id or not isinstance(context.workspace_id, str):
                return False, None, "workspace_id is required for memory summarization."

        if context.user_id and len(context.user_id) > 256:
            return False, None, "user_id is too long."
        if context.workspace_id and len(context.workspace_id) > 256:
            return False, None, "workspace_id is too long."

        return True, context, None

    def _requires_security_check(
        self,
        request: SummaryRequest,
    ) -> bool:
        """
        Decide whether summarization should go through Security Agent approval.

        Summarization itself is non-destructive, but sensitive or restricted
        memory can require approval before storage or downstream use.
        """

        if request.privacy_level in {PrivacyLevel.CONFIDENTIAL, PrivacyLevel.RESTRICTED}:
            return True

        lowered = request.text[:50_000].lower()
        return any(keyword in lowered for keyword in self.config.sensitive_keywords)

    def _request_security_approval(
        self,
        request: SummaryRequest,
        reason: str = "Sensitive summarization request",
    ) -> Dict[str, Any]:
        """
        Security Agent approval hook.

        This file does not directly call Security Agent because the future
        module may not exist yet. It returns a structured approval request that
        Master Agent/Security Agent can process.
        """

        approval_payload = {
            "approval_required": True,
            "reason": reason,
            "agent": self.AGENT_ID,
            "module": self.MODULE,
            "action": "summarize_memory_input",
            "user_id": request.context.user_id,
            "workspace_id": request.context.workspace_id,
            "request_id": request.context.request_id,
            "privacy_level": request.privacy_level.value,
            "source_id": request.source_id,
            "project_id": request.project_id,
            "client_id": request.client_id,
            "created_at": self._utc_now(),
        }

        return self._safe_result(
            message="Security approval is recommended before storing or routing this summary.",
            data=approval_payload,
            metadata={"security_hook": True},
        )

    def _prepare_verification_payload(
        self,
        *,
        request: SummaryRequest,
        summary_data: SummaryResultData,
    ) -> Dict[str, Any]:
        """
        Prepare payload for Verification Agent.

        The Verification Agent can check summary completeness, privacy, action
        extraction quality, and memory payload readiness.
        """

        return {
            "verification_type": "memory_summary_completed",
            "agent": self.AGENT_ID,
            "module": self.MODULE,
            "user_id": request.context.user_id,
            "workspace_id": request.context.workspace_id,
            "request_id": request.context.request_id,
            "task_id": request.context.task_id,
            "source_id": request.source_id,
            "project_id": request.project_id,
            "client_id": request.client_id,
            "checks": {
                "has_summary": bool(summary_data.summary),
                "has_compact_summary": bool(summary_data.compact_summary),
                "has_key_points": bool(summary_data.key_points),
                "has_source_hash": bool(summary_data.source_hash),
                "privacy_level": summary_data.privacy_level,
                "importance": summary_data.importance,
                "memory_candidate_count": len(summary_data.memory_candidates),
            },
            "summary_preview": summary_data.compact_summary[:500],
            "created_at": self._utc_now(),
        }

    def _prepare_memory_payload(
        self,
        *,
        request: SummaryRequest,
        summary_data: SummaryResultData,
    ) -> Dict[str, Any]:
        """
        Prepare structured Memory Agent payload.

        This does not store memory directly. It prepares clean data for
        memory_agent.py, memory_router.py, long_term.py, project_memory.py, or
        future privacy_guard.py.
        """

        return {
            "memory_payload_type": "summarized_memory",
            "agent": self.AGENT_ID,
            "module": self.MODULE,
            "user_id": request.context.user_id,
            "workspace_id": request.context.workspace_id,
            "request_id": request.context.request_id,
            "task_id": request.context.task_id,
            "source_agent": request.context.source_agent,
            "session_id": request.context.session_id,
            "source_id": request.source_id,
            "project_id": request.project_id,
            "client_id": request.client_id,
            "title": summary_data.title,
            "summary": summary_data.summary,
            "compact_summary": summary_data.compact_summary,
            "key_points": summary_data.key_points,
            "decisions": summary_data.decisions,
            "action_items": summary_data.action_items,
            "risks_or_blockers": summary_data.risks_or_blockers,
            "entities": summary_data.entities,
            "memory_candidates": summary_data.memory_candidates,
            "privacy_level": summary_data.privacy_level,
            "importance": summary_data.importance,
            "tags": request.tags,
            "source_hash": summary_data.source_hash,
            "input_type": summary_data.input_type,
            "style": summary_data.style,
            "metadata": {
                **summary_data.metadata,
                "request_metadata": request.metadata,
                "context_metadata": request.context.metadata,
            },
            "created_at": self._utc_now(),
        }

    def _emit_agent_event(
        self,
        event_name: str,
        payload: Dict[str, Any],
    ) -> None:
        """
        Emit an event for Master Agent, Dashboard, or event stream.

        Import-safe: uses BaseAgent.emit_event when available; otherwise logs.
        """

        try:
            if hasattr(super(), "emit_event"):
                super().emit_event(event_name, payload)  # type: ignore[misc]
            else:
                self.logger.debug("Agent event: %s %s", event_name, payload)
        except Exception as exc:
            self.logger.debug("Failed to emit event %s: %s", event_name, exc)

    def _log_audit_event(
        self,
        action: str,
        payload: Dict[str, Any],
    ) -> None:
        """
        Audit hook for SaaS dashboard/compliance logs.
        """

        if not self.config.include_audit_events:
            return

        audit_payload = {
            "action": action,
            "agent": self.AGENT_ID,
            "module": self.MODULE,
            "created_at": self._utc_now(),
            **payload,
        }

        try:
            if hasattr(super(), "log_audit"):
                super().log_audit(audit_payload)  # type: ignore[misc]
            else:
                self.logger.info("Audit event: %s", json.dumps(audit_payload, default=str)[:2000])
        except Exception as exc:
            self.logger.debug("Failed to write audit event: %s", exc)

    def _safe_result(
        self,
        *,
        message: str,
        data: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard William/Jarvis success result.
        """

        return {
            "success": True,
            "message": message,
            "data": data if data is not None else {},
            "error": None,
            "metadata": {
                "agent": self.AGENT_ID,
                "module": self.MODULE,
                "version": self.VERSION,
                "timestamp": self._utc_now(),
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Union[str, Exception],
        data: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard William/Jarvis error result.
        """

        error_message = str(error)
        self.logger.error("%s: %s", message, error_message)

        return {
            "success": False,
            "message": message,
            "data": data if data is not None else {},
            "error": {
                "type": error.__class__.__name__ if isinstance(error, Exception) else "Error",
                "message": error_message,
            },
            "metadata": {
                "agent": self.AGENT_ID,
                "module": self.MODULE,
                "version": self.VERSION,
                "timestamp": self._utc_now(),
                **(metadata or {}),
            },
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def summarize(
        self,
        request: Union[SummaryRequest, Dict[str, Any]],
        *,
        require_security_approval: bool = False,
    ) -> Dict[str, Any]:
        """
        Main public summarization method.

        Args:
            request:
                SummaryRequest or dict.
            require_security_approval:
                If True, sensitive content returns a security approval payload
                instead of producing a final memory payload.

        Returns:
            Structured dict:
                success, message, data, error, metadata
        """

        started = time.time()

        try:
            parsed_request = self._parse_summary_request(request)

            valid, context, context_error = self._validate_task_context(parsed_request.context)
            if not valid or context is None:
                return self._error_result(
                    message="Invalid summarization context.",
                    error=context_error or "Unknown context error.",
                )

            parsed_request.context = context

            text_validation_error = self._validate_text(parsed_request.text)
            if text_validation_error:
                return self._error_result(
                    message="Invalid summarization text.",
                    error=text_validation_error,
                    metadata={
                        "user_id": context.user_id,
                        "workspace_id": context.workspace_id,
                        "request_id": context.request_id,
                    },
                )

            if self._requires_security_check(parsed_request):
                security_payload = self._request_security_approval(parsed_request)
                if require_security_approval:
                    return security_payload

            self._emit_agent_event(
                "memory_summarizer.started",
                {
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                    "input_type": parsed_request.input_type.value,
                    "style": parsed_request.style.value,
                },
            )

            normalized_text = self._normalize_text(
                parsed_request.text,
                preserve_code_blocks=parsed_request.preserve_code_blocks,
            )

            summary_data = self._summarize_normalized_text(parsed_request, normalized_text)
            memory_payload = self._prepare_memory_payload(
                request=parsed_request,
                summary_data=summary_data,
            )
            verification_payload = self._prepare_verification_payload(
                request=parsed_request,
                summary_data=summary_data,
            )

            elapsed_ms = round((time.time() - started) * 1000, 2)

            result_data = {
                "summary": asdict(summary_data),
                "memory_payload": memory_payload,
                "verification_payload": verification_payload,
            }

            self._log_audit_event(
                "memory_summary_created",
                {
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                    "source_id": parsed_request.source_id,
                    "project_id": parsed_request.project_id,
                    "client_id": parsed_request.client_id,
                    "input_chars": len(parsed_request.text),
                    "summary_chars": len(summary_data.summary),
                    "memory_candidate_count": len(summary_data.memory_candidates),
                    "elapsed_ms": elapsed_ms,
                },
            )

            self._emit_agent_event(
                "memory_summarizer.completed",
                {
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                    "elapsed_ms": elapsed_ms,
                    "memory_candidate_count": len(summary_data.memory_candidates),
                },
            )

            return self._safe_result(
                message="Memory summary created successfully.",
                data=result_data,
                metadata={
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                    "elapsed_ms": elapsed_ms,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to summarize memory input.",
                error=exc,
            )

    def summarize_text(
        self,
        text: str,
        *,
        user_id: str,
        workspace_id: str,
        title: Optional[str] = None,
        input_type: SummaryInputType = SummaryInputType.UNKNOWN,
        style: SummaryStyle = SummaryStyle.CLEAN_MEMORY,
        target_chars: Optional[int] = None,
        privacy_level: PrivacyLevel = PrivacyLevel.PRIVATE,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Convenience method for direct text summarization.
        """

        request = SummaryRequest(
            text=text,
            title=title,
            input_type=input_type,
            style=style,
            target_chars=target_chars,
            privacy_level=privacy_level,
            context=TaskContext(user_id=user_id, workspace_id=workspace_id),
            metadata=metadata or {},
        )
        return self.summarize(request)

    def summarize_chat(
        self,
        messages: Sequence[Union[str, Dict[str, Any]]],
        *,
        user_id: str,
        workspace_id: str,
        title: Optional[str] = None,
        session_id: Optional[str] = None,
        project_id: Optional[str] = None,
        client_id: Optional[str] = None,
        target_chars: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Summarize a chat transcript.

        messages can be:
            - list[str]
            - list[dict] with role/content/name/timestamp
        """

        text = self._messages_to_text(messages)

        request = SummaryRequest(
            text=text,
            title=title or "Chat Summary",
            input_type=SummaryInputType.CHAT,
            style=SummaryStyle.CLEAN_MEMORY,
            target_chars=target_chars,
            project_id=project_id,
            client_id=client_id,
            context=TaskContext(
                user_id=user_id,
                workspace_id=workspace_id,
                session_id=session_id,
                metadata=metadata or {},
            ),
            metadata=metadata or {},
        )
        return self.summarize(request)

    def summarize_document(
        self,
        document_text: str,
        *,
        user_id: str,
        workspace_id: str,
        title: Optional[str] = None,
        source_id: Optional[str] = None,
        project_id: Optional[str] = None,
        client_id: Optional[str] = None,
        target_chars: Optional[int] = None,
        privacy_level: PrivacyLevel = PrivacyLevel.PRIVATE,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Summarize a long document.
        """

        request = SummaryRequest(
            text=document_text,
            title=title or "Document Summary",
            source_id=source_id,
            project_id=project_id,
            client_id=client_id,
            input_type=SummaryInputType.DOCUMENT,
            style=SummaryStyle.DETAILED,
            target_chars=target_chars,
            privacy_level=privacy_level,
            context=TaskContext(
                user_id=user_id,
                workspace_id=workspace_id,
                metadata=metadata or {},
            ),
            metadata=metadata or {},
        )
        return self.summarize(request)

    def summarize_project_update(
        self,
        update_text: str,
        *,
        user_id: str,
        workspace_id: str,
        project_id: str,
        title: Optional[str] = None,
        target_chars: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Summarize project progress/update text.
        """

        request = SummaryRequest(
            text=update_text,
            title=title or "Project Update Summary",
            project_id=project_id,
            input_type=SummaryInputType.PROJECT_UPDATE,
            style=SummaryStyle.DECISION_LOG,
            target_chars=target_chars,
            privacy_level=PrivacyLevel.INTERNAL,
            context=TaskContext(
                user_id=user_id,
                workspace_id=workspace_id,
                metadata=metadata or {},
            ),
            metadata=metadata or {},
        )
        return self.summarize(request)

    def summarize_many(
        self,
        requests: Sequence[Union[SummaryRequest, Dict[str, Any]]],
        *,
        stop_on_error: bool = False,
    ) -> Dict[str, Any]:
        """
        Summarize multiple inputs.

        Each request must include its own SaaS context. This prevents accidental
        cross-user/workspace mixing.
        """

        results: List[Dict[str, Any]] = []
        errors: List[Dict[str, Any]] = []

        for index, request in enumerate(requests):
            result = self.summarize(request)
            results.append(result)

            if not result.get("success"):
                errors.append({"index": index, "error": result.get("error")})
                if stop_on_error:
                    break

        return self._safe_result(
            message="Batch summarization completed.",
            data={
                "results": results,
                "total": len(results),
                "success_count": sum(1 for item in results if item.get("success")),
                "error_count": len(errors),
                "errors": errors,
            },
            metadata={"batch": True},
        )

    def build_memory_payload_from_summary(
        self,
        summary_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Extract Memory Agent payload from a summarize() response.
        """

        try:
            if not summary_result.get("success"):
                return self._error_result(
                    message="Cannot build memory payload from failed summary result.",
                    error=summary_result.get("error") or "Summary result failed.",
                )

            data = summary_result.get("data") or {}
            memory_payload = data.get("memory_payload")

            if not memory_payload:
                return self._error_result(
                    message="Memory payload not found in summary result.",
                    error="Missing data.memory_payload.",
                )

            return self._safe_result(
                message="Memory payload extracted successfully.",
                data=memory_payload,
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to extract memory payload.",
                error=exc,
            )

    def health_check(self) -> Dict[str, Any]:
        """
        Lightweight health check for API/dashboard.
        """

        return self._safe_result(
            message="MemorySummarizer is healthy.",
            data={
                "agent": self.AGENT_ID,
                "module": self.MODULE,
                "version": self.VERSION,
                "file_path": self.FILE_PATH,
                "config": asdict(self.config),
            },
        )

    def get_registry_metadata(self) -> Dict[str, Any]:
        """
        Metadata for Agent Registry / Agent Loader.
        """

        return {
            "agent_name": self.AGENT_NAME,
            "agent_id": self.AGENT_ID,
            "module": self.MODULE,
            "file_path": self.FILE_PATH,
            "version": self.VERSION,
            "class_name": self.__class__.__name__,
            "capabilities": [
                "summarize_long_chat",
                "summarize_document",
                "summarize_project_update",
                "extract_key_points",
                "extract_decisions",
                "extract_action_items",
                "extract_memory_candidates",
                "prepare_memory_payload",
                "prepare_verification_payload",
                "saas_context_validation",
            ],
            "requires_user_context": True,
            "requires_workspace_context": True,
            "safe_to_import": True,
            "destructive_actions": False,
            "external_network_calls": False,
        }

    # ------------------------------------------------------------------
    # Internal Request Parsing
    # ------------------------------------------------------------------

    def _parse_summary_request(
        self,
        request: Union[SummaryRequest, Dict[str, Any]],
    ) -> SummaryRequest:
        if isinstance(request, SummaryRequest):
            return request

        if not isinstance(request, dict):
            raise TypeError("Summary request must be SummaryRequest or dict.")

        context_raw = request.get("context") or {}
        valid, context, error = self._validate_task_context(context_raw)
        if not valid or context is None:
            raise ValueError(error or "Invalid context.")

        return SummaryRequest(
            text=str(request.get("text") or ""),
            context=context,
            input_type=self._coerce_enum(
                SummaryInputType,
                request.get("input_type"),
                SummaryInputType.UNKNOWN,
            ),
            style=self._coerce_enum(
                SummaryStyle,
                request.get("style"),
                SummaryStyle.CLEAN_MEMORY,
            ),
            target_chars=request.get("target_chars"),
            title=request.get("title"),
            source_id=request.get("source_id"),
            project_id=request.get("project_id"),
            client_id=request.get("client_id"),
            tags=list(request.get("tags") or []),
            privacy_level=self._coerce_enum(
                PrivacyLevel,
                request.get("privacy_level"),
                PrivacyLevel.PRIVATE,
            ),
            importance_hint=self._coerce_optional_enum(
                MemoryImportance,
                request.get("importance_hint"),
            ),
            preserve_code_blocks=bool(request.get("preserve_code_blocks", True)),
            include_action_items=bool(request.get("include_action_items", True)),
            include_decisions=bool(request.get("include_decisions", True)),
            include_entities=bool(request.get("include_entities", True)),
            include_memory_candidates=bool(request.get("include_memory_candidates", True)),
            metadata=dict(request.get("metadata") or {}),
        )

    @staticmethod
    def _coerce_enum(
        enum_cls: Any,
        value: Any,
        default: Any,
    ) -> Any:
        if isinstance(value, enum_cls):
            return value
        if value is None:
            return default
        try:
            return enum_cls(str(value))
        except Exception:
            return default

    @staticmethod
    def _coerce_optional_enum(
        enum_cls: Any,
        value: Any,
    ) -> Optional[Any]:
        if value is None:
            return None
        if isinstance(value, enum_cls):
            return value
        try:
            return enum_cls(str(value))
        except Exception:
            return None

    def _validate_text(self, text: str) -> Optional[str]:
        if not isinstance(text, str):
            return "Text must be a string."
        if not text.strip():
            return "Text cannot be empty."
        if len(text) > self.config.max_input_chars:
            return (
                f"Text is too large. Maximum allowed characters: "
                f"{self.config.max_input_chars}."
            )
        return None

    # ------------------------------------------------------------------
    # Core Summarization Pipeline
    # ------------------------------------------------------------------

    def _summarize_normalized_text(
        self,
        request: SummaryRequest,
        normalized_text: str,
    ) -> SummaryResultData:
        chunks = self._chunk_text(normalized_text)

        chunk_summaries: List[str] = []
        for chunk in chunks:
            chunk_summaries.append(
                self._extractive_summary(
                    chunk,
                    target_chars=max(
                        self.config.min_target_chars,
                        min(
                            self.config.default_target_chars,
                            int((request.target_chars or self.config.default_target_chars) / max(len(chunks), 1)) + 500,
                        ),
                    ),
                    style=request.style,
                )
            )

        merged_text = "\n\n".join(chunk_summaries).strip()
        target_chars = self._normalize_target_chars(request.target_chars)

        final_summary = self._extractive_summary(
            merged_text or normalized_text,
            target_chars=target_chars,
            style=request.style,
        )

        key_points = self._extract_key_points(normalized_text, max_items=self.config.max_bullets)

        decisions = (
            self._extract_decisions(normalized_text, max_items=self.config.max_decisions)
            if request.include_decisions
            else []
        )

        action_items = (
            self._extract_action_items(normalized_text, max_items=self.config.max_action_items)
            if request.include_action_items
            else []
        )

        risks = self._extract_risks_or_blockers(normalized_text, max_items=20)

        entities = (
            self._extract_entities(normalized_text, max_items=self.config.max_entities)
            if request.include_entities
            else []
        )

        importance = self._infer_importance(
            text=normalized_text,
            request=request,
            decisions=decisions,
            action_items=action_items,
            risks=risks,
        )

        memory_candidates = (
            self._extract_memory_candidates(
                text=normalized_text,
                summary=final_summary,
                request=request,
                key_points=key_points,
                decisions=decisions,
                action_items=action_items,
                risks=risks,
                entities=entities,
                importance=importance,
            )
            if request.include_memory_candidates
            else []
        )

        compact_summary = self._make_compact_summary(
            final_summary,
            key_points=key_points,
            decisions=decisions,
            action_items=action_items,
        )

        title = self._make_title(request, normalized_text, compact_summary)
        source_hash = self._hash_text(normalized_text) if self.config.include_source_hash else None

        return SummaryResultData(
            title=title,
            summary=final_summary,
            compact_summary=compact_summary,
            key_points=key_points,
            decisions=decisions,
            action_items=action_items,
            risks_or_blockers=risks,
            entities=entities,
            memory_candidates=[asdict(candidate) for candidate in memory_candidates],
            source_hash=source_hash,
            input_type=request.input_type.value,
            style=request.style.value,
            privacy_level=request.privacy_level.value,
            importance=importance.value,
            token_estimate={
                "input_tokens_estimate": self._estimate_tokens(normalized_text),
                "summary_tokens_estimate": self._estimate_tokens(final_summary),
                "compact_summary_tokens_estimate": self._estimate_tokens(compact_summary),
            },
            metadata={
                "chunk_count": len(chunks),
                "input_chars": len(normalized_text),
                "summary_chars": len(final_summary),
                "compact_summary_chars": len(compact_summary),
                "generated_at": self._utc_now(),
                "summarizer_version": self.VERSION,
            },
        )

    def _extractive_summary(
        self,
        text: str,
        *,
        target_chars: int,
        style: SummaryStyle,
    ) -> str:
        """
        Deterministic extractive summarizer.

        Scores sentences by:
            - keyword importance
            - decision/action/risk signals
            - entity density
            - position
            - length quality

        This is intentionally provider-free and import-safe.
        """

        text = text.strip()
        if len(text) <= target_chars:
            return text

        sentences = self._split_sentences(text)
        if not sentences:
            return text[:target_chars].strip()

        keyword_freq = self._keyword_frequency(text)
        scored: List[Tuple[float, int, str]] = []

        for idx, sentence in enumerate(sentences):
            score = self._score_sentence(
                sentence=sentence,
                index=idx,
                total=len(sentences),
                keyword_freq=keyword_freq,
                style=style,
            )
            scored.append((score, idx, sentence))

        selected: List[Tuple[int, str]] = []
        current_chars = 0

        for _, idx, sentence in sorted(scored, key=lambda item: item[0], reverse=True):
            sentence = sentence.strip()
            if not sentence:
                continue
            if current_chars + len(sentence) > target_chars and selected:
                continue

            selected.append((idx, sentence))
            current_chars += len(sentence) + 1

            if current_chars >= target_chars:
                break

        ordered = [sentence for _, sentence in sorted(selected, key=lambda item: item[0])]
        summary = " ".join(ordered).strip()

        if len(summary) > target_chars:
            summary = summary[:target_chars].rsplit(" ", 1)[0].strip() + "..."

        return self._format_summary_by_style(summary, style)

    def _score_sentence(
        self,
        *,
        sentence: str,
        index: int,
        total: int,
        keyword_freq: Dict[str, int],
        style: SummaryStyle,
    ) -> float:
        lower = sentence.lower()
        words = self._words(lower)
        if not words:
            return 0.0

        score = 0.0

        for word in words:
            score += min(keyword_freq.get(word, 0), 8) * 0.25

        if any(marker in lower for marker in self._decision_markers()):
            score += 6.0

        if any(marker in lower for marker in self._action_markers()):
            score += 5.5

        if any(marker in lower for marker in self._risk_markers()):
            score += 5.0

        if any(marker in lower for marker in self._memory_markers()):
            score += 4.5

        if re.search(r"\b(user_id|workspace_id|security|verification|memory|agent|saas|registry|router|permission)\b", lower):
            score += 3.0

        if re.search(r"\b\d+(\.\d+)?%|\b\d{4}-\d{2}-\d{2}\b|\b\d+\s*(files?|agents?|modules?|users?|workspaces?)\b", lower):
            score += 2.5

        entity_count = len(re.findall(r"\b[A-Z][a-zA-Z0-9_/-]{2,}\b", sentence))
        score += min(entity_count, 6) * 0.4

        length = len(sentence)
        if 60 <= length <= 280:
            score += 2.0
        elif length < 25:
            score -= 2.0
        elif length > 600:
            score -= 1.5

        if index < max(3, total * 0.08):
            score += 1.8
        if index > total * 0.92:
            score += 1.2

        if style == SummaryStyle.TECHNICAL:
            if re.search(r"\b(class|function|method|api|schema|json|python|fastapi|database|import|module)\b", lower):
                score += 3.0

        if style == SummaryStyle.DECISION_LOG:
            if any(marker in lower for marker in self._decision_markers()):
                score += 3.0

        if style == SummaryStyle.ACTION_ITEMS:
            if any(marker in lower for marker in self._action_markers()):
                score += 4.0

        return score

    def _format_summary_by_style(self, summary: str, style: SummaryStyle) -> str:
        summary = self._dedupe_lines(summary)

        if style == SummaryStyle.COMPACT:
            return summary

        if style == SummaryStyle.EXECUTIVE:
            return self._ensure_clean_paragraphs(summary)

        if style == SummaryStyle.TECHNICAL:
            return self._ensure_clean_paragraphs(summary)

        if style == SummaryStyle.DECISION_LOG:
            return self._ensure_clean_paragraphs(summary)

        if style == SummaryStyle.ACTION_ITEMS:
            return self._ensure_clean_paragraphs(summary)

        if style == SummaryStyle.DETAILED:
            return self._ensure_clean_paragraphs(summary)

        return self._ensure_clean_paragraphs(summary)

    # ------------------------------------------------------------------
    # Extractors
    # ------------------------------------------------------------------

    def _extract_key_points(self, text: str, *, max_items: int) -> List[str]:
        sentences = self._split_sentences(text)
        keyword_freq = self._keyword_frequency(text)

        scored = [
            (
                self._score_sentence(
                    sentence=sentence,
                    index=index,
                    total=len(sentences),
                    keyword_freq=keyword_freq,
                    style=SummaryStyle.CLEAN_MEMORY,
                ),
                sentence,
            )
            for index, sentence in enumerate(sentences)
        ]

        selected = [
            self._clean_bullet(sentence)
            for _, sentence in sorted(scored, key=lambda item: item[0], reverse=True)
            if len(sentence.strip()) >= 30
        ]

        return self._unique_keep_order(selected, max_items=max_items)

    def _extract_decisions(self, text: str, *, max_items: int) -> List[str]:
        return self._extract_by_markers(
            text,
            markers=self._decision_markers(),
            max_items=max_items,
            fallback_patterns=[
                r"\bdecided\s+to\b.+",
                r"\bconfirmed\s+that\b.+",
                r"\bagreed\s+to\b.+",
                r"\bfinal\s+decision\b.+",
                r"\bapproved\s+.+",
            ],
        )

    def _extract_action_items(self, text: str, *, max_items: int) -> List[str]:
        return self._extract_by_markers(
            text,
            markers=self._action_markers(),
            max_items=max_items,
            fallback_patterns=[
                r"\bneed\s+to\b.+",
                r"\bmust\s+.+",
                r"\bshould\s+.+",
                r"\bnext\s+.+",
                r"\bcreate\s+.+",
                r"\bfix\s+.+",
                r"\bimplement\s+.+",
            ],
        )

    def _extract_risks_or_blockers(self, text: str, *, max_items: int) -> List[str]:
        return self._extract_by_markers(
            text,
            markers=self._risk_markers(),
            max_items=max_items,
            fallback_patterns=[
                r"\bblocked\b.+",
                r"\berror\b.+",
                r"\bbug\b.+",
                r"\brisk\b.+",
                r"\bissue\b.+",
                r"\bfailed\b.+",
                r"\bmissing\b.+",
            ],
        )

    def _extract_by_markers(
        self,
        text: str,
        *,
        markers: Sequence[str],
        max_items: int,
        fallback_patterns: Sequence[str],
    ) -> List[str]:
        sentences = self._split_sentences(text)
        matches: List[str] = []

        for sentence in sentences:
            lower = sentence.lower()
            if any(marker in lower for marker in markers):
                matches.append(self._clean_bullet(sentence))

        if len(matches) < max_items:
            for pattern in fallback_patterns:
                for match in re.findall(pattern, text, flags=re.IGNORECASE):
                    matches.append(self._clean_bullet(match))

        return self._unique_keep_order(matches, max_items=max_items)

    def _extract_entities(self, text: str, *, max_items: int) -> List[str]:
        """
        Lightweight entity extraction.

        Avoids external NLP dependencies. Good enough for project names,
        modules, file paths, classes, services, organizations, and technical
        terms.
        """

        candidates: List[str] = []

        path_patterns = re.findall(
            r"\b(?:agents|apps|services|modules|backend|frontend|api|core|utils)/[A-Za-z0-9_./-]+\b",
            text,
        )
        candidates.extend(path_patterns)

        class_patterns = re.findall(r"\b[A-Z][A-Za-z0-9]+(?:Agent|Manager|Router|Engine|Summarizer|Cleaner|Guard|Service)\b", text)
        candidates.extend(class_patterns)

        quoted = re.findall(r"['\"]([^'\"]{3,80})['\"]", text)
        candidates.extend(item for item in quoted if not item.strip().startswith("{"))

        title_entities = re.findall(r"\b[A-Z][a-zA-Z0-9]*(?:\s+[A-Z][a-zA-Z0-9]*){0,4}\b", text)
        candidates.extend(title_entities)

        technical = re.findall(
            r"\b(?:user_id|workspace_id|BaseAgent|Master Agent|Security Agent|Verification Agent|Memory Agent|FastAPI|Dashboard|Registry|Agent Loader|Agent Router)\b",
            text,
            flags=re.IGNORECASE,
        )
        candidates.extend(technical)

        cleaned = []
        for item in candidates:
            value = re.sub(r"\s+", " ", item).strip(" -_:;,.")
            if len(value) < 3 or len(value) > 100:
                continue
            if value.lower() in self._stop_phrases():
                continue
            cleaned.append(value)

        return self._unique_keep_order(cleaned, max_items=max_items)

    def _extract_memory_candidates(
        self,
        *,
        text: str,
        summary: str,
        request: SummaryRequest,
        key_points: List[str],
        decisions: List[str],
        action_items: List[str],
        risks: List[str],
        entities: List[str],
        importance: MemoryImportance,
    ) -> List[MemoryCandidate]:
        candidates: List[MemoryCandidate] = []

        if summary:
            candidates.append(
                MemoryCandidate(
                    content=summary[:3000],
                    category="summary",
                    importance=importance,
                    privacy_level=request.privacy_level,
                    confidence=0.88,
                    reason="Primary compressed summary of long input.",
                    tags=self._candidate_tags(request, ["summary"]),
                )
            )

        for decision in decisions[:10]:
            candidates.append(
                MemoryCandidate(
                    content=decision,
                    category="decision",
                    importance=self._raise_importance(importance, minimum=MemoryImportance.HIGH),
                    privacy_level=request.privacy_level,
                    confidence=0.86,
                    reason="Detected decision marker in source text.",
                    tags=self._candidate_tags(request, ["decision"]),
                )
            )

        for action in action_items[:10]:
            candidates.append(
                MemoryCandidate(
                    content=action,
                    category="action_item",
                    importance=self._raise_importance(importance, minimum=MemoryImportance.MEDIUM),
                    privacy_level=request.privacy_level,
                    confidence=0.82,
                    reason="Detected action/next-step marker in source text.",
                    tags=self._candidate_tags(request, ["action_item"]),
                )
            )

        for risk in risks[:8]:
            candidates.append(
                MemoryCandidate(
                    content=risk,
                    category="risk_or_blocker",
                    importance=self._raise_importance(importance, minimum=MemoryImportance.HIGH),
                    privacy_level=request.privacy_level,
                    confidence=0.8,
                    reason="Detected risk/blocker/error marker in source text.",
                    tags=self._candidate_tags(request, ["risk"]),
                )
            )

        preference_candidates = self._extract_preferences(text)
        for pref in preference_candidates[:8]:
            candidates.append(
                MemoryCandidate(
                    content=pref,
                    category="preference",
                    importance=MemoryImportance.HIGH,
                    privacy_level=request.privacy_level,
                    confidence=0.84,
                    reason="Detected user preference or persistent instruction.",
                    tags=self._candidate_tags(request, ["preference"]),
                )
            )

        project_candidates = self._extract_project_rules(text)
        for rule in project_candidates[:8]:
            candidates.append(
                MemoryCandidate(
                    content=rule,
                    category="project_rule",
                    importance=MemoryImportance.HIGH,
                    privacy_level=request.privacy_level,
                    confidence=0.83,
                    reason="Detected project rule or architecture constraint.",
                    tags=self._candidate_tags(request, ["project_rule"]),
                )
            )

        for point in key_points[:8]:
            if self._looks_memory_worthy(point):
                candidates.append(
                    MemoryCandidate(
                        content=point,
                        category="key_fact",
                        importance=importance,
                        privacy_level=request.privacy_level,
                        confidence=0.72,
                        reason="High-scoring key point that appears memory-worthy.",
                        tags=self._candidate_tags(request, ["key_fact"]),
                    )
                )

        deduped: List[MemoryCandidate] = []
        seen: set[str] = set()

        for candidate in candidates:
            fingerprint = self._fingerprint(candidate.content)
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            deduped.append(candidate)

            if len(deduped) >= self.config.max_memory_candidates:
                break

        return deduped

    def _extract_preferences(self, text: str) -> List[str]:
        patterns = [
            r"\buser prefers\b.+",
            r"\buser wants\b.+",
            r"\buser requires\b.+",
            r"\bfrom now on\b.+",
            r"\bin future\b.+",
            r"\balways\b.+",
            r"\bnever\b.+",
            r"\bmust include\b.+",
            r"\bmust not\b.+",
            r"\bdo not\b.+",
        ]
        matches: List[str] = []

        for sentence in self._split_sentences(text):
            lower = sentence.lower()
            if any(re.search(pattern, lower, flags=re.IGNORECASE) for pattern in patterns):
                matches.append(self._clean_bullet(sentence))

        return self._unique_keep_order(matches, max_items=20)

    def _extract_project_rules(self, text: str) -> List[str]:
        markers = [
            "architecture",
            "compatibility",
            "baseagent",
            "master agent",
            "security agent",
            "verification agent",
            "memory agent",
            "user_id",
            "workspace_id",
            "never mix",
            "safe import",
            "structured result",
            "audit",
            "registry",
            "router",
        ]

        matches: List[str] = []
        for sentence in self._split_sentences(text):
            lower = sentence.lower()
            marker_count = sum(1 for marker in markers if marker in lower)
            if marker_count >= 1 and len(sentence) > 40:
                matches.append(self._clean_bullet(sentence))

        return self._unique_keep_order(matches, max_items=20)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _messages_to_text(self, messages: Sequence[Union[str, Dict[str, Any]]]) -> str:
        lines: List[str] = []

        for item in messages:
            if isinstance(item, str):
                lines.append(item.strip())
                continue

            if isinstance(item, dict):
                role = str(item.get("role") or item.get("sender") or "unknown").strip()
                name = str(item.get("name") or "").strip()
                content = str(item.get("content") or item.get("text") or item.get("message") or "").strip()
                timestamp = str(item.get("timestamp") or item.get("created_at") or "").strip()

                prefix_parts = [part for part in [timestamp, role, name] if part]
                prefix = " | ".join(prefix_parts)
                if prefix:
                    lines.append(f"{prefix}: {content}")
                else:
                    lines.append(content)

        return "\n".join(line for line in lines if line)

    def _normalize_text(self, text: str, *, preserve_code_blocks: bool) -> str:
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        text = re.sub(r"\n{4,}", "\n\n\n", text)

        if preserve_code_blocks:
            return text.strip()

        text = re.sub(r"```.*?```", "[code block omitted]", text, flags=re.DOTALL)
        return text.strip()

    def _chunk_text(self, text: str) -> List[str]:
        if len(text) <= self.config.chunk_size_chars:
            return [text]

        chunks: List[str] = []
        start = 0
        text_len = len(text)

        while start < text_len:
            end = min(start + self.config.chunk_size_chars, text_len)

            if end < text_len:
                boundary = text.rfind("\n\n", start, end)
                if boundary == -1 or boundary <= start + self.config.chunk_size_chars // 2:
                    boundary = text.rfind(". ", start, end)
                if boundary != -1 and boundary > start:
                    end = boundary + 1

            chunk = text[start:end].strip()
            if chunk:
                chunks.append(chunk)

            if end >= text_len:
                break

            start = max(end - self.config.chunk_overlap_chars, start + 1)

        return chunks

    def _normalize_target_chars(self, target_chars: Optional[int]) -> int:
        if target_chars is None:
            return self.config.default_target_chars

        try:
            value = int(target_chars)
        except Exception:
            return self.config.default_target_chars

        return max(self.config.min_target_chars, min(value, self.config.max_target_chars))

    def _split_sentences(self, text: str) -> List[str]:
        lines = []
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            if line.startswith(("-", "*", "•")):
                lines.append(line)
                continue

            parts = re.split(r"(?<=[.!?])\s+(?=[A-Z0-9])", line)
            lines.extend(part.strip() for part in parts if part.strip())

        cleaned = []
        for sentence in lines:
            sentence = re.sub(r"\s+", " ", sentence).strip()
            if sentence:
                cleaned.append(sentence)

        return cleaned

    def _keyword_frequency(self, text: str) -> Dict[str, int]:
        words = [
            word
            for word in self._words(text.lower())
            if len(word) >= 4 and word not in self._stop_words()
        ]

        freq: Dict[str, int] = {}
        for word in words:
            freq[word] = freq.get(word, 0) + 1
        return freq

    @staticmethod
    def _words(text: str) -> List[str]:
        return re.findall(r"\b[a-zA-Z][a-zA-Z0-9_/-]*\b", text)

    def _make_compact_summary(
        self,
        summary: str,
        *,
        key_points: List[str],
        decisions: List[str],
        action_items: List[str],
    ) -> str:
        lines: List[str] = []

        first_sentence = self._split_sentences(summary)
        if first_sentence:
            lines.append(first_sentence[0][:500].strip())

        if key_points:
            lines.append(f"Key: {key_points[0][:350]}")
        if decisions:
            lines.append(f"Decision: {decisions[0][:350]}")
        if action_items:
            lines.append(f"Next: {action_items[0][:350]}")

        compact = " ".join(lines).strip()
        if not compact:
            compact = summary[:700].strip()

        if len(compact) > 900:
            compact = compact[:900].rsplit(" ", 1)[0].strip() + "..."

        return compact

    def _make_title(
        self,
        request: SummaryRequest,
        text: str,
        compact_summary: str,
    ) -> str:
        if request.title and request.title.strip():
            return request.title.strip()[:160]

        if request.project_id:
            return f"Project Memory Summary - {request.project_id}"

        if request.client_id:
            return f"Client Memory Summary - {request.client_id}"

        first_line = next((line.strip() for line in text.splitlines() if line.strip()), "")
        if first_line:
            cleaned = re.sub(r"[^a-zA-Z0-9 _./:-]", "", first_line)
            return cleaned[:120] or "Memory Summary"

        if compact_summary:
            return compact_summary[:100].strip()

        return "Memory Summary"

    def _infer_importance(
        self,
        *,
        text: str,
        request: SummaryRequest,
        decisions: List[str],
        action_items: List[str],
        risks: List[str],
    ) -> MemoryImportance:
        if request.importance_hint:
            return request.importance_hint

        lower = text.lower()
        score = 0

        if decisions:
            score += 3
        if action_items:
            score += 2
        if risks:
            score += 3

        high_markers = [
            "critical",
            "must",
            "never",
            "always",
            "required",
            "security",
            "permission",
            "user_id",
            "workspace_id",
            "production",
            "architecture",
            "client",
            "project",
            "billing",
            "subscription",
        ]

        score += sum(1 for marker in high_markers if marker in lower)

        if request.input_type in {
            SummaryInputType.PROJECT_UPDATE,
            SummaryInputType.TASK_HISTORY,
            SummaryInputType.AGENT_LOG,
        }:
            score += 2

        if score >= 9:
            return MemoryImportance.CRITICAL
        if score >= 5:
            return MemoryImportance.HIGH
        if score >= 2:
            return MemoryImportance.MEDIUM
        return MemoryImportance.LOW

    def _raise_importance(
        self,
        importance: MemoryImportance,
        *,
        minimum: MemoryImportance,
    ) -> MemoryImportance:
        order = {
            MemoryImportance.LOW: 1,
            MemoryImportance.MEDIUM: 2,
            MemoryImportance.HIGH: 3,
            MemoryImportance.CRITICAL: 4,
        }
        return importance if order[importance] >= order[minimum] else minimum

    def _candidate_tags(self, request: SummaryRequest, extra: List[str]) -> List[str]:
        tags = list(request.tags or [])
        tags.extend(extra)

        if request.input_type:
            tags.append(request.input_type.value)
        if request.project_id:
            tags.append(f"project:{request.project_id}")
        if request.client_id:
            tags.append(f"client:{request.client_id}")

        return self._unique_keep_order(tags, max_items=20)

    def _looks_memory_worthy(self, text: str) -> bool:
        lower = text.lower()
        markers = [
            "user wants",
            "user prefers",
            "must",
            "required",
            "architecture",
            "project",
            "client",
            "decision",
            "important",
            "remember",
            "from now on",
            "always",
            "never",
            "user_id",
            "workspace_id",
            "security",
            "verification",
            "agent",
        ]
        return any(marker in lower for marker in markers)

    @staticmethod
    def _clean_bullet(text: str) -> str:
        text = re.sub(r"\s+", " ", text).strip()
        text = text.strip("-*• \t")
        return text

    @staticmethod
    def _unique_keep_order(items: Iterable[str], *, max_items: int) -> List[str]:
        seen: set[str] = set()
        output: List[str] = []

        for item in items:
            cleaned = re.sub(r"\s+", " ", str(item)).strip()
            if not cleaned:
                continue

            key = cleaned.lower()
            if key in seen:
                continue

            seen.add(key)
            output.append(cleaned)

            if len(output) >= max_items:
                break

        return output

    @staticmethod
    def _dedupe_lines(text: str) -> str:
        lines = [line.strip() for line in text.splitlines()]
        seen: set[str] = set()
        output: List[str] = []

        for line in lines:
            if not line:
                if output and output[-1]:
                    output.append("")
                continue

            key = line.lower()
            if key in seen:
                continue

            seen.add(key)
            output.append(line)

        return "\n".join(output).strip()

    @staticmethod
    def _ensure_clean_paragraphs(text: str) -> str:
        text = re.sub(r"[ \t]+", " ", text)
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip()

    @staticmethod
    def _hash_text(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    @staticmethod
    def _fingerprint(text: str) -> str:
        normalized = re.sub(r"\W+", "", text.lower())[:500]
        return hashlib.sha1(normalized.encode("utf-8")).hexdigest()

    @staticmethod
    def _estimate_tokens(text: str) -> int:
        return max(1, int(len(text) / 4))

    @staticmethod
    def _utc_now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _stop_words() -> set[str]:
        return {
            "this",
            "that",
            "with",
            "from",
            "have",
            "will",
            "should",
            "could",
            "would",
            "there",
            "their",
            "about",
            "after",
            "before",
            "where",
            "which",
            "when",
            "what",
            "your",
            "they",
            "them",
            "then",
            "than",
            "into",
            "only",
            "also",
            "more",
            "some",
            "such",
            "been",
            "being",
            "make",
            "made",
            "using",
            "used",
            "file",
            "full",
            "final",
        }

    @staticmethod
    def _stop_phrases() -> set[str]:
        return {
            "the",
            "and",
            "for",
            "with",
            "this",
            "that",
            "full final file",
            "file complete",
        }

    @staticmethod
    def _decision_markers() -> Tuple[str, ...]:
        return (
            "decided",
            "decision",
            "approved",
            "confirmed",
            "agreed",
            "finalized",
            "chosen",
            "selected",
            "locked",
            "accepted",
            "rejected",
            "resolved",
        )

    @staticmethod
    def _action_markers() -> Tuple[str, ...]:
        return (
            "todo",
            "to do",
            "next step",
            "need to",
            "needs to",
            "must",
            "should",
            "implement",
            "create",
            "build",
            "fix",
            "update",
            "generate",
            "test",
            "review",
            "add",
            "remove",
            "replace",
            "continue",
        )

    @staticmethod
    def _risk_markers() -> Tuple[str, ...]:
        return (
            "risk",
            "blocker",
            "blocked",
            "issue",
            "problem",
            "bug",
            "error",
            "failed",
            "failure",
            "missing",
            "conflict",
            "unsafe",
            "leak",
            "sensitive",
            "permission",
            "security",
        )

    @staticmethod
    def _memory_markers() -> Tuple[str, ...]:
        return (
            "remember",
            "memory",
            "preference",
            "project rule",
            "from now on",
            "always",
            "never",
            "user wants",
            "user prefers",
            "user requires",
            "important",
            "must support",
            "do not",
        )


# ---------------------------------------------------------------------------
# Optional module-level convenience functions
# ---------------------------------------------------------------------------

def create_memory_summarizer(config: Optional[SummaryConfig] = None) -> MemorySummarizer:
    """
    Factory helper for Agent Loader / Registry.
    """
    return MemorySummarizer(config=config)


def get_agent_metadata() -> Dict[str, Any]:
    """
    Module-level metadata helper for registries that inspect files directly.
    """
    return MemorySummarizer().get_registry_metadata()


__all__ = [
    "MemorySummarizer",
    "SummaryConfig",
    "SummaryRequest",
    "SummaryResultData",
    "TaskContext",
    "MemoryCandidate",
    "SummaryInputType",
    "SummaryStyle",
    "MemoryImportance",
    "PrivacyLevel",
    "create_memory_summarizer",
    "get_agent_metadata",
]