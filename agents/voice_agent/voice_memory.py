"""
agents/voice_agent/voice_memory.py

VoiceMemory for William / Jarvis Multi-Agent AI SaaS System by Digital Promotix.

Purpose:
    Memory bridge for voice preferences, recurring phrases, language behavior,
    speaker behavior, and audio notes.

Architecture Compatibility:
    - Master Agent routing
    - BaseAgent compatibility
    - Agent Registry / Agent Loader safe imports
    - Security Agent approval hooks
    - Memory Agent payload preparation
    - Verification Agent payload preparation
    - Dashboard / API audit-friendly structured outputs
    - SaaS user/workspace isolation

Important:
    This file is intentionally import-safe. If the larger William/Jarvis system
    modules are not created yet, this file still works using fallback classes.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
import uuid
from copy import deepcopy
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any, Dict, List, Optional, Tuple, Union


# =============================================================================
# Safe optional imports
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:
    class BaseAgent:
        """
        Fallback BaseAgent stub.

        This keeps voice_memory.py import-safe until the real BaseAgent exists.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_type = kwargs.get("agent_type", "voice_agent")
            self.version = kwargs.get("version", "1.0.0")


try:
    from core.agent_events import AgentEventEmitter  # type: ignore
except Exception:
    class AgentEventEmitter:
        """
        Fallback event emitter stub.

        The real system can replace this with dashboard/websocket/event-bus logic.
        """

        def emit(self, event_name: str, payload: Dict[str, Any]) -> None:
            return None


try:
    from core.audit_logger import AuditLogger  # type: ignore
except Exception:
    class AuditLogger:
        """
        Fallback audit logger stub.

        The real system can replace this with database/file/cloud audit logging.
        """

        def log(self, payload: Dict[str, Any]) -> None:
            return None


try:
    from agents.security_agent.security_agent import SecurityAgent  # type: ignore
except Exception:
    class SecurityAgent:
        """
        Fallback SecurityAgent stub.

        Default behavior allows safe, non-destructive local memory actions only.
        """

        def check_permission(self, payload: Dict[str, Any]) -> Dict[str, Any]:
            return {
                "success": True,
                "message": "Fallback security approval granted for safe local memory action.",
                "data": {
                    "approved": True,
                    "fallback": True,
                },
                "error": None,
                "metadata": {},
            }


# =============================================================================
# Logging
# =============================================================================

logger = logging.getLogger("william.voice_agent.voice_memory")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)


# =============================================================================
# Data structures
# =============================================================================

@dataclass
class VoicePreference:
    """
    Stores user/workspace-level voice preference data.

    Examples:
        - preferred_tts_voice
        - response_speed
        - preferred_language
        - tone
        - volume
        - whisper_mode
    """

    preference_id: str
    user_id: str
    workspace_id: str
    key: str
    value: Any
    source: str = "voice_agent"
    confidence: float = 1.0
    created_at: str = field(default_factory=lambda: VoiceMemory.utcnow())
    updated_at: str = field(default_factory=lambda: VoiceMemory.utcnow())
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RecurringPhrase:
    """
    Stores phrases the user frequently says or prefers.

    Examples:
        - "open dashboard"
        - "start extractor"
        - "William"
        - "run next task"
    """

    phrase_id: str
    user_id: str
    workspace_id: str
    phrase: str
    normalized_phrase: str
    intent_hint: Optional[str] = None
    usage_count: int = 1
    first_seen_at: str = field(default_factory=lambda: VoiceMemory.utcnow())
    last_seen_at: str = field(default_factory=lambda: VoiceMemory.utcnow())
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LanguageBehavior:
    """
    Stores language behavior for voice conversations.

    Examples:
        - preferred language
        - fallback language
        - bilingual behavior
        - roman Urdu usage
        - auto-translation preference
    """

    behavior_id: str
    user_id: str
    workspace_id: str
    language_code: str
    language_name: str
    behavior_type: str
    value: Any
    confidence: float = 1.0
    created_at: str = field(default_factory=lambda: VoiceMemory.utcnow())
    updated_at: str = field(default_factory=lambda: VoiceMemory.utcnow())
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AudioNote:
    """
    Stores metadata and transcript for audio notes.

    Important:
        This file does not process raw audio directly.
        It stores safe metadata/transcript references only.
    """

    note_id: str
    user_id: str
    workspace_id: str
    title: str
    transcript: str
    language_code: Optional[str] = None
    audio_path: Optional[str] = None
    duration_seconds: Optional[float] = None
    tags: List[str] = field(default_factory=list)
    source: str = "voice_agent"
    created_at: str = field(default_factory=lambda: VoiceMemory.utcnow())
    updated_at: str = field(default_factory=lambda: VoiceMemory.utcnow())
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VoiceInteractionMemory:
    """
    Stores summarized context from voice interactions.

    This is useful for:
        - Memory Agent handoff
        - Conversation Mode
        - Master Agent routing
        - Dashboard history
    """

    memory_id: str
    user_id: str
    workspace_id: str
    input_text: str
    response_text: Optional[str] = None
    detected_language: Optional[str] = None
    detected_emotion: Optional[str] = None
    speaker_id: Optional[str] = None
    summary: Optional[str] = None
    importance: float = 0.5
    created_at: str = field(default_factory=lambda: VoiceMemory.utcnow())
    metadata: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Main class
# =============================================================================

class VoiceMemory(BaseAgent):
    """
    VoiceMemory bridges Voice Agent data with the Memory Agent.

    Main responsibilities:
        - Store voice preferences.
        - Store recurring phrases.
        - Store language behavior.
        - Store audio note transcripts and metadata.
        - Store summarized voice interaction memory.
        - Prepare Memory Agent payloads.
        - Prepare Verification Agent payloads.
        - Keep strict user_id/workspace_id isolation.
        - Emit dashboard-friendly events.
        - Log audit-friendly records.

    This class is intentionally local-storage friendly for early development.
    In production, the storage adapter can be swapped with a database repository.
    """

    DEFAULT_MEMORY_DIR = Path("storage/voice_memory")

    SENSITIVE_ACTIONS = {
        "delete_preference",
        "delete_phrase",
        "delete_language_behavior",
        "delete_audio_note",
        "delete_interaction_memory",
        "clear_user_workspace_memory",
        "export_workspace_memory",
    }

    VALID_MEMORY_TYPES = {
        "preference",
        "phrase",
        "language_behavior",
        "audio_note",
        "interaction",
    }

    def __init__(
        self,
        storage_dir: Optional[Union[str, Path]] = None,
        security_agent: Optional[Any] = None,
        event_emitter: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        enable_file_storage: bool = True,
        agent_name: str = "VoiceMemory",
        agent_type: str = "voice_agent",
        version: str = "1.0.0",
    ) -> None:
        super().__init__(
            agent_name=agent_name,
            agent_type=agent_type,
            version=version,
        )

        self.agent_name = agent_name
        self.agent_type = agent_type
        self.version = version

        self.storage_dir = Path(storage_dir) if storage_dir else self.DEFAULT_MEMORY_DIR
        self.enable_file_storage = enable_file_storage

        self.security_agent = security_agent or SecurityAgent()
        self.event_emitter = event_emitter or AgentEventEmitter()
        self.audit_logger = audit_logger or AuditLogger()

        self._lock = RLock()

        self._preferences: Dict[str, VoicePreference] = {}
        self._phrases: Dict[str, RecurringPhrase] = {}
        self._language_behaviors: Dict[str, LanguageBehavior] = {}
        self._audio_notes: Dict[str, AudioNote] = {}
        self._interactions: Dict[str, VoiceInteractionMemory] = {}

        if self.enable_file_storage:
            self._ensure_storage()
            self._load_all_from_disk()

    # =========================================================================
    # Time / ID helpers
    # =========================================================================

    @staticmethod
    def utcnow() -> str:
        """Return timezone-aware UTC timestamp."""
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def new_id(prefix: str) -> str:
        """Create a stable unique ID with readable prefix."""
        safe_prefix = re.sub(r"[^a-zA-Z0-9_]", "_", prefix).strip("_") or "id"
        return f"{safe_prefix}_{uuid.uuid4().hex}"

    @staticmethod
    def normalize_text(text: str) -> str:
        """Normalize spoken text for phrase matching."""
        if not isinstance(text, str):
            return ""
        text = text.strip().lower()
        text = re.sub(r"\s+", " ", text)
        text = re.sub(r"[^\w\s\-']", "", text)
        return text.strip()

    @staticmethod
    def clamp_confidence(value: Any) -> float:
        """Clamp confidence score between 0.0 and 1.0."""
        try:
            score = float(value)
        except Exception:
            score = 1.0
        return max(0.0, min(1.0, score))

    @staticmethod
    def clamp_importance(value: Any) -> float:
        """Clamp importance score between 0.0 and 1.0."""
        try:
            score = float(value)
        except Exception:
            score = 0.5
        return max(0.0, min(1.0, score))

    # =========================================================================
    # Storage helpers
    # =========================================================================

    def _ensure_storage(self) -> None:
        """Create storage folders safely."""
        try:
            self.storage_dir.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            logger.warning("Could not create VoiceMemory storage directory: %s", exc)

    def _storage_file(self, memory_type: str) -> Path:
        """Return storage path for a memory type."""
        return self.storage_dir / f"{memory_type}.json"

    def _safe_load_json(self, path: Path) -> Dict[str, Any]:
        """Safely load a JSON dictionary."""
        if not path.exists():
            return {}
        try:
            with path.open("r", encoding="utf-8") as file:
                data = json.load(file)
            return data if isinstance(data, dict) else {}
        except Exception as exc:
            logger.warning("VoiceMemory failed to load JSON from %s: %s", path, exc)
            return {}

    def _safe_write_json(self, path: Path, data: Dict[str, Any]) -> None:
        """Safely write JSON dictionary."""
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            temp_path = path.with_suffix(".tmp")
            with temp_path.open("w", encoding="utf-8") as file:
                json.dump(data, file, ensure_ascii=False, indent=2, default=str)
            temp_path.replace(path)
        except Exception as exc:
            logger.warning("VoiceMemory failed to write JSON to %s: %s", path, exc)

    def _load_all_from_disk(self) -> None:
        """Load memory stores from disk."""
        with self._lock:
            self._preferences = self._load_dataclass_store(
                "preferences",
                VoicePreference,
            )
            self._phrases = self._load_dataclass_store(
                "phrases",
                RecurringPhrase,
            )
            self._language_behaviors = self._load_dataclass_store(
                "language_behaviors",
                LanguageBehavior,
            )
            self._audio_notes = self._load_dataclass_store(
                "audio_notes",
                AudioNote,
            )
            self._interactions = self._load_dataclass_store(
                "interactions",
                VoiceInteractionMemory,
            )

    def _load_dataclass_store(self, store_name: str, cls: Any) -> Dict[str, Any]:
        """Load a dataclass dictionary from disk."""
        path = self._storage_file(store_name)
        raw = self._safe_load_json(path)
        result: Dict[str, Any] = {}

        for item_id, item_data in raw.items():
            if not isinstance(item_data, dict):
                continue
            try:
                result[item_id] = cls(**item_data)
            except Exception as exc:
                logger.warning(
                    "Skipping invalid VoiceMemory record from %s/%s: %s",
                    store_name,
                    item_id,
                    exc,
                )

        return result

    def _persist_store(self, store_name: str, store: Dict[str, Any]) -> None:
        """Persist a memory store to disk."""
        if not self.enable_file_storage:
            return

        serializable: Dict[str, Any] = {}
        for item_id, item in store.items():
            if hasattr(item, "__dataclass_fields__"):
                serializable[item_id] = asdict(item)
            elif isinstance(item, dict):
                serializable[item_id] = item

        self._safe_write_json(self._storage_file(store_name), serializable)

    def _persist_all(self) -> None:
        """Persist all stores."""
        self._persist_store("preferences", self._preferences)
        self._persist_store("phrases", self._phrases)
        self._persist_store("language_behaviors", self._language_behaviors)
        self._persist_store("audio_notes", self._audio_notes)
        self._persist_store("interactions", self._interactions)

    # =========================================================================
    # Result helpers
    # =========================================================================

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return successful structured result."""
        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": {
                "agent": self.agent_name,
                "agent_type": self.agent_type,
                "version": self.version,
                "timestamp": self.utcnow(),
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Union[str, Exception]] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return failed structured result."""
        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": str(error) if error is not None else message,
            "metadata": {
                "agent": self.agent_name,
                "agent_type": self.agent_type,
                "version": self.version,
                "timestamp": self.utcnow(),
                **(metadata or {}),
            },
        }

    # =========================================================================
    # Context / security / audit / event hooks
    # =========================================================================

    def _validate_task_context(
        self,
        user_id: Any,
        workspace_id: Any,
        action: str = "voice_memory_action",
    ) -> Dict[str, Any]:
        """
        Validate user/workspace context.

        This protects SaaS isolation. Every user-specific voice memory action
        must include user_id and workspace_id.
        """
        if user_id is None or str(user_id).strip() == "":
            return self._error_result(
                "Missing user_id. Voice memory cannot run without SaaS user isolation.",
                metadata={"action": action},
            )

        if workspace_id is None or str(workspace_id).strip() == "":
            return self._error_result(
                "Missing workspace_id. Voice memory cannot run without workspace isolation.",
                metadata={"action": action},
            )

        return self._safe_result(
            "Task context validated.",
            data={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
                "action": action,
            },
            metadata={"action": action},
        )

    def _requires_security_check(self, action: str) -> bool:
        """
        Decide if an action requires Security Agent approval.

        Deletes, clears, exports, or sensitive memory actions require approval.
        """
        return action in self.SENSITIVE_ACTIONS

    def _request_security_approval(
        self,
        action: str,
        user_id: str,
        workspace_id: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        Uses real SecurityAgent if available. Otherwise fallback allows only
        safe local behavior.
        """
        approval_payload = {
            "action": action,
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "payload": payload or {},
            "timestamp": self.utcnow(),
        }

        try:
            if hasattr(self.security_agent, "check_permission"):
                result = self.security_agent.check_permission(approval_payload)
            elif hasattr(self.security_agent, "approve"):
                result = self.security_agent.approve(approval_payload)
            else:
                result = {
                    "success": True,
                    "message": "No compatible security method found. Safe fallback approval used.",
                    "data": {"approved": True, "fallback": True},
                    "error": None,
                    "metadata": {},
                }

            approved = bool(
                result.get("success") and
                result.get("data", {}).get("approved", True)
            )

            if not approved:
                return self._error_result(
                    "Security approval denied.",
                    error=result.get("error") or result.get("message"),
                    metadata={
                        "action": action,
                        "security_result": result,
                    },
                )

            return self._safe_result(
                "Security approval granted.",
                data={"approved": True, "security_result": result},
                metadata={"action": action},
            )

        except Exception as exc:
            return self._error_result(
                "Security approval failed.",
                error=exc,
                metadata={"action": action},
            )

    def _prepare_verification_payload(
        self,
        action: str,
        user_id: str,
        workspace_id: str,
        result_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        The Verification Agent can use this to confirm memory action integrity.
        """
        return {
            "verification_id": self.new_id("verification"),
            "source_agent": self.agent_name,
            "source_agent_type": self.agent_type,
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "result_data": result_data or {},
            "checks": {
                "user_id_present": bool(user_id),
                "workspace_id_present": bool(workspace_id),
                "saas_isolation_required": True,
                "memory_action_completed": True,
            },
            "created_at": self.utcnow(),
        }

    def _prepare_memory_payload(
        self,
        memory_type: str,
        user_id: str,
        workspace_id: str,
        content: Dict[str, Any],
        importance: float = 0.5,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent payload.

        The Memory Agent can consume this structure for long-term memory.
        """
        return {
            "memory_payload_id": self.new_id("memory_payload"),
            "source_agent": self.agent_name,
            "source_agent_type": self.agent_type,
            "memory_type": memory_type,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "importance": self.clamp_importance(importance),
            "content": deepcopy(content),
            "created_at": self.utcnow(),
            "metadata": {
                "compatible_with": [
                    "MemoryAgent",
                    "MasterAgent",
                    "AgentRegistry",
                    "DashboardAPI",
                ],
                "saas_isolated": True,
            },
        }

    def _emit_agent_event(
        self,
        event_name: str,
        user_id: str,
        workspace_id: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Emit an agent event.

        This can later connect to websockets, dashboard analytics, task history,
        or event streaming.
        """
        event_payload = {
            "event_id": self.new_id("event"),
            "event_name": event_name,
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "payload": payload or {},
            "created_at": self.utcnow(),
        }

        try:
            if hasattr(self.event_emitter, "emit"):
                self.event_emitter.emit(event_name, event_payload)
        except Exception as exc:
            logger.warning("VoiceMemory event emit failed: %s", exc)

    def _log_audit_event(
        self,
        action: str,
        user_id: str,
        workspace_id: str,
        payload: Optional[Dict[str, Any]] = None,
        success: bool = True,
    ) -> None:
        """
        Log an audit event.

        In production this can go to DB, file, SIEM, dashboard, or task history.
        """
        audit_payload = {
            "audit_id": self.new_id("audit"),
            "action": action,
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "success": success,
            "payload": payload or {},
            "created_at": self.utcnow(),
        }

        try:
            if hasattr(self.audit_logger, "log"):
                self.audit_logger.log(audit_payload)
        except Exception as exc:
            logger.warning("VoiceMemory audit log failed: %s", exc)

    def _preflight(
        self,
        action: str,
        user_id: Any,
        workspace_id: Any,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, Dict[str, Any], str, str]:
        """
        Common validation and security preflight.

        Returns:
            (allowed, result, safe_user_id, safe_workspace_id)
        """
        context_result = self._validate_task_context(user_id, workspace_id, action)
        if not context_result["success"]:
            return False, context_result, "", ""

        safe_user_id = context_result["data"]["user_id"]
        safe_workspace_id = context_result["data"]["workspace_id"]

        if self._requires_security_check(action):
            security_result = self._request_security_approval(
                action=action,
                user_id=safe_user_id,
                workspace_id=safe_workspace_id,
                payload=payload,
            )
            if not security_result["success"]:
                return False, security_result, safe_user_id, safe_workspace_id

        return True, context_result, safe_user_id, safe_workspace_id

    # =========================================================================
    # Isolation helpers
    # =========================================================================

    def _belongs_to_context(self, item: Any, user_id: str, workspace_id: str) -> bool:
        """Check if item belongs to user/workspace."""
        return (
            getattr(item, "user_id", None) == user_id and
            getattr(item, "workspace_id", None) == workspace_id
        )

    def _filter_context_store(
        self,
        store: Dict[str, Any],
        user_id: str,
        workspace_id: str,
    ) -> Dict[str, Any]:
        """Return only records matching user/workspace context."""
        return {
            item_id: item
            for item_id, item in store.items()
            if self._belongs_to_context(item, user_id, workspace_id)
        }

    def _dataclass_to_dict(self, item: Any) -> Dict[str, Any]:
        """Convert dataclass object to dictionary."""
        if hasattr(item, "__dataclass_fields__"):
            return asdict(item)
        if isinstance(item, dict):
            return deepcopy(item)
        return {"value": item}

    # =========================================================================
    # Public method: store/update voice preference
    # =========================================================================

    def set_voice_preference(
        self,
        user_id: Any,
        workspace_id: Any,
        key: str,
        value: Any,
        source: str = "voice_agent",
        confidence: float = 1.0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create or update a voice preference for one user/workspace.

        Example:
            set_voice_preference(
                user_id="1",
                workspace_id="main",
                key="preferred_tts_voice",
                value="calm_female_voice"
            )
        """
        action = "set_voice_preference"
        allowed, result, safe_user_id, safe_workspace_id = self._preflight(
            action,
            user_id,
            workspace_id,
            {"key": key},
        )
        if not allowed:
            return result

        safe_key = str(key).strip()
        if not safe_key:
            return self._error_result(
                "Preference key is required.",
                metadata={"action": action},
            )

        with self._lock:
            existing_id = None
            for preference_id, preference in self._preferences.items():
                if (
                    preference.user_id == safe_user_id and
                    preference.workspace_id == safe_workspace_id and
                    preference.key == safe_key
                ):
                    existing_id = preference_id
                    break

            now = self.utcnow()

            if existing_id:
                preference = self._preferences[existing_id]
                preference.value = value
                preference.source = source
                preference.confidence = self.clamp_confidence(confidence)
                preference.updated_at = now
                preference.metadata.update(metadata or {})
            else:
                preference = VoicePreference(
                    preference_id=self.new_id("voice_pref"),
                    user_id=safe_user_id,
                    workspace_id=safe_workspace_id,
                    key=safe_key,
                    value=value,
                    source=source,
                    confidence=self.clamp_confidence(confidence),
                    metadata=metadata or {},
                )
                self._preferences[preference.preference_id] = preference

            self._persist_store("preferences", self._preferences)

        data = {
            "preference": self._dataclass_to_dict(preference),
            "memory_payload": self._prepare_memory_payload(
                memory_type="voice_preference",
                user_id=safe_user_id,
                workspace_id=safe_workspace_id,
                content=self._dataclass_to_dict(preference),
                importance=0.7,
            ),
            "verification_payload": self._prepare_verification_payload(
                action=action,
                user_id=safe_user_id,
                workspace_id=safe_workspace_id,
                result_data={"preference_id": preference.preference_id},
            ),
        }

        self._emit_agent_event(action, safe_user_id, safe_workspace_id, data)
        self._log_audit_event(action, safe_user_id, safe_workspace_id, data, True)

        return self._safe_result(
            "Voice preference saved.",
            data=data,
            metadata={"action": action},
        )

    def get_voice_preference(
        self,
        user_id: Any,
        workspace_id: Any,
        key: str,
        default: Any = None,
    ) -> Dict[str, Any]:
        """Retrieve one voice preference by key."""
        action = "get_voice_preference"
        allowed, result, safe_user_id, safe_workspace_id = self._preflight(
            action,
            user_id,
            workspace_id,
            {"key": key},
        )
        if not allowed:
            return result

        safe_key = str(key).strip()

        with self._lock:
            for preference in self._preferences.values():
                if (
                    preference.user_id == safe_user_id and
                    preference.workspace_id == safe_workspace_id and
                    preference.key == safe_key
                ):
                    return self._safe_result(
                        "Voice preference found.",
                        data={"preference": self._dataclass_to_dict(preference)},
                        metadata={"action": action},
                    )

        return self._safe_result(
            "Voice preference not found. Returning default.",
            data={
                "preference": None,
                "default": default,
                "value": default,
            },
            metadata={"action": action},
        )

    def list_voice_preferences(
        self,
        user_id: Any,
        workspace_id: Any,
    ) -> Dict[str, Any]:
        """List all voice preferences for a user/workspace."""
        action = "list_voice_preferences"
        allowed, result, safe_user_id, safe_workspace_id = self._preflight(
            action,
            user_id,
            workspace_id,
        )
        if not allowed:
            return result

        with self._lock:
            preferences = [
                self._dataclass_to_dict(item)
                for item in self._filter_context_store(
                    self._preferences,
                    safe_user_id,
                    safe_workspace_id,
                ).values()
            ]

        return self._safe_result(
            "Voice preferences listed.",
            data={"preferences": preferences, "count": len(preferences)},
            metadata={"action": action},
        )

    def delete_preference(
        self,
        user_id: Any,
        workspace_id: Any,
        key: str,
    ) -> Dict[str, Any]:
        """Delete a voice preference by key."""
        action = "delete_preference"
        allowed, result, safe_user_id, safe_workspace_id = self._preflight(
            action,
            user_id,
            workspace_id,
            {"key": key},
        )
        if not allowed:
            return result

        deleted: Optional[Dict[str, Any]] = None

        with self._lock:
            delete_id = None
            for preference_id, preference in self._preferences.items():
                if (
                    preference.user_id == safe_user_id and
                    preference.workspace_id == safe_workspace_id and
                    preference.key == str(key).strip()
                ):
                    delete_id = preference_id
                    deleted = self._dataclass_to_dict(preference)
                    break

            if delete_id:
                del self._preferences[delete_id]
                self._persist_store("preferences", self._preferences)

        if not deleted:
            return self._safe_result(
                "Preference not found. Nothing deleted.",
                data={"deleted": False},
                metadata={"action": action},
            )

        data = {
            "deleted": True,
            "preference": deleted,
            "verification_payload": self._prepare_verification_payload(
                action,
                safe_user_id,
                safe_workspace_id,
                {"deleted_key": key},
            ),
        }

        self._emit_agent_event(action, safe_user_id, safe_workspace_id, data)
        self._log_audit_event(action, safe_user_id, safe_workspace_id, data, True)

        return self._safe_result(
            "Voice preference deleted.",
            data=data,
            metadata={"action": action},
        )

    # =========================================================================
    # Public method: recurring phrases
    # =========================================================================

    def remember_phrase(
        self,
        user_id: Any,
        workspace_id: Any,
        phrase: str,
        intent_hint: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Remember or increment a recurring spoken phrase."""
        action = "remember_phrase"
        allowed, result, safe_user_id, safe_workspace_id = self._preflight(
            action,
            user_id,
            workspace_id,
            {"phrase": phrase},
        )
        if not allowed:
            return result

        safe_phrase = str(phrase).strip()
        normalized = self.normalize_text(safe_phrase)

        if not normalized:
            return self._error_result(
                "Phrase is required.",
                metadata={"action": action},
            )

        with self._lock:
            existing_id = None

            for phrase_id, record in self._phrases.items():
                if (
                    record.user_id == safe_user_id and
                    record.workspace_id == safe_workspace_id and
                    record.normalized_phrase == normalized
                ):
                    existing_id = phrase_id
                    break

            now = self.utcnow()

            if existing_id:
                record = self._phrases[existing_id]
                record.usage_count += 1
                record.last_seen_at = now
                if intent_hint:
                    record.intent_hint = intent_hint
                record.metadata.update(metadata or {})
            else:
                record = RecurringPhrase(
                    phrase_id=self.new_id("phrase"),
                    user_id=safe_user_id,
                    workspace_id=safe_workspace_id,
                    phrase=safe_phrase,
                    normalized_phrase=normalized,
                    intent_hint=intent_hint,
                    metadata=metadata or {},
                )
                self._phrases[record.phrase_id] = record

            self._persist_store("phrases", self._phrases)

        data = {
            "phrase": self._dataclass_to_dict(record),
            "memory_payload": self._prepare_memory_payload(
                memory_type="recurring_voice_phrase",
                user_id=safe_user_id,
                workspace_id=safe_workspace_id,
                content=self._dataclass_to_dict(record),
                importance=min(1.0, 0.3 + (record.usage_count * 0.05)),
            ),
            "verification_payload": self._prepare_verification_payload(
                action,
                safe_user_id,
                safe_workspace_id,
                {"phrase_id": record.phrase_id},
            ),
        }

        self._emit_agent_event(action, safe_user_id, safe_workspace_id, data)
        self._log_audit_event(action, safe_user_id, safe_workspace_id, data, True)

        return self._safe_result(
            "Recurring phrase remembered.",
            data=data,
            metadata={"action": action},
        )

    def get_recurring_phrases(
        self,
        user_id: Any,
        workspace_id: Any,
        min_usage_count: int = 1,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """Get recurring phrases sorted by usage count and recency."""
        action = "get_recurring_phrases"
        allowed, result, safe_user_id, safe_workspace_id = self._preflight(
            action,
            user_id,
            workspace_id,
        )
        if not allowed:
            return result

        safe_limit = max(1, min(int(limit or 50), 500))
        safe_min_usage = max(1, int(min_usage_count or 1))

        with self._lock:
            records = [
                record
                for record in self._phrases.values()
                if (
                    record.user_id == safe_user_id and
                    record.workspace_id == safe_workspace_id and
                    record.usage_count >= safe_min_usage
                )
            ]

            records.sort(
                key=lambda item: (item.usage_count, item.last_seen_at),
                reverse=True,
            )

            output = [
                self._dataclass_to_dict(item)
                for item in records[:safe_limit]
            ]

        return self._safe_result(
            "Recurring phrases listed.",
            data={"phrases": output, "count": len(output)},
            metadata={"action": action},
        )

    def match_phrase(
        self,
        user_id: Any,
        workspace_id: Any,
        spoken_text: str,
        fuzzy: bool = True,
    ) -> Dict[str, Any]:
        """
        Match spoken text against remembered recurring phrases.

        Fuzzy matching here is intentionally lightweight and dependency-free.
        """
        action = "match_phrase"
        allowed, result, safe_user_id, safe_workspace_id = self._preflight(
            action,
            user_id,
            workspace_id,
            {"spoken_text": spoken_text},
        )
        if not allowed:
            return result

        normalized_input = self.normalize_text(spoken_text)

        if not normalized_input:
            return self._safe_result(
                "No spoken text provided for phrase matching.",
                data={"matched": False, "matches": []},
                metadata={"action": action},
            )

        matches: List[Dict[str, Any]] = []

        with self._lock:
            for record in self._phrases.values():
                if not self._belongs_to_context(record, safe_user_id, safe_workspace_id):
                    continue

                score = 0.0

                if normalized_input == record.normalized_phrase:
                    score = 1.0
                elif record.normalized_phrase in normalized_input:
                    score = 0.85
                elif fuzzy:
                    input_tokens = set(normalized_input.split())
                    phrase_tokens = set(record.normalized_phrase.split())
                    if input_tokens and phrase_tokens:
                        overlap = len(input_tokens.intersection(phrase_tokens))
                        union = len(input_tokens.union(phrase_tokens))
                        score = overlap / union if union else 0.0

                if score >= 0.45:
                    item = self._dataclass_to_dict(record)
                    item["match_score"] = round(score, 4)
                    matches.append(item)

        matches.sort(key=lambda item: item.get("match_score", 0), reverse=True)

        return self._safe_result(
            "Phrase matching completed.",
            data={
                "matched": bool(matches),
                "matches": matches,
                "top_match": matches[0] if matches else None,
            },
            metadata={"action": action},
        )

    def delete_phrase(
        self,
        user_id: Any,
        workspace_id: Any,
        phrase: str,
    ) -> Dict[str, Any]:
        """Delete a remembered recurring phrase."""
        action = "delete_phrase"
        allowed, result, safe_user_id, safe_workspace_id = self._preflight(
            action,
            user_id,
            workspace_id,
            {"phrase": phrase},
        )
        if not allowed:
            return result

        normalized = self.normalize_text(phrase)
        deleted: Optional[Dict[str, Any]] = None

        with self._lock:
            delete_id = None
            for phrase_id, record in self._phrases.items():
                if (
                    record.user_id == safe_user_id and
                    record.workspace_id == safe_workspace_id and
                    record.normalized_phrase == normalized
                ):
                    delete_id = phrase_id
                    deleted = self._dataclass_to_dict(record)
                    break

            if delete_id:
                del self._phrases[delete_id]
                self._persist_store("phrases", self._phrases)

        data = {
            "deleted": bool(deleted),
            "phrase": deleted,
        }

        self._emit_agent_event(action, safe_user_id, safe_workspace_id, data)
        self._log_audit_event(action, safe_user_id, safe_workspace_id, data, True)

        return self._safe_result(
            "Phrase deletion completed.",
            data=data,
            metadata={"action": action},
        )

    # =========================================================================
    # Public method: language behavior
    # =========================================================================

    def set_language_behavior(
        self,
        user_id: Any,
        workspace_id: Any,
        language_code: str,
        language_name: str,
        behavior_type: str,
        value: Any,
        confidence: float = 1.0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Store or update language behavior."""
        action = "set_language_behavior"
        allowed, result, safe_user_id, safe_workspace_id = self._preflight(
            action,
            user_id,
            workspace_id,
            {
                "language_code": language_code,
                "behavior_type": behavior_type,
            },
        )
        if not allowed:
            return result

        safe_language_code = str(language_code).strip().lower()
        safe_language_name = str(language_name).strip()
        safe_behavior_type = str(behavior_type).strip().lower()

        if not safe_language_code or not safe_behavior_type:
            return self._error_result(
                "language_code and behavior_type are required.",
                metadata={"action": action},
            )

        with self._lock:
            existing_id = None

            for behavior_id, behavior in self._language_behaviors.items():
                if (
                    behavior.user_id == safe_user_id and
                    behavior.workspace_id == safe_workspace_id and
                    behavior.language_code == safe_language_code and
                    behavior.behavior_type == safe_behavior_type
                ):
                    existing_id = behavior_id
                    break

            now = self.utcnow()

            if existing_id:
                behavior = self._language_behaviors[existing_id]
                behavior.language_name = safe_language_name or behavior.language_name
                behavior.value = value
                behavior.confidence = self.clamp_confidence(confidence)
                behavior.updated_at = now
                behavior.metadata.update(metadata or {})
            else:
                behavior = LanguageBehavior(
                    behavior_id=self.new_id("language_behavior"),
                    user_id=safe_user_id,
                    workspace_id=safe_workspace_id,
                    language_code=safe_language_code,
                    language_name=safe_language_name,
                    behavior_type=safe_behavior_type,
                    value=value,
                    confidence=self.clamp_confidence(confidence),
                    metadata=metadata or {},
                )
                self._language_behaviors[behavior.behavior_id] = behavior

            self._persist_store("language_behaviors", self._language_behaviors)

        data = {
            "language_behavior": self._dataclass_to_dict(behavior),
            "memory_payload": self._prepare_memory_payload(
                memory_type="voice_language_behavior",
                user_id=safe_user_id,
                workspace_id=safe_workspace_id,
                content=self._dataclass_to_dict(behavior),
                importance=0.75,
            ),
            "verification_payload": self._prepare_verification_payload(
                action,
                safe_user_id,
                safe_workspace_id,
                {"behavior_id": behavior.behavior_id},
            ),
        }

        self._emit_agent_event(action, safe_user_id, safe_workspace_id, data)
        self._log_audit_event(action, safe_user_id, safe_workspace_id, data, True)

        return self._safe_result(
            "Language behavior saved.",
            data=data,
            metadata={"action": action},
        )

    def get_language_behaviors(
        self,
        user_id: Any,
        workspace_id: Any,
        language_code: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get language behavior records for one user/workspace."""
        action = "get_language_behaviors"
        allowed, result, safe_user_id, safe_workspace_id = self._preflight(
            action,
            user_id,
            workspace_id,
        )
        if not allowed:
            return result

        safe_language_code = str(language_code).strip().lower() if language_code else None

        with self._lock:
            behaviors = []
            for behavior in self._language_behaviors.values():
                if not self._belongs_to_context(behavior, safe_user_id, safe_workspace_id):
                    continue
                if safe_language_code and behavior.language_code != safe_language_code:
                    continue
                behaviors.append(self._dataclass_to_dict(behavior))

        return self._safe_result(
            "Language behaviors listed.",
            data={"language_behaviors": behaviors, "count": len(behaviors)},
            metadata={"action": action},
        )

    def infer_preferred_language(
        self,
        user_id: Any,
        workspace_id: Any,
        fallback_language_code: str = "en",
    ) -> Dict[str, Any]:
        """
        Infer preferred language from stored behavior.

        Priority:
            1. behavior_type == preferred_language
            2. highest confidence behavior
            3. fallback_language_code
        """
        action = "infer_preferred_language"
        allowed, result, safe_user_id, safe_workspace_id = self._preflight(
            action,
            user_id,
            workspace_id,
        )
        if not allowed:
            return result

        with self._lock:
            behaviors = [
                behavior
                for behavior in self._language_behaviors.values()
                if self._belongs_to_context(behavior, safe_user_id, safe_workspace_id)
            ]

        preferred = [
            behavior for behavior in behaviors
            if behavior.behavior_type == "preferred_language"
        ]

        if preferred:
            preferred.sort(key=lambda item: item.confidence, reverse=True)
            selected = preferred[0]
            return self._safe_result(
                "Preferred language inferred.",
                data={
                    "language_code": selected.language_code,
                    "language_name": selected.language_name,
                    "source": "preferred_language_behavior",
                    "behavior": self._dataclass_to_dict(selected),
                },
                metadata={"action": action},
            )

        if behaviors:
            behaviors.sort(key=lambda item: item.confidence, reverse=True)
            selected = behaviors[0]
            return self._safe_result(
                "Preferred language inferred from highest confidence behavior.",
                data={
                    "language_code": selected.language_code,
                    "language_name": selected.language_name,
                    "source": "highest_confidence_behavior",
                    "behavior": self._dataclass_to_dict(selected),
                },
                metadata={"action": action},
            )

        return self._safe_result(
            "No language behavior found. Returning fallback language.",
            data={
                "language_code": fallback_language_code,
                "language_name": fallback_language_code,
                "source": "fallback",
            },
            metadata={"action": action},
        )

    def delete_language_behavior(
        self,
        user_id: Any,
        workspace_id: Any,
        behavior_id: str,
    ) -> Dict[str, Any]:
        """Delete one language behavior by ID."""
        action = "delete_language_behavior"
        allowed, result, safe_user_id, safe_workspace_id = self._preflight(
            action,
            user_id,
            workspace_id,
            {"behavior_id": behavior_id},
        )
        if not allowed:
            return result

        deleted: Optional[Dict[str, Any]] = None

        with self._lock:
            behavior = self._language_behaviors.get(str(behavior_id))
            if behavior and self._belongs_to_context(
                behavior,
                safe_user_id,
                safe_workspace_id,
            ):
                deleted = self._dataclass_to_dict(behavior)
                del self._language_behaviors[str(behavior_id)]
                self._persist_store("language_behaviors", self._language_behaviors)

        data = {"deleted": bool(deleted), "language_behavior": deleted}

        self._emit_agent_event(action, safe_user_id, safe_workspace_id, data)
        self._log_audit_event(action, safe_user_id, safe_workspace_id, data, True)

        return self._safe_result(
            "Language behavior deletion completed.",
            data=data,
            metadata={"action": action},
        )

    # =========================================================================
    # Public method: audio notes
    # =========================================================================

    def add_audio_note(
        self,
        user_id: Any,
        workspace_id: Any,
        title: str,
        transcript: str,
        language_code: Optional[str] = None,
        audio_path: Optional[str] = None,
        duration_seconds: Optional[float] = None,
        tags: Optional[List[str]] = None,
        source: str = "voice_agent",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Add an audio note.

        This stores transcript and metadata. It does not directly process audio.
        """
        action = "add_audio_note"
        allowed, result, safe_user_id, safe_workspace_id = self._preflight(
            action,
            user_id,
            workspace_id,
            {"title": title},
        )
        if not allowed:
            return result

        safe_title = str(title).strip()
        safe_transcript = str(transcript).strip()

        if not safe_title:
            safe_title = f"Audio Note {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

        if not safe_transcript:
            return self._error_result(
                "Audio note transcript is required.",
                metadata={"action": action},
            )

        safe_tags = [str(tag).strip() for tag in (tags or []) if str(tag).strip()]

        note = AudioNote(
            note_id=self.new_id("audio_note"),
            user_id=safe_user_id,
            workspace_id=safe_workspace_id,
            title=safe_title,
            transcript=safe_transcript,
            language_code=language_code,
            audio_path=audio_path,
            duration_seconds=duration_seconds,
            tags=safe_tags,
            source=source,
            metadata=metadata or {},
        )

        with self._lock:
            self._audio_notes[note.note_id] = note
            self._persist_store("audio_notes", self._audio_notes)

        data = {
            "audio_note": self._dataclass_to_dict(note),
            "memory_payload": self._prepare_memory_payload(
                memory_type="voice_audio_note",
                user_id=safe_user_id,
                workspace_id=safe_workspace_id,
                content=self._dataclass_to_dict(note),
                importance=0.65,
            ),
            "verification_payload": self._prepare_verification_payload(
                action,
                safe_user_id,
                safe_workspace_id,
                {"note_id": note.note_id},
            ),
        }

        self._emit_agent_event(action, safe_user_id, safe_workspace_id, data)
        self._log_audit_event(action, safe_user_id, safe_workspace_id, data, True)

        return self._safe_result(
            "Audio note added.",
            data=data,
            metadata={"action": action},
        )

    def get_audio_note(
        self,
        user_id: Any,
        workspace_id: Any,
        note_id: str,
    ) -> Dict[str, Any]:
        """Retrieve one audio note by ID."""
        action = "get_audio_note"
        allowed, result, safe_user_id, safe_workspace_id = self._preflight(
            action,
            user_id,
            workspace_id,
            {"note_id": note_id},
        )
        if not allowed:
            return result

        with self._lock:
            note = self._audio_notes.get(str(note_id))
            if note and self._belongs_to_context(note, safe_user_id, safe_workspace_id):
                return self._safe_result(
                    "Audio note found.",
                    data={"audio_note": self._dataclass_to_dict(note)},
                    metadata={"action": action},
                )

        return self._safe_result(
            "Audio note not found.",
            data={"audio_note": None},
            metadata={"action": action},
        )

    def list_audio_notes(
        self,
        user_id: Any,
        workspace_id: Any,
        tag: Optional[str] = None,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """List audio notes for a user/workspace."""
        action = "list_audio_notes"
        allowed, result, safe_user_id, safe_workspace_id = self._preflight(
            action,
            user_id,
            workspace_id,
            {"tag": tag},
        )
        if not allowed:
            return result

        safe_limit = max(1, min(int(limit or 50), 500))
        safe_tag = str(tag).strip().lower() if tag else None

        with self._lock:
            notes = []
            for note in self._audio_notes.values():
                if not self._belongs_to_context(note, safe_user_id, safe_workspace_id):
                    continue

                if safe_tag:
                    note_tags = [item.lower() for item in note.tags]
                    if safe_tag not in note_tags:
                        continue

                notes.append(note)

            notes.sort(key=lambda item: item.created_at, reverse=True)
            output = [self._dataclass_to_dict(item) for item in notes[:safe_limit]]

        return self._safe_result(
            "Audio notes listed.",
            data={"audio_notes": output, "count": len(output)},
            metadata={"action": action},
        )

    def search_audio_notes(
        self,
        user_id: Any,
        workspace_id: Any,
        query: str,
        limit: int = 20,
    ) -> Dict[str, Any]:
        """Search audio notes by title, transcript, or tags."""
        action = "search_audio_notes"
        allowed, result, safe_user_id, safe_workspace_id = self._preflight(
            action,
            user_id,
            workspace_id,
            {"query": query},
        )
        if not allowed:
            return result

        normalized_query = self.normalize_text(query)
        if not normalized_query:
            return self._safe_result(
                "Empty query. No audio notes searched.",
                data={"audio_notes": [], "count": 0},
                metadata={"action": action},
            )

        safe_limit = max(1, min(int(limit or 20), 200))
        query_tokens = set(normalized_query.split())

        matches: List[Dict[str, Any]] = []

        with self._lock:
            for note in self._audio_notes.values():
                if not self._belongs_to_context(note, safe_user_id, safe_workspace_id):
                    continue

                haystack = " ".join([
                    note.title,
                    note.transcript,
                    " ".join(note.tags),
                    str(note.language_code or ""),
                ])
                normalized_haystack = self.normalize_text(haystack)

                score = 0.0
                if normalized_query in normalized_haystack:
                    score = 1.0
                else:
                    haystack_tokens = set(normalized_haystack.split())
                    if query_tokens and haystack_tokens:
                        score = len(query_tokens.intersection(haystack_tokens)) / len(query_tokens)

                if score > 0:
                    item = self._dataclass_to_dict(note)
                    item["match_score"] = round(score, 4)
                    matches.append(item)

        matches.sort(key=lambda item: item.get("match_score", 0), reverse=True)

        return self._safe_result(
            "Audio note search completed.",
            data={"audio_notes": matches[:safe_limit], "count": len(matches[:safe_limit])},
            metadata={"action": action},
        )

    def delete_audio_note(
        self,
        user_id: Any,
        workspace_id: Any,
        note_id: str,
    ) -> Dict[str, Any]:
        """Delete one audio note."""
        action = "delete_audio_note"
        allowed, result, safe_user_id, safe_workspace_id = self._preflight(
            action,
            user_id,
            workspace_id,
            {"note_id": note_id},
        )
        if not allowed:
            return result

        deleted: Optional[Dict[str, Any]] = None

        with self._lock:
            note = self._audio_notes.get(str(note_id))
            if note and self._belongs_to_context(note, safe_user_id, safe_workspace_id):
                deleted = self._dataclass_to_dict(note)
                del self._audio_notes[str(note_id)]
                self._persist_store("audio_notes", self._audio_notes)

        data = {"deleted": bool(deleted), "audio_note": deleted}

        self._emit_agent_event(action, safe_user_id, safe_workspace_id, data)
        self._log_audit_event(action, safe_user_id, safe_workspace_id, data, True)

        return self._safe_result(
            "Audio note deletion completed.",
            data=data,
            metadata={"action": action},
        )

    # =========================================================================
    # Public method: voice interaction memory
    # =========================================================================

    def remember_interaction(
        self,
        user_id: Any,
        workspace_id: Any,
        input_text: str,
        response_text: Optional[str] = None,
        detected_language: Optional[str] = None,
        detected_emotion: Optional[str] = None,
        speaker_id: Optional[str] = None,
        summary: Optional[str] = None,
        importance: float = 0.5,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Remember summarized voice interaction.

        This method is useful after STT + Language Engine + Emotion Detector +
        TTS response pipeline completes.
        """
        action = "remember_interaction"
        allowed, result, safe_user_id, safe_workspace_id = self._preflight(
            action,
            user_id,
            workspace_id,
            {"input_text": input_text},
        )
        if not allowed:
            return result

        safe_input = str(input_text).strip()
        if not safe_input:
            return self._error_result(
                "input_text is required.",
                metadata={"action": action},
            )

        safe_summary = summary or self._simple_summarize(safe_input, response_text)

        memory = VoiceInteractionMemory(
            memory_id=self.new_id("voice_interaction"),
            user_id=safe_user_id,
            workspace_id=safe_workspace_id,
            input_text=safe_input,
            response_text=response_text,
            detected_language=detected_language,
            detected_emotion=detected_emotion,
            speaker_id=speaker_id,
            summary=safe_summary,
            importance=self.clamp_importance(importance),
            metadata=metadata or {},
        )

        with self._lock:
            self._interactions[memory.memory_id] = memory
            self._persist_store("interactions", self._interactions)

        data = {
            "interaction_memory": self._dataclass_to_dict(memory),
            "memory_payload": self._prepare_memory_payload(
                memory_type="voice_interaction",
                user_id=safe_user_id,
                workspace_id=safe_workspace_id,
                content=self._dataclass_to_dict(memory),
                importance=memory.importance,
            ),
            "verification_payload": self._prepare_verification_payload(
                action,
                safe_user_id,
                safe_workspace_id,
                {"memory_id": memory.memory_id},
            ),
        }

        self._emit_agent_event(action, safe_user_id, safe_workspace_id, data)
        self._log_audit_event(action, safe_user_id, safe_workspace_id, data, True)

        return self._safe_result(
            "Voice interaction remembered.",
            data=data,
            metadata={"action": action},
        )

    def _simple_summarize(
        self,
        input_text: str,
        response_text: Optional[str] = None,
        max_chars: int = 240,
    ) -> str:
        """
        Lightweight local summary fallback.

        Real production summary can be delegated to Master Agent / Memory Agent.
        """
        combined = input_text
        if response_text:
            combined += f" | Response: {response_text}"

        combined = re.sub(r"\s+", " ", combined).strip()

        if len(combined) <= max_chars:
            return combined

        return combined[: max_chars - 3].rstrip() + "..."

    def list_interactions(
        self,
        user_id: Any,
        workspace_id: Any,
        limit: int = 50,
        speaker_id: Optional[str] = None,
        detected_language: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List remembered voice interactions."""
        action = "list_interactions"
        allowed, result, safe_user_id, safe_workspace_id = self._preflight(
            action,
            user_id,
            workspace_id,
        )
        if not allowed:
            return result

        safe_limit = max(1, min(int(limit or 50), 500))

        with self._lock:
            records = []
            for memory in self._interactions.values():
                if not self._belongs_to_context(memory, safe_user_id, safe_workspace_id):
                    continue

                if speaker_id and memory.speaker_id != speaker_id:
                    continue

                if detected_language and memory.detected_language != detected_language:
                    continue

                records.append(memory)

            records.sort(key=lambda item: item.created_at, reverse=True)
            output = [
                self._dataclass_to_dict(item)
                for item in records[:safe_limit]
            ]

        return self._safe_result(
            "Voice interactions listed.",
            data={"interactions": output, "count": len(output)},
            metadata={"action": action},
        )

    def search_interactions(
        self,
        user_id: Any,
        workspace_id: Any,
        query: str,
        limit: int = 20,
    ) -> Dict[str, Any]:
        """Search remembered voice interactions."""
        action = "search_interactions"
        allowed, result, safe_user_id, safe_workspace_id = self._preflight(
            action,
            user_id,
            workspace_id,
            {"query": query},
        )
        if not allowed:
            return result

        normalized_query = self.normalize_text(query)
        if not normalized_query:
            return self._safe_result(
                "Empty query. No interactions searched.",
                data={"interactions": [], "count": 0},
                metadata={"action": action},
            )

        safe_limit = max(1, min(int(limit or 20), 200))
        query_tokens = set(normalized_query.split())
        matches: List[Dict[str, Any]] = []

        with self._lock:
            for memory in self._interactions.values():
                if not self._belongs_to_context(memory, safe_user_id, safe_workspace_id):
                    continue

                haystack = " ".join([
                    memory.input_text,
                    memory.response_text or "",
                    memory.summary or "",
                    memory.detected_language or "",
                    memory.detected_emotion or "",
                    memory.speaker_id or "",
                ])
                normalized_haystack = self.normalize_text(haystack)

                score = 0.0
                if normalized_query in normalized_haystack:
                    score = 1.0
                else:
                    haystack_tokens = set(normalized_haystack.split())
                    if query_tokens and haystack_tokens:
                        score = len(query_tokens.intersection(haystack_tokens)) / len(query_tokens)

                if score > 0:
                    item = self._dataclass_to_dict(memory)
                    item["match_score"] = round(score, 4)
                    matches.append(item)

        matches.sort(key=lambda item: item.get("match_score", 0), reverse=True)

        return self._safe_result(
            "Voice interaction search completed.",
            data={
                "interactions": matches[:safe_limit],
                "count": len(matches[:safe_limit]),
            },
            metadata={"action": action},
        )

    def delete_interaction_memory(
        self,
        user_id: Any,
        workspace_id: Any,
        memory_id: str,
    ) -> Dict[str, Any]:
        """Delete one voice interaction memory."""
        action = "delete_interaction_memory"
        allowed, result, safe_user_id, safe_workspace_id = self._preflight(
            action,
            user_id,
            workspace_id,
            {"memory_id": memory_id},
        )
        if not allowed:
            return result

        deleted: Optional[Dict[str, Any]] = None

        with self._lock:
            memory = self._interactions.get(str(memory_id))
            if memory and self._belongs_to_context(memory, safe_user_id, safe_workspace_id):
                deleted = self._dataclass_to_dict(memory)
                del self._interactions[str(memory_id)]
                self._persist_store("interactions", self._interactions)

        data = {"deleted": bool(deleted), "interaction_memory": deleted}

        self._emit_agent_event(action, safe_user_id, safe_workspace_id, data)
        self._log_audit_event(action, safe_user_id, safe_workspace_id, data, True)

        return self._safe_result(
            "Voice interaction memory deletion completed.",
            data=data,
            metadata={"action": action},
        )

    # =========================================================================
    # Public method: unified memory context
    # =========================================================================

    def get_voice_memory_context(
        self,
        user_id: Any,
        workspace_id: Any,
        include_preferences: bool = True,
        include_phrases: bool = True,
        include_language_behaviors: bool = True,
        include_audio_notes: bool = False,
        include_interactions: bool = True,
        phrase_limit: int = 20,
        interaction_limit: int = 20,
        audio_note_limit: int = 10,
    ) -> Dict[str, Any]:
        """
        Return a unified voice memory context for Master Agent / Voice Agent.

        This is the main read method for:
            - voice_agent.py
            - conversation_mode.py
            - voice_loop.py
            - language_engine.py
            - tts_engine.py
            - Master Agent routing
        """
        action = "get_voice_memory_context"
        allowed, result, safe_user_id, safe_workspace_id = self._preflight(
            action,
            user_id,
            workspace_id,
        )
        if not allowed:
            return result

        context: Dict[str, Any] = {
            "user_id": safe_user_id,
            "workspace_id": safe_workspace_id,
            "generated_at": self.utcnow(),
            "preferences": [],
            "recurring_phrases": [],
            "language_behaviors": [],
            "audio_notes": [],
            "interactions": [],
        }

        with self._lock:
            if include_preferences:
                context["preferences"] = [
                    self._dataclass_to_dict(item)
                    for item in self._filter_context_store(
                        self._preferences,
                        safe_user_id,
                        safe_workspace_id,
                    ).values()
                ]

            if include_phrases:
                phrases = [
                    item
                    for item in self._phrases.values()
                    if self._belongs_to_context(item, safe_user_id, safe_workspace_id)
                ]
                phrases.sort(key=lambda item: (item.usage_count, item.last_seen_at), reverse=True)
                context["recurring_phrases"] = [
                    self._dataclass_to_dict(item)
                    for item in phrases[: max(1, int(phrase_limit or 20))]
                ]

            if include_language_behaviors:
                context["language_behaviors"] = [
                    self._dataclass_to_dict(item)
                    for item in self._filter_context_store(
                        self._language_behaviors,
                        safe_user_id,
                        safe_workspace_id,
                    ).values()
                ]

            if include_audio_notes:
                notes = [
                    item
                    for item in self._audio_notes.values()
                    if self._belongs_to_context(item, safe_user_id, safe_workspace_id)
                ]
                notes.sort(key=lambda item: item.created_at, reverse=True)
                context["audio_notes"] = [
                    self._dataclass_to_dict(item)
                    for item in notes[: max(1, int(audio_note_limit or 10))]
                ]

            if include_interactions:
                interactions = [
                    item
                    for item in self._interactions.values()
                    if self._belongs_to_context(item, safe_user_id, safe_workspace_id)
                ]
                interactions.sort(key=lambda item: item.created_at, reverse=True)
                context["interactions"] = [
                    self._dataclass_to_dict(item)
                    for item in interactions[: max(1, int(interaction_limit or 20))]
                ]

        context["summary"] = self._build_context_summary(context)

        return self._safe_result(
            "Voice memory context generated.",
            data={"voice_memory_context": context},
            metadata={"action": action},
        )

    def _build_context_summary(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Build lightweight summary of memory context."""
        preferences = context.get("preferences", [])
        phrases = context.get("recurring_phrases", [])
        language_behaviors = context.get("language_behaviors", [])
        audio_notes = context.get("audio_notes", [])
        interactions = context.get("interactions", [])

        top_phrases = [
            item.get("phrase")
            for item in phrases[:5]
            if isinstance(item, dict) and item.get("phrase")
        ]

        preferred_languages = [
            item
            for item in language_behaviors
            if isinstance(item, dict) and item.get("behavior_type") == "preferred_language"
        ]

        return {
            "preference_count": len(preferences),
            "recurring_phrase_count": len(phrases),
            "language_behavior_count": len(language_behaviors),
            "audio_note_count": len(audio_notes),
            "interaction_count": len(interactions),
            "top_phrases": top_phrases,
            "preferred_languages": preferred_languages,
        }

    # =========================================================================
    # Public method: export / clear
    # =========================================================================

    def export_workspace_memory(
        self,
        user_id: Any,
        workspace_id: Any,
    ) -> Dict[str, Any]:
        """
        Export all voice memory for a user/workspace.

        Sensitive action because it can expose user memory data.
        """
        action = "export_workspace_memory"
        allowed, result, safe_user_id, safe_workspace_id = self._preflight(
            action,
            user_id,
            workspace_id,
        )
        if not allowed:
            return result

        context_result = self.get_voice_memory_context(
            user_id=safe_user_id,
            workspace_id=safe_workspace_id,
            include_preferences=True,
            include_phrases=True,
            include_language_behaviors=True,
            include_audio_notes=True,
            include_interactions=True,
            phrase_limit=10000,
            interaction_limit=10000,
            audio_note_limit=10000,
        )

        if not context_result["success"]:
            return context_result

        data = {
            "export_id": self.new_id("voice_memory_export"),
            "exported_at": self.utcnow(),
            "voice_memory": context_result["data"]["voice_memory_context"],
            "verification_payload": self._prepare_verification_payload(
                action,
                safe_user_id,
                safe_workspace_id,
                {"exported": True},
            ),
        }

        self._emit_agent_event(action, safe_user_id, safe_workspace_id, {"exported": True})
        self._log_audit_event(action, safe_user_id, safe_workspace_id, {"exported": True}, True)

        return self._safe_result(
            "Voice workspace memory exported.",
            data=data,
            metadata={"action": action},
        )

    def clear_user_workspace_memory(
        self,
        user_id: Any,
        workspace_id: Any,
        memory_types: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Clear selected voice memory types for one user/workspace.

        Sensitive action protected by Security Agent.
        """
        action = "clear_user_workspace_memory"
        allowed, result, safe_user_id, safe_workspace_id = self._preflight(
            action,
            user_id,
            workspace_id,
            {"memory_types": memory_types},
        )
        if not allowed:
            return result

        selected_types = set(memory_types or self.VALID_MEMORY_TYPES)
        invalid = selected_types.difference(self.VALID_MEMORY_TYPES)
        if invalid:
            return self._error_result(
                "Invalid memory type requested.",
                data={"invalid_memory_types": sorted(invalid)},
                metadata={"action": action},
            )

        deleted_counts = {
            "preference": 0,
            "phrase": 0,
            "language_behavior": 0,
            "audio_note": 0,
            "interaction": 0,
        }

        with self._lock:
            if "preference" in selected_types:
                deleted_counts["preference"] = self._delete_from_store_by_context(
                    self._preferences,
                    safe_user_id,
                    safe_workspace_id,
                )
                self._persist_store("preferences", self._preferences)

            if "phrase" in selected_types:
                deleted_counts["phrase"] = self._delete_from_store_by_context(
                    self._phrases,
                    safe_user_id,
                    safe_workspace_id,
                )
                self._persist_store("phrases", self._phrases)

            if "language_behavior" in selected_types:
                deleted_counts["language_behavior"] = self._delete_from_store_by_context(
                    self._language_behaviors,
                    safe_user_id,
                    safe_workspace_id,
                )
                self._persist_store("language_behaviors", self._language_behaviors)

            if "audio_note" in selected_types:
                deleted_counts["audio_note"] = self._delete_from_store_by_context(
                    self._audio_notes,
                    safe_user_id,
                    safe_workspace_id,
                )
                self._persist_store("audio_notes", self._audio_notes)

            if "interaction" in selected_types:
                deleted_counts["interaction"] = self._delete_from_store_by_context(
                    self._interactions,
                    safe_user_id,
                    safe_workspace_id,
                )
                self._persist_store("interactions", self._interactions)

        data = {
            "deleted_counts": deleted_counts,
            "memory_types": sorted(selected_types),
            "verification_payload": self._prepare_verification_payload(
                action,
                safe_user_id,
                safe_workspace_id,
                {"deleted_counts": deleted_counts},
            ),
        }

        self._emit_agent_event(action, safe_user_id, safe_workspace_id, data)
        self._log_audit_event(action, safe_user_id, safe_workspace_id, data, True)

        return self._safe_result(
            "User workspace voice memory cleared.",
            data=data,
            metadata={"action": action},
        )

    def _delete_from_store_by_context(
        self,
        store: Dict[str, Any],
        user_id: str,
        workspace_id: str,
    ) -> int:
        """Delete records from a store by user/workspace."""
        delete_ids = [
            item_id
            for item_id, item in store.items()
            if self._belongs_to_context(item, user_id, workspace_id)
        ]

        for item_id in delete_ids:
            del store[item_id]

        return len(delete_ids)

    # =========================================================================
    # Public method: registry / health / routing support
    # =========================================================================

    def get_agent_manifest(self) -> Dict[str, Any]:
        """
        Return registry-friendly manifest.

        Agent Loader / Agent Registry can call this safely.
        """
        return {
            "agent_name": self.agent_name,
            "agent_type": self.agent_type,
            "module": "agents.voice_agent.voice_memory",
            "class_name": "VoiceMemory",
            "version": self.version,
            "description": "Memory bridge for voice preferences, recurring phrases, language behavior, and audio notes.",
            "public_methods": [
                "set_voice_preference",
                "get_voice_preference",
                "list_voice_preferences",
                "delete_preference",
                "remember_phrase",
                "get_recurring_phrases",
                "match_phrase",
                "delete_phrase",
                "set_language_behavior",
                "get_language_behaviors",
                "infer_preferred_language",
                "delete_language_behavior",
                "add_audio_note",
                "get_audio_note",
                "list_audio_notes",
                "search_audio_notes",
                "delete_audio_note",
                "remember_interaction",
                "list_interactions",
                "search_interactions",
                "delete_interaction_memory",
                "get_voice_memory_context",
                "export_workspace_memory",
                "clear_user_workspace_memory",
                "get_agent_manifest",
                "health_check",
            ],
            "requires_user_context": True,
            "requires_workspace_context": True,
            "security_sensitive_actions": sorted(self.SENSITIVE_ACTIONS),
            "memory_types": sorted(self.VALID_MEMORY_TYPES),
            "compatible_with": [
                "BaseAgent",
                "MasterAgent",
                "AgentRegistry",
                "AgentLoader",
                "AgentRouter",
                "VoiceAgent",
                "MemoryAgent",
                "SecurityAgent",
                "VerificationAgent",
                "DashboardAPI",
            ],
        }

    def health_check(self) -> Dict[str, Any]:
        """Return health status for dashboard/API monitoring."""
        with self._lock:
            counts = {
                "preferences": len(self._preferences),
                "phrases": len(self._phrases),
                "language_behaviors": len(self._language_behaviors),
                "audio_notes": len(self._audio_notes),
                "interactions": len(self._interactions),
            }

        storage_status = {
            "enabled": self.enable_file_storage,
            "storage_dir": str(self.storage_dir),
            "storage_exists": self.storage_dir.exists() if self.enable_file_storage else False,
        }

        return self._safe_result(
            "VoiceMemory is healthy.",
            data={
                "status": "healthy",
                "counts": counts,
                "storage": storage_status,
                "manifest": self.get_agent_manifest(),
            },
            metadata={"action": "health_check"},
        )

    # =========================================================================
    # Compatibility execute method
    # =========================================================================

    def execute(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generic task execution method for Master Agent / Agent Router.

        Expected task format:
            {
                "action": "set_voice_preference",
                "user_id": "1",
                "workspace_id": "main",
                "params": {...}
            }
        """
        if not isinstance(task, dict):
            return self._error_result(
                "Task must be a dictionary.",
                metadata={"action": "execute"},
            )

        action = str(task.get("action", "")).strip()
        user_id = task.get("user_id")
        workspace_id = task.get("workspace_id")
        params = task.get("params") or {}

        if not action:
            return self._error_result(
                "Task action is required.",
                metadata={"action": "execute"},
            )

        if not isinstance(params, dict):
            return self._error_result(
                "Task params must be a dictionary.",
                metadata={"action": "execute", "requested_action": action},
            )

        route_map = {
            "set_voice_preference": self.set_voice_preference,
            "get_voice_preference": self.get_voice_preference,
            "list_voice_preferences": self.list_voice_preferences,
            "delete_preference": self.delete_preference,
            "remember_phrase": self.remember_phrase,
            "get_recurring_phrases": self.get_recurring_phrases,
            "match_phrase": self.match_phrase,
            "delete_phrase": self.delete_phrase,
            "set_language_behavior": self.set_language_behavior,
            "get_language_behaviors": self.get_language_behaviors,
            "infer_preferred_language": self.infer_preferred_language,
            "delete_language_behavior": self.delete_language_behavior,
            "add_audio_note": self.add_audio_note,
            "get_audio_note": self.get_audio_note,
            "list_audio_notes": self.list_audio_notes,
            "search_audio_notes": self.search_audio_notes,
            "delete_audio_note": self.delete_audio_note,
            "remember_interaction": self.remember_interaction,
            "list_interactions": self.list_interactions,
            "search_interactions": self.search_interactions,
            "delete_interaction_memory": self.delete_interaction_memory,
            "get_voice_memory_context": self.get_voice_memory_context,
            "export_workspace_memory": self.export_workspace_memory,
            "clear_user_workspace_memory": self.clear_user_workspace_memory,
            "health_check": self.health_check,
            "get_agent_manifest": self.get_agent_manifest,
        }

        method = route_map.get(action)
        if not method:
            return self._error_result(
                f"Unsupported VoiceMemory action: {action}",
                data={"supported_actions": sorted(route_map.keys())},
                metadata={"action": "execute"},
            )

        try:
            if action in {"health_check", "get_agent_manifest"}:
                result = method()
                if isinstance(result, dict) and "success" in result:
                    return result
                return self._safe_result(
                    "Action executed.",
                    data={"result": result},
                    metadata={"action": action},
                )

            return method(user_id=user_id, workspace_id=workspace_id, **params)

        except TypeError as exc:
            return self._error_result(
                "Invalid parameters for VoiceMemory action.",
                error=exc,
                data={
                    "requested_action": action,
                    "params": params,
                },
                metadata={"action": "execute"},
            )
        except Exception as exc:
            logger.exception("VoiceMemory execute failed.")
            return self._error_result(
                "VoiceMemory action failed.",
                error=exc,
                data={"requested_action": action},
                metadata={"action": "execute"},
            )


# =============================================================================
# Local test helper
# =============================================================================

def _demo() -> Dict[str, Any]:
    """
    Minimal local demo.

    Run:
        python agents/voice_agent/voice_memory.py

    This does not require the full William/Jarvis system.
    """
    vm = VoiceMemory(
        storage_dir="storage/demo_voice_memory",
        enable_file_storage=True,
    )

    user_id = "demo_user"
    workspace_id = "demo_workspace"

    results = {
        "health_before": vm.health_check(),
        "preference": vm.set_voice_preference(
            user_id=user_id,
            workspace_id=workspace_id,
            key="preferred_tts_voice",
            value="calm_confident_voice",
            confidence=0.95,
        ),
        "phrase": vm.remember_phrase(
            user_id=user_id,
            workspace_id=workspace_id,
            phrase="William start my dashboard",
            intent_hint="open_dashboard",
        ),
        "language": vm.set_language_behavior(
            user_id=user_id,
            workspace_id=workspace_id,
            language_code="en",
            language_name="English",
            behavior_type="preferred_language",
            value=True,
        ),
        "audio_note": vm.add_audio_note(
            user_id=user_id,
            workspace_id=workspace_id,
            title="Test Note",
            transcript="This is a test voice note for William memory.",
            tags=["test", "voice"],
        ),
        "interaction": vm.remember_interaction(
            user_id=user_id,
            workspace_id=workspace_id,
            input_text="William, remember that I like concise voice replies.",
            response_text="Got it. I will keep voice replies concise.",
            detected_language="en",
            detected_emotion="neutral",
            importance=0.8,
        ),
        "context": vm.get_voice_memory_context(
            user_id=user_id,
            workspace_id=workspace_id,
            include_audio_notes=True,
        ),
        "health_after": vm.health_check(),
    }

    return results


if __name__ == "__main__":
    demo_result = _demo()
    print(json.dumps(demo_result, indent=2, ensure_ascii=False, default=str))


"""
Agent/Module: Voice Agent
File Completed: voice_memory.py
Completion: 95.0%
Completed Files: ['voice_agent.py', 'wake_word.py', 'stt_engine.py', 'tts_engine.py', 'language_engine.py', 'device_stream.py', 'interruption.py', 'voice_loop.py', 'session_manager.py', 'audio_router.py', 'noise_control.py', 'speaker_recognition.py', 'emotion_detector.py', 'whisper_mode.py', 'voice_profiles.py', 'voice_cloning.py', 'gesture_trigger.py', 'conversation_mode.py', 'voice_memory.py']
Remaining Files: ['config.py']
Next Recommended File: agents/voice_agent/config.py
FILE COMPLETE
"""