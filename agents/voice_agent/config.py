"""
agents/voice_agent/config.py

VoiceConfig for William / Jarvis Multi-Agent AI SaaS System by Digital Promotix.

Purpose:
    Voice Agent settings, languages, wake word, engine choices, audio defaults,
    privacy flags, SaaS user/workspace overrides, and registry-safe configuration.

Architecture Compatibility:
    - Master Agent routing
    - BaseAgent compatibility
    - Agent Registry / Agent Loader safe imports
    - Security Agent approval hooks
    - Memory Agent payload preparation
    - Verification Agent payload preparation
    - Dashboard / API structured outputs
    - SaaS user/workspace isolation

Important:
    This file is import-safe. If the larger William/Jarvis system modules are
    not created yet, this file still works using fallback classes.
"""

from __future__ import annotations

import json
import logging
import os
import re
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

        Keeps this file import-safe until the real William/Jarvis BaseAgent exists.
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

        Default behavior allows safe local config actions.
        Sensitive actions still pass through this interface.
        """

        def check_permission(self, payload: Dict[str, Any]) -> Dict[str, Any]:
            return {
                "success": True,
                "message": "Fallback security approval granted for safe local config action.",
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

logger = logging.getLogger("william.voice_agent.config")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)


# =============================================================================
# Data structures
# =============================================================================

@dataclass
class EngineConfig:
    """
    STT/TTS/wake-word/noise/emotion engine configuration.

    This does not contain secrets.
    Secret API keys should come from environment variables or secure vaults.
    """

    engine_id: str
    engine_type: str
    provider: str
    model: Optional[str] = None
    enabled: bool = True
    priority: int = 100
    local_only: bool = False
    requires_network: bool = False
    supports_streaming: bool = False
    supports_realtime: bool = False
    supported_languages: List[str] = field(default_factory=list)
    options: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LanguageConfig:
    """
    Language configuration for voice input/output behavior.
    """

    language_code: str
    language_name: str
    enabled: bool = True
    default_voice: Optional[str] = None
    stt_supported: bool = True
    tts_supported: bool = True
    auto_detect_supported: bool = True
    romanized_supported: bool = False
    fallback_language_code: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PrivacyConfig:
    """
    Privacy flags for voice behavior.

    These settings are critical for SaaS trust and user/workspace isolation.
    """

    local_processing_preferred: bool = True
    allow_cloud_stt: bool = False
    allow_cloud_tts: bool = False
    allow_voice_storage: bool = False
    allow_audio_note_storage: bool = False
    allow_speaker_recognition: bool = False
    allow_voice_cloning: bool = False
    allow_emotion_detection: bool = True
    redact_sensitive_transcripts: bool = True
    store_raw_audio: bool = False
    store_transcripts: bool = True
    share_with_memory_agent: bool = True
    require_security_for_voice_clone: bool = True
    require_security_for_raw_audio_export: bool = True
    data_retention_days: int = 30
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WakeWordConfig:
    """
    Wake word configuration.

    William/Jarvis can support multiple wake words in the future.
    """

    primary_wake_word: str = "William"
    aliases: List[str] = field(default_factory=lambda: ["Jarvis", "Hey William"])
    enabled: bool = True
    sensitivity: float = 0.65
    cooldown_seconds: float = 1.5
    require_confirmation: bool = False
    allow_custom_wake_words: bool = True
    custom_wake_words: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AudioBehaviorConfig:
    """
    General microphone/speaker/audio behavior.
    """

    input_sample_rate: int = 16000
    output_sample_rate: int = 24000
    channels: int = 1
    chunk_ms: int = 30
    max_record_seconds: int = 120
    silence_timeout_seconds: float = 2.5
    interruption_enabled: bool = True
    barge_in_enabled: bool = True
    noise_suppression_enabled: bool = True
    echo_cancellation_enabled: bool = True
    auto_gain_control_enabled: bool = True
    whisper_mode_enabled: bool = False
    conversation_mode_enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VoiceAgentSettings:
    """
    Complete Voice Agent settings for a user/workspace context.
    """

    user_id: str
    workspace_id: str
    wake_word: WakeWordConfig = field(default_factory=WakeWordConfig)
    audio_behavior: AudioBehaviorConfig = field(default_factory=AudioBehaviorConfig)
    privacy: PrivacyConfig = field(default_factory=PrivacyConfig)
    default_language_code: str = "en"
    fallback_language_code: str = "en"
    default_stt_engine_id: str = "local_whisper"
    default_tts_engine_id: str = "local_tts"
    default_wake_engine_id: str = "local_wake_word"
    default_noise_engine_id: str = "local_noise_control"
    default_emotion_engine_id: str = "local_emotion_detector"
    dashboard_visible: bool = True
    agent_enabled: bool = True
    created_at: str = field(default_factory=lambda: VoiceConfig.utcnow())
    updated_at: str = field(default_factory=lambda: VoiceConfig.utcnow())
    metadata: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Main class
# =============================================================================

class VoiceConfig(BaseAgent):
    """
    Central Voice Agent configuration manager.

    Responsibilities:
        - Manage global/default voice settings.
        - Manage SaaS user/workspace-specific voice settings.
        - Manage supported languages.
        - Manage STT/TTS/wake-word/noise/emotion engine choices.
        - Manage privacy flags.
        - Provide structured dict/JSON style results.
        - Prepare Memory Agent and Verification Agent payloads.
        - Emit dashboard/agent events.
        - Log audit records.
        - Stay import-safe while the wider system is still being built.
    """

    DEFAULT_CONFIG_DIR = Path("storage/voice_config")

    SENSITIVE_ACTIONS = {
        "set_privacy_config",
        "set_voice_cloning_allowed",
        "set_raw_audio_storage_allowed",
        "export_workspace_config",
        "reset_workspace_config",
        "delete_workspace_config",
    }

    VALID_ENGINE_TYPES = {
        "stt",
        "tts",
        "wake_word",
        "noise_control",
        "speaker_recognition",
        "emotion_detection",
        "voice_cloning",
        "language_detection",
        "audio_router",
    }

    DEFAULT_SUPPORTED_LANGUAGES = [
        LanguageConfig("en", "English", default_voice="default_english", romanized_supported=False),
        LanguageConfig("ur", "Urdu", default_voice="default_urdu", romanized_supported=True, fallback_language_code="en"),
        LanguageConfig("hi", "Hindi", default_voice="default_hindi", romanized_supported=True, fallback_language_code="en"),
        LanguageConfig("ar", "Arabic", default_voice="default_arabic", romanized_supported=True, fallback_language_code="en"),
        LanguageConfig("es", "Spanish", default_voice="default_spanish", fallback_language_code="en"),
        LanguageConfig("fr", "French", default_voice="default_french", fallback_language_code="en"),
        LanguageConfig("de", "German", default_voice="default_german", fallback_language_code="en"),
        LanguageConfig("it", "Italian", default_voice="default_italian", fallback_language_code="en"),
        LanguageConfig("pt", "Portuguese", default_voice="default_portuguese", fallback_language_code="en"),
        LanguageConfig("zh", "Chinese", default_voice="default_chinese", fallback_language_code="en"),
        LanguageConfig("ja", "Japanese", default_voice="default_japanese", fallback_language_code="en"),
        LanguageConfig("ko", "Korean", default_voice="default_korean", fallback_language_code="en"),
    ]

    DEFAULT_ENGINES = [
        EngineConfig(
            engine_id="local_whisper",
            engine_type="stt",
            provider="local",
            model="whisper-base",
            enabled=True,
            priority=10,
            local_only=True,
            requires_network=False,
            supports_streaming=True,
            supports_realtime=True,
            supported_languages=["en", "ur", "hi", "ar", "es", "fr", "de", "it", "pt", "zh", "ja", "ko"],
            options={
                "temperature": 0.0,
                "vad_enabled": True,
                "safe_fallback": True,
            },
        ),
        EngineConfig(
            engine_id="cloud_stt",
            engine_type="stt",
            provider="cloud",
            model=None,
            enabled=False,
            priority=50,
            local_only=False,
            requires_network=True,
            supports_streaming=True,
            supports_realtime=True,
            supported_languages=["en", "ur", "hi", "ar", "es", "fr", "de"],
            options={
                "requires_privacy_allow_cloud_stt": True,
            },
        ),
        EngineConfig(
            engine_id="local_tts",
            engine_type="tts",
            provider="local",
            model="local-default-tts",
            enabled=True,
            priority=10,
            local_only=True,
            requires_network=False,
            supports_streaming=True,
            supports_realtime=True,
            supported_languages=["en"],
            options={
                "voice_style": "calm",
                "speed": 1.0,
            },
        ),
        EngineConfig(
            engine_id="cloud_tts",
            engine_type="tts",
            provider="cloud",
            model=None,
            enabled=False,
            priority=50,
            local_only=False,
            requires_network=True,
            supports_streaming=True,
            supports_realtime=True,
            supported_languages=["en", "ur", "hi", "ar", "es", "fr", "de"],
            options={
                "requires_privacy_allow_cloud_tts": True,
            },
        ),
        EngineConfig(
            engine_id="local_wake_word",
            engine_type="wake_word",
            provider="local",
            model="wake-word-default",
            enabled=True,
            priority=10,
            local_only=True,
            requires_network=False,
            supports_streaming=True,
            supports_realtime=True,
            supported_languages=["en"],
            options={
                "wake_word": "William",
                "sensitivity": 0.65,
            },
        ),
        EngineConfig(
            engine_id="local_noise_control",
            engine_type="noise_control",
            provider="local",
            model="noise-control-default",
            enabled=True,
            priority=10,
            local_only=True,
            requires_network=False,
            supports_streaming=True,
            supports_realtime=True,
            supported_languages=[],
            options={
                "noise_suppression": True,
                "echo_cancellation": True,
                "auto_gain_control": True,
            },
        ),
        EngineConfig(
            engine_id="local_emotion_detector",
            engine_type="emotion_detection",
            provider="local",
            model="emotion-default",
            enabled=True,
            priority=20,
            local_only=True,
            requires_network=False,
            supports_streaming=False,
            supports_realtime=True,
            supported_languages=["en"],
            options={
                "safe_mode": True,
                "non_diagnostic": True,
            },
        ),
        EngineConfig(
            engine_id="local_speaker_recognition",
            engine_type="speaker_recognition",
            provider="local",
            model="speaker-recognition-default",
            enabled=False,
            priority=30,
            local_only=True,
            requires_network=False,
            supports_streaming=True,
            supports_realtime=True,
            supported_languages=[],
            options={
                "requires_privacy_allow_speaker_recognition": True,
            },
        ),
        EngineConfig(
            engine_id="local_voice_cloning",
            engine_type="voice_cloning",
            provider="local",
            model="voice-cloning-default",
            enabled=False,
            priority=90,
            local_only=True,
            requires_network=False,
            supports_streaming=False,
            supports_realtime=False,
            supported_languages=["en"],
            options={
                "requires_security_approval": True,
                "requires_explicit_consent": True,
            },
        ),
    ]

    def __init__(
        self,
        config_dir: Optional[Union[str, Path]] = None,
        security_agent: Optional[Any] = None,
        event_emitter: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        enable_file_storage: bool = True,
        agent_name: str = "VoiceConfig",
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

        self.config_dir = Path(config_dir) if config_dir else self.DEFAULT_CONFIG_DIR
        self.enable_file_storage = enable_file_storage

        self.security_agent = security_agent or SecurityAgent()
        self.event_emitter = event_emitter or AgentEventEmitter()
        self.audit_logger = audit_logger or AuditLogger()

        self._lock = RLock()

        self._languages: Dict[str, LanguageConfig] = {
            item.language_code: deepcopy(item)
            for item in self.DEFAULT_SUPPORTED_LANGUAGES
        }

        self._engines: Dict[str, EngineConfig] = {
            item.engine_id: deepcopy(item)
            for item in self.DEFAULT_ENGINES
        }

        self._workspace_settings: Dict[str, VoiceAgentSettings] = {}

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
        """Create a stable unique ID."""
        safe_prefix = re.sub(r"[^a-zA-Z0-9_]", "_", prefix).strip("_") or "id"
        return f"{safe_prefix}_{uuid.uuid4().hex}"

    @staticmethod
    def clamp_float(value: Any, minimum: float, maximum: float, default: float) -> float:
        """Safely clamp float values."""
        try:
            number = float(value)
        except Exception:
            number = default
        return max(minimum, min(maximum, number))

    @staticmethod
    def clamp_int(value: Any, minimum: int, maximum: int, default: int) -> int:
        """Safely clamp integer values."""
        try:
            number = int(value)
        except Exception:
            number = default
        return max(minimum, min(maximum, number))

    @staticmethod
    def normalize_key(value: Any) -> str:
        """Normalize a user/workspace/config key."""
        return str(value).strip()

    @staticmethod
    def normalize_language_code(value: Any) -> str:
        """Normalize language code."""
        return str(value).strip().lower()

    @staticmethod
    def normalize_engine_type(value: Any) -> str:
        """Normalize engine type."""
        return str(value).strip().lower()

    # =========================================================================
    # Storage helpers
    # =========================================================================

    def _ensure_storage(self) -> None:
        """Create config storage folder."""
        try:
            self.config_dir.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            logger.warning("Could not create VoiceConfig storage directory: %s", exc)

    def _storage_file(self, name: str) -> Path:
        """Return storage file path."""
        return self.config_dir / f"{name}.json"

    def _safe_load_json(self, path: Path) -> Dict[str, Any]:
        """Safely load JSON dictionary."""
        if not path.exists():
            return {}
        try:
            with path.open("r", encoding="utf-8") as file:
                data = json.load(file)
            return data if isinstance(data, dict) else {}
        except Exception as exc:
            logger.warning("VoiceConfig failed to load JSON from %s: %s", path, exc)
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
            logger.warning("VoiceConfig failed to write JSON to %s: %s", path, exc)

    def _load_all_from_disk(self) -> None:
        """Load config stores from disk."""
        with self._lock:
            self._languages.update(
                self._load_dataclass_store(
                    "languages",
                    LanguageConfig,
                    key_field="language_code",
                )
            )

            self._engines.update(
                self._load_dataclass_store(
                    "engines",
                    EngineConfig,
                    key_field="engine_id",
                )
            )

            self._workspace_settings = self._load_workspace_settings()

    def _load_dataclass_store(
        self,
        store_name: str,
        cls: Any,
        key_field: str,
    ) -> Dict[str, Any]:
        """Load dataclass records from disk."""
        raw = self._safe_load_json(self._storage_file(store_name))
        result: Dict[str, Any] = {}

        for item_key, item_data in raw.items():
            if not isinstance(item_data, dict):
                continue
            try:
                item = cls(**item_data)
                result[str(getattr(item, key_field, item_key))] = item
            except Exception as exc:
                logger.warning(
                    "Skipping invalid VoiceConfig %s record %s: %s",
                    store_name,
                    item_key,
                    exc,
                )

        return result

    def _load_workspace_settings(self) -> Dict[str, VoiceAgentSettings]:
        """Load workspace settings from disk."""
        raw = self._safe_load_json(self._storage_file("workspace_settings"))
        result: Dict[str, VoiceAgentSettings] = {}

        for item_key, item_data in raw.items():
            if not isinstance(item_data, dict):
                continue

            try:
                wake_word_data = item_data.get("wake_word", {})
                audio_behavior_data = item_data.get("audio_behavior", {})
                privacy_data = item_data.get("privacy", {})

                item_data["wake_word"] = WakeWordConfig(**wake_word_data)
                item_data["audio_behavior"] = AudioBehaviorConfig(**audio_behavior_data)
                item_data["privacy"] = PrivacyConfig(**privacy_data)

                settings = VoiceAgentSettings(**item_data)
                result[self._context_key(settings.user_id, settings.workspace_id)] = settings
            except Exception as exc:
                logger.warning(
                    "Skipping invalid workspace settings %s: %s",
                    item_key,
                    exc,
                )

        return result

    def _persist_store(self, store_name: str, store: Dict[str, Any]) -> None:
        """Persist a dataclass store."""
        if not self.enable_file_storage:
            return

        serializable: Dict[str, Any] = {}
        for item_key, item in store.items():
            if hasattr(item, "__dataclass_fields__"):
                serializable[item_key] = asdict(item)
            elif isinstance(item, dict):
                serializable[item_key] = deepcopy(item)

        self._safe_write_json(self._storage_file(store_name), serializable)

    def _persist_all(self) -> None:
        """Persist all config stores."""
        self._persist_store("languages", self._languages)
        self._persist_store("engines", self._engines)
        self._persist_store("workspace_settings", self._workspace_settings)

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
        action: str = "voice_config_action",
    ) -> Dict[str, Any]:
        """
        Validate SaaS user/workspace context.

        Every user-specific config action must include user_id and workspace_id.
        """
        if user_id is None or str(user_id).strip() == "":
            return self._error_result(
                "Missing user_id. Voice config cannot run without SaaS user isolation.",
                metadata={"action": action},
            )

        if workspace_id is None or str(workspace_id).strip() == "":
            return self._error_result(
                "Missing workspace_id. Voice config cannot run without workspace isolation.",
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
        """Return whether action requires Security Agent approval."""
        return action in self.SENSITIVE_ACTIONS

    def _request_security_approval(
        self,
        action: str,
        user_id: str,
        workspace_id: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Request approval from Security Agent."""
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
                data={
                    "approved": True,
                    "security_result": result,
                },
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

        Verification Agent can confirm config integrity after changes.
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
                "config_action_completed": True,
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
        Prepare Memory Agent-compatible payload.

        Useful when config changes should become remembered preferences.
        """
        return {
            "memory_payload_id": self.new_id("memory_payload"),
            "source_agent": self.agent_name,
            "source_agent_type": self.agent_type,
            "memory_type": memory_type,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "importance": self.clamp_float(importance, 0.0, 1.0, 0.5),
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
        """Emit dashboard/API-friendly agent event."""
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
            logger.warning("VoiceConfig event emit failed: %s", exc)

    def _log_audit_event(
        self,
        action: str,
        user_id: str,
        workspace_id: str,
        payload: Optional[Dict[str, Any]] = None,
        success: bool = True,
    ) -> None:
        """Log audit record for dashboard/security/task history."""
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
            logger.warning("VoiceConfig audit log failed: %s", exc)

    def _preflight(
        self,
        action: str,
        user_id: Any,
        workspace_id: Any,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, Dict[str, Any], str, str]:
        """Common context validation and security approval."""
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
    # Serialization helpers
    # =========================================================================

    def _dataclass_to_dict(self, item: Any) -> Dict[str, Any]:
        """Convert dataclass/dict to dictionary."""
        if hasattr(item, "__dataclass_fields__"):
            return asdict(item)
        if isinstance(item, dict):
            return deepcopy(item)
        return {"value": item}

    def _context_key(self, user_id: Any, workspace_id: Any) -> str:
        """Create strict SaaS isolation key."""
        return f"{str(user_id).strip()}::{str(workspace_id).strip()}"

    # =========================================================================
    # Workspace config methods
    # =========================================================================

    def get_or_create_workspace_config(
        self,
        user_id: Any,
        workspace_id: Any,
    ) -> Dict[str, Any]:
        """Get or create workspace-specific Voice Agent settings."""
        action = "get_or_create_workspace_config"
        allowed, result, safe_user_id, safe_workspace_id = self._preflight(
            action,
            user_id,
            workspace_id,
        )
        if not allowed:
            return result

        key = self._context_key(safe_user_id, safe_workspace_id)

        with self._lock:
            if key not in self._workspace_settings:
                self._workspace_settings[key] = VoiceAgentSettings(
                    user_id=safe_user_id,
                    workspace_id=safe_workspace_id,
                )
                self._persist_store("workspace_settings", self._workspace_settings)

            settings = self._workspace_settings[key]

        return self._safe_result(
            "Workspace voice config loaded.",
            data={
                "config": self._dataclass_to_dict(settings),
                "created": key not in self._workspace_settings,
            },
            metadata={"action": action},
        )

    def update_workspace_config(
        self,
        user_id: Any,
        workspace_id: Any,
        updates: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Update workspace-level Voice Agent settings.

        This method updates safe non-sensitive fields.
        Privacy-specific updates should use set_privacy_config().
        """
        action = "update_workspace_config"
        allowed, result, safe_user_id, safe_workspace_id = self._preflight(
            action,
            user_id,
            workspace_id,
            {"updates": updates},
        )
        if not allowed:
            return result

        if not isinstance(updates, dict):
            return self._error_result(
                "updates must be a dictionary.",
                metadata={"action": action},
            )

        blocked_fields = {"privacy", "user_id", "workspace_id", "created_at"}
        clean_updates = {
            key: value
            for key, value in updates.items()
            if key not in blocked_fields
        }

        key = self._context_key(safe_user_id, safe_workspace_id)

        with self._lock:
            if key not in self._workspace_settings:
                self._workspace_settings[key] = VoiceAgentSettings(
                    user_id=safe_user_id,
                    workspace_id=safe_workspace_id,
                )

            settings = self._workspace_settings[key]

            for update_key, update_value in clean_updates.items():
                if hasattr(settings, update_key):
                    setattr(settings, update_key, update_value)

            settings.updated_at = self.utcnow()
            self._persist_store("workspace_settings", self._workspace_settings)

        data = {
            "config": self._dataclass_to_dict(settings),
            "applied_updates": clean_updates,
            "blocked_fields": sorted(blocked_fields.intersection(updates.keys())),
            "memory_payload": self._prepare_memory_payload(
                memory_type="voice_config_update",
                user_id=safe_user_id,
                workspace_id=safe_workspace_id,
                content={
                    "applied_updates": clean_updates,
                },
                importance=0.4,
            ),
            "verification_payload": self._prepare_verification_payload(
                action,
                safe_user_id,
                safe_workspace_id,
                {"applied_updates": clean_updates},
            ),
        }

        self._emit_agent_event(action, safe_user_id, safe_workspace_id, data)
        self._log_audit_event(action, safe_user_id, safe_workspace_id, data, True)

        return self._safe_result(
            "Workspace voice config updated.",
            data=data,
            metadata={"action": action},
        )

    def reset_workspace_config(
        self,
        user_id: Any,
        workspace_id: Any,
    ) -> Dict[str, Any]:
        """Reset workspace config to safe defaults."""
        action = "reset_workspace_config"
        allowed, result, safe_user_id, safe_workspace_id = self._preflight(
            action,
            user_id,
            workspace_id,
        )
        if not allowed:
            return result

        key = self._context_key(safe_user_id, safe_workspace_id)

        with self._lock:
            self._workspace_settings[key] = VoiceAgentSettings(
                user_id=safe_user_id,
                workspace_id=safe_workspace_id,
            )
            self._persist_store("workspace_settings", self._workspace_settings)
            settings = self._workspace_settings[key]

        data = {
            "config": self._dataclass_to_dict(settings),
            "verification_payload": self._prepare_verification_payload(
                action,
                safe_user_id,
                safe_workspace_id,
                {"reset": True},
            ),
        }

        self._emit_agent_event(action, safe_user_id, safe_workspace_id, data)
        self._log_audit_event(action, safe_user_id, safe_workspace_id, data, True)

        return self._safe_result(
            "Workspace voice config reset.",
            data=data,
            metadata={"action": action},
        )

    def delete_workspace_config(
        self,
        user_id: Any,
        workspace_id: Any,
    ) -> Dict[str, Any]:
        """Delete workspace-specific Voice Agent config."""
        action = "delete_workspace_config"
        allowed, result, safe_user_id, safe_workspace_id = self._preflight(
            action,
            user_id,
            workspace_id,
        )
        if not allowed:
            return result

        key = self._context_key(safe_user_id, safe_workspace_id)

        with self._lock:
            deleted = self._workspace_settings.pop(key, None)
            self._persist_store("workspace_settings", self._workspace_settings)

        data = {
            "deleted": deleted is not None,
            "config": self._dataclass_to_dict(deleted) if deleted else None,
            "verification_payload": self._prepare_verification_payload(
                action,
                safe_user_id,
                safe_workspace_id,
                {"deleted": deleted is not None},
            ),
        }

        self._emit_agent_event(action, safe_user_id, safe_workspace_id, data)
        self._log_audit_event(action, safe_user_id, safe_workspace_id, data, True)

        return self._safe_result(
            "Workspace voice config deletion completed.",
            data=data,
            metadata={"action": action},
        )

    # =========================================================================
    # Wake word config
    # =========================================================================

    def set_wake_word_config(
        self,
        user_id: Any,
        workspace_id: Any,
        wake_word_config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Update wake word settings for one user/workspace."""
        action = "set_wake_word_config"
        allowed, result, safe_user_id, safe_workspace_id = self._preflight(
            action,
            user_id,
            workspace_id,
            {"wake_word_config": wake_word_config},
        )
        if not allowed:
            return result

        if not isinstance(wake_word_config, dict):
            return self._error_result(
                "wake_word_config must be a dictionary.",
                metadata={"action": action},
            )

        key = self._context_key(safe_user_id, safe_workspace_id)

        with self._lock:
            if key not in self._workspace_settings:
                self._workspace_settings[key] = VoiceAgentSettings(
                    user_id=safe_user_id,
                    workspace_id=safe_workspace_id,
                )

            current = self._workspace_settings[key].wake_word
            current_dict = asdict(current)
            current_dict.update(wake_word_config)

            current_dict["sensitivity"] = self.clamp_float(
                current_dict.get("sensitivity"),
                0.0,
                1.0,
                0.65,
            )

            current_dict["cooldown_seconds"] = self.clamp_float(
                current_dict.get("cooldown_seconds"),
                0.1,
                30.0,
                1.5,
            )

            current_dict["primary_wake_word"] = str(
                current_dict.get("primary_wake_word") or "William"
            ).strip()

            aliases = current_dict.get("aliases") or []
            custom = current_dict.get("custom_wake_words") or []

            current_dict["aliases"] = [
                str(item).strip()
                for item in aliases
                if str(item).strip()
            ]

            current_dict["custom_wake_words"] = [
                str(item).strip()
                for item in custom
                if str(item).strip()
            ]

            self._workspace_settings[key].wake_word = WakeWordConfig(**current_dict)
            self._workspace_settings[key].updated_at = self.utcnow()
            self._persist_store("workspace_settings", self._workspace_settings)

            settings = self._workspace_settings[key]

        data = {
            "wake_word": self._dataclass_to_dict(settings.wake_word),
            "memory_payload": self._prepare_memory_payload(
                memory_type="voice_wake_word_config",
                user_id=safe_user_id,
                workspace_id=safe_workspace_id,
                content=self._dataclass_to_dict(settings.wake_word),
                importance=0.6,
            ),
            "verification_payload": self._prepare_verification_payload(
                action,
                safe_user_id,
                safe_workspace_id,
                {"wake_word_updated": True},
            ),
        }

        self._emit_agent_event(action, safe_user_id, safe_workspace_id, data)
        self._log_audit_event(action, safe_user_id, safe_workspace_id, data, True)

        return self._safe_result(
            "Wake word config updated.",
            data=data,
            metadata={"action": action},
        )

    def get_wake_words(
        self,
        user_id: Any,
        workspace_id: Any,
    ) -> Dict[str, Any]:
        """Return all active wake words for one user/workspace."""
        action = "get_wake_words"
        config_result = self.get_or_create_workspace_config(user_id, workspace_id)
        if not config_result["success"]:
            return config_result

        config = config_result["data"]["config"]
        wake = config.get("wake_word", {})

        wake_words = []
        primary = wake.get("primary_wake_word")
        if primary:
            wake_words.append(primary)

        wake_words.extend(wake.get("aliases") or [])
        wake_words.extend(wake.get("custom_wake_words") or [])

        unique = []
        seen = set()
        for item in wake_words:
            normalized = item.strip().lower()
            if normalized and normalized not in seen:
                seen.add(normalized)
                unique.append(item.strip())

        return self._safe_result(
            "Wake words loaded.",
            data={
                "wake_words": unique,
                "enabled": bool(wake.get("enabled", True)),
                "sensitivity": wake.get("sensitivity", 0.65),
                "cooldown_seconds": wake.get("cooldown_seconds", 1.5),
            },
            metadata={"action": action},
        )

    # =========================================================================
    # Audio behavior config
    # =========================================================================

    def set_audio_behavior_config(
        self,
        user_id: Any,
        workspace_id: Any,
        audio_behavior_config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Update microphone/speaker/audio behavior settings."""
        action = "set_audio_behavior_config"
        allowed, result, safe_user_id, safe_workspace_id = self._preflight(
            action,
            user_id,
            workspace_id,
            {"audio_behavior_config": audio_behavior_config},
        )
        if not allowed:
            return result

        if not isinstance(audio_behavior_config, dict):
            return self._error_result(
                "audio_behavior_config must be a dictionary.",
                metadata={"action": action},
            )

        key = self._context_key(safe_user_id, safe_workspace_id)

        with self._lock:
            if key not in self._workspace_settings:
                self._workspace_settings[key] = VoiceAgentSettings(
                    user_id=safe_user_id,
                    workspace_id=safe_workspace_id,
                )

            current = self._workspace_settings[key].audio_behavior
            current_dict = asdict(current)
            current_dict.update(audio_behavior_config)

            current_dict["input_sample_rate"] = self.clamp_int(
                current_dict.get("input_sample_rate"),
                8000,
                192000,
                16000,
            )

            current_dict["output_sample_rate"] = self.clamp_int(
                current_dict.get("output_sample_rate"),
                8000,
                192000,
                24000,
            )

            current_dict["channels"] = self.clamp_int(
                current_dict.get("channels"),
                1,
                8,
                1,
            )

            current_dict["chunk_ms"] = self.clamp_int(
                current_dict.get("chunk_ms"),
                10,
                1000,
                30,
            )

            current_dict["max_record_seconds"] = self.clamp_int(
                current_dict.get("max_record_seconds"),
                1,
                3600,
                120,
            )

            current_dict["silence_timeout_seconds"] = self.clamp_float(
                current_dict.get("silence_timeout_seconds"),
                0.1,
                60.0,
                2.5,
            )

            self._workspace_settings[key].audio_behavior = AudioBehaviorConfig(**current_dict)
            self._workspace_settings[key].updated_at = self.utcnow()
            self._persist_store("workspace_settings", self._workspace_settings)

            settings = self._workspace_settings[key]

        data = {
            "audio_behavior": self._dataclass_to_dict(settings.audio_behavior),
            "verification_payload": self._prepare_verification_payload(
                action,
                safe_user_id,
                safe_workspace_id,
                {"audio_behavior_updated": True},
            ),
        }

        self._emit_agent_event(action, safe_user_id, safe_workspace_id, data)
        self._log_audit_event(action, safe_user_id, safe_workspace_id, data, True)

        return self._safe_result(
            "Audio behavior config updated.",
            data=data,
            metadata={"action": action},
        )

    # =========================================================================
    # Privacy config
    # =========================================================================

    def set_privacy_config(
        self,
        user_id: Any,
        workspace_id: Any,
        privacy_config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Update privacy settings.

        Sensitive action. Goes through Security Agent.
        """
        action = "set_privacy_config"
        allowed, result, safe_user_id, safe_workspace_id = self._preflight(
            action,
            user_id,
            workspace_id,
            {"privacy_config": privacy_config},
        )
        if not allowed:
            return result

        if not isinstance(privacy_config, dict):
            return self._error_result(
                "privacy_config must be a dictionary.",
                metadata={"action": action},
            )

        key = self._context_key(safe_user_id, safe_workspace_id)

        with self._lock:
            if key not in self._workspace_settings:
                self._workspace_settings[key] = VoiceAgentSettings(
                    user_id=safe_user_id,
                    workspace_id=safe_workspace_id,
                )

            current = self._workspace_settings[key].privacy
            current_dict = asdict(current)
            current_dict.update(privacy_config)

            current_dict["data_retention_days"] = self.clamp_int(
                current_dict.get("data_retention_days"),
                0,
                3650,
                30,
            )

            self._workspace_settings[key].privacy = PrivacyConfig(**current_dict)
            self._workspace_settings[key].updated_at = self.utcnow()
            self._persist_store("workspace_settings", self._workspace_settings)

            settings = self._workspace_settings[key]

        data = {
            "privacy": self._dataclass_to_dict(settings.privacy),
            "memory_payload": self._prepare_memory_payload(
                memory_type="voice_privacy_config",
                user_id=safe_user_id,
                workspace_id=safe_workspace_id,
                content=self._dataclass_to_dict(settings.privacy),
                importance=0.9,
            ),
            "verification_payload": self._prepare_verification_payload(
                action,
                safe_user_id,
                safe_workspace_id,
                {"privacy_updated": True},
            ),
        }

        self._emit_agent_event(action, safe_user_id, safe_workspace_id, data)
        self._log_audit_event(action, safe_user_id, safe_workspace_id, data, True)

        return self._safe_result(
            "Privacy config updated.",
            data=data,
            metadata={"action": action},
        )

    def get_privacy_config(
        self,
        user_id: Any,
        workspace_id: Any,
    ) -> Dict[str, Any]:
        """Return privacy config for one user/workspace."""
        action = "get_privacy_config"
        config_result = self.get_or_create_workspace_config(user_id, workspace_id)
        if not config_result["success"]:
            return config_result

        privacy = config_result["data"]["config"].get("privacy", {})

        return self._safe_result(
            "Privacy config loaded.",
            data={"privacy": privacy},
            metadata={"action": action},
        )

    def set_voice_cloning_allowed(
        self,
        user_id: Any,
        workspace_id: Any,
        allowed_value: bool,
    ) -> Dict[str, Any]:
        """Enable/disable voice cloning permission safely."""
        return self.set_privacy_config(
            user_id=user_id,
            workspace_id=workspace_id,
            privacy_config={"allow_voice_cloning": bool(allowed_value)},
        )

    def set_raw_audio_storage_allowed(
        self,
        user_id: Any,
        workspace_id: Any,
        allowed_value: bool,
    ) -> Dict[str, Any]:
        """Enable/disable raw audio storage safely."""
        return self.set_privacy_config(
            user_id=user_id,
            workspace_id=workspace_id,
            privacy_config={"store_raw_audio": bool(allowed_value)},
        )

    # =========================================================================
    # Language methods
    # =========================================================================

    def register_language(
        self,
        language_code: str,
        language_name: str,
        enabled: bool = True,
        default_voice: Optional[str] = None,
        stt_supported: bool = True,
        tts_supported: bool = True,
        auto_detect_supported: bool = True,
        romanized_supported: bool = False,
        fallback_language_code: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Register or update a global language config."""
        action = "register_language"

        code = self.normalize_language_code(language_code)
        name = str(language_name).strip()

        if not code or not name:
            return self._error_result(
                "language_code and language_name are required.",
                metadata={"action": action},
            )

        language = LanguageConfig(
            language_code=code,
            language_name=name,
            enabled=bool(enabled),
            default_voice=default_voice,
            stt_supported=bool(stt_supported),
            tts_supported=bool(tts_supported),
            auto_detect_supported=bool(auto_detect_supported),
            romanized_supported=bool(romanized_supported),
            fallback_language_code=fallback_language_code,
            metadata=metadata or {},
        )

        with self._lock:
            self._languages[code] = language
            self._persist_store("languages", self._languages)

        return self._safe_result(
            "Language registered.",
            data={"language": self._dataclass_to_dict(language)},
            metadata={"action": action},
        )

    def list_languages(
        self,
        enabled_only: bool = True,
    ) -> Dict[str, Any]:
        """List supported languages."""
        action = "list_languages"

        with self._lock:
            languages = []
            for language in self._languages.values():
                if enabled_only and not language.enabled:
                    continue
                languages.append(self._dataclass_to_dict(language))

        languages.sort(key=lambda item: item.get("language_name", ""))

        return self._safe_result(
            "Languages listed.",
            data={
                "languages": languages,
                "count": len(languages),
            },
            metadata={"action": action},
        )

    def get_language(
        self,
        language_code: str,
    ) -> Dict[str, Any]:
        """Get one language config."""
        action = "get_language"
        code = self.normalize_language_code(language_code)

        with self._lock:
            language = self._languages.get(code)

        if not language:
            return self._safe_result(
                "Language not found.",
                data={"language": None},
                metadata={"action": action},
            )

        return self._safe_result(
            "Language found.",
            data={"language": self._dataclass_to_dict(language)},
            metadata={"action": action},
        )

    def set_default_language(
        self,
        user_id: Any,
        workspace_id: Any,
        language_code: str,
        fallback_language_code: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Set workspace default language."""
        action = "set_default_language"
        allowed, result, safe_user_id, safe_workspace_id = self._preflight(
            action,
            user_id,
            workspace_id,
            {"language_code": language_code},
        )
        if not allowed:
            return result

        code = self.normalize_language_code(language_code)
        fallback = self.normalize_language_code(fallback_language_code or code)

        if code not in self._languages:
            return self._error_result(
                "Unsupported language_code.",
                data={"language_code": code},
                metadata={"action": action},
            )

        key = self._context_key(safe_user_id, safe_workspace_id)

        with self._lock:
            if key not in self._workspace_settings:
                self._workspace_settings[key] = VoiceAgentSettings(
                    user_id=safe_user_id,
                    workspace_id=safe_workspace_id,
                )

            settings = self._workspace_settings[key]
            settings.default_language_code = code
            settings.fallback_language_code = fallback
            settings.updated_at = self.utcnow()
            self._persist_store("workspace_settings", self._workspace_settings)

        data = {
            "default_language_code": code,
            "fallback_language_code": fallback,
            "memory_payload": self._prepare_memory_payload(
                memory_type="voice_default_language",
                user_id=safe_user_id,
                workspace_id=safe_workspace_id,
                content={
                    "default_language_code": code,
                    "fallback_language_code": fallback,
                },
                importance=0.7,
            ),
            "verification_payload": self._prepare_verification_payload(
                action,
                safe_user_id,
                safe_workspace_id,
                {
                    "default_language_code": code,
                    "fallback_language_code": fallback,
                },
            ),
        }

        self._emit_agent_event(action, safe_user_id, safe_workspace_id, data)
        self._log_audit_event(action, safe_user_id, safe_workspace_id, data, True)

        return self._safe_result(
            "Default language updated.",
            data=data,
            metadata={"action": action},
        )

    # =========================================================================
    # Engine methods
    # =========================================================================

    def register_engine(
        self,
        engine_id: str,
        engine_type: str,
        provider: str,
        model: Optional[str] = None,
        enabled: bool = True,
        priority: int = 100,
        local_only: bool = False,
        requires_network: bool = False,
        supports_streaming: bool = False,
        supports_realtime: bool = False,
        supported_languages: Optional[List[str]] = None,
        options: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Register or update an engine config."""
        action = "register_engine"

        safe_engine_id = str(engine_id).strip()
        safe_engine_type = self.normalize_engine_type(engine_type)
        safe_provider = str(provider).strip()

        if not safe_engine_id or not safe_engine_type or not safe_provider:
            return self._error_result(
                "engine_id, engine_type, and provider are required.",
                metadata={"action": action},
            )

        if safe_engine_type not in self.VALID_ENGINE_TYPES:
            return self._error_result(
                "Invalid engine_type.",
                data={
                    "engine_type": safe_engine_type,
                    "valid_engine_types": sorted(self.VALID_ENGINE_TYPES),
                },
                metadata={"action": action},
            )

        engine = EngineConfig(
            engine_id=safe_engine_id,
            engine_type=safe_engine_type,
            provider=safe_provider,
            model=model,
            enabled=bool(enabled),
            priority=self.clamp_int(priority, 0, 10000, 100),
            local_only=bool(local_only),
            requires_network=bool(requires_network),
            supports_streaming=bool(supports_streaming),
            supports_realtime=bool(supports_realtime),
            supported_languages=[
                self.normalize_language_code(item)
                for item in (supported_languages or [])
                if self.normalize_language_code(item)
            ],
            options=options or {},
            metadata=metadata or {},
        )

        with self._lock:
            self._engines[safe_engine_id] = engine
            self._persist_store("engines", self._engines)

        return self._safe_result(
            "Engine registered.",
            data={"engine": self._dataclass_to_dict(engine)},
            metadata={"action": action},
        )

    def list_engines(
        self,
        engine_type: Optional[str] = None,
        enabled_only: bool = True,
    ) -> Dict[str, Any]:
        """List available engines."""
        action = "list_engines"
        safe_engine_type = self.normalize_engine_type(engine_type) if engine_type else None

        with self._lock:
            engines = []
            for engine in self._engines.values():
                if enabled_only and not engine.enabled:
                    continue
                if safe_engine_type and engine.engine_type != safe_engine_type:
                    continue
                engines.append(self._dataclass_to_dict(engine))

        engines.sort(key=lambda item: (item.get("priority", 100), item.get("engine_id", "")))

        return self._safe_result(
            "Engines listed.",
            data={
                "engines": engines,
                "count": len(engines),
            },
            metadata={"action": action},
        )

    def get_engine(
        self,
        engine_id: str,
    ) -> Dict[str, Any]:
        """Get one engine by ID."""
        action = "get_engine"

        with self._lock:
            engine = self._engines.get(str(engine_id).strip())

        if not engine:
            return self._safe_result(
                "Engine not found.",
                data={"engine": None},
                metadata={"action": action},
            )

        return self._safe_result(
            "Engine found.",
            data={"engine": self._dataclass_to_dict(engine)},
            metadata={"action": action},
        )

    def set_default_engine(
        self,
        user_id: Any,
        workspace_id: Any,
        engine_type: str,
        engine_id: str,
    ) -> Dict[str, Any]:
        """Set default engine for a workspace."""
        action = "set_default_engine"
        allowed, result, safe_user_id, safe_workspace_id = self._preflight(
            action,
            user_id,
            workspace_id,
            {
                "engine_type": engine_type,
                "engine_id": engine_id,
            },
        )
        if not allowed:
            return result

        safe_engine_type = self.normalize_engine_type(engine_type)
        safe_engine_id = str(engine_id).strip()

        if safe_engine_type not in self.VALID_ENGINE_TYPES:
            return self._error_result(
                "Invalid engine_type.",
                data={
                    "engine_type": safe_engine_type,
                    "valid_engine_types": sorted(self.VALID_ENGINE_TYPES),
                },
                metadata={"action": action},
            )

        with self._lock:
            engine = self._engines.get(safe_engine_id)

        if not engine:
            return self._error_result(
                "Engine does not exist.",
                data={"engine_id": safe_engine_id},
                metadata={"action": action},
            )

        if engine.engine_type != safe_engine_type:
            return self._error_result(
                "Engine type mismatch.",
                data={
                    "requested_engine_type": safe_engine_type,
                    "actual_engine_type": engine.engine_type,
                },
                metadata={"action": action},
            )

        key = self._context_key(safe_user_id, safe_workspace_id)

        field_map = {
            "stt": "default_stt_engine_id",
            "tts": "default_tts_engine_id",
            "wake_word": "default_wake_engine_id",
            "noise_control": "default_noise_engine_id",
            "emotion_detection": "default_emotion_engine_id",
        }

        target_field = field_map.get(safe_engine_type)
        if not target_field:
            return self._error_result(
                "This engine type cannot be set as a default workspace engine through this method.",
                data={"engine_type": safe_engine_type},
                metadata={"action": action},
            )

        with self._lock:
            if key not in self._workspace_settings:
                self._workspace_settings[key] = VoiceAgentSettings(
                    user_id=safe_user_id,
                    workspace_id=safe_workspace_id,
                )

            settings = self._workspace_settings[key]
            setattr(settings, target_field, safe_engine_id)
            settings.updated_at = self.utcnow()
            self._persist_store("workspace_settings", self._workspace_settings)

        data = {
            "engine_type": safe_engine_type,
            "engine_id": safe_engine_id,
            "target_field": target_field,
            "verification_payload": self._prepare_verification_payload(
                action,
                safe_user_id,
                safe_workspace_id,
                {
                    "engine_type": safe_engine_type,
                    "engine_id": safe_engine_id,
                },
            ),
        }

        self._emit_agent_event(action, safe_user_id, safe_workspace_id, data)
        self._log_audit_event(action, safe_user_id, safe_workspace_id, data, True)

        return self._safe_result(
            "Default engine updated.",
            data=data,
            metadata={"action": action},
        )

    def resolve_engine(
        self,
        user_id: Any,
        workspace_id: Any,
        engine_type: str,
        language_code: Optional[str] = None,
        require_realtime: bool = False,
        require_streaming: bool = False,
        allow_network: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Resolve the best engine for a workspace request.

        This is used by:
            - stt_engine.py
            - tts_engine.py
            - wake_word.py
            - noise_control.py
            - emotion_detector.py
        """
        action = "resolve_engine"
        config_result = self.get_or_create_workspace_config(user_id, workspace_id)
        if not config_result["success"]:
            return config_result

        config = config_result["data"]["config"]
        safe_engine_type = self.normalize_engine_type(engine_type)
        safe_language_code = self.normalize_language_code(
            language_code or config.get("default_language_code", "en")
        )

        if safe_engine_type not in self.VALID_ENGINE_TYPES:
            return self._error_result(
                "Invalid engine_type.",
                data={
                    "engine_type": safe_engine_type,
                    "valid_engine_types": sorted(self.VALID_ENGINE_TYPES),
                },
                metadata={"action": action},
            )

        privacy = config.get("privacy", {})
        if allow_network is None:
            allow_network = bool(
                privacy.get("allow_cloud_stt", False)
                if safe_engine_type == "stt"
                else privacy.get("allow_cloud_tts", False)
                if safe_engine_type == "tts"
                else False
            )

        default_field_map = {
            "stt": "default_stt_engine_id",
            "tts": "default_tts_engine_id",
            "wake_word": "default_wake_engine_id",
            "noise_control": "default_noise_engine_id",
            "emotion_detection": "default_emotion_engine_id",
        }

        preferred_engine_id = config.get(default_field_map.get(safe_engine_type, ""), None)

        with self._lock:
            candidates = [
                engine
                for engine in self._engines.values()
                if engine.engine_type == safe_engine_type and engine.enabled
            ]

        filtered: List[EngineConfig] = []

        for engine in candidates:
            if engine.requires_network and not allow_network:
                continue

            if require_realtime and not engine.supports_realtime:
                continue

            if require_streaming and not engine.supports_streaming:
                continue

            if engine.supported_languages and safe_language_code not in engine.supported_languages:
                continue

            filtered.append(engine)

        filtered.sort(key=lambda item: item.priority)

        selected = None

        if preferred_engine_id:
            for engine in filtered:
                if engine.engine_id == preferred_engine_id:
                    selected = engine
                    break

        if not selected and filtered:
            selected = filtered[0]

        if not selected:
            return self._error_result(
                "No compatible engine found.",
                data={
                    "engine_type": safe_engine_type,
                    "language_code": safe_language_code,
                    "allow_network": allow_network,
                    "require_realtime": require_realtime,
                    "require_streaming": require_streaming,
                },
                metadata={"action": action},
            )

        return self._safe_result(
            "Engine resolved.",
            data={
                "engine": self._dataclass_to_dict(selected),
                "engine_type": safe_engine_type,
                "language_code": safe_language_code,
                "allow_network": allow_network,
            },
            metadata={"action": action},
        )

    # =========================================================================
    # Full runtime config
    # =========================================================================

    def get_runtime_config(
        self,
        user_id: Any,
        workspace_id: Any,
    ) -> Dict[str, Any]:
        """
        Return complete runtime config for Voice Agent startup.

        This is the main method used by:
            - voice_agent.py
            - voice_loop.py
            - audio_router.py
            - dashboard/API
            - Master Agent routing
        """
        action = "get_runtime_config"
        config_result = self.get_or_create_workspace_config(user_id, workspace_id)
        if not config_result["success"]:
            return config_result

        config = config_result["data"]["config"]

        stt = self.resolve_engine(
            user_id=user_id,
            workspace_id=workspace_id,
            engine_type="stt",
            language_code=config.get("default_language_code"),
            require_streaming=False,
            require_realtime=False,
        )

        tts = self.resolve_engine(
            user_id=user_id,
            workspace_id=workspace_id,
            engine_type="tts",
            language_code=config.get("default_language_code"),
            require_streaming=False,
            require_realtime=False,
        )

        wake = self.resolve_engine(
            user_id=user_id,
            workspace_id=workspace_id,
            engine_type="wake_word",
            language_code=config.get("default_language_code"),
            require_streaming=True,
            require_realtime=True,
        )

        noise = self.resolve_engine(
            user_id=user_id,
            workspace_id=workspace_id,
            engine_type="noise_control",
            language_code=config.get("default_language_code"),
            require_streaming=True,
            require_realtime=True,
        )

        runtime = {
            "workspace_config": config,
            "resolved_engines": {
                "stt": stt.get("data", {}).get("engine") if stt.get("success") else None,
                "tts": tts.get("data", {}).get("engine") if tts.get("success") else None,
                "wake_word": wake.get("data", {}).get("engine") if wake.get("success") else None,
                "noise_control": noise.get("data", {}).get("engine") if noise.get("success") else None,
            },
            "engine_resolution_status": {
                "stt": stt.get("success"),
                "tts": tts.get("success"),
                "wake_word": wake.get("success"),
                "noise_control": noise.get("success"),
            },
            "languages": self.list_languages(enabled_only=True).get("data", {}).get("languages", []),
            "generated_at": self.utcnow(),
        }

        return self._safe_result(
            "Voice runtime config generated.",
            data={
                "runtime_config": runtime,
                "verification_payload": self._prepare_verification_payload(
                    action,
                    str(user_id),
                    str(workspace_id),
                    {"runtime_config_generated": True},
                ),
            },
            metadata={"action": action},
        )

    def export_workspace_config(
        self,
        user_id: Any,
        workspace_id: Any,
    ) -> Dict[str, Any]:
        """
        Export workspace Voice Agent config.

        Sensitive action because it may expose privacy settings.
        """
        action = "export_workspace_config"
        allowed, result, safe_user_id, safe_workspace_id = self._preflight(
            action,
            user_id,
            workspace_id,
        )
        if not allowed:
            return result

        runtime_result = self.get_runtime_config(safe_user_id, safe_workspace_id)
        if not runtime_result["success"]:
            return runtime_result

        data = {
            "export_id": self.new_id("voice_config_export"),
            "exported_at": self.utcnow(),
            "runtime_config": runtime_result["data"]["runtime_config"],
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
            "Workspace voice config exported.",
            data=data,
            metadata={"action": action},
        )

    # =========================================================================
    # Registry / health / compatibility
    # =========================================================================

    def get_agent_manifest(self) -> Dict[str, Any]:
        """Return registry-friendly manifest."""
        return {
            "agent_name": self.agent_name,
            "agent_type": self.agent_type,
            "module": "agents.voice_agent.config",
            "class_name": "VoiceConfig",
            "version": self.version,
            "description": "Voice Agent settings, languages, wake word, engine choices, and privacy flags.",
            "public_methods": [
                "get_or_create_workspace_config",
                "update_workspace_config",
                "reset_workspace_config",
                "delete_workspace_config",
                "set_wake_word_config",
                "get_wake_words",
                "set_audio_behavior_config",
                "set_privacy_config",
                "get_privacy_config",
                "set_voice_cloning_allowed",
                "set_raw_audio_storage_allowed",
                "register_language",
                "list_languages",
                "get_language",
                "set_default_language",
                "register_engine",
                "list_engines",
                "get_engine",
                "set_default_engine",
                "resolve_engine",
                "get_runtime_config",
                "export_workspace_config",
                "get_agent_manifest",
                "health_check",
                "execute",
            ],
            "requires_user_context": True,
            "requires_workspace_context": True,
            "security_sensitive_actions": sorted(self.SENSITIVE_ACTIONS),
            "valid_engine_types": sorted(self.VALID_ENGINE_TYPES),
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
        """Return health status for dashboard/API."""
        with self._lock:
            counts = {
                "languages": len(self._languages),
                "engines": len(self._engines),
                "workspace_settings": len(self._workspace_settings),
            }

        storage_status = {
            "enabled": self.enable_file_storage,
            "config_dir": str(self.config_dir),
            "config_dir_exists": self.config_dir.exists() if self.enable_file_storage else False,
        }

        return self._safe_result(
            "VoiceConfig is healthy.",
            data={
                "status": "healthy",
                "counts": counts,
                "storage": storage_status,
                "manifest": self.get_agent_manifest(),
            },
            metadata={"action": "health_check"},
        )

    def execute(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generic execution method for Master Agent / Agent Router.

        Expected:
            {
                "action": "get_runtime_config",
                "user_id": "1",
                "workspace_id": "main",
                "params": {}
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
            "get_or_create_workspace_config": self.get_or_create_workspace_config,
            "update_workspace_config": self.update_workspace_config,
            "reset_workspace_config": self.reset_workspace_config,
            "delete_workspace_config": self.delete_workspace_config,
            "set_wake_word_config": self.set_wake_word_config,
            "get_wake_words": self.get_wake_words,
            "set_audio_behavior_config": self.set_audio_behavior_config,
            "set_privacy_config": self.set_privacy_config,
            "get_privacy_config": self.get_privacy_config,
            "set_voice_cloning_allowed": self.set_voice_cloning_allowed,
            "set_raw_audio_storage_allowed": self.set_raw_audio_storage_allowed,
            "set_default_language": self.set_default_language,
            "set_default_engine": self.set_default_engine,
            "resolve_engine": self.resolve_engine,
            "get_runtime_config": self.get_runtime_config,
            "export_workspace_config": self.export_workspace_config,
            "health_check": self.health_check,
            "get_agent_manifest": self.get_agent_manifest,
            "register_language": self.register_language,
            "list_languages": self.list_languages,
            "get_language": self.get_language,
            "register_engine": self.register_engine,
            "list_engines": self.list_engines,
            "get_engine": self.get_engine,
        }

        method = route_map.get(action)
        if not method:
            return self._error_result(
                f"Unsupported VoiceConfig action: {action}",
                data={"supported_actions": sorted(route_map.keys())},
                metadata={"action": "execute"},
            )

        try:
            global_actions = {
                "health_check",
                "get_agent_manifest",
                "register_language",
                "list_languages",
                "get_language",
                "register_engine",
                "list_engines",
                "get_engine",
            }

            if action in {"health_check", "get_agent_manifest"}:
                result = method()
                if isinstance(result, dict) and "success" in result:
                    return result
                return self._safe_result(
                    "Action executed.",
                    data={"result": result},
                    metadata={"action": action},
                )

            if action in global_actions:
                return method(**params)

            return method(user_id=user_id, workspace_id=workspace_id, **params)

        except TypeError as exc:
            return self._error_result(
                "Invalid parameters for VoiceConfig action.",
                error=exc,
                data={
                    "requested_action": action,
                    "params": params,
                },
                metadata={"action": "execute"},
            )
        except Exception as exc:
            logger.exception("VoiceConfig execute failed.")
            return self._error_result(
                "VoiceConfig action failed.",
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
        python agents/voice_agent/config.py
    """
    config = VoiceConfig(
        config_dir="storage/demo_voice_config",
        enable_file_storage=True,
    )

    user_id = "demo_user"
    workspace_id = "demo_workspace"

    results = {
        "health_before": config.health_check(),
        "workspace_config": config.get_or_create_workspace_config(
            user_id=user_id,
            workspace_id=workspace_id,
        ),
        "wake_word": config.set_wake_word_config(
            user_id=user_id,
            workspace_id=workspace_id,
            wake_word_config={
                "primary_wake_word": "William",
                "aliases": ["Jarvis", "Hey William"],
                "sensitivity": 0.72,
            },
        ),
        "privacy": config.set_privacy_config(
            user_id=user_id,
            workspace_id=workspace_id,
            privacy_config={
                "allow_cloud_stt": False,
                "allow_cloud_tts": False,
                "allow_voice_storage": True,
                "store_raw_audio": False,
            },
        ),
        "language": config.set_default_language(
            user_id=user_id,
            workspace_id=workspace_id,
            language_code="en",
        ),
        "engines": config.list_engines(),
        "runtime": config.get_runtime_config(
            user_id=user_id,
            workspace_id=workspace_id,
        ),
        "health_after": config.health_check(),
    }

    return results


if __name__ == "__main__":
    demo_result = _demo()
    print(json.dumps(demo_result, indent=2, ensure_ascii=False, default=str))


"""
Agent/Module: Voice Agent
File Completed: config.py
Completion: 100.0%
Completed Files: ['voice_agent.py', 'wake_word.py', 'stt_engine.py', 'tts_engine.py', 'language_engine.py', 'device_stream.py', 'interruption.py', 'voice_loop.py', 'session_manager.py', 'audio_router.py', 'noise_control.py', 'speaker_recognition.py', 'emotion_detector.py', 'whisper_mode.py', 'voice_profiles.py', 'voice_cloning.py', 'gesture_trigger.py', 'conversation_mode.py', 'voice_memory.py', 'config.py']
Remaining Files: []
Next Recommended File: Next module from build order
FILE COMPLETE
"""