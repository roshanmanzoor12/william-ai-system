"""
agents/voice_agent/language_engine.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Voice Agent - Language Engine

Purpose:
    Detects English, Roman Urdu, Urdu, Hindi, Arabic, mixed speech,
    and chooses the best reply language for William/Jarvis responses.

Architecture Compatibility:
    - BaseAgent compatible
    - Agent Registry compatible
    - Agent Loader compatible
    - Master Agent routing compatible
    - Security Agent approval compatible
    - Verification Agent payload compatible
    - Memory Agent payload compatible
    - Dashboard/API analytics compatible
    - SaaS user/workspace isolation compatible

Important:
    This file is import-safe. If William core modules are not created yet,
    fallback stubs are used so the file can still run and be tested.
"""

from __future__ import annotations

import logging
import re
import time
import unicodedata
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple, Union


# =============================================================================
# Safe Optional BaseAgent Import
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe until the real William/Jarvis BaseAgent
        exists. The real BaseAgent can later provide registry, routing,
        permissions, memory, verification, audit, and analytics integrations.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_type = kwargs.get("agent_type", "voice_agent")
            self.version = kwargs.get("version", "1.0.0")


# =============================================================================
# Logging
# =============================================================================

logger = logging.getLogger("william.voice_agent.language_engine")
if not logger.handlers:
    logger.addHandler(logging.NullHandler())


# =============================================================================
# Constants
# =============================================================================

SUPPORTED_LANGUAGE_CODES = {
    "en": "English",
    "roman_urdu": "Roman Urdu",
    "ur": "Urdu",
    "hi": "Hindi",
    "ar": "Arabic",
    "mixed": "Mixed",
    "unknown": "Unknown",
}

SUPPORTED_SCRIPTS = {
    "latin": "Latin",
    "arabic": "Arabic/Urdu",
    "devanagari": "Devanagari/Hindi",
    "mixed": "Mixed Script",
    "unknown": "Unknown Script",
}

DEFAULT_CONFIDENCE_THRESHOLD = 0.42
MIN_TEXT_LENGTH_FOR_CONFIDENT_DETECTION = 2

LANGUAGE_DIRECTION = {
    "en": "ltr",
    "roman_urdu": "ltr",
    "ur": "rtl",
    "hi": "ltr",
    "ar": "rtl",
    "mixed": "auto",
    "unknown": "auto",
}

REPLY_STYLE_BY_LANGUAGE = {
    "en": {
        "name": "English",
        "tone": "clear, natural, professional",
        "direction": "ltr",
    },
    "roman_urdu": {
        "name": "Roman Urdu",
        "tone": "natural Roman Urdu with simple English where helpful",
        "direction": "ltr",
    },
    "ur": {
        "name": "Urdu",
        "tone": "natural Urdu, respectful and clear",
        "direction": "rtl",
    },
    "hi": {
        "name": "Hindi",
        "tone": "natural Hindi, respectful and clear",
        "direction": "ltr",
    },
    "ar": {
        "name": "Arabic",
        "tone": "natural Arabic, respectful and clear",
        "direction": "rtl",
    },
    "mixed": {
        "name": "Mixed",
        "tone": "reply in the dominant user language and keep mixed terms where natural",
        "direction": "auto",
    },
    "unknown": {
        "name": "English",
        "tone": "clear, natural, professional",
        "direction": "ltr",
    },
}


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class LanguageScore:
    """Stores score details for one candidate language."""

    language: str
    score: float
    signals: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "language": self.language,
            "language_name": SUPPORTED_LANGUAGE_CODES.get(self.language, self.language),
            "score": round(float(self.score), 4),
            "signals": list(self.signals),
        }


@dataclass
class LanguageDetectionResult:
    """Structured language detection result."""

    detected_language: str
    detected_language_name: str
    confidence: float
    script: str
    script_name: str
    is_mixed: bool
    mixed_languages: List[str]
    direction: str
    reply_language: str
    reply_language_name: str
    reply_direction: str
    normalized_text: str
    original_text: str
    scores: Dict[str, float]
    signals: Dict[str, List[str]]
    metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detected_language": self.detected_language,
            "detected_language_name": self.detected_language_name,
            "confidence": round(float(self.confidence), 4),
            "script": self.script,
            "script_name": self.script_name,
            "is_mixed": self.is_mixed,
            "mixed_languages": list(self.mixed_languages),
            "direction": self.direction,
            "reply_language": self.reply_language,
            "reply_language_name": self.reply_language_name,
            "reply_direction": self.reply_direction,
            "normalized_text": self.normalized_text,
            "original_text": self.original_text,
            "scores": {k: round(float(v), 4) for k, v in self.scores.items()},
            "signals": {k: list(v) for k, v in self.signals.items()},
            "metadata": dict(self.metadata),
        }


@dataclass
class LanguageEngineConfig:
    """Runtime configuration for LanguageEngine."""

    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD
    prefer_user_previous_language: bool = True
    default_reply_language: str = "en"
    allow_mixed_language_reply: bool = True
    emit_events: bool = True
    audit_enabled: bool = True
    memory_enabled: bool = True
    verification_enabled: bool = True
    max_text_length: int = 12000

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# =============================================================================
# Language Engine
# =============================================================================

class LanguageEngine(BaseAgent):
    """
    Voice Agent helper that detects user language and chooses reply language.

    This file does not perform destructive actions. It is safe to run without
    Security Agent approval by default. Still, it includes security hooks so
    Master Agent can route sensitive future operations through Security Agent.

    Public Methods:
        - analyze()
        - detect_language()
        - choose_reply_language()
        - detect_script()
        - normalize_text()
        - get_supported_languages()
        - health_check()
        - run()
    """

    VERSION = "1.0.0"

    ENGLISH_STOPWORDS = {
        "the", "is", "are", "am", "i", "you", "we", "they", "he", "she", "it",
        "this", "that", "these", "those", "what", "where", "when", "why", "how",
        "can", "could", "should", "would", "will", "shall", "do", "does", "did",
        "have", "has", "had", "my", "your", "our", "their", "me", "him", "her",
        "please", "help", "make", "create", "write", "give", "tell", "explain",
        "file", "code", "final", "full", "now", "next", "agent", "system",
    }

    ROMAN_URDU_WORDS = {
        "hai", "hain", "tha", "thi", "thay", "ho", "hon", "hun", "hy", "h",
        "kya", "kia", "kiya", "kyun", "q", "kaise", "kesy", "kaisa", "kaisi",
        "mujhe", "mujhy", "muje", "mjy", "main", "mein", "mai", "me", "hum",
        "tum", "aap", "ap", "apko", "apkay", "apki", "apka", "mera", "meri",
        "mere", "tera", "teri", "tere", "iska", "iski", "iske", "uska", "uski",
        "uske", "ye", "ya", "yeh", "wo", "woh", "wahan", "yahan", "idhar",
        "udhar", "kr", "kar", "karo", "kery", "kren", "karta", "karti", "karte",
        "kerna", "karna", "bana", "banao", "banado", "bna", "bnado", "likh",
        "likho", "likhna", "de", "do", "dy", "dijiye", "btao", "batao", "samjhao",
        "samajh", "samjh", "chahiye", "chahta", "chahti", "chahye", "acha",
        "achha", "theek", "thik", "sahi", "galat", "nahi", "nhi", "nahin",
        "han", "haan", "ji", "yaar", "bhai", "bhut", "bohat", "ziyada", "kam",
        "abhi", "phir", "phr", "agar", "lekin", "lkn", "magar", "aur", "or",
        "se", "say", "ko", "ke", "ki", "ka", "kay", "liye", "liyeh", "waly",
        "wala", "wali", "walay", "aisa", "aisi", "aisy", "jese", "jaise",
        "jaisy", "kunky", "kyunki", "qk", "matlab", "bas", "bus", "sirf",
        "pura", "pori", "poora", "poori", "final", "file", "code", "same",
        "exact", "isy", "isko", "usko", "yeh", "ye", "wo", "ab", "aj", "kal",
    }

    HINDI_ROMAN_WORDS = {
        "namaste", "kya", "kaise", "kaisa", "kaisi", "mujhe", "main", "mein",
        "hum", "tum", "aap", "mera", "meri", "mere", "yeh", "yah", "vo", "woh",
        "hai", "hain", "tha", "thi", "karo", "karna", "banana", "likhna",
        "batana", "samjhana", "chahiye", "nahi", "haan", "achha", "theek",
        "bahut", "zyada", "kam", "abhi", "phir", "agar", "lekin", "aur",
        "kyunki", "matlab", "sirf",
    }

    ARABIC_COMMON_WORDS = {
        "انا", "أنت", "انت", "نحن", "هو", "هي", "هذا", "هذه", "ذلك", "ما",
        "ماذا", "متى", "أين", "اين", "لماذا", "كيف", "هل", "نعم", "لا",
        "من", "في", "على", "الى", "إلى", "عن", "مع", "كان", "كانت", "يكون",
        "اريد", "أريد", "اكتب", "اشرح", "ساعدني", "شكرا", "مرحبا", "السلام",
    }

    URDU_COMMON_WORDS = {
        "میں", "مجھے", "میرا", "میری", "میرے", "تم", "آپ", "ہم", "وہ", "یہ",
        "کیا", "کیوں", "کہاں", "کب", "کیسے", "ہے", "ہیں", "تھا", "تھی", "تھے",
        "نہیں", "ہاں", "جی", "اور", "یا", "لیکن", "اگر", "کے", "کی", "کا",
        "کو", "سے", "پر", "لئے", "لیے", "چاہیے", "کرنا", "کرو", "بناؤ",
        "لکھو", "بتاؤ", "سمجھاؤ", "بہت", "زیادہ", "کم", "ابھی", "پھر",
    }

    HINDI_COMMON_WORDS = {
        "मैं", "मुझे", "मेरा", "मेरी", "मेरे", "तुम", "आप", "हम", "वह", "यह",
        "क्या", "क्यों", "कहाँ", "कब", "कैसे", "है", "हैं", "था", "थी", "थे",
        "नहीं", "हाँ", "जी", "और", "या", "लेकिन", "अगर", "के", "की", "का",
        "को", "से", "पर", "लिए", "चाहिए", "करना", "करो", "बनाओ", "लिखो",
        "बताओ", "समझाओ", "बहुत", "ज्यादा", "कम", "अभी", "फिर",
    }

    ARABIC_DIACRITICS_PATTERN = re.compile(
        r"[\u0610-\u061A\u064B-\u065F\u0670\u06D6-\u06ED]"
    )

    URL_PATTERN = re.compile(
        r"(https?://|www\.|[a-zA-Z0-9-]+\.(com|net|org|io|dev|ai|pk|in|ae|co)\b)",
        re.IGNORECASE,
    )

    EMAIL_PATTERN = re.compile(
        r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
        re.IGNORECASE,
    )

    PHONE_PATTERN = re.compile(
        r"(\+?\d[\d\s().-]{6,}\d)"
    )

    def __init__(
        self,
        config: Optional[Union[LanguageEngineConfig, Dict[str, Any]]] = None,
        event_bus: Optional[Any] = None,
        security_client: Optional[Any] = None,
        memory_client: Optional[Any] = None,
        verification_client: Optional[Any] = None,
        audit_client: Optional[Any] = None,
        logger_instance: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            agent_name="LanguageEngine",
            agent_type="voice_agent",
            version=self.VERSION,
            **kwargs,
        )

        if isinstance(config, LanguageEngineConfig):
            self.config = config
        elif isinstance(config, dict):
            self.config = LanguageEngineConfig(**{
                key: value for key, value in config.items()
                if key in LanguageEngineConfig.__dataclass_fields__
            })
        else:
            self.config = LanguageEngineConfig()

        self.event_bus = event_bus
        self.security_client = security_client
        self.memory_client = memory_client
        self.verification_client = verification_client
        self.audit_client = audit_client
        self.logger = logger_instance or logger

        self.agent_name = "LanguageEngine"
        self.agent_module = "Voice Agent"
        self.file_path = "agents/voice_agent/language_engine.py"

    # =========================================================================
    # Public API
    # =========================================================================

    def analyze(
        self,
        text: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        previous_language: Optional[str] = None,
        preferred_reply_language: Optional[str] = None,
        task_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Full language analysis entrypoint for Master Agent / Voice Agent.

        Returns structured dict:
            {
                success,
                message,
                data,
                error,
                metadata
            }
        """

        started_at = time.time()
        metadata = metadata or {}

        context = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "task_id": task_id,
            "agent": self.agent_name,
            "module": self.agent_module,
        }

        try:
            context_result = self._validate_task_context(context)
            if not context_result["success"]:
                return context_result

            if self._requires_security_check("language_detection", context):
                approval = self._request_security_approval(
                    action="language_detection",
                    context=context,
                    metadata=metadata,
                )
                if not approval.get("approved", False):
                    return self._error_result(
                        message="Language detection blocked by Security Agent.",
                        error="security_approval_denied",
                        metadata={
                            "context": context,
                            "approval": approval,
                        },
                    )

            if not isinstance(text, str):
                return self._error_result(
                    message="Text must be a string.",
                    error="invalid_text_type",
                    metadata={"received_type": type(text).__name__, "context": context},
                )

            if len(text) > self.config.max_text_length:
                text = text[:self.config.max_text_length]
                metadata["text_truncated"] = True
                metadata["max_text_length"] = self.config.max_text_length

            detection = self._detect_language_internal(
                text=text,
                previous_language=previous_language,
                preferred_reply_language=preferred_reply_language,
                metadata=metadata,
            )

            verification_payload = self._prepare_verification_payload(
                action="language_detection",
                result=detection.to_dict(),
                context=context,
            )

            memory_payload = self._prepare_memory_payload(
                text=text,
                detection=detection,
                context=context,
            )

            event_payload = {
                "event": "voice.language.detected",
                "user_id": user_id,
                "workspace_id": workspace_id,
                "task_id": task_id,
                "detected_language": detection.detected_language,
                "reply_language": detection.reply_language,
                "confidence": detection.confidence,
                "is_mixed": detection.is_mixed,
                "timestamp": time.time(),
            }

            self._emit_agent_event(event_payload)
            self._log_audit_event(
                action="language_detection",
                context=context,
                result_summary={
                    "detected_language": detection.detected_language,
                    "reply_language": detection.reply_language,
                    "confidence": detection.confidence,
                    "is_mixed": detection.is_mixed,
                },
            )

            duration_ms = round((time.time() - started_at) * 1000, 3)

            return self._safe_result(
                message="Language analysis completed successfully.",
                data={
                    "language": detection.to_dict(),
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={
                    "context": context,
                    "duration_ms": duration_ms,
                    "engine": self.agent_name,
                    "version": self.VERSION,
                },
            )

        except Exception as exc:
            self.logger.exception("LanguageEngine analyze failed")
            return self._error_result(
                message="Language analysis failed.",
                error=str(exc),
                metadata={
                    "context": context,
                    "duration_ms": round((time.time() - started_at) * 1000, 3),
                },
            )

    def detect_language(
        self,
        text: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        previous_language: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Detect language only.

        This is a lighter public method for STT/Voice Loop usage.
        """

        result = self.analyze(
            text=text,
            user_id=user_id,
            workspace_id=workspace_id,
            previous_language=previous_language,
            metadata=metadata,
        )

        if not result.get("success"):
            return result

        language_data = result["data"]["language"]

        return self._safe_result(
            message="Language detected successfully.",
            data={
                "detected_language": language_data["detected_language"],
                "detected_language_name": language_data["detected_language_name"],
                "confidence": language_data["confidence"],
                "script": language_data["script"],
                "is_mixed": language_data["is_mixed"],
                "mixed_languages": language_data["mixed_languages"],
                "direction": language_data["direction"],
                "scores": language_data["scores"],
                "signals": language_data["signals"],
            },
            metadata=result.get("metadata", {}),
        )

    def choose_reply_language(
        self,
        text: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        previous_language: Optional[str] = None,
        preferred_reply_language: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Choose the best reply language.

        Used by:
            - Voice Agent before TTS response
            - Master Agent before final reply
            - Dashboard/API for multilingual settings
        """

        result = self.analyze(
            text=text,
            user_id=user_id,
            workspace_id=workspace_id,
            previous_language=previous_language,
            preferred_reply_language=preferred_reply_language,
            metadata=metadata,
        )

        if not result.get("success"):
            return result

        language_data = result["data"]["language"]
        reply_language = language_data["reply_language"]
        reply_profile = REPLY_STYLE_BY_LANGUAGE.get(
            reply_language,
            REPLY_STYLE_BY_LANGUAGE["unknown"],
        )

        return self._safe_result(
            message="Reply language selected successfully.",
            data={
                "reply_language": reply_language,
                "reply_language_name": language_data["reply_language_name"],
                "reply_direction": language_data["reply_direction"],
                "reply_tone": reply_profile["tone"],
                "detected_language": language_data["detected_language"],
                "confidence": language_data["confidence"],
                "is_mixed": language_data["is_mixed"],
                "mixed_languages": language_data["mixed_languages"],
            },
            metadata=result.get("metadata", {}),
        )

    def detect_script(self, text: str) -> Dict[str, Any]:
        """
        Detect text script:
            - latin
            - arabic
            - devanagari
            - mixed
            - unknown
        """

        try:
            normalized = self.normalize_text(text)
            script, counts = self._detect_script_internal(normalized)

            return self._safe_result(
                message="Script detected successfully.",
                data={
                    "script": script,
                    "script_name": SUPPORTED_SCRIPTS.get(script, script),
                    "counts": counts,
                    "direction": self._direction_for_script(script),
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Script detection failed.",
                error=str(exc),
            )

    def normalize_text(self, text: str) -> str:
        """
        Normalize text for language detection without destroying meaning.

        This keeps Urdu/Arabic/Hindi scripts intact and normalizes whitespace.
        """

        if not isinstance(text, str):
            return ""

        text = unicodedata.normalize("NFKC", text)
        text = text.replace("\u200c", " ")
        text = text.replace("\u200d", " ")
        text = text.replace("\ufeff", "")
        text = re.sub(r"\s+", " ", text).strip()

        return text

    def get_supported_languages(self) -> Dict[str, Any]:
        """Return supported languages for Dashboard/API integration."""

        return self._safe_result(
            message="Supported languages loaded successfully.",
            data={
                "languages": SUPPORTED_LANGUAGE_CODES,
                "scripts": SUPPORTED_SCRIPTS,
                "directions": LANGUAGE_DIRECTION,
                "reply_profiles": REPLY_STYLE_BY_LANGUAGE,
            },
            metadata={
                "engine": self.agent_name,
                "version": self.VERSION,
            },
        )

    def health_check(self) -> Dict[str, Any]:
        """Health check for Agent Registry / Dashboard."""

        sample_checks = {
            "english": self._detect_language_internal("hello how are you").detected_language,
            "roman_urdu": self._detect_language_internal("bhai mujhe final file do").detected_language,
            "urdu": self._detect_language_internal("مجھے یہ فائل چاہیے").detected_language,
            "hindi": self._detect_language_internal("मुझे यह फाइल चाहिए").detected_language,
            "arabic": self._detect_language_internal("مرحبا كيف حالك").detected_language,
        }

        return self._safe_result(
            message="LanguageEngine is healthy.",
            data={
                "status": "healthy",
                "sample_checks": sample_checks,
                "supported_languages": list(SUPPORTED_LANGUAGE_CODES.keys()),
                "config": self.config.to_dict(),
            },
            metadata={
                "engine": self.agent_name,
                "module": self.agent_module,
                "version": self.VERSION,
                "file_path": self.file_path,
            },
        )

    def run(
        self,
        task: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Generic BaseAgent-compatible run method.

        Expected task:
            {
                "action": "analyze" | "detect_language" | "choose_reply_language" | "detect_script",
                "text": "...",
                "user_id": "...",
                "workspace_id": "...",
                "previous_language": "roman_urdu",
                "preferred_reply_language": "en",
                "metadata": {}
            }
        """

        task = task or {}
        action = task.get("action") or kwargs.get("action") or "analyze"
        text = task.get("text", kwargs.get("text", ""))

        user_id = task.get("user_id", kwargs.get("user_id"))
        workspace_id = task.get("workspace_id", kwargs.get("workspace_id"))
        previous_language = task.get("previous_language", kwargs.get("previous_language"))
        preferred_reply_language = task.get(
            "preferred_reply_language",
            kwargs.get("preferred_reply_language"),
        )
        metadata = task.get("metadata", kwargs.get("metadata", {}))
        task_id = task.get("task_id", kwargs.get("task_id"))

        if action == "analyze":
            return self.analyze(
                text=text,
                user_id=user_id,
                workspace_id=workspace_id,
                previous_language=previous_language,
                preferred_reply_language=preferred_reply_language,
                task_id=task_id,
                metadata=metadata,
            )

        if action == "detect_language":
            return self.detect_language(
                text=text,
                user_id=user_id,
                workspace_id=workspace_id,
                previous_language=previous_language,
                metadata=metadata,
            )

        if action == "choose_reply_language":
            return self.choose_reply_language(
                text=text,
                user_id=user_id,
                workspace_id=workspace_id,
                previous_language=previous_language,
                preferred_reply_language=preferred_reply_language,
                metadata=metadata,
            )

        if action == "detect_script":
            return self.detect_script(text=text)

        if action == "supported_languages":
            return self.get_supported_languages()

        if action == "health_check":
            return self.health_check()

        return self._error_result(
            message=f"Unsupported LanguageEngine action: {action}",
            error="unsupported_action",
            metadata={"action": action},
        )

    # =========================================================================
    # Internal Detection Logic
    # =========================================================================

    def _detect_language_internal(
        self,
        text: str,
        previous_language: Optional[str] = None,
        preferred_reply_language: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> LanguageDetectionResult:
        metadata = metadata or {}
        original_text = text or ""
        normalized = self.normalize_text(original_text)

        if not normalized:
            reply_language = self._safe_language_code(
                preferred_reply_language or previous_language or self.config.default_reply_language
            )

            return LanguageDetectionResult(
                detected_language="unknown",
                detected_language_name=SUPPORTED_LANGUAGE_CODES["unknown"],
                confidence=0.0,
                script="unknown",
                script_name=SUPPORTED_SCRIPTS["unknown"],
                is_mixed=False,
                mixed_languages=[],
                direction="auto",
                reply_language=reply_language,
                reply_language_name=SUPPORTED_LANGUAGE_CODES.get(reply_language, "English"),
                reply_direction=LANGUAGE_DIRECTION.get(reply_language, "ltr"),
                normalized_text=normalized,
                original_text=original_text,
                scores={
                    "en": 0.0,
                    "roman_urdu": 0.0,
                    "ur": 0.0,
                    "hi": 0.0,
                    "ar": 0.0,
                },
                signals={},
                metadata={
                    "reason": "empty_text",
                    **metadata,
                },
            )

        script, script_counts = self._detect_script_internal(normalized)
        tokens = self._tokenize(normalized)

        score_objects = {
            "en": LanguageScore("en", 0.0, []),
            "roman_urdu": LanguageScore("roman_urdu", 0.0, []),
            "ur": LanguageScore("ur", 0.0, []),
            "hi": LanguageScore("hi", 0.0, []),
            "ar": LanguageScore("ar", 0.0, []),
        }

        self._apply_script_scores(score_objects, script, script_counts)
        self._apply_dictionary_scores(score_objects, normalized, tokens)
        self._apply_pattern_scores(score_objects, normalized, tokens)
        self._apply_contextual_scores(score_objects, normalized, tokens)

        scores = {lang: obj.score for lang, obj in score_objects.items()}
        signals = {lang: obj.signals for lang, obj in score_objects.items() if obj.signals}

        scores = self._normalize_scores(scores)
        sorted_scores = sorted(scores.items(), key=lambda item: item[1], reverse=True)

        top_language, top_score = sorted_scores[0]
        second_language, second_score = sorted_scores[1] if len(sorted_scores) > 1 else ("unknown", 0.0)

        is_mixed, mixed_languages = self._detect_mixed_language(
            scores=scores,
            top_language=top_language,
            second_language=second_language,
            top_score=top_score,
            second_score=second_score,
            script=script,
        )

        detected_language = top_language
        confidence = top_score

        if confidence < self.config.confidence_threshold:
            if previous_language and self.config.prefer_user_previous_language:
                safe_previous = self._safe_language_code(previous_language)
                if safe_previous != "unknown":
                    detected_language = safe_previous
                    confidence = max(confidence, 0.38)
                    signals.setdefault(detected_language, []).append("previous_language_fallback")
                else:
                    detected_language = "unknown"
            else:
                detected_language = "unknown"

        if is_mixed and self.config.allow_mixed_language_reply:
            detected_language_for_reply = "mixed"
        else:
            detected_language_for_reply = detected_language

        reply_language = self._choose_reply_language_internal(
            detected_language=detected_language_for_reply,
            top_language=top_language,
            preferred_reply_language=preferred_reply_language,
            previous_language=previous_language,
            mixed_languages=mixed_languages,
            scores=scores,
        )

        direction = LANGUAGE_DIRECTION.get(detected_language, "auto")
        reply_direction = LANGUAGE_DIRECTION.get(reply_language, "auto")

        return LanguageDetectionResult(
            detected_language=detected_language,
            detected_language_name=SUPPORTED_LANGUAGE_CODES.get(
                detected_language,
                SUPPORTED_LANGUAGE_CODES["unknown"],
            ),
            confidence=confidence,
            script=script,
            script_name=SUPPORTED_SCRIPTS.get(script, script),
            is_mixed=is_mixed,
            mixed_languages=mixed_languages,
            direction=direction,
            reply_language=reply_language,
            reply_language_name=SUPPORTED_LANGUAGE_CODES.get(
                reply_language,
                SUPPORTED_LANGUAGE_CODES["unknown"],
            ),
            reply_direction=reply_direction,
            normalized_text=normalized,
            original_text=original_text,
            scores=scores,
            signals=signals,
            metadata={
                "script_counts": script_counts,
                "token_count": len(tokens),
                "top_language": top_language,
                "top_score": round(float(top_score), 4),
                "second_language": second_language,
                "second_score": round(float(second_score), 4),
                "confidence_threshold": self.config.confidence_threshold,
                **metadata,
            },
        )

    def _detect_script_internal(self, text: str) -> Tuple[str, Dict[str, int]]:
        latin = 0
        arabic = 0
        devanagari = 0
        digits = 0
        other = 0

        for char in text:
            if char.isspace() or unicodedata.category(char).startswith("P"):
                continue

            code = ord(char)

            if "0" <= char <= "9":
                digits += 1
            elif (
                0x0041 <= code <= 0x005A
                or 0x0061 <= code <= 0x007A
                or 0x00C0 <= code <= 0x024F
            ):
                latin += 1
            elif 0x0600 <= code <= 0x06FF or 0x0750 <= code <= 0x077F or 0x08A0 <= code <= 0x08FF:
                arabic += 1
            elif 0x0900 <= code <= 0x097F:
                devanagari += 1
            else:
                other += 1

        counts = {
            "latin": latin,
            "arabic": arabic,
            "devanagari": devanagari,
            "digits": digits,
            "other": other,
        }

        major_counts = {
            "latin": latin,
            "arabic": arabic,
            "devanagari": devanagari,
        }

        non_zero = [name for name, count in major_counts.items() if count > 0]

        if not non_zero:
            return "unknown", counts

        if len(non_zero) > 1:
            return "mixed", counts

        return non_zero[0], counts

    def _apply_script_scores(
        self,
        score_objects: Dict[str, LanguageScore],
        script: str,
        script_counts: Dict[str, int],
    ) -> None:
        total_script_chars = (
            script_counts.get("latin", 0)
            + script_counts.get("arabic", 0)
            + script_counts.get("devanagari", 0)
        )

        if total_script_chars <= 0:
            return

        latin_ratio = script_counts.get("latin", 0) / total_script_chars
        arabic_ratio = script_counts.get("arabic", 0) / total_script_chars
        devanagari_ratio = script_counts.get("devanagari", 0) / total_script_chars

        if script == "latin":
            score_objects["en"].score += 0.24 + (latin_ratio * 0.12)
            score_objects["en"].signals.append("latin_script")
            score_objects["roman_urdu"].score += 0.25 + (latin_ratio * 0.12)
            score_objects["roman_urdu"].signals.append("latin_script_possible_roman_urdu")

        elif script == "arabic":
            score_objects["ur"].score += 0.30 + (arabic_ratio * 0.15)
            score_objects["ur"].signals.append("arabic_script_possible_urdu")
            score_objects["ar"].score += 0.30 + (arabic_ratio * 0.15)
            score_objects["ar"].signals.append("arabic_script_possible_arabic")

        elif script == "devanagari":
            score_objects["hi"].score += 0.55 + (devanagari_ratio * 0.20)
            score_objects["hi"].signals.append("devanagari_script")

        elif script == "mixed":
            if latin_ratio > 0:
                score_objects["en"].score += latin_ratio * 0.18
                score_objects["roman_urdu"].score += latin_ratio * 0.18
                score_objects["en"].signals.append("mixed_script_latin")
                score_objects["roman_urdu"].signals.append("mixed_script_latin")

            if arabic_ratio > 0:
                score_objects["ur"].score += arabic_ratio * 0.24
                score_objects["ar"].score += arabic_ratio * 0.24
                score_objects["ur"].signals.append("mixed_script_arabic")
                score_objects["ar"].signals.append("mixed_script_arabic")

            if devanagari_ratio > 0:
                score_objects["hi"].score += devanagari_ratio * 0.30
                score_objects["hi"].signals.append("mixed_script_devanagari")

    def _apply_dictionary_scores(
        self,
        score_objects: Dict[str, LanguageScore],
        normalized_text: str,
        tokens: List[str],
    ) -> None:
        lower_tokens = [token.lower() for token in tokens]

        english_hits = self._count_hits(lower_tokens, self.ENGLISH_STOPWORDS)
        roman_urdu_hits = self._count_hits(lower_tokens, self.ROMAN_URDU_WORDS)
        hindi_roman_hits = self._count_hits(lower_tokens, self.HINDI_ROMAN_WORDS)

        if english_hits:
            score_objects["en"].score += min(0.46, english_hits * 0.055)
            score_objects["en"].signals.append(f"english_dictionary_hits:{english_hits}")

        if roman_urdu_hits:
            score_objects["roman_urdu"].score += min(0.60, roman_urdu_hits * 0.075)
            score_objects["roman_urdu"].signals.append(f"roman_urdu_dictionary_hits:{roman_urdu_hits}")

        if hindi_roman_hits:
            score_objects["hi"].score += min(0.25, hindi_roman_hits * 0.035)
            score_objects["hi"].signals.append(f"hindi_roman_dictionary_hits:{hindi_roman_hits}")

        urdu_hits = self._count_script_word_hits(normalized_text, self.URDU_COMMON_WORDS)
        arabic_hits = self._count_script_word_hits(normalized_text, self.ARABIC_COMMON_WORDS)
        hindi_hits = self._count_script_word_hits(normalized_text, self.HINDI_COMMON_WORDS)

        if urdu_hits:
            score_objects["ur"].score += min(0.62, urdu_hits * 0.09)
            score_objects["ur"].signals.append(f"urdu_dictionary_hits:{urdu_hits}")

        if arabic_hits:
            score_objects["ar"].score += min(0.62, arabic_hits * 0.09)
            score_objects["ar"].signals.append(f"arabic_dictionary_hits:{arabic_hits}")

        if hindi_hits:
            score_objects["hi"].score += min(0.62, hindi_hits * 0.09)
            score_objects["hi"].signals.append(f"hindi_dictionary_hits:{hindi_hits}")

    def _apply_pattern_scores(
        self,
        score_objects: Dict[str, LanguageScore],
        normalized_text: str,
        tokens: List[str],
    ) -> None:
        lower_text = normalized_text.lower()
        lower_tokens = [token.lower() for token in tokens]

        roman_urdu_patterns = [
            r"\b(gave|give)\s+me\s+.*\b(file|code)\b",
            r"\bnow\s+(gave|give)\s+me\b",
            r"\bfull\s+final\s+file\b",
            r"\bpori|poori|pura|poora\b",
            r"\bkero|karo|krdo|kar\s+do|ker\s+do\b",
            r"\bmujh(e|y|y)?\b",
            r"\bisy|isko|yeh|ye|wo|woh\b",
            r"\bkyun|q|kunky|kyunki|qk\b",
        ]

        english_patterns = [
            r"\bplease\s+(create|write|explain|help|make|give)\b",
            r"\bhow\s+(to|can|do|does)\b",
            r"\bwhat\s+(is|are|does|do)\b",
            r"\bi\s+want\s+(you|to)\b",
            r"\bcan\s+you\b",
        ]

        arabic_patterns = [
            r"[\u0600-\u06FF]+",
        ]

        hindi_patterns = [
            r"[\u0900-\u097F]+",
        ]

        for pattern in roman_urdu_patterns:
            if re.search(pattern, lower_text, re.IGNORECASE):
                score_objects["roman_urdu"].score += 0.07
                score_objects["roman_urdu"].signals.append(f"roman_urdu_pattern:{pattern}")

        for pattern in english_patterns:
            if re.search(pattern, lower_text, re.IGNORECASE):
                score_objects["en"].score += 0.06
                score_objects["en"].signals.append(f"english_pattern:{pattern}")

        for pattern in arabic_patterns:
            if re.search(pattern, normalized_text):
                score_objects["ur"].score += 0.06
                score_objects["ar"].score += 0.06
                score_objects["ur"].signals.append("arabic_unicode_pattern")
                score_objects["ar"].signals.append("arabic_unicode_pattern")

        for pattern in hindi_patterns:
            if re.search(pattern, normalized_text):
                score_objects["hi"].score += 0.08
                score_objects["hi"].signals.append("devanagari_unicode_pattern")

        if any(token.endswith(("ing", "tion", "ment", "able", "ness")) for token in lower_tokens):
            score_objects["en"].score += 0.04
            score_objects["en"].signals.append("english_suffix_pattern")

        if any(token in {"bhai", "yaar", "acha", "theek", "nhi", "nahi"} for token in lower_tokens):
            score_objects["roman_urdu"].score += 0.08
            score_objects["roman_urdu"].signals.append("roman_urdu_conversation_marker")

    def _apply_contextual_scores(
        self,
        score_objects: Dict[str, LanguageScore],
        normalized_text: str,
        tokens: List[str],
    ) -> None:
        clean_for_context = self._remove_non_language_noise(normalized_text)
        lower_text = clean_for_context.lower()

        if not tokens:
            return

        latin_tokens = [
            token for token in tokens
            if re.fullmatch(r"[a-zA-Z][a-zA-Z'-]*", token)
        ]

        if latin_tokens and len(latin_tokens) == len(tokens):
            avg_len = sum(len(token) for token in latin_tokens) / max(1, len(latin_tokens))

            if avg_len >= 4.2:
                score_objects["en"].score += 0.03
                score_objects["en"].signals.append("latin_average_word_length_english_possible")

            roman_markers = {"hai", "kya", "mujhe", "mujhy", "kero", "karo", "nhi", "btao", "isy"}
            if roman_markers.intersection({token.lower() for token in latin_tokens}):
                score_objects["roman_urdu"].score += 0.09
                score_objects["roman_urdu"].signals.append("roman_urdu_marker_intersection")

        technical_words = {
            "api", "json", "python", "flutter", "kotlin", "backend", "frontend",
            "database", "server", "file", "class", "function", "agent", "module",
            "dashboard", "route", "endpoint", "config", "import",
        }

        tech_hits = self._count_hits([token.lower() for token in tokens], technical_words)
        if tech_hits >= 2:
            score_objects["en"].score += min(0.12, tech_hits * 0.02)
            score_objects["en"].signals.append(f"technical_english_hits:{tech_hits}")

        roman_urdu_command_mix = (
            ("gave me" in lower_text or "give me" in lower_text)
            and any(marker in lower_text for marker in ["full final", "file", "code", "ab", "isy", "mujhe"])
        )
        if roman_urdu_command_mix:
            score_objects["roman_urdu"].score += 0.11
            score_objects["roman_urdu"].signals.append("user_style_roman_urdu_english_mix")

    def _detect_mixed_language(
        self,
        scores: Dict[str, float],
        top_language: str,
        second_language: str,
        top_score: float,
        second_score: float,
        script: str,
    ) -> Tuple[bool, List[str]]:
        meaningful = [
            lang for lang, score in scores.items()
            if score >= 0.22 and lang != "unknown"
        ]

        close_scores = (
            top_score >= 0.30
            and second_score >= 0.22
            and abs(top_score - second_score) <= 0.20
        )

        mixed_script = script == "mixed"

        roman_urdu_english_mix = (
            {"en", "roman_urdu"}.issubset(set(meaningful))
            and second_score >= 0.20
        )

        if mixed_script or close_scores or roman_urdu_english_mix or len(meaningful) >= 3:
            return True, meaningful[:4]

        return False, []

    def _choose_reply_language_internal(
        self,
        detected_language: str,
        top_language: str,
        preferred_reply_language: Optional[str],
        previous_language: Optional[str],
        mixed_languages: List[str],
        scores: Dict[str, float],
    ) -> str:
        preferred = self._safe_language_code(preferred_reply_language)
        if preferred != "unknown":
            return preferred

        if detected_language == "mixed":
            if "roman_urdu" in mixed_languages and "en" in mixed_languages:
                return "roman_urdu"

            if top_language in SUPPORTED_LANGUAGE_CODES and top_language != "unknown":
                return top_language

            if mixed_languages:
                return mixed_languages[0]

        detected_safe = self._safe_language_code(detected_language)
        if detected_safe != "unknown":
            return detected_safe

        previous = self._safe_language_code(previous_language)
        if previous != "unknown" and self.config.prefer_user_previous_language:
            return previous

        default = self._safe_language_code(self.config.default_reply_language)
        if default != "unknown":
            return default

        if scores:
            best = max(scores.items(), key=lambda item: item[1])[0]
            best_safe = self._safe_language_code(best)
            if best_safe != "unknown":
                return best_safe

        return "en"

    def _normalize_scores(self, scores: Dict[str, float]) -> Dict[str, float]:
        cleaned = {
            lang: max(0.0, min(1.0, float(score)))
            for lang, score in scores.items()
        }

        max_score = max(cleaned.values()) if cleaned else 0.0

        if max_score <= 0:
            return cleaned

        if max_score > 1.0:
            return {
                lang: score / max_score
                for lang, score in cleaned.items()
            }

        return cleaned

    def _tokenize(self, text: str) -> List[str]:
        clean_text = self._remove_non_language_noise(text)
        tokens = re.findall(
            r"[\w\u0600-\u06FF\u0900-\u097F']+",
            clean_text,
            flags=re.UNICODE,
        )
        return [token for token in tokens if token.strip()]

    def _remove_non_language_noise(self, text: str) -> str:
        text = self.URL_PATTERN.sub(" ", text)
        text = self.EMAIL_PATTERN.sub(" ", text)
        text = self.PHONE_PATTERN.sub(" ", text)
        text = re.sub(r"[_*#`~<>|{}\[\]\\]+", " ", text)
        text = re.sub(r"\s+", " ", text).strip()
        return text

    def _count_hits(self, tokens: List[str], dictionary: set) -> int:
        return sum(1 for token in tokens if token in dictionary)

    def _count_script_word_hits(self, text: str, dictionary: set) -> int:
        count = 0
        for word in dictionary:
            if word and word in text:
                count += 1
        return count

    def _safe_language_code(self, language_code: Optional[str]) -> str:
        if not language_code:
            return "unknown"

        normalized = str(language_code).strip().lower().replace("-", "_")

        aliases = {
            "english": "en",
            "eng": "en",
            "roman": "roman_urdu",
            "romanurdu": "roman_urdu",
            "roman_urdu": "roman_urdu",
            "urdu_roman": "roman_urdu",
            "ur": "ur",
            "urdu": "ur",
            "hi": "hi",
            "hindi": "hi",
            "ar": "ar",
            "arabic": "ar",
            "mixed": "mixed",
            "auto": "unknown",
            "unknown": "unknown",
        }

        return aliases.get(normalized, "unknown")

    def _direction_for_script(self, script: str) -> str:
        if script == "arabic":
            return "rtl"
        if script in {"latin", "devanagari"}:
            return "ltr"
        return "auto"

    # =========================================================================
    # Required Compatibility Hooks
    # =========================================================================

    def _validate_task_context(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate SaaS user/workspace context.

        Language detection can run without user_id/workspace_id for local tests,
        but when either is provided, both are preserved in metadata to prevent
        accidental cross-user mixing in future logs, memory, and analytics.
        """

        user_id = context.get("user_id")
        workspace_id = context.get("workspace_id")

        if user_id is not None and str(user_id).strip() == "":
            return self._error_result(
                message="Invalid user_id.",
                error="invalid_user_id",
                metadata={"context": context},
            )

        if workspace_id is not None and str(workspace_id).strip() == "":
            return self._error_result(
                message="Invalid workspace_id.",
                error="invalid_workspace_id",
                metadata={"context": context},
            )

        return self._safe_result(
            message="Task context validated.",
            data={"context_valid": True},
            metadata={"context": context},
        )

    def _requires_security_check(
        self,
        action: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Language detection is non-destructive and does not require approval.

        This hook exists for compatibility with Security Agent. If future
        language tasks attempt to trigger calls/messages/browser/system actions,
        this method can require approval.
        """

        sensitive_actions = {
            "send_message",
            "make_call",
            "browser_action",
            "system_action",
            "financial_action",
            "delete_memory",
            "export_user_data",
        }

        return action in sensitive_actions

    def _request_security_approval(
        self,
        action: str,
        context: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request approval from Security Agent if available.

        Fallback behavior:
            - Non-sensitive action: approved
            - Sensitive action with no Security Agent: denied
        """

        context = context or {}
        metadata = metadata or {}

        if self.security_client and hasattr(self.security_client, "approve"):
            try:
                approval = self.security_client.approve(
                    action=action,
                    context=context,
                    metadata=metadata,
                )
                if isinstance(approval, dict):
                    return approval
            except Exception as exc:
                self.logger.warning("Security approval request failed: %s", exc)
                return {
                    "approved": False,
                    "reason": "security_client_error",
                    "error": str(exc),
                }

        if not self._requires_security_check(action, context):
            return {
                "approved": True,
                "reason": "non_sensitive_language_engine_action",
            }

        return {
            "approved": False,
            "reason": "security_client_unavailable_for_sensitive_action",
        }

    def _prepare_verification_payload(
        self,
        action: str,
        result: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent compatible payload.

        Verification Agent can use this to check:
            - detected language
            - reply language
            - confidence score
            - whether fallback was used
        """

        if not self.config.verification_enabled:
            return {
                "enabled": False,
                "reason": "verification_disabled",
            }

        payload = {
            "enabled": True,
            "agent": self.agent_name,
            "module": self.agent_module,
            "file_path": self.file_path,
            "action": action,
            "context": context or {},
            "result_summary": {
                "detected_language": result.get("detected_language"),
                "detected_language_name": result.get("detected_language_name"),
                "reply_language": result.get("reply_language"),
                "reply_language_name": result.get("reply_language_name"),
                "confidence": result.get("confidence"),
                "is_mixed": result.get("is_mixed"),
                "mixed_languages": result.get("mixed_languages"),
            },
            "verification_checks": [
                "language_code_supported",
                "confidence_score_present",
                "reply_language_selected",
                "saas_context_preserved",
            ],
            "created_at": time.time(),
        }

        if self.verification_client and hasattr(self.verification_client, "prepare"):
            try:
                prepared = self.verification_client.prepare(payload)
                if isinstance(prepared, dict):
                    return prepared
            except Exception as exc:
                self.logger.warning("Verification payload preparation failed: %s", exc)
                payload["verification_client_error"] = str(exc)

        return payload

    def _prepare_memory_payload(
        self,
        text: str,
        detection: LanguageDetectionResult,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        The payload stores useful preference-level language signals only.
        It does not store secrets or raw private content unnecessarily.
        """

        if not self.config.memory_enabled:
            return {
                "enabled": False,
                "reason": "memory_disabled",
            }

        context = context or {}

        payload = {
            "enabled": True,
            "agent": self.agent_name,
            "module": self.agent_module,
            "memory_type": "language_preference_signal",
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "task_id": context.get("task_id"),
            "data": {
                "detected_language": detection.detected_language,
                "detected_language_name": detection.detected_language_name,
                "reply_language": detection.reply_language,
                "reply_language_name": detection.reply_language_name,
                "confidence": detection.confidence,
                "is_mixed": detection.is_mixed,
                "mixed_languages": detection.mixed_languages,
                "direction": detection.direction,
                "reply_direction": detection.reply_direction,
            },
            "privacy": {
                "stores_raw_text": False,
                "cross_workspace_allowed": False,
                "cross_user_allowed": False,
            },
            "created_at": time.time(),
        }

        if self.memory_client and hasattr(self.memory_client, "prepare"):
            try:
                prepared = self.memory_client.prepare(payload)
                if isinstance(prepared, dict):
                    return prepared
            except Exception as exc:
                self.logger.warning("Memory payload preparation failed: %s", exc)
                payload["memory_client_error"] = str(exc)

        return payload

    def _emit_agent_event(self, payload: Dict[str, Any]) -> None:
        """
        Emit event for Agent Registry / Dashboard analytics if event bus exists.
        """

        if not self.config.emit_events:
            return

        try:
            if self.event_bus and hasattr(self.event_bus, "emit"):
                self.event_bus.emit(payload)
                return

            self.logger.debug("LanguageEngine event: %s", payload)

        except Exception as exc:
            self.logger.warning("Failed to emit LanguageEngine event: %s", exc)

    def _log_audit_event(
        self,
        action: str,
        context: Optional[Dict[str, Any]] = None,
        result_summary: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log audit event without mixing SaaS user/workspace data.
        """

        if not self.config.audit_enabled:
            return

        payload = {
            "agent": self.agent_name,
            "module": self.agent_module,
            "action": action,
            "context": context or {},
            "result_summary": result_summary or {},
            "timestamp": time.time(),
        }

        try:
            if self.audit_client and hasattr(self.audit_client, "log"):
                self.audit_client.log(payload)
                return

            self.logger.debug("LanguageEngine audit: %s", payload)

        except Exception as exc:
            self.logger.warning("Failed to log LanguageEngine audit event: %s", exc)

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Standard William/Jarvis success result."""

        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Any] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Standard William/Jarvis error result."""

        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": str(error) if error is not None else "unknown_error",
            "metadata": metadata or {},
        }


# =============================================================================
# Local Manual Test
# =============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    engine = LanguageEngine()

    samples = [
        "Hello, can you create this full final file?",
        "bhai mujhe ye full final file do",
        "مجھے یہ فائل چاہیے",
        "मुझे यह फाइल चाहिए",
        "مرحبا كيف حالك",
        "now gave me full final file isy complete kero",
    ]

    for sample in samples:
        output = engine.analyze(
            text=sample,
            user_id="local_test_user",
            workspace_id="local_test_workspace",
        )
        print("-" * 80)
        print(sample)
        print(output)

"""
Agent/Module: Voice Agent
File Completed: language_engine.py
Completion: 25.0%
Completed Files: ['voice_agent.py', 'wake_word.py', 'stt_engine.py', 'tts_engine.py', 'language_engine.py']
Remaining Files: ['device_stream.py', 'interruption.py', 'voice_loop.py', 'session_manager.py', 'audio_router.py', 'noise_control.py', 'speaker_recognition.py', 'emotion_detector.py', 'whisper_mode.py', 'voice_profiles.py', 'voice_cloning.py', 'gesture_trigger.py', 'conversation_mode.py', 'voice_memory.py', 'config.py']
Next Recommended File: agents/voice_agent/device_stream.py
FILE COMPLETE
"""