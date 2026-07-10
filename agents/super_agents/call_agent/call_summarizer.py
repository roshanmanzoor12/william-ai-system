"""
agents/super_agents/call_agent/call_summarizer.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix

Purpose:
    Summarizes calls, action items, sentiment, and next steps for the Call Agent.

Import Safety:
    - Safe to import even if the full William/Jarvis framework is not created yet.
    - Uses fallback BaseAgent if unavailable.
    - Does not execute real calls, messages, bookings, browser, financial, or destructive actions.
    - Keeps user_id/workspace_id isolation for every user-specific operation.

Architecture Connections:
    - Master Agent / Agent Router:
        Exposes router-friendly `run()` and structured public methods.
    - Security Agent:
        Sensitive export/retention actions can be protected through security approval.
    - Memory Agent:
        Produces sanitized call summary memory payloads.
    - Verification Agent:
        Produces verification payloads after completed summarization.
    - Dashboard/API:
        Returns JSON-style summaries, analytics, action items, and sentiment results.
    - Agent Registry / Agent Loader:
        Stable class name: CallSummarizer.
"""

from __future__ import annotations

import copy
import json
import logging
import re
import statistics
import threading
import uuid
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional BaseAgent import
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps this file import-safe before the full William/Jarvis
        framework exists.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
            self.logger = logging.getLogger(self.agent_name)

        async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent.run is not implemented.",
                "data": {},
                "error": {
                    "code": "base_agent_not_available",
                    "message": "BaseAgent is unavailable.",
                },
                "metadata": {},
            }


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

AGENT_NAME = "CallSummarizer"
AGENT_MODULE = "call_agent"
FILE_NAME = "call_summarizer.py"
SCHEMA_VERSION = "1.0.0"

DEFAULT_MAX_TRANSCRIPT_CHARS = 120000
DEFAULT_MAX_ACTION_ITEMS = 25
DEFAULT_MAX_NEXT_STEPS = 15
DEFAULT_MAX_KEY_POINTS = 20
DEFAULT_MIN_ACTION_CONFIDENCE = 0.45


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class CallSummaryStatus(str, Enum):
    """Call summary lifecycle status."""

    CREATED = "created"
    UPDATED = "updated"
    FAILED = "failed"


class SentimentLabel(str, Enum):
    """Supported sentiment labels."""

    POSITIVE = "positive"
    NEUTRAL = "neutral"
    NEGATIVE = "negative"
    MIXED = "mixed"
    UNKNOWN = "unknown"


class CallOutcome(str, Enum):
    """Detected call outcome."""

    INTERESTED = "interested"
    NOT_INTERESTED = "not_interested"
    CALLBACK_REQUESTED = "callback_requested"
    APPOINTMENT_REQUESTED = "appointment_requested"
    PRICE_DISCUSSION = "price_discussion"
    SUPPORT_REQUEST = "support_request"
    COMPLAINT = "complaint"
    WRONG_NUMBER = "wrong_number"
    VOICEMAIL = "voicemail"
    NO_CLEAR_OUTCOME = "no_clear_outcome"


class ActionPriority(str, Enum):
    """Action item priority."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    URGENT = "urgent"


class RiskLevel(str, Enum):
    """Compliance or escalation risk level."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class CallSummarizerConfig:
    """
    Configuration for CallSummarizer.

    The default summarizer is deterministic and offline. It does not require an
    LLM provider, which keeps this module safe and testable.
    """

    max_transcript_chars: int = DEFAULT_MAX_TRANSCRIPT_CHARS
    max_action_items: int = DEFAULT_MAX_ACTION_ITEMS
    max_next_steps: int = DEFAULT_MAX_NEXT_STEPS
    max_key_points: int = DEFAULT_MAX_KEY_POINTS
    min_action_confidence: float = DEFAULT_MIN_ACTION_CONFIDENCE
    allow_sensitive_without_security: bool = False
    enable_memory_payloads: bool = True
    enable_verification_payloads: bool = True
    enable_audit_log: bool = True
    enable_agent_events: bool = True
    redact_sensitive_data: bool = True
    keep_raw_transcript_in_result: bool = False
    default_language: str = "en"
    expected_call_data_fields: Tuple[str, ...] = (
        "call_id",
        "phone_number",
        "direction",
        "started_at",
        "ended_at",
        "duration_seconds",
        "agent_name",
        "caller_name",
        "campaign_id",
        "lead_id",
    )


@dataclass
class TranscriptTurn:
    """A normalized transcript turn."""

    speaker: str
    text: str
    timestamp: Optional[str] = None
    confidence: Optional[float] = None


@dataclass
class ActionItem:
    """A detected call action item."""

    action_id: str
    title: str
    description: str
    owner: Optional[str]
    priority: str
    due_hint: Optional[str]
    source_text: str
    confidence: float
    created_at: str


@dataclass
class NextStep:
    """A recommended next step."""

    step_id: str
    title: str
    description: str
    priority: str
    recommended_owner: Optional[str]
    reason: str
    created_at: str


@dataclass
class SentimentResult:
    """Sentiment analysis result."""

    label: str
    score: float
    positive_hits: int
    negative_hits: int
    neutral_hits: int
    evidence: List[str] = field(default_factory=list)


@dataclass
class CallSummaryRecord:
    """Stored call summary record."""

    summary_id: str
    call_id: str
    user_id: str
    workspace_id: str
    status: str
    summary_text: str
    short_summary: str
    key_points: List[str]
    action_items: List[ActionItem]
    next_steps: List[NextStep]
    sentiment: SentimentResult
    outcome: str
    risk_level: str
    risk_flags: List[str]
    entities: Dict[str, Any]
    call_metadata: Dict[str, Any]
    transcript_stats: Dict[str, Any]
    created_at: str
    updated_at: str
    error: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _utcnow() -> datetime:
    """Return timezone-aware UTC datetime."""

    return datetime.now(timezone.utc)


def _iso_now() -> str:
    """Return current UTC timestamp as ISO string."""

    return _utcnow().isoformat()


def _safe_uuid(prefix: str) -> str:
    """Create readable stable unique ID."""

    return f"{prefix}_{uuid.uuid4().hex}"


def _deepcopy_json_safe(value: Any) -> Any:
    """Safely copy data into JSON-compatible structure."""

    try:
        return json.loads(json.dumps(value, default=str))
    except Exception:
        try:
            return copy.deepcopy(value)
        except Exception:
            return str(value)


def _redact_sensitive_value(key: str, value: Any) -> Any:
    """Redact common sensitive values from nested structures."""

    lowered = key.lower()
    sensitive_markers = (
        "password",
        "secret",
        "token",
        "api_key",
        "apikey",
        "authorization",
        "bearer",
        "private_key",
        "credential",
        "cookie",
        "session",
        "otp",
        "pin",
        "card",
        "cvv",
        "ssn",
    )

    if any(marker in lowered for marker in sensitive_markers):
        return "***REDACTED***"

    if isinstance(value, Mapping):
        return {str(k): _redact_sensitive_value(str(k), v) for k, v in value.items()}

    if isinstance(value, list):
        return [_redact_sensitive_value(key, item) for item in value]

    if isinstance(value, tuple):
        return tuple(_redact_sensitive_value(key, item) for item in value)

    return value


def _sanitize_dict(payload: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    """Sanitize dict-like payload."""

    if not payload:
        return {}

    safe: Dict[str, Any] = {}
    for key, value in payload.items():
        safe[str(key)] = _redact_sensitive_value(str(key), _deepcopy_json_safe(value))
    return safe


def _as_serializable(value: Any) -> Any:
    """Convert dataclasses/enums to JSON-style data."""

    if isinstance(value, Enum):
        return value.value

    if hasattr(value, "__dataclass_fields__"):
        return _as_serializable(asdict(value))

    if isinstance(value, dict):
        return {str(k): _as_serializable(v) for k, v in value.items()}

    if isinstance(value, list):
        return [_as_serializable(v) for v in value]

    if isinstance(value, tuple):
        return [_as_serializable(v) for v in value]

    return _deepcopy_json_safe(value)


def _normalize_error(
    error: Optional[Union[str, BaseException, Mapping[str, Any]]],
    *,
    code: Optional[str] = None,
) -> Dict[str, Any]:
    """Normalize any error into structured dict."""

    if error is None:
        return {
            "code": code or "unknown_error",
            "message": "Unknown error.",
            "type": "unknown_error",
            "timestamp": _iso_now(),
        }

    if isinstance(error, BaseException):
        return {
            "code": code or error.__class__.__name__,
            "message": str(error) or error.__class__.__name__,
            "type": error.__class__.__name__,
            "timestamp": _iso_now(),
        }

    if isinstance(error, Mapping):
        safe = _sanitize_dict(error)
        return {
            "code": str(code or safe.get("code") or safe.get("type") or "error"),
            "message": str(safe.get("message") or safe.get("error") or "Error"),
            "type": str(safe.get("type") or "error"),
            "details": safe,
            "timestamp": _iso_now(),
        }

    return {
        "code": code or "error",
        "message": str(error),
        "type": "error",
        "timestamp": _iso_now(),
    }


def _strip_extra_spaces(text: str) -> str:
    """Normalize whitespace."""

    return re.sub(r"\s+", " ", text or "").strip()


def _split_sentences(text: str) -> List[str]:
    """Simple sentence splitter without external dependencies."""

    cleaned = _strip_extra_spaces(text)
    if not cleaned:
        return []

    pieces = re.split(r"(?<=[.!?])\s+|\n+", cleaned)
    sentences = [_strip_extra_spaces(piece) for piece in pieces if _strip_extra_spaces(piece)]

    if len(sentences) <= 1 and len(cleaned) > 240:
        chunks: List[str] = []
        words = cleaned.split()
        for i in range(0, len(words), 35):
            chunks.append(" ".join(words[i:i + 35]))
        return chunks

    return sentences


def _word_count(text: str) -> int:
    """Count words."""

    return len(re.findall(r"\b[\w'-]+\b", text or ""))


def _safe_ratio(numerator: Union[int, float], denominator: Union[int, float]) -> float:
    """Safe ratio rounded to 4 decimals."""

    if not denominator:
        return 0.0

    try:
        return round(float(numerator) / float(denominator), 4)
    except Exception:
        return 0.0


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

class InMemoryCallSummaryStore:
    """
    Thread-safe in-memory call summary store.

    This is suitable for local tests and default import-safe behavior.
    Production can replace it with DB-backed storage while preserving method
    signatures.
    """

    def __init__(self) -> None:
        self._records: Dict[str, CallSummaryRecord] = {}
        self._tenant_index: Dict[Tuple[str, str], List[str]] = defaultdict(list)
        self._lock = threading.RLock()

    @staticmethod
    def make_key(user_id: str, workspace_id: str, summary_id: str) -> str:
        """Build tenant-isolated key."""

        return f"{user_id}::{workspace_id}::{summary_id}"

    def save(self, record: CallSummaryRecord) -> None:
        """Save summary record."""

        with self._lock:
            key = self.make_key(record.user_id, record.workspace_id, record.summary_id)
            tenant_key = (record.user_id, record.workspace_id)
            is_new = key not in self._records

            self._records[key] = record

            if is_new:
                self._tenant_index[tenant_key].append(record.summary_id)

    def get(self, user_id: str, workspace_id: str, summary_id: str) -> Optional[CallSummaryRecord]:
        """Get summary by tenant-isolated key."""

        with self._lock:
            return self._records.get(self.make_key(user_id, workspace_id, summary_id))

    def find_by_call_id(
        self,
        user_id: str,
        workspace_id: str,
        call_id: str,
    ) -> Optional[CallSummaryRecord]:
        """Find latest summary for a call ID in one tenant."""

        with self._lock:
            records = self.list(user_id=user_id, workspace_id=workspace_id, limit=10000)
            matches = [record for record in records if record.call_id == call_id]
            matches.sort(key=lambda item: item.created_at, reverse=True)
            return matches[0] if matches else None

    def list(
        self,
        user_id: str,
        workspace_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
        outcome: Optional[str] = None,
        sentiment: Optional[str] = None,
        newest_first: bool = True,
    ) -> List[CallSummaryRecord]:
        """List tenant-isolated summaries."""

        with self._lock:
            tenant_key = (user_id, workspace_id)
            summary_ids = list(self._tenant_index.get(tenant_key, []))
            records: List[CallSummaryRecord] = []

            for summary_id in summary_ids:
                record = self._records.get(self.make_key(user_id, workspace_id, summary_id))
                if not record:
                    continue

                if outcome and record.outcome != outcome:
                    continue

                if sentiment and record.sentiment.label != sentiment:
                    continue

                records.append(record)

            records.sort(key=lambda item: item.created_at, reverse=newest_first)
            return records[max(0, offset): max(0, offset) + max(1, limit)]


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class CallSummarizer(BaseAgent):
    """
    Summarizes call transcripts and extracts:
        - summary text
        - short summary
        - key points
        - action items
        - next steps
        - sentiment
        - outcome
        - risk flags
        - useful memory and verification payloads

    This class is deterministic and provider-agnostic by default. A future LLM
    provider can be injected outside this file, but this file does not require
    one to work.
    """

    POSITIVE_TERMS = {
        "interested", "great", "good", "excellent", "perfect", "yes", "sure",
        "sounds good", "thank you", "thanks", "helpful", "like", "love",
        "happy", "appreciate", "agree", "confirm", "confirmed", "ready",
        "let's do", "send me", "call me", "book", "schedule", "appointment",
    }

    NEGATIVE_TERMS = {
        "not interested", "no thanks", "bad", "angry", "upset", "complaint",
        "problem", "issue", "cancel", "stop calling", "remove me", "wrong number",
        "busy", "expensive", "too much", "don't call", "never", "hate",
        "frustrated", "unhappy", "spam", "scam",
    }

    ACTION_PATTERNS = (
        r"\b(call back|callback|follow up|send|email|text|whatsapp|schedule|book|confirm|check|review|share|prepare|update|create|quote|proposal)\b",
        r"\b(need to|needs to|have to|has to|should|must|will|please)\b",
    )

    NEXT_STEP_PATTERNS = (
        r"\b(next step|after this|then|tomorrow|later|follow up|call back|schedule|book|send proposal|send quote)\b",
    )

    RISK_PATTERNS = {
        "do_not_call_request": r"\b(stop calling|do not call|don't call|remove me|unsubscribe)\b",
        "wrong_number": r"\b(wrong number|not my number|you have the wrong)\b",
        "complaint": r"\b(complaint|angry|upset|frustrated|bad service|terrible)\b",
        "payment_sensitive": r"\b(card number|credit card|cvv|bank account|routing number|password|otp|pin)\b",
        "legal_sensitive": r"\b(lawsuit|lawyer|attorney|legal action|sue)\b",
    }

    OUTCOME_RULES = (
        (CallOutcome.WRONG_NUMBER, r"\b(wrong number|not my number|you have the wrong)\b"),
        (CallOutcome.VOICEMAIL, r"\b(voicemail|leave a message|after the tone)\b"),
        (CallOutcome.CALLBACK_REQUESTED, r"\b(call back|callback|call me later|busy right now)\b"),
        (CallOutcome.APPOINTMENT_REQUESTED, r"\b(book|schedule|appointment|meeting|demo)\b"),
        (CallOutcome.PRICE_DISCUSSION, r"\b(price|pricing|cost|quote|proposal|budget|expensive|cheap)\b"),
        (CallOutcome.SUPPORT_REQUEST, r"\b(help|support|issue|problem|fix|trouble)\b"),
        (CallOutcome.COMPLAINT, r"\b(complaint|angry|upset|bad service|frustrated)\b"),
        (CallOutcome.NOT_INTERESTED, r"\b(not interested|no thanks|don't need|do not need|stop calling)\b"),
        (CallOutcome.INTERESTED, r"\b(interested|send me|sounds good|yes|sure|let's do|ready)\b"),
    )

    def __init__(
        self,
        *,
        config: Optional[CallSummarizerConfig] = None,
        store: Optional[InMemoryCallSummaryStore] = None,
        security_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        event_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
        audit_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
        agent_name: str = AGENT_NAME,
        agent_id: str = "call_summarizer",
        **kwargs: Any,
    ) -> None:
        try:
            super().__init__(agent_name=agent_name, agent_id=agent_id, **kwargs)
        except TypeError:
            super().__init__()

        self.agent_name = agent_name
        self.agent_id = agent_id
        self.module_name = AGENT_MODULE

        self.config = config or CallSummarizerConfig()
        self.store = store or InMemoryCallSummaryStore()

        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.verification_agent = verification_agent
        self.event_sink = event_sink
        self.audit_sink = audit_sink

        self.logger = getattr(self, "logger", logging.getLogger(f"{AGENT_MODULE}.{AGENT_NAME}"))

    # ------------------------------------------------------------------
    # Router-compatible entrypoint
    # ------------------------------------------------------------------

    async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Route CallSummarizer task from Master Agent / Agent Router.

        Supported actions:
            - summarize_call
            - summarize_transcript
            - extract_action_items
            - analyze_sentiment
            - get_summary
            - list_summaries
            - get_summary_analytics
        """

        if not isinstance(task, dict):
            return self._error_result(
                message="CallSummarizer task must be a dictionary.",
                error="invalid_task_type",
            )

        action = str(task.get("action") or "summarize_call").strip()

        action_map = {
            "summarize_call": self.summarize_call,
            "summarize_transcript": self.summarize_call,
            "extract_action_items": self.extract_action_items,
            "analyze_sentiment": self.analyze_sentiment,
            "get_summary": self.get_summary,
            "list_summaries": self.list_summaries,
            "get_summary_analytics": self.get_summary_analytics,
            "export_summary": self.export_summary,
        }

        handler = action_map.get(action)
        if not handler:
            return self._error_result(
                message=f"Unsupported CallSummarizer action: {action}",
                error="unsupported_action",
                metadata={"allowed_actions": sorted(action_map.keys())},
            )

        kwargs = {k: v for k, v in task.items() if k != "action"}

        try:
            result = handler(**kwargs)
            if hasattr(result, "__await__"):
                return await result  # type: ignore[no-any-return]
            return result
        except TypeError as exc:
            return self._error_result(
                message=f"Invalid arguments for action '{action}'.",
                error=exc,
                metadata={"action": action},
            )
        except Exception as exc:
            self.logger.exception("CallSummarizer action failed: %s", action)
            return self._error_result(
                message=f"CallSummarizer action failed: {action}",
                error=exc,
                metadata={"action": action},
            )

    # ------------------------------------------------------------------
    # Main public methods
    # ------------------------------------------------------------------

    def summarize_call(
        self,
        *,
        user_id: str,
        workspace_id: str,
        transcript: Union[str, List[Mapping[str, Any]], List[TranscriptTurn]],
        call_id: Optional[str] = None,
        call_metadata: Optional[Mapping[str, Any]] = None,
        language: Optional[str] = None,
        overwrite_existing: bool = True,
        request_context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Summarize a call transcript.

        This method is safe for dashboard/API usage and always enforces
        user_id/workspace_id isolation.
        """

        context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not context_result["success"]:
            return context_result

        normalized_turns = self._normalize_transcript(transcript)
        if not normalized_turns:
            return self._error_result(
                message="Transcript is empty or invalid.",
                error="empty_transcript",
                metadata=self._base_metadata(user_id, workspace_id, call_id=call_id),
            )

        normalized_text = self._turns_to_text(normalized_turns)
        if len(normalized_text) > self.config.max_transcript_chars:
            normalized_text = normalized_text[: self.config.max_transcript_chars].strip()

        resolved_call_id = str(call_id or _safe_uuid("call"))

        existing = self.store.find_by_call_id(user_id, workspace_id, resolved_call_id)
        if existing and not overwrite_existing:
            return self._safe_result(
                message="Existing call summary found.",
                data={"summary": self._serialize_summary(existing)},
                metadata=self._base_metadata(user_id, workspace_id, call_id=resolved_call_id),
            )

        now = _iso_now()
        summary_id = existing.summary_id if existing else _safe_uuid("summary")
        sanitized_call_metadata = self._sanitize_call_metadata(call_metadata)

        try:
            key_points = self._extract_key_points(normalized_text)
            sentiment = self._analyze_sentiment_internal(normalized_text)
            action_items = self._extract_action_items_internal(normalized_text)
            next_steps = self._extract_next_steps_internal(
                normalized_text=normalized_text,
                action_items=action_items,
                sentiment=sentiment,
            )
            outcome = self._detect_outcome(normalized_text)
            risk_flags = self._detect_risk_flags(normalized_text)
            risk_level = self._risk_level_from_flags(risk_flags)
            entities = self._extract_entities(normalized_text)
            transcript_stats = self._transcript_stats(normalized_turns, normalized_text)
            summary_text = self._build_summary_text(
                key_points=key_points,
                sentiment=sentiment,
                outcome=outcome,
                action_items=action_items,
                next_steps=next_steps,
                risk_flags=risk_flags,
            )
            short_summary = self._build_short_summary(
                key_points=key_points,
                outcome=outcome,
                sentiment=sentiment,
            )

            record = CallSummaryRecord(
                summary_id=summary_id,
                call_id=resolved_call_id,
                user_id=str(user_id),
                workspace_id=str(workspace_id),
                status=CallSummaryStatus.UPDATED.value if existing else CallSummaryStatus.CREATED.value,
                summary_text=summary_text,
                short_summary=short_summary,
                key_points=key_points,
                action_items=action_items,
                next_steps=next_steps,
                sentiment=sentiment,
                outcome=outcome.value,
                risk_level=risk_level.value,
                risk_flags=risk_flags,
                entities=entities,
                call_metadata=sanitized_call_metadata,
                transcript_stats=transcript_stats,
                created_at=existing.created_at if existing else now,
                updated_at=now,
                error=None,
            )

            self.store.save(record)

            memory_payload = self._prepare_memory_payload(
                user_id=user_id,
                workspace_id=workspace_id,
                event_type="call_summary_created",
                data=self._memory_summary(record),
            )
            verification_payload = self._prepare_verification_payload(
                action="call_summary_created",
                user_id=user_id,
                workspace_id=workspace_id,
                call_id=resolved_call_id,
                summary_id=summary_id,
                status=record.status,
                data=self._verification_summary(record),
            )

            self._emit_agent_event(
                event_name="call.summary.created",
                user_id=user_id,
                workspace_id=workspace_id,
                payload=self._verification_summary(record),
            )
            self._log_audit_event(
                action="call_summarized",
                user_id=user_id,
                workspace_id=workspace_id,
                call_id=resolved_call_id,
                summary_id=summary_id,
                details={
                    "outcome": record.outcome,
                    "sentiment": record.sentiment.label,
                    "risk_level": record.risk_level,
                    "action_items_count": len(record.action_items),
                    "request_context": self._sanitize_call_metadata(request_context),
                },
            )

            response_summary = self._serialize_summary(record)
            if self.config.keep_raw_transcript_in_result:
                response_summary["transcript"] = normalized_text

            return self._safe_result(
                message="Call summarized successfully.",
                data={
                    "summary": response_summary,
                    "memory_payload": memory_payload,
                    "verification_payload": verification_payload,
                },
                metadata=self._base_metadata(
                    user_id,
                    workspace_id,
                    call_id=resolved_call_id,
                    summary_id=summary_id,
                ),
            )

        except Exception as exc:
            self.logger.exception("Call summarization failed.")

            error_record = CallSummaryRecord(
                summary_id=summary_id,
                call_id=resolved_call_id,
                user_id=str(user_id),
                workspace_id=str(workspace_id),
                status=CallSummaryStatus.FAILED.value,
                summary_text="",
                short_summary="",
                key_points=[],
                action_items=[],
                next_steps=[],
                sentiment=SentimentResult(
                    label=SentimentLabel.UNKNOWN.value,
                    score=0.0,
                    positive_hits=0,
                    negative_hits=0,
                    neutral_hits=0,
                    evidence=[],
                ),
                outcome=CallOutcome.NO_CLEAR_OUTCOME.value,
                risk_level=RiskLevel.LOW.value,
                risk_flags=[],
                entities={},
                call_metadata=sanitized_call_metadata,
                transcript_stats={},
                created_at=existing.created_at if existing else now,
                updated_at=_iso_now(),
                error=_normalize_error(exc, code="call_summary_failed"),
            )
            self.store.save(error_record)

            return self._error_result(
                message="Call summarization failed.",
                error=exc,
                metadata=self._base_metadata(
                    user_id,
                    workspace_id,
                    call_id=resolved_call_id,
                    summary_id=summary_id,
                ),
            )

    def extract_action_items(
        self,
        *,
        user_id: str,
        workspace_id: str,
        transcript: Union[str, List[Mapping[str, Any]], List[TranscriptTurn]],
        call_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Extract action items only."""

        context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not context_result["success"]:
            return context_result

        turns = self._normalize_transcript(transcript)
        text = self._turns_to_text(turns)

        if not text:
            return self._error_result(
                message="Transcript is empty or invalid.",
                error="empty_transcript",
                metadata=self._base_metadata(user_id, workspace_id, call_id=call_id),
            )

        items = self._extract_action_items_internal(text)

        return self._safe_result(
            message="Action items extracted.",
            data={"action_items": [self._serialize_action_item(item) for item in items]},
            metadata=self._base_metadata(user_id, workspace_id, call_id=call_id),
        )

    def analyze_sentiment(
        self,
        *,
        user_id: str,
        workspace_id: str,
        transcript: Union[str, List[Mapping[str, Any]], List[TranscriptTurn]],
        call_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Analyze call sentiment only."""

        context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not context_result["success"]:
            return context_result

        turns = self._normalize_transcript(transcript)
        text = self._turns_to_text(turns)

        if not text:
            return self._error_result(
                message="Transcript is empty or invalid.",
                error="empty_transcript",
                metadata=self._base_metadata(user_id, workspace_id, call_id=call_id),
            )

        sentiment = self._analyze_sentiment_internal(text)

        return self._safe_result(
            message="Sentiment analyzed.",
            data={"sentiment": self._serialize_sentiment(sentiment)},
            metadata=self._base_metadata(user_id, workspace_id, call_id=call_id),
        )

    def get_summary(
        self,
        *,
        user_id: str,
        workspace_id: str,
        summary_id: Optional[str] = None,
        call_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get a stored call summary by summary_id or call_id."""

        context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not context_result["success"]:
            return context_result

        record: Optional[CallSummaryRecord] = None

        if summary_id:
            record = self.store.get(user_id, workspace_id, summary_id)
        elif call_id:
            record = self.store.find_by_call_id(user_id, workspace_id, call_id)
        else:
            return self._error_result(
                message="summary_id or call_id is required.",
                error="missing_summary_lookup",
                metadata=self._base_metadata(user_id, workspace_id),
            )

        if not record:
            return self._error_result(
                message="Call summary not found for this user/workspace.",
                error="summary_not_found",
                metadata=self._base_metadata(user_id, workspace_id, call_id=call_id, summary_id=summary_id),
            )

        return self._safe_result(
            message="Call summary fetched.",
            data={"summary": self._serialize_summary(record)},
            metadata=self._base_metadata(
                user_id,
                workspace_id,
                call_id=record.call_id,
                summary_id=record.summary_id,
            ),
        )

    def list_summaries(
        self,
        *,
        user_id: str,
        workspace_id: str,
        limit: int = 100,
        offset: int = 0,
        outcome: Optional[Union[str, CallOutcome]] = None,
        sentiment: Optional[Union[str, SentimentLabel]] = None,
        newest_first: bool = True,
    ) -> Dict[str, Any]:
        """List stored summaries for one user/workspace."""

        context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not context_result["success"]:
            return context_result

        safe_limit = min(max(1, int(limit)), 1000)
        safe_offset = max(0, int(offset))
        outcome_value = outcome.value if isinstance(outcome, CallOutcome) else outcome
        sentiment_value = sentiment.value if isinstance(sentiment, SentimentLabel) else sentiment

        records = self.store.list(
            user_id=user_id,
            workspace_id=workspace_id,
            limit=safe_limit,
            offset=safe_offset,
            outcome=outcome_value,
            sentiment=sentiment_value,
            newest_first=newest_first,
        )

        return self._safe_result(
            message="Call summaries fetched.",
            data={
                "summaries": [self._serialize_summary(record) for record in records],
                "count": len(records),
                "limit": safe_limit,
                "offset": safe_offset,
            },
            metadata=self._base_metadata(user_id, workspace_id),
        )

    def get_summary_analytics(
        self,
        *,
        user_id: str,
        workspace_id: str,
    ) -> Dict[str, Any]:
        """Return summary analytics for dashboard/API."""

        context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not context_result["success"]:
            return context_result

        records = self.store.list(
            user_id=user_id,
            workspace_id=workspace_id,
            limit=10000,
            offset=0,
            newest_first=False,
        )

        outcome_counts = Counter(record.outcome for record in records)
        sentiment_counts = Counter(record.sentiment.label for record in records)
        risk_counts = Counter(record.risk_level for record in records)

        action_counts = [len(record.action_items) for record in records]
        next_step_counts = [len(record.next_steps) for record in records]
        duration_values = [
            float(record.transcript_stats.get("estimated_duration_seconds", 0))
            for record in records
            if record.transcript_stats.get("estimated_duration_seconds")
        ]

        analytics = {
            "total_summaries": len(records),
            "outcome_counts": dict(outcome_counts),
            "sentiment_counts": dict(sentiment_counts),
            "risk_counts": dict(risk_counts),
            "average_action_items": self._average(action_counts),
            "average_next_steps": self._average(next_step_counts),
            "duration_seconds": self._stats(duration_values),
            "high_risk_count": risk_counts.get(RiskLevel.HIGH.value, 0),
            "positive_rate": _safe_ratio(sentiment_counts.get(SentimentLabel.POSITIVE.value, 0), len(records)),
            "negative_rate": _safe_ratio(sentiment_counts.get(SentimentLabel.NEGATIVE.value, 0), len(records)),
            "generated_at": _iso_now(),
        }

        return self._safe_result(
            message="Call summary analytics generated.",
            data={"analytics": analytics},
            metadata=self._base_metadata(user_id, workspace_id),
        )

    def export_summary(
        self,
        *,
        user_id: str,
        workspace_id: str,
        summary_id: Optional[str] = None,
        call_id: Optional[str] = None,
        request_context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Export a call summary.

        Export can expose customer/caller information, so it requires Security
        Agent approval unless config explicitly allows sensitive operations
        without Security Agent.
        """

        context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not context_result["success"]:
            return context_result

        action = "call_summary_export"
        if self._requires_security_check(action=action):
            approval = self._request_security_approval(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                context={
                    "summary_id": summary_id,
                    "call_id": call_id,
                    "request_context": self._sanitize_call_metadata(request_context),
                },
            )
            if not approval.get("approved"):
                return self._error_result(
                    message="Security approval denied for call summary export.",
                    error="security_approval_denied",
                    metadata={
                        "approval": approval,
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                    },
                )

        summary_result = self.get_summary(
            user_id=user_id,
            workspace_id=workspace_id,
            summary_id=summary_id,
            call_id=call_id,
        )
        if not summary_result["success"]:
            return summary_result

        summary = summary_result["data"]["summary"]

        self._log_audit_event(
            action=action,
            user_id=user_id,
            workspace_id=workspace_id,
            call_id=summary.get("call_id"),
            summary_id=summary.get("summary_id"),
            details={"request_context": self._sanitize_call_metadata(request_context)},
        )

        return self._safe_result(
            message="Call summary exported.",
            data={
                "export": {
                    "format": "json",
                    "schema_version": SCHEMA_VERSION,
                    "summary": summary,
                    "exported_at": _iso_now(),
                }
            },
            metadata=self._base_metadata(
                user_id,
                workspace_id,
                call_id=summary.get("call_id"),
                summary_id=summary.get("summary_id"),
            ),
        )

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(
        self,
        *,
        user_id: Optional[str],
        workspace_id: Optional[str],
        require_workspace: bool = True,
    ) -> Dict[str, Any]:
        """
        Validate SaaS context.

        Every call summary belongs to exactly one user_id and workspace_id.
        This prevents transcript, lead, call note, memory, or analytics mixing.
        """

        if not user_id or not str(user_id).strip():
            return self._error_result(
                message="user_id is required for CallSummarizer operations.",
                error="missing_user_id",
            )

        if require_workspace and (not workspace_id or not str(workspace_id).strip()):
            return self._error_result(
                message="workspace_id is required for CallSummarizer operations.",
                error="missing_workspace_id",
                metadata={"user_id": user_id},
            )

        return self._safe_result(
            message="Task context validated.",
            data={"user_id": str(user_id), "workspace_id": str(workspace_id)},
        )

    def _requires_security_check(self, *, action: str, **_: Any) -> bool:
        """Return True when action should be approved by Security Agent."""

        sensitive_actions = {
            "call_summary_export",
            "call_transcript_export",
            "call_summary_delete",
            "call_summary_bulk_export",
        }
        return action in sensitive_actions

    def _request_security_approval(
        self,
        *,
        action: str,
        user_id: str,
        workspace_id: str,
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval for sensitive actions.

        Safe default:
            Deny sensitive action if no Security Agent exists unless explicitly
            allowed in config.
        """

        if not self._requires_security_check(action=action):
            return {
                "approved": True,
                "message": "Security approval not required.",
                "source": "call_summarizer",
            }

        approval_payload = {
            "action": action,
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "module": self.module_name,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "context": self._sanitize_call_metadata(context),
            "requested_at": _iso_now(),
        }

        if self.security_agent is None:
            if self.config.allow_sensitive_without_security:
                return {
                    "approved": True,
                    "message": "Sensitive action allowed by config without Security Agent.",
                    "source": "config",
                    "payload": approval_payload,
                }

            return {
                "approved": False,
                "message": "Security Agent is not configured for sensitive action.",
                "source": "call_summarizer",
                "payload": approval_payload,
            }

        try:
            if hasattr(self.security_agent, "approve_action"):
                response = self.security_agent.approve_action(approval_payload)
            elif hasattr(self.security_agent, "validate_action"):
                response = self.security_agent.validate_action(approval_payload)
            elif hasattr(self.security_agent, "run"):
                response = self.security_agent.run({"action": "approve_action", **approval_payload})
            else:
                return {
                    "approved": False,
                    "message": "Security Agent has no compatible approval method.",
                    "source": "call_summarizer",
                    "payload": approval_payload,
                }

            if isinstance(response, Mapping):
                approved = bool(
                    response.get("approved")
                    or response.get("success") is True
                    or response.get("status") == "approved"
                )
                return {
                    "approved": approved,
                    "message": str(response.get("message") or "Security Agent response received."),
                    "source": "security_agent",
                    "response": _sanitize_dict(response),
                    "payload": approval_payload,
                }

            return {
                "approved": bool(response),
                "message": "Security Agent returned non-dict response.",
                "source": "security_agent",
                "payload": approval_payload,
            }
        except Exception as exc:
            self.logger.exception("Security approval failed.")
            return {
                "approved": False,
                "message": f"Security approval failed: {exc}",
                "source": "security_agent",
                "payload": approval_payload,
            }

    def _prepare_verification_payload(
        self,
        *,
        action: str,
        user_id: str,
        workspace_id: str,
        call_id: Optional[str] = None,
        summary_id: Optional[str] = None,
        status: Optional[str] = None,
        data: Optional[Mapping[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Prepare Verification Agent compatible payload."""

        if not self.config.enable_verification_payloads:
            return None

        payload = {
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "module": self.module_name,
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "call_id": call_id,
            "summary_id": summary_id,
            "status": status,
            "data": _sanitize_dict(data),
            "schema_version": SCHEMA_VERSION,
            "created_at": _iso_now(),
        }

        if self.verification_agent is not None:
            try:
                if hasattr(self.verification_agent, "prepare_payload"):
                    self.verification_agent.prepare_payload(payload)
                elif hasattr(self.verification_agent, "record"):
                    self.verification_agent.record(payload)
            except Exception:
                self.logger.exception("Verification payload handoff failed.")

        return payload

    def _prepare_memory_payload(
        self,
        *,
        user_id: str,
        workspace_id: str,
        event_type: str,
        data: Optional[Mapping[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Prepare Memory Agent compatible call summary payload."""

        if not self.config.enable_memory_payloads:
            return None

        payload = {
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "module": self.module_name,
            "memory_type": "call_summary",
            "event_type": event_type,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "data": _sanitize_dict(data),
            "created_at": _iso_now(),
            "schema_version": SCHEMA_VERSION,
        }

        if self.memory_agent is not None:
            try:
                if hasattr(self.memory_agent, "prepare_memory"):
                    self.memory_agent.prepare_memory(payload)
                elif hasattr(self.memory_agent, "remember"):
                    self.memory_agent.remember(payload)
                elif hasattr(self.memory_agent, "record"):
                    self.memory_agent.record(payload)
            except Exception:
                self.logger.exception("Memory payload handoff failed.")

        return payload

    def _emit_agent_event(
        self,
        *,
        event_name: str,
        user_id: str,
        workspace_id: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """Emit agent event for Master Agent, Registry, Dashboard, or event bus."""

        if not self.config.enable_agent_events:
            return

        event = {
            "event_name": event_name,
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "module": self.module_name,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "payload": _sanitize_dict(payload),
            "timestamp": _iso_now(),
        }

        try:
            if self.event_sink:
                self.event_sink(event)
            else:
                self.logger.debug("Agent event emitted: %s", event)
        except Exception:
            self.logger.exception("Failed to emit agent event.")

    def _log_audit_event(
        self,
        *,
        action: str,
        user_id: str,
        workspace_id: str,
        call_id: Optional[str] = None,
        summary_id: Optional[str] = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """Log sanitized audit event."""

        if not self.config.enable_audit_log:
            return

        audit_event = {
            "action": action,
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "module": self.module_name,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "call_id": call_id,
            "summary_id": summary_id,
            "details": _sanitize_dict(details),
            "timestamp": _iso_now(),
            "schema_version": SCHEMA_VERSION,
        }

        try:
            if self.audit_sink:
                self.audit_sink(audit_event)
            else:
                self.logger.info("Audit event: %s", audit_event)
        except Exception:
            self.logger.exception("Failed to write audit event.")

    def _safe_result(
        self,
        *,
        message: str,
        data: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard success result."""

        return {
            "success": True,
            "message": message,
            "data": _as_serializable(data if data is not None else {}),
            "error": None,
            "metadata": _sanitize_dict(metadata),
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Optional[Union[str, BaseException, Mapping[str, Any]]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard error result."""

        return {
            "success": False,
            "message": message,
            "data": {},
            "error": _normalize_error(error or message),
            "metadata": _sanitize_dict(metadata),
        }

    # ------------------------------------------------------------------
    # Transcript normalization
    # ------------------------------------------------------------------

    def _normalize_transcript(
        self,
        transcript: Union[str, List[Mapping[str, Any]], List[TranscriptTurn]],
    ) -> List[TranscriptTurn]:
        """Normalize string/list transcript into TranscriptTurn list."""

        if isinstance(transcript, str):
            clean = self._redact_text(transcript)
            return [TranscriptTurn(speaker="unknown", text=clean)]

        if not isinstance(transcript, list):
            return []

        turns: List[TranscriptTurn] = []
        for item in transcript:
            if isinstance(item, TranscriptTurn):
                text = self._redact_text(item.text)
                if text:
                    turns.append(
                        TranscriptTurn(
                            speaker=item.speaker or "unknown",
                            text=text,
                            timestamp=item.timestamp,
                            confidence=item.confidence,
                        )
                    )
                continue

            if isinstance(item, Mapping):
                text = str(
                    item.get("text")
                    or item.get("transcript")
                    or item.get("message")
                    or item.get("content")
                    or ""
                )
                text = self._redact_text(text)

                if not text:
                    continue

                speaker = str(
                    item.get("speaker")
                    or item.get("role")
                    or item.get("participant")
                    or "unknown"
                )

                confidence_raw = item.get("confidence")
                try:
                    confidence = float(confidence_raw) if confidence_raw is not None else None
                except Exception:
                    confidence = None

                turns.append(
                    TranscriptTurn(
                        speaker=speaker,
                        text=text,
                        timestamp=item.get("timestamp") if item.get("timestamp") else None,
                        confidence=confidence,
                    )
                )

        return turns

    def _turns_to_text(self, turns: Iterable[TranscriptTurn]) -> str:
        """Convert transcript turns into readable text."""

        lines: List[str] = []
        for turn in turns:
            speaker = _strip_extra_spaces(turn.speaker or "unknown")
            text = _strip_extra_spaces(turn.text or "")
            if text:
                lines.append(f"{speaker}: {text}")
        return "\n".join(lines).strip()

    def _redact_text(self, text: str) -> str:
        """Redact sensitive text patterns if enabled."""

        cleaned = str(text or "")

        if not self.config.redact_sensitive_data:
            return cleaned

        patterns = [
            (r"\b\d{3}-\d{2}-\d{4}\b", "***REDACTED_SSN***"),
            (r"\b(?:\d[ -]*?){13,19}\b", "***REDACTED_CARD_OR_LONG_NUMBER***"),
            (r"\b\d{3,4}\s?(?:cvv|cvc|security code)\b", "***REDACTED_SECURITY_CODE***"),
            (r"\b(?:password|passcode|otp|pin)\s*(?:is|:)?\s*\S+\b", "***REDACTED_SECRET***"),
            (r"(?i)\b(api[_ -]?key|token|secret)\s*(?:is|:|=)?\s*\S+\b", "***REDACTED_SECRET***"),
        ]

        for pattern, replacement in patterns:
            cleaned = re.sub(pattern, replacement, cleaned, flags=re.IGNORECASE)

        return cleaned.strip()

    # ------------------------------------------------------------------
    # Summary extraction internals
    # ------------------------------------------------------------------

    def _extract_key_points(self, text: str) -> List[str]:
        """Extract key points using deterministic scoring."""

        sentences = _split_sentences(text)
        if not sentences:
            return []

        keywords = {
            "interested", "price", "pricing", "quote", "proposal", "call back",
            "schedule", "appointment", "book", "website", "service", "problem",
            "issue", "support", "email", "phone", "whatsapp", "next", "confirm",
            "budget", "decision", "owner", "manager", "payment", "deadline",
        }

        scored: List[Tuple[float, str]] = []
        for index, sentence in enumerate(sentences):
            lowered = sentence.lower()
            score = 0.0

            for keyword in keywords:
                if keyword in lowered:
                    score += 1.0

            if "?" in sentence:
                score += 0.3

            if re.search(r"\b(today|tomorrow|next week|monday|tuesday|wednesday|thursday|friday|saturday|sunday)\b", lowered):
                score += 0.7

            if re.search(r"\b\d+(\.\d+)?\b", sentence):
                score += 0.3

            if index < 3:
                score += 0.2

            word_len = _word_count(sentence)
            if 6 <= word_len <= 35:
                score += 0.4

            if score > 0:
                scored.append((score, sentence))

        if not scored:
            fallback = [sentence for sentence in sentences if _word_count(sentence) >= 5]
            return fallback[: self.config.max_key_points]

        scored.sort(key=lambda item: item[0], reverse=True)
        points: List[str] = []
        seen: set[str] = set()

        for _, sentence in scored:
            normalized = sentence.lower()
            if normalized in seen:
                continue
            seen.add(normalized)
            points.append(sentence)
            if len(points) >= self.config.max_key_points:
                break

        return points

    def _analyze_sentiment_internal(self, text: str) -> SentimentResult:
        """Analyze sentiment with transparent deterministic keyword logic."""

        lowered = text.lower()
        positive_hits = 0
        negative_hits = 0
        evidence: List[str] = []

        for term in self.POSITIVE_TERMS:
            if term in lowered:
                count = lowered.count(term)
                positive_hits += count
                if len(evidence) < 8:
                    evidence.append(f"positive:{term}")

        for term in self.NEGATIVE_TERMS:
            if term in lowered:
                count = lowered.count(term)
                negative_hits += count
                if len(evidence) < 8:
                    evidence.append(f"negative:{term}")

        neutral_hits = max(0, len(_split_sentences(text)) - positive_hits - negative_hits)

        if positive_hits == 0 and negative_hits == 0:
            label = SentimentLabel.NEUTRAL
            score = 0.0
        elif positive_hits > 0 and negative_hits > 0:
            if abs(positive_hits - negative_hits) <= 1:
                label = SentimentLabel.MIXED
            elif positive_hits > negative_hits:
                label = SentimentLabel.POSITIVE
            else:
                label = SentimentLabel.NEGATIVE
            score = round((positive_hits - negative_hits) / max(1, positive_hits + negative_hits), 4)
        elif positive_hits > negative_hits:
            label = SentimentLabel.POSITIVE
            score = round(positive_hits / max(1, positive_hits + negative_hits), 4)
        else:
            label = SentimentLabel.NEGATIVE
            score = round(-negative_hits / max(1, positive_hits + negative_hits), 4)

        return SentimentResult(
            label=label.value,
            score=score,
            positive_hits=positive_hits,
            negative_hits=negative_hits,
            neutral_hits=neutral_hits,
            evidence=evidence,
        )

    def _extract_action_items_internal(self, text: str) -> List[ActionItem]:
        """Extract call action items from transcript."""

        sentences = _split_sentences(text)
        items: List[ActionItem] = []
        seen: set[str] = set()

        for sentence in sentences:
            lowered = sentence.lower()
            matched = any(re.search(pattern, lowered, flags=re.IGNORECASE) for pattern in self.ACTION_PATTERNS)

            if not matched:
                continue

            confidence = 0.45
            if re.search(r"\b(call back|follow up|schedule|book|send|email|whatsapp|quote|proposal)\b", lowered):
                confidence += 0.25
            if re.search(r"\b(today|tomorrow|next week|monday|tuesday|wednesday|thursday|friday|saturday|sunday|later)\b", lowered):
                confidence += 0.15
            if re.search(r"\b(customer|caller|agent|team|specialist|manager|sales)\b", lowered):
                confidence += 0.1

            confidence = min(0.99, round(confidence, 2))
            if confidence < self.config.min_action_confidence:
                continue

            title = self._action_title_from_sentence(sentence)
            normalized_title = title.lower()
            if normalized_title in seen:
                continue
            seen.add(normalized_title)

            item = ActionItem(
                action_id=_safe_uuid("action"),
                title=title,
                description=sentence,
                owner=self._detect_owner(sentence),
                priority=self._detect_priority(sentence).value,
                due_hint=self._detect_due_hint(sentence),
                source_text=sentence,
                confidence=confidence,
                created_at=_iso_now(),
            )
            items.append(item)

            if len(items) >= self.config.max_action_items:
                break

        return items

    def _extract_next_steps_internal(
        self,
        *,
        normalized_text: str,
        action_items: List[ActionItem],
        sentiment: SentimentResult,
    ) -> List[NextStep]:
        """Build recommended next steps from transcript and action items."""

        next_steps: List[NextStep] = []

        for item in action_items[: self.config.max_next_steps]:
            next_steps.append(
                NextStep(
                    step_id=_safe_uuid("next"),
                    title=item.title,
                    description=item.description,
                    priority=item.priority,
                    recommended_owner=item.owner,
                    reason="Derived from detected call action item.",
                    created_at=_iso_now(),
                )
            )

        lowered = normalized_text.lower()

        if not next_steps:
            if "call back" in lowered or "callback" in lowered:
                next_steps.append(
                    self._make_next_step(
                        title="Call the contact back",
                        description="The caller requested or implied a callback.",
                        priority=ActionPriority.HIGH,
                        owner="call_agent",
                        reason="Callback language detected.",
                    )
                )
            elif sentiment.label == SentimentLabel.POSITIVE.value:
                next_steps.append(
                    self._make_next_step(
                        title="Send follow-up details",
                        description="Send a helpful follow-up with offer details and next action.",
                        priority=ActionPriority.MEDIUM,
                        owner="call_agent",
                        reason="Positive sentiment detected.",
                    )
                )
            elif sentiment.label == SentimentLabel.NEGATIVE.value:
                next_steps.append(
                    self._make_next_step(
                        title="Escalate for human review",
                        description="Review the call because negative sentiment was detected.",
                        priority=ActionPriority.HIGH,
                        owner="human_team",
                        reason="Negative sentiment detected.",
                    )
                )
            else:
                next_steps.append(
                    self._make_next_step(
                        title="Review call notes",
                        description="No clear next step was detected. Review the call before further action.",
                        priority=ActionPriority.LOW,
                        owner="call_agent",
                        reason="No explicit action item found.",
                    )
                )

        if re.search(r"\b(price|pricing|quote|proposal|budget)\b", lowered):
            extra = self._make_next_step(
                title="Prepare pricing or proposal",
                description="Pricing or proposal discussion was detected.",
                priority=ActionPriority.HIGH,
                owner="sales_team",
                reason="Price/proposal keywords detected.",
            )
            if not any(step.title == extra.title for step in next_steps):
                next_steps.append(extra)

        if re.search(r"\b(book|schedule|appointment|meeting|demo)\b", lowered):
            extra = self._make_next_step(
                title="Schedule appointment",
                description="Appointment or booking intent was detected.",
                priority=ActionPriority.HIGH,
                owner="appointment_booker",
                reason="Scheduling keywords detected.",
            )
            if not any(step.title == extra.title for step in next_steps):
                next_steps.append(extra)

        return next_steps[: self.config.max_next_steps]

    def _detect_outcome(self, text: str) -> CallOutcome:
        """Detect call outcome."""

        lowered = text.lower()
        for outcome, pattern in self.OUTCOME_RULES:
            if re.search(pattern, lowered, flags=re.IGNORECASE):
                return outcome

        return CallOutcome.NO_CLEAR_OUTCOME

    def _detect_risk_flags(self, text: str) -> List[str]:
        """Detect compliance/escalation risk flags."""

        flags: List[str] = []
        lowered = text.lower()

        for flag, pattern in self.RISK_PATTERNS.items():
            if re.search(pattern, lowered, flags=re.IGNORECASE):
                flags.append(flag)

        return flags

    def _risk_level_from_flags(self, flags: List[str]) -> RiskLevel:
        """Convert risk flags to risk level."""

        high_flags = {"do_not_call_request", "payment_sensitive", "legal_sensitive"}
        medium_flags = {"wrong_number", "complaint"}

        if any(flag in high_flags for flag in flags):
            return RiskLevel.HIGH

        if any(flag in medium_flags for flag in flags):
            return RiskLevel.MEDIUM

        return RiskLevel.LOW

    def _extract_entities(self, text: str) -> Dict[str, Any]:
        """Extract simple useful call entities."""

        emails = sorted(set(re.findall(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", text)))
        urls = sorted(set(re.findall(r"\bhttps?://[^\s]+|\bwww\.[^\s]+", text, flags=re.IGNORECASE)))

        phone_candidates = re.findall(
            r"(?:(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)?\d{3,4}[\s.-]?\d{3,4})",
            text,
        )
        phones = sorted(set(candidate.strip() for candidate in phone_candidates if len(re.sub(r"\D", "", candidate)) >= 7))

        money = sorted(set(re.findall(r"(?:\$|£|€|Rs\.?|PKR|USD|GBP|AED|SAR)\s?\d+(?:,\d{3})*(?:\.\d+)?", text, flags=re.IGNORECASE)))

        return {
            "emails": emails[:20],
            "phones": phones[:20],
            "urls": urls[:20],
            "money_mentions": money[:20],
        }

    def _transcript_stats(self, turns: List[TranscriptTurn], text: str) -> Dict[str, Any]:
        """Build transcript statistics."""

        speaker_counts = Counter(turn.speaker for turn in turns)
        words = _word_count(text)
        estimated_duration_seconds = round(words / 2.4, 2) if words else 0.0

        confidences = [
            float(turn.confidence)
            for turn in turns
            if isinstance(turn.confidence, (int, float))
        ]

        return {
            "turn_count": len(turns),
            "speaker_counts": dict(speaker_counts),
            "word_count": words,
            "character_count": len(text),
            "estimated_duration_seconds": estimated_duration_seconds,
            "average_turn_confidence": self._average(confidences),
            "language": self.config.default_language,
        }

    # ------------------------------------------------------------------
    # Summary text helpers
    # ------------------------------------------------------------------

    def _build_summary_text(
        self,
        *,
        key_points: List[str],
        sentiment: SentimentResult,
        outcome: CallOutcome,
        action_items: List[ActionItem],
        next_steps: List[NextStep],
        risk_flags: List[str],
    ) -> str:
        """Build readable call summary."""

        parts: List[str] = []

        parts.append(f"Outcome: {outcome.value.replace('_', ' ')}.")
        parts.append(f"Sentiment: {sentiment.label} with score {sentiment.score}.")

        if key_points:
            parts.append("Key points: " + " ".join(f"- {point}" for point in key_points[:5]))

        if action_items:
            parts.append(
                "Action items: "
                + " ".join(f"- {item.title}" for item in action_items[:5])
            )
        else:
            parts.append("Action items: No clear action items detected.")

        if next_steps:
            parts.append(
                "Next steps: "
                + " ".join(f"- {step.title}" for step in next_steps[:5])
            )

        if risk_flags:
            parts.append("Risk flags: " + ", ".join(risk_flags) + ".")

        return "\n".join(parts).strip()

    def _build_short_summary(
        self,
        *,
        key_points: List[str],
        outcome: CallOutcome,
        sentiment: SentimentResult,
    ) -> str:
        """Build compact one-paragraph summary."""

        first_point = key_points[0] if key_points else "No major discussion point was detected."
        return (
            f"Call outcome was {outcome.value.replace('_', ' ')} with "
            f"{sentiment.label} sentiment. {first_point}"
        )

    def _action_title_from_sentence(self, sentence: str) -> str:
        """Create short action title from source sentence."""

        lowered = sentence.lower()

        if "call back" in lowered or "callback" in lowered:
            return "Call back the contact"
        if "send" in lowered and "proposal" in lowered:
            return "Send proposal"
        if "send" in lowered and "quote" in lowered:
            return "Send quote"
        if "send" in lowered and "email" in lowered:
            return "Send email follow-up"
        if "whatsapp" in lowered or "text" in lowered:
            return "Send message follow-up"
        if "schedule" in lowered or "book" in lowered or "appointment" in lowered:
            return "Schedule appointment"
        if "confirm" in lowered:
            return "Confirm details"
        if "review" in lowered:
            return "Review call request"
        if "price" in lowered or "pricing" in lowered:
            return "Prepare pricing details"

        words = re.findall(r"\b[\w'-]+\b", sentence)
        short = " ".join(words[:8]).strip()
        return short[:1].upper() + short[1:] if short else "Follow up"

    def _detect_owner(self, sentence: str) -> Optional[str]:
        """Detect likely owner from sentence."""

        lowered = sentence.lower()

        if "specialist" in lowered or "sales" in lowered:
            return "sales_team"
        if "agent" in lowered or "assistant" in lowered:
            return "call_agent"
        if "manager" in lowered:
            return "manager"
        if "team" in lowered:
            return "team"
        if "customer" in lowered or "caller" in lowered or "client" in lowered:
            return "customer"

        return "call_agent"

    def _detect_priority(self, sentence: str) -> ActionPriority:
        """Detect action priority."""

        lowered = sentence.lower()

        if re.search(r"\b(urgent|asap|immediately|right now|today|complaint|stop calling)\b", lowered):
            return ActionPriority.URGENT

        if re.search(r"\b(tomorrow|call back|schedule|book|proposal|quote|price)\b", lowered):
            return ActionPriority.HIGH

        if re.search(r"\b(next week|later|follow up|send)\b", lowered):
            return ActionPriority.MEDIUM

        return ActionPriority.LOW

    def _detect_due_hint(self, sentence: str) -> Optional[str]:
        """Extract simple due date/time hint."""

        patterns = [
            r"\b(today|tomorrow|tonight|next week|next month)\b",
            r"\b(monday|tuesday|wednesday|thursday|friday|saturday|sunday)\b",
            r"\b\d{1,2}\s?(am|pm)\b",
            r"\b\d{1,2}/\d{1,2}(?:/\d{2,4})?\b",
        ]

        lowered = sentence.lower()
        for pattern in patterns:
            match = re.search(pattern, lowered, flags=re.IGNORECASE)
            if match:
                return match.group(0)

        return None

    def _make_next_step(
        self,
        *,
        title: str,
        description: str,
        priority: ActionPriority,
        owner: Optional[str],
        reason: str,
    ) -> NextStep:
        """Create NextStep dataclass."""

        return NextStep(
            step_id=_safe_uuid("next"),
            title=title,
            description=description,
            priority=priority.value,
            recommended_owner=owner,
            reason=reason,
            created_at=_iso_now(),
        )

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def _serialize_summary(self, record: CallSummaryRecord) -> Dict[str, Any]:
        """Serialize summary record."""

        return {
            "summary_id": record.summary_id,
            "call_id": record.call_id,
            "user_id": record.user_id,
            "workspace_id": record.workspace_id,
            "status": record.status,
            "summary_text": record.summary_text,
            "short_summary": record.short_summary,
            "key_points": list(record.key_points),
            "action_items": [self._serialize_action_item(item) for item in record.action_items],
            "next_steps": [self._serialize_next_step(step) for step in record.next_steps],
            "sentiment": self._serialize_sentiment(record.sentiment),
            "outcome": record.outcome,
            "risk_level": record.risk_level,
            "risk_flags": list(record.risk_flags),
            "entities": _sanitize_dict(record.entities),
            "call_metadata": _sanitize_dict(record.call_metadata),
            "transcript_stats": _sanitize_dict(record.transcript_stats),
            "created_at": record.created_at,
            "updated_at": record.updated_at,
            "error": _sanitize_dict(record.error),
        }

    def _serialize_action_item(self, item: ActionItem) -> Dict[str, Any]:
        """Serialize action item."""

        return {
            "action_id": item.action_id,
            "title": item.title,
            "description": item.description,
            "owner": item.owner,
            "priority": item.priority,
            "due_hint": item.due_hint,
            "source_text": item.source_text,
            "confidence": item.confidence,
            "created_at": item.created_at,
        }

    def _serialize_next_step(self, step: NextStep) -> Dict[str, Any]:
        """Serialize next step."""

        return {
            "step_id": step.step_id,
            "title": step.title,
            "description": step.description,
            "priority": step.priority,
            "recommended_owner": step.recommended_owner,
            "reason": step.reason,
            "created_at": step.created_at,
        }

    def _serialize_sentiment(self, sentiment: SentimentResult) -> Dict[str, Any]:
        """Serialize sentiment result."""

        return {
            "label": sentiment.label,
            "score": sentiment.score,
            "positive_hits": sentiment.positive_hits,
            "negative_hits": sentiment.negative_hits,
            "neutral_hits": sentiment.neutral_hits,
            "evidence": list(sentiment.evidence),
        }

    def _memory_summary(self, record: CallSummaryRecord) -> Dict[str, Any]:
        """Prepare compact Memory Agent summary."""

        return {
            "summary_id": record.summary_id,
            "call_id": record.call_id,
            "short_summary": record.short_summary,
            "outcome": record.outcome,
            "sentiment": record.sentiment.label,
            "risk_level": record.risk_level,
            "action_items": [
                {
                    "title": item.title,
                    "priority": item.priority,
                    "owner": item.owner,
                    "due_hint": item.due_hint,
                }
                for item in record.action_items[:10]
            ],
            "next_steps": [
                {
                    "title": step.title,
                    "priority": step.priority,
                    "owner": step.recommended_owner,
                }
                for step in record.next_steps[:10]
            ],
            "created_at": record.created_at,
        }

    def _verification_summary(self, record: CallSummaryRecord) -> Dict[str, Any]:
        """Prepare compact Verification Agent summary."""

        return {
            "summary_id": record.summary_id,
            "call_id": record.call_id,
            "status": record.status,
            "outcome": record.outcome,
            "sentiment": self._serialize_sentiment(record.sentiment),
            "risk_level": record.risk_level,
            "risk_flags": record.risk_flags,
            "action_items_count": len(record.action_items),
            "next_steps_count": len(record.next_steps),
            "transcript_stats": record.transcript_stats,
            "created_at": record.created_at,
            "updated_at": record.updated_at,
        }

    # ------------------------------------------------------------------
    # Misc helpers
    # ------------------------------------------------------------------

    def _sanitize_call_metadata(self, metadata: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
        """Sanitize call metadata."""

        return _sanitize_dict(metadata)

    def _base_metadata(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
        *,
        call_id: Optional[str] = None,
        summary_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Build standard response metadata."""

        return {
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "module": self.module_name,
            "file": FILE_NAME,
            "schema_version": SCHEMA_VERSION,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "call_id": call_id,
            "summary_id": summary_id,
            "timestamp": _iso_now(),
        }

    @staticmethod
    def _average(values: Iterable[Union[int, float]]) -> float:
        """Safe average."""

        numeric = [float(value) for value in values if isinstance(value, (int, float))]
        if not numeric:
            return 0.0
        return round(sum(numeric) / len(numeric), 4)

    @staticmethod
    def _stats(values: Iterable[Union[int, float]]) -> Dict[str, Optional[float]]:
        """Basic numeric stats."""

        numeric = [float(value) for value in values if isinstance(value, (int, float))]
        if not numeric:
            return {
                "count": 0,
                "min": None,
                "max": None,
                "avg": None,
                "median": None,
                "p95": None,
            }

        sorted_values = sorted(numeric)
        p95_index = min(len(sorted_values) - 1, int(round((len(sorted_values) - 1) * 0.95)))

        return {
            "count": len(sorted_values),
            "min": round(min(sorted_values), 4),
            "max": round(max(sorted_values), 4),
            "avg": round(sum(sorted_values) / len(sorted_values), 4),
            "median": round(statistics.median(sorted_values), 4),
            "p95": round(sorted_values[p95_index], 4),
        }


# ---------------------------------------------------------------------------
# Module exports
# ---------------------------------------------------------------------------

__all__ = [
    "CallSummarizer",
    "CallSummarizerConfig",
    "CallSummaryStatus",
    "SentimentLabel",
    "CallOutcome",
    "ActionPriority",
    "RiskLevel",
    "TranscriptTurn",
    "ActionItem",
    "NextStep",
    "SentimentResult",
    "CallSummaryRecord",
    "InMemoryCallSummaryStore",
]