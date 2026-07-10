"""
agents/browser_agent/browser_memory.py

Browser Memory module for William / Jarvis Multi-Agent AI SaaS System.

Purpose:
    Save useful research findings, competitor notes, and source history
    produced by the Browser Agent and related browser tools.

Core responsibilities:
    - Store research findings with user/workspace isolation.
    - Store competitor notes.
    - Store source history and visited/researched URLs.
    - Search, list, update, archive, and export browser memory records.
    - Prepare Memory Agent compatible payloads.
    - Prepare Verification Agent compatible payloads.
    - Emit dashboard/API/agent events.
    - Write audit-ready structured logs.
    - Remain import-safe even when other William modules are not created yet.

Important:
    This file does not perform real browser actions.
    This file does not scrape, download, log in, submit forms, or execute automation.
    It only stores and retrieves memory-like browser research data.

Author:
    Digital Promotix / William-Jarvis Architecture
"""

from __future__ import annotations

import json
import logging
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union
from urllib.parse import urlparse


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# =============================================================================
# Safe fallback BaseAgent
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Import-safe fallback BaseAgent.

        The real William/Jarvis project should provide:
            agents/base_agent.py

        This fallback keeps browser_memory.py safe to import while the project
        is still being generated file-by-file.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)

        def emit_event(self, *args: Any, **kwargs: Any) -> None:
            return None


# =============================================================================
# Enums
# =============================================================================

class BrowserMemoryType(str, Enum):
    """
    Browser memory record types.
    """

    RESEARCH_FINDING = "research_finding"
    COMPETITOR_NOTE = "competitor_note"
    SOURCE_HISTORY = "source_history"
    PAGE_SUMMARY = "page_summary"
    SEO_NOTE = "seo_note"
    PRICE_NOTE = "price_note"
    WORKFLOW_NOTE = "workflow_note"
    CONTENT_EXTRACT = "content_extract"
    GENERAL_NOTE = "general_note"


class BrowserMemoryStatus(str, Enum):
    """
    Lifecycle status for a memory record.
    """

    ACTIVE = "active"
    ARCHIVED = "archived"
    DELETED = "deleted"


class BrowserMemoryImportance(str, Enum):
    """
    Importance level for ranking useful browser memory.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class BrowserMemoryRiskLevel(str, Enum):
    """
    Risk level for stored browser context.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class BrowserMemoryDecision(str, Enum):
    """
    Result decision style compatible with other William/Jarvis files.
    """

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_SECURITY_APPROVAL = "require_security_approval"
    REQUIRE_USER_CONFIRMATION = "require_user_confirmation"
    REQUIRE_MORE_CONTEXT = "require_more_context"


# =============================================================================
# Data models
# =============================================================================

@dataclass
class BrowserMemoryRecord:
    """
    A browser memory record.

    Every record is isolated by user_id and workspace_id.
    """

    memory_id: str
    user_id: str
    workspace_id: str
    memory_type: BrowserMemoryType
    title: str
    content: str
    url: Optional[str] = None
    domain: Optional[str] = None
    source_name: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    keywords: List[str] = field(default_factory=list)
    importance: BrowserMemoryImportance = BrowserMemoryImportance.MEDIUM
    status: BrowserMemoryStatus = BrowserMemoryStatus.ACTIVE
    confidence_score: float = 1.0
    task_id: Optional[str] = None
    session_id: Optional[str] = None
    agent_name: str = "BrowserMemory"
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BrowserSourceHistoryRecord:
    """
    Source history record for URLs researched by Browser Agent.
    """

    source_id: str
    user_id: str
    workspace_id: str
    url: str
    domain: str
    title: Optional[str] = None
    source_name: Optional[str] = None
    first_seen_at: float = field(default_factory=time.time)
    last_seen_at: float = field(default_factory=time.time)
    visit_count: int = 1
    task_ids: List[str] = field(default_factory=list)
    session_ids: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BrowserMemorySearchQuery:
    """
    Search query for browser memory records.
    """

    user_id: str
    workspace_id: str
    query: Optional[str] = None
    memory_type: Optional[BrowserMemoryType] = None
    domain: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    status: BrowserMemoryStatus = BrowserMemoryStatus.ACTIVE
    limit: int = 25
    include_archived: bool = False


# =============================================================================
# BrowserMemory
# =============================================================================

class BrowserMemory(BaseAgent):
    """
    Browser memory manager for William / Jarvis Browser Agent.

    This class can be used by:
        - Master Agent:
            To retrieve previous browser research context before planning.
        - Browser Agent:
            To save findings, competitor notes, source history, and summaries.
        - Memory Agent:
            To receive structured memory payloads from browser activity.
        - Verification Agent:
            To verify saved memory records after task completion.
        - Dashboard/API:
            To list, search, archive, and export browser memory.
        - Agent Registry / Loader / Router:
            This file is import-safe and exposes stable public methods.

    Storage:
        Default storage is in-memory for import safety and testing.
        Production can inject persistence callbacks or later replace this with
        database/repository integration without changing public methods.
    """

    DEFAULT_MAX_CONTENT_CHARS = 25000
    DEFAULT_MAX_TITLE_CHARS = 300
    DEFAULT_MAX_TAGS = 50
    DEFAULT_MAX_KEYWORDS = 100
    DEFAULT_SEARCH_LIMIT = 25

    SENSITIVE_KEY_PATTERNS = (
        "password",
        "pass",
        "pwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "private_key",
        "authorization",
        "cookie",
        "set-cookie",
        "session",
        "credit_card",
        "card_number",
        "cvv",
        "ssn",
        "otp",
        "2fa",
        "mfa",
        "pin",
    )

    def __init__(
        self,
        *,
        agent_name: str = "BrowserMemory",
        storage: Optional[Dict[str, BrowserMemoryRecord]] = None,
        source_history_storage: Optional[Dict[str, BrowserSourceHistoryRecord]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        security_approval_callback: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        max_content_chars: int = DEFAULT_MAX_CONTENT_CHARS,
        max_title_chars: int = DEFAULT_MAX_TITLE_CHARS,
        max_tags: int = DEFAULT_MAX_TAGS,
        max_keywords: int = DEFAULT_MAX_KEYWORDS,
        default_search_limit: int = DEFAULT_SEARCH_LIMIT,
        strict_isolation: bool = True,
    ) -> None:
        super().__init__(agent_name=agent_name)

        self.agent_name = agent_name
        self.storage: Dict[str, BrowserMemoryRecord] = storage if storage is not None else {}
        self.source_history_storage: Dict[str, BrowserSourceHistoryRecord] = (
            source_history_storage if source_history_storage is not None else {}
        )

        self.audit_callback = audit_callback
        self.event_callback = event_callback
        self.security_approval_callback = security_approval_callback

        self.max_content_chars = int(max_content_chars)
        self.max_title_chars = int(max_title_chars)
        self.max_tags = int(max_tags)
        self.max_keywords = int(max_keywords)
        self.default_search_limit = int(default_search_limit)
        self.strict_isolation = bool(strict_isolation)

    # -------------------------------------------------------------------------
    # Public save methods
    # -------------------------------------------------------------------------

    def save_research_finding(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        title: str,
        content: str,
        url: Optional[str] = None,
        source_name: Optional[str] = None,
        tags: Optional[Sequence[str]] = None,
        keywords: Optional[Sequence[str]] = None,
        importance: Union[str, BrowserMemoryImportance] = BrowserMemoryImportance.MEDIUM,
        confidence_score: float = 1.0,
        task_id: Optional[str] = None,
        session_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Save a useful research finding from browser research.
        """

        return self._save_memory_record(
            user_id=user_id,
            workspace_id=workspace_id,
            memory_type=BrowserMemoryType.RESEARCH_FINDING,
            title=title,
            content=content,
            url=url,
            source_name=source_name,
            tags=tags,
            keywords=keywords,
            importance=importance,
            confidence_score=confidence_score,
            task_id=task_id,
            session_id=session_id,
            metadata=metadata,
        )

    def save_competitor_note(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        competitor_name: str,
        note: str,
        url: Optional[str] = None,
        source_name: Optional[str] = None,
        tags: Optional[Sequence[str]] = None,
        keywords: Optional[Sequence[str]] = None,
        importance: Union[str, BrowserMemoryImportance] = BrowserMemoryImportance.HIGH,
        confidence_score: float = 1.0,
        task_id: Optional[str] = None,
        session_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Save competitor research notes.

        Useful for competitor_analyzer.py, seo_analyzer.py, price_monitor.py,
        and Browser Agent reporting.
        """

        title = f"Competitor Note: {competitor_name}".strip()

        merged_metadata = dict(metadata or {})
        merged_metadata["competitor_name"] = competitor_name

        merged_tags = self._normalize_tags([*(tags or []), "competitor"])

        return self._save_memory_record(
            user_id=user_id,
            workspace_id=workspace_id,
            memory_type=BrowserMemoryType.COMPETITOR_NOTE,
            title=title,
            content=note,
            url=url,
            source_name=source_name,
            tags=merged_tags,
            keywords=keywords,
            importance=importance,
            confidence_score=confidence_score,
            task_id=task_id,
            session_id=session_id,
            metadata=merged_metadata,
        )

    def save_page_summary(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        title: str,
        summary: str,
        url: str,
        source_name: Optional[str] = None,
        tags: Optional[Sequence[str]] = None,
        keywords: Optional[Sequence[str]] = None,
        importance: Union[str, BrowserMemoryImportance] = BrowserMemoryImportance.MEDIUM,
        confidence_score: float = 1.0,
        task_id: Optional[str] = None,
        session_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Save a page summary produced by page_analyzer.py/content_extractor.py.
        """

        merged_tags = self._normalize_tags([*(tags or []), "page-summary"])

        result = self._save_memory_record(
            user_id=user_id,
            workspace_id=workspace_id,
            memory_type=BrowserMemoryType.PAGE_SUMMARY,
            title=title,
            content=summary,
            url=url,
            source_name=source_name,
            tags=merged_tags,
            keywords=keywords,
            importance=importance,
            confidence_score=confidence_score,
            task_id=task_id,
            session_id=session_id,
            metadata=metadata,
        )

        if result.get("success"):
            self.record_source_history(
                user_id=user_id,
                workspace_id=workspace_id,
                url=url,
                title=title,
                source_name=source_name,
                task_id=task_id,
                session_id=session_id,
                tags=merged_tags,
                metadata={"reason": "page_summary_saved"},
            )

        return result

    def save_seo_note(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        title: str,
        note: str,
        url: Optional[str] = None,
        source_name: Optional[str] = None,
        tags: Optional[Sequence[str]] = None,
        keywords: Optional[Sequence[str]] = None,
        importance: Union[str, BrowserMemoryImportance] = BrowserMemoryImportance.HIGH,
        confidence_score: float = 1.0,
        task_id: Optional[str] = None,
        session_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Save SEO-related browser memory.
        """

        merged_tags = self._normalize_tags([*(tags or []), "seo"])

        return self._save_memory_record(
            user_id=user_id,
            workspace_id=workspace_id,
            memory_type=BrowserMemoryType.SEO_NOTE,
            title=title,
            content=note,
            url=url,
            source_name=source_name,
            tags=merged_tags,
            keywords=keywords,
            importance=importance,
            confidence_score=confidence_score,
            task_id=task_id,
            session_id=session_id,
            metadata=metadata,
        )

    def save_price_note(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        title: str,
        note: str,
        url: Optional[str] = None,
        source_name: Optional[str] = None,
        tags: Optional[Sequence[str]] = None,
        keywords: Optional[Sequence[str]] = None,
        importance: Union[str, BrowserMemoryImportance] = BrowserMemoryImportance.MEDIUM,
        confidence_score: float = 1.0,
        task_id: Optional[str] = None,
        session_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Save pricing or offer-monitoring memory.
        """

        merged_tags = self._normalize_tags([*(tags or []), "price"])

        return self._save_memory_record(
            user_id=user_id,
            workspace_id=workspace_id,
            memory_type=BrowserMemoryType.PRICE_NOTE,
            title=title,
            content=note,
            url=url,
            source_name=source_name,
            tags=merged_tags,
            keywords=keywords,
            importance=importance,
            confidence_score=confidence_score,
            task_id=task_id,
            session_id=session_id,
            metadata=metadata,
        )

    def save_content_extract(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        title: str,
        extracted_content: str,
        url: Optional[str] = None,
        source_name: Optional[str] = None,
        tags: Optional[Sequence[str]] = None,
        keywords: Optional[Sequence[str]] = None,
        importance: Union[str, BrowserMemoryImportance] = BrowserMemoryImportance.MEDIUM,
        confidence_score: float = 1.0,
        task_id: Optional[str] = None,
        session_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Save extracted public content in summarized/safe form.
        """

        merged_tags = self._normalize_tags([*(tags or []), "content-extract"])

        return self._save_memory_record(
            user_id=user_id,
            workspace_id=workspace_id,
            memory_type=BrowserMemoryType.CONTENT_EXTRACT,
            title=title,
            content=extracted_content,
            url=url,
            source_name=source_name,
            tags=merged_tags,
            keywords=keywords,
            importance=importance,
            confidence_score=confidence_score,
            task_id=task_id,
            session_id=session_id,
            metadata=metadata,
        )

    def save_workflow_note(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        title: str,
        note: str,
        url: Optional[str] = None,
        source_name: Optional[str] = None,
        tags: Optional[Sequence[str]] = None,
        keywords: Optional[Sequence[str]] = None,
        importance: Union[str, BrowserMemoryImportance] = BrowserMemoryImportance.MEDIUM,
        confidence_score: float = 1.0,
        task_id: Optional[str] = None,
        session_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Save browser workflow learning notes.
        """

        merged_tags = self._normalize_tags([*(tags or []), "workflow"])

        return self._save_memory_record(
            user_id=user_id,
            workspace_id=workspace_id,
            memory_type=BrowserMemoryType.WORKFLOW_NOTE,
            title=title,
            content=note,
            url=url,
            source_name=source_name,
            tags=merged_tags,
            keywords=keywords,
            importance=importance,
            confidence_score=confidence_score,
            task_id=task_id,
            session_id=session_id,
            metadata=metadata,
        )

    def record_source_history(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        url: str,
        title: Optional[str] = None,
        source_name: Optional[str] = None,
        task_id: Optional[str] = None,
        session_id: Optional[str] = None,
        tags: Optional[Sequence[str]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Save or update source history for a researched URL.
        """

        try:
            context_result = self._validate_task_context(
                user_id=user_id,
                workspace_id=workspace_id,
                action="record_source_history",
                task_id=task_id,
                session_id=session_id,
                metadata=metadata,
            )
            if not context_result["success"]:
                return context_result

            clean_url = self._normalize_url(url)
            if not clean_url:
                return self._error_result(
                    message="Invalid source URL.",
                    error="url is required",
                    user_id=str(user_id),
                    workspace_id=str(workspace_id),
                )

            domain = self._extract_domain(clean_url)
            if not domain:
                return self._error_result(
                    message="Invalid source domain.",
                    error="domain could not be parsed from URL",
                    user_id=str(user_id),
                    workspace_id=str(workspace_id),
                )

            normalized_user_id = str(user_id).strip()
            normalized_workspace_id = str(workspace_id).strip()
            source_key = self._source_key(
                user_id=normalized_user_id,
                workspace_id=normalized_workspace_id,
                url=clean_url,
            )

            now = time.time()
            normalized_tags = self._normalize_tags(tags or [])

            if source_key in self.source_history_storage:
                record = self.source_history_storage[source_key]
                record.last_seen_at = now
                record.visit_count += 1

                if title:
                    record.title = self._clean_text(title, self.max_title_chars)

                if source_name:
                    record.source_name = self._clean_text(source_name, 200)

                if task_id and task_id not in record.task_ids:
                    record.task_ids.append(task_id)

                if session_id and session_id not in record.session_ids:
                    record.session_ids.append(session_id)

                record.tags = self._normalize_tags([*record.tags, *normalized_tags])
                record.metadata.update(self._sanitize_metadata(metadata or {}))

                message = "Source history updated."
            else:
                record = BrowserSourceHistoryRecord(
                    source_id=str(uuid.uuid4()),
                    user_id=normalized_user_id,
                    workspace_id=normalized_workspace_id,
                    url=clean_url,
                    domain=domain,
                    title=self._clean_text(title or "", self.max_title_chars) or None,
                    source_name=self._clean_text(source_name or "", 200) or None,
                    first_seen_at=now,
                    last_seen_at=now,
                    visit_count=1,
                    task_ids=[task_id] if task_id else [],
                    session_ids=[session_id] if session_id else [],
                    tags=normalized_tags,
                    metadata=self._sanitize_metadata(metadata or {}),
                )
                self.source_history_storage[source_key] = record
                message = "Source history saved."

            result = self._safe_result(
                message=message,
                data={"source": self._source_to_dict(record)},
                user_id=record.user_id,
                workspace_id=record.workspace_id,
                metadata={
                    "operation": "record_source_history",
                    "source_id": record.source_id,
                    "domain": record.domain,
                },
            )

            self._emit_agent_event("browser_source_history_recorded", result)
            self._log_audit_event(
                event_type="browser_source_history_recorded",
                user_id=record.user_id,
                workspace_id=record.workspace_id,
                task_id=task_id,
                session_id=session_id,
                result=result,
            )

            return result

        except Exception as exc:
            logger.exception("Failed to record source history.")
            return self._error_result(
                message="Failed to record source history.",
                error=str(exc),
                user_id=str(user_id),
                workspace_id=str(workspace_id),
            )

    # -------------------------------------------------------------------------
    # Public retrieval/search methods
    # -------------------------------------------------------------------------

    def get_memory(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        memory_id: str,
        include_archived: bool = False,
    ) -> Dict[str, Any]:
        """
        Get one browser memory record by ID with strict SaaS isolation.
        """

        try:
            validation = self._validate_task_context(
                user_id=user_id,
                workspace_id=workspace_id,
                action="get_memory",
            )
            if not validation["success"]:
                return validation

            record = self.storage.get(str(memory_id).strip())
            if not record:
                return self._error_result(
                    message="Browser memory record not found.",
                    error="not_found",
                    user_id=str(user_id),
                    workspace_id=str(workspace_id),
                )

            if not self._record_belongs_to_context(record, str(user_id), str(workspace_id)):
                return self._isolation_denied_result(
                    user_id=str(user_id),
                    workspace_id=str(workspace_id),
                    requested_record_id=memory_id,
                )

            if record.status == BrowserMemoryStatus.ARCHIVED and not include_archived:
                return self._error_result(
                    message="Browser memory record is archived.",
                    error="archived",
                    user_id=str(user_id),
                    workspace_id=str(workspace_id),
                )

            if record.status == BrowserMemoryStatus.DELETED:
                return self._error_result(
                    message="Browser memory record was deleted.",
                    error="deleted",
                    user_id=str(user_id),
                    workspace_id=str(workspace_id),
                )

            return self._safe_result(
                message="Browser memory record retrieved.",
                data={"memory": self._record_to_dict(record)},
                user_id=record.user_id,
                workspace_id=record.workspace_id,
                metadata={"operation": "get_memory", "memory_id": record.memory_id},
            )

        except Exception as exc:
            logger.exception("Failed to get browser memory.")
            return self._error_result(
                message="Failed to get browser memory.",
                error=str(exc),
                user_id=str(user_id),
                workspace_id=str(workspace_id),
            )

    def search_memory(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        query: Optional[str] = None,
        memory_type: Optional[Union[str, BrowserMemoryType]] = None,
        domain: Optional[str] = None,
        tags: Optional[Sequence[str]] = None,
        status: Union[str, BrowserMemoryStatus] = BrowserMemoryStatus.ACTIVE,
        include_archived: bool = False,
        limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Search browser memory records inside one user/workspace only.
        """

        try:
            validation = self._validate_task_context(
                user_id=user_id,
                workspace_id=workspace_id,
                action="search_memory",
            )
            if not validation["success"]:
                return validation

            normalized_user_id = str(user_id).strip()
            normalized_workspace_id = str(workspace_id).strip()
            normalized_type = self._normalize_memory_type(memory_type) if memory_type else None
            normalized_status = self._normalize_status(status)
            normalized_domain = self._normalize_domain(domain) if domain else None
            normalized_tags = self._normalize_tags(tags or [])
            safe_limit = self._safe_limit(limit)

            query_text = self._clean_text(query or "", 500).lower()

            matches: List[BrowserMemoryRecord] = []

            for record in self.storage.values():
                if not self._record_belongs_to_context(record, normalized_user_id, normalized_workspace_id):
                    continue

                if record.status == BrowserMemoryStatus.DELETED:
                    continue

                if not include_archived and record.status == BrowserMemoryStatus.ARCHIVED:
                    continue

                if normalized_status and not include_archived and record.status != normalized_status:
                    continue

                if normalized_type and record.memory_type != normalized_type:
                    continue

                if normalized_domain and self._normalize_domain(record.domain or "") != normalized_domain:
                    continue

                if normalized_tags:
                    record_tags = set(self._normalize_tags(record.tags))
                    if not set(normalized_tags).issubset(record_tags):
                        continue

                if query_text:
                    haystack = " ".join(
                        [
                            record.title,
                            record.content,
                            record.domain or "",
                            record.source_name or "",
                            " ".join(record.tags),
                            " ".join(record.keywords),
                        ]
                    ).lower()

                    if query_text not in haystack:
                        continue

                matches.append(record)

            matches = self._sort_records(matches)[:safe_limit]

            return self._safe_result(
                message="Browser memory search completed.",
                data={
                    "results": [self._record_to_dict(record) for record in matches],
                    "count": len(matches),
                    "limit": safe_limit,
                    "query": {
                        "query": query,
                        "memory_type": normalized_type.value if normalized_type else None,
                        "domain": normalized_domain,
                        "tags": normalized_tags,
                        "status": normalized_status.value if normalized_status else None,
                        "include_archived": include_archived,
                    },
                },
                user_id=normalized_user_id,
                workspace_id=normalized_workspace_id,
                metadata={"operation": "search_memory"},
            )

        except Exception as exc:
            logger.exception("Failed to search browser memory.")
            return self._error_result(
                message="Failed to search browser memory.",
                error=str(exc),
                user_id=str(user_id),
                workspace_id=str(workspace_id),
            )

    def list_recent_memory(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        memory_type: Optional[Union[str, BrowserMemoryType]] = None,
        limit: Optional[int] = None,
        include_archived: bool = False,
    ) -> Dict[str, Any]:
        """
        List recent browser memory records for dashboard/API.
        """

        return self.search_memory(
            user_id=user_id,
            workspace_id=workspace_id,
            memory_type=memory_type,
            include_archived=include_archived,
            limit=limit,
        )

    def list_source_history(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        domain: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        List source history for one user/workspace only.
        """

        try:
            validation = self._validate_task_context(
                user_id=user_id,
                workspace_id=workspace_id,
                action="list_source_history",
            )
            if not validation["success"]:
                return validation

            normalized_user_id = str(user_id).strip()
            normalized_workspace_id = str(workspace_id).strip()
            normalized_domain = self._normalize_domain(domain) if domain else None
            safe_limit = self._safe_limit(limit)

            records: List[BrowserSourceHistoryRecord] = []

            for record in self.source_history_storage.values():
                if record.user_id != normalized_user_id:
                    continue

                if record.workspace_id != normalized_workspace_id:
                    continue

                if normalized_domain and record.domain != normalized_domain:
                    continue

                records.append(record)

            records.sort(key=lambda item: item.last_seen_at, reverse=True)
            records = records[:safe_limit]

            return self._safe_result(
                message="Browser source history listed.",
                data={
                    "sources": [self._source_to_dict(record) for record in records],
                    "count": len(records),
                    "limit": safe_limit,
                    "domain": normalized_domain,
                },
                user_id=normalized_user_id,
                workspace_id=normalized_workspace_id,
                metadata={"operation": "list_source_history"},
            )

        except Exception as exc:
            logger.exception("Failed to list browser source history.")
            return self._error_result(
                message="Failed to list browser source history.",
                error=str(exc),
                user_id=str(user_id),
                workspace_id=str(workspace_id),
            )

    def get_research_context(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        query: Optional[str] = None,
        domain: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Return compact research context for Master Agent planning.

        This is useful before the Browser Agent starts a new research task.
        """

        search_result = self.search_memory(
            user_id=user_id,
            workspace_id=workspace_id,
            query=query,
            domain=domain,
            include_archived=False,
            limit=limit or 10,
        )

        if not search_result.get("success"):
            return search_result

        sources_result = self.list_source_history(
            user_id=user_id,
            workspace_id=workspace_id,
            domain=domain,
            limit=limit or 10,
        )

        memory_items = search_result.get("data", {}).get("results", [])
        source_items = sources_result.get("data", {}).get("sources", []) if sources_result.get("success") else []

        compact_context = {
            "memory_count": len(memory_items),
            "source_count": len(source_items),
            "key_findings": [
                {
                    "memory_id": item.get("memory_id"),
                    "type": item.get("memory_type"),
                    "title": item.get("title"),
                    "domain": item.get("domain"),
                    "importance": item.get("importance"),
                    "content_preview": self._preview(item.get("content", ""), 300),
                }
                for item in memory_items
            ],
            "recent_sources": [
                {
                    "source_id": item.get("source_id"),
                    "url": item.get("url"),
                    "domain": item.get("domain"),
                    "title": item.get("title"),
                    "visit_count": item.get("visit_count"),
                }
                for item in source_items
            ],
        }

        return self._safe_result(
            message="Research context prepared.",
            data={"research_context": compact_context},
            user_id=str(user_id),
            workspace_id=str(workspace_id),
            metadata={"operation": "get_research_context"},
        )

    # -------------------------------------------------------------------------
    # Update/archive/delete/export methods
    # -------------------------------------------------------------------------

    def update_memory(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        memory_id: str,
        title: Optional[str] = None,
        content: Optional[str] = None,
        tags: Optional[Sequence[str]] = None,
        keywords: Optional[Sequence[str]] = None,
        importance: Optional[Union[str, BrowserMemoryImportance]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Update an existing memory record with isolation protection.
        """

        try:
            get_result = self.get_memory(
                user_id=user_id,
                workspace_id=workspace_id,
                memory_id=memory_id,
                include_archived=True,
            )
            if not get_result.get("success"):
                return get_result

            record = self.storage.get(str(memory_id).strip())
            if not record:
                return self._error_result(
                    message="Browser memory record not found.",
                    error="not_found",
                    user_id=str(user_id),
                    workspace_id=str(workspace_id),
                )

            if title is not None:
                record.title = self._clean_text(title, self.max_title_chars)

            if content is not None:
                record.content = self._clean_text(content, self.max_content_chars)

            if tags is not None:
                record.tags = self._normalize_tags(tags)

            if keywords is not None:
                record.keywords = self._normalize_keywords(keywords)

            if importance is not None:
                record.importance = self._normalize_importance(importance)

            if metadata is not None:
                record.metadata.update(self._sanitize_metadata(metadata))

            record.updated_at = time.time()

            result = self._safe_result(
                message="Browser memory record updated.",
                data={"memory": self._record_to_dict(record)},
                user_id=record.user_id,
                workspace_id=record.workspace_id,
                metadata={"operation": "update_memory", "memory_id": record.memory_id},
            )

            self._emit_agent_event("browser_memory_updated", result)
            self._log_audit_event(
                event_type="browser_memory_updated",
                user_id=record.user_id,
                workspace_id=record.workspace_id,
                task_id=record.task_id,
                session_id=record.session_id,
                result=result,
            )

            return result

        except Exception as exc:
            logger.exception("Failed to update browser memory.")
            return self._error_result(
                message="Failed to update browser memory.",
                error=str(exc),
                user_id=str(user_id),
                workspace_id=str(workspace_id),
            )

    def archive_memory(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        memory_id: str,
    ) -> Dict[str, Any]:
        """
        Archive a memory record.
        """

        return self._set_memory_status(
            user_id=user_id,
            workspace_id=workspace_id,
            memory_id=memory_id,
            status=BrowserMemoryStatus.ARCHIVED,
            operation="archive_memory",
            message="Browser memory record archived.",
        )

    def restore_memory(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        memory_id: str,
    ) -> Dict[str, Any]:
        """
        Restore an archived memory record.
        """

        return self._set_memory_status(
            user_id=user_id,
            workspace_id=workspace_id,
            memory_id=memory_id,
            status=BrowserMemoryStatus.ACTIVE,
            operation="restore_memory",
            message="Browser memory record restored.",
        )

    def delete_memory(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        memory_id: str,
        soft_delete: bool = True,
    ) -> Dict[str, Any]:
        """
        Delete a memory record.

        Default is soft delete to keep audit safety.
        """

        if soft_delete:
            return self._set_memory_status(
                user_id=user_id,
                workspace_id=workspace_id,
                memory_id=memory_id,
                status=BrowserMemoryStatus.DELETED,
                operation="delete_memory",
                message="Browser memory record soft-deleted.",
            )

        try:
            get_result = self.get_memory(
                user_id=user_id,
                workspace_id=workspace_id,
                memory_id=memory_id,
                include_archived=True,
            )
            if not get_result.get("success"):
                return get_result

            record = self.storage.pop(str(memory_id).strip(), None)
            if not record:
                return self._error_result(
                    message="Browser memory record not found.",
                    error="not_found",
                    user_id=str(user_id),
                    workspace_id=str(workspace_id),
                )

            result = self._safe_result(
                message="Browser memory record permanently deleted.",
                data={"memory_id": memory_id},
                user_id=str(user_id),
                workspace_id=str(workspace_id),
                metadata={"operation": "delete_memory", "soft_delete": False},
            )

            self._emit_agent_event("browser_memory_deleted", result)
            self._log_audit_event(
                event_type="browser_memory_deleted",
                user_id=str(user_id),
                workspace_id=str(workspace_id),
                task_id=record.task_id,
                session_id=record.session_id,
                result=result,
            )

            return result

        except Exception as exc:
            logger.exception("Failed to delete browser memory.")
            return self._error_result(
                message="Failed to delete browser memory.",
                error=str(exc),
                user_id=str(user_id),
                workspace_id=str(workspace_id),
            )

    def export_memory(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        include_archived: bool = False,
        include_deleted: bool = False,
    ) -> Dict[str, Any]:
        """
        Export browser memory for one user/workspace.

        Returns JSON-serializable data. Does not write files directly.
        """

        try:
            validation = self._validate_task_context(
                user_id=user_id,
                workspace_id=workspace_id,
                action="export_memory",
            )
            if not validation["success"]:
                return validation

            normalized_user_id = str(user_id).strip()
            normalized_workspace_id = str(workspace_id).strip()

            records: List[Dict[str, Any]] = []

            for record in self.storage.values():
                if not self._record_belongs_to_context(record, normalized_user_id, normalized_workspace_id):
                    continue

                if record.status == BrowserMemoryStatus.ARCHIVED and not include_archived:
                    continue

                if record.status == BrowserMemoryStatus.DELETED and not include_deleted:
                    continue

                records.append(self._record_to_dict(record))

            sources = [
                self._source_to_dict(source)
                for source in self.source_history_storage.values()
                if source.user_id == normalized_user_id and source.workspace_id == normalized_workspace_id
            ]

            export_payload = {
                "export_id": str(uuid.uuid4()),
                "user_id": normalized_user_id,
                "workspace_id": normalized_workspace_id,
                "created_at": time.time(),
                "memory_records": records,
                "source_history": sources,
                "counts": {
                    "memory_records": len(records),
                    "source_history": len(sources),
                },
            }

            return self._safe_result(
                message="Browser memory export prepared.",
                data={"export": export_payload},
                user_id=normalized_user_id,
                workspace_id=normalized_workspace_id,
                metadata={"operation": "export_memory"},
            )

        except Exception as exc:
            logger.exception("Failed to export browser memory.")
            return self._error_result(
                message="Failed to export browser memory.",
                error=str(exc),
                user_id=str(user_id),
                workspace_id=str(workspace_id),
            )

    def to_json(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        include_archived: bool = False,
        include_deleted: bool = False,
        indent: int = 2,
    ) -> Dict[str, Any]:
        """
        Export browser memory as JSON string inside structured result.
        """

        export_result = self.export_memory(
            user_id=user_id,
            workspace_id=workspace_id,
            include_archived=include_archived,
            include_deleted=include_deleted,
        )

        if not export_result.get("success"):
            return export_result

        try:
            json_text = json.dumps(
                export_result["data"]["export"],
                indent=indent,
                ensure_ascii=False,
                default=str,
            )

            return self._safe_result(
                message="Browser memory JSON prepared.",
                data={"json": json_text},
                user_id=str(user_id),
                workspace_id=str(workspace_id),
                metadata={"operation": "to_json"},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to serialize browser memory JSON.",
                error=str(exc),
                user_id=str(user_id),
                workspace_id=str(workspace_id),
            )

    # -------------------------------------------------------------------------
    # Required compatibility hooks
    # -------------------------------------------------------------------------

    def _validate_task_context(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        action: str,
        task_id: Optional[str] = None,
        session_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate task context for SaaS isolation.

        Every browser memory operation must include user_id and workspace_id.
        """

        normalized_user_id = str(user_id).strip() if user_id is not None else ""
        normalized_workspace_id = str(workspace_id).strip() if workspace_id is not None else ""

        blocked_reasons: List[str] = []

        if not normalized_user_id:
            blocked_reasons.append("missing_user_id")

        if not normalized_workspace_id:
            blocked_reasons.append("missing_workspace_id")

        if normalized_user_id.lower() in {"none", "null", "undefined", "0"}:
            blocked_reasons.append("invalid_user_id")

        if normalized_workspace_id.lower() in {"none", "null", "undefined", "0"}:
            blocked_reasons.append("invalid_workspace_id")

        if not str(action).strip():
            blocked_reasons.append("missing_action")

        if blocked_reasons:
            return self._safe_result(
                success=False,
                message="Browser memory task context failed validation.",
                data={
                    "action": action,
                    "task_id": task_id,
                    "session_id": session_id,
                    "blocked_reasons": blocked_reasons,
                },
                error="; ".join(blocked_reasons),
                user_id=normalized_user_id or None,
                workspace_id=normalized_workspace_id or None,
                metadata={
                    "operation": "validate_task_context",
                    "blocked_reasons": blocked_reasons,
                    **dict(metadata or {}),
                },
            )

        return self._safe_result(
            message="Browser memory task context validated.",
            data={
                "action": action,
                "task_id": task_id,
                "session_id": session_id,
            },
            user_id=normalized_user_id,
            workspace_id=normalized_workspace_id,
            metadata={"operation": "validate_task_context", **dict(metadata or {})},
        )

    def _requires_security_check(
        self,
        *,
        memory_type: Union[str, BrowserMemoryType],
        title: str = "",
        content: str = "",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Decide whether a browser memory save requires Security Agent approval.

        This protects accidental storage of secrets, credentials, cookies,
        private tokens, payment fields, or sensitive session data.
        """

        normalized_type = self._normalize_memory_type(memory_type)
        metadata = metadata or {}

        combined = " ".join(
            [
                str(title or ""),
                str(content or ""),
                " ".join(str(key) for key in metadata.keys()),
            ]
        ).lower()

        if normalized_type in {
            BrowserMemoryType.SOURCE_HISTORY,
            BrowserMemoryType.PAGE_SUMMARY,
            BrowserMemoryType.RESEARCH_FINDING,
            BrowserMemoryType.COMPETITOR_NOTE,
            BrowserMemoryType.SEO_NOTE,
            BrowserMemoryType.PRICE_NOTE,
            BrowserMemoryType.WORKFLOW_NOTE,
            BrowserMemoryType.CONTENT_EXTRACT,
        }:
            for pattern in self.SENSITIVE_KEY_PATTERNS:
                if pattern in combined:
                    return True

        return False

    def _request_security_approval(
        self,
        *,
        user_id: str,
        workspace_id: str,
        action: str,
        reason: str,
        memory_type: Optional[Union[str, BrowserMemoryType]] = None,
        task_id: Optional[str] = None,
        session_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        If a callback is injected, it is called.
        Otherwise, a structured approval-required result is returned.
        """

        approval_payload = {
            "approval_id": str(uuid.uuid4()),
            "source_agent": self.agent_name,
            "target_agent": "SecurityAgent",
            "user_id": user_id,
            "workspace_id": workspace_id,
            "action": action,
            "reason": reason,
            "memory_type": (
                self._normalize_memory_type(memory_type).value
                if memory_type is not None
                else None
            ),
            "task_id": task_id,
            "session_id": session_id,
            "risk_level": BrowserMemoryRiskLevel.HIGH.value,
            "created_at": time.time(),
            "metadata": self._sanitize_metadata(metadata or {}),
        }

        if self.security_approval_callback:
            try:
                response = self.security_approval_callback(approval_payload)
                if isinstance(response, Mapping):
                    return dict(response)
            except Exception as exc:
                logger.exception("Browser memory security approval callback failed.")
                return self._error_result(
                    message="Security approval callback failed.",
                    error=str(exc),
                    user_id=user_id,
                    workspace_id=workspace_id,
                    metadata={"approval_payload": approval_payload},
                )

        return self._safe_result(
            success=True,
            message="Security Agent approval is required before saving this browser memory.",
            data={"approval_payload": approval_payload},
            user_id=user_id,
            workspace_id=workspace_id,
            metadata={
                "operation": "request_security_approval",
                "decision": BrowserMemoryDecision.REQUIRE_SECURITY_APPROVAL.value,
                "risk_level": BrowserMemoryRiskLevel.HIGH.value,
            },
        )

    def _prepare_verification_payload(
        self,
        *,
        record: Optional[BrowserMemoryRecord],
        action: str,
        result: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload for completed browser memory actions.
        """

        return {
            "verification_id": str(uuid.uuid4()),
            "source_agent": self.agent_name,
            "target_agent": "VerificationAgent",
            "action": action,
            "success": bool(result.get("success")),
            "message": result.get("message"),
            "memory_id": record.memory_id if record else None,
            "memory_type": record.memory_type.value if record else None,
            "user_id": record.user_id if record else result.get("user_id"),
            "workspace_id": record.workspace_id if record else result.get("workspace_id"),
            "task_id": record.task_id if record else None,
            "session_id": record.session_id if record else None,
            "created_at": time.time(),
            "metadata": {
                "module": "agents/browser_agent/browser_memory.py",
                "status": record.status.value if record else None,
            },
        }

    def _prepare_memory_payload(
        self,
        *,
        record: BrowserMemoryRecord,
        action: str = "save_browser_memory",
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        The BrowserMemory class stores local browser memory and can also pass
        safe memory payloads to a future central Memory Agent.
        """

        return {
            "memory_payload_id": str(uuid.uuid4()),
            "source_agent": self.agent_name,
            "target_agent": "MemoryAgent",
            "action": action,
            "user_id": record.user_id,
            "workspace_id": record.workspace_id,
            "task_id": record.task_id,
            "session_id": record.session_id,
            "memory_type": record.memory_type.value,
            "title": record.title,
            "summary": self._preview(record.content, 500),
            "url": record.url,
            "domain": record.domain,
            "source_name": record.source_name,
            "tags": list(record.tags),
            "keywords": list(record.keywords),
            "importance": record.importance.value,
            "confidence_score": record.confidence_score,
            "created_at": time.time(),
            "metadata": {
                "browser_memory_id": record.memory_id,
                "contains_sensitive_values": False,
                "module": "agents/browser_agent/browser_memory.py",
            },
        }

    def _emit_agent_event(
        self,
        event_name: str,
        payload: Mapping[str, Any],
    ) -> None:
        """
        Emit agent/dashboard event.
        """

        event = {
            "event_id": str(uuid.uuid4()),
            "event_name": event_name,
            "agent_name": self.agent_name,
            "created_at": time.time(),
            "payload": dict(payload),
        }

        if self.event_callback:
            try:
                self.event_callback(event)
                return
            except Exception:
                logger.exception("Browser memory event callback failed.")

        try:
            if hasattr(super(), "emit_event"):
                super().emit_event(event_name, event)  # type: ignore[misc]
        except Exception:
            logger.debug("BaseAgent event emission unavailable.", exc_info=True)

    def _log_audit_event(
        self,
        *,
        event_type: str,
        user_id: str,
        workspace_id: str,
        result: Mapping[str, Any],
        task_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> None:
        """
        Log an audit event for browser memory actions.
        """

        audit_event = {
            "audit_id": str(uuid.uuid4()),
            "event_type": event_type,
            "agent_name": self.agent_name,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "task_id": task_id,
            "session_id": session_id,
            "success": bool(result.get("success")),
            "message": result.get("message"),
            "error": result.get("error"),
            "created_at": time.time(),
            "metadata": dict(result.get("metadata") or {}),
        }

        if self.audit_callback:
            try:
                self.audit_callback(audit_event)
                return
            except Exception:
                logger.exception("Browser memory audit callback failed.")

        logger.info("Browser memory audit event: %s", audit_event)

    def _safe_result(
        self,
        *,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        success: bool = True,
        error: Optional[str] = None,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard William/Jarvis structured success result.
        """

        return {
            "success": bool(success),
            "message": message,
            "data": dict(data or {}),
            "error": error,
            "metadata": {
                "agent_name": self.agent_name,
                "module": "agents/browser_agent/browser_memory.py",
                "timestamp": time.time(),
                **dict(metadata or {}),
            },
            "user_id": user_id,
            "workspace_id": workspace_id,
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Optional[str] = None,
        data: Optional[Mapping[str, Any]] = None,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard William/Jarvis structured error result.
        """

        return {
            "success": False,
            "message": message,
            "data": dict(data or {}),
            "error": error or message,
            "metadata": {
                "agent_name": self.agent_name,
                "module": "agents/browser_agent/browser_memory.py",
                "timestamp": time.time(),
                **dict(metadata or {}),
            },
            "user_id": user_id,
            "workspace_id": workspace_id,
        }

    # -------------------------------------------------------------------------
    # Internal save/update helpers
    # -------------------------------------------------------------------------

    def _save_memory_record(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        memory_type: Union[str, BrowserMemoryType],
        title: str,
        content: str,
        url: Optional[str] = None,
        source_name: Optional[str] = None,
        tags: Optional[Sequence[str]] = None,
        keywords: Optional[Sequence[str]] = None,
        importance: Union[str, BrowserMemoryImportance] = BrowserMemoryImportance.MEDIUM,
        confidence_score: float = 1.0,
        task_id: Optional[str] = None,
        session_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Core record save function.
        """

        try:
            validation = self._validate_task_context(
                user_id=user_id,
                workspace_id=workspace_id,
                action="save_memory_record",
                task_id=task_id,
                session_id=session_id,
                metadata=metadata,
            )
            if not validation["success"]:
                return validation

            normalized_user_id = str(user_id).strip()
            normalized_workspace_id = str(workspace_id).strip()
            normalized_type = self._normalize_memory_type(memory_type)

            clean_title = self._clean_text(title, self.max_title_chars)
            clean_content = self._clean_text(content, self.max_content_chars)

            if not clean_title:
                return self._error_result(
                    message="Memory title is required.",
                    error="missing_title",
                    user_id=normalized_user_id,
                    workspace_id=normalized_workspace_id,
                )

            if not clean_content:
                return self._error_result(
                    message="Memory content is required.",
                    error="missing_content",
                    user_id=normalized_user_id,
                    workspace_id=normalized_workspace_id,
                )

            sanitized_metadata = self._sanitize_metadata(metadata or {})

            if self._requires_security_check(
                memory_type=normalized_type,
                title=clean_title,
                content=clean_content,
                metadata=sanitized_metadata,
            ):
                return self._request_security_approval(
                    user_id=normalized_user_id,
                    workspace_id=normalized_workspace_id,
                    action="save_browser_memory",
                    reason="Memory content appears to contain sensitive browser/session/credential data.",
                    memory_type=normalized_type,
                    task_id=task_id,
                    session_id=session_id,
                    metadata=sanitized_metadata,
                )

            clean_url = self._normalize_url(url) if url else None
            domain = self._extract_domain(clean_url) if clean_url else None

            record = BrowserMemoryRecord(
                memory_id=str(uuid.uuid4()),
                user_id=normalized_user_id,
                workspace_id=normalized_workspace_id,
                memory_type=normalized_type,
                title=clean_title,
                content=clean_content,
                url=clean_url,
                domain=domain,
                source_name=self._clean_text(source_name or "", 200) or None,
                tags=self._normalize_tags(tags or []),
                keywords=self._normalize_keywords(keywords or []),
                importance=self._normalize_importance(importance),
                status=BrowserMemoryStatus.ACTIVE,
                confidence_score=self._normalize_confidence(confidence_score),
                task_id=task_id,
                session_id=session_id,
                agent_name=self.agent_name,
                created_at=time.time(),
                updated_at=time.time(),
                metadata=sanitized_metadata,
            )

            self.storage[record.memory_id] = record

            if clean_url:
                self.record_source_history(
                    user_id=normalized_user_id,
                    workspace_id=normalized_workspace_id,
                    url=clean_url,
                    title=clean_title,
                    source_name=source_name,
                    task_id=task_id,
                    session_id=session_id,
                    tags=record.tags,
                    metadata={"reason": "memory_record_saved"},
                )

            base_result = self._safe_result(
                message="Browser memory record saved.",
                data={"memory": self._record_to_dict(record)},
                user_id=record.user_id,
                workspace_id=record.workspace_id,
                metadata={
                    "operation": "save_memory_record",
                    "memory_id": record.memory_id,
                    "memory_type": record.memory_type.value,
                },
            )

            verification_payload = self._prepare_verification_payload(
                record=record,
                action="save_memory_record",
                result=base_result,
            )
            memory_payload = self._prepare_memory_payload(record=record)

            base_result["data"]["verification_payload"] = verification_payload
            base_result["data"]["memory_payload"] = memory_payload

            self._emit_agent_event("browser_memory_saved", base_result)
            self._log_audit_event(
                event_type="browser_memory_saved",
                user_id=record.user_id,
                workspace_id=record.workspace_id,
                task_id=record.task_id,
                session_id=record.session_id,
                result=base_result,
            )

            return base_result

        except Exception as exc:
            logger.exception("Failed to save browser memory record.")
            return self._error_result(
                message="Failed to save browser memory record.",
                error=str(exc),
                user_id=str(user_id),
                workspace_id=str(workspace_id),
            )

    def _set_memory_status(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        memory_id: str,
        status: BrowserMemoryStatus,
        operation: str,
        message: str,
    ) -> Dict[str, Any]:
        """
        Set memory status with isolation protection.
        """

        try:
            get_result = self.get_memory(
                user_id=user_id,
                workspace_id=workspace_id,
                memory_id=memory_id,
                include_archived=True,
            )

            if not get_result.get("success") and status != BrowserMemoryStatus.ACTIVE:
                return get_result

            record = self.storage.get(str(memory_id).strip())
            if not record:
                return self._error_result(
                    message="Browser memory record not found.",
                    error="not_found",
                    user_id=str(user_id),
                    workspace_id=str(workspace_id),
                )

            if not self._record_belongs_to_context(record, str(user_id), str(workspace_id)):
                return self._isolation_denied_result(
                    user_id=str(user_id),
                    workspace_id=str(workspace_id),
                    requested_record_id=memory_id,
                )

            record.status = status
            record.updated_at = time.time()

            result = self._safe_result(
                message=message,
                data={"memory": self._record_to_dict(record)},
                user_id=record.user_id,
                workspace_id=record.workspace_id,
                metadata={"operation": operation, "memory_id": record.memory_id},
            )

            self._emit_agent_event(f"browser_memory_{status.value}", result)
            self._log_audit_event(
                event_type=f"browser_memory_{status.value}",
                user_id=record.user_id,
                workspace_id=record.workspace_id,
                task_id=record.task_id,
                session_id=record.session_id,
                result=result,
            )

            return result

        except Exception as exc:
            logger.exception("Failed to set browser memory status.")
            return self._error_result(
                message="Failed to set browser memory status.",
                error=str(exc),
                user_id=str(user_id),
                workspace_id=str(workspace_id),
            )

    # -------------------------------------------------------------------------
    # Isolation helpers
    # -------------------------------------------------------------------------

    def _record_belongs_to_context(
        self,
        record: BrowserMemoryRecord,
        user_id: str,
        workspace_id: str,
    ) -> bool:
        """
        Enforce strict user/workspace isolation.
        """

        if not self.strict_isolation:
            return True

        return record.user_id == str(user_id).strip() and record.workspace_id == str(workspace_id).strip()

    def _isolation_denied_result(
        self,
        *,
        user_id: str,
        workspace_id: str,
        requested_record_id: str,
    ) -> Dict[str, Any]:
        """
        Return isolation denial.
        """

        return self._safe_result(
            success=False,
            message="Access denied. Browser memory record does not belong to this user/workspace.",
            data={"requested_record_id": requested_record_id},
            error="workspace_isolation_violation",
            user_id=user_id,
            workspace_id=workspace_id,
            metadata={
                "operation": "isolation_check",
                "risk_level": BrowserMemoryRiskLevel.CRITICAL.value,
            },
        )

    # -------------------------------------------------------------------------
    # Serialization helpers
    # -------------------------------------------------------------------------

    def _record_to_dict(self, record: BrowserMemoryRecord) -> Dict[str, Any]:
        """
        Convert memory record to JSON-safe dict.
        """

        data = asdict(record)
        data["memory_type"] = record.memory_type.value
        data["importance"] = record.importance.value
        data["status"] = record.status.value
        return data

    def _source_to_dict(self, record: BrowserSourceHistoryRecord) -> Dict[str, Any]:
        """
        Convert source history record to JSON-safe dict.
        """

        return asdict(record)

    # -------------------------------------------------------------------------
    # Normalization helpers
    # -------------------------------------------------------------------------

    def _normalize_memory_type(
        self,
        memory_type: Union[str, BrowserMemoryType],
    ) -> BrowserMemoryType:
        if isinstance(memory_type, BrowserMemoryType):
            return memory_type

        raw = str(memory_type or "").strip().lower()

        aliases = {
            "research": BrowserMemoryType.RESEARCH_FINDING,
            "finding": BrowserMemoryType.RESEARCH_FINDING,
            "competitor": BrowserMemoryType.COMPETITOR_NOTE,
            "source": BrowserMemoryType.SOURCE_HISTORY,
            "history": BrowserMemoryType.SOURCE_HISTORY,
            "summary": BrowserMemoryType.PAGE_SUMMARY,
            "page": BrowserMemoryType.PAGE_SUMMARY,
            "seo": BrowserMemoryType.SEO_NOTE,
            "price": BrowserMemoryType.PRICE_NOTE,
            "pricing": BrowserMemoryType.PRICE_NOTE,
            "workflow": BrowserMemoryType.WORKFLOW_NOTE,
            "extract": BrowserMemoryType.CONTENT_EXTRACT,
            "content": BrowserMemoryType.CONTENT_EXTRACT,
            "note": BrowserMemoryType.GENERAL_NOTE,
        }

        if raw in aliases:
            return aliases[raw]

        try:
            return BrowserMemoryType(raw)
        except ValueError:
            return BrowserMemoryType.GENERAL_NOTE

    def _normalize_status(
        self,
        status: Union[str, BrowserMemoryStatus],
    ) -> BrowserMemoryStatus:
        if isinstance(status, BrowserMemoryStatus):
            return status

        raw = str(status or "").strip().lower()

        try:
            return BrowserMemoryStatus(raw)
        except ValueError:
            return BrowserMemoryStatus.ACTIVE

    def _normalize_importance(
        self,
        importance: Union[str, BrowserMemoryImportance],
    ) -> BrowserMemoryImportance:
        if isinstance(importance, BrowserMemoryImportance):
            return importance

        raw = str(importance or "").strip().lower()

        try:
            return BrowserMemoryImportance(raw)
        except ValueError:
            return BrowserMemoryImportance.MEDIUM

    def _normalize_confidence(self, confidence_score: Union[int, float]) -> float:
        try:
            value = float(confidence_score)
        except Exception:
            value = 1.0

        if value < 0:
            return 0.0

        if value > 1:
            return 1.0

        return value

    def _normalize_tags(self, tags: Iterable[str]) -> List[str]:
        clean_tags: List[str] = []
        seen = set()

        for tag in tags:
            clean = self._slug(str(tag or "").strip().lower())
            if not clean:
                continue

            if clean in seen:
                continue

            clean_tags.append(clean)
            seen.add(clean)

            if len(clean_tags) >= self.max_tags:
                break

        return clean_tags

    def _normalize_keywords(self, keywords: Iterable[str]) -> List[str]:
        clean_keywords: List[str] = []
        seen = set()

        for keyword in keywords:
            clean = self._clean_text(str(keyword or "").strip().lower(), 120)
            if not clean:
                continue

            if clean in seen:
                continue

            clean_keywords.append(clean)
            seen.add(clean)

            if len(clean_keywords) >= self.max_keywords:
                break

        return clean_keywords

    def _normalize_url(self, url: Optional[str]) -> Optional[str]:
        if not url:
            return None

        clean = str(url).strip()

        if not clean:
            return None

        parsed = urlparse(clean)

        if not parsed.scheme:
            clean = f"https://{clean}"
            parsed = urlparse(clean)

        if parsed.scheme.lower() not in {"http", "https"}:
            return None

        if not parsed.netloc:
            return None

        return clean

    def _extract_domain(self, url: Optional[str]) -> Optional[str]:
        if not url:
            return None

        try:
            parsed = urlparse(url)
            domain = parsed.netloc or ""
            domain = domain.split("@")[-1]
            domain = domain.split(":")[0]
            return self._normalize_domain(domain)
        except Exception:
            return None

    def _normalize_domain(self, domain: Optional[str]) -> Optional[str]:
        if not domain:
            return None

        clean = str(domain).strip().lower()
        clean = clean.replace("http://", "").replace("https://", "")
        clean = clean.split("/")[0].split(":")[0]
        clean = clean[4:] if clean.startswith("www.") else clean
        return clean or None

    def _source_key(self, *, user_id: str, workspace_id: str, url: str) -> str:
        return f"{user_id}:{workspace_id}:{url}"

    def _clean_text(self, value: Optional[str], max_chars: int) -> str:
        clean = str(value or "").replace("\x00", "").strip()
        clean = re.sub(r"[ \t]+", " ", clean)
        clean = re.sub(r"\n{4,}", "\n\n\n", clean)

        if len(clean) > max_chars:
            clean = clean[: max_chars - 3].rstrip() + "..."

        return clean

    def _sanitize_metadata(self, metadata: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Remove sensitive-looking metadata values before storage.
        """

        sanitized: Dict[str, Any] = {}

        for key, value in metadata.items():
            clean_key = str(key)
            lower_key = clean_key.lower()

            if any(pattern in lower_key for pattern in self.SENSITIVE_KEY_PATTERNS):
                sanitized[clean_key] = "[REDACTED]"
                continue

            if isinstance(value, Mapping):
                sanitized[clean_key] = self._sanitize_metadata(value)
            elif isinstance(value, (list, tuple)):
                sanitized[clean_key] = [
                    self._sanitize_metadata(item) if isinstance(item, Mapping) else item
                    for item in value
                ]
            else:
                sanitized[clean_key] = value

        return sanitized

    def _safe_limit(self, limit: Optional[int]) -> int:
        try:
            value = int(limit) if limit is not None else self.default_search_limit
        except Exception:
            value = self.default_search_limit

        if value <= 0:
            return self.default_search_limit

        return min(value, 250)

    def _sort_records(self, records: Sequence[BrowserMemoryRecord]) -> List[BrowserMemoryRecord]:
        importance_rank = {
            BrowserMemoryImportance.CRITICAL: 4,
            BrowserMemoryImportance.HIGH: 3,
            BrowserMemoryImportance.MEDIUM: 2,
            BrowserMemoryImportance.LOW: 1,
        }

        return sorted(
            records,
            key=lambda record: (
                importance_rank.get(record.importance, 0),
                record.updated_at,
                record.confidence_score,
            ),
            reverse=True,
        )

    def _slug(self, value: str) -> str:
        clean = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
        return clean[:80]

    def _preview(self, value: str, max_chars: int = 300) -> str:
        clean = self._clean_text(value, max_chars)
        return clean

    # -------------------------------------------------------------------------
    # Debug / stats helpers
    # -------------------------------------------------------------------------

    def get_stats(
        self,
        *,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
    ) -> Dict[str, Any]:
        """
        Return dashboard-friendly browser memory stats for one user/workspace.
        """

        try:
            validation = self._validate_task_context(
                user_id=user_id,
                workspace_id=workspace_id,
                action="get_stats",
            )
            if not validation["success"]:
                return validation

            normalized_user_id = str(user_id).strip()
            normalized_workspace_id = str(workspace_id).strip()

            records = [
                record
                for record in self.storage.values()
                if self._record_belongs_to_context(record, normalized_user_id, normalized_workspace_id)
            ]

            sources = [
                source
                for source in self.source_history_storage.values()
                if source.user_id == normalized_user_id and source.workspace_id == normalized_workspace_id
            ]

            by_type: Dict[str, int] = {}
            by_status: Dict[str, int] = {}
            by_domain: Dict[str, int] = {}

            for record in records:
                by_type[record.memory_type.value] = by_type.get(record.memory_type.value, 0) + 1
                by_status[record.status.value] = by_status.get(record.status.value, 0) + 1

                if record.domain:
                    by_domain[record.domain] = by_domain.get(record.domain, 0) + 1

            return self._safe_result(
                message="Browser memory stats prepared.",
                data={
                    "total_memory_records": len(records),
                    "total_source_history_records": len(sources),
                    "by_type": by_type,
                    "by_status": by_status,
                    "top_domains": sorted(
                        by_domain.items(),
                        key=lambda item: item[1],
                        reverse=True,
                    )[:20],
                },
                user_id=normalized_user_id,
                workspace_id=normalized_workspace_id,
                metadata={"operation": "get_stats"},
            )

        except Exception as exc:
            logger.exception("Failed to get browser memory stats.")
            return self._error_result(
                message="Failed to get browser memory stats.",
                error=str(exc),
                user_id=str(user_id),
                workspace_id=str(workspace_id),
            )


# =============================================================================
# Factory helper
# =============================================================================

def create_browser_memory(**kwargs: Any) -> BrowserMemory:
    """
    Factory helper for Agent Loader / Agent Registry.

    Example:
        browser_memory = create_browser_memory()
    """

    return BrowserMemory(**kwargs)


# =============================================================================
# Module exports
# =============================================================================

__all__ = [
    "BrowserMemoryType",
    "BrowserMemoryStatus",
    "BrowserMemoryImportance",
    "BrowserMemoryRiskLevel",
    "BrowserMemoryDecision",
    "BrowserMemoryRecord",
    "BrowserSourceHistoryRecord",
    "BrowserMemorySearchQuery",
    "BrowserMemory",
    "create_browser_memory",
]