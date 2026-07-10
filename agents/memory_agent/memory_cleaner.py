"""
agents/memory_agent/memory_cleaner.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Memory Agent Helper: MemoryCleaner

Purpose:
    Deduplicates, merges, marks outdated, and cleans noisy memories.

Architecture Role:
    - Used by Memory Agent to maintain clean, useful, low-noise memory stores.
    - Compatible with Master Agent routing, Agent Registry, Agent Loader, and Dashboard/API usage.
    - Protects SaaS isolation using user_id and workspace_id validation.
    - Does not directly delete or destructively modify external storage.
    - Produces structured results, audit payloads, verification payloads, and memory payloads.

Important:
    This file is import-safe. If William core modules are not created yet, fallback stubs are used.
"""

from __future__ import annotations

import copy
import hashlib
import logging
import math
import re
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from difflib import SequenceMatcher
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------
# Safe optional imports for William/Jarvis architecture compatibility
# ---------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # fallback stub
        """
        Fallback BaseAgent stub.

        This keeps the file safe to import before the real William BaseAgent
        exists. The real BaseAgent can later provide routing, registry, auth,
        telemetry, and lifecycle hooks.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)

        async def run(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent run() not implemented.",
                "data": {},
                "error": None,
                "metadata": {},
            }


try:
    from agents.security_agent.security_agent import SecurityAgent  # type: ignore
except Exception:  # pragma: no cover
    SecurityAgent = None  # type: ignore


try:
    from agents.verification_agent.verification_agent import VerificationAgent  # type: ignore
except Exception:  # pragma: no cover
    VerificationAgent = None  # type: ignore


# ---------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------
# Enums and data structures
# ---------------------------------------------------------------------

class CleanupAction(str, Enum):
    """Supported memory cleanup action names."""

    DEDUPLICATE = "deduplicate"
    MERGE = "merge"
    MARK_OUTDATED = "mark_outdated"
    MARK_NOISY = "mark_noisy"
    NORMALIZE = "normalize"
    QUALITY_ANALYSIS = "quality_analysis"
    FULL_CLEAN = "full_clean"


class MemoryStatus(str, Enum):
    """Standard status labels for memory records."""

    ACTIVE = "active"
    MERGED = "merged"
    DUPLICATE = "duplicate"
    OUTDATED = "outdated"
    NOISY = "noisy"
    ARCHIVED = "archived"


class MemoryPrivacyLevel(str, Enum):
    """Memory privacy labels compatible with privacy/security upgrades."""

    PUBLIC = "public"
    INTERNAL = "internal"
    PRIVATE = "private"
    SENSITIVE = "sensitive"
    UNKNOWN = "unknown"


@dataclass
class MemoryCleanerConfig:
    """
    Configuration for MemoryCleaner.

    All thresholds are intentionally conservative to prevent accidental
    aggressive memory cleanup.
    """

    duplicate_similarity_threshold: float = 0.92
    merge_similarity_threshold: float = 0.78
    noisy_min_content_length: int = 8
    noisy_max_symbol_ratio: float = 0.45
    outdated_days_threshold: int = 365
    max_records_per_run: int = 5000
    allow_sensitive_cleanup_without_security: bool = False
    default_dry_run: bool = True
    preserve_original_records: bool = True
    normalize_whitespace: bool = True
    normalize_case_for_matching: bool = True
    keep_highest_importance_record: bool = True
    version: str = "1.0.0"


@dataclass
class CleanupCandidate:
    """
    Represents one proposed cleanup operation.

    This object is returned in structured data so Dashboard/API can display
    exactly what changed or what would change in dry-run mode.
    """

    action: str
    source_memory_id: Optional[str] = None
    target_memory_id: Optional[str] = None
    reason: str = ""
    confidence: float = 0.0
    before: Dict[str, Any] = field(default_factory=dict)
    after: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MemoryQualityReport:
    """Quality report for one memory record."""

    memory_id: str
    score: float
    is_noisy: bool
    is_potentially_outdated: bool
    issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------
# MemoryCleaner
# ---------------------------------------------------------------------

class MemoryCleaner(BaseAgent):
    """
    Deduplicates, merges, marks outdated, and cleans noisy memories.

    Integration:
        - Master Agent can route memory maintenance tasks here.
        - Memory Agent can call clean_memories() on retrieved memory records.
        - Security Agent can approve destructive or sensitive cleanup.
        - Verification Agent receives verification payloads after cleanup.
        - Dashboard/API can use structured results for preview and approval.

    Record Format:
        This class accepts flexible dict-based memory records. Recommended keys:

        {
            "id": "memory-id",
            "user_id": "user-id",
            "workspace_id": "workspace-id",
            "content": "memory text",
            "category": "preference/project/client/general",
            "importance": 0.0 to 1.0,
            "privacy_level": "private",
            "status": "active",
            "created_at": ISO datetime,
            "updated_at": ISO datetime,
            "metadata": {}
        }

    Safety:
        - Does not execute external deletes.
        - Does not mix records across users/workspaces.
        - Defaults to dry_run=True.
        - Sensitive destructive actions request Security Agent approval hook.
    """

    def __init__(
        self,
        config: Optional[MemoryCleanerConfig] = None,
        security_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
        event_emitter: Optional[Callable[[Dict[str, Any]], None]] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name="MemoryCleaner", **kwargs)
        self.config = config or MemoryCleanerConfig()
        self.security_agent = security_agent
        self.verification_agent = verification_agent
        self.audit_logger = audit_logger
        self.event_emitter = event_emitter
        self.logger = logging.getLogger(f"{__name__}.MemoryCleaner")

    # -----------------------------------------------------------------
    # Public orchestration methods
    # -----------------------------------------------------------------

    def clean_memories(
        self,
        memories: Sequence[Dict[str, Any]],
        *,
        user_id: str,
        workspace_id: str,
        actions: Optional[Sequence[Union[str, CleanupAction]]] = None,
        dry_run: Optional[bool] = None,
        require_security: bool = True,
        task_id: Optional[str] = None,
        requested_by: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Run a full or selected memory cleanup workflow.

        Args:
            memories:
                Memory records to clean.
            user_id:
                SaaS user isolation key.
            workspace_id:
                SaaS workspace isolation key.
            actions:
                Selected actions. Defaults to normalize, deduplicate, merge,
                mark_outdated, and mark_noisy.
            dry_run:
                If True, returns proposed changes without applying them.
            require_security:
                If True, sensitive or non-dry-run actions call security hook.
            task_id:
                Optional Master Agent task id.
            requested_by:
                Optional actor id.
            context:
                Optional routing/dashboard metadata.

        Returns:
            Structured dict result.
        """

        start_time = time.time()
        dry_run = self.config.default_dry_run if dry_run is None else bool(dry_run)
        task_id = task_id or self._new_id("memory-clean-task")
        context = context or {}

        validation = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            memories=memories,
            task_id=task_id,
        )
        if not validation["success"]:
            return validation

        selected_actions = self._normalize_actions(actions)

        if require_security and self._requires_security_check(
            actions=selected_actions,
            memories=memories,
            dry_run=dry_run,
        ):
            approval = self._request_security_approval(
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                action="memory_cleanup",
                details={
                    "actions": [a.value for a in selected_actions],
                    "record_count": len(memories),
                    "dry_run": dry_run,
                    "requested_by": requested_by,
                },
            )
            if not approval.get("success"):
                return self._error_result(
                    message="Security approval failed or was not granted for memory cleanup.",
                    error=approval.get("error") or approval.get("message"),
                    metadata={
                        "task_id": task_id,
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                        "security": approval,
                    },
                )

        isolated_records = self._filter_isolated_memories(
            memories=memories,
            user_id=user_id,
            workspace_id=workspace_id,
        )

        working_records = copy.deepcopy(isolated_records)
        all_candidates: List[CleanupCandidate] = []
        reports: List[MemoryQualityReport] = []

        try:
            if CleanupAction.NORMALIZE in selected_actions:
                normalized_result = self.normalize_memories(
                    working_records,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    dry_run=dry_run,
                    task_id=task_id,
                )
                all_candidates.extend(
                    self._candidate_objects(normalized_result["data"].get("candidates", []))
                )
                if not dry_run:
                    working_records = normalized_result["data"].get("memories", working_records)

            if CleanupAction.QUALITY_ANALYSIS in selected_actions:
                quality_result = self.analyze_memory_quality(
                    working_records,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    task_id=task_id,
                )
                reports.extend(
                    self._quality_report_objects(quality_result["data"].get("reports", []))
                )

            if CleanupAction.DEDUPLICATE in selected_actions:
                dedupe_result = self.deduplicate_memories(
                    working_records,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    dry_run=dry_run,
                    task_id=task_id,
                )
                all_candidates.extend(
                    self._candidate_objects(dedupe_result["data"].get("candidates", []))
                )
                if not dry_run:
                    working_records = dedupe_result["data"].get("memories", working_records)

            if CleanupAction.MERGE in selected_actions:
                merge_result = self.merge_memories(
                    working_records,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    dry_run=dry_run,
                    task_id=task_id,
                )
                all_candidates.extend(
                    self._candidate_objects(merge_result["data"].get("candidates", []))
                )
                if not dry_run:
                    working_records = merge_result["data"].get("memories", working_records)

            if CleanupAction.MARK_OUTDATED in selected_actions:
                outdated_result = self.mark_outdated_memories(
                    working_records,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    dry_run=dry_run,
                    task_id=task_id,
                )
                all_candidates.extend(
                    self._candidate_objects(outdated_result["data"].get("candidates", []))
                )
                if not dry_run:
                    working_records = outdated_result["data"].get("memories", working_records)

            if CleanupAction.MARK_NOISY in selected_actions:
                noisy_result = self.mark_noisy_memories(
                    working_records,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    dry_run=dry_run,
                    task_id=task_id,
                )
                all_candidates.extend(
                    self._candidate_objects(noisy_result["data"].get("candidates", []))
                )
                if not dry_run:
                    working_records = noisy_result["data"].get("memories", working_records)

            elapsed_ms = round((time.time() - start_time) * 1000, 2)

            verification_payload = self._prepare_verification_payload(
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                action="memory_cleanup",
                before_count=len(isolated_records),
                after_count=len(working_records),
                candidates=[asdict(c) for c in all_candidates],
                dry_run=dry_run,
            )

            memory_payload = self._prepare_memory_payload(
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                summary=f"Memory cleanup {'previewed' if dry_run else 'completed'} with {len(all_candidates)} candidate changes.",
                metadata={
                    "actions": [a.value for a in selected_actions],
                    "dry_run": dry_run,
                    "candidate_count": len(all_candidates),
                },
            )

            self._emit_agent_event(
                {
                    "event": "memory_cleaner.completed",
                    "task_id": task_id,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "dry_run": dry_run,
                    "actions": [a.value for a in selected_actions],
                    "candidate_count": len(all_candidates),
                    "elapsed_ms": elapsed_ms,
                }
            )

            self._log_audit_event(
                {
                    "event": "memory_cleanup",
                    "task_id": task_id,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "requested_by": requested_by,
                    "dry_run": dry_run,
                    "actions": [a.value for a in selected_actions],
                    "input_count": len(memories),
                    "isolated_count": len(isolated_records),
                    "output_count": len(working_records),
                    "candidate_count": len(all_candidates),
                    "timestamp": self._now_iso(),
                }
            )

            return self._safe_result(
                message="Memory cleanup preview generated successfully."
                if dry_run else "Memory cleanup completed successfully.",
                data={
                    "memories": working_records,
                    "candidates": [asdict(c) for c in all_candidates],
                    "quality_reports": [asdict(r) for r in reports],
                    "summary": {
                        "input_count": len(memories),
                        "isolated_count": len(isolated_records),
                        "output_count": len(working_records),
                        "candidate_count": len(all_candidates),
                        "dry_run": dry_run,
                        "actions": [a.value for a in selected_actions],
                    },
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={
                    "task_id": task_id,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "elapsed_ms": elapsed_ms,
                    "agent": "MemoryCleaner",
                    "version": self.config.version,
                },
            )

        except Exception as exc:
            self.logger.exception("Memory cleanup failed.")
            return self._error_result(
                message="Memory cleanup failed.",
                error=str(exc),
                metadata={
                    "task_id": task_id,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "agent": "MemoryCleaner",
                },
            )

    def normalize_memories(
        self,
        memories: Sequence[Dict[str, Any]],
        *,
        user_id: str,
        workspace_id: str,
        dry_run: Optional[bool] = None,
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Normalize memory content and required fields.

        Normalization includes:
            - Ensuring ids exist.
            - Normalizing whitespace.
            - Adding default status.
            - Adding default metadata.
            - Ensuring user/workspace fields match context.
        """

        dry_run = self.config.default_dry_run if dry_run is None else bool(dry_run)
        task_id = task_id or self._new_id("normalize-task")

        validation = self._validate_task_context(user_id, workspace_id, memories, task_id)
        if not validation["success"]:
            return validation

        records = self._filter_isolated_memories(memories, user_id, workspace_id)
        updated_records: List[Dict[str, Any]] = []
        candidates: List[CleanupCandidate] = []

        for record in records:
            before = copy.deepcopy(record)
            after = copy.deepcopy(record)

            after["id"] = str(after.get("id") or after.get("memory_id") or self._new_id("memory"))
            after["user_id"] = user_id
            after["workspace_id"] = workspace_id
            after.setdefault("status", MemoryStatus.ACTIVE.value)
            after.setdefault("metadata", {})
            after.setdefault("created_at", self._now_iso())
            after.setdefault("updated_at", self._now_iso())
            after.setdefault("privacy_level", MemoryPrivacyLevel.UNKNOWN.value)

            if "content" not in after:
                after["content"] = str(after.get("text") or after.get("summary") or "")

            if self.config.normalize_whitespace:
                after["content"] = self._normalize_text(after.get("content", ""))

            if before != after:
                candidate = CleanupCandidate(
                    action=CleanupAction.NORMALIZE.value,
                    source_memory_id=str(after["id"]),
                    reason="Normalized memory schema/content defaults.",
                    confidence=1.0,
                    before=before,
                    after=after,
                    metadata={"dry_run": dry_run},
                )
                candidates.append(candidate)

            updated_records.append(before if dry_run else after)

        return self._safe_result(
            message="Memory normalization preview generated."
            if dry_run else "Memories normalized successfully.",
            data={
                "memories": updated_records,
                "candidates": [asdict(c) for c in candidates],
            },
            metadata={
                "task_id": task_id,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "dry_run": dry_run,
            },
        )

    def deduplicate_memories(
        self,
        memories: Sequence[Dict[str, Any]],
        *,
        user_id: str,
        workspace_id: str,
        dry_run: Optional[bool] = None,
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Detect duplicate memories and mark duplicates.

        The canonical record is selected by:
            1. Highest importance.
            2. Most recent updated_at.
            3. Longest useful content.
        """

        dry_run = self.config.default_dry_run if dry_run is None else bool(dry_run)
        task_id = task_id or self._new_id("dedupe-task")

        validation = self._validate_task_context(user_id, workspace_id, memories, task_id)
        if not validation["success"]:
            return validation

        records = self._filter_isolated_memories(memories, user_id, workspace_id)
        records = [copy.deepcopy(r) for r in records]
        candidates: List[CleanupCandidate] = []
        duplicate_ids: set[str] = set()

        grouped = self._group_by_category(records)

        for _, group in grouped.items():
            for i, first in enumerate(group):
                first_id = self._memory_id(first)
                if first_id in duplicate_ids:
                    continue

                for second in group[i + 1:]:
                    second_id = self._memory_id(second)
                    if second_id in duplicate_ids:
                        continue

                    score = self._memory_similarity(first, second)
                    if score >= self.config.duplicate_similarity_threshold:
                        canonical, duplicate = self._select_canonical(first, second)
                        duplicate_id = self._memory_id(duplicate)
                        duplicate_ids.add(duplicate_id)

                        after = copy.deepcopy(duplicate)
                        after["status"] = MemoryStatus.DUPLICATE.value
                        after["duplicate_of"] = self._memory_id(canonical)
                        after["updated_at"] = self._now_iso()
                        after.setdefault("metadata", {})
                        after["metadata"]["duplicate_similarity"] = score
                        after["metadata"]["duplicate_reason"] = "Highly similar memory content/category."

                        candidates.append(
                            CleanupCandidate(
                                action=CleanupAction.DEDUPLICATE.value,
                                source_memory_id=duplicate_id,
                                target_memory_id=self._memory_id(canonical),
                                reason="Duplicate memory detected.",
                                confidence=round(score, 4),
                                before=duplicate,
                                after=after,
                                metadata={
                                    "similarity": score,
                                    "dry_run": dry_run,
                                },
                            )
                        )

        if not dry_run:
            candidate_by_id = {
                c.source_memory_id: c.after
                for c in candidates
                if c.source_memory_id
            }
            for index, record in enumerate(records):
                rid = self._memory_id(record)
                if rid in candidate_by_id:
                    records[index] = candidate_by_id[rid]

        return self._safe_result(
            message="Memory deduplication preview generated."
            if dry_run else "Memory deduplication completed.",
            data={
                "memories": records,
                "candidates": [asdict(c) for c in candidates],
                "duplicate_count": len(candidates),
            },
            metadata={
                "task_id": task_id,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "dry_run": dry_run,
                "threshold": self.config.duplicate_similarity_threshold,
            },
        )

    def merge_memories(
        self,
        memories: Sequence[Dict[str, Any]],
        *,
        user_id: str,
        workspace_id: str,
        dry_run: Optional[bool] = None,
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Merge strongly related but not exact duplicate memories.

        Source records are marked as merged into a canonical memory. The canonical
        record receives merged content and source ids in metadata.
        """

        dry_run = self.config.default_dry_run if dry_run is None else bool(dry_run)
        task_id = task_id or self._new_id("merge-task")

        validation = self._validate_task_context(user_id, workspace_id, memories, task_id)
        if not validation["success"]:
            return validation

        records = self._filter_isolated_memories(memories, user_id, workspace_id)
        records = [copy.deepcopy(r) for r in records]
        candidates: List[CleanupCandidate] = []
        consumed_ids: set[str] = set()
        replacement_by_id: Dict[str, Dict[str, Any]] = {}

        grouped = self._group_by_category(records)

        for _, group in grouped.items():
            for i, first in enumerate(group):
                first_id = self._memory_id(first)
                if first_id in consumed_ids:
                    continue

                for second in group[i + 1:]:
                    second_id = self._memory_id(second)
                    if second_id in consumed_ids:
                        continue

                    score = self._memory_similarity(first, second)

                    if (
                        self.config.merge_similarity_threshold
                        <= score
                        < self.config.duplicate_similarity_threshold
                    ):
                        canonical, source = self._select_canonical(first, second)
                        canonical_id = self._memory_id(canonical)
                        source_id = self._memory_id(source)

                        merged = self._build_merged_memory(
                            canonical=canonical,
                            source=source,
                            user_id=user_id,
                            workspace_id=workspace_id,
                            similarity=score,
                        )

                        source_after = copy.deepcopy(source)
                        source_after["status"] = MemoryStatus.MERGED.value
                        source_after["merged_into"] = canonical_id
                        source_after["updated_at"] = self._now_iso()
                        source_after.setdefault("metadata", {})
                        source_after["metadata"]["merge_similarity"] = score

                        candidates.append(
                            CleanupCandidate(
                                action=CleanupAction.MERGE.value,
                                source_memory_id=source_id,
                                target_memory_id=canonical_id,
                                reason="Related memory merged into canonical record.",
                                confidence=round(score, 4),
                                before={
                                    "canonical": canonical,
                                    "source": source,
                                },
                                after={
                                    "canonical": merged,
                                    "source": source_after,
                                },
                                metadata={
                                    "similarity": score,
                                    "dry_run": dry_run,
                                },
                            )
                        )

                        replacement_by_id[canonical_id] = merged
                        replacement_by_id[source_id] = source_after
                        consumed_ids.add(source_id)

        if not dry_run:
            for index, record in enumerate(records):
                rid = self._memory_id(record)
                if rid in replacement_by_id:
                    records[index] = replacement_by_id[rid]

        return self._safe_result(
            message="Memory merge preview generated."
            if dry_run else "Memory merge completed.",
            data={
                "memories": records,
                "candidates": [asdict(c) for c in candidates],
                "merge_count": len(candidates),
            },
            metadata={
                "task_id": task_id,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "dry_run": dry_run,
                "threshold": self.config.merge_similarity_threshold,
            },
        )

    def mark_outdated_memories(
        self,
        memories: Sequence[Dict[str, Any]],
        *,
        user_id: str,
        workspace_id: str,
        dry_run: Optional[bool] = None,
        task_id: Optional[str] = None,
        reference_time: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Mark old memories as outdated when they are stale and low-confidence.

        Important preferences, project rules, and sensitive records are treated
        conservatively and are not marked outdated unless metadata explicitly
        indicates expiration.
        """

        dry_run = self.config.default_dry_run if dry_run is None else bool(dry_run)
        task_id = task_id or self._new_id("outdated-task")
        reference_time = reference_time or datetime.now(timezone.utc)

        validation = self._validate_task_context(user_id, workspace_id, memories, task_id)
        if not validation["success"]:
            return validation

        records = self._filter_isolated_memories(memories, user_id, workspace_id)
        records = [copy.deepcopy(r) for r in records]
        candidates: List[CleanupCandidate] = []

        for index, record in enumerate(records):
            if self._is_terminal_status(record):
                continue

            should_outdate, reason, confidence = self._should_mark_outdated(
                record,
                reference_time=reference_time,
            )

            if should_outdate:
                after = copy.deepcopy(record)
                after["status"] = MemoryStatus.OUTDATED.value
                after["updated_at"] = self._now_iso()
                after.setdefault("metadata", {})
                after["metadata"]["outdated_reason"] = reason
                after["metadata"]["outdated_confidence"] = confidence

                candidates.append(
                    CleanupCandidate(
                        action=CleanupAction.MARK_OUTDATED.value,
                        source_memory_id=self._memory_id(record),
                        reason=reason,
                        confidence=confidence,
                        before=record,
                        after=after,
                        metadata={"dry_run": dry_run},
                    )
                )

                if not dry_run:
                    records[index] = after

        return self._safe_result(
            message="Outdated memory marking preview generated."
            if dry_run else "Outdated memories marked successfully.",
            data={
                "memories": records,
                "candidates": [asdict(c) for c in candidates],
                "outdated_count": len(candidates),
            },
            metadata={
                "task_id": task_id,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "dry_run": dry_run,
                "outdated_days_threshold": self.config.outdated_days_threshold,
            },
        )

    def mark_noisy_memories(
        self,
        memories: Sequence[Dict[str, Any]],
        *,
        user_id: str,
        workspace_id: str,
        dry_run: Optional[bool] = None,
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Mark low-value, broken, empty, or noisy memories.

        This does not permanently delete memories. It only marks records as noisy
        so storage layers can hide/archive them after review.
        """

        dry_run = self.config.default_dry_run if dry_run is None else bool(dry_run)
        task_id = task_id or self._new_id("noisy-task")

        validation = self._validate_task_context(user_id, workspace_id, memories, task_id)
        if not validation["success"]:
            return validation

        records = self._filter_isolated_memories(memories, user_id, workspace_id)
        records = [copy.deepcopy(r) for r in records]
        candidates: List[CleanupCandidate] = []

        for index, record in enumerate(records):
            if self._is_terminal_status(record):
                continue

            is_noisy, issues, score = self._is_noisy_memory(record)

            if is_noisy:
                after = copy.deepcopy(record)
                after["status"] = MemoryStatus.NOISY.value
                after["updated_at"] = self._now_iso()
                after.setdefault("metadata", {})
                after["metadata"]["noise_issues"] = issues
                after["metadata"]["quality_score"] = score

                candidates.append(
                    CleanupCandidate(
                        action=CleanupAction.MARK_NOISY.value,
                        source_memory_id=self._memory_id(record),
                        reason="Memory appears noisy or low-value.",
                        confidence=round(1.0 - score, 4),
                        before=record,
                        after=after,
                        metadata={
                            "issues": issues,
                            "quality_score": score,
                            "dry_run": dry_run,
                        },
                    )
                )

                if not dry_run:
                    records[index] = after

        return self._safe_result(
            message="Noisy memory marking preview generated."
            if dry_run else "Noisy memories marked successfully.",
            data={
                "memories": records,
                "candidates": [asdict(c) for c in candidates],
                "noisy_count": len(candidates),
            },
            metadata={
                "task_id": task_id,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "dry_run": dry_run,
            },
        )

    def analyze_memory_quality(
        self,
        memories: Sequence[Dict[str, Any]],
        *,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Generate quality reports for memory records without changing them.
        """

        task_id = task_id or self._new_id("quality-task")

        validation = self._validate_task_context(user_id, workspace_id, memories, task_id)
        if not validation["success"]:
            return validation

        records = self._filter_isolated_memories(memories, user_id, workspace_id)
        reports: List[MemoryQualityReport] = []

        for record in records:
            is_noisy, issues, score = self._is_noisy_memory(record)
            is_outdated, outdated_reason, outdated_confidence = self._should_mark_outdated(
                record,
                reference_time=datetime.now(timezone.utc),
            )

            recommendations: List[str] = []
            if is_noisy:
                recommendations.append("Review and archive if not useful.")
            if is_outdated:
                recommendations.append("Refresh or mark as outdated.")
            if not issues and not is_outdated:
                recommendations.append("Keep active.")

            report = MemoryQualityReport(
                memory_id=self._memory_id(record),
                score=score,
                is_noisy=is_noisy,
                is_potentially_outdated=is_outdated,
                issues=issues + ([outdated_reason] if is_outdated else []),
                recommendations=recommendations,
                metadata={
                    "outdated_confidence": outdated_confidence,
                    "status": record.get("status", MemoryStatus.ACTIVE.value),
                    "category": record.get("category"),
                    "privacy_level": record.get("privacy_level"),
                },
            )
            reports.append(report)

        return self._safe_result(
            message="Memory quality analysis completed.",
            data={
                "reports": [asdict(r) for r in reports],
                "summary": {
                    "record_count": len(records),
                    "noisy_count": sum(1 for r in reports if r.is_noisy),
                    "potentially_outdated_count": sum(
                        1 for r in reports if r.is_potentially_outdated
                    ),
                    "average_score": round(
                        sum(r.score for r in reports) / len(reports), 4
                    ) if reports else 0.0,
                },
            },
            metadata={
                "task_id": task_id,
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    # -----------------------------------------------------------------
    # Compatibility hooks required by William/Jarvis prompt bible
    # -----------------------------------------------------------------

    def _validate_task_context(
        self,
        user_id: str,
        workspace_id: str,
        memories: Optional[Sequence[Dict[str, Any]]] = None,
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Validate SaaS task context.

        This protects user/workspace isolation before memory cleanup logic runs.
        """

        if not user_id or not isinstance(user_id, str):
            return self._error_result(
                message="Invalid task context: user_id is required.",
                error="missing_user_id",
                metadata={"task_id": task_id},
            )

        if not workspace_id or not isinstance(workspace_id, str):
            return self._error_result(
                message="Invalid task context: workspace_id is required.",
                error="missing_workspace_id",
                metadata={"task_id": task_id, "user_id": user_id},
            )

        if memories is not None:
            if not isinstance(memories, Sequence):
                return self._error_result(
                    message="Invalid memories input: expected a sequence of dict records.",
                    error="invalid_memories_type",
                    metadata={
                        "task_id": task_id,
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                    },
                )

            if len(memories) > self.config.max_records_per_run:
                return self._error_result(
                    message="Too many memory records for one cleanup run.",
                    error="max_records_exceeded",
                    metadata={
                        "task_id": task_id,
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                        "max_records_per_run": self.config.max_records_per_run,
                        "received": len(memories),
                    },
                )

            for index, memory in enumerate(memories):
                if not isinstance(memory, dict):
                    return self._error_result(
                        message="Invalid memory record: each memory must be a dict.",
                        error="invalid_memory_record",
                        metadata={
                            "task_id": task_id,
                            "user_id": user_id,
                            "workspace_id": workspace_id,
                            "index": index,
                        },
                    )

        return self._safe_result(
            message="Task context validated.",
            data={},
            metadata={
                "task_id": task_id,
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    def _requires_security_check(
        self,
        *,
        actions: Sequence[CleanupAction],
        memories: Sequence[Dict[str, Any]],
        dry_run: bool,
    ) -> bool:
        """
        Decide whether Security Agent approval is needed.

        Non-dry-run cleanup and sensitive records require security approval.
        """

        if dry_run:
            return False

        sensitive_present = any(
            str(m.get("privacy_level", "")).lower()
            in {
                MemoryPrivacyLevel.SENSITIVE.value,
                "secret",
                "restricted",
                "confidential",
            }
            for m in memories
            if isinstance(m, dict)
        )

        destructive_actions = {
            CleanupAction.DEDUPLICATE,
            CleanupAction.MERGE,
            CleanupAction.MARK_OUTDATED,
            CleanupAction.MARK_NOISY,
        }

        if sensitive_present and not self.config.allow_sensitive_cleanup_without_security:
            return True

        return any(action in destructive_actions for action in actions)

    def _request_security_approval(
        self,
        *,
        user_id: str,
        workspace_id: str,
        task_id: str,
        action: str,
        details: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        This method is safe if the Security Agent is not installed yet. In that
        case, it allows dry-run safe behavior but blocks non-dry-run sensitive
        cleanup by returning a failed approval.
        """

        if self.security_agent and hasattr(self.security_agent, "approve_action"):
            try:
                approval = self.security_agent.approve_action(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    task_id=task_id,
                    action=action,
                    details=details,
                )
                if isinstance(approval, dict):
                    return approval
            except Exception as exc:
                return self._error_result(
                    message="Security Agent approval call failed.",
                    error=str(exc),
                    metadata={
                        "task_id": task_id,
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                    },
                )

        if details.get("dry_run") is True:
            return self._safe_result(
                message="Security approval bypassed for dry-run cleanup.",
                data={"approved": True, "fallback": True},
                metadata={
                    "task_id": task_id,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

        return self._error_result(
            message="Security Agent is unavailable for non-dry-run memory cleanup.",
            error="security_agent_unavailable",
            metadata={
                "task_id": task_id,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "action": action,
            },
        )

    def _prepare_verification_payload(
        self,
        *,
        user_id: str,
        workspace_id: str,
        task_id: str,
        action: str,
        before_count: int,
        after_count: int,
        candidates: List[Dict[str, Any]],
        dry_run: bool,
    ) -> Dict[str, Any]:
        """
        Prepare payload for Verification Agent.

        Verification Agent can use this to confirm cleanup safety, counts,
        changed ids, and confidence levels.
        """

        return {
            "verification_id": self._new_id("verify-memory-clean"),
            "agent": "MemoryCleaner",
            "action": action,
            "task_id": task_id,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "dry_run": dry_run,
            "before_count": before_count,
            "after_count": after_count,
            "candidate_count": len(candidates),
            "candidate_actions": self._count_by_key(candidates, "action"),
            "requires_human_review": any(
                float(c.get("confidence", 0.0)) < 0.85 for c in candidates
            ),
            "created_at": self._now_iso(),
        }

    def _prepare_memory_payload(
        self,
        *,
        user_id: str,
        workspace_id: str,
        task_id: str,
        summary: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare payload compatible with Memory Agent storage.

        This is not written directly here. Memory Agent or Master Agent can
        decide whether to store this operational memory.
        """

        return {
            "memory_id": self._new_id("memory-clean-summary"),
            "user_id": user_id,
            "workspace_id": workspace_id,
            "category": "system.memory_maintenance",
            "content": summary,
            "importance": 0.35,
            "privacy_level": MemoryPrivacyLevel.INTERNAL.value,
            "source_agent": "MemoryCleaner",
            "task_id": task_id,
            "created_at": self._now_iso(),
            "metadata": metadata or {},
        }

    def _emit_agent_event(self, event: Dict[str, Any]) -> None:
        """
        Emit event to Agent Registry, Dashboard, or telemetry.

        Uses injected event_emitter if available. Otherwise logs safely.
        """

        try:
            if self.event_emitter:
                self.event_emitter(event)
            else:
                self.logger.debug("Agent event: %s", event)
        except Exception:
            self.logger.exception("Failed to emit MemoryCleaner event.")

    def _log_audit_event(self, event: Dict[str, Any]) -> None:
        """
        Log audit event.

        Uses injected audit_logger if available. Otherwise logs safely.
        """

        try:
            if self.audit_logger:
                self.audit_logger(event)
            else:
                self.logger.info("MemoryCleaner audit event: %s", event)
        except Exception:
            self.logger.exception("Failed to log MemoryCleaner audit event.")

    def _safe_result(
        self,
        *,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard success result."""

        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Optional[Any] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard error result."""

        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": metadata or {},
        }

    # -----------------------------------------------------------------
    # Internal helper methods
    # -----------------------------------------------------------------

    def _normalize_actions(
        self,
        actions: Optional[Sequence[Union[str, CleanupAction]]],
    ) -> List[CleanupAction]:
        """Normalize action names into CleanupAction enum values."""

        if not actions:
            return [
                CleanupAction.NORMALIZE,
                CleanupAction.QUALITY_ANALYSIS,
                CleanupAction.DEDUPLICATE,
                CleanupAction.MERGE,
                CleanupAction.MARK_OUTDATED,
                CleanupAction.MARK_NOISY,
            ]

        normalized: List[CleanupAction] = []

        for action in actions:
            if isinstance(action, CleanupAction):
                normalized.append(action)
                continue

            value = str(action).strip().lower()

            if value == CleanupAction.FULL_CLEAN.value:
                return [
                    CleanupAction.NORMALIZE,
                    CleanupAction.QUALITY_ANALYSIS,
                    CleanupAction.DEDUPLICATE,
                    CleanupAction.MERGE,
                    CleanupAction.MARK_OUTDATED,
                    CleanupAction.MARK_NOISY,
                ]

            try:
                normalized.append(CleanupAction(value))
            except ValueError:
                self.logger.warning("Unsupported cleanup action ignored: %s", action)

        return normalized or [CleanupAction.QUALITY_ANALYSIS]

    def _filter_isolated_memories(
        self,
        memories: Sequence[Dict[str, Any]],
        user_id: str,
        workspace_id: str,
    ) -> List[Dict[str, Any]]:
        """
        Return records belonging only to requested user/workspace.

        Records missing user_id/workspace_id are allowed only if they are
        clearly local unsaved records. They are normalized into this context
        later by normalize_memories().
        """

        isolated: List[Dict[str, Any]] = []

        for memory in memories:
            record_user = memory.get("user_id")
            record_workspace = memory.get("workspace_id")

            if record_user is None and record_workspace is None:
                isolated.append(memory)
                continue

            if str(record_user) == str(user_id) and str(record_workspace) == str(workspace_id):
                isolated.append(memory)
                continue

            self.logger.warning(
                "Skipped cross-context memory record. expected=(%s,%s) got=(%s,%s)",
                user_id,
                workspace_id,
                record_user,
                record_workspace,
            )

        return isolated

    def _group_by_category(
        self,
        memories: Sequence[Dict[str, Any]],
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Group memories by category and privacy level for safer matching."""

        grouped: Dict[str, List[Dict[str, Any]]] = {}

        for record in memories:
            status = str(record.get("status", MemoryStatus.ACTIVE.value)).lower()
            if status in {
                MemoryStatus.DUPLICATE.value,
                MemoryStatus.MERGED.value,
                MemoryStatus.ARCHIVED.value,
            }:
                continue

            key = "|".join(
                [
                    str(record.get("category", "general")).lower(),
                    str(record.get("privacy_level", MemoryPrivacyLevel.UNKNOWN.value)).lower(),
                ]
            )
            grouped.setdefault(key, []).append(record)

        return grouped

    def _memory_similarity(self, first: Dict[str, Any], second: Dict[str, Any]) -> float:
        """
        Compute similarity between two memory records.

        Uses a balanced score:
            - normalized content similarity
            - token overlap
            - category match
            - entity hints from metadata
        """

        first_text = self._match_text(first)
        second_text = self._match_text(second)

        if not first_text or not second_text:
            return 0.0

        sequence_score = SequenceMatcher(None, first_text, second_text).ratio()
        token_score = self._token_jaccard(first_text, second_text)

        category_score = 1.0 if str(first.get("category", "")).lower() == str(second.get("category", "")).lower() else 0.0
        privacy_score = 1.0 if str(first.get("privacy_level", "")).lower() == str(second.get("privacy_level", "")).lower() else 0.0

        entity_score = self._metadata_entity_similarity(first, second)

        weighted = (
            sequence_score * 0.45
            + token_score * 0.35
            + category_score * 0.08
            + privacy_score * 0.05
            + entity_score * 0.07
        )

        return max(0.0, min(1.0, weighted))

    def _metadata_entity_similarity(
        self,
        first: Dict[str, Any],
        second: Dict[str, Any],
    ) -> float:
        """Compare optional metadata entities/tags/projects/clients."""

        first_meta = first.get("metadata") or {}
        second_meta = second.get("metadata") or {}

        keys = ["tags", "entities", "project_id", "client_id", "source", "agent"]
        scores: List[float] = []

        for key in keys:
            a = first_meta.get(key) or first.get(key)
            b = second_meta.get(key) or second.get(key)

            if a is None or b is None:
                continue

            if isinstance(a, list) or isinstance(b, list):
                a_set = {str(x).lower() for x in self._as_list(a)}
                b_set = {str(x).lower() for x in self._as_list(b)}
                if a_set or b_set:
                    scores.append(len(a_set & b_set) / max(1, len(a_set | b_set)))
            else:
                scores.append(1.0 if str(a).lower() == str(b).lower() else 0.0)

        if not scores:
            return 0.0

        return sum(scores) / len(scores)

    def _select_canonical(
        self,
        first: Dict[str, Any],
        second: Dict[str, Any],
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Select canonical memory record and secondary record.

        Higher importance wins, then most recent update, then longer content.
        """

        first_rank = self._canonical_rank(first)
        second_rank = self._canonical_rank(second)

        if first_rank >= second_rank:
            return first, second

        return second, first

    def _canonical_rank(self, record: Dict[str, Any]) -> Tuple[float, float, int]:
        """Ranking tuple for canonical memory selection."""

        importance = self._safe_float(record.get("importance"), default=0.0)
        updated_ts = self._datetime_score(record.get("updated_at") or record.get("created_at"))
        content_length = len(str(record.get("content") or record.get("text") or ""))

        return importance, updated_ts, content_length

    def _build_merged_memory(
        self,
        *,
        canonical: Dict[str, Any],
        source: Dict[str, Any],
        user_id: str,
        workspace_id: str,
        similarity: float,
    ) -> Dict[str, Any]:
        """
        Build merged canonical memory from source and canonical records.
        """

        merged = copy.deepcopy(canonical)
        canonical_content = self._normalize_text(merged.get("content", ""))
        source_content = self._normalize_text(source.get("content", ""))

        if source_content and source_content.lower() not in canonical_content.lower():
            merged["content"] = f"{canonical_content}\n\nAdditional context: {source_content}".strip()
        else:
            merged["content"] = canonical_content

        merged["user_id"] = user_id
        merged["workspace_id"] = workspace_id
        merged["status"] = MemoryStatus.ACTIVE.value
        merged["importance"] = max(
            self._safe_float(canonical.get("importance"), 0.0),
            self._safe_float(source.get("importance"), 0.0),
        )
        merged["updated_at"] = self._now_iso()
        merged.setdefault("metadata", {})

        merged_sources = set(self._as_list(merged["metadata"].get("merged_source_ids")))
        merged_sources.add(self._memory_id(source))
        merged["metadata"]["merged_source_ids"] = sorted(merged_sources)
        merged["metadata"]["last_merge_similarity"] = round(similarity, 4)
        merged["metadata"]["last_merged_at"] = self._now_iso()

        return merged

    def _should_mark_outdated(
        self,
        record: Dict[str, Any],
        *,
        reference_time: datetime,
    ) -> Tuple[bool, str, float]:
        """
        Decide if a memory should be marked outdated.

        Conservative behavior:
            - High-importance memories are not automatically outdated.
            - Project rules/preferences are not automatically outdated.
            - Records with explicit expires_at are outdated after expiration.
        """

        metadata = record.get("metadata") or {}
        status = str(record.get("status", MemoryStatus.ACTIVE.value)).lower()

        if status != MemoryStatus.ACTIVE.value:
            return False, "Memory is not active.", 0.0

        expires_at = metadata.get("expires_at") or record.get("expires_at")
        if expires_at:
            parsed_expiry = self._parse_datetime(expires_at)
            if parsed_expiry and parsed_expiry <= reference_time:
                return True, "Memory has passed explicit expiration date.", 0.98

        category = str(record.get("category", "")).lower()
        importance = self._safe_float(record.get("importance"), default=0.0)

        protected_categories = {
            "preference",
            "preferences",
            "project_rule",
            "system_rule",
            "client_rule",
            "security",
            "privacy",
        }

        if category in protected_categories:
            return False, "Protected category is not auto-marked outdated.", 0.0

        if importance >= 0.75:
            return False, "High-importance memory is not auto-marked outdated.", 0.0

        timestamp = (
            record.get("last_used_at")
            or record.get("updated_at")
            or record.get("created_at")
        )
        parsed = self._parse_datetime(timestamp)

        if not parsed:
            return False, "No reliable timestamp available.", 0.0

        age_days = (reference_time - parsed).days

        if age_days >= self.config.outdated_days_threshold:
            confidence = min(0.95, 0.55 + (age_days / max(1, self.config.outdated_days_threshold)) * 0.2)
            return (
                True,
                f"Memory is stale: {age_days} days since last update/use.",
                round(confidence, 4),
            )

        return False, "Memory is not older than outdated threshold.", 0.0

    def _is_noisy_memory(self, record: Dict[str, Any]) -> Tuple[bool, List[str], float]:
        """
        Detect whether a memory is noisy.

        Returns:
            (is_noisy, issues, quality_score)
        """

        content = str(record.get("content") or record.get("text") or "").strip()
        issues: List[str] = []
        score = 1.0

        if len(content) == 0:
            issues.append("Empty content.")
            score -= 0.7

        if 0 < len(content) < self.config.noisy_min_content_length:
            issues.append("Content is too short to be useful.")
            score -= 0.35

        if self._symbol_ratio(content) > self.config.noisy_max_symbol_ratio:
            issues.append("Content has too many symbols or corrupted characters.")
            score -= 0.35

        if self._looks_like_placeholder(content):
            issues.append("Content looks like placeholder or test text.")
            score -= 0.45

        if self._looks_like_stack_trace(content):
            issues.append("Content looks like raw error/stack trace noise.")
            score -= 0.25

        if self._repetition_ratio(content) > 0.65:
            issues.append("Content is highly repetitive.")
            score -= 0.3

        category = str(record.get("category", "")).lower()
        importance = self._safe_float(record.get("importance"), default=0.0)

        if category in {"preference", "project_rule", "client_rule"}:
            score += 0.15

        if importance >= 0.7:
            score += 0.15

        score = max(0.0, min(1.0, score))

        is_noisy = score < 0.45 and importance < 0.8

        return is_noisy, issues, round(score, 4)

    def _is_terminal_status(self, record: Dict[str, Any]) -> bool:
        """Return True for statuses that should not be cleaned again."""

        return str(record.get("status", "")).lower() in {
            MemoryStatus.DUPLICATE.value,
            MemoryStatus.MERGED.value,
            MemoryStatus.ARCHIVED.value,
        }

    def _match_text(self, record: Dict[str, Any]) -> str:
        """Return normalized matching text for similarity checks."""

        parts = [
            str(record.get("content") or record.get("text") or ""),
            str(record.get("title") or ""),
            str(record.get("summary") or ""),
        ]

        text = " ".join(p for p in parts if p)
        text = self._normalize_text(text)

        if self.config.normalize_case_for_matching:
            text = text.lower()

        return text

    def _normalize_text(self, text: Any) -> str:
        """Normalize text safely."""

        value = str(text or "")
        value = value.replace("\x00", " ")
        value = re.sub(r"\s+", " ", value).strip()
        return value

    def _token_jaccard(self, first: str, second: str) -> float:
        """Jaccard token similarity."""

        a = self._tokens(first)
        b = self._tokens(second)

        if not a or not b:
            return 0.0

        return len(a & b) / max(1, len(a | b))

    def _tokens(self, text: str) -> set[str]:
        """Extract normalized tokens."""

        return {
            token
            for token in re.findall(r"[a-zA-Z0-9_@.#-]+", text.lower())
            if len(token) > 1
        }

    def _symbol_ratio(self, text: str) -> float:
        """Return ratio of non-alphanumeric non-space characters."""

        if not text:
            return 0.0

        symbols = sum(1 for char in text if not char.isalnum() and not char.isspace())
        return symbols / max(1, len(text))

    def _looks_like_placeholder(self, text: str) -> bool:
        """Detect placeholder/test content."""

        lowered = text.strip().lower()

        placeholders = {
            "test",
            "testing",
            "todo",
            "lorem ipsum",
            "sample",
            "dummy",
            "placeholder",
            "n/a",
            "na",
            "none",
            "null",
            "undefined",
        }

        if lowered in placeholders:
            return True

        return any(phrase in lowered for phrase in ["lorem ipsum", "add your logic here"])

    def _looks_like_stack_trace(self, text: str) -> bool:
        """Detect raw traceback/error noise."""

        lowered = text.lower()
        signals = [
            "traceback (most recent call last)",
            "nullpointerexception",
            "syntaxerror:",
            "typeerror:",
            "referenceerror:",
            "stack trace",
        ]
        return any(signal in lowered for signal in signals)

    def _repetition_ratio(self, text: str) -> float:
        """Estimate repetitive token ratio."""

        tokens = list(self._tokens(text))
        if not tokens:
            return 0.0

        raw_words = re.findall(r"[a-zA-Z0-9_@.#-]+", text.lower())
        if not raw_words:
            return 0.0

        unique_count = len(set(raw_words))
        total_count = len(raw_words)

        return 1.0 - (unique_count / max(1, total_count))

    def _memory_id(self, record: Dict[str, Any]) -> str:
        """Return stable memory id or generate a deterministic fallback."""

        existing = record.get("id") or record.get("memory_id")
        if existing:
            return str(existing)

        raw = "|".join(
            [
                str(record.get("user_id", "")),
                str(record.get("workspace_id", "")),
                str(record.get("category", "")),
                str(record.get("content", "")),
            ]
        )
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
        return f"memory-{digest}"

    def _datetime_score(self, value: Any) -> float:
        """Convert datetime-like value to comparable timestamp."""

        parsed = self._parse_datetime(value)
        if not parsed:
            return 0.0

        return parsed.timestamp()

    def _parse_datetime(self, value: Any) -> Optional[datetime]:
        """Parse common datetime values safely."""

        if value is None:
            return None

        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)

        if isinstance(value, (int, float)):
            try:
                return datetime.fromtimestamp(float(value), tz=timezone.utc)
            except Exception:
                return None

        text = str(value).strip()
        if not text:
            return None

        try:
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            parsed = datetime.fromisoformat(text)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except Exception:
            return None

    def _safe_float(self, value: Any, default: float = 0.0) -> float:
        """Convert value to float safely."""

        try:
            if value is None:
                return default
            number = float(value)
            if math.isnan(number) or math.isinf(number):
                return default
            return number
        except Exception:
            return default

    def _as_list(self, value: Any) -> List[Any]:
        """Normalize value to list."""

        if value is None:
            return []

        if isinstance(value, list):
            return value

        if isinstance(value, tuple):
            return list(value)

        if isinstance(value, set):
            return list(value)

        return [value]

    def _candidate_objects(
        self,
        candidates: Sequence[Union[CleanupCandidate, Dict[str, Any]]],
    ) -> List[CleanupCandidate]:
        """Convert dict candidates to CleanupCandidate objects."""

        output: List[CleanupCandidate] = []

        for candidate in candidates:
            if isinstance(candidate, CleanupCandidate):
                output.append(candidate)
            elif isinstance(candidate, dict):
                output.append(
                    CleanupCandidate(
                        action=str(candidate.get("action", "")),
                        source_memory_id=candidate.get("source_memory_id"),
                        target_memory_id=candidate.get("target_memory_id"),
                        reason=str(candidate.get("reason", "")),
                        confidence=self._safe_float(candidate.get("confidence"), 0.0),
                        before=candidate.get("before") or {},
                        after=candidate.get("after") or {},
                        metadata=candidate.get("metadata") or {},
                    )
                )

        return output

    def _quality_report_objects(
        self,
        reports: Sequence[Union[MemoryQualityReport, Dict[str, Any]]],
    ) -> List[MemoryQualityReport]:
        """Convert dict reports to MemoryQualityReport objects."""

        output: List[MemoryQualityReport] = []

        for report in reports:
            if isinstance(report, MemoryQualityReport):
                output.append(report)
            elif isinstance(report, dict):
                output.append(
                    MemoryQualityReport(
                        memory_id=str(report.get("memory_id", "")),
                        score=self._safe_float(report.get("score"), 0.0),
                        is_noisy=bool(report.get("is_noisy")),
                        is_potentially_outdated=bool(
                            report.get("is_potentially_outdated")
                        ),
                        issues=list(report.get("issues") or []),
                        recommendations=list(report.get("recommendations") or []),
                        metadata=report.get("metadata") or {},
                    )
                )

        return output

    def _count_by_key(self, records: Sequence[Dict[str, Any]], key: str) -> Dict[str, int]:
        """Count values by key."""

        counts: Dict[str, int] = {}

        for record in records:
            value = str(record.get(key, "unknown"))
            counts[value] = counts.get(value, 0) + 1

        return counts

    def _new_id(self, prefix: str) -> str:
        """Generate safe unique id."""

        return f"{prefix}-{uuid.uuid4().hex[:16]}"

    def _now_iso(self) -> str:
        """Current UTC timestamp."""

        return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------
# Convenience function for simple integrations/tests
# ---------------------------------------------------------------------

def clean_memories(
    memories: Sequence[Dict[str, Any]],
    *,
    user_id: str,
    workspace_id: str,
    actions: Optional[Sequence[Union[str, CleanupAction]]] = None,
    dry_run: bool = True,
) -> Dict[str, Any]:
    """
    Convenience wrapper for simple usage without manually instantiating class.

    Example:
        result = clean_memories(memories, user_id="u1", workspace_id="w1")
    """

    cleaner = MemoryCleaner()
    return cleaner.clean_memories(
        memories=memories,
        user_id=user_id,
        workspace_id=workspace_id,
        actions=actions,
        dry_run=dry_run,
    )


__all__ = [
    "CleanupAction",
    "MemoryStatus",
    "MemoryPrivacyLevel",
    "MemoryCleanerConfig",
    "CleanupCandidate",
    "MemoryQualityReport",
    "MemoryCleaner",
    "clean_memories",
]