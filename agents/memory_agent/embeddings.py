"""
agents/memory_agent/embeddings.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Memory Agent - Embedding Engine

Purpose:
    Chunking, embedding creation, vector storage, and semantic search.

This file is designed to be:
    - Production-ready
    - Import-safe
    - SaaS-isolated by user_id and workspace_id
    - Compatible with BaseAgent, MasterAgent routing, Agent Registry, Agent Loader,
      Security Agent, Verification Agent, Memory Agent, Dashboard/API, and future
      vector database backends.

Core responsibilities:
    1. Validate user/workspace task context.
    2. Chunk large text safely.
    3. Generate deterministic local embeddings by default.
    4. Optionally support external embedding providers through adapter injection.
    5. Store vectors in an import-safe local JSON vector store.
    6. Search vectors semantically using cosine similarity.
    7. Prepare structured memory, verification, audit, and event payloads.

Important:
    This file does not hardcode secrets.
    This file does not perform destructive actions.
    This file is safe to import even if other William modules do not exist yet.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Protocol, Tuple, Union


# ======================================================================================
# Optional / Safe BaseAgent Import
# ======================================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Safe fallback BaseAgent stub.

        This keeps the file import-safe before the full William/Jarvis system is created.
        The real BaseAgent should provide richer lifecycle, registry, routing, audit,
        and permission behavior.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())


# ======================================================================================
# Logging
# ======================================================================================

LOGGER = logging.getLogger("william.memory_agent.embeddings")
if not LOGGER.handlers:
    LOGGER.addHandler(logging.NullHandler())


# ======================================================================================
# Protocols / Interfaces
# ======================================================================================

class EmbeddingProvider(Protocol):
    """
    External embedding provider protocol.

    Future adapters can implement this protocol for OpenAI, local sentence-transformers,
    Ollama, Hugging Face, custom GPU services, or private embedding APIs.
    """

    def embed_texts(
        self,
        texts: List[str],
        *,
        user_id: str,
        workspace_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> List[List[float]]:
        """
        Convert a list of text strings into embedding vectors.
        """
        ...


class EventEmitter(Protocol):
    """
    Optional event emitter protocol for dashboard/API/agent registry integration.
    """

    def emit(self, event_name: str, payload: Dict[str, Any]) -> None:
        ...


class AuditLogger(Protocol):
    """
    Optional audit logger protocol.
    """

    def log(self, payload: Dict[str, Any]) -> None:
        ...


# ======================================================================================
# Data Structures
# ======================================================================================

@dataclass
class EmbeddingConfig:
    """
    Configuration for chunking, embedding, vector storage, and search.

    The default embedding mode is deterministic_hash, which is:
        - offline
        - dependency-free
        - deterministic
        - import-safe
        - useful for tests and early system development

    In production, inject a real EmbeddingProvider for higher semantic quality.
    """

    vector_dimension: int = 384
    chunk_size: int = 1200
    chunk_overlap: int = 150
    min_chunk_chars: int = 30
    max_text_chars: int = 2_000_000
    store_dir: str = "data/memory_vectors"
    store_filename: str = "vectors.json"
    default_top_k: int = 10
    max_top_k: int = 50
    similarity_threshold: float = 0.0
    normalize_embeddings: bool = True
    embedding_mode: str = "deterministic_hash"
    allow_external_provider: bool = True
    audit_enabled: bool = True
    events_enabled: bool = True
    verification_enabled: bool = True
    memory_payload_enabled: bool = True


@dataclass
class ChunkRecord:
    """
    Represents a text chunk before embedding storage.
    """

    chunk_id: str
    source_id: str
    user_id: str
    workspace_id: str
    text: str
    chunk_index: int
    start_char: int
    end_char: int
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)


@dataclass
class VectorRecord:
    """
    Represents one vectorized memory chunk.
    """

    vector_id: str
    chunk_id: str
    source_id: str
    user_id: str
    workspace_id: str
    text: str
    embedding: List[float]
    chunk_index: int
    start_char: int
    end_char: int
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)


@dataclass
class SearchResult:
    """
    Represents one semantic search match.
    """

    vector_id: str
    chunk_id: str
    source_id: str
    user_id: str
    workspace_id: str
    text: str
    score: float
    chunk_index: int
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: Optional[float] = None


# ======================================================================================
# Utility Helpers
# ======================================================================================

def _now() -> float:
    return time.time()


def _safe_uuid(prefix: str = "id") -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def _ensure_dict(value: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _clean_text(text: str) -> str:
    """
    Basic text normalization for memory chunking.

    This avoids destroying meaning while removing excessive whitespace.
    """
    if not isinstance(text, str):
        text = str(text)

    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _safe_float_list(vector: Iterable[Any]) -> List[float]:
    output: List[float] = []
    for item in vector:
        try:
            value = float(item)
            if math.isfinite(value):
                output.append(value)
            else:
                output.append(0.0)
        except Exception:
            output.append(0.0)
    return output


def _l2_normalize(vector: List[float]) -> List[float]:
    norm = math.sqrt(sum(v * v for v in vector))
    if norm <= 0:
        return vector
    return [v / norm for v in vector]


def _cosine_similarity(left: List[float], right: List[float]) -> float:
    if not left or not right:
        return 0.0

    size = min(len(left), len(right))
    if size <= 0:
        return 0.0

    dot = sum(left[i] * right[i] for i in range(size))
    left_norm = math.sqrt(sum(left[i] * left[i] for i in range(size)))
    right_norm = math.sqrt(sum(right[i] * right[i] for i in range(size)))

    if left_norm <= 0 or right_norm <= 0:
        return 0.0

    return dot / (left_norm * right_norm)


# ======================================================================================
# Local JSON Vector Store
# ======================================================================================

class LocalJSONVectorStore:
    """
    Small dependency-free vector store.

    This is intentionally simple and import-safe. It is suitable for:
        - local development
        - tests
        - early dashboard integration
        - fallback mode when a production vector DB is unavailable

    Production upgrade path:
        Replace this class with a Qdrant, Chroma, Weaviate, pgvector, Pinecone,
        Milvus, Redis Vector, or Elasticsearch adapter while keeping the same
        public behavior in EmbeddingEngine.
    """

    def __init__(self, store_path: Union[str, Path]) -> None:
        self.store_path = Path(store_path)
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

        if not self.store_path.exists():
            self._write_raw({"vectors": []})

    def _read_raw(self) -> Dict[str, Any]:
        with self._lock:
            try:
                if not self.store_path.exists():
                    return {"vectors": []}

                with self.store_path.open("r", encoding="utf-8") as file:
                    data = json.load(file)

                if not isinstance(data, dict):
                    return {"vectors": []}

                vectors = data.get("vectors", [])
                if not isinstance(vectors, list):
                    data["vectors"] = []

                return data

            except json.JSONDecodeError:
                backup_path = self.store_path.with_suffix(
                    f".corrupt.{int(time.time())}.json"
                )
                try:
                    self.store_path.rename(backup_path)
                except Exception:
                    pass

                clean = {"vectors": []}
                self._write_raw(clean)
                return clean

            except Exception:
                LOGGER.exception("Failed reading local vector store.")
                return {"vectors": []}

    def _write_raw(self, data: Dict[str, Any]) -> None:
        with self._lock:
            temp_path = self.store_path.with_suffix(".tmp")
            with temp_path.open("w", encoding="utf-8") as file:
                json.dump(data, file, ensure_ascii=False, indent=2)
            temp_path.replace(self.store_path)

    def list_vectors(
        self,
        *,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        source_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        data = self._read_raw()
        vectors = data.get("vectors", [])

        output: List[Dict[str, Any]] = []
        for item in vectors:
            if not isinstance(item, dict):
                continue

            if user_id is not None and item.get("user_id") != user_id:
                continue

            if workspace_id is not None and item.get("workspace_id") != workspace_id:
                continue

            if source_id is not None and item.get("source_id") != source_id:
                continue

            output.append(item)

        return output

    def upsert_vectors(self, records: List[VectorRecord]) -> int:
        if not records:
            return 0

        with self._lock:
            data = self._read_raw()
            vectors = data.get("vectors", [])
            if not isinstance(vectors, list):
                vectors = []

            existing_by_id: Dict[str, Dict[str, Any]] = {}
            for item in vectors:
                if isinstance(item, dict) and item.get("vector_id"):
                    existing_by_id[str(item["vector_id"])] = item

            changed = 0
            for record in records:
                payload = asdict(record)
                vector_id = record.vector_id

                if vector_id in existing_by_id:
                    existing_by_id[vector_id].update(payload)
                else:
                    existing_by_id[vector_id] = payload

                changed += 1

            data["vectors"] = list(existing_by_id.values())
            data["updated_at"] = _now()
            self._write_raw(data)

            return changed

    def delete_vectors(
        self,
        *,
        user_id: str,
        workspace_id: str,
        source_id: Optional[str] = None,
        vector_ids: Optional[List[str]] = None,
    ) -> int:
        """
        Deletes vectors only inside the exact SaaS user/workspace boundary.
        """

        with self._lock:
            data = self._read_raw()
            vectors = data.get("vectors", [])
            if not isinstance(vectors, list):
                vectors = []

            vector_id_set = set(vector_ids or [])
            kept: List[Dict[str, Any]] = []
            deleted = 0

            for item in vectors:
                if not isinstance(item, dict):
                    continue

                same_scope = (
                    item.get("user_id") == user_id
                    and item.get("workspace_id") == workspace_id
                )

                if not same_scope:
                    kept.append(item)
                    continue

                should_delete = False

                if source_id is not None and item.get("source_id") == source_id:
                    should_delete = True

                if vector_id_set and item.get("vector_id") in vector_id_set:
                    should_delete = True

                if source_id is None and not vector_id_set:
                    should_delete = True

                if should_delete:
                    deleted += 1
                else:
                    kept.append(item)

            data["vectors"] = kept
            data["updated_at"] = _now()
            self._write_raw(data)

            return deleted


# ======================================================================================
# Embedding Engine
# ======================================================================================

class EmbeddingEngine(BaseAgent):
    """
    Memory Agent embedding engine.

    Connects to:
        - Master Agent:
            Can be called as a routed helper for memory indexing and semantic recall.

        - Security Agent:
            Uses _requires_security_check and _request_security_approval hooks for
            sensitive memory operations.

        - Memory Agent:
            Prepares _prepare_memory_payload outputs after indexing/searching.

        - Verification Agent:
            Prepares _prepare_verification_payload after completed operations.

        - Dashboard/API:
            Public methods return structured JSON/dict style results.

        - Agent Registry / Agent Loader / Agent Router:
            Safe class name and import-safe fallback behavior allow dynamic loading.
    """

    def __init__(
        self,
        config: Optional[EmbeddingConfig] = None,
        embedding_provider: Optional[EmbeddingProvider] = None,
        event_emitter: Optional[EventEmitter] = None,
        audit_logger: Optional[AuditLogger] = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            agent_name=kwargs.get("agent_name", "EmbeddingEngine"),
            agent_id=kwargs.get("agent_id", "memory_embedding_engine"),
        )

        self.config = config or EmbeddingConfig()
        self.embedding_provider = embedding_provider
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger
        self.logger = logger or LOGGER

        store_path = Path(self.config.store_dir) / self.config.store_filename
        self.vector_store = LocalJSONVectorStore(store_path)

    # ----------------------------------------------------------------------------------
    # Required Compatibility Hooks
    # ----------------------------------------------------------------------------------

    def _safe_result(
        self,
        *,
        success: bool = True,
        message: str = "Operation completed successfully.",
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Union[str, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "success": bool(success),
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        *,
        message: str = "Operation failed.",
        error: Optional[Union[str, Dict[str, Any], Exception]] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if isinstance(error, Exception):
            error_payload: Union[str, Dict[str, Any]] = {
                "type": error.__class__.__name__,
                "detail": str(error),
            }
        elif error is None:
            error_payload = message
        else:
            error_payload = error

        return self._safe_result(
            success=False,
            message=message,
            data=data or {},
            error=error_payload,
            metadata=metadata or {},
        )

    def _validate_task_context(
        self,
        *,
        user_id: Optional[str],
        workspace_id: Optional[str],
        task_id: Optional[str] = None,
        strict: bool = True,
    ) -> Dict[str, Any]:
        """
        Enforces SaaS isolation requirements.

        Every user-specific memory operation must have user_id and workspace_id.
        """
        errors: List[str] = []

        if not user_id or not isinstance(user_id, str) or not user_id.strip():
            errors.append("Missing or invalid user_id.")

        if not workspace_id or not isinstance(workspace_id, str) or not workspace_id.strip():
            errors.append("Missing or invalid workspace_id.")

        if task_id is not None and not isinstance(task_id, str):
            errors.append("task_id must be a string when provided.")

        is_valid = len(errors) == 0

        if strict and not is_valid:
            return self._error_result(
                message="Invalid task context.",
                error={"errors": errors},
                metadata={
                    "hook": "_validate_task_context",
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "task_id": task_id,
                },
            )

        return self._safe_result(
            message="Task context validated.",
            data={
                "valid": is_valid,
                "errors": errors,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "task_id": task_id,
            },
            metadata={"hook": "_validate_task_context"},
        )

    def _requires_security_check(
        self,
        *,
        operation: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Determines whether the operation requires Security Agent approval.

        Embedding and search are generally safe.
        Delete operations and bulk indexing of sensitive categories can require approval.
        """
        metadata = _ensure_dict(metadata)
        sensitive = bool(metadata.get("sensitive", False))
        operation = operation.lower().strip()

        sensitive_operations = {
            "delete_vectors",
            "bulk_delete",
            "purge_workspace_memory",
            "index_sensitive_memory",
        }

        return sensitive or operation in sensitive_operations

    def _request_security_approval(
        self,
        *,
        operation: str,
        user_id: str,
        workspace_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Security Agent integration hook.

        This file does not directly call an external Security Agent because future files
        may not exist yet. The default behavior is safe and structured.

        Production integration:
            Replace or override this hook to call Security Agent permission checks.
        """
        metadata = _ensure_dict(metadata)

        if not self._requires_security_check(operation=operation, metadata=metadata):
            return self._safe_result(
                message="Security approval not required.",
                data={"approved": True, "required": False},
                metadata={
                    "operation": operation,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "hook": "_request_security_approval",
                },
            )

        approved = bool(metadata.get("security_approved", False))

        if not approved:
            return self._error_result(
                message="Security approval required before this memory operation.",
                error={
                    "operation": operation,
                    "required": True,
                    "approved": False,
                    "reason": "Operation marked sensitive or destructive.",
                },
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "hook": "_request_security_approval",
                },
            )

        return self._safe_result(
            message="Security approval granted.",
            data={"approved": True, "required": True},
            metadata={
                "operation": operation,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "hook": "_request_security_approval",
            },
        )

    def _prepare_verification_payload(
        self,
        *,
        operation: str,
        user_id: str,
        workspace_id: str,
        success: bool,
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Payload prepared for Verification Agent.

        Verification Agent can use this to verify memory indexing/search/delete results.
        """
        return {
            "agent": "EmbeddingEngine",
            "module": "Memory Agent",
            "operation": operation,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "success": success,
            "data": data or {},
            "error": error,
            "metadata": metadata or {},
            "created_at": _now(),
        }

    def _prepare_memory_payload(
        self,
        *,
        operation: str,
        user_id: str,
        workspace_id: str,
        content: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Payload prepared for Memory Agent.

        This lets the broader Memory Agent store useful context about indexing/search
        operations without mixing tenant data.
        """
        return {
            "agent": "EmbeddingEngine",
            "module": "Memory Agent",
            "operation": operation,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "content": content,
            "data": data or {},
            "metadata": metadata or {},
            "created_at": _now(),
        }

    def _emit_agent_event(
        self,
        *,
        event_name: str,
        payload: Dict[str, Any],
    ) -> None:
        """
        Emits events for dashboard/API/registry listeners.

        Safe fallback: logs only if no event emitter is injected.
        """
        if not self.config.events_enabled:
            return

        try:
            if self.event_emitter is not None:
                self.event_emitter.emit(event_name, payload)
            else:
                self.logger.debug("Agent event emitted: %s | %s", event_name, payload)
        except Exception:
            self.logger.exception("Failed emitting agent event: %s", event_name)

    def _log_audit_event(
        self,
        *,
        operation: str,
        user_id: str,
        workspace_id: str,
        status: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Logs audit events in a safe structured format.

        This should be connected to the final SaaS audit log service later.
        """
        if not self.config.audit_enabled:
            return

        payload = {
            "agent": "EmbeddingEngine",
            "module": "Memory Agent",
            "operation": operation,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "status": status,
            "metadata": metadata or {},
            "created_at": _now(),
        }

        try:
            if self.audit_logger is not None:
                self.audit_logger.log(payload)
            else:
                self.logger.info("Audit event: %s", payload)
        except Exception:
            self.logger.exception("Failed writing audit event.")

    # ----------------------------------------------------------------------------------
    # Public Methods
    # ----------------------------------------------------------------------------------

    def chunk_text(
        self,
        text: str,
        *,
        user_id: str,
        workspace_id: str,
        source_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Splits text into overlapping chunks.

        Public API/dashboard friendly structured result.
        """

        context = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
        )
        if not context["success"]:
            return context

        try:
            metadata = _ensure_dict(metadata)
            cleaned = _clean_text(text)

            if not cleaned:
                return self._error_result(
                    message="Cannot chunk empty text.",
                    error="Text is empty after cleaning.",
                    metadata={"operation": "chunk_text"},
                )

            if len(cleaned) > self.config.max_text_chars:
                return self._error_result(
                    message="Text exceeds maximum allowed size.",
                    error={
                        "max_text_chars": self.config.max_text_chars,
                        "received_chars": len(cleaned),
                    },
                    metadata={"operation": "chunk_text"},
                )

            source_id = source_id or f"src_{_sha256_text(cleaned)[:16]}"
            chunks = self._create_chunks(
                cleaned,
                user_id=user_id,
                workspace_id=workspace_id,
                source_id=source_id,
                metadata=metadata,
            )

            payload = {
                "source_id": source_id,
                "chunks": [asdict(chunk) for chunk in chunks],
                "chunk_count": len(chunks),
            }

            self._emit_agent_event(
                event_name="memory.embedding.chunked",
                payload={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "source_id": source_id,
                    "chunk_count": len(chunks),
                },
            )

            self._log_audit_event(
                operation="chunk_text",
                user_id=user_id,
                workspace_id=workspace_id,
                status="success",
                metadata={"source_id": source_id, "chunk_count": len(chunks)},
            )

            return self._safe_result(
                message="Text chunked successfully.",
                data=payload,
                metadata={
                    "operation": "chunk_text",
                    "verification_payload": self._prepare_verification_payload(
                        operation="chunk_text",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        success=True,
                        data={
                            "source_id": source_id,
                            "chunk_count": len(chunks),
                        },
                    ),
                },
            )

        except Exception as exc:
            self.logger.exception("chunk_text failed.")
            self._log_audit_event(
                operation="chunk_text",
                user_id=user_id,
                workspace_id=workspace_id,
                status="failed",
                metadata={"error": str(exc)},
            )
            return self._error_result(
                message="Failed to chunk text.",
                error=exc,
                metadata={"operation": "chunk_text"},
            )

    def embed_texts(
        self,
        texts: List[str],
        *,
        user_id: str,
        workspace_id: str,
        metadata: Optional[Dict[str, Any]] = None,
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Embeds raw text list without storing it.

        Useful for:
            - search query embedding
            - tests
            - API preview
            - future recall engine integration
        """

        context = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
        )
        if not context["success"]:
            return context

        try:
            metadata = _ensure_dict(metadata)

            if not isinstance(texts, list) or not texts:
                return self._error_result(
                    message="texts must be a non-empty list.",
                    error="Invalid texts input.",
                    metadata={"operation": "embed_texts"},
                )

            clean_texts = [_clean_text(item) for item in texts]
            clean_texts = [item for item in clean_texts if item]

            if not clean_texts:
                return self._error_result(
                    message="No valid text found for embedding.",
                    error="All text entries are empty after cleaning.",
                    metadata={"operation": "embed_texts"},
                )

            embeddings = self._embed_texts_internal(
                clean_texts,
                user_id=user_id,
                workspace_id=workspace_id,
                metadata=metadata,
            )

            return self._safe_result(
                message="Embeddings created successfully.",
                data={
                    "embeddings": embeddings,
                    "count": len(embeddings),
                    "dimension": len(embeddings[0]) if embeddings else 0,
                    "embedding_mode": self._active_embedding_mode(),
                },
                metadata={
                    "operation": "embed_texts",
                    "verification_payload": self._prepare_verification_payload(
                        operation="embed_texts",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        success=True,
                        data={
                            "count": len(embeddings),
                            "dimension": len(embeddings[0]) if embeddings else 0,
                        },
                    ),
                },
            )

        except Exception as exc:
            self.logger.exception("embed_texts failed.")
            return self._error_result(
                message="Failed to create embeddings.",
                error=exc,
                metadata={"operation": "embed_texts"},
            )

    def index_text(
        self,
        text: str,
        *,
        user_id: str,
        workspace_id: str,
        source_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        replace_existing_source: bool = False,
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Chunks, embeds, and stores text vectors inside a user/workspace boundary.

        This is the main method Memory Agent / Master Agent should call when storing
        semantic memory.
        """

        context = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
        )
        if not context["success"]:
            return context

        metadata = _ensure_dict(metadata)

        security = self._request_security_approval(
            operation="index_sensitive_memory" if metadata.get("sensitive") else "index_text",
            user_id=user_id,
            workspace_id=workspace_id,
            metadata=metadata,
        )
        if not security["success"]:
            return security

        try:
            chunk_result = self.chunk_text(
                text,
                user_id=user_id,
                workspace_id=workspace_id,
                source_id=source_id,
                metadata=metadata,
                task_id=task_id,
            )
            if not chunk_result["success"]:
                return chunk_result

            chunk_payload = chunk_result["data"]
            chunk_dicts = chunk_payload.get("chunks", [])
            source_id = chunk_payload.get("source_id")

            chunks = [
                ChunkRecord(
                    chunk_id=item["chunk_id"],
                    source_id=item["source_id"],
                    user_id=item["user_id"],
                    workspace_id=item["workspace_id"],
                    text=item["text"],
                    chunk_index=int(item["chunk_index"]),
                    start_char=int(item["start_char"]),
                    end_char=int(item["end_char"]),
                    metadata=item.get("metadata", {}),
                    created_at=float(item.get("created_at", _now())),
                )
                for item in chunk_dicts
                if isinstance(item, dict)
            ]

            if replace_existing_source and source_id:
                self.vector_store.delete_vectors(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    source_id=source_id,
                )

            embeddings = self._embed_texts_internal(
                [chunk.text for chunk in chunks],
                user_id=user_id,
                workspace_id=workspace_id,
                metadata=metadata,
            )

            records: List[VectorRecord] = []
            for chunk, embedding in zip(chunks, embeddings):
                vector_id = self._make_vector_id(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    source_id=chunk.source_id,
                    chunk_id=chunk.chunk_id,
                    text=chunk.text,
                )

                records.append(
                    VectorRecord(
                        vector_id=vector_id,
                        chunk_id=chunk.chunk_id,
                        source_id=chunk.source_id,
                        user_id=user_id,
                        workspace_id=workspace_id,
                        text=chunk.text,
                        embedding=embedding,
                        chunk_index=chunk.chunk_index,
                        start_char=chunk.start_char,
                        end_char=chunk.end_char,
                        metadata=chunk.metadata,
                        created_at=chunk.created_at,
                        updated_at=_now(),
                    )
                )

            stored_count = self.vector_store.upsert_vectors(records)

            result_data = {
                "source_id": source_id,
                "stored_count": stored_count,
                "chunk_count": len(chunks),
                "vector_ids": [record.vector_id for record in records],
                "embedding_mode": self._active_embedding_mode(),
                "dimension": len(records[0].embedding) if records else 0,
            }

            self._emit_agent_event(
                event_name="memory.embedding.indexed",
                payload={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "source_id": source_id,
                    "stored_count": stored_count,
                    "chunk_count": len(chunks),
                },
            )

            self._log_audit_event(
                operation="index_text",
                user_id=user_id,
                workspace_id=workspace_id,
                status="success",
                metadata=result_data,
            )

            return self._safe_result(
                message="Text indexed successfully.",
                data=result_data,
                metadata={
                    "operation": "index_text",
                    "memory_payload": self._prepare_memory_payload(
                        operation="index_text",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        content=f"Indexed semantic memory source {source_id}.",
                        data=result_data,
                        metadata=metadata,
                    ),
                    "verification_payload": self._prepare_verification_payload(
                        operation="index_text",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        success=True,
                        data=result_data,
                        metadata=metadata,
                    ),
                },
            )

        except Exception as exc:
            self.logger.exception("index_text failed.")
            self._log_audit_event(
                operation="index_text",
                user_id=user_id,
                workspace_id=workspace_id,
                status="failed",
                metadata={"error": str(exc)},
            )
            return self._error_result(
                message="Failed to index text.",
                error=exc,
                metadata={"operation": "index_text"},
            )

    def semantic_search(
        self,
        query: str,
        *,
        user_id: str,
        workspace_id: str,
        top_k: Optional[int] = None,
        source_id: Optional[str] = None,
        similarity_threshold: Optional[float] = None,
        metadata_filter: Optional[Dict[str, Any]] = None,
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Semantic search scoped to exact user_id and workspace_id.

        No result can leak from another user/workspace.
        """

        context = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
        )
        if not context["success"]:
            return context

        try:
            cleaned_query = _clean_text(query)
            if not cleaned_query:
                return self._error_result(
                    message="Search query cannot be empty.",
                    error="Empty query.",
                    metadata={"operation": "semantic_search"},
                )

            top_k = int(top_k or self.config.default_top_k)
            top_k = max(1, min(top_k, self.config.max_top_k))

            threshold = (
                self.config.similarity_threshold
                if similarity_threshold is None
                else float(similarity_threshold)
            )

            query_embedding = self._embed_texts_internal(
                [cleaned_query],
                user_id=user_id,
                workspace_id=workspace_id,
                metadata={"search_query": True},
            )[0]

            candidate_vectors = self.vector_store.list_vectors(
                user_id=user_id,
                workspace_id=workspace_id,
                source_id=source_id,
            )

            filtered_candidates = self._apply_metadata_filter(
                candidate_vectors,
                metadata_filter=metadata_filter,
            )

            results: List[SearchResult] = []
            for item in filtered_candidates:
                embedding = _safe_float_list(item.get("embedding", []))
                score = _cosine_similarity(query_embedding, embedding)

                if score < threshold:
                    continue

                results.append(
                    SearchResult(
                        vector_id=str(item.get("vector_id", "")),
                        chunk_id=str(item.get("chunk_id", "")),
                        source_id=str(item.get("source_id", "")),
                        user_id=str(item.get("user_id", "")),
                        workspace_id=str(item.get("workspace_id", "")),
                        text=str(item.get("text", "")),
                        score=score,
                        chunk_index=int(item.get("chunk_index", 0)),
                        metadata=item.get("metadata", {}) if isinstance(item.get("metadata"), dict) else {},
                        created_at=item.get("created_at"),
                    )
                )

            results.sort(key=lambda item: item.score, reverse=True)
            results = results[:top_k]

            result_data = {
                "query": cleaned_query,
                "results": [asdict(item) for item in results],
                "result_count": len(results),
                "candidate_count": len(candidate_vectors),
                "filtered_candidate_count": len(filtered_candidates),
                "top_k": top_k,
                "similarity_threshold": threshold,
                "source_id": source_id,
            }

            self._emit_agent_event(
                event_name="memory.embedding.searched",
                payload={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "query_hash": _sha256_text(cleaned_query)[:16],
                    "result_count": len(results),
                    "candidate_count": len(candidate_vectors),
                },
            )

            self._log_audit_event(
                operation="semantic_search",
                user_id=user_id,
                workspace_id=workspace_id,
                status="success",
                metadata={
                    "result_count": len(results),
                    "candidate_count": len(candidate_vectors),
                    "source_id": source_id,
                },
            )

            return self._safe_result(
                message="Semantic search completed successfully.",
                data=result_data,
                metadata={
                    "operation": "semantic_search",
                    "memory_payload": self._prepare_memory_payload(
                        operation="semantic_search",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        content=f"Semantic search completed with {len(results)} results.",
                        data={
                            "query_hash": _sha256_text(cleaned_query)[:16],
                            "result_count": len(results),
                        },
                    ),
                    "verification_payload": self._prepare_verification_payload(
                        operation="semantic_search",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        success=True,
                        data={
                            "result_count": len(results),
                            "candidate_count": len(candidate_vectors),
                        },
                    ),
                },
            )

        except Exception as exc:
            self.logger.exception("semantic_search failed.")
            self._log_audit_event(
                operation="semantic_search",
                user_id=user_id,
                workspace_id=workspace_id,
                status="failed",
                metadata={"error": str(exc)},
            )
            return self._error_result(
                message="Semantic search failed.",
                error=exc,
                metadata={"operation": "semantic_search"},
            )

    def list_indexed_sources(
        self,
        *,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Lists indexed sources inside a user/workspace only.
        """

        context = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
        )
        if not context["success"]:
            return context

        try:
            vectors = self.vector_store.list_vectors(
                user_id=user_id,
                workspace_id=workspace_id,
            )

            sources: Dict[str, Dict[str, Any]] = {}
            for item in vectors:
                source_id = str(item.get("source_id", "unknown"))
                if source_id not in sources:
                    sources[source_id] = {
                        "source_id": source_id,
                        "chunk_count": 0,
                        "vector_count": 0,
                        "created_at": item.get("created_at"),
                        "updated_at": item.get("updated_at"),
                        "metadata": item.get("metadata", {}),
                    }

                sources[source_id]["chunk_count"] += 1
                sources[source_id]["vector_count"] += 1

                item_created = item.get("created_at")
                item_updated = item.get("updated_at")

                if item_created and (
                    sources[source_id]["created_at"] is None
                    or item_created < sources[source_id]["created_at"]
                ):
                    sources[source_id]["created_at"] = item_created

                if item_updated and (
                    sources[source_id]["updated_at"] is None
                    or item_updated > sources[source_id]["updated_at"]
                ):
                    sources[source_id]["updated_at"] = item_updated

            data = {
                "sources": list(sources.values()),
                "source_count": len(sources),
                "total_vectors": len(vectors),
            }

            return self._safe_result(
                message="Indexed sources listed successfully.",
                data=data,
                metadata={"operation": "list_indexed_sources"},
            )

        except Exception as exc:
            self.logger.exception("list_indexed_sources failed.")
            return self._error_result(
                message="Failed to list indexed sources.",
                error=exc,
                metadata={"operation": "list_indexed_sources"},
            )

    def delete_vectors(
        self,
        *,
        user_id: str,
        workspace_id: str,
        source_id: Optional[str] = None,
        vector_ids: Optional[List[str]] = None,
        security_approved: bool = False,
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Deletes vectors from exact user/workspace boundary.

        Requires security approval because it is destructive.
        """

        context = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
        )
        if not context["success"]:
            return context

        security = self._request_security_approval(
            operation="delete_vectors",
            user_id=user_id,
            workspace_id=workspace_id,
            metadata={"security_approved": security_approved},
        )
        if not security["success"]:
            return security

        try:
            deleted_count = self.vector_store.delete_vectors(
                user_id=user_id,
                workspace_id=workspace_id,
                source_id=source_id,
                vector_ids=vector_ids,
            )

            data = {
                "deleted_count": deleted_count,
                "source_id": source_id,
                "vector_ids": vector_ids or [],
            }

            self._emit_agent_event(
                event_name="memory.embedding.deleted",
                payload={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "deleted_count": deleted_count,
                    "source_id": source_id,
                },
            )

            self._log_audit_event(
                operation="delete_vectors",
                user_id=user_id,
                workspace_id=workspace_id,
                status="success",
                metadata=data,
            )

            return self._safe_result(
                message="Vectors deleted successfully.",
                data=data,
                metadata={
                    "operation": "delete_vectors",
                    "verification_payload": self._prepare_verification_payload(
                        operation="delete_vectors",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        success=True,
                        data=data,
                    ),
                },
            )

        except Exception as exc:
            self.logger.exception("delete_vectors failed.")
            self._log_audit_event(
                operation="delete_vectors",
                user_id=user_id,
                workspace_id=workspace_id,
                status="failed",
                metadata={"error": str(exc)},
            )
            return self._error_result(
                message="Failed to delete vectors.",
                error=exc,
                metadata={"operation": "delete_vectors"},
            )

    def get_stats(
        self,
        *,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Returns vector memory stats for one SaaS user/workspace.
        """

        context = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
        )
        if not context["success"]:
            return context

        try:
            vectors = self.vector_store.list_vectors(
                user_id=user_id,
                workspace_id=workspace_id,
            )

            source_ids = {
                str(item.get("source_id"))
                for item in vectors
                if item.get("source_id")
            }

            total_chars = sum(
                len(str(item.get("text", "")))
                for item in vectors
                if isinstance(item, dict)
            )

            dimensions = [
                len(item.get("embedding", []))
                for item in vectors
                if isinstance(item.get("embedding", []), list)
            ]

            data = {
                "user_id": user_id,
                "workspace_id": workspace_id,
                "vector_count": len(vectors),
                "source_count": len(source_ids),
                "total_indexed_chars": total_chars,
                "embedding_dimensions": sorted(set(dimensions)),
                "embedding_mode": self._active_embedding_mode(),
                "store_backend": "LocalJSONVectorStore",
            }

            return self._safe_result(
                message="Embedding stats loaded successfully.",
                data=data,
                metadata={"operation": "get_stats"},
            )

        except Exception as exc:
            self.logger.exception("get_stats failed.")
            return self._error_result(
                message="Failed to load embedding stats.",
                error=exc,
                metadata={"operation": "get_stats"},
            )

    # ----------------------------------------------------------------------------------
    # Internal Methods
    # ----------------------------------------------------------------------------------

    def _create_chunks(
        self,
        text: str,
        *,
        user_id: str,
        workspace_id: str,
        source_id: str,
        metadata: Dict[str, Any],
    ) -> List[ChunkRecord]:
        chunk_size = max(100, int(self.config.chunk_size))
        overlap = max(0, min(int(self.config.chunk_overlap), chunk_size - 1))
        min_chars = max(1, int(self.config.min_chunk_chars))

        chunks: List[ChunkRecord] = []
        text_length = len(text)
        start = 0
        index = 0

        while start < text_length:
            raw_end = min(start + chunk_size, text_length)
            end = self._find_natural_break(text, start, raw_end)

            if end <= start:
                end = raw_end

            chunk_text = text[start:end].strip()

            if len(chunk_text) >= min_chars:
                chunk_id = self._make_chunk_id(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    source_id=source_id,
                    chunk_index=index,
                    text=chunk_text,
                )

                chunks.append(
                    ChunkRecord(
                        chunk_id=chunk_id,
                        source_id=source_id,
                        user_id=user_id,
                        workspace_id=workspace_id,
                        text=chunk_text,
                        chunk_index=index,
                        start_char=start,
                        end_char=end,
                        metadata={
                            **metadata,
                            "chunk_size": chunk_size,
                            "chunk_overlap": overlap,
                            "text_sha256": _sha256_text(chunk_text),
                        },
                    )
                )
                index += 1

            if end >= text_length:
                break

            start = max(end - overlap, start + 1)

        return chunks

    def _find_natural_break(self, text: str, start: int, raw_end: int) -> int:
        """
        Attempts to split near paragraph/sentence/word boundaries.
        """

        if raw_end >= len(text):
            return len(text)

        window = text[start:raw_end]

        break_patterns = [
            "\n\n",
            "\n",
            ". ",
            "! ",
            "? ",
            "; ",
            ", ",
            " ",
        ]

        min_acceptable = int(len(window) * 0.55)

        for pattern in break_patterns:
            position = window.rfind(pattern)
            if position >= min_acceptable:
                return start + position + len(pattern)

        return raw_end

    def _embed_texts_internal(
        self,
        texts: List[str],
        *,
        user_id: str,
        workspace_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> List[List[float]]:
        metadata = _ensure_dict(metadata)

        if (
            self.embedding_provider is not None
            and self.config.allow_external_provider
        ):
            embeddings = self.embedding_provider.embed_texts(
                texts,
                user_id=user_id,
                workspace_id=workspace_id,
                metadata=metadata,
            )
            embeddings = [_safe_float_list(item) for item in embeddings]
        else:
            embeddings = [
                self._deterministic_hash_embedding(text)
                for text in texts
            ]

        if self.config.normalize_embeddings:
            embeddings = [_l2_normalize(item) for item in embeddings]

        return embeddings

    def _deterministic_hash_embedding(self, text: str) -> List[float]:
        """
        Dependency-free fallback embedding.

        This is not as semantically powerful as a neural embedding model, but it is:
            - deterministic
            - offline
            - fast
            - safe for testing
            - good enough for bootstrap behavior

        It uses token hashing into a fixed-size vector.
        """
        dimension = max(16, int(self.config.vector_dimension))
        vector = [0.0] * dimension

        tokens = self._tokenize_for_embedding(text)

        if not tokens:
            return vector

        for token in tokens:
            digest = hashlib.blake2b(token.encode("utf-8"), digest_size=16).digest()
            index = int.from_bytes(digest[:4], "big") % dimension
            sign = 1.0 if digest[4] % 2 == 0 else -1.0

            # Slight weight boost for longer meaningful tokens.
            weight = 1.0 + min(len(token), 20) / 40.0
            vector[index] += sign * weight

            # Add a second weaker projection for better spread.
            index_2 = int.from_bytes(digest[5:9], "big") % dimension
            sign_2 = 1.0 if digest[9] % 2 == 0 else -1.0
            vector[index_2] += sign_2 * weight * 0.35

        return vector

    def _tokenize_for_embedding(self, text: str) -> List[str]:
        cleaned = _clean_text(text).lower()

        words = re.findall(r"[a-z0-9_@./:-]+", cleaned)
        if not words:
            return []

        tokens: List[str] = []

        # Unigrams
        tokens.extend(words)

        # Bigrams for phrase sensitivity.
        for i in range(len(words) - 1):
            tokens.append(f"{words[i]} {words[i + 1]}")

        # Trigrams for better local context.
        for i in range(len(words) - 2):
            tokens.append(f"{words[i]} {words[i + 1]} {words[i + 2]}")

        return tokens

    def _active_embedding_mode(self) -> str:
        if self.embedding_provider is not None and self.config.allow_external_provider:
            return "external_provider"
        return self.config.embedding_mode

    def _make_chunk_id(
        self,
        *,
        user_id: str,
        workspace_id: str,
        source_id: str,
        chunk_index: int,
        text: str,
    ) -> str:
        raw = f"{user_id}:{workspace_id}:{source_id}:{chunk_index}:{_sha256_text(text)}"
        return f"chunk_{_sha256_text(raw)[:24]}"

    def _make_vector_id(
        self,
        *,
        user_id: str,
        workspace_id: str,
        source_id: str,
        chunk_id: str,
        text: str,
    ) -> str:
        raw = f"{user_id}:{workspace_id}:{source_id}:{chunk_id}:{_sha256_text(text)}"
        return f"vec_{_sha256_text(raw)[:24]}"

    def _apply_metadata_filter(
        self,
        candidate_vectors: List[Dict[str, Any]],
        *,
        metadata_filter: Optional[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Exact-match metadata filter.

        Example:
            metadata_filter={"project_id": "abc", "memory_type": "client_note"}
        """
        if not metadata_filter:
            return candidate_vectors

        output: List[Dict[str, Any]] = []

        for item in candidate_vectors:
            item_metadata = item.get("metadata", {})
            if not isinstance(item_metadata, dict):
                continue

            matched = True
            for key, expected_value in metadata_filter.items():
                if item_metadata.get(key) != expected_value:
                    matched = False
                    break

            if matched:
                output.append(item)

        return output


# ======================================================================================
# Module-Level Factory
# ======================================================================================

def create_embedding_engine(
    *,
    config: Optional[EmbeddingConfig] = None,
    embedding_provider: Optional[EmbeddingProvider] = None,
    event_emitter: Optional[EventEmitter] = None,
    audit_logger: Optional[AuditLogger] = None,
    **kwargs: Any,
) -> EmbeddingEngine:
    """
    Factory helper for Agent Loader / Registry / FastAPI dependency injection.
    """
    return EmbeddingEngine(
        config=config,
        embedding_provider=embedding_provider,
        event_emitter=event_emitter,
        audit_logger=audit_logger,
        **kwargs,
    )


__all__ = [
    "EmbeddingConfig",
    "ChunkRecord",
    "VectorRecord",
    "SearchResult",
    "EmbeddingProvider",
    "LocalJSONVectorStore",
    "EmbeddingEngine",
    "create_embedding_engine",
]