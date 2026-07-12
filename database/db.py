"""
database/db.py

William / Jarvis Multi-Agent AI SaaS System
Database Engine, Session, Base Config, Health, Audit, Security Hooks

Purpose:
- PostgreSQL-ready database engine/session/base config
- Local SQLite fallback
- FastAPI dependency support
- Alembic compatibility
- SaaS-safe user/workspace isolation helpers
- Security Agent approval hook
- Verification Agent payload preparation
- Memory Agent payload compatibility
- Audit/event logging support

Author: Digital Promotix
"""

from __future__ import annotations

import logging
import os
import re
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Generator, Iterable, List, Mapping, Optional, Tuple, Union

try:
    from sqlalchemy import create_engine, text
    from sqlalchemy.engine import Engine
    from sqlalchemy.exc import SQLAlchemyError
    from sqlalchemy.orm import Session, declarative_base, sessionmaker
    from sqlalchemy.pool import StaticPool
except Exception as exc:  # pragma: no cover
    raise ImportError(
        "SQLAlchemy is required for database/db.py. "
        "Install it with: pip install sqlalchemy psycopg2-binary"
    ) from exc


# ---------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------

logger = logging.getLogger("william.database")

if not logger.handlers:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

logger.setLevel(os.getenv("DATABASE_LOG_LEVEL", "INFO"))


# ---------------------------------------------------------------------
# Base ORM
# ---------------------------------------------------------------------

Base = declarative_base()


# ---------------------------------------------------------------------
# SaaS scope helpers
# ---------------------------------------------------------------------
# Shared by database/models/workspace.py, subscription.py, and
# role_permission.py, each of which previously carried an identical
# private fallback copy of these two names and imported them from here
# alongside Base in a single `from database.db import Base, DbScope,
# validate_scope_id` statement. Because this module never actually
# defined DbScope/validate_scope_id, that import always raised
# ImportError -- which meant those three files silently fell back to a
# bare `class Base: pass` stub instead of the real declarative Base,
# so Workspace/WorkspaceMembership/WorkspaceInvitation,
# SubscriptionPlan/WorkspaceSubscription/UsageLimits/UsageTracking/
# AgentAccess/Invoice/BillingEvent, and Role/Permission/
# RolePermissionLink/UserRoleMapping were never real SQLAlchemy models
# (no __tablename__ registration, unusable with Base.metadata / a real
# session). Defining the real versions here fixes the import for all
# three consumers at the source.

SCOPE_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-:.@]+$")


class DbScope:
    """A validated (user_id, workspace_id) pair for SaaS-isolated queries."""

    def __init__(self, user_id: str, workspace_id: str) -> None:
        self.user_id = validate_scope_id(user_id, "user_id") if user_id else user_id
        self.workspace_id = (
            validate_scope_id(workspace_id, "workspace_id") if workspace_id else workspace_id
        )

    def as_filter_kwargs(self) -> Dict[str, str]:
        return {"user_id": self.user_id, "workspace_id": self.workspace_id}


def validate_scope_id(value: str, field_name: str) -> str:
    """Validate a user_id/workspace_id-shaped identifier before it touches a query."""
    cleaned = str(value).strip()
    if not cleaned:
        raise ValueError(f"{field_name} is required.")
    if len(cleaned) > 140:
        raise ValueError(f"{field_name} is too long.")
    if not SCOPE_ID_PATTERN.match(cleaned):
        raise ValueError(f"{field_name} contains unsafe characters.")
    return cleaned


# ---------------------------------------------------------------------
# Utility Types
# ---------------------------------------------------------------------

QueryParams = Optional[Union[Mapping[str, Any], Dict[str, Any]]]


# ---------------------------------------------------------------------
# Fallback Security Agent
# ---------------------------------------------------------------------

class SecurityAgentStub:
    """
    Safe fallback Security Agent.

    Real SecurityAgent can be injected later by calling:
        db.set_security_agent(security_agent)

    Expected real agent method:
        authorize(action=..., user_id=..., workspace_id=..., metadata=...)
    """

    def authorize(self, **kwargs: Any) -> bool:
        logger.warning(
            "SecurityAgentStub used. Action allowed by fallback. kwargs=%s",
            kwargs,
        )
        return True


# ---------------------------------------------------------------------
# Database Manager
# ---------------------------------------------------------------------

class Db:
    """
    Central database manager for William/Jarvis.

    Supports:
    - PostgreSQL via DATABASE_URL
    - Local SQLite fallback
    - FastAPI dependency usage
    - Alembic migration compatibility
    - user_id/workspace_id isolation checks
    - Security Agent approval hook
    - Verification payload preparation
    - Memory payload compatibility
    """

    DEFAULT_SQLITE_URL = "sqlite:///./william.db"

    READ_ONLY_PATTERN = re.compile(
        r"^\s*(SELECT|WITH|PRAGMA|EXPLAIN)\b",
        re.IGNORECASE,
    )

    SENSITIVE_WRITE_PATTERN = re.compile(
        r"^\s*(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|REPLACE)\b",
        re.IGNORECASE,
    )

    def __init__(
        self,
        database_url: Optional[str] = None,
        echo: Optional[bool] = None,
        security_agent: Optional[Any] = None,
    ) -> None:
        self.database_url = self._resolve_database_url(database_url)
        self.echo = self._resolve_echo(echo)
        self.security_agent = security_agent or SecurityAgentStub()

        self.engine: Engine = self._create_engine(self.database_url, self.echo)

        self.SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self.engine,
            expire_on_commit=False,
        )

        logger.info(
            "Database manager initialized. dialect=%s url=%s",
            self.engine.dialect.name,
            self._safe_database_url(),
        )

    # -----------------------------------------------------------------
    # Environment / Engine Setup
    # -----------------------------------------------------------------

    def _resolve_database_url(self, database_url: Optional[str]) -> str:
        url = (
            database_url
            or os.getenv("DATABASE_URL")
            or os.getenv("POSTGRES_URL")
            or self.DEFAULT_SQLITE_URL
        ).strip()

        if not url:
            return self.DEFAULT_SQLITE_URL

        return url

    def _resolve_echo(self, echo: Optional[bool]) -> bool:
        if echo is not None:
            return bool(echo)

        raw = os.getenv("DATABASE_ECHO", "false").strip().lower()
        return raw in {"1", "true", "yes", "on"}

    def _create_engine(self, database_url: str, echo: bool) -> Engine:
        connect_args: Dict[str, Any] = {}
        engine_kwargs: Dict[str, Any] = {
            "echo": echo,
            "future": True,
            "pool_pre_ping": True,
        }

        if database_url.startswith("sqlite"):
            connect_args["check_same_thread"] = False

            # A plain sqlite:///:memory: URL gives every checked-out
            # connection its own private, empty in-memory database under
            # SQLAlchemy's default pooling -- a row written in one
            # session_scope() call would be invisible to the next one.
            # StaticPool keeps a single connection alive for the whole
            # engine so the in-memory DB is actually shared, which is the
            # standard SQLAlchemy pattern for testing against SQLite memory.
            if ":memory:" in database_url:
                engine_kwargs["poolclass"] = StaticPool
                engine_kwargs.pop("pool_pre_ping", None)
        else:
            engine_kwargs["pool_size"] = int(os.getenv("DATABASE_POOL_SIZE", "5"))
            engine_kwargs["max_overflow"] = int(os.getenv("DATABASE_MAX_OVERFLOW", "10"))
            engine_kwargs["pool_recycle"] = int(os.getenv("DATABASE_POOL_RECYCLE", "1800"))

        return create_engine(
            database_url,
            connect_args=connect_args,
            **engine_kwargs,
        )

    def _safe_database_url(self) -> str:
        """
        Prevent leaking DB passwords in logs/results.
        """
        try:
            return self.engine.url.render_as_string(hide_password=True)
        except Exception:
            return "hidden"

    # -----------------------------------------------------------------
    # Result Helpers
    # -----------------------------------------------------------------

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        verification_payload: Optional[Dict[str, Any]] = None,
        memory_payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        final_metadata = metadata or {}

        if verification_payload is not None:
            final_metadata["verification_payload"] = verification_payload

        if memory_payload is not None:
            final_metadata["memory_payload"] = memory_payload

        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": final_metadata,
            "timestamp": self._now(),
        }

    def _error_result(
        self,
        message: str,
        error: Any = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "success": False,
            "message": message,
            "data": {},
            "error": str(error) if error else None,
            "metadata": metadata or {},
            "timestamp": self._now(),
        }

    # -----------------------------------------------------------------
    # SaaS Context Validation
    # -----------------------------------------------------------------

    def validate_task_context(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
    ) -> bool:
        """
        Every user-specific task must carry user_id and workspace_id.
        """
        return bool(str(user_id or "").strip()) and bool(str(workspace_id or "").strip())

    def _validate_task_context(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
    ) -> bool:
        return self.validate_task_context(user_id, workspace_id)

    # -----------------------------------------------------------------
    # Security Hooks
    # -----------------------------------------------------------------

    def set_security_agent(self, security_agent: Any) -> None:
        """
        Inject real Security Agent after app bootstraps.
        """
        self.security_agent = security_agent or SecurityAgentStub()

    def _requires_security_check(self, action: str) -> bool:
        """
        Database reads and writes are sensitive because they can expose or mutate
        tenant data. Keep this strict by default.
        """
        return action.startswith("database_")

    def _request_security_approval(
        self,
        action: str,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        if not self._requires_security_check(action):
            return True

        try:
            return bool(
                self.security_agent.authorize(
                    action=action,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    metadata=metadata or {},
                )
            )
        except Exception as exc:
            logger.exception("Security approval failed for action=%s", action)
            logger.error("Security error: %s", exc)
            return False

    # -----------------------------------------------------------------
    # Verification Hooks
    # -----------------------------------------------------------------

    def _prepare_verification_payload(
        self,
        action: str,
        result_summary: Optional[Dict[str, Any]] = None,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        return {
            "agent": "database",
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "timestamp": self._now(),
            "result_summary": result_summary or {},
        }

    # -----------------------------------------------------------------
    # Memory Hooks
    # -----------------------------------------------------------------

    def _prepare_memory_payload(
        self,
        action: str,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "agent": "database",
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "metadata": metadata or {},
            "timestamp": self._now(),
        }

    # -----------------------------------------------------------------
    # Audit / Event Hooks
    # -----------------------------------------------------------------

    def _log_audit_event(
        self,
        action: str,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        logger.info(
            "[AUDIT] action=%s user_id=%s workspace_id=%s metadata=%s",
            action,
            user_id,
            workspace_id,
            metadata or {},
        )

    def _emit_agent_event(
        self,
        event_name: str,
        payload: Dict[str, Any],
    ) -> None:
        logger.info("[EVENT] %s payload=%s", event_name, payload)

    # -----------------------------------------------------------------
    # Session Helpers
    # -----------------------------------------------------------------

    def create_session(self) -> Session:
        """
        Create a new SQLAlchemy session.
        """
        return self.SessionLocal()

    @contextmanager
    def session_scope(self) -> Generator[Session, None, None]:
        """
        Transaction-safe session wrapper.

        Usage:
            with db.session_scope() as session:
                session.add(model)
        """
        session = self.create_session()

        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            logger.exception("Database session rolled back due to error.")
            raise
        finally:
            session.close()

    def get_db(self) -> Generator[Session, None, None]:
        """
        FastAPI dependency generator.

        Usage:
            from fastapi import Depends

            def route(db: Session = Depends(get_db)):
                ...
        """
        session = self.create_session()

        try:
            yield session
        finally:
            session.close()

    # -----------------------------------------------------------------
    # Database Initialization
    # -----------------------------------------------------------------

    def initialize_database(
        self,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        require_context: bool = False,
    ) -> Dict[str, Any]:
        """
        Create all tables registered on Base.metadata.

        For app startup, require_context can stay False.
        For user-triggered DB initialization, set require_context=True.
        """
        action = "database_initialize"

        if require_context and not self.validate_task_context(user_id, workspace_id):
            return self._error_result("Invalid SaaS context for database initialization.")

        if require_context and not self._request_security_approval(
            action=action,
            user_id=user_id,
            workspace_id=workspace_id,
        ):
            return self._error_result("Security approval denied for database initialization.")

        try:
            Base.metadata.create_all(bind=self.engine)

            summary = {
                "tables": sorted(Base.metadata.tables.keys()),
                "database_url": self._safe_database_url(),
            }

            self._log_audit_event(
                action,
                user_id=user_id,
                workspace_id=workspace_id,
                metadata=summary,
            )

            verification_payload = self._prepare_verification_payload(
                action=action,
                result_summary=summary,
                user_id=user_id,
                workspace_id=workspace_id,
            )

            memory_payload = self._prepare_memory_payload(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                metadata=summary,
            )

            return self._safe_result(
                "Database initialized successfully.",
                data=summary,
                verification_payload=verification_payload,
                memory_payload=memory_payload,
            )

        except Exception as exc:
            logger.exception("Database initialization failed.")
            return self._error_result("Database initialization failed.", exc)

    # -----------------------------------------------------------------
    # Health Check
    # -----------------------------------------------------------------

    def health_check(self) -> Dict[str, Any]:
        """
        Lightweight database health check.
        """
        started = time.perf_counter()

        try:
            with self.engine.connect() as conn:
                conn.execute(text("SELECT 1"))

            latency_ms = round((time.perf_counter() - started) * 1000, 2)

            data = {
                "status": "healthy",
                "latency_ms": latency_ms,
                "database_url": self._safe_database_url(),
                "dialect": self.engine.dialect.name,
                "driver": self.engine.dialect.driver,
            }

            return self._safe_result(
                "Database healthy.",
                data=data,
                verification_payload=self._prepare_verification_payload(
                    action="database_health_check",
                    result_summary=data,
                ),
                memory_payload=self._prepare_memory_payload(
                    action="database_health_check",
                    metadata=data,
                ),
            )

        except Exception as exc:
            logger.exception("Database health check failed.")
            return self._error_result("Database unhealthy.", exc)

    # -----------------------------------------------------------------
    # Migration Compatibility
    # -----------------------------------------------------------------

    def get_alembic_config(self) -> Dict[str, Any]:
        """
        Alembic compatibility helper.
        """
        return {
            "sqlalchemy.url": self.database_url,
            "target_metadata": Base.metadata,
        }

    # -----------------------------------------------------------------
    # Query Safety
    # -----------------------------------------------------------------

    def _is_read_only_query(self, query: str) -> bool:
        return bool(self.READ_ONLY_PATTERN.match(query or ""))

    def _is_write_query(self, query: str) -> bool:
        return bool(self.SENSITIVE_WRITE_PATTERN.match(query or ""))

    def _normalize_query(self, query: str) -> str:
        if not isinstance(query, str):
            raise ValueError("Query must be a string.")

        cleaned = query.strip()

        if not cleaned:
            raise ValueError("Query cannot be empty.")

        return cleaned

    # -----------------------------------------------------------------
    # Raw Query Execution
    # -----------------------------------------------------------------

    def execute_query(
        self,
        query: str,
        params: QueryParams = None,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        read_only: bool = True,
    ) -> Dict[str, Any]:
        """
        Execute a raw SQL query safely.

        Rules:
        - user_id and workspace_id are required.
        - Security Agent approval is required.
        - read_only=True blocks write queries.
        - Use params instead of string formatting to avoid SQL injection.

        Example:
            db.execute_query(
                "SELECT * FROM users WHERE user_id = :user_id",
                params={"user_id": "u_123"},
                user_id="u_123",
                workspace_id="w_123",
            )
        """
        action = "database_query"

        if not self.validate_task_context(user_id, workspace_id):
            return self._error_result(
                "Invalid SaaS context. user_id and workspace_id are required."
            )

        try:
            cleaned_query = self._normalize_query(query)
        except ValueError as exc:
            return self._error_result("Invalid query.", exc)

        is_write = self._is_write_query(cleaned_query)

        if read_only and is_write:
            return self._error_result(
                "Write query blocked because read_only=True. "
                "Set read_only=False only for approved internal write operations."
            )

        approval_metadata = {
            "read_only": read_only,
            "is_write": is_write,
            "query_preview": cleaned_query[:160],
        }

        if not self._request_security_approval(
            action=action,
            user_id=user_id,
            workspace_id=workspace_id,
            metadata=approval_metadata,
        ):
            return self._error_result("Security approval denied for database query.")

        started = time.perf_counter()

        try:
            rows: List[Dict[str, Any]] = []
            affected_rows: Optional[int] = None

            with self.engine.begin() as conn:
                result = conn.execute(text(cleaned_query), params or {})

                if result.returns_rows:
                    rows = [dict(row._mapping) for row in result.fetchall()]
                else:
                    affected_rows = result.rowcount

            latency_ms = round((time.perf_counter() - started) * 1000, 2)

            data = {
                "rows": rows,
                "count": len(rows),
                "affected_rows": affected_rows,
                "latency_ms": latency_ms,
                "read_only": read_only,
                "is_write": is_write,
            }

            self._log_audit_event(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                metadata={
                    "count": len(rows),
                    "affected_rows": affected_rows,
                    "latency_ms": latency_ms,
                    "read_only": read_only,
                    "is_write": is_write,
                },
            )

            self._emit_agent_event(
                "database.query.completed",
                {
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "count": len(rows),
                    "affected_rows": affected_rows,
                    "latency_ms": latency_ms,
                },
            )

            verification_payload = self._prepare_verification_payload(
                action=action,
                result_summary=data,
                user_id=user_id,
                workspace_id=workspace_id,
            )

            memory_payload = self._prepare_memory_payload(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                metadata={
                    "query_type": "write" if is_write else "read",
                    "count": len(rows),
                    "affected_rows": affected_rows,
                },
            )

            return self._safe_result(
                "Query executed successfully.",
                data=data,
                verification_payload=verification_payload,
                memory_payload=memory_payload,
            )

        except SQLAlchemyError as exc:
            logger.exception("Database query failed.")
            return self._error_result("Query execution failed.", exc)

        except Exception as exc:
            logger.exception("Unexpected database query error.")
            return self._error_result("Unexpected query execution error.", exc)

    # -----------------------------------------------------------------
    # Bulk Query Execution
    # -----------------------------------------------------------------

    def execute_many(
        self,
        query: str,
        params_list: Iterable[Mapping[str, Any]],
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Execute one write query against many parameter sets.

        Example:
            db.execute_many(
                "INSERT INTO logs (user_id, workspace_id, event) VALUES (:user_id, :workspace_id, :event)",
                [{"user_id": "u1", "workspace_id": "w1", "event": "login"}],
                user_id="u1",
                workspace_id="w1",
            )
        """
        action = "database_bulk_query"

        if not self.validate_task_context(user_id, workspace_id):
            return self._error_result(
                "Invalid SaaS context. user_id and workspace_id are required."
            )

        try:
            cleaned_query = self._normalize_query(query)
        except ValueError as exc:
            return self._error_result("Invalid query.", exc)

        params_batch = list(params_list or [])

        if not params_batch:
            return self._error_result("params_list cannot be empty.")

        approval_metadata = {
            "batch_size": len(params_batch),
            "query_preview": cleaned_query[:160],
        }

        if not self._request_security_approval(
            action=action,
            user_id=user_id,
            workspace_id=workspace_id,
            metadata=approval_metadata,
        ):
            return self._error_result("Security approval denied for bulk database query.")

        started = time.perf_counter()

        try:
            with self.engine.begin() as conn:
                result = conn.execute(text(cleaned_query), params_batch)
                affected_rows = result.rowcount

            latency_ms = round((time.perf_counter() - started) * 1000, 2)

            data = {
                "batch_size": len(params_batch),
                "affected_rows": affected_rows,
                "latency_ms": latency_ms,
            }

            self._log_audit_event(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                metadata=data,
            )

            verification_payload = self._prepare_verification_payload(
                action=action,
                result_summary=data,
                user_id=user_id,
                workspace_id=workspace_id,
            )

            memory_payload = self._prepare_memory_payload(
                action=action,
                user_id=user_id,
                workspace_id=workspace_id,
                metadata=data,
            )

            return self._safe_result(
                "Bulk query executed successfully.",
                data=data,
                verification_payload=verification_payload,
                memory_payload=memory_payload,
            )

        except SQLAlchemyError as exc:
            logger.exception("Bulk database query failed.")
            return self._error_result("Bulk query execution failed.", exc)

        except Exception as exc:
            logger.exception("Unexpected bulk database query error.")
            return self._error_result("Unexpected bulk query execution error.", exc)

    # -----------------------------------------------------------------
    # Diagnostics
    # -----------------------------------------------------------------

    def database_statistics(self) -> Dict[str, Any]:
        """
        Return safe diagnostic information.
        """
        try:
            table_names = sorted(Base.metadata.tables.keys())

            data = {
                "database_url": self._safe_database_url(),
                "dialect": self.engine.dialect.name,
                "driver": self.engine.dialect.driver,
                "tables_registered": table_names,
                "table_count": len(table_names),
            }

            return self._safe_result(
                "Database statistics generated.",
                data=data,
                verification_payload=self._prepare_verification_payload(
                    action="database_statistics",
                    result_summary=data,
                ),
                memory_payload=self._prepare_memory_payload(
                    action="database_statistics",
                    metadata=data,
                ),
            )

        except Exception as exc:
            logger.exception("Failed to collect database statistics.")
            return self._error_result("Failed to collect statistics.", exc)

    # -----------------------------------------------------------------
    # Shutdown
    # -----------------------------------------------------------------

    def shutdown(self) -> Dict[str, Any]:
        """
        Dispose database engine connections.
        """
        try:
            self.engine.dispose()

            data = {
                "database_url": self._safe_database_url(),
                "status": "disposed",
            }

            return self._safe_result(
                "Database engine disposed.",
                data=data,
                verification_payload=self._prepare_verification_payload(
                    action="database_shutdown",
                    result_summary=data,
                ),
                memory_payload=self._prepare_memory_payload(
                    action="database_shutdown",
                    metadata=data,
                ),
            )

        except Exception as exc:
            logger.exception("Database shutdown failed.")
            return self._error_result("Shutdown failed.", exc)


# ---------------------------------------------------------------------
# Backward Compatibility Alias
# ---------------------------------------------------------------------

DatabaseManager = Db


# ---------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------

db_manager = Db()


# ---------------------------------------------------------------------
# FastAPI Dependency
# ---------------------------------------------------------------------

def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency.

    Example:
        from fastapi import Depends
        from database.db import get_db

        def route(db: Session = Depends(get_db)):
            ...
    """
    yield from db_manager.get_db()


# ---------------------------------------------------------------------
# Utility Exports
# ---------------------------------------------------------------------

def initialize_database(
    user_id: Optional[str] = None,
    workspace_id: Optional[str] = None,
    require_context: bool = False,
) -> Dict[str, Any]:
    return db_manager.initialize_database(
        user_id=user_id,
        workspace_id=workspace_id,
        require_context=require_context,
    )


def database_health() -> Dict[str, Any]:
    return db_manager.health_check()


def database_statistics() -> Dict[str, Any]:
    return db_manager.database_statistics()


def execute_query(
    query: str,
    params: QueryParams = None,
    user_id: Optional[str] = None,
    workspace_id: Optional[str] = None,
    read_only: bool = True,
) -> Dict[str, Any]:
    return db_manager.execute_query(
        query=query,
        params=params,
        user_id=user_id,
        workspace_id=workspace_id,
        read_only=read_only,
    )


def shutdown_database() -> Dict[str, Any]:
    return db_manager.shutdown()


__all__ = [
    "Base",
    "Db",
    "DatabaseManager",
    "db_manager",
    "get_db",
    "initialize_database",
    "database_health",
    "database_statistics",
    "execute_query",
    "shutdown_database",
]