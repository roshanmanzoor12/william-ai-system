"""
agents/agent_health.py

William / Jarvis Multi-Agent AI SaaS System - Digital Promotix

Purpose:
    Production-ready health checker for global agent infrastructure.

This file checks:
    - Agent availability
    - Required agent files
    - Import safety
    - Python dependencies
    - Optional William/Jarvis modules
    - Agent Registry compatibility
    - Agent Loader compatibility
    - Agent Router compatibility
    - Agent Events compatibility
    - Agent Permissions compatibility
    - SaaS user/workspace context safety
    - Dashboard/API friendly health snapshots

Architecture Compatibility:
    - BaseAgent compatible
    - MasterAgent compatible
    - Registry compatible
    - Loader compatible
    - Router compatible
    - Events compatible
    - Permissions compatible
    - Security Agent aware
    - Verification Agent payload compatible
    - Memory Agent payload compatible
    - FastAPI/Dashboard ready

Important:
    This module does NOT perform destructive actions.
    This module does NOT make external network calls.
    This module does NOT hardcode secrets.
    This module is safe to import even before all future files exist.
"""

from __future__ import annotations

import importlib
import inspect
import logging
import os
import pkgutil
import platform
import sys
import time
import traceback
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union


# =============================================================================
# Optional BaseAgent compatibility
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Safe fallback BaseAgent stub.

        This allows agent_health.py to import safely before base_agent.py
        exists or before the full William/Jarvis stack is completed.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())


# =============================================================================
# Optional AgentEvents compatibility
# =============================================================================

try:
    from agents.agent_events import get_agent_events  # type: ignore
except Exception:  # pragma: no cover
    def get_agent_events() -> Any:  # type: ignore
        return None


# =============================================================================
# Logging
# =============================================================================

logger = logging.getLogger("william.agents.agent_health")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)


# =============================================================================
# Enums
# =============================================================================

class HealthStatus(str, Enum):
    """
    Health status values used across William/Jarvis infrastructure.
    """

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    MISSING = "missing"
    UNKNOWN = "unknown"


class HealthSeverity(str, Enum):
    """
    Health issue severity values.
    """

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class HealthCheckType(str, Enum):
    """
    Supported health check categories.
    """

    FILE = "file"
    IMPORT = "import"
    DEPENDENCY = "dependency"
    PERMISSION = "permission"
    AGENT = "agent"
    REGISTRY = "registry"
    LOADER = "loader"
    ROUTER = "router"
    EVENTS = "events"
    CONFIG = "config"
    SYSTEM = "system"
    SECURITY = "security"
    DATABASE = "database"
    DASHBOARD = "dashboard"
    CUSTOM = "custom"


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class HealthIssue:
    """
    Represents one health issue.
    """

    issue_id: str
    check_type: str
    severity: str
    message: str
    target: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: AgentHealth.utc_now())


@dataclass
class HealthCheckResult:
    """
    Represents one health check result.
    """

    check_id: str
    check_type: str
    target: str
    status: str
    success: bool
    message: str
    data: Dict[str, Any] = field(default_factory=dict)
    issues: List[Dict[str, Any]] = field(default_factory=list)
    duration_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    checked_at: str = field(default_factory=lambda: AgentHealth.utc_now())


@dataclass
class AgentHealthSnapshot:
    """
    Dashboard/API friendly global health snapshot.
    """

    snapshot_id: str
    overall_status: str
    score: float
    total_checks: int
    passed_checks: int
    failed_checks: int
    warning_checks: int
    critical_issues: int
    checks: List[Dict[str, Any]] = field(default_factory=list)
    issues: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: AgentHealth.utc_now())


# =============================================================================
# AgentHealth
# =============================================================================

class AgentHealth(BaseAgent):
    """
    Production health checker for William/Jarvis agent infrastructure.

    Responsibilities:
        - Check required files
        - Check import availability
        - Check Python/package dependencies
        - Check core William/Jarvis global infrastructure modules
        - Check agent module availability
        - Check permission module compatibility
        - Check event bus compatibility
        - Check registry/loader/router import safety
        - Return structured JSON-style health snapshots
        - Emit health/audit events if AgentEvents is available

    This class is intentionally safe:
        - No destructive system actions
        - No network calls
        - No secret access
        - No database mutations
    """

    CORE_INFRASTRUCTURE_FILES: List[str] = [
        "agents/base_agent.py",
        "agents/registry.py",
        "agents/agent_loader.py",
        "agents/agent_router.py",
        "agents/agent_manifest.py",
        "agents/agent_permissions.py",
        "agents/agent_events.py",
        "agents/agent_health.py",
        "agents/agent_config.py",
    ]

    CORE_INFRASTRUCTURE_MODULES: List[str] = [
        "agents.base_agent",
        "agents.registry",
        "agents.agent_loader",
        "agents.agent_router",
        "agents.agent_manifest",
        "agents.agent_permissions",
        "agents.agent_events",
        "agents.agent_health",
    ]

    OPTIONAL_INFRASTRUCTURE_MODULES: List[str] = [
        "agents.agent_config",
        "agents.master_agent",
        "agents.security_agent",
        "agents.memory_agent",
        "agents.verification_agent",
    ]

    EXPECTED_AGENT_NAMES: List[str] = [
        "voice",
        "system",
        "browser",
        "code",
        "memory",
        "security",
        "verification",
        "visual",
        "workflow",
        "hologram",
        "call",
        "business",
        "finance",
        "creator",
    ]

    OPTIONAL_DEPENDENCIES: List[str] = [
        "fastapi",
        "pydantic",
        "sqlalchemy",
        "uvicorn",
        "requests",
        "httpx",
        "dotenv",
    ]

    REQUIRED_PUBLIC_METHODS: Dict[str, List[str]] = {
        "agents.agent_events": [
            "get_agent_events",
            "emit_agent_event",
            "send_agent_message",
        ],
        "agents.agent_permissions": [
            "AgentPermissions",
        ],
        "agents.registry": [
            "AgentRegistry",
        ],
        "agents.agent_loader": [
            "AgentLoader",
        ],
        "agents.agent_router": [
            "AgentRouter",
        ],
    }

    def __init__(
        self,
        project_root: Optional[Union[str, Path]] = None,
        enable_event_emission: bool = True,
        agent_name: str = "AgentHealth",
        agent_id: str = "agent_health",
        **kwargs: Any,
    ) -> None:
        try:
            super().__init__(agent_name=agent_name, agent_id=agent_id, **kwargs)
        except TypeError:
            try:
                super().__init__()
            except Exception:
                pass

        self.agent_name = agent_name
        self.agent_id = agent_id
        self.project_root = Path(project_root or os.getcwd()).resolve()
        self.enable_event_emission = bool(enable_event_emission)

        self._last_snapshot: Optional[Dict[str, Any]] = None
        self._last_checked_at: Optional[str] = None

    # =========================================================================
    # Time / IDs
    # =========================================================================

    @staticmethod
    def utc_now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def new_id(prefix: str = "health") -> str:
        return f"{prefix}_{uuid.uuid4().hex}"

    # =========================================================================
    # Standard Result Helpers
    # =========================================================================

    def _safe_result(
        self,
        success: bool = True,
        message: str = "OK",
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Union[str, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "success": bool(success),
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": metadata or {
                "agent": self.agent_name,
                "agent_id": self.agent_id,
                "timestamp": self.utc_now(),
            },
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Union[str, Exception, Dict[str, Any]]] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if isinstance(error, Exception):
            error_payload: Union[str, Dict[str, Any]] = {
                "type": error.__class__.__name__,
                "message": str(error),
                "traceback": traceback.format_exc(),
            }
        elif isinstance(error, dict):
            error_payload = error
        else:
            error_payload = str(error) if error is not None else message

        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": error_payload,
            "metadata": metadata or {
                "agent": self.agent_name,
                "agent_id": self.agent_id,
                "timestamp": self.utc_now(),
            },
        }

    # =========================================================================
    # Required Compatibility Hooks
    # =========================================================================

    def _validate_task_context(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        require_user: bool = False,
        require_workspace: bool = False,
    ) -> Dict[str, Any]:
        """
        Validate SaaS user/workspace context.

        Health checks can be global/system-level, but when checking user-specific
        workspace configuration, user_id and workspace_id must remain isolated.
        """

        errors: List[str] = []

        if require_user and self._is_empty(user_id):
            errors.append("user_id is required")

        if require_workspace and self._is_empty(workspace_id):
            errors.append("workspace_id is required")

        if user_id is not None and not self._is_valid_context_value(user_id):
            errors.append("user_id must be a safe string or integer")

        if workspace_id is not None and not self._is_valid_context_value(workspace_id):
            errors.append("workspace_id must be a safe string or integer")

        if errors:
            return self._error_result(
                message="Invalid health check context",
                error={"errors": errors},
                data={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "require_user": require_user,
                    "require_workspace": require_workspace,
                },
            )

        return self._safe_result(
            message="Health check context valid",
            data={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "require_user": require_user,
                "require_workspace": require_workspace,
            },
        )

    def _requires_security_check(self, action: str, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """
        Health checks are read-only by default.

        Security approval is required only when caller explicitly marks
        the health check as sensitive, privileged, or admin-only.
        """

        metadata = metadata or {}

        if metadata.get("requires_security_check") is True:
            return True

        if metadata.get("admin_only") is True:
            return True

        if action in {
            "admin_health_snapshot",
            "security_health_check",
            "permission_health_check",
        }:
            return True

        return False

    def _request_security_approval(
        self,
        action: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Security approval hook.

        This file does not directly call a real Security Agent to avoid hard
        dependency. It emits structured intent and safely allows read-only checks
        unless explicitly marked dangerous.
        """

        metadata = metadata or {}

        if metadata.get("dangerous") is True or metadata.get("destructive_action") is True:
            return self._error_result(
                message="Security approval denied",
                error="Health checks cannot perform dangerous or destructive actions",
                data={
                    "action": action,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

        return self._safe_result(
            message="Security approval granted for read-only health check",
            data={
                "approved": True,
                "action": action,
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    def _prepare_verification_payload(
        self,
        health_result: Dict[str, Any],
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent-compatible payload.
        """

        return {
            "verification_id": self.new_id("ver"),
            "source": "AgentHealth",
            "user_id": user_id,
            "workspace_id": workspace_id,
            "status": health_result.get("data", {}).get("overall_status"),
            "score": health_result.get("data", {}).get("score"),
            "summary": health_result.get("message"),
            "health_result": health_result,
            "metadata": {
                "prepared_by": self.agent_name,
                "prepared_at": self.utc_now(),
                "requires_review": health_result.get("data", {}).get("overall_status") in {
                    HealthStatus.DEGRADED.value,
                    HealthStatus.UNHEALTHY.value,
                },
            },
        }

    def _prepare_memory_payload(
        self,
        health_result: Dict[str, Any],
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent-compatible payload.
        """

        data = health_result.get("data", {})

        return {
            "memory_id": self.new_id("mem"),
            "source": "AgentHealth",
            "user_id": user_id,
            "workspace_id": workspace_id,
            "content": {
                "overall_status": data.get("overall_status"),
                "score": data.get("score"),
                "total_checks": data.get("total_checks"),
                "failed_checks": data.get("failed_checks"),
                "critical_issues": data.get("critical_issues"),
            },
            "metadata": {
                "prepared_by": self.agent_name,
                "prepared_at": self.utc_now(),
                "importance": "high" if data.get("overall_status") != HealthStatus.HEALTHY.value else "normal",
            },
        }

    def _emit_agent_event(
        self,
        event_type: str,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        severity: str = "info",
    ) -> Dict[str, Any]:
        """
        Emit health event if AgentEvents exists.

        Safe fallback if events module is unavailable.
        """

        if not self.enable_event_emission:
            return self._safe_result(
                message="Event emission disabled",
                data={"emitted": False},
            )

        try:
            event_bus = get_agent_events()
            if event_bus is None or not hasattr(event_bus, "publish_event"):
                return self._safe_result(
                    message="AgentEvents unavailable",
                    data={"emitted": False},
                )

            result = event_bus.publish_event(
                event_type=event_type,
                source_agent=self.agent_name,
                message=message,
                user_id=user_id,
                workspace_id=workspace_id,
                severity=severity,
                data=data or {},
                require_user=False,
                require_workspace=False,
            )

            return result if isinstance(result, dict) else self._safe_result(
                message="Event emitted",
                data={"emitted": True},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to emit health event",
                error=exc,
            )

    def _log_audit_event(
        self,
        action: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Log audit event through AgentEvents if available.
        """

        try:
            event_bus = get_agent_events()
            if event_bus is not None and hasattr(event_bus, "_log_audit_event"):
                return event_bus._log_audit_event(
                    action=action,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    metadata=metadata or {},
                )
        except Exception:
            pass

        return self._safe_result(
            message="Audit event prepared locally",
            data={
                "action": action,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "metadata": metadata or {},
                "created_at": self.utc_now(),
            },
        )

    # =========================================================================
    # Main Public Health Methods
    # =========================================================================

    def run_full_health_check(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        include_optional: bool = True,
        include_agent_scan: bool = True,
        include_dependencies: bool = True,
        include_permissions: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Run complete William/Jarvis infrastructure health check.

        This method is safe for dashboard/API usage.
        """

        metadata = metadata or {}

        context = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            require_user=False,
            require_workspace=False,
        )
        if not context.get("success"):
            return context

        if self._requires_security_check("admin_health_snapshot", metadata):
            approval = self._request_security_approval(
                action="admin_health_snapshot",
                user_id=user_id,
                workspace_id=workspace_id,
                metadata=metadata,
            )
            if not approval.get("success"):
                return approval

        started = time.perf_counter()
        checks: List[Dict[str, Any]] = []

        try:
            checks.extend(self.check_required_files().get("data", {}).get("checks", []))
            checks.extend(self.check_core_imports(include_optional=include_optional).get("data", {}).get("checks", []))

            if include_dependencies:
                checks.extend(self.check_dependencies().get("data", {}).get("checks", []))

            if include_permissions:
                checks.extend(self.check_permissions_module().get("data", {}).get("checks", []))

            checks.extend(self.check_events_module().get("data", {}).get("checks", []))
            checks.extend(self.check_registry_loader_router().get("data", {}).get("checks", []))

            if include_agent_scan:
                checks.extend(self.check_expected_agents().get("data", {}).get("checks", []))

            checks.append(self.check_system_environment().get("data", {}).get("check", {}))

            snapshot = self._build_snapshot(
                checks=checks,
                duration_ms=(time.perf_counter() - started) * 1000,
                user_id=user_id,
                workspace_id=workspace_id,
                metadata=metadata,
            )

            result = self._safe_result(
                success=snapshot["overall_status"] != HealthStatus.UNHEALTHY.value,
                message="Full health check completed",
                data=snapshot,
            )

            self._last_snapshot = snapshot
            self._last_checked_at = self.utc_now()

            self._emit_agent_event(
                event_type="health_event",
                message="AgentHealth full health check completed",
                data={
                    "overall_status": snapshot["overall_status"],
                    "score": snapshot["score"],
                    "failed_checks": snapshot["failed_checks"],
                    "critical_issues": snapshot["critical_issues"],
                },
                user_id=user_id,
                workspace_id=workspace_id,
                severity="warning" if snapshot["overall_status"] != HealthStatus.HEALTHY.value else "info",
            )

            self._log_audit_event(
                action="full_health_check_completed",
                user_id=user_id,
                workspace_id=workspace_id,
                metadata={
                    "overall_status": snapshot["overall_status"],
                    "score": snapshot["score"],
                    "total_checks": snapshot["total_checks"],
                },
            )

            return result

        except Exception as exc:
            return self._error_result(
                message="Full health check failed",
                error=exc,
            )

    def quick_health_check(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
    ) -> Dict[str, Any]:
        """
        Fast health check for API ping/dashboard badge.

        Checks only core files, imports, event bus, and system environment.
        """

        started = time.perf_counter()
        checks: List[Dict[str, Any]] = []

        try:
            checks.extend(self.check_required_files().get("data", {}).get("checks", []))
            checks.extend(self.check_core_imports(include_optional=False).get("data", {}).get("checks", []))
            checks.extend(self.check_events_module().get("data", {}).get("checks", []))
            checks.append(self.check_system_environment().get("data", {}).get("check", {}))

            snapshot = self._build_snapshot(
                checks=checks,
                duration_ms=(time.perf_counter() - started) * 1000,
                user_id=user_id,
                workspace_id=workspace_id,
                metadata={"mode": "quick"},
            )

            return self._safe_result(
                success=snapshot["overall_status"] != HealthStatus.UNHEALTHY.value,
                message="Quick health check completed",
                data=snapshot,
            )

        except Exception as exc:
            return self._error_result(
                message="Quick health check failed",
                error=exc,
            )

    def get_last_snapshot(self) -> Dict[str, Any]:
        """
        Return last cached health snapshot.
        """

        if not self._last_snapshot:
            return self._safe_result(
                success=False,
                message="No health snapshot available yet",
                data={
                    "snapshot": None,
                    "last_checked_at": None,
                },
            )

        return self._safe_result(
            message="Last health snapshot fetched",
            data={
                "snapshot": self._last_snapshot,
                "last_checked_at": self._last_checked_at,
            },
        )

    # =========================================================================
    # File Checks
    # =========================================================================

    def check_required_files(
        self,
        required_files: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        """
        Check required William/Jarvis infrastructure files.
        """

        files = list(required_files or self.CORE_INFRASTRUCTURE_FILES)
        checks: List[Dict[str, Any]] = []

        for file_path in files:
            started = time.perf_counter()
            absolute_path = self.project_root / file_path
            exists = absolute_path.exists()
            is_file = absolute_path.is_file() if exists else False

            issues: List[Dict[str, Any]] = []
            status = HealthStatus.HEALTHY.value if exists and is_file else HealthStatus.MISSING.value
            success = exists and is_file

            if not exists:
                issues.append(self._issue(
                    check_type=HealthCheckType.FILE,
                    severity=HealthSeverity.ERROR,
                    message=f"Required file missing: {file_path}",
                    target=file_path,
                    details={"path": str(absolute_path)},
                ))
            elif not is_file:
                issues.append(self._issue(
                    check_type=HealthCheckType.FILE,
                    severity=HealthSeverity.ERROR,
                    message=f"Required path exists but is not a file: {file_path}",
                    target=file_path,
                    details={"path": str(absolute_path)},
                ))

            checks.append(self._check(
                check_type=HealthCheckType.FILE,
                target=file_path,
                status=status,
                success=success,
                message="File exists" if success else "File missing or invalid",
                data={
                    "path": str(absolute_path),
                    "exists": exists,
                    "is_file": is_file,
                    "size_bytes": absolute_path.stat().st_size if exists and is_file else 0,
                },
                issues=issues,
                started=started,
            ))

        return self._safe_result(
            message="Required file checks completed",
            data={
                "checks": checks,
                "count": len(checks),
            },
        )

    # =========================================================================
    # Import Checks
    # =========================================================================

    def check_core_imports(
        self,
        include_optional: bool = True,
    ) -> Dict[str, Any]:
        """
        Check core William/Jarvis modules import safely.
        """

        modules = list(self.CORE_INFRASTRUCTURE_MODULES)
        if include_optional:
            modules.extend(self.OPTIONAL_INFRASTRUCTURE_MODULES)

        checks: List[Dict[str, Any]] = []

        for module_name in modules:
            checks.append(self._check_import(module_name))

        return self._safe_result(
            message="Core import checks completed",
            data={
                "checks": checks,
                "count": len(checks),
                "include_optional": include_optional,
            },
        )

    def check_module_import(self, module_name: str) -> Dict[str, Any]:
        """
        Public method to check one module import.
        """

        if not module_name or not isinstance(module_name, str):
            return self._error_result(
                message="module_name is required",
                error="missing_module_name",
            )

        return self._safe_result(
            message="Module import check completed",
            data={
                "check": self._check_import(module_name),
            },
        )

    def _check_import(self, module_name: str) -> Dict[str, Any]:
        started = time.perf_counter()
        issues: List[Dict[str, Any]] = []

        try:
            module = importlib.import_module(module_name)

            missing_methods: List[str] = []
            for public_name in self.REQUIRED_PUBLIC_METHODS.get(module_name, []):
                if not hasattr(module, public_name):
                    missing_methods.append(public_name)

            if missing_methods:
                issues.append(self._issue(
                    check_type=HealthCheckType.IMPORT,
                    severity=HealthSeverity.WARNING,
                    message=f"Module imports but missing expected public names: {module_name}",
                    target=module_name,
                    details={"missing": missing_methods},
                ))

            status = HealthStatus.DEGRADED.value if missing_methods else HealthStatus.HEALTHY.value

            return self._check(
                check_type=HealthCheckType.IMPORT,
                target=module_name,
                status=status,
                success=True,
                message="Module imported successfully",
                data={
                    "module": module_name,
                    "file": getattr(module, "__file__", None),
                    "missing_public_names": missing_methods,
                },
                issues=issues,
                started=started,
            )

        except Exception as exc:
            issues.append(self._issue(
                check_type=HealthCheckType.IMPORT,
                severity=HealthSeverity.ERROR,
                message=f"Failed to import module: {module_name}",
                target=module_name,
                details={
                    "error_type": exc.__class__.__name__,
                    "error": str(exc),
                },
            ))

            return self._check(
                check_type=HealthCheckType.IMPORT,
                target=module_name,
                status=HealthStatus.MISSING.value,
                success=False,
                message="Module import failed",
                data={
                    "module": module_name,
                    "error_type": exc.__class__.__name__,
                    "error": str(exc),
                },
                issues=issues,
                started=started,
            )

    # =========================================================================
    # Dependency Checks
    # =========================================================================

    def check_dependencies(
        self,
        dependencies: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        """
        Check optional Python dependencies.

        Dependencies are optional at this infrastructure stage. Missing optional
        dependencies are warnings, not hard failures.
        """

        deps = list(dependencies or self.OPTIONAL_DEPENDENCIES)
        checks: List[Dict[str, Any]] = []

        for dep in deps:
            started = time.perf_counter()
            found = pkgutil.find_loader(dep) is not None

            issues: List[Dict[str, Any]] = []
            if not found:
                issues.append(self._issue(
                    check_type=HealthCheckType.DEPENDENCY,
                    severity=HealthSeverity.WARNING,
                    message=f"Optional dependency not installed: {dep}",
                    target=dep,
                    details={"dependency": dep},
                ))

            checks.append(self._check(
                check_type=HealthCheckType.DEPENDENCY,
                target=dep,
                status=HealthStatus.HEALTHY.value if found else HealthStatus.DEGRADED.value,
                success=True,
                message="Dependency available" if found else "Optional dependency missing",
                data={
                    "dependency": dep,
                    "available": found,
                    "optional": True,
                },
                issues=issues,
                started=started,
            ))

        return self._safe_result(
            message="Dependency checks completed",
            data={
                "checks": checks,
                "count": len(checks),
            },
        )

    # =========================================================================
    # Permission / Security / Events Checks
    # =========================================================================

    def check_permissions_module(self) -> Dict[str, Any]:
        """
        Check agent_permissions.py compatibility.
        """

        started = time.perf_counter()
        issues: List[Dict[str, Any]] = []

        try:
            module = importlib.import_module("agents.agent_permissions")
            cls = getattr(module, "AgentPermissions", None)

            if cls is None:
                issues.append(self._issue(
                    check_type=HealthCheckType.PERMISSION,
                    severity=HealthSeverity.ERROR,
                    message="AgentPermissions class missing",
                    target="agents.agent_permissions",
                ))

                return self._safe_result(
                    message="Permission module check completed",
                    data={
                        "checks": [
                            self._check(
                                check_type=HealthCheckType.PERMISSION,
                                target="agents.agent_permissions",
                                status=HealthStatus.UNHEALTHY.value,
                                success=False,
                                message="AgentPermissions class missing",
                                issues=issues,
                                started=started,
                            )
                        ]
                    },
                )

            expected_methods = [
                "_validate_task_context",
                "_requires_security_check",
                "_request_security_approval",
                "_safe_result",
                "_error_result",
            ]

            missing = [name for name in expected_methods if not hasattr(cls, name)]

            if missing:
                issues.append(self._issue(
                    check_type=HealthCheckType.PERMISSION,
                    severity=HealthSeverity.WARNING,
                    message="AgentPermissions missing some compatibility hooks",
                    target="AgentPermissions",
                    details={"missing_methods": missing},
                ))

            check = self._check(
                check_type=HealthCheckType.PERMISSION,
                target="AgentPermissions",
                status=HealthStatus.DEGRADED.value if missing else HealthStatus.HEALTHY.value,
                success=True,
                message="Permission module available",
                data={
                    "class_found": True,
                    "missing_methods": missing,
                },
                issues=issues,
                started=started,
            )

            return self._safe_result(
                message="Permission module check completed",
                data={"checks": [check]},
            )

        except Exception as exc:
            issues.append(self._issue(
                check_type=HealthCheckType.PERMISSION,
                severity=HealthSeverity.ERROR,
                message="Permission module import failed",
                target="agents.agent_permissions",
                details={"error": str(exc)},
            ))

            return self._safe_result(
                success=False,
                message="Permission module check failed",
                data={
                    "checks": [
                        self._check(
                            check_type=HealthCheckType.PERMISSION,
                            target="agents.agent_permissions",
                            status=HealthStatus.UNHEALTHY.value,
                            success=False,
                            message="Permission module failed",
                            data={"error": str(exc)},
                            issues=issues,
                            started=started,
                        )
                    ]
                },
            )

    def check_events_module(self) -> Dict[str, Any]:
        """
        Check agent_events.py compatibility.
        """

        started = time.perf_counter()
        issues: List[Dict[str, Any]] = []

        try:
            event_bus = get_agent_events()

            if event_bus is None:
                issues.append(self._issue(
                    check_type=HealthCheckType.EVENTS,
                    severity=HealthSeverity.WARNING,
                    message="AgentEvents singleton unavailable",
                    target="agent_events",
                ))

                check = self._check(
                    check_type=HealthCheckType.EVENTS,
                    target="agent_events",
                    status=HealthStatus.DEGRADED.value,
                    success=True,
                    message="AgentEvents unavailable but system can continue",
                    data={"available": False},
                    issues=issues,
                    started=started,
                )

                return self._safe_result(
                    message="Events module check completed",
                    data={"checks": [check]},
                )

            expected = [
                "publish_event",
                "send_agent_message",
                "health_check",
                "get_stats",
            ]

            missing = [name for name in expected if not hasattr(event_bus, name)]

            if missing:
                issues.append(self._issue(
                    check_type=HealthCheckType.EVENTS,
                    severity=HealthSeverity.WARNING,
                    message="AgentEvents missing expected methods",
                    target="AgentEvents",
                    details={"missing_methods": missing},
                ))

            event_health = {}
            if hasattr(event_bus, "health_check"):
                try:
                    event_health = event_bus.health_check()
                except Exception as health_exc:
                    issues.append(self._issue(
                        check_type=HealthCheckType.EVENTS,
                        severity=HealthSeverity.WARNING,
                        message="AgentEvents health_check failed",
                        target="AgentEvents",
                        details={"error": str(health_exc)},
                    ))

            check = self._check(
                check_type=HealthCheckType.EVENTS,
                target="AgentEvents",
                status=HealthStatus.DEGRADED.value if missing else HealthStatus.HEALTHY.value,
                success=True,
                message="AgentEvents module available",
                data={
                    "available": True,
                    "missing_methods": missing,
                    "event_health": event_health,
                },
                issues=issues,
                started=started,
            )

            return self._safe_result(
                message="Events module check completed",
                data={"checks": [check]},
            )

        except Exception as exc:
            issues.append(self._issue(
                check_type=HealthCheckType.EVENTS,
                severity=HealthSeverity.ERROR,
                message="Events module check failed",
                target="AgentEvents",
                details={"error": str(exc)},
            ))

            return self._safe_result(
                success=False,
                message="Events module check failed",
                data={
                    "checks": [
                        self._check(
                            check_type=HealthCheckType.EVENTS,
                            target="AgentEvents",
                            status=HealthStatus.UNHEALTHY.value,
                            success=False,
                            message="AgentEvents failed",
                            data={"error": str(exc)},
                            issues=issues,
                            started=started,
                        )
                    ]
                },
            )

    # =========================================================================
    # Registry / Loader / Router
    # =========================================================================

    def check_registry_loader_router(self) -> Dict[str, Any]:
        """
        Check Registry, Loader, and Router compatibility.
        """

        modules = [
            ("agents.registry", "AgentRegistry", HealthCheckType.REGISTRY),
            ("agents.agent_loader", "AgentLoader", HealthCheckType.LOADER),
            ("agents.agent_router", "AgentRouter", HealthCheckType.ROUTER),
        ]

        checks: List[Dict[str, Any]] = []

        for module_name, class_name, check_type in modules:
            started = time.perf_counter()
            issues: List[Dict[str, Any]] = []

            try:
                module = importlib.import_module(module_name)
                cls = getattr(module, class_name, None)

                if cls is None:
                    issues.append(self._issue(
                        check_type=check_type,
                        severity=HealthSeverity.ERROR,
                        message=f"{class_name} class missing",
                        target=module_name,
                    ))

                    checks.append(self._check(
                        check_type=check_type,
                        target=class_name,
                        status=HealthStatus.UNHEALTHY.value,
                        success=False,
                        message=f"{class_name} missing",
                        issues=issues,
                        started=started,
                    ))
                    continue

                public_methods = [
                    name for name, value in inspect.getmembers(cls)
                    if not name.startswith("_") and callable(value)
                ]

                checks.append(self._check(
                    check_type=check_type,
                    target=class_name,
                    status=HealthStatus.HEALTHY.value,
                    success=True,
                    message=f"{class_name} available",
                    data={
                        "module": module_name,
                        "class": class_name,
                        "public_methods": public_methods,
                    },
                    issues=issues,
                    started=started,
                ))

            except Exception as exc:
                issues.append(self._issue(
                    check_type=check_type,
                    severity=HealthSeverity.ERROR,
                    message=f"{module_name} check failed",
                    target=module_name,
                    details={"error": str(exc)},
                ))

                checks.append(self._check(
                    check_type=check_type,
                    target=module_name,
                    status=HealthStatus.UNHEALTHY.value,
                    success=False,
                    message=f"{module_name} failed",
                    data={"error": str(exc)},
                    issues=issues,
                    started=started,
                ))

        return self._safe_result(
            message="Registry/Loader/Router checks completed",
            data={
                "checks": checks,
                "count": len(checks),
            },
        )

    # =========================================================================
    # Agent Availability
    # =========================================================================

    def check_expected_agents(
        self,
        expected_agents: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        """
        Check expected William/Jarvis agent module availability.

        Expected agent names:
            Voice, System, Browser, Code, Memory, Security, Verification,
            Visual, Workflow, Hologram, Call, Business, Finance, Creator
        """

        agents = list(expected_agents or self.EXPECTED_AGENT_NAMES)
        checks: List[Dict[str, Any]] = []

        for agent in agents:
            started = time.perf_counter()
            issues: List[Dict[str, Any]] = []

            possible_modules = [
                f"agents.{agent}_agent",
                f"agents.{agent}.{agent}_agent",
                f"agents.{agent}",
            ]

            found_module = None
            import_error = None

            for module_name in possible_modules:
                try:
                    found_module = importlib.import_module(module_name)
                    break
                except Exception as exc:
                    import_error = str(exc)

            if found_module is None:
                issues.append(self._issue(
                    check_type=HealthCheckType.AGENT,
                    severity=HealthSeverity.WARNING,
                    message=f"Expected agent module not found: {agent}",
                    target=agent,
                    details={
                        "tried_modules": possible_modules,
                        "last_error": import_error,
                    },
                ))

                checks.append(self._check(
                    check_type=HealthCheckType.AGENT,
                    target=agent,
                    status=HealthStatus.MISSING.value,
                    success=True,
                    message="Expected agent not created yet",
                    data={
                        "agent": agent,
                        "available": False,
                        "tried_modules": possible_modules,
                    },
                    issues=issues,
                    started=started,
                ))
                continue

            classes = [
                name for name, value in inspect.getmembers(found_module)
                if inspect.isclass(value)
            ]

            checks.append(self._check(
                check_type=HealthCheckType.AGENT,
                target=agent,
                status=HealthStatus.HEALTHY.value,
                success=True,
                message="Agent module available",
                data={
                    "agent": agent,
                    "available": True,
                    "module": getattr(found_module, "__name__", None),
                    "file": getattr(found_module, "__file__", None),
                    "classes": classes,
                },
                issues=issues,
                started=started,
            ))

        return self._safe_result(
            message="Expected agent checks completed",
            data={
                "checks": checks,
                "count": len(checks),
            },
        )

    # =========================================================================
    # System Environment
    # =========================================================================

    def check_system_environment(self) -> Dict[str, Any]:
        """
        Check safe system-level environment facts.

        This does not read secrets.
        """

        started = time.perf_counter()
        issues: List[Dict[str, Any]] = []

        python_version = sys.version_info
        is_supported_python = python_version.major == 3 and python_version.minor >= 9

        if not is_supported_python:
            issues.append(self._issue(
                check_type=HealthCheckType.SYSTEM,
                severity=HealthSeverity.WARNING,
                message="Python 3.9+ recommended",
                target="python",
                details={
                    "current": platform.python_version(),
                    "recommended": "3.9+",
                },
            ))

        agents_dir = self.project_root / "agents"
        if not agents_dir.exists():
            issues.append(self._issue(
                check_type=HealthCheckType.SYSTEM,
                severity=HealthSeverity.ERROR,
                message="agents directory missing",
                target="agents",
                details={"path": str(agents_dir)},
            ))

        check = self._check(
            check_type=HealthCheckType.SYSTEM,
            target="environment",
            status=HealthStatus.DEGRADED.value if issues else HealthStatus.HEALTHY.value,
            success=True,
            message="System environment checked",
            data={
                "python_version": platform.python_version(),
                "python_executable": sys.executable,
                "platform": platform.platform(),
                "system": platform.system(),
                "machine": platform.machine(),
                "project_root": str(self.project_root),
                "agents_dir_exists": agents_dir.exists(),
                "cwd": os.getcwd(),
            },
            issues=issues,
            started=started,
        )

        return self._safe_result(
            message="System environment check completed",
            data={"check": check},
        )

    # =========================================================================
    # Custom Checks
    # =========================================================================

    def run_custom_check(
        self,
        name: str,
        check_function: Any,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Run a safe custom health check function.

        The function must be callable and should return dict/bool/string.
        """

        metadata = metadata or {}
        started = time.perf_counter()

        if not callable(check_function):
            return self._error_result(
                message="check_function must be callable",
                error="invalid_check_function",
            )

        context = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            require_user=False,
            require_workspace=False,
        )
        if not context.get("success"):
            return context

        try:
            raw = check_function()

            if isinstance(raw, dict):
                success = bool(raw.get("success", True))
                message = str(raw.get("message", "Custom check completed"))
                data = raw.get("data", raw)
            elif isinstance(raw, bool):
                success = raw
                message = "Custom check passed" if raw else "Custom check failed"
                data = {"result": raw}
            else:
                success = True
                message = str(raw)
                data = {"result": raw}

            issues: List[Dict[str, Any]] = []
            if not success:
                issues.append(self._issue(
                    check_type=HealthCheckType.CUSTOM,
                    severity=HealthSeverity.WARNING,
                    message=message,
                    target=name,
                ))

            check = self._check(
                check_type=HealthCheckType.CUSTOM,
                target=name,
                status=HealthStatus.HEALTHY.value if success else HealthStatus.DEGRADED.value,
                success=success,
                message=message,
                data=data if isinstance(data, dict) else {"data": data},
                issues=issues,
                started=started,
                metadata=metadata,
            )

            return self._safe_result(
                success=success,
                message="Custom check completed",
                data={"check": check},
            )

        except Exception as exc:
            issue = self._issue(
                check_type=HealthCheckType.CUSTOM,
                severity=HealthSeverity.ERROR,
                message=f"Custom check failed: {name}",
                target=name,
                details={"error": str(exc)},
            )

            check = self._check(
                check_type=HealthCheckType.CUSTOM,
                target=name,
                status=HealthStatus.UNHEALTHY.value,
                success=False,
                message="Custom check failed",
                data={"error": str(exc)},
                issues=[issue],
                started=started,
                metadata=metadata,
            )

            return self._safe_result(
                success=False,
                message="Custom check failed",
                data={"check": check},
                error=str(exc),
            )

    # =========================================================================
    # Snapshot Builder
    # =========================================================================

    def _build_snapshot(
        self,
        checks: List[Dict[str, Any]],
        duration_ms: float,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Build dashboard/API-ready health snapshot.
        """

        metadata = metadata or {}

        clean_checks = [check for check in checks if check]
        total = len(clean_checks)

        failed = 0
        warning = 0
        passed = 0
        critical_issues = 0
        all_issues: List[Dict[str, Any]] = []

        for check in clean_checks:
            status = check.get("status")
            success = bool(check.get("success"))

            if success and status == HealthStatus.HEALTHY.value:
                passed += 1
            elif status in {HealthStatus.DEGRADED.value, HealthStatus.MISSING.value}:
                warning += 1
            elif not success or status == HealthStatus.UNHEALTHY.value:
                failed += 1

            for issue in check.get("issues", []):
                all_issues.append(issue)
                if issue.get("severity") == HealthSeverity.CRITICAL.value:
                    critical_issues += 1

        if total == 0:
            score = 0.0
            overall = HealthStatus.UNKNOWN.value
        else:
            weighted_penalty = (failed * 20) + (warning * 7) + (critical_issues * 25)
            score = max(0.0, min(100.0, 100.0 - weighted_penalty))

            if critical_issues > 0 or failed >= max(1, total // 3):
                overall = HealthStatus.UNHEALTHY.value
            elif failed > 0 or warning > 0 or score < 90:
                overall = HealthStatus.DEGRADED.value
            else:
                overall = HealthStatus.HEALTHY.value

        snapshot = AgentHealthSnapshot(
            snapshot_id=self.new_id("snapshot"),
            overall_status=overall,
            score=round(score, 2),
            total_checks=total,
            passed_checks=passed,
            failed_checks=failed,
            warning_checks=warning,
            critical_issues=critical_issues,
            checks=clean_checks,
            issues=all_issues,
            metadata={
                "agent": self.agent_name,
                "agent_id": self.agent_id,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "duration_ms": round(duration_ms, 2),
                "project_root": str(self.project_root),
                **metadata,
            },
        )

        return asdict(snapshot)

    def _check(
        self,
        check_type: Union[str, HealthCheckType],
        target: str,
        status: Union[str, HealthStatus],
        success: bool,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        issues: Optional[List[Dict[str, Any]]] = None,
        started: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Build one standard health check result.
        """

        duration_ms = 0.0
        if started is not None:
            duration_ms = (time.perf_counter() - started) * 1000

        result = HealthCheckResult(
            check_id=self.new_id("check"),
            check_type=self._enum_value(check_type),
            target=target,
            status=self._enum_value(status),
            success=bool(success),
            message=message,
            data=data or {},
            issues=issues or [],
            duration_ms=round(duration_ms, 2),
            metadata=metadata or {},
        )

        return asdict(result)

    def _issue(
        self,
        check_type: Union[str, HealthCheckType],
        severity: Union[str, HealthSeverity],
        message: str,
        target: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Build one standard health issue.
        """

        issue = HealthIssue(
            issue_id=self.new_id("issue"),
            check_type=self._enum_value(check_type),
            severity=self._enum_value(severity),
            message=message,
            target=target,
            details=details or {},
        )

        return asdict(issue)

    # =========================================================================
    # Utility
    # =========================================================================

    @staticmethod
    def _enum_value(value: Any) -> str:
        if isinstance(value, Enum):
            return str(value.value)
        if value is None:
            return ""
        return str(value)

    @staticmethod
    def _is_empty(value: Any) -> bool:
        return value is None or value == ""

    @staticmethod
    def _is_valid_context_value(value: Any) -> bool:
        if isinstance(value, int):
            return value >= 0
        if isinstance(value, str):
            if not value.strip():
                return False
            if len(value) > 128:
                return False
            return True
        return False


# =============================================================================
# Global Singleton Helpers
# =============================================================================

_GLOBAL_AGENT_HEALTH: Optional[AgentHealth] = None


def get_agent_health() -> AgentHealth:
    """
    Get global AgentHealth singleton.

    Useful for dashboard/API routes, Master Agent, Registry, Loader,
    Router, and future monitoring services.
    """

    global _GLOBAL_AGENT_HEALTH

    if _GLOBAL_AGENT_HEALTH is None:
        _GLOBAL_AGENT_HEALTH = AgentHealth()

    return _GLOBAL_AGENT_HEALTH


def set_agent_health(agent_health: AgentHealth) -> Dict[str, Any]:
    """
    Override global AgentHealth singleton.

    Useful for tests or production dependency injection.
    """

    global _GLOBAL_AGENT_HEALTH

    if not isinstance(agent_health, AgentHealth):
        return {
            "success": False,
            "message": "agent_health must be an AgentHealth instance",
            "data": {},
            "error": "invalid_agent_health_instance",
            "metadata": {
                "timestamp": AgentHealth.utc_now(),
            },
        }

    _GLOBAL_AGENT_HEALTH = agent_health

    return {
        "success": True,
        "message": "Global AgentHealth instance set",
        "data": {
            "agent_name": agent_health.agent_name,
            "agent_id": agent_health.agent_id,
        },
        "error": None,
        "metadata": {
            "timestamp": AgentHealth.utc_now(),
        },
    }


def run_health_check(*args: Any, **kwargs: Any) -> Dict[str, Any]:
    """
    Convenience global full health check function.
    """

    return get_agent_health().run_full_health_check(*args, **kwargs)


def quick_health_check(*args: Any, **kwargs: Any) -> Dict[str, Any]:
    """
    Convenience global quick health check function.
    """

    return get_agent_health().quick_health_check(*args, **kwargs)


# =============================================================================
# Self-Test
# =============================================================================

def _self_test() -> Dict[str, Any]:
    """
    Lightweight self-test.

    Run:
        python agents/agent_health.py
    """

    health = AgentHealth(enable_event_emission=False)

    quick = health.quick_health_check()
    full = health.run_full_health_check(
        include_optional=True,
        include_agent_scan=True,
        include_dependencies=True,
        include_permissions=True,
    )

    return {
        "success": bool(quick.get("success")) and bool(full.get("success")),
        "message": "AgentHealth self-test completed",
        "data": {
            "quick_status": quick.get("data", {}).get("overall_status"),
            "quick_score": quick.get("data", {}).get("score"),
            "full_status": full.get("data", {}).get("overall_status"),
            "full_score": full.get("data", {}).get("score"),
            "quick": quick,
            "full": full,
        },
        "error": None,
        "metadata": {
            "timestamp": AgentHealth.utc_now(),
        },
    }


if __name__ == "__main__":
    import json

    print(json.dumps(_self_test(), indent=2, default=str))


"""
Agent/Module: Global Agent Infrastructure Files
File Completed: agent_health.py
Completion: 88.9%
Completed Files: ['base_agent.py', 'registry.py', 'agent_loader.py', 'agent_router.py', 'agent_manifest.py', 'agent_permissions.py', 'agent_events.py', 'agent_health.py']
Remaining Files: ['agent_config.py']
Next Recommended File: agents/agent_config.py
FILE COMPLETE
"""