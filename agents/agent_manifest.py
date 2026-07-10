"""
agents/agent_manifest.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Stores metadata, capabilities, versions, dependencies, status, and file counts
    for each agent in the William / Jarvis multi-agent SaaS architecture.

This file is designed to be:
    - Import-safe even when future modules are missing
    - Compatible with BaseAgent, Agent Registry, Agent Loader, Agent Router, Master Agent
    - SaaS-ready with user_id and workspace_id validation
    - Dashboard/API-ready with structured dict responses
    - Safe-by-default for permissions, audit, memory, and verification flows

Architecture:
    William contains a Master Agent plus 14 core agents:
        Voice, System, Browser, Code, Memory, Security, Verification, Visual,
        Workflow, Hologram, Call, Business, Finance, Creator.

Important:
    This file does NOT execute real agent actions.
    It only stores, validates, updates, exports, and reports agent manifest metadata.
"""

from __future__ import annotations

import copy
import json
import logging
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union


# ============================================================
# Safe Optional Imports
# ============================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps agent_manifest.py import-safe before base_agent.py
        or other future infrastructure files are available.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.name = kwargs.get("name", self.__class__.__name__)
            self.logger = logging.getLogger(self.name)


try:
    from agents.registry import AgentRegistry  # type: ignore
except Exception:
    AgentRegistry = None  # type: ignore


# ============================================================
# Logging
# ============================================================

logger = logging.getLogger("William.AgentManifest")
if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


# ============================================================
# Enums
# ============================================================

class AgentStatus(str, Enum):
    """Supported lifecycle states for William agents."""

    PLANNED = "planned"
    ACTIVE = "active"
    INACTIVE = "inactive"
    DISABLED = "disabled"
    DEGRADED = "degraded"
    MAINTENANCE = "maintenance"
    ERROR = "error"
    DEPRECATED = "deprecated"


class AgentRiskLevel(str, Enum):
    """Risk level used by Security Agent and permission checks."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AgentCategory(str, Enum):
    """High-level agent groups for dashboard and routing."""

    CORE = "core"
    SYSTEM = "system"
    AUTOMATION = "automation"
    INTELLIGENCE = "intelligence"
    COMMUNICATION = "communication"
    FINANCE = "finance"
    CREATIVE = "creative"
    SECURITY = "security"
    EXPERIMENTAL = "experimental"


# ============================================================
# Dataclasses
# ============================================================

@dataclass
class AgentFileCount:
    """
    Tracks planned, completed, and remaining files for an agent/module.
    """

    total_files: int = 0
    completed_files: int = 0
    remaining_files: int = 0
    completed_file_names: List[str] = field(default_factory=list)
    remaining_file_names: List[str] = field(default_factory=list)

    def completion_percent(self) -> float:
        """Return completion percentage rounded to one decimal place."""
        if self.total_files <= 0:
            return 0.0
        value = (self.completed_files / self.total_files) * 100
        return round(value, 1)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize file count metadata."""
        return {
            "total_files": self.total_files,
            "completed_files": self.completed_files,
            "remaining_files": self.remaining_files,
            "completed_file_names": list(self.completed_file_names),
            "remaining_file_names": list(self.remaining_file_names),
            "completion_percent": self.completion_percent(),
        }


@dataclass
class AgentDependency:
    """
    Defines dependency relationships for loading, routing, and health checks.
    """

    name: str
    required: bool = True
    min_version: Optional[str] = None
    reason: Optional[str] = None
    status: str = "unknown"

    def to_dict(self) -> Dict[str, Any]:
        """Serialize dependency metadata."""
        return asdict(self)


@dataclass
class AgentCapability:
    """
    Defines an individual capability exposed by an agent.
    """

    key: str
    description: str
    enabled: bool = True
    requires_security: bool = False
    risk_level: AgentRiskLevel = AgentRiskLevel.LOW
    permissions: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize capability metadata."""
        return {
            "key": self.key,
            "description": self.description,
            "enabled": self.enabled,
            "requires_security": self.requires_security,
            "risk_level": self.risk_level.value,
            "permissions": list(self.permissions),
            "tags": list(self.tags),
        }


@dataclass
class AgentManifestEntry:
    """
    Complete manifest entry for one William/Jarvis agent.
    """

    agent_key: str
    display_name: str
    description: str
    category: AgentCategory
    version: str = "1.0.0"
    status: AgentStatus = AgentStatus.PLANNED
    module_path: Optional[str] = None
    class_name: Optional[str] = None
    owner: str = "Digital Promotix"
    capabilities: List[AgentCapability] = field(default_factory=list)
    dependencies: List[AgentDependency] = field(default_factory=list)
    file_count: AgentFileCount = field(default_factory=AgentFileCount)
    supports_user_context: bool = True
    supports_workspace_context: bool = True
    requires_security_agent: bool = False
    supports_memory_agent: bool = True
    supports_verification_agent: bool = True
    supports_audit_logs: bool = True
    supports_dashboard: bool = True
    is_plugin_style: bool = True
    tags: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: AgentManifest.utcnow())
    updated_at: str = field(default_factory=lambda: AgentManifest.utcnow())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def capability_keys(self) -> List[str]:
        """Return enabled and disabled capability keys."""
        return [cap.key for cap in self.capabilities]

    def enabled_capability_keys(self) -> List[str]:
        """Return enabled capability keys only."""
        return [cap.key for cap in self.capabilities if cap.enabled]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize manifest entry to dictionary."""
        return {
            "agent_key": self.agent_key,
            "display_name": self.display_name,
            "description": self.description,
            "category": self.category.value,
            "version": self.version,
            "status": self.status.value,
            "module_path": self.module_path,
            "class_name": self.class_name,
            "owner": self.owner,
            "capabilities": [cap.to_dict() for cap in self.capabilities],
            "dependencies": [dep.to_dict() for dep in self.dependencies],
            "file_count": self.file_count.to_dict(),
            "supports_user_context": self.supports_user_context,
            "supports_workspace_context": self.supports_workspace_context,
            "requires_security_agent": self.requires_security_agent,
            "supports_memory_agent": self.supports_memory_agent,
            "supports_verification_agent": self.supports_verification_agent,
            "supports_audit_logs": self.supports_audit_logs,
            "supports_dashboard": self.supports_dashboard,
            "is_plugin_style": self.is_plugin_style,
            "tags": list(self.tags),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "metadata": copy.deepcopy(self.metadata),
        }


# ============================================================
# Agent Manifest
# ============================================================

class AgentManifest(BaseAgent):
    """
    AgentManifest manages all metadata for William/Jarvis agents.

    It connects to:
        - Master Agent:
            Provides routing metadata and capability discovery.
        - Agent Registry:
            Provides registry-ready manifest exports.
        - Agent Loader:
            Provides module path, class name, dependencies, and status.
        - Agent Router:
            Provides capability-to-agent matching.
        - Security Agent:
            Marks risky capabilities and security-required agents.
        - Memory Agent:
            Prepares useful context for memory-safe storage.
        - Verification Agent:
            Prepares verification payloads after manifest operations.
        - Dashboard/API:
            Exposes summaries, completion percentage, health, and status.
    """

    SYSTEM_NAME = "William / Jarvis Multi-Agent AI SaaS System"
    OWNER = "Digital Promotix"
    MANIFEST_VERSION = "1.0.0"

    CORE_AGENT_KEYS = [
        "master",
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

    def __init__(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        registry: Optional[Any] = None,
        auto_seed: bool = True,
    ) -> None:
        super().__init__(name="AgentManifest")

        self.user_id = str(user_id) if user_id is not None else None
        self.workspace_id = str(workspace_id) if workspace_id is not None else None
        self.registry = registry

        self._manifest: Dict[str, AgentManifestEntry] = {}
        self._events: List[Dict[str, Any]] = []
        self._audit_logs: List[Dict[str, Any]] = []

        if auto_seed:
            self.seed_default_agents()

    # ========================================================
    # Time / IDs
    # ========================================================

    @staticmethod
    def utcnow() -> str:
        """Return current UTC ISO timestamp."""
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def new_event_id() -> str:
        """Return a unique event ID."""
        return f"evt_{uuid.uuid4().hex}"

    @staticmethod
    def normalize_key(value: str) -> str:
        """Normalize agent/capability keys."""
        return str(value).strip().lower().replace(" ", "_").replace("-", "_")

    # ========================================================
    # Structured Result Helpers
    # ========================================================

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard success response."""
        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": {
                "system": self.SYSTEM_NAME,
                "manifest_version": self.MANIFEST_VERSION,
                "timestamp": self.utcnow(),
                "user_id": self.user_id,
                "workspace_id": self.workspace_id,
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
        """Return standard error response."""
        err = str(error) if error is not None else message
        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": err,
            "metadata": {
                "system": self.SYSTEM_NAME,
                "manifest_version": self.MANIFEST_VERSION,
                "timestamp": self.utcnow(),
                "user_id": self.user_id,
                "workspace_id": self.workspace_id,
                **(metadata or {}),
            },
        }

    # ========================================================
    # SaaS Context / Safety Hooks
    # ========================================================

    def _validate_task_context(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        require_context: bool = False,
    ) -> Dict[str, Any]:
        """
        Validate user/workspace context for SaaS isolation.

        Manifest read operations can work globally.
        User-specific updates should include user_id and workspace_id.
        """

        resolved_user_id = str(user_id) if user_id is not None else self.user_id
        resolved_workspace_id = (
            str(workspace_id) if workspace_id is not None else self.workspace_id
        )

        if require_context and not resolved_user_id:
            return self._error_result(
                "Missing user_id for user-specific manifest operation.",
                metadata={"hook": "_validate_task_context"},
            )

        if require_context and not resolved_workspace_id:
            return self._error_result(
                "Missing workspace_id for workspace-specific manifest operation.",
                metadata={"hook": "_validate_task_context"},
            )

        return self._safe_result(
            "Task context validated.",
            data={
                "user_id": resolved_user_id,
                "workspace_id": resolved_workspace_id,
                "require_context": require_context,
            },
            metadata={"hook": "_validate_task_context"},
        )

    def _requires_security_check(
        self,
        operation: str,
        agent_key: Optional[str] = None,
        capability_key: Optional[str] = None,
    ) -> bool:
        """
        Decide whether a manifest operation requires Security Agent approval.

        Security is required for:
            - disabling security/verification/memory agents
            - changing high-risk capability metadata
            - deleting manifest entries
            - changing permission-related metadata
        """

        operation_key = self.normalize_key(operation)

        high_risk_operations = {
            "delete_agent",
            "remove_agent",
            "disable_agent",
            "update_permissions",
            "update_security",
            "set_requires_security",
            "bulk_import",
            "registry_sync_write",
        }

        sensitive_agents = {"security", "verification", "memory", "system", "browser", "call", "finance"}

        if operation_key in high_risk_operations:
            return True

        if agent_key and self.normalize_key(agent_key) in sensitive_agents:
            if operation_key in {"disable", "delete", "remove", "update", "status_change"}:
                return True

        if agent_key and capability_key:
            entry = self._manifest.get(self.normalize_key(agent_key))
            if entry:
                cap = self._find_capability(entry, capability_key)
                if cap and (cap.requires_security or cap.risk_level in {AgentRiskLevel.HIGH, AgentRiskLevel.CRITICAL}):
                    return True

        return False

    def _request_security_approval(
        self,
        operation: str,
        agent_key: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare a Security Agent approval request.

        This file does not call or execute Security Agent directly.
        It returns a structured payload for Master Agent / Security Agent.
        """

        approval_payload = {
            "approval_id": f"sec_{uuid.uuid4().hex}",
            "operation": operation,
            "agent_key": agent_key,
            "payload": payload or {},
            "risk_reason": "Manifest operation may affect routing, permissions, safety, or SaaS isolation.",
            "requested_at": self.utcnow(),
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "target_agent": "security",
            "status": "approval_required",
        }

        self._emit_agent_event(
            event_type="security_approval_requested",
            agent_key=agent_key or "manifest",
            payload=approval_payload,
        )

        return self._safe_result(
            "Security approval payload prepared.",
            data=approval_payload,
            metadata={"hook": "_request_security_approval"},
        )

    def _prepare_verification_payload(
        self,
        operation: str,
        result: Dict[str, Any],
        agent_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload after a manifest operation.
        """

        payload = {
            "verification_id": f"ver_{uuid.uuid4().hex}",
            "target_agent": "verification",
            "source_module": "agents.agent_manifest",
            "operation": operation,
            "agent_key": agent_key,
            "result_success": bool(result.get("success")),
            "result_message": result.get("message"),
            "result_error": result.get("error"),
            "timestamp": self.utcnow(),
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "checks": {
                "manifest_import_safe": True,
                "structured_result": all(
                    key in result for key in ["success", "message", "data", "error", "metadata"]
                ),
                "saas_context_attached": True,
            },
        }

        return payload

    def _prepare_memory_payload(
        self,
        operation: str,
        agent_key: Optional[str] = None,
        summary: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent-compatible payload.

        No sensitive secrets are included.
        """

        return {
            "memory_id": f"mem_{uuid.uuid4().hex}",
            "target_agent": "memory",
            "source_module": "agents.agent_manifest",
            "operation": operation,
            "agent_key": agent_key,
            "summary": summary or f"Manifest operation completed: {operation}",
            "safe_to_store": True,
            "contains_secret": False,
            "timestamp": self.utcnow(),
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "data": data or {},
        }

    def _emit_agent_event(
        self,
        event_type: str,
        agent_key: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Emit an internal manifest event.

        Later this can connect to agents/agent_events.py, WebSocket dashboard,
        FastAPI event streams, or audit pipelines.
        """

        event = {
            "event_id": self.new_event_id(),
            "event_type": event_type,
            "agent_key": self.normalize_key(agent_key),
            "payload": payload or {},
            "created_at": self.utcnow(),
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "source": "AgentManifest",
        }

        self._events.append(event)
        logger.info("Agent manifest event: %s | %s", event_type, agent_key)
        return event

    def _log_audit_event(
        self,
        action: str,
        agent_key: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        risk_level: AgentRiskLevel = AgentRiskLevel.LOW,
    ) -> Dict[str, Any]:
        """
        Record audit log metadata.

        Later this can connect to database-backed audit logs.
        """

        audit = {
            "audit_id": f"audit_{uuid.uuid4().hex}",
            "action": action,
            "agent_key": self.normalize_key(agent_key) if agent_key else None,
            "details": details or {},
            "risk_level": risk_level.value,
            "created_at": self.utcnow(),
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "source": "AgentManifest",
        }

        self._audit_logs.append(audit)
        logger.info("Audit event: %s | %s", action, agent_key or "manifest")
        return audit

    # ========================================================
    # Default Agent Seed
    # ========================================================

    def seed_default_agents(self) -> Dict[str, Any]:
        """
        Seed the default William/Jarvis agents into the manifest.

        This can run safely multiple times.
        Existing keys are overwritten with current defaults.
        """

        defaults = self._build_default_manifest_entries()

        for entry in defaults:
            self._manifest[entry.agent_key] = entry

        result = self._safe_result(
            "Default William/Jarvis agent manifest seeded.",
            data={
                "agent_count": len(self._manifest),
                "agent_keys": sorted(self._manifest.keys()),
            },
        )

        self._emit_agent_event(
            event_type="manifest_seeded",
            agent_key="manifest",
            payload={"agent_count": len(self._manifest)},
        )

        return result

    def _build_default_manifest_entries(self) -> List[AgentManifestEntry]:
        """Build default manifest entries for Master Agent plus 14 agents."""

        security_dependency = AgentDependency(
            name="security",
            required=True,
            min_version="1.0.0",
            reason="Sensitive operations must go through Security Agent.",
            status="expected",
        )

        verification_dependency = AgentDependency(
            name="verification",
            required=True,
            min_version="1.0.0",
            reason="Completed actions should prepare Verification Agent payloads.",
            status="expected",
        )

        memory_dependency = AgentDependency(
            name="memory",
            required=False,
            min_version="1.0.0",
            reason="Useful safe context can be sent to Memory Agent.",
            status="expected",
        )

        return [
            AgentManifestEntry(
                agent_key="master",
                display_name="Master Agent",
                description="Central orchestrator that routes user tasks across all William/Jarvis agents.",
                category=AgentCategory.CORE,
                status=AgentStatus.ACTIVE,
                module_path="agents.master_agent",
                class_name="MasterAgent",
                capabilities=[
                    AgentCapability(
                        key="route_tasks",
                        description="Route tasks to the correct specialist agent.",
                        enabled=True,
                        requires_security=False,
                        risk_level=AgentRiskLevel.MEDIUM,
                        permissions=["agent.route"],
                        tags=["routing", "orchestration"],
                    ),
                    AgentCapability(
                        key="coordinate_agents",
                        description="Coordinate multi-agent workflows and collect structured outputs.",
                        enabled=True,
                        risk_level=AgentRiskLevel.MEDIUM,
                        permissions=["agent.coordinate"],
                        tags=["workflow", "coordination"],
                    ),
                ],
                dependencies=[security_dependency, verification_dependency, memory_dependency],
                file_count=AgentFileCount(total_files=0, completed_files=0, remaining_files=0),
                requires_security_agent=True,
                tags=["core", "router", "orchestrator"],
            ),
            AgentManifestEntry(
                agent_key="voice",
                display_name="Voice Agent",
                description="Handles wake word, speech-to-text, text-to-speech, device stream, interruptions, and voice UX.",
                category=AgentCategory.COMMUNICATION,
                status=AgentStatus.PLANNED,
                module_path="agents.voice_agent.voice_agent",
                class_name="VoiceAgent",
                capabilities=[
                    AgentCapability("wake_word_detection", "Detect wake words such as William.", True, False, AgentRiskLevel.LOW, ["voice.listen"], ["voice"]),
                    AgentCapability("speech_to_text", "Convert speech input to text.", True, False, AgentRiskLevel.LOW, ["voice.stt"], ["stt"]),
                    AgentCapability("text_to_speech", "Convert agent responses into speech.", True, False, AgentRiskLevel.LOW, ["voice.tts"], ["tts"]),
                    AgentCapability("interruption_handling", "Handle user interruptions during speech playback.", True, False, AgentRiskLevel.MEDIUM, ["voice.interrupt"], ["conversation"]),
                ],
                dependencies=[security_dependency, memory_dependency],
                file_count=AgentFileCount(total_files=7, completed_files=0, remaining_files=7),
                tags=["voice", "stt", "tts", "wake-word"],
            ),
            AgentManifestEntry(
                agent_key="system",
                display_name="System Agent",
                description="Manages safe device/system-level operations, diagnostics, app control, and OS interactions.",
                category=AgentCategory.SYSTEM,
                status=AgentStatus.PLANNED,
                module_path="agents.system_agent.system_agent",
                class_name="SystemAgent",
                capabilities=[
                    AgentCapability("system_diagnostics", "Read safe diagnostics and device status.", True, True, AgentRiskLevel.HIGH, ["system.read"], ["diagnostics"]),
                    AgentCapability("app_control", "Safely control apps where permission is approved.", True, True, AgentRiskLevel.HIGH, ["system.app_control"], ["apps"]),
                    AgentCapability("device_integration", "Support connected devices through approved channels.", True, True, AgentRiskLevel.HIGH, ["system.devices"], ["devices"]),
                ],
                dependencies=[security_dependency, verification_dependency],
                file_count=AgentFileCount(total_files=0, completed_files=0, remaining_files=0),
                requires_security_agent=True,
                tags=["system", "device", "os"],
            ),
            AgentManifestEntry(
                agent_key="browser",
                display_name="Browser Agent",
                description="Handles web browsing, safe research, page reading, browser workflows, and web automation.",
                category=AgentCategory.AUTOMATION,
                status=AgentStatus.PLANNED,
                module_path="agents.browser_agent.browser_agent",
                class_name="BrowserAgent",
                capabilities=[
                    AgentCapability("web_research", "Research web pages and summarize findings.", True, False, AgentRiskLevel.MEDIUM, ["browser.read"], ["research"]),
                    AgentCapability("browser_automation", "Automate browser actions with permission gating.", True, True, AgentRiskLevel.HIGH, ["browser.automate"], ["automation"]),
                ],
                dependencies=[security_dependency, verification_dependency, memory_dependency],
                file_count=AgentFileCount(total_files=0, completed_files=0, remaining_files=0),
                requires_security_agent=True,
                tags=["browser", "web", "research"],
            ),
            AgentManifestEntry(
                agent_key="code",
                display_name="Code Agent",
                description="Generates, reviews, repairs, explains, and tests code safely.",
                category=AgentCategory.INTELLIGENCE,
                status=AgentStatus.PLANNED,
                module_path="agents.code_agent.code_agent",
                class_name="CodeAgent",
                capabilities=[
                    AgentCapability("generate_code", "Generate production-ready code files.", True, False, AgentRiskLevel.MEDIUM, ["code.generate"], ["coding"]),
                    AgentCapability("review_code", "Review code for bugs, security, and architecture issues.", True, False, AgentRiskLevel.MEDIUM, ["code.review"], ["review"]),
                    AgentCapability("safe_execution_plan", "Prepare safe execution and testing plans without destructive action.", True, True, AgentRiskLevel.HIGH, ["code.plan"], ["testing"]),
                ],
                dependencies=[security_dependency, verification_dependency, memory_dependency],
                file_count=AgentFileCount(total_files=0, completed_files=0, remaining_files=0),
                requires_security_agent=True,
                tags=["code", "developer", "testing"],
            ),
            AgentManifestEntry(
                agent_key="memory",
                display_name="Memory Agent",
                description="Stores, retrieves, scopes, and manages safe user/workspace memory.",
                category=AgentCategory.CORE,
                status=AgentStatus.PLANNED,
                module_path="agents.memory_agent.memory_agent",
                class_name="MemoryAgent",
                capabilities=[
                    AgentCapability("store_memory", "Store safe user/workspace-scoped memory.", True, True, AgentRiskLevel.HIGH, ["memory.write"], ["memory"]),
                    AgentCapability("retrieve_memory", "Retrieve user/workspace-scoped memory.", True, True, AgentRiskLevel.HIGH, ["memory.read"], ["memory"]),
                    AgentCapability("forget_memory", "Delete user/workspace memory by request.", True, True, AgentRiskLevel.HIGH, ["memory.delete"], ["privacy"]),
                ],
                dependencies=[security_dependency, verification_dependency],
                file_count=AgentFileCount(total_files=0, completed_files=0, remaining_files=0),
                requires_security_agent=True,
                tags=["memory", "privacy", "saas-isolation"],
            ),
            AgentManifestEntry(
                agent_key="security",
                display_name="Security Agent",
                description="Handles permissions, approval gates, risk scoring, policy checks, and sensitive action control.",
                category=AgentCategory.SECURITY,
                status=AgentStatus.PLANNED,
                module_path="agents.security_agent.security_agent",
                class_name="SecurityAgent",
                capabilities=[
                    AgentCapability("permission_check", "Check user/workspace permissions before sensitive actions.", True, False, AgentRiskLevel.CRITICAL, ["security.check"], ["security"]),
                    AgentCapability("risk_score", "Score actions by risk before execution.", True, False, AgentRiskLevel.CRITICAL, ["security.risk"], ["risk"]),
                    AgentCapability("approval_gate", "Approve, reject, or escalate sensitive actions.", True, False, AgentRiskLevel.CRITICAL, ["security.approve"], ["approval"]),
                ],
                dependencies=[],
                file_count=AgentFileCount(total_files=0, completed_files=0, remaining_files=0),
                requires_security_agent=False,
                supports_memory_agent=False,
                tags=["security", "permissions", "policy"],
            ),
            AgentManifestEntry(
                agent_key="verification",
                display_name="Verification Agent",
                description="Verifies completed actions, output quality, success state, and structured payloads.",
                category=AgentCategory.CORE,
                status=AgentStatus.PLANNED,
                module_path="agents.verification_agent.verification_agent",
                class_name="VerificationAgent",
                capabilities=[
                    AgentCapability("verify_result", "Verify task result success, integrity, and completeness.", True, False, AgentRiskLevel.MEDIUM, ["verification.run"], ["verification"]),
                    AgentCapability("quality_check", "Check generated output quality and consistency.", True, False, AgentRiskLevel.MEDIUM, ["verification.quality"], ["quality"]),
                ],
                dependencies=[security_dependency],
                file_count=AgentFileCount(total_files=0, completed_files=0, remaining_files=0),
                requires_security_agent=False,
                tags=["verification", "quality", "post-check"],
            ),
            AgentManifestEntry(
                agent_key="visual",
                display_name="Visual Agent",
                description="Handles image understanding, visual generation planning, design analysis, and multimodal workflows.",
                category=AgentCategory.CREATIVE,
                status=AgentStatus.PLANNED,
                module_path="agents.visual_agent.visual_agent",
                class_name="VisualAgent",
                capabilities=[
                    AgentCapability("analyze_image", "Analyze images, UI screenshots, designs, and visual context.", True, False, AgentRiskLevel.MEDIUM, ["visual.analyze"], ["image"]),
                    AgentCapability("visual_prompting", "Prepare production-ready prompts for visual generation tools.", True, False, AgentRiskLevel.LOW, ["visual.prompt"], ["prompting"]),
                ],
                dependencies=[security_dependency, memory_dependency],
                file_count=AgentFileCount(total_files=0, completed_files=0, remaining_files=0),
                tags=["visual", "image", "design"],
            ),
            AgentManifestEntry(
                agent_key="workflow",
                display_name="Workflow Agent",
                description="Creates, runs, monitors, and reports safe multi-step workflows.",
                category=AgentCategory.AUTOMATION,
                status=AgentStatus.PLANNED,
                module_path="agents.workflow_agent.workflow_agent",
                class_name="WorkflowAgent",
                capabilities=[
                    AgentCapability("build_workflow", "Build multi-step automation workflows.", True, True, AgentRiskLevel.HIGH, ["workflow.build"], ["automation"]),
                    AgentCapability("monitor_workflow", "Monitor workflow progress and status.", True, False, AgentRiskLevel.MEDIUM, ["workflow.monitor"], ["monitoring"]),
                ],
                dependencies=[security_dependency, verification_dependency, memory_dependency],
                file_count=AgentFileCount(total_files=0, completed_files=0, remaining_files=0),
                requires_security_agent=True,
                tags=["workflow", "automation", "tasks"],
            ),
            AgentManifestEntry(
                agent_key="hologram",
                display_name="Hologram Agent",
                description="Future-facing agent for avatar, AR, hologram, visual presence, and spatial interfaces.",
                category=AgentCategory.EXPERIMENTAL,
                status=AgentStatus.PLANNED,
                module_path="agents.hologram_agent.hologram_agent",
                class_name="HologramAgent",
                capabilities=[
                    AgentCapability("avatar_presence", "Manage avatar or hologram-style user interface behavior.", True, False, AgentRiskLevel.LOW, ["hologram.avatar"], ["avatar"]),
                    AgentCapability("spatial_ui_planning", "Prepare spatial interface layouts and visual interaction flows.", True, False, AgentRiskLevel.LOW, ["hologram.spatial"], ["ar"]),
                ],
                dependencies=[memory_dependency],
                file_count=AgentFileCount(total_files=0, completed_files=0, remaining_files=0),
                tags=["hologram", "avatar", "future"],
            ),
            AgentManifestEntry(
                agent_key="call",
                display_name="Call Agent",
                description="Handles safe call workflows, call planning, call summaries, and future voice-call automation.",
                category=AgentCategory.COMMUNICATION,
                status=AgentStatus.PLANNED,
                module_path="agents.call_agent.call_agent",
                class_name="CallAgent",
                capabilities=[
                    AgentCapability("call_planning", "Prepare call scripts, goals, and safe call workflows.", True, False, AgentRiskLevel.MEDIUM, ["call.plan"], ["calls"]),
                    AgentCapability("call_execution_gate", "Gate real call actions behind explicit permission.", True, True, AgentRiskLevel.CRITICAL, ["call.execute"], ["calls", "permission"]),
                    AgentCapability("call_summary", "Summarize call notes and next actions.", True, False, AgentRiskLevel.MEDIUM, ["call.summary"], ["summary"]),
                ],
                dependencies=[security_dependency, verification_dependency, memory_dependency],
                file_count=AgentFileCount(total_files=0, completed_files=0, remaining_files=0),
                requires_security_agent=True,
                tags=["call", "communication", "approval-required"],
            ),
            AgentManifestEntry(
                agent_key="business",
                display_name="Business Agent",
                description="Handles business strategy, marketing, sales, proposals, audits, dashboards, and client workflows.",
                category=AgentCategory.INTELLIGENCE,
                status=AgentStatus.PLANNED,
                module_path="agents.business_agent.business_agent",
                class_name="BusinessAgent",
                capabilities=[
                    AgentCapability("business_strategy", "Generate business strategy and growth plans.", True, False, AgentRiskLevel.MEDIUM, ["business.strategy"], ["strategy"]),
                    AgentCapability("marketing_audit", "Create marketing, SEO, PPC, and sales audit frameworks.", True, False, AgentRiskLevel.MEDIUM, ["business.audit"], ["audit"]),
                    AgentCapability("proposal_generation", "Generate client-facing proposals and reports.", True, False, AgentRiskLevel.MEDIUM, ["business.proposal"], ["proposal"]),
                ],
                dependencies=[memory_dependency, verification_dependency],
                file_count=AgentFileCount(total_files=0, completed_files=0, remaining_files=0),
                tags=["business", "marketing", "sales"],
            ),
            AgentManifestEntry(
                agent_key="finance",
                display_name="Finance Agent",
                description="Handles financial summaries, budget planning, invoices, pricing, and permission-gated finance workflows.",
                category=AgentCategory.FINANCE,
                status=AgentStatus.PLANNED,
                module_path="agents.finance_agent.finance_agent",
                class_name="FinanceAgent",
                capabilities=[
                    AgentCapability("budget_planning", "Prepare budgets, forecasts, and financial summaries.", True, False, AgentRiskLevel.MEDIUM, ["finance.plan"], ["finance"]),
                    AgentCapability("invoice_support", "Prepare invoice metadata and billing workflows.", True, True, AgentRiskLevel.HIGH, ["finance.invoice"], ["billing"]),
                    AgentCapability("financial_action_gate", "Require approval for sensitive finance-related actions.", True, True, AgentRiskLevel.CRITICAL, ["finance.execute"], ["approval"]),
                ],
                dependencies=[security_dependency, verification_dependency, memory_dependency],
                file_count=AgentFileCount(total_files=0, completed_files=0, remaining_files=0),
                requires_security_agent=True,
                tags=["finance", "billing", "approval-required"],
            ),
            AgentManifestEntry(
                agent_key="creator",
                display_name="Creator Agent",
                description="Handles content creation, scripts, prompts, design briefs, ads, videos, and creative workflows.",
                category=AgentCategory.CREATIVE,
                status=AgentStatus.PLANNED,
                module_path="agents.creator_agent.creator_agent",
                class_name="CreatorAgent",
                capabilities=[
                    AgentCapability("scriptwriting", "Create scripts for ads, videos, voiceovers, and storytelling.", True, False, AgentRiskLevel.LOW, ["creator.script"], ["script"]),
                    AgentCapability("prompt_generation", "Generate AI prompts for visual, video, and creative tools.", True, False, AgentRiskLevel.LOW, ["creator.prompt"], ["prompt"]),
                    AgentCapability("content_strategy", "Plan content campaigns and creative systems.", True, False, AgentRiskLevel.MEDIUM, ["creator.strategy"], ["content"]),
                ],
                dependencies=[memory_dependency, verification_dependency],
                file_count=AgentFileCount(total_files=0, completed_files=0, remaining_files=0),
                tags=["creator", "content", "ads", "video"],
            ),
        ]

    # ========================================================
    # Public Manifest CRUD
    # ========================================================

    def register_agent(
        self,
        agent_key: str,
        display_name: str,
        description: str,
        category: Union[str, AgentCategory],
        version: str = "1.0.0",
        status: Union[str, AgentStatus] = AgentStatus.PLANNED,
        module_path: Optional[str] = None,
        class_name: Optional[str] = None,
        capabilities: Optional[List[Union[AgentCapability, Dict[str, Any]]]] = None,
        dependencies: Optional[List[Union[AgentDependency, Dict[str, Any]]]] = None,
        file_count: Optional[Union[AgentFileCount, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        require_context: bool = False,
    ) -> Dict[str, Any]:
        """
        Register or replace one agent manifest entry.
        """

        context_result = self._validate_task_context(require_context=require_context)
        if not context_result["success"]:
            return context_result

        normalized_key = self.normalize_key(agent_key)

        if self._requires_security_check("register_agent", normalized_key):
            approval = self._request_security_approval(
                operation="register_agent",
                agent_key=normalized_key,
                payload={"display_name": display_name},
            )
            return approval

        try:
            entry = AgentManifestEntry(
                agent_key=normalized_key,
                display_name=display_name.strip(),
                description=description.strip(),
                category=self._coerce_category(category),
                version=version.strip(),
                status=self._coerce_status(status),
                module_path=module_path,
                class_name=class_name,
                capabilities=self._coerce_capabilities(capabilities or []),
                dependencies=self._coerce_dependencies(dependencies or []),
                file_count=self._coerce_file_count(file_count),
                metadata=metadata or {},
                updated_at=self.utcnow(),
            )

            self._manifest[normalized_key] = entry

            self._emit_agent_event(
                event_type="agent_registered",
                agent_key=normalized_key,
                payload={"display_name": display_name, "version": version},
            )

            self._log_audit_event(
                action="register_agent",
                agent_key=normalized_key,
                details={"display_name": display_name, "version": version},
            )

            result = self._safe_result(
                "Agent registered successfully.",
                data={"agent": entry.to_dict()},
            )

            result["metadata"]["verification_payload"] = self._prepare_verification_payload(
                "register_agent",
                result,
                normalized_key,
            )
            result["metadata"]["memory_payload"] = self._prepare_memory_payload(
                "register_agent",
                normalized_key,
                summary=f"Registered manifest metadata for {display_name}.",
                data={"agent_key": normalized_key, "version": version},
            )

            return result

        except Exception as exc:
            logger.exception("Failed to register agent: %s", agent_key)
            return self._error_result(
                "Failed to register agent.",
                error=exc,
                metadata={"agent_key": normalized_key},
            )

    def get_agent(self, agent_key: str) -> Dict[str, Any]:
        """Return one agent manifest entry."""
        normalized_key = self.normalize_key(agent_key)
        entry = self._manifest.get(normalized_key)

        if not entry:
            return self._error_result(
                "Agent not found in manifest.",
                data={"agent_key": normalized_key},
            )

        return self._safe_result(
            "Agent manifest entry found.",
            data={"agent": entry.to_dict()},
        )

    def list_agents(
        self,
        status: Optional[Union[str, AgentStatus]] = None,
        category: Optional[Union[str, AgentCategory]] = None,
        include_capabilities: bool = True,
    ) -> Dict[str, Any]:
        """
        List manifest entries with optional status/category filters.
        """

        entries = list(self._manifest.values())

        if status is not None:
            target_status = self._coerce_status(status)
            entries = [entry for entry in entries if entry.status == target_status]

        if category is not None:
            target_category = self._coerce_category(category)
            entries = [entry for entry in entries if entry.category == target_category]

        serialized = []
        for entry in entries:
            item = entry.to_dict()
            if not include_capabilities:
                item["capabilities"] = []
            serialized.append(item)

        return self._safe_result(
            "Agent manifest entries listed.",
            data={
                "count": len(serialized),
                "agents": serialized,
            },
        )

    def update_agent_status(
        self,
        agent_key: str,
        status: Union[str, AgentStatus],
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Update the status of an agent.

        Sensitive agents require security approval before disabling/removing.
        """

        normalized_key = self.normalize_key(agent_key)
        entry = self._manifest.get(normalized_key)

        if not entry:
            return self._error_result(
                "Cannot update status because agent was not found.",
                data={"agent_key": normalized_key},
            )

        target_status = self._coerce_status(status)

        if target_status in {AgentStatus.DISABLED, AgentStatus.DEPRECATED, AgentStatus.ERROR}:
            if self._requires_security_check("status_change", normalized_key):
                return self._request_security_approval(
                    operation="status_change",
                    agent_key=normalized_key,
                    payload={
                        "old_status": entry.status.value,
                        "new_status": target_status.value,
                        "reason": reason,
                    },
                )

        old_status = entry.status
        entry.status = target_status
        entry.updated_at = self.utcnow()
        entry.metadata["status_reason"] = reason

        self._emit_agent_event(
            event_type="agent_status_updated",
            agent_key=normalized_key,
            payload={
                "old_status": old_status.value,
                "new_status": target_status.value,
                "reason": reason,
            },
        )

        self._log_audit_event(
            action="update_agent_status",
            agent_key=normalized_key,
            details={
                "old_status": old_status.value,
                "new_status": target_status.value,
                "reason": reason,
            },
            risk_level=AgentRiskLevel.MEDIUM,
        )

        result = self._safe_result(
            "Agent status updated.",
            data={"agent": entry.to_dict()},
        )

        result["metadata"]["verification_payload"] = self._prepare_verification_payload(
            "update_agent_status",
            result,
            normalized_key,
        )

        return result

    def remove_agent(self, agent_key: str, force: bool = False) -> Dict[str, Any]:
        """
        Remove one agent from manifest.

        This is a sensitive operation and normally requires Security Agent approval.
        """

        normalized_key = self.normalize_key(agent_key)

        if normalized_key not in self._manifest:
            return self._error_result(
                "Cannot remove agent because it was not found.",
                data={"agent_key": normalized_key},
            )

        if self._requires_security_check("remove_agent", normalized_key) and not force:
            return self._request_security_approval(
                operation="remove_agent",
                agent_key=normalized_key,
                payload={"force": force},
            )

        removed = self._manifest.pop(normalized_key)

        self._emit_agent_event(
            event_type="agent_removed",
            agent_key=normalized_key,
            payload={"removed_agent": removed.to_dict()},
        )

        self._log_audit_event(
            action="remove_agent",
            agent_key=normalized_key,
            details={"force": force},
            risk_level=AgentRiskLevel.HIGH,
        )

        result = self._safe_result(
            "Agent removed from manifest.",
            data={"removed_agent": removed.to_dict()},
        )

        result["metadata"]["verification_payload"] = self._prepare_verification_payload(
            "remove_agent",
            result,
            normalized_key,
        )

        return result

    # ========================================================
    # Capability Methods
    # ========================================================

    def add_capability(
        self,
        agent_key: str,
        capability_key: str,
        description: str,
        enabled: bool = True,
        requires_security: bool = False,
        risk_level: Union[str, AgentRiskLevel] = AgentRiskLevel.LOW,
        permissions: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Add or replace one capability for an agent."""

        normalized_agent = self.normalize_key(agent_key)
        normalized_capability = self.normalize_key(capability_key)
        entry = self._manifest.get(normalized_agent)

        if not entry:
            return self._error_result(
                "Cannot add capability because agent was not found.",
                data={"agent_key": normalized_agent},
            )

        coerced_risk = self._coerce_risk_level(risk_level)

        if requires_security or coerced_risk in {AgentRiskLevel.HIGH, AgentRiskLevel.CRITICAL}:
            if self._requires_security_check(
                "update_permissions",
                normalized_agent,
                normalized_capability,
            ):
                return self._request_security_approval(
                    operation="add_capability",
                    agent_key=normalized_agent,
                    payload={
                        "capability_key": normalized_capability,
                        "requires_security": requires_security,
                        "risk_level": coerced_risk.value,
                    },
                )

        capability = AgentCapability(
            key=normalized_capability,
            description=description.strip(),
            enabled=enabled,
            requires_security=requires_security,
            risk_level=coerced_risk,
            permissions=permissions or [],
            tags=tags or [],
        )

        entry.capabilities = [
            cap for cap in entry.capabilities
            if self.normalize_key(cap.key) != normalized_capability
        ]
        entry.capabilities.append(capability)
        entry.updated_at = self.utcnow()

        self._emit_agent_event(
            event_type="capability_added",
            agent_key=normalized_agent,
            payload=capability.to_dict(),
        )

        self._log_audit_event(
            action="add_capability",
            agent_key=normalized_agent,
            details=capability.to_dict(),
            risk_level=coerced_risk,
        )

        return self._safe_result(
            "Capability added successfully.",
            data={"agent": entry.to_dict(), "capability": capability.to_dict()},
        )

    def get_agent_by_capability(self, capability_key: str) -> Dict[str, Any]:
        """
        Find all agents that expose a capability.
        """

        normalized_capability = self.normalize_key(capability_key)
        matches: List[Dict[str, Any]] = []

        for entry in self._manifest.values():
            for capability in entry.capabilities:
                if self.normalize_key(capability.key) == normalized_capability:
                    matches.append({
                        "agent_key": entry.agent_key,
                        "display_name": entry.display_name,
                        "status": entry.status.value,
                        "capability": capability.to_dict(),
                    })

        if not matches:
            return self._error_result(
                "No agent found for requested capability.",
                data={"capability_key": normalized_capability},
            )

        return self._safe_result(
            "Agents found for requested capability.",
            data={
                "capability_key": normalized_capability,
                "matches": matches,
                "count": len(matches),
            },
        )

    def list_capabilities(self, enabled_only: bool = False) -> Dict[str, Any]:
        """List all capabilities across all agents."""

        capabilities: List[Dict[str, Any]] = []

        for entry in self._manifest.values():
            for capability in entry.capabilities:
                if enabled_only and not capability.enabled:
                    continue

                item = capability.to_dict()
                item["agent_key"] = entry.agent_key
                item["agent_display_name"] = entry.display_name
                item["agent_status"] = entry.status.value
                capabilities.append(item)

        return self._safe_result(
            "Capabilities listed.",
            data={
                "count": len(capabilities),
                "capabilities": capabilities,
            },
        )

    # ========================================================
    # Dependencies
    # ========================================================

    def add_dependency(
        self,
        agent_key: str,
        dependency_name: str,
        required: bool = True,
        min_version: Optional[str] = None,
        reason: Optional[str] = None,
        status: str = "unknown",
    ) -> Dict[str, Any]:
        """Add or replace one dependency for an agent."""

        normalized_agent = self.normalize_key(agent_key)
        normalized_dependency = self.normalize_key(dependency_name)
        entry = self._manifest.get(normalized_agent)

        if not entry:
            return self._error_result(
                "Cannot add dependency because agent was not found.",
                data={"agent_key": normalized_agent},
            )

        dependency = AgentDependency(
            name=normalized_dependency,
            required=required,
            min_version=min_version,
            reason=reason,
            status=status,
        )

        entry.dependencies = [
            dep for dep in entry.dependencies
            if self.normalize_key(dep.name) != normalized_dependency
        ]
        entry.dependencies.append(dependency)
        entry.updated_at = self.utcnow()

        self._emit_agent_event(
            event_type="dependency_added",
            agent_key=normalized_agent,
            payload=dependency.to_dict(),
        )

        return self._safe_result(
            "Dependency added successfully.",
            data={"agent": entry.to_dict(), "dependency": dependency.to_dict()},
        )

    def validate_dependencies(self, agent_key: Optional[str] = None) -> Dict[str, Any]:
        """
        Validate whether required dependencies exist in the manifest.

        This does not import or execute dependency modules.
        It only validates manifest-level availability.
        """

        entries = (
            [self._manifest[self.normalize_key(agent_key)]]
            if agent_key and self.normalize_key(agent_key) in self._manifest
            else list(self._manifest.values())
        )

        if agent_key and self.normalize_key(agent_key) not in self._manifest:
            return self._error_result(
                "Cannot validate dependencies because agent was not found.",
                data={"agent_key": self.normalize_key(agent_key)},
            )

        reports: List[Dict[str, Any]] = []

        for entry in entries:
            missing_required = []
            optional_missing = []

            for dep in entry.dependencies:
                dep_key = self.normalize_key(dep.name)
                exists = dep_key in self._manifest

                if not exists and dep.required:
                    missing_required.append(dep.to_dict())
                elif not exists:
                    optional_missing.append(dep.to_dict())

            reports.append({
                "agent_key": entry.agent_key,
                "display_name": entry.display_name,
                "dependency_count": len(entry.dependencies),
                "missing_required": missing_required,
                "optional_missing": optional_missing,
                "valid": len(missing_required) == 0,
            })

        all_valid = all(report["valid"] for report in reports)

        return self._safe_result(
            "Dependency validation completed.",
            data={
                "valid": all_valid,
                "reports": reports,
            },
        )

    # ========================================================
    # File Count / Completion Tracking
    # ========================================================

    def update_file_count(
        self,
        agent_key: str,
        total_files: int,
        completed_files: int,
        completed_file_names: Optional[List[str]] = None,
        remaining_file_names: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Update file count and completion metadata for an agent/module.
        """

        normalized_key = self.normalize_key(agent_key)
        entry = self._manifest.get(normalized_key)

        if not entry:
            return self._error_result(
                "Cannot update file count because agent was not found.",
                data={"agent_key": normalized_key},
            )

        total_files = max(0, int(total_files))
        completed_files = max(0, int(completed_files))
        completed_files = min(completed_files, total_files)
        remaining_files = max(0, total_files - completed_files)

        file_count = AgentFileCount(
            total_files=total_files,
            completed_files=completed_files,
            remaining_files=remaining_files,
            completed_file_names=completed_file_names or [],
            remaining_file_names=remaining_file_names or [],
        )

        entry.file_count = file_count
        entry.updated_at = self.utcnow()

        self._emit_agent_event(
            event_type="file_count_updated",
            agent_key=normalized_key,
            payload=file_count.to_dict(),
        )

        return self._safe_result(
            "Agent file count updated.",
            data={
                "agent_key": normalized_key,
                "file_count": file_count.to_dict(),
                "agent": entry.to_dict(),
            },
        )

    def get_completion_report(self) -> Dict[str, Any]:
        """Return completion report for all agents/modules."""

        reports = []
        total_files = 0
        completed_files = 0
        remaining_files = 0

        for entry in self._manifest.values():
            fc = entry.file_count
            total_files += fc.total_files
            completed_files += fc.completed_files
            remaining_files += fc.remaining_files

            reports.append({
                "agent_key": entry.agent_key,
                "display_name": entry.display_name,
                "status": entry.status.value,
                "file_count": fc.to_dict(),
            })

        overall_percent = 0.0
        if total_files > 0:
            overall_percent = round((completed_files / total_files) * 100, 1)

        return self._safe_result(
            "Completion report generated.",
            data={
                "overall": {
                    "total_files": total_files,
                    "completed_files": completed_files,
                    "remaining_files": remaining_files,
                    "completion_percent": overall_percent,
                },
                "agents": reports,
            },
        )

    # ========================================================
    # Dashboard / Registry / Loader Exports
    # ========================================================

    def export_manifest(self, as_json: bool = False) -> Union[Dict[str, Any], str]:
        """
        Export full manifest for dashboard/API/config usage.
        """

        payload = {
            "system": self.SYSTEM_NAME,
            "owner": self.OWNER,
            "manifest_version": self.MANIFEST_VERSION,
            "exported_at": self.utcnow(),
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "agent_count": len(self._manifest),
            "agents": {
                key: entry.to_dict()
                for key, entry in sorted(self._manifest.items())
            },
        }

        if as_json:
            return json.dumps(payload, indent=2, ensure_ascii=False)

        return payload

    def export_registry_payload(self) -> Dict[str, Any]:
        """
        Export registry-compatible payload.

        This is useful for agents/registry.py, AgentLoader, AgentRouter,
        and MasterAgent bootstrapping.
        """

        agents = []

        for entry in self._manifest.values():
            agents.append({
                "agent_key": entry.agent_key,
                "display_name": entry.display_name,
                "module_path": entry.module_path,
                "class_name": entry.class_name,
                "version": entry.version,
                "status": entry.status.value,
                "capabilities": entry.enabled_capability_keys(),
                "dependencies": [dep.name for dep in entry.dependencies if dep.required],
                "requires_security_agent": entry.requires_security_agent,
                "supports_user_context": entry.supports_user_context,
                "supports_workspace_context": entry.supports_workspace_context,
                "metadata": {
                    "category": entry.category.value,
                    "tags": entry.tags,
                    "file_count": entry.file_count.to_dict(),
                },
            })

        return self._safe_result(
            "Registry payload exported.",
            data={
                "registry_payload": {
                    "system": self.SYSTEM_NAME,
                    "manifest_version": self.MANIFEST_VERSION,
                    "agents": agents,
                }
            },
        )

    def export_router_map(self) -> Dict[str, Any]:
        """
        Export capability-to-agent routing map for Agent Router / Master Agent.
        """

        routing_map: Dict[str, List[Dict[str, Any]]] = {}

        for entry in self._manifest.values():
            if entry.status not in {AgentStatus.ACTIVE, AgentStatus.PLANNED, AgentStatus.DEGRADED}:
                continue

            for capability in entry.capabilities:
                if not capability.enabled:
                    continue

                routing_map.setdefault(capability.key, []).append({
                    "agent_key": entry.agent_key,
                    "display_name": entry.display_name,
                    "status": entry.status.value,
                    "risk_level": capability.risk_level.value,
                    "requires_security": capability.requires_security or entry.requires_security_agent,
                    "permissions": capability.permissions,
                })

        return self._safe_result(
            "Router map exported.",
            data={
                "routing_map": routing_map,
                "capability_count": len(routing_map),
            },
        )

    def get_dashboard_summary(self) -> Dict[str, Any]:
        """
        Return dashboard-ready summary.

        Useful for FastAPI/admin UI.
        """

        status_counts: Dict[str, int] = {}
        category_counts: Dict[str, int] = {}
        security_required_count = 0
        dashboard_enabled_count = 0

        for entry in self._manifest.values():
            status_counts[entry.status.value] = status_counts.get(entry.status.value, 0) + 1
            category_counts[entry.category.value] = category_counts.get(entry.category.value, 0) + 1

            if entry.requires_security_agent:
                security_required_count += 1

            if entry.supports_dashboard:
                dashboard_enabled_count += 1

        completion = self.get_completion_report()
        completion_data = completion.get("data", {}).get("overall", {})

        return self._safe_result(
            "Dashboard summary generated.",
            data={
                "system": self.SYSTEM_NAME,
                "owner": self.OWNER,
                "manifest_version": self.MANIFEST_VERSION,
                "agent_count": len(self._manifest),
                "status_counts": status_counts,
                "category_counts": category_counts,
                "security_required_count": security_required_count,
                "dashboard_enabled_count": dashboard_enabled_count,
                "completion": completion_data,
                "recent_events": self._events[-10:],
                "recent_audit_logs": self._audit_logs[-10:],
            },
        )

    # ========================================================
    # Health / Validation
    # ========================================================

    def validate_manifest(self) -> Dict[str, Any]:
        """
        Validate manifest structure and required metadata.
        """

        issues: List[Dict[str, Any]] = []
        seen_keys: Set[str] = set()

        for key, entry in self._manifest.items():
            if key in seen_keys:
                issues.append({
                    "agent_key": key,
                    "issue": "duplicate_agent_key",
                    "severity": "high",
                })

            seen_keys.add(key)

            if not entry.display_name:
                issues.append({
                    "agent_key": key,
                    "issue": "missing_display_name",
                    "severity": "medium",
                })

            if not entry.module_path:
                issues.append({
                    "agent_key": key,
                    "issue": "missing_module_path",
                    "severity": "low",
                })

            if not entry.class_name:
                issues.append({
                    "agent_key": key,
                    "issue": "missing_class_name",
                    "severity": "low",
                })

            if entry.supports_user_context and entry.supports_workspace_context is False:
                issues.append({
                    "agent_key": key,
                    "issue": "user_context_without_workspace_context",
                    "severity": "medium",
                })

            for cap in entry.capabilities:
                if cap.requires_security and not entry.requires_security_agent:
                    issues.append({
                        "agent_key": key,
                        "capability_key": cap.key,
                        "issue": "capability_requires_security_but_agent_not_marked",
                        "severity": "medium",
                    })

        dependency_report = self.validate_dependencies()
        dependency_valid = bool(dependency_report.get("data", {}).get("valid", False))

        valid = len([i for i in issues if i["severity"] in {"high", "critical"}]) == 0 and dependency_valid

        return self._safe_result(
            "Manifest validation completed.",
            data={
                "valid": valid,
                "issue_count": len(issues),
                "issues": issues,
                "dependency_validation": dependency_report.get("data", {}),
            },
        )

    def get_health_snapshot(self) -> Dict[str, Any]:
        """
        Return manifest health metadata.

        Later this can connect to agents/agent_health.py.
        """

        validation = self.validate_manifest()
        dependency_report = self.validate_dependencies()
        dashboard = self.get_dashboard_summary()

        return self._safe_result(
            "Manifest health snapshot generated.",
            data={
                "manifest_valid": validation.get("data", {}).get("valid", False),
                "dependency_valid": dependency_report.get("data", {}).get("valid", False),
                "agent_count": len(self._manifest),
                "status_counts": dashboard.get("data", {}).get("status_counts", {}),
                "issue_count": validation.get("data", {}).get("issue_count", 0),
                "last_updated_at": self._latest_updated_at(),
            },
        )

    # ========================================================
    # Event / Audit Access
    # ========================================================

    def list_events(self, limit: int = 50) -> Dict[str, Any]:
        """Return recent manifest events."""
        limit = max(1, min(int(limit), 500))
        return self._safe_result(
            "Manifest events listed.",
            data={
                "count": min(limit, len(self._events)),
                "events": self._events[-limit:],
            },
        )

    def list_audit_logs(self, limit: int = 50) -> Dict[str, Any]:
        """Return recent audit logs."""
        limit = max(1, min(int(limit), 500))
        return self._safe_result(
            "Manifest audit logs listed.",
            data={
                "count": min(limit, len(self._audit_logs)),
                "audit_logs": self._audit_logs[-limit:],
            },
        )

    # ========================================================
    # Import / Restore
    # ========================================================

    def load_from_dict(self, payload: Dict[str, Any], merge: bool = True) -> Dict[str, Any]:
        """
        Load manifest entries from dictionary.

        This is permission-sensitive because it can change routing metadata.
        """

        if self._requires_security_check("bulk_import"):
            return self._request_security_approval(
                operation="bulk_import",
                agent_key="manifest",
                payload={"merge": merge, "keys": list(payload.keys())[:50]},
            )

        try:
            agents_payload = payload.get("agents", payload)

            if not isinstance(agents_payload, dict):
                return self._error_result(
                    "Invalid manifest payload. Expected dict with agents.",
                    data={"payload_type": type(agents_payload).__name__},
                )

            if not merge:
                self._manifest.clear()

            imported_count = 0

            for key, raw_entry in agents_payload.items():
                if not isinstance(raw_entry, dict):
                    continue

                entry = self._entry_from_dict(raw_entry)
                self._manifest[self.normalize_key(entry.agent_key or key)] = entry
                imported_count += 1

            self._emit_agent_event(
                event_type="manifest_imported",
                agent_key="manifest",
                payload={"imported_count": imported_count, "merge": merge},
            )

            return self._safe_result(
                "Manifest imported successfully.",
                data={
                    "imported_count": imported_count,
                    "agent_count": len(self._manifest),
                },
            )

        except Exception as exc:
            logger.exception("Failed to load manifest from dict.")
            return self._error_result(
                "Failed to load manifest from dictionary.",
                error=exc,
            )

    def load_from_json(self, json_text: str, merge: bool = True) -> Dict[str, Any]:
        """Load manifest entries from JSON string."""
        try:
            payload = json.loads(json_text)
            return self.load_from_dict(payload, merge=merge)
        except Exception as exc:
            return self._error_result(
                "Invalid JSON manifest payload.",
                error=exc,
            )

    # ========================================================
    # Internal Coercion Helpers
    # ========================================================

    def _coerce_status(self, value: Union[str, AgentStatus]) -> AgentStatus:
        """Coerce value into AgentStatus."""
        if isinstance(value, AgentStatus):
            return value

        normalized = self.normalize_key(str(value))
        for status in AgentStatus:
            if status.value == normalized:
                return status

        return AgentStatus.PLANNED

    def _coerce_category(self, value: Union[str, AgentCategory]) -> AgentCategory:
        """Coerce value into AgentCategory."""
        if isinstance(value, AgentCategory):
            return value

        normalized = self.normalize_key(str(value))
        for category in AgentCategory:
            if category.value == normalized:
                return category

        return AgentCategory.EXPERIMENTAL

    def _coerce_risk_level(self, value: Union[str, AgentRiskLevel]) -> AgentRiskLevel:
        """Coerce value into AgentRiskLevel."""
        if isinstance(value, AgentRiskLevel):
            return value

        normalized = self.normalize_key(str(value))
        for level in AgentRiskLevel:
            if level.value == normalized:
                return level

        return AgentRiskLevel.LOW

    def _coerce_capabilities(
        self,
        capabilities: List[Union[AgentCapability, Dict[str, Any]]],
    ) -> List[AgentCapability]:
        """Coerce capability dictionaries into AgentCapability objects."""
        result: List[AgentCapability] = []

        for cap in capabilities:
            if isinstance(cap, AgentCapability):
                result.append(cap)
                continue

            if isinstance(cap, dict):
                result.append(
                    AgentCapability(
                        key=self.normalize_key(cap.get("key", "")),
                        description=str(cap.get("description", "")),
                        enabled=bool(cap.get("enabled", True)),
                        requires_security=bool(cap.get("requires_security", False)),
                        risk_level=self._coerce_risk_level(cap.get("risk_level", "low")),
                        permissions=list(cap.get("permissions", [])),
                        tags=list(cap.get("tags", [])),
                    )
                )

        return result

    def _coerce_dependencies(
        self,
        dependencies: List[Union[AgentDependency, Dict[str, Any]]],
    ) -> List[AgentDependency]:
        """Coerce dependency dictionaries into AgentDependency objects."""
        result: List[AgentDependency] = []

        for dep in dependencies:
            if isinstance(dep, AgentDependency):
                result.append(dep)
                continue

            if isinstance(dep, dict):
                result.append(
                    AgentDependency(
                        name=self.normalize_key(dep.get("name", "")),
                        required=bool(dep.get("required", True)),
                        min_version=dep.get("min_version"),
                        reason=dep.get("reason"),
                        status=str(dep.get("status", "unknown")),
                    )
                )

        return result

    def _coerce_file_count(
        self,
        file_count: Optional[Union[AgentFileCount, Dict[str, Any]]],
    ) -> AgentFileCount:
        """Coerce file count dictionary into AgentFileCount object."""
        if isinstance(file_count, AgentFileCount):
            return file_count

        if isinstance(file_count, dict):
            total_files = max(0, int(file_count.get("total_files", 0)))
            completed_files = max(0, int(file_count.get("completed_files", 0)))
            completed_files = min(completed_files, total_files)
            remaining_files = file_count.get("remaining_files")
            if remaining_files is None:
                remaining_files = max(0, total_files - completed_files)

            return AgentFileCount(
                total_files=total_files,
                completed_files=completed_files,
                remaining_files=max(0, int(remaining_files)),
                completed_file_names=list(file_count.get("completed_file_names", [])),
                remaining_file_names=list(file_count.get("remaining_file_names", [])),
            )

        return AgentFileCount()

    def _entry_from_dict(self, raw: Dict[str, Any]) -> AgentManifestEntry:
        """Create AgentManifestEntry from dict."""
        return AgentManifestEntry(
            agent_key=self.normalize_key(raw.get("agent_key", "")),
            display_name=str(raw.get("display_name", "")),
            description=str(raw.get("description", "")),
            category=self._coerce_category(raw.get("category", "experimental")),
            version=str(raw.get("version", "1.0.0")),
            status=self._coerce_status(raw.get("status", "planned")),
            module_path=raw.get("module_path"),
            class_name=raw.get("class_name"),
            owner=str(raw.get("owner", self.OWNER)),
            capabilities=self._coerce_capabilities(list(raw.get("capabilities", []))),
            dependencies=self._coerce_dependencies(list(raw.get("dependencies", []))),
            file_count=self._coerce_file_count(raw.get("file_count")),
            supports_user_context=bool(raw.get("supports_user_context", True)),
            supports_workspace_context=bool(raw.get("supports_workspace_context", True)),
            requires_security_agent=bool(raw.get("requires_security_agent", False)),
            supports_memory_agent=bool(raw.get("supports_memory_agent", True)),
            supports_verification_agent=bool(raw.get("supports_verification_agent", True)),
            supports_audit_logs=bool(raw.get("supports_audit_logs", True)),
            supports_dashboard=bool(raw.get("supports_dashboard", True)),
            is_plugin_style=bool(raw.get("is_plugin_style", True)),
            tags=list(raw.get("tags", [])),
            created_at=str(raw.get("created_at", self.utcnow())),
            updated_at=str(raw.get("updated_at", self.utcnow())),
            metadata=dict(raw.get("metadata", {})),
        )

    def _find_capability(
        self,
        entry: AgentManifestEntry,
        capability_key: str,
    ) -> Optional[AgentCapability]:
        """Find a capability inside an entry."""
        normalized = self.normalize_key(capability_key)
        for capability in entry.capabilities:
            if self.normalize_key(capability.key) == normalized:
                return capability
        return None

    def _latest_updated_at(self) -> Optional[str]:
        """Return latest updated_at timestamp across manifest entries."""
        if not self._manifest:
            return None
        return max(entry.updated_at for entry in self._manifest.values())

    # ========================================================
    # Python Helpers
    # ========================================================

    def __len__(self) -> int:
        """Return number of manifest agents."""
        return len(self._manifest)

    def __contains__(self, agent_key: str) -> bool:
        """Check if agent exists in manifest."""
        return self.normalize_key(agent_key) in self._manifest

    def __repr__(self) -> str:
        """Developer-friendly representation."""
        return (
            f"AgentManifest(system={self.SYSTEM_NAME!r}, "
            f"agents={len(self._manifest)}, "
            f"version={self.MANIFEST_VERSION!r})"
        )


# ============================================================
# Module-Level Safe Singleton Helpers
# ============================================================

_default_manifest: Optional[AgentManifest] = None


def get_default_manifest() -> AgentManifest:
    """
    Return a module-level default manifest instance.

    Safe for simple imports, tests, registry bootstrap, and dashboard reads.
    """
    global _default_manifest

    if _default_manifest is None:
        _default_manifest = AgentManifest(auto_seed=True)

    return _default_manifest


def export_default_manifest(as_json: bool = False) -> Union[Dict[str, Any], str]:
    """
    Export default manifest without manually creating AgentManifest.
    """
    return get_default_manifest().export_manifest(as_json=as_json)


def get_agent_manifest_summary() -> Dict[str, Any]:
    """
    Return dashboard summary from default manifest.
    """
    return get_default_manifest().get_dashboard_summary()


# ============================================================
# Local Smoke Test
# ============================================================

if __name__ == "__main__":
    manifest = AgentManifest(user_id="demo_user", workspace_id="demo_workspace")
    print(json.dumps(manifest.get_dashboard_summary(), indent=2))
    print(json.dumps(manifest.export_router_map(), indent=2))
    print("FILE COMPLETE")