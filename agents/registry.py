"""
agents/registry.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

AgentRegistry is the central registry responsible for safely registering,
tracking, importing, inspecting, enabling, disabling, and exposing all William
agents to the Master Agent, Agent Loader, Agent Router, Dashboard/API layer,
Security Agent, Memory Agent, and Verification Agent.

This file is intentionally import-safe.

If future agent files are not created yet, this registry will NOT crash.
It creates safe registry records and fallback metadata so the project can be
built file-by-file.

Core responsibilities:

- Register all default William/Jarvis agents
- Safely import existing agent classes when available
- Store agent metadata for dashboard/API usage
- Support plugin-style future agents
- Support SaaS user/workspace isolation metadata
- Support permission/security/verification/memory compatibility metadata
- Provide structured JSON-style results
- Avoid executing real system/browser/call/finance/destructive actions directly
- Stay compatible with BaseAgent, Agent Loader, Agent Router, and Master Agent

Default William/Jarvis Agents:

- Master
- Voice
- System
- Browser
- Code
- Memory
- Security
- Verification
- Visual
- Workflow
- Hologram
- Call
- Business
- Finance
- Creator
"""

from __future__ import annotations

import importlib
import inspect
import logging
import traceback
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Type, Union


# ============================================================
# Logging
# ============================================================

logger = logging.getLogger("william.agents.registry")

if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


# ============================================================
# Safe BaseAgent Import
# ============================================================

try:
    from agents.base_agent import BaseAgent
except Exception:
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This fallback keeps registry.py import-safe when base_agent.py has not
        been created yet or has an import error during early development.
        """

        agent_name = "fallback_base_agent"
        agent_type = "fallback"
        agent_version = "0.0.0"
        description = "Fallback BaseAgent stub."
        capabilities: List[str] = []

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.enabled = True
            self.status = "idle"

        def get_identity(self) -> Dict[str, Any]:
            return {
                "agent_name": self.agent_name,
                "agent_type": self.agent_type,
                "agent_version": self.agent_version,
                "description": self.description,
                "capabilities": self.capabilities,
                "module_path": self.__class__.__module__,
                "class_name": self.__class__.__name__,
                "enabled": self.enabled,
            }

        def health_check(self) -> Dict[str, Any]:
            return {
                "success": True,
                "message": "Fallback BaseAgent health check.",
                "data": {
                    "agent_name": self.agent_name,
                    "agent_type": self.agent_type,
                    "agent_version": self.agent_version,
                    "enabled": self.enabled,
                    "status": self.status,
                },
                "error": None,
                "metadata": {},
            }


# ============================================================
# Utility Helpers
# ============================================================

def utc_now_iso() -> str:
    """
    Return timezone-aware UTC timestamp.
    """

    return datetime.now(timezone.utc).isoformat()


def safe_uuid(prefix: Optional[str] = None) -> str:
    """
    Generate a safe unique id.
    """

    value = uuid.uuid4().hex

    if prefix:
        return f"{prefix}_{value}"

    return value


def sanitize_for_registry(value: Any, max_length: int = 800) -> Any:
    """
    Sanitize registry payloads for logs/API output.

    Prevents oversized values and masks obvious sensitive fields.
    """

    secret_keys = {
        "password",
        "token",
        "secret",
        "api_key",
        "apikey",
        "authorization",
        "auth",
        "access_token",
        "refresh_token",
        "private_key",
    }

    if isinstance(value, dict):
        cleaned: Dict[str, Any] = {}

        for key, item in value.items():
            key_lower = str(key).lower()

            if key_lower in secret_keys or any(secret in key_lower for secret in secret_keys):
                cleaned[key] = "***REDACTED***"
            else:
                cleaned[key] = sanitize_for_registry(item, max_length=max_length)

        return cleaned

    if isinstance(value, list):
        return [sanitize_for_registry(item, max_length=max_length) for item in value[:50]]

    if isinstance(value, tuple):
        return tuple(sanitize_for_registry(item, max_length=max_length) for item in value[:50])

    if isinstance(value, str):
        if len(value) > max_length:
            return value[:max_length] + "...[TRUNCATED]"
        return value

    return value


def structured_result(
    success: bool,
    message: str,
    data: Optional[Dict[str, Any]] = None,
    error: Optional[Any] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Standard registry result format.

    Compatible with William API/dashboard style:
    success, message, data, error, metadata.
    """

    return {
        "success": success,
        "message": message,
        "data": data or {},
        "error": str(error) if error is not None else None,
        "metadata": {
            "timestamp": utc_now_iso(),
            "source": "AgentRegistry",
            **(metadata or {}),
        },
    }


def safe_issubclass(candidate: Any, parent: Any) -> bool:
    """
    Safe issubclass wrapper.
    """

    try:
        return inspect.isclass(candidate) and issubclass(candidate, parent)
    except Exception:
        return False


# ============================================================
# Enums
# ============================================================

class RegistryStatus(str, Enum):
    """
    Registry record status.
    """

    REGISTERED = "registered"
    IMPORTED = "imported"
    AVAILABLE = "available"
    MISSING = "missing"
    FAILED_IMPORT = "failed_import"
    DISABLED = "disabled"
    PLACEHOLDER = "placeholder"


class AgentCategory(str, Enum):
    """
    High-level category for William agents.
    """

    CORE = "core"
    INTELLIGENCE = "intelligence"
    AUTOMATION = "automation"
    SECURITY = "security"
    MEMORY = "memory"
    COMMUNICATION = "communication"
    BUSINESS = "business"
    CREATIVE = "creative"
    FINANCE = "finance"
    SYSTEM = "system"
    FUTURE_PLUGIN = "future_plugin"


# ============================================================
# Dataclasses
# ============================================================

@dataclass
class RegisteredAgent:
    """
    Registry record for one William/Jarvis agent.

    This does not necessarily instantiate the agent.
    It stores safe metadata, import path, class name, status, capabilities,
    permissions, and compatibility flags.
    """

    registry_id: str
    agent_key: str
    agent_name: str
    agent_type: str
    module_path: str
    class_name: str
    category: str = AgentCategory.CORE.value
    description: str = ""
    capabilities: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    sensitive_permissions: List[str] = field(default_factory=list)
    requires_user_context: bool = True
    requires_workspace_context: bool = True
    requires_security_for_sensitive_actions: bool = True
    prepares_verification_payload: bool = True
    prepares_memory_payload: bool = True
    enabled: bool = True
    is_core: bool = True
    is_plugin: bool = False
    status: str = RegistryStatus.REGISTERED.value
    import_error: Optional[str] = None
    class_loaded: bool = False
    instance_created: bool = False
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PluginAgentSpec:
    """
    Plugin agent registration specification.

    Future plugin agents can be registered through this structure.
    """

    agent_key: str
    agent_name: str
    agent_type: str
    module_path: str
    class_name: str
    category: str = AgentCategory.FUTURE_PLUGIN.value
    description: str = ""
    capabilities: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    sensitive_permissions: List[str] = field(default_factory=list)
    requires_user_context: bool = True
    requires_workspace_context: bool = True
    enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


# ============================================================
# Default Agent Catalog
# ============================================================

DEFAULT_AGENT_SPECS: List[Dict[str, Any]] = [
    {
        "agent_key": "master",
        "agent_name": "Master Agent",
        "agent_type": "master",
        "module_path": "core.master_agent",
        "class_name": "MasterAgent",
        "category": AgentCategory.CORE.value,
        "description": "Main orchestrator that routes user requests to all William agents.",
        "capabilities": [
            "intent_routing",
            "agent_orchestration",
            "task_planning",
            "multi_agent_coordination",
            "dashboard_reporting",
        ],
        "permissions": [
            "agent.route",
            "agent.coordinate",
            "agent.report",
        ],
        "sensitive_permissions": [
            "agent.execute_sensitive",
        ],
        "is_core": True,
    },
    {
        "agent_key": "voice",
        "agent_name": "Voice Agent",
        "agent_type": "voice",
        "module_path": "agents.voice_agent.voice_agent",
        "class_name": "VoiceAgent",
        "category": AgentCategory.COMMUNICATION.value,
        "description": "Handles wake word, speech-to-text, text-to-speech, voice commands, interruptions, and multilingual voice interaction.",
        "capabilities": [
            "wake_word_detection",
            "speech_to_text",
            "text_to_speech",
            "voice_command_processing",
            "language_detection",
            "interruption_handling",
        ],
        "permissions": [
            "voice.listen",
            "voice.transcribe",
            "voice.speak",
        ],
        "sensitive_permissions": [
            "microphone.access",
            "voice.background_listening",
        ],
        "is_core": True,
    },
    {
        "agent_key": "system",
        "agent_name": "System Agent",
        "agent_type": "system",
        "module_path": "agents.system_agent.system_agent",
        "class_name": "SystemAgent",
        "category": AgentCategory.SYSTEM.value,
        "description": "Handles device/system operations, environment checks, operating system helpers, and safe automation interfaces.",
        "capabilities": [
            "system_status",
            "device_control",
            "environment_check",
            "safe_os_helpers",
            "cross_platform_operations",
        ],
        "permissions": [
            "system.read",
            "system.status",
        ],
        "sensitive_permissions": [
            "system.write",
            "system.execute",
            "device.control",
        ],
        "is_core": True,
    },
    {
        "agent_key": "browser",
        "agent_name": "Browser Agent",
        "agent_type": "browser",
        "module_path": "agents.browser_agent.browser_agent",
        "class_name": "BrowserAgent",
        "category": AgentCategory.AUTOMATION.value,
        "description": "Handles browser automation, web navigation, research workflows, page extraction, and safe browsing actions.",
        "capabilities": [
            "browser_navigation",
            "web_research",
            "page_extraction",
            "form_assistance",
            "safe_browser_automation",
        ],
        "permissions": [
            "browser.read",
            "browser.navigate",
        ],
        "sensitive_permissions": [
            "browser.submit_form",
            "browser.purchase",
            "browser.login",
        ],
        "is_core": True,
    },
    {
        "agent_key": "code",
        "agent_name": "Code Agent",
        "agent_type": "code",
        "module_path": "agents.code_agent.code_agent",
        "class_name": "CodeAgent",
        "category": AgentCategory.INTELLIGENCE.value,
        "description": "Handles code generation, code review, debugging, architecture planning, testing, and safe developer workflows.",
        "capabilities": [
            "code_generation",
            "code_review",
            "debugging",
            "architecture_design",
            "test_generation",
            "developer_assistance",
        ],
        "permissions": [
            "code.read",
            "code.generate",
            "code.review",
        ],
        "sensitive_permissions": [
            "code.execute",
            "file.write",
            "repo.modify",
        ],
        "is_core": True,
    },
    {
        "agent_key": "memory",
        "agent_name": "Memory Agent",
        "agent_type": "memory",
        "module_path": "agents.memory_agent.memory_agent",
        "class_name": "MemoryAgent",
        "category": AgentCategory.MEMORY.value,
        "description": "Handles user-specific and workspace-specific long-term memory, retrieval, preference storage, and context isolation.",
        "capabilities": [
            "memory_store",
            "memory_retrieve",
            "user_context",
            "workspace_context",
            "preference_tracking",
            "memory_isolation",
        ],
        "permissions": [
            "memory.read",
            "memory.write",
        ],
        "sensitive_permissions": [
            "memory.delete",
            "memory.export",
            "user.data_access",
        ],
        "is_core": True,
    },
    {
        "agent_key": "security",
        "agent_name": "Security Agent",
        "agent_type": "security",
        "module_path": "agents.security_agent.security_agent",
        "class_name": "SecurityAgent",
        "category": AgentCategory.SECURITY.value,
        "description": "Handles permission checks, policy validation, sensitive action approval, risk scoring, and security audit decisions.",
        "capabilities": [
            "permission_check",
            "security_approval",
            "risk_scoring",
            "policy_validation",
            "audit_review",
            "sensitive_action_gatekeeping",
        ],
        "permissions": [
            "security.read",
            "security.validate",
            "security.approve",
        ],
        "sensitive_permissions": [
            "security.override",
            "policy.modify",
        ],
        "is_core": True,
    },
    {
        "agent_key": "verification",
        "agent_name": "Verification Agent",
        "agent_type": "verification",
        "module_path": "agents.verification_agent.verification_agent",
        "class_name": "VerificationAgent",
        "category": AgentCategory.SECURITY.value,
        "description": "Verifies completed actions, checks result correctness, validates outputs, and prepares confidence reports.",
        "capabilities": [
            "result_verification",
            "output_validation",
            "fact_checking",
            "action_confirmation",
            "quality_scoring",
        ],
        "permissions": [
            "verification.read",
            "verification.validate",
        ],
        "sensitive_permissions": [
            "verification.override",
        ],
        "is_core": True,
    },
    {
        "agent_key": "visual",
        "agent_name": "Visual Agent",
        "agent_type": "visual",
        "module_path": "agents.visual_agent.visual_agent",
        "class_name": "VisualAgent",
        "category": AgentCategory.CREATIVE.value,
        "description": "Handles image understanding, screen analysis, visual reasoning, design feedback, and multimodal workflows.",
        "capabilities": [
            "image_analysis",
            "screen_understanding",
            "visual_reasoning",
            "design_review",
            "multimodal_context",
        ],
        "permissions": [
            "visual.read",
            "visual.analyze",
        ],
        "sensitive_permissions": [
            "camera.access",
            "screen.capture",
            "image.private_analysis",
        ],
        "is_core": True,
    },
    {
        "agent_key": "workflow",
        "agent_name": "Workflow Agent",
        "agent_type": "workflow",
        "module_path": "agents.workflow_agent.workflow_agent",
        "class_name": "WorkflowAgent",
        "category": AgentCategory.AUTOMATION.value,
        "description": "Builds, runs, monitors, and optimizes multi-step workflows, automations, triggers, and agent pipelines.",
        "capabilities": [
            "workflow_creation",
            "workflow_execution",
            "automation_planning",
            "pipeline_monitoring",
            "trigger_management",
        ],
        "permissions": [
            "workflow.read",
            "workflow.create",
            "workflow.run",
        ],
        "sensitive_permissions": [
            "workflow.execute_external",
            "workflow.modify_data",
            "workflow.schedule",
        ],
        "is_core": True,
    },
    {
        "agent_key": "hologram",
        "agent_name": "Hologram Agent",
        "agent_type": "hologram",
        "module_path": "agents.super_agents.hologram_agent.hologram_agent",
        "class_name": "HologramAgent",
        "category": AgentCategory.CREATIVE.value,
        "description": "Handles future avatar, spatial UI, hologram-like presentation, 3D assistant display, and immersive interfaces.",
        "capabilities": [
            "avatar_interface",
            "spatial_ui",
            "presentation_mode",
            "immersive_display",
            "future_hologram_support",
        ],
        "permissions": [
            "hologram.render",
            "hologram.present",
        ],
        "sensitive_permissions": [
            "camera.access",
            "spatial_device.access",
        ],
        "is_core": True,
    },
    {
        "agent_key": "call",
        "agent_name": "Call Agent",
        "agent_type": "call",
        "module_path": "agents.super_agents.call_agent.call_agent",
        "class_name": "CallAgent",
        "category": AgentCategory.COMMUNICATION.value,
        "description": "Handles call planning, call assistance, call summaries, outbound/inbound call workflows, and future phone integration.",
        "capabilities": [
            "call_planning",
            "call_summary",
            "call_script_generation",
            "inbound_call_support",
            "outbound_call_support",
        ],
        "permissions": [
            "call.read",
            "call.summarize",
            "call.plan",
        ],
        "sensitive_permissions": [
            "call.place",
            "call.record",
            "phone.access",
        ],
        "is_core": True,
    },
    {
        "agent_key": "business",
        "agent_name": "Business Agent",
        "agent_type": "business",
        "module_path": "agents.super_agents.business_agent.business_agent",
        "class_name": "BusinessAgent",
        "category": AgentCategory.BUSINESS.value,
        "description": "Handles business strategy, SaaS planning, marketing systems, proposals, reports, CRM workflows, and business operations.",
        "capabilities": [
            "business_strategy",
            "proposal_generation",
            "crm_workflows",
            "marketing_planning",
            "sales_enablement",
            "saas_operations",
        ],
        "permissions": [
            "business.read",
            "business.plan",
            "business.generate",
        ],
        "sensitive_permissions": [
            "business.send_proposal",
            "crm.write",
            "client.data_access",
        ],
        "is_core": True,
    },
    {
        "agent_key": "finance",
        "agent_name": "Finance Agent",
        "agent_type": "finance",
        "module_path": "agents.super_agents.finance_agent.finance_agent",
        "class_name": "FinanceAgent",
        "category": AgentCategory.FINANCE.value,
        "description": "Handles finance analysis, budgeting, billing logic, subscription insights, invoices, and safe financial workflows.",
        "capabilities": [
            "budget_analysis",
            "billing_support",
            "invoice_review",
            "subscription_analysis",
            "financial_reporting",
        ],
        "permissions": [
            "finance.read",
            "finance.analyze",
            "billing.read",
        ],
        "sensitive_permissions": [
            "finance.write",
            "billing.modify",
            "payment.initiate",
        ],
        "is_core": True,
    },
    {
        "agent_key": "creator",
        "agent_name": "Creator Agent",
        "agent_type": "creator",
        "module_path": "agents.super_agents.creator_agent.creator_agent",
        "class_name": "CreatorAgent",
        "category": AgentCategory.CREATIVE.value,
        "description": "Handles content creation, video scripts, ad scripts, design copy, creative campaigns, and brand storytelling.",
        "capabilities": [
            "content_creation",
            "video_script_generation",
            "ad_copywriting",
            "creative_campaigns",
            "brand_storytelling",
            "design_copy",
        ],
        "permissions": [
            "creator.generate",
            "creator.plan",
            "creator.review",
        ],
        "sensitive_permissions": [
            "creator.publish",
            "social.post",
            "brand.asset_modify",
        ],
        "is_core": True,
    },
]


# ============================================================
# AgentRegistry
# ============================================================

class AgentRegistry:
    """
    Central registry for William/Jarvis agents.

    This class is used by:

    - Master Agent:
        To discover agents and decide which one should handle a task.

    - Agent Loader:
        To safely import and instantiate agent classes.

    - Agent Router:
        To locate target agent metadata and route tasks.

    - Dashboard/API:
        To list agents, statuses, capabilities, health, and configuration.

    - Security Agent:
        To inspect sensitive permissions and required approval metadata.

    - Memory Agent:
        To understand which agent generated memory-compatible payloads.

    - Verification Agent:
        To understand which agent produced an action result.

    The registry does not perform dangerous actions.
    It only stores metadata and optionally instantiates agent classes.
    """

    def __init__(
        self,
        auto_register_defaults: bool = True,
        auto_import: bool = False,
        auto_instantiate: bool = False,
        allow_plugins: bool = True,
        strict_baseagent_subclass: bool = False,
    ) -> None:
        """
        Initialize registry.

        Args:
            auto_register_defaults:
                Registers all 15 default William agents immediately.

            auto_import:
                Attempts to import existing modules/classes.

            auto_instantiate:
                Attempts to instantiate imported classes.

            allow_plugins:
                Allows plugin-style future agents.

            strict_baseagent_subclass:
                If True, imported agent classes must inherit BaseAgent.
                If False, compatible classes may still be registered.
        """

        self.registry_id = safe_uuid("registry")
        self.created_at = utc_now_iso()
        self.updated_at = utc_now_iso()

        self.allow_plugins = allow_plugins
        self.strict_baseagent_subclass = strict_baseagent_subclass

        self._agents: Dict[str, RegisteredAgent] = {}
        self._agent_classes: Dict[str, Type[Any]] = {}
        self._agent_instances: Dict[str, Any] = {}

        self._import_failures: Dict[str, str] = {}
        self._events: List[Dict[str, Any]] = []

        if auto_register_defaults:
            self.register_default_agents(
                auto_import=auto_import,
                auto_instantiate=auto_instantiate,
            )

    # ========================================================
    # Registration
    # ========================================================

    def register_default_agents(
        self,
        auto_import: bool = False,
        auto_instantiate: bool = False,
    ) -> Dict[str, Any]:
        """
        Register the default William/Jarvis agent catalog.

        This is safe even if agent files do not exist yet.
        """

        registered: List[str] = []
        failed: List[Dict[str, Any]] = []

        for spec in DEFAULT_AGENT_SPECS:
            result = self.register_agent_spec(spec)

            if result["success"]:
                registered.append(spec["agent_key"])

                if auto_import:
                    self.safe_import_agent(spec["agent_key"])

                if auto_instantiate:
                    self.get_or_create_agent_instance(spec["agent_key"])
            else:
                failed.append(
                    {
                        "agent_key": spec.get("agent_key"),
                        "error": result.get("error"),
                        "message": result.get("message"),
                    }
                )

        self._touch()

        return structured_result(
            success=len(failed) == 0,
            message="Default agents registered." if not failed else "Default agents registered with some failures.",
            data={
                "registered": registered,
                "failed": failed,
                "total_registered": len(self._agents),
            },
        )

    def register_agent_spec(
        self,
        spec: Union[Dict[str, Any], PluginAgentSpec, RegisteredAgent],
        *,
        overwrite: bool = False,
    ) -> Dict[str, Any]:
        """
        Register an agent from dictionary, PluginAgentSpec, or RegisteredAgent.
        """

        try:
            record = self._build_registered_agent(spec)

            validation = self._validate_registered_agent(record)

            if not validation["success"]:
                return validation

            if record.agent_key in self._agents and not overwrite:
                return structured_result(
                    success=False,
                    message=f"Agent already registered: {record.agent_key}",
                    error="AGENT_ALREADY_REGISTERED",
                    data={
                        "agent_key": record.agent_key,
                    },
                )

            if record.is_plugin and not self.allow_plugins:
                return structured_result(
                    success=False,
                    message="Plugin agents are disabled for this registry.",
                    error="PLUGINS_DISABLED",
                    data={
                        "agent_key": record.agent_key,
                    },
                )

            self._agents[record.agent_key] = record
            self._touch()

            self._record_event(
                "agent_registered",
                {
                    "agent_key": record.agent_key,
                    "agent_name": record.agent_name,
                    "module_path": record.module_path,
                    "class_name": record.class_name,
                },
            )

            return structured_result(
                success=True,
                message=f"Agent registered: {record.agent_key}",
                data={
                    "agent": asdict(record),
                },
            )

        except Exception as exc:
            return structured_result(
                success=False,
                message="Failed to register agent.",
                error=str(exc),
                data={
                    "traceback": traceback.format_exc(),
                    "spec": sanitize_for_registry(spec if isinstance(spec, dict) else str(spec)),
                },
            )

    def register_plugin_agent(
        self,
        plugin_spec: Union[PluginAgentSpec, Dict[str, Any]],
        *,
        overwrite: bool = False,
        auto_import: bool = False,
        auto_instantiate: bool = False,
    ) -> Dict[str, Any]:
        """
        Register future plugin-style agent.

        Plugin agents are treated as non-core by default.
        """

        if not self.allow_plugins:
            return structured_result(
                success=False,
                message="Plugin registration is disabled.",
                error="PLUGINS_DISABLED",
            )

        if isinstance(plugin_spec, dict):
            plugin_spec = dict(plugin_spec)
            plugin_spec["is_plugin"] = True
            plugin_spec["is_core"] = False

        result = self.register_agent_spec(plugin_spec, overwrite=overwrite)

        if not result["success"]:
            return result

        agent_key = result["data"]["agent"]["agent_key"]

        import_result: Optional[Dict[str, Any]] = None
        instance_result: Optional[Dict[str, Any]] = None

        if auto_import:
            import_result = self.safe_import_agent(agent_key)

        if auto_instantiate:
            instance_result = self.get_or_create_agent_instance(agent_key)

        return structured_result(
            success=True,
            message=f"Plugin agent registered: {agent_key}",
            data={
                "agent_key": agent_key,
                "registration": result,
                "import_result": import_result,
                "instance_result": instance_result,
            },
        )

    def unregister_agent(
        self,
        agent_key: str,
        *,
        allow_core_unregister: bool = False,
    ) -> Dict[str, Any]:
        """
        Remove an agent from registry.

        Core agents cannot be removed unless allow_core_unregister=True.
        """

        if agent_key not in self._agents:
            return structured_result(
                success=False,
                message=f"Agent not found: {agent_key}",
                error="AGENT_NOT_FOUND",
            )

        record = self._agents[agent_key]

        if record.is_core and not allow_core_unregister:
            return structured_result(
                success=False,
                message=f"Cannot unregister core agent without explicit override: {agent_key}",
                error="CORE_AGENT_PROTECTED",
            )

        self._agents.pop(agent_key, None)
        self._agent_classes.pop(agent_key, None)
        self._agent_instances.pop(agent_key, None)
        self._import_failures.pop(agent_key, None)
        self._touch()

        self._record_event(
            "agent_unregistered",
            {
                "agent_key": agent_key,
            },
        )

        return structured_result(
            success=True,
            message=f"Agent unregistered: {agent_key}",
            data={
                "agent_key": agent_key,
            },
        )

    # ========================================================
    # Safe Importing
    # ========================================================

    def safe_import_agent(self, agent_key: str) -> Dict[str, Any]:
        """
        Safely import an agent module and class.

        Import failures are captured instead of crashing.
        """

        record = self._agents.get(agent_key)

        if not record:
            return structured_result(
                success=False,
                message=f"Agent not registered: {agent_key}",
                error="AGENT_NOT_REGISTERED",
            )

        try:
            module = importlib.import_module(record.module_path)
            agent_class = getattr(module, record.class_name)

            if self.strict_baseagent_subclass and not safe_issubclass(agent_class, BaseAgent):
                record.status = RegistryStatus.FAILED_IMPORT.value
                record.import_error = f"{record.class_name} does not inherit BaseAgent."
                record.updated_at = utc_now_iso()

                return structured_result(
                    success=False,
                    message=f"Imported class is not a BaseAgent subclass: {agent_key}",
                    error="INVALID_AGENT_CLASS",
                    data={
                        "agent_key": agent_key,
                        "module_path": record.module_path,
                        "class_name": record.class_name,
                    },
                )

            self._agent_classes[agent_key] = agent_class

            record.status = RegistryStatus.IMPORTED.value
            record.class_loaded = True
            record.import_error = None
            record.updated_at = utc_now_iso()

            self._import_failures.pop(agent_key, None)
            self._touch()

            self._record_event(
                "agent_imported",
                {
                    "agent_key": agent_key,
                    "module_path": record.module_path,
                    "class_name": record.class_name,
                },
            )

            return structured_result(
                success=True,
                message=f"Agent imported: {agent_key}",
                data={
                    "agent_key": agent_key,
                    "module_path": record.module_path,
                    "class_name": record.class_name,
                    "class_loaded": True,
                    "is_baseagent_subclass": safe_issubclass(agent_class, BaseAgent),
                },
            )

        except Exception as exc:
            error_text = str(exc)

            record.status = RegistryStatus.MISSING.value if isinstance(exc, ModuleNotFoundError) else RegistryStatus.FAILED_IMPORT.value
            record.import_error = error_text
            record.class_loaded = False
            record.updated_at = utc_now_iso()

            self._import_failures[agent_key] = error_text
            self._touch()

            self._record_event(
                "agent_import_failed",
                {
                    "agent_key": agent_key,
                    "module_path": record.module_path,
                    "class_name": record.class_name,
                    "error": error_text,
                },
            )

            return structured_result(
                success=False,
                message=f"Agent import failed safely: {agent_key}",
                error=error_text,
                data={
                    "agent_key": agent_key,
                    "module_path": record.module_path,
                    "class_name": record.class_name,
                    "status": record.status,
                    "traceback": traceback.format_exc(),
                },
            )

    def import_all_agents(self) -> Dict[str, Any]:
        """
        Attempt to import all registered agents safely.
        """

        imported: List[str] = []
        failed: List[Dict[str, Any]] = []

        for agent_key in list(self._agents.keys()):
            result = self.safe_import_agent(agent_key)

            if result["success"]:
                imported.append(agent_key)
            else:
                failed.append(
                    {
                        "agent_key": agent_key,
                        "message": result.get("message"),
                        "error": result.get("error"),
                    }
                )

        return structured_result(
            success=True,
            message="Agent import scan completed.",
            data={
                "imported": imported,
                "failed": failed,
                "imported_count": len(imported),
                "failed_count": len(failed),
                "total": len(self._agents),
            },
        )

    # ========================================================
    # Instance Management
    # ========================================================

    def get_or_create_agent_instance(
        self,
        agent_key: str,
        *,
        force_new: bool = False,
        init_kwargs: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Get or create an agent instance.

        This does NOT execute agent actions.
        It only creates an object instance for router/loader use.
        """

        init_kwargs = init_kwargs or {}

        record = self._agents.get(agent_key)

        if not record:
            return structured_result(
                success=False,
                message=f"Agent not registered: {agent_key}",
                error="AGENT_NOT_REGISTERED",
            )

        if not record.enabled:
            return structured_result(
                success=False,
                message=f"Agent is disabled: {agent_key}",
                error="AGENT_DISABLED",
                data={
                    "agent_key": agent_key,
                },
            )

        if not force_new and agent_key in self._agent_instances:
            return structured_result(
                success=True,
                message=f"Existing agent instance returned: {agent_key}",
                data={
                    "agent_key": agent_key,
                    "instance": self._agent_instances[agent_key],
                    "instance_created": False,
                },
                metadata={
                    "return_contains_python_object": True,
                },
            )

        if agent_key not in self._agent_classes:
            import_result = self.safe_import_agent(agent_key)

            if not import_result["success"]:
                return structured_result(
                    success=False,
                    message=f"Cannot instantiate agent because import failed: {agent_key}",
                    error=import_result.get("error"),
                    data={
                        "agent_key": agent_key,
                        "import_result": import_result,
                    },
                )

        agent_class = self._agent_classes.get(agent_key)

        if not agent_class:
            return structured_result(
                success=False,
                message=f"Agent class unavailable after import: {agent_key}",
                error="AGENT_CLASS_UNAVAILABLE",
            )

        try:
            instance = self._instantiate_agent(record, agent_class, init_kwargs)

            self._agent_instances[agent_key] = instance

            record.instance_created = True
            record.status = RegistryStatus.AVAILABLE.value
            record.updated_at = utc_now_iso()
            self._touch()

            self._record_event(
                "agent_instance_created",
                {
                    "agent_key": agent_key,
                    "class_name": record.class_name,
                },
            )

            return structured_result(
                success=True,
                message=f"Agent instance created: {agent_key}",
                data={
                    "agent_key": agent_key,
                    "instance": instance,
                    "instance_created": True,
                },
                metadata={
                    "return_contains_python_object": True,
                },
            )

        except Exception as exc:
            record.status = RegistryStatus.FAILED_IMPORT.value
            record.import_error = str(exc)
            record.updated_at = utc_now_iso()
            self._touch()

            return structured_result(
                success=False,
                message=f"Agent instantiation failed: {agent_key}",
                error=str(exc),
                data={
                    "agent_key": agent_key,
                    "traceback": traceback.format_exc(),
                },
            )

    def _instantiate_agent(
        self,
        record: RegisteredAgent,
        agent_class: Type[Any],
        init_kwargs: Dict[str, Any],
    ) -> Any:
        """
        Instantiate an agent class with safe fallbacks.

        First tries kwargs.
        Then tries no args.
        """

        try:
            return agent_class(**init_kwargs)
        except TypeError:
            pass

        try:
            return agent_class(
                agent_name=record.agent_key,
                agent_type=record.agent_type,
                capabilities=record.capabilities,
            )
        except TypeError:
            pass

        return agent_class()

    def get_agent_instance(self, agent_key: str) -> Optional[Any]:
        """
        Return existing instance if already created.
        """

        return self._agent_instances.get(agent_key)

    def clear_agent_instance(self, agent_key: str) -> Dict[str, Any]:
        """
        Remove cached instance without unregistering the agent.
        """

        if agent_key not in self._agents:
            return structured_result(
                success=False,
                message=f"Agent not registered: {agent_key}",
                error="AGENT_NOT_REGISTERED",
            )

        existed = agent_key in self._agent_instances
        self._agent_instances.pop(agent_key, None)

        record = self._agents[agent_key]
        record.instance_created = False
        record.updated_at = utc_now_iso()
        self._touch()

        return structured_result(
            success=True,
            message=f"Agent instance cache cleared: {agent_key}",
            data={
                "agent_key": agent_key,
                "existed": existed,
            },
        )

    # ========================================================
    # Lookup
    # ========================================================

    def get_agent(self, agent_key: str) -> Dict[str, Any]:
        """
        Get registered agent metadata.
        """

        record = self._agents.get(agent_key)

        if not record:
            return structured_result(
                success=False,
                message=f"Agent not found: {agent_key}",
                error="AGENT_NOT_FOUND",
            )

        return structured_result(
            success=True,
            message=f"Agent found: {agent_key}",
            data={
                "agent": asdict(record),
            },
        )

    def get_agent_class(self, agent_key: str) -> Optional[Type[Any]]:
        """
        Return imported class if available.
        """

        return self._agent_classes.get(agent_key)

    def has_agent(self, agent_key: str) -> bool:
        """
        Check whether agent is registered.
        """

        return agent_key in self._agents

    def is_agent_available(self, agent_key: str) -> bool:
        """
        Check whether agent exists, is enabled, and has loaded class or instance.
        """

        record = self._agents.get(agent_key)

        if not record:
            return False

        if not record.enabled:
            return False

        return agent_key in self._agent_classes or agent_key in self._agent_instances

    def list_agents(
        self,
        *,
        include_disabled: bool = True,
        include_plugins: bool = True,
        category: Optional[str] = None,
        status: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        List registered agents.
        """

        records: List[Dict[str, Any]] = []

        for record in self._agents.values():
            if not include_disabled and not record.enabled:
                continue

            if not include_plugins and record.is_plugin:
                continue

            if category and record.category != category:
                continue

            if status and record.status != status:
                continue

            records.append(asdict(record))

        records.sort(key=lambda item: item["agent_key"])

        return structured_result(
            success=True,
            message="Agents listed.",
            data={
                "agents": records,
                "count": len(records),
                "total_registered": len(self._agents),
            },
        )

    def list_agent_keys(self) -> List[str]:
        """
        Return all registered agent keys.
        """

        return sorted(self._agents.keys())

    def list_capabilities(self) -> Dict[str, Any]:
        """
        Return capabilities grouped by agent.
        """

        capabilities = {
            agent_key: list(record.capabilities)
            for agent_key, record in sorted(self._agents.items())
        }

        return structured_result(
            success=True,
            message="Agent capabilities listed.",
            data={
                "capabilities": capabilities,
            },
        )

    def find_agents_by_capability(self, capability: str) -> Dict[str, Any]:
        """
        Find agents that support a capability.
        """

        matches = []

        for record in self._agents.values():
            if capability in record.capabilities:
                matches.append(asdict(record))

        return structured_result(
            success=True,
            message=f"Agents matched by capability: {capability}",
            data={
                "capability": capability,
                "agents": matches,
                "count": len(matches),
            },
        )

    def find_agents_by_permission(self, permission: str) -> Dict[str, Any]:
        """
        Find agents that declare a permission.
        """

        matches = []

        for record in self._agents.values():
            if permission in record.permissions or permission in record.sensitive_permissions:
                matches.append(asdict(record))

        return structured_result(
            success=True,
            message=f"Agents matched by permission: {permission}",
            data={
                "permission": permission,
                "agents": matches,
                "count": len(matches),
            },
        )

    def search_agents(self, query: str) -> Dict[str, Any]:
        """
        Search agents by key, name, type, description, category, capabilities,
        or permissions.
        """

        query_lower = query.lower().strip()

        matches: List[Dict[str, Any]] = []

        for record in self._agents.values():
            haystack = " ".join(
                [
                    record.agent_key,
                    record.agent_name,
                    record.agent_type,
                    record.category,
                    record.description,
                    " ".join(record.capabilities),
                    " ".join(record.permissions),
                    " ".join(record.sensitive_permissions),
                ]
            ).lower()

            if query_lower in haystack:
                matches.append(asdict(record))

        return structured_result(
            success=True,
            message=f"Agent search completed: {query}",
            data={
                "query": query,
                "agents": matches,
                "count": len(matches),
            },
        )

    # ========================================================
    # Enable / Disable
    # ========================================================

    def enable_agent(self, agent_key: str) -> Dict[str, Any]:
        """
        Enable an agent.
        """

        record = self._agents.get(agent_key)

        if not record:
            return structured_result(
                success=False,
                message=f"Agent not found: {agent_key}",
                error="AGENT_NOT_FOUND",
            )

        record.enabled = True
        record.status = RegistryStatus.REGISTERED.value if record.status == RegistryStatus.DISABLED.value else record.status
        record.updated_at = utc_now_iso()
        self._touch()

        self._record_event(
            "agent_enabled",
            {
                "agent_key": agent_key,
            },
        )

        return structured_result(
            success=True,
            message=f"Agent enabled: {agent_key}",
            data={
                "agent": asdict(record),
            },
        )

    def disable_agent(
        self,
        agent_key: str,
        *,
        reason: Optional[str] = None,
        allow_core_disable: bool = True,
    ) -> Dict[str, Any]:
        """
        Disable an agent.

        Core agent disabling is allowed by default because SaaS dashboards
        may need to disable modules by plan. You can block it by setting
        allow_core_disable=False.
        """

        record = self._agents.get(agent_key)

        if not record:
            return structured_result(
                success=False,
                message=f"Agent not found: {agent_key}",
                error="AGENT_NOT_FOUND",
            )

        if record.is_core and not allow_core_disable:
            return structured_result(
                success=False,
                message=f"Cannot disable core agent without override: {agent_key}",
                error="CORE_AGENT_PROTECTED",
            )

        record.enabled = False
        record.status = RegistryStatus.DISABLED.value
        record.updated_at = utc_now_iso()

        if reason:
            record.metadata["disabled_reason"] = reason

        self._agent_instances.pop(agent_key, None)
        self._touch()

        self._record_event(
            "agent_disabled",
            {
                "agent_key": agent_key,
                "reason": reason,
            },
        )

        return structured_result(
            success=True,
            message=f"Agent disabled: {agent_key}",
            data={
                "agent": asdict(record),
            },
        )

    # ========================================================
    # Dashboard / Manifest / Router Support
    # ========================================================

    def get_registry_manifest(self) -> Dict[str, Any]:
        """
        Return full registry manifest for dashboard/API/agent_manifest.py.
        """

        agents = {
            key: asdict(record)
            for key, record in sorted(self._agents.items())
        }

        return structured_result(
            success=True,
            message="Registry manifest generated.",
            data={
                "registry": {
                    "registry_id": self.registry_id,
                    "created_at": self.created_at,
                    "updated_at": self.updated_at,
                    "allow_plugins": self.allow_plugins,
                    "strict_baseagent_subclass": self.strict_baseagent_subclass,
                    "total_agents": len(self._agents),
                    "loaded_classes": sorted(self._agent_classes.keys()),
                    "created_instances": sorted(self._agent_instances.keys()),
                    "import_failures": dict(self._import_failures),
                },
                "agents": agents,
            },
        )

    def get_router_map(self) -> Dict[str, Any]:
        """
        Build Agent Router compatible map.

        The router can use this to route by agent_key, agent_type,
        capabilities, and permissions.
        """

        by_type: Dict[str, List[str]] = {}
        by_capability: Dict[str, List[str]] = {}
        by_permission: Dict[str, List[str]] = {}

        for key, record in self._agents.items():
            if not record.enabled:
                continue

            by_type.setdefault(record.agent_type, []).append(key)

            for capability in record.capabilities:
                by_capability.setdefault(capability, []).append(key)

            for permission in record.permissions:
                by_permission.setdefault(permission, []).append(key)

            for permission in record.sensitive_permissions:
                by_permission.setdefault(permission, []).append(key)

        return structured_result(
            success=True,
            message="Router map generated.",
            data={
                "by_agent_key": {
                    key: {
                        "agent_name": record.agent_name,
                        "agent_type": record.agent_type,
                        "module_path": record.module_path,
                        "class_name": record.class_name,
                        "enabled": record.enabled,
                        "status": record.status,
                        "capabilities": list(record.capabilities),
                        "permissions": list(record.permissions),
                        "sensitive_permissions": list(record.sensitive_permissions),
                    }
                    for key, record in self._agents.items()
                    if record.enabled
                },
                "by_type": by_type,
                "by_capability": by_capability,
                "by_permission": by_permission,
            },
        )

    def get_security_map(self) -> Dict[str, Any]:
        """
        Build Security Agent compatible map.

        Security Agent can use this to know which agents have sensitive
        permissions and require approval.
        """

        security_map: Dict[str, Dict[str, Any]] = {}

        for key, record in self._agents.items():
            security_map[key] = {
                "agent_name": record.agent_name,
                "agent_type": record.agent_type,
                "requires_security_for_sensitive_actions": record.requires_security_for_sensitive_actions,
                "permissions": list(record.permissions),
                "sensitive_permissions": list(record.sensitive_permissions),
                "requires_user_context": record.requires_user_context,
                "requires_workspace_context": record.requires_workspace_context,
            }

        return structured_result(
            success=True,
            message="Security map generated.",
            data={
                "security_map": security_map,
            },
        )

    def get_memory_map(self) -> Dict[str, Any]:
        """
        Build Memory Agent compatible map.
        """

        memory_map = {
            key: {
                "agent_name": record.agent_name,
                "agent_type": record.agent_type,
                "prepares_memory_payload": record.prepares_memory_payload,
                "requires_user_context": record.requires_user_context,
                "requires_workspace_context": record.requires_workspace_context,
            }
            for key, record in self._agents.items()
        }

        return structured_result(
            success=True,
            message="Memory map generated.",
            data={
                "memory_map": memory_map,
            },
        )

    def get_verification_map(self) -> Dict[str, Any]:
        """
        Build Verification Agent compatible map.
        """

        verification_map = {
            key: {
                "agent_name": record.agent_name,
                "agent_type": record.agent_type,
                "prepares_verification_payload": record.prepares_verification_payload,
                "requires_security_for_sensitive_actions": record.requires_security_for_sensitive_actions,
            }
            for key, record in self._agents.items()
        }

        return structured_result(
            success=True,
            message="Verification map generated.",
            data={
                "verification_map": verification_map,
            },
        )

    # ========================================================
    # Health
    # ========================================================

    def health_check(self) -> Dict[str, Any]:
        """
        Return registry health summary.
        """

        total = len(self._agents)
        enabled = len([record for record in self._agents.values() if record.enabled])
        disabled = total - enabled
        imported = len(self._agent_classes)
        instantiated = len(self._agent_instances)
        failed = len(self._import_failures)
        missing = len(
            [
                record
                for record in self._agents.values()
                if record.status in {RegistryStatus.MISSING.value, RegistryStatus.FAILED_IMPORT.value}
            ]
        )

        status = "healthy"

        if failed > 0 or missing > 0:
            status = "degraded"

        if total == 0:
            status = "empty"

        return structured_result(
            success=True,
            message="Agent registry health check completed.",
            data={
                "registry_id": self.registry_id,
                "status": status,
                "created_at": self.created_at,
                "updated_at": self.updated_at,
                "total_agents": total,
                "enabled_agents": enabled,
                "disabled_agents": disabled,
                "imported_classes": imported,
                "created_instances": instantiated,
                "import_failures": failed,
                "missing_or_failed_agents": missing,
                "allow_plugins": self.allow_plugins,
                "strict_baseagent_subclass": self.strict_baseagent_subclass,
            },
        )

    def health_check_agents(self) -> Dict[str, Any]:
        """
        Run health checks on instantiated agents only.

        This does not instantiate missing agents automatically.
        """

        results: Dict[str, Any] = {}

        for agent_key, instance in self._agent_instances.items():
            try:
                if hasattr(instance, "health_check") and callable(instance.health_check):
                    results[agent_key] = instance.health_check()
                else:
                    results[agent_key] = {
                        "success": False,
                        "message": "Agent instance has no health_check method.",
                        "data": {},
                        "error": "HEALTH_CHECK_UNAVAILABLE",
                        "metadata": {},
                    }
            except Exception as exc:
                results[agent_key] = {
                    "success": False,
                    "message": "Agent health check failed.",
                    "data": {
                        "traceback": traceback.format_exc(),
                    },
                    "error": str(exc),
                    "metadata": {},
                }

        return structured_result(
            success=True,
            message="Instantiated agent health checks completed.",
            data={
                "agent_health": results,
                "checked_count": len(results),
            },
        )

    # ========================================================
    # Validation
    # ========================================================

    def validate_registry(self) -> Dict[str, Any]:
        """
        Validate registry records without importing modules.
        """

        valid: List[str] = []
        invalid: List[Dict[str, Any]] = []

        for key, record in self._agents.items():
            result = self._validate_registered_agent(record)

            if result["success"]:
                valid.append(key)
            else:
                invalid.append(
                    {
                        "agent_key": key,
                        "message": result.get("message"),
                        "error": result.get("error"),
                        "data": result.get("data"),
                    }
                )

        return structured_result(
            success=len(invalid) == 0,
            message="Registry validation completed.",
            data={
                "valid": valid,
                "invalid": invalid,
                "valid_count": len(valid),
                "invalid_count": len(invalid),
            },
        )

    def _validate_registered_agent(self, record: RegisteredAgent) -> Dict[str, Any]:
        """
        Validate a RegisteredAgent record.
        """

        missing: List[str] = []

        if not record.agent_key:
            missing.append("agent_key")

        if not record.agent_name:
            missing.append("agent_name")

        if not record.agent_type:
            missing.append("agent_type")

        if not record.module_path:
            missing.append("module_path")

        if not record.class_name:
            missing.append("class_name")

        if missing:
            return structured_result(
                success=False,
                message=f"Registered agent missing required fields: {', '.join(missing)}",
                error="INVALID_AGENT_RECORD",
                data={
                    "missing": missing,
                    "agent": asdict(record),
                },
            )

        if "." not in record.module_path:
            return structured_result(
                success=False,
                message="module_path should be a dotted Python import path.",
                error="INVALID_MODULE_PATH",
                data={
                    "agent_key": record.agent_key,
                    "module_path": record.module_path,
                },
            )

        return structured_result(
            success=True,
            message="Registered agent is valid.",
            data={
                "agent_key": record.agent_key,
            },
        )

    # ========================================================
    # Internal Build Helpers
    # ========================================================

    def _build_registered_agent(
        self,
        spec: Union[Dict[str, Any], PluginAgentSpec, RegisteredAgent],
    ) -> RegisteredAgent:
        """
        Convert supported spec types into RegisteredAgent.
        """

        if isinstance(spec, RegisteredAgent):
            spec.updated_at = utc_now_iso()
            return spec

        if isinstance(spec, PluginAgentSpec):
            return RegisteredAgent(
                registry_id=safe_uuid("agent"),
                agent_key=spec.agent_key,
                agent_name=spec.agent_name,
                agent_type=spec.agent_type,
                module_path=spec.module_path,
                class_name=spec.class_name,
                category=spec.category,
                description=spec.description,
                capabilities=list(spec.capabilities),
                permissions=list(spec.permissions),
                sensitive_permissions=list(spec.sensitive_permissions),
                requires_user_context=spec.requires_user_context,
                requires_workspace_context=spec.requires_workspace_context,
                enabled=spec.enabled,
                is_core=False,
                is_plugin=True,
                status=RegistryStatus.REGISTERED.value,
                metadata=dict(spec.metadata),
            )

        if isinstance(spec, dict):
            return RegisteredAgent(
                registry_id=str(spec.get("registry_id") or safe_uuid("agent")),
                agent_key=str(spec.get("agent_key") or "").strip(),
                agent_name=str(spec.get("agent_name") or "").strip(),
                agent_type=str(spec.get("agent_type") or "").strip(),
                module_path=str(spec.get("module_path") or "").strip(),
                class_name=str(spec.get("class_name") or "").strip(),
                category=str(spec.get("category") or AgentCategory.CORE.value),
                description=str(spec.get("description") or ""),
                capabilities=list(spec.get("capabilities") or []),
                permissions=list(spec.get("permissions") or []),
                sensitive_permissions=list(spec.get("sensitive_permissions") or []),
                requires_user_context=bool(spec.get("requires_user_context", True)),
                requires_workspace_context=bool(spec.get("requires_workspace_context", True)),
                requires_security_for_sensitive_actions=bool(
                    spec.get("requires_security_for_sensitive_actions", True)
                ),
                prepares_verification_payload=bool(spec.get("prepares_verification_payload", True)),
                prepares_memory_payload=bool(spec.get("prepares_memory_payload", True)),
                enabled=bool(spec.get("enabled", True)),
                is_core=bool(spec.get("is_core", True)),
                is_plugin=bool(spec.get("is_plugin", False)),
                status=str(spec.get("status") or RegistryStatus.REGISTERED.value),
                import_error=spec.get("import_error"),
                class_loaded=bool(spec.get("class_loaded", False)),
                instance_created=bool(spec.get("instance_created", False)),
                created_at=str(spec.get("created_at") or utc_now_iso()),
                updated_at=str(spec.get("updated_at") or utc_now_iso()),
                metadata=dict(spec.get("metadata") or {}),
            )

        raise TypeError(f"Unsupported agent spec type: {type(spec)}")

    def _touch(self) -> None:
        """
        Update registry timestamp.
        """

        self.updated_at = utc_now_iso()

    def _record_event(self, event_type: str, payload: Dict[str, Any]) -> None:
        """
        Store lightweight registry event.

        Dashboard/API can expose this later.
        """

        event = {
            "event_id": safe_uuid("registry_event"),
            "event_type": event_type,
            "timestamp": utc_now_iso(),
            "payload": sanitize_for_registry(payload),
        }

        self._events.append(event)

        if len(self._events) > 500:
            self._events = self._events[-500:]

        logger.debug("Registry event: %s", event)

    def get_events(self, limit: int = 100) -> Dict[str, Any]:
        """
        Return latest registry events.
        """

        safe_limit = max(1, min(int(limit), 500))

        return structured_result(
            success=True,
            message="Registry events returned.",
            data={
                "events": self._events[-safe_limit:],
                "count": min(len(self._events), safe_limit),
            },
        )

    # ========================================================
    # Export / Import Registry State
    # ========================================================

    def export_registry_state(self) -> Dict[str, Any]:
        """
        Export serializable registry state.

        Does not include live Python instances/classes.
        """

        return structured_result(
            success=True,
            message="Registry state exported.",
            data={
                "registry_id": self.registry_id,
                "created_at": self.created_at,
                "updated_at": self.updated_at,
                "allow_plugins": self.allow_plugins,
                "strict_baseagent_subclass": self.strict_baseagent_subclass,
                "agents": {
                    key: asdict(record)
                    for key, record in sorted(self._agents.items())
                },
                "import_failures": dict(self._import_failures),
                "events": list(self._events),
            },
        )

    def import_registry_state(
        self,
        state: Dict[str, Any],
        *,
        overwrite: bool = False,
    ) -> Dict[str, Any]:
        """
        Import registry state from exported data.

        Live classes and instances are not imported.
        """

        try:
            agents = state.get("agents", {})

            imported: List[str] = []
            failed: List[Dict[str, Any]] = []

            for key, record_data in agents.items():
                if key in self._agents and not overwrite:
                    failed.append(
                        {
                            "agent_key": key,
                            "error": "AGENT_ALREADY_EXISTS",
                        }
                    )
                    continue

                result = self.register_agent_spec(record_data, overwrite=overwrite)

                if result["success"]:
                    imported.append(key)
                else:
                    failed.append(
                        {
                            "agent_key": key,
                            "error": result.get("error"),
                            "message": result.get("message"),
                        }
                    )

            self._touch()

            return structured_result(
                success=len(failed) == 0,
                message="Registry state imported." if not failed else "Registry state imported with some failures.",
                data={
                    "imported": imported,
                    "failed": failed,
                },
            )

        except Exception as exc:
            return structured_result(
                success=False,
                message="Failed to import registry state.",
                error=str(exc),
                data={
                    "traceback": traceback.format_exc(),
                },
            )


# ============================================================
# Global Registry Singleton Helpers
# ============================================================

_GLOBAL_REGISTRY: Optional[AgentRegistry] = None


def get_global_registry(
    *,
    auto_register_defaults: bool = True,
    auto_import: bool = False,
    auto_instantiate: bool = False,
) -> AgentRegistry:
    """
    Return global singleton registry.

    Useful for FastAPI, dashboard, Master Agent, Agent Router,
    and CLI scripts.
    """

    global _GLOBAL_REGISTRY

    if _GLOBAL_REGISTRY is None:
        _GLOBAL_REGISTRY = AgentRegistry(
            auto_register_defaults=auto_register_defaults,
            auto_import=auto_import,
            auto_instantiate=auto_instantiate,
        )

    return _GLOBAL_REGISTRY


def reset_global_registry() -> AgentRegistry:
    """
    Reset global registry.

    Useful for tests.
    """

    global _GLOBAL_REGISTRY

    _GLOBAL_REGISTRY = AgentRegistry()

    return _GLOBAL_REGISTRY


# ============================================================
# Development Self-Test
# ============================================================

def _self_test() -> Dict[str, Any]:
    """
    Run a safe registry self-test.

    Command:
        python agents/registry.py
    """

    registry = AgentRegistry(
        auto_register_defaults=True,
        auto_import=False,
        auto_instantiate=False,
    )

    health = registry.health_check()
    manifest = registry.get_registry_manifest()
    router_map = registry.get_router_map()
    security_map = registry.get_security_map()
    capabilities = registry.list_capabilities()
    validation = registry.validate_registry()

    return {
        "health": health,
        "validation": validation,
        "agent_keys": registry.list_agent_keys(),
        "manifest_summary": {
            "total_agents": manifest["data"]["registry"]["total_agents"],
            "loaded_classes": manifest["data"]["registry"]["loaded_classes"],
            "created_instances": manifest["data"]["registry"]["created_instances"],
        },
        "router_map_summary": {
            "agent_count": len(router_map["data"]["by_agent_key"]),
            "types": sorted(router_map["data"]["by_type"].keys()),
        },
        "security_map_summary": {
            "agent_count": len(security_map["data"]["security_map"]),
        },
        "capability_agent_count": len(capabilities["data"]["capabilities"]),
    }


def _self_test_print() -> None:
    """
    Print self-test as JSON.
    """

    import json

    print(json.dumps(_self_test(), indent=2, default=str))


if __name__ == "__main__":
    _self_test_print()


# ============================================================
# Completion Tracking
# ============================================================

"""
Agent/Module: Global Agent Infrastructure Files
File Completed: registry.py
Completion: 22.2%
Completed Files: ['base_agent.py', 'registry.py']
Remaining Files: ['agent_loader.py', 'agent_router.py', 'agent_manifest.py', 'agent_permissions.py', 'agent_events.py', 'agent_health.py', 'agent_config.py']
Next Recommended File: agents/agent_loader.py
FILE COMPLETE.
"""