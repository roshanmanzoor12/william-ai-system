"""
agents/visual_agent/workflow_learner.py

Visual Workflow Learner for William / Jarvis Multi-Agent AI SaaS System.

Purpose:
    Learns workflows from visual steps and produces safe automation recipes.

Responsibilities:
    - Accept visual steps from screenshots, OCR, UI mapper, element detector,
      video analyzer, or manual dashboard input.
    - Normalize visual observations into stable workflow steps.
    - Infer likely action types: click, type, select, wait, scroll, navigate,
      upload, download, submit, confirm, unknown.
    - Build a reusable automation recipe without executing actions.
    - Detect repeated patterns, sensitive steps, required approvals, and
      verification checkpoints.
    - Prepare payloads compatible with Master Agent, Workflow Agent,
      Security Agent, Memory Agent, Verification Agent, Dashboard/API,
      Agent Registry, and future plugins.

Safety:
    - This file does not execute browser, system, financial, messaging,
      calling, or destructive actions.
    - It only learns and describes workflows.
    - Sensitive / destructive / credential / payment-like actions are flagged.
    - Approval hooks are included for Security Agent compatibility.

Import Safety:
    - Safe to import even if William core files are not created yet.
    - Uses fallback BaseAgent when unavailable.
    - Uses standard library only.

Public Class:
    VisualWorkflowLearner
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# =============================================================================
# Optional William imports with safe fallbacks
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Minimal fallback BaseAgent.

        The real William BaseAgent may provide:
        - agent identity
        - event emission
        - task lifecycle
        - permissions
        - registry hooks
        - memory hooks
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)


# =============================================================================
# Logging
# =============================================================================

logger = logging.getLogger(__name__)
if not logger.handlers:
    logger.addHandler(logging.NullHandler())


# =============================================================================
# Enums / constants
# =============================================================================

class WorkflowActionType(str, Enum):
    CLICK = "click"
    DOUBLE_CLICK = "double_click"
    RIGHT_CLICK = "right_click"
    TYPE_TEXT = "type_text"
    SELECT = "select"
    CHECK = "check"
    UNCHECK = "uncheck"
    SCROLL = "scroll"
    WAIT = "wait"
    NAVIGATE = "navigate"
    SUBMIT = "submit"
    CONFIRM = "confirm"
    CANCEL = "cancel"
    UPLOAD = "upload"
    DOWNLOAD = "download"
    COPY = "copy"
    PASTE = "paste"
    HOVER = "hover"
    DRAG = "drag"
    DROP = "drop"
    SCREEN_CHANGE = "screen_change"
    VERIFY = "verify"
    UNKNOWN = "unknown"


class WorkflowRiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class WorkflowStepStatus(str, Enum):
    LEARNED = "learned"
    NEEDS_REVIEW = "needs_review"
    NEEDS_SECURITY_APPROVAL = "needs_security_approval"
    UNSUPPORTED = "unsupported"


DEFAULT_SENSITIVE_KEYWORDS = {
    "password",
    "passcode",
    "otp",
    "2fa",
    "verification code",
    "secret",
    "api key",
    "token",
    "private key",
    "card",
    "credit card",
    "debit card",
    "cvv",
    "ssn",
    "social security",
    "bank",
    "routing",
    "wire",
    "payment",
    "pay",
    "purchase",
    "checkout",
    "transfer",
    "delete",
    "remove",
    "archive",
    "trash",
    "send",
    "submit",
    "publish",
    "post",
    "call",
    "dial",
    "message",
    "email",
    "whatsapp",
    "telegram",
    "sms",
    "confirm",
    "approve",
    "accept",
    "decline",
    "signature",
}

DEFAULT_DESTRUCTIVE_KEYWORDS = {
    "delete",
    "remove",
    "trash",
    "archive",
    "cancel subscription",
    "close account",
    "drop",
    "wipe",
    "reset",
    "terminate",
    "revoke",
    "disable",
    "ban",
    "block",
}

DEFAULT_SUBMIT_KEYWORDS = {
    "submit",
    "save",
    "continue",
    "next",
    "finish",
    "done",
    "confirm",
    "apply",
    "send",
    "publish",
    "checkout",
    "place order",
    "book",
    "schedule",
    "create",
    "update",
}

DEFAULT_NAVIGATION_KEYWORDS = {
    "url",
    "address bar",
    "go to",
    "navigate",
    "open page",
    "visit",
    "link",
    "browser",
}

DEFAULT_WAIT_KEYWORDS = {
    "loading",
    "please wait",
    "processing",
    "spinner",
    "progress",
    "pending",
    "saving",
    "uploading",
    "downloading",
}

DEFAULT_INPUT_KEYWORDS = {
    "input",
    "field",
    "textbox",
    "textarea",
    "search",
    "email",
    "phone",
    "name",
    "password",
    "message",
    "description",
    "amount",
    "address",
}

DEFAULT_RECIPE_VERSION = "1.0"


# =============================================================================
# Data structures
# =============================================================================

@dataclass
class VisualWorkflowLearnerConfig:
    """
    Runtime configuration for VisualWorkflowLearner.
    """

    require_context: bool = True
    min_step_confidence: float = 0.35
    high_confidence_threshold: float = 0.80
    duplicate_similarity_threshold: float = 0.92
    max_steps: int = 500
    max_text_length: int = 2000
    max_recipe_steps: int = 500
    allow_sensitive_recipe_creation: bool = True
    require_security_for_sensitive_steps: bool = True
    require_security_for_destructive_steps: bool = True
    include_raw_observations: bool = False
    include_visual_bounds: bool = True
    include_element_selectors: bool = True
    include_verification_checkpoints: bool = True
    include_memory_payload: bool = True
    default_wait_seconds: float = 1.0
    screen_change_wait_seconds: float = 1.5
    navigation_wait_seconds: float = 3.0


@dataclass
class VisualElementRef:
    """
    Stable reference to a UI element detected from screenshot/video/OCR.
    """

    element_id: str
    label: Optional[str] = None
    role: Optional[str] = None
    text: Optional[str] = None
    placeholder: Optional[str] = None
    selector: Optional[str] = None
    bounds: Optional[Dict[str, Union[int, float]]] = None
    center: Optional[Dict[str, Union[int, float]]] = None
    confidence: float = 0.0
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VisualWorkflowStep:
    """
    Normalized visual workflow step.
    """

    step_id: str
    index: int
    action_type: WorkflowActionType
    title: str
    description: str
    screen_name: Optional[str] = None
    app_name: Optional[str] = None
    page_url: Optional[str] = None
    element: Optional[VisualElementRef] = None
    input_value: Optional[str] = None
    expected_result: Optional[str] = None
    wait_seconds: Optional[float] = None
    confidence: float = 0.0
    risk_level: WorkflowRiskLevel = WorkflowRiskLevel.LOW
    status: WorkflowStepStatus = WorkflowStepStatus.LEARNED
    sensitive: bool = False
    destructive: bool = False
    requires_security: bool = False
    verification_hint: Optional[str] = None
    source: str = "visual"
    raw_observation: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AutomationRecipeStep:
    """
    Output automation recipe step.

    Important:
        This describes what a future Workflow Agent may do.
        It does not execute anything.
    """

    recipe_step_id: str
    order: int
    action: str
    target: Dict[str, Any]
    value: Optional[Any] = None
    wait_seconds: Optional[float] = None
    preconditions: List[Dict[str, Any]] = field(default_factory=list)
    postconditions: List[Dict[str, Any]] = field(default_factory=list)
    verification: Dict[str, Any] = field(default_factory=dict)
    safety: Dict[str, Any] = field(default_factory=dict)
    retry: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AutomationRecipe:
    """
    Safe reusable automation recipe generated from learned visual steps.
    """

    recipe_id: str
    name: str
    version: str
    description: str
    user_id: str
    workspace_id: str
    source: str
    steps: List[AutomationRecipeStep]
    variables: Dict[str, Any] = field(default_factory=dict)
    required_permissions: List[str] = field(default_factory=list)
    security_review_required: bool = False
    verification_required: bool = True
    risk_level: WorkflowRiskLevel = WorkflowRiskLevel.LOW
    confidence: float = 0.0
    tags: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# VisualWorkflowLearner
# =============================================================================

class VisualWorkflowLearner(BaseAgent):
    """
    Learns workflows from visual steps and produces automation recipes.

    How it connects to William/Jarvis:

    Master Agent:
        Routes visual learning tasks here when user wants William to learn
        a workflow from screenshots, screen recordings, or detected UI steps.

    Visual Agent:
        Provides OCR, screen context, UI map, screenshot reader, video analyzer,
        image analyzer, and element detector outputs.

    Workflow Agent:
        Can later consume the generated recipe. This file does not execute it.

    Security Agent:
        Reviews sensitive, destructive, financial, messaging, calling, publishing,
        credential, or account-changing steps.

    Verification Agent:
        Receives prepared verification payloads and checkpoints.

    Memory Agent:
        Receives compact reusable workflow memory payloads, scoped by user_id
        and workspace_id.

    Dashboard/API:
        Can call public methods and receive structured JSON-safe results.

    Agent Registry / Loader:
        Class and module are import-safe and expose stable public interfaces.
    """

    agent_type = "visual_agent_helper"
    file_path = "agents/visual_agent/workflow_learner.py"
    public_name = "Visual Workflow Learner"
    supported_input_sources = {
        "screenshot_reader",
        "video_analyzer",
        "ocr_engine",
        "ui_mapper",
        "element_detector",
        "screen_context",
        "manual",
        "dashboard",
        "api",
        "visual_agent",
    }

    def __init__(
        self,
        config: Optional[Union[VisualWorkflowLearnerConfig, Mapping[str, Any]]] = None,
        security_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        workflow_agent: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        logger_instance: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name="VisualWorkflowLearner", **kwargs)

        if isinstance(config, VisualWorkflowLearnerConfig):
            self.config = config
        elif isinstance(config, Mapping):
            self.config = VisualWorkflowLearnerConfig(**dict(config))
        else:
            self.config = VisualWorkflowLearnerConfig()

        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.verification_agent = verification_agent
        self.workflow_agent = workflow_agent
        self.event_bus = event_bus
        self.audit_logger = audit_logger
        self.logger = logger_instance or logger

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def learn_workflow(
        self,
        *,
        user_id: Optional[str],
        workspace_id: Optional[str],
        visual_steps: Sequence[Mapping[str, Any]],
        workflow_name: Optional[str] = None,
        workflow_description: Optional[str] = None,
        source: str = "visual_agent",
        task_id: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        require_security: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Learn a workflow from visual steps and produce an automation recipe.

        Args:
            user_id: SaaS user id.
            workspace_id: SaaS workspace id.
            visual_steps: Ordered visual observations.
            workflow_name: Optional recipe name.
            workflow_description: Optional recipe description.
            source: Source module or channel.
            task_id: Optional Master Agent task id.
            request_id: Optional dashboard/API request id.
            metadata: Optional extra metadata.
            require_security: Optional explicit security requirement.

        Returns:
            Structured William/Jarvis result.
        """

        started_at = self._utc_now_iso()
        context = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "task_id": task_id,
            "request_id": request_id,
            "source": source,
            "metadata": dict(metadata or {}),
        }

        valid_context = self._validate_task_context(context)
        if not valid_context["success"]:
            return valid_context

        if not isinstance(visual_steps, Sequence) or isinstance(visual_steps, (str, bytes)):
            return self._error_result(
                message="visual_steps must be a sequence of visual observation dictionaries.",
                error_code="INVALID_VISUAL_STEPS",
                data={"received_type": type(visual_steps).__name__},
                metadata=context,
            )

        if len(visual_steps) == 0:
            return self._error_result(
                message="No visual steps were provided for workflow learning.",
                error_code="EMPTY_VISUAL_STEPS",
                data={},
                metadata=context,
            )

        if len(visual_steps) > self.config.max_steps:
            return self._error_result(
                message=f"Too many visual steps. Max allowed is {self.config.max_steps}.",
                error_code="TOO_MANY_VISUAL_STEPS",
                data={"received": len(visual_steps), "max_steps": self.config.max_steps},
                metadata=context,
            )

        normalized_steps = self.normalize_visual_steps(
            visual_steps=visual_steps,
            source=source,
            include_raw=self.config.include_raw_observations,
        )

        learned_steps = self.infer_workflow_steps(
            normalized_steps=normalized_steps,
            source=source,
        )

        learned_steps = self.optimize_workflow_steps(learned_steps)
        risk_summary = self.assess_workflow_risk(learned_steps)

        if require_security is None:
            require_security = self._requires_security_check(
                action="learn_workflow",
                context=context,
                learned_steps=learned_steps,
                risk_summary=risk_summary,
            )

        security_approval: Dict[str, Any] = {
            "approved": True,
            "required": False,
            "source": "not_required",
            "message": "Security review was not required.",
        }

        if require_security:
            security_approval = self._request_security_approval(
                action="learn_workflow",
                context=context,
                learned_steps=learned_steps,
                risk_summary=risk_summary,
            )

            if not security_approval.get("approved", False):
                return self._error_result(
                    message="Workflow learning blocked by security policy.",
                    error_code="SECURITY_APPROVAL_DENIED",
                    data={
                        "risk_summary": risk_summary,
                        "security_approval": security_approval,
                    },
                    metadata=context,
                )

        recipe = self.build_automation_recipe(
            user_id=str(user_id),
            workspace_id=str(workspace_id),
            learned_steps=learned_steps,
            workflow_name=workflow_name,
            workflow_description=workflow_description,
            source=source,
            metadata={
                **dict(metadata or {}),
                "task_id": task_id,
                "request_id": request_id,
                "security_approval": security_approval,
            },
        )

        verification_payload = self._prepare_verification_payload(
            action="learn_workflow",
            context=context,
            learned_steps=learned_steps,
            recipe=recipe,
            risk_summary=risk_summary,
            started_at=started_at,
        )

        memory_payload = self._prepare_memory_payload(
            action="learn_workflow",
            context=context,
            learned_steps=learned_steps,
            recipe=recipe,
            risk_summary=risk_summary,
        )

        self._emit_agent_event(
            event_name="visual.workflow.learned",
            payload={
                "recipe_id": recipe.recipe_id,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "risk_level": recipe.risk_level.value,
                "step_count": len(recipe.steps),
                "confidence": recipe.confidence,
            },
        )

        self._log_audit_event(
            action="learn_workflow",
            context=context,
            outcome={
                "recipe_id": recipe.recipe_id,
                "step_count": len(recipe.steps),
                "risk_level": recipe.risk_level.value,
                "security_review_required": recipe.security_review_required,
                "success": True,
            },
        )

        return self._safe_result(
            success=True,
            message="Visual workflow learned and automation recipe generated.",
            data={
                "recipe": self.recipe_to_dict(recipe),
                "learned_steps": [self.step_to_dict(step) for step in learned_steps],
                "risk_summary": risk_summary,
                "security_approval": security_approval,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                **context,
                "started_at": started_at,
                "finished_at": self._utc_now_iso(),
                "agent": self.agent_name,
                "module": self.file_path,
            },
        )

    def normalize_visual_steps(
        self,
        *,
        visual_steps: Sequence[Mapping[str, Any]],
        source: str = "visual_agent",
        include_raw: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Normalize visual observations from different Visual Agent tools.

        Supported input shapes:
            - screenshot_reader result
            - video_analyzer frame step
            - ui_mapper element/action
            - element_detector item
            - manual dashboard action dict
            - generic dict with text, bounds, role, action, screen, etc.
        """

        normalized: List[Dict[str, Any]] = []

        for idx, raw_step in enumerate(visual_steps):
            if not isinstance(raw_step, Mapping):
                continue

            text = self._clean_text(
                raw_step.get("text")
                or raw_step.get("label")
                or raw_step.get("ocr_text")
                or raw_step.get("visible_text")
                or raw_step.get("description")
                or raw_step.get("title")
                or ""
            )

            action_hint = self._clean_text(
                raw_step.get("action")
                or raw_step.get("action_type")
                or raw_step.get("event")
                or raw_step.get("gesture")
                or raw_step.get("intent")
                or ""
            ).lower()

            element_data = self._extract_element_data(raw_step, fallback_index=idx)
            screen_name = self._clean_text(
                raw_step.get("screen_name")
                or raw_step.get("screen")
                or raw_step.get("page_title")
                or raw_step.get("context")
                or raw_step.get("workflow_context")
                or ""
            ) or None

            app_name = self._clean_text(
                raw_step.get("app_name")
                or raw_step.get("application")
                or raw_step.get("browser")
                or raw_step.get("window_title")
                or ""
            ) or None

            page_url = self._clean_text(
                raw_step.get("page_url")
                or raw_step.get("url")
                or raw_step.get("current_url")
                or raw_step.get("href")
                or ""
            ) or None

            input_value = raw_step.get("input_value", raw_step.get("value", raw_step.get("typed_text")))
            if isinstance(input_value, str):
                input_value = self._clean_text(input_value)

            confidence = self._safe_float(
                raw_step.get("confidence")
                or raw_step.get("score")
                or raw_step.get("detection_confidence")
                or element_data.get("confidence")
                or 0.5,
                default=0.5,
            )

            timestamp = raw_step.get("timestamp") or raw_step.get("created_at") or raw_step.get("time")

            normalized_step = {
                "index": idx,
                "source": source,
                "text": text,
                "action_hint": action_hint,
                "screen_name": screen_name,
                "app_name": app_name,
                "page_url": page_url,
                "input_value": input_value,
                "element": element_data,
                "confidence": max(0.0, min(1.0, confidence)),
                "timestamp": timestamp,
                "metadata": self._safe_metadata(raw_step.get("metadata", {})),
            }

            if include_raw:
                normalized_step["raw_observation"] = self._json_safe_dict(raw_step)

            normalized.append(normalized_step)

        return normalized

    def infer_workflow_steps(
        self,
        *,
        normalized_steps: Sequence[Mapping[str, Any]],
        source: str = "visual_agent",
    ) -> List[VisualWorkflowStep]:
        """
        Infer automation-oriented workflow steps from normalized observations.
        """

        learned: List[VisualWorkflowStep] = []

        for idx, item in enumerate(normalized_steps):
            if not isinstance(item, Mapping):
                continue

            confidence = self._safe_float(item.get("confidence"), default=0.5)
            action_type = self._infer_action_type(item)
            element = self._build_element_ref(item.get("element"), fallback_index=idx)

            text = self._clean_text(item.get("text") or "")
            action_hint = self._clean_text(item.get("action_hint") or "")
            screen_name = item.get("screen_name")
            app_name = item.get("app_name")
            page_url = item.get("page_url")
            input_value = item.get("input_value")

            sensitive = self._is_sensitive_step(
                text=text,
                action_hint=action_hint,
                input_value=input_value,
                element=element,
                action_type=action_type,
            )
            destructive = self._is_destructive_step(
                text=text,
                action_hint=action_hint,
                element=element,
                action_type=action_type,
            )

            risk_level = self._infer_step_risk(
                action_type=action_type,
                sensitive=sensitive,
                destructive=destructive,
                text=text,
                action_hint=action_hint,
            )

            requires_security = self._step_requires_security(
                action_type=action_type,
                sensitive=sensitive,
                destructive=destructive,
                risk_level=risk_level,
            )

            status = WorkflowStepStatus.LEARNED
            if confidence < self.config.min_step_confidence or action_type == WorkflowActionType.UNKNOWN:
                status = WorkflowStepStatus.NEEDS_REVIEW
            if requires_security:
                status = WorkflowStepStatus.NEEDS_SECURITY_APPROVAL

            title = self._make_step_title(
                action_type=action_type,
                text=text,
                element=element,
                input_value=input_value,
            )
            description = self._make_step_description(
                action_type=action_type,
                text=text,
                element=element,
                input_value=input_value,
                screen_name=screen_name,
                page_url=page_url,
            )

            wait_seconds = self._infer_wait_seconds(action_type, text, action_hint)

            learned.append(
                VisualWorkflowStep(
                    step_id=self._stable_step_id(item, idx),
                    index=idx,
                    action_type=action_type,
                    title=title,
                    description=description,
                    screen_name=str(screen_name) if screen_name else None,
                    app_name=str(app_name) if app_name else None,
                    page_url=str(page_url) if page_url else None,
                    element=element,
                    input_value=self._mask_sensitive_value(input_value, sensitive),
                    expected_result=self._infer_expected_result(
                        action_type=action_type,
                        text=text,
                        element=element,
                        page_url=page_url,
                    ),
                    wait_seconds=wait_seconds,
                    confidence=round(confidence, 4),
                    risk_level=risk_level,
                    status=status,
                    sensitive=sensitive,
                    destructive=destructive,
                    requires_security=requires_security,
                    verification_hint=self._infer_verification_hint(
                        action_type=action_type,
                        text=text,
                        element=element,
                        screen_name=screen_name,
                        page_url=page_url,
                    ),
                    source=source,
                    raw_observation=item.get("raw_observation") if self.config.include_raw_observations else None,
                    metadata=self._safe_metadata(item.get("metadata", {})),
                )
            )

        return learned

    def optimize_workflow_steps(
        self,
        learned_steps: Sequence[VisualWorkflowStep],
    ) -> List[VisualWorkflowStep]:
        """
        Remove weak duplicates and insert wait/verify hints where useful.

        This does not change the meaning of the workflow. It only improves
        recipe quality.
        """

        optimized: List[VisualWorkflowStep] = []
        last_signature: Optional[str] = None

        for step in learned_steps:
            signature = self._step_signature(step)

            if signature == last_signature and step.confidence < self.config.high_confidence_threshold:
                continue

            optimized.append(step)
            last_signature = signature

        return optimized[: self.config.max_recipe_steps]

    def build_automation_recipe(
        self,
        *,
        user_id: str,
        workspace_id: str,
        learned_steps: Sequence[VisualWorkflowStep],
        workflow_name: Optional[str] = None,
        workflow_description: Optional[str] = None,
        source: str = "visual_agent",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> AutomationRecipe:
        """
        Build a safe automation recipe from learned visual steps.

        The recipe is declarative. It is designed for later Workflow Agent
        execution only after appropriate permissions and verification.
        """

        recipe_steps: List[AutomationRecipeStep] = []
        required_permissions: List[str] = []
        tags: List[str] = []

        for order, step in enumerate(learned_steps, start=1):
            target = self._build_recipe_target(step)
            safety = self._build_recipe_safety(step)
            verification = self._build_recipe_verification(step)
            retry = self._build_recipe_retry(step)

            if step.requires_security and "security.review" not in required_permissions:
                required_permissions.append("security.review")

            if step.action_type in {WorkflowActionType.NAVIGATE} and "browser.navigation" not in required_permissions:
                required_permissions.append("browser.navigation")

            if step.action_type in {WorkflowActionType.UPLOAD, WorkflowActionType.DOWNLOAD} and "file.access" not in required_permissions:
                required_permissions.append("file.access")

            if step.action_type in {WorkflowActionType.SUBMIT, WorkflowActionType.CONFIRM} and "workflow.submit" not in required_permissions:
                required_permissions.append("workflow.submit")

            if step.sensitive and "sensitive_data.handling" not in required_permissions:
                required_permissions.append("sensitive_data.handling")

            if step.destructive and "destructive_action.review" not in required_permissions:
                required_permissions.append("destructive_action.review")

            recipe_steps.append(
                AutomationRecipeStep(
                    recipe_step_id=f"rstep_{order:04d}_{step.step_id[-8:]}",
                    order=order,
                    action=step.action_type.value,
                    target=target,
                    value=step.input_value,
                    wait_seconds=step.wait_seconds,
                    preconditions=self._build_preconditions(step),
                    postconditions=self._build_postconditions(step),
                    verification=verification,
                    safety=safety,
                    retry=retry,
                    metadata={
                        "source_step_id": step.step_id,
                        "source": step.source,
                        "confidence": step.confidence,
                        "status": step.status.value,
                    },
                )
            )

            if step.app_name:
                tags.append(self._slugify(step.app_name))
            if step.screen_name:
                tags.append(self._slugify(step.screen_name))

        risk_summary = self.assess_workflow_risk(learned_steps)
        recipe_risk = WorkflowRiskLevel(risk_summary["overall_risk_level"])
        confidence = self._average_confidence([step.confidence for step in learned_steps])

        recipe_name = workflow_name or self._infer_recipe_name(learned_steps)
        recipe_description = workflow_description or self._infer_recipe_description(learned_steps)

        recipe_id = self._make_recipe_id(
            user_id=user_id,
            workspace_id=workspace_id,
            name=recipe_name,
            steps=recipe_steps,
        )

        return AutomationRecipe(
            recipe_id=recipe_id,
            name=recipe_name,
            version=DEFAULT_RECIPE_VERSION,
            description=recipe_description,
            user_id=user_id,
            workspace_id=workspace_id,
            source=source,
            steps=recipe_steps,
            variables=self._extract_recipe_variables(learned_steps),
            required_permissions=sorted(required_permissions),
            security_review_required=bool(risk_summary["security_review_required"]),
            verification_required=True,
            risk_level=recipe_risk,
            confidence=confidence,
            tags=sorted(set(tag for tag in tags if tag)),
            created_at=self._utc_now_iso(),
            metadata={
                **dict(metadata or {}),
                "step_count": len(recipe_steps),
                "learned_step_count": len(learned_steps),
                "risk_summary": risk_summary,
                "generated_by": self.agent_name,
            },
        )

    def assess_workflow_risk(
        self,
        learned_steps: Sequence[VisualWorkflowStep],
    ) -> Dict[str, Any]:
        """
        Assess workflow-level safety risk.
        """

        risk_rank = {
            WorkflowRiskLevel.LOW: 1,
            WorkflowRiskLevel.MEDIUM: 2,
            WorkflowRiskLevel.HIGH: 3,
            WorkflowRiskLevel.CRITICAL: 4,
        }

        highest = WorkflowRiskLevel.LOW
        sensitive_count = 0
        destructive_count = 0
        security_required_count = 0
        needs_review_count = 0

        for step in learned_steps:
            if risk_rank[step.risk_level] > risk_rank[highest]:
                highest = step.risk_level
            if step.sensitive:
                sensitive_count += 1
            if step.destructive:
                destructive_count += 1
            if step.requires_security:
                security_required_count += 1
            if step.status != WorkflowStepStatus.LEARNED:
                needs_review_count += 1

        if destructive_count > 0:
            highest = WorkflowRiskLevel.CRITICAL
        elif sensitive_count > 0 and highest == WorkflowRiskLevel.LOW:
            highest = WorkflowRiskLevel.MEDIUM

        return {
            "overall_risk_level": highest.value,
            "step_count": len(learned_steps),
            "sensitive_step_count": sensitive_count,
            "destructive_step_count": destructive_count,
            "security_required_step_count": security_required_count,
            "needs_review_step_count": needs_review_count,
            "security_review_required": security_required_count > 0,
            "confidence": self._average_confidence([step.confidence for step in learned_steps]),
        }

    def export_recipe_json(
        self,
        recipe: Union[AutomationRecipe, Mapping[str, Any]],
        *,
        indent: int = 2,
    ) -> str:
        """
        Export an automation recipe as JSON.
        """

        if isinstance(recipe, AutomationRecipe):
            payload = self.recipe_to_dict(recipe)
        else:
            payload = self._json_safe_dict(recipe)

        return json.dumps(payload, indent=indent, ensure_ascii=False, sort_keys=True)

    def recipe_to_dict(self, recipe: AutomationRecipe) -> Dict[str, Any]:
        """
        Convert AutomationRecipe dataclass to JSON-safe dict.
        """

        return {
            "recipe_id": recipe.recipe_id,
            "name": recipe.name,
            "version": recipe.version,
            "description": recipe.description,
            "user_id": recipe.user_id,
            "workspace_id": recipe.workspace_id,
            "source": recipe.source,
            "steps": [self.recipe_step_to_dict(step) for step in recipe.steps],
            "variables": self._json_safe_dict(recipe.variables),
            "required_permissions": list(recipe.required_permissions),
            "security_review_required": recipe.security_review_required,
            "verification_required": recipe.verification_required,
            "risk_level": recipe.risk_level.value,
            "confidence": recipe.confidence,
            "tags": list(recipe.tags),
            "created_at": recipe.created_at,
            "metadata": self._json_safe_dict(recipe.metadata),
        }

    def recipe_step_to_dict(self, step: AutomationRecipeStep) -> Dict[str, Any]:
        """
        Convert AutomationRecipeStep dataclass to JSON-safe dict.
        """

        return {
            "recipe_step_id": step.recipe_step_id,
            "order": step.order,
            "action": step.action,
            "target": self._json_safe_dict(step.target),
            "value": step.value,
            "wait_seconds": step.wait_seconds,
            "preconditions": self._json_safe_list(step.preconditions),
            "postconditions": self._json_safe_list(step.postconditions),
            "verification": self._json_safe_dict(step.verification),
            "safety": self._json_safe_dict(step.safety),
            "retry": self._json_safe_dict(step.retry),
            "metadata": self._json_safe_dict(step.metadata),
        }

    def step_to_dict(self, step: VisualWorkflowStep) -> Dict[str, Any]:
        """
        Convert VisualWorkflowStep dataclass to JSON-safe dict.
        """

        return {
            "step_id": step.step_id,
            "index": step.index,
            "action_type": step.action_type.value,
            "title": step.title,
            "description": step.description,
            "screen_name": step.screen_name,
            "app_name": step.app_name,
            "page_url": step.page_url,
            "element": asdict(step.element) if step.element else None,
            "input_value": step.input_value,
            "expected_result": step.expected_result,
            "wait_seconds": step.wait_seconds,
            "confidence": step.confidence,
            "risk_level": step.risk_level.value,
            "status": step.status.value,
            "sensitive": step.sensitive,
            "destructive": step.destructive,
            "requires_security": step.requires_security,
            "verification_hint": step.verification_hint,
            "source": step.source,
            "raw_observation": self._json_safe_dict(step.raw_observation or {}),
            "metadata": self._json_safe_dict(step.metadata),
        }

    # -------------------------------------------------------------------------
    # Compatibility hooks
    # -------------------------------------------------------------------------

    def _validate_task_context(self, context: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Validate SaaS isolation context.

        Every workflow learning task must be scoped by user_id and workspace_id
        unless disabled for local tests.
        """

        user_id = context.get("user_id")
        workspace_id = context.get("workspace_id")

        if self.config.require_context:
            if not self._valid_context_id(user_id):
                return self._error_result(
                    message="Missing or invalid user_id for visual workflow learning.",
                    error_code="INVALID_USER_CONTEXT",
                    data={"user_id_present": bool(user_id)},
                    metadata=dict(context),
                )

            if not self._valid_context_id(workspace_id):
                return self._error_result(
                    message="Missing or invalid workspace_id for visual workflow learning.",
                    error_code="INVALID_WORKSPACE_CONTEXT",
                    data={"workspace_id_present": bool(workspace_id)},
                    metadata=dict(context),
                )

        return self._safe_result(
            success=True,
            message="Task context validated.",
            data={
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
            metadata=dict(context),
        )

    def _requires_security_check(
        self,
        *,
        action: str,
        context: Optional[Mapping[str, Any]] = None,
        learned_steps: Optional[Sequence[VisualWorkflowStep]] = None,
        risk_summary: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Determine whether Security Agent review is required.
        """

        if action not in {"learn_workflow", "build_automation_recipe"}:
            return False

        if risk_summary and bool(risk_summary.get("security_review_required")):
            return True

        for step in learned_steps or []:
            if step.requires_security:
                return True
            if self.config.require_security_for_sensitive_steps and step.sensitive:
                return True
            if self.config.require_security_for_destructive_steps and step.destructive:
                return True

        return False

    def _request_security_approval(
        self,
        *,
        action: str,
        context: Mapping[str, Any],
        learned_steps: Sequence[VisualWorkflowStep],
        risk_summary: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval if attached.

        If no Security Agent is present, this returns approved=True only for
        non-critical learned recipes. Critical/destructive recipes remain blocked
        unless a real Security Agent approves them.
        """

        payload = {
            "agent": self.agent_name,
            "action": action,
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "task_id": context.get("task_id"),
            "request_id": context.get("request_id"),
            "risk_summary": dict(risk_summary),
            "sensitive_steps": [
                self.step_to_dict(step)
                for step in learned_steps
                if step.sensitive or step.destructive or step.requires_security
            ],
            "requested_at": self._utc_now_iso(),
            "read_only_learning": True,
            "executes_actions": False,
        }

        if self.security_agent is None:
            overall_risk = str(risk_summary.get("overall_risk_level", "low"))
            destructive_count = int(risk_summary.get("destructive_step_count", 0) or 0)

            if overall_risk == WorkflowRiskLevel.CRITICAL.value or destructive_count > 0:
                return {
                    "approved": False,
                    "required": True,
                    "source": "local_default",
                    "message": "Critical or destructive workflow recipe requires real Security Agent approval.",
                    "payload": payload,
                }

            return {
                "approved": True,
                "required": True,
                "source": "local_default",
                "message": "No Security Agent attached; non-critical read-only workflow learning allowed.",
                "payload": payload,
            }

        try:
            if hasattr(self.security_agent, "approve"):
                response = self.security_agent.approve(payload)
            elif hasattr(self.security_agent, "request_approval"):
                response = self.security_agent.request_approval(payload)
            elif hasattr(self.security_agent, "check_permission"):
                response = self.security_agent.check_permission(payload)
            else:
                return {
                    "approved": False,
                    "required": True,
                    "source": "security_agent",
                    "message": "Security Agent does not expose an approval method.",
                    "payload": payload,
                }

            if isinstance(response, Mapping):
                return {
                    "approved": bool(response.get("approved", response.get("success", False))),
                    "required": True,
                    "source": "security_agent",
                    "message": str(response.get("message", "Security Agent response received.")),
                    "payload": payload,
                    "response": self._json_safe_dict(response),
                }

            return {
                "approved": bool(response),
                "required": True,
                "source": "security_agent",
                "message": "Security Agent returned non-dict response.",
                "payload": payload,
            }

        except Exception as exc:
            self.logger.exception("Security approval request failed.")
            return {
                "approved": False,
                "required": True,
                "source": "security_agent",
                "message": f"Security approval request failed: {exc}",
                "payload": payload,
            }

    def _prepare_verification_payload(
        self,
        *,
        action: str,
        context: Mapping[str, Any],
        learned_steps: Sequence[VisualWorkflowStep],
        recipe: AutomationRecipe,
        risk_summary: Mapping[str, Any],
        started_at: str,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent compatible payload.
        """

        checkpoints: List[Dict[str, Any]] = []

        if self.config.include_verification_checkpoints:
            for step in learned_steps:
                if step.verification_hint:
                    checkpoints.append(
                        {
                            "source_step_id": step.step_id,
                            "action": step.action_type.value,
                            "hint": step.verification_hint,
                            "screen_name": step.screen_name,
                            "page_url": step.page_url,
                            "confidence": step.confidence,
                        }
                    )

        return {
            "type": "visual_workflow_learning_verification",
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "action": action,
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "task_id": context.get("task_id"),
            "request_id": context.get("request_id"),
            "recipe_id": recipe.recipe_id,
            "recipe_name": recipe.name,
            "step_count": len(recipe.steps),
            "learned_step_count": len(learned_steps),
            "risk_summary": dict(risk_summary),
            "confidence": recipe.confidence,
            "security_review_required": recipe.security_review_required,
            "verification_checkpoints": checkpoints,
            "success": True,
            "started_at": started_at,
            "finished_at": self._utc_now_iso(),
        }

    def _prepare_memory_payload(
        self,
        *,
        action: str,
        context: Mapping[str, Any],
        learned_steps: Sequence[VisualWorkflowStep],
        recipe: AutomationRecipe,
        risk_summary: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare compact Memory Agent payload.

        Memory payload is scoped by user_id and workspace_id and avoids storing
        raw screenshots or excessive sensitive values.
        """

        if not self.config.include_memory_payload:
            return {}

        compact_steps = []
        for step in learned_steps:
            compact_steps.append(
                {
                    "step_id": step.step_id,
                    "index": step.index,
                    "action_type": step.action_type.value,
                    "title": step.title,
                    "screen_name": step.screen_name,
                    "app_name": step.app_name,
                    "risk_level": step.risk_level.value,
                    "sensitive": step.sensitive,
                    "destructive": step.destructive,
                    "confidence": step.confidence,
                }
            )

        return {
            "memory_type": "visual_workflow_recipe",
            "agent": self.agent_name,
            "action": action,
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "task_id": context.get("task_id"),
            "request_id": context.get("request_id"),
            "recipe_id": recipe.recipe_id,
            "recipe_name": recipe.name,
            "recipe_description": recipe.description,
            "risk_level": recipe.risk_level.value,
            "confidence": recipe.confidence,
            "step_count": len(recipe.steps),
            "security_review_required": recipe.security_review_required,
            "required_permissions": list(recipe.required_permissions),
            "steps": compact_steps,
            "risk_summary": dict(risk_summary),
            "created_at": self._utc_now_iso(),
        }

    def _emit_agent_event(self, *, event_name: str, payload: Mapping[str, Any]) -> None:
        """
        Emit an event to William event bus if attached.
        """

        try:
            if self.event_bus is None:
                return
            if hasattr(self.event_bus, "emit"):
                self.event_bus.emit(event_name, dict(payload))
            elif hasattr(self.event_bus, "publish"):
                self.event_bus.publish(event_name, dict(payload))
        except Exception:
            self.logger.exception("Failed to emit event: %s", event_name)

    def _log_audit_event(
        self,
        *,
        action: str,
        context: Mapping[str, Any],
        outcome: Mapping[str, Any],
    ) -> None:
        """
        Log SaaS audit event for workflow learning.
        """

        payload = {
            "agent": self.agent_name,
            "module": self.file_path,
            "action": action,
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "task_id": context.get("task_id"),
            "request_id": context.get("request_id"),
            "outcome": dict(outcome),
            "timestamp": self._utc_now_iso(),
        }

        try:
            if self.audit_logger is not None:
                if hasattr(self.audit_logger, "log"):
                    self.audit_logger.log(payload)
                    return
                if hasattr(self.audit_logger, "write"):
                    self.audit_logger.write(payload)
                    return

            self.logger.info("VisualWorkflowLearner audit event: %s", payload)
        except Exception:
            self.logger.exception("Failed to log audit event.")

    def _safe_result(
        self,
        *,
        success: bool,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        error: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard William/Jarvis structured result.
        """

        return {
            "success": bool(success),
            "message": message,
            "data": self._json_safe_dict(data or {}),
            "error": self._json_safe_dict(error) if error else None,
            "metadata": {
                "agent": self.agent_name,
                "module": self.file_path,
                "timestamp": self._utc_now_iso(),
                **self._json_safe_dict(metadata or {}),
            },
        }

    def _error_result(
        self,
        *,
        message: str,
        error_code: str,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        exception: Optional[BaseException] = None,
    ) -> Dict[str, Any]:
        """
        Standard William/Jarvis error result.
        """

        error = {
            "code": error_code,
            "message": message,
        }
        if exception is not None:
            error["exception_type"] = exception.__class__.__name__
            error["exception_message"] = str(exception)

        return self._safe_result(
            success=False,
            message=message,
            data=data or {},
            error=error,
            metadata=metadata or {},
        )

    # -------------------------------------------------------------------------
    # Inference helpers
    # -------------------------------------------------------------------------

    def _infer_action_type(self, item: Mapping[str, Any]) -> WorkflowActionType:
        text = self._clean_text(item.get("text") or "").lower()
        hint = self._clean_text(item.get("action_hint") or "").lower()
        element = item.get("element") if isinstance(item.get("element"), Mapping) else {}
        role = self._clean_text(element.get("role") if isinstance(element, Mapping) else "").lower()
        label = self._clean_text(element.get("label") if isinstance(element, Mapping) else "").lower()
        combined = " ".join([hint, text, role, label]).strip()

        if any(word in combined for word in ["double click", "double-click"]):
            return WorkflowActionType.DOUBLE_CLICK

        if any(word in combined for word in ["right click", "right-click", "context menu"]):
            return WorkflowActionType.RIGHT_CLICK

        if any(word in combined for word in ["scroll", "swipe"]):
            return WorkflowActionType.SCROLL

        if any(word in combined for word in ["hover", "mouse over"]):
            return WorkflowActionType.HOVER

        if any(word in combined for word in ["drag"]):
            return WorkflowActionType.DRAG

        if any(word in combined for word in ["drop"]):
            return WorkflowActionType.DROP

        if any(word in combined for word in ["upload", "choose file", "attach file", "browse file"]):
            return WorkflowActionType.UPLOAD

        if any(word in combined for word in ["download", "export"]):
            return WorkflowActionType.DOWNLOAD

        if any(word in combined for word in ["copy"]):
            return WorkflowActionType.COPY

        if any(word in combined for word in ["paste"]):
            return WorkflowActionType.PASTE

        if any(word in combined for word in DEFAULT_WAIT_KEYWORDS):
            return WorkflowActionType.WAIT

        if any(word in combined for word in DEFAULT_NAVIGATION_KEYWORDS):
            return WorkflowActionType.NAVIGATE

        if any(word in combined for word in ["checkbox", "checked", "tick box"]):
            if any(word in combined for word in ["uncheck", "untick", "disable"]):
                return WorkflowActionType.UNCHECK
            return WorkflowActionType.CHECK

        if any(word in combined for word in ["dropdown", "select", "combo", "option"]):
            return WorkflowActionType.SELECT

        if any(word in combined for word in ["type", "enter text", "fill", "input"]) or role in {
            "input",
            "textbox",
            "textarea",
            "searchbox",
            "password",
            "email",
        }:
            return WorkflowActionType.TYPE_TEXT

        if any(word in combined for word in ["cancel", "close", "dismiss"]):
            return WorkflowActionType.CANCEL

        if any(word in combined for word in ["confirm", "approve", "accept", "yes"]):
            return WorkflowActionType.CONFIRM

        if any(word in combined for word in DEFAULT_SUBMIT_KEYWORDS):
            return WorkflowActionType.SUBMIT

        if role in {"button", "link", "menuitem", "tab", "icon", "card"}:
            return WorkflowActionType.CLICK

        if item.get("page_url") and not text and not hint:
            return WorkflowActionType.SCREEN_CHANGE

        if label or text:
            return WorkflowActionType.CLICK

        return WorkflowActionType.UNKNOWN

    def _extract_element_data(self, raw_step: Mapping[str, Any], fallback_index: int) -> Dict[str, Any]:
        element = raw_step.get("element")
        if not isinstance(element, Mapping):
            element = raw_step.get("ui_element")
        if not isinstance(element, Mapping):
            element = raw_step.get("target")
        if not isinstance(element, Mapping):
            element = {}

        label = (
            element.get("label")
            or raw_step.get("label")
            or raw_step.get("button_text")
            or raw_step.get("text")
            or raw_step.get("visible_text")
        )

        role = (
            element.get("role")
            or raw_step.get("role")
            or raw_step.get("element_type")
            or raw_step.get("type")
        )

        bounds = (
            element.get("bounds")
            or raw_step.get("bounds")
            or raw_step.get("bbox")
            or raw_step.get("bounding_box")
        )

        center = (
            element.get("center")
            or raw_step.get("center")
            or self._center_from_bounds(bounds)
        )

        selector = (
            element.get("selector")
            or raw_step.get("selector")
            or raw_step.get("css_selector")
            or raw_step.get("xpath")
        )

        element_id = (
            element.get("element_id")
            or element.get("id")
            or raw_step.get("element_id")
            or raw_step.get("id")
            or f"visual_element_{fallback_index}"
        )

        return {
            "element_id": str(element_id),
            "label": self._clean_text(label or "") or None,
            "role": self._clean_text(role or "") or None,
            "text": self._clean_text(element.get("text") or raw_step.get("text") or "") or None,
            "placeholder": self._clean_text(element.get("placeholder") or raw_step.get("placeholder") or "") or None,
            "selector": str(selector) if selector else None,
            "bounds": self._normalize_bounds(bounds),
            "center": self._normalize_center(center),
            "confidence": self._safe_float(element.get("confidence") or raw_step.get("confidence") or 0.5, default=0.5),
            "attributes": self._safe_metadata(element.get("attributes", {})),
        }

    def _build_element_ref(self, element_data: Any, fallback_index: int) -> Optional[VisualElementRef]:
        if not isinstance(element_data, Mapping):
            return None

        return VisualElementRef(
            element_id=str(element_data.get("element_id") or f"visual_element_{fallback_index}"),
            label=self._clean_text(element_data.get("label") or "") or None,
            role=self._clean_text(element_data.get("role") or "") or None,
            text=self._clean_text(element_data.get("text") or "") or None,
            placeholder=self._clean_text(element_data.get("placeholder") or "") or None,
            selector=str(element_data.get("selector")) if element_data.get("selector") else None,
            bounds=self._normalize_bounds(element_data.get("bounds")),
            center=self._normalize_center(element_data.get("center")),
            confidence=self._safe_float(element_data.get("confidence"), default=0.5),
            attributes=self._safe_metadata(element_data.get("attributes", {})),
        )

    def _is_sensitive_step(
        self,
        *,
        text: str,
        action_hint: str,
        input_value: Any,
        element: Optional[VisualElementRef],
        action_type: WorkflowActionType,
    ) -> bool:
        combined = " ".join(
            [
                text or "",
                action_hint or "",
                element.label if element and element.label else "",
                element.role if element and element.role else "",
                element.placeholder if element and element.placeholder else "",
                str(input_value) if input_value is not None else "",
            ]
        ).lower()

        if any(keyword in combined for keyword in DEFAULT_SENSITIVE_KEYWORDS):
            return True

        if action_type in {
            WorkflowActionType.SUBMIT,
            WorkflowActionType.CONFIRM,
            WorkflowActionType.UPLOAD,
            WorkflowActionType.DOWNLOAD,
        }:
            return True

        return False

    def _is_destructive_step(
        self,
        *,
        text: str,
        action_hint: str,
        element: Optional[VisualElementRef],
        action_type: WorkflowActionType,
    ) -> bool:
        combined = " ".join(
            [
                text or "",
                action_hint or "",
                element.label if element and element.label else "",
                element.role if element and element.role else "",
            ]
        ).lower()

        if any(keyword in combined for keyword in DEFAULT_DESTRUCTIVE_KEYWORDS):
            return True

        if action_type == WorkflowActionType.CANCEL and any(word in combined for word in ["subscription", "account", "order"]):
            return True

        return False

    def _infer_step_risk(
        self,
        *,
        action_type: WorkflowActionType,
        sensitive: bool,
        destructive: bool,
        text: str,
        action_hint: str,
    ) -> WorkflowRiskLevel:
        combined = f"{text} {action_hint}".lower()

        if destructive:
            return WorkflowRiskLevel.CRITICAL

        if any(word in combined for word in ["payment", "checkout", "transfer", "bank", "card", "publish", "send", "call", "dial"]):
            return WorkflowRiskLevel.HIGH

        if sensitive:
            return WorkflowRiskLevel.MEDIUM

        if action_type in {
            WorkflowActionType.SUBMIT,
            WorkflowActionType.CONFIRM,
            WorkflowActionType.UPLOAD,
            WorkflowActionType.DOWNLOAD,
        }:
            return WorkflowRiskLevel.MEDIUM

        if action_type == WorkflowActionType.UNKNOWN:
            return WorkflowRiskLevel.MEDIUM

        return WorkflowRiskLevel.LOW

    def _step_requires_security(
        self,
        *,
        action_type: WorkflowActionType,
        sensitive: bool,
        destructive: bool,
        risk_level: WorkflowRiskLevel,
    ) -> bool:
        if destructive and self.config.require_security_for_destructive_steps:
            return True

        if sensitive and self.config.require_security_for_sensitive_steps:
            return True

        if risk_level in {WorkflowRiskLevel.HIGH, WorkflowRiskLevel.CRITICAL}:
            return True

        if action_type in {
            WorkflowActionType.SUBMIT,
            WorkflowActionType.CONFIRM,
            WorkflowActionType.UPLOAD,
            WorkflowActionType.DOWNLOAD,
        } and self.config.require_security_for_sensitive_steps:
            return True

        return False

    def _make_step_title(
        self,
        *,
        action_type: WorkflowActionType,
        text: str,
        element: Optional[VisualElementRef],
        input_value: Any,
    ) -> str:
        label = ""
        if element:
            label = element.label or element.text or element.placeholder or element.role or ""

        target = self._clean_text(label or text or "")
        if target:
            target = target[:80]

        if action_type == WorkflowActionType.TYPE_TEXT:
            return f"Type into {target or 'field'}"
        if action_type == WorkflowActionType.CLICK:
            return f"Click {target or 'target'}"
        if action_type == WorkflowActionType.SUBMIT:
            return f"Submit using {target or 'button'}"
        if action_type == WorkflowActionType.NAVIGATE:
            return f"Navigate to {target or 'page'}"
        if action_type == WorkflowActionType.WAIT:
            return "Wait for screen to update"
        if action_type == WorkflowActionType.SCROLL:
            return "Scroll the page"
        if action_type == WorkflowActionType.SELECT:
            return f"Select {target or 'option'}"
        if action_type == WorkflowActionType.UPLOAD:
            return f"Upload file using {target or 'file picker'}"
        if action_type == WorkflowActionType.DOWNLOAD:
            return f"Download from {target or 'page'}"
        if action_type == WorkflowActionType.CONFIRM:
            return f"Confirm {target or 'action'}"
        if action_type == WorkflowActionType.CANCEL:
            return f"Cancel {target or 'action'}"

        return f"{action_type.value.replace('_', ' ').title()} {target}".strip()

    def _make_step_description(
        self,
        *,
        action_type: WorkflowActionType,
        text: str,
        element: Optional[VisualElementRef],
        input_value: Any,
        screen_name: Any,
        page_url: Any,
    ) -> str:
        pieces = [f"Perform {action_type.value.replace('_', ' ')}"]

        if element:
            label = element.label or element.text or element.placeholder
            if label:
                pieces.append(f"on element '{label}'")
            elif element.role:
                pieces.append(f"on {element.role} element")

        if text and (not element or text not in {element.label, element.text}):
            pieces.append(f"near visible text '{text[:120]}'")

        if screen_name:
            pieces.append(f"on screen '{screen_name}'")

        if page_url:
            pieces.append(f"at URL '{page_url}'")

        return " ".join(pieces).strip() + "."

    def _infer_expected_result(
        self,
        *,
        action_type: WorkflowActionType,
        text: str,
        element: Optional[VisualElementRef],
        page_url: Any,
    ) -> Optional[str]:
        if action_type == WorkflowActionType.NAVIGATE:
            return "Target page should load successfully."
        if action_type == WorkflowActionType.TYPE_TEXT:
            return "Input field should contain the expected value."
        if action_type in {WorkflowActionType.CLICK, WorkflowActionType.SUBMIT, WorkflowActionType.CONFIRM}:
            label = element.label if element else None
            return f"UI should respond after activating '{label}'." if label else "UI should respond after the action."
        if action_type == WorkflowActionType.WAIT:
            return "Loading or processing state should complete."
        if action_type == WorkflowActionType.SCROLL:
            return "New visible content should appear after scrolling."
        if action_type == WorkflowActionType.SELECT:
            return "Selected option should be active."
        if action_type == WorkflowActionType.UPLOAD:
            return "Selected file should be attached or uploaded."
        if action_type == WorkflowActionType.DOWNLOAD:
            return "Download should start or exported file should become available."
        return None

    def _infer_verification_hint(
        self,
        *,
        action_type: WorkflowActionType,
        text: str,
        element: Optional[VisualElementRef],
        screen_name: Any,
        page_url: Any,
    ) -> Optional[str]:
        if action_type == WorkflowActionType.TYPE_TEXT:
            return "Verify target input contains expected text or masked value."
        if action_type in {WorkflowActionType.CLICK, WorkflowActionType.SUBMIT, WorkflowActionType.CONFIRM}:
            return "Verify expected UI state, success message, navigation change, or target screen appears."
        if action_type == WorkflowActionType.NAVIGATE:
            return "Verify URL, page title, or screen context matches expected destination."
        if action_type == WorkflowActionType.WAIT:
            return "Verify loading indicator disappeared and screen is stable."
        if action_type == WorkflowActionType.SCROLL:
            return "Verify viewport changed and target element is visible."
        if action_type in {WorkflowActionType.UPLOAD, WorkflowActionType.DOWNLOAD}:
            return "Verify file operation completed and filename/status is visible."
        return "Verify screen context and visible UI match expected result."

    def _infer_wait_seconds(self, action_type: WorkflowActionType, text: str, action_hint: str) -> Optional[float]:
        combined = f"{text} {action_hint}".lower()

        if action_type == WorkflowActionType.WAIT:
            return self.config.default_wait_seconds

        if action_type == WorkflowActionType.NAVIGATE:
            return self.config.navigation_wait_seconds

        if action_type in {WorkflowActionType.SCREEN_CHANGE, WorkflowActionType.SUBMIT, WorkflowActionType.CONFIRM}:
            return self.config.screen_change_wait_seconds

        if any(word in combined for word in DEFAULT_WAIT_KEYWORDS):
            return self.config.screen_change_wait_seconds

        return None

    # -------------------------------------------------------------------------
    # Recipe helpers
    # -------------------------------------------------------------------------

    def _build_recipe_target(self, step: VisualWorkflowStep) -> Dict[str, Any]:
        target: Dict[str, Any] = {
            "type": "visual_element",
            "screen_name": step.screen_name,
            "app_name": step.app_name,
            "page_url": step.page_url,
        }

        if step.element:
            target.update(
                {
                    "element_id": step.element.element_id,
                    "label": step.element.label,
                    "role": step.element.role,
                    "text": step.element.text,
                    "placeholder": step.element.placeholder,
                    "confidence": step.element.confidence,
                }
            )

            if self.config.include_element_selectors:
                target["selector"] = step.element.selector

            if self.config.include_visual_bounds:
                target["bounds"] = step.element.bounds
                target["center"] = step.element.center

        return self._json_safe_dict(target)

    def _build_recipe_safety(self, step: VisualWorkflowStep) -> Dict[str, Any]:
        return {
            "risk_level": step.risk_level.value,
            "sensitive": step.sensitive,
            "destructive": step.destructive,
            "requires_security": step.requires_security,
            "status": step.status.value,
            "notes": self._safety_notes_for_step(step),
        }

    def _build_recipe_verification(self, step: VisualWorkflowStep) -> Dict[str, Any]:
        return {
            "required": True,
            "hint": step.verification_hint,
            "expected_result": step.expected_result,
            "confidence": step.confidence,
            "suggested_checker": self._suggest_verification_checker(step),
        }

    def _build_recipe_retry(self, step: VisualWorkflowStep) -> Dict[str, Any]:
        if step.risk_level in {WorkflowRiskLevel.HIGH, WorkflowRiskLevel.CRITICAL}:
            return {
                "enabled": False,
                "reason": "High-risk steps should not be retried automatically without review.",
            }

        if step.action_type in {WorkflowActionType.WAIT, WorkflowActionType.SCREEN_CHANGE}:
            return {
                "enabled": True,
                "max_attempts": 2,
                "backoff_seconds": 1.0,
            }

        return {
            "enabled": True,
            "max_attempts": 1,
            "backoff_seconds": 0.5,
        }

    def _build_preconditions(self, step: VisualWorkflowStep) -> List[Dict[str, Any]]:
        preconditions: List[Dict[str, Any]] = []

        if step.screen_name:
            preconditions.append(
                {
                    "type": "screen_context",
                    "expected": step.screen_name,
                    "required": False,
                }
            )

        if step.page_url:
            preconditions.append(
                {
                    "type": "url_context",
                    "expected": step.page_url,
                    "required": False,
                }
            )

        if step.element:
            preconditions.append(
                {
                    "type": "element_visible",
                    "target": {
                        "label": step.element.label,
                        "role": step.element.role,
                        "selector": step.element.selector if self.config.include_element_selectors else None,
                    },
                    "required": True,
                }
            )

        return preconditions

    def _build_postconditions(self, step: VisualWorkflowStep) -> List[Dict[str, Any]]:
        postconditions: List[Dict[str, Any]] = []

        if step.expected_result:
            postconditions.append(
                {
                    "type": "expected_result",
                    "description": step.expected_result,
                    "required": True,
                }
            )

        if step.action_type == WorkflowActionType.TYPE_TEXT:
            postconditions.append(
                {
                    "type": "input_value_present",
                    "description": "Field contains the provided or masked input value.",
                    "required": True,
                }
            )

        if step.action_type in {WorkflowActionType.SUBMIT, WorkflowActionType.CONFIRM}:
            postconditions.append(
                {
                    "type": "screen_stable_or_success_visible",
                    "description": "A success state, navigation, or stable screen should be visible.",
                    "required": True,
                }
            )

        return postconditions

    def _extract_recipe_variables(self, learned_steps: Sequence[VisualWorkflowStep]) -> Dict[str, Any]:
        variables: Dict[str, Any] = {}

        for step in learned_steps:
            if step.action_type != WorkflowActionType.TYPE_TEXT:
                continue

            label = None
            if step.element:
                label = step.element.label or step.element.placeholder or step.element.text or step.element.role

            variable_name = self._slugify(label or f"input_{step.index}")
            if not variable_name:
                variable_name = f"input_{step.index}"

            variables[variable_name] = {
                "type": "string",
                "required": True,
                "sensitive": step.sensitive,
                "default": None if step.sensitive else step.input_value,
                "source_step_id": step.step_id,
            }

        return variables

    def _infer_recipe_name(self, learned_steps: Sequence[VisualWorkflowStep]) -> str:
        screen_names = [step.screen_name for step in learned_steps if step.screen_name]
        app_names = [step.app_name for step in learned_steps if step.app_name]

        if screen_names:
            return f"Workflow for {screen_names[0]}"
        if app_names:
            return f"Workflow for {app_names[0]}"
        if learned_steps:
            return f"Visual Workflow with {len(learned_steps)} Steps"
        return "Visual Workflow"

    def _infer_recipe_description(self, learned_steps: Sequence[VisualWorkflowStep]) -> str:
        if not learned_steps:
            return "Automation recipe learned from visual observations."

        first = learned_steps[0].title
        last = learned_steps[-1].title

        if first == last:
            return f"Automation recipe learned from visual observations: {first}."

        return f"Automation recipe learned from visual observations, starting with '{first}' and ending with '{last}'."

    def _make_recipe_id(
        self,
        *,
        user_id: str,
        workspace_id: str,
        name: str,
        steps: Sequence[AutomationRecipeStep],
    ) -> str:
        digest_input = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "name": name,
            "steps": [
                {
                    "action": step.action,
                    "target": step.target,
                    "value_present": step.value is not None,
                }
                for step in steps
            ],
            "created_salt": str(uuid.uuid4()),
        }
        digest = hashlib.sha256(json.dumps(digest_input, sort_keys=True, default=str).encode("utf-8")).hexdigest()
        return f"visual_recipe_{digest[:20]}"

    # -------------------------------------------------------------------------
    # Safety / signature helpers
    # -------------------------------------------------------------------------

    def _safety_notes_for_step(self, step: VisualWorkflowStep) -> List[str]:
        notes: List[str] = []

        if step.sensitive:
            notes.append("Step may involve sensitive information or external side effects.")

        if step.destructive:
            notes.append("Step appears destructive and must require explicit approval before execution.")

        if step.requires_security:
            notes.append("Security Agent review required before using this step in live automation.")

        if step.status == WorkflowStepStatus.NEEDS_REVIEW:
            notes.append("Step confidence is low or action type is uncertain.")

        if not notes:
            notes.append("No special safety issue detected from visual learning.")

        return notes

    def _suggest_verification_checker(self, step: VisualWorkflowStep) -> str:
        if step.action_type == WorkflowActionType.NAVIGATE:
            return "browser_state_checker"
        if step.action_type in {WorkflowActionType.CLICK, WorkflowActionType.SUBMIT, WorkflowActionType.CONFIRM}:
            return "ui_element_checker"
        if step.action_type == WorkflowActionType.TYPE_TEXT:
            return "form_reader"
        if step.action_type in {WorkflowActionType.UPLOAD, WorkflowActionType.DOWNLOAD}:
            return "file_state_checker"
        return "visual_validator"

    def _step_signature(self, step: VisualWorkflowStep) -> str:
        payload = {
            "action": step.action_type.value,
            "screen": step.screen_name,
            "app": step.app_name,
            "url": step.page_url,
            "element_label": step.element.label if step.element else None,
            "element_role": step.element.role if step.element else None,
            "element_text": step.element.text if step.element else None,
        }
        return hashlib.sha1(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()

    def _stable_step_id(self, item: Mapping[str, Any], index: int) -> str:
        payload = {
            "index": index,
            "text": item.get("text"),
            "action_hint": item.get("action_hint"),
            "screen_name": item.get("screen_name"),
            "page_url": item.get("page_url"),
            "element": item.get("element"),
        }
        digest = hashlib.sha1(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()
        return f"vstep_{index:04d}_{digest[:12]}"

    def _mask_sensitive_value(self, value: Any, sensitive: bool) -> Optional[str]:
        if value is None:
            return None

        text = str(value)

        if not sensitive:
            return self._clean_text(text)[: self.config.max_text_length]

        if not text:
            return ""

        return f"***MASKED_LENGTH_{len(text)}***"

    # -------------------------------------------------------------------------
    # Low-level utilities
    # -------------------------------------------------------------------------

    def _clean_text(self, value: Any) -> str:
        if value is None:
            return ""

        text = str(value)
        text = re.sub(r"\s+", " ", text).strip()

        if len(text) > self.config.max_text_length:
            text = text[: self.config.max_text_length] + "...[trimmed]"

        return text

    def _normalize_bounds(self, bounds: Any) -> Optional[Dict[str, Union[int, float]]]:
        if bounds is None:
            return None

        if isinstance(bounds, Mapping):
            keys = ["x", "y", "width", "height", "left", "top", "right", "bottom"]
            result: Dict[str, Union[int, float]] = {}
            for key in keys:
                if key in bounds:
                    number = self._safe_number(bounds.get(key))
                    if number is not None:
                        result[key] = number
            return result or None

        if isinstance(bounds, Sequence) and not isinstance(bounds, (str, bytes)):
            values = list(bounds)
            if len(values) >= 4:
                nums = [self._safe_number(v) for v in values[:4]]
                if all(v is not None for v in nums):
                    return {
                        "x": nums[0],  # type: ignore[index]
                        "y": nums[1],  # type: ignore[index]
                        "width": nums[2],  # type: ignore[index]
                        "height": nums[3],  # type: ignore[index]
                    }

        return None

    def _normalize_center(self, center: Any) -> Optional[Dict[str, Union[int, float]]]:
        if center is None:
            return None

        if isinstance(center, Mapping):
            x = self._safe_number(center.get("x"))
            y = self._safe_number(center.get("y"))
            if x is not None and y is not None:
                return {"x": x, "y": y}

        if isinstance(center, Sequence) and not isinstance(center, (str, bytes)):
            values = list(center)
            if len(values) >= 2:
                x = self._safe_number(values[0])
                y = self._safe_number(values[1])
                if x is not None and y is not None:
                    return {"x": x, "y": y}

        return None

    def _center_from_bounds(self, bounds: Any) -> Optional[Dict[str, Union[int, float]]]:
        normalized = self._normalize_bounds(bounds)
        if not normalized:
            return None

        if all(k in normalized for k in ("x", "y", "width", "height")):
            return {
                "x": float(normalized["x"]) + float(normalized["width"]) / 2,
                "y": float(normalized["y"]) + float(normalized["height"]) / 2,
            }

        if all(k in normalized for k in ("left", "top", "right", "bottom")):
            return {
                "x": (float(normalized["left"]) + float(normalized["right"])) / 2,
                "y": (float(normalized["top"]) + float(normalized["bottom"])) / 2,
            }

        return None

    def _safe_number(self, value: Any) -> Optional[Union[int, float]]:
        try:
            if value is None:
                return None
            if isinstance(value, bool):
                return int(value)
            number = float(value)
            if number.is_integer():
                return int(number)
            return number
        except Exception:
            return None

    def _safe_float(self, value: Any, *, default: float = 0.0) -> float:
        try:
            if value is None:
                return default
            return float(value)
        except Exception:
            return default

    def _average_confidence(self, values: Sequence[float]) -> float:
        valid = [float(v) for v in values if isinstance(v, (int, float))]
        if not valid:
            return 0.0
        return round(sum(valid) / len(valid), 4)

    def _valid_context_id(self, value: Any) -> bool:
        if value is None:
            return False
        text = str(value).strip()
        if not text:
            return False
        if len(text) > 256:
            return False
        return bool(re.match(r"^[A-Za-z0-9_.:@\-]+$", text))

    def _utc_now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _slugify(self, value: Any) -> str:
        text = self._clean_text(value or "").lower()
        text = re.sub(r"[^a-z0-9]+", "_", text)
        text = re.sub(r"_+", "_", text).strip("_")
        return text[:80]

    def _safe_metadata(self, value: Any) -> Dict[str, Any]:
        if not isinstance(value, Mapping):
            return {}
        return self._json_safe_dict(value)

    def _json_safe_dict(self, value: Any) -> Dict[str, Any]:
        if value is None:
            return {}

        if not isinstance(value, Mapping):
            return {"value": self._json_safe_value(value)}

        result: Dict[str, Any] = {}
        for key, val in value.items():
            result[str(key)] = self._json_safe_value(val)
        return result

    def _json_safe_list(self, value: Any) -> List[Any]:
        if value is None:
            return []
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
            return [self._json_safe_value(value)]
        return [self._json_safe_value(item) for item in value]

    def _json_safe_value(self, value: Any) -> Any:
        if value is None:
            return None

        if isinstance(value, (str, int, float, bool)):
            return value

        if isinstance(value, Enum):
            return value.value

        if isinstance(value, Mapping):
            return self._json_safe_dict(value)

        if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
            return [self._json_safe_value(item) for item in value]

        if hasattr(value, "__dataclass_fields__"):
            return self._json_safe_dict(asdict(value))

        return str(value)


# =============================================================================
# Module-level convenience function
# =============================================================================

def learn_visual_workflow(
    *,
    user_id: Optional[str],
    workspace_id: Optional[str],
    visual_steps: Sequence[Mapping[str, Any]],
    workflow_name: Optional[str] = None,
    workflow_description: Optional[str] = None,
    source: str = "visual_agent",
    task_id: Optional[str] = None,
    request_id: Optional[str] = None,
    config: Optional[Union[VisualWorkflowLearnerConfig, Mapping[str, Any]]] = None,
    metadata: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Convenience wrapper for API/dashboard integration.
    """

    learner = VisualWorkflowLearner(config=config)
    return learner.learn_workflow(
        user_id=user_id,
        workspace_id=workspace_id,
        visual_steps=visual_steps,
        workflow_name=workflow_name,
        workflow_description=workflow_description,
        source=source,
        task_id=task_id,
        request_id=request_id,
        metadata=metadata,
    )


__all__ = [
    "VisualWorkflowLearner",
    "VisualWorkflowLearnerConfig",
    "VisualElementRef",
    "VisualWorkflowStep",
    "AutomationRecipeStep",
    "AutomationRecipe",
    "WorkflowActionType",
    "WorkflowRiskLevel",
    "WorkflowStepStatus",
    "learn_visual_workflow",
]


# =============================================================================
# Safe local smoke test
# =============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    sample_steps = [
        {
            "screen_name": "Login Page",
            "app_name": "Browser",
            "page_url": "https://example.com/login",
            "text": "Email",
            "role": "input",
            "action": "type",
            "value": "user@example.com",
            "bounds": {"x": 100, "y": 200, "width": 300, "height": 40},
            "confidence": 0.92,
        },
        {
            "screen_name": "Login Page",
            "app_name": "Browser",
            "text": "Password",
            "role": "password",
            "action": "type",
            "value": "secret-password",
            "bounds": {"x": 100, "y": 260, "width": 300, "height": 40},
            "confidence": 0.90,
        },
        {
            "screen_name": "Login Page",
            "app_name": "Browser",
            "text": "Sign In",
            "role": "button",
            "action": "click",
            "bounds": {"x": 100, "y": 320, "width": 120, "height": 40},
            "confidence": 0.95,
        },
        {
            "screen_name": "Dashboard",
            "app_name": "Browser",
            "text": "Welcome",
            "action": "screen change",
            "confidence": 0.88,
        },
    ]

    learner = VisualWorkflowLearner(
        config=VisualWorkflowLearnerConfig(
            require_context=False,
            include_raw_observations=False,
        )
    )

    result = learner.learn_workflow(
        user_id="local_user",
        workspace_id="local_workspace",
        visual_steps=sample_steps,
        workflow_name="Sample Login Workflow",
        source="manual",
        task_id="local_test",
        request_id=f"workflow_learner_{int(time.time())}",
    )

    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))