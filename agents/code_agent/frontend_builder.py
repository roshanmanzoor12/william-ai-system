"""
agents/code_agent/frontend_builder.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Builds React, Next.js, and Flutter frontend screens, dashboards, forms,
    layouts, reusable components, API service files, and basic frontend
    project structures.

Architecture Compatibility:
    - Master Agent routing compatible
    - Agent Registry compatible
    - Agent Loader compatible
    - Agent Router compatible
    - BaseAgent compatible
    - SaaS user/workspace isolation aware
    - Security Agent approval compatible
    - Verification Agent payload compatible
    - Memory Agent payload compatible
    - Dashboard/API structured result compatible

Safety:
    - This file does not directly write files unless explicitly requested
      through a public build method and after context validation.
    - It does not run npm/flutter/build/system commands.
    - It never hardcodes secrets.
    - It marks destructive/sensitive operations for Security Agent review.

This file is import-safe even if the rest of the William/Jarvis system
has not been created yet.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional BaseAgent import
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent.

        Keeps this file import-safe until the real William/Jarvis BaseAgent
        exists in the project.
        """

        def __init__(
            self,
            agent_name: str = "frontend_builder",
            user_id: Optional[Union[str, int]] = None,
            workspace_id: Optional[Union[str, int]] = None,
            **kwargs: Any,
        ) -> None:
            self.agent_name = agent_name
            self.user_id = user_id
            self.workspace_id = workspace_id
            self.extra_config = kwargs

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            logging.getLogger(__name__).debug(
                "Fallback BaseAgent event emitted: %s | %s",
                event_name,
                payload,
            )


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Enums / Data Structures
# ---------------------------------------------------------------------------

class FrontendFramework(str, Enum):
    REACT = "react"
    NEXTJS = "nextjs"
    FLUTTER = "flutter"


class ComponentKind(str, Enum):
    SCREEN = "screen"
    PAGE = "page"
    DASHBOARD = "dashboard"
    FORM = "form"
    CARD = "card"
    TABLE = "table"
    LAYOUT = "layout"
    NAVIGATION = "navigation"
    API_SERVICE = "api_service"
    WIDGET = "widget"
    THEME = "theme"
    MODEL = "model"
    ROUTES = "routes"
    UNKNOWN = "unknown"


class BuildStatus(str, Enum):
    GENERATED = "generated"
    VALIDATED = "validated"
    WRITTEN = "written"
    FAILED = "failed"
    SECURITY_REVIEW_REQUIRED = "security_review_required"


@dataclass
class FrontendField:
    """
    Represents a frontend form/model field.
    """

    name: str
    label: Optional[str] = None
    field_type: str = "text"
    required: bool = False
    placeholder: Optional[str] = None
    default_value: Optional[Any] = None
    validation: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FrontendAction:
    """
    Represents a UI action such as button, link, form submit, API call.
    """

    name: str
    label: str
    action_type: str = "button"
    endpoint: Optional[str] = None
    method: str = "GET"
    requires_auth: bool = True
    confirmation_required: bool = False


@dataclass
class FrontendBuildRequest:
    """
    Normalized frontend generation request.
    """

    framework: str
    component_kind: str
    name: str
    description: Optional[str] = None
    route_path: Optional[str] = None
    output_path: Optional[str] = None
    fields: List[FrontendField] = field(default_factory=list)
    actions: List[FrontendAction] = field(default_factory=list)
    data_model: Dict[str, Any] = field(default_factory=dict)
    style_preferences: Dict[str, Any] = field(default_factory=dict)
    api_base_url_name: str = "API_BASE_URL"
    use_auth: bool = True
    use_state: bool = True
    use_loading_state: bool = True
    use_error_state: bool = True
    responsive: bool = True
    dark_mode: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GeneratedFrontendFile:
    """
    A generated frontend file.
    """

    file_path: str
    file_name: str
    framework: str
    component_kind: str
    language: str
    content: str
    description: str
    status: str = BuildStatus.GENERATED.value
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FrontendBuildResult:
    """
    Full build result returned by this agent.
    """

    framework: str
    component_kind: str
    name: str
    files: List[GeneratedFrontendFile] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    next_steps: List[str] = field(default_factory=list)
    security_review: Optional[Dict[str, Any]] = None
    verification_payload: Optional[Dict[str, Any]] = None
    memory_payload: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Main FrontendBuilder
# ---------------------------------------------------------------------------

class FrontendBuilder(BaseAgent):
    """
    FrontendBuilder for William/Jarvis Code Agent.

    Responsibilities:
        - Generate React components/screens/forms/dashboards.
        - Generate Next.js pages/components/API client helpers.
        - Generate Flutter screens/widgets/services/models.
        - Return structured JSON-compatible results.
        - Maintain SaaS user/workspace isolation.
        - Prepare Security Agent review payloads for risky write actions.
        - Prepare Verification Agent and Memory Agent payloads.
        - Stay compatible with Master Agent, Router, Registry, and Dashboard.
    """

    AGENT_NAME = "frontend_builder"
    AGENT_MODULE = "code_agent"
    VERSION = "1.0.0"

    SAFE_FILENAME_RE = re.compile(r"^[a-zA-Z0-9_\-./]+$")

    def __init__(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        strict_context: bool = True,
        enable_file_write: bool = False,
        enable_audit_logs: bool = True,
        enable_memory_payload: bool = True,
        enable_verification_payload: bool = True,
        allowed_output_root: Optional[Union[str, Path]] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            agent_name=self.AGENT_NAME,
            user_id=user_id,
            workspace_id=workspace_id,
            **kwargs,
        )

        self.user_id = user_id
        self.workspace_id = workspace_id
        self.strict_context = strict_context
        self.enable_file_write = enable_file_write
        self.enable_audit_logs = enable_audit_logs
        self.enable_memory_payload = enable_memory_payload
        self.enable_verification_payload = enable_verification_payload
        self.allowed_output_root = Path(allowed_output_root).resolve() if allowed_output_root else None

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def build(
        self,
        request: Union[FrontendBuildRequest, Dict[str, Any]],
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        write_files: bool = False,
    ) -> Dict[str, Any]:
        """
        Main build entrypoint.

        Args:
            request:
                FrontendBuildRequest or dict.
            user_id:
                SaaS user id.
            workspace_id:
                SaaS workspace id.
            write_files:
                If True, generated files are written to disk only when
                enable_file_write=True and Security validation passes.

        Returns:
            Standard structured result.
        """

        validation = self._validate_task_context(user_id, workspace_id, {"write_files": write_files})
        if not validation["success"]:
            return validation

        try:
            normalized_request = self._normalize_request(request)

            self._emit_agent_event(
                "frontend_build_started",
                {
                    "user_id": user_id or self.user_id,
                    "workspace_id": workspace_id or self.workspace_id,
                    "framework": normalized_request.framework,
                    "component_kind": normalized_request.component_kind,
                    "name": normalized_request.name,
                    "write_files": write_files,
                },
            )

            request_validation = self._validate_build_request(normalized_request)
            if not request_validation["success"]:
                return request_validation

            security_review = None
            if write_files or self._requires_security_check(
                "frontend_build",
                {"request": asdict(normalized_request), "write_files": write_files},
            ):
                security_review = self._request_security_approval(
                    "frontend_build_write_files" if write_files else "frontend_build",
                    {
                        "request": asdict(normalized_request),
                        "write_files": write_files,
                    },
                )

                if write_files and security_review.get("required") and not self.enable_file_write:
                    build_result = FrontendBuildResult(
                        framework=normalized_request.framework,
                        component_kind=normalized_request.component_kind,
                        name=normalized_request.name,
                        files=[],
                        warnings=[
                            "File writing was requested but enable_file_write=False. Returning generated content only.",
                        ],
                        next_steps=[
                            "Review generated files.",
                            "Enable controlled file writing only after Security Agent approval.",
                        ],
                        security_review=security_review,
                        metadata={
                            "status": BuildStatus.SECURITY_REVIEW_REQUIRED.value,
                            "created_at": self._utc_now(),
                        },
                    )
                    return self._safe_result(
                        message="Security review required before writing frontend files.",
                        data=self._build_result_to_dict(build_result),
                        metadata=self._base_metadata(user_id, workspace_id),
                    )

            files = self._generate_files(normalized_request)

            warnings = self._collect_warnings(normalized_request, files)
            next_steps = self._build_next_steps(normalized_request, write_files)

            written_files: List[str] = []
            if write_files and self.enable_file_write:
                written_files = self._write_generated_files(files)
                for file in files:
                    if file.file_path in written_files:
                        file.status = BuildStatus.WRITTEN.value

            build_result = FrontendBuildResult(
                framework=normalized_request.framework,
                component_kind=normalized_request.component_kind,
                name=normalized_request.name,
                files=files,
                warnings=warnings,
                next_steps=next_steps,
                security_review=security_review,
                metadata={
                    "status": BuildStatus.WRITTEN.value if written_files else BuildStatus.GENERATED.value,
                    "files_count": len(files),
                    "written_files": written_files,
                    "created_at": self._utc_now(),
                },
            )

            if self.enable_verification_payload:
                build_result.verification_payload = self._prepare_verification_payload(
                    build_result,
                    asdict(normalized_request),
                )

            if self.enable_memory_payload:
                build_result.memory_payload = self._prepare_memory_payload(
                    build_result,
                    asdict(normalized_request),
                )

            self._log_audit_event(
                action="build_frontend",
                status="success",
                user_id=user_id or self.user_id,
                workspace_id=workspace_id or self.workspace_id,
                details={
                    "framework": normalized_request.framework,
                    "component_kind": normalized_request.component_kind,
                    "name": normalized_request.name,
                    "files_count": len(files),
                    "write_files": write_files,
                },
            )

            self._emit_agent_event(
                "frontend_build_completed",
                {
                    "user_id": user_id or self.user_id,
                    "workspace_id": workspace_id or self.workspace_id,
                    "framework": normalized_request.framework,
                    "component_kind": normalized_request.component_kind,
                    "name": normalized_request.name,
                    "files_count": len(files),
                },
            )

            return self._safe_result(
                message="Frontend files generated successfully.",
                data=self._build_result_to_dict(build_result),
                metadata=self._base_metadata(user_id, workspace_id),
            )

        except Exception as exc:
            logger.exception("FrontendBuilder build failed.")
            self._log_audit_event(
                action="build_frontend",
                status="failed",
                user_id=user_id or self.user_id,
                workspace_id=workspace_id or self.workspace_id,
                details={"exception": str(exc)},
            )
            return self._error_result(
                message="FrontendBuilder failed while generating frontend files.",
                code="FRONTEND_BUILD_FAILED",
                exception=exc,
                metadata=self._base_metadata(user_id, workspace_id),
            )

    def build_react_component(
        self,
        name: str,
        component_kind: str = ComponentKind.SCREEN.value,
        description: Optional[str] = None,
        fields: Optional[List[Union[FrontendField, Dict[str, Any]]]] = None,
        actions: Optional[List[Union[FrontendAction, Dict[str, Any]]]] = None,
        output_path: Optional[str] = None,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
    ) -> Dict[str, Any]:
        """
        Convenience method for React generation.
        """

        return self.build(
            {
                "framework": FrontendFramework.REACT.value,
                "component_kind": component_kind,
                "name": name,
                "description": description,
                "fields": fields or [],
                "actions": actions or [],
                "output_path": output_path,
            },
            user_id=user_id,
            workspace_id=workspace_id,
        )

    def build_next_page(
        self,
        name: str,
        route_path: Optional[str] = None,
        description: Optional[str] = None,
        fields: Optional[List[Union[FrontendField, Dict[str, Any]]]] = None,
        actions: Optional[List[Union[FrontendAction, Dict[str, Any]]]] = None,
        output_path: Optional[str] = None,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
    ) -> Dict[str, Any]:
        """
        Convenience method for Next.js page generation.
        """

        return self.build(
            {
                "framework": FrontendFramework.NEXTJS.value,
                "component_kind": ComponentKind.PAGE.value,
                "name": name,
                "route_path": route_path,
                "description": description,
                "fields": fields or [],
                "actions": actions or [],
                "output_path": output_path,
            },
            user_id=user_id,
            workspace_id=workspace_id,
        )

    def build_flutter_screen(
        self,
        name: str,
        description: Optional[str] = None,
        fields: Optional[List[Union[FrontendField, Dict[str, Any]]]] = None,
        actions: Optional[List[Union[FrontendAction, Dict[str, Any]]]] = None,
        output_path: Optional[str] = None,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
    ) -> Dict[str, Any]:
        """
        Convenience method for Flutter screen generation.
        """

        return self.build(
            {
                "framework": FrontendFramework.FLUTTER.value,
                "component_kind": ComponentKind.SCREEN.value,
                "name": name,
                "description": description,
                "fields": fields or [],
                "actions": actions or [],
                "output_path": output_path,
            },
            user_id=user_id,
            workspace_id=workspace_id,
        )

    def preview_file_tree(
        self,
        framework: str,
        name: str,
        component_kind: str = ComponentKind.SCREEN.value,
    ) -> Dict[str, Any]:
        """
        Preview expected generated file tree without generating full code.
        """

        try:
            framework_enum = self._parse_framework(framework)
            safe_name = self._safe_component_name(name)
            paths = self._default_paths(framework_enum, component_kind, safe_name)

            return self._safe_result(
                message="Frontend file tree preview prepared.",
                data={
                    "framework": framework_enum.value,
                    "component_kind": component_kind,
                    "name": safe_name,
                    "paths": paths,
                },
                metadata=self._base_metadata(),
            )
        except Exception as exc:
            return self._error_result(
                message="Could not preview frontend file tree.",
                code="FRONTEND_TREE_PREVIEW_FAILED",
                exception=exc,
            )

    # -----------------------------------------------------------------------
    # Request normalization / validation
    # -----------------------------------------------------------------------

    def _normalize_request(
        self,
        request: Union[FrontendBuildRequest, Dict[str, Any]],
    ) -> FrontendBuildRequest:
        if isinstance(request, FrontendBuildRequest):
            return request

        if not isinstance(request, dict):
            raise TypeError("request must be FrontendBuildRequest or dict.")

        fields = [
            field if isinstance(field, FrontendField) else FrontendField(**field)
            for field in request.get("fields", []) or []
        ]

        actions = [
            action if isinstance(action, FrontendAction) else FrontendAction(**action)
            for action in request.get("actions", []) or []
        ]

        return FrontendBuildRequest(
            framework=str(request.get("framework", FrontendFramework.REACT.value)).lower(),
            component_kind=str(request.get("component_kind", ComponentKind.SCREEN.value)).lower(),
            name=str(request.get("name", "GeneratedScreen")),
            description=request.get("description"),
            route_path=request.get("route_path"),
            output_path=request.get("output_path"),
            fields=fields,
            actions=actions,
            data_model=request.get("data_model", {}) or {},
            style_preferences=request.get("style_preferences", {}) or {},
            api_base_url_name=request.get("api_base_url_name", "API_BASE_URL"),
            use_auth=bool(request.get("use_auth", True)),
            use_state=bool(request.get("use_state", True)),
            use_loading_state=bool(request.get("use_loading_state", True)),
            use_error_state=bool(request.get("use_error_state", True)),
            responsive=bool(request.get("responsive", True)),
            dark_mode=bool(request.get("dark_mode", True)),
            metadata=request.get("metadata", {}) or {},
        )

    def _validate_build_request(self, request: FrontendBuildRequest) -> Dict[str, Any]:
        try:
            self._parse_framework(request.framework)
        except ValueError:
            return self._error_result(
                message=f"Unsupported frontend framework: {request.framework}",
                code="UNSUPPORTED_FRONTEND_FRAMEWORK",
            )

        if not request.name or not request.name.strip():
            return self._error_result(
                message="Frontend component name is required.",
                code="MISSING_COMPONENT_NAME",
            )

        if request.output_path and not self._is_safe_relative_path(request.output_path):
            return self._error_result(
                message="Unsafe output_path. Use a safe project-relative path only.",
                code="UNSAFE_OUTPUT_PATH",
            )

        for field_item in request.fields:
            if not field_item.name or not self._is_safe_identifier(field_item.name):
                return self._error_result(
                    message=f"Unsafe or invalid field name: {field_item.name}",
                    code="INVALID_FIELD_NAME",
                )

        for action in request.actions:
            if not action.name or not self._is_safe_identifier(action.name):
                return self._error_result(
                    message=f"Unsafe or invalid action name: {action.name}",
                    code="INVALID_ACTION_NAME",
                )

        return self._safe_result(
            message="Frontend build request validated.",
            data={"request": asdict(request)},
        )

    # -----------------------------------------------------------------------
    # File generation
    # -----------------------------------------------------------------------

    def _generate_files(self, request: FrontendBuildRequest) -> List[GeneratedFrontendFile]:
        framework = self._parse_framework(request.framework)

        if framework == FrontendFramework.REACT:
            return self._generate_react_files(request)

        if framework == FrontendFramework.NEXTJS:
            return self._generate_nextjs_files(request)

        if framework == FrontendFramework.FLUTTER:
            return self._generate_flutter_files(request)

        raise ValueError(f"Unsupported framework: {request.framework}")

    def _generate_react_files(self, request: FrontendBuildRequest) -> List[GeneratedFrontendFile]:
        component_name = self._safe_component_name(request.name)
        paths = self._default_paths(FrontendFramework.REACT, request.component_kind, component_name)

        main_content = self._render_react_component(request, component_name)
        api_content = self._render_ts_api_service(request)
        types_content = self._render_ts_types(request, component_name)

        return [
            GeneratedFrontendFile(
                file_path=request.output_path or paths["component"],
                file_name=os.path.basename(request.output_path or paths["component"]),
                framework=FrontendFramework.REACT.value,
                component_kind=request.component_kind,
                language="tsx",
                content=main_content,
                description=f"React {request.component_kind} component for {component_name}.",
            ),
            GeneratedFrontendFile(
                file_path=paths["api_service"],
                file_name=os.path.basename(paths["api_service"]),
                framework=FrontendFramework.REACT.value,
                component_kind=ComponentKind.API_SERVICE.value,
                language="ts",
                content=api_content,
                description="Reusable React API service helper.",
            ),
            GeneratedFrontendFile(
                file_path=paths["types"],
                file_name=os.path.basename(paths["types"]),
                framework=FrontendFramework.REACT.value,
                component_kind=ComponentKind.MODEL.value,
                language="ts",
                content=types_content,
                description="TypeScript model/types for generated frontend component.",
            ),
        ]

    def _generate_nextjs_files(self, request: FrontendBuildRequest) -> List[GeneratedFrontendFile]:
        component_name = self._safe_component_name(request.name)
        paths = self._default_paths(FrontendFramework.NEXTJS, request.component_kind, component_name)

        page_content = self._render_nextjs_page(request, component_name)
        client_content = self._render_ts_api_service(request, use_next_env=True)
        types_content = self._render_ts_types(request, component_name)

        return [
            GeneratedFrontendFile(
                file_path=request.output_path or paths["page"],
                file_name=os.path.basename(request.output_path or paths["page"]),
                framework=FrontendFramework.NEXTJS.value,
                component_kind=request.component_kind,
                language="tsx",
                content=page_content,
                description=f"Next.js page/client component for {component_name}.",
            ),
            GeneratedFrontendFile(
                file_path=paths["api_service"],
                file_name=os.path.basename(paths["api_service"]),
                framework=FrontendFramework.NEXTJS.value,
                component_kind=ComponentKind.API_SERVICE.value,
                language="ts",
                content=client_content,
                description="Next.js-safe API client helper.",
            ),
            GeneratedFrontendFile(
                file_path=paths["types"],
                file_name=os.path.basename(paths["types"]),
                framework=FrontendFramework.NEXTJS.value,
                component_kind=ComponentKind.MODEL.value,
                language="ts",
                content=types_content,
                description="TypeScript model/types for generated Next.js page.",
            ),
        ]

    def _generate_flutter_files(self, request: FrontendBuildRequest) -> List[GeneratedFrontendFile]:
        class_name = self._safe_component_name(request.name)
        snake_name = self._to_snake_case(class_name)
        paths = self._default_paths(FrontendFramework.FLUTTER, request.component_kind, class_name)

        screen_content = self._render_flutter_screen(request, class_name)
        service_content = self._render_flutter_api_service(request)
        model_content = self._render_flutter_model(request, class_name)

        return [
            GeneratedFrontendFile(
                file_path=request.output_path or paths["screen"],
                file_name=os.path.basename(request.output_path or paths["screen"]),
                framework=FrontendFramework.FLUTTER.value,
                component_kind=request.component_kind,
                language="dart",
                content=screen_content,
                description=f"Flutter screen/widget for {class_name}.",
                metadata={"snake_name": snake_name},
            ),
            GeneratedFrontendFile(
                file_path=paths["api_service"],
                file_name=os.path.basename(paths["api_service"]),
                framework=FrontendFramework.FLUTTER.value,
                component_kind=ComponentKind.API_SERVICE.value,
                language="dart",
                content=service_content,
                description="Flutter API service helper.",
            ),
            GeneratedFrontendFile(
                file_path=paths["model"],
                file_name=os.path.basename(paths["model"]),
                framework=FrontendFramework.FLUTTER.value,
                component_kind=ComponentKind.MODEL.value,
                language="dart",
                content=model_content,
                description="Flutter model for generated screen.",
            ),
        ]

    # -----------------------------------------------------------------------
    # React / Next renderers
    # -----------------------------------------------------------------------

    def _render_react_component(self, request: FrontendBuildRequest, component_name: str) -> str:
        fields_state = self._react_initial_state(request.fields)
        form_fields = self._react_form_fields(request.fields)
        action_buttons = self._react_action_buttons(request.actions)
        description = request.description or f"{component_name} generated by William/Jarvis FrontendBuilder."

        return f'''import React, {{ useMemo, useState }} from "react";
import type {{ {component_name}FormState }} from "../types/{self._to_kebab_case(component_name)}";

type {component_name}Props = {{
  userId?: string | number;
  workspaceId?: string | number;
  title?: string;
  onSubmit?: (payload: {component_name}FormState) => Promise<void> | void;
}};

const initialState: {component_name}FormState = {fields_state};

export default function {component_name}({{
  userId,
  workspaceId,
  title = "{self._humanize_name(component_name)}",
  onSubmit,
}}: {component_name}Props) {{
  const [form, setForm] = useState<{component_name}FormState>(initialState);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const canSubmit = useMemo(() => {{
    return Boolean(userId && workspaceId);
  }}, [userId, workspaceId]);

  function updateField<K extends keyof {component_name}FormState>(
    key: K,
    value: {component_name}FormState[K],
  ) {{
    setForm((current) => ({{
      ...current,
      [key]: value,
    }}));
  }}

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {{
    event.preventDefault();
    setError(null);
    setSuccessMessage(null);

    if (!canSubmit) {{
      setError("Missing user or workspace context.");
      return;
    }}

    try {{
      setLoading(true);
      if (onSubmit) {{
        await onSubmit(form);
      }}
      setSuccessMessage("Saved successfully.");
    }} catch (err) {{
      setError(err instanceof Error ? err.message : "Something went wrong.");
    }} finally {{
      setLoading(false);
    }}
  }}

  return (
    <section className="w-full rounded-2xl border border-slate-800 bg-slate-950 p-6 text-slate-100 shadow-xl">
      <div className="mb-6">
        <p className="text-sm font-medium uppercase tracking-wide text-slate-400">
          William / Jarvis
        </p>
        <h1 className="mt-2 text-2xl font-bold">{{title}}</h1>
        <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">
          {self._escape_jsx_text(description)}
        </p>
      </div>

      <form onSubmit={{handleSubmit}} className="space-y-4">
{form_fields}

        {{error && (
          <div className="rounded-xl border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-200">
            {{error}}
          </div>
        )}}

        {{successMessage && (
          <div className="rounded-xl border border-emerald-500/40 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-200">
            {{successMessage}}
          </div>
        )}}

        <div className="flex flex-wrap items-center gap-3 pt-2">
          <button
            type="submit"
            disabled={{loading || !canSubmit}}
            className="rounded-xl bg-white px-5 py-2.5 text-sm font-semibold text-slate-950 transition hover:bg-slate-200 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {{loading ? "Saving..." : "Save"}}
          </button>
{action_buttons}
        </div>
      </form>
    </section>
  );
}}
'''

    def _render_nextjs_page(self, request: FrontendBuildRequest, component_name: str) -> str:
        base_component = self._render_react_component(request, component_name)
        route_comment = request.route_path or f"/{self._to_kebab_case(component_name)}"

        return f'''"use client";

/*
  Next.js page/component generated by William/Jarvis FrontendBuilder.
  Suggested route: {route_comment}

  Security:
    - Pass userId/workspaceId from authenticated server/session context.
    - Do not expose secrets in NEXT_PUBLIC variables.
*/

{base_component}
'''

    def _render_ts_api_service(self, request: FrontendBuildRequest, use_next_env: bool = False) -> str:
        env_key = f"NEXT_PUBLIC_{request.api_base_url_name}" if use_next_env else request.api_base_url_name
        default_base = "process.env.NEXT_PUBLIC_API_BASE_URL" if use_next_env else "import.meta.env.VITE_API_BASE_URL"

        return f'''/*
  API service generated by William/Jarvis FrontendBuilder.

  SaaS Isolation:
    Every request supports user_id and workspace_id.
*/

export type ApiRequestOptions = {{
  token?: string;
  userId?: string | number;
  workspaceId?: string | number;
  headers?: Record<string, string>;
}};

export type ApiResult<T = unknown> = {{
  success: boolean;
  message: string;
  data?: T;
  error?: unknown;
  metadata?: Record<string, unknown>;
}};

const API_BASE_URL =
  {default_base} ||
  process.env.{env_key} ||
  "http://localhost:8000";

export async function apiRequest<T = unknown>(
  path: string,
  method: string = "GET",
  body?: unknown,
  options: ApiRequestOptions = {{}},
): Promise<ApiResult<T>> {{
  const headers: Record<string, string> = {{
    "Content-Type": "application/json",
    ...(options.headers || {{}}),
  }};

  if (options.token) {{
    headers.Authorization = `Bearer ${{options.token}}`;
  }}

  if (options.userId !== undefined) {{
    headers["X-User-Id"] = String(options.userId);
  }}

  if (options.workspaceId !== undefined) {{
    headers["X-Workspace-Id"] = String(options.workspaceId);
  }}

  const response = await fetch(`${{API_BASE_URL}}${{path}}`, {{
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "include",
  }});

  const text = await response.text();

  let payload: ApiResult<T>;
  try {{
    payload = text ? JSON.parse(text) : {{
      success: response.ok,
      message: response.ok ? "Request completed." : "Request failed.",
    }};
  }} catch {{
    payload = {{
      success: false,
      message: "Invalid JSON response from API.",
      error: text,
    }};
  }}

  if (!response.ok) {{
    return {{
      success: false,
      message: payload.message || `HTTP ${{response.status}}`,
      data: payload.data,
      error: payload.error || payload,
      metadata: {{
        status: response.status,
        path,
      }},
    }};
  }}

  return payload;
}}
'''

    def _render_ts_types(self, request: FrontendBuildRequest, component_name: str) -> str:
        lines = [f"export type {component_name}FormState = {{"]
        if request.fields:
            for field_item in request.fields:
                ts_type = self._field_to_ts_type(field_item)
                optional = "" if field_item.required else "?"
                lines.append(f"  {field_item.name}{optional}: {ts_type};")
        else:
            lines.append("  name?: string;")
            lines.append("  description?: string;")
        lines.append("};")
        lines.append("")
        lines.append(f"export type {component_name}Record = {component_name}FormState & {{")
        lines.append("  id?: string | number;")
        lines.append("  user_id?: string | number;")
        lines.append("  workspace_id?: string | number;")
        lines.append("  created_at?: string;")
        lines.append("  updated_at?: string;")
        lines.append("};")
        return "\n".join(lines) + "\n"

    # -----------------------------------------------------------------------
    # Flutter renderers
    # -----------------------------------------------------------------------

    def _render_flutter_screen(self, request: FrontendBuildRequest, class_name: str) -> str:
        controllers = self._flutter_controllers(request.fields)
        dispose_lines = self._flutter_dispose_lines(request.fields)
        field_widgets = self._flutter_field_widgets(request.fields)
        action_buttons = self._flutter_action_buttons(request.actions)
        description = request.description or f"{class_name} generated by William/Jarvis FrontendBuilder."

        return f'''import 'package:flutter/material.dart';

class {class_name} extends StatefulWidget {{
  final String? userId;
  final String? workspaceId;
  final Future<void> Function(Map<String, dynamic> payload)? onSubmit;

  const {class_name}({{
    super.key,
    this.userId,
    this.workspaceId,
    this.onSubmit,
  }});

  @override
  State<{class_name}> createState() => _{class_name}State();
}}

class _{class_name}State extends State<{class_name}> {{
{controllers}
  bool _loading = false;
  String? _error;
  String? _successMessage;

  bool get _hasContext =>
      widget.userId != null &&
      widget.userId!.isNotEmpty &&
      widget.workspaceId != null &&
      widget.workspaceId!.isNotEmpty;

  @override
  void dispose() {{
{dispose_lines}
    super.dispose();
  }}

  Future<void> _submit() async {{
    setState(() {{
      _loading = true;
      _error = null;
      _successMessage = null;
    }});

    if (!_hasContext) {{
      setState(() {{
        _loading = false;
        _error = 'Missing user or workspace context.';
      }});
      return;
    }}

    final payload = <String, dynamic>{{
{self._flutter_payload_fields(request.fields)}
      'user_id': widget.userId,
      'workspace_id': widget.workspaceId,
    }};

    try {{
      if (widget.onSubmit != null) {{
        await widget.onSubmit!(payload);
      }}

      if (!mounted) return;
      setState(() {{
        _successMessage = 'Saved successfully.';
      }});
    }} catch (error) {{
      if (!mounted) return;
      setState(() {{
        _error = error.toString();
      }});
    }} finally {{
      if (!mounted) return;
      setState(() {{
        _loading = false;
      }});
    }}
  }}

  @override
  Widget build(BuildContext context) {{
    return Scaffold(
      backgroundColor: const Color(0xFF0F172A),
      appBar: AppBar(
        backgroundColor: const Color(0xFF111827),
        title: const Text('{self._humanize_name(class_name)}'),
      ),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(18),
          child: Container(
            width: double.infinity,
            padding: const EdgeInsets.all(18),
            decoration: BoxDecoration(
              color: const Color(0xFF111827),
              borderRadius: BorderRadius.circular(22),
              border: Border.all(color: const Color(0xFF1F2937)),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'William / Jarvis',
                  style: TextStyle(
                    color: Color(0xFF94A3B8),
                    fontSize: 12,
                    fontWeight: FontWeight.w600,
                    letterSpacing: 1,
                  ),
                ),
                const SizedBox(height: 8),
                const Text(
                  '{self._humanize_name(class_name)}',
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: 24,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                const SizedBox(height: 8),
                Text(
                  '{self._escape_dart_text(description)}',
                  style: const TextStyle(
                    color: Color(0xFFCBD5E1),
                    height: 1.5,
                  ),
                ),
                const SizedBox(height: 20),
{field_widgets}
                if (_error != null) ...[
                  const SizedBox(height: 14),
                  _StatusBox(
                    message: _error!,
                    backgroundColor: const Color(0xFF7F1D1D),
                    borderColor: const Color(0xFFEF4444),
                  ),
                ],
                if (_successMessage != null) ...[
                  const SizedBox(height: 14),
                  _StatusBox(
                    message: _successMessage!,
                    backgroundColor: const Color(0xFF064E3B),
                    borderColor: const Color(0xFF10B981),
                  ),
                ],
                const SizedBox(height: 20),
                Wrap(
                  spacing: 10,
                  runSpacing: 10,
                  children: [
                    ElevatedButton(
                      onPressed: _loading ? null : _submit,
                      child: Text(_loading ? 'Saving...' : 'Save'),
                    ),
{action_buttons}
                  ],
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }}
}}

class _StatusBox extends StatelessWidget {{
  final String message;
  final Color backgroundColor;
  final Color borderColor;

  const _StatusBox({{
    required this.message,
    required this.backgroundColor,
    required this.borderColor,
  }});

  @override
  Widget build(BuildContext context) {{
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: backgroundColor,
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: borderColor),
      ),
      child: Text(
        message,
        style: const TextStyle(color: Colors.white),
      ),
    );
  }}
}}
'''

    def _render_flutter_api_service(self, request: FrontendBuildRequest) -> str:
        return '''import 'dart:convert';
import 'package:http/http.dart' as http;

/// API service generated by William/Jarvis FrontendBuilder.
///
/// SaaS Isolation:
/// Every request supports userId and workspaceId headers.
class FrontendApiService {
  final String baseUrl;
  final String? token;

  const FrontendApiService({
    required this.baseUrl,
    this.token,
  });

  Future<Map<String, dynamic>> request({
    required String path,
    String method = 'GET',
    Map<String, dynamic>? body,
    String? userId,
    String? workspaceId,
    Map<String, String>? headers,
  }) async {
    final uri = Uri.parse('$baseUrl$path');

    final requestHeaders = <String, String>{
      'Content-Type': 'application/json',
      if (token != null && token!.isNotEmpty) 'Authorization': 'Bearer $token',
      if (userId != null && userId.isNotEmpty) 'X-User-Id': userId,
      if (workspaceId != null && workspaceId.isNotEmpty) 'X-Workspace-Id': workspaceId,
      ...?headers,
    };

    late http.Response response;

    switch (method.toUpperCase()) {
      case 'POST':
        response = await http.post(
          uri,
          headers: requestHeaders,
          body: body == null ? null : jsonEncode(body),
        );
        break;
      case 'PUT':
        response = await http.put(
          uri,
          headers: requestHeaders,
          body: body == null ? null : jsonEncode(body),
        );
        break;
      case 'PATCH':
        response = await http.patch(
          uri,
          headers: requestHeaders,
          body: body == null ? null : jsonEncode(body),
        );
        break;
      case 'DELETE':
        response = await http.delete(
          uri,
          headers: requestHeaders,
          body: body == null ? null : jsonEncode(body),
        );
        break;
      case 'GET':
      default:
        response = await http.get(uri, headers: requestHeaders);
        break;
    }

    Map<String, dynamic> payload;
    try {
      payload = response.body.isEmpty
          ? <String, dynamic>{
              'success': response.statusCode >= 200 && response.statusCode < 300,
              'message': 'Empty response body.',
            }
          : jsonDecode(response.body) as Map<String, dynamic>;
    } catch (_) {
      payload = <String, dynamic>{
        'success': false,
        'message': 'Invalid JSON response from API.',
        'error': response.body,
      };
    }

    if (response.statusCode < 200 || response.statusCode >= 300) {
      return <String, dynamic>{
        'success': false,
        'message': payload['message'] ?? 'HTTP ${response.statusCode}',
        'data': payload['data'],
        'error': payload['error'] ?? payload,
        'metadata': <String, dynamic>{
          'status': response.statusCode,
          'path': path,
        },
      };
    }

    return payload;
  }
}
'''

    def _render_flutter_model(self, request: FrontendBuildRequest, class_name: str) -> str:
        model_name = f"{class_name}Model"
        fields = request.fields or [
            FrontendField(name="name", field_type="text"),
            FrontendField(name="description", field_type="text"),
        ]

        declarations = []
        constructor_fields = []
        from_json_fields = []
        to_json_fields = []

        for field_item in fields:
            dart_type = self._field_to_dart_type(field_item)
            declarations.append(f"  final {dart_type}? {field_item.name};")
            constructor_fields.append(f"    this.{field_item.name},")
            from_json_fields.append(
                f"      {field_item.name}: json['{field_item.name}'] as {dart_type}?,"
            )
            to_json_fields.append(f"      '{field_item.name}': {field_item.name},")

        return f'''class {model_name} {{
  final String? id;
  final String? userId;
  final String? workspaceId;
{chr(10).join(declarations)}
  final String? createdAt;
  final String? updatedAt;

  const {model_name}({{
    this.id,
    this.userId,
    this.workspaceId,
{chr(10).join(constructor_fields)}
    this.createdAt,
    this.updatedAt,
  }});

  factory {model_name}.fromJson(Map<String, dynamic> json) {{
    return {model_name}(
      id: json['id']?.toString(),
      userId: json['user_id']?.toString(),
      workspaceId: json['workspace_id']?.toString(),
{chr(10).join(from_json_fields)}
      createdAt: json['created_at']?.toString(),
      updatedAt: json['updated_at']?.toString(),
    );
  }}

  Map<String, dynamic> toJson() {{
    return <String, dynamic>{{
      'id': id,
      'user_id': userId,
      'workspace_id': workspaceId,
{chr(10).join(to_json_fields)}
      'created_at': createdAt,
      'updated_at': updatedAt,
    }};
  }}
}}
'''

    # -----------------------------------------------------------------------
    # React helper renderers
    # -----------------------------------------------------------------------

    def _react_initial_state(self, fields: List[FrontendField]) -> str:
        if not fields:
            return '{\n  name: "",\n  description: "",\n}'

        lines = ["{"]
        for field_item in fields:
            value = self._field_default_js_value(field_item)
            lines.append(f"  {field_item.name}: {value},")
        lines.append("}")
        return "\n".join(lines)

    def _react_form_fields(self, fields: List[FrontendField]) -> str:
        if not fields:
            fields = [
                FrontendField(name="name", label="Name", field_type="text", required=True),
                FrontendField(name="description", label="Description", field_type="textarea"),
            ]

        chunks = []
        for field_item in fields:
            label = field_item.label or self._humanize_name(field_item.name)
            placeholder = field_item.placeholder or f"Enter {label.lower()}"
            required = "required" if field_item.required else ""

            if field_item.field_type in {"textarea", "longtext"}:
                chunks.append(f'''        <label className="block">
          <span className="mb-1 block text-sm font-medium text-slate-300">{self._escape_jsx_text(label)}</span>
          <textarea
            {required}
            value={{String(form.{field_item.name} ?? "")}}
            onChange={{(event) => updateField("{field_item.name}", event.target.value as never)}}
            placeholder="{self._escape_jsx_attr(placeholder)}"
            className="min-h-28 w-full rounded-xl border border-slate-700 bg-slate-900 px-4 py-3 text-sm text-white outline-none transition focus:border-white"
          />
        </label>''')
            elif field_item.field_type in {"boolean", "checkbox"}:
                chunks.append(f'''        <label className="flex items-center gap-3 rounded-xl border border-slate-800 bg-slate-900 px-4 py-3">
          <input
            type="checkbox"
            checked={{Boolean(form.{field_item.name})}}
            onChange={{(event) => updateField("{field_item.name}", event.target.checked as never)}}
            className="h-4 w-4"
          />
          <span className="text-sm font-medium text-slate-300">{self._escape_jsx_text(label)}</span>
        </label>''')
            else:
                input_type = self._field_to_html_input_type(field_item)
                chunks.append(f'''        <label className="block">
          <span className="mb-1 block text-sm font-medium text-slate-300">{self._escape_jsx_text(label)}</span>
          <input
            {required}
            type="{input_type}"
            value={{String(form.{field_item.name} ?? "")}}
            onChange={{(event) => updateField("{field_item.name}", event.target.value as never)}}
            placeholder="{self._escape_jsx_attr(placeholder)}"
            className="w-full rounded-xl border border-slate-700 bg-slate-900 px-4 py-3 text-sm text-white outline-none transition focus:border-white"
          />
        </label>''')

        return "\n".join(chunks)

    def _react_action_buttons(self, actions: List[FrontendAction]) -> str:
        if not actions:
            return ""

        chunks = []
        for action in actions:
            chunks.append(f'''          <button
            type="button"
            onClick={{() => console.info("{self._escape_jsx_attr(action.name)} action clicked")}}
            className="rounded-xl border border-slate-700 px-5 py-2.5 text-sm font-semibold text-slate-100 transition hover:bg-slate-900"
          >
            {self._escape_jsx_text(action.label)}
          </button>''')
        return "\n".join(chunks)

    # -----------------------------------------------------------------------
    # Flutter helper renderers
    # -----------------------------------------------------------------------

    def _flutter_controllers(self, fields: List[FrontendField]) -> str:
        if not fields:
            fields = [
                FrontendField(name="name"),
                FrontendField(name="description"),
            ]

        lines = []
        for field_item in fields:
            if field_item.field_type not in {"boolean", "checkbox"}:
                lines.append(
                    f"  final TextEditingController _{field_item.name}Controller = TextEditingController();"
                )
            else:
                lines.append(f"  bool _{field_item.name} = false;")
        return "\n".join(lines)

    def _flutter_dispose_lines(self, fields: List[FrontendField]) -> str:
        if not fields:
            fields = [
                FrontendField(name="name"),
                FrontendField(name="description"),
            ]

        lines = []
        for field_item in fields:
            if field_item.field_type not in {"boolean", "checkbox"}:
                lines.append(f"    _{field_item.name}Controller.dispose();")
        return "\n".join(lines) or "    // No controllers to dispose."

    def _flutter_field_widgets(self, fields: List[FrontendField]) -> str:
        if not fields:
            fields = [
                FrontendField(name="name", label="Name", required=True),
                FrontendField(name="description", label="Description", field_type="textarea"),
            ]

        chunks = []
        for field_item in fields:
            label = field_item.label or self._humanize_name(field_item.name)
            placeholder = field_item.placeholder or f"Enter {label.lower()}"

            if field_item.field_type in {"boolean", "checkbox"}:
                chunks.append(f'''                SwitchListTile(
                  value: _{field_item.name},
                  onChanged: (value) {{
                    setState(() {{
                      _{field_item.name} = value;
                    }});
                  }},
                  title: const Text(
                    '{self._escape_dart_text(label)}',
                    style: TextStyle(color: Colors.white),
                  ),
                  activeColor: Colors.white,
                ),
                const SizedBox(height: 12),''')
            else:
                max_lines = "4" if field_item.field_type in {"textarea", "longtext"} else "1"
                chunks.append(f'''                TextField(
                  controller: _{field_item.name}Controller,
                  maxLines: {max_lines},
                  style: const TextStyle(color: Colors.white),
                  decoration: InputDecoration(
                    labelText: '{self._escape_dart_text(label)}',
                    hintText: '{self._escape_dart_text(placeholder)}',
                    labelStyle: const TextStyle(color: Color(0xFFCBD5E1)),
                    hintStyle: const TextStyle(color: Color(0xFF64748B)),
                    enabledBorder: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(14),
                      borderSide: const BorderSide(color: Color(0xFF334155)),
                    ),
                    focusedBorder: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(14),
                      borderSide: const BorderSide(color: Colors.white),
                    ),
                  ),
                ),
                const SizedBox(height: 12),''')
        return "\n".join(chunks)

    def _flutter_payload_fields(self, fields: List[FrontendField]) -> str:
        if not fields:
            fields = [
                FrontendField(name="name"),
                FrontendField(name="description"),
            ]

        lines = []
        for field_item in fields:
            if field_item.field_type in {"boolean", "checkbox"}:
                lines.append(f"      '{field_item.name}': _{field_item.name},")
            else:
                lines.append(f"      '{field_item.name}': _{field_item.name}Controller.text.trim(),")
        return "\n".join(lines)

    def _flutter_action_buttons(self, actions: List[FrontendAction]) -> str:
        if not actions:
            return ""

        chunks = []
        for action in actions:
            chunks.append(f'''                    OutlinedButton(
                      onPressed: () {{
                        debugPrint('{self._escape_dart_text(action.name)} action clicked');
                      }},
                      child: const Text('{self._escape_dart_text(action.label)}'),
                    ),''')
        return "\n".join(chunks)

    # -----------------------------------------------------------------------
    # File writing
    # -----------------------------------------------------------------------

    def _write_generated_files(self, files: List[GeneratedFrontendFile]) -> List[str]:
        """
        Write generated files to disk.

        Only allowed when:
            - enable_file_write=True
            - allowed_output_root is configured
            - target path stays within allowed_output_root
        """

        if not self.enable_file_write:
            raise PermissionError("File writing is disabled for FrontendBuilder.")

        if self.allowed_output_root is None:
            raise PermissionError("allowed_output_root must be configured before writing files.")

        written: List[str] = []

        for generated_file in files:
            relative_path = generated_file.file_path
            if not self._is_safe_relative_path(relative_path):
                raise ValueError(f"Unsafe file path: {relative_path}")

            target_path = (self.allowed_output_root / relative_path).resolve()

            if not str(target_path).startswith(str(self.allowed_output_root)):
                raise PermissionError(f"Target path escapes allowed root: {target_path}")

            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.write_text(generated_file.content, encoding="utf-8")
            written.append(generated_file.file_path)

        return written

    # -----------------------------------------------------------------------
    # Required Compatibility Hooks
    # -----------------------------------------------------------------------

    def _validate_task_context(
        self,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate SaaS user/workspace isolation context.
        """

        effective_user_id = user_id or self.user_id
        effective_workspace_id = workspace_id or self.workspace_id

        if self.strict_context:
            if effective_user_id is None:
                return self._error_result(
                    message="Missing user_id. Frontend generation must be scoped to a SaaS user.",
                    code="MISSING_USER_ID",
                )

            if effective_workspace_id is None:
                return self._error_result(
                    message="Missing workspace_id. Frontend generation must be scoped to a workspace.",
                    code="MISSING_WORKSPACE_ID",
                )

        return self._safe_result(
            message="Task context validated.",
            data={
                "user_id": effective_user_id,
                "workspace_id": effective_workspace_id,
                "context": context or {},
            },
        )

    def _requires_security_check(
        self,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Determine whether Security Agent approval is required.
        """

        action_lower = action.lower()
        payload_text = json.dumps(payload or {}, default=str).lower()

        sensitive_keywords = [
            "write_files",
            "delete",
            "overwrite",
            "remove",
            "secret",
            "token",
            "private_key",
            "password",
            "credential",
            "production",
            "destructive",
        ]

        return any(keyword in action_lower or keyword in payload_text for keyword in sensitive_keywords)

    def _request_security_approval(
        self,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Security Agent approval payload.
        """

        return {
            "required": self._requires_security_check(action, payload),
            "agent": self.AGENT_NAME,
            "module": self.AGENT_MODULE,
            "action": action,
            "payload": payload or {},
            "reason": "Frontend file generation may write files or affect app structure. Security approval is required before sensitive actions.",
            "created_at": self._utc_now(),
        }

    def _prepare_verification_payload(
        self,
        build_result: FrontendBuildResult,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare payload for Verification Agent.
        """

        return {
            "agent": self.AGENT_NAME,
            "module": self.AGENT_MODULE,
            "verification_type": "frontend_build_review",
            "status": "pending",
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "framework": build_result.framework,
            "component_kind": build_result.component_kind,
            "name": build_result.name,
            "files": [
                {
                    "file_path": file.file_path,
                    "language": file.language,
                    "description": file.description,
                    "status": file.status,
                }
                for file in build_result.files
            ],
            "checks": [
                "Confirm generated files match requested framework.",
                "Confirm user_id and workspace_id are preserved in API/service logic.",
                "Confirm generated UI does not expose secrets.",
                "Confirm file paths are safe and project-relative.",
                "Confirm generated code can be formatted/linted.",
                "Confirm no destructive command is executed.",
            ],
            "context": context or {},
            "created_at": self._utc_now(),
        }

    def _prepare_memory_payload(
        self,
        build_result: FrontendBuildResult,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.
        """

        return {
            "agent": self.AGENT_NAME,
            "module": self.AGENT_MODULE,
            "memory_type": "frontend_generation_pattern",
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "should_store": True,
            "title": f"{build_result.framework} {build_result.component_kind}: {build_result.name}",
            "summary": f"Generated {len(build_result.files)} frontend file(s) for {build_result.name}.",
            "framework": build_result.framework,
            "component_kind": build_result.component_kind,
            "files": [file.file_path for file in build_result.files],
            "warnings": build_result.warnings,
            "context": context or {},
            "created_at": self._utc_now(),
        }

    def _emit_agent_event(
        self,
        event_name: str,
        payload: Dict[str, Any],
    ) -> None:
        """
        Emit dashboard/registry/router event.
        """

        try:
            event_payload = {
                "agent": self.AGENT_NAME,
                "module": self.AGENT_MODULE,
                "event_name": event_name,
                "payload": payload,
                "timestamp": self._utc_now(),
            }

            if hasattr(super(), "emit_event"):
                try:
                    super().emit_event(event_name, event_payload)  # type: ignore
                except Exception:
                    pass

            logger.debug("Agent event: %s", event_payload)

        except Exception:
            logger.exception("Failed to emit FrontendBuilder event.")

    def _log_audit_event(
        self,
        action: str,
        status: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Write audit log event.

        Future system can replace this with DB-backed AuditLog model/service.
        """

        if not self.enable_audit_logs:
            return

        try:
            audit_payload = {
                "agent": self.AGENT_NAME,
                "module": self.AGENT_MODULE,
                "action": action,
                "status": status,
                "user_id": user_id or self.user_id,
                "workspace_id": workspace_id or self.workspace_id,
                "details": details or {},
                "timestamp": self._utc_now(),
            }
            logger.info("AUDIT_EVENT %s", json.dumps(audit_payload, default=str))
        except Exception:
            logger.exception("Failed to write FrontendBuilder audit event.")

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard success result.
        """

        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": metadata or self._base_metadata(),
        }

    def _error_result(
        self,
        message: str,
        code: str = "ERROR",
        exception: Optional[BaseException] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard error result.
        """

        error_payload: Dict[str, Any] = {
            "code": code,
            "message": message,
        }

        if exception is not None:
            error_payload["exception_type"] = exception.__class__.__name__
            error_payload["exception_message"] = str(exception)

        return {
            "success": False,
            "message": message,
            "data": {},
            "error": error_payload,
            "metadata": metadata or self._base_metadata(),
        }

    # -----------------------------------------------------------------------
    # Utility Methods
    # -----------------------------------------------------------------------

    def _build_result_to_dict(self, build_result: FrontendBuildResult) -> Dict[str, Any]:
        payload = asdict(build_result)
        payload["files"] = [asdict(file) for file in build_result.files]
        return payload

    def _collect_warnings(
        self,
        request: FrontendBuildRequest,
        files: List[GeneratedFrontendFile],
    ) -> List[str]:
        warnings: List[str] = []

        if request.use_auth:
            warnings.append("Generated frontend expects authenticated user/workspace context.")

        if not request.fields:
            warnings.append("No fields were provided, so default name/description fields were generated.")

        if request.framework == FrontendFramework.NEXTJS.value:
            warnings.append("For Next.js, do not place secrets in NEXT_PUBLIC environment variables.")

        if request.framework == FrontendFramework.FLUTTER.value:
            warnings.append("Flutter API service requires package:http in pubspec.yaml.")

        if any("localhost" in file.content for file in files):
            warnings.append("Default localhost API URL is included as a development fallback only.")

        return self._deduplicate_strings(warnings)

    def _build_next_steps(
        self,
        request: FrontendBuildRequest,
        write_files: bool,
    ) -> List[str]:
        steps = [
            "Review generated code before adding it to production.",
            "Run framework formatter/linter.",
            "Connect API endpoints to real backend routes.",
            "Pass user_id and workspace_id from authenticated session context.",
            "Send generated payload to Verification Agent for validation.",
        ]

        if request.framework == FrontendFramework.REACT.value:
            steps.extend([
                "Run npm install if the React project dependencies are not installed.",
                "Import the generated component into your route or dashboard layout.",
            ])

        elif request.framework == FrontendFramework.NEXTJS.value:
            steps.extend([
                "Place page files under the correct app/ or pages/ route directory.",
                "Keep server-only secrets outside NEXT_PUBLIC variables.",
            ])

        elif request.framework == FrontendFramework.FLUTTER.value:
            steps.extend([
                "Add package:http to pubspec.yaml if using the generated API service.",
                "Register the generated screen in your Flutter route table.",
            ])

        if not write_files:
            steps.append("Copy generated files manually or enable controlled file writing after Security Agent approval.")

        return self._deduplicate_strings(steps)

    def _default_paths(
        self,
        framework: FrontendFramework,
        component_kind: str,
        name: str,
    ) -> Dict[str, str]:
        kebab = self._to_kebab_case(name)
        snake = self._to_snake_case(name)

        if framework == FrontendFramework.REACT:
            return {
                "component": f"src/components/{kebab}.tsx",
                "api_service": "src/services/frontend-api.ts",
                "types": f"src/types/{kebab}.ts",
            }

        if framework == FrontendFramework.NEXTJS:
            return {
                "page": f"app/{kebab}/page.tsx",
                "api_service": "src/services/frontend-api.ts",
                "types": f"src/types/{kebab}.ts",
            }

        if framework == FrontendFramework.FLUTTER:
            return {
                "screen": f"lib/screens/{snake}.dart",
                "api_service": "lib/services/frontend_api_service.dart",
                "model": f"lib/models/{snake}_model.dart",
            }

        return {}

    def _parse_framework(self, framework: str) -> FrontendFramework:
        normalized = framework.lower().strip()
        if normalized in {"react", "reactjs", "react.js"}:
            return FrontendFramework.REACT
        if normalized in {"next", "nextjs", "next.js"}:
            return FrontendFramework.NEXTJS
        if normalized in {"flutter", "dart"}:
            return FrontendFramework.FLUTTER
        raise ValueError(f"Unsupported framework: {framework}")

    def _safe_component_name(self, name: str) -> str:
        cleaned = re.sub(r"[^a-zA-Z0-9_\\-\\s]", "", name).strip()
        if not cleaned:
            cleaned = "GeneratedScreen"

        parts = re.split(r"[\\s_\\-]+", cleaned)
        pascal = "".join(part[:1].upper() + part[1:] for part in parts if part)

        if not pascal:
            pascal = "GeneratedScreen"

        if pascal[0].isdigit():
            pascal = f"Generated{pascal}"

        return pascal

    def _is_safe_identifier(self, value: str) -> bool:
        return bool(re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", value))

    def _is_safe_relative_path(self, value: str) -> bool:
        if not value or os.path.isabs(value):
            return False

        if ".." in Path(value).parts:
            return False

        if not self.SAFE_FILENAME_RE.match(value):
            return False

        return True

    def _field_to_ts_type(self, field_item: FrontendField) -> str:
        field_type = field_item.field_type.lower()

        if field_type in {"number", "int", "float", "decimal"}:
            return "number"
        if field_type in {"boolean", "checkbox", "bool"}:
            return "boolean"
        if field_type in {"array", "list"}:
            return "unknown[]"
        if field_type in {"object", "json"}:
            return "Record<string, unknown>"
        return "string"

    def _field_to_dart_type(self, field_item: FrontendField) -> str:
        field_type = field_item.field_type.lower()

        if field_type in {"number", "int"}:
            return "int"
        if field_type in {"float", "decimal"}:
            return "double"
        if field_type in {"boolean", "checkbox", "bool"}:
            return "bool"
        if field_type in {"array", "list"}:
            return "List<dynamic>"
        if field_type in {"object", "json"}:
            return "Map<String, dynamic>"
        return "String"

    def _field_to_html_input_type(self, field_item: FrontendField) -> str:
        field_type = field_item.field_type.lower()
        mapping = {
            "email": "email",
            "password": "password",
            "number": "number",
            "int": "number",
            "float": "number",
            "date": "date",
            "datetime": "datetime-local",
            "phone": "tel",
            "tel": "tel",
            "url": "url",
            "search": "search",
        }
        return mapping.get(field_type, "text")

    def _field_default_js_value(self, field_item: FrontendField) -> str:
        if field_item.default_value is not None:
            return json.dumps(field_item.default_value)

        field_type = field_item.field_type.lower()

        if field_type in {"number", "int", "float", "decimal"}:
            return "0"
        if field_type in {"boolean", "checkbox", "bool"}:
            return "false"
        if field_type in {"array", "list"}:
            return "[]"
        if field_type in {"object", "json"}:
            return "{}"
        return '""'

    def _to_snake_case(self, value: str) -> str:
        value = re.sub(r"(.)([A-Z][a-z]+)", r"\\1_\\2", value)
        value = re.sub(r"([a-z0-9])([A-Z])", r"\\1_\\2", value)
        value = re.sub(r"[^a-zA-Z0-9]+", "_", value)
        return value.strip("_").lower() or "generated_screen"

    def _to_kebab_case(self, value: str) -> str:
        snake = self._to_snake_case(value)
        return snake.replace("_", "-")

    def _humanize_name(self, value: str) -> str:
        snake = self._to_snake_case(value)
        return snake.replace("_", " ").title()

    def _escape_jsx_text(self, value: str) -> str:
        return (
            str(value)
            .replace("{", "&#123;")
            .replace("}", "&#125;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )

    def _escape_jsx_attr(self, value: str) -> str:
        return (
            str(value)
            .replace("&", "&amp;")
            .replace('"', "&quot;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )

    def _escape_dart_text(self, value: str) -> str:
        return str(value).replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n")

    def _deduplicate_strings(self, items: List[str]) -> List[str]:
        seen = set()
        output = []
        for item in items:
            key = item.strip().lower()
            if key and key not in seen:
                seen.add(key)
                output.append(item.strip())
        return output

    def _base_metadata(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
    ) -> Dict[str, Any]:
        return {
            "agent": self.AGENT_NAME,
            "module": self.AGENT_MODULE,
            "version": self.VERSION,
            "user_id": user_id or self.user_id,
            "workspace_id": workspace_id or self.workspace_id,
            "timestamp": self._utc_now(),
        }

    def _utc_now(self) -> str:
        return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Convenience wrapper
# ---------------------------------------------------------------------------

def build_frontend(
    request: Union[FrontendBuildRequest, Dict[str, Any]],
    user_id: Optional[Union[str, int]] = None,
    workspace_id: Optional[Union[str, int]] = None,
    strict_context: bool = False,
) -> Dict[str, Any]:
    """
    Convenience function for direct usage in scripts/tests.
    """

    builder = FrontendBuilder(
        user_id=user_id,
        workspace_id=workspace_id,
        strict_context=strict_context,
    )

    return builder.build(
        request=request,
        user_id=user_id,
        workspace_id=workspace_id,
    )


# ---------------------------------------------------------------------------
# Manual test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    demo_request = {
        "framework": "react",
        "component_kind": "dashboard",
        "name": "ClientDashboard",
        "description": "Dashboard for viewing client project status, analytics, and actions.",
        "fields": [
            {
                "name": "projectName",
                "label": "Project Name",
                "field_type": "text",
                "required": True,
            },
            {
                "name": "budget",
                "label": "Budget",
                "field_type": "number",
                "required": False,
            },
            {
                "name": "isActive",
                "label": "Active Project",
                "field_type": "boolean",
                "required": False,
            },
        ],
        "actions": [
            {
                "name": "refreshAnalytics",
                "label": "Refresh Analytics",
                "action_type": "button",
                "method": "GET",
            }
        ],
    }

    result = build_frontend(
        request=demo_request,
        user_id="demo_user",
        workspace_id="demo_workspace",
        strict_context=True,
    )

    print(json.dumps(result, indent=2, default=str))