"""
agents/visual_agent/ui_mapper.py

William / Jarvis Multi-Agent AI SaaS System - Visual Agent

Purpose:
    Maps UI elements, hierarchy, clickable areas, cards, tables, and menus from
    screenshot/OCR/element-detection inputs.

This file is designed to be:
    - Production-level and import-safe
    - SaaS user/workspace isolated
    - Compatible with BaseAgent, MasterAgent routing, Agent Registry, and Agent Loader
    - Compatible with Security Agent approval hooks
    - Compatible with Memory Agent payload preparation
    - Compatible with Verification Agent payload preparation
    - Ready for FastAPI/dashboard integration

Important:
    This mapper is read-only by default. It does not click, type, browse, call,
    message, pay, upload, delete, or perform destructive actions. It only maps
    visual/UI structure from provided input data.

Public class:
    UIMapper

Main public methods:
    - map_ui()
    - map_from_ocr()
    - map_from_elements()
    - find_clickable_areas()
    - infer_hierarchy()
    - detect_cards()
    - detect_tables()
    - detect_menus()
    - export_ui_map()
"""

from __future__ import annotations

import json
import logging
import math
import re
import traceback
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple, Union


try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback keeps file import-safe

    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This allows this file to import safely before the real William/Jarvis
        BaseAgent exists. The real project BaseAgent should override this.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.logger = logging.getLogger(self.agent_name)

        async def run(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent does not implement run().",
                "data": {},
                "error": "BASE_AGENT_FALLBACK_RUN_NOT_IMPLEMENTED",
                "metadata": {},
            }


class UIElementType(str, Enum):
    """Normalized UI element types."""

    UNKNOWN = "unknown"
    TEXT = "text"
    BUTTON = "button"
    LINK = "link"
    INPUT = "input"
    TEXTAREA = "textarea"
    CHECKBOX = "checkbox"
    RADIO = "radio"
    SELECT = "select"
    TOGGLE = "toggle"
    ICON = "icon"
    IMAGE = "image"
    CARD = "card"
    TABLE = "table"
    TABLE_ROW = "table_row"
    TABLE_CELL = "table_cell"
    MENU = "menu"
    MENU_ITEM = "menu_item"
    NAV = "nav"
    TAB = "tab"
    MODAL = "modal"
    FORM = "form"
    HEADER = "header"
    FOOTER = "footer"
    SIDEBAR = "sidebar"
    TOOLBAR = "toolbar"
    LIST = "list"
    LIST_ITEM = "list_item"
    DROPDOWN = "dropdown"
    BADGE = "badge"
    ALERT = "alert"
    TOAST = "toast"
    LOADER = "loader"
    PROGRESS = "progress"
    PAGINATION = "pagination"
    SEARCH_BOX = "search_box"


class UIContainerType(str, Enum):
    """Normalized UI container/group types."""

    ROOT = "root"
    SECTION = "section"
    ROW = "row"
    COLUMN = "column"
    CARD_GROUP = "card_group"
    TABLE_GROUP = "table_group"
    MENU_GROUP = "menu_group"
    FORM_GROUP = "form_group"
    NAV_GROUP = "nav_group"
    FLOATING_GROUP = "floating_group"
    UNKNOWN = "unknown"


class Clickability(str, Enum):
    """Clickability confidence labels."""

    NONE = "none"
    POSSIBLE = "possible"
    LIKELY = "likely"
    CONFIRMED = "confirmed"


@dataclass
class BoundingBox:
    """Rectangle bounds in screen/image coordinates."""

    x: float
    y: float
    width: float
    height: float

    @property
    def left(self) -> float:
        return self.x

    @property
    def top(self) -> float:
        return self.y

    @property
    def right(self) -> float:
        return self.x + self.width

    @property
    def bottom(self) -> float:
        return self.y + self.height

    @property
    def center_x(self) -> float:
        return self.x + self.width / 2

    @property
    def center_y(self) -> float:
        return self.y + self.height / 2

    @property
    def area(self) -> float:
        return max(0.0, self.width) * max(0.0, self.height)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "x": round(self.x, 3),
            "y": round(self.y, 3),
            "width": round(self.width, 3),
            "height": round(self.height, 3),
            "left": round(self.left, 3),
            "top": round(self.top, 3),
            "right": round(self.right, 3),
            "bottom": round(self.bottom, 3),
            "center_x": round(self.center_x, 3),
            "center_y": round(self.center_y, 3),
            "area": round(self.area, 3),
        }


@dataclass
class UIElement:
    """Normalized UI element."""

    element_id: str
    element_type: UIElementType
    bbox: BoundingBox
    text: str = ""
    role: Optional[str] = None
    label: Optional[str] = None
    confidence: float = 0.5
    clickable: Clickability = Clickability.NONE
    click_target: Optional[Dict[str, float]] = None
    parent_id: Optional[str] = None
    child_ids: List[str] = field(default_factory=list)
    source: str = "unknown"
    attributes: Dict[str, Any] = field(default_factory=dict)
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "element_id": self.element_id,
            "element_type": self.element_type.value,
            "bbox": self.bbox.to_dict(),
            "text": self.text,
            "role": self.role,
            "label": self.label,
            "confidence": round(float(self.confidence), 3),
            "clickable": self.clickable.value,
            "click_target": self.click_target,
            "parent_id": self.parent_id,
            "child_ids": self.child_ids,
            "source": self.source,
            "attributes": self.attributes,
            "evidence": self.evidence,
        }


@dataclass
class UIContainer:
    """Logical container/group in the UI hierarchy."""

    container_id: str
    container_type: UIContainerType
    bbox: BoundingBox
    child_ids: List[str] = field(default_factory=list)
    parent_id: Optional[str] = None
    label: Optional[str] = None
    confidence: float = 0.5
    attributes: Dict[str, Any] = field(default_factory=dict)
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "container_id": self.container_id,
            "container_type": self.container_type.value,
            "bbox": self.bbox.to_dict(),
            "child_ids": self.child_ids,
            "parent_id": self.parent_id,
            "label": self.label,
            "confidence": round(float(self.confidence), 3),
            "attributes": self.attributes,
            "evidence": self.evidence,
        }


@dataclass
class UIMapRequest:
    """
    Request object for UI mapping.

    Inputs can come from:
        - Visual Agent screenshot_reader.py
        - Visual Agent ocr_engine.py
        - Visual Agent element_detector.py
        - Browser Agent DOM/screenshot bridge
        - Mobile/desktop worker screenshots
        - Dashboard/API uploads
    """

    user_id: str
    workspace_id: str
    screenshot_width: int
    screenshot_height: int
    ocr_blocks: List[Dict[str, Any]] = field(default_factory=list)
    detected_elements: List[Dict[str, Any]] = field(default_factory=list)
    screenshot_id: Optional[str] = None
    image_path: Optional[str] = None
    page_url: Optional[str] = None
    app_name: Optional[str] = None
    screen_name: Optional[str] = None
    task_id: Optional[str] = None
    correlation_id: Optional[str] = None
    source_agent: Optional[str] = None
    requested_by: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_context(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "task_id": self.task_id,
            "correlation_id": self.correlation_id,
            "source_agent": self.source_agent,
            "requested_by": self.requested_by,
            "metadata": self.metadata,
        }


@dataclass
class UIMap:
    """Complete mapped UI output."""

    screenshot_width: int
    screenshot_height: int
    elements: List[Dict[str, Any]]
    containers: List[Dict[str, Any]]
    hierarchy: Dict[str, Any]
    clickable_areas: List[Dict[str, Any]]
    cards: List[Dict[str, Any]]
    tables: List[Dict[str, Any]]
    menus: List[Dict[str, Any]]
    summary: Dict[str, Any]
    user_id: str
    workspace_id: str
    screenshot_id: Optional[str] = None
    page_url: Optional[str] = None
    app_name: Optional[str] = None
    screen_name: Optional[str] = None
    correlation_id: Optional[str] = None
    mapped_at: str = field(default_factory=lambda: _utc_now_iso())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""

    return datetime.now(timezone.utc).isoformat()


def _safe_float(value: Any, default: float = 0.0) -> float:
    """Safely convert value to float."""

    try:
        if value is None:
            return default
        return float(value)
    except Exception:
        return default


def _safe_int(value: Any, default: int = 0) -> int:
    """Safely convert value to int."""

    try:
        if value is None:
            return default
        return int(float(value))
    except Exception:
        return default


def _normalize_text(value: Any) -> str:
    """Normalize text safely."""

    if value is None:
        return ""
    return re.sub(r"\s+", " ", str(value)).strip()


def _lower(value: Any) -> str:
    return _normalize_text(value).lower()


def _clamp(value: float, min_value: float, max_value: float) -> float:
    return max(min_value, min(value, max_value))


def _bbox_from_any(raw: Dict[str, Any], screen_width: int, screen_height: int) -> BoundingBox:
    """
    Normalize bounding boxes from common formats.

    Supported formats:
        - x, y, width, height
        - left, top, right, bottom
        - bbox: {x,y,width,height} or [x,y,width,height]
        - bounds: {left,top,right,bottom} or [left,top,right,bottom]
    """

    source: Any = raw.get("bbox") or raw.get("bounds") or raw.get("box") or raw

    if isinstance(source, (list, tuple)):
        values = list(source)
        if len(values) >= 4:
            x = _safe_float(values[0])
            y = _safe_float(values[1])
            third = _safe_float(values[2])
            fourth = _safe_float(values[3])

            if third > x and fourth > y and (raw.get("format") == "ltrb" or source is raw.get("bounds")):
                width = third - x
                height = fourth - y
            else:
                width = third
                height = fourth

            return _sanitize_bbox(x, y, width, height, screen_width, screen_height)

    if isinstance(source, dict):
        if all(key in source for key in ("left", "top", "right", "bottom")):
            left = _safe_float(source.get("left"))
            top = _safe_float(source.get("top"))
            right = _safe_float(source.get("right"))
            bottom = _safe_float(source.get("bottom"))
            return _sanitize_bbox(left, top, right - left, bottom - top, screen_width, screen_height)

        if all(key in source for key in ("x1", "y1", "x2", "y2")):
            left = _safe_float(source.get("x1"))
            top = _safe_float(source.get("y1"))
            right = _safe_float(source.get("x2"))
            bottom = _safe_float(source.get("y2"))
            return _sanitize_bbox(left, top, right - left, bottom - top, screen_width, screen_height)

        x = _safe_float(source.get("x", raw.get("x", 0)))
        y = _safe_float(source.get("y", raw.get("y", 0)))
        width = _safe_float(source.get("width", raw.get("width", 0)))
        height = _safe_float(source.get("height", raw.get("height", 0)))

        return _sanitize_bbox(x, y, width, height, screen_width, screen_height)

    return _sanitize_bbox(0, 0, 0, 0, screen_width, screen_height)


def _sanitize_bbox(
    x: float,
    y: float,
    width: float,
    height: float,
    screen_width: int,
    screen_height: int,
) -> BoundingBox:
    """Clamp bounding box to screenshot bounds."""

    max_w = max(1, screen_width)
    max_h = max(1, screen_height)

    x = _clamp(x, 0, max_w)
    y = _clamp(y, 0, max_h)
    width = max(0.0, width)
    height = max(0.0, height)

    if x + width > max_w:
        width = max(0.0, max_w - x)
    if y + height > max_h:
        height = max(0.0, max_h - y)

    return BoundingBox(x=x, y=y, width=width, height=height)


def _iou(a: BoundingBox, b: BoundingBox) -> float:
    """Intersection-over-union for two boxes."""

    left = max(a.left, b.left)
    top = max(a.top, b.top)
    right = min(a.right, b.right)
    bottom = min(a.bottom, b.bottom)

    if right <= left or bottom <= top:
        return 0.0

    intersection = (right - left) * (bottom - top)
    union = a.area + b.area - intersection

    if union <= 0:
        return 0.0

    return intersection / union


def _contains(parent: BoundingBox, child: BoundingBox, tolerance: float = 4.0) -> bool:
    """Return true if parent contains child with tolerance."""

    return (
        child.left >= parent.left - tolerance
        and child.top >= parent.top - tolerance
        and child.right <= parent.right + tolerance
        and child.bottom <= parent.bottom + tolerance
    )


def _union_bbox(boxes: Sequence[BoundingBox]) -> BoundingBox:
    """Return union bounding box."""

    if not boxes:
        return BoundingBox(0, 0, 0, 0)

    left = min(box.left for box in boxes)
    top = min(box.top for box in boxes)
    right = max(box.right for box in boxes)
    bottom = max(box.bottom for box in boxes)

    return BoundingBox(left, top, right - left, bottom - top)


def _distance(a: BoundingBox, b: BoundingBox) -> float:
    """Euclidean distance between centers."""

    return math.hypot(a.center_x - b.center_x, a.center_y - b.center_y)


class UIMapper(BaseAgent):
    """
    Maps UI elements and structure for the William/Jarvis Visual Agent.

    Integration notes:
        - Master Agent can route screenshot/UI mapping tasks here.
        - Visual Agent can call this after OCR and element detection.
        - Verification Agent can use UI maps to verify visible buttons, modals,
          forms, cards, tables, menus, and clickable areas.
        - Memory Agent can store recurring UI patterns by app/page/workspace.
        - Dashboard/API can render the UI map as overlays on screenshots.
        - Security Agent can approve mapping when sensitive screens are flagged.

    This class is read-only and does not interact with the UI directly.
    """

    AGENT_NAME = "visual_agent.ui_mapper"
    AGENT_VERSION = "1.0.0"

    CLICK_WORDS = {
        "ok",
        "yes",
        "no",
        "next",
        "back",
        "done",
        "save",
        "submit",
        "cancel",
        "close",
        "open",
        "continue",
        "start",
        "stop",
        "login",
        "log in",
        "sign in",
        "signup",
        "sign up",
        "register",
        "buy",
        "pay",
        "checkout",
        "apply",
        "send",
        "search",
        "filter",
        "upload",
        "download",
        "edit",
        "delete",
        "remove",
        "view",
        "details",
        "learn more",
        "call",
        "email",
        "chat",
        "book",
        "schedule",
        "accept",
        "decline",
        "confirm",
        "retry",
        "refresh",
        "more",
        "menu",
    }

    INPUT_HINT_WORDS = {
        "name",
        "email",
        "phone",
        "password",
        "search",
        "address",
        "message",
        "username",
        "amount",
        "city",
        "state",
        "zip",
        "postal",
        "country",
        "company",
        "website",
        "subject",
    }

    MENU_HINT_WORDS = {
        "file",
        "edit",
        "view",
        "tools",
        "settings",
        "help",
        "dashboard",
        "home",
        "profile",
        "account",
        "billing",
        "reports",
        "analytics",
        "logout",
        "log out",
    }

    def __init__(
        self,
        security_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        event_emitter: Optional[Callable[[Dict[str, Any]], Any]] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], Any]] = None,
        logger: Optional[logging.Logger] = None,
        min_clickable_width: int = 18,
        min_clickable_height: int = 14,
        grouping_vertical_gap: int = 18,
        grouping_horizontal_gap: int = 24,
        max_elements_returned: int = 500,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name=self.AGENT_NAME, **kwargs)

        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.verification_agent = verification_agent
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger
        self.logger = logger or logging.getLogger(self.AGENT_NAME)

        self.min_clickable_width = int(min_clickable_width)
        self.min_clickable_height = int(min_clickable_height)
        self.grouping_vertical_gap = int(grouping_vertical_gap)
        self.grouping_horizontal_gap = int(grouping_horizontal_gap)
        self.max_elements_returned = int(max_elements_returned)

    async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        BaseAgent-compatible async entry point.

        Expected task example:
            {
                "user_id": "user_123",
                "workspace_id": "workspace_456",
                "screenshot_width": 1365,
                "screenshot_height": 768,
                "ocr_blocks": [...],
                "detected_elements": [...]
            }
        """

        try:
            request = self._build_request_from_task(task)
            return self.map_ui(request)
        except Exception as exc:
            return self._error_result(
                message="Failed to run UI mapping task.",
                error=exc,
                metadata={"agent": self.AGENT_NAME, "task_type": "run"},
            )

    def map_ui(self, request: Union[UIMapRequest, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Build a full UI map from OCR blocks and/or detected elements.

        Returns standard William/Jarvis structured result:
            {
                "success": bool,
                "message": str,
                "data": {
                    "ui_map": {...},
                    "verification": {...},
                    "memory_payload": {...}
                },
                "error": None | str | dict,
                "metadata": {...}
            }
        """

        try:
            normalized_request = (
                request if isinstance(request, UIMapRequest) else self._build_request_from_task(request)
            )

            context = normalized_request.to_context()
            context_validation = self._validate_task_context(context)
            if not context_validation["success"]:
                return context_validation

            size_validation = self._validate_screen_size(
                normalized_request.screenshot_width,
                normalized_request.screenshot_height,
            )
            if not size_validation["success"]:
                return size_validation

            if self._requires_security_check(
                action="map_ui",
                task_context=context,
                request=normalized_request,
            ):
                approval = self._request_security_approval(
                    action="map_ui",
                    task_context=context,
                    request=normalized_request,
                )
                if not approval.get("approved", False):
                    return self._safe_result(
                        success=False,
                        message="Security approval denied for UI mapping.",
                        data={
                            "approval": approval,
                            "verification": self._prepare_verification_payload(
                                success=False,
                                request=normalized_request,
                                ui_map=None,
                                reason="Security approval denied.",
                            ),
                        },
                        error="SECURITY_APPROVAL_DENIED",
                        metadata={
                            "agent": self.AGENT_NAME,
                            "version": self.AGENT_VERSION,
                            "user_id": normalized_request.user_id,
                            "workspace_id": normalized_request.workspace_id,
                        },
                    )

            self._emit_agent_event(
                event_type="visual.ui_mapping.started",
                payload={
                    "context": context,
                    "screenshot_width": normalized_request.screenshot_width,
                    "screenshot_height": normalized_request.screenshot_height,
                    "ocr_blocks": len(normalized_request.ocr_blocks),
                    "detected_elements": len(normalized_request.detected_elements),
                },
            )

            elements = self._normalize_inputs(normalized_request)
            elements = self._deduplicate_elements(elements)
            elements = self._classify_elements(elements, normalized_request)
            elements = self._assign_click_targets(elements)
            containers = self._build_containers(elements, normalized_request)
            elements, containers = self._attach_hierarchy(elements, containers)

            hierarchy = self._build_hierarchy(elements, containers)
            clickable_areas = self._extract_clickable_areas(elements)
            cards = self._detect_cards_from_elements(elements, normalized_request)
            tables = self._detect_tables_from_elements(elements, normalized_request)
            menus = self._detect_menus_from_elements(elements, normalized_request)

            summary = self._build_summary(
                elements=elements,
                containers=containers,
                clickable_areas=clickable_areas,
                cards=cards,
                tables=tables,
                menus=menus,
            )

            ui_map = UIMap(
                screenshot_width=normalized_request.screenshot_width,
                screenshot_height=normalized_request.screenshot_height,
                elements=[element.to_dict() for element in elements[: self.max_elements_returned]],
                containers=[container.to_dict() for container in containers],
                hierarchy=hierarchy,
                clickable_areas=clickable_areas,
                cards=cards,
                tables=tables,
                menus=menus,
                summary=summary,
                user_id=normalized_request.user_id,
                workspace_id=normalized_request.workspace_id,
                screenshot_id=normalized_request.screenshot_id,
                page_url=normalized_request.page_url,
                app_name=normalized_request.app_name,
                screen_name=normalized_request.screen_name,
                correlation_id=normalized_request.correlation_id,
            )

            ui_map_dict = ui_map.to_dict()

            verification_payload = self._prepare_verification_payload(
                success=True,
                request=normalized_request,
                ui_map=ui_map_dict,
                reason="UI map created successfully.",
            )

            memory_payload = self._prepare_memory_payload(
                task_context=context,
                request=normalized_request,
                ui_map=ui_map_dict,
            )

            if self.memory_agent is not None:
                self._send_memory_payload(memory_payload)

            self._log_audit_event(
                action="map_ui",
                task_context=context,
                result_summary={
                    "success": True,
                    "elements": len(elements),
                    "containers": len(containers),
                    "clickable_areas": len(clickable_areas),
                    "cards": len(cards),
                    "tables": len(tables),
                    "menus": len(menus),
                },
            )

            self._emit_agent_event(
                event_type="visual.ui_mapping.completed",
                payload={
                    "context": context,
                    "summary": summary,
                },
            )

            return self._safe_result(
                success=True,
                message="UI map created successfully.",
                data={
                    "ui_map": ui_map_dict,
                    "verification": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={
                    "agent": self.AGENT_NAME,
                    "version": self.AGENT_VERSION,
                    "user_id": normalized_request.user_id,
                    "workspace_id": normalized_request.workspace_id,
                    "element_count": len(elements),
                    "container_count": len(containers),
                    "clickable_count": len(clickable_areas),
                    "card_count": len(cards),
                    "table_count": len(tables),
                    "menu_count": len(menus),
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Unhandled error during UI mapping.",
                error=exc,
                metadata={"agent": self.AGENT_NAME, "version": self.AGENT_VERSION},
            )

    def map_from_ocr(
        self,
        ocr_blocks: List[Dict[str, Any]],
        screenshot_width: int,
        screenshot_height: int,
        user_id: str,
        workspace_id: str,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Map UI using OCR blocks only."""

        request = UIMapRequest(
            user_id=user_id,
            workspace_id=workspace_id,
            screenshot_width=screenshot_width,
            screenshot_height=screenshot_height,
            ocr_blocks=ocr_blocks,
            detected_elements=[],
            screenshot_id=kwargs.get("screenshot_id"),
            image_path=kwargs.get("image_path"),
            page_url=kwargs.get("page_url"),
            app_name=kwargs.get("app_name"),
            screen_name=kwargs.get("screen_name"),
            task_id=kwargs.get("task_id"),
            correlation_id=kwargs.get("correlation_id"),
            source_agent=kwargs.get("source_agent") or "visual_agent.ocr_engine",
            requested_by=kwargs.get("requested_by"),
            metadata=dict(kwargs.get("metadata") or {}),
        )
        return self.map_ui(request)

    def map_from_elements(
        self,
        detected_elements: List[Dict[str, Any]],
        screenshot_width: int,
        screenshot_height: int,
        user_id: str,
        workspace_id: str,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Map UI using detected elements only."""

        request = UIMapRequest(
            user_id=user_id,
            workspace_id=workspace_id,
            screenshot_width=screenshot_width,
            screenshot_height=screenshot_height,
            ocr_blocks=[],
            detected_elements=detected_elements,
            screenshot_id=kwargs.get("screenshot_id"),
            image_path=kwargs.get("image_path"),
            page_url=kwargs.get("page_url"),
            app_name=kwargs.get("app_name"),
            screen_name=kwargs.get("screen_name"),
            task_id=kwargs.get("task_id"),
            correlation_id=kwargs.get("correlation_id"),
            source_agent=kwargs.get("source_agent") or "visual_agent.element_detector",
            requested_by=kwargs.get("requested_by"),
            metadata=dict(kwargs.get("metadata") or {}),
        )
        return self.map_ui(request)

    def find_clickable_areas(
        self,
        elements: List[Dict[str, Any]],
        screenshot_width: int,
        screenshot_height: int,
        user_id: str,
        workspace_id: str,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Return clickable areas from raw elements."""

        result = self.map_from_elements(
            detected_elements=elements,
            screenshot_width=screenshot_width,
            screenshot_height=screenshot_height,
            user_id=user_id,
            workspace_id=workspace_id,
            **kwargs,
        )

        if not result.get("success"):
            return result

        ui_map = result.get("data", {}).get("ui_map", {})
        return self._safe_result(
            success=True,
            message="Clickable areas extracted.",
            data={
                "clickable_areas": ui_map.get("clickable_areas", []),
                "summary": {
                    "clickable_count": len(ui_map.get("clickable_areas", [])),
                },
            },
            metadata=result.get("metadata", {}),
        )

    def infer_hierarchy(
        self,
        elements: List[Dict[str, Any]],
        screenshot_width: int,
        screenshot_height: int,
        user_id: str,
        workspace_id: str,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Infer UI hierarchy from raw elements."""

        result = self.map_from_elements(
            detected_elements=elements,
            screenshot_width=screenshot_width,
            screenshot_height=screenshot_height,
            user_id=user_id,
            workspace_id=workspace_id,
            **kwargs,
        )

        if not result.get("success"):
            return result

        ui_map = result.get("data", {}).get("ui_map", {})
        return self._safe_result(
            success=True,
            message="UI hierarchy inferred.",
            data={
                "hierarchy": ui_map.get("hierarchy", {}),
                "containers": ui_map.get("containers", []),
            },
            metadata=result.get("metadata", {}),
        )

    def detect_cards(
        self,
        elements: List[Dict[str, Any]],
        screenshot_width: int,
        screenshot_height: int,
        user_id: str,
        workspace_id: str,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Detect card-like UI groups."""

        result = self.map_from_elements(
            detected_elements=elements,
            screenshot_width=screenshot_width,
            screenshot_height=screenshot_height,
            user_id=user_id,
            workspace_id=workspace_id,
            **kwargs,
        )

        if not result.get("success"):
            return result

        ui_map = result.get("data", {}).get("ui_map", {})
        return self._safe_result(
            success=True,
            message="Cards detected.",
            data={"cards": ui_map.get("cards", [])},
            metadata=result.get("metadata", {}),
        )

    def detect_tables(
        self,
        elements: List[Dict[str, Any]],
        screenshot_width: int,
        screenshot_height: int,
        user_id: str,
        workspace_id: str,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Detect table-like UI groups."""

        result = self.map_from_elements(
            detected_elements=elements,
            screenshot_width=screenshot_width,
            screenshot_height=screenshot_height,
            user_id=user_id,
            workspace_id=workspace_id,
            **kwargs,
        )

        if not result.get("success"):
            return result

        ui_map = result.get("data", {}).get("ui_map", {})
        return self._safe_result(
            success=True,
            message="Tables detected.",
            data={"tables": ui_map.get("tables", [])},
            metadata=result.get("metadata", {}),
        )

    def detect_menus(
        self,
        elements: List[Dict[str, Any]],
        screenshot_width: int,
        screenshot_height: int,
        user_id: str,
        workspace_id: str,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Detect menu/navigation UI groups."""

        result = self.map_from_elements(
            detected_elements=elements,
            screenshot_width=screenshot_width,
            screenshot_height=screenshot_height,
            user_id=user_id,
            workspace_id=workspace_id,
            **kwargs,
        )

        if not result.get("success"):
            return result

        ui_map = result.get("data", {}).get("ui_map", {})
        return self._safe_result(
            success=True,
            message="Menus detected.",
            data={"menus": ui_map.get("menus", [])},
            metadata=result.get("metadata", {}),
        )

    def export_ui_map(self, ui_map: Dict[str, Any], pretty: bool = True) -> str:
        """Export UI map as JSON string for dashboard/API/debug storage."""

        return json.dumps(ui_map, indent=2 if pretty else None, default=str, ensure_ascii=False)

    def _normalize_inputs(self, request: UIMapRequest) -> List[UIElement]:
        """Normalize OCR blocks and detected elements into UIElement objects."""

        elements: List[UIElement] = []

        for index, block in enumerate(request.ocr_blocks):
            try:
                bbox = _bbox_from_any(block, request.screenshot_width, request.screenshot_height)
                if bbox.area <= 0:
                    continue

                text = _normalize_text(
                    block.get("text")
                    or block.get("value")
                    or block.get("label")
                    or block.get("content")
                    or ""
                )

                element_type = self._infer_type_from_text_and_shape(text=text, bbox=bbox, raw=block)

                elements.append(
                    UIElement(
                        element_id=f"ocr_{index + 1}",
                        element_type=element_type,
                        bbox=bbox,
                        text=text,
                        role=block.get("role"),
                        label=block.get("label") or text[:80],
                        confidence=_safe_float(block.get("confidence", block.get("score", 0.65)), 0.65),
                        clickable=self._infer_clickability(element_type, text, bbox, block),
                        source=block.get("source") or "ocr",
                        attributes={
                            "raw_index": index,
                            "ocr_engine": block.get("engine"),
                            "language": block.get("language"),
                        },
                        evidence=["normalized_from_ocr"],
                    )
                )
            except Exception as exc:
                self.logger.debug("Skipping invalid OCR block %s: %s", index, exc)

        offset = len(elements)

        for index, raw in enumerate(request.detected_elements):
            try:
                bbox = _bbox_from_any(raw, request.screenshot_width, request.screenshot_height)
                if bbox.area <= 0:
                    continue

                text = _normalize_text(
                    raw.get("text")
                    or raw.get("value")
                    or raw.get("label")
                    or raw.get("name")
                    or raw.get("aria_label")
                    or ""
                )

                raw_type = raw.get("type") or raw.get("element_type") or raw.get("role")
                element_type = self._normalize_element_type(raw_type)
                if element_type == UIElementType.UNKNOWN:
                    element_type = self._infer_type_from_text_and_shape(text=text, bbox=bbox, raw=raw)

                elements.append(
                    UIElement(
                        element_id=str(raw.get("element_id") or raw.get("id") or f"detected_{index + 1 + offset}"),
                        element_type=element_type,
                        bbox=bbox,
                        text=text,
                        role=raw.get("role"),
                        label=raw.get("label") or raw.get("aria_label") or text[:80],
                        confidence=_safe_float(raw.get("confidence", raw.get("score", 0.7)), 0.7),
                        clickable=self._infer_clickability(element_type, text, bbox, raw),
                        source=raw.get("source") or "element_detector",
                        attributes={
                            key: value
                            for key, value in raw.items()
                            if key
                            not in {
                                "bbox",
                                "bounds",
                                "box",
                                "x",
                                "y",
                                "width",
                                "height",
                                "left",
                                "top",
                                "right",
                                "bottom",
                                "text",
                                "value",
                                "label",
                                "name",
                            }
                        },
                        evidence=["normalized_from_detected_element"],
                    )
                )
            except Exception as exc:
                self.logger.debug("Skipping invalid detected element %s: %s", index, exc)

        elements.sort(key=lambda item: (item.bbox.top, item.bbox.left, item.bbox.height, item.bbox.width))
        return self._renumber_elements(elements)

    def _renumber_elements(self, elements: List[UIElement]) -> List[UIElement]:
        """Assign stable ordered IDs while preserving original IDs in attributes."""

        for index, element in enumerate(elements, start=1):
            original_id = element.element_id
            element.attributes.setdefault("original_element_id", original_id)
            element.element_id = f"ui_{index:04d}"
        return elements

    def _deduplicate_elements(self, elements: List[UIElement]) -> List[UIElement]:
        """Deduplicate overlapping elements while merging useful evidence."""

        if not elements:
            return []

        kept: List[UIElement] = []

        for element in elements:
            duplicate_index: Optional[int] = None

            for idx, existing in enumerate(kept):
                same_text = _lower(element.text) == _lower(existing.text)
                overlap = _iou(element.bbox, existing.bbox)

                if overlap >= 0.78 and (same_text or not element.text or not existing.text):
                    duplicate_index = idx
                    break

            if duplicate_index is None:
                kept.append(element)
                continue

            existing = kept[duplicate_index]

            if element.confidence > existing.confidence:
                element.evidence = list(set(existing.evidence + element.evidence + ["deduplicated_preferred_higher_confidence"]))
                element.attributes["merged_from"] = existing.attributes.get("original_element_id", existing.element_id)
                kept[duplicate_index] = element
            else:
                existing.evidence = list(set(existing.evidence + element.evidence + ["deduplicated_kept_existing"]))
                existing.attributes.setdefault("merged_duplicates", []).append(
                    element.attributes.get("original_element_id", element.element_id)
                )

        return self._renumber_elements(kept)

    def _classify_elements(self, elements: List[UIElement], request: UIMapRequest) -> List[UIElement]:
        """Improve element types using text, geometry, and neighboring context."""

        for element in elements:
            original_type = element.element_type
            inferred = self._infer_type_from_text_and_shape(element.text, element.bbox, element.attributes)

            if element.element_type in {UIElementType.UNKNOWN, UIElementType.TEXT} and inferred != UIElementType.UNKNOWN:
                element.element_type = inferred
                element.evidence.append(f"type_inferred:{inferred.value}")

            if self._looks_like_header(element, request.screenshot_height):
                element.attributes["region_hint"] = "header"
                if element.element_type == UIElementType.TEXT:
                    element.element_type = UIElementType.HEADER

            if self._looks_like_footer(element, request.screenshot_height):
                element.attributes["region_hint"] = "footer"
                if element.element_type == UIElementType.TEXT:
                    element.element_type = UIElementType.FOOTER

            if self._looks_like_sidebar(element, request.screenshot_width):
                element.attributes["region_hint"] = "sidebar"

            if original_type != element.element_type:
                element.evidence.append(f"reclassified_from:{original_type.value}")

            element.clickable = self._infer_clickability(
                element.element_type,
                element.text,
                element.bbox,
                element.attributes,
            )

        return elements

    def _normalize_element_type(self, raw_type: Any) -> UIElementType:
        """Normalize raw detector/DOM/OCR type to UIElementType."""

        value = _lower(raw_type)
        if not value:
            return UIElementType.UNKNOWN

        aliases = {
            "btn": UIElementType.BUTTON,
            "button": UIElementType.BUTTON,
            "a": UIElementType.LINK,
            "anchor": UIElementType.LINK,
            "link": UIElementType.LINK,
            "input": UIElementType.INPUT,
            "textbox": UIElementType.INPUT,
            "text_field": UIElementType.INPUT,
            "textarea": UIElementType.TEXTAREA,
            "checkbox": UIElementType.CHECKBOX,
            "radio": UIElementType.RADIO,
            "select": UIElementType.SELECT,
            "dropdown": UIElementType.DROPDOWN,
            "toggle": UIElementType.TOGGLE,
            "switch": UIElementType.TOGGLE,
            "img": UIElementType.IMAGE,
            "image": UIElementType.IMAGE,
            "icon": UIElementType.ICON,
            "card": UIElementType.CARD,
            "table": UIElementType.TABLE,
            "row": UIElementType.TABLE_ROW,
            "cell": UIElementType.TABLE_CELL,
            "menu": UIElementType.MENU,
            "menuitem": UIElementType.MENU_ITEM,
            "menu_item": UIElementType.MENU_ITEM,
            "nav": UIElementType.NAV,
            "navigation": UIElementType.NAV,
            "tab": UIElementType.TAB,
            "modal": UIElementType.MODAL,
            "dialog": UIElementType.MODAL,
            "form": UIElementType.FORM,
            "header": UIElementType.HEADER,
            "footer": UIElementType.FOOTER,
            "sidebar": UIElementType.SIDEBAR,
            "toolbar": UIElementType.TOOLBAR,
            "list": UIElementType.LIST,
            "listitem": UIElementType.LIST_ITEM,
            "list_item": UIElementType.LIST_ITEM,
            "badge": UIElementType.BADGE,
            "alert": UIElementType.ALERT,
            "toast": UIElementType.TOAST,
            "loader": UIElementType.LOADER,
            "spinner": UIElementType.LOADER,
            "progress": UIElementType.PROGRESS,
            "pagination": UIElementType.PAGINATION,
            "search": UIElementType.SEARCH_BOX,
            "text": UIElementType.TEXT,
            "label": UIElementType.TEXT,
        }

        return aliases.get(value, UIElementType.UNKNOWN)

    def _infer_type_from_text_and_shape(self, text: str, bbox: BoundingBox, raw: Dict[str, Any]) -> UIElementType:
        """Infer UI element type from text, raw attributes, and geometry."""

        lowered = _lower(text)
        raw_role = _lower(raw.get("role") or raw.get("aria_role") or raw.get("class") or raw.get("tag"))
        placeholder = _lower(raw.get("placeholder"))
        raw_clickable = raw.get("clickable")
        raw_enabled = raw.get("enabled")

        if raw_role:
            role_type = self._normalize_element_type(raw_role)
            if role_type != UIElementType.UNKNOWN:
                return role_type

        if raw_clickable is True or _lower(raw_clickable) in {"true", "yes", "1"}:
            if lowered in self.CLICK_WORDS or len(lowered) <= 24:
                return UIElementType.BUTTON

        if placeholder or any(word in lowered for word in self.INPUT_HINT_WORDS):
            if bbox.height >= 18 and bbox.width >= 80:
                return UIElementType.INPUT

        if lowered.startswith("http") or lowered.startswith("www.") or "@" in lowered:
            return UIElementType.LINK

        if lowered in self.CLICK_WORDS:
            return UIElementType.BUTTON

        if any(word == lowered for word in self.MENU_HINT_WORDS):
            return UIElementType.MENU_ITEM

        if lowered in {"☰", "⋮", "…", "≡"} or lowered in {"menu", "more"}:
            return UIElementType.MENU

        if lowered in {"x", "×", "close"} and bbox.width <= 80 and bbox.height <= 80:
            return UIElementType.BUTTON

        if raw_enabled is not None and bbox.width > 20 and bbox.height > 10 and len(lowered) <= 32:
            return UIElementType.BUTTON

        if bbox.width >= 160 and bbox.height >= 90 and len(lowered) > 20:
            return UIElementType.CARD

        return UIElementType.TEXT if text else UIElementType.UNKNOWN

    def _infer_clickability(
        self,
        element_type: UIElementType,
        text: str,
        bbox: BoundingBox,
        raw: Dict[str, Any],
    ) -> Clickability:
        """Infer if an element is clickable."""

        raw_clickable = raw.get("clickable")
        raw_enabled = raw.get("enabled")
        role = _lower(raw.get("role"))
        lowered = _lower(text)

        if raw_clickable is True or _lower(raw_clickable) in {"true", "yes", "1"}:
            return Clickability.CONFIRMED

        if element_type in {
            UIElementType.BUTTON,
            UIElementType.LINK,
            UIElementType.CHECKBOX,
            UIElementType.RADIO,
            UIElementType.SELECT,
            UIElementType.TOGGLE,
            UIElementType.TAB,
            UIElementType.MENU_ITEM,
            UIElementType.DROPDOWN,
            UIElementType.SEARCH_BOX,
            UIElementType.INPUT,
            UIElementType.TEXTAREA,
            UIElementType.PAGINATION,
        }:
            return Clickability.LIKELY

        if role in {"button", "link", "menuitem", "tab", "checkbox", "radio", "switch"}:
            return Clickability.LIKELY

        if raw_enabled is True and bbox.width >= self.min_clickable_width and bbox.height >= self.min_clickable_height:
            return Clickability.POSSIBLE

        if lowered in self.CLICK_WORDS and bbox.width >= self.min_clickable_width and bbox.height >= self.min_clickable_height:
            return Clickability.POSSIBLE

        if lowered in {"☰", "⋮", "…", "≡", "x", "×"}:
            return Clickability.POSSIBLE

        return Clickability.NONE

    def _assign_click_targets(self, elements: List[UIElement]) -> List[UIElement]:
        """Assign click target center points for clickable elements."""

        for element in elements:
            if element.clickable == Clickability.NONE:
                element.click_target = None
                continue

            element.click_target = {
                "x": round(element.bbox.center_x, 3),
                "y": round(element.bbox.center_y, 3),
                "strategy": "bbox_center",
                "confidence": round(element.confidence, 3),
            }
            element.evidence.append("click_target:center")

        return elements

    def _build_containers(self, elements: List[UIElement], request: UIMapRequest) -> List[UIContainer]:
        """Build logical UI containers."""

        containers: List[UIContainer] = [
            UIContainer(
                container_id="root",
                container_type=UIContainerType.ROOT,
                bbox=BoundingBox(0, 0, request.screenshot_width, request.screenshot_height),
                child_ids=[element.element_id for element in elements],
                parent_id=None,
                label="Screen Root",
                confidence=1.0,
                evidence=["root_container"],
            )
        ]

        region_containers = self._detect_region_containers(elements, request)
        containers.extend(region_containers)

        row_containers = self._detect_row_containers(elements)
        containers.extend(row_containers)

        form_containers = self._detect_form_containers(elements)
        containers.extend(form_containers)

        return containers

    def _detect_region_containers(self, elements: List[UIElement], request: UIMapRequest) -> List[UIContainer]:
        """Detect header, sidebar, and footer containers."""

        containers: List[UIContainer] = []

        header_children = [
            e for e in elements if e.bbox.top <= request.screenshot_height * 0.14
        ]
        if len(header_children) >= 2:
            bbox = _union_bbox([e.bbox for e in header_children])
            containers.append(
                UIContainer(
                    container_id="region_header",
                    container_type=UIContainerType.NAV_GROUP,
                    bbox=bbox,
                    child_ids=[e.element_id for e in header_children],
                    parent_id="root",
                    label="Header / Top Navigation",
                    confidence=0.75,
                    attributes={"region": "header"},
                    evidence=["top_screen_cluster"],
                )
            )

        footer_children = [
            e for e in elements if e.bbox.bottom >= request.screenshot_height * 0.88
        ]
        if len(footer_children) >= 2:
            bbox = _union_bbox([e.bbox for e in footer_children])
            containers.append(
                UIContainer(
                    container_id="region_footer",
                    container_type=UIContainerType.SECTION,
                    bbox=bbox,
                    child_ids=[e.element_id for e in footer_children],
                    parent_id="root",
                    label="Footer / Bottom Area",
                    confidence=0.65,
                    attributes={"region": "footer"},
                    evidence=["bottom_screen_cluster"],
                )
            )

        sidebar_children = [
            e
            for e in elements
            if e.bbox.left <= request.screenshot_width * 0.22
            and e.bbox.height < request.screenshot_height * 0.25
        ]
        if len(sidebar_children) >= 4:
            bbox = _union_bbox([e.bbox for e in sidebar_children])
            containers.append(
                UIContainer(
                    container_id="region_sidebar",
                    container_type=UIContainerType.NAV_GROUP,
                    bbox=bbox,
                    child_ids=[e.element_id for e in sidebar_children],
                    parent_id="root",
                    label="Sidebar / Left Navigation",
                    confidence=0.68,
                    attributes={"region": "sidebar"},
                    evidence=["left_screen_vertical_cluster"],
                )
            )

        return containers

    def _detect_row_containers(self, elements: List[UIElement]) -> List[UIContainer]:
        """Group nearby elements into row containers."""

        if not elements:
            return []

        sorted_elements = sorted(elements, key=lambda e: (e.bbox.center_y, e.bbox.left))
        rows: List[List[UIElement]] = []

        for element in sorted_elements:
            placed = False
            for row in rows:
                row_center = sum(item.bbox.center_y for item in row) / len(row)
                row_height = max(item.bbox.height for item in row)
                if abs(element.bbox.center_y - row_center) <= max(self.grouping_vertical_gap, row_height * 0.55):
                    row.append(element)
                    placed = True
                    break

            if not placed:
                rows.append([element])

        containers: List[UIContainer] = []
        row_index = 1

        for row in rows:
            if len(row) < 2:
                continue

            row_sorted = sorted(row, key=lambda e: e.bbox.left)
            bbox = _union_bbox([e.bbox for e in row_sorted])

            if bbox.width < 80 or bbox.height > 180:
                continue

            containers.append(
                UIContainer(
                    container_id=f"row_{row_index:03d}",
                    container_type=UIContainerType.ROW,
                    bbox=bbox,
                    child_ids=[e.element_id for e in row_sorted],
                    parent_id="root",
                    label=f"Row {row_index}",
                    confidence=0.62,
                    evidence=["horizontal_alignment"],
                )
            )
            row_index += 1

        return containers

    def _detect_form_containers(self, elements: List[UIElement]) -> List[UIContainer]:
        """Detect form-like groups from input fields and buttons."""

        input_like = [
            e
            for e in elements
            if e.element_type
            in {
                UIElementType.INPUT,
                UIElementType.TEXTAREA,
                UIElementType.SELECT,
                UIElementType.CHECKBOX,
                UIElementType.RADIO,
                UIElementType.SEARCH_BOX,
            }
        ]

        if not input_like:
            return []

        groups: List[List[UIElement]] = []
        sorted_inputs = sorted(input_like, key=lambda e: (e.bbox.top, e.bbox.left))

        for element in sorted_inputs:
            group_found = False
            for group in groups:
                group_bbox = _union_bbox([item.bbox for item in group])
                vertical_gap = min(abs(element.bbox.top - group_bbox.bottom), abs(group_bbox.top - element.bbox.bottom))
                horizontal_overlap = not (element.bbox.right < group_bbox.left or element.bbox.left > group_bbox.right)

                if vertical_gap <= 90 and horizontal_overlap:
                    group.append(element)
                    group_found = True
                    break

            if not group_found:
                groups.append([element])

        containers: List[UIContainer] = []
        form_index = 1

        for group in groups:
            if len(group) < 1:
                continue

            group_bbox = _union_bbox([e.bbox for e in group])
            nearby_buttons = [
                e
                for e in elements
                if e.element_type == UIElementType.BUTTON
                and e.bbox.top >= group_bbox.top - 20
                and e.bbox.top <= group_bbox.bottom + 120
                and e.bbox.left >= group_bbox.left - 80
                and e.bbox.right <= group_bbox.right + 160
            ]
            all_children = sorted(group + nearby_buttons, key=lambda e: (e.bbox.top, e.bbox.left))
            form_bbox = _union_bbox([e.bbox for e in all_children])

            containers.append(
                UIContainer(
                    container_id=f"form_{form_index:03d}",
                    container_type=UIContainerType.FORM_GROUP,
                    bbox=form_bbox,
                    child_ids=[e.element_id for e in all_children],
                    parent_id="root",
                    label=f"Form Group {form_index}",
                    confidence=0.75 if len(group) >= 2 else 0.58,
                    attributes={
                        "input_count": len(group),
                        "button_count": len(nearby_buttons),
                    },
                    evidence=["input_field_cluster"],
                )
            )
            form_index += 1

        return containers

    def _attach_hierarchy(
        self,
        elements: List[UIElement],
        containers: List[UIContainer],
    ) -> Tuple[List[UIElement], List[UIContainer]]:
        """Attach elements to the most specific containing container."""

        non_root_containers = [c for c in containers if c.container_id != "root"]
        non_root_containers.sort(key=lambda c: c.bbox.area)

        for element in elements:
            best_container: Optional[UIContainer] = None
            for container in non_root_containers:
                if element.element_id in container.child_ids or _contains(container.bbox, element.bbox, tolerance=8):
                    best_container = container
                    break

            element.parent_id = best_container.container_id if best_container else "root"

        container_by_id = {container.container_id: container for container in containers}

        for container in containers:
            if container.container_id == "root":
                continue

            parent_id = "root"
            for possible_parent in sorted(containers, key=lambda c: c.bbox.area):
                if possible_parent.container_id == container.container_id:
                    continue
                if possible_parent.bbox.area <= container.bbox.area:
                    continue
                if _contains(possible_parent.bbox, container.bbox, tolerance=12):
                    parent_id = possible_parent.container_id
                    break

            container.parent_id = parent_id
            if parent_id in container_by_id:
                if container.container_id not in container_by_id[parent_id].child_ids:
                    container_by_id[parent_id].child_ids.append(container.container_id)

        return elements, containers

    def _build_hierarchy(self, elements: List[UIElement], containers: List[UIContainer]) -> Dict[str, Any]:
        """Build tree-like hierarchy representation."""

        element_lookup = {element.element_id: element for element in elements}
        container_lookup = {container.container_id: container for container in containers}

        def build_node(container: UIContainer) -> Dict[str, Any]:
            child_nodes: List[Dict[str, Any]] = []

            container_child_ids = list(container.child_ids)

            child_containers = [
                container_lookup[child_id]
                for child_id in container_child_ids
                if child_id in container_lookup and child_id != container.container_id
            ]

            child_elements = [
                element_lookup[child_id]
                for child_id in container_child_ids
                if child_id in element_lookup and element_lookup[child_id].parent_id == container.container_id
            ]

            for child_container in sorted(child_containers, key=lambda c: (c.bbox.top, c.bbox.left)):
                child_nodes.append(build_node(child_container))

            for child_element in sorted(child_elements, key=lambda e: (e.bbox.top, e.bbox.left)):
                child_nodes.append(
                    {
                        "kind": "element",
                        "id": child_element.element_id,
                        "type": child_element.element_type.value,
                        "label": child_element.label or child_element.text[:80],
                        "clickable": child_element.clickable.value,
                        "bbox": child_element.bbox.to_dict(),
                    }
                )

            return {
                "kind": "container",
                "id": container.container_id,
                "type": container.container_type.value,
                "label": container.label,
                "bbox": container.bbox.to_dict(),
                "children": child_nodes,
            }

        root = container_lookup.get("root")
        if not root:
            return {
                "kind": "container",
                "id": "root",
                "type": UIContainerType.ROOT.value,
                "children": [],
            }

        return build_node(root)

    def _extract_clickable_areas(self, elements: List[UIElement]) -> List[Dict[str, Any]]:
        """Extract clickable areas sorted by screen order."""

        clickable_elements = [
            e
            for e in elements
            if e.clickable in {Clickability.CONFIRMED, Clickability.LIKELY, Clickability.POSSIBLE}
        ]

        clickable_elements.sort(
            key=lambda e: (
                0 if e.clickable == Clickability.CONFIRMED else 1 if e.clickable == Clickability.LIKELY else 2,
                e.bbox.top,
                e.bbox.left,
            )
        )

        areas: List[Dict[str, Any]] = []

        for element in clickable_elements:
            areas.append(
                {
                    "element_id": element.element_id,
                    "element_type": element.element_type.value,
                    "label": element.label or element.text[:80],
                    "text": element.text,
                    "bbox": element.bbox.to_dict(),
                    "click_target": element.click_target,
                    "clickability": element.clickable.value,
                    "confidence": round(element.confidence, 3),
                    "reason": self._clickable_reason(element),
                    "parent_id": element.parent_id,
                }
            )

        return areas

    def _clickable_reason(self, element: UIElement) -> str:
        """Human-readable clickability reason."""

        if element.clickable == Clickability.CONFIRMED:
            return "Element is marked clickable by source data."
        if element.element_type in {UIElementType.BUTTON, UIElementType.LINK, UIElementType.INPUT, UIElementType.MENU_ITEM}:
            return f"Element type '{element.element_type.value}' is typically interactive."
        if _lower(element.text) in self.CLICK_WORDS:
            return "Element text matches common action wording."
        return "Element may be interactive based on shape/text."

    def _detect_cards_from_elements(self, elements: List[UIElement], request: UIMapRequest) -> List[Dict[str, Any]]:
        """Detect card-like UI groups."""

        candidates = [
            e
            for e in elements
            if e.element_type == UIElementType.CARD
            or (
                e.bbox.width >= request.screenshot_width * 0.18
                and e.bbox.height >= 70
                and e.bbox.height <= request.screenshot_height * 0.45
            )
        ]

        cards: List[Dict[str, Any]] = []
        used_ids: set[str] = set()

        for index, candidate in enumerate(candidates, start=1):
            if candidate.element_id in used_ids:
                continue

            nearby = [
                e
                for e in elements
                if e.element_id != candidate.element_id
                and e.element_id not in used_ids
                and _distance(e.bbox, candidate.bbox) <= max(candidate.bbox.width, candidate.bbox.height) * 0.9
                and e.bbox.top >= candidate.bbox.top - 20
                and e.bbox.bottom <= candidate.bbox.bottom + 80
            ]

            children = [candidate] + nearby
            if len(children) < 2 and candidate.element_type != UIElementType.CARD:
                continue

            bbox = _union_bbox([e.bbox for e in children])
            title = self._best_title_for_group(children)

            cards.append(
                {
                    "card_id": f"card_{len(cards) + 1:03d}",
                    "bbox": bbox.to_dict(),
                    "title": title,
                    "element_ids": [e.element_id for e in sorted(children, key=lambda item: (item.bbox.top, item.bbox.left))],
                    "clickable_element_ids": [
                        e.element_id for e in children if e.clickable != Clickability.NONE
                    ],
                    "confidence": 0.72 if len(children) >= 3 else 0.58,
                    "evidence": ["large_group_or_card_element", "nearby_elements_cluster"],
                }
            )

            for child in children:
                used_ids.add(child.element_id)

        return cards

    def _detect_tables_from_elements(self, elements: List[UIElement], request: UIMapRequest) -> List[Dict[str, Any]]:
        """Detect table-like UI groups by aligned rows and columns."""

        text_elements = [
            e
            for e in elements
            if e.text and e.bbox.width > 8 and e.bbox.height > 6
        ]

        if len(text_elements) < 6:
            return []

        rows = self._cluster_by_y(text_elements)
        if len(rows) < 2:
            return []

        row_lengths = [len(row) for row in rows]
        likely_rows = [row for row in rows if len(row) >= 2]

        if len(likely_rows) < 2:
            return []

        column_centers: List[float] = []
        for row in likely_rows:
            for element in row:
                matched = False
                for idx, center in enumerate(column_centers):
                    if abs(element.bbox.center_x - center) <= 35:
                        column_centers[idx] = (center + element.bbox.center_x) / 2
                        matched = True
                        break
                if not matched:
                    column_centers.append(element.bbox.center_x)

        column_centers.sort()

        if len(column_centers) < 2:
            return []

        table_elements = [item for row in likely_rows for item in row]
        table_bbox = _union_bbox([e.bbox for e in table_elements])

        if table_bbox.width < request.screenshot_width * 0.25:
            return []

        header_row = sorted(likely_rows[0], key=lambda e: e.bbox.left)

        table = {
            "table_id": "table_001",
            "bbox": table_bbox.to_dict(),
            "row_count": len(likely_rows),
            "column_count": len(column_centers),
            "header_cells": [
                {
                    "element_id": e.element_id,
                    "text": e.text,
                    "bbox": e.bbox.to_dict(),
                }
                for e in header_row
            ],
            "rows": [
                [
                    {
                        "element_id": e.element_id,
                        "text": e.text,
                        "bbox": e.bbox.to_dict(),
                    }
                    for e in sorted(row, key=lambda item: item.bbox.left)
                ]
                for row in likely_rows
            ],
            "confidence": min(0.9, 0.55 + len(likely_rows) * 0.04 + len(column_centers) * 0.03),
            "evidence": ["repeated_row_alignment", "multiple_column_centers"],
        }

        return [table]

    def _detect_menus_from_elements(self, elements: List[UIElement], request: UIMapRequest) -> List[Dict[str, Any]]:
        """Detect menu/navigation groups."""

        menu_like = [
            e
            for e in elements
            if e.element_type in {UIElementType.MENU, UIElementType.MENU_ITEM, UIElementType.NAV, UIElementType.TAB}
            or _lower(e.text) in self.MENU_HINT_WORDS
            or e.clickable in {Clickability.CONFIRMED, Clickability.LIKELY}
            and e.bbox.height <= 70
        ]

        if not menu_like:
            return []

        menus: List[Dict[str, Any]] = []

        top_menu_items = [
            e for e in menu_like if e.bbox.top <= request.screenshot_height * 0.18
        ]
        if len(top_menu_items) >= 2:
            bbox = _union_bbox([e.bbox for e in top_menu_items])
            menus.append(
                {
                    "menu_id": "menu_top_001",
                    "menu_type": "top_navigation",
                    "bbox": bbox.to_dict(),
                    "element_ids": [e.element_id for e in sorted(top_menu_items, key=lambda item: item.bbox.left)],
                    "labels": [e.label or e.text for e in sorted(top_menu_items, key=lambda item: item.bbox.left)],
                    "confidence": 0.78,
                    "evidence": ["top_aligned_interactive_items"],
                }
            )

        left_menu_items = [
            e
            for e in menu_like
            if e.bbox.left <= request.screenshot_width * 0.24
            and e.bbox.top > request.screenshot_height * 0.08
        ]
        left_rows = self._cluster_by_y(left_menu_items)
        if len(left_rows) >= 3:
            flat = [item for row in left_rows for item in row]
            bbox = _union_bbox([e.bbox for e in flat])
            menus.append(
                {
                    "menu_id": "menu_left_001",
                    "menu_type": "sidebar_navigation",
                    "bbox": bbox.to_dict(),
                    "element_ids": [e.element_id for e in sorted(flat, key=lambda item: (item.bbox.top, item.bbox.left))],
                    "labels": [e.label or e.text for e in sorted(flat, key=lambda item: (item.bbox.top, item.bbox.left))],
                    "confidence": 0.72,
                    "evidence": ["left_vertical_interactive_items"],
                }
            )

        dropdown_like = [
            e
            for e in elements
            if e.element_type in {UIElementType.DROPDOWN, UIElementType.SELECT}
            or "▼" in e.text
            or "▾" in e.text
        ]
        for idx, item in enumerate(dropdown_like, start=1):
            menus.append(
                {
                    "menu_id": f"menu_dropdown_{idx:03d}",
                    "menu_type": "dropdown",
                    "bbox": item.bbox.to_dict(),
                    "element_ids": [item.element_id],
                    "labels": [item.label or item.text],
                    "confidence": 0.7,
                    "evidence": ["dropdown_or_select_element"],
                }
            )

        return menus

    def _cluster_by_y(self, elements: List[UIElement]) -> List[List[UIElement]]:
        """Cluster elements into rows by center y."""

        if not elements:
            return []

        rows: List[List[UIElement]] = []
        for element in sorted(elements, key=lambda e: (e.bbox.center_y, e.bbox.left)):
            placed = False
            for row in rows:
                center = sum(item.bbox.center_y for item in row) / len(row)
                if abs(element.bbox.center_y - center) <= max(12, element.bbox.height * 0.7):
                    row.append(element)
                    placed = True
                    break
            if not placed:
                rows.append([element])

        return [sorted(row, key=lambda e: e.bbox.left) for row in rows]

    def _best_title_for_group(self, elements: List[UIElement]) -> Optional[str]:
        """Pick best visible title for a group/card."""

        text_items = [e for e in elements if e.text]
        if not text_items:
            return None

        text_items.sort(key=lambda e: (e.bbox.top, -e.bbox.height, e.bbox.left))
        return text_items[0].text[:120]

    def _looks_like_header(self, element: UIElement, screen_height: int) -> bool:
        return element.bbox.top <= max(80, screen_height * 0.12)

    def _looks_like_footer(self, element: UIElement, screen_height: int) -> bool:
        return element.bbox.bottom >= screen_height * 0.9

    def _looks_like_sidebar(self, element: UIElement, screen_width: int) -> bool:
        return element.bbox.left <= screen_width * 0.2 and element.bbox.width <= screen_width * 0.35

    def _build_summary(
        self,
        elements: List[UIElement],
        containers: List[UIContainer],
        clickable_areas: List[Dict[str, Any]],
        cards: List[Dict[str, Any]],
        tables: List[Dict[str, Any]],
        menus: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Build compact UI map summary."""

        type_counts: Dict[str, int] = {}
        for element in elements:
            type_counts[element.element_type.value] = type_counts.get(element.element_type.value, 0) + 1

        clickable_by_confidence: Dict[str, int] = {}
        for element in elements:
            clickable_by_confidence[element.clickable.value] = clickable_by_confidence.get(element.clickable.value, 0) + 1

        return {
            "element_count": len(elements),
            "container_count": len(containers),
            "clickable_area_count": len(clickable_areas),
            "card_count": len(cards),
            "table_count": len(tables),
            "menu_count": len(menus),
            "element_type_counts": type_counts,
            "clickability_counts": clickable_by_confidence,
            "has_forms": any(c.container_type == UIContainerType.FORM_GROUP for c in containers),
            "has_navigation": bool(menus) or any(c.container_type == UIContainerType.NAV_GROUP for c in containers),
            "has_tables": bool(tables),
            "has_cards": bool(cards),
        }

    def _build_request_from_task(self, task: Dict[str, Any]) -> UIMapRequest:
        """Build UIMapRequest from dict-based MasterAgent/API task."""

        if not isinstance(task, dict):
            raise ValueError("Task must be a dictionary.")

        user_id = str(task.get("user_id") or "").strip()
        workspace_id = str(task.get("workspace_id") or "").strip()

        screenshot_width = _safe_int(
            task.get("screenshot_width")
            or task.get("width")
            or task.get("image_width")
            or task.get("screen_width"),
            0,
        )
        screenshot_height = _safe_int(
            task.get("screenshot_height")
            or task.get("height")
            or task.get("image_height")
            or task.get("screen_height"),
            0,
        )

        ocr_blocks = task.get("ocr_blocks") or task.get("ocr_results") or task.get("text_blocks") or []
        detected_elements = task.get("detected_elements") or task.get("elements") or task.get("ui_elements") or []

        if not isinstance(ocr_blocks, list):
            raise ValueError("ocr_blocks must be a list.")
        if not isinstance(detected_elements, list):
            raise ValueError("detected_elements must be a list.")

        return UIMapRequest(
            user_id=user_id,
            workspace_id=workspace_id,
            screenshot_width=screenshot_width,
            screenshot_height=screenshot_height,
            ocr_blocks=ocr_blocks,
            detected_elements=detected_elements,
            screenshot_id=task.get("screenshot_id"),
            image_path=task.get("image_path"),
            page_url=task.get("page_url") or task.get("url"),
            app_name=task.get("app_name"),
            screen_name=task.get("screen_name") or task.get("page_name"),
            task_id=task.get("task_id"),
            correlation_id=task.get("correlation_id"),
            source_agent=task.get("source_agent"),
            requested_by=task.get("requested_by"),
            metadata=dict(task.get("metadata") or {}),
        )

    def _validate_task_context(self, task_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate SaaS isolation context.

        Every user-specific visual task must include user_id and workspace_id so
        visual maps, memory, audit logs, and dashboard data cannot mix tenants.
        """

        user_id = str(task_context.get("user_id") or "").strip()
        workspace_id = str(task_context.get("workspace_id") or "").strip()

        if not user_id:
            return self._safe_result(
                success=False,
                message="Missing required user_id for SaaS isolation.",
                data={},
                error="MISSING_USER_ID",
                metadata={"agent": self.AGENT_NAME, "hook": "_validate_task_context"},
            )

        if not workspace_id:
            return self._safe_result(
                success=False,
                message="Missing required workspace_id for SaaS isolation.",
                data={},
                error="MISSING_WORKSPACE_ID",
                metadata={"agent": self.AGENT_NAME, "hook": "_validate_task_context"},
            )

        return self._safe_result(
            success=True,
            message="Task context validated.",
            data={"user_id": user_id, "workspace_id": workspace_id},
            metadata={"agent": self.AGENT_NAME, "hook": "_validate_task_context"},
        )

    def _validate_screen_size(self, width: int, height: int) -> Dict[str, Any]:
        """Validate screenshot/screen dimensions."""

        if width <= 0 or height <= 0:
            return self._safe_result(
                success=False,
                message="Invalid screenshot dimensions.",
                data={"screenshot_width": width, "screenshot_height": height},
                error="INVALID_SCREEN_SIZE",
                metadata={"agent": self.AGENT_NAME, "hook": "_validate_screen_size"},
            )

        if width > 20000 or height > 20000:
            return self._safe_result(
                success=False,
                message="Screenshot dimensions are too large for safe UI mapping.",
                data={"screenshot_width": width, "screenshot_height": height},
                error="SCREEN_SIZE_TOO_LARGE",
                metadata={"agent": self.AGENT_NAME, "hook": "_validate_screen_size"},
            )

        return self._safe_result(
            success=True,
            message="Screenshot dimensions validated.",
            data={"screenshot_width": width, "screenshot_height": height},
            metadata={"agent": self.AGENT_NAME, "hook": "_validate_screen_size"},
        )

    def _requires_security_check(
        self,
        action: str,
        task_context: Dict[str, Any],
        request: Optional[UIMapRequest] = None,
    ) -> bool:
        """
        Decide whether Security Agent approval is needed.

        UI mapping is read-only, but approval is required when:
            - metadata marks task as sensitive
            - screenshot/page is protected
            - user requests sensitive-screen mapping
        """

        metadata = dict(task_context.get("metadata") or {})
        request_metadata = dict(request.metadata if request else {})

        sensitive_flags = [
            metadata.get("sensitive"),
            metadata.get("requires_security_check"),
            metadata.get("protected_screen"),
            request_metadata.get("sensitive"),
            request_metadata.get("requires_security_check"),
            request_metadata.get("protected_screen"),
            request_metadata.get("contains_credentials"),
            request_metadata.get("contains_payment_info"),
            request_metadata.get("contains_private_data"),
        ]

        return any(self._is_truthy(flag) for flag in sensitive_flags)

    def _request_security_approval(
        self,
        action: str,
        task_context: Dict[str, Any],
        request: Optional[UIMapRequest] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval if available.

        Fallback behavior:
            If no Security Agent is attached and the task is read-only,
            approve by fallback policy. Sensitive data is not exposed outside
            the current structured result.
        """

        approval_request = {
            "action": action,
            "agent": self.AGENT_NAME,
            "read_only": True,
            "task_context": task_context,
            "screenshot_id": request.screenshot_id if request else None,
            "page_url": request.page_url if request else None,
            "app_name": request.app_name if request else None,
            "screen_name": request.screen_name if request else None,
            "requested_at": _utc_now_iso(),
        }

        if self.security_agent is None:
            return {
                "approved": True,
                "reason": "No Security Agent attached; read-only UI mapping approved by fallback policy.",
                "fallback": True,
                "request": approval_request,
            }

        try:
            if hasattr(self.security_agent, "approve"):
                response = self.security_agent.approve(approval_request)
            elif hasattr(self.security_agent, "request_approval"):
                response = self.security_agent.request_approval(approval_request)
            elif hasattr(self.security_agent, "validate_action"):
                response = self.security_agent.validate_action(approval_request)
            else:
                return {
                    "approved": False,
                    "reason": "Attached Security Agent has no supported approval method.",
                    "fallback": False,
                    "request": approval_request,
                }

            if isinstance(response, dict):
                return {
                    "approved": bool(response.get("approved") or response.get("success")),
                    "reason": response.get("reason") or response.get("message") or "Security Agent returned response.",
                    "fallback": False,
                    "raw_response": response,
                    "request": approval_request,
                }

            return {
                "approved": bool(response),
                "reason": "Security Agent returned boolean-like response.",
                "fallback": False,
                "raw_response": response,
                "request": approval_request,
            }

        except Exception as exc:
            return {
                "approved": False,
                "reason": f"Security approval request failed: {exc}",
                "fallback": False,
                "request": approval_request,
            }

    def _prepare_verification_payload(
        self,
        success: bool,
        request: UIMapRequest,
        ui_map: Optional[Dict[str, Any]],
        reason: str,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent-compatible payload.

        Verification Agent can use this to validate whether target UI elements,
        forms, tables, cards, menus, or clickable regions are visible.
        """

        summary = ui_map.get("summary", {}) if isinstance(ui_map, dict) else {}

        return {
            "verification_type": "visual_ui_map",
            "agent": self.AGENT_NAME,
            "agent_version": self.AGENT_VERSION,
            "success": bool(success),
            "reason": reason,
            "user_id": request.user_id,
            "workspace_id": request.workspace_id,
            "task_id": request.task_id,
            "correlation_id": request.correlation_id,
            "source_agent": request.source_agent,
            "screenshot_id": request.screenshot_id,
            "page_url": request.page_url,
            "app_name": request.app_name,
            "screen_name": request.screen_name,
            "summary": summary,
            "checked_at": _utc_now_iso(),
        }

    def _prepare_memory_payload(
        self,
        task_context: Dict[str, Any],
        request: UIMapRequest,
        ui_map: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent-compatible payload.

        Stores useful UI structure patterns without crossing user/workspace
        boundaries.
        """

        summary = ui_map.get("summary", {})
        return {
            "memory_type": "visual_ui_map",
            "agent": self.AGENT_NAME,
            "user_id": task_context.get("user_id"),
            "workspace_id": task_context.get("workspace_id"),
            "task_id": task_context.get("task_id"),
            "correlation_id": task_context.get("correlation_id"),
            "summary": {
                "screenshot_id": request.screenshot_id,
                "page_url": request.page_url,
                "app_name": request.app_name,
                "screen_name": request.screen_name,
                "element_count": summary.get("element_count", 0),
                "clickable_area_count": summary.get("clickable_area_count", 0),
                "card_count": summary.get("card_count", 0),
                "table_count": summary.get("table_count", 0),
                "menu_count": summary.get("menu_count", 0),
                "has_forms": summary.get("has_forms", False),
                "has_navigation": summary.get("has_navigation", False),
            },
            "raw": {
                "summary": summary,
                "screenshot_width": request.screenshot_width,
                "screenshot_height": request.screenshot_height,
            },
            "created_at": _utc_now_iso(),
        }

    def _send_memory_payload(self, payload: Dict[str, Any]) -> None:
        """Send payload to Memory Agent if compatible method exists."""

        try:
            if self.memory_agent is None:
                return

            if hasattr(self.memory_agent, "remember"):
                self.memory_agent.remember(payload)
            elif hasattr(self.memory_agent, "store"):
                self.memory_agent.store(payload)
            elif hasattr(self.memory_agent, "save_memory"):
                self.memory_agent.save_memory(payload)
            else:
                self.logger.debug("Memory Agent attached but no supported memory method found.")

        except Exception as exc:
            self.logger.warning("Failed to send UI map memory payload: %s", exc)

    def _emit_agent_event(self, event_type: str, payload: Dict[str, Any]) -> None:
        """
        Emit event for dashboard/API/agent bus integration.

        Event emission is optional and failure-safe.
        """

        event = {
            "event_type": event_type,
            "agent": self.AGENT_NAME,
            "version": self.AGENT_VERSION,
            "payload": payload,
            "timestamp": _utc_now_iso(),
        }

        try:
            if self.event_emitter:
                self.event_emitter(event)
            else:
                self.logger.debug("Agent event: %s", json.dumps(event, default=str))
        except Exception as exc:
            self.logger.warning("Failed to emit agent event '%s': %s", event_type, exc)

    def _log_audit_event(
        self,
        action: str,
        task_context: Dict[str, Any],
        result_summary: Dict[str, Any],
    ) -> None:
        """
        Log audit event with SaaS context.

        Keeps visual audit data tied to user_id/workspace_id and avoids
        cross-tenant mixing.
        """

        audit_event = {
            "action": action,
            "agent": self.AGENT_NAME,
            "version": self.AGENT_VERSION,
            "user_id": task_context.get("user_id"),
            "workspace_id": task_context.get("workspace_id"),
            "task_id": task_context.get("task_id"),
            "correlation_id": task_context.get("correlation_id"),
            "source_agent": task_context.get("source_agent"),
            "result_summary": result_summary,
            "timestamp": _utc_now_iso(),
        }

        try:
            if self.audit_logger:
                self.audit_logger(audit_event)
            else:
                self.logger.info("Audit event: %s", json.dumps(audit_event, default=str))
        except Exception as exc:
            self.logger.warning("Failed to log audit event '%s': %s", action, exc)

    def _safe_result(
        self,
        success: bool,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Union[str, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return William/Jarvis standard structured result."""

        return {
            "success": bool(success),
            "message": str(message),
            "data": data or {},
            "error": error,
            "metadata": {
                "agent": self.AGENT_NAME,
                "version": self.AGENT_VERSION,
                "timestamp": _utc_now_iso(),
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error: Union[BaseException, str, Dict[str, Any]],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return structured error result with safe traceback support."""

        if isinstance(error, BaseException):
            error_payload: Dict[str, Any] = {
                "type": error.__class__.__name__,
                "message": str(error),
            }

            if metadata and metadata.get("include_traceback"):
                error_payload["traceback"] = traceback.format_exc()

        elif isinstance(error, dict):
            error_payload = error

        else:
            error_payload = {
                "type": "Error",
                "message": str(error),
            }

        self.logger.error("%s Error=%s", message, error_payload)

        return self._safe_result(
            success=False,
            message=message,
            data={},
            error=error_payload,
            metadata=metadata or {},
        )

    def _is_truthy(self, value: Any) -> bool:
        """Safe truthy parser."""

        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "y", "ok", "success"}
        return bool(value)


__all__ = [
    "UIMapper",
    "UIElement",
    "UIContainer",
    "UIMap",
    "UIMapRequest",
    "BoundingBox",
    "UIElementType",
    "UIContainerType",
    "Clickability",
]


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    mapper = UIMapper()

    demo_result = mapper.map_ui(
        {
            "user_id": "demo_user",
            "workspace_id": "demo_workspace",
            "screenshot_width": 1365,
            "screenshot_height": 768,
            "app_name": "Demo App",
            "screen_name": "Login",
            "ocr_blocks": [
                {
                    "text": "Email",
                    "bbox": {"x": 420, "y": 250, "width": 320, "height": 38},
                    "confidence": 0.91,
                },
                {
                    "text": "Password",
                    "bbox": {"x": 420, "y": 305, "width": 320, "height": 38},
                    "confidence": 0.9,
                },
                {
                    "text": "Login",
                    "bbox": {"x": 420, "y": 365, "width": 160, "height": 44},
                    "confidence": 0.96,
                },
                {
                    "text": "Forgot password?",
                    "bbox": {"x": 590, "y": 370, "width": 150, "height": 30},
                    "confidence": 0.88,
                },
            ],
            "detected_elements": [
                {
                    "type": "button",
                    "label": "Login",
                    "bbox": {"x": 420, "y": 365, "width": 160, "height": 44},
                    "clickable": True,
                    "confidence": 0.95,
                }
            ],
            "metadata": {"demo": True},
        }
    )

    print(json.dumps(demo_result, indent=2, default=str))