"""
agents/verification_agent/device_state_checker.py

Device State Checker for William / Jarvis Multi-Agent AI SaaS System.

Purpose:
    Confirms device-level states:
    - WiFi
    - Bluetooth
    - Volume
    - Brightness
    - Battery
    - Screen lock / lock-related state

Architecture Role:
    This module belongs to the Verification Agent. It is designed to be called
    after the System Agent, Voice Agent, Browser Agent, Workflow Agent, or Master
    Agent performs a device-related task and needs proof that the expected state
    is actually true.

Safety:
    - Read-only by default.
    - Does not change WiFi, Bluetooth, volume, brightness, battery, or lock state.
    - Uses guarded subprocess calls with timeouts.
    - Every user/workspace scoped call validates SaaS isolation context.
    - Sensitive checks can be routed through Security Agent compatibility hooks.

Import Safety:
    - This file can be imported even if BaseAgent or other William modules are
      not created yet.
    - Optional third-party libraries are used only if available.
    - Platform-specific commands fail gracefully and return "unknown" instead
      of crashing.

Public Class:
    DeviceStateChecker
"""

from __future__ import annotations

import ctypes
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Optional imports with safe fallbacks
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for standalone import safety
    class BaseAgent:  # type: ignore
        """
        Minimal BaseAgent fallback.

        The real William BaseAgent may provide richer routing, telemetry,
        permissions, memory, registry, or audit behavior. This fallback keeps
        this file import-safe until the full system is available.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)


try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None  # type: ignore


try:
    import screen_brightness_control as sbc  # type: ignore
except Exception:  # pragma: no cover
    sbc = None  # type: ignore


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
if not logger.handlers:
    logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

UNKNOWN = "unknown"
ENABLED = "enabled"
DISABLED = "disabled"
CONNECTED = "connected"
DISCONNECTED = "disconnected"
LOCKED = "locked"
UNLOCKED = "unlocked"
NOT_SUPPORTED = "not_supported"

SUPPORTED_CHECKS = {
    "wifi",
    "bluetooth",
    "volume",
    "brightness",
    "battery",
    "screen_lock",
}

DEFAULT_COMMAND_TIMEOUT_SECONDS = 4.0


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DeviceStateExpectation:
    """
    Expected state for one device feature.

    Examples:
        DeviceStateExpectation(name="wifi", expected_enabled=True)
        DeviceStateExpectation(name="volume", expected_level_min=20)
        DeviceStateExpectation(name="battery", expected_level_min=25)
    """

    name: str
    expected_enabled: Optional[bool] = None
    expected_connected: Optional[bool] = None
    expected_locked: Optional[bool] = None
    expected_level: Optional[int] = None
    expected_level_min: Optional[int] = None
    expected_level_max: Optional[int] = None
    expected_charging: Optional[bool] = None
    expected_status: Optional[str] = None
    tolerance: int = 0


@dataclass
class DeviceCheckEvidence:
    """
    Raw and normalized evidence for a device state check.
    """

    source: str
    command: Optional[str] = None
    raw: Optional[str] = None
    parsed: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    notes: List[str] = field(default_factory=list)


@dataclass
class DeviceStateConfig:
    """
    Runtime configuration for DeviceStateChecker.
    """

    command_timeout_seconds: float = DEFAULT_COMMAND_TIMEOUT_SECONDS
    allow_subprocess_checks: bool = True
    allow_optional_library_checks: bool = True
    require_context: bool = True
    security_required_for_screen_lock: bool = False
    security_required_for_device_state: bool = False
    collect_raw_evidence: bool = True
    max_raw_evidence_chars: int = 4000


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class DeviceStateChecker(BaseAgent):
    """
    Verification helper that confirms WiFi, Bluetooth, volume, brightness,
    battery, and screen lock states.

    This class is intended to be called by:
        - Verification Agent after a task has completed.
        - Master Agent when routing verification tasks.
        - Dashboard/API endpoints that need structured state proof.
        - Security Agent workflows when sensitive checks require approval.
        - Memory Agent through prepared memory payloads.

    The checker is read-only. It does not toggle settings or perform actions.
    """

    agent_type = "verification_agent_helper"
    file_path = "agents/verification_agent/device_state_checker.py"
    supported_checks = SUPPORTED_CHECKS

    def __init__(
        self,
        config: Optional[Union[DeviceStateConfig, Mapping[str, Any]]] = None,
        security_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        logger_instance: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name="DeviceStateChecker", **kwargs)

        if isinstance(config, DeviceStateConfig):
            self.config = config
        elif isinstance(config, Mapping):
            self.config = DeviceStateConfig(**dict(config))
        else:
            self.config = DeviceStateConfig()

        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.event_bus = event_bus
        self.audit_logger = audit_logger
        self.logger = logger_instance or logger

        self.platform_name = platform.system().lower()
        self.platform_release = platform.release()
        self.hostname = platform.node()

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def check_device_state(
        self,
        *,
        user_id: Optional[str],
        workspace_id: Optional[str],
        checks: Optional[Sequence[str]] = None,
        expected: Optional[Union[Mapping[str, Any], Sequence[Mapping[str, Any]]]] = None,
        task_id: Optional[str] = None,
        request_id: Optional[str] = None,
        require_security: Optional[bool] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Run one or more device state checks and optionally validate expectations.

        Args:
            user_id: SaaS user identifier.
            workspace_id: SaaS workspace identifier.
            checks: List of checks to run. Defaults to all supported checks.
            expected: Optional expectation mapping or list of mappings.
            task_id: Optional task identifier from Master Agent / task history.
            request_id: Optional API/dashboard request identifier.
            require_security: Override security requirement.
            metadata: Extra structured metadata.

        Returns:
            Structured dict with success, message, data, error, metadata.
        """

        started_at = self._utc_now_iso()
        context = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "task_id": task_id,
            "request_id": request_id,
            "metadata": dict(metadata or {}),
        }

        valid_context = self._validate_task_context(context)
        if not valid_context["success"]:
            return valid_context

        normalized_checks = self._normalize_checks(checks)
        if not normalized_checks:
            return self._error_result(
                message="No valid device checks requested.",
                error_code="NO_VALID_CHECKS",
                data={
                    "requested_checks": list(checks or []),
                    "supported_checks": sorted(self.supported_checks),
                },
                metadata=context,
            )

        if require_security is None:
            require_security = self._requires_security_check(
                action="check_device_state",
                checks=normalized_checks,
                context=context,
            )

        if require_security:
            approval = self._request_security_approval(
                action="check_device_state",
                checks=normalized_checks,
                context=context,
            )
            if not approval.get("approved", False):
                return self._error_result(
                    message="Device state check blocked by security policy.",
                    error_code="SECURITY_APPROVAL_DENIED",
                    data={"approval": approval},
                    metadata=context,
                )

        expectations = self._normalize_expectations(expected)
        results: Dict[str, Any] = {}

        for check_name in normalized_checks:
            try:
                if check_name == "wifi":
                    results[check_name] = self.check_wifi_state(
                        user_id=user_id,
                        workspace_id=workspace_id,
                        task_id=task_id,
                        request_id=request_id,
                    )["data"]
                elif check_name == "bluetooth":
                    results[check_name] = self.check_bluetooth_state(
                        user_id=user_id,
                        workspace_id=workspace_id,
                        task_id=task_id,
                        request_id=request_id,
                    )["data"]
                elif check_name == "volume":
                    results[check_name] = self.check_volume_state(
                        user_id=user_id,
                        workspace_id=workspace_id,
                        task_id=task_id,
                        request_id=request_id,
                    )["data"]
                elif check_name == "brightness":
                    results[check_name] = self.check_brightness_state(
                        user_id=user_id,
                        workspace_id=workspace_id,
                        task_id=task_id,
                        request_id=request_id,
                    )["data"]
                elif check_name == "battery":
                    results[check_name] = self.check_battery_state(
                        user_id=user_id,
                        workspace_id=workspace_id,
                        task_id=task_id,
                        request_id=request_id,
                    )["data"]
                elif check_name == "screen_lock":
                    results[check_name] = self.check_screen_lock_state(
                        user_id=user_id,
                        workspace_id=workspace_id,
                        task_id=task_id,
                        request_id=request_id,
                    )["data"]
            except Exception as exc:
                self.logger.exception("Device check failed: %s", check_name)
                results[check_name] = {
                    "name": check_name,
                    "status": UNKNOWN,
                    "success": False,
                    "message": f"Failed to check {check_name}.",
                    "error": {
                        "code": "CHECK_EXCEPTION",
                        "message": str(exc),
                    },
                    "confidence": 0.0,
                    "evidence": [],
                }

        validation = self.validate_expected_states(results, expectations)
        verification_payload = self._prepare_verification_payload(
            action="check_device_state",
            context=context,
            checks=normalized_checks,
            results=results,
            validation=validation,
            started_at=started_at,
        )
        memory_payload = self._prepare_memory_payload(
            action="check_device_state",
            context=context,
            results=results,
            validation=validation,
        )

        self._emit_agent_event(
            event_name="verification.device_state.checked",
            payload=verification_payload,
        )
        self._log_audit_event(
            action="check_device_state",
            context=context,
            outcome={
                "checks": normalized_checks,
                "success": validation["overall_success"],
                "confidence": validation["overall_confidence"],
            },
        )

        return self._safe_result(
            success=validation["overall_success"],
            message=validation["message"],
            data={
                "checks": results,
                "validation": validation,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                **context,
                "agent": self.agent_name,
                "platform": self._platform_metadata(),
                "started_at": started_at,
                "finished_at": self._utc_now_iso(),
            },
        )

    def check_wifi_state(
        self,
        *,
        user_id: Optional[str],
        workspace_id: Optional[str],
        task_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Confirm WiFi state.

        Returns normalized fields:
            enabled: bool | None
            connected: bool | None
            ssid: str | None
            adapter: str | None
            status: enabled/disabled/connected/disconnected/unknown
        """

        context_result = self._validate_task_context(
            {"user_id": user_id, "workspace_id": workspace_id, "task_id": task_id, "request_id": request_id}
        )
        if not context_result["success"]:
            return context_result

        evidence: List[Dict[str, Any]] = []
        parsed: Dict[str, Any] = {
            "enabled": None,
            "connected": None,
            "ssid": None,
            "adapter": None,
            "status": UNKNOWN,
        }

        if self.platform_name == "windows":
            parsed, evidence = self._check_wifi_windows()
        elif self.platform_name == "darwin":
            parsed, evidence = self._check_wifi_macos()
        elif self.platform_name == "linux":
            parsed, evidence = self._check_wifi_linux()
        else:
            evidence.append(asdict(DeviceCheckEvidence(
                source="platform",
                parsed={"platform": self.platform_name},
                confidence=0.1,
                notes=["Unsupported platform for WiFi check."],
            )))

        success = parsed.get("status") != UNKNOWN
        return self._safe_result(
            success=success,
            message="WiFi state checked." if success else "WiFi state could not be confirmed.",
            data={
                "name": "wifi",
                **parsed,
                "confidence": self._evidence_confidence(evidence),
                "evidence": evidence,
                "checked_at": self._utc_now_iso(),
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "task_id": task_id,
                "request_id": request_id,
                "platform": self._platform_metadata(),
            },
        )

    def check_bluetooth_state(
        self,
        *,
        user_id: Optional[str],
        workspace_id: Optional[str],
        task_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Confirm Bluetooth state.

        Returns normalized fields:
            enabled: bool | None
            connected_devices: list
            status: enabled/disabled/unknown
        """

        context_result = self._validate_task_context(
            {"user_id": user_id, "workspace_id": workspace_id, "task_id": task_id, "request_id": request_id}
        )
        if not context_result["success"]:
            return context_result

        evidence: List[Dict[str, Any]] = []
        parsed: Dict[str, Any] = {
            "enabled": None,
            "connected_devices": [],
            "status": UNKNOWN,
        }

        if self.platform_name == "windows":
            parsed, evidence = self._check_bluetooth_windows()
        elif self.platform_name == "darwin":
            parsed, evidence = self._check_bluetooth_macos()
        elif self.platform_name == "linux":
            parsed, evidence = self._check_bluetooth_linux()
        else:
            evidence.append(asdict(DeviceCheckEvidence(
                source="platform",
                parsed={"platform": self.platform_name},
                confidence=0.1,
                notes=["Unsupported platform for Bluetooth check."],
            )))

        success = parsed.get("status") != UNKNOWN
        return self._safe_result(
            success=success,
            message="Bluetooth state checked." if success else "Bluetooth state could not be confirmed.",
            data={
                "name": "bluetooth",
                **parsed,
                "confidence": self._evidence_confidence(evidence),
                "evidence": evidence,
                "checked_at": self._utc_now_iso(),
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "task_id": task_id,
                "request_id": request_id,
                "platform": self._platform_metadata(),
            },
        )

    def check_volume_state(
        self,
        *,
        user_id: Optional[str],
        workspace_id: Optional[str],
        task_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Confirm system volume state.

        Returns normalized fields:
            level: int | None
            muted: bool | None
            status: enabled/disabled/unknown
        """

        context_result = self._validate_task_context(
            {"user_id": user_id, "workspace_id": workspace_id, "task_id": task_id, "request_id": request_id}
        )
        if not context_result["success"]:
            return context_result

        evidence: List[Dict[str, Any]] = []
        parsed: Dict[str, Any] = {
            "level": None,
            "muted": None,
            "status": UNKNOWN,
        }

        if self.platform_name == "windows":
            parsed, evidence = self._check_volume_windows()
        elif self.platform_name == "darwin":
            parsed, evidence = self._check_volume_macos()
        elif self.platform_name == "linux":
            parsed, evidence = self._check_volume_linux()
        else:
            evidence.append(asdict(DeviceCheckEvidence(
                source="platform",
                parsed={"platform": self.platform_name},
                confidence=0.1,
                notes=["Unsupported platform for volume check."],
            )))

        success = parsed.get("status") != UNKNOWN
        return self._safe_result(
            success=success,
            message="Volume state checked." if success else "Volume state could not be confirmed.",
            data={
                "name": "volume",
                **parsed,
                "confidence": self._evidence_confidence(evidence),
                "evidence": evidence,
                "checked_at": self._utc_now_iso(),
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "task_id": task_id,
                "request_id": request_id,
                "platform": self._platform_metadata(),
            },
        )

    def check_brightness_state(
        self,
        *,
        user_id: Optional[str],
        workspace_id: Optional[str],
        task_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Confirm screen brightness state.

        Returns normalized fields:
            level: int | None
            displays: list
            status: enabled/unknown
        """

        context_result = self._validate_task_context(
            {"user_id": user_id, "workspace_id": workspace_id, "task_id": task_id, "request_id": request_id}
        )
        if not context_result["success"]:
            return context_result

        evidence: List[Dict[str, Any]] = []
        parsed: Dict[str, Any] = {
            "level": None,
            "displays": [],
            "status": UNKNOWN,
        }

        if self.config.allow_optional_library_checks and sbc is not None:
            parsed, evidence = self._check_brightness_with_library()

        if parsed.get("status") == UNKNOWN:
            if self.platform_name == "windows":
                parsed, extra = self._check_brightness_windows()
            elif self.platform_name == "darwin":
                parsed, extra = self._check_brightness_macos()
            elif self.platform_name == "linux":
                parsed, extra = self._check_brightness_linux()
            else:
                extra = [asdict(DeviceCheckEvidence(
                    source="platform",
                    parsed={"platform": self.platform_name},
                    confidence=0.1,
                    notes=["Unsupported platform for brightness check."],
                ))]
            evidence.extend(extra)

        success = parsed.get("status") != UNKNOWN
        return self._safe_result(
            success=success,
            message="Brightness state checked." if success else "Brightness state could not be confirmed.",
            data={
                "name": "brightness",
                **parsed,
                "confidence": self._evidence_confidence(evidence),
                "evidence": evidence,
                "checked_at": self._utc_now_iso(),
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "task_id": task_id,
                "request_id": request_id,
                "platform": self._platform_metadata(),
            },
        )

    def check_battery_state(
        self,
        *,
        user_id: Optional[str],
        workspace_id: Optional[str],
        task_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Confirm battery state.

        Returns normalized fields:
            level: int | None
            charging: bool | None
            plugged: bool | None
            seconds_left: int | None
            status: charging/discharging/full/no_battery/unknown
        """

        context_result = self._validate_task_context(
            {"user_id": user_id, "workspace_id": workspace_id, "task_id": task_id, "request_id": request_id}
        )
        if not context_result["success"]:
            return context_result

        evidence: List[Dict[str, Any]] = []
        parsed: Dict[str, Any] = {
            "level": None,
            "charging": None,
            "plugged": None,
            "seconds_left": None,
            "status": UNKNOWN,
        }

        if self.config.allow_optional_library_checks and psutil is not None:
            battery = None
            try:
                battery = psutil.sensors_battery()
            except Exception as exc:
                evidence.append(asdict(DeviceCheckEvidence(
                    source="psutil.sensors_battery",
                    parsed={},
                    confidence=0.1,
                    notes=[f"psutil battery check failed: {exc}"],
                )))

            if battery is not None:
                level = int(round(float(battery.percent)))
                plugged = bool(battery.power_plugged)
                seconds_left = None
                if isinstance(getattr(battery, "secsleft", None), int) and battery.secsleft >= 0:
                    seconds_left = int(battery.secsleft)

                if level >= 99 and plugged:
                    status = "full"
                elif plugged:
                    status = "charging"
                else:
                    status = "discharging"

                parsed = {
                    "level": level,
                    "charging": plugged,
                    "plugged": plugged,
                    "seconds_left": seconds_left,
                    "status": status,
                }
                evidence.append(asdict(DeviceCheckEvidence(
                    source="psutil.sensors_battery",
                    parsed=parsed,
                    confidence=0.92,
                    notes=[],
                )))
            else:
                parsed = {
                    "level": None,
                    "charging": None,
                    "plugged": None,
                    "seconds_left": None,
                    "status": "no_battery",
                }
                evidence.append(asdict(DeviceCheckEvidence(
                    source="psutil.sensors_battery",
                    parsed=parsed,
                    confidence=0.85,
                    notes=["No battery detected. This is normal on many desktop/server systems."],
                )))

        if parsed.get("status") == UNKNOWN:
            if self.platform_name == "windows":
                parsed, extra = self._check_battery_windows()
            elif self.platform_name == "darwin":
                parsed, extra = self._check_battery_macos()
            elif self.platform_name == "linux":
                parsed, extra = self._check_battery_linux()
            else:
                extra = [asdict(DeviceCheckEvidence(
                    source="platform",
                    parsed={"platform": self.platform_name},
                    confidence=0.1,
                    notes=["Unsupported platform for battery check."],
                ))]
            evidence.extend(extra)

        success = parsed.get("status") != UNKNOWN
        return self._safe_result(
            success=success,
            message="Battery state checked." if success else "Battery state could not be confirmed.",
            data={
                "name": "battery",
                **parsed,
                "confidence": self._evidence_confidence(evidence),
                "evidence": evidence,
                "checked_at": self._utc_now_iso(),
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "task_id": task_id,
                "request_id": request_id,
                "platform": self._platform_metadata(),
            },
        )

    def check_screen_lock_state(
        self,
        *,
        user_id: Optional[str],
        workspace_id: Optional[str],
        task_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Confirm screen lock related state.

        Important:
            Most operating systems do not expose a fully reliable lock-state API
            to a normal user process. This method uses safe best-effort signals.

        Returns normalized fields:
            locked: bool | None
            screen_saver_active: bool | None
            status: locked/unlocked/unknown/not_supported
        """

        context = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "task_id": task_id,
            "request_id": request_id,
        }
        context_result = self._validate_task_context(context)
        if not context_result["success"]:
            return context_result

        if self._requires_security_check(
            action="check_screen_lock_state",
            checks=["screen_lock"],
            context=context,
        ):
            approval = self._request_security_approval(
                action="check_screen_lock_state",
                checks=["screen_lock"],
                context=context,
            )
            if not approval.get("approved", False):
                return self._error_result(
                    message="Screen lock state check blocked by security policy.",
                    error_code="SECURITY_APPROVAL_DENIED",
                    data={"approval": approval},
                    metadata=context,
                )

        evidence: List[Dict[str, Any]] = []
        parsed: Dict[str, Any] = {
            "locked": None,
            "screen_saver_active": None,
            "status": UNKNOWN,
        }

        if self.platform_name == "windows":
            parsed, evidence = self._check_screen_lock_windows()
        elif self.platform_name == "darwin":
            parsed, evidence = self._check_screen_lock_macos()
        elif self.platform_name == "linux":
            parsed, evidence = self._check_screen_lock_linux()
        else:
            parsed = {
                "locked": None,
                "screen_saver_active": None,
                "status": NOT_SUPPORTED,
            }
            evidence.append(asdict(DeviceCheckEvidence(
                source="platform",
                parsed={"platform": self.platform_name},
                confidence=0.15,
                notes=["Unsupported platform for screen lock check."],
            )))

        success = parsed.get("status") not in {UNKNOWN, NOT_SUPPORTED}
        return self._safe_result(
            success=success,
            message="Screen lock state checked." if success else "Screen lock state could not be fully confirmed.",
            data={
                "name": "screen_lock",
                **parsed,
                "confidence": self._evidence_confidence(evidence),
                "evidence": evidence,
                "checked_at": self._utc_now_iso(),
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "task_id": task_id,
                "request_id": request_id,
                "platform": self._platform_metadata(),
            },
        )

    def validate_expected_states(
        self,
        actual_results: Mapping[str, Any],
        expectations: Mapping[str, DeviceStateExpectation],
    ) -> Dict[str, Any]:
        """
        Compare actual device check results with expectations.

        Args:
            actual_results: Output map from device checks.
            expectations: Normalized expectations by check name.

        Returns:
            Structured validation result.
        """

        if not expectations:
            confidence_values = [
                float(v.get("confidence", 0.0))
                for v in actual_results.values()
                if isinstance(v, Mapping)
            ]
            avg_confidence = round(sum(confidence_values) / len(confidence_values), 4) if confidence_values else 0.0
            return {
                "overall_success": all(bool(v.get("success", True)) for v in actual_results.values() if isinstance(v, Mapping)),
                "message": "Device state checks completed. No expectations were provided.",
                "overall_confidence": avg_confidence,
                "expectations_provided": False,
                "items": {},
            }

        items: Dict[str, Any] = {}
        passed_count = 0
        total_count = 0
        confidence_values: List[float] = []

        for name, expectation in expectations.items():
            total_count += 1
            actual = actual_results.get(name)
            if not isinstance(actual, Mapping):
                items[name] = {
                    "passed": False,
                    "message": f"No actual result found for expected check: {name}",
                    "expected": asdict(expectation),
                    "actual": None,
                    "confidence": 0.0,
                }
                continue

            check_passed, check_message = self._validate_one_expectation(actual, expectation)
            confidence = float(actual.get("confidence", 0.0))
            confidence_values.append(confidence)

            if check_passed:
                passed_count += 1

            items[name] = {
                "passed": check_passed,
                "message": check_message,
                "expected": asdict(expectation),
                "actual": dict(actual),
                "confidence": confidence,
            }

        overall_success = total_count > 0 and passed_count == total_count
        overall_confidence = round(sum(confidence_values) / len(confidence_values), 4) if confidence_values else 0.0

        return {
            "overall_success": overall_success,
            "message": (
                "All expected device states matched."
                if overall_success
                else f"{passed_count}/{total_count} expected device states matched."
            ),
            "overall_confidence": overall_confidence,
            "expectations_provided": True,
            "passed_count": passed_count,
            "total_count": total_count,
            "items": items,
        }

    # -----------------------------------------------------------------------
    # Windows checks
    # -----------------------------------------------------------------------

    def _check_wifi_windows(self) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        evidence: List[Dict[str, Any]] = []

        result = self._run_command(["netsh", "wlan", "show", "interfaces"])
        raw = result.get("stdout", "")
        parsed = {
            "enabled": None,
            "connected": None,
            "ssid": None,
            "adapter": None,
            "status": UNKNOWN,
        }

        if result["success"] and raw.strip():
            state_match = re.search(r"^\s*State\s*:\s*(.+)$", raw, re.IGNORECASE | re.MULTILINE)
            ssid_match = re.search(r"^\s*SSID\s*:\s*(.+)$", raw, re.IGNORECASE | re.MULTILINE)
            adapter_match = re.search(r"^\s*Name\s*:\s*(.+)$", raw, re.IGNORECASE | re.MULTILINE)

            state = state_match.group(1).strip().lower() if state_match else ""
            connected = "connected" in state and "disconnected" not in state
            parsed = {
                "enabled": True,
                "connected": connected,
                "ssid": ssid_match.group(1).strip() if ssid_match and connected else None,
                "adapter": adapter_match.group(1).strip() if adapter_match else None,
                "status": CONNECTED if connected else DISCONNECTED,
            }
            confidence = 0.9
        else:
            radio = self._run_powershell(
                "Get-NetAdapter -Name '*Wi-Fi*','*Wireless*' -ErrorAction SilentlyContinue | "
                "Select-Object -First 1 Name,Status | ConvertTo-Json -Compress"
            )
            raw_radio = radio.get("stdout", "")
            if radio["success"] and raw_radio.strip():
                try:
                    data = json.loads(raw_radio)
                    if isinstance(data, list):
                        data = data[0] if data else {}
                    adapter_status = str(data.get("Status", "")).lower()
                    adapter_name = data.get("Name")
                    enabled = adapter_status not in {"disabled", "not present", ""}
                    parsed = {
                        "enabled": enabled,
                        "connected": adapter_status == "up",
                        "ssid": None,
                        "adapter": adapter_name,
                        "status": ENABLED if enabled else DISABLED,
                    }
                    confidence = 0.72
                except Exception:
                    confidence = 0.25
            else:
                confidence = 0.1

        evidence.append(asdict(DeviceCheckEvidence(
            source="windows.netsh_wlan",
            command="netsh wlan show interfaces",
            raw=self._trim_raw(raw),
            parsed=parsed,
            confidence=confidence,
            notes=[] if parsed["status"] != UNKNOWN else ["WiFi state could not be parsed from Windows commands."],
        )))
        return parsed, evidence

    def _check_bluetooth_windows(self) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        command = (
            "Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | "
            "Select-Object FriendlyName,Status | ConvertTo-Json -Compress"
        )
        result = self._run_powershell(command)
        raw = result.get("stdout", "")
        parsed = {
            "enabled": None,
            "connected_devices": [],
            "status": UNKNOWN,
        }
        confidence = 0.1

        if result["success"] and raw.strip():
            try:
                data = json.loads(raw)
                devices = data if isinstance(data, list) else [data]
                statuses = [str(item.get("Status", "")).lower() for item in devices if isinstance(item, Mapping)]
                names = [
                    item.get("FriendlyName")
                    for item in devices
                    if isinstance(item, Mapping) and item.get("FriendlyName")
                ]

                enabled = any(status in {"ok", "unknown"} for status in statuses) if statuses else None
                connected_devices = [
                    {"name": name, "status": status}
                    for name, status in zip(names, statuses)
                    if name and status == "ok"
                ]

                parsed = {
                    "enabled": enabled,
                    "connected_devices": connected_devices,
                    "status": ENABLED if enabled else DISABLED if enabled is False else UNKNOWN,
                }
                confidence = 0.75
            except Exception as exc:
                parsed["status"] = UNKNOWN
                confidence = 0.2
                raw = f"{raw}\nParse error: {exc}"

        return parsed, [asdict(DeviceCheckEvidence(
            source="windows.pnp_bluetooth",
            command=command,
            raw=self._trim_raw(raw),
            parsed=parsed,
            confidence=confidence,
            notes=[] if parsed["status"] != UNKNOWN else ["Bluetooth state could not be parsed from Windows PnP data."],
        ))]

    def _check_volume_windows(self) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        command = (
            "Add-Type -TypeDefinition @'\n"
            "using System.Runtime.InteropServices;\n"
            "public class Audio {\n"
            "[DllImport(\"winmm.dll\")] public static extern int waveOutGetVolume(System.IntPtr hwo, out uint dwVolume);\n"
            "}\n"
            "'@; "
            "$v=0; [Audio]::waveOutGetVolume([IntPtr]::Zero, [ref]$v) | Out-Null; "
            "$left=$v -band 0xffff; "
            "$level=[Math]::Round(($left/65535)*100); "
            "[pscustomobject]@{Level=$level; Muted=$false} | ConvertTo-Json -Compress"
        )
        result = self._run_powershell(command)
        raw = result.get("stdout", "")
        parsed = {
            "level": None,
            "muted": None,
            "status": UNKNOWN,
        }
        confidence = 0.1

        if result["success"] and raw.strip():
            try:
                data = json.loads(raw)
                level = self._safe_int(data.get("Level"))
                muted = bool(data.get("Muted", False))
                parsed = {
                    "level": level,
                    "muted": muted,
                    "status": DISABLED if muted or level == 0 else ENABLED,
                }
                confidence = 0.7
            except Exception as exc:
                raw = f"{raw}\nParse error: {exc}"
                confidence = 0.2

        return parsed, [asdict(DeviceCheckEvidence(
            source="windows.winmm_waveout",
            command="PowerShell winmm waveOutGetVolume",
            raw=self._trim_raw(raw),
            parsed=parsed,
            confidence=confidence,
            notes=["Mute detection is conservative on Windows fallback."] if parsed["status"] != UNKNOWN else [],
        ))]

    def _check_brightness_windows(self) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        command = (
            "Get-CimInstance -Namespace root/WMI -ClassName WmiMonitorBrightness "
            "-ErrorAction SilentlyContinue | Select-Object CurrentBrightness,InstanceName | ConvertTo-Json -Compress"
        )
        result = self._run_powershell(command)
        raw = result.get("stdout", "")
        parsed = {
            "level": None,
            "displays": [],
            "status": UNKNOWN,
        }
        confidence = 0.1

        if result["success"] and raw.strip():
            try:
                data = json.loads(raw)
                items = data if isinstance(data, list) else [data]
                displays = []
                levels = []
                for item in items:
                    if not isinstance(item, Mapping):
                        continue
                    level = self._safe_int(item.get("CurrentBrightness"))
                    if level is not None:
                        levels.append(level)
                    displays.append({
                        "name": item.get("InstanceName"),
                        "level": level,
                    })
                avg = int(round(sum(levels) / len(levels))) if levels else None
                parsed = {
                    "level": avg,
                    "displays": displays,
                    "status": ENABLED if avg is not None else UNKNOWN,
                }
                confidence = 0.82 if avg is not None else 0.25
            except Exception as exc:
                raw = f"{raw}\nParse error: {exc}"
                confidence = 0.2

        return parsed, [asdict(DeviceCheckEvidence(
            source="windows.wmi_brightness",
            command=command,
            raw=self._trim_raw(raw),
            parsed=parsed,
            confidence=confidence,
            notes=[] if parsed["status"] != UNKNOWN else ["Brightness may not be exposed on desktop monitors."],
        ))]

    def _check_battery_windows(self) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        command = (
            "Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue | "
            "Select-Object EstimatedChargeRemaining,BatteryStatus | ConvertTo-Json -Compress"
        )
        result = self._run_powershell(command)
        raw = result.get("stdout", "")
        parsed = {
            "level": None,
            "charging": None,
            "plugged": None,
            "seconds_left": None,
            "status": UNKNOWN,
        }
        confidence = 0.1

        if result["success"] and raw.strip():
            try:
                data = json.loads(raw)
                if isinstance(data, list):
                    data = data[0] if data else {}
                level = self._safe_int(data.get("EstimatedChargeRemaining"))
                battery_status = self._safe_int(data.get("BatteryStatus"))
                charging = battery_status in {6, 7, 8, 9, 11}
                discharging = battery_status == 1
                status = "charging" if charging else "discharging" if discharging else UNKNOWN

                parsed = {
                    "level": level,
                    "charging": charging if status != UNKNOWN else None,
                    "plugged": charging if status != UNKNOWN else None,
                    "seconds_left": None,
                    "status": status,
                }
                confidence = 0.78 if level is not None else 0.35
            except Exception as exc:
                raw = f"{raw}\nParse error: {exc}"
                confidence = 0.2
        elif result["success"]:
            parsed["status"] = "no_battery"
            confidence = 0.75

        return parsed, [asdict(DeviceCheckEvidence(
            source="windows.win32_battery",
            command=command,
            raw=self._trim_raw(raw),
            parsed=parsed,
            confidence=confidence,
            notes=[],
        ))]

    def _check_screen_lock_windows(self) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """
        Best-effort Windows lock check.

        A normal process cannot always confirm lock state. We use desktop access:
        if OpenInputDesktop fails, the active desktop may be secure/locked.
        """

        parsed = {
            "locked": None,
            "screen_saver_active": None,
            "status": UNKNOWN,
        }
        notes: List[str] = []
        confidence = 0.25

        try:
            user32 = ctypes.windll.User32  # type: ignore[attr-defined]
            DESKTOP_SWITCHDESKTOP = 0x0100
            desktop = user32.OpenInputDesktop(0, False, DESKTOP_SWITCHDESKTOP)
            if desktop:
                can_switch = bool(user32.SwitchDesktop(desktop))
                user32.CloseDesktop(desktop)
                parsed = {
                    "locked": not can_switch,
                    "screen_saver_active": None,
                    "status": LOCKED if not can_switch else UNLOCKED,
                }
                confidence = 0.65
                notes.append("Windows lock state inferred from desktop switch accessibility.")
            else:
                parsed = {
                    "locked": True,
                    "screen_saver_active": None,
                    "status": LOCKED,
                }
                confidence = 0.55
                notes.append("OpenInputDesktop failed; lock state inferred as locked/secure desktop.")
        except Exception as exc:
            notes.append(f"Windows lock heuristic failed: {exc}")

        return parsed, [asdict(DeviceCheckEvidence(
            source="windows.user32_input_desktop",
            command=None,
            raw=None,
            parsed=parsed,
            confidence=confidence,
            notes=notes,
        ))]

    # -----------------------------------------------------------------------
    # macOS checks
    # -----------------------------------------------------------------------

    def _check_wifi_macos(self) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        airport = (
            "/System/Library/PrivateFrameworks/Apple80211.framework/"
            "Versions/Current/Resources/airport"
        )
        evidence: List[Dict[str, Any]] = []
        parsed = {
            "enabled": None,
            "connected": None,
            "ssid": None,
            "adapter": None,
            "status": UNKNOWN,
        }

        if os.path.exists(airport):
            result = self._run_command([airport, "-I"])
            raw = result.get("stdout", "")
            if result["success"] and raw.strip():
                ssid_match = re.search(r"^\s*SSID:\s*(.+)$", raw, re.MULTILINE)
                state_match = re.search(r"^\s*state:\s*(.+)$", raw, re.MULTILINE)
                ssid = ssid_match.group(1).strip() if ssid_match else None
                connected = bool(ssid)
                parsed = {
                    "enabled": True,
                    "connected": connected,
                    "ssid": ssid,
                    "adapter": "airport",
                    "status": CONNECTED if connected else DISCONNECTED,
                }
                if state_match and "running" not in state_match.group(1).lower():
                    parsed["connected"] = False
                    parsed["status"] = DISCONNECTED

                evidence.append(asdict(DeviceCheckEvidence(
                    source="macos.airport",
                    command=f"{airport} -I",
                    raw=self._trim_raw(raw),
                    parsed=parsed,
                    confidence=0.86,
                    notes=[],
                )))
                return parsed, evidence

        result = self._run_command(["networksetup", "-getairportpower", "en0"])
        raw = result.get("stdout", "")
        if result["success"] and raw.strip():
            enabled = "on" in raw.lower()
            parsed = {
                "enabled": enabled,
                "connected": None,
                "ssid": None,
                "adapter": "en0",
                "status": ENABLED if enabled else DISABLED,
            }
            confidence = 0.65
        else:
            confidence = 0.1

        evidence.append(asdict(DeviceCheckEvidence(
            source="macos.networksetup",
            command="networksetup -getairportpower en0",
            raw=self._trim_raw(raw),
            parsed=parsed,
            confidence=confidence,
            notes=[] if parsed["status"] != UNKNOWN else ["Unable to confirm macOS WiFi state."],
        )))
        return parsed, evidence

    def _check_bluetooth_macos(self) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        if shutil.which("blueutil"):
            result = self._run_command(["blueutil", "--power"])
            raw = result.get("stdout", "")
            enabled = raw.strip() == "1" if result["success"] else None
            parsed = {
                "enabled": enabled,
                "connected_devices": [],
                "status": ENABLED if enabled else DISABLED if enabled is False else UNKNOWN,
            }
            confidence = 0.85 if enabled is not None else 0.2
            return parsed, [asdict(DeviceCheckEvidence(
                source="macos.blueutil",
                command="blueutil --power",
                raw=self._trim_raw(raw),
                parsed=parsed,
                confidence=confidence,
                notes=[],
            ))]

        result = self._run_command(["system_profiler", "SPBluetoothDataType"])
        raw = result.get("stdout", "")
        enabled = None
        connected_devices: List[Dict[str, Any]] = []
        if result["success"] and raw.strip():
            if re.search(r"Bluetooth Power:\s*On", raw, re.IGNORECASE):
                enabled = True
            elif re.search(r"Bluetooth Power:\s*Off", raw, re.IGNORECASE):
                enabled = False

            connected_names = re.findall(r"^\s{8}([^:\n]+):\s*$", raw, re.MULTILINE)
            connected_devices = [{"name": name.strip(), "status": "reported"} for name in connected_names[:20]]

        parsed = {
            "enabled": enabled,
            "connected_devices": connected_devices,
            "status": ENABLED if enabled else DISABLED if enabled is False else UNKNOWN,
        }
        return parsed, [asdict(DeviceCheckEvidence(
            source="macos.system_profiler_bluetooth",
            command="system_profiler SPBluetoothDataType",
            raw=self._trim_raw(raw),
            parsed=parsed,
            confidence=0.65 if enabled is not None else 0.2,
            notes=["Install blueutil for more reliable macOS Bluetooth state."] if not shutil.which("blueutil") else [],
        ))]

    def _check_volume_macos(self) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        result = self._run_command(["osascript", "-e", "output volume of (get volume settings)"])
        raw_level = result.get("stdout", "")
        mute_result = self._run_command(["osascript", "-e", "output muted of (get volume settings)"])
        raw_mute = mute_result.get("stdout", "")

        level = self._safe_int(raw_level.strip()) if result["success"] else None
        muted = raw_mute.strip().lower() == "true" if mute_result["success"] else None
        status = DISABLED if muted or level == 0 else ENABLED if level is not None else UNKNOWN

        parsed = {
            "level": level,
            "muted": muted,
            "status": status,
        }

        return parsed, [asdict(DeviceCheckEvidence(
            source="macos.osascript_volume",
            command="osascript output volume/muted",
            raw=self._trim_raw(f"level={raw_level}; muted={raw_mute}"),
            parsed=parsed,
            confidence=0.86 if level is not None else 0.2,
            notes=[],
        ))]

    def _check_brightness_macos(self) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        if shutil.which("brightness"):
            result = self._run_command(["brightness", "-l"])
            raw = result.get("stdout", "")
            levels = [float(x) for x in re.findall(r"brightness\s+([0-9.]+)", raw, re.IGNORECASE)]
            percent_levels = [int(round(x * 100)) if x <= 1 else int(round(x)) for x in levels]
            avg = int(round(sum(percent_levels) / len(percent_levels))) if percent_levels else None
            displays = [{"level": level} for level in percent_levels]
            parsed = {
                "level": avg,
                "displays": displays,
                "status": ENABLED if avg is not None else UNKNOWN,
            }
            confidence = 0.78 if avg is not None else 0.2
        else:
            result = {"stdout": "", "success": False}
            raw = ""
            parsed = {
                "level": None,
                "displays": [],
                "status": UNKNOWN,
            }
            confidence = 0.15

        return parsed, [asdict(DeviceCheckEvidence(
            source="macos.brightness_cli",
            command="brightness -l",
            raw=self._trim_raw(raw),
            parsed=parsed,
            confidence=confidence,
            notes=["Install the macOS brightness CLI or screen_brightness_control for better support."] if parsed["status"] == UNKNOWN else [],
        ))]

    def _check_battery_macos(self) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        result = self._run_command(["pmset", "-g", "batt"])
        raw = result.get("stdout", "")
        parsed = {
            "level": None,
            "charging": None,
            "plugged": None,
            "seconds_left": None,
            "status": UNKNOWN,
        }

        if result["success"] and raw.strip():
            level_match = re.search(r"(\d+)%", raw)
            level = self._safe_int(level_match.group(1)) if level_match else None
            lower = raw.lower()
            charging = "charging" in lower or "charged" in lower
            discharging = "discharging" in lower
            status = "charging" if charging else "discharging" if discharging else "full" if "charged" in lower else UNKNOWN
            parsed = {
                "level": level,
                "charging": charging if status != UNKNOWN else None,
                "plugged": charging if status != UNKNOWN else None,
                "seconds_left": None,
                "status": status,
            }
            confidence = 0.86
        else:
            confidence = 0.15

        return parsed, [asdict(DeviceCheckEvidence(
            source="macos.pmset_batt",
            command="pmset -g batt",
            raw=self._trim_raw(raw),
            parsed=parsed,
            confidence=confidence,
            notes=[],
        ))]

    def _check_screen_lock_macos(self) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        result = self._run_command(["python3", "-c", "import Quartz; print(Quartz.CGSessionCopyCurrentDictionary())"])
        raw = result.get("stdout", "")
        parsed = {
            "locked": None,
            "screen_saver_active": None,
            "status": UNKNOWN,
        }
        confidence = 0.15
        notes: List[str] = []

        if result["success"] and raw.strip():
            lower = raw.lower()
            if "cgsessionscreensaverisrunning" in lower:
                active = "cgsessionscreensaverisrunning': 1" in lower or "cgsessionscreensaverisrunning': true" in lower
                parsed["screen_saver_active"] = active
            if "cgsessiononsconsolekey" in lower:
                parsed["locked"] = False
                parsed["status"] = UNLOCKED
                confidence = 0.55
            notes.append("macOS lock state inferred from Quartz session dictionary.")
        else:
            notes.append("Quartz not available through python3; lock state unavailable.")

        return parsed, [asdict(DeviceCheckEvidence(
            source="macos.quartz_session",
            command="python3 Quartz CGSessionCopyCurrentDictionary",
            raw=self._trim_raw(raw),
            parsed=parsed,
            confidence=confidence,
            notes=notes,
        ))]

    # -----------------------------------------------------------------------
    # Linux checks
    # -----------------------------------------------------------------------

    def _check_wifi_linux(self) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        evidence: List[Dict[str, Any]] = []
        parsed = {
            "enabled": None,
            "connected": None,
            "ssid": None,
            "adapter": None,
            "status": UNKNOWN,
        }

        if shutil.which("nmcli"):
            result = self._run_command(["nmcli", "-t", "-f", "WIFI", "radio"])
            raw_radio = result.get("stdout", "")
            enabled = raw_radio.strip().lower() == "enabled" if result["success"] else None

            dev_result = self._run_command(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device"])
            raw_dev = dev_result.get("stdout", "")
            connected = False
            ssid = None
            adapter = None

            if dev_result["success"]:
                for line in raw_dev.splitlines():
                    parts = line.split(":")
                    if len(parts) >= 4 and parts[1] == "wifi":
                        adapter = parts[0]
                        if parts[2].lower() == "connected":
                            connected = True
                            ssid = parts[3] or None
                            break

            parsed = {
                "enabled": enabled,
                "connected": connected if enabled is not None else None,
                "ssid": ssid,
                "adapter": adapter,
                "status": CONNECTED if connected else ENABLED if enabled else DISABLED if enabled is False else UNKNOWN,
            }
            confidence = 0.88 if enabled is not None else 0.2
            evidence.append(asdict(DeviceCheckEvidence(
                source="linux.nmcli_wifi",
                command="nmcli radio/device",
                raw=self._trim_raw(f"{raw_radio}\n{raw_dev}"),
                parsed=parsed,
                confidence=confidence,
                notes=[],
            )))
            return parsed, evidence

        if shutil.which("iwgetid"):
            result = self._run_command(["iwgetid", "-r"])
            raw = result.get("stdout", "")
            ssid = raw.strip() or None
            parsed = {
                "enabled": True if ssid else None,
                "connected": bool(ssid),
                "ssid": ssid,
                "adapter": None,
                "status": CONNECTED if ssid else UNKNOWN,
            }
            evidence.append(asdict(DeviceCheckEvidence(
                source="linux.iwgetid",
                command="iwgetid -r",
                raw=self._trim_raw(raw),
                parsed=parsed,
                confidence=0.68 if ssid else 0.2,
                notes=[],
            )))
            return parsed, evidence

        evidence.append(asdict(DeviceCheckEvidence(
            source="linux.no_wifi_tool",
            parsed=parsed,
            confidence=0.1,
            notes=["Neither nmcli nor iwgetid is available."],
        )))
        return parsed, evidence

    def _check_bluetooth_linux(self) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        parsed = {
            "enabled": None,
            "connected_devices": [],
            "status": UNKNOWN,
        }

        if shutil.which("rfkill"):
            rfkill = self._run_command(["rfkill", "list", "bluetooth"])
            raw_rfkill = rfkill.get("stdout", "")
            hard_blocked = "hard blocked: yes" in raw_rfkill.lower()
            soft_blocked = "soft blocked: yes" in raw_rfkill.lower()
            enabled = not (hard_blocked or soft_blocked) if rfkill["success"] and raw_rfkill.strip() else None
        else:
            rfkill = {"stdout": "", "success": False}
            raw_rfkill = ""
            enabled = None

        connected_devices: List[Dict[str, Any]] = []
        raw_bt = ""
        if shutil.which("bluetoothctl"):
            bt = self._run_command(["bluetoothctl", "devices", "Connected"])
            raw_bt = bt.get("stdout", "")
            if bt["success"]:
                for line in raw_bt.splitlines():
                    match = re.match(r"Device\s+([0-9A-Fa-f:]+)\s+(.+)$", line)
                    if match:
                        connected_devices.append({
                            "address": match.group(1),
                            "name": match.group(2).strip(),
                            "status": CONNECTED,
                        })
                if enabled is None:
                    enabled = True

        parsed = {
            "enabled": enabled,
            "connected_devices": connected_devices,
            "status": ENABLED if enabled else DISABLED if enabled is False else UNKNOWN,
        }

        return parsed, [asdict(DeviceCheckEvidence(
            source="linux.rfkill_bluetoothctl",
            command="rfkill list bluetooth; bluetoothctl devices Connected",
            raw=self._trim_raw(f"{raw_rfkill}\n{raw_bt}"),
            parsed=parsed,
            confidence=0.78 if enabled is not None else 0.2,
            notes=[] if enabled is not None else ["Bluetooth tools are unavailable or returned no data."],
        ))]

    def _check_volume_linux(self) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        commands = [
            ["pamixer", "--get-volume"],
            ["pactl", "get-sink-volume", "@DEFAULT_SINK@"],
            ["amixer", "get", "Master"],
        ]

        parsed = {
            "level": None,
            "muted": None,
            "status": UNKNOWN,
        }
        evidence: List[Dict[str, Any]] = []

        if shutil.which("pamixer"):
            vol = self._run_command(["pamixer", "--get-volume"])
            mute = self._run_command(["pamixer", "--get-mute"])
            raw = f"{vol.get('stdout', '')}\n{mute.get('stdout', '')}"
            if vol["success"]:
                level = self._safe_int(vol.get("stdout", "").strip())
                muted = mute.get("stdout", "").strip().lower() == "true" if mute["success"] else None
                parsed = {
                    "level": level,
                    "muted": muted,
                    "status": DISABLED if muted or level == 0 else ENABLED if level is not None else UNKNOWN,
                }
                evidence.append(asdict(DeviceCheckEvidence(
                    source="linux.pamixer",
                    command="pamixer --get-volume; pamixer --get-mute",
                    raw=self._trim_raw(raw),
                    parsed=parsed,
                    confidence=0.86 if level is not None else 0.2,
                    notes=[],
                )))
                return parsed, evidence

        if shutil.which("pactl"):
            result = self._run_command(["pactl", "get-sink-volume", "@DEFAULT_SINK@"])
            raw = result.get("stdout", "")
            mute_result = self._run_command(["pactl", "get-sink-mute", "@DEFAULT_SINK@"])
            raw_mute = mute_result.get("stdout", "")
            levels = [self._safe_int(x) for x in re.findall(r"(\d+)%", raw)]
            levels = [x for x in levels if x is not None]
            level = int(round(sum(levels) / len(levels))) if levels else None
            muted = "yes" in raw_mute.lower() if mute_result["success"] else None
            parsed = {
                "level": level,
                "muted": muted,
                "status": DISABLED if muted or level == 0 else ENABLED if level is not None else UNKNOWN,
            }
            evidence.append(asdict(DeviceCheckEvidence(
                source="linux.pactl",
                command="pactl get-sink-volume/mute @DEFAULT_SINK@",
                raw=self._trim_raw(f"{raw}\n{raw_mute}"),
                parsed=parsed,
                confidence=0.82 if level is not None else 0.2,
                notes=[],
            )))
            return parsed, evidence

        if shutil.which("amixer"):
            result = self._run_command(["amixer", "get", "Master"])
            raw = result.get("stdout", "")
            levels = [self._safe_int(x) for x in re.findall(r"\[(\d+)%\]", raw)]
            levels = [x for x in levels if x is not None]
            level = int(round(sum(levels) / len(levels))) if levels else None
            muted = "[off]" in raw.lower()
            parsed = {
                "level": level,
                "muted": muted,
                "status": DISABLED if muted or level == 0 else ENABLED if level is not None else UNKNOWN,
            }
            evidence.append(asdict(DeviceCheckEvidence(
                source="linux.amixer",
                command="amixer get Master",
                raw=self._trim_raw(raw),
                parsed=parsed,
                confidence=0.72 if level is not None else 0.2,
                notes=[],
            )))
            return parsed, evidence

        evidence.append(asdict(DeviceCheckEvidence(
            source="linux.no_volume_tool",
            command="; ".join(" ".join(c) for c in commands),
            parsed=parsed,
            confidence=0.1,
            notes=["No supported Linux volume tool found: pamixer, pactl, or amixer."],
        )))
        return parsed, evidence

    def _check_brightness_linux(self) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        parsed = {
            "level": None,
            "displays": [],
            "status": UNKNOWN,
        }
        evidence: List[Dict[str, Any]] = []

        backlight_dir = "/sys/class/backlight"
        if os.path.isdir(backlight_dir):
            displays: List[Dict[str, Any]] = []
            levels: List[int] = []
            raw_parts: List[str] = []

            for name in sorted(os.listdir(backlight_dir)):
                base = os.path.join(backlight_dir, name)
                brightness_file = os.path.join(base, "brightness")
                max_file = os.path.join(base, "max_brightness")
                try:
                    with open(brightness_file, "r", encoding="utf-8") as f:
                        current = int(f.read().strip())
                    with open(max_file, "r", encoding="utf-8") as f:
                        maximum = int(f.read().strip())
                    if maximum > 0:
                        level = int(round((current / maximum) * 100))
                        levels.append(level)
                        displays.append({
                            "name": name,
                            "level": level,
                            "raw_brightness": current,
                            "raw_max_brightness": maximum,
                        })
                        raw_parts.append(f"{name}: {current}/{maximum}={level}%")
                except Exception as exc:
                    raw_parts.append(f"{name}: error={exc}")

            avg = int(round(sum(levels) / len(levels))) if levels else None
            parsed = {
                "level": avg,
                "displays": displays,
                "status": ENABLED if avg is not None else UNKNOWN,
            }
            evidence.append(asdict(DeviceCheckEvidence(
                source="linux.sys_class_backlight",
                command=None,
                raw=self._trim_raw("\n".join(raw_parts)),
                parsed=parsed,
                confidence=0.84 if avg is not None else 0.2,
                notes=[] if avg is not None else ["No readable backlight entries found."],
            )))
            return parsed, evidence

        if shutil.which("xbacklight"):
            result = self._run_command(["xbacklight", "-get"])
            raw = result.get("stdout", "")
            level_float = None
            try:
                level_float = float(raw.strip())
            except Exception:
                level_float = None
            level = int(round(level_float)) if level_float is not None else None
            parsed = {
                "level": level,
                "displays": [{"level": level}] if level is not None else [],
                "status": ENABLED if level is not None else UNKNOWN,
            }
            evidence.append(asdict(DeviceCheckEvidence(
                source="linux.xbacklight",
                command="xbacklight -get",
                raw=self._trim_raw(raw),
                parsed=parsed,
                confidence=0.7 if level is not None else 0.2,
                notes=[],
            )))
            return parsed, evidence

        evidence.append(asdict(DeviceCheckEvidence(
            source="linux.no_brightness_source",
            parsed=parsed,
            confidence=0.1,
            notes=["No supported Linux brightness source found."],
        )))
        return parsed, evidence

    def _check_battery_linux(self) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        if shutil.which("upower"):
            result = self._run_command(["upower", "-e"])
            devices_raw = result.get("stdout", "")
            battery_paths = [line.strip() for line in devices_raw.splitlines() if "battery" in line.lower()]
            if battery_paths:
                info = self._run_command(["upower", "-i", battery_paths[0]])
                raw = info.get("stdout", "")
                percentage_match = re.search(r"percentage:\s*(\d+)%", raw, re.IGNORECASE)
                state_match = re.search(r"state:\s*(\w+)", raw, re.IGNORECASE)

                level = self._safe_int(percentage_match.group(1)) if percentage_match else None
                state = state_match.group(1).lower() if state_match else UNKNOWN
                charging = state in {"charging", "fully-charged", "pending-charge"}
                status = "full" if state == "fully-charged" else "charging" if charging else "discharging" if state == "discharging" else UNKNOWN

                parsed = {
                    "level": level,
                    "charging": charging if status != UNKNOWN else None,
                    "plugged": charging if status != UNKNOWN else None,
                    "seconds_left": None,
                    "status": status,
                }
                confidence = 0.85 if level is not None else 0.25
                return parsed, [asdict(DeviceCheckEvidence(
                    source="linux.upower",
                    command=f"upower -i {battery_paths[0]}",
                    raw=self._trim_raw(raw),
                    parsed=parsed,
                    confidence=confidence,
                    notes=[],
                ))]

        power_supply = "/sys/class/power_supply"
        if os.path.isdir(power_supply):
            batteries = [x for x in os.listdir(power_supply) if x.upper().startswith("BAT")]
            if batteries:
                base = os.path.join(power_supply, batteries[0])
                capacity = self._read_text_file(os.path.join(base, "capacity"))
                status_text = self._read_text_file(os.path.join(base, "status"))
                level = self._safe_int(capacity.strip()) if capacity else None
                lower_status = status_text.strip().lower() if status_text else UNKNOWN
                charging = lower_status in {"charging", "full"}
                parsed = {
                    "level": level,
                    "charging": charging if lower_status != UNKNOWN else None,
                    "plugged": charging if lower_status != UNKNOWN else None,
                    "seconds_left": None,
                    "status": "full" if lower_status == "full" else "charging" if charging else "discharging" if lower_status == "discharging" else UNKNOWN,
                }
                return parsed, [asdict(DeviceCheckEvidence(
                    source="linux.sys_power_supply",
                    command=None,
                    raw=self._trim_raw(f"capacity={capacity}; status={status_text}"),
                    parsed=parsed,
                    confidence=0.8 if level is not None else 0.2,
                    notes=[],
                ))]

        parsed = {
            "level": None,
            "charging": None,
            "plugged": None,
            "seconds_left": None,
            "status": "no_battery",
        }
        return parsed, [asdict(DeviceCheckEvidence(
            source="linux.no_battery_source",
            parsed=parsed,
            confidence=0.72,
            notes=["No battery detected through upower or /sys/class/power_supply."],
        ))]

    def _check_screen_lock_linux(self) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        evidence: List[Dict[str, Any]] = []
        parsed = {
            "locked": None,
            "screen_saver_active": None,
            "status": UNKNOWN,
        }

        desktop = os.environ.get("XDG_CURRENT_DESKTOP", "").lower()
        session_type = os.environ.get("XDG_SESSION_TYPE", "").lower()

        if shutil.which("gnome-screensaver-command"):
            result = self._run_command(["gnome-screensaver-command", "-q"])
            raw = result.get("stdout", "") + result.get("stderr", "")
            lower = raw.lower()
            if "is active" in lower:
                parsed = {
                    "locked": True,
                    "screen_saver_active": True,
                    "status": LOCKED,
                }
                confidence = 0.62
            elif "is inactive" in lower:
                parsed = {
                    "locked": False,
                    "screen_saver_active": False,
                    "status": UNLOCKED,
                }
                confidence = 0.55
            else:
                confidence = 0.2

            evidence.append(asdict(DeviceCheckEvidence(
                source="linux.gnome_screensaver",
                command="gnome-screensaver-command -q",
                raw=self._trim_raw(raw),
                parsed=parsed,
                confidence=confidence,
                notes=[],
            )))
            return parsed, evidence

        if shutil.which("loginctl") and os.environ.get("XDG_SESSION_ID"):
            session_id = os.environ["XDG_SESSION_ID"]
            result = self._run_command(["loginctl", "show-session", session_id, "-p", "LockedHint"])
            raw = result.get("stdout", "")
            locked = None
            if "LockedHint=yes" in raw:
                locked = True
            elif "LockedHint=no" in raw:
                locked = False

            parsed = {
                "locked": locked,
                "screen_saver_active": None,
                "status": LOCKED if locked else UNLOCKED if locked is False else UNKNOWN,
            }
            evidence.append(asdict(DeviceCheckEvidence(
                source="linux.loginctl_locked_hint",
                command=f"loginctl show-session {session_id} -p LockedHint",
                raw=self._trim_raw(raw),
                parsed=parsed,
                confidence=0.72 if locked is not None else 0.2,
                notes=[],
            )))
            return parsed, evidence

        evidence.append(asdict(DeviceCheckEvidence(
            source="linux.session_heuristic",
            parsed={
                "desktop": desktop,
                "session_type": session_type,
                **parsed,
            },
            confidence=0.12,
            notes=["No supported Linux screen lock query tool found."],
        )))
        return parsed, evidence

    # -----------------------------------------------------------------------
    # Optional library checks
    # -----------------------------------------------------------------------

    def _check_brightness_with_library(self) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        parsed = {
            "level": None,
            "displays": [],
            "status": UNKNOWN,
        }
        evidence: List[Dict[str, Any]] = []

        try:
            values = sbc.get_brightness()  # type: ignore[union-attr]
            if isinstance(values, int):
                levels = [values]
            elif isinstance(values, list):
                levels = [self._safe_int(v) for v in values]
                levels = [v for v in levels if v is not None]
            else:
                levels = []

            avg = int(round(sum(levels) / len(levels))) if levels else None
            parsed = {
                "level": avg,
                "displays": [{"level": level} for level in levels],
                "status": ENABLED if avg is not None else UNKNOWN,
            }
            evidence.append(asdict(DeviceCheckEvidence(
                source="screen_brightness_control",
                command=None,
                raw=None,
                parsed=parsed,
                confidence=0.88 if avg is not None else 0.2,
                notes=[],
            )))
        except Exception as exc:
            evidence.append(asdict(DeviceCheckEvidence(
                source="screen_brightness_control",
                command=None,
                raw=None,
                parsed=parsed,
                confidence=0.1,
                notes=[f"screen_brightness_control failed: {exc}"],
            )))

        return parsed, evidence

    # -----------------------------------------------------------------------
    # Compatibility hooks required by William / Jarvis architecture
    # -----------------------------------------------------------------------

    def _validate_task_context(self, context: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Validate SaaS isolation context.

        Every user-specific verification must include user_id and workspace_id
        unless config.require_context is disabled for local tests.
        """

        user_id = context.get("user_id")
        workspace_id = context.get("workspace_id")

        if self.config.require_context:
            if not self._valid_context_id(user_id):
                return self._error_result(
                    message="Missing or invalid user_id for device state verification.",
                    error_code="INVALID_USER_CONTEXT",
                    data={"user_id_present": bool(user_id)},
                    metadata=dict(context),
                )
            if not self._valid_context_id(workspace_id):
                return self._error_result(
                    message="Missing or invalid workspace_id for device state verification.",
                    error_code="INVALID_WORKSPACE_CONTEXT",
                    data={"workspace_id_present": bool(workspace_id)},
                    metadata=dict(context),
                )

        return self._safe_result(
            success=True,
            message="Task context validated.",
            data={"user_id": user_id, "workspace_id": workspace_id},
            metadata=dict(context),
        )

    def _requires_security_check(
        self,
        *,
        action: str,
        checks: Optional[Sequence[str]] = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Decide if a device-state verification requires Security Agent approval.

        Read-only checks are normally safe, but deployments may require approval
        for screen lock checks or all device checks.
        """

        checks_set = set(checks or [])

        if self.config.security_required_for_device_state:
            return True

        if self.config.security_required_for_screen_lock and "screen_lock" in checks_set:
            return True

        if action == "check_screen_lock_state" and self.config.security_required_for_screen_lock:
            return True

        return False

    def _request_security_approval(
        self,
        *,
        action: str,
        checks: Optional[Sequence[str]] = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Ask Security Agent for approval if available.

        If no Security Agent is injected, read-only checks are allowed by default
        unless system policy requires blocking. This keeps the module testable
        and import-safe.
        """

        payload = {
            "agent": self.agent_name,
            "action": action,
            "checks": list(checks or []),
            "context": dict(context or {}),
            "read_only": True,
            "requested_at": self._utc_now_iso(),
        }

        if self.security_agent is None:
            return {
                "approved": True,
                "source": "local_default",
                "message": "No Security Agent attached; read-only verification allowed by local default.",
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
                    "source": "security_agent",
                    "message": "Security Agent does not expose an approval method.",
                    "payload": payload,
                }

            if isinstance(response, Mapping):
                approved = bool(response.get("approved", response.get("success", False)))
                return {
                    "approved": approved,
                    "source": "security_agent",
                    "message": str(response.get("message", "Security Agent response received.")),
                    "payload": payload,
                    "response": dict(response),
                }

            return {
                "approved": bool(response),
                "source": "security_agent",
                "message": "Security Agent returned non-dict approval response.",
                "payload": payload,
            }
        except Exception as exc:
            self.logger.exception("Security approval request failed.")
            return {
                "approved": False,
                "source": "security_agent",
                "message": f"Security approval request failed: {exc}",
                "payload": payload,
            }

    def _prepare_verification_payload(
        self,
        *,
        action: str,
        context: Mapping[str, Any],
        checks: Sequence[str],
        results: Mapping[str, Any],
        validation: Mapping[str, Any],
        started_at: str,
    ) -> Dict[str, Any]:
        """
        Prepare payload for Verification Agent proof reports, task history,
        dashboard/API response, and Master Agent routing.
        """

        return {
            "type": "device_state_verification",
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "action": action,
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "task_id": context.get("task_id"),
            "request_id": context.get("request_id"),
            "checks": list(checks),
            "results": dict(results),
            "validation": dict(validation),
            "platform": self._platform_metadata(),
            "started_at": started_at,
            "finished_at": self._utc_now_iso(),
            "success": bool(validation.get("overall_success", False)),
            "confidence": float(validation.get("overall_confidence", 0.0)),
        }

    def _prepare_memory_payload(
        self,
        *,
        action: str,
        context: Mapping[str, Any],
        results: Mapping[str, Any],
        validation: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare compact Memory Agent compatible payload.

        This avoids storing excessive raw evidence while preserving useful
        verification history.
        """

        compact_checks: Dict[str, Any] = {}
        for name, result in results.items():
            if isinstance(result, Mapping):
                compact_checks[name] = {
                    "status": result.get("status"),
                    "confidence": result.get("confidence"),
                    "checked_at": result.get("checked_at"),
                }

        return {
            "memory_type": "verification_device_state",
            "agent": self.agent_name,
            "action": action,
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "task_id": context.get("task_id"),
            "request_id": context.get("request_id"),
            "summary": validation.get("message"),
            "success": validation.get("overall_success"),
            "confidence": validation.get("overall_confidence"),
            "checks": compact_checks,
            "created_at": self._utc_now_iso(),
        }

    def _emit_agent_event(self, *, event_name: str, payload: Mapping[str, Any]) -> None:
        """
        Emit an event to William's event bus if present.
        """

        try:
            if self.event_bus is None:
                return
            if hasattr(self.event_bus, "emit"):
                self.event_bus.emit(event_name, dict(payload))
            elif hasattr(self.event_bus, "publish"):
                self.event_bus.publish(event_name, dict(payload))
        except Exception:
            self.logger.exception("Failed to emit agent event: %s", event_name)

    def _log_audit_event(
        self,
        *,
        action: str,
        context: Mapping[str, Any],
        outcome: Mapping[str, Any],
    ) -> None:
        """
        Log audit event for SaaS traceability.
        """

        audit_payload = {
            "agent": self.agent_name,
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
                    self.audit_logger.log(audit_payload)
                    return
                if hasattr(self.audit_logger, "write"):
                    self.audit_logger.write(audit_payload)
                    return

            self.logger.info("DeviceStateChecker audit event: %s", audit_payload)
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
            "data": dict(data or {}),
            "error": dict(error or {}) if error else None,
            "metadata": {
                "agent": self.agent_name,
                "module": self.file_path,
                "timestamp": self._utc_now_iso(),
                **dict(metadata or {}),
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

        error: Dict[str, Any] = {
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

    # -----------------------------------------------------------------------
    # Internal validation helpers
    # -----------------------------------------------------------------------

    def _normalize_checks(self, checks: Optional[Sequence[str]]) -> List[str]:
        if checks is None:
            return sorted(self.supported_checks)

        normalized: List[str] = []
        for item in checks:
            name = str(item).strip().lower().replace("-", "_").replace(" ", "_")
            aliases = {
                "wifi_state": "wifi",
                "wi_fi": "wifi",
                "wireless": "wifi",
                "bt": "bluetooth",
                "bluetooth_state": "bluetooth",
                "audio": "volume",
                "sound": "volume",
                "volume_state": "volume",
                "screen_brightness": "brightness",
                "brightness_state": "brightness",
                "battery_state": "battery",
                "power": "battery",
                "lock": "screen_lock",
                "screenlock": "screen_lock",
                "locked": "screen_lock",
            }
            name = aliases.get(name, name)
            if name in self.supported_checks and name not in normalized:
                normalized.append(name)

        return normalized

    def _normalize_expectations(
        self,
        expected: Optional[Union[Mapping[str, Any], Sequence[Mapping[str, Any]]]],
    ) -> Dict[str, DeviceStateExpectation]:
        if not expected:
            return {}

        expectations: Dict[str, DeviceStateExpectation] = {}

        if isinstance(expected, Mapping):
            if "name" in expected:
                items: List[Mapping[str, Any]] = [expected]
            else:
                items = []
                for key, value in expected.items():
                    if isinstance(value, Mapping):
                        item = {"name": key, **dict(value)}
                    else:
                        item = {"name": key, "expected_status": value}
                    items.append(item)
        else:
            items = list(expected)

        for item in items:
            if not isinstance(item, Mapping):
                continue
            name = str(item.get("name", "")).strip().lower().replace("-", "_").replace(" ", "_")
            if name not in self.supported_checks:
                continue
            expectations[name] = DeviceStateExpectation(
                name=name,
                expected_enabled=self._optional_bool(item.get("expected_enabled", item.get("enabled"))),
                expected_connected=self._optional_bool(item.get("expected_connected", item.get("connected"))),
                expected_locked=self._optional_bool(item.get("expected_locked", item.get("locked"))),
                expected_level=self._optional_int(item.get("expected_level", item.get("level"))),
                expected_level_min=self._optional_int(item.get("expected_level_min", item.get("level_min", item.get("min")))),
                expected_level_max=self._optional_int(item.get("expected_level_max", item.get("level_max", item.get("max")))),
                expected_charging=self._optional_bool(item.get("expected_charging", item.get("charging"))),
                expected_status=str(item.get("expected_status", item.get("status"))).lower()
                if item.get("expected_status", item.get("status")) is not None
                else None,
                tolerance=self._optional_int(item.get("tolerance")) or 0,
            )

        return expectations

    def _validate_one_expectation(
        self,
        actual: Mapping[str, Any],
        expectation: DeviceStateExpectation,
    ) -> Tuple[bool, str]:
        failures: List[str] = []

        def check_equal(field_name: str, expected_value: Any, actual_value: Any) -> None:
            if expected_value is not None and actual_value != expected_value:
                failures.append(f"{field_name} expected {expected_value!r}, got {actual_value!r}")

        check_equal("enabled", expectation.expected_enabled, actual.get("enabled"))
        check_equal("connected", expectation.expected_connected, actual.get("connected"))
        check_equal("locked", expectation.expected_locked, actual.get("locked"))
        check_equal("charging", expectation.expected_charging, actual.get("charging"))

        if expectation.expected_status is not None:
            actual_status = str(actual.get("status", "")).lower()
            if actual_status != expectation.expected_status.lower():
                failures.append(f"status expected {expectation.expected_status!r}, got {actual_status!r}")

        actual_level = self._optional_int(actual.get("level"))
        if expectation.expected_level is not None:
            if actual_level is None:
                failures.append(f"level expected {expectation.expected_level}, got unknown")
            elif abs(actual_level - expectation.expected_level) > expectation.tolerance:
                failures.append(
                    f"level expected {expectation.expected_level} ±{expectation.tolerance}, got {actual_level}"
                )

        if expectation.expected_level_min is not None:
            if actual_level is None:
                failures.append(f"level_min expected >= {expectation.expected_level_min}, got unknown")
            elif actual_level < expectation.expected_level_min:
                failures.append(f"level expected >= {expectation.expected_level_min}, got {actual_level}")

        if expectation.expected_level_max is not None:
            if actual_level is None:
                failures.append(f"level_max expected <= {expectation.expected_level_max}, got unknown")
            elif actual_level > expectation.expected_level_max:
                failures.append(f"level expected <= {expectation.expected_level_max}, got {actual_level}")

        if failures:
            return False, "; ".join(failures)

        return True, "Expected state matched."

    # -----------------------------------------------------------------------
    # Command helpers
    # -----------------------------------------------------------------------

    def _run_powershell(self, script: str) -> Dict[str, Any]:
        executable = shutil.which("powershell") or shutil.which("pwsh")
        if not executable:
            return {
                "success": False,
                "stdout": "",
                "stderr": "PowerShell executable not found.",
                "returncode": None,
            }
        return self._run_command([executable, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script])

    def _run_command(self, command: Sequence[str]) -> Dict[str, Any]:
        if not self.config.allow_subprocess_checks:
            return {
                "success": False,
                "stdout": "",
                "stderr": "Subprocess checks are disabled by configuration.",
                "returncode": None,
            }

        if not command:
            return {
                "success": False,
                "stdout": "",
                "stderr": "Empty command.",
                "returncode": None,
            }

        executable = command[0]
        if os.path.sep not in executable and shutil.which(executable) is None:
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Executable not found: {executable}",
                "returncode": None,
            }

        try:
            completed = subprocess.run(
                list(command),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.config.command_timeout_seconds,
                check=False,
                shell=False,
            )
            return {
                "success": completed.returncode == 0,
                "stdout": completed.stdout or "",
                "stderr": completed.stderr or "",
                "returncode": completed.returncode,
            }
        except subprocess.TimeoutExpired as exc:
            return {
                "success": False,
                "stdout": exc.stdout if isinstance(exc.stdout, str) else "",
                "stderr": f"Command timed out after {self.config.command_timeout_seconds} seconds.",
                "returncode": None,
            }
        except Exception as exc:
            return {
                "success": False,
                "stdout": "",
                "stderr": str(exc),
                "returncode": None,
            }

    # -----------------------------------------------------------------------
    # Utility helpers
    # -----------------------------------------------------------------------

    def _platform_metadata(self) -> Dict[str, Any]:
        return {
            "system": platform.system(),
            "system_normalized": self.platform_name,
            "release": self.platform_release,
            "version": platform.version(),
            "machine": platform.machine(),
            "python": sys.version.split()[0],
            "hostname": self.hostname,
        }

    def _utc_now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _valid_context_id(self, value: Any) -> bool:
        if value is None:
            return False
        text = str(value).strip()
        if not text:
            return False
        if len(text) > 256:
            return False
        return bool(re.match(r"^[A-Za-z0-9_.:@\-]+$", text))

    def _safe_int(self, value: Any) -> Optional[int]:
        try:
            if value is None:
                return None
            if isinstance(value, bool):
                return int(value)
            if isinstance(value, float):
                return int(round(value))
            text = str(value).strip()
            if not text:
                return None
            return int(float(text))
        except Exception:
            return None

    def _optional_int(self, value: Any) -> Optional[int]:
        if value is None:
            return None
        return self._safe_int(value)

    def _optional_bool(self, value: Any) -> Optional[bool]:
        if value is None:
            return None
        if isinstance(value, bool):
            return value
        text = str(value).strip().lower()
        if text in {"true", "1", "yes", "y", "on", "enabled", "connected", "locked", "charging"}:
            return True
        if text in {"false", "0", "no", "n", "off", "disabled", "disconnected", "unlocked", "discharging"}:
            return False
        return None

    def _read_text_file(self, path: str) -> Optional[str]:
        try:
            with open(path, "r", encoding="utf-8") as file:
                return file.read().strip()
        except Exception:
            return None

    def _trim_raw(self, raw: Optional[str]) -> Optional[str]:
        if raw is None:
            return None
        if not self.config.collect_raw_evidence:
            return None
        raw = str(raw)
        if len(raw) <= self.config.max_raw_evidence_chars:
            return raw
        return raw[: self.config.max_raw_evidence_chars] + "...[trimmed]"

    def _evidence_confidence(self, evidence: Sequence[Mapping[str, Any]]) -> float:
        values: List[float] = []
        for item in evidence:
            try:
                values.append(float(item.get("confidence", 0.0)))
            except Exception:
                continue
        if not values:
            return 0.0
        return round(max(values), 4)


# ---------------------------------------------------------------------------
# Module-level convenience function
# ---------------------------------------------------------------------------

def check_device_state(
    *,
    user_id: Optional[str],
    workspace_id: Optional[str],
    checks: Optional[Sequence[str]] = None,
    expected: Optional[Union[Mapping[str, Any], Sequence[Mapping[str, Any]]]] = None,
    task_id: Optional[str] = None,
    request_id: Optional[str] = None,
    config: Optional[Union[DeviceStateConfig, Mapping[str, Any]]] = None,
    metadata: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Convenience wrapper for simple API/dashboard usage.

    Example:
        result = check_device_state(
            user_id="user_123",
            workspace_id="workspace_abc",
            checks=["wifi", "battery"],
            expected={
                "wifi": {"connected": True},
                "battery": {"level_min": 20},
            },
        )
    """

    checker = DeviceStateChecker(config=config)
    return checker.check_device_state(
        user_id=user_id,
        workspace_id=workspace_id,
        checks=checks,
        expected=expected,
        task_id=task_id,
        request_id=request_id,
        metadata=metadata,
    )


__all__ = [
    "DeviceStateChecker",
    "DeviceStateConfig",
    "DeviceStateExpectation",
    "DeviceCheckEvidence",
    "check_device_state",
]


if __name__ == "__main__":
    """
    Safe local smoke test.

    This does not modify device settings. Context requirement is disabled only
    for direct local testing.
    """

    logging.basicConfig(level=logging.INFO)

    local_checker = DeviceStateChecker(
        config=DeviceStateConfig(
            require_context=False,
            collect_raw_evidence=False,
        )
    )

    output = local_checker.check_device_state(
        user_id="local_user",
        workspace_id="local_workspace",
        checks=["wifi", "bluetooth", "volume", "brightness", "battery", "screen_lock"],
        expected=None,
        task_id="local_smoke_test",
        request_id=f"device_state_checker_{int(time.time())}",
    )

    print(json.dumps(output, indent=2, default=str))