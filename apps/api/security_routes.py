"""
Security Routes Module - William / Jarvis SaaS System

Handles:
- Risk checks
- Security approvals
- Audit logs
- Policy management
- Emergency system lock

Connected Agents:
- Security Agent (primary enforcement)
- Master Agent (routing decisions)
- Memory Agent (context logging)
- Verification Agent (post-action validation)
"""

from __future__ import annotations

import time
import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime

try:
    from fastapi import APIRouter, HTTPException, Depends
except Exception:
    # Safe fallback if FastAPI not installed yet
    APIRouter = object
    HTTPException = Exception
    Depends = None


# =========================================================
# Security Routes Class
# =========================================================

class SecurityRoutes:
    """
    SecurityRoutes exposes all security-related API endpoints
    for approvals, audits, risk checks, and emergency controls.
    """

    def __init__(self):
        self.router = APIRouter() if APIRouter != object else None

        # In-memory security stores (replace with DB later)
        self.audit_logs: List[Dict[str, Any]] = []
        self.security_policies: Dict[str, Any] = {
            "default_risk_threshold": 0.7,
            "emergency_lock": False,
            "allowed_actions": ["read", "query", "analyze"],
            "blocked_actions": ["delete_all", "system_shutdown"]
        }

        self.pending_approvals: Dict[str, Dict[str, Any]] = {}

        self._register_routes()

    # =====================================================
    # ROUTE REGISTRATION
    # =====================================================

    def _register_routes(self):
        if not self.router:
            return

        self.router.add_api_route(
            "/security/risk-check",
            self.risk_check,
            methods=["POST"]
        )

        self.router.add_api_route(
            "/security/approve",
            self.approve_action,
            methods=["POST"]
        )

        self.router.add_api_route(
            "/security/audit/logs",
            self.get_audit_logs,
            methods=["GET"]
        )

        self.router.add_api_route(
            "/security/policy",
            self.get_policies,
            methods=["GET"]
        )

        self.router.add_api_route(
            "/security/policy/update",
            self.update_policies,
            methods=["POST"]
        )

        self.router.add_api_route(
            "/security/emergency-lock",
            self.emergency_lock,
            methods=["POST"]
        )

    # =====================================================
    # CORE SECURITY METHODS
    # =====================================================

    def risk_check(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate risk score for an incoming action.
        """
        try:
            user_id = payload.get("user_id")
            workspace_id = payload.get("workspace_id")
            action = payload.get("action", "unknown")

            if not user_id or not workspace_id:
                return self._error_result("Missing user or workspace context")

            risk_score = self._calculate_risk_score(action, payload)

            allowed = risk_score < self.security_policies["default_risk_threshold"]

            result = {
                "user_id": user_id,
                "workspace_id": workspace_id,
                "action": action,
                "risk_score": risk_score,
                "allowed": allowed,
                "timestamp": self._now(),
                "requires_approval": not allowed
            }

            self._log_audit_event("risk_check", result)
            return self._safe_result(result)

        except Exception as e:
            return self._error_result(str(e))

    def approve_action(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Approve or reject a pending sensitive action.
        """
        try:
            approval_id = payload.get("approval_id")
            decision = payload.get("decision", "reject")

            if not approval_id or approval_id not in self.pending_approvals:
                return self._error_result("Invalid approval ID")

            record = self.pending_approvals[approval_id]
            record["status"] = "approved" if decision == "approve" else "rejected"
            record["decided_at"] = self._now()

            self._log_audit_event("approval_decision", record)

            return self._safe_result(record)

        except Exception as e:
            return self._error_result(str(e))

    def get_audit_logs(self, limit: int = 50) -> Dict[str, Any]:
        """
        Return latest audit logs.
        """
        try:
            return self._safe_result({
                "logs": self.audit_logs[-limit:],
                "count": len(self.audit_logs)
            })
        except Exception as e:
            return self._error_result(str(e))

    def get_policies(self) -> Dict[str, Any]:
        """
        Return current security policies.
        """
        return self._safe_result(self.security_policies)

    def update_policies(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update security policies.
        """
        try:
            self.security_policies.update(payload)
            self._log_audit_event("policy_update", payload)

            return self._safe_result({
                "message": "Policies updated",
                "policies": self.security_policies
            })

        except Exception as e:
            return self._error_result(str(e))

    def emergency_lock(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enable or disable emergency system lock.
        """
        try:
            enable = payload.get("enable", False)
            reason = payload.get("reason", "no reason provided")

            self.security_policies["emergency_lock"] = enable

            event = {
                "event": "emergency_lock",
                "enabled": enable,
                "reason": reason,
                "timestamp": self._now()
            }

            self._log_audit_event("emergency_lock", event)

            return self._safe_result(event)

        except Exception as e:
            return self._error_result(str(e))

    # =====================================================
    # INTERNAL SECURITY LOGIC
    # =====================================================

    def _calculate_risk_score(self, action: str, payload: Dict[str, Any]) -> float:
        base = 0.2

        if action in self.security_policies.get("blocked_actions", []):
            base += 0.7

        if payload.get("sensitive", False):
            base += 0.3

        if payload.get("external_call", False):
            base += 0.2

        return min(base, 1.0)

    def _log_audit_event(self, event_type: str, data: Dict[str, Any]):
        log_entry = {
            "id": str(uuid.uuid4()),
            "event_type": event_type,
            "data": data,
            "timestamp": self._now()
        }
        self.audit_logs.append(log_entry)

    # =====================================================
    # COMPATIBILITY HOOKS (Master Agent Ecosystem)
    # =====================================================

    def _validate_task_context(self, user_id: str, workspace_id: str) -> bool:
        return bool(user_id and workspace_id)

    def _requires_security_check(self, action: str) -> bool:
        return action not in self.security_policies.get("allowed_actions", [])

    def _request_security_approval(self, action: str, payload: Dict[str, Any]) -> str:
        approval_id = str(uuid.uuid4())
        self.pending_approvals[approval_id] = {
            "action": action,
            "payload": payload,
            "status": "pending",
            "created_at": self._now()
        }
        return approval_id

    def _prepare_verification_payload(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "verification_id": str(uuid.uuid4()),
            "data": data,
            "timestamp": self._now()
        }

    def _prepare_memory_payload(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "memory_type": "security_event",
            "content": data,
            "timestamp": self._now()
        }

    def _emit_agent_event(self, event: str, data: Dict[str, Any]):
        # Placeholder for Master Agent event bus
        pass

    # =====================================================
    # RESPONSE HELPERS
    # =====================================================

    def _safe_result(self, data: Any) -> Dict[str, Any]:
        return {
            "success": True,
            "message": "ok",
            "data": data,
            "error": None,
            "metadata": {"ts": self._now()}
        }

    def _error_result(self, error: str) -> Dict[str, Any]:
        return {
            "success": False,
            "message": "error",
            "data": None,
            "error": error,
            "metadata": {"ts": self._now()}
        }

    def _now(self) -> str:
        return datetime.utcnow().isoformat()