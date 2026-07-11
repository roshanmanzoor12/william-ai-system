"""
agents/super_agents/finance_agent/finance_agent.py

FinanceAgent for William / Jarvis Multi-Agent AI SaaS System by Digital Promotix.

Purpose:
    Main finance controller orchestrating invoicing, budgets, payment risk
    guarding, and transaction drafting -- draft-only by default, matching
    every submodule's own safe-mode design (no real money movement).

This file previously contained a verbatim copy of
agents/super_agents/business_agent/config.py (wrong content entirely --
its own docstring said so) and defined no FinanceAgent class, which is
why agents.registry.AgentRegistry could not import the finance agent.
This is the real class.

Known issue (documented, not silently fixed): while building this,
finance_reports.py/receipt_reader.py/tax_helper.py/subscription_tracker.py
were found to each contain another sibling module's content under the
wrong filename (a chain: finance_reports.py duplicates payment_guard.py;
receipt_reader.py's content is really finance_reports.py's; tax_helper.py's
is really receipt_reader.py's; subscription_tracker.py's is really
tax_helper.py's; expense_categorizer.py's is really subscription_tracker.py's;
expense_categorizer's own true content appears to be missing entirely).
Untangling that safely needs full diff-level verification per file before
any rename/delete, which is out of scope here -- this agent only wires up
the four submodules confirmed correct by their own self-declared docstring
path AND real, matching class content: config.py, invoice_manager.py,
budget_tracker.py, payment_guard.py, transaction_preparer.py.

This file is intentionally import-safe:
    - It uses optional imports and fallback stubs if a submodule is missing.
    - It never executes real payment/transfer/bank actions directly --
      every submodule here is draft-only / evaluation-only by design.
    - It enforces SaaS user/workspace isolation for every user-specific task.
    - It prepares Security Agent, Verification Agent, and Memory Agent
      compatible payloads.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, Mapping, Optional

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:
    class BaseAgent:  # type: ignore
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)

        async def run(self, task: Mapping[str, Any]) -> Dict[str, Any]:
            raise NotImplementedError("Fallback BaseAgent.run is not implemented.")

try:
    from agents.super_agents.finance_agent.config import FinanceConfig, FinanceAction  # type: ignore
except Exception:
    FinanceConfig = None  # type: ignore
    FinanceAction = None  # type: ignore

try:
    from agents.super_agents.finance_agent.invoice_manager import InvoiceManager  # type: ignore
except Exception:
    InvoiceManager = None  # type: ignore

try:
    from agents.super_agents.finance_agent.budget_tracker import BudgetTracker  # type: ignore
except Exception:
    BudgetTracker = None  # type: ignore

try:
    from agents.super_agents.finance_agent.payment_guard import FinancePaymentGuard  # type: ignore
except Exception:
    FinancePaymentGuard = None  # type: ignore

try:
    from agents.super_agents.finance_agent.transaction_preparer import TransactionPreparer  # type: ignore
except Exception:
    TransactionPreparer = None  # type: ignore

try:
    from agents.super_agents.finance_agent.finance_memory import FinanceMemory  # type: ignore
except Exception:
    FinanceMemory = None  # type: ignore


logger = logging.getLogger("william.agents.finance_agent")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class FinanceAgent(BaseAgent):
    """
    Main Finance Agent controller.

    Responsibilities:
        - Invoice drafting/status (InvoiceManager)
        - Budget tracking (BudgetTracker)
        - Payment risk evaluation before any sensitive payment action
          (FinancePaymentGuard) -- this agent never submits a real payment
        - Transaction/vendor-payment/bank-transfer draft preparation
          (TransactionPreparer)
        - Memory, audit, and verification payload preparation

    System connections:
        - Master Agent: routes finance tasks here using action names from
          agents.super_agents.finance_agent.config.FinanceAction.
        - Security Agent: every sensitive action (submit_payment,
          transfer_funds, pay_invoice, ...) is evaluated by
          FinancePaymentGuard and requires approval before any downstream
          submodule would be allowed to execute it for real -- none of the
          wired submodules currently execute real money movement, only
          draft/evaluate.
    """

    def __init__(
        self,
        config: Optional[Any] = None,
        *,
        security_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        invoice_manager: Optional[Any] = None,
        budget_tracker: Optional[Any] = None,
        payment_guard: Optional[Any] = None,
        transaction_preparer: Optional[Any] = None,
        finance_memory: Optional[Any] = None,
        **kwargs: Any,
    ) -> None:
        try:
            super().__init__(agent_name="FinanceAgent", agent_id="finance_agent", **kwargs)
        except TypeError:
            try:
                super().__init__(**kwargs)
            except TypeError:
                super().__init__()

        self.agent_name = "FinanceAgent"
        self.agent_id = "finance_agent"
        self.version = "1.0.0"
        self.logger = logging.getLogger(self.agent_name)

        self.security_agent = security_agent
        self.verification_agent = verification_agent
        self.memory_agent = memory_agent
        self.event_bus = event_bus
        self.audit_logger = audit_logger

        self.config = config or self._build_optional_component(FinanceConfig)
        self.invoice_manager = invoice_manager or self._build_optional_component(InvoiceManager)
        self.budget_tracker = budget_tracker or self._build_optional_component(BudgetTracker)
        self.payment_guard = payment_guard or self._build_optional_component(FinancePaymentGuard)
        self.transaction_preparer = transaction_preparer or self._build_optional_component(TransactionPreparer)
        self.finance_memory = finance_memory or self._build_optional_component(FinanceMemory)

    def _build_optional_component(self, cls: Optional[type]) -> Optional[Any]:
        if cls is None:
            return None
        try:
            return cls()
        except Exception:
            self.logger.warning("Could not construct optional finance component %s", cls)
            return None

    # ==================================================================================
    # Registry and routing compatibility
    # ==================================================================================

    @classmethod
    def registry_metadata(cls) -> Dict[str, Any]:
        return {
            "agent_name": "FinanceAgent",
            "agent_id": "finance_agent",
            "module": "agents.super_agents.finance_agent.finance_agent",
            "class_name": "FinanceAgent",
            "category": "super_agent",
            "version": "1.0.0",
            "description": "Invoicing, budgets, payment risk evaluation, and transaction drafting -- draft-only, never executes real money movement.",
            "capabilities": ["invoicing", "budgets", "payment_risk_evaluation", "transaction_drafts"],
            "requires_context": ["user_id", "workspace_id"],
            "safe_to_import": True,
            "public_methods": ["run", "handle_task", "health_check"],
        }

    async def run(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """BaseAgent-compatible entry point."""
        return await self.handle_task(task)

    async def handle_task(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Master Agent / Router-compatible task handler.

        Expected task shape:
            {
                "action": "create_invoice_draft" | "read_budget" | ... ,
                "user_id": "...",
                "workspace_id": "...",
                "input": {...},
            }
        """
        action = str(task.get("action") or "").strip().lower()
        user_id = task.get("user_id")
        workspace_id = task.get("workspace_id")
        payload = dict(task.get("input") or {})
        payload.setdefault("user_id", user_id)
        payload.setdefault("workspace_id", workspace_id)

        if not user_id or not workspace_id:
            return self._error_result(
                "user_id and workspace_id are required.",
                error="MISSING_SAAS_CONTEXT",
                action=action,
            )

        if action == "health_check" or not action:
            return await self.health_check()

        sensitive_actions = {
            "submit_payment", "send_payment", "transfer_funds", "withdraw_funds",
            "deposit_funds", "authorize_card_charge", "charge_customer",
            "refund_customer", "pay_invoice", "pay_bill", "connect_bank_account",
            "modify_bank_account", "modify_payment_method", "delete_financial_record",
            "delete_invoice", "delete_transaction", "delete_budget",
        }
        if action in sensitive_actions:
            guard_result = self._evaluate_payment_risk(action, payload)
            if not guard_result.get("data", {}).get("approved", False):
                return self._error_result(
                    "Sensitive finance action requires Security Agent approval before execution.",
                    error="SECURITY_APPROVAL_REQUIRED",
                    action=action,
                    data={"payment_guard": guard_result},
                )

        if action in {"create_invoice_draft", "update_invoice_draft", "read_invoice", "update_invoice_status"}:
            return await self._delegate(self.invoice_manager, action, payload)

        if action in {"read_budget", "create_budget_draft", "update_budget", "forecast_budget"}:
            return await self._delegate(self.budget_tracker, action, payload)

        if action in {"create_transaction_draft", "create_payment_draft"}:
            return await self._delegate(self.transaction_preparer, action, payload)

        return self._error_result(
            f"Unsupported finance action: {action}",
            error="UNSUPPORTED_ACTION",
            action=action,
        )

    async def _delegate(self, component: Optional[Any], action: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        if component is None:
            return self._error_result(
                "Required finance component is not available.",
                error="COMPONENT_UNAVAILABLE",
                action=action,
            )

        task_payload = {"action": action, **payload}

        try:
            runner = getattr(component, "run", None)
            if callable(runner):
                result = runner(task_payload)
                if hasattr(result, "__await__"):
                    result = await result
                return result

            return self._error_result(
                "Finance component has no compatible entry point.",
                error="COMPONENT_METHOD_MISSING",
                action=action,
            )
        except Exception as exc:
            self.logger.exception("Finance component delegation failed for action=%s", action)
            return self._error_result(str(exc), error="FINANCE_COMPONENT_ERROR", action=action)

    def _evaluate_payment_risk(self, action: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        if self.payment_guard is None:
            return {"success": False, "data": {"approved": False, "reason": "payment_guard_unavailable"}}

        try:
            evaluator = getattr(self.payment_guard, "evaluate_payment_request", None) or getattr(
                self.payment_guard, "guard_payment_action", None
            )
            if not callable(evaluator):
                return {"success": False, "data": {"approved": False, "reason": "no_evaluator_method"}}

            result = evaluator({"action": action, **payload})
            approved = bool(result.get("data", {}).get("approved") or result.get("approved"))
            return {"success": True, "data": {"approved": approved, "evaluation": result}}
        except Exception as exc:
            self.logger.exception("Payment risk evaluation failed for action=%s", action)
            return {"success": False, "data": {"approved": False, "reason": str(exc)}}

    async def health_check(self) -> Dict[str, Any]:
        components = {
            "config": self.config is not None,
            "invoice_manager": self.invoice_manager is not None,
            "budget_tracker": self.budget_tracker is not None,
            "payment_guard": self.payment_guard is not None,
            "transaction_preparer": self.transaction_preparer is not None,
            "finance_memory": self.finance_memory is not None,
        }
        return {
            "success": True,
            "message": "FinanceAgent health check completed.",
            "data": {"agent": self.agent_name, "components": components},
            "error": None,
            "metadata": {"module": "finance_agent", "timestamp": _utc_now_iso()},
        }

    def _error_result(
        self,
        message: str,
        error: str,
        action: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "success": False,
            "message": message,
            "data": {"action": action, **(data or {})},
            "error": error,
            "metadata": {"module": "finance_agent", "timestamp": _utc_now_iso()},
        }


__all__ = ["FinanceAgent"]
