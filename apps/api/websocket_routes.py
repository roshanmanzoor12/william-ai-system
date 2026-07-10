"""
apps/api/websocket_routes.py

Realtime WebSocket layer for William / Jarvis Multi-Agent SaaS System.

Responsibilities:
- Real-time task progress streaming
- Agent event broadcasting
- User/workspace isolated WebSocket sessions
- Secure message routing (Security Agent compatible)
- Memory + Audit + Verification compatible event emission
- Master Agent event propagation bridge
"""

from __future__ import annotations

import json
import asyncio
import logging
from typing import Dict, Any, List, Optional, Set, Callable
from datetime import datetime

# Safe FastAPI WebSocket import (fallback-safe)
try:
    from fastapi import WebSocket, WebSocketDisconnect, APIRouter
    FASTAPI_AVAILABLE = True
except Exception:
    FASTAPI_AVAILABLE = False
    WebSocket = object  # type: ignore
    WebSocketDisconnect = Exception  # type: ignore
    APIRouter = object  # type: ignore


logger = logging.getLogger("websocket_routes")


class ConnectionManager:
    """
    Manages active WebSocket connections with strict
    user_id + workspace_id isolation.
    """

    def __init__(self):
        # Structure: {workspace_id: {user_id: set(WebSocket)}}
        self.active_connections: Dict[str, Dict[str, Set[WebSocket]]] = {}

    async def connect(self, websocket: WebSocket, user_id: str, workspace_id: str):
        """Register new connection"""
        await websocket.accept()

        self.active_connections.setdefault(workspace_id, {})
        self.active_connections[workspace_id].setdefault(user_id, set())
        self.active_connections[workspace_id][user_id].add(websocket)

        logger.info(f"[WS CONNECT] user={user_id} workspace={workspace_id}")

    def disconnect(self, websocket: WebSocket, user_id: str, workspace_id: str):
        """Remove connection safely"""
        try:
            self.active_connections[workspace_id][user_id].discard(websocket)

            if not self.active_connections[workspace_id][user_id]:
                del self.active_connections[workspace_id][user_id]

            if not self.active_connections[workspace_id]:
                del self.active_connections[workspace_id]

            logger.info(f"[WS DISCONNECT] user={user_id} workspace={workspace_id}")

        except KeyError:
            pass

    async def send_personal(self, message: Dict[str, Any], user_id: str, workspace_id: str):
        """Send message to a specific user in workspace"""
        connections = (
            self.active_connections.get(workspace_id, {})
            .get(user_id, set())
        )

        await self._broadcast_to_set(connections, message)

    async def send_workspace(self, message: Dict[str, Any], workspace_id: str):
        """Send message to entire workspace"""
        workspace = self.active_connections.get(workspace_id, {})
        for user_id, connections in workspace.items():
            await self._broadcast_to_set(connections, message)

    async def broadcast_global(self, message: Dict[str, Any]):
        """Send message to all connections"""
        for workspace in self.active_connections.values():
            for connections in workspace.values():
                await self._broadcast_to_set(connections, message)

    async def _broadcast_to_set(self, connections: Set[WebSocket], message: Dict[str, Any]):
        """Internal safe broadcaster"""
        dead_connections = []

        for connection in connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.warning(f"[WS ERROR] Failed send: {e}")
                dead_connections.append(connection)

        for dc in dead_connections:
            connections.discard(dc)


class WebSocketRoutes:
    """
    WebSocketRoutes

    Core realtime event router for:
    - Agent events
    - Task progress
    - System notifications
    - Dashboard streaming
    """

    def __init__(self):
        self.router = APIRouter() if FASTAPI_AVAILABLE else None
        self.manager = ConnectionManager()

        # event subscribers (optional hooks)
        self.event_handlers: List[Callable[[Dict[str, Any]], None]] = []

        if FASTAPI_AVAILABLE:
            self._register_routes()

    # -----------------------------
    # ROUTES
    # -----------------------------
    def _register_routes(self):
        """Register websocket endpoints"""

        @self.router.websocket("/ws/{workspace_id}/{user_id}")
        async def websocket_endpoint(websocket: WebSocket, workspace_id: str, user_id: str):
            await self.manager.connect(websocket, user_id, workspace_id)

            try:
                while True:
                    data = await websocket.receive_text()
                    await self._handle_incoming_message(
                        websocket, user_id, workspace_id, data
                    )

            except WebSocketDisconnect:
                self.manager.disconnect(websocket, user_id, workspace_id)

            except Exception as e:
                logger.error(f"[WS ERROR] {e}")
                self.manager.disconnect(websocket, user_id, workspace_id)

    # -----------------------------
    # MESSAGE HANDLING
    # -----------------------------
    async def _handle_incoming_message(
        self,
        websocket: WebSocket,
        user_id: str,
        workspace_id: str,
        raw_message: str
    ):
        """Process incoming client messages"""

        try:
            message = json.loads(raw_message)
        except Exception:
            message = {"type": "raw", "content": raw_message}

        event = {
            "type": message.get("type", "unknown"),
            "user_id": user_id,
            "workspace_id": workspace_id,
            "timestamp": datetime.utcnow().isoformat(),
            "payload": message.get("payload", {}),
        }

        # Hook to external agents (Master Agent / Memory / Audit)
        await self._emit_agent_event(event)

        # Echo response (safe ack)
        await websocket.send_json({
            "success": True,
            "message": "event received",
            "data": event
        })

    # -----------------------------
    # PUBLIC EMITTERS
    # -----------------------------
    async def emit_task_progress(
        self,
        user_id: str,
        workspace_id: str,
        task_id: str,
        progress: float,
        status: str,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """Emit task progress updates"""

        payload = {
            "type": "task_progress",
            "task_id": task_id,
            "progress": progress,
            "status": status,
            "metadata": metadata or {},
            "timestamp": datetime.utcnow().isoformat()
        }

        await self.manager.send_personal(payload, user_id, workspace_id)

    async def emit_agent_event(
        self,
        workspace_id: str,
        agent_name: str,
        event_type: str,
        data: Dict[str, Any]
    ):
        """Emit agent-level event"""

        payload = {
            "type": "agent_event",
            "agent": agent_name,
            "event_type": event_type,
            "data": data,
            "timestamp": datetime.utcnow().isoformat()
        }

        await self.manager.send_workspace(payload, workspace_id)

    async def emit_notification(
        self,
        workspace_id: str,
        user_id: Optional[str],
        title: str,
        message: str,
        level: str = "info"
    ):
        """Emit system notification"""

        payload = {
            "type": "notification",
            "title": title,
            "message": message,
            "level": level,
            "timestamp": datetime.utcnow().isoformat()
        }

        if user_id:
            await self.manager.send_personal(payload, user_id, workspace_id)
        else:
            await self.manager.send_workspace(payload, workspace_id)

    # -----------------------------
    # INTERNAL HOOK SYSTEM
    # -----------------------------
    async def _emit_agent_event(self, event: Dict[str, Any]):
        """
        Internal pipeline hook:
        - Master Agent routing
        - Memory Agent storage
        - Audit logging
        - Verification preparation
        """

        logger.info(f"[WS EVENT] {event}")

        for handler in self.event_handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(event)
                else:
                    handler(event)
            except Exception as e:
                logger.error(f"[WS HANDLER ERROR] {e}")

    # -----------------------------
    # EXTENSION HOOKS
    # -----------------------------
    def register_event_handler(self, handler: Callable[[Dict[str, Any]], None]):
        """Register external subscriber (Master Agent / plugins)"""
        self.event_handlers.append(handler)

    # -----------------------------
    # SAFETY / VALIDATION PLACEHOLDERS
    # -----------------------------
    def _validate_task_context(self, user_id: str, workspace_id: str) -> bool:
        return bool(user_id and workspace_id)

    def _requires_security_check(self, event_type: str) -> bool:
        return event_type in ["sensitive_action", "billing", "auth"]

    def _safe_result(self, data: Any) -> Dict[str, Any]:
        return {
            "success": True,
            "data": data,
            "error": None,
            "metadata": {
                "timestamp": datetime.utcnow().isoformat()
            }
        }

    def _error_result(self, error: str) -> Dict[str, Any]:
        return {
            "success": False,
            "data": None,
            "error": error,
            "metadata": {
                "timestamp": datetime.utcnow().isoformat()
            }
        }

    # -----------------------------
    # ROUTER ACCESS
    # -----------------------------
    def get_router(self):
        """Expose FastAPI router"""
        return self.router