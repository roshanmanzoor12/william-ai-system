"""
agents/code_agent/git_manager.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Git status, diff, branch, commit, rollback with approval.

This file is designed for the Code Agent module and is compatible with:
    - BaseAgent
    - Agent Registry
    - Agent Loader
    - Agent Router
    - Master Agent routing
    - Security Agent approvals
    - Verification Agent payloads
    - Memory Agent context payloads
    - Dashboard/API audit logs and analytics

Safety Rules:
    - Read-only Git actions are allowed after context/path validation.
    - Write/destructive Git actions require Security Agent approval.
    - Never run Git commands outside the user's isolated workspace.
    - Never mix files, logs, memory, analytics, or audit data across users/workspaces.
    - Always return structured dict results.
    - Import safely even if future William modules do not exist yet.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
import sys
import time
import uuid
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Optional William/Jarvis imports with safe fallbacks
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        Keeps this file import-safe while the full William/Jarvis system is
        still being generated.
        """

        agent_name: str = "base_agent"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)


try:
    from agents.security_agent.security_agent import SecurityAgent  # type: ignore
except Exception:
    SecurityAgent = None  # type: ignore


try:
    from agents.verification_agent.verification_agent import VerificationAgent  # type: ignore
except Exception:
    VerificationAgent = None  # type: ignore


try:
    from agents.memory_agent.memory_agent import MemoryAgent  # type: ignore
except Exception:
    MemoryAgent = None  # type: ignore


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class GitTaskContext:
    """
    SaaS execution context.

    Every user/workspace Git action must be bound to this context so the
    system never mixes repositories, logs, memory, analytics, or audit records.
    """

    user_id: Union[int, str]
    workspace_id: Union[int, str]
    actor_id: Optional[Union[int, str]] = None
    role: Optional[str] = None
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GitManagerPolicy:
    """
    Safety policy for GitManager.

    Read operations:
        status, diff, log, branch list, current branch

    Sensitive write operations:
        init, add, commit, checkout, switch, branch create/delete,
        reset, revert, clean, merge, rebase, tag, push, pull, fetch
    """

    default_timeout_seconds: int = 90
    max_timeout_seconds: int = 600
    max_output_chars: int = 100_000

    allow_git_init: bool = True
    allow_branch_create: bool = True
    allow_branch_delete: bool = False
    allow_commit: bool = True
    allow_rollback: bool = True
    allow_remote_operations: bool = False

    require_security_for_init: bool = True
    require_security_for_add: bool = True
    require_security_for_commit: bool = True
    require_security_for_checkout: bool = True
    require_security_for_branch_write: bool = True
    require_security_for_rollback: bool = True
    require_security_for_remote_operations: bool = True

    blocked_patterns: List[str] = field(default_factory=lambda: [
        r"\bgit\s+push\b",
        r"\bgit\s+pull\b",
        r"\bgit\s+fetch\b",
        r"\bgit\s+remote\b",
        r"\bgit\s+clean\s+-fdx\b",
        r"\bgit\s+reset\s+--hard\b",
        r"\bgit\s+rebase\b",
        r"\bgit\s+filter-branch\b",
        r"\bgit\s+gc\s+--prune\b",
        r"\bgit\s+submodule\b",
        r"\bgit\s+worktree\b",
    ])

    allowed_read_subcommands: List[str] = field(default_factory=lambda: [
        "status",
        "diff",
        "log",
        "branch",
        "rev-parse",
        "show",
        "ls-files",
        "describe",
    ])

    allowed_write_subcommands: List[str] = field(default_factory=lambda: [
        "init",
        "add",
        "commit",
        "checkout",
        "switch",
        "branch",
        "reset",
        "revert",
        "merge",
        "tag",
    ])


# ---------------------------------------------------------------------------
# GitManager
# ---------------------------------------------------------------------------

class GitManager(BaseAgent):
    """
    Safe Git operations manager for William/Jarvis Code Agent.

    Public methods:
        - git_status()
        - git_diff()
        - git_log()
        - current_branch()
        - list_branches()
        - create_branch()
        - checkout_branch()
        - init_repo()
        - add_files()
        - commit()
        - rollback()
        - revert_commit()
        - run_git_command()

    How it connects to the wider system:
        - Master Agent routes Git tasks here.
        - Security Agent approves sensitive Git write/destructive actions.
        - Verification Agent receives verification payloads after actions.
        - Memory Agent receives useful Git context.
        - Dashboard/API receives events and audit logs.
    """

    agent_name = "code_agent.git_manager"

    def __init__(
        self,
        base_dir: Optional[Union[str, Path]] = None,
        policy: Optional[GitManagerPolicy] = None,
        security_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        agent_name: Optional[str] = None,
    ) -> None:
        super().__init__(agent_name=agent_name or self.agent_name)

        self.base_dir = Path(base_dir or os.getcwd()).resolve()
        self.policy = policy or GitManagerPolicy()

        self.security_agent = security_agent
        self.verification_agent = verification_agent
        self.memory_agent = memory_agent

        self.event_callback = event_callback
        self.audit_callback = audit_callback

        self.base_dir.mkdir(parents=True, exist_ok=True)

    # -----------------------------------------------------------------------
    # Structured result helpers
    # -----------------------------------------------------------------------

    def _safe_result(
        self,
        success: bool,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Union[str, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "success": bool(success),
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": metadata or {},
            "timestamp": self._now(),
            "agent": self.agent_name,
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Union[str, Dict[str, Any]]] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self._safe_result(
            success=False,
            message=message,
            data=data or {},
            error=error or message,
            metadata=metadata or {},
        )

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # -----------------------------------------------------------------------
    # SaaS context and workspace isolation
    # -----------------------------------------------------------------------

    def _validate_task_context(
        self,
        context: Union[GitTaskContext, Dict[str, Any]],
    ) -> Tuple[bool, Optional[GitTaskContext], Optional[str]]:
        """
        Validate user_id and workspace_id for SaaS isolation.
        """

        if isinstance(context, GitTaskContext):
            ctx = context
        elif isinstance(context, dict):
            try:
                ctx = GitTaskContext(
                    user_id=context.get("user_id"),
                    workspace_id=context.get("workspace_id"),
                    actor_id=context.get("actor_id"),
                    role=context.get("role"),
                    request_id=context.get("request_id") or str(uuid.uuid4()),
                    session_id=context.get("session_id"),
                    metadata=context.get("metadata") or {},
                )
            except Exception as exc:
                return False, None, f"Invalid context format: {exc}"
        else:
            return False, None, "Context must be GitTaskContext or dict."

        if ctx.user_id is None or str(ctx.user_id).strip() == "":
            return False, None, "Missing required user_id."

        if ctx.workspace_id is None or str(ctx.workspace_id).strip() == "":
            return False, None, "Missing required workspace_id."

        return True, ctx, None

    def _workspace_root(self, context: GitTaskContext) -> Path:
        """
        Return isolated workspace root:

            base_dir/workspaces/{user_id}/{workspace_id}
        """

        safe_user = self._safe_path_part(str(context.user_id))
        safe_workspace = self._safe_path_part(str(context.workspace_id))
        root = self.base_dir / "workspaces" / safe_user / safe_workspace
        root.mkdir(parents=True, exist_ok=True)
        return root.resolve()

    @staticmethod
    def _safe_path_part(value: str) -> str:
        value = value.strip()
        value = re.sub(r"[^a-zA-Z0-9_.-]", "_", value)
        return value[:120] or "unknown"

    def _resolve_repo_path(
        self,
        context: GitTaskContext,
        repo_path: Optional[Union[str, Path]] = None,
        create: bool = True,
    ) -> Tuple[bool, Optional[Path], Optional[str]]:
        """
        Resolve a repo path safely inside the user's workspace root.
        """

        workspace_root = self._workspace_root(context)

        if repo_path is None:
            resolved = workspace_root
        else:
            raw_path = Path(repo_path)
            if raw_path.is_absolute():
                resolved = raw_path.resolve()
            else:
                resolved = (workspace_root / raw_path).resolve()

        try:
            resolved.relative_to(workspace_root)
        except ValueError:
            return (
                False,
                None,
                f"Repository path is outside isolated workspace: {resolved}",
            )

        if create:
            resolved.mkdir(parents=True, exist_ok=True)

        return True, resolved, None

    # -----------------------------------------------------------------------
    # Security hooks
    # -----------------------------------------------------------------------

    def _requires_security_check(
        self,
        action_type: str,
        command: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, str]:
        """
        Determine whether an action must go through Security Agent.
        """

        metadata = metadata or {}
        command_text = self._command_to_text(command or [])

        if metadata.get("requires_security") is True:
            return True, "metadata_requires_security"

        action_type = action_type.lower().strip()

        if action_type == "init" and self.policy.require_security_for_init:
            return True, "git_init_requires_security"

        if action_type == "add" and self.policy.require_security_for_add:
            return True, "git_add_requires_security"

        if action_type == "commit" and self.policy.require_security_for_commit:
            return True, "git_commit_requires_security"

        if action_type in {"checkout", "switch"} and self.policy.require_security_for_checkout:
            return True, "git_checkout_requires_security"

        if action_type in {"branch_create", "branch_delete"} and self.policy.require_security_for_branch_write:
            return True, "git_branch_write_requires_security"

        if action_type in {"rollback", "reset", "revert"} and self.policy.require_security_for_rollback:
            return True, "git_rollback_requires_security"

        if action_type in {"push", "pull", "fetch", "remote"} and self.policy.require_security_for_remote_operations:
            return True, "git_remote_operation_requires_security"

        for pattern in self.policy.blocked_patterns:
            if re.search(pattern, command_text, flags=re.IGNORECASE):
                return True, f"blocked_or_sensitive_pattern:{pattern}"

        return False, "not_required"

    def _request_security_approval(
        self,
        context: GitTaskContext,
        action: str,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        Safe fallback:
            If Security Agent is unavailable, sensitive actions are denied
            unless approved_by_security=True is explicitly provided by a
            trusted caller.
        """

        approval_payload = {
            "approval_id": str(uuid.uuid4()),
            "agent": self.agent_name,
            "action": action,
            "context": asdict(context),
            "payload": payload,
            "timestamp": self._now(),
        }

        if self.security_agent and hasattr(self.security_agent, "approve_action"):
            try:
                decision = self.security_agent.approve_action(approval_payload)
                if isinstance(decision, dict):
                    return decision
            except Exception as exc:
                return {
                    "approved": False,
                    "reason": f"Security Agent approval failed: {exc}",
                    "source": "security_agent_exception",
                }

        if payload.get("approved_by_security") is True:
            return {
                "approved": True,
                "reason": "Pre-approved by trusted caller payload.",
                "source": "payload_flag",
            }

        return {
            "approved": False,
            "reason": "Security Agent unavailable or approval missing.",
            "source": "safe_default_deny",
        }

    # -----------------------------------------------------------------------
    # Public Git methods
    # -----------------------------------------------------------------------

    def git_status(
        self,
        context: Union[GitTaskContext, Dict[str, Any]],
        repo_path: Optional[Union[str, Path]] = None,
        short: bool = False,
        branch: bool = True,
    ) -> Dict[str, Any]:
        command = ["git", "status"]

        if short:
            command.append("--short")
        if branch:
            command.append("--branch")

        result = self.run_git_command(
            command=command,
            context=context,
            repo_path=repo_path,
            action_type="status",
            read_only=True,
        )

        if result.get("success"):
            result["data"]["parsed_status"] = self._parse_status(result["data"].get("stdout", ""))

        return result

    def git_diff(
        self,
        context: Union[GitTaskContext, Dict[str, Any]],
        repo_path: Optional[Union[str, Path]] = None,
        staged: bool = False,
        file_path: Optional[str] = None,
        stat: bool = False,
    ) -> Dict[str, Any]:
        command = ["git", "diff"]

        if staged:
            command.append("--staged")

        if stat:
            command.append("--stat")

        if file_path:
            safe_file = self._validate_relative_file_path(file_path)
            if not safe_file[0]:
                return self._error_result(
                    message="Invalid file path.",
                    error=safe_file[1],
                )
            command.extend(["--", file_path])

        return self.run_git_command(
            command=command,
            context=context,
            repo_path=repo_path,
            action_type="diff",
            read_only=True,
        )

    def git_log(
        self,
        context: Union[GitTaskContext, Dict[str, Any]],
        repo_path: Optional[Union[str, Path]] = None,
        limit: int = 20,
        oneline: bool = True,
    ) -> Dict[str, Any]:
        limit = max(1, min(int(limit or 20), 100))

        command = ["git", "log", f"-{limit}"]

        if oneline:
            command.append("--oneline")
        else:
            command.extend([
                "--pretty=format:%H%x09%an%x09%ae%x09%ad%x09%s",
                "--date=iso",
            ])

        result = self.run_git_command(
            command=command,
            context=context,
            repo_path=repo_path,
            action_type="log",
            read_only=True,
        )

        if result.get("success"):
            result["data"]["commits"] = self._parse_log(result["data"].get("stdout", ""), oneline=oneline)

        return result

    def current_branch(
        self,
        context: Union[GitTaskContext, Dict[str, Any]],
        repo_path: Optional[Union[str, Path]] = None,
    ) -> Dict[str, Any]:
        result = self.run_git_command(
            command=["git", "rev-parse", "--abbrev-ref", "HEAD"],
            context=context,
            repo_path=repo_path,
            action_type="current_branch",
            read_only=True,
        )

        if result.get("success"):
            result["data"]["current_branch"] = result["data"].get("stdout", "").strip()

        return result

    def list_branches(
        self,
        context: Union[GitTaskContext, Dict[str, Any]],
        repo_path: Optional[Union[str, Path]] = None,
        include_remote: bool = False,
    ) -> Dict[str, Any]:
        command = ["git", "branch"]

        if include_remote:
            command.append("--all")

        result = self.run_git_command(
            command=command,
            context=context,
            repo_path=repo_path,
            action_type="branch",
            read_only=True,
        )

        if result.get("success"):
            result["data"]["branches"] = self._parse_branches(result["data"].get("stdout", ""))

        return result

    def init_repo(
        self,
        context: Union[GitTaskContext, Dict[str, Any]],
        repo_path: Optional[Union[str, Path]] = None,
        default_branch: str = "main",
        approved_by_security: bool = False,
    ) -> Dict[str, Any]:
        if not self.policy.allow_git_init:
            return self._error_result(
                message="Git init is disabled by policy.",
                error="git_init_disabled",
            )

        valid_branch, branch_error = self._validate_branch_name(default_branch)
        if not valid_branch:
            return self._error_result(
                message="Invalid default branch name.",
                error=branch_error,
            )

        command = ["git", "init", "-b", default_branch]

        return self.run_git_command(
            command=command,
            context=context,
            repo_path=repo_path,
            action_type="init",
            read_only=False,
            approved_by_security=approved_by_security,
        )

    def create_branch(
        self,
        context: Union[GitTaskContext, Dict[str, Any]],
        branch_name: str,
        repo_path: Optional[Union[str, Path]] = None,
        checkout: bool = False,
        approved_by_security: bool = False,
    ) -> Dict[str, Any]:
        if not self.policy.allow_branch_create:
            return self._error_result(
                message="Branch creation is disabled by policy.",
                error="branch_create_disabled",
            )

        valid, error = self._validate_branch_name(branch_name)
        if not valid:
            return self._error_result(
                message="Invalid branch name.",
                error=error,
            )

        command = ["git", "checkout", "-b", branch_name] if checkout else ["git", "branch", branch_name]

        return self.run_git_command(
            command=command,
            context=context,
            repo_path=repo_path,
            action_type="branch_create",
            read_only=False,
            approved_by_security=approved_by_security,
        )

    def checkout_branch(
        self,
        context: Union[GitTaskContext, Dict[str, Any]],
        branch_name: str,
        repo_path: Optional[Union[str, Path]] = None,
        create: bool = False,
        approved_by_security: bool = False,
    ) -> Dict[str, Any]:
        valid, error = self._validate_branch_name(branch_name)
        if not valid:
            return self._error_result(
                message="Invalid branch name.",
                error=error,
            )

        command = ["git", "checkout", "-b", branch_name] if create else ["git", "checkout", branch_name]

        return self.run_git_command(
            command=command,
            context=context,
            repo_path=repo_path,
            action_type="checkout",
            read_only=False,
            approved_by_security=approved_by_security,
        )

    def add_files(
        self,
        context: Union[GitTaskContext, Dict[str, Any]],
        files: Optional[List[str]] = None,
        repo_path: Optional[Union[str, Path]] = None,
        approved_by_security: bool = False,
    ) -> Dict[str, Any]:
        files = files or ["."]

        safe_files: List[str] = []
        for file_item in files:
            valid, error = self._validate_relative_file_path(file_item, allow_dot=True)
            if not valid:
                return self._error_result(
                    message="Invalid file path.",
                    error=error,
                    data={"file": file_item},
                )
            safe_files.append(file_item)

        command = ["git", "add", "--"] + safe_files

        return self.run_git_command(
            command=command,
            context=context,
            repo_path=repo_path,
            action_type="add",
            read_only=False,
            approved_by_security=approved_by_security,
        )

    def commit(
        self,
        context: Union[GitTaskContext, Dict[str, Any]],
        message: str,
        repo_path: Optional[Union[str, Path]] = None,
        files: Optional[List[str]] = None,
        add_before_commit: bool = True,
        approved_by_security: bool = False,
        author_name: Optional[str] = None,
        author_email: Optional[str] = None,
    ) -> Dict[str, Any]:
        clean_message = self._validate_commit_message(message)
        if not clean_message[0]:
            return self._error_result(
                message="Invalid commit message.",
                error=clean_message[1],
            )

        valid, ctx, ctx_error = self._validate_task_context(context)
        if not valid or ctx is None:
            return self._error_result(
                message="Invalid task context.",
                error=ctx_error,
            )

        if add_before_commit:
            add_result = self.add_files(
                context=ctx,
                files=files or ["."],
                repo_path=repo_path,
                approved_by_security=approved_by_security,
            )
            if not add_result.get("success"):
                return self._error_result(
                    message="Failed to add files before commit.",
                    error=add_result.get("error"),
                    data={"add_result": add_result},
                    metadata={"context": asdict(ctx)},
                )

        command = ["git"]

        if author_name or author_email:
            author = self._build_author(author_name, author_email)
            if author:
                command.extend(["-c", f"user.name={author['name']}"])
                command.extend(["-c", f"user.email={author['email']}"])

        command.extend(["commit", "-m", message.strip()])

        return self.run_git_command(
            command=command,
            context=ctx,
            repo_path=repo_path,
            action_type="commit",
            read_only=False,
            approved_by_security=approved_by_security,
            metadata={
                "message": message.strip(),
                "add_before_commit": add_before_commit,
                "files": files or ["."],
            },
        )

    def rollback(
        self,
        context: Union[GitTaskContext, Dict[str, Any]],
        repo_path: Optional[Union[str, Path]] = None,
        mode: str = "soft",
        target: str = "HEAD~1",
        approved_by_security: bool = False,
    ) -> Dict[str, Any]:
        """
        Rollback repository state using git reset.

        Modes:
            soft  -> keep staged changes
            mixed -> keep working tree changes, unstage
            hard  -> discard changes, requires approval

        All rollback actions require Security Agent approval by default.
        """

        if not self.policy.allow_rollback:
            return self._error_result(
                message="Rollback is disabled by policy.",
                error="rollback_disabled",
            )

        mode = mode.lower().strip()
        if mode not in {"soft", "mixed", "hard"}:
            return self._error_result(
                message="Invalid rollback mode.",
                error="mode must be one of: soft, mixed, hard",
            )

        valid_target, target_error = self._validate_git_ref(target)
        if not valid_target:
            return self._error_result(
                message="Invalid rollback target.",
                error=target_error,
            )

        command = ["git", "reset", f"--{mode}", target]

        return self.run_git_command(
            command=command,
            context=context,
            repo_path=repo_path,
            action_type="rollback",
            read_only=False,
            approved_by_security=approved_by_security,
            metadata={
                "rollback_mode": mode,
                "target": target,
                "destructive": mode == "hard",
            },
        )

    def revert_commit(
        self,
        context: Union[GitTaskContext, Dict[str, Any]],
        commit_ref: str,
        repo_path: Optional[Union[str, Path]] = None,
        no_edit: bool = True,
        approved_by_security: bool = False,
    ) -> Dict[str, Any]:
        """
        Revert a commit safely by creating a new revert commit.
        """

        valid_ref, ref_error = self._validate_git_ref(commit_ref)
        if not valid_ref:
            return self._error_result(
                message="Invalid commit reference.",
                error=ref_error,
            )

        command = ["git", "revert"]
        if no_edit:
            command.append("--no-edit")
        command.append(commit_ref)

        return self.run_git_command(
            command=command,
            context=context,
            repo_path=repo_path,
            action_type="revert",
            read_only=False,
            approved_by_security=approved_by_security,
        )

    # -----------------------------------------------------------------------
    # Core command runner
    # -----------------------------------------------------------------------

    def run_git_command(
        self,
        command: Union[str, List[str]],
        context: Union[GitTaskContext, Dict[str, Any]],
        repo_path: Optional[Union[str, Path]] = None,
        action_type: str = "git",
        read_only: bool = False,
        timeout: Optional[int] = None,
        approved_by_security: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Run a validated Git command inside the user's isolated workspace.
        """

        started = time.time()
        metadata = metadata or {}

        valid, ctx, ctx_error = self._validate_task_context(context)
        if not valid or ctx is None:
            return self._error_result(
                message="Invalid task context.",
                error=ctx_error,
                metadata={"action_type": action_type},
            )

        try:
            command_list = self._normalize_command(command)

            safety_ok, safety_error = self._validate_git_command(
                command_list=command_list,
                read_only=read_only,
                action_type=action_type,
            )
            if not safety_ok:
                self._log_audit_event(
                    context=ctx,
                    action="git.command.blocked",
                    payload={
                        "command": command_list,
                        "reason": safety_error,
                        "action_type": action_type,
                    },
                )
                return self._error_result(
                    message="Git command blocked by policy.",
                    error=safety_error,
                    data={"command": command_list},
                    metadata={"context": asdict(ctx), "action_type": action_type},
                )

            repo_ok, resolved_repo, repo_error = self._resolve_repo_path(
                context=ctx,
                repo_path=repo_path,
                create=True,
            )
            if not repo_ok or resolved_repo is None:
                return self._error_result(
                    message="Invalid repository path.",
                    error=repo_error,
                    metadata={"context": asdict(ctx), "action_type": action_type},
                )

            requires_security, security_reason = self._requires_security_check(
                action_type=action_type,
                command=command_list,
                metadata=metadata,
            )

            if requires_security and not read_only:
                approval = self._request_security_approval(
                    context=ctx,
                    action=f"git.{action_type}",
                    payload={
                        "command": command_list,
                        "repo_path": str(resolved_repo),
                        "action_type": action_type,
                        "approved_by_security": approved_by_security,
                        "security_reason": security_reason,
                        "metadata": metadata,
                    },
                )
                if not approval.get("approved"):
                    self._log_audit_event(
                        context=ctx,
                        action="git.command.denied",
                        payload={
                            "command": command_list,
                            "repo_path": str(resolved_repo),
                            "action_type": action_type,
                            "approval": approval,
                        },
                    )
                    return self._error_result(
                        message="Git action requires Security Agent approval.",
                        error=approval.get("reason"),
                        data={
                            "approval": approval,
                            "security_reason": security_reason,
                            "command": command_list,
                        },
                        metadata={"context": asdict(ctx), "action_type": action_type},
                    )

            timeout_seconds = self._safe_timeout(timeout)

            self._emit_agent_event(
                context=ctx,
                event_type="git.command.started",
                payload={
                    "command": command_list,
                    "repo_path": str(resolved_repo),
                    "action_type": action_type,
                    "read_only": read_only,
                },
            )

            env = self._build_safe_env(ctx)

            completed = subprocess.run(
                command_list,
                cwd=str(resolved_repo),
                env=env,
                text=True,
                capture_output=True,
                timeout=timeout_seconds,
                shell=False,
            )

            duration_ms = int((time.time() - started) * 1000)

            stdout = self._truncate_output(completed.stdout or "")
            stderr = self._truncate_output(completed.stderr or "")

            result_data = {
                "command": command_list,
                "command_text": self._command_to_text(command_list),
                "repo_path": str(resolved_repo),
                "return_code": completed.returncode,
                "stdout": stdout,
                "stderr": stderr,
                "duration_ms": duration_ms,
                "timeout_seconds": timeout_seconds,
                "action_type": action_type,
                "read_only": read_only,
            }

            success = completed.returncode == 0

            verification_payload = self._prepare_verification_payload(
                context=ctx,
                action=f"git.{action_type}",
                result_data=result_data,
                success=success,
            )

            memory_payload = self._prepare_memory_payload(
                context=ctx,
                action=f"git.{action_type}",
                result_data=result_data,
                success=success,
            )

            self._log_audit_event(
                context=ctx,
                action="git.command.completed",
                payload={
                    "command": command_list,
                    "repo_path": str(resolved_repo),
                    "return_code": completed.returncode,
                    "duration_ms": duration_ms,
                    "action_type": action_type,
                    "success": success,
                },
            )

            self._emit_agent_event(
                context=ctx,
                event_type="git.command.completed",
                payload={
                    "command": command_list,
                    "return_code": completed.returncode,
                    "duration_ms": duration_ms,
                    "action_type": action_type,
                    "success": success,
                },
            )

            return self._safe_result(
                success=success,
                message="Git command completed successfully." if success else "Git command completed with errors.",
                data=result_data,
                error=None if success else stderr or f"Git command failed with return code {completed.returncode}",
                metadata={
                    "context": asdict(ctx),
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                    "security_required": requires_security,
                    "security_reason": security_reason,
                    "action_type": action_type,
                },
            )

        except subprocess.TimeoutExpired as exc:
            duration_ms = int((time.time() - started) * 1000)
            return self._error_result(
                message="Git command timed out.",
                error=str(exc),
                data={
                    "stdout": self._truncate_output(exc.stdout or ""),
                    "stderr": self._truncate_output(exc.stderr or ""),
                    "duration_ms": duration_ms,
                },
                metadata={"context": asdict(ctx), "action_type": action_type},
            )

        except FileNotFoundError as exc:
            return self._error_result(
                message="Git executable not found. Please install Git.",
                error=str(exc),
                metadata={"context": asdict(ctx), "action_type": action_type},
            )

        except Exception as exc:
            logger.exception("Git command failed.")
            return self._error_result(
                message="Git command failed.",
                error=str(exc),
                metadata={"context": asdict(ctx), "action_type": action_type},
            )

    # -----------------------------------------------------------------------
    # Validation helpers
    # -----------------------------------------------------------------------

    def _normalize_command(self, command: Union[str, List[str]]) -> List[str]:
        if isinstance(command, str):
            command_list = shlex.split(command, posix=os.name != "nt")
        elif isinstance(command, list):
            command_list = [str(part) for part in command]
        else:
            raise ValueError("Command must be a string or list.")

        if not command_list:
            raise ValueError("Command cannot be empty.")

        if command_list[0] != "git":
            raise ValueError("Only git commands are allowed.")

        return command_list

    def _validate_git_command(
        self,
        command_list: List[str],
        read_only: bool,
        action_type: str,
    ) -> Tuple[bool, Optional[str]]:
        if not command_list or command_list[0] != "git":
            return False, "Only git commands are allowed."

        command_text = self._command_to_text(command_list)

        for pattern in self.policy.blocked_patterns:
            if re.search(pattern, command_text, flags=re.IGNORECASE):
                if not self._remote_allowed_for_command(command_list):
                    return False, f"Blocked Git pattern: {pattern}"

        if len(command_list) < 2:
            return False, "Missing Git subcommand."

        subcommand = command_list[1].lower().strip()

        if subcommand.startswith("-"):
            # Allows commands like git -c user.name=... commit -m ...
            subcommand = self._find_real_subcommand(command_list)
            if not subcommand:
                return False, "Could not determine Git subcommand."

        if read_only:
            if subcommand not in self.policy.allowed_read_subcommands:
                return False, f"Git subcommand is not read-only allowed: {subcommand}"
        else:
            allowed = set(self.policy.allowed_read_subcommands) | set(self.policy.allowed_write_subcommands)
            if subcommand not in allowed:
                return False, f"Git subcommand is not allowed: {subcommand}"

        if subcommand in {"push", "pull", "fetch", "remote"} and not self.policy.allow_remote_operations:
            return False, "Remote Git operations are disabled by policy."

        if subcommand == "branch" and "-d" in command_list and not self.policy.allow_branch_delete:
            return False, "Branch delete is disabled by policy."

        return True, None

    @staticmethod
    def _find_real_subcommand(command_list: List[str]) -> Optional[str]:
        known = {
            "status", "diff", "log", "branch", "rev-parse", "show", "ls-files",
            "describe", "init", "add", "commit", "checkout", "switch", "reset",
            "revert", "merge", "tag", "push", "pull", "fetch", "remote",
        }
        for item in command_list[1:]:
            item_lower = item.lower().strip()
            if item_lower in known:
                return item_lower
        return None

    def _remote_allowed_for_command(self, command_list: List[str]) -> bool:
        if self.policy.allow_remote_operations:
            return True

        subcommand = self._find_real_subcommand(command_list) or (command_list[1] if len(command_list) > 1 else "")
        return subcommand not in {"push", "pull", "fetch", "remote"}

    @staticmethod
    def _validate_branch_name(branch_name: str) -> Tuple[bool, Optional[str]]:
        branch_name = str(branch_name or "").strip()

        if not branch_name:
            return False, "Branch name cannot be empty."

        if len(branch_name) > 180:
            return False, "Branch name is too long."

        blocked = [
            "..",
            "~",
            "^",
            ":",
            "?",
            "*",
            "[",
            "\\",
            " ",
            "\t",
            "\n",
            "\r",
        ]

        for item in blocked:
            if item in branch_name:
                return False, f"Branch name contains invalid character/sequence: {item!r}"

        if branch_name.startswith("/") or branch_name.endswith("/"):
            return False, "Branch name cannot start or end with slash."

        if branch_name.endswith(".lock"):
            return False, "Branch name cannot end with .lock."

        if branch_name in {"HEAD", "FETCH_HEAD", "ORIG_HEAD"}:
            return False, "Reserved Git reference name."

        return True, None

    @staticmethod
    def _validate_git_ref(ref: str) -> Tuple[bool, Optional[str]]:
        ref = str(ref or "").strip()

        if not ref:
            return False, "Git reference cannot be empty."

        if len(ref) > 200:
            return False, "Git reference is too long."

        if re.search(r"[^a-zA-Z0-9_\-./~^:@{}]", ref):
            return False, "Git reference contains unsafe characters."

        if ".." in ref:
            return False, "Git reference cannot contain '..'."

        return True, None

    @staticmethod
    def _validate_relative_file_path(
        file_path: str,
        allow_dot: bool = False,
    ) -> Tuple[bool, Optional[str]]:
        file_path = str(file_path or "").strip()

        if allow_dot and file_path == ".":
            return True, None

        if not file_path:
            return False, "File path cannot be empty."

        path = Path(file_path)

        if path.is_absolute():
            return False, "Absolute file paths are not allowed."

        if ".." in path.parts:
            return False, "Parent directory traversal is not allowed."

        if re.search(r"[\x00\r\n]", file_path):
            return False, "File path contains invalid control characters."

        return True, None

    @staticmethod
    def _validate_commit_message(message: str) -> Tuple[bool, Optional[str]]:
        message = str(message or "").strip()

        if not message:
            return False, "Commit message cannot be empty."

        if len(message) > 1000:
            return False, "Commit message is too long."

        if "\x00" in message:
            return False, "Commit message contains invalid null byte."

        return True, None

    @staticmethod
    def _build_author(
        author_name: Optional[str],
        author_email: Optional[str],
    ) -> Optional[Dict[str, str]]:
        name = str(author_name or "William Code Agent").strip()
        email = str(author_email or "william-code-agent@local.invalid").strip()

        name = re.sub(r"[\r\n\x00]", "", name)[:120]
        email = re.sub(r"[\r\n\x00]", "", email)[:180]

        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            email = "william-code-agent@local.invalid"

        return {"name": name, "email": email}

    # -----------------------------------------------------------------------
    # Parsing helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _parse_status(stdout: str) -> Dict[str, Any]:
        lines = stdout.splitlines()

        branch = None
        changed_files: List[Dict[str, str]] = []

        for line in lines:
            if line.startswith("## "):
                branch = line.replace("## ", "", 1).strip()
                continue

            if not line.strip():
                continue

            if len(line) >= 3:
                status_code = line[:2]
                path = line[3:].strip()
                changed_files.append({
                    "status": status_code,
                    "path": path,
                })

        return {
            "branch": branch,
            "changed_files": changed_files,
            "changed_count": len(changed_files),
            "clean": len(changed_files) == 0,
        }

    @staticmethod
    def _parse_branches(stdout: str) -> List[Dict[str, Any]]:
        branches = []

        for line in stdout.splitlines():
            raw = line.rstrip()
            if not raw:
                continue

            current = raw.startswith("*")
            name = raw.replace("*", "", 1).strip()

            branches.append({
                "name": name,
                "current": current,
            })

        return branches

    @staticmethod
    def _parse_log(stdout: str, oneline: bool = True) -> List[Dict[str, Any]]:
        commits = []

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue

            if oneline:
                parts = line.split(" ", 1)
                commits.append({
                    "short_hash": parts[0],
                    "message": parts[1] if len(parts) > 1 else "",
                })
            else:
                parts = line.split("\t")
                commits.append({
                    "hash": parts[0] if len(parts) > 0 else "",
                    "author_name": parts[1] if len(parts) > 1 else "",
                    "author_email": parts[2] if len(parts) > 2 else "",
                    "date": parts[3] if len(parts) > 3 else "",
                    "message": parts[4] if len(parts) > 4 else "",
                })

        return commits

    # -----------------------------------------------------------------------
    # Payload hooks
    # -----------------------------------------------------------------------

    def _prepare_verification_payload(
        self,
        context: GitTaskContext,
        action: str,
        result_data: Dict[str, Any],
        success: bool,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent-compatible payload.
        """

        payload = {
            "verification_id": str(uuid.uuid4()),
            "agent": self.agent_name,
            "action": action,
            "success": success,
            "context": asdict(context),
            "result_summary": {
                "command": result_data.get("command"),
                "repo_path": result_data.get("repo_path"),
                "return_code": result_data.get("return_code"),
                "duration_ms": result_data.get("duration_ms"),
                "action_type": result_data.get("action_type"),
                "read_only": result_data.get("read_only"),
            },
            "checks": {
                "git_command_completed": success,
                "workspace_isolated": True,
                "structured_result": True,
                "audit_prepared": True,
            },
            "timestamp": self._now(),
        }

        if self.verification_agent and hasattr(self.verification_agent, "prepare_payload"):
            try:
                maybe_payload = self.verification_agent.prepare_payload(payload)
                if isinstance(maybe_payload, dict):
                    return maybe_payload
            except Exception:
                logger.exception("Verification Agent payload hook failed.")

        return payload

    def _prepare_memory_payload(
        self,
        context: GitTaskContext,
        action: str,
        result_data: Dict[str, Any],
        success: bool,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent-compatible payload.
        """

        payload = {
            "memory_id": str(uuid.uuid4()),
            "agent": self.agent_name,
            "action": action,
            "context": asdict(context),
            "success": success,
            "summary": self._summarize_git_execution(result_data, success),
            "signals": {
                "command": result_data.get("command"),
                "repo_path": result_data.get("repo_path"),
                "return_code": result_data.get("return_code"),
                "action_type": result_data.get("action_type"),
                "read_only": result_data.get("read_only"),
                "has_stdout": bool(result_data.get("stdout")),
                "has_stderr": bool(result_data.get("stderr")),
            },
            "timestamp": self._now(),
        }

        if self.memory_agent and hasattr(self.memory_agent, "prepare_payload"):
            try:
                maybe_payload = self.memory_agent.prepare_payload(payload)
                if isinstance(maybe_payload, dict):
                    return maybe_payload
            except Exception:
                logger.exception("Memory Agent payload hook failed.")

        return payload

    @staticmethod
    def _summarize_git_execution(result_data: Dict[str, Any], success: bool) -> str:
        command_text = result_data.get("command_text") or result_data.get("command")
        action_type = result_data.get("action_type", "git")
        return_code = result_data.get("return_code")
        status = "succeeded" if success else "failed"
        return f"Git {action_type} {status}. Command={command_text}, return_code={return_code}."

    def _emit_agent_event(
        self,
        context: GitTaskContext,
        event_type: str,
        payload: Dict[str, Any],
    ) -> None:
        """
        Emit event for dashboard/API/analytics integrations.
        """

        event = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "agent": self.agent_name,
            "context": asdict(context),
            "payload": payload,
            "timestamp": self._now(),
        }

        if self.event_callback:
            try:
                self.event_callback(event)
            except Exception:
                logger.exception("Event callback failed.")

        logger.info("Agent event: %s", event_type)

    def _log_audit_event(
        self,
        context: GitTaskContext,
        action: str,
        payload: Dict[str, Any],
    ) -> None:
        """
        Log audit event for security, compliance, and dashboard history.
        """

        audit_event = {
            "audit_id": str(uuid.uuid4()),
            "action": action,
            "agent": self.agent_name,
            "context": asdict(context),
            "payload": payload,
            "timestamp": self._now(),
        }

        if self.audit_callback:
            try:
                self.audit_callback(audit_event)
            except Exception:
                logger.exception("Audit callback failed.")

        logger.info("Audit event: %s", action)

    # -----------------------------------------------------------------------
    # Utility helpers
    # -----------------------------------------------------------------------

    def _safe_timeout(self, timeout: Optional[int]) -> int:
        if timeout is None:
            return self.policy.default_timeout_seconds

        try:
            timeout_int = int(timeout)
        except Exception:
            return self.policy.default_timeout_seconds

        if timeout_int <= 0:
            return self.policy.default_timeout_seconds

        return min(timeout_int, self.policy.max_timeout_seconds)

    def _build_safe_env(self, context: GitTaskContext) -> Dict[str, str]:
        env = os.environ.copy()
        env["WILLIAM_USER_ID"] = str(context.user_id)
        env["WILLIAM_WORKSPACE_ID"] = str(context.workspace_id)
        env["WILLIAM_REQUEST_ID"] = str(context.request_id)
        env["WILLIAM_AGENT"] = self.agent_name
        env.setdefault("GIT_TERMINAL_PROMPT", "0")
        return env

    def _truncate_output(self, value: str) -> str:
        value = str(value or "")
        if len(value) <= self.policy.max_output_chars:
            return value

        return (
            value[: self.policy.max_output_chars]
            + "\n\n...[output truncated by GitManager safety policy]..."
        )

    @staticmethod
    def _command_to_text(command: List[str]) -> str:
        return " ".join(shlex.quote(str(part)) for part in command)

    # -----------------------------------------------------------------------
    # Registry / router compatibility
    # -----------------------------------------------------------------------

    def get_capabilities(self) -> Dict[str, Any]:
        """
        Expose capabilities to Agent Registry, Agent Loader, Agent Router,
        and Master Agent routing.
        """

        return {
            "agent": self.agent_name,
            "module": "code_agent",
            "file": "git_manager.py",
            "class": self.__class__.__name__,
            "capabilities": [
                "git_status",
                "git_diff",
                "git_log",
                "current_branch",
                "list_branches",
                "init_repo_with_approval",
                "create_branch_with_approval",
                "checkout_branch_with_approval",
                "add_files_with_approval",
                "commit_with_approval",
                "rollback_with_approval",
                "revert_commit_with_approval",
                "audit_git_actions",
                "prepare_verification_payloads",
                "prepare_memory_payloads",
            ],
            "requires_context": ["user_id", "workspace_id"],
            "security_sensitive": True,
            "supports_saas_isolation": True,
            "supports_dashboard_events": True,
            "supports_audit_logs": True,
        }

    def health_check(self) -> Dict[str, Any]:
        """
        Basic health check for dashboard/API.
        """

        git_available = False
        git_version = ""

        try:
            completed = subprocess.run(
                ["git", "--version"],
                text=True,
                capture_output=True,
                timeout=10,
                shell=False,
            )
            git_available = completed.returncode == 0
            git_version = (completed.stdout or completed.stderr or "").strip()
        except Exception:
            git_available = False

        return self._safe_result(
            success=True,
            message="GitManager health check completed.",
            data={
                "base_dir": str(self.base_dir),
                "base_dir_exists": self.base_dir.exists(),
                "git_available": git_available,
                "git_version": git_version,
                "policy": {
                    "default_timeout_seconds": self.policy.default_timeout_seconds,
                    "max_timeout_seconds": self.policy.max_timeout_seconds,
                    "allow_remote_operations": self.policy.allow_remote_operations,
                    "allow_rollback": self.policy.allow_rollback,
                    "allow_commit": self.policy.allow_commit,
                    "allow_git_init": self.policy.allow_git_init,
                },
            },
        )


# ---------------------------------------------------------------------------
# Simple manual test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    manager = GitManager(base_dir=Path.cwd() / ".william_git_manager_test")

    demo_context = {
        "user_id": "demo_user",
        "workspace_id": "demo_workspace",
        "actor_id": "local_test",
        "role": "developer",
    }

    print(manager.health_check())
    print(manager.git_status(context=demo_context))