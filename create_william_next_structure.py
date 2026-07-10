
#!/usr/bin/env python3
"""
William / Jarvis Next Prompt Pack scaffold creator.

Creates the expansion-pack folder/file structure from:
William_Jarvis_Next_Prompt_Pack_And_Futuristic_Capabilities.pdf

Safe behavior:
- Creates missing folders.
- Creates missing files.
- Skips files that already exist.
- Never overwrites existing generated code.
- Writes a JSON report after every run.

Usage:
    python create_william_next_structure.py
    python create_william_next_structure.py --dry-run
    python create_william_next_structure.py --empty
    python create_william_next_structure.py --root C:\\William-Jarvis
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Tuple

FILES: List[Tuple[str, str, str]] = [('apps/api/main.py', 'API Prompt Bible', 'FastAPI application entry with middleware, routers, auth hooks, health checks, CORS, request IDs'), ('apps/api/routes/auth.py', 'API Prompt Bible', 'login/register/refresh/logout endpoints with workspace-aware sessions'), ('apps/api/routes/users.py', 'API Prompt Bible', 'user CRUD, roles, profile, activation, plan visibility'), ('apps/api/routes/workspaces.py', 'API Prompt Bible', 'workspace create/update/member invite/access management'), ('apps/api/routes/agents.py', 'API Prompt Bible', 'list agents, enable/disable, capabilities, health, user access'), ('apps/api/routes/tasks.py', 'API Prompt Bible', 'create/run/cancel task, task history, progress events'), ('apps/api/routes/memory.py', 'API Prompt Bible', 'short/long/project/client memory save/search/delete/export'), ('apps/api/routes/security.py', 'API Prompt Bible', 'approval requests, audit logs, risky action decisions'), ('apps/api/routes/workflows.py', 'API Prompt Bible', 'workflow templates, run workflow, webhook management'), ('apps/api/routes/billing.py', 'API Prompt Bible', 'plans, subscription status, usage limits, invoices'), ('apps/api/routes/files.py', 'API Prompt Bible', 'uploads/reports/screenshots/downloads with user isolation'), ('apps/api/websockets/agent_events.py', 'API Prompt Bible', 'real-time agent status and task events to dashboard'), ('database/db.py', 'Database Prompt Bible', 'database engine/session/base config for PostgreSQL and local fallback'), ('database/models/user.py', 'Database Prompt Bible', 'User model with auth fields, status, profile, timestamps'), ('database/models/workspace.py', 'Database Prompt Bible', 'Workspace and membership models'), ('database/models/role_permission.py', 'Database Prompt Bible', 'roles, permissions, user role mappings'), ('database/models/subscription.py', 'Database Prompt Bible', 'plans, subscriptions, usage limits, billing state'), ('database/models/agent_registry.py', 'Database Prompt Bible', 'agent metadata, versions, capabilities, enabled flags'), ('database/models/agent_task.py', 'Database Prompt Bible', 'tasks, subtasks, status, agent, user/workspace, progress'), ('database/models/agent_event.py', 'Database Prompt Bible', 'event stream records and audit-friendly payloads'), ('database/models/memory.py', 'Database Prompt Bible', 'short/long/project/client/team/vector memory tables'), ('database/models/security.py', 'Database Prompt Bible', 'audit logs, approval requests, risk decisions'), ('database/models/business.py', 'Database Prompt Bible', 'clients, leads, CRM contacts/deals, campaigns'), ('database/models/workflow.py', 'Database Prompt Bible', 'workflows, workflow runs, nodes, logs, failures'), ('database/models/finance.py', 'Database Prompt Bible', 'invoices, expenses, receipts, subscriptions safe finance'), ('database/migrations/env.py', 'Database Prompt Bible', 'Alembic migration environment'), ('database/seeders/default_plans.py', 'Database Prompt Bible', 'starter SaaS plans, roles, permissions, agents'), ('apps/dashboard/src/app/login/page.tsx', 'Dashboard Prompt Bible', 'login UI and auth flow'), ('apps/dashboard/src/app/dashboard/page.tsx', 'Dashboard Prompt Bible', 'main AI command console'), ('apps/dashboard/src/app/agents/page.tsx', 'Dashboard Prompt Bible', 'agent control center with enable/disable/status'), ('apps/dashboard/src/app/agent-permissions/page.tsx', 'Dashboard Prompt Bible', 'assign agents by user/role/plan'), ('apps/dashboard/src/app/memory/page.tsx', 'Dashboard Prompt Bible', 'memory manager with search/delete/export'), ('apps/dashboard/src/app/tasks/page.tsx', 'Dashboard Prompt Bible', 'task history and live progress'), ('apps/dashboard/src/app/analytics/page.tsx', 'Dashboard Prompt Bible', 'usage, task, lead, workflow analytics'), ('apps/dashboard/src/app/workflows/page.tsx', 'Dashboard Prompt Bible', 'workflow builder and templates'), ('apps/dashboard/src/app/crm/page.tsx', 'Dashboard Prompt Bible', 'leads, clients, pipeline'), ('apps/dashboard/src/app/calls/page.tsx', 'Dashboard Prompt Bible', 'call agent/receptionist panel'), ('apps/dashboard/src/app/creator/page.tsx', 'Dashboard Prompt Bible', 'content studio'), ('apps/dashboard/src/app/finance/page.tsx', 'Dashboard Prompt Bible', 'safe finance dashboard'), ('apps/dashboard/src/app/billing/page.tsx', 'Dashboard Prompt Bible', 'plans/subscription usage'), ('apps/dashboard/src/app/security/page.tsx', 'Dashboard Prompt Bible', 'audit logs and approval queue'), ('apps/dashboard/src/app/settings/page.tsx', 'Dashboard Prompt Bible', 'workspace/user/global settings'), ('apps/worker_nodes/common/worker_client.py', 'Device Worker Prompt Bible', 'shared worker client that connects devices to backend'), ('apps/worker_nodes/windows/windows_worker.py', 'Device Worker Prompt Bible', 'Windows app/file/browser/system automation worker'), ('apps/worker_nodes/windows/app_control.py', 'Device Worker Prompt Bible', 'open/focus/close Windows apps'), ('apps/worker_nodes/windows/screen_capture.py', 'Device Worker Prompt Bible', 'permission-based screenshots and UI proof'), ('apps/worker_nodes/mac/mac_worker.py', 'Device Worker Prompt Bible', 'macOS worker with AppleScript/automation hooks'), ('apps/worker_nodes/android/MainActivity.kt', 'Device Worker Prompt Bible', 'Android worker login/status/control shell'), ('apps/worker_nodes/android/AccessibilityWorker.kt', 'Device Worker Prompt Bible', 'AccessibilityService automation bridge'), ('apps/worker_nodes/android/NotificationBridge.kt', 'Device Worker Prompt Bible', 'notification access with permission'), ('apps/worker_nodes/android/CallBridge.kt', 'Device Worker Prompt Bible', 'call detection/handling with permission'), ('apps/worker_nodes/ios/ios_client_plan.md', 'Device Worker Prompt Bible', 'iOS limitations and Shortcuts/API client design'), ('Dockerfile', 'Deployment Prompt Bible', 'production backend Dockerfile'), ('docker-compose.yml', 'Deployment Prompt Bible', 'backend, PostgreSQL, Redis, worker, dashboard services'), ('deploy/nginx/william.conf', 'Deployment Prompt Bible', 'Nginx reverse proxy config'), ('deploy/systemd/william-api.service', 'Deployment Prompt Bible', 'systemd service for API'), ('deploy/ssl/setup_ssl.md', 'Deployment Prompt Bible', 'SSL setup guide'), ('deploy/scripts/backup_db.sh', 'Deployment Prompt Bible', 'database backup script'), ('deploy/scripts/restore_db.sh', 'Deployment Prompt Bible', 'database restore script'), ('deploy/scripts/deploy.sh', 'Deployment Prompt Bible', 'safe deployment script'), ('deploy/monitoring/healthchecks.py', 'Deployment Prompt Bible', 'service health checks'), ('deploy/README_DEPLOYMENT.md', 'Deployment Prompt Bible', 'complete deployment guide'), ('tests/conftest.py', 'Testing Prompt Bible', 'test fixtures for app/db/users/workspaces'), ('tests/agent_tests/test_base_agent.py', 'Testing Prompt Bible', 'BaseAgent behavior tests'), ('tests/agent_tests/test_security_agent.py', 'Testing Prompt Bible', 'security/risk/approval tests'), ('tests/agent_tests/test_memory_agent.py', 'Testing Prompt Bible', 'memory isolation and recall tests'), ('tests/api_tests/test_auth.py', 'Testing Prompt Bible', 'auth endpoint tests'), ('tests/api_tests/test_agents.py', 'Testing Prompt Bible', 'agent list/access/task tests'), ('tests/api_tests/test_memory.py', 'Testing Prompt Bible', 'memory API tests'), ('tests/integration_tests/test_master_flow.py', 'Testing Prompt Bible', 'request->planner->security->agent->verification flow'), ('tests/integration_tests/test_saas_isolation.py', 'Testing Prompt Bible', 'user/workspace isolation tests'), ('tests/integration_tests/test_workflow_form_to_crm.py', 'Testing Prompt Bible', 'workflow pipeline test')]

PY_STUB = '''"""
{path}

Module: {module}
Purpose: {purpose}

Generated by create_william_next_structure.py.
This is a safe starter stub only. Replace this file with the full final generated code
when you generate this exact file from the William/Jarvis Next Prompt Pack.

Project rules:
- Keep user_id and workspace_id isolation.
- Do not hardcode secrets.
- Route sensitive actions through Security Agent.
- Prepare Verification Agent payloads for completed actions.
- Keep imports safe while future files may still be missing.
"""

from __future__ import annotations


FILE_METADATA = {{
    "path": "{path}",
    "module": "{module}",
    "purpose": "{purpose}",
    "status": "scaffold_created",
}}


def describe() -> dict:
    """Return scaffold metadata for this file."""
    return FILE_METADATA.copy()
'''

TSX_STUB = '''"use client";

/**
 * {path}
 *
 * Module: {module}
 * Purpose: {purpose}
 *
 * Generated by create_william_next_structure.py.
 * This is a safe starter page only. Replace it with the full final generated code
 * when you generate this exact file from the William/Jarvis Next Prompt Pack.
 */

export default function Page() {{
  return (
    <main style={{{{ padding: "24px", fontFamily: "Inter, system-ui, sans-serif" }}}}>
      <h1>William / Jarvis</h1>
      <h2>{module}</h2>
      <p><strong>File:</strong> {path}</p>
      <p><strong>Purpose:</strong> {purpose}</p>
      <p>This scaffold was created safely and can be replaced with the full production page later.</p>
    </main>
  );
}}
'''

KT_STUB = '''/*
 * {path}
 *
 * Module: {module}
 * Purpose: {purpose}
 *
 * Generated by create_william_next_structure.py.
 * This is a safe starter Kotlin file only. Replace it with the full final generated code
 * when you generate this exact file from the William/Jarvis Next Prompt Pack.
 */

package com.digitalpromotix.william.worker

object ScaffoldInfo {{
    const val path: String = "{path}"
    const val module: String = "{module}"
    const val purpose: String = "{purpose}"
}}
'''

MD_STUB = '''# {title}

**Path:** `{path}`  
**Module:** {module}  
**Purpose:** {purpose}

Generated by `create_william_next_structure.py`.

This is a safe starter document only. Replace it with the full final generated file
when you generate this exact file from the William/Jarvis Next Prompt Pack.

## William / Jarvis safety notes

- Keep `user_id` and `workspace_id` isolation.
- Do not hardcode secrets.
- Route sensitive actions through Security Agent.
- Prepare Verification Agent payloads for completed actions.
- Keep files import-safe while future files may still be missing.
'''

SH_STUB = '''#!/usr/bin/env bash
set -euo pipefail

# {path}
# Module: {module}
# Purpose: {purpose}
#
# Generated by create_william_next_structure.py.
# This is a safe starter script only. Replace it with the full final generated code
# when you generate this exact file from the William/Jarvis Next Prompt Pack.

echo "William / Jarvis scaffold script"
echo "File: {path}"
echo "Purpose: {purpose}"
'''

DOCKERFILE_STUB = '''# {path}
# Module: {module}
# Purpose: {purpose}
#
# Generated by create_william_next_structure.py.
# This is a safe starter Dockerfile only. Replace with the production Dockerfile later.

FROM python:3.11-slim

WORKDIR /app

COPY . /app

CMD ["python", "-c", "print('William / Jarvis scaffold Dockerfile. Replace with production Dockerfile.')"]
'''

YAML_STUB = '''# {path}
# Module: {module}
# Purpose: {purpose}
#
# Generated by create_william_next_structure.py.
# This is a safe starter compose/config file only. Replace with the production file later.

services:
  william-api:
    image: python:3.11-slim
    working_dir: /app
    volumes:
      - .:/app
    command: python -c "print('William / Jarvis scaffold docker-compose. Replace with production compose later.')"
'''

CONF_STUB = '''# {path}
# Module: {module}
# Purpose: {purpose}
#
# Generated by create_william_next_structure.py.
# This is a safe starter config only. Replace with the production config later.

server {{
    listen 80;
    server_name _;
    location / {{
        return 200 "William / Jarvis scaffold nginx config. Replace with production config.";
    }}
}}
'''

SERVICE_STUB = '''# {path}
# Module: {module}
# Purpose: {purpose}
#
# Generated by create_william_next_structure.py.
# This is a safe starter systemd service only. Replace with production values later.

[Unit]
Description=William Jarvis API Scaffold
After=network.target

[Service]
WorkingDirectory=/opt/william
ExecStart=/usr/bin/python3 -c "print('William / Jarvis scaffold service. Replace with production service.')"
Restart=on-failure

[Install]
WantedBy=multi-user.target
'''


def render_stub(path: str, module: str, purpose: str, empty: bool) -> str:
    if empty:
        return ""

    suffix = Path(path).suffix.lower()
    filename = Path(path).name

    if filename == "Dockerfile":
        template = DOCKERFILE_STUB
    elif filename == "docker-compose.yml" or suffix in {".yml", ".yaml"}:
        template = YAML_STUB
    elif suffix == ".tsx":
        template = TSX_STUB
    elif suffix == ".kt":
        template = KT_STUB
    elif suffix == ".md":
        template = MD_STUB
    elif suffix == ".sh":
        template = SH_STUB
    elif suffix == ".conf":
        template = CONF_STUB
    elif suffix == ".service":
        template = SERVICE_STUB
    else:
        template = PY_STUB

    return template.format(
        path=path,
        module=module,
        purpose=purpose,
        title=Path(path).name,
    )


def create_structure(root: Path, dry_run: bool = False, empty: bool = False) -> Dict[str, object]:
    created_files: List[str] = []
    skipped_files: List[str] = []
    created_dirs: List[str] = []
    errors: List[Dict[str, str]] = []

    root = root.resolve()

    for rel_path, module, purpose in FILES:
        target = root / rel_path
        parent = target.parent

        try:
            if not parent.exists():
                created_dirs.append(str(parent.relative_to(root)))
                if not dry_run:
                    parent.mkdir(parents=True, exist_ok=True)

            if target.exists():
                skipped_files.append(rel_path)
                continue

            created_files.append(rel_path)
            if not dry_run:
                content = render_stub(rel_path, module, purpose, empty)
                target.write_text(content, encoding="utf-8")
                if target.suffix.lower() == ".sh":
                    target.chmod(target.stat().st_mode | 0o111)

        except Exception as exc:
            errors.append({"path": rel_path, "error": str(exc)})

    report: Dict[str, object] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "root": str(root),
        "dry_run": dry_run,
        "empty_files": empty,
        "total_files_in_manifest": len(FILES),
        "created_file_count": len(created_files),
        "skipped_existing_file_count": len(skipped_files),
        "created_dir_count": len(set(created_dirs)),
        "error_count": len(errors),
        "created_files": created_files,
        "skipped_existing_files": skipped_files,
        "created_dirs": sorted(set(created_dirs)),
        "errors": errors,
    }

    if not dry_run:
        report_path = root / "william_next_scaffold_report.json"
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create William/Jarvis Next Prompt Pack folder and file structure without overwriting existing files."
    )
    parser.add_argument(
        "--root",
        default=".",
        help="Project root folder where the structure should be created. Default: current folder.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be created without writing files.",
    )
    parser.add_argument(
        "--empty",
        action="store_true",
        help="Create empty files instead of starter scaffold content.",
    )
    args = parser.parse_args()

    report = create_structure(Path(args.root), dry_run=args.dry_run, empty=args.empty)

    print("\nWilliam / Jarvis Next Prompt Pack scaffold")
    print("=" * 48)
    print(f"Root: {report['root']}")
    print(f"Dry run: {report['dry_run']}")
    print(f"Files in manifest: {report['total_files_in_manifest']}")
    print(f"Created files: {report['created_file_count']}")
    print(f"Skipped existing files: {report['skipped_existing_file_count']}")
    print(f"Created folders: {report['created_dir_count']}")
    print(f"Errors: {report['error_count']}")

    if report["error_count"]:
        print("\nErrors:")
        for item in report["errors"]:
            print(f"- {item['path']}: {item['error']}")
        return 1

    if not args.dry_run:
        print("\nReport saved: william_next_scaffold_report.json")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
