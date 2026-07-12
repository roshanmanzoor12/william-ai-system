"""
database/seeders/seed_voice_defaults.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Phase 9 — idempotent voice-settings seeding.

Ensures every existing workspace has a VoiceSettings row, always defaulting
to mode="disabled" (no workspace ever starts with voice/wake-word listening
enabled). Safe to run multiple times: existing rows are left untouched, not
duplicated or reset.

No trusted voice profiles are seeded by default -- per the mission spec,
owner/admin must explicitly enroll their own voice and any trusted profiles
through the real API/dashboard flow (POST /api/v1/voice/enroll/start,
POST /api/v1/voice/profiles), never fabricated by a seeder.

Usage:
    python -m database.seeders.seed_voice_defaults
"""

from __future__ import annotations

import logging
from typing import Any, Dict

logger = logging.getLogger("william.database.seeders.seed_voice_defaults")

DEFAULT_SYSTEM_USER_ID = "system"


def get_or_create_voice_settings(db, workspace_id: str, created_by_user_id: str = DEFAULT_SYSTEM_USER_ID):
    """
    Idempotent lookup/creation of one workspace's VoiceSettings row.

    This is the single entrypoint apps/api/routes/voice.py should use too
    (not just this seeder) so "first GET /voice/status ever made for a
    workspace" and "bulk seed pass" both converge on exactly one row per
    workspace, never a duplicate.
    """
    from database.models.voice import VoiceSettings

    existing = db.query(VoiceSettings).filter(VoiceSettings.workspace_id == workspace_id).first()
    if existing is not None:
        return existing, False

    settings = VoiceSettings(
        workspace_id=workspace_id,
        created_by_user_id=created_by_user_id,
    )
    db.add(settings)
    db.flush()
    return settings, True


def seed_voice_defaults_for_all_workspaces() -> Dict[str, Any]:
    from database.db import db_manager
    from database.models.workspace import Workspace

    report: Dict[str, Any] = {"success": True, "created": [], "already_existed": [], "errors": []}

    with db_manager.session_scope() as db:
        workspaces = db.query(Workspace).all()

        for workspace in workspaces:
            try:
                _settings, created = get_or_create_voice_settings(
                    db,
                    workspace_id=workspace.workspace_id,
                    created_by_user_id=getattr(workspace, "owner_user_id", DEFAULT_SYSTEM_USER_ID) or DEFAULT_SYSTEM_USER_ID,
                )
                bucket = report["created"] if created else report["already_existed"]
                bucket.append(workspace.workspace_id)
            except Exception as exc:  # noqa: BLE001
                report["success"] = False
                report["errors"].append({"workspace_id": getattr(workspace, "workspace_id", None), "detail": str(exc)})
                logger.warning("seed_voice_defaults: failed for workspace %s: %s", getattr(workspace, "workspace_id", None), exc)

    return report


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    result = seed_voice_defaults_for_all_workspaces()
    print(f"created: {len(result['created'])}  already_existed: {len(result['already_existed'])}  errors: {len(result['errors'])}")
    if result["errors"]:
        print("errors:", result["errors"])
    print("overall success:", result["success"])
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
