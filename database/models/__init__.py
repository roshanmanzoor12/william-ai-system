"""
database/models/__init__.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Single source of truth for "every real SQLAlchemy model module under
database/models/". Before this file existed, the exact same 15-module list
was hand-duplicated in three places (tests/conftest.py, database/migrations/
env.py, and nowhere at all for the real running app) -- apps/api/main.py
never imported any model module or called Base.metadata.create_all() at
startup, so a brand-new or deleted-and-recreated SQLite dev database had no
tables until something else (a stray Alembic run, or the test suite's own
import-time side effect) happened to populate it first. Deleting
william.db while nothing else had done that produced "no such table:
users" on the very next request.

Usage:
    from database.models import MODEL_MODULES, import_all_models
    import_all_models()  # registers every model's table on database.db.Base.metadata
"""

from __future__ import annotations

import importlib
import logging
from typing import Iterable, List, Tuple

logger = logging.getLogger("william.database.models")

# Every real model module under database/models/. Kept as an explicit list
# (not a directory scan) so a broken/renamed file fails loudly via the
# warning log below rather than silently vanishing from create_all/
# Alembic autogenerate.
MODEL_MODULES: Tuple[str, ...] = (
    "database.models.user",
    "database.models.workspace",
    "database.models.role_permission",
    "database.models.subscription",
    "database.models.agent_registry",
    "database.models.agent_task",
    "database.models.agent_event",
    "database.models.agent",
    "database.models.memory",
    "database.models.security",
    "database.models.file",
    "database.models.workflow",
    "database.models.business",
    "database.models.finance",
    "database.models.voice",
    "database.models.system_worker",
    "database.models.conversation_session",
    "database.models.worker_task",
    "database.models.device_setup_token",
    "database.models.system_worker_event",
)


def import_all_models(module_paths: Iterable[str] = MODEL_MODULES) -> List[str]:
    """
    Import every model module so its table registers on database.db.Base.metadata.

    Missing modules are tolerated (this project is generated progressively);
    a module that exists but fails to import for a real reason (syntax
    error, missing dependency) is logged clearly instead of silently eaten,
    the same contract database/migrations/env.py's own import loop already
    had.
    """
    imported: List[str] = []

    for module_path in module_paths:
        try:
            importlib.import_module(module_path)
            imported.append(module_path)
        except ModuleNotFoundError as exc:
            missing_name = getattr(exc, "name", "")
            if missing_name and (missing_name == module_path or module_path.startswith(f"{missing_name}.")):
                logger.debug("Model module not found yet, skipping: %s", module_path)
            else:
                logger.warning("Model module %s exists but a dependency is missing: %s", module_path, exc)
        except Exception as exc:  # noqa: BLE001 -- must never take the app down
            logger.warning("Could not import model module %s: %s", module_path, exc)

    if imported:
        logger.info("Imported %d model module(s) for metadata discovery.", len(imported))
    else:
        logger.warning("No model modules imported. create_all()/autogenerate may produce an empty schema.")

    return imported


__all__ = ["MODEL_MODULES", "import_all_models"]
