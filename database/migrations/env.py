"""
database/migrations/env.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix

Purpose:
    Alembic migration environment.

This file configures Alembic so database migrations can safely discover SQLAlchemy
models and run schema migrations in both offline and online modes.

Safety design:
    - No hardcoded secrets.
    - Database URL is read from environment/config.
    - Imports models safely even while the project is still being built.
    - Does not expose dashboard/API functionality.
    - Does not handle user data directly.
    - Keeps migrations deterministic and production-safe.
    - Supports PostgreSQL, SQLite, MySQL/MariaDB, and other SQLAlchemy-supported DBs.
"""

from __future__ import annotations

import importlib
import logging
import os
import sys
from logging.config import fileConfig
from pathlib import Path
from typing import Any, Iterable, Optional

from alembic import context
from sqlalchemy import engine_from_config, pool
from sqlalchemy.engine import Connection
from sqlalchemy.engine.url import make_url

try:
    from sqlalchemy import MetaData
except Exception as exc:  # pragma: no cover
    raise RuntimeError("SQLAlchemy is required for Alembic migrations.") from exc


# --------------------------------------------------------------------------------------
# Project path setup
# --------------------------------------------------------------------------------------

CURRENT_FILE = Path(__file__).resolve()
MIGRATIONS_DIR = CURRENT_FILE.parent
DATABASE_DIR = MIGRATIONS_DIR.parent
PROJECT_ROOT = DATABASE_DIR.parent

for path in (PROJECT_ROOT, DATABASE_DIR):
    path_str = str(path)
    if path_str not in sys.path:
        sys.path.insert(0, path_str)


# --------------------------------------------------------------------------------------
# Alembic config and logging
# --------------------------------------------------------------------------------------

config = context.config

if config.config_file_name is not None:
    try:
        fileConfig(config.config_file_name)
    except Exception:
        logging.basicConfig(level=logging.INFO)
else:
    logging.basicConfig(level=logging.INFO)

logger = logging.getLogger("william.database.migrations.env")


# --------------------------------------------------------------------------------------
# Base metadata discovery
# --------------------------------------------------------------------------------------

def _create_fallback_metadata() -> MetaData:
    """
    Return empty metadata if the project Base cannot be imported yet.

    This keeps Alembic import-safe during early project setup, but migrations should
    normally run with the real project Base available.
    """
    logger.warning(
        "Using fallback empty MetaData because project Base could not be imported. "
        "Autogenerate may not detect models until database.base or database.models.base exists."
    )
    return MetaData()


def _load_project_base_metadata() -> MetaData:
    """
    Load SQLAlchemy Base.metadata from the most likely project locations.
    """
    base_import_paths = (
        "database.db",
        "database.base",
        "database.models.base",
        "base",
    )

    for module_path in base_import_paths:
        try:
            module = importlib.import_module(module_path)
            base = getattr(module, "Base", None)
            metadata = getattr(base, "metadata", None)
            if metadata is not None:
                logger.info("Loaded SQLAlchemy metadata from %s.Base.metadata", module_path)
                return metadata
        except Exception as exc:
            logger.debug("Could not import %s: %s", module_path, exc)

    return _create_fallback_metadata()


target_metadata = _load_project_base_metadata()


# --------------------------------------------------------------------------------------
# Safe model imports
# --------------------------------------------------------------------------------------

try:
    # Single source of truth for "every real model module" -- previously
    # this tuple was hand-duplicated here, in tests/conftest.py, and (for
    # the real running app) nowhere at all, which is how apps/api/main.py
    # ended up never importing any model module or calling create_all() at
    # startup. See database/models/__init__.py.
    from database.models import MODEL_MODULES  # type: ignore
except Exception:  # pragma: no cover -- keep Alembic import-safe if the package itself is broken
    MODEL_MODULES: tuple[str, ...] = (
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
    )


def safe_import_model_modules(module_paths: Iterable[str]) -> list[str]:
    """
    Import all available model modules so SQLAlchemy registers mapped tables.

    Missing modules are tolerated because this project is generated progressively.
    Syntax/runtime errors inside existing files are logged clearly.
    """
    imported: list[str] = []

    for module_path in module_paths:
        try:
            importlib.import_module(module_path)
            imported.append(module_path)
            logger.debug("Imported model module: %s", module_path)
        except ModuleNotFoundError as exc:
            missing_name = getattr(exc, "name", "")
            if missing_name and (
                missing_name == module_path or module_path.startswith(f"{missing_name}.")
            ):
                logger.debug("Model module not found yet, skipping: %s", module_path)
            else:
                logger.warning(
                    "Model module %s exists but a dependency is missing: %s",
                    module_path,
                    exc,
                )
        except Exception as exc:
            logger.warning("Could not import model module %s: %s", module_path, exc)

    if imported:
        logger.info("Imported %d model module(s) for Alembic metadata discovery.", len(imported))
    else:
        logger.warning("No model modules imported. Autogenerate may produce empty migrations.")

    return imported


safe_import_model_modules(MODEL_MODULES)


# Refresh metadata after imports in case Base metadata was populated by model imports.
target_metadata = _load_project_base_metadata()


# --------------------------------------------------------------------------------------
# Env helper class
# --------------------------------------------------------------------------------------

class Env:
    """
    Alembic environment helper for William/Jarvis.

    This class centralizes migration configuration:
        - database URL discovery
        - secret-safe logging
        - offline migration setup
        - online migration setup
        - autogenerate filtering
    """

    ENV_DATABASE_KEYS: tuple[str, ...] = (
        "DATABASE_URL",
        "WILLIAM_DATABASE_URL",
        "JARVIS_DATABASE_URL",
        "SQLALCHEMY_DATABASE_URI",
        "DB_URL",
    )

    # Must match database/db.py's own Db.DEFAULT_SQLITE_URL exactly -- these
    # were two independently hardcoded fallback filenames ("william_jarvis.db"
    # here vs "william.db" there), so running migrations with no DATABASE_URL
    # set silently migrated a different SQLite file than the one the app
    # actually reads from, leaving the real file's schema stale forever.
    DEFAULT_SQLITE_PATH: str = "sqlite:///./william.db"

    INTERNAL_TABLE_PREFIXES: tuple[str, ...] = (
        "alembic_",
    )

    def __init__(self, alembic_config: Any, metadata: MetaData):
        self.config = alembic_config
        self.metadata = metadata
        self.logger = logging.getLogger("william.database.migrations.Env")

    @classmethod
    def get_database_url_from_env(cls) -> Optional[str]:
        """
        Find database URL from supported environment keys.

        No value is logged directly because database URLs may contain credentials.
        """
        for key in cls.ENV_DATABASE_KEYS:
            value = os.getenv(key)
            if value and value.strip():
                return value.strip()
        return None

    @classmethod
    def get_database_url_from_config(cls, alembic_config: Any) -> Optional[str]:
        """
        Read database URL from alembic.ini if present.

        Environment variables should normally be preferred for real deployments.
        """
        try:
            value = alembic_config.get_main_option("sqlalchemy.url")
        except Exception:
            value = None

        if value and value.strip() and "driver://user:pass@localhost/dbname" not in value:
            return value.strip()

        return None

    @classmethod
    def mask_database_url(cls, database_url: str) -> str:
        """
        Return a safe version of a database URL for logs.
        """
        try:
            parsed = make_url(database_url)
            return parsed.render_as_string(hide_password=True)
        except Exception:
            return "[INVALID_OR_HIDDEN_DATABASE_URL]"

    def resolve_database_url(self) -> str:
        """
        Resolve database URL using safe priority:
            1. Environment variables
            2. alembic.ini sqlalchemy.url
            3. local SQLite development fallback if explicitly allowed or in dev mode

        For production, set DATABASE_URL or WILLIAM_DATABASE_URL.
        """
        env_url = self.get_database_url_from_env()
        if env_url:
            self.logger.info("Using database URL from environment: %s", self.mask_database_url(env_url))
            return env_url

        config_url = self.get_database_url_from_config(self.config)
        if config_url:
            self.logger.info("Using database URL from Alembic config: %s", self.mask_database_url(config_url))
            return config_url

        allow_sqlite_fallback = os.getenv("WILLIAM_ALLOW_SQLITE_FALLBACK", "true").lower() in {
            "1",
            "true",
            "yes",
            "dev",
            "local",
        }

        app_env = os.getenv("WILLIAM_ENV", os.getenv("APP_ENV", "development")).lower()
        is_production = app_env in {"prod", "production", "live"}

        if is_production and not allow_sqlite_fallback:
            raise RuntimeError(
                "Database URL is required in production. Set DATABASE_URL or WILLIAM_DATABASE_URL."
            )

        self.logger.warning(
            "No database URL found. Using local SQLite fallback for development only."
        )
        return self.DEFAULT_SQLITE_PATH

    def configure_database_url(self) -> str:
        """
        Apply resolved database URL into Alembic config.
        """
        database_url = self.resolve_database_url()
        self.config.set_main_option("sqlalchemy.url", database_url)
        return database_url

    @staticmethod
    def include_name(
        name: Optional[str],
        type_: str,
        parent_names: dict[str, Optional[str]],
    ) -> bool:
        """
        Filter objects during autogenerate by name.

        Keeps Alembic internals out of generated schema changes.
        """
        if not name:
            return True

        if type_ == "table" and name.startswith(Env.INTERNAL_TABLE_PREFIXES):
            return False

        return True

    @staticmethod
    def include_object(
        object_: Any,
        name: Optional[str],
        type_: str,
        reflected: bool,
        compare_to: Any,
    ) -> bool:
        """
        Filter objects during autogenerate by SQLAlchemy object.

        This avoids deleting tables that intentionally exist outside SQLAlchemy metadata
        when WILLIAM_ALEMBIC_INCLUDE_EXTERNAL_TABLES=false.
        """
        include_external = os.getenv("WILLIAM_ALEMBIC_INCLUDE_EXTERNAL_TABLES", "true").lower() in {
            "1",
            "true",
            "yes",
        }

        if type_ == "table" and reflected and compare_to is None and not include_external:
            return False

        if name and name.startswith(Env.INTERNAL_TABLE_PREFIXES):
            return False

        return True

    @staticmethod
    def compare_type() -> bool:
        """
        Enable or disable type comparison.

        Enabled by default because SaaS systems need schema drift caught early.
        """
        return os.getenv("WILLIAM_ALEMBIC_COMPARE_TYPE", "true").lower() in {
            "1",
            "true",
            "yes",
        }

    @staticmethod
    def compare_server_default() -> bool:
        """
        Enable or disable server default comparison.

        Disabled by default to avoid noisy migrations across database providers.
        """
        return os.getenv("WILLIAM_ALEMBIC_COMPARE_SERVER_DEFAULT", "false").lower() in {
            "1",
            "true",
            "yes",
        }

    @staticmethod
    def render_as_batch(database_url: str) -> bool:
        """
        SQLite often needs batch mode for ALTER TABLE operations.
        """
        return database_url.startswith("sqlite")

    def common_context_options(self, database_url: str) -> dict[str, Any]:
        """
        Shared Alembic context options.
        """
        return {
            "target_metadata": self.metadata,
            "include_name": self.include_name,
            "include_object": self.include_object,
            "compare_type": self.compare_type(),
            "compare_server_default": self.compare_server_default(),
            "render_as_batch": self.render_as_batch(database_url),
            "transaction_per_migration": True,
        }

    def run_migrations_offline(self) -> None:
        """
        Run migrations in offline mode.

        Offline mode emits SQL without creating an Engine. This is useful for CI,
        review, or generating SQL scripts.
        """
        database_url = self.configure_database_url()

        self.logger.info(
            "Running Alembic migrations in offline mode against %s",
            self.mask_database_url(database_url),
        )

        context.configure(
            url=database_url,
            literal_binds=True,
            dialect_opts={"paramstyle": "named"},
            **self.common_context_options(database_url),
        )

        with context.begin_transaction():
            context.run_migrations()

    def run_migrations_online(self) -> None:
        """
        Run migrations in online mode.

        Online mode creates an Engine and applies migrations directly to the target DB.
        """
        database_url = self.configure_database_url()

        self.logger.info(
            "Running Alembic migrations in online mode against %s",
            self.mask_database_url(database_url),
        )

        configuration = self.config.get_section(self.config.config_ini_section)
        if configuration is None:
            configuration = {}

        configuration["sqlalchemy.url"] = database_url

        connectable = engine_from_config(
            configuration,
            prefix="sqlalchemy.",
            poolclass=pool.NullPool,
            future=True,
        )

        with connectable.connect() as connection:
            self.configure_online_context(connection=connection, database_url=database_url)

            with context.begin_transaction():
                context.run_migrations()

        connectable.dispose()

    def configure_online_context(self, *, connection: Connection, database_url: str) -> None:
        """
        Configure Alembic context for an active SQLAlchemy connection.
        """
        context.configure(
            connection=connection,
            **self.common_context_options(database_url),
        )

    def structured_status(self) -> dict[str, Any]:
        """
        Return a safe status payload useful for tests or debugging.

        This does not include secrets or raw database credentials.
        """
        database_url = self.resolve_database_url()
        tables = sorted(self.metadata.tables.keys()) if self.metadata is not None else []

        return {
            "ok": True,
            "environment": os.getenv("WILLIAM_ENV", os.getenv("APP_ENV", "development")),
            "database_url": self.mask_database_url(database_url),
            "table_count": len(tables),
            "tables": tables,
            "compare_type": self.compare_type(),
            "compare_server_default": self.compare_server_default(),
            "render_as_batch": self.render_as_batch(database_url),
        }


# --------------------------------------------------------------------------------------
# Alembic entrypoint
# --------------------------------------------------------------------------------------

env = Env(config, target_metadata)


def run_migrations_offline() -> None:
    """Alembic-required offline migration entrypoint."""
    env.run_migrations_offline()


def run_migrations_online() -> None:
    """Alembic-required online migration entrypoint."""
    env.run_migrations_online()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()