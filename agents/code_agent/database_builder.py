"""
agents/code_agent/database_builder.py

DatabaseBuilder for the William / Jarvis Multi-Agent AI SaaS System by Digital Promotix.

Purpose:
    Creates models, migrations, schemas, relationships, indexes, and seed data.

This file is production-oriented and import-safe. It generates SQLAlchemy model
code, Pydantic schema code, Alembic-style migrations, relationship/index code,
and tenant-aware seed scripts. It validates SaaS user/workspace context and
uses Security/Verification/Memory hooks when available.
"""

from __future__ import annotations

import json
import logging
import re
import traceback
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        agent_name = "base_agent"
        agent_type = "generic"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.user_id = kwargs.get("user_id")
            self.workspace_id = kwargs.get("workspace_id")
            self.logger = logging.getLogger(self.__class__.__name__)

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback emit_event: %s %s", event_name, payload)

        def log_audit(self, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback audit: %s", payload)

try:
    from agents.security_agent.security_agent import SecurityAgent  # type: ignore
except Exception:  # pragma: no cover
    SecurityAgent = None  # type: ignore

try:
    from agents.verification_agent.verification_agent import VerificationAgent  # type: ignore
except Exception:  # pragma: no cover
    VerificationAgent = None  # type: ignore

try:
    from agents.memory_agent.memory_agent import MemoryAgent  # type: ignore
except Exception:  # pragma: no cover
    MemoryAgent = None  # type: ignore


DEFAULT_AGENT_NAME = "database_builder"
DEFAULT_AGENT_TYPE = "code_agent"
DEFAULT_ENCODING = "utf-8"

SAFE_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SAFE_TABLE_RE = re.compile(r"^[a-z][a-z0-9_]*$")

DEFAULT_BLOCKED_DIRECTORIES = (
    ".git", ".venv", "venv", "env", "__pycache__", "node_modules",
    "dist", "build", ".pytest_cache", ".mypy_cache", ".ruff_cache",
)

SENSITIVE_PATH_PARTS = {
    ".env", ".ssh", ".aws", ".gcp", ".azure", "secrets", "secret",
    "credentials", "private_key", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
}

SQLALCHEMY_TYPE_MAP = {
    "str": "String", "string": "String", "text": "Text", "int": "Integer",
    "integer": "Integer", "bigint": "BigInteger", "float": "Float",
    "decimal": "Numeric", "bool": "Boolean", "boolean": "Boolean",
    "datetime": "DateTime", "date": "Date", "time": "Time", "json": "JSON",
    "uuid": "String", "email": "String", "url": "String",
}

PYTHON_TYPE_MAP = {
    "str": "str", "string": "str", "text": "str", "int": "int",
    "integer": "int", "bigint": "int", "float": "float", "decimal": "Decimal",
    "bool": "bool", "boolean": "bool", "datetime": "datetime", "date": "date",
    "time": "time", "json": "Dict[str, Any]", "uuid": "str", "email": "str", "url": "str",
}


@dataclass
class DatabaseBuilderConfig:
    """Runtime configuration for DatabaseBuilder."""

    project_root: Union[str, Path] = "."
    output_models_path: str = "models.py"
    output_schemas_path: str = "schemas.py"
    output_seed_path: str = "seed_data.py"
    migrations_dir: str = "migrations/versions"
    encoding: str = DEFAULT_ENCODING
    allow_file_writes: bool = False
    require_security_for_writes: bool = True
    create_backups: bool = True
    backup_suffix: str = ".database_builder.bak"
    blocked_directory_names: Tuple[str, ...] = DEFAULT_BLOCKED_DIRECTORIES
    allowed_file_extensions: Tuple[str, ...] = (".py", ".sql", ".md", ".txt", ".json", ".yaml", ".yml")
    default_id_autoincrement: bool = True
    enforce_tenant_fields: bool = True
    include_timestamp_columns: bool = True
    include_soft_delete_column: bool = False
    include_repr_methods: bool = True
    include_table_args: bool = True
    use_pydantic_v2: bool = True
    migration_revision_prefix: str = "william"
    max_generated_file_bytes: int = 750_000

    def normalized_project_root(self) -> Path:
        return Path(self.project_root).expanduser().resolve()


@dataclass
class BuilderTaskContext:
    """SaaS execution context. user_id and workspace_id are required."""

    user_id: Union[str, int]
    workspace_id: Union[str, int]
    request_id: Optional[str] = None
    role: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FieldDefinition:
    name: str
    type: str = "str"
    nullable: bool = True
    default: Optional[Any] = None
    primary_key: bool = False
    unique: bool = False
    index: bool = False
    foreign_key: Optional[str] = None
    length: Optional[int] = None
    max_digits: Optional[int] = None
    decimal_places: Optional[int] = None
    server_default: Optional[str] = None
    description: Optional[str] = None
    sensitive: bool = False
    read_only: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RelationshipDefinition:
    name: str
    target_model: str
    back_populates: Optional[str] = None
    cascade: Optional[str] = None
    uselist: Optional[bool] = None
    lazy: str = "selectin"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class IndexDefinition:
    name: str
    columns: List[str]
    unique: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ModelDefinition:
    class_name: str
    table_name: str
    fields: List[FieldDefinition] = field(default_factory=list)
    relationships: List[RelationshipDefinition] = field(default_factory=list)
    indexes: List[IndexDefinition] = field(default_factory=list)
    description: Optional[str] = None
    seed_rows: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "class_name": self.class_name,
            "table_name": self.table_name,
            "fields": [x.to_dict() for x in self.fields],
            "relationships": [x.to_dict() for x in self.relationships],
            "indexes": [x.to_dict() for x in self.indexes],
            "description": self.description,
            "seed_rows": list(self.seed_rows),
        }


@dataclass
class GeneratedArtifact:
    name: str
    relative_path: str
    content: str
    artifact_type: str
    written: bool = False
    absolute_path: Optional[str] = None
    backup_path: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MigrationDefinition:
    revision_id: str
    down_revision: Optional[str]
    message: str
    upgrade_ops: List[str] = field(default_factory=list)
    downgrade_ops: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class DatabaseBuilder(BaseAgent):
    """Database code generator for William/Jarvis Code Agent."""

    agent_name = DEFAULT_AGENT_NAME
    agent_type = DEFAULT_AGENT_TYPE
    public_methods = (
        "build_database_artifacts", "generate_models_code", "generate_schemas_code",
        "generate_migration_code", "generate_seed_data_code", "validate_model_definitions",
        "write_artifacts",
    )

    def __init__(
        self,
        config: Optional[DatabaseBuilderConfig] = None,
        security_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        event_emitter: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.config = config or DatabaseBuilderConfig()
        self.project_root = self.config.normalized_project_root()
        self.security_agent = security_agent or self._safe_instantiate_agent(SecurityAgent)
        self.verification_agent = verification_agent or self._safe_instantiate_agent(VerificationAgent)
        self.memory_agent = memory_agent or self._safe_instantiate_agent(MemoryAgent)
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger
        self.logger = logger or logging.getLogger(self.__class__.__name__)

    def build_database_artifacts(
        self,
        context: Union[BuilderTaskContext, Mapping[str, Any]],
        models: Sequence[Union[ModelDefinition, Mapping[str, Any]]],
        include_models: bool = True,
        include_schemas: bool = True,
        include_migration: bool = True,
        include_seed_data: bool = True,
        write_files: bool = False,
        migration_message: str = "create william jarvis tables",
        down_revision: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        safe_context = self._coerce_context(context)
        validation = self._validate_task_context(safe_context)
        if not validation["success"]:
            return validation

        run_metadata = dict(metadata or {})
        started_at = self._utc_now()
        self._emit_agent_event("code_agent.database_builder.started", {
            "context": self._context_public_dict(safe_context),
            "model_count": len(models or []),
            "write_files": write_files,
            "metadata": run_metadata,
        })

        try:
            normalized_models = self._coerce_model_definitions(models)
            validation_result = self.validate_model_definitions(safe_context, normalized_models, run_metadata)
            if not validation_result.get("success"):
                return validation_result

            artifacts: List[GeneratedArtifact] = []
            if include_models:
                result = self.generate_models_code(safe_context, normalized_models, run_metadata)
                if not result.get("success"):
                    return result
                artifacts.append(GeneratedArtifact("models", self.config.output_models_path, result["data"]["content"], "models"))

            if include_schemas:
                result = self.generate_schemas_code(safe_context, normalized_models, run_metadata)
                if not result.get("success"):
                    return result
                artifacts.append(GeneratedArtifact("schemas", self.config.output_schemas_path, result["data"]["content"], "schemas"))

            if include_migration:
                result = self.generate_migration_code(safe_context, normalized_models, migration_message, down_revision, run_metadata)
                if not result.get("success"):
                    return result
                artifacts.append(GeneratedArtifact("migration", result["data"]["relative_path"], result["data"]["content"], "migration"))

            if include_seed_data:
                result = self.generate_seed_data_code(safe_context, normalized_models, run_metadata)
                if not result.get("success"):
                    return result
                artifacts.append(GeneratedArtifact("seed_data", self.config.output_seed_path, result["data"]["content"], "seed_data"))

            write_result = None
            if write_files:
                write_result = self.write_artifacts(safe_context, artifacts, run_metadata)
                if not write_result.get("success"):
                    return write_result
                artifacts = [self._artifact_from_mapping(x) for x in write_result.get("data", {}).get("artifacts", [])]

            verification_payload = self._prepare_verification_payload(
                safe_context,
                "database_builder.build_database_artifacts",
                True,
                {"artifact_count": len(artifacts), "model_count": len(normalized_models), "write_files": write_files},
            )
            memory_payload = self._prepare_memory_payload(
                safe_context,
                "database_artifacts_generated",
                {
                    "model_names": [m.class_name for m in normalized_models],
                    "table_names": [m.table_name for m in normalized_models],
                    "artifact_paths": [a.relative_path for a in artifacts],
                    "write_files": write_files,
                },
            )
            self._log_audit_event(safe_context, "database_builder.build_database_artifacts", "success", {
                "model_count": len(normalized_models),
                "artifact_count": len(artifacts),
                "write_files": write_files,
            })
            self._emit_agent_event("code_agent.database_builder.completed", {
                "context": self._context_public_dict(safe_context),
                "success": True,
                "artifact_count": len(artifacts),
                "write_files": write_files,
            })
            return self._safe_result(True, "Database artifacts generated successfully.", {
                "started_at": started_at,
                "completed_at": self._utc_now(),
                "models": [m.to_dict() for m in normalized_models],
                "artifacts": [a.to_dict() for a in artifacts],
                "write_result": write_result,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            }, metadata={"agent": self.agent_name, "module": self.agent_type, **run_metadata})
        except Exception as exc:
            self.logger.exception("DatabaseBuilder failed")
            self._log_audit_event(safe_context, "database_builder.build_database_artifacts", "error", {"error": str(exc)})
            return self._error_result("Database artifact generation failed unexpectedly.", exc, metadata={"agent": self.agent_name, **run_metadata})

    def validate_model_definitions(
        self,
        context: Union[BuilderTaskContext, Mapping[str, Any]],
        models: Sequence[Union[ModelDefinition, Mapping[str, Any]]],
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        safe_context = self._coerce_context(context)
        validation = self._validate_task_context(safe_context)
        if not validation["success"]:
            return validation
        normalized_models = self._coerce_model_definitions(models)
        errors: List[Dict[str, Any]] = []
        warnings: List[Dict[str, Any]] = []
        class_names: set[str] = set()
        table_names: set[str] = set()

        if not normalized_models:
            errors.append({"code": "no_models", "message": "At least one model definition is required."})

        for model in normalized_models:
            if not self._is_safe_class_name(model.class_name):
                errors.append({"code": "invalid_class_name", "model": model.class_name, "message": "class_name must be PascalCase safe identifier."})
            if not self._is_safe_table_name(model.table_name):
                errors.append({"code": "invalid_table_name", "table": model.table_name, "message": "table_name must be lowercase snake_case."})
            if model.class_name in class_names:
                errors.append({"code": "duplicate_class_name", "model": model.class_name})
            if model.table_name in table_names:
                errors.append({"code": "duplicate_table_name", "table": model.table_name})
            class_names.add(model.class_name)
            table_names.add(model.table_name)
            field_names = set()
            has_pk = False
            for f in model.fields:
                if not self._is_safe_identifier(f.name):
                    errors.append({"code": "invalid_field_name", "model": model.class_name, "field": f.name})
                if f.name in field_names:
                    errors.append({"code": "duplicate_field_name", "model": model.class_name, "field": f.name})
                field_names.add(f.name)
                has_pk = has_pk or f.primary_key
                if f.foreign_key and "." not in f.foreign_key:
                    errors.append({"code": "invalid_foreign_key", "model": model.class_name, "field": f.name, "foreign_key": f.foreign_key})
            if not has_pk:
                warnings.append({"code": "missing_primary_key", "model": model.class_name, "message": "Generated code will add id primary key."})
            if self.config.enforce_tenant_fields:
                missing = [x for x in ("user_id", "workspace_id") if x not in field_names]
                if missing:
                    warnings.append({"code": "tenant_fields_missing", "model": model.class_name, "missing": missing, "message": "Generated code will add tenant fields."})
            allowed_generated = {"id", "user_id", "workspace_id", "created_at", "updated_at", "deleted_at"}
            for idx in model.indexes:
                if not self._is_safe_identifier(idx.name):
                    errors.append({"code": "invalid_index_name", "model": model.class_name, "index": idx.name})
                for col in idx.columns:
                    if col not in field_names and col not in allowed_generated:
                        errors.append({"code": "index_column_missing", "model": model.class_name, "index": idx.name, "column": col})
            for rel in model.relationships:
                if not self._is_safe_identifier(rel.name):
                    errors.append({"code": "invalid_relationship_name", "model": model.class_name, "relationship": rel.name})
                if not self._is_safe_class_name(rel.target_model):
                    errors.append({"code": "invalid_relationship_target", "model": model.class_name, "target_model": rel.target_model})
        return self._safe_result(not errors, "Model definitions validated." if not errors else "Model definition validation failed.", {
            "valid": not errors,
            "errors": errors,
            "warnings": warnings,
            "model_count": len(normalized_models),
        }, metadata={"agent": self.agent_name, **dict(metadata or {})})

    def generate_models_code(self, context: Union[BuilderTaskContext, Mapping[str, Any]], models: Sequence[Union[ModelDefinition, Mapping[str, Any]]], metadata: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        safe_context = self._coerce_context(context)
        validation = self._validate_task_context(safe_context)
        if not validation["success"]:
            return validation
        normalized_models = self._coerce_model_definitions(models)
        validation_result = self.validate_model_definitions(safe_context, normalized_models)
        if not validation_result.get("success"):
            return validation_result
        content = "\n\n".join([
            self._generated_header("SQLAlchemy models generated by DatabaseBuilder"),
            self._generate_models_imports(normalized_models),
            self._generate_models_base_block(),
            *[self._generate_single_model_code(m) for m in normalized_models],
        ]).rstrip() + "\n"
        size = self._validate_generated_size(content)
        if not size["success"]:
            return size
        return self._safe_result(True, "SQLAlchemy model code generated.", {"content": content, "model_count": len(normalized_models), "relative_path": self.config.output_models_path}, metadata={"agent": self.agent_name, **dict(metadata or {})})

    def generate_schemas_code(self, context: Union[BuilderTaskContext, Mapping[str, Any]], models: Sequence[Union[ModelDefinition, Mapping[str, Any]]], metadata: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        safe_context = self._coerce_context(context)
        validation = self._validate_task_context(safe_context)
        if not validation["success"]:
            return validation
        normalized_models = self._coerce_model_definitions(models)
        validation_result = self.validate_model_definitions(safe_context, normalized_models)
        if not validation_result.get("success"):
            return validation_result
        content = "\n\n".join([
            self._generated_header("Pydantic schemas generated by DatabaseBuilder"),
            self._generate_schema_imports(normalized_models),
            *[self._generate_single_schema_code(m) for m in normalized_models],
        ]).rstrip() + "\n"
        size = self._validate_generated_size(content)
        if not size["success"]:
            return size
        return self._safe_result(True, "Pydantic schema code generated.", {"content": content, "model_count": len(normalized_models), "relative_path": self.config.output_schemas_path}, metadata={"agent": self.agent_name, **dict(metadata or {})})

    def generate_migration_code(self, context: Union[BuilderTaskContext, Mapping[str, Any]], models: Sequence[Union[ModelDefinition, Mapping[str, Any]]], message: str = "create william jarvis tables", down_revision: Optional[str] = None, metadata: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        safe_context = self._coerce_context(context)
        validation = self._validate_task_context(safe_context)
        if not validation["success"]:
            return validation
        normalized_models = self._coerce_model_definitions(models)
        validation_result = self.validate_model_definitions(safe_context, normalized_models)
        if not validation_result.get("success"):
            return validation_result
        revision_id = self._generate_revision_id(message)
        migration = self._build_migration_definition(normalized_models, revision_id, down_revision, message)
        content = self._render_migration_code(migration)
        relative_path = str(Path(self.config.migrations_dir) / f"{revision_id}_{self._slugify(message)}.py")
        size = self._validate_generated_size(content)
        if not size["success"]:
            return size
        return self._safe_result(True, "Alembic migration code generated.", {"content": content, "migration": migration.to_dict(), "relative_path": relative_path}, metadata={"agent": self.agent_name, **dict(metadata or {})})

    def generate_seed_data_code(self, context: Union[BuilderTaskContext, Mapping[str, Any]], models: Sequence[Union[ModelDefinition, Mapping[str, Any]]], metadata: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        safe_context = self._coerce_context(context)
        validation = self._validate_task_context(safe_context)
        if not validation["success"]:
            return validation
        normalized_models = self._coerce_model_definitions(models)
        content = self._render_seed_data_code(normalized_models)
        size = self._validate_generated_size(content)
        if not size["success"]:
            return size
        return self._safe_result(True, "Seed data code generated.", {"content": content, "model_count": len(normalized_models), "relative_path": self.config.output_seed_path}, metadata={"agent": self.agent_name, **dict(metadata or {})})

    def write_artifacts(self, context: Union[BuilderTaskContext, Mapping[str, Any]], artifacts: Sequence[Union[GeneratedArtifact, Mapping[str, Any]]], metadata: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        safe_context = self._coerce_context(context)
        validation = self._validate_task_context(safe_context)
        if not validation["success"]:
            return validation
        normalized = [self._artifact_from_mapping(x) for x in artifacts]
        if not self.config.allow_file_writes:
            return self._error_result("File writes are disabled by DatabaseBuilder config.", "file_writes_disabled", {"artifact_count": len(normalized)}, {"agent": self.agent_name, **dict(metadata or {})})
        errors = []
        for artifact in normalized:
            result = self._validate_artifact_write_target(artifact)
            if not result.get("success"):
                errors.append({"artifact": artifact.to_dict(), "error": result.get("error"), "message": result.get("message")})
        if errors:
            return self._error_result("One or more artifact paths are unsafe.", "unsafe_artifact_paths", {"errors": errors}, {"agent": self.agent_name, **dict(metadata or {})})
        if self._requires_security_check("file_write", "database_artifacts"):
            approval = self._request_security_approval(safe_context, "database_builder.write_artifacts", "file_system", {"artifacts": [{"name": a.name, "relative_path": a.relative_path, "artifact_type": a.artifact_type} for a in normalized]})
            if not approval.get("success"):
                return approval
        written = [self._write_single_artifact(a) for a in normalized]
        error_count = sum(1 for a in written if a.error)
        self._log_audit_event(safe_context, "database_builder.write_artifacts", "success" if error_count == 0 else "partial", {"artifact_count": len(written), "error_count": error_count})
        return self._safe_result(error_count == 0, "Artifacts written successfully." if error_count == 0 else "Some artifacts failed to write.", {"artifacts": [a.to_dict() for a in written]}, metadata={"agent": self.agent_name, **dict(metadata or {})})

    def _generate_models_imports(self, models: Sequence[ModelDefinition]) -> str:
        sa_types = {"Column", "DateTime", "ForeignKey", "Index", "Integer", "String", "func"}
        needs_relationship = any(m.relationships for m in models)
        for m in models:
            for f in self._fields_with_defaults(m):
                sa_types.add(self._sqlalchemy_type_name(f).split("(", 1)[0])
        lines = [
            "from __future__ import annotations", "",
            "from datetime import datetime", "from typing import Any, Dict, Optional", "",
            f"from sqlalchemy import {', '.join(sorted(sa_types))}",
        ]
        if needs_relationship:
            lines.append("from sqlalchemy.orm import relationship")
        lines.append("from sqlalchemy.orm import declarative_base")
        return "\n".join(lines)

    def _generate_models_base_block(self) -> str:
        return "\n".join([
            "Base = declarative_base()", "", "",
            "class TenantMixin:",
            "    \"\"\"Tenant isolation mixin for William/Jarvis SaaS workspaces.\"\"\"",
            "    user_id = Column(Integer, nullable=False, index=True)",
            "    workspace_id = Column(Integer, nullable=False, index=True)", "", "",
            "class TimestampMixin:",
            "    \"\"\"Standard created/updated timestamps.\"\"\"",
            "    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)",
            "    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)",
        ])

    def _generate_single_model_code(self, model: ModelDefinition) -> str:
        bases = ["Base"]
        if self.config.enforce_tenant_fields:
            bases.append("TenantMixin")
        if self.config.include_timestamp_columns:
            bases.append("TimestampMixin")
        lines = [f"class {model.class_name}({', '.join(bases)}):", f"    \"\"\"{self._escape_docstring(model.description or model.class_name + ' database model.')}\"\"\"", f"    __tablename__ = {model.table_name!r}", ""]
        table_args = self._generate_table_args(model)
        if table_args:
            lines.extend(table_args)
            lines.append("")
        for f in self._fields_with_defaults(model):
            if self._field_is_provided_by_mixins(f.name):
                continue
            lines.append(f"    {f.name} = {self._render_sqlalchemy_column(f)}")
        if model.relationships:
            lines.append("")
            for rel in model.relationships:
                lines.append(f"    {rel.name} = {self._render_relationship(rel)}")
        if self.config.include_repr_methods:
            lines.extend(["", "    def __repr__(self) -> str:", f"        return f\"<{model.class_name}(id={{getattr(self, 'id', None)}})>\""])
        return "\n".join(lines)

    def _generate_table_args(self, model: ModelDefinition) -> List[str]:
        if not self.config.include_table_args:
            return []
        indexes = list(model.indexes)
        if self.config.enforce_tenant_fields:
            name = f"ix_{model.table_name}_tenant"
            if not any(i.name == name for i in indexes):
                indexes.append(IndexDefinition(name, ["user_id", "workspace_id"]))
        items = []
        for idx in indexes:
            args = ", ".join([repr(idx.name), *[repr(c) for c in idx.columns]])
            if idx.unique:
                args += ", unique=True"
            items.append(f"Index({args})")
        if not items:
            return []
        if len(items) == 1:
            return [f"    __table_args__ = ({items[0]},)"]
        return ["    __table_args__ = (", *[f"        {x}," for x in items], "    )"]

    def _render_sqlalchemy_column(self, f: FieldDefinition) -> str:
        args = [self._sqlalchemy_type_name(f)]
        if f.foreign_key:
            args.append(f"ForeignKey({f.foreign_key!r})")
        kwargs = []
        if f.primary_key:
            kwargs.append("primary_key=True")
            if self.config.default_id_autoincrement and f.name == "id":
                kwargs.append("autoincrement=True")
        kwargs.append(f"nullable={bool(f.nullable and not f.primary_key)}")
        if f.unique:
            kwargs.append("unique=True")
        if f.index:
            kwargs.append("index=True")
        if f.default is not None:
            kwargs.append(f"default={self._python_literal(f.default)}")
        if f.server_default is not None:
            kwargs.append(f"server_default={self._python_literal(f.server_default)}")
        return f"Column({', '.join([*args, *kwargs])})"

    def _render_relationship(self, rel: RelationshipDefinition) -> str:
        args = [repr(rel.target_model)]
        kwargs = []
        if rel.back_populates:
            kwargs.append(f"back_populates={rel.back_populates!r}")
        if rel.cascade:
            kwargs.append(f"cascade={rel.cascade!r}")
        if rel.uselist is not None:
            kwargs.append(f"uselist={rel.uselist!r}")
        if rel.lazy:
            kwargs.append(f"lazy={rel.lazy!r}")
        return f"relationship({', '.join([*args, *kwargs])})"

    def _generate_schema_imports(self, models: Sequence[ModelDefinition]) -> str:
        need_decimal = need_date = need_datetime = need_time = need_any = need_dict = False
        for m in models:
            for f in self._fields_with_defaults(m):
                t = self._python_type_name(f)
                need_decimal |= "Decimal" in t
                need_date |= t == "date"
                need_datetime |= t == "datetime"
                need_time |= t == "time"
                need_any |= "Any" in t
                need_dict |= "Dict" in t
        lines = ["from __future__ import annotations", ""]
        dt = []
        if need_date: dt.append("date")
        if need_datetime: dt.append("datetime")
        if need_time: dt.append("time")
        if dt:
            lines.append(f"from datetime import {', '.join(sorted(dt))}")
        if need_decimal:
            lines.append("from decimal import Decimal")
        typing_items = ["Optional"]
        if need_any: typing_items.append("Any")
        if need_dict: typing_items.append("Dict")
        lines.append(f"from typing import {', '.join(sorted(set(typing_items)))}")
        lines.extend(["", "from pydantic import BaseModel, Field"])
        if self.config.use_pydantic_v2:
            lines.append("from pydantic import ConfigDict")
        return "\n".join(lines)

    def _generate_single_schema_code(self, model: ModelDefinition) -> str:
        fields = self._fields_with_defaults(model)
        writable = [f for f in fields if not f.primary_key and not f.read_only and f.name not in {"created_at", "updated_at", "deleted_at"} and not (self.config.enforce_tenant_fields and f.name in {"user_id", "workspace_id"})]
        base = [f"class {model.class_name}Base(BaseModel):", f"    \"\"\"Base schema for {model.class_name}.\"\"\""]
        if writable:
            base.extend([f"    {f.name}: {self._schema_type_annotation(f, False)}" for f in writable])
        else:
            base.append("    pass")
        create = ["", f"class {model.class_name}Create({model.class_name}Base):", f"    \"\"\"Create schema for {model.class_name}.\"\"\"", "    pass"]
        update = ["", f"class {model.class_name}Update(BaseModel):", f"    \"\"\"Update schema for {model.class_name}. All fields are optional.\"\"\""]
        if writable:
            update.extend([f"    {f.name}: {self._schema_type_annotation(f, True)}" for f in writable])
        else:
            update.append("    pass")
        read = ["", f"class {model.class_name}Read({model.class_name}Base):", f"    \"\"\"Read schema for {model.class_name}.\"\"\""]
        read.extend([f"    {f.name}: {self._schema_type_annotation(f, False, force_optional=f.nullable)}" for f in fields])
        if self.config.use_pydantic_v2:
            read.extend(["", "    model_config = ConfigDict(from_attributes=True)"])
        else:
            read.extend(["", "    class Config:", "        orm_mode = True"])
        return "\n".join([*base, *create, *update, *read])

    def _schema_type_annotation(self, f: FieldDefinition, for_update: bool, force_optional: bool = False) -> str:
        py_type = self._python_type_name(f)
        optional = for_update or force_optional or f.nullable
        if optional:
            return f"Optional[{py_type}] = Field(default=None, description={f.description!r})"
        if f.default is not None:
            return f"{py_type} = Field(default={self._python_literal(f.default)}, description={f.description!r})"
        return f"{py_type} = Field(..., description={f.description!r})"

    def _build_migration_definition(self, models: Sequence[ModelDefinition], revision_id: str, down_revision: Optional[str], message: str) -> MigrationDefinition:
        upgrade_ops: List[str] = []
        downgrade_ops: List[str] = []
        for model in models:
            upgrade_ops.extend(self._migration_create_table_ops(model))
            downgrade_ops.insert(0, f'op.drop_table("{model.table_name}")')
        return MigrationDefinition(revision_id, down_revision, message, upgrade_ops, downgrade_ops)

    def _migration_create_table_ops(self, model: ModelDefinition) -> List[str]:
        lines = [f'op.create_table("{model.table_name}",']
        for f in self._fields_with_defaults(model):
            lines.append(f"    {self._render_alembic_column(f)},")
        lines.append(")")
        ops = ["\n".join(lines)]
        indexes = list(model.indexes)
        if self.config.enforce_tenant_fields:
            name = f"ix_{model.table_name}_tenant"
            if not any(i.name == name for i in indexes):
                indexes.append(IndexDefinition(name, ["user_id", "workspace_id"]))
        for idx in indexes:
            cols = ", ".join(repr(c) for c in idx.columns)
            ops.append(f'op.create_index("{idx.name}", "{model.table_name}", [{cols}], unique={idx.unique})')
        return ops

    def _render_alembic_column(self, f: FieldDefinition) -> str:
        args = [repr(f.name), f"sa.{self._sqlalchemy_type_name(f)}"]
        if f.foreign_key:
            args.append(f"sa.ForeignKey({f.foreign_key!r})")
        kwargs = []
        if f.primary_key:
            kwargs.append("primary_key=True")
            if f.name == "id" and self.config.default_id_autoincrement:
                kwargs.append("autoincrement=True")
        kwargs.append(f"nullable={bool(f.nullable and not f.primary_key)}")
        if f.unique: kwargs.append("unique=True")
        if f.index: kwargs.append("index=True")
        if f.server_default is not None: kwargs.append(f"server_default={self._python_literal(f.server_default)}")
        return f"sa.Column({', '.join([*args, *kwargs])})"

    def _render_migration_code(self, migration: MigrationDefinition) -> str:
        down = "None" if migration.down_revision is None else repr(migration.down_revision)
        upgrade_body = self._indent_lines("\n\n".join(migration.upgrade_ops) if migration.upgrade_ops else "pass", 4)
        downgrade_body = self._indent_lines("\n\n".join(migration.downgrade_ops) if migration.downgrade_ops else "pass", 4)
        return "\n".join([
            self._generated_header("Alembic migration generated by DatabaseBuilder"),
            "from __future__ import annotations", "", "from alembic import op", "import sqlalchemy as sa", "",
            f"revision = {migration.revision_id!r}", f"down_revision = {down}", "branch_labels = None", "depends_on = None", "", "",
            "def upgrade() -> None:", upgrade_body, "", "", "def downgrade() -> None:", downgrade_body, "",
        ])

    def _render_seed_data_code(self, models: Sequence[ModelDefinition]) -> str:
        model_import = "from models import " + ", ".join(m.class_name for m in models) if models else "pass"
        lines = [
            self._generated_header("Seed data generated by DatabaseBuilder"),
            "from __future__ import annotations", "", "from typing import Any, Dict, List", "", "try:", f"    {model_import}", "except Exception:", "    pass", "", "",
            "def get_seed_rows(user_id: int, workspace_id: int) -> Dict[str, List[Dict[str, Any]]]:",
            "    \"\"\"Return tenant-aware seed rows grouped by model class name.\"\"\"", "    return {",
        ]
        for model in models:
            rows = []
            for row in model.seed_rows:
                clean = dict(row)
                if self.config.enforce_tenant_fields:
                    clean.setdefault("user_id", "%%USER_ID%%")
                    clean.setdefault("workspace_id", "%%WORKSPACE_ID%%")
                rows.append(clean)
            rendered = json.dumps(rows, indent=8, ensure_ascii=False, default=str).replace('"%%USER_ID%%"', "user_id").replace('"%%WORKSPACE_ID%%"', "workspace_id")
            lines.append(f"        {model.class_name!r}: {rendered},")
        lines.extend([
            "    }", "", "",
            "def _replace_tenant_tokens(row: Dict[str, Any], user_id: int, workspace_id: int) -> Dict[str, Any]:",
            "    clean = dict(row)", "    if clean.get('user_id') == '%%USER_ID%%':", "        clean['user_id'] = user_id",
            "    if clean.get('workspace_id') == '%%WORKSPACE_ID%%':", "        clean['workspace_id'] = workspace_id", "    return clean", "", "",
            "def seed_database(session: Any, user_id: int, workspace_id: int, commit: bool = True) -> Dict[str, Any]:",
            "    \"\"\"Seed database with tenant-aware rows. Expects an SQLAlchemy session.\"\"\"",
            "    seed_rows = get_seed_rows(user_id=user_id, workspace_id=workspace_id)", "    inserted = {}", "    globals_map = globals()",
            "    for model_name, rows in seed_rows.items():", "        model_cls = globals_map.get(model_name)",
            "        if model_cls is None:", "            inserted[model_name] = {'inserted': 0, 'error': 'model_not_imported'}", "            continue",
            "        count = 0", "        for row in rows:", "            obj = model_cls(**_replace_tenant_tokens(row, user_id, workspace_id))", "            session.add(obj)", "            count += 1",
            "        inserted[model_name] = {'inserted': count, 'error': None}", "    if commit:", "        session.commit()", "    return {'success': True, 'inserted': inserted}", "",
        ])
        return "\n".join(lines)

    def _fields_with_defaults(self, model: ModelDefinition) -> List[FieldDefinition]:
        fields = list(model.fields)
        names = {f.name for f in fields}
        if "id" not in names:
            fields.insert(0, FieldDefinition("id", "int", False, primary_key=True, description="Primary key.", read_only=True))
        if self.config.enforce_tenant_fields:
            names = {f.name for f in fields}
            insert_at = 1 if fields and fields[0].name == "id" else 0
            if "workspace_id" not in names:
                fields.insert(insert_at, FieldDefinition("workspace_id", "int", False, index=True, description="Workspace isolation ID."))
            if "user_id" not in names:
                fields.insert(insert_at, FieldDefinition("user_id", "int", False, index=True, description="User isolation ID."))
        if self.config.include_timestamp_columns:
            names = {f.name for f in fields}
            if "created_at" not in names:
                fields.append(FieldDefinition("created_at", "datetime", False, server_default="func.now()", description="Creation timestamp.", read_only=True))
            if "updated_at" not in names:
                fields.append(FieldDefinition("updated_at", "datetime", False, server_default="func.now()", description="Last update timestamp.", read_only=True))
        if self.config.include_soft_delete_column and "deleted_at" not in {f.name for f in fields}:
            fields.append(FieldDefinition("deleted_at", "datetime", True, description="Soft delete timestamp.", read_only=True))
        return fields

    def _field_is_provided_by_mixins(self, field_name: str) -> bool:
        return (self.config.enforce_tenant_fields and field_name in {"user_id", "workspace_id"}) or (self.config.include_timestamp_columns and field_name in {"created_at", "updated_at"})

    def _sqlalchemy_type_name(self, f: FieldDefinition) -> str:
        normalized = str(f.type or "str").lower().strip()
        base = SQLALCHEMY_TYPE_MAP.get(normalized, "String")
        if base == "String":
            length = f.length or (255 if normalized in {"str", "string", "email"} else 2048 if normalized == "url" else 36 if normalized == "uuid" else 255)
            return f"String({int(length)})"
        if base == "Numeric" and f.max_digits and f.decimal_places is not None:
            return f"Numeric({int(f.max_digits)}, {int(f.decimal_places)})"
        return base

    def _python_type_name(self, f: FieldDefinition) -> str:
        return PYTHON_TYPE_MAP.get(str(f.type or "str").lower().strip(), "str")

    def _validate_artifact_write_target(self, artifact: GeneratedArtifact) -> Dict[str, Any]:
        if not artifact.relative_path:
            return self._error_result("Artifact relative_path is required.", "missing_relative_path")
        path = self._resolve_project_path(artifact.relative_path)
        if not self._is_path_inside_project(path):
            return self._error_result("Artifact path is outside project_root.", "path_outside_project", {"path": str(path)})
        if self._is_sensitive_path(str(path)):
            return self._error_result("Artifact path is sensitive and blocked.", "sensitive_path_blocked", {"path": str(path)})
        if self._is_in_blocked_directory(path):
            return self._error_result("Artifact path is inside a blocked directory.", "blocked_directory", {"path": str(path)})
        if path.suffix and path.suffix not in self.config.allowed_file_extensions:
            return self._error_result("Artifact extension is not allowed.", "extension_not_allowed", {"path": str(path), "extension": path.suffix})
        size = len(artifact.content.encode(self.config.encoding, errors="ignore"))
        if size > self.config.max_generated_file_bytes:
            return self._error_result("Generated artifact is too large.", "artifact_too_large", {"path": str(path), "size": size})
        return self._safe_result(True, "Artifact path validated.", {"path": str(path)})

    def _write_single_artifact(self, artifact: GeneratedArtifact) -> GeneratedArtifact:
        path = self._resolve_project_path(artifact.relative_path)
        artifact.absolute_path = str(path)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists() and self.config.create_backups:
                backup = self._build_backup_path(path)
                backup.write_text(path.read_text(encoding=self.config.encoding), encoding=self.config.encoding)
                artifact.backup_path = str(backup)
            path.write_text(artifact.content, encoding=self.config.encoding)
            artifact.written = True
            artifact.error = None
        except Exception as exc:
            artifact.written = False
            artifact.error = str(exc)
        return artifact

    def _validate_task_context(self, context: BuilderTaskContext) -> Dict[str, Any]:
        if context is None:
            return self._error_result("Task context is required.", "missing_context")
        if context.user_id in (None, "", 0):
            return self._error_result("user_id is required for DatabaseBuilder execution.", "missing_user_id")
        if context.workspace_id in (None, "", 0):
            return self._error_result("workspace_id is required for DatabaseBuilder execution.", "missing_workspace_id")
        return self._safe_result(True, "Task context validated.", {"context": self._context_public_dict(context)})

    def _requires_security_check(self, action: str, resource: Optional[str] = None) -> bool:
        if action == "file_write":
            return bool(self.config.require_security_for_writes)
        if action in {"migration_execute", "database_execute", "seed_execute"}:
            return True
        return True

    def _request_security_approval(self, context: BuilderTaskContext, action: str, resource: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        if self.security_agent is None:
            return self._error_result("Security approval is required but Security Agent is unavailable.", "security_agent_unavailable", {"approved": False, "action": action, "resource": resource})
        for method_name in ("approve_action", "request_approval", "check_permission", "authorize"):
            method = getattr(self.security_agent, method_name, None)
            if callable(method):
                try:
                    response = method(user_id=context.user_id, workspace_id=context.workspace_id, action=action, resource=resource, payload=dict(payload))
                    return self._normalize_security_response(response)
                except TypeError:
                    try:
                        response = method({"user_id": context.user_id, "workspace_id": context.workspace_id, "action": action, "resource": resource, "payload": dict(payload)})
                        return self._normalize_security_response(response)
                    except Exception as exc:
                        return self._error_result("Security approval failed.", exc)
                except Exception as exc:
                    return self._error_result("Security approval failed.", exc)
        return self._error_result("Security Agent does not expose an approval method.", "security_approval_method_missing", {"approved": False})

    def _prepare_verification_payload(self, context: BuilderTaskContext, action: str, success: bool, data: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        payload = {"agent": self.agent_name, "module": self.agent_type, "action": action, "success": success, "user_id": context.user_id, "workspace_id": context.workspace_id, "request_id": context.request_id, "data": dict(data or {}), "created_at": self._utc_now()}
        self._try_agent_payload(self.verification_agent, payload, ("prepare_payload", "build_payload", "receive_payload"), "verification_agent")
        return payload

    def _prepare_memory_payload(self, context: BuilderTaskContext, memory_type: str, content: Mapping[str, Any]) -> Dict[str, Any]:
        payload = {"agent": self.agent_name, "module": self.agent_type, "memory_type": memory_type, "user_id": context.user_id, "workspace_id": context.workspace_id, "request_id": context.request_id, "content": dict(content), "created_at": self._utc_now()}
        self._try_agent_payload(self.memory_agent, payload, ("prepare_memory", "build_memory_payload", "remember"), "memory_agent")
        return payload

    def _emit_agent_event(self, event_name: str, payload: Dict[str, Any]) -> None:
        event_payload = {"event": event_name, "agent": self.agent_name, "module": self.agent_type, "payload": payload, "created_at": self._utc_now()}
        try:
            if self.event_emitter:
                self.event_emitter(event_name, event_payload)
            elif callable(getattr(super(), "emit_event", None)):
                super().emit_event(event_name, event_payload)
            else:
                self.logger.debug("Agent event: %s", event_payload)
        except Exception:
            self.logger.debug("Failed to emit agent event", exc_info=True)

    def _log_audit_event(self, context: BuilderTaskContext, action: str, status: str, details: Optional[Mapping[str, Any]] = None) -> None:
        payload = {"agent": self.agent_name, "module": self.agent_type, "action": action, "status": status, "user_id": context.user_id, "workspace_id": context.workspace_id, "request_id": context.request_id, "details": dict(details or {}), "created_at": self._utc_now()}
        try:
            if self.audit_logger:
                self.audit_logger(payload)
            elif callable(getattr(super(), "log_audit", None)):
                super().log_audit(payload)
            else:
                self.logger.info("Audit event: %s", payload)
        except Exception:
            self.logger.debug("Failed to log audit event", exc_info=True)

    def _safe_result(self, success: bool, message: str, data: Optional[Mapping[str, Any]] = None, error: Optional[Any] = None, metadata: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        return {"success": bool(success), "message": message, "data": dict(data or {}), "error": self._serialize_error(error) if error else None, "metadata": {"agent": self.agent_name, "module": self.agent_type, "timestamp": self._utc_now(), **dict(metadata or {})}}

    def _error_result(self, message: str, error: Any, data: Optional[Mapping[str, Any]] = None, metadata: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        return self._safe_result(False, message, data or {}, error, metadata or {})

    def _coerce_context(self, context: Union[BuilderTaskContext, Mapping[str, Any]]) -> BuilderTaskContext:
        if isinstance(context, BuilderTaskContext):
            return context
        if isinstance(context, Mapping):
            permissions_raw = context.get("permissions", [])
            permissions = [permissions_raw] if isinstance(permissions_raw, str) else [str(x) for x in permissions_raw] if isinstance(permissions_raw, Iterable) else []
            metadata = dict(context.get("metadata", {})) if isinstance(context.get("metadata", {}), Mapping) else {}
            return BuilderTaskContext(context.get("user_id"), context.get("workspace_id"), context.get("request_id"), context.get("role"), permissions, metadata)
        return BuilderTaskContext(None, None)  # type: ignore[arg-type]

    def _coerce_model_definitions(self, models: Sequence[Union[ModelDefinition, Mapping[str, Any]]]) -> List[ModelDefinition]:
        normalized: List[ModelDefinition] = []
        for raw in models or []:
            if isinstance(raw, ModelDefinition):
                normalized.append(raw)
            elif isinstance(raw, Mapping):
                class_name = str(raw.get("class_name") or raw.get("name") or "")
                normalized.append(ModelDefinition(
                    class_name=class_name,
                    table_name=str(raw.get("table_name") or self._camel_to_snake(class_name)),
                    fields=[x for x in (self._coerce_field_definition(i) for i in raw.get("fields", []) or []) if x is not None],
                    relationships=[x for x in (self._coerce_relationship_definition(i) for i in raw.get("relationships", []) or []) if x is not None],
                    indexes=[x for x in (self._coerce_index_definition(i) for i in raw.get("indexes", []) or []) if x is not None],
                    description=raw.get("description"),
                    seed_rows=list(raw.get("seed_rows", []) or []),
                ))
        return normalized

    def _coerce_field_definition(self, raw: Any) -> Optional[FieldDefinition]:
        if isinstance(raw, FieldDefinition): return raw
        if not isinstance(raw, Mapping): return None
        return FieldDefinition(
            name=str(raw.get("name") or ""), type=str(raw.get("type") or "str"), nullable=bool(raw.get("nullable", True)), default=raw.get("default"), primary_key=bool(raw.get("primary_key", False)), unique=bool(raw.get("unique", False)), index=bool(raw.get("index", False)), foreign_key=raw.get("foreign_key"), length=self._optional_int(raw.get("length")), max_digits=self._optional_int(raw.get("max_digits")), decimal_places=self._optional_int(raw.get("decimal_places")), server_default=raw.get("server_default"), description=raw.get("description"), sensitive=bool(raw.get("sensitive", False)), read_only=bool(raw.get("read_only", False)),
        )

    def _coerce_relationship_definition(self, raw: Any) -> Optional[RelationshipDefinition]:
        if isinstance(raw, RelationshipDefinition): return raw
        if not isinstance(raw, Mapping): return None
        return RelationshipDefinition(str(raw.get("name") or ""), str(raw.get("target_model") or ""), raw.get("back_populates"), raw.get("cascade"), raw.get("uselist"), str(raw.get("lazy") or "selectin"))

    def _coerce_index_definition(self, raw: Any) -> Optional[IndexDefinition]:
        if isinstance(raw, IndexDefinition): return raw
        if not isinstance(raw, Mapping): return None
        cols_raw = raw.get("columns", []) or []
        cols = [cols_raw] if isinstance(cols_raw, str) else [str(x) for x in cols_raw]
        return IndexDefinition(str(raw.get("name") or ""), cols, bool(raw.get("unique", False)))

    def _artifact_from_mapping(self, raw: Union[GeneratedArtifact, Mapping[str, Any]]) -> GeneratedArtifact:
        if isinstance(raw, GeneratedArtifact):
            return raw
        return GeneratedArtifact(str(raw.get("name") or ""), str(raw.get("relative_path") or ""), str(raw.get("content") or ""), str(raw.get("artifact_type") or "unknown"), bool(raw.get("written", False)), raw.get("absolute_path"), raw.get("backup_path"), raw.get("error"))

    def _generated_header(self, title: str) -> str:
        return '\n'.join(['"""', title, '', 'Generated for the William / Jarvis Multi-Agent AI SaaS System.', 'Do not hardcode secrets in this file.', 'Every tenant-aware operation should use user_id and workspace_id.', '"""'])

    def _python_literal(self, value: Any) -> str:
        if isinstance(value, str):
            return "func.now()" if value == "func.now()" else repr(value)
        return repr(value)

    def _indent_lines(self, content: str, spaces: int = 4) -> str:
        pad = " " * spaces
        return "\n".join(pad + line if line.strip() else line for line in content.splitlines())

    def _escape_docstring(self, text: str) -> str:
        return str(text).replace('"""', '\\\"\\\"\\\"')

    def _generate_revision_id(self, message: str) -> str:
        return f"{self.config.migration_revision_prefix}_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}_{self._slugify(message)[:32]}"

    def _slugify(self, text: str) -> str:
        return re.sub(r"[^a-zA-Z0-9]+", "_", text.strip().lower()).strip("_") or "migration"

    def _camel_to_snake(self, text: str) -> str:
        if not text: return ""
        text = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", text)
        return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", text).lower()

    def _is_safe_identifier(self, value: str) -> bool:
        return bool(SAFE_IDENTIFIER_RE.match(value or "")) and not value.startswith("__")

    def _is_safe_class_name(self, value: str) -> bool:
        return self._is_safe_identifier(value) and value[:1].isupper()

    def _is_safe_table_name(self, value: str) -> bool:
        return bool(SAFE_TABLE_RE.match(value or ""))

    def _optional_int(self, value: Any) -> Optional[int]:
        if value in (None, ""): return None
        try: return int(value)
        except Exception: return None

    def _validate_generated_size(self, content: str) -> Dict[str, Any]:
        size = len(content.encode(self.config.encoding, errors="ignore"))
        if size > self.config.max_generated_file_bytes:
            return self._error_result("Generated content exceeds max size.", "generated_content_too_large", {"size": size, "max": self.config.max_generated_file_bytes})
        return self._safe_result(True, "Generated content size validated.", {"size": size})

    def _resolve_project_path(self, path: Union[str, Path]) -> Path:
        candidate = Path(path).expanduser()
        return candidate.resolve() if candidate.is_absolute() else (self.project_root / candidate).resolve()

    def _is_path_inside_project(self, path: Path) -> bool:
        try:
            path.resolve().relative_to(self.project_root)
            return True
        except Exception:
            return False

    def _is_sensitive_path(self, path: str) -> bool:
        lowered = path.replace("\\", "/").lower()
        parts = set(Path(lowered).parts)
        return any(p in parts for p in SENSITIVE_PATH_PARTS) or any(token in lowered for token in SENSITIVE_PATH_PARTS)

    def _is_in_blocked_directory(self, path: Path) -> bool:
        parts = {p.lower() for p in path.parts}
        return any(b.lower() in parts for b in self.config.blocked_directory_names)

    def _build_backup_path(self, target: Path) -> Path:
        return target.with_name(f"{target.name}.{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}{self.config.backup_suffix}")

    def _normalize_security_response(self, response: Any) -> Dict[str, Any]:
        if isinstance(response, Mapping):
            approved = bool(response.get("approved") if "approved" in response else response.get("success", False))
            if approved:
                return self._safe_result(True, str(response.get("message") or "Security approval granted."), {"approved": True, "security_response": dict(response)})
            return self._error_result(str(response.get("message") or "Security approval denied."), response.get("error") or "security_denied", {"approved": False, "security_response": dict(response)})
        if response is True:
            return self._safe_result(True, "Security approval granted.", {"approved": True})
        return self._error_result("Security approval denied.", "security_denied", {"approved": False, "security_response": response})

    def _try_agent_payload(self, agent: Optional[Any], payload: Dict[str, Any], methods: Sequence[str], prefix: str) -> None:
        if agent is None:
            return
        for name in methods:
            method = getattr(agent, name, None)
            if callable(method):
                try:
                    response = method(payload)
                    if isinstance(response, Mapping):
                        payload[f"{prefix}_response"] = dict(response)
                    return
                except Exception as exc:
                    payload[f"{prefix}_error"] = str(exc)
                    return

    def _safe_instantiate_agent(self, cls: Any) -> Optional[Any]:
        if cls is None:
            return None
        try:
            return cls()
        except Exception:
            try:
                return cls(user_id=None, workspace_id=None)
            except Exception:
                return None

    def _context_public_dict(self, context: BuilderTaskContext) -> Dict[str, Any]:
        return {"user_id": context.user_id, "workspace_id": context.workspace_id, "request_id": context.request_id, "role": context.role, "permissions": list(context.permissions), "metadata": dict(context.metadata)}

    def _serialize_error(self, error: Any) -> Dict[str, Any]:
        if isinstance(error, BaseException):
            return {"type": error.__class__.__name__, "message": str(error), "traceback": traceback.format_exc()}
        if isinstance(error, Mapping):
            return dict(error)
        return {"type": error.__class__.__name__ if error is not None else "None", "message": str(error)}

    def _utc_now(self) -> str:
        return datetime.now(timezone.utc).isoformat()


def _standalone_smoke_test() -> Dict[str, Any]:
    """Run a safe in-memory smoke test."""
    builder = DatabaseBuilder(DatabaseBuilderConfig(project_root=".", allow_file_writes=False, enforce_tenant_fields=True))
    models = [{
        "class_name": "AgentTask",
        "table_name": "agent_tasks",
        "description": "Task history for William/Jarvis agents.",
        "fields": [
            {"name": "title", "type": "str", "nullable": False, "length": 255},
            {"name": "status", "type": "str", "nullable": False, "length": 50, "index": True},
            {"name": "payload", "type": "json", "nullable": True},
        ],
        "indexes": [{"name": "ix_agent_tasks_status", "columns": ["status"], "unique": False}],
        "seed_rows": [{"title": "Welcome task", "status": "pending", "payload": {"source": "seed"}}],
    }]
    return builder.build_database_artifacts({"user_id": "demo_user", "workspace_id": "demo_workspace"}, models, write_files=False, metadata={"source": "standalone_smoke_test"})


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(json.dumps(_standalone_smoke_test(), indent=2, default=str))
