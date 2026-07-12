"""Capability data for the Code Agent (agent_key="code").

Purpose (from mission spec): Build, edit, debug, test, and deploy code safely.

Live MVP behavior:
- Analyze and propose patches.
- Run commands only with approval.
- No unsafe commands.
- No commit without explicit user command.
"""

from __future__ import annotations

import re
from typing import List, Optional

from agents.capability_manifest import (
    AgentCapabilityEntry,
    CapabilityPermissionLevel as Perm,
    CapabilityRiskLevel as Risk,
    CapabilityStatus as Status,
)

AGENT_KEY = "code"


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


def _cap(
    index: int,
    name: str,
    description: str,
    risk: Risk,
    permission: Perm,
    status: Status,
    safe_mvp_behavior: str,
    verification_method: str,
    memory_policy: str,
    audit_required: bool = True,
    required_integrations: Optional[List[str]] = None,
) -> AgentCapabilityEntry:
    return AgentCapabilityEntry(
        id=f"{AGENT_KEY}.{index:03d}_{_slug(name)}",
        name=name,
        description=description,
        risk_level=risk,
        permission_level=permission,
        status=status,
        required_integrations=required_integrations or [],
        safe_mvp_behavior=safe_mvp_behavior,
        verification_method=verification_method,
        memory_policy=memory_policy,
        audit_required=audit_required,
    )


DB_SCOPED = "Stored in the DB-backed memory table, keyed by user_id + workspace_id; never mixed across tenants."
EPHEMERAL = "Held only for the lifetime of the active task; not persisted to durable storage."
APPROVAL_GATED = "Executed/persisted only after explicit user/Security Agent approval; the request is logged either way."
NOT_PERSISTED = "Not persisted; returns an analysis result derived from already-available project files."

SCHEMA_CHECK = "VerificationAgent confirms response matches the normalized result schema."
DB_CHECK = "VerificationAgent confirms the expected row exists/changed in the memory table for the scoped user_id/workspace_id."
AUDIT_CHECK = "VerificationAgent confirms a matching audit log row was written for this action."
UNAVAILABLE_CHECK = "N/A while capability_status is external_dependency_required or planned; verification is skipped and surfaced as such."
FS_CHECK = "VerificationAgent confirms the target file(s) exist on disk with the expected updated content/mtime."
RUN_CHECK = "VerificationAgent confirms the command's exit code and captured output match the expected outcome before marking success."
GIT_CHECK = "VerificationAgent confirms the git working tree/history reflects the expected change via `git status`/`git log`."

CAPABILITIES: List[AgentCapabilityEntry] = [
    _cap(1, "Project structure analysis", "Analyze a project's directory/file structure.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Walks the project tree and summarizes structure using local static analysis.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(2, "Framework detection", "Detect which frameworks a project uses.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Inspects config/manifest files locally to identify frameworks in use.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(3, "Dependency file detection", "Detect a project's dependency manifest files (requirements.txt, package.json, etc).",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Scans the project tree locally for known dependency manifest filenames.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(4, "Generate folder structure plan", "Propose a folder/file structure plan for a new feature or project.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Generates a proposed structure as text/data without creating any files.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(5, "Generate full final files", "Generate complete new file contents for review/application.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Writes the generated file(s) to disk in the project workspace.", FS_CHECK, NOT_PERSISTED),
    _cap(6, "Patch existing files safely", "Apply a targeted patch to an existing file.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Applies the patch to the target file on disk and preserves surrounding content.", FS_CHECK, NOT_PERSISTED),
    _cap(7, "Exact block replacement mode", "Replace an exact matched block of code rather than rewriting a whole file.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Locates the exact matching block and replaces only that block on disk.", FS_CHECK, NOT_PERSISTED),
    _cap(8, "Preserve class/function names", "Ensure a patch does not accidentally rename existing classes/functions.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Diffs symbol names before/after a proposed patch and flags unintended renames.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(9, "Read logs and tracebacks", "Read and parse application logs/error tracebacks.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Reads the supplied log/traceback text and parses it into a structured error summary.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(10, "Root-cause analysis", "Analyze a bug/error to identify its likely root cause.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Cross-references the parsed traceback with the relevant source files to propose a root cause.",
         SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(11, "Self-debug loop with max attempts", "Iteratively propose and apply fixes for a failing test/build, bounded by a max-attempts limit.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Applies successive local patches up to a configured attempt limit, stopping and reporting if unresolved.",
         FS_CHECK, EPHEMERAL),
    _cap(12, "Run syntax checks with approval", "Run a syntax/compile check against modified code, only with approval.",
         Risk.LOW, Perm.APPROVAL_REQUIRED, Status.APPROVAL_REQUIRED,
         "Returns approval_required; once approved, runs a local syntax/compile check (no network access) and reports the result.",
         RUN_CHECK, APPROVAL_GATED),
    _cap(13, "Run tests with approval", "Run the project's test suite, only with approval.",
         Risk.MEDIUM, Perm.APPROVAL_REQUIRED, Status.APPROVAL_REQUIRED,
         "Returns approval_required; once approved, runs the local test suite (e.g. pytest) and reports pass/fail results.",
         RUN_CHECK, APPROVAL_GATED),
    _cap(14, "Run frontend build with approval", "Run the dashboard's frontend build, only with approval.",
         Risk.MEDIUM, Perm.APPROVAL_REQUIRED, Status.APPROVAL_REQUIRED,
         "Returns approval_required; once approved, runs the local frontend build command and reports the result.",
         RUN_CHECK, APPROVAL_GATED),
    _cap(15, "Run backend smoke tests", "Run a lightweight backend smoke-test pass, only with approval.",
         Risk.MEDIUM, Perm.APPROVAL_REQUIRED, Status.APPROVAL_REQUIRED,
         "Returns approval_required; once approved, runs the local API-smoke test path and reports the result.",
         RUN_CHECK, APPROVAL_GATED),
    _cap(16, "Generate unit tests", "Generate unit test files for existing code.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Writes generated unit test file(s) to disk; does not execute them.", FS_CHECK, NOT_PERSISTED),
    _cap(17, "Generate API tests", "Generate API-level test files for existing endpoints.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Writes generated API test file(s) to disk; does not execute them.", FS_CHECK, NOT_PERSISTED),
    _cap(18, "Generate integration tests", "Generate integration test files spanning multiple components.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Writes generated integration test file(s) to disk; does not execute them.", FS_CHECK, NOT_PERSISTED),
    _cap(19, "Generate docs/README", "Generate documentation or a README file for a project/module.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Writes the generated documentation file to disk.", FS_CHECK, NOT_PERSISTED),
    _cap(20, "Generate Docker files", "Generate a Dockerfile/docker-compose configuration for a project.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Writes the generated Docker configuration file(s) to disk; does not build or run any image.", FS_CHECK, NOT_PERSISTED),
    _cap(21, "Generate CI/CD workflows", "Generate a CI/CD pipeline configuration file.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Writes the generated CI/CD workflow file to disk; does not trigger any pipeline run.", FS_CHECK, NOT_PERSISTED),
    _cap(22, "Git status with approval", "Show the current git working-tree status, only with approval.",
         Risk.LOW, Perm.APPROVAL_REQUIRED, Status.APPROVAL_REQUIRED,
         "Returns approval_required; once approved, runs `git status` locally and reports the result. Read-only, no mutation.",
         GIT_CHECK, APPROVAL_GATED),
    _cap(23, "Git diff summary", "Summarize the current git diff.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Runs `git diff` locally (read-only) and summarizes the changes.", GIT_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(24, "Git commit only with explicit approval", "Create a git commit, only with the user's explicit approval.",
         Risk.HIGH, Perm.APPROVAL_REQUIRED, Status.APPROVAL_REQUIRED,
         "Refuses to commit unless the user has given an explicit commit instruction; commits locally once approved.",
         GIT_CHECK, APPROVAL_GATED),
    _cap(25, "Rollback unsafe patches", "Revert a previously applied patch found to be unsafe/broken.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Reverts the target file(s) to their pre-patch state on disk.", FS_CHECK, NOT_PERSISTED),
    _cap(26, "Database model builder", "Generate SQLAlchemy/ORM model code for a new entity.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Writes the generated model file to disk following the project's existing model conventions.", FS_CHECK, NOT_PERSISTED),
    _cap(27, "Migration generator", "Generate a database migration file for a schema change.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Writes the generated migration file to disk; does not apply it to any database.", FS_CHECK, NOT_PERSISTED),
    _cap(28, "REST API builder", "Generate REST API endpoint code.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Writes the generated endpoint code to disk following existing route conventions.", FS_CHECK, NOT_PERSISTED),
    _cap(29, "FastAPI router builder", "Generate a new FastAPI router module.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Writes the generated router file to disk following the project's router conventions.", FS_CHECK, NOT_PERSISTED),
    _cap(30, "React/Next page builder", "Generate a new React/Next.js page/component for the dashboard.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Writes the generated page/component file to disk under apps/dashboard.", FS_CHECK, NOT_PERSISTED),
    _cap(31, "Flutter screen builder", "Generate a new Flutter screen/widget.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Writes the generated Flutter screen file to disk following the project's conventions.", FS_CHECK, NOT_PERSISTED),
    _cap(32, "Android Kotlin module builder", "Generate a new Android Kotlin module (e.g. a worker-node bridge).",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Writes the generated Kotlin module file(s) to disk under apps/worker_nodes/android.", FS_CHECK, NOT_PERSISTED),
    _cap(33, "Package/dependency manager", "Install/update a package dependency for a project.",
         Risk.HIGH, Perm.APPROVAL_REQUIRED, Status.APPROVAL_REQUIRED,
         "Returns approval_required; once approved, runs the local package manager (pip/npm) command and reports the result.",
         RUN_CHECK, APPROVAL_GATED),
    _cap(34, "Security scan for secrets", "Scan source files for accidentally committed secrets/credentials.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Runs a local regex/pattern scan for secret-like strings across the project tree.", SCHEMA_CHECK, NOT_PERSISTED),
    _cap(35, "Injection risk scan", "Scan source code for likely SQL/command injection vulnerabilities.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Runs a local static-analysis pattern scan for unsafe query/command construction.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(36, "User/workspace isolation checker", "Check code paths for missing user_id/workspace_id scoping.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Runs a local static-analysis pass looking for DB/queries missing user_id/workspace_id filters.",
         SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(37, "Endpoint health checker", "Check whether configured API endpoints respond correctly.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Issues local health-check requests against configured endpoints and reports status.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(38, "Deployment assistant", "Assist with deploying the application to a hosting target.",
         Risk.HIGH, Perm.APPROVAL_REQUIRED, Status.EXTERNAL_DEPENDENCY_REQUIRED,
         "Returns approval_required and external_dependency_required until deployment target credentials are configured; no deploy runs without both.",
         RUN_CHECK, APPROVAL_GATED, required_integrations=["deployment_target_credentials"]),
    _cap(39, "APK build assistant", "Assist with building an Android APK from the mobile worker-node project.",
         Risk.MEDIUM, Perm.APPROVAL_REQUIRED, Status.EXTERNAL_DEPENDENCY_REQUIRED,
         "Returns approval_required and external_dependency_required until an Android build toolchain/SDK is configured.",
         RUN_CHECK, APPROVAL_GATED, required_integrations=["android_build_toolchain"]),
    _cap(40, "Code style normalization", "Normalize code style/formatting (black/prettier) across changed files.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Runs the project's local formatter against changed files and writes the formatted result to disk.",
         FS_CHECK, NOT_PERSISTED),
    _cap(41, "Compatibility stubs for missing files", "Generate an import-safe stub for a not-yet-built dependency module.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Writes a stub module to disk following this repo's import-safe try/except fallback pattern.", FS_CHECK, NOT_PERSISTED),
    _cap(42, "Environment config validator", "Validate a project's .env file against its .env.example template.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Compares .env against .env.example locally and reports missing/extra keys.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(43, "TypeScript error fixer", "Propose/apply fixes for TypeScript compiler errors in the dashboard.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Parses tsc error output and applies a targeted patch to the offending file(s) on disk.", FS_CHECK, NOT_PERSISTED),
    _cap(44, "Python import graph checker", "Report a project's Python module import graph.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Statically parses import statements across the project tree to build the graph.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(45, "Circular import detector", "Detect circular import chains in the Python codebase.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Analyzes the local import graph for cycles and reports the offending chain.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(46, "Test coverage summary", "Summarize existing test coverage results.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Parses an already-generated coverage report and summarizes it; does not run tests itself.",
         SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(47, "Changelog writer", "Generate a changelog entry from recent git history.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Reads local git log output and writes a generated changelog file to disk.", FS_CHECK, NOT_PERSISTED),
    _cap(48, "Architecture report writer", "Generate a written summary of the project's architecture.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Analyzes the project tree/imports and writes a generated architecture report file to disk.", FS_CHECK, NOT_PERSISTED),
    _cap(49, "Code memory save", "Save code-related notes/conventions to memory for future tasks.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Stores the note via the DB-backed memory table with a code-convention tag.", DB_CHECK, DB_SCOPED, audit_required=False),
    _cap(50, "Code Agent health/dependency check", "Report Code Agent health and which build/test/deploy tooling is configured.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Reports process health plus whether local test/build tooling and deployment credentials are configured.",
         SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
]

assert len(CAPABILITIES) == 50, f"code capability_data must declare exactly 50 entries, got {len(CAPABILITIES)}"
