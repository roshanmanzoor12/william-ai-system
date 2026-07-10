# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

William / Jarvis — a multi-agent AI SaaS system by Digital Promotix. A FastAPI backend routes tasks
through a Master Agent to ~15 specialized agents (voice, system, browser, code, memory, security,
verification, visual, workflow, hologram, call, business, finance, creator), all behind SaaS user/workspace
isolation. Frontend is a separate Next.js dashboard in `apps/dashboard`.

Most of the codebase is deliberately **import-safe scaffolding**: modules catch import errors for
not-yet-built dependencies and fall back to stubs rather than crashing (see "Import-safe" pattern below).
Expect large docstring headers on nearly every file restating the SaaS isolation and safety rules — treat
those as authoritative when editing that file.

## Commands

### Python backend

```bash
python -m venv .venv && .venv\Scripts\activate      # Windows
pip install -r requirements.txt
Copy-Item .env.example .env                          # then edit values

uvicorn main:app --host 0.0.0.0 --port 8000 --reload  # dev server
pytest                                                 # all tests
pytest -v
pytest tests/test_health.py                            # single file
pytest tests/integration_tests/test_saas_isolation.py
pytest tests/agent_tests/test_security_agent.py
pytest -k test_name                                    # single test by name
```

There is no `pyproject.toml`/`pytest.ini`/lint config at the root, so `black`/`ruff`/`mypy`/`isort` (all in
requirements.txt) run with defaults if invoked manually — no enforced project-wide config exists yet.

`main.py` is the CLI/orchestration entrypoint (not the FastAPI app): it boots the Master/Registry/Router
chain directly for local testing without HTTP.

```bash
python main.py --boot                    # boot and print result
python main.py --smoke-test
python main.py --status
python main.py --task '{"agent":"creator","action":"...","user_id":"u1","workspace_id":"w1","input":{}}'
python main.py --cli                      # interactive typed CLI
python main.py --voice [--listen]         # voice mode (pyttsx3 / SpeechRecognition, optional)
```

The actual HTTP API app lives at `apps/api/main.py` (FastAPI), separate from `main.py`.

### Whole-project structural test runner

`test_william_project.py` (root) scans the whole tree — checks expected files/folders exist, Python files
compile, config parses, imports are safe, and can optionally run pytest / smoke-import the API / build the
dashboard. Useful before large refactors:

```bash
python test_william_project.py --root . --all       # imports + pytest + API smoke + dashboard build
python test_william_project.py --root . --strict     # fail if expected high-level files missing
python test_william_project.py --root . --import-python
python test_william_project.py --root . --api-smoke
python test_william_project.py --root . --dashboard-build
```

Writes a JSON report to `william_test_report.json` by default. `test_security_module.py` is a standalone
smoke test for `security/secrets_manager.py` and `security/encryption.py`.

### Dashboard (`apps/dashboard`, Next.js/TypeScript)

```bash
npm run dev            # dev server (next dev)
npm run build
npm run lint            # next lint
npm run type-check      # tsc --noEmit
npm run format:check    # prettier --check
npm run check            # type-check + lint + format:check — run before considering dashboard work done
```

Note: there is a second, near-empty `package.json` at the repo root — it is not the dashboard app; the real
dashboard app and its scripts live in `apps/dashboard/package.json`.

### Docker

`docker-compose.yml` defines `postgres`, `redis`, `api`, `worker`, `dashboard` services plus internal/public
networks. `Dockerfile` builds the Python backend (tini entrypoint, health check hits `/health` or
`/api/health` on `$PORT`, default exposed port 8000).

## Architecture

### Task lifecycle

Every task, in principle, flows:

```
API / Dashboard / CLI / Voice
        -> Master Agent            (core/master_agent.py)
        -> Router                  (core/router.py, agents/agent_router.py)
        -> Registry + Loader       (agents/registry.py, agents/agent_loader.py)
        -> Specialized Agent       (agents/<name>_agent/<name>_agent.py, subclasses BaseAgent)
        -> Security Agent check (if sensitive) -> Execution -> Verification Agent -> Memory Agent -> Audit Log
```

- `core/master_agent.py` — `MasterAgent`, the central brain: receives tasks, recalls memory, plans, routes,
  enforces security, verifies, saves memory, returns a structured result.
- `core/router.py` and `agents/agent_router.py` are **two different router layers**: `core/router.py` is
  the lightweight router `MasterAgent` calls directly; `agents/agent_router.py` is the richer intent-mapping
  router with fallback chains and multi-agent chaining. Check which one a given code path actually uses
  before assuming — don't conflate them.
- `agents/registry.py` (`AgentRegistry`) — registers/tracks all agents and their metadata (enabled,
  sensitive, requires_security, supports_memory/verification) for the Master Agent, dashboard, and API.
- `agents/agent_loader.py` — resolves registry entries to real classes and instantiates them per
  user_id/workspace_id, catching broken imports so one bad agent module can't take down boot.
- `agents/base_agent.py` — `BaseAgent`, the parent class every agent should extend. Also defines
  `AgentStatus` and `TaskRiskLevel` enums used throughout.
- `core/safety_bridge.py`, `core/verification_bridge.py`, `core/memory_bridge.py`,
  `core/task_manager.py`, `core/planner.py`, `core/response_builder.py`, `core/context.py` — the supporting
  pieces MasterAgent composes; look here for how security approval, verification payloads, and memory
  payloads actually get built.

### Import-safe pattern

Nearly every core/agent module wraps forward-looking imports (e.g. `agents.agent_events`,
`agents.agent_permissions`) in `try/except`, falling back to `None`/stub behavior so the file still imports
even when a dependency hasn't been built yet. When adding a new module other files might depend on, follow
this pattern rather than adding a hard import — it's load-bearing for this codebase's incremental-build
strategy, not incidental.

### Agent contract

Every agent is expected to implement (per `agents/base_agent.py` and `README.md`):
`_validate_task_context()`, `_requires_security_check()`, `_request_security_approval()`,
`_prepare_verification_payload()`, `_prepare_memory_payload()`, `_emit_agent_event()`,
`_log_audit_event()`, `_safe_result()`, `_error_result()`.

Every task response is a structured dict:

```json
{"success": true, "message": "...", "data": {}, "error": null,
 "metadata": {"agent": "...", "user_id": "...", "workspace_id": "...", "task_id": "..."}}
```

Sensitive actions (`system_command`, `browser_action`, `payment_action`, `call_action`, `file_delete`,
`user_data_export`, `workspace_admin_change`) must never execute directly — they route through the Security
Agent for approval first, regardless of the calling agent's own permission flag.

### SaaS isolation

`user_id` and `workspace_id` are required on every user-specific task and must never be mixed across users
or workspaces — this applies to memory, files, logs, tasks, analytics, audit data, agent permissions, and
subscription limits alike. Missing `user_id`/`workspace_id`/permission should produce a structured error,
not an exception.

### Agent module layout

Each specialized agent lives in `agents/<name>_agent/` (e.g. `agents/voice_agent/`, `agents/browser_agent/`,
`agents/code_agent/`) with a primary `<name>_agent.py` plus many capability submodules (e.g. voice_agent has
`wake_word.py`, `stt_engine.py`, `tts_engine.py`, `emotion_detector.py`, `voice_cloning.py`; browser_agent
has `scraper.py`, `seo_analyzer.py`, `price_monitor.py`; code_agent has `project_builder.py`,
`self_debugger.py`, `git_manager.py`) and its own `config.py`. `agents/super_agents/` and `agents/tools/`
exist as directories for future cross-agent orchestration/tooling but are currently empty.

### API layer (`apps/api`)

FastAPI app entrypoint is `apps/api/main.py`. Route files exist in **two places** —
flat legacy files at `apps/api/*_routes.py` (`agent_routes.py`, `auth_routes.py`, `dashboard_routes.py`,
`memory_routes.py`, `security_routes.py`, `subscription_routes.py`, `websocket_routes.py`) and a newer
`apps/api/routes/` package (`agents.py`, `auth.py`, `billing.py`, `files.py`, `memory.py`, `security.py`,
`tasks.py`, `users.py`, `workflows.py`, `workspaces.py`). Check which set is actually wired into `main.py`
before assuming a route is live — don't assume both are active.

### Database (`database/`)

SQLAlchemy models in `database/models/` (`user.py`, `workspace.py`, `subscription.py`, `agent.py`,
`agent_registry.py`, `agent_task.py`, `agent_event.py`, `memory.py`, `security.py`, `role_permission.py`,
`business.py`, `finance.py`, `workflow.py`), Alembic migrations under `database/migrations/`, seed data in
`database/seeders/default_plans.py`. `william.db` at the repo root is a local SQLite dev DB — treat it as
disposable dev state, not a source of truth.

### Security & subscriptions

- `security/secrets_manager.py`, `security/encryption.py`, `security/policies/default_policy.json` —
  secret access and encryption; smoke-tested by `test_security_module.py`.
- `subscriptions/access_control.py`, `billing_manager.py`, `plan_rules.py`, `usage_meter.py` — plan/billing
  gating, separate from the Security Agent's action-approval flow.

### Worker nodes (`apps/worker_nodes`)

Platform-specific automation clients that talk to the backend: `windows/` (Python, screen capture/app
control), `mac/mac_worker.py` (Python), `android/` (Kotlin, accessibility/call/notification bridges), plus
an `ios/ios_client_plan.md` (not yet implemented). `common/worker_client.py` is the shared client logic.

## Key conventions from README.md

- Global rule priority when changes conflict: safety/permission rules > SaaS user/workspace isolation >
  BaseAgent compatibility > MasterAgent/Registry compatibility > file-specific functionality > future
  upgrades.
- Default wake word for the Voice Agent is "William".
- Creator Agent's default brand is "Digital Promotix".
- Finance Agent must never execute real transactions unless explicitly approved (`real transaction
  permission` defaults to `false`).
- Call Agent must never place real calls without explicit user + Security Agent approval.
