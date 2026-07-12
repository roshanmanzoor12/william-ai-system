# VOICE_AGENT_RUNTIME.md

William / Jarvis Multi-Agent AI SaaS System — Digital Promotix
**Phase 9 — User-Based Admin Voice Agent + Wake Word + Voice Identity + Multilingual MasterAgent Handoff**

---

## 1. Architecture (text diagram)

```
                    ┌─────────────────────────────────────────────┐
                    │              Dashboard (owner/admin)          │
                    │  Settings → Voice Control / Trusted Profiles   │
                    │  AI Console → "William Voice" panel            │
                    └───────────────────┬─────────────────────────┘
                                        │ real JWT (Authorization: Bearer)
                                        ▼
   ┌───────────────────────────────────────────────────────────────────┐
   │                  apps/api/routes/voice.py  (FastAPI)                │
   │  GET  /voice/status          POST /voice/config                     │
   │  GET  /voice/profiles        POST/PATCH/DELETE /voice/profiles/*    │
   │  POST /voice/wake-event      POST /voice/command                    │
   │  POST /voice/push-to-talk/text                                       │
   │  POST /voice/enroll/start    POST /voice/enroll/complete             │
   └───────────────────┬───────────────────────────┬─────────────────────┘
                        │                           │
                        ▼                           ▼
   ┌─────────────────────────────┐   ┌───────────────────────────────────┐
   │ apps/api/services/            │   │ database/models/voice.py            │
   │ voice_service.py              │   │  VoiceSettings (1/workspace)        │
   │  - permission enforcement      │◄─►│  VoiceIdentityProfile (trusted     │
   │    (allowed/blocked agents,    │   │    speakers, role, permissions)    │
   │    finance/system/code gates)  │   │  VoiceSession (durable)             │
   │  - MasterAgent payload builder │   │  VoiceEvent (rich event stream)     │
   │  - voice event + audit logging │   └───────────────────────────────────┘
   └───────────────┬─────────────┘
                    │ role + "agents.<key>.use" permissions threaded into
                    │ metadata/permissions (zero core/master_agent.py changes)
                    ▼
   ┌───────────────────────────────────────────────────────────────────┐
   │         apps/api/services/master_agent_bridge.py                    │
   │         (the SAME real, already-fixed MasterAgentBridge used by      │
   │          typed dashboard commands — voice is an additional INPUT     │
   │          CHANNEL into the identical pipeline, not a separate brain)  │
   └───────────────────┬───────────────────────────────────────────────┘
                        ▼
   MasterAgent → Memory recall → Planner → Router → SecurityAgent (per-step,
   role/permission-aware) → target agent (via AgentExecutionAdapter) →
   VerificationAgent → MemoryAgent save → Audit log → structured response
                        │
                        ▼
              response_text + reply_language + speech_output_status
                        │
        ┌───────────────┴────────────────┐
        ▼                                 ▼
  Dashboard "William Voice" panel   apps/worker_nodes/voice/voice_worker.py
  (typed / push-to-talk text)      (wake word → STT → speaker verify →
                                     /voice/command → TTS if configured)

   Ears/mouth layer (agents/voice_agent/*):
     wake_word.py          — real text-based wake-word detection (no provider needed)
     stt_engine.py          — real provider-routing STT (honest failure, no provider configured)
     tts_engine.py           — real provider-routing TTS (silent mock; Phase 9 marks this
                               external_dependency_required at the API layer, never claims
                               real speech happened)
     speaker_recognition.py  — Phase 9: real provider-routing speaker-identity engine
                               (previously a duplicate-file bug with NO real implementation)
     language_engine.py       — real multilingual detection (en/roman_urdu/ur/hi/ar)
```

**MasterAgent vs. Voice Agent — the key distinction the whole design rests on:**
MasterAgent is the brain: it owns planning, routing, memory recall, security review, verification,
and the final response, for every input channel. The Voice Agent (and the new voice worker/API layer)
is the ears and mouth: it converts speech to text, verifies who is speaking, checks that speaker's
permissions, and converts the final text response back to speech. **Voice never plans, routes, or
executes a task itself** — every voice command becomes an ordinary MasterAgent task, going through
the exact same `MasterAgentBridge.execute()` call typed dashboard commands already use. This is why
Phase 9 required zero changes to `core/master_agent.py`'s routing logic.

---

## 2. Setup

No new Python dependencies are required for the text/API layer (everything Phase 9 ships is provider-
routing code with honest `external_dependency_required` fallbacks). Real STT/TTS/speaker-recognition/
wake-word providers are BYOP (bring your own provider) — none is bundled.

```bash
# Backend (same as always)
python -m venv .venv && .venv\Scripts\activate
pip install -r requirements.txt
python -m alembic upgrade head          # or rely on the dev create-all fallback (see below)
```

If you are not running Alembic migrations, the voice tables are created automatically by the same
dev create-all fallback every other model in this codebase uses — `database.models.voice` is now
registered in `tests/conftest.py`'s and `database/migrations/env.py`'s `MODEL_MODULES` lists, so
`Base.metadata.create_all()` (called at boot in `database/db.py::Db.initialize_database()`) creates
`voice_settings`, `voice_identity_profiles`, `voice_sessions`, and `voice_events` alongside every
other table.

Seed default (disabled) voice settings for every existing workspace (idempotent, safe to re-run):

```bash
python -m database.seeders.seed_voice_defaults
```

## 3. Environment variables

| Variable | Purpose | Default |
|---|---|---|
| `WILLIAM_STT_PROVIDER` | Real speech-to-text provider identifier. Unset = honest `external_dependency_required`. | unset |
| `WILLIAM_TTS_PROVIDER` | Real text-to-speech provider identifier. Unset = honest `external_dependency_required`. | unset |
| `WILLIAM_SPEAKER_RECOGNITION_PROVIDER` | Real speaker-recognition provider identifier. Unset = honest `external_dependency_required`. | unset |
| `WILLIAM_AUDIO_INPUT_WORKER_URL` | Real audio-capture worker endpoint (for a future real microphone integration). Unset = honest `external_dependency_required`. | unset |
| `WILLIAM_VOICE_DEV_ADMIN_BYPASS` | **Dev-only.** When `true`, speaker verification with no real provider configured resolves to the workspace **owner** identity instead of refusing. Every use is audit-logged with `dev_bypass: true`. | `false` (unset) |
| `WILLIAM_ENVIRONMENT` / `ENVIRONMENT` | Must NOT be `production` for the dev bypass above to ever activate, even if the flag is set. | `development` |
| `WILLIAM_VOICE_WORKER_TOKEN` | Real JWT access token the voice worker authenticates with (same auth as the dashboard — no separate device-token system exists yet). | unset |
| `WILLIAM_API_BASE_URL` | Base URL the voice worker calls. | `http://localhost:8000/api/v1` |

**Never set `WILLIAM_VOICE_DEV_ADMIN_BYPASS=true` in production.** It is refused automatically if
`WILLIAM_ENVIRONMENT`/`ENVIRONMENT` is `production`, but treat it as a local-development-only flag.

## 4. Run commands

```bash
# Backend
uvicorn apps.api.main:app --host 0.0.0.0 --port 8000 --reload

# Frontend
cd apps/dashboard && npm run dev

# Voice worker -- real background listening mode (separate process/machine,
# the "ears and mouth"; keeps running and sending a heartbeat every
# --poll-interval seconds without the dashboard tab staying open)
python -m apps.worker_nodes.voice.voice_worker --token <real JWT access token> --api-base-url http://localhost:8000/api/v1

# Voice worker — text simulation mode (no mic/audio required, for testing)
python -m apps.worker_nodes.voice.voice_worker --token <token> --api-base-url http://localhost:8000/api/v1 --simulate-text "William create a VEO prompt for ClickRonix"
```

### 4a. Voice modes (database/models/voice.py::VALID_VOICE_MODES)

| Mode | Approval required | Behavior |
|---|---|---|
| `disabled` | No | Voice fully off (default for every new workspace). |
| `push_to_talk` | No | Typed/PTT text only, no wake-word gating. |
| `wake_word_admin` | Yes | Wake-word listening, owner/admin speakers only. |
| `wake_word_trusted_users` | Yes | Wake-word listening for any active trusted profile. |
| `continuous_conversation` | Yes | Always-listening; blocked unless explicitly approved. |
| `standby` | No | Worker stays connected but /voice/command refuses any request that doesn't carry a locally-detected wake word (`wake_word` field set) -- reactivates into `push_to_talk` automatically on the next wake-word-carrying command. Say "William standby" / "William shutdown voice" to a listening session to reach this or `disabled` without touching the dashboard. |

`GET /voice/status` returns both the raw `settings` object (backward compatible) and a flattened dashboard-shaped view at the top level of `data`: `mode`, `enabled`, `runtime_state` (`disabled`/`push_to_talk`/`worker_offline`/`dependency_required`/`listening`/`standby`), `wake_word_enabled`, `wake_word_phrase`, `worker_connected` (staleness-aware -- false again ~90s after the last heartbeat/wake-event), `worker_last_seen_at`, `dependencies`, `missing_dependencies`, `active_sessions`, `last_wake_event`, `last_command`, `last_detected_language`, `last_speaker_name`, `last_routed_agent`, `last_error`, `user_id`, `workspace_id`.

`POST /voice/worker/heartbeat` -- called by the worker's idle loop independent of wake events, so `worker_connected` reflects a genuinely-alive worker rather than only updating whenever a wake word happens to fire.

## 5. Dashboard instructions

1. Log in as the workspace owner or an admin.
2. Go to **Settings → Voice Control**. Default mode is always `disabled`.
3. Toggle **push_to_talk** — this is the safe mode, no Security Agent approval needed, works with typed
   text immediately (no real audio provider required).
4. To enable **wake_word_admin** or **wake_word_trusted_users** or **continuous_conversation**, request
   the mode change — it routes through Security Agent approval and **fails closed** (mode stays
   `disabled`) if approval isn't granted. The Settings page shows this state clearly.
5. Under **Trusted Voice Profiles**, add a profile for a friend/employee: display name, role
   (`trusted_developer` / `trusted_manager` / `trusted_assistant` / `guest`), which of the 14 agents
   they may use, and the finance/system/code/private-memory access flags (all default OFF for
   non-owner profiles).
6. On the main dashboard, the **"William Voice"** panel lets any authenticated user send a typed
   push-to-talk command using their own real session identity — no separate profile needed for
   yourself, only for other people you're trusting with voice access to your workspace.

## 6. Enrolling the owner's voice

```
POST /api/v1/voice/enroll/start   { "display_name": "Owner Voice" }
```
Returns a `profile_id` and the real dependency status. With no speaker-recognition provider
configured (the default), enrollment honestly reports `external_dependency_required` — connect a
real provider and set `WILLIAM_SPEAKER_RECOGNITION_PROVIDER` before expecting real voice-based login;
until then, the owner/admin's dashboard JWT session itself is sufficient authorization for voice
commands sent via `/voice/command` (no `speaker_profile_id`) or `/voice/push-to-talk/text`.

## 7. Adding a trusted voice profile

```
POST /api/v1/voice/profiles
{
  "display_name": "Alex (friend)",
  "role": "trusted_developer",
  "allowed_agents": ["code", "browser", "creator", "verification"],
  "can_run_code_agent": true
}
```
`finance` and `system` are automatically added to `blocked_agents` unless `can_access_finance` /
`can_access_system_agent` are explicitly set `true`. Enforcement happens in two layers: a pre-routing
keyword guard (refuses obviously-blocked commands before MasterAgent is even called) and a real
SecurityAgent permission check inside MasterAgent's own pipeline (defense in depth for whatever the
Planner actually routes to).

## 8. Multilingual behavior

Supported today (real, local, no external provider needed for text-mode): English, Roman Urdu, Urdu,
Hindi, Arabic detection via `agents/voice_agent/language_engine.py`. `detected_language` is stored on
every voice session/event. Reply language defaults to `same_as_speaker` (mirrors the detected input
language); a profile can instead pin `fixed_language` or `text_only`. Real spoken TTS output requires
`WILLIAM_TTS_PROVIDER` — without it, every response still returns real `response_text` in the correct
language, with `speech_output_status: "external_dependency_required"` (never a fake "spoken" claim).

## 9. Test commands

```bash
python -m compileall .
python -m pytest tests/api_tests/test_voice.py -v      # 32 targeted voice tests
python -m pytest -q                                       # full suite
cd apps/dashboard && npm run build
python -m apps.worker_nodes.voice.voice_worker --simulate-text "William create a VEO prompt for ClickRonix" --token <token>
```

## 10. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `GET /voice/status` returns 401/403 | No/invalid JWT | Log in again, use a fresh access token |
| `/voice/config` mode change silently stays `disabled` | Security Agent approval not granted (fails closed by design) | Check `/api/v1/security/approvals` for a pending request; approve as owner/admin |
| `/voice/command` returns "You are not authorized to use this William workspace." | Speaker not resolved to any active profile, or `can_use_voice=false` | Create/enable a trusted profile, or use `/voice/push-to-talk/text` with your own real session |
| `speech_output_status` is always `external_dependency_required` | No `WILLIAM_TTS_PROVIDER` configured | Expected until a real TTS provider is connected — text response still works |
| Voice worker prints "dependency-check mode" and exits/idles | STT/TTS/speaker-recognition/audio-input libraries genuinely not installed | Expected in this repo by default; connect real providers and set the corresponding env vars |
| A specific agent (e.g. Code Agent) always returns `Unsupported <Agent> action` after a permission check passes | Pre-existing Planner↔agent action-vocabulary mismatch, unrelated to voice/Phase 9 (see PRODUCTION_READINESS_REPORT.md PART A8 #1) | Not a voice bug — same gap affects typed commands to that agent too |
| `/voice/status`, `/voice/config`, or `/voice/worker/heartbeat` return a 500 with `no such column: voice_settings.last_speaker_display_name` (or `last_error_message`/`last_error_at`) | The dev-only `william.db` SQLite file was created before this update added new `voice_settings` columns; `Base.metadata.create_all()` only creates missing *tables*, never adds columns to existing ones | Stop the backend, delete the repo-root `william.db` (disposable dev state, not a source of truth — see CLAUDE.md), restart so it's recreated with the current schema |
