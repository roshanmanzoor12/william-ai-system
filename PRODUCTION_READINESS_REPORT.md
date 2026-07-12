# William / Jarvis — Production Readiness Report

**Latest update: Phase 9 — Voice Agent Mission** (user/workspace-based admin voice control, wake word,
trusted voice identity profiles, multilingual MasterAgent handoff — this section, PART 0). PART A below
it is the prior Capability System Mission (14 agents × 50 futuristic capabilities). PART B is the
original Phase 17 repair-engagement report. Nothing in either earlier part was rolled back — Phase 9
only builds on top of the already-completed capability system and MasterAgent pipeline.

---

## PART 0 — Phase 9: Voice Agent Mission (this update)

### 0.1 What Phase 9 added

A safe, user/workspace-scoped voice input/output layer on top of the existing, unmodified MasterAgent
pipeline. Voice is an **additional input channel**, not a new brain: every voice command becomes an
ordinary MasterAgent task routed through the exact same `MasterAgentBridge.execute()` call typed
dashboard commands already use (confirmed: zero changes to `core/master_agent.py`'s routing/planning
logic were needed or made).

**New database models** (`database/models/voice.py`, 4 tables, all workspace-scoped):
- `VoiceSettings` — one row per workspace; default `mode="disabled"` always; wake word, dependency
  status cache, last wake event/speaker/language/transcript/routed-agent/response for dashboard display.
- `VoiceIdentityProfile` — trusted speaker identity + permission profile (role, allowed/blocked agents
  and capabilities, `can_access_finance`/`can_access_system_agent`/`can_run_code_agent`/
  `can_access_private_memory` flags, `voiceprint_status`/`voiceprint_reference_id` — never raw audio).
  Deliberately a different concept from the pre-existing `agents/voice_agent/voice_profiles.py`
  `VoiceProfile` (which stores HOW a user's voice sounds/behaves — persona, TTS voice, speed/pitch, not
  WHO is allowed to speak).
- `VoiceSession` — durable (DB-persisted) session record, complementing the in-memory
  `agents/voice_agent/session_manager.py::VoiceSessionManager`.
- `VoiceEvent` — rich voice-specific event stream (wake detected, speaker verified/denied, command
  received/routed, response generated, enrollment, config change), additive alongside standard
  `AuditLogModel` rows written for every real command/enrollment/config-change.

**Root-cause fix**: `agents/voice_agent/speaker_recognition.py` was a byte-for-byte duplicate of
`emotion_detector.py` (wrong file, same class, no real speaker-identity logic existed anywhere in the
codebase). Replaced with a real provider-routing `SpeakerRecognitionEngine`: enrolls/verifies through
an injected provider callback if one is configured; with none configured (the default), every attempt
honestly returns `external_dependency_required` — never a fake match. A narrow, explicit
`WILLIAM_VOICE_DEV_ADMIN_BYPASS` dev-only flag (refused outright if `WILLIAM_ENVIRONMENT`/`ENVIRONMENT`
is `production`, verified live) lets local development exercise the pipeline without a real biometric
provider, always resolving to the workspace owner identity only (never an arbitrary trusted profile),
and always audit-logged with `dev_bypass: true`.

**New service layer** (`apps/api/services/voice_service.py`): VoiceIdentityProfile CRUD, two-layer
permission enforcement (a pre-routing keyword guard that refuses obviously-blocked commands before
MasterAgent is even called, plus role/`"agents.<key>.use"`-permission-string injection into the real
MasterAgent payload so SecurityAgent's own per-step check — already existing, unmodified — provides
defense-in-depth for whatever the Planner actually routes to), MasterAgent payload building, and an
honest response envelope that **never claims spoken output happened without a real TTS provider**
(`speech_output_status: "external_dependency_required"` unless the caller confirms a real provider is
configured).

**New API routes** (`apps/api/routes/voice.py`, mounted at `/api/v1/voice/*`): `GET /status`,
`POST /config` (owner/admin only; `wake_word_admin`/`wake_word_trusted_users`/`continuous_conversation`
require Security Agent approval and **fail closed** — mode stays `disabled` if approval isn't granted,
verified live), `GET/POST /profiles`, `PATCH/DELETE /profiles/{id}`, `POST /wake-event`,
`POST /command`, `POST /push-to-talk/text` (safe fallback using the caller's own real JWT identity, no
separate enrollment needed), `POST /enroll/start`, `POST /enroll/complete`. Every endpoint requires the
same real, JWT-verified `get_current_auth_context` every other router in this codebase uses — voice
never bypasses existing session/JWT security, and every query/write is scoped to `context.workspace_id`.

**New idempotent seeder** (`database/seeders/seed_voice_defaults.py`): ensures every existing workspace
has a `VoiceSettings` row, always `mode="disabled"`. Verified idempotent (created 7 on first run,
0 created / 7 already-existed on the second run against the same DB).

### 0.2 How voice mode works

Five modes, `disabled` by default for every workspace: `push_to_talk` (safe, no approval needed, works
with typed/PTT text immediately), `wake_word_admin` (owner/admin only, requires Security Agent
approval), `wake_word_trusted_users` (extends wake-word listening to enrolled trusted profiles, also
requires approval), `continuous_conversation` (blocked unless explicitly approved). Enabling any
approval-gated mode calls the real Security Agent; if it doesn't approve, the mode change is rejected
and the workspace stays on its previous mode (verified live: `wake_word_admin` request against a fresh
workspace correctly stayed `disabled` when approval wasn't granted).

### 0.3 MasterAgent vs. Voice Agent

MasterAgent is the brain (planning, routing, memory recall, security review, verification, final
response) for every input channel. The Voice Agent/voice worker is the ears and mouth only: STT,
speaker verification, permission pre-check, and TTS. Voice never plans, routes, or executes a task
itself — it hands a plain text command to the identical `MasterAgentBridge.execute()` pipeline typed
dashboard commands use, with speaker identity/language threaded through `metadata` (an injection point
that already existed and required no structural change to `core/master_agent.py`, confirmed by direct
inspection before writing any code).

### 0.4 User/workspace-based voice access

No global voice identity exists. Every `VoiceSettings`/`VoiceIdentityProfile`/`VoiceSession`/
`VoiceEvent` row is scoped by `workspace_id` (verified live: a profile created in workspace A is
invisible to workspace B's `GET /voice/profiles`). The owner/admin's own JWT session is sufficient
authorization for voice commands without any separate voice profile (`owner_virtual_profile()`/
`authenticated_user_virtual_profile()` in `voice_service.py`) — voice profiles exist specifically for
enrolling OTHER people (friends/employees) who don't need or have their own dashboard login.

### 0.5 How trusted voice profiles work

Owner/admin creates a profile via `POST /voice/profiles` with a role (`trusted_developer`/
`trusted_manager`/`trusted_assistant`/`guest`), an explicit `allowed_agents` list from the 14 real
agent keys, and boolean gates for finance/system/code/private-memory access. `finance` and `system` are
automatically added to `blocked_agents` unless the corresponding `can_access_*` flag is explicitly set
true (verified live: a `trusted_developer` profile with no finance flag correctly got `["finance",
"system"]` in `blocked_agents`). A voice command from that profile is checked twice: once locally
(keyword-based pre-routing guard, refuses before MasterAgent is even called — verified live: a finance-
sounding command from the trusted-developer profile was correctly blocked with "This voice profile is
not allowed to use the finance agent."), and once inside MasterAgent's own real per-step SecurityAgent
check (defense in depth for whatever the Planner actually decides to route to, since the local keyword
guess can't be 100% precise). Unknown/unrecognized speakers get exactly the mandated response: "You are
not authorized to use this William workspace." (verified live, HTTP 403, `SPEAKER_UNAUTHORIZED`).

### 0.6 How multilingual voice behavior works

`agents/voice_agent/language_engine.py` (pre-existing, real, non-stub) detects English, Roman Urdu,
Urdu, Hindi, and Arabic from transcript text with no external provider needed. `detected_language` is
stored on every voice command's audit/event trail and the workspace's `VoiceSettings.
last_detected_language`. Reply language defaults to mirroring the detected input language
(`reply_language_mode: "same_as_speaker"`); a profile can instead pin a fixed language or force
text-only replies. Verified live via real HTTP calls: an English command returns
`reply_language: "en"`; a Roman Urdu command (`"mera ClickRonix dashboard premium black orange style
mein banao"`) returns `reply_language: "roman_urdu"`. Real synthesized speech output requires a
configured `WILLIAM_TTS_PROVIDER`; without one, the response always still contains real, correct-
language `response_text`, with `speech_output_status: "external_dependency_required"` — never a fake
"spoken" claim (verified live on every command tested).

### 0.7 Files changed / created

**New:**
```
database/models/voice.py
database/seeders/seed_voice_defaults.py
apps/api/services/voice_service.py
apps/api/routes/voice.py
tests/api_tests/test_voice.py
VOICE_AGENT_RUNTIME.md
apps/worker_nodes/voice/voice_worker.py            (see §0.9)
apps/dashboard/src/components/voice/*.tsx           (see §0.10)
```

**Modified:**
```
agents/voice_agent/speaker_recognition.py    (real implementation, was a duplicate-file bug)
apps/api/main.py                               (mounted apps.api.routes.voice at /voice)
tests/conftest.py                                (added database.models.voice to schema-creation list)
database/migrations/env.py                        (added database.models.voice to MODEL_MODULES)
apps/dashboard/src/lib/api-client.ts                (added voiceApi; see §0.10)
apps/dashboard/src/app/(dashboard)/settings/page.tsx  (Voice Control + Trusted Profiles sections; see §0.10)
apps/dashboard/src/app/(dashboard)/dashboard/page.tsx (William Voice panel; see §0.10)
```

### 0.8 Backend test results

```
$ python -m pytest tests/api_tests/test_voice.py -v
32 passed

$ python -m pytest -q
266 passed, 6 skipped, 0 failed     (up from 234 passed before Phase 9; +32 new voice tests, zero regressions)

$ python -m compileall -q .
(clean, exit 0)
```

Real HTTP tests (not mocked) confirm: default mode disabled; JWT required on every endpoint;
owner/admin-only gating on config/profile mutation endpoints (non-admin gets 403); `wake_word_admin`/
`continuous_conversation` correctly require and, when not granted, are correctly refused by Security
Agent approval; profile creation defaults block finance/system; role-based permission enforcement
blocks a trusted developer's finance/system-sounding commands while allowing their permitted
code/browser/creator commands (confirmed the command reaches the real CodeAgent — the only observed
failure past that point is the pre-existing, separately-documented Planner↔agent action-vocabulary gap,
not a Phase 9 regression); unknown speaker profile ids are refused with the exact mandated message;
workspace isolation confirmed (profiles created in one workspace are invisible to another); wake events
write real audit log rows; English and Roman Urdu text-mode commands both work end-to-end; enrollment
without a configured provider honestly reports `external_dependency_required`.

### 0.9 Voice worker

`apps/worker_nodes/voice/voice_worker.py` (new, ~640 lines). Composes `apps/worker_nodes/common/
worker_client.py::WorkerClient` for HTTP transport and `agents/voice_agent/wake_word.py::
WakeWordDetector` for real text-based wake-word gating — no new third-party dependencies added.

Implements all 9 required console states (`idle, listening, wake_detected, verifying_speaker,
transcribing, language_detected, sending_to_master, speaking, error`), exponential reconnect backoff
(capped at 30s), a `--simulate-text` one-shot mode, an interactive stdin fallback, and a non-interactive
idle loop with periodic `/voice/status` re-checks. Client-side wake-word gating mirrors the server's own
mode semantics: `disabled` never sends; `wake_word_admin`/`wake_word_trusted_users` only send if the
wake word was locally detected; `push_to_talk`/`continuous_conversation` send regardless. The frame-
handling entrypoint intended for a future real microphone integration (`on_audio_frame()`) documents
and enforces the no-raw-audio-persisted rule even though no real audio capture exists in this
environment today.

**Verified independently, twice** (once by the implementing agent, once by me against a freshly-started
real `uvicorn` backend with a freshly-registered real user):
```
$ python -m compileall -q apps/worker_nodes/voice
(clean, exit 0)

$ python -m apps.worker_nodes.voice.voice_worker --token <real JWT> \
    --api-base-url http://127.0.0.1:8123/api/v1 \
    --simulate-text "William create a VEO prompt for ClickRonix"

[state] idle -> listening | input_length=42 mode=push_to_talk
[state] listening -> wake_detected | trigger='william' confidence=0.99
Wake event registered. should_listen=True server_mode=push_to_talk
[state] wake_detected -> verifying_speaker | no speaker-recognition provider configured; skipping local verification
[state] verifying_speaker -> transcribing | no real STT provider installed; using provided text as transcript
[state] transcribing -> language_detected | detected_language=en (default; no language-ID provider configured)
[state] language_detected -> sending_to_master | session_id=f8f16a18-...
[state] sending_to_master -> speaking | speech_output_status=external_dependency_required
============================================================
Voice command response
success              : False
response_text        : Master Agent completed request with errors.
reply_language       : en
speech_output_status : external_dependency_required
============================================================
[state] speaking -> idle | simulate-text run complete
```
(The one failure inside `master_result` — `Unsupported or missing business action` for a
`browser_action` the Planner chose — is the same pre-existing Planner↔agent action-vocabulary gap
documented in §0.14 item 3 / PART A §A8.1, not a worker or Phase 9 defect. The wake word was correctly
detected, the real `/voice/wake-event` and `/voice/command` endpoints were correctly called in
sequence, and a real MasterAgent response — success or structured failure — was correctly returned and
printed either way.)

No-token and unreachable-backend runs were also verified: both fail honestly (`Bearer access token is
required.` / `[state] idle -> error | backend unreachable (attempt N...)` with growing backoff) with no
raw traceback.

### 0.10 Dashboard

**New:**
- `apps/dashboard/src/components/voice/VoiceControlSettings.tsx` — live mode status, dependency-status
  badges for all 5 dependencies, mode-toggle controls with Security-Agent-approval messaging, wake-word
  editor, and the last wake-event/speaker/language/transcript/routed-agent/response fields, all read
  from the real `/voice/status` and `/voice/config` endpoints. Owner/admin-gated via the shared
  `@/lib/auth.ts` role check.
- `apps/dashboard/src/components/voice/TrustedVoiceProfiles.tsx` — profile list plus a create/edit
  modal (role picker, 14-agent allow/block multi-select, safe-default-off boolean toggles for finance/
  system/code/private-memory access) and disable/re-enable/revoke actions, wired to the real
  `/voice/profiles` CRUD endpoints. Owner/admin-gated.
- `apps/dashboard/src/components/voice/WilliamVoicePanel.tsx` — status badge, push-to-talk text input
  (plus an optional, honestly-degrading native browser `SpeechRecognition` mic button — text-only if
  unavailable, never a fake transcript), last transcript/detected/reply language, response text, a
  `speech_output_status`-gated "speak response" toggle, and a clear-session button, wired to
  `/voice/push-to-talk/text`.

**Modified:** `apps/dashboard/src/lib/api-client.ts` (new `voiceApi`, 10 methods, concrete TypeScript
interfaces matching `apps/api/routes/voice.py` exactly), `settings/page.tsx` (the two new sections
inserted, nothing existing removed), `(dashboard)/dashboard/page.tsx` (the William Voice panel added
below the existing command console, which is untouched).

Verified (both by the implementing agent and confirmed independently by me after a clean `.next`
rebuild — the first two build attempts hit a transient Windows file-lock ENOENT during Next's trace-
collection step, unrelated to the new code; a clean retry succeeded both times):
```
$ npm run type-check      -- clean, 0 errors
$ npm run lint             -- ✔ No ESLint warnings or errors
$ npm run build
✓ Compiled successfully
✓ Generating static pages (19/19)
Route (app)                              Size     First Load JS
├ ○ /agents                              10.9 kB        98.2 kB     (unchanged, confirmed intact)
├ ○ /dashboard                           9.22 kB         123 kB     (William Voice panel added)
├ ○ /settings                            8.07 kB         122 kB     (Voice Control + Trusted Profiles added)
... all 17 routes build successfully
```

### 0.11 What works live now

- Full HTTP round trip verified: register → enable push_to_talk → send a real command → MasterAgent
  routes it (confirmed real CreatorAgent execution: "Creative brief prepared successfully.") → real
  Security/Verification/Memory Agent involvement → structured response with correct
  `speech_output_status`/`reply_language`.
- Trusted voice profile creation, role-based permission enforcement (both defense layers), and revoke,
  all via real HTTP calls with real JWT auth.
- Security-Agent-gated mode changes, failing closed when not approved.
- Multilingual text-mode commands (English + Roman Urdu tested; Urdu/Hindi/Arabic use the same real
  detection code path and just weren't hand-tested this session — architecture supports them
  identically once exercised).

### 0.12 What needs external providers

Per the honest dependency-status contract (`GET /voice/status` → `data.settings.dependency_status`):
`stt_provider`, `tts_provider`, `speaker_recognition_provider`, and `audio_input_worker` all report
`external_dependency_required` by default (no provider ships with this repo) — only `wake_word_engine`
(text-based detection) is `available` with zero external dependency. Connecting real providers means
setting the corresponding env var from §3 of `VOICE_AGENT_RUNTIME.md` and wiring a real
`provider_callbacks` entry into `SpeakerRecognitionEngine`/`STTEngine`/`TTSEngine` at construction time
(the provider-callback injection points already exist in all three engines; Phase 9 did not need to
add them, only correctly report their absence).

### 0.13 Which env variables are required

None are required to run Phase 9's text-mode voice pipeline (push_to_talk, trusted profiles, permission
enforcement, MasterAgent handoff all work with zero configuration). See §3 of
`VOICE_AGENT_RUNTIME.md` for the full list of optional provider/dev-bypass env vars.

### 0.14 Security limitations / honest gaps

1. **No real biometric speaker verification ships with this repo.** Every `speaker_profile_id`-based
   command today relies on the caller already knowing/supplying a valid profile id, or on the caller
   being an already-JWT-authenticated owner/admin — real voice-biometric "prove you are this specific
   voice" verification requires connecting a real provider, which is out of scope for this phase (no
   provider is bundled or purchased).
2. **Wake-word detection is text-based only.** `agents/voice_agent/wake_word.py`'s real, working
   algorithmic detection operates on transcript text; real audio-stream wake-word listening (a mic
   picking up "William" mid-silence) requires a connected `audio_input_worker`, honestly reported
   `external_dependency_required`.
3. **The pre-existing Planner↔agent action-vocabulary gap** (documented in PART A §A8.1 of this same
   report) affects voice commands exactly as much as typed commands — a permission-allowed command can
   still surface a structured `Unsupported <Agent> action` error from the target agent itself. This is
   not a voice-specific or Phase-9-introduced issue.
4. **`agents/voice_agent/voice_loop.py`/`voice_agent.py`'s own internal orchestrators were deliberately
   left unmodified and unused by the new API layer.** Research before writing any code confirmed real
   adapter-signature mismatches between those orchestrators' internal wake-word/STT/TTS fallback stubs
   and the real engine classes' actual method names — wiring through them would have required either
   risky changes to well-established existing files or building yet another adapter layer. Phase 9
   instead built a clean, direct `voice_service.py` → `MasterAgentBridge` path, which is lower-risk and
   fully testable, at the cost of not (yet) reusing `voice_loop.py`'s richer in-process conversation-
   mode state machine (IDLE/ACTIVE/CONVERSATION/PRIVATE/SLEEP). Documented here as a deliberate,
   conscious tradeoff, not an oversight.

### 0.15 Remaining work

- Connect a real STT/TTS/speaker-recognition provider and verify the full spoken round trip (not just
  the text-mode pipeline, which is fully verified).
- Reconcile `voice_loop.py`'s conversation-mode state machine with the new `voice_service.py` path, or
  formally deprecate the former, once a decision is made about whether richer in-process conversation
  state (interruptions, sleep/wake phrases) is wanted on top of the stateless per-command API model
  Phase 9 shipped.
- Fix the pre-existing Planner↔agent action-vocabulary gap (§0.14 item 3) — this would improve voice AND
  typed command success rates equally, and is the single highest-leverage next fix for the whole system.
- Extend the dashboard's push-to-talk text panel with real browser `SpeechRecognition` Web Speech API
  integration as a progressive enhancement, if desired (optional, not required for this phase's
  acceptance criteria).

### 0.16 Safe to commit?

**Yes, on the same terms as PART A/PART B's assessments: verified safe, but nothing has been committed
— no commit has been made this phase either, per the standing "do not commit unless explicitly
approved" instruction.** Every backend change was verified independently (compile check, 266-test full
suite, live HTTP smoke tests covering every endpoint and every permission-enforcement path). Nothing
fake is included: every honestly-incomplete area (external providers, the pre-existing Planner gap)
fails with a structured, correct response rather than a fabricated success, and no raw audio is stored
anywhere in the new schema.

---

## PART A — Capability System Mission (prior update)

### A0. What was broken at the start of this mission

Verified directly (not assumed) before any edit was made:

1. **`core/master_agent.py`'s `MasterAgent.__init__` defaulted `self.agent_registry` to an empty dict**
   (`agent_registry or {}`) whenever nothing populated it — the confirmed root cause of every real task
   failing routing with `"No suitable registered agent found"`, reconfirmed live via
   `POST /tasks/run` before any fix.
2. **Four parallel, inconsistent agent-capability catalogs existed**, none close to 50 items/agent:
   `agents/registry.py::DEFAULT_AGENT_SPECS` (plain strings, ~5/agent), `agents/agent_manifest.py`
   (~2–4/agent, mostly `status=PLANNED`), `apps/api/routes/agents.py::AGENT_CATALOG` (~2/agent — the one
   actually serving the live `/agents` endpoint), and each real agent class's own undocumented behavior.
3. **The dashboard `/agents` page had zero capability-display UI** and, separately, read the wrong
   response shape (`response.data` assumed to be a flat array; the real shape is
   `response.data.agents[]` of `{agent, workspace_config, access, health}` objects).
4. **A universal, previously-undiscovered dispatch bug**: a live smoke test invoking every one of the 14
   specialized agents through `BaseAgent`'s inherited `execute_task()` pipeline showed **all 14 crashed**,
   each with a different signature/attribute mismatch in that agent's own override of a `BaseAgent`
   internal hook (`_emit_agent_event`, `_log_audit_event`, `_error_result`, etc.) — each agent's override
   was written for that agent's own calling convention only, not `BaseAgent`'s actual internal call sites.
5. **`SystemAgent`'s own `_validate_task_context()`** silently converted its live `TaskContext` object
   into a plain dict via `_safe_json()`'s dataclass-serialization fallback, then crashed on the next line
   needing `.user_id` off what was now a dict.
6. **`database/seeders/default_plans.py`** had three separate bugs preventing it from ever completing a
   seed run: ISO-string timestamps passed into native `DateTime` SQLAlchemy columns, a field-name
   mismatch (`key`/`name` vs. the real `agent_key`/`agent_name`/`display_name` columns) that silently
   left every seeded agent row's identity columns `NULL`, and a dedup check keyed on the wrong field name
   (so re-running the seeder always re-attempted duplicate inserts instead of skipping).
7. **Two plan-tier vocabulary mismatches**: `database/models/subscription.py::PlanKey` was missing
   `STARTER` (a plan every real, live API route's own `Plan` enum has had all along), and the seeder's
   own plan list used `"growth"` where the rest of the system uses `"pro"` — both caused a SQLAlchemy
   `before_insert` event listener to raise `ValueError: Unknown plan: ...` on every seed attempt.
8. **`database/models/role_permission.py::PermissionCategory`** was missing `integrations`/`plugins`
   members that the seeder's own permission list used — silently broke the seeder's own duplicate-check
   query for exactly those two permissions (enum lookup failure inside the query was swallowed and
   treated as "not found"), causing a `UNIQUE constraint failed` crash on every second seed run.

### A1. What was fixed / built

**New capability manifest system** (`agents/capability_manifest.py` + `agents/capability_data/*.py`,
one file per agent): a single, versioned, import-safe source of truth for all 700 capabilities (14
agents × 50), each with the full required schema (`id`, `name`, `description`, `risk_level`,
`permission_level`, `status`, `required_integrations`, `safe_mvp_behavior`, `verification_method`,
`memory_policy`, `audit_required`). Verified complete via `agents.capability_manifest.validate_manifest()`
and the new automated tests (§A4). This does not replace `agents/registry.py` (class registration) or
`agents/agent_manifest.py` (lifecycle metadata) — it owns capability-level metadata only.

**`apps/api/routes/agents.py`**: `public_agent_definition()` now additively includes
`capability_manifest` (all 50 real entries) and `capability_manifest_meta` (count/complete/status
breakdown) in every agent object `GET /api/v1/agents` returns, without touching the existing short
`capabilities` list real permission-gate logic elsewhere in the file depends on.

**`apps/api/services/master_agent_bridge.py`** (new): builds a real, populated `agents/registry.py:
AgentRegistry`, instantiates all 14 specialized agents, and injects that dict into a real
`core.master_agent.MasterAgent(agent_registry=...)` — the direct fix for root cause #1. Registered as
`apps/api/routes/tasks.py`'s `MASTER_AGENT` hook's first-preference import candidate (a slot that
already existed, unused, before this fix).

**`agents/agent_execution_adapter.py`** (new): the common execution interface the mission's Phase 1 file
list anticipated. Calls each real agent's own actual entrypoint directly
(`run_task`/`handle_task`/`arun`/`run`/`execute`, in the order confirmed correct per agent by the live
smoke test) instead of routing through the broken inherited `execute_task()` path, with every step
wrapped so one agent's internal bug degrades to a structured error rather than crashing the pipeline.
Wired into `core/master_agent.py::_execute_routed_step()`, replacing its previous narrower dispatch
chain.

**Root-cause fixes for the dispatch bug** (root cause #4), rather than routing around them:
- `agents/super_agents/business_agent/business_agent.py::_emit_agent_event()` — signature made
  positional-or-keyword compatible (was keyword-only, breaking `BaseAgent`'s positional internal calls);
  `context` now accessed via `getattr` instead of assumed to be a `TaskContext`.
- `agents/system_agent/system_agent.py::_validate_task_context()` — success path no longer routes the
  live `TaskContext` object through `_safe_result()`'s JSON-safety helper (which silently converted it
  to a plain dict via `dataclasses.asdict`), fixing root cause #5.
- `agents/visual_agent/visual_agent.py` — added a `run(task)` generic dispatcher (VisualAgent had none;
  it only exposed specific `analyze_screenshot`/`analyze_image`/`analyze_video` methods). Routes to the
  right real method based on what input the task actually supplies; returns an honest, structured
  `capability_unavailable`-style response for text-only requests rather than fabricating a visual result.

**`apps/api/services/verification_agent_bridge.py`** (new): fixes the same class of bug in
`apps/api/routes/auth.py`'s registration/login flow — `VerificationAgent.verify_task(context,
task_payload, ...)` takes two required args, incompatible with the generic single-payload
`OptionalAgentHook.call()`. This bridge is `VERIFICATION_AGENT`'s first-preference import candidate
(same existing-but-unused slot pattern as the master agent bridge). Note: `core/verification_bridge.py`
already had a correct version of this same context/task_payload split from a prior session — this new
bridge fixes the *separate*, still-broken `auth.py` call site the same way.

**Seeder fixes** (root causes #6–8), each traced to its exact origin and fixed there rather than
patched around: `_make_model_instance()` now coerces ISO-string timestamps to real `datetime` objects
only for columns actually typed `DateTime` on the target model; `AgentDefinition.to_dict()` now also
emits `agent_key`/`agent_name`/`display_name`; the "agents" bucket's dedup check now uses the real
`agent_key` field; `PlanKey` gained `STARTER` (with correctly-scoped limits/features/price/rank entries,
not just the enum member); the seeder's `"growth"` plan key was renamed to `"pro"`; `PermissionCategory`
gained `INTEGRATIONS`/`PLUGINS`. Result: `database/seeders/default_plans.py` now completes successfully
and is fully idempotent (verified via 3 consecutive runs against a fresh DB: run 1 seeds 61 records,
runs 2–3 skip all 61 with zero errors).

**`database/seeders/seed_agent_capabilities.py`** (new): idempotent entrypoint
(`python -m database.seeders.seed_agent_capabilities`) that seeds the real `agent_registry` DB table
with all 15 agents and stamps each of the 14 specialized agents' `capabilities_json` with their real 50
capability IDs from the manifest. Safe to re-run any number of times (verified).

**Dashboard `/agents` page** (`apps/dashboard/src/app/(dashboard)/agents/page.tsx`, plus a new
`apps/dashboard/src/components/` state-component directory): fixed the response-shape bug (now reads
`response.data.agents[]` correctly), and added a capability summary badge per agent card
(e.g. "50 capabilities · 23 available · 22 need setup · 3 need approval · 2 planned") that opens a
slide-over drawer showing the full 50-capability list (filterable by status), health, aggregated
dependencies, approval requirements, and a realistic example test prompt per agent. Never fabricates
capability data client-side — an agent with no manifest (e.g. `master`) shows an honest empty state.
`npm run type-check` / `lint` / `format:check` / `build` all pass clean (verified both by the
implementing pass and independently re-verified after further backend changes).

### A2. Files changed / created this mission

**New:**
```
AGENT_CAPABILITY_MATRIX.md
agents/agent_execution_adapter.py
agents/capability_manifest.py
agents/capability_data/__init__.py
agents/capability_data/{voice,system,browser,code,memory,security,verification,
                        visual,workflow,hologram,call,business,finance,creator}.py
apps/api/services/__init__.py
apps/api/services/master_agent_bridge.py
apps/api/services/verification_agent_bridge.py
database/seeders/seed_agent_capabilities.py
tests/agent_tests/test_capability_manifest.py
tests/integration_tests/test_agent_capability_seeding.py
apps/dashboard/src/components/          (new state/drawer components added by the agents-page fix)
```

**Modified:**
```
agents/base_agent.py                                    (unrelated small fix carried from before this
                                                           mission; see PART B)
agents/super_agents/business_agent/business_agent.py     (_emit_agent_event signature fix)
agents/system_agent/system_agent.py                      (_validate_task_context TaskContext-object fix)
agents/visual_agent/visual_agent.py                       (added generic run() dispatcher)
apps/api/routes/agents.py                                 (capability_manifest in public_agent_definition)
apps/api/routes/auth.py                                    (VerificationAgentBridge wired as first candidate)
apps/api/routes/tasks.py                                    (MasterAgentBridge wired as first candidate)
core/master_agent.py                                        (_execute_routed_step uses agent_execution_adapter)
database/models/role_permission.py                          (PermissionCategory.INTEGRATIONS/PLUGINS)
database/models/subscription.py                              (PlanKey.STARTER + full tier wiring)
database/seeders/default_plans.py                             (datetime coercion, field mapping, dedup key,
                                                                 growth->pro rename)
apps/dashboard/src/app/(dashboard)/agents/page.tsx              (response-shape fix + capability UI)
tests/api_tests/test_agents.py                                   (new TestAgentCapabilityManifestEndpoint class)
```

Files from the prior (Phase 17) engagement remain modified/untracked exactly as PART B describes —
nothing there was reverted.

### A3. Database seeding (Phase 5)

```
$ python -m database.seeders.seed_agent_capabilities
agent_registry_seed: {'success': True, 'message': 'Core agents seeded successfully.'}
  voice          success=True count=50
  system         success=True count=50
  ... (all 14 agents, count=50) ...
overall success: True
```

Idempotency verified: running the command a second time makes zero changes (all rows already exist,
capability IDs already correct). `database/seeders/default_plans.py` (permissions/roles/plans, run via
`seed_default_plans(session=db)`) verified idempotent separately: run 1 seeds 61 records (34 permissions
+ 7 roles + 15 agents + 5 plans), runs 2–3 skip all 61 with zero errors.

### A4. Tests run and exact results

```
$ python -m compileall -q .
(clean, exit 0, no output)

$ python -m pytest -q
234 passed, 6 skipped, 0 failed   (up from 186 passed/6 skipped at the start of this mission;
                                    48 new tests added, zero regressions in the pre-existing 186)

$ cd apps/dashboard && npm run type-check
> tsc --noEmit    (clean, 0 errors)
```

New test coverage added this mission (`tests/agent_tests/test_capability_manifest.py`, 44 tests;
`tests/api_tests/test_agents.py` +4 tests; `tests/integration_tests/test_agent_capability_seeding.py`,
2 tests):
- All 14 agents present in the manifest; none named `master` (by design).
- Every agent has exactly 50 capabilities; every capability has all 10 required metadata fields.
- Capability IDs are unique within and across agents (700 total, all unique).
- `status`/`permission_level`/`risk_level` values match the mission's exact vocabulary.
- Security/Finance/System agents each have real `approval_required`/`blocked_by_default` capabilities.
- Finance Agent's auto-transfer/credential-storage refusals are `blocked_by_default`, not merely
  `approval_required` (a hard rule, not a human-overridable one).
- Every one of the 14 real specialized agent instances can be called through
  `agent_execution_adapter.call_agent()` with a generic task without raising (crash-safety regression
  test for root cause #4).
- `MasterAgentBridge` populates all 14 agents into a real `MasterAgent.agent_registry`, and a real task
  never returns `"No suitable registered agent found"` (regression test for root cause #1).
- The real `VerificationBridge`/`VerificationAgentBridge` both verify a completed task without raising.
- `GET /api/v1/agents` (real HTTP, real JWT) returns all 14 agents with exactly 50 capabilities each,
  all required fields present; `master` honestly returns an empty manifest; at least one real
  `external_dependency_required` capability is present with a non-empty `required_integrations` list.
- Both seeders are idempotent (§A3).

**One test-infrastructure bug found and fixed while adding these tests**: raw `asyncio.run()` calls
inside otherwise-synchronous test functions were closing/resetting the thread's default asyncio event
loop, which broke `pytest-asyncio`'s own event-loop fixture for unrelated `async def` tests running
later in the same full-suite process (manifested as 68 spurious failures across 4 unrelated files,
`RuntimeError: There is no current event loop in thread 'MainThread'`, only reproducible in a full
`pytest` run, never in isolation). Fixed by converting those test functions to real
`@pytest.mark.asyncio async def` tests matching this codebase's existing convention, and by sharing one
module-scoped `MasterAgentBridge` fixture across the new test file instead of constructing several.

### A5. Commands, URLs, and example prompts

```bash
# Backend
python -m pytest -q                                              # expect 234 passed, 6 skipped, 0 failed
python -m compileall -q .
python -m database.seeders.seed_agent_capabilities                 # idempotent, safe to re-run
uvicorn apps.api.main:app --host 0.0.0.0 --port 8000 --reload

# Frontend
cd apps/dashboard && npm run type-check && npm run build
npm run dev
```

URLs to test: `http://localhost:8000/api/v1/agents` (real JWT required — register/login first via
`POST /api/v1/auth/register`), `http://localhost:3000/agents` (dashboard, after login).

Example prompt for every agent, plus the full 50-capability breakdown per agent (id, name, description,
risk level, permission level, status, required integrations, safe MVP behavior, verification method,
memory policy, audit requirement): see **`AGENT_CAPABILITY_MATRIX.md`** (auto-generated directly from
`agents/capability_manifest.py`, so it can never drift from the live data the API actually serves).

### A6. What works live now

- Real JWT-authenticated `GET /api/v1/agents` returns all 14 agents × 50 real capabilities plus `master`,
  with health/access/workspace-config data, verified via live HTTP calls with a real registered user.
- `POST /api/v1/tasks/run` reaches the real `MasterAgent` pipeline via `MasterAgentBridge`: memory recall,
  planning, security check, routed execution, verification, memory save, audit logging all occur for a
  real submitted task. Verified live: a "generate a video ad script" task correctly routed to and
  executed by the real `CreatorAgent` ("Creative brief prepared successfully"), with a real (and
  honestly-reported) partial failure on a co-planned `VisualAgent` step needing image input it wasn't
  given — not a crash, not a fake success.
- All 14 specialized agents can be invoked through the common execution adapter without crashing, each
  returning a real, structured, honest result (success or a specific, correct validation/capability
  error) for a generic task.
- The real `VerificationAgent` verifies completed tasks end-to-end via two independent, now-fixed call
  paths (`core/verification_bridge.py` and the new `apps/api/services/verification_agent_bridge.py`).
- Database seeding for all 14 agents' 50 capabilities, plus 34 permissions/7 roles/5 plans, completes
  successfully and idempotently.
- Dashboard `/agents` page displays real capability data with a working detail drawer; builds and
  type-checks clean.

### A7. What needs external keys/devices, and what still requires approval

See `AGENT_CAPABILITY_MATRIX.md`'s per-agent tables for the exhaustive, exact list (each of the 700
capabilities is individually tagged). Summary by agent (available / needs external dependency /
approval required / planned):

| Agent | Available | Needs ext. dep. | Approval req. | Planned |
|---|---|---|---|---|
| Voice | 23 | 22 | 3 | 2 |
| System | 23 | 25 | 1 | 1 |
| Browser | 43 | 7 | 0 | 0 |
| Code | 41 | 2 | 7 | 0 |
| Memory | 36 | 2 | 9 | 3 |
| Security | 45 | 2 | 3 | 0 |
| Verification | 44 | 6 | 0 | 0 |
| Visual | 18 | 32 | 0 | 0 |
| Workflow | 35 | 14 | 1 | 0 |
| Hologram | 42 | 7 | 1 | 0 |
| Call | 39 | 4 | 7 | 0 |
| Business | 46 | 1 | 3 | 0 |
| Finance | 45 | 2 | 3 | 0 |
| Creator | 49 | 0 | 1 | 0 |

The most common missing external dependencies are STT/TTS providers (Voice), OS-level worker bridges
for Windows/Mac/Android/iOS (System), OCR/image-analysis engines (Visual), and third-party connectors
like n8n/Slack/Discord/WhatsApp/Google Sheets (Workflow). None of these silently fake success — every
one returns a structured `external_dependency_required` response naming exactly what's missing.

### A8. Remaining limitations (honest, not fixed this mission)

1. **Planner-vocabulary vs. agent-action-vocabulary mismatch.** The Planner emits generic action names
   (e.g. `"business_assist"`) that don't always match a specific agent's real action enum (e.g.
   `BusinessAgent` expects specific action keys, not a generic catch-all) — this surfaces as an honest
   `INVALID_ACTION`/`unsupported_action` structured error rather than a crash or fake success, but real
   multi-step task plans routed generically will often need this addressed for full end-to-end success.
   Out of scope for this mission (a Planner-side change, not a capability-catalog or registry-wiring
   issue); tracked here for the next phase.
2. **`agent_registry_service.list_agents()`'s own query filter** did not return the system-scoped rows
   this mission's seeding created when queried with `user_id="system", workspace_id="system"` (direct
   SQLAlchemy queries against the table confirm the data is correct) — a pre-existing helper-method
   quirk in `database/models/agent_registry.py`, not a data-integrity issue; not chased further given
   time constraints.
3. **VisualAgent's generic `run()` dispatcher is intentionally minimal** — it routes to real existing
   methods based on what input is present, but doesn't invent any new visual-analysis capability; a
   text-only request correctly gets `capability_unavailable`, which is honest but means VisualAgent
   capabilities aren't exercisable through the generic task pipeline without real image/screenshot input
   attached to the task.
4. Frontend: the agents page still uses its own local `readSession()`/`apiRequest` helpers rather than
   the shared `@/lib/auth.ts`/`@/lib/api-client.ts` modules other pages use (a pre-existing inconsistency,
   flagged but not fixed, since migrating it was assessed as unnecessary risk for an unrelated cleanup).
   The enable/disable/health-check button handlers' expected response shape doesn't exactly match the
   real backend's `{agent, workspace_config, audit, memory_result, verification_result}` shape either —
   both degrade gracefully (existing `??` fallbacks) rather than crash, but aren't fully wired.
5. PART B's still-open items (§7/§8 below) are unaffected by this mission and remain as described there,
   except **§8.1 and §8.2 of PART B are now fixed** by this mission's work (A1) — kept below only as a
   historical record of what was true before this mission started.

### A9. Safe to commit?

**Yes, on the same terms as PART B's assessment: verified safe, but nothing has been committed — no
commit has been made this mission either, per the standing "do not commit unless explicitly approved"
instruction.** Every change in §A2 was verified independently (compile check, full pytest suite,
frontend type-check, live HTTP smoke tests) and the full test suite is green (234 passed, 0 failed).
Nothing fake or half-finished is included: every honestly-incomplete area (A7, A8) fails with a
structured, correct error rather than a fabricated success.

---

## PART B — Prior repair engagement (Phase 17 report, historical)

**Phase 17 of the repository repair engagement.** Digital Promotix, multi-agent AI SaaS system.
Report generated at the end of a repair effort spanning Phases 1–16 (baseline audit through live
runtime verification). All findings below are backed by commands actually run this session — no
claim in this report is asserted without a corresponding compile/test/build/runtime check.

---

## 1. What was fixed

### Backend (Python / FastAPI)

| Area | Root cause | Fix |
|---|---|---|
| Environment/config | Stray root Node install, bad env config | Phase 1 |
| Python syntax | Syntax error blocking `compileall` | Phase 2 |
| Database models/migrations | Broken `Base` import silently disabled 13 models, reserved-attribute crashes, table/index collisions | Phase 3 |
| Authentication | Real JWT+PBKDF2 auth moved into the file `main.py` actually mounts; in-memory store replaced with real DB-backed store | Phase 4 |
| API routing | Router-mounting bug made `routes/agents.py`'s entire 12-endpoint surface unreachable; double-prefix bug on 4 routers | Phase 5 |
| Agent orchestration | Real `AgentRouter` wired in; all 15 agents now import cleanly; real auth enforced on `main.py`'s built-in routes | Phase 6 |
| Security/Verification/Memory bridges | Real agents wired in; adapter mismatches and two crash bugs fixed | Phase 7 |
| **Auth bypass (see §3)** | Spoofable `X-User-Id`/`X-Workspace-Id`/`X-User-Role` headers trusted with no JWT verification in 4 routers | Fixed, see §3 |
| Test fixture | `tests/conftest.py`'s `app`/`client` fixtures silently fell back to a 2-route fake stub for every test because `apps/api/main.py` had no module-level `create_app()` | Added real `create_app(testing=True)` factory; `testing=True` also forces dev-auth-header-trust off regardless of ambient `.env` |
| Test database | `DATABASE_URL` used an async driver (`sqlite+aiosqlite`) against a fully synchronous DB layer — every real write threw `MissingGreenlet` | Fixed dialect; added `StaticPool` so in-memory SQLite is actually shared across connections; added real schema creation at test session start |
| Workspace registration | `Workspace.slug` derived from name with a DB `UNIQUE` constraint but no collision handling — two users registering with the same workspace name got a raw 500 in **production**, not just tests | Deterministic slug-suffixing before insert |
| `agents/base_agent.py` | `normalize_task()` only handled `AgentTask`/`dict`/`str` — any dataclass/object task (real callers included) silently became `"unknown_task"`, discarding every field | Added object/dataclass normalization; added flat `user_id`/`workspace_id`/`task_id` at the top level of every response (kept nested `metadata` copy for backward compatibility) |
| `agents/base_agent.py` | `_normalize_security_decision()` only recognized a `"success"` key; a security agent returning `{"approved": True}` was always treated as denied | Recognizes both `"success"` and `"approved"` conventions |
| `agents/base_agent.py` | Audit logger was called as `self.audit_logger(payload)` (assumed callable); real audit loggers expose `.log_event()`/`.log()` methods | Tries common method names before falling back to direct call |
| `agents/base_agent.py` | Audit `"action"` field conflated the task's own business action (`"update"`) with the audit lifecycle stage (`"task_completed"`) | Split into `"action"` (business action) and `"event_type"` (lifecycle stage) |
| `agents/base_agent.py` | Sensitive actions with no injected Security Agent produced a successful result with no visible evidence a security review happened | Security review outcome now recorded in `metadata.security_review` |
| `core/master_agent.py` (via `apps/api/routes/tasks.py`) | Task dispatcher tried `handle_request` (needs 3 keyword args) before `execute` (the dict-based entrypoint built for this), crashing every task with `TypeError: handle_request() missing 2 required positional arguments` | Reordered dispatch to try `execute` first |
| `apps/api/routes/tasks.py` | `MasterAgent._error_result()`'s own convention is a string `error` field; a caller assumed a dict unconditionally (`master_result.get("error", {}).get("code")`), crashing with `AttributeError` on any real task failure | Defensive dict-type check before `.get()` |
| `core/master_agent.py`, `apps/api/routes/tasks.py`, `apps/api/routes/auth.py` | `SecurityAgent`/`MemoryAgent` expose a bespoke sync `run_task(task: dict)` entrypoint, not `run()`/`execute()`; three separate dispatchers tried other method names first and fell through to `BaseAgent`'s unimplemented placeholder `run()`, crashing with `'dict' object has no attribute 'task_name'` on **every** register/login/task call | `run_task`/`execute_task` added as preferred dispatch candidates in all three files |
| `apps/api/main.py` | Pydantic's default validation-error handler echoed the caller's **plaintext password** back in 422 responses whenever password validation failed (also crashed with an unrelated `TypeError` when a custom validator's raised exception object leaked into the JSON body) | New `sanitize_validation_errors()`: drops sensitive keys entirely (not just masks values) recursively through nested `input`/`ctx`, and stringifies any non-JSON-safe values |
| `apps/api/routes/auth.py` | Duplicate-email registration returned a blanket `400` for every `ValueError`, including the semantically-a-`409`-conflict "already registered" case | `409 EMAIL_ALREADY_REGISTERED` for the duplicate-email case specifically |
| `database/migrations/env.py` vs `database/db.py` | Two independently hardcoded SQLite fallback filenames (`william_jarvis.db` vs `william.db`) — running `alembic upgrade head` with no `DATABASE_URL` set silently migrated a **different file** than the one the app actually reads | Unified to `william.db` |
| Local dev database | `william.db` at the repo root had a stale schema (missing `users.full_name` and other columns from since-added migrations) — every real registration 500'd | Backed up (not deleted) as `william.db.stale-backup-<timestamp>`; fresh DB created via real `alembic upgrade head` |

### Frontend (Next.js / TypeScript dashboard)

- **Phase 8**: Fixed a double-shell bug on 9 pages (duplicate `<main>`/sidebar wrapper nested inside the real layout); split root layout into a route group so `/login` stops inheriting dashboard chrome; removed a dead `/forgot-password` link.
- **Phase 9**: Built the shared session module (`src/lib/auth.ts`) and API client (`src/lib/api-client.ts`) the dashboard never had; fixed the real login/register/refresh response-shape mismatch (nested `data.tokens.access_token`, not flat); fixed `UserRole`/`UserPlan` to match the real backend's 8-role/5-plan enums (two different, both-wrong, invented vocabularies existed across 5 pages before this).
- **Phase 10**: Rewired `analytics`, `tasks`, `workflows`, `billing`, `finance`, `creator`, `calls`, and `memory` pages off fabricated/demo data onto real backend contracts (or honest "not available"/"not connected" states where no real backend exists, e.g. CRM). Removed hundreds of lines of invented data-generator functions across these pages.
- **Phase 11**: Built shared `LoadingState`/`EmptyState`/`ErrorState`/`ForbiddenState` components plus a global `OfflineBanner`; retrofitted all 12 real data-fetching pages onto them.
- **Config hygiene**: Added a missing `.prettierignore` (Prettier was scanning `.next/` build output — a pre-existing gap, not something introduced this session); removed one stray debris file (`tasks/FILE COMPLETE.md`, an untracked two-word marker file with no git history).

---

## 2. Files changed (uncommitted, this session forward from `be1ef48`)

```
git diff --stat: 40 files changed, 10564 insertions(+), 10118 deletions(-)
```

**Backend / tests (15 files):**
```
agents/base_agent.py
apps/api/main.py
apps/api/routes/agents.py
apps/api/routes/auth.py
apps/api/routes/tasks.py
apps/api/websockets/agent_events.py
core/master_agent.py
database/db.py
database/migrations/env.py
tests/agent_tests/test_base_agent.py
tests/api_tests/test_agents.py
tests/api_tests/test_auth.py
tests/api_tests/test_memory.py
tests/conftest.py
tests/integration_tests/test_master_flow.py
```

**New (untracked):**
```
apps/dashboard/.prettierignore
apps/dashboard/src/components/state/{EmptyState,ErrorState,ForbiddenState,LoadingState,OfflineBanner}.tsx
tests/api_tests/conftest.py                  (real-JWT test-auth helper: make_owner/make_member/set_plan fixtures)
william.db.stale-backup-20260711220838       (backup of the pre-migration dev DB, not committed -- see .gitignore)
```

**Deleted:**
```
apps/dashboard/src/app/(dashboard)/tasks/FILE COMPLETE.md   (untracked debris, no git history)
```

**Frontend (25 files):** all 17 dashboard pages, `layout.tsx` (root + dashboard), `login/page.tsx`,
`globals.css`, `lib/api-client.ts`, `lib/auth.ts`, `tailwind.config.ts`, `tsconfig.json`,
`.eslintrc.json`, `next-env.d.ts`, `postcss.config.js` (last several are Prettier formatting-only
changes, see §4).

**Already committed** (prior sessions, commits `ad0c06f`..`be1ef48`, 22 commits): Phases 1–9 plus the
first 4 auth-bypass fixes. See `git log --oneline` for the full list — not reproduced here since it
predates this report's scope and is unchanged.

---

## 3. Security vulnerabilities fixed

### 3.1 Repo-wide auth bypass — `workflows.py`, `billing.py`, `memory.py`, `security.py` (committed, prior session)

All four routers shared an identical, copy-pasted `get_actor_context` dependency that built the
request's identity **directly from caller-supplied headers** (`X-User-Id`, `X-Workspace-Id`,
`X-User-Role`, `X-Subscription-Plan`) with **no signature verification at all**. Any HTTP client could
claim to be any user, in any workspace, with any role — including owner/admin — on every endpoint these
four routers exposed (workflow templates/runs, billing/subscription management, memory read/write/
delete/export, and the security risk-decision gate itself).

**Fix:** all four now depend on the real, JWT-verified `get_current_auth_context` from
`apps/api/routes/auth.py` (imported via the same import-safe try/except pattern used throughout this
codebase), translating the verified `AuthContext` into each router's local context type. Each fails
closed (503) if the real auth module is somehow unavailable, instead of falling back to trusting
headers. Verified via: direct compile check, real-import-resolution check (confirmed the real module
loaded, not the fallback), full app boot check (route count unchanged), and the full pytest suite
(baseline held with zero regressions at the time: 88 failed/89 passed/14 skipped, all 88 failures
pre-existing and unrelated).

Commits: `70927b1` (workflows.py), `be1ef48` (billing.py, memory.py, security.py).

### 3.2 WebSocket auth bypass — `apps/api/websockets/agent_events.py` (this session, uncommitted)

The dashboard's real-time event WebSocket (`/ws/agent-events`) built its `ActorContext` **directly from
URL query parameters** (`user_id`, `workspace_id`, `role`, `plan`) with no verification whatsoever. The
endpoint's own docstring demonstrated the exploit:

```
ws://localhost:8000/ws/agent-events?user_id=user_1&workspace_id=workspace_1&role=admin&plan=pro
```

Any client could connect claiming to be any user in any workspace with `role=admin`, and would receive
that workspace's live agent events — a real cross-workspace data leak, and a bypass of the
`can_connect(actor.role)` role gate the connection code otherwise enforces correctly.

**Fix (approved via explicit check-in, "token-as-query-param" option selected):** the endpoint now
requires a real, signed access token as `?token=<jwt>` (browsers cannot set a custom `Authorization`
header during a WebSocket handshake, so the token travels as a query parameter — the only architectural
difference from the HTTP routers). `websocket_actor_from_token()` verifies it through the exact same
chain every HTTP route uses: `TOKEN_SERVICE.verify_token()` → JTI revocation check → active-user check →
live session lookup → live membership lookup. `ActorContext` is built entirely from this verified data;
client-supplied values are never trusted again. Verified live:

```
No token           -> 403 Forbidden (handshake rejected before accept())
Bogus token         -> 403 Forbidden
Real, valid token   -> connects; receives real "connected" + live "dashboard.notification" events
```

Full pytest suite re-run after this fix: zero regressions (186 passed, 6 skipped).

### 3.3 Password leak in validation errors — `apps/api/main.py` (this session, uncommitted)

Pydantic's default `RequestValidationError.errors()` includes the raw submitted value for every failing
field under `"input"`. For a `password` field that failed validation (too short, etc.), the API's 422
response echoed the caller's **actual plaintext password** back in the JSON body — and for body-level
errors, `"input"` is the entire submitted payload dict, password included, regardless of which field
actually failed. A related bug: Pydantic v2 puts the raised exception *object* (not a string) in `ctx`
for custom validator failures, which crashed the response serializer with an unrelated 500 instead of
returning the validation error at all.

**Fix:** `sanitize_validation_errors()` recursively drops (not just masks) any key matching a sensitivity
marker (`password`, `secret`, `token`, `api_key`, `authorization`, `credential`, `private_key`) from
both `input` and `ctx`, and stringifies any non-JSON-safe value it encounters. Verified via the exact
payloads that triggered the original leak (`tests/api_tests/test_auth.py`), now passing.

---

## 4. Backend test result

```
$ python -m pytest -q -p no:warnings
........................................................................ [ 37%]
......................s...............sss...................ss.......... [ 75%]
................................................                         [100%]
186 passed, 6 skipped in 136.23s (0:02:16)
```

**0 failed.** This was re-run after every fix in this report to confirm zero regressions — the number
never dropped below 186 passed once reached. Starting baseline at the top of this session's Phase 12
work was 88 failed / 89 passed / 14 skipped; every one of the 88 original failures is now fixed or
converted to an honestly-skipped test with a documented reason (see §7 for the 2 in
`test_memory.py` — no memory-audit-log endpoint exists to test against).

```
$ python -m compileall -q apps agents core database security subscriptions tests
(clean, exit 0, no output)
```

Also fixed as part of getting here: a real-JWT test-auth helper (`tests/api_tests/conftest.py`,
`make_owner`/`make_member`/`set_plan` fixtures) replacing every spoofable-header test fixture across
`test_agents.py` and `test_memory.py` with genuine registration → login → real Bearer token flows.

---

## 5. Frontend check / build result

```
$ npm run check          (type-check && lint && format:check)
> tsc --noEmit            -- clean, 0 errors
> next lint                -- ✔ No ESLint warnings or errors
> prettier --check .       -- All matched files use Prettier code style!

$ npm run build
✓ Compiled successfully
✓ Generating static pages (19/19)

Route (app)                              Size     First Load JS
┌ ○ /                                    146 B          87.5 kB
├ ○ /agent-permissions                   8.72 kB          96 kB
├ ○ /agents                              8.45 kB        95.8 kB
├ ○ /analytics                           13.2 kB         104 kB
├ ○ /billing                             8.66 kB          96 kB
├ ○ /calls                               9.62 kB        96.9 kB
├ ○ /creator                             10.3 kB        97.6 kB
├ ○ /crm                                 13 kB           104 kB
├ ○ /dashboard                           7.23 kB        94.5 kB
├ ○ /finance                             8.66 kB          96 kB
├ ○ /login                               30.3 kB         118 kB
├ ○ /memory                              7.75 kB        95.1 kB
├ ○ /security                            146 B          87.5 kB
├ ○ /settings                            146 B          87.5 kB
├ ○ /tasks                               12.4 kB         103 kB
└ ○ /workflows                           13.5 kB         104 kB
```

All 17 routes build cleanly. All bundle sizes identical before/after the Prettier formatting pass this
session, confirming that pass changed only whitespace/quote style, not logic.

---

## 6. Runtime verification results (live backend + frontend booted together)

Backend booted via real `uvicorn apps.api.main:app`, frontend via real `next dev`, against a freshly
migrated local SQLite database (see §1). Live HTTP/WebSocket calls, not mocked:

| Step | Result |
|---|---|
| `POST /auth/register` | Real user + workspace + membership + session + signed JWT created; real audit row written |
| `POST /auth/login` | Real credential verification, real session, real JWT |
| `GET /users/me` (Bearer auth) | Real profile/workspace/membership returned, correctly scoped |
| `POST /tasks/run` (non-sensitive) | Routes through the real `MasterAgent` pipeline (planning, step routing, real audit logging throughout); fails at agent-registry resolution — see §8 gap #2 |
| `POST /security/decide` (sensitive action) | Real Security Agent decision (`outcome: requires_approval`, real risk assessment, real `approval_id`), real Verification payload attached |
| `POST /memory/save` | Real memory row persisted, real Verification payload attached |
| `GET /audit` | Real, persisted, workspace-scoped audit trail; session IDs correctly masked in the response |
| `ws://.../ws/agent-events?token=<jwt>` | No token → 403; bogus token → 403; real token → connects, receives real `connected` confirmation + live `dashboard.notification` event |
| CORS preflight (`Origin: http://localhost:3002`) | Correctly allowed, credentials enabled, all needed headers present |
| Frontend pages (`/login`, `/dashboard`, `/`) | All return 200 after a stale-dev-server restart (see §7) |

Full pytest suite re-confirmed green (186 passed / 6 skipped / 0 failed) after every fix made during
this runtime pass.

---

## 7. What was not completed, and why

1. **Visual browser walkthrough (click-through register → login → dashboard rendering).** The Claude
   Chrome extension is not connected in this environment (`tabs_context_mcp` returned "Browser extension
   is not connected" on repeated attempts) — a genuinely unavailable external dependency, not something
   fixable from inside the repair session. Compensated with thorough HTTP-level verification instead
   (§6): every response shape the frontend code parses was confirmed correct against the real backend,
   CORS was confirmed correctly configured for the dashboard's origin, and the full production build
   (§5) already proves the code compiles and type-checks against these exact real contracts.
2. **Two skipped tests in `test_memory.py`** (`test_memory_audit_logs_are_visible_only_to_current_
   workspace_admin_scope`, `test_viewer_cannot_read_memory_audit_logs`) — both premised on a
   memory-specific audit-log endpoint that doesn't exist. `Memory.audit()` calls
   `apps.api.services.audit.audit_log`, a module that isn't implemented anywhere in this codebase, so
   memory audit events currently silently no-op rather than persisting anywhere queryable.
3. **`VerificationAgent`, `MasterAgent` registry gap** — see §8, items 1–2.
4. Two stray, incidentally-discovered dev-server processes on ports 3000/3001 were found running with a
   stale `.next` build during this session (left over from earlier Phase 13-14 build/dev-mode
   switching) — killed and replaced with a clean instance on port 3002 as part of verification. Not a
   code bug, noted here only because it's the reason `/login` briefly 404'd during this session's own
   testing before the restart.

---

## 8. Remaining architecture gaps

### 8.1 `VerificationAgent` cannot be dispatched through the generic adapter

The real `agents/verification_agent/verification_agent.py::VerificationAgent.verify_task()` requires
**two mandatory positional arguments** (`context`, `task_payload`), not the single dict every generic
dispatcher (`OptionalHook`/`OptionalAgentHook` in `tasks.py`/`auth.py`, and `MasterAgent`'s own step
executor) is built to call (`method(payload)`). Unlike the `SecurityAgent`/`MemoryAgent` fixes made this
session (which were pure method-name-ordering bugs — the right method existed and just wasn't tried
first), this one needs a real, purpose-built adapter function that splits one incoming payload into
`context=`/`task_payload=` and maps each call site's payload shape onto `verify_task`'s actual
parameters (`expected_state`, `actual_state`, `verification_plan`, `proof_inputs`, `require_security`).
Documented inline at both dispatcher definitions (`apps/api/routes/auth.py`, `apps/api/routes/
tasks.py`). Until built, `verification_result` will keep failing honestly (a structured, logged failure)
rather than silently faking success.

### 8.2 `MasterAgent`'s internal agent registry doesn't resolve planner-requested capabilities

Confirmed live during runtime verification (§6): a real task submitted through `POST /tasks/run` routes
correctly through the entire `MasterAgent` pipeline (context validation, memory recall, planning,
step-by-step execution, audit logging) but fails at the routing step for the planned step itself:

```json
"route": {
  "success": false,
  "error": "No suitable registered agent found.",
  "data": {"decision": {"agent_name": null, "confidence": 0.0, "reason": "No suitable registered agent found."}}
}
```

`MasterAgent` maintains its own internal `self.agent_registry` dict, separate from the shared
`agents/registry.py:AgentRegistry` class the rest of the system uses — and it isn't populated with the
15 real specialized agents at boot/instantiation time. This is the same gap flagged in the original
Phase 6 planning notes ("unify MasterAgent's own dict-based agent map with a single shared
`agents.registry.AgentRegistry` instance") — confirmed still open by this session's live runtime test,
not newly discovered. Fixing it requires wiring `MasterAgent`'s registry lookup to the real shared
`AgentRegistry`/`AgentLoader` chain, plus (once that's done) very likely surfacing the same payload-
vocabulary mismatch each individual agent's bespoke `run_task()` expects (e.g. `MemoryAgent.run_task()`
wants `action` to be one of `store`/`recall`/`search`/`update`/`delete`, not the planner's generic
`"general_request"`/`"memory_assist"` action names) — i.e., §8.1's per-agent adapter problem, at scale,
for all 15 agents once routing itself works.

### 8.3 Visual browser walkthrough blocked by unavailable Chrome extension

See §7, item 1. Not a code gap — an environment/tooling limitation for this specific session. Retry in
an environment with the Claude Chrome extension installed and connected.

---

## 9. Exact next recommended repair phase

**Phase 18 (new, not in the original 17-phase plan): MasterAgent registry unification + per-agent
payload adapters.**

1. Wire `core/master_agent.py`'s `self.agent_registry` to the real, shared `agents/registry.py:
   AgentRegistry` (already correctly populated and used elsewhere in the system — confirmed all 15
   agents import cleanly as of Phase 6). This alone should fix the "No suitable registered agent found"
   routing failure for every task.
2. Build the `VerificationAgent` adapter described in §8.1 (a `context`/`task_payload`-splitting wrapper
   function, reused at both dispatcher call sites).
3. Once routing works end-to-end, re-run the exact live task-execution walkthrough from §6 and confirm a
   **fully successful** (not just honestly-failing) sensitive-action flow: task → security approval →
   real agent execution → real verification → real memory write → audit rows, all in one request.
4. Audit the other 12 specialized agents' real entrypoint signatures the same way this session did for
   `SecurityAgent`/`MemoryAgent`/`VerificationAgent` (grep each `agents/*/*.py` for its actual public
   method, don't assume `execute_task()`/`run()` compatibility) before wiring them into
   `MasterAgent`'s step executor, to avoid rediscovering the same class of bug agent-by-agent.
5. Re-run the visual browser walkthrough (§7, item 1) once the Chrome extension is available, to close
   the one verification step this session couldn't complete.

Do **not** re-run Phases 1–16 — all are confirmed complete and green as of this report.

---

## 10. Is the repo safe to commit now?

**Yes, for the security fixes and root-cause bug fixes — no, don't commit yet, per your standing
instruction.** Nothing has been committed this session (all changes in §2 remain in the working tree),
consistent with "do not commit unless explicitly approved." Assessment, if/when you do approve a commit:

- **Safe and recommended to commit as-is:** every fix in §1 and §3. Each was verified independently
  (compile check, targeted test re-run, full-suite regression check) and the full suite is green
  (§4). The WebSocket auth fix (§3.2) closes a real, exploitable vulnerability and should not sit
  uncommitted longer than necessary.
- **Nothing half-finished or fake is included.** The two remaining architecture gaps (§8.1, §8.2) fail
  *honestly* (structured errors, real audit logging of the failure) rather than being silently patched
  over — there is no fabricated success path hiding them.
- **One judgment call worth your explicit sign-off before committing:** `william.db` was reset (old
  version preserved as `william.db.stale-backup-20260711220838`, not deleted, not committed — it's a
  local dev SQLite file, gitignored either way). Confirm you're fine with that backup file being left
  in the working directory (harmless, but you may want to delete it once you've confirmed you don't
  need the old data).
- Suggested commit split, if useful: (a) the WebSocket security fix alone, since it's the most
  time-sensitive; (b) the agent-dispatch/error-shape/DB-config bug fixes together (all "runtime
  verification" findings); (c) the frontend Prettier formatting pass separately from any frontend logic
  changes, since it's a large, pure-formatting diff that's easiest to review in isolation.

---

## 11. Commands to run after pulling/opening next time

```bash
# Backend
python -m venv .venv && .venv\Scripts\activate          # if not already set up
pip install -r requirements.txt
python -m alembic upgrade head                            # ensure DB schema is current
python -m pytest -q                                        # expect: 186 passed, 6 skipped, 0 failed
python -m compileall -q apps agents core database security subscriptions tests

# Backend runtime (for manual/API testing)
python -m uvicorn apps.api.main:app --host 0.0.0.0 --port 8000 --reload

# Frontend
cd apps/dashboard
npm install                                                 # if not already set up
npm run check                                                # type-check + lint + format:check, expect clean
npm run build                                                 # expect all 17 routes to build
npm run dev                                                   # dev server; NEXT_PUBLIC_API_BASE_URL is in .env.local

# If you see a stale/404'ing dev server (as this session did once):
# check for zombie node processes on 3000/3001 before assuming a real bug:
netstat -ano | findstr ":3000 :3001"
```

`apps/dashboard/.env.local` (created this session, gitignored, not committed) points
`NEXT_PUBLIC_API_BASE_URL` at `http://localhost:8000/api/v1` for local dev — recreate it if missing:

```
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000/api/v1
```
