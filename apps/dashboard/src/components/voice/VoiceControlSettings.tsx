"use client";

/**
 * apps/dashboard/src/components/voice/VoiceControlSettings.tsx
 *
 * Live-wired "Voice Control" settings section for Phase 9's real voice
 * backend (apps/api/routes/voice.py, mounted at /voice/*). Unlike the rest
 * of settings/page.tsx (still static mock data), this section always talks
 * to the real API through lib/api-client.ts's voiceApi -- no fabricated
 * values. Visually matches this page's own existing dark card language
 * (border-neutral-100, bg-white, orange-500 accents) since that is
 * what already surrounds it on this page.
 */

import { useCallback, useEffect, useState } from "react";
import {
  Check,
  Copy,
  Mic,
  RefreshCcw,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  UserPlus,
  Users,
} from "lucide-react";
import { readSession, hasMinRole, type SessionData } from "@/lib/auth";
import {
  voiceApi,
  type VoiceDependencyEntry,
  type VoiceDependencyStatus,
  type VoiceDependencyStatusValue,
  type VoiceMode,
  type VoiceProfile,
  type VoiceProfileRole,
  type VoiceSettings,
  type VoiceStatusData,
} from "@/lib/api-client";
import { LoadingState } from "@/components/state/LoadingState";
import { ErrorState } from "@/components/state/ErrorState";
import { VoiceWorkerStatusCard } from "@/components/voice/VoiceWorkerStatusCard";

type LoadState = "loading" | "ready" | "error";

const VOICE_MODE_OPTIONS: {
  value: VoiceMode;
  label: string;
  description: string;
  requiresApproval: boolean;
}[] = [
  {
    value: "disabled",
    label: "Disabled",
    description: "Voice is fully off for this workspace.",
    requiresApproval: false,
  },
  {
    value: "push_to_talk",
    label: "Push-to-talk",
    description: "Only explicit typed/PTT commands from signed-in users.",
    requiresApproval: false,
  },
  {
    value: "wake_word_admin",
    label: "Wake word (admin only)",
    description: "Wake word listening, restricted to owner/admin speakers.",
    requiresApproval: true,
  },
  {
    value: "wake_word_trusted_users",
    label: "Wake word (trusted users)",
    description: "Wake word listening for any active trusted voice profile.",
    requiresApproval: true,
  },
  {
    value: "continuous_conversation",
    label: "Continuous conversation",
    description: "Always-listening conversational mode.",
    requiresApproval: true,
  },
  {
    value: "standby",
    label: "Standby",
    description:
      "Worker stays connected but ignores commands until the wake word is heard again or voice is re-enabled here.",
    requiresApproval: false,
  },
];

function runtimeStateLabel(state: string): string {
  const labels: Record<string, string> = {
    disabled: "Disabled",
    push_to_talk: "Push to Talk",
    worker_offline: "Worker Offline",
    dependency_required: "Dependency Required",
    listening: "Listening",
    standby: "Standby",
  };
  return labels[state] || state.replace(/_/g, " ");
}

function runtimeStateStyle(state: string): string {
  if (state === "listening")
    return "border-emerald-200 bg-emerald-50 text-emerald-700";
  if (state === "push_to_talk")
    return "border-blue-200 bg-blue-50 text-blue-700";
  if (state === "worker_offline" || state === "dependency_required")
    return "border-orange-400/25 bg-orange-500/10 text-[#ff5a3d]";
  if (state === "standby")
    return "border-purple-200 bg-purple-50 text-purple-700";
  return "border-red-200 bg-red-50 text-red-700";
}

const DEPENDENCY_LABELS: Record<keyof VoiceDependencyStatus, string> = {
  wake_word_engine: "Wake word engine (text)",
  wake_word_provider: "Wake word engine (real audio)",
  audio_input_worker: "Audio input worker",
  stt_provider: "Speech-to-text provider",
  tts_provider: "Text-to-speech provider",
  speaker_recognition_provider: "Speaker recognition provider",
};

const WAKE_WORD_GATED_MODES = new Set([
  "wake_word_admin",
  "wake_word_trusted_users",
  "continuous_conversation",
]);

function dependencyStyle(status: VoiceDependencyStatusValue): string {
  if (status === "available" || status === "configured") {
    return "border-emerald-200 bg-emerald-50 text-emerald-700";
  }
  return "border-orange-400/25 bg-orange-500/10 text-[#ff5a3d]";
}

function dependencyLabel(status: VoiceDependencyStatusValue): string {
  if (status === "available") return "Available";
  if (status === "configured") return "Configured";
  return "Needs setup";
}

function modeStyle(mode: VoiceMode): string {
  if (mode === "disabled") return "border-red-200 bg-red-50 text-red-700";
  if (mode === "push_to_talk")
    return "border-blue-200 bg-blue-50 text-blue-700";
  return "border-emerald-200 bg-emerald-50 text-emerald-700";
}

function formatDate(value?: string | null): string {
  if (!value) return "—";
  try {
    return new Intl.DateTimeFormat("en-US", {
      month: "short",
      day: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    }).format(new Date(value));
  } catch {
    return value;
  }
}

function fieldValue(value?: string | null): string {
  return value && value.trim().length > 0 ? value : "—";
}

const TRUSTED_VOICE_ROLE_OPTIONS: { value: VoiceProfileRole; label: string }[] =
  [
    { value: "admin", label: "Admin" },
    { value: "trusted_friend", label: "Friend" },
    { value: "trusted_family", label: "Family" },
    { value: "trusted_team_member", label: "Team member" },
    { value: "guest", label: "Guest" },
  ];

function profileTypeLabel(role: VoiceProfileRole): string {
  const match = TRUSTED_VOICE_ROLE_OPTIONS.find((option) => option.value === role);
  if (match) return match.label;
  if (role === "owner") return "Owner";
  if (role === "trusted_developer") return "Trusted developer";
  if (role === "trusted_manager") return "Trusted manager";
  if (role === "trusted_assistant") return "Trusted assistant";
  return role;
}

const PROVIDER_LABELS: Record<
  | "audio_input_status"
  | "stt_status"
  | "tts_status"
  | "wake_word_status"
  | "speaker_recognition_status",
  string
> = {
  audio_input_status: "Microphone / audio input",
  stt_status: "Speech-to-text (STT)",
  tts_status: "Text-to-speech (TTS)",
  wake_word_status: "Wake word (real audio)",
  speaker_recognition_status: "Speaker recognition",
};

function providerEntryStyle(entry: VoiceDependencyEntry): string {
  return entry.status === "configured" || entry.status === "available"
    ? "border-emerald-200 bg-emerald-50 text-emerald-700"
    : "border-orange-400/25 bg-orange-500/10 text-[#ff5a3d]";
}

function providerEntryLabel(entry: VoiceDependencyEntry): string {
  if (entry.status === "configured" || entry.status === "available")
    return "Ready";
  return "Needs setup";
}

export function VoiceControlSettings() {
  const [session, setSession] = useState<SessionData | null>(null);
  const [state, setState] = useState<LoadState>("loading");
  const [errorMessage, setErrorMessage] = useState("");
  const [settings, setSettings] = useState<VoiceSettings | null>(null);
  const [status, setStatus] = useState<VoiceStatusData | null>(null);
  const [wakeWordDefault, setWakeWordDefault] = useState("william");
  const [wakeWordInput, setWakeWordInput] = useState("");
  const [assistantNameInput, setAssistantNameInput] = useState("");
  const [savingMode, setSavingMode] = useState<VoiceMode | null>(null);
  const [savingWakeWord, setSavingWakeWord] = useState(false);
  const [savingAssistantName, setSavingAssistantName] = useState(false);
  const [enablingVoice, setEnablingVoice] = useState(false);
  const [decidingApproval, setDecidingApproval] = useState<
    "approve" | "deny" | null
  >(null);
  const [notice, setNotice] = useState<{
    type: "success" | "error" | "info";
    message: string;
  } | null>(null);
  const [copiedCommand, setCopiedCommand] = useState<string | null>(null);

  // Trusted Voice Profiles (Part 5) -- own loading/error state, separate
  // from the voice-status load above, since profiles are a distinct
  // resource that can be refreshed independently.
  const [voiceProfiles, setVoiceProfiles] = useState<VoiceProfile[]>([]);
  const [profilesLoading, setProfilesLoading] = useState(true);
  const [profilesError, setProfilesError] = useState("");
  const [enrollingOwner, setEnrollingOwner] = useState(false);
  const [showAddTrustedVoiceForm, setShowAddTrustedVoiceForm] = useState(false);
  const [newProfileName, setNewProfileName] = useState("");
  const [newProfileRole, setNewProfileRole] =
    useState<VoiceProfileRole>("trusted_friend");
  const [addingProfile, setAddingProfile] = useState(false);
  const [revokingProfileId, setRevokingProfileId] = useState<string | null>(
    null,
  );
  const [enrollCliCommand, setEnrollCliCommand] = useState<string | null>(
    null,
  );

  const loadVoiceProfiles = useCallback(async () => {
    setProfilesLoading(true);
    setProfilesError("");
    const response = await voiceApi.listProfiles();
    if (response.success === false) {
      setProfilesError(
        response.error.message || "Could not load voice profiles.",
      );
      setProfilesLoading(false);
      return;
    }
    setVoiceProfiles(response.data.profiles);
    setProfilesLoading(false);
  }, []);

  useEffect(() => {
    void loadVoiceProfiles();
  }, [loadVoiceProfiles]);

  async function handleEnrollOwnerVoice() {
    if (!canConfigureVoice || enrollingOwner) return;
    setEnrollingOwner(true);
    setNotice(null);
    const response = await voiceApi.createProfile({
      display_name: "Owner",
      role: "owner",
      can_use_voice: true,
      can_use_wake_word: true,
    });
    setEnrollingOwner(false);
    if (response.success === false) {
      setNotice({
        type: "error",
        message: response.error.message || "Could not create owner voice profile.",
      });
      return;
    }
    setEnrollCliCommand(
      `python -m apps.worker_nodes.voice.voice_worker --enroll-voice owner`,
    );
    setNotice({
      type: "info",
      message:
        "Owner profile created. Run the enrollment command below on the machine with the Voice Worker and a microphone to finish enrollment.",
    });
    await loadVoiceProfiles();
  }

  async function handleAddTrustedVoice() {
    if (!canConfigureVoice || addingProfile || !newProfileName.trim()) return;
    setAddingProfile(true);
    setNotice(null);
    const response = await voiceApi.createProfile({
      display_name: newProfileName.trim(),
      role: newProfileRole,
      can_use_voice: true,
      can_use_wake_word: newProfileRole !== "guest",
    });
    setAddingProfile(false);
    if (response.success === false) {
      setNotice({
        type: "error",
        message: response.error.message || "Could not create voice profile.",
      });
      return;
    }
    setEnrollCliCommand(
      `python -m apps.worker_nodes.voice.voice_worker --enroll-voice ${newProfileRole}`,
    );
    setNotice({
      type: "info",
      message: `${newProfileName.trim()} added. Run the enrollment command below on the machine with the Voice Worker and a microphone to finish enrollment.`,
    });
    setNewProfileName("");
    setShowAddTrustedVoiceForm(false);
    await loadVoiceProfiles();
  }

  async function handleRevokeProfile(profileId: string) {
    if (!canConfigureVoice || revokingProfileId) return;
    setRevokingProfileId(profileId);
    setNotice(null);
    const response = await voiceApi.deleteProfile(profileId);
    setRevokingProfileId(null);
    if (response.success === false) {
      setNotice({
        type: "error",
        message: response.error.message || "Could not revoke voice profile.",
      });
      return;
    }
    setNotice({ type: "success", message: "Voice profile revoked." });
    await loadVoiceProfiles();
  }

  const copyCommand = useCallback(async (key: string, command: string) => {
    try {
      await navigator.clipboard.writeText(command);
      setCopiedCommand(key);
      setTimeout(
        () => setCopiedCommand((current) => (current === key ? null : current)),
        2000,
      );
    } catch {
      // Clipboard access denied/unavailable -- the command text is still
      // visible on the page, so this is a non-fatal degradation.
    }
  }, []);

  const canConfigureVoice = Boolean(
    session && hasMinRole(session.role, "admin"),
  );

  const load = useCallback(async () => {
    setState("loading");
    setErrorMessage("");

    const response = await voiceApi.status();

    if (response.success === false) {
      setState("error");
      setErrorMessage(response.error.message || "Could not load voice status.");
      return;
    }

    setSettings(response.data.settings);
    setStatus(response.data);
    setWakeWordDefault(response.data.wake_word_default || "william");
    setWakeWordInput(response.data.settings.wake_word || "");
    setAssistantNameInput(response.data.assistant_display_name || "William");
    setState("ready");
  }, []);

  useEffect(() => {
    setSession(readSession());
    void load();
  }, [load]);

  async function handleModeChange(mode: VoiceMode) {
    if (!canConfigureVoice || savingMode) return;

    setSavingMode(mode);
    setNotice(null);

    const response = await voiceApi.updateConfig({ mode });

    if (response.success === false) {
      setNotice({
        type: "error",
        message: response.error.message || "Voice mode could not be updated.",
      });
      setSavingMode(null);
      return;
    }

    setSettings(response.data.settings);
    void load();

    if (response.data.requires_approval && !response.data.approved) {
      setNotice({
        type: "error",
        message: `Mode "${mode}" requires Security Agent approval, which was not granted. Voice mode is unchanged.`,
      });
    } else {
      setNotice({
        type: "success",
        message: `Voice mode updated to "${mode}".`,
      });
    }

    setSavingMode(null);
  }

  async function handleSaveWakeWord() {
    if (!canConfigureVoice || savingWakeWord) return;
    const trimmed = wakeWordInput.trim();
    if (!trimmed) return;

    setSavingWakeWord(true);
    setNotice(null);

    const response = await voiceApi.updateConfig({ wake_word: trimmed });

    if (response.success === false) {
      setNotice({
        type: "error",
        message: response.error.message || "Wake word could not be updated.",
      });
      setSavingWakeWord(false);
      return;
    }

    setSettings(response.data.settings);
    setNotice({ type: "success", message: "Wake word updated." });
    setSavingWakeWord(false);
  }

  async function handleSaveAssistantName() {
    if (!canConfigureVoice || savingAssistantName) return;
    const trimmed = assistantNameInput.trim();
    if (!trimmed) return;

    setSavingAssistantName(true);
    setNotice(null);

    const response = await voiceApi.updateConfig({
      assistant_display_name: trimmed,
    });

    if (response.success === false) {
      setNotice({
        type: "error",
        message:
          response.error.message || "Assistant name could not be updated.",
      });
      setSavingAssistantName(false);
      return;
    }

    setSettings(response.data.settings);
    setNotice({ type: "success", message: "Assistant name updated." });
    setSavingAssistantName(false);
  }

  async function handleEnableVoiceAgent() {
    if (enablingVoice) return;
    setEnablingVoice(true);
    setNotice(null);

    const response = await voiceApi.enable();

    if (response.success === false) {
      setNotice({
        type: "error",
        message: response.error.message || "Voice Agent could not be enabled.",
      });
      setEnablingVoice(false);
      return;
    }

    setSettings(response.data.settings);
    void load();

    if (response.data.approved) {
      setNotice({
        type: "success",
        message: "Voice Agent enabled. Runtime mode is now Wake Word (Admin).",
      });
    } else {
      setNotice({
        type: "info",
        message: `This needs a workspace owner/admin to approve it (approval_id: ${response.data.approval_id}). Ask an owner/admin to approve it below.`,
      });
    }
    setEnablingVoice(false);
  }

  async function handleDecideModeRequest(decision: "approve" | "deny") {
    if (!settings?.pending_approval_id || decidingApproval) return;
    setDecidingApproval(decision);
    setNotice(null);

    const response = await voiceApi.decideModeRequest({
      approval_id: settings.pending_approval_id,
      decision,
    });

    if (response.success === false) {
      setNotice({
        type: "error",
        message: response.error.message || "Could not decide this request.",
      });
      setDecidingApproval(null);
      return;
    }

    setSettings(response.data.settings);
    setNotice({
      type: "success",
      message:
        decision === "approve"
          ? "Approved. Wake Word (Admin) mode is now active."
          : "Denied. Voice mode is unchanged.",
    });
    setDecidingApproval(null);
  }

  return (
    <section className="rounded-[32px] border border-neutral-100 bg-white p-5 shadow-sm md:p-6">
      <div className="mb-6 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <div>
          <p className="text-sm font-bold text-[#ff5a3d]">Voice Control</p>
          <h2 className="mt-2 text-2xl font-black tracking-tight text-neutral-950">
            William Voice Agent (Phase 9)
          </h2>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-neutral-400">
            Live workspace voice mode, wake word, and dependency status -- wired
            directly to /voice/status and /voice/config.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {canConfigureVoice ? (
            <button
              type="button"
              onClick={() => void handleEnableVoiceAgent()}
              disabled={enablingVoice || settings?.mode === "wake_word_admin"}
              className="inline-flex items-center gap-2 rounded-2xl bg-[#ff5a3d] px-4 py-2 text-xs font-black text-white shadow-lg shadow-[#ff5a3d]/20 transition hover:bg-neutral-950 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <Mic className="h-3.5 w-3.5" />
              {settings?.mode === "wake_word_admin"
                ? "Voice Agent Enabled"
                : enablingVoice
                  ? "Enabling..."
                  : "Enable Voice Agent"}
            </button>
          ) : null}
          <button
            type="button"
            onClick={() => void load()}
            className="inline-flex items-center gap-2 rounded-2xl border border-neutral-100 bg-neutral-50 px-3 py-2 text-xs font-bold text-neutral-600 transition hover:border-orange-500/30 hover:bg-orange-500/10 hover:text-[#ff5a3d]"
          >
            <RefreshCcw className="h-3.5 w-3.5" />
            Refresh
          </button>
        </div>
      </div>

      {state === "loading" ? (
        <LoadingState
          variant="light"
          title="Loading voice status..."
          subtitle="Calling /voice/status."
        />
      ) : state === "error" ? (
        <ErrorState
          variant="light"
          title="Voice status could not load"
          message={errorMessage}
          onRetry={() => void load()}
        />
      ) : settings ? (
        <div className="space-y-5">
          {notice ? (
            <div
              className={[
                "rounded-2xl border px-4 py-3 text-sm font-bold",
                notice.type === "success"
                  ? "border-emerald-200 bg-emerald-50 text-emerald-700"
                  : notice.type === "error"
                    ? "border-red-200 bg-red-50 text-red-700"
                    : "border-blue-200 bg-blue-50 text-blue-700",
              ].join(" ")}
            >
              {notice.message}
            </div>
          ) : null}

          {settings.pending_approval_id ? (
            <div className="rounded-2xl border border-orange-400/25 bg-orange-500/10 px-4 py-3">
              <p className="text-sm font-bold text-[#ff5a3d]">
                Approval required: {settings.pending_mode?.replace(/_/g, " ")}{" "}
                mode is waiting on a workspace owner/admin.
              </p>
              <p className="mt-1 text-xs font-semibold text-neutral-500">
                approval_id: {settings.pending_approval_id}
              </p>
              {canConfigureVoice ? (
                <div className="mt-3 flex gap-2">
                  <button
                    type="button"
                    onClick={() => void handleDecideModeRequest("approve")}
                    disabled={decidingApproval !== null}
                    className="rounded-full bg-emerald-600 px-4 py-2 text-xs font-black text-white transition hover:bg-emerald-700 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    {decidingApproval === "approve"
                      ? "Approving..."
                      : "Approve"}
                  </button>
                  <button
                    type="button"
                    onClick={() => void handleDecideModeRequest("deny")}
                    disabled={decidingApproval !== null}
                    className="rounded-full border border-red-200 px-4 py-2 text-xs font-black text-red-600 transition hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    {decidingApproval === "deny" ? "Denying..." : "Deny"}
                  </button>
                </div>
              ) : null}
            </div>
          ) : null}

          <div className="grid gap-4 sm:grid-cols-3">
            <div className="rounded-2xl border border-neutral-100 bg-neutral-50 p-4">
              <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-neutral-400">
                Current mode
              </p>
              <span
                className={`mt-2 inline-flex rounded-full border px-3 py-1 text-xs font-black capitalize ${modeStyle(
                  settings.mode,
                )}`}
              >
                {settings.mode.replace(/_/g, " ")}
              </span>
              {settings.requires_security_approval ? (
                <p className="mt-3 flex items-center gap-2 text-xs font-semibold text-[#ff5a3d]">
                  <ShieldAlert className="h-3.5 w-3.5" />
                  This mode required Security Agent approval to enable.
                </p>
              ) : null}
            </div>

            <div className="rounded-2xl border border-neutral-100 bg-neutral-50 p-4">
              <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-neutral-400">
                Runtime state
              </p>
              {status ? (
                <span
                  className={`mt-2 inline-flex rounded-full border px-3 py-1 text-xs font-black ${runtimeStateStyle(
                    status.runtime_state,
                  )}`}
                >
                  {runtimeStateLabel(status.runtime_state)}
                </span>
              ) : (
                <p className="mt-2 text-sm font-bold text-neutral-400">—</p>
              )}
              <p className="mt-1 text-xs text-neutral-400">
                Active sessions: {status?.active_sessions ?? 0}
              </p>
            </div>

            <div className="rounded-2xl border border-neutral-100 bg-neutral-50 p-4">
              <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-neutral-400">
                Voice worker
              </p>
              <p className="mt-2 text-sm font-bold text-neutral-950">
                {settings.voice_worker_connected
                  ? "Connected"
                  : "Not connected"}
              </p>
              <p className="mt-1 text-xs text-neutral-400">
                Last seen: {formatDate(settings.voice_worker_last_seen_at)}
              </p>
            </div>
          </div>

          {status && status.missing_dependencies.length > 0 ? (
            <div className="rounded-2xl border border-orange-400/25 bg-orange-500/10 px-4 py-3 text-xs font-bold text-orange-200">
              Missing providers: {status.missing_dependencies.join(", ")}. The
              dashboard never simulates a working microphone/speaker/speaker-ID
              pipeline -- connect real providers to move past{" "}
              {runtimeStateLabel("dependency_required")}.
            </div>
          ) : null}

          {status &&
          !status.always_listening_available &&
          WAKE_WORD_GATED_MODES.has(settings.mode) ? (
            <div className="rounded-2xl border border-orange-400/25 bg-orange-500/10 px-4 py-3 text-xs font-bold text-orange-200">
              Wake word mode is enabled, but real listening needs audio input,
              STT, and wake-word provider.
            </div>
          ) : null}

          {status?.always_listening_available ? (
            <div className="rounded-2xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-xs font-bold text-emerald-700">
              Voice Worker ready. Say &ldquo;William&rdquo; followed by your
              command.
            </div>
          ) : null}

          {status?.text_command_available ? (
            <div className="rounded-2xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-xs font-bold text-emerald-700">
              Text push-to-talk works right now, even with the missing providers
              above -- only always-listening wake-word mode needs them.
            </div>
          ) : null}

          {settings.last_error_message ? (
            <div className="rounded-2xl border border-red-200 bg-red-50 px-4 py-3 text-xs font-bold text-red-700">
              Last error: {settings.last_error_message}
            </div>
          ) : null}

          {status ? (
            <div>
              <p className="mb-3 text-[11px] font-semibold uppercase tracking-[0.16em] text-neutral-400">
                Real voice providers
              </p>
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                {(
                  Object.keys(PROVIDER_LABELS) as Array<
                    keyof typeof PROVIDER_LABELS
                  >
                ).map((key) => {
                  const entry = status[key];
                  return (
                    <div
                      key={key}
                      className="flex flex-col gap-2 rounded-2xl border border-neutral-100 bg-neutral-50 px-4 py-3"
                    >
                      <div className="flex items-center justify-between gap-3">
                        <span className="text-xs font-semibold text-neutral-600">
                          {PROVIDER_LABELS[key]}
                        </span>
                        <span
                          className={`rounded-full border px-2.5 py-1 text-[10px] font-black ${providerEntryStyle(entry)}`}
                        >
                          {providerEntryLabel(entry)}
                        </span>
                      </div>
                      {entry.install_guidance ? (
                        <p className="text-[11px] leading-4 text-neutral-400">
                          {entry.install_guidance}
                        </p>
                      ) : null}
                    </div>
                  );
                })}
              </div>

              <div className="mt-4 flex flex-wrap gap-2">
                {[
                  {
                    key: "install",
                    label: "Copy Voice Dependency Install Command",
                    command: status.setup_commands.install_dependencies,
                  },
                  {
                    key: "check",
                    label: "Check Voice Dependencies",
                    command: status.setup_commands.check_dependencies,
                  },
                  {
                    key: "test-tts",
                    label: "Test TTS",
                    command: `python -m apps.worker_nodes.voice.voice_worker --config "%USERPROFILE%\\.william\\voice_worker.json" --test-tts`,
                  },
                  {
                    key: "test-mic",
                    label: "Test Mic",
                    command: `python -m apps.worker_nodes.voice.voice_worker --config "%USERPROFILE%\\.william\\voice_worker.json" --test-mic`,
                  },
                  {
                    key: "test-wake-word",
                    label: "Test Wake Word",
                    command: `python -m apps.worker_nodes.voice.voice_worker --config "%USERPROFILE%\\.william\\voice_worker.json" --test-wake-word`,
                  },
                  {
                    key: "test-sim",
                    label: "Test Voice Command",
                    command: `python -m apps.worker_nodes.voice.voice_worker --config "%USERPROFILE%\\.william\\voice_worker.json" --simulate-text "William open Notepad"`,
                  },
                ].map((item) => (
                  <button
                    key={item.key}
                    type="button"
                    onClick={() => void copyCommand(item.key, item.command)}
                    className="inline-flex items-center gap-1.5 rounded-full border border-neutral-200 px-3 py-2 text-[11px] font-black text-neutral-600 transition hover:border-[#ff5a3d] hover:text-[#ff5a3d]"
                  >
                    {copiedCommand === item.key ? (
                      <Check size={12} />
                    ) : (
                      <Copy size={12} />
                    )}
                    {copiedCommand === item.key ? "Copied" : item.label}
                  </button>
                ))}
              </div>
            </div>
          ) : null}

          <VoiceWorkerStatusCard />

          <div>
            <p className="mb-3 text-[11px] font-semibold uppercase tracking-[0.16em] text-neutral-400">
              Mode controls
            </p>

            {!canConfigureVoice ? (
              <div className="mb-3 rounded-2xl border border-orange-400/25 bg-orange-500/10 px-4 py-3 text-xs font-bold text-orange-200">
                Only owner/admin roles can change voice mode. You are viewing in
                read-only mode.
              </div>
            ) : null}

            <div className="grid gap-3 sm:grid-cols-2">
              {VOICE_MODE_OPTIONS.map((option) => {
                const isActive = settings.mode === option.value;
                const isBusy = savingMode === option.value;

                return (
                  <button
                    key={option.value}
                    type="button"
                    disabled={!canConfigureVoice || Boolean(savingMode)}
                    onClick={() => void handleModeChange(option.value)}
                    className={[
                      "rounded-2xl border p-4 text-left transition disabled:cursor-not-allowed disabled:opacity-50",
                      isActive
                        ? "border-orange-500/40 bg-orange-500/10"
                        : "border-neutral-100 bg-white hover:border-orange-500/25 hover:bg-orange-500/[0.06]",
                    ].join(" ")}
                  >
                    <div className="flex items-center justify-between gap-3">
                      <p className="text-sm font-black text-neutral-950">
                        {option.label}
                      </p>
                      {isActive ? (
                        <ShieldCheck className="h-4 w-4 shrink-0 text-emerald-700" />
                      ) : option.requiresApproval ? (
                        <ShieldAlert className="h-4 w-4 shrink-0 text-[#ff5a3d]" />
                      ) : null}
                    </div>
                    <p className="mt-1 text-xs leading-5 text-neutral-400">
                      {option.description}
                    </p>
                    {option.requiresApproval ? (
                      <p className="mt-2 text-[11px] font-bold text-[#ff5a3d]">
                        Requires Security Agent approval
                      </p>
                    ) : null}
                    {isBusy ? (
                      <p className="mt-2 text-[11px] font-bold text-neutral-500">
                        Saving...
                      </p>
                    ) : null}
                  </button>
                );
              })}
            </div>
          </div>

          <div className="rounded-2xl border border-neutral-100 bg-neutral-50 p-4">
            <p className="mb-2 text-[11px] font-semibold uppercase tracking-[0.16em] text-neutral-400">
              Wake word (default: {wakeWordDefault})
            </p>
            <div className="flex flex-col gap-3 sm:flex-row">
              <input
                type="text"
                value={wakeWordInput}
                disabled={!canConfigureVoice || savingWakeWord}
                onChange={(event) => setWakeWordInput(event.target.value)}
                maxLength={60}
                placeholder={wakeWordDefault}
                className="w-full rounded-2xl border border-neutral-100 bg-neutral-50 px-4 py-3 text-sm font-semibold text-neutral-700 outline-none transition placeholder:text-neutral-400 focus:border-orange-500/40 focus:ring-4 focus:ring-orange-500/10 disabled:cursor-not-allowed disabled:opacity-50 sm:max-w-xs"
              />
              <button
                type="button"
                disabled={
                  !canConfigureVoice ||
                  savingWakeWord ||
                  !wakeWordInput.trim() ||
                  wakeWordInput.trim() === settings.wake_word
                }
                onClick={() => void handleSaveWakeWord()}
                className="inline-flex items-center justify-center gap-2 rounded-2xl bg-orange-500 px-4 py-3 text-sm font-black text-black transition hover:bg-orange-400 disabled:cursor-not-allowed disabled:opacity-50"
              >
                <Mic className="h-4 w-4" />
                {savingWakeWord ? "Saving..." : "Save Wake Word"}
              </button>
            </div>
            {status ? (
              <p className="mt-3 text-[11px] font-semibold text-neutral-500">
                Real audio wake-word model in use:{" "}
                <span className="font-black text-neutral-700">
                  {status.active_wake_word_model}
                </span>
              </p>
            ) : null}
            {status?.wake_word_custom_model_notice ? (
              <p className="mt-2 rounded-2xl border border-orange-400/25 bg-orange-500/10 px-3 py-2 text-xs font-bold text-orange-200">
                {status.wake_word_custom_model_notice}
              </p>
            ) : null}
          </div>

          <div className="rounded-2xl border border-neutral-100 bg-neutral-50 p-4">
            <p className="mb-2 text-[11px] font-semibold uppercase tracking-[0.16em] text-neutral-400">
              Assistant name
            </p>
            <p className="mb-3 text-xs text-neutral-400">
              What William calls itself in typed/spoken responses. Any name
              works for text commands -- only the real audio wake word above is
              limited to a supported model.
            </p>
            <div className="flex flex-col gap-3 sm:flex-row">
              <input
                type="text"
                value={assistantNameInput}
                disabled={!canConfigureVoice || savingAssistantName}
                onChange={(event) => setAssistantNameInput(event.target.value)}
                maxLength={60}
                placeholder="William"
                className="w-full rounded-2xl border border-neutral-100 bg-white px-4 py-3 text-sm font-semibold text-neutral-700 outline-none transition placeholder:text-neutral-400 focus:border-orange-500/40 focus:ring-4 focus:ring-orange-500/10 disabled:cursor-not-allowed disabled:opacity-50 sm:max-w-xs"
              />
              <button
                type="button"
                disabled={
                  !canConfigureVoice ||
                  savingAssistantName ||
                  !assistantNameInput.trim() ||
                  assistantNameInput.trim() === settings.assistant_display_name
                }
                onClick={() => void handleSaveAssistantName()}
                className="inline-flex items-center justify-center gap-2 rounded-2xl bg-orange-500 px-4 py-3 text-sm font-black text-black transition hover:bg-orange-400 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {savingAssistantName ? "Saving..." : "Save Assistant Name"}
              </button>
            </div>
          </div>

          <div>
            <p className="mb-3 text-[11px] font-semibold uppercase tracking-[0.16em] text-neutral-400">
              Dependency status
            </p>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {(
                Object.keys(DEPENDENCY_LABELS) as Array<
                  keyof VoiceDependencyStatus
                >
              ).map((key) => {
                const entry = settings.dependency_status[key];
                return (
                  <div
                    key={key}
                    className="flex flex-col gap-2 rounded-2xl border border-neutral-100 bg-neutral-50 px-4 py-3"
                  >
                    <div className="flex items-center justify-between gap-3">
                      <span className="text-xs font-semibold text-neutral-600">
                        {DEPENDENCY_LABELS[key]}
                      </span>
                      <span
                        className={`rounded-full border px-2.5 py-1 text-[10px] font-black ${dependencyStyle(
                          entry.status,
                        )}`}
                      >
                        {dependencyLabel(entry.status)}
                      </span>
                    </div>
                    {entry.install_guidance ? (
                      <p className="text-[11px] leading-4 text-neutral-400">
                        {entry.install_guidance}
                      </p>
                    ) : null}
                  </div>
                );
              })}
            </div>
          </div>

          <div>
            <p className="mb-3 text-[11px] font-semibold uppercase tracking-[0.16em] text-neutral-400">
              Last voice activity
            </p>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              <div className="rounded-2xl border border-neutral-100 bg-neutral-50 p-3">
                <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-neutral-400">
                  Last wake event
                </p>
                <p className="mt-1 text-sm font-bold text-neutral-950">
                  {formatDate(settings.last_wake_event_at)}
                </p>
              </div>
              <div className="rounded-2xl border border-neutral-100 bg-neutral-50 p-3">
                <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-neutral-400">
                  Recognized speaker
                </p>
                <p className="mt-1 truncate text-sm font-bold text-neutral-950">
                  {fieldValue(
                    settings.last_speaker_display_name ||
                      settings.last_recognized_speaker_profile_id,
                  )}
                </p>
              </div>
              <div className="rounded-2xl border border-neutral-100 bg-neutral-50 p-3">
                <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-neutral-400">
                  Detected language
                </p>
                <p className="mt-1 text-sm font-bold text-neutral-950">
                  {fieldValue(settings.last_detected_language)}
                </p>
              </div>
              <div className="rounded-2xl border border-neutral-100 bg-neutral-50 p-3 sm:col-span-2 lg:col-span-3">
                <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-neutral-400">
                  Last command transcript
                </p>
                <p className="mt-1 text-sm font-medium leading-5 text-neutral-950">
                  {fieldValue(settings.last_command_transcript)}
                </p>
              </div>
              <div className="rounded-2xl border border-neutral-100 bg-neutral-50 p-3 sm:col-span-2 lg:col-span-3">
                <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-neutral-400">
                  Last command timing (ms, worker-measured)
                </p>
                {settings.last_command_timing ? (
                  <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1 text-sm font-bold text-neutral-950">
                    {Object.entries(settings.last_command_timing).map(
                      ([key, value]) => (
                        <span key={key}>
                          {key.replace(/_ms$/, "")}:{" "}
                          <span className="font-black text-[#ff5a3d]">
                            {value}
                          </span>
                        </span>
                      ),
                    )}
                  </div>
                ) : (
                  <p className="mt-1 text-sm font-bold text-neutral-400">
                    No timing reported yet.
                  </p>
                )}
              </div>
              <div className="rounded-2xl border border-neutral-100 bg-neutral-50 p-3">
                <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-neutral-400">
                  Routed agent
                </p>
                <p className="mt-1 text-sm font-bold text-neutral-950">
                  {fieldValue(settings.last_routed_agent)}
                </p>
              </div>
              <div className="rounded-2xl border border-neutral-100 bg-neutral-50 p-3 sm:col-span-2">
                <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-neutral-400">
                  Last response
                </p>
                <p className="mt-1 text-sm font-medium leading-5 text-neutral-950">
                  {fieldValue(settings.last_response_text)}
                </p>
              </div>
            </div>
          </div>

          <div className="border-t border-neutral-100 pt-5">
            <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <p className="flex items-center gap-2 text-sm font-black text-neutral-950">
                  <Users className="h-4 w-4 text-[#ff5a3d]" />
                  Trusted Voice Profiles
                </p>
                <p className="mt-1 max-w-xl text-xs leading-5 text-neutral-400">
                  Owner and trusted friend/family/team-member voices William can
                  verify for sensitive commands. Defense-in-depth alongside
                  Security Agent, never a replacement for it.
                </p>
              </div>
              <span
                className={`inline-flex w-fit items-center gap-1.5 rounded-full border px-3 py-1 text-[10px] font-black ${
                  status?.speaker_recognition_status.status === "configured"
                    ? "border-emerald-200 bg-emerald-50 text-emerald-700"
                    : "border-orange-400/25 bg-orange-500/10 text-[#ff5a3d]"
                }`}
              >
                {status?.speaker_recognition_status.status === "configured"
                  ? "Verification: Configured"
                  : "Verification: Missing"}
              </span>
            </div>

            {status?.speaker_recognition_status.status !== "configured" ? (
              <div className="mb-4 rounded-2xl border border-orange-400/25 bg-orange-500/10 px-4 py-3 text-xs font-bold leading-5 text-[#ff5a3d]">
                Speaker recognition is not configured. Normal commands still
                work, but sensitive voice actions require dashboard approval.
              </div>
            ) : null}

            <div className="mb-4 rounded-2xl border border-neutral-100 bg-neutral-50 px-4 py-3 text-[11px] leading-5 text-neutral-400">
              Voice samples are processed locally. Raw audio is not stored by
              default.
            </div>

            {canConfigureVoice ? (
              <div className="mb-4 flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={() => void handleEnrollOwnerVoice()}
                  disabled={enrollingOwner}
                  className="inline-flex items-center gap-2 rounded-2xl bg-[#ff5a3d] px-4 py-2 text-xs font-black text-white shadow-lg shadow-[#ff5a3d]/20 transition hover:bg-neutral-950 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  <Mic className="h-3.5 w-3.5" />
                  {enrollingOwner ? "Creating..." : "Enroll Owner Voice"}
                </button>
                <button
                  type="button"
                  onClick={() => setShowAddTrustedVoiceForm((current) => !current)}
                  className="inline-flex items-center gap-2 rounded-2xl border border-neutral-100 bg-white px-4 py-2 text-xs font-bold text-neutral-600 transition hover:border-orange-500/30 hover:bg-orange-500/10 hover:text-[#ff5a3d]"
                >
                  <UserPlus className="h-3.5 w-3.5" />
                  Add Trusted Voice
                </button>
                <button
                  type="button"
                  onClick={() => void loadVoiceProfiles()}
                  className="inline-flex items-center gap-2 rounded-2xl border border-neutral-100 bg-neutral-50 px-3 py-2 text-xs font-bold text-neutral-600 transition hover:border-orange-500/30 hover:bg-orange-500/10 hover:text-[#ff5a3d]"
                >
                  <RefreshCcw className="h-3.5 w-3.5" />
                  Refresh Profiles
                </button>
              </div>
            ) : null}

            {showAddTrustedVoiceForm ? (
              <div className="mb-4 flex flex-col gap-3 rounded-2xl border border-neutral-100 bg-neutral-50 p-4 sm:flex-row sm:items-end">
                <div className="flex-1">
                  <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-[0.14em] text-neutral-400">
                    Display name
                  </p>
                  <input
                    type="text"
                    value={newProfileName}
                    onChange={(event) => setNewProfileName(event.target.value)}
                    placeholder="e.g. Sarah"
                    maxLength={160}
                    className="w-full rounded-2xl border border-neutral-100 bg-white px-4 py-2.5 text-sm font-semibold text-neutral-700 outline-none transition placeholder:text-neutral-400 focus:border-orange-500/40 focus:ring-4 focus:ring-orange-500/10"
                  />
                </div>
                <div>
                  <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-[0.14em] text-neutral-400">
                    Profile type
                  </p>
                  <select
                    value={newProfileRole}
                    onChange={(event) =>
                      setNewProfileRole(event.target.value as VoiceProfileRole)
                    }
                    className="w-full rounded-2xl border border-neutral-100 bg-white px-4 py-2.5 text-sm font-semibold text-neutral-700 outline-none transition focus:border-orange-500/40 focus:ring-4 focus:ring-orange-500/10 sm:w-44"
                  >
                    {TRUSTED_VOICE_ROLE_OPTIONS.map((option) => (
                      <option key={option.value} value={option.value}>
                        {option.label}
                      </option>
                    ))}
                  </select>
                </div>
                <button
                  type="button"
                  onClick={() => void handleAddTrustedVoice()}
                  disabled={addingProfile || !newProfileName.trim()}
                  className="inline-flex items-center justify-center gap-2 rounded-2xl bg-[#ff5a3d] px-4 py-2.5 text-sm font-black text-white shadow-lg shadow-[#ff5a3d]/20 transition hover:bg-neutral-950 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {addingProfile ? "Adding..." : "Add"}
                </button>
              </div>
            ) : null}

            {enrollCliCommand ? (
              <div className="mb-4 flex flex-col gap-2 rounded-2xl border border-neutral-100 bg-neutral-950 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
                <code className="break-all text-[11px] font-semibold text-neutral-100">
                  {enrollCliCommand}
                </code>
                <button
                  type="button"
                  onClick={() => void copyCommand("enroll-voice", enrollCliCommand)}
                  className="inline-flex shrink-0 items-center gap-1.5 rounded-xl border border-white/10 bg-white/5 px-3 py-1.5 text-[10px] font-black text-white transition hover:bg-white/10"
                >
                  {copiedCommand === "enroll-voice" ? (
                    <Check className="h-3 w-3" />
                  ) : (
                    <Copy className="h-3 w-3" />
                  )}
                  {copiedCommand === "enroll-voice" ? "Copied" : "Copy"}
                </button>
              </div>
            ) : null}

            {profilesLoading ? (
              <p className="text-xs font-semibold text-neutral-400">
                Loading voice profiles...
              </p>
            ) : profilesError ? (
              <p className="text-xs font-bold text-red-600">{profilesError}</p>
            ) : voiceProfiles.length === 0 ? (
              <p className="text-xs font-semibold text-neutral-400">
                No trusted voice profiles enrolled yet.
              </p>
            ) : (
              <div className="overflow-x-auto rounded-2xl border border-neutral-100">
                <table className="w-full min-w-[560px] text-left text-xs">
                  <thead className="bg-neutral-50 text-[10px] font-semibold uppercase tracking-[0.12em] text-neutral-400">
                    <tr>
                      <th className="px-4 py-2.5">Name</th>
                      <th className="px-4 py-2.5">Type</th>
                      <th className="px-4 py-2.5">Status</th>
                      <th className="px-4 py-2.5">Last verified</th>
                      {canConfigureVoice ? (
                        <th className="px-4 py-2.5 text-right">Action</th>
                      ) : null}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-neutral-100">
                    {voiceProfiles.map((profile) => (
                      <tr key={profile.id}>
                        <td className="px-4 py-3 font-bold text-neutral-950">
                          {profile.display_name}
                          {!profile.has_voice_embedding ? (
                            <span className="ml-2 rounded-full border border-orange-400/25 bg-orange-500/10 px-2 py-0.5 text-[9px] font-black text-[#ff5a3d]">
                              No embedding
                            </span>
                          ) : null}
                        </td>
                        <td className="px-4 py-3 text-neutral-600">
                          {profileTypeLabel(profile.role)}
                        </td>
                        <td className="px-4 py-3">
                          <span
                            className={`rounded-full border px-2.5 py-1 text-[10px] font-black ${
                              profile.status === "active"
                                ? "border-emerald-200 bg-emerald-50 text-emerald-700"
                                : "border-neutral-200 bg-neutral-50 text-neutral-500"
                            }`}
                          >
                            {profile.status}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-neutral-600">
                          {fieldValue(profile.last_verified_at)}
                        </td>
                        {canConfigureVoice ? (
                          <td className="px-4 py-3 text-right">
                            {profile.status === "active" ? (
                              <button
                                type="button"
                                onClick={() => void handleRevokeProfile(profile.id)}
                                disabled={revokingProfileId === profile.id}
                                className="inline-flex items-center gap-1.5 rounded-xl border border-red-200 bg-red-50 px-3 py-1.5 text-[10px] font-black text-red-700 transition hover:bg-red-100 disabled:cursor-not-allowed disabled:opacity-60"
                              >
                                <Trash2 className="h-3 w-3" />
                                {revokingProfileId === profile.id
                                  ? "Revoking..."
                                  : "Revoke"}
                              </button>
                            ) : (
                              <span className="text-neutral-300">—</span>
                            )}
                          </td>
                        ) : null}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      ) : null}
    </section>
  );
}
