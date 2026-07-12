"use client";

/**
 * apps/dashboard/src/components/voice/VoiceControlSettings.tsx
 *
 * Live-wired "Voice Control" settings section for Phase 9's real voice
 * backend (apps/api/routes/voice.py, mounted at /voice/*). Unlike the rest
 * of settings/page.tsx (still static mock data), this section always talks
 * to the real API through lib/api-client.ts's voiceApi -- no fabricated
 * values. Visually matches this page's own existing dark card language
 * (border-white/10, bg-white/[0.035], orange-500 accents) since that is
 * what already surrounds it on this page.
 */

import { useCallback, useEffect, useState } from "react";
import { Mic, RefreshCcw, ShieldAlert, ShieldCheck } from "lucide-react";
import { readSession, hasMinRole, type SessionData } from "@/lib/auth";
import {
  voiceApi,
  type VoiceDependencyStatus,
  type VoiceDependencyStatusValue,
  type VoiceMode,
  type VoiceSettings,
} from "@/lib/api-client";
import { LoadingState } from "@/components/state/LoadingState";
import { ErrorState } from "@/components/state/ErrorState";

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
];

const DEPENDENCY_LABELS: Record<keyof VoiceDependencyStatus, string> = {
  wake_word_engine: "Wake word engine",
  audio_input_worker: "Audio input worker",
  stt_provider: "Speech-to-text provider",
  tts_provider: "Text-to-speech provider",
  speaker_recognition_provider: "Speaker recognition provider",
};

function dependencyStyle(status: VoiceDependencyStatusValue): string {
  if (status === "available" || status === "configured") {
    return "border-emerald-400/20 bg-emerald-400/10 text-emerald-300";
  }
  return "border-orange-400/25 bg-orange-500/10 text-orange-300";
}

function dependencyLabel(status: VoiceDependencyStatusValue): string {
  if (status === "available") return "Available";
  if (status === "configured") return "Configured";
  return "Needs setup";
}

function modeStyle(mode: VoiceMode): string {
  if (mode === "disabled") return "border-red-400/25 bg-red-500/10 text-red-300";
  if (mode === "push_to_talk")
    return "border-blue-400/20 bg-blue-400/10 text-blue-300";
  return "border-emerald-400/20 bg-emerald-400/10 text-emerald-300";
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

export function VoiceControlSettings() {
  const [session, setSession] = useState<SessionData | null>(null);
  const [state, setState] = useState<LoadState>("loading");
  const [errorMessage, setErrorMessage] = useState("");
  const [settings, setSettings] = useState<VoiceSettings | null>(null);
  const [wakeWordDefault, setWakeWordDefault] = useState("william");
  const [wakeWordInput, setWakeWordInput] = useState("");
  const [savingMode, setSavingMode] = useState<VoiceMode | null>(null);
  const [savingWakeWord, setSavingWakeWord] = useState(false);
  const [notice, setNotice] = useState<{
    type: "success" | "error" | "info";
    message: string;
  } | null>(null);

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
    setWakeWordDefault(response.data.wake_word_default || "william");
    setWakeWordInput(response.data.settings.wake_word || "");
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

  return (
    <section className="rounded-[32px] border border-white/10 bg-white/[0.035] p-5 shadow-[0_30px_100px_rgba(0,0,0,0.32)] md:p-6">
      <div className="mb-6 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <div>
          <p className="text-sm font-bold text-orange-300">Voice Control</p>
          <h2 className="mt-2 text-2xl font-black tracking-tight text-white">
            William Voice Agent (Phase 9)
          </h2>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-zinc-500">
            Live workspace voice mode, wake word, and dependency status --
            wired directly to /voice/status and /voice/config.
          </p>
        </div>

        <button
          type="button"
          onClick={() => void load()}
          className="inline-flex items-center gap-2 rounded-2xl border border-white/10 bg-white/[0.04] px-3 py-2 text-xs font-bold text-zinc-300 transition hover:border-orange-500/30 hover:bg-orange-500/10 hover:text-orange-300"
        >
          <RefreshCcw className="h-3.5 w-3.5" />
          Refresh
        </button>
      </div>

      {state === "loading" ? (
        <LoadingState
          variant="dark"
          title="Loading voice status..."
          subtitle="Calling /voice/status."
        />
      ) : state === "error" ? (
        <ErrorState
          variant="dark"
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
                  ? "border-emerald-400/20 bg-emerald-400/10 text-emerald-300"
                  : notice.type === "error"
                    ? "border-red-400/25 bg-red-500/10 text-red-300"
                    : "border-blue-400/20 bg-blue-400/10 text-blue-300",
              ].join(" ")}
            >
              {notice.message}
            </div>
          ) : null}

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="rounded-2xl border border-white/10 bg-black/25 p-4">
              <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-zinc-500">
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
                <p className="mt-3 flex items-center gap-2 text-xs font-semibold text-orange-300">
                  <ShieldAlert className="h-3.5 w-3.5" />
                  This mode required Security Agent approval to enable.
                </p>
              ) : null}
            </div>

            <div className="rounded-2xl border border-white/10 bg-black/25 p-4">
              <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-zinc-500">
                Voice worker
              </p>
              <p className="mt-2 text-sm font-bold text-white">
                {settings.voice_worker_connected ? "Connected" : "Not connected"}
              </p>
              <p className="mt-1 text-xs text-zinc-500">
                Last seen: {formatDate(settings.voice_worker_last_seen_at)}
              </p>
            </div>
          </div>

          <div>
            <p className="mb-3 text-[11px] font-semibold uppercase tracking-[0.16em] text-zinc-500">
              Mode controls
            </p>

            {!canConfigureVoice ? (
              <div className="mb-3 rounded-2xl border border-orange-400/25 bg-orange-500/10 px-4 py-3 text-xs font-bold text-orange-200">
                Only owner/admin roles can change voice mode. You are viewing
                in read-only mode.
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
                        : "border-white/10 bg-white/[0.03] hover:border-orange-500/25 hover:bg-orange-500/[0.06]",
                    ].join(" ")}
                  >
                    <div className="flex items-center justify-between gap-3">
                      <p className="text-sm font-black text-white">
                        {option.label}
                      </p>
                      {isActive ? (
                        <ShieldCheck className="h-4 w-4 shrink-0 text-emerald-300" />
                      ) : option.requiresApproval ? (
                        <ShieldAlert className="h-4 w-4 shrink-0 text-orange-300" />
                      ) : null}
                    </div>
                    <p className="mt-1 text-xs leading-5 text-zinc-500">
                      {option.description}
                    </p>
                    {option.requiresApproval ? (
                      <p className="mt-2 text-[11px] font-bold text-orange-300">
                        Requires Security Agent approval
                      </p>
                    ) : null}
                    {isBusy ? (
                      <p className="mt-2 text-[11px] font-bold text-zinc-400">
                        Saving...
                      </p>
                    ) : null}
                  </button>
                );
              })}
            </div>
          </div>

          <div className="rounded-2xl border border-white/10 bg-black/25 p-4">
            <p className="mb-2 text-[11px] font-semibold uppercase tracking-[0.16em] text-zinc-500">
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
                className="w-full rounded-2xl border border-white/10 bg-[#07080b] px-4 py-3 text-sm font-semibold text-zinc-200 outline-none transition placeholder:text-zinc-600 focus:border-orange-500/40 focus:ring-4 focus:ring-orange-500/10 disabled:cursor-not-allowed disabled:opacity-50 sm:max-w-xs"
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
          </div>

          <div>
            <p className="mb-3 text-[11px] font-semibold uppercase tracking-[0.16em] text-zinc-500">
              Dependency status
            </p>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {(
                Object.keys(DEPENDENCY_LABELS) as Array<
                  keyof VoiceDependencyStatus
                >
              ).map((key) => (
                <div
                  key={key}
                  className="flex items-center justify-between gap-3 rounded-2xl border border-white/10 bg-black/25 px-4 py-3"
                >
                  <span className="text-xs font-semibold text-zinc-300">
                    {DEPENDENCY_LABELS[key]}
                  </span>
                  <span
                    className={`rounded-full border px-2.5 py-1 text-[10px] font-black ${dependencyStyle(
                      settings.dependency_status[key],
                    )}`}
                  >
                    {dependencyLabel(settings.dependency_status[key])}
                  </span>
                </div>
              ))}
            </div>
          </div>

          <div>
            <p className="mb-3 text-[11px] font-semibold uppercase tracking-[0.16em] text-zinc-500">
              Last voice activity
            </p>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              <div className="rounded-2xl border border-white/10 bg-black/25 p-3">
                <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-500">
                  Last wake event
                </p>
                <p className="mt-1 text-sm font-bold text-white">
                  {formatDate(settings.last_wake_event_at)}
                </p>
              </div>
              <div className="rounded-2xl border border-white/10 bg-black/25 p-3">
                <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-500">
                  Recognized speaker
                </p>
                <p className="mt-1 truncate text-sm font-bold text-white">
                  {fieldValue(settings.last_recognized_speaker_profile_id)}
                </p>
              </div>
              <div className="rounded-2xl border border-white/10 bg-black/25 p-3">
                <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-500">
                  Detected language
                </p>
                <p className="mt-1 text-sm font-bold text-white">
                  {fieldValue(settings.last_detected_language)}
                </p>
              </div>
              <div className="rounded-2xl border border-white/10 bg-black/25 p-3 sm:col-span-2 lg:col-span-3">
                <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-500">
                  Last command transcript
                </p>
                <p className="mt-1 text-sm font-medium leading-5 text-white">
                  {fieldValue(settings.last_command_transcript)}
                </p>
              </div>
              <div className="rounded-2xl border border-white/10 bg-black/25 p-3">
                <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-500">
                  Routed agent
                </p>
                <p className="mt-1 text-sm font-bold text-white">
                  {fieldValue(settings.last_routed_agent)}
                </p>
              </div>
              <div className="rounded-2xl border border-white/10 bg-black/25 p-3 sm:col-span-2">
                <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-500">
                  Last response
                </p>
                <p className="mt-1 text-sm font-medium leading-5 text-white">
                  {fieldValue(settings.last_response_text)}
                </p>
              </div>
            </div>
          </div>
        </div>
      ) : null}
    </section>
  );
}
