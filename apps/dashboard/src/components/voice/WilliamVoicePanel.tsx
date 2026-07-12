"use client";

/**
 * apps/dashboard/src/components/voice/WilliamVoicePanel.tsx
 *
 * "William Voice" panel for the real AI console (dashboard/page.tsx). Talks
 * to the real /voice/push-to-talk/text endpoint via voiceApi -- this is the
 * one Phase 9 endpoint designed for an already-authenticated dashboard user
 * (no separate speaker_profile_id needed). There is no real browser
 * microphone/audio pipeline in this codebase yet, so this is primarily a
 * text input styled as push-to-talk; the browser's native SpeechRecognition
 * Web Speech API is wired as a progressive enhancement only -- if it is
 * unavailable, the mic button stays disabled and the panel degrades to
 * text-only, never fabricating a transcript.
 */

import { useEffect, useMemo, useRef, useState } from "react";
import { Mic, MicOff, RotateCcw, Volume2, VolumeX } from "lucide-react";
import {
  voiceApi,
  type VoiceCommandResponseData,
  type VoiceMode,
  type VoiceSpeechOutputStatus,
} from "@/lib/api-client";

type PanelState = "idle" | "checking_status" | "sending" | "error";

type SpeechRecognitionLike = {
  lang: string;
  interimResults: boolean;
  continuous: boolean;
  onresult: ((event: unknown) => void) | null;
  onerror: (() => void) | null;
  onend: (() => void) | null;
  start: () => void;
  stop: () => void;
};

function getSpeechRecognitionCtor():
  | (new () => SpeechRecognitionLike)
  | null {
  if (typeof window === "undefined") return null;
  const w = window as unknown as Record<string, unknown>;
  const ctor = w.SpeechRecognition || w.webkitSpeechRecognition;
  return (ctor as new () => SpeechRecognitionLike) || null;
}

function extractTranscriptFromEvent(event: unknown): string | null {
  try {
    const withResults = event as {
      results?: ArrayLike<{ 0: { transcript?: string } }>;
    };
    const first = withResults.results?.[0]?.[0]?.transcript;
    return typeof first === "string" ? first : null;
  } catch {
    return null;
  }
}

function modeStyle(mode: VoiceMode): string {
  if (mode === "disabled") return "bg-red-50 text-red-700";
  if (mode === "push_to_talk") return "bg-blue-50 text-blue-700";
  return "bg-emerald-50 text-emerald-700";
}

export function WilliamVoicePanel() {
  const [voiceMode, setVoiceMode] = useState<VoiceMode | null>(null);
  const [panelState, setPanelState] = useState<PanelState>("checking_status");
  const [statusError, setStatusError] = useState("");
  const [transcript, setTranscript] = useState("");
  const [detectedLanguageInput, setDetectedLanguageInput] = useState("en");
  const [sessionId, setSessionId] = useState<string | undefined>(undefined);
  const [lastTranscript, setLastTranscript] = useState("");
  const [detectedLanguage, setDetectedLanguage] = useState("");
  const [replyLanguage, setReplyLanguage] = useState("");
  const [responseText, setResponseText] = useState("");
  const [speechOutputStatus, setSpeechOutputStatus] =
    useState<VoiceSpeechOutputStatus | null>(null);
  const [speakResponse, setSpeakResponse] = useState(false);
  const [sendError, setSendError] = useState("");
  const [isListening, setIsListening] = useState(false);
  const recognitionRef = useRef<SpeechRecognitionLike | null>(null);

  const speechRecognitionAvailable = useMemo(
    () => getSpeechRecognitionCtor() !== null,
    [],
  );

  useEffect(() => {
    let cancelled = false;

    async function loadStatus() {
      const response = await voiceApi.status();
      if (cancelled) return;

      if (response.success === false) {
        setStatusError(response.error.message || "Could not load voice status.");
        setPanelState("error");
        return;
      }

      setVoiceMode(response.data.settings.mode);
      setPanelState("idle");
    }

    void loadStatus();
    return () => {
      cancelled = true;
    };
  }, []);

  function handleSpeechToggle() {
    const Ctor = getSpeechRecognitionCtor();
    if (!Ctor) return;

    if (isListening) {
      recognitionRef.current?.stop();
      setIsListening(false);
      return;
    }

    const recognition = new Ctor();
    recognition.lang = "en-US";
    recognition.interimResults = false;
    recognition.continuous = false;

    recognition.onresult = (event: unknown) => {
      const text = extractTranscriptFromEvent(event);
      if (text) setTranscript(text);
    };
    recognition.onerror = () => setIsListening(false);
    recognition.onend = () => setIsListening(false);

    recognitionRef.current = recognition;
    recognition.start();
    setIsListening(true);
  }

  async function handleSend() {
    const trimmed = transcript.trim();
    if (!trimmed || panelState === "sending") return;

    setPanelState("sending");
    setSendError("");

    // The backend never echoes back the session_id it used, so continuity
    // across turns has to come from us: generate one client-side on the
    // first send and reuse it until "Clear session" is pressed.
    const activeSessionId =
      sessionId ||
      (typeof crypto !== "undefined" && "randomUUID" in crypto
        ? crypto.randomUUID()
        : `session_${Date.now()}_${Math.random().toString(16).slice(2)}`);

    if (!sessionId) setSessionId(activeSessionId);

    const response = await voiceApi.sendPushToTalkText({
      transcript: trimmed,
      detected_language: detectedLanguageInput.trim() || undefined,
      session_id: activeSessionId,
    });

    if (response.success === false) {
      setSendError(response.error.message || "William could not process this command.");
      setPanelState("idle");
      return;
    }

    const data: VoiceCommandResponseData = response.data;

    setLastTranscript(trimmed);
    setDetectedLanguage(detectedLanguageInput.trim() || "en");
    setReplyLanguage(data.reply_language || "");
    setResponseText(data.response_text || "");
    setSpeechOutputStatus(data.speech_output_status);
    setTranscript("");
    setPanelState("idle");
  }

  function handleClearSession() {
    setSessionId(undefined);
    setTranscript("");
    setLastTranscript("");
    setDetectedLanguage("");
    setReplyLanguage("");
    setResponseText("");
    setSpeechOutputStatus(null);
    setSendError("");
  }

  const canSpeakResponse = speechOutputStatus === "available";

  return (
    <div className="rounded-[1.6rem] bg-white p-5 shadow-sm">
      <div className="mb-5 flex items-center justify-between">
        <div>
          <p className="text-base font-black text-neutral-950">
            William Voice
          </p>
          <p className="text-xs font-medium text-neutral-500">
            Push-to-talk console for the real Phase 9 voice backend.
          </p>
        </div>

        {voiceMode ? (
          <span
            className={[
              "rounded-full px-3 py-1 text-[11px] font-black capitalize",
              modeStyle(voiceMode),
            ].join(" ")}
          >
            {voiceMode.replace(/_/g, " ")}
          </span>
        ) : panelState === "checking_status" ? (
          <span className="rounded-full bg-neutral-100 px-3 py-1 text-[11px] font-black text-neutral-500">
            Checking...
          </span>
        ) : null}
      </div>

      {panelState === "error" && !voiceMode ? (
        <div className="rounded-2xl border border-red-100 bg-red-50 px-4 py-3 text-sm font-bold text-red-700">
          {statusError}
        </div>
      ) : (
        <>
          {voiceMode === "disabled" ? (
            <div className="mb-4 rounded-2xl border border-red-100 bg-red-50 px-4 py-3 text-xs font-bold text-red-700">
              Voice mode is disabled for this workspace. Push-to-talk still
              works through your own signed-in identity, but wake-word
              listening is off.
            </div>
          ) : null}

          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <textarea
                value={transcript}
                disabled={panelState === "sending"}
                onChange={(event) => setTranscript(event.target.value)}
                placeholder="Type what you'd say to William (push-to-talk text input)..."
                className="min-h-20 w-full resize-none rounded-2xl border border-neutral-200 bg-neutral-50 p-4 text-sm font-semibold outline-none transition placeholder:text-neutral-400 focus:border-[#ff5a3d] focus:bg-white focus:ring-4 focus:ring-[#ff5a3d]/10 disabled:cursor-not-allowed disabled:opacity-60"
              />
            </div>

            <label className="flex items-center gap-2 text-xs font-bold text-neutral-500">
              Detected language
              <input
                type="text"
                value={detectedLanguageInput}
                disabled={panelState === "sending"}
                onChange={(event) => setDetectedLanguageInput(event.target.value)}
                maxLength={8}
                className="w-16 rounded-xl border border-neutral-200 bg-neutral-50 px-2 py-1 text-center text-xs font-black text-neutral-800 outline-none focus:border-[#ff5a3d] focus:ring-4 focus:ring-[#ff5a3d]/10 disabled:cursor-not-allowed disabled:opacity-60"
              />
            </label>

            {sendError ? (
              <div className="rounded-2xl bg-red-50 px-4 py-3 text-xs font-bold text-red-700">
                {sendError}
              </div>
            ) : null}

            <div className="flex flex-wrap items-center gap-3">
              <button
                type="button"
                title={
                  speechRecognitionAvailable
                    ? "Speak your command (browser SpeechRecognition)"
                    : "Microphone input is not available in this browser -- text-only push-to-talk"
                }
                disabled={!speechRecognitionAvailable}
                onClick={handleSpeechToggle}
                className={[
                  "flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl transition disabled:cursor-not-allowed disabled:opacity-40",
                  isListening
                    ? "bg-red-600 text-white"
                    : "bg-neutral-950 text-white hover:bg-[#ff5a3d]",
                ].join(" ")}
                aria-label="Push to talk"
              >
                {isListening ? (
                  <MicOff className="h-5 w-5" />
                ) : (
                  <Mic className="h-5 w-5" />
                )}
              </button>

              <button
                type="button"
                disabled={!transcript.trim() || panelState === "sending"}
                onClick={() => void handleSend()}
                className="flex-1 rounded-2xl bg-neutral-950 px-5 py-3.5 text-sm font-black text-white shadow-lg shadow-black/10 transition hover:bg-[#ff5a3d] disabled:cursor-not-allowed disabled:opacity-50"
              >
                {panelState === "sending" ? "Sending..." : "Push to Talk →"}
              </button>

              <button
                type="button"
                onClick={handleClearSession}
                className="flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl border border-neutral-200 bg-white text-neutral-500 transition hover:border-[#ff5a3d] hover:text-[#ff5a3d]"
                aria-label="Clear session"
                title="Clear session"
              >
                <RotateCcw className="h-4 w-4" />
              </button>

              <button
                type="button"
                disabled={!canSpeakResponse}
                onClick={() => setSpeakResponse((current) => !current)}
                title={
                  canSpeakResponse
                    ? "Toggle spoken response"
                    : "Speaking responses requires a configured TTS provider (currently unavailable)"
                }
                className={[
                  "flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl border transition disabled:cursor-not-allowed disabled:opacity-40",
                  speakResponse && canSpeakResponse
                    ? "border-emerald-200 bg-emerald-50 text-emerald-700"
                    : "border-neutral-200 bg-white text-neutral-400",
                ].join(" ")}
                aria-label="Speak response"
              >
                {speakResponse && canSpeakResponse ? (
                  <Volume2 className="h-4 w-4" />
                ) : (
                  <VolumeX className="h-4 w-4" />
                )}
              </button>
            </div>

            {!speechRecognitionAvailable ? (
              <p className="text-[11px] font-medium text-neutral-400">
                Browser microphone input is not available -- push-to-talk is
                text-only in this session.
              </p>
            ) : null}
          </div>

          <div className="mt-5 grid gap-3 sm:grid-cols-3">
            <div className="rounded-2xl bg-neutral-50 p-3 sm:col-span-1">
              <p className="text-[10px] font-black uppercase tracking-[0.14em] text-neutral-400">
                Last transcript
              </p>
              <p className="mt-1 text-sm font-bold text-neutral-800">
                {lastTranscript || "—"}
              </p>
            </div>
            <div className="rounded-2xl bg-neutral-50 p-3">
              <p className="text-[10px] font-black uppercase tracking-[0.14em] text-neutral-400">
                Detected language
              </p>
              <p className="mt-1 text-sm font-bold text-neutral-800">
                {detectedLanguage || "—"}
              </p>
            </div>
            <div className="rounded-2xl bg-neutral-50 p-3">
              <p className="text-[10px] font-black uppercase tracking-[0.14em] text-neutral-400">
                Reply language
              </p>
              <p className="mt-1 text-sm font-bold text-neutral-800">
                {replyLanguage || "—"}
              </p>
            </div>
          </div>

          <div className="mt-3 rounded-2xl bg-neutral-50 p-4">
            <div className="mb-2 flex items-center justify-between">
              <p className="text-[10px] font-black uppercase tracking-[0.14em] text-neutral-400">
                William&apos;s response
              </p>
              {speechOutputStatus ? (
                <span
                  className={[
                    "rounded-full px-2.5 py-1 text-[10px] font-black",
                    speechOutputStatus === "available"
                      ? "bg-emerald-50 text-emerald-700"
                      : "bg-orange-50 text-orange-700",
                  ].join(" ")}
                >
                  {speechOutputStatus === "available"
                    ? "Speech output available"
                    : "Speech output needs setup"}
                </span>
              ) : null}
            </div>
            <p className="text-sm font-medium leading-6 text-neutral-800">
              {responseText || "No response yet. Send a command to William."}
            </p>
          </div>
        </>
      )}
    </div>
  );
}
