"use client";

/**
 * apps/dashboard/src/app/(dashboard)/assistant/page.tsx
 *
 * Phase 1 -- Conversational Assistant Brain. Talks to
 * apps/api/routes/assistant.py's POST /assistant/message. Every William
 * reply shows `final_answer` as the primary bubble text -- never raw JSON.
 * `follow_up_questions` render as quick-reply chips when William is waiting
 * for a detail; the full response envelope is only ever available behind a
 * collapsed "Export JSON" toggle per message.
 */

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { Download, FileText } from "lucide-react";
import { readSession, type SessionData } from "@/lib/auth";
import {
  assistantApi,
  API_BASE_URL,
  type AssistantMessageData,
} from "@/lib/api-client";
import { EmptyState } from "@/components/state/EmptyState";
import { ErrorState } from "@/components/state/ErrorState";
import { LoadingState } from "@/components/state/LoadingState";

type ChatMessage = {
  id: string;
  role: "user" | "william";
  text: string;
  followUpQuestions?: string[];
  status?: AssistantMessageData["status"];
  route?: string[];
  generatedFiles?: AssistantMessageData["generated_files"];
  raw?: AssistantMessageData;
};

function newMessageId(): string {
  return `msg_${Date.now()}_${Math.random().toString(16).slice(2)}`;
}

function statusStyle(status?: string): string {
  if (status === "completed") return "bg-emerald-50 text-emerald-700";
  if (status === "waiting_for_user") return "bg-amber-50 text-amber-800";
  if (status === "failed") return "bg-red-50 text-red-700";
  return "bg-neutral-100 text-neutral-600";
}

export default function AssistantPage() {
  const router = useRouter();

  const [session, setSession] = useState<SessionData | null>(null);
  const [checkingSession, setCheckingSession] = useState(true);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [conversationThreadId, setConversationThreadId] = useState<
    string | null
  >(null);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const scrollAnchorRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const activeSession = readSession();
    if (!activeSession) {
      router.replace("/login");
      return;
    }
    setSession(activeSession);
    setCheckingSession(false);
  }, [router]);

  useEffect(() => {
    scrollAnchorRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  async function handleSend(overrideText?: string) {
    const text = (overrideText ?? input).trim();
    if (!text || sending) return;

    setSending(true);
    setError(null);
    setMessages((current) => [
      ...current,
      { id: newMessageId(), role: "user", text },
    ]);
    setInput("");

    const result = await assistantApi.sendMessage({
      message: text,
      conversation_thread_id: conversationThreadId,
    });

    if (result.success === false) {
      setError(result.error.message || "William could not respond just now.");
      setSending(false);
      return;
    }

    const data = result.data;
    setConversationThreadId(data.conversation_thread_id);
    setMessages((current) => [
      ...current,
      {
        id: newMessageId(),
        role: "william",
        text: data.final_answer,
        followUpQuestions: data.follow_up_questions,
        status: data.status,
        route: data.route,
        generatedFiles: data.generated_files,
        raw: data,
      },
    ]);
    setSending(false);
  }

  function handleNewChat() {
    setConversationThreadId(null);
    setMessages([]);
    setError(null);
    setInput("");
  }

  if (checkingSession || !session) {
    return (
      <div className="grid min-h-[420px] place-items-center text-neutral-950">
        <LoadingState
          variant="light"
          title="Loading William..."
          subtitle="Checking your session."
        />
      </div>
    );
  }

  return (
    <div className="flex h-[calc(100vh-8rem)] flex-col text-neutral-950">
      <div className="mb-5 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-3xl font-black tracking-[-0.045em] text-neutral-950 sm:text-4xl">
            Talk to William
          </h1>
          <p className="mt-1 text-sm font-medium text-neutral-500">
            Type naturally — William will ask for anything it&apos;s missing
            before it acts.
          </p>
        </div>
        <button
          type="button"
          onClick={handleNewChat}
          className="self-start rounded-full border border-neutral-200 bg-white px-4 py-2 text-xs font-black text-neutral-600 shadow-sm transition hover:border-[#ff5a3d] hover:text-[#ff5a3d] sm:self-auto"
        >
          + New chat
        </button>
      </div>

      <div className="flex flex-1 flex-col overflow-hidden rounded-[1.75rem] bg-white shadow-sm">
        <div className="flex-1 space-y-4 overflow-y-auto p-5">
          {messages.length === 0 ? (
            <EmptyState
              variant="light"
              icon="💬"
              title="Say hello to William"
              message='Try: "William create a VEO prompt for ClickRonix" — William will ask for the style, duration, main visual, and CTA before generating it.'
            />
          ) : (
            messages.map((message) => (
              <div
                key={message.id}
                className={`flex ${message.role === "user" ? "justify-end" : "justify-start"}`}
              >
                <div
                  className={[
                    "max-w-2xl rounded-[1.5rem] px-5 py-4 text-sm leading-6",
                    message.role === "user"
                      ? "bg-[#ff5a3d] text-white"
                      : "border border-neutral-100 bg-neutral-50 text-neutral-800",
                  ].join(" ")}
                >
                  <p className="whitespace-pre-wrap font-medium">
                    {message.text}
                  </p>

                  {message.role === "william" ? (
                    <div className="mt-3 flex flex-wrap items-center gap-2">
                      {message.status ? (
                        <span
                          className={[
                            "rounded-full px-3 py-1 text-[11px] font-black capitalize",
                            statusStyle(message.status),
                          ].join(" ")}
                        >
                          {message.status.replaceAll("_", " ")}
                        </span>
                      ) : null}
                      {message.route && message.route.length > 0 ? (
                        <span className="rounded-full bg-neutral-100 px-3 py-1 text-[11px] font-black text-neutral-600">
                          via {message.route.join(", ")}
                        </span>
                      ) : null}
                    </div>
                  ) : null}

                  {message.followUpQuestions &&
                  message.followUpQuestions.length > 0 ? (
                    <div className="mt-3 flex flex-wrap gap-2">
                      {message.followUpQuestions.map((question) => (
                        <button
                          key={question}
                          type="button"
                          onClick={() => setInput(question)}
                          className="rounded-full border border-[#ff5a3d]/25 bg-[#fff3ed] px-3 py-1.5 text-[11px] font-bold text-[#ff5a3d] transition hover:bg-[#ff5a3d]/10"
                        >
                          {question}
                        </button>
                      ))}
                    </div>
                  ) : null}

                  {message.generatedFiles &&
                  message.generatedFiles.length > 0 ? (
                    <div className="mt-3 flex flex-col gap-2">
                      {message.generatedFiles.map((file) =>
                        file.download_url ? (
                          <a
                            key={file.file_id ?? file.download_url}
                            href={`${API_BASE_URL}${file.download_url}`}
                            target="_blank"
                            rel="noreferrer"
                            className="flex items-center gap-2 rounded-2xl border border-[#ff5a3d]/25 bg-[#fff3ed] px-4 py-2.5 text-xs font-black text-[#ff5a3d] transition hover:bg-[#ff5a3d]/10"
                          >
                            <FileText size={14} />
                            <span className="flex-1 truncate">
                              {file.filename || "Download file"}
                            </span>
                            <Download size={14} />
                          </a>
                        ) : null,
                      )}
                    </div>
                  ) : null}

                  {message.raw ? (
                    <details className="mt-3">
                      <summary className="cursor-pointer text-[11px] font-black uppercase tracking-[0.14em] text-neutral-400 hover:text-neutral-600">
                        Export JSON
                      </summary>
                      <pre className="mt-2 max-h-64 overflow-auto rounded-xl bg-neutral-950 p-3 text-[11px] text-neutral-100">
                        {JSON.stringify(message.raw, null, 2)}
                      </pre>
                    </details>
                  ) : null}
                </div>
              </div>
            ))
          )}
          {sending ? (
            <div className="flex justify-start">
              <div className="rounded-[1.5rem] border border-neutral-100 bg-neutral-50 px-5 py-4 text-sm font-medium text-neutral-400">
                William is thinking...
              </div>
            </div>
          ) : null}
          <div ref={scrollAnchorRef} />
        </div>

        {error ? (
          <div className="px-5 pb-2">
            <ErrorState
              variant="light"
              title="William couldn't respond"
              message={error}
              onRetry={() => setError(null)}
            />
          </div>
        ) : null}

        <form
          onSubmit={(event) => {
            event.preventDefault();
            void handleSend();
          }}
          className="flex items-center gap-3 border-t border-neutral-100 p-4"
        >
          <input
            type="text"
            value={input}
            onChange={(event) => setInput(event.target.value)}
            placeholder="Ask William anything, or tell it what to do..."
            disabled={sending}
            className="h-12 flex-1 rounded-full border border-neutral-200 bg-neutral-50 px-5 text-sm font-semibold outline-none transition placeholder:text-neutral-400 focus:border-[#ff5a3d] focus:bg-white focus:ring-4 focus:ring-[#ff5a3d]/10 disabled:cursor-not-allowed disabled:opacity-60"
          />
          <button
            type="submit"
            disabled={sending || !input.trim()}
            className="h-12 rounded-full bg-[#ff5a3d] px-6 text-sm font-black text-white shadow-lg shadow-[#ff5a3d]/20 transition hover:bg-neutral-950 disabled:cursor-not-allowed disabled:opacity-50"
          >
            Send
          </button>
        </form>
      </div>
    </div>
  );
}
