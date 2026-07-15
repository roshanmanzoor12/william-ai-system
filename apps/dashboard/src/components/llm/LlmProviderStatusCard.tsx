"use client";

/**
 * apps/dashboard/src/components/llm/LlmProviderStatusCard.tsx
 *
 * Real LLM/knowledge-provider status card -- reads GET /assistant/llm/status
 * (core/llm_provider.py::check_status()). configured=false is never shown
 * as an error state -- it honestly means no WILLIAM_LLM_PROVIDER/BASE_URL/
 * MODEL env var is set for this deployment yet, with install_guidance
 * naming exactly what to set (OpenAI, or a local Ollama/LM Studio server).
 * There is no "Enable" button here: unlike Voice/Windows Worker, this is a
 * server-side .env setting, not a local device the dashboard can install --
 * so this card is read-only plus a manual refresh.
 */

import { useEffect, useState } from "react";
import { Brain, CheckCircle2, RefreshCw } from "lucide-react";
import { llmApi, type LlmProviderStatus } from "@/lib/api-client";

type Props = {
  variant?: "full" | "compact";
};

export function LlmProviderStatusCard({ variant = "full" }: Props) {
  const [status, setStatus] = useState<LlmProviderStatus | null>(null);
  const [loading, setLoading] = useState(true);

  async function load() {
    setLoading(true);
    const result = await llmApi.getStatus();
    if (result.success && result.data) {
      setStatus(result.data.llm_provider);
    }
    setLoading(false);
  }

  useEffect(() => {
    void load();
  }, []);

  const configured = status?.configured ?? false;

  return (
    <div className="rounded-[1.6rem] bg-white p-5 shadow-sm">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span
            className={`flex h-9 w-9 items-center justify-center rounded-xl ${
              configured
                ? "bg-emerald-50 text-emerald-600"
                : "bg-neutral-100 text-neutral-400"
            }`}
          >
            {configured ? <CheckCircle2 size={18} /> : <Brain size={18} />}
          </span>
          <div>
            <p className="text-sm font-black text-neutral-900">LLM Provider</p>
            <p className="text-xs font-bold text-neutral-500">
              {loading
                ? "Checking..."
                : configured
                  ? "Configured"
                  : "Not configured"}
            </p>
          </div>
        </div>
        <span
          className={`rounded-full px-3 py-1 text-xs font-black ${
            configured
              ? "bg-emerald-50 text-emerald-700"
              : "bg-amber-50 text-amber-800"
          }`}
        >
          {configured ? "Ready" : "Not Configured"}
        </span>
      </div>

      {variant === "full" && (
        <>
          <p className="mt-4 text-xs font-medium leading-6 text-neutral-500">
            William answers general knowledge questions through an
            OpenAI-compatible /chat/completions endpoint -- real OpenAI, or a
            local Ollama/LM Studio server. Live/current data (weather, news,
            stock prices) is never answered from the LLM, configured or not.
          </p>

          {!configured && status?.reason && (
            <p className="mt-3 rounded-2xl bg-amber-50 px-4 py-3 text-xs font-bold text-amber-800">
              {status.reason}
            </p>
          )}

          {status?.install_guidance && (
            <p className="mt-3 rounded-2xl bg-neutral-50 px-4 py-3 text-xs font-bold text-neutral-600">
              {status.install_guidance}
            </p>
          )}

          <div className="mt-4 rounded-2xl bg-neutral-50 p-4">
            <p className="text-[10px] font-black uppercase tracking-wide text-neutral-400">
              Set in your .env (see .env.example)
            </p>
            <pre className="mt-2 overflow-x-auto whitespace-pre text-[11px] font-bold leading-relaxed text-neutral-600">
              {
                "WILLIAM_LLM_PROVIDER=openai\nWILLIAM_LLM_BASE_URL=https://api.openai.com/v1\nWILLIAM_LLM_API_KEY=sk-...\nWILLIAM_LLM_MODEL=gpt-4o-mini"
              }
            </pre>
          </div>

          <div className="mt-4 flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => void load()}
              className="flex items-center gap-1.5 rounded-full border border-neutral-200 px-4 py-2 text-xs font-black text-neutral-600 transition hover:border-[#ff5a3d] hover:text-[#ff5a3d]"
            >
              <RefreshCw size={12} />
              Refresh Status
            </button>
          </div>
        </>
      )}
    </div>
  );
}
