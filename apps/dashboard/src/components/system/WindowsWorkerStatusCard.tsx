"use client";

/**
 * apps/dashboard/src/components/system/WindowsWorkerStatusCard.tsx
 *
 * Real Windows Worker presence card -- reads GET /system/worker/status
 * (systemWorkerApi.status()) and shows exactly what the backend actually
 * knows: connected/offline, device name, last heartbeat, supported
 * actions, last command/result. Never fabricates a "connected" state --
 * an errored fetch or a worker that has never checked in both render as
 * Offline, and the exact command to start the real worker is always
 * shown so the user can act on it immediately.
 */

import { useEffect, useState } from "react";
import { Check, Copy, Laptop, WifiOff } from "lucide-react";
import { systemWorkerApi, type SystemWorkerStatusData } from "@/lib/api-client";

const RUN_COMMAND = [
  "python -m apps.worker_nodes.windows.windows_worker \\",
  '  --token $token \\',
  "  --api-base-url http://localhost:8001/api/v1 \\",
  '  --device-name "Roshan Windows Laptop"',
].join("\n");

function timeAgo(iso: string | null): string {
  if (!iso) return "Never";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "Unknown";
  const seconds = Math.max(0, Math.floor((Date.now() - then) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ago`;
}

type Props = {
  /** "full" shows the whole card (settings/admin); "compact" is a smaller widget (dashboard home, /agents card). */
  variant?: "full" | "compact";
};

export function WindowsWorkerStatusCard({ variant = "full" }: Props) {
  const [status, setStatus] = useState<SystemWorkerStatusData | null>(null);
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      const result = await systemWorkerApi.status();
      if (cancelled) return;
      if (result.success && result.data) {
        setStatus(result.data);
      }
      setLoading(false);
    }

    void load();
    const interval = setInterval(load, 15000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  const connected = status?.worker_connected ?? false;

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(RUN_COMMAND);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard access denied/unavailable -- the command is still
      // visible and selectable, so this is a non-fatal degradation.
    }
  };

  return (
    <div className="rounded-[1.6rem] bg-white p-5 shadow-sm">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span
            className={`flex h-9 w-9 items-center justify-center rounded-xl ${
              connected ? "bg-emerald-50 text-emerald-600" : "bg-neutral-100 text-neutral-400"
            }`}
          >
            {connected ? <Laptop size={18} /> : <WifiOff size={18} />}
          </span>
          <div>
            <p className="text-sm font-black text-neutral-900">Windows Worker</p>
            <p className="text-xs font-bold text-neutral-500">
              {loading ? "Checking..." : status?.device_name || "No device registered"}
            </p>
          </div>
        </div>
        <span
          className={`rounded-full px-3 py-1 text-xs font-black ${
            connected ? "bg-emerald-50 text-emerald-700" : "bg-neutral-100 text-neutral-600"
          }`}
        >
          {connected ? "Connected" : "Offline"}
        </span>
      </div>

      {variant === "full" && (
        <>
          <div className="mt-4 grid grid-cols-2 gap-3">
            <div className="rounded-2xl bg-neutral-50 p-3">
              <p className="text-[10px] font-black uppercase tracking-wide text-neutral-400">
                Last Heartbeat
              </p>
              <p className="mt-1 text-sm font-bold text-neutral-900">
                {timeAgo(status?.worker_last_seen_at ?? null)}
              </p>
            </div>
            <div className="rounded-2xl bg-neutral-50 p-3">
              <p className="text-[10px] font-black uppercase tracking-wide text-neutral-400">
                Platform
              </p>
              <p className="mt-1 text-sm font-bold text-neutral-900">
                {status?.platform || "--"}
              </p>
            </div>
            <div className="rounded-2xl bg-neutral-50 p-3">
              <p className="text-[10px] font-black uppercase tracking-wide text-neutral-400">
                Last Command
              </p>
              <p className="mt-1 truncate text-sm font-bold text-neutral-900">
                {status?.last_command || "--"}
              </p>
            </div>
            <div className="rounded-2xl bg-neutral-50 p-3">
              <p className="text-[10px] font-black uppercase tracking-wide text-neutral-400">
                Last Result
              </p>
              <p className="mt-1 truncate text-sm font-bold text-neutral-900">
                {status?.last_result || "--"}
              </p>
            </div>
          </div>

          {status?.supported_actions && status.supported_actions.length > 0 && (
            <div className="mt-4">
              <p className="text-[10px] font-black uppercase tracking-wide text-neutral-400">
                Supported Actions
              </p>
              <div className="mt-2 flex flex-wrap gap-1.5">
                {status.supported_actions.map((action) => (
                  <span
                    key={action}
                    className="rounded-full bg-neutral-100 px-2.5 py-1 text-[11px] font-bold text-neutral-600"
                  >
                    {action}
                  </span>
                ))}
              </div>
            </div>
          )}

          {!connected && (
            <div className="mt-4 rounded-2xl bg-neutral-900 p-4">
              <div className="flex items-center justify-between">
                <p className="text-[10px] font-black uppercase tracking-wide text-neutral-400">
                  Run this to connect
                </p>
                <button
                  type="button"
                  onClick={handleCopy}
                  className="flex items-center gap-1 rounded-full bg-white/10 px-2.5 py-1 text-[11px] font-black text-white transition hover:bg-[#ff5a3d]"
                >
                  {copied ? <Check size={12} /> : <Copy size={12} />}
                  {copied ? "Copied" : "Copy"}
                </button>
              </div>
              <pre className="mt-2 overflow-x-auto whitespace-pre text-[11px] font-bold leading-relaxed text-emerald-300">
                {RUN_COMMAND}
              </pre>
            </div>
          )}
        </>
      )}
    </div>
  );
}
