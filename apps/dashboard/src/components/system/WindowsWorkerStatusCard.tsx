"use client";

/**
 * apps/dashboard/src/components/system/WindowsWorkerStatusCard.tsx
 *
 * Real Windows Worker device-connector card -- reads GET /system/worker/status
 * (systemWorkerApi.status()) and shows exactly what the backend actually
 * knows: connection_state (Needs Setup / Connected / Offline / Disabled),
 * device name, last heartbeat, supported actions, last command/result.
 *
 * "Enable Windows Worker" never pretends a browser click starts a local
 * process -- it calls POST /system/device/setup-token and shows the real,
 * server-generated one-time setup command for the user to run themselves.
 * Only that local run (scripts/windows/install_windows_worker.ps1) can ever
 * flip the state to Connected; this card just reflects reality, polling
 * every 15s, and never fabricates a connected state.
 */

import { useEffect, useState } from "react";
import { Check, Copy, Download, Laptop, PowerOff, RefreshCw, WifiOff } from "lucide-react";
import { API_BASE_URL, deviceSetupApi, systemWorkerApi, type DeviceSetupTokenData, type SystemWorkerStatusData } from "@/lib/api-client";

const DEV_RUN_COMMAND = [
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

function countdown(expiresAtIso: string | null): string {
  if (!expiresAtIso) return "";
  const remainingMs = new Date(expiresAtIso).getTime() - Date.now();
  if (remainingMs <= 0) return "Expired";
  const minutes = Math.floor(remainingMs / 60000);
  const seconds = Math.floor((remainingMs % 60000) / 1000);
  return `Expires in ${minutes}:${String(seconds).padStart(2, "0")}`;
}

const STATE_LABELS: Record<string, string> = {
  needs_setup: "Needs Setup",
  disabled: "Disabled",
  connected: "Connected",
  offline: "Offline",
};

const STATE_STYLES: Record<string, string> = {
  needs_setup: "bg-amber-50 text-amber-700",
  disabled: "bg-neutral-100 text-neutral-500",
  connected: "bg-emerald-50 text-emerald-700",
  offline: "bg-orange-50 text-orange-700",
};

type Props = {
  /** "full" shows the whole card (settings/admin); "compact" is a smaller widget (dashboard home, /agents card). */
  variant?: "full" | "compact";
};

export function WindowsWorkerStatusCard({ variant = "full" }: Props) {
  const [status, setStatus] = useState<SystemWorkerStatusData | null>(null);
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState<"setup" | "dev" | null>(null);
  const [setupData, setSetupData] = useState<DeviceSetupTokenData | null>(null);
  const [enabling, setEnabling] = useState(false);
  const [disabling, setDisabling] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [, setTick] = useState(0);

  async function load() {
    const result = await systemWorkerApi.status();
    if (result.success && result.data) {
      setStatus(result.data);
    }
    setLoading(false);
  }

  useEffect(() => {
    let cancelled = false;

    async function poll() {
      const result = await systemWorkerApi.status();
      if (cancelled) return;
      if (result.success && result.data) {
        setStatus(result.data);
        if (result.data.connection_state === "connected") {
          setSetupData(null);
        }
      }
      setLoading(false);
    }

    void poll();
    const interval = setInterval(poll, 15000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  // Re-render once a second while a setup command is showing, purely to
  // keep its expiry countdown live -- no extra network calls.
  useEffect(() => {
    if (!setupData) return;
    const interval = setInterval(() => setTick((value) => value + 1), 1000);
    return () => clearInterval(interval);
  }, [setupData]);

  const connectionState = status?.connection_state ?? "needs_setup";
  const connected = connectionState === "connected";

  const handleCopy = async (text: string, which: "setup" | "dev") => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(which);
      setTimeout(() => setCopied(null), 2000);
    } catch {
      // Clipboard access denied/unavailable -- the command is still
      // visible and selectable, so this is a non-fatal degradation.
    }
  };

  const handleEnable = async () => {
    setEnabling(true);
    setActionError(null);
    const result = await deviceSetupApi.createSetupToken();
    if (result.success && result.data) {
      setSetupData(result.data);
    } else {
      setActionError(result.success === false ? result.error.message : "Could not create a setup token.");
    }
    setEnabling(false);
  };

  const handleDisable = async () => {
    if (!window.confirm("Disable Windows Worker? The installed worker will stop being able to receive commands until you re-enable it.")) {
      return;
    }
    setDisabling(true);
    setActionError(null);
    const result = await deviceSetupApi.disable();
    if (result.success) {
      setSetupData(null);
      await load();
    } else {
      setActionError(result.success === false ? result.error.message : "Could not disable Windows Worker.");
    }
    setDisabling(false);
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
        <span className={`rounded-full px-3 py-1 text-xs font-black ${STATE_STYLES[connectionState]}`}>
          {STATE_LABELS[connectionState]}
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

          <p className="mt-4 rounded-2xl bg-amber-50 px-4 py-3 text-xs font-bold text-amber-800">
            Browser cannot start local worker directly. Run the setup command once to install the worker.
          </p>

          {actionError && (
            <p className="mt-3 rounded-2xl bg-red-50 px-4 py-3 text-xs font-bold text-red-700">
              {actionError}
            </p>
          )}

          <div className="mt-4 flex flex-wrap items-center gap-2">
            {connectionState !== "connected" && (
              <button
                type="button"
                onClick={handleEnable}
                disabled={enabling}
                className="rounded-full bg-[#ff5a3d] px-4 py-2 text-xs font-black text-white shadow-lg shadow-[#ff5a3d]/20 transition hover:bg-neutral-950 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {enabling ? "Generating..." : "Enable Windows Worker"}
              </button>
            )}
            <button
              type="button"
              onClick={() => void load()}
              className="flex items-center gap-1.5 rounded-full border border-neutral-200 px-4 py-2 text-xs font-black text-neutral-600 transition hover:border-[#ff5a3d] hover:text-[#ff5a3d]"
            >
              <RefreshCw size={12} />
              Refresh Status
            </button>
            {connectionState === "connected" || connectionState === "offline" ? (
              <button
                type="button"
                onClick={handleDisable}
                disabled={disabling}
                className="flex items-center gap-1.5 rounded-full border border-red-200 px-4 py-2 text-xs font-black text-red-600 transition hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-60"
              >
                <PowerOff size={12} />
                {disabling ? "Disabling..." : "Disable Worker"}
              </button>
            ) : null}
          </div>

          {setupData && (
            <div className="mt-4 rounded-2xl bg-neutral-900 p-4">
              <div className="flex items-center justify-between">
                <p className="text-[10px] font-black uppercase tracking-wide text-neutral-400">
                  Run this once to connect &mdash; {countdown(setupData.expires_at)}
                </p>
                <div className="flex items-center gap-2">
                  <a
                    href={`${API_BASE_URL}${setupData.install_script_url}`}
                    download="install_windows_worker.ps1"
                    className="flex items-center gap-1 rounded-full bg-white/10 px-2.5 py-1 text-[11px] font-black text-white transition hover:bg-[#ff5a3d]"
                  >
                    <Download size={12} />
                    Download script
                  </a>
                  <button
                    type="button"
                    onClick={() => void handleCopy(setupData.setup_command, "setup")}
                    className="flex items-center gap-1 rounded-full bg-white/10 px-2.5 py-1 text-[11px] font-black text-white transition hover:bg-[#ff5a3d]"
                  >
                    {copied === "setup" ? <Check size={12} /> : <Copy size={12} />}
                    {copied === "setup" ? "Copied" : "Copy"}
                  </button>
                </div>
              </div>
              <pre className="mt-2 overflow-x-auto whitespace-pre text-[11px] font-bold leading-relaxed text-emerald-300">
                {setupData.setup_command}
              </pre>
            </div>
          )}

          {connectionState !== "connected" && (
            <div className="mt-4 rounded-2xl bg-neutral-50 p-4">
              <div className="flex items-center justify-between">
                <p className="text-[10px] font-black uppercase tracking-wide text-neutral-400">
                  For local development
                </p>
                <button
                  type="button"
                  onClick={() => void handleCopy(DEV_RUN_COMMAND, "dev")}
                  className="flex items-center gap-1 rounded-full bg-neutral-200 px-2.5 py-1 text-[11px] font-black text-neutral-700 transition hover:bg-neutral-300"
                >
                  {copied === "dev" ? <Check size={12} /> : <Copy size={12} />}
                  {copied === "dev" ? "Copied" : "Copy"}
                </button>
              </div>
              <pre className="mt-2 overflow-x-auto whitespace-pre text-[11px] font-bold leading-relaxed text-neutral-600">
                {DEV_RUN_COMMAND}
              </pre>
            </div>
          )}
        </>
      )}
    </div>
  );
}
