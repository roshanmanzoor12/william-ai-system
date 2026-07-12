"use client";

import { useCallback, useEffect, useState } from "react";
import { AdminGuard } from "@/components/admin/AdminGuard";
import { AdminNav } from "@/components/admin/AdminNav";
import { LoadingState } from "@/components/state/LoadingState";
import { ErrorState } from "@/components/state/ErrorState";
import { EmptyState } from "@/components/state/EmptyState";
import { adminApi, type AdminAuditEntry } from "@/lib/api-client";

type LoadState = "loading" | "ready" | "error";

function actionStyle(action: string): string {
  if (action.includes("plan_changed") || action.includes("owner_changed")) return "bg-orange-50 text-orange-700";
  if (action.includes("created")) return "bg-emerald-50 text-emerald-700";
  if (action.includes("blocked") || action.includes("denied")) return "bg-red-50 text-red-700";
  return "bg-neutral-100 text-neutral-600";
}

function AdminAuditContent() {
  const [state, setState] = useState<LoadState>("loading");
  const [errorMessage, setErrorMessage] = useState("");
  const [entries, setEntries] = useState<AdminAuditEntry[]>([]);
  const [filter, setFilter] = useState("");

  const load = useCallback(async () => {
    setState("loading");
    const response = await adminApi.audit({ limit: 200 });
    if (response.success === false) {
      setState("error");
      setErrorMessage(response.error.message || "Could not load audit log.");
      return;
    }
    setEntries(response.data.entries);
    setState("ready");
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const filtered = filter
    ? entries.filter((e) => e.action.toLowerCase().includes(filter.toLowerCase()) || e.actor.toLowerCase().includes(filter.toLowerCase()))
    : entries;

  return (
    <div className="text-neutral-950">
      <h1 className="text-4xl font-black tracking-[-0.055em] text-neutral-950 lg:text-5xl">Admin Audit</h1>
      <p className="mt-2 text-sm font-medium text-neutral-500">Admin actions, plan changes, role changes, invite events, and agent permission changes across every workspace.</p>

      <AdminNav />

      <input
        type="search"
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
        placeholder="Filter by action or actor..."
        className="mb-5 w-full rounded-full border border-neutral-200 bg-white px-5 py-3 text-sm font-semibold outline-none focus:border-[#ff5a3d]"
      />

      {state === "loading" ? (
        <LoadingState variant="light" title="Loading audit log..." />
      ) : state === "error" ? (
        <ErrorState variant="light" title="Audit log could not load" message={errorMessage} onRetry={() => void load()} />
      ) : filtered.length === 0 ? (
        <EmptyState variant="light" icon="▤" title="No audit entries" message="Admin actions will appear here as they happen." />
      ) : (
        <div className="overflow-x-auto rounded-[1.6rem] bg-white shadow-sm">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-neutral-100 text-[11px] font-black uppercase tracking-wide text-neutral-400">
                <th className="px-5 py-3">Action</th>
                <th className="px-5 py-3">Actor</th>
                <th className="px-5 py-3">Resource</th>
                <th className="px-5 py-3">Workspace</th>
                <th className="px-5 py-3">Status</th>
                <th className="px-5 py-3">When</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((entry) => (
                <tr key={entry.id} className="border-b border-neutral-50 last:border-0">
                  <td className="px-5 py-3">
                    <span className={["rounded-full px-2.5 py-1 text-[11px] font-black", actionStyle(entry.action)].join(" ")}>{entry.action}</span>
                  </td>
                  <td className="px-5 py-3 font-bold text-neutral-700">{entry.actor}</td>
                  <td className="px-5 py-3 text-xs text-neutral-500">
                    {entry.resource_type}
                    {entry.resource_id ? ` #${entry.resource_id.slice(0, 10)}` : ""}
                  </td>
                  <td className="px-5 py-3 text-xs text-neutral-500">{entry.workspace_id}</td>
                  <td className="px-5 py-3 text-xs font-bold capitalize text-neutral-600">{entry.status}</td>
                  <td className="px-5 py-3 text-xs text-neutral-400">{entry.created_at ? new Date(entry.created_at).toLocaleString() : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default function AdminAuditPage() {
  return (
    <AdminGuard>
      <AdminAuditContent />
    </AdminGuard>
  );
}
