"use client";

import { useCallback, useEffect, useState } from "react";
import { Users, Building2, CreditCard, Mail, Bot, History } from "lucide-react";
import { AdminGuard } from "@/components/admin/AdminGuard";
import { AdminNav } from "@/components/admin/AdminNav";
import { LoadingState } from "@/components/state/LoadingState";
import { ErrorState } from "@/components/state/ErrorState";
import { adminApi, type AdminOverviewData } from "@/lib/api-client";

type LoadState = "loading" | "ready" | "error";

function StatCard({
  title,
  value,
  subtitle,
  icon: Icon,
  highlight,
}: {
  title: string;
  value: string;
  subtitle: string;
  icon: React.ComponentType<{ className?: string }>;
  highlight?: boolean;
}) {
  return (
    <div
      className={[
        "rounded-[1.55rem] p-5 shadow-sm",
        highlight ? "bg-[#ff5a3d] text-white shadow-xl shadow-[#ff5a3d]/25" : "bg-white text-neutral-950",
      ].join(" ")}
    >
      <div className="mb-6 flex items-center justify-between">
        <p className={["text-sm font-bold", highlight ? "text-white/80" : "text-neutral-500"].join(" ")}>{title}</p>
        <span
          className={[
            "grid h-9 w-9 place-items-center rounded-full",
            highlight ? "bg-white/15 text-white" : "bg-neutral-100 text-neutral-500",
          ].join(" ")}
        >
          <Icon className="h-4 w-4" />
        </span>
      </div>
      <p className="text-4xl font-black tracking-[-0.05em]">{value}</p>
      <p className={["mt-2 text-xs font-bold", highlight ? "text-white/75" : "text-emerald-600"].join(" ")}>{subtitle}</p>
    </div>
  );
}

function AdminOverviewContent() {
  const [state, setState] = useState<LoadState>("loading");
  const [errorMessage, setErrorMessage] = useState("");
  const [data, setData] = useState<AdminOverviewData | null>(null);

  const load = useCallback(async () => {
    setState("loading");
    const response = await adminApi.overview();
    if (response.success === false) {
      setState("error");
      setErrorMessage(response.error.message || "Could not load admin overview.");
      return;
    }
    setData(response.data);
    setState("ready");
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <div className="text-neutral-950">
      <h1 className="text-4xl font-black tracking-[-0.055em] text-neutral-950 lg:text-5xl">Admin Control Center</h1>
      <p className="mt-2 text-sm font-medium text-neutral-500">
        Platform-wide management: users, workspaces, plans, invites, agent access, and audit -- across every workspace.
      </p>

      <AdminNav />

      {state === "loading" ? (
        <LoadingState variant="light" title="Loading admin overview..." />
      ) : state === "error" ? (
        <ErrorState variant="light" title="Overview could not load" message={errorMessage} onRetry={() => void load()} />
      ) : data ? (
        <div className="space-y-5">
          <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            <StatCard title="Users" value={String(data.users_count)} subtitle="Across all workspaces" icon={Users} highlight />
            <StatCard title="Workspaces" value={String(data.workspaces_count)} subtitle="Total tenants" icon={Building2} />
            <StatCard title="Pending Invites" value={String(data.pending_invites)} subtitle="Awaiting acceptance" icon={Mail} />
            <StatCard
              title="Agent Configs"
              value={`${data.agent_usage_summary.enabled_configs}/${data.agent_usage_summary.total_configs}`}
              subtitle="Enabled / total across workspaces"
              icon={Bot}
            />
          </section>

          <section className="grid gap-5 lg:grid-cols-2">
            <div className="rounded-[1.6rem] bg-white p-5 shadow-sm">
              <div className="mb-4 flex items-center gap-2">
                <CreditCard className="h-4 w-4 text-neutral-400" />
                <p className="text-base font-black text-neutral-950">Active Plans</p>
              </div>
              {Object.keys(data.active_plans).length === 0 ? (
                <p className="text-xs font-bold text-neutral-400">No workspaces yet.</p>
              ) : (
                <div className="space-y-3">
                  {Object.entries(data.active_plans).map(([plan, count]) => (
                    <div key={plan} className="flex items-center justify-between rounded-2xl bg-neutral-50 px-4 py-3">
                      <span className="text-sm font-bold capitalize text-neutral-800">{plan}</span>
                      <span className="rounded-full bg-neutral-950 px-3 py-1 text-xs font-black text-white">{count}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="rounded-[1.6rem] bg-white p-5 shadow-sm">
              <div className="mb-4 flex items-center gap-2">
                <History className="h-4 w-4 text-neutral-400" />
                <p className="text-base font-black text-neutral-950">Recent Admin Actions</p>
              </div>
              {data.recent_admin_actions.length === 0 ? (
                <p className="text-xs font-bold text-neutral-400">No admin actions recorded yet.</p>
              ) : (
                <div className="space-y-2">
                  {data.recent_admin_actions.slice(0, 8).map((entry) => (
                    <div key={entry.id} className="rounded-2xl bg-neutral-50 px-4 py-3">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-black text-neutral-800">{entry.action}</span>
                        <span className="text-[10px] font-bold text-neutral-400">
                          {entry.created_at ? new Date(entry.created_at).toLocaleString() : "—"}
                        </span>
                      </div>
                      <p className="mt-1 text-[11px] font-medium text-neutral-500">
                        by {entry.actor} · {entry.resource_type} {entry.resource_id ? `#${entry.resource_id.slice(0, 10)}` : ""}
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </section>
        </div>
      ) : null}
    </div>
  );
}

export default function AdminOverviewPage() {
  return (
    <AdminGuard>
      <AdminOverviewContent />
    </AdminGuard>
  );
}
