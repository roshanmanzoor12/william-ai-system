"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { CheckCircle2, XCircle } from "lucide-react";
import { AdminGuard } from "@/components/admin/AdminGuard";
import { AdminNav } from "@/components/admin/AdminNav";
import { LoadingState } from "@/components/state/LoadingState";
import { ErrorState } from "@/components/state/ErrorState";
import { adminApi, type AdminWorkspace } from "@/lib/api-client";

type LoadState = "loading" | "ready" | "error";

// Mirrors database/models/workspace.py's plan_member_limit()/
// plan_agent_limit()/default_agent_access() exactly (read directly from
// source, not guessed) -- there is no dedicated /admin/plans read endpoint
// for these five fixed numbers, and building one just to serve static
// backend constants would be pure overhead. Editing plan limits from the
// dashboard is NOT wired to a real backend endpoint yet (none of the
// required admin routes cover it) -- shown as read-only with an honest
// note rather than a button that would silently do nothing.
const PLAN_DEFINITIONS = [
  { key: "free", label: "Free", memberLimit: 1, agentLimit: 3, allAgents: false },
  { key: "starter", label: "Starter", memberLimit: 3, agentLimit: 5, allAgents: true },
  { key: "pro", label: "Pro", memberLimit: 5, agentLimit: 14, allAgents: true },
  { key: "business", label: "Business", memberLimit: 25, agentLimit: 14, allAgents: true },
  { key: "enterprise", label: "Enterprise", memberLimit: 1000, agentLimit: 14, allAgents: true },
];

function AdminPlansContent() {
  const [state, setState] = useState<LoadState>("loading");
  const [errorMessage, setErrorMessage] = useState("");
  const [workspaces, setWorkspaces] = useState<AdminWorkspace[]>([]);

  const load = useCallback(async () => {
    setState("loading");
    const response = await adminApi.listWorkspaces();
    if (response.success === false) {
      setState("error");
      setErrorMessage(response.error.message || "Could not load workspaces.");
      return;
    }
    setWorkspaces(response.data.workspaces);
    setState("ready");
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <div className="text-neutral-950">
      <h1 className="text-4xl font-black tracking-[-0.055em] text-neutral-950 lg:text-5xl">Admin Plans</h1>
      <p className="mt-2 text-sm font-medium text-neutral-500">
        The five real SaaS plan tiers, their limits, and how many workspaces currently use each one.
      </p>

      <AdminNav />

      <div className="mb-6 rounded-2xl border border-orange-100 bg-orange-50 px-4 py-3 text-xs font-bold text-orange-800">
        Plan limits below are read-only -- no backend endpoint exists yet to edit them from the dashboard. To assign a plan
        to a workspace, use <Link href="/admin/workspaces" className="underline">Admin Workspaces</Link>.
      </div>

      {state === "loading" ? (
        <LoadingState variant="light" title="Loading plan usage..." />
      ) : state === "error" ? (
        <ErrorState variant="light" title="Plan usage could not load" message={errorMessage} onRetry={() => void load()} />
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {PLAN_DEFINITIONS.map((plan) => {
            const workspacesOnPlan = workspaces.filter((w) => w.plan === plan.key);
            return (
              <div key={plan.key} className="rounded-[1.6rem] bg-white p-5 shadow-sm">
                <div className="mb-4 flex items-center justify-between">
                  <p className="text-lg font-black text-neutral-950">{plan.label}</p>
                  <span className="rounded-full bg-neutral-950 px-3 py-1 text-xs font-black text-white">{workspacesOnPlan.length} workspaces</span>
                </div>
                <div className="space-y-2 text-sm font-bold text-neutral-700">
                  <div className="flex items-center justify-between rounded-xl bg-neutral-50 px-3 py-2">
                    <span>Member limit</span>
                    <span>{plan.memberLimit >= 1000 ? "Unlimited" : plan.memberLimit}</span>
                  </div>
                  <div className="flex items-center justify-between rounded-xl bg-neutral-50 px-3 py-2">
                    <span>Agent limit</span>
                    <span>{plan.agentLimit} / 14</span>
                  </div>
                  <div className="flex items-center justify-between rounded-xl bg-neutral-50 px-3 py-2">
                    <span>All agents unlocked</span>
                    {plan.allAgents ? <CheckCircle2 className="h-4 w-4 text-emerald-600" /> : <XCircle className="h-4 w-4 text-red-500" />}
                  </div>
                </div>
                {workspacesOnPlan.length > 0 ? (
                  <div className="mt-4 flex flex-wrap gap-1.5">
                    {workspacesOnPlan.slice(0, 6).map((w) => (
                      <span key={w.workspace_id} className="rounded-full bg-neutral-100 px-2.5 py-1 text-[10px] font-black text-neutral-600">{w.name}</span>
                    ))}
                    {workspacesOnPlan.length > 6 ? <span className="text-[10px] font-black text-neutral-400">+{workspacesOnPlan.length - 6} more</span> : null}
                  </div>
                ) : null}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default function AdminPlansPage() {
  return (
    <AdminGuard>
      <AdminPlansContent />
    </AdminGuard>
  );
}
