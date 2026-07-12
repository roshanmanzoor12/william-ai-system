"use client";

import { useCallback, useEffect, useState } from "react";
import { Plus, Users2, X } from "lucide-react";
import { AdminGuard } from "@/components/admin/AdminGuard";
import { AdminNav } from "@/components/admin/AdminNav";
import { LoadingState } from "@/components/state/LoadingState";
import { ErrorState } from "@/components/state/ErrorState";
import { EmptyState } from "@/components/state/EmptyState";
import { adminApi, type AdminWorkspace } from "@/lib/api-client";

type LoadState = "loading" | "ready" | "error";

const PLAN_OPTIONS = ["free", "starter", "pro", "business", "enterprise"];

function AdminWorkspacesContent() {
  const [state, setState] = useState<LoadState>("loading");
  const [errorMessage, setErrorMessage] = useState("");
  const [workspaces, setWorkspaces] = useState<AdminWorkspace[]>([]);
  const [notice, setNotice] = useState<{ type: "success" | "error"; message: string } | null>(null);
  const [busyWorkspaceId, setBusyWorkspaceId] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [membersFor, setMembersFor] = useState<AdminWorkspace | null>(null);
  const [members, setMembers] = useState<Array<{ user_id: string; role: string; email: string | null; full_name: string | null }>>([]);

  const [newName, setNewName] = useState("");
  const [newOwnerId, setNewOwnerId] = useState("");
  const [newPlan, setNewPlan] = useState("free");

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

  async function handleCreate() {
    if (!newName.trim() || !newOwnerId.trim()) return;
    setSubmitting(true);
    const response = await adminApi.createWorkspace({ name: newName.trim(), owner_user_id: newOwnerId.trim(), plan: newPlan });
    if (response.success === false) {
      setNotice({ type: "error", message: response.error.message || "Workspace could not be created." });
      setSubmitting(false);
      return;
    }
    setNotice({ type: "success", message: `${newName.trim()} created.` });
    setShowCreate(false);
    setNewName("");
    setNewOwnerId("");
    setSubmitting(false);
    void load();
  }

  async function handlePlanChange(workspace: AdminWorkspace, plan: string) {
    setBusyWorkspaceId(workspace.workspace_id);
    const response = await adminApi.updateWorkspacePlan(workspace.workspace_id, plan);
    if (response.success === false) {
      setNotice({ type: "error", message: response.error.message || "Plan could not be updated." });
      setBusyWorkspaceId(null);
      return;
    }
    setWorkspaces((current) => current.map((w) => (w.workspace_id === workspace.workspace_id ? response.data.workspace : w)));
    setNotice({ type: "success", message: `${workspace.name} moved to ${plan}.` });
    setBusyWorkspaceId(null);
  }

  async function handleChangeOwner(workspace: AdminWorkspace) {
    const newOwner = window.prompt(`New owner user_id for ${workspace.name}:`, workspace.owner_user_id);
    if (!newOwner || newOwner === workspace.owner_user_id) return;
    setBusyWorkspaceId(workspace.workspace_id);
    const response = await adminApi.updateWorkspaceOwner(workspace.workspace_id, newOwner.trim());
    if (response.success === false) {
      setNotice({ type: "error", message: response.error.message || "Owner could not be changed." });
      setBusyWorkspaceId(null);
      return;
    }
    setWorkspaces((current) => current.map((w) => (w.workspace_id === workspace.workspace_id ? response.data.workspace : w)));
    setNotice({ type: "success", message: `Owner updated for ${workspace.name}.` });
    setBusyWorkspaceId(null);
  }

  async function handleViewMembers(workspace: AdminWorkspace) {
    setMembersFor(workspace);
    const response = await adminApi.getWorkspaceMembers(workspace.workspace_id);
    if (response.success) setMembers(response.data.members);
  }

  return (
    <div className="text-neutral-950">
      <div className="mb-6 flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <h1 className="text-4xl font-black tracking-[-0.055em] text-neutral-950 lg:text-5xl">Admin Workspaces</h1>
          <p className="mt-2 text-sm font-medium text-neutral-500">Every workspace, its plan, owner, and member count.</p>
        </div>
        <button type="button" onClick={() => setShowCreate(true)} className="inline-flex items-center gap-2 rounded-full bg-[#ff5a3d] px-5 py-3 text-xs font-black text-white shadow-lg shadow-[#ff5a3d]/20">
          <Plus className="h-4 w-4" /> Create Workspace
        </button>
      </div>

      <AdminNav />

      {notice ? (
        <div className={["mb-5 rounded-2xl px-4 py-3 text-sm font-bold", notice.type === "success" ? "border border-emerald-100 bg-emerald-50 text-emerald-700" : "border border-red-100 bg-red-50 text-red-700"].join(" ")}>
          {notice.message}
        </div>
      ) : null}

      {state === "loading" ? (
        <LoadingState variant="light" title="Loading workspaces..." />
      ) : state === "error" ? (
        <ErrorState variant="light" title="Workspaces could not load" message={errorMessage} onRetry={() => void load()} />
      ) : workspaces.length === 0 ? (
        <EmptyState variant="light" icon="◈" title="No workspaces yet" message="Create the first workspace above." />
      ) : (
        <div className="grid gap-4 xl:grid-cols-2">
          {workspaces.map((workspace) => {
            const isBusy = busyWorkspaceId === workspace.workspace_id;
            return (
              <article key={workspace.workspace_id} className="rounded-[1.5rem] border border-neutral-100 bg-neutral-50 p-4">
                <div className="mb-2 flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <h2 className="truncate text-base font-black text-neutral-950">{workspace.name}</h2>
                    <p className="truncate text-xs font-bold text-neutral-400">{workspace.slug}</p>
                  </div>
                  <span className="rounded-full bg-neutral-950 px-3 py-1 text-[10px] font-black text-white">{workspace.member_count ?? 0} members</span>
                </div>

                <p className="text-xs font-medium text-neutral-500">Owner: {workspace.owner_user_id}</p>

                <div className="mt-3 flex flex-wrap items-center gap-2">
                  <select
                    value={workspace.plan}
                    disabled={isBusy}
                    onChange={(e) => void handlePlanChange(workspace, e.target.value)}
                    className="rounded-full border border-neutral-200 bg-white px-3 py-1.5 text-xs font-black capitalize outline-none focus:border-[#ff5a3d]"
                  >
                    {PLAN_OPTIONS.map((p) => (
                      <option key={p} value={p}>{p}</option>
                    ))}
                  </select>
                  <span className={["rounded-full px-2.5 py-1 text-[10px] font-black", workspace.is_suspended ? "bg-red-50 text-red-700" : "bg-emerald-50 text-emerald-700"].join(" ")}>
                    {workspace.is_suspended ? "Suspended" : workspace.status}
                  </span>
                </div>

                <div className="mt-4 flex flex-wrap gap-2">
                  <button type="button" onClick={() => void handleViewMembers(workspace)} className="flex items-center gap-1.5 rounded-2xl border border-neutral-200 bg-white px-3 py-2 text-xs font-black text-neutral-700">
                    <Users2 className="h-3.5 w-3.5" /> Members
                  </button>
                  <button type="button" disabled={isBusy} onClick={() => void handleChangeOwner(workspace)} className="rounded-2xl border border-neutral-200 bg-white px-3 py-2 text-xs font-black text-neutral-700 disabled:opacity-50">
                    Change Owner
                  </button>
                </div>
              </article>
            );
          })}
        </div>
      )}

      {showCreate ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" role="dialog" aria-modal="true">
          <button type="button" aria-label="Close" onClick={() => setShowCreate(false)} className="absolute inset-0 h-full w-full cursor-default" />
          <div className="relative w-full max-w-md rounded-[1.8rem] bg-white p-6 shadow-2xl">
            <div className="mb-4 flex items-start justify-between">
              <h3 className="text-lg font-black text-neutral-950">Create Workspace</h3>
              <button type="button" onClick={() => setShowCreate(false)} className="grid h-9 w-9 place-items-center rounded-full bg-neutral-100"><X className="h-4 w-4" /></button>
            </div>
            <div className="space-y-3">
              <input type="text" placeholder="Workspace name" value={newName} onChange={(e) => setNewName(e.target.value)} className="w-full rounded-2xl border border-neutral-200 bg-neutral-50 px-4 py-3 text-sm font-semibold outline-none" />
              <input type="text" placeholder="Owner user_id (from Admin Users)" value={newOwnerId} onChange={(e) => setNewOwnerId(e.target.value)} className="w-full rounded-2xl border border-neutral-200 bg-neutral-50 px-4 py-3 text-sm font-semibold outline-none" />
              <select value={newPlan} onChange={(e) => setNewPlan(e.target.value)} className="w-full rounded-2xl border border-neutral-200 bg-neutral-50 px-4 py-3 text-sm font-semibold outline-none">
                {PLAN_OPTIONS.map((p) => (
                  <option key={p} value={p}>{p}</option>
                ))}
              </select>
            </div>
            <div className="mt-6 flex justify-end gap-3">
              <button type="button" onClick={() => setShowCreate(false)} className="rounded-2xl border border-neutral-200 px-4 py-3 text-sm font-bold text-neutral-600">Cancel</button>
              <button type="button" disabled={submitting || !newName.trim() || !newOwnerId.trim()} onClick={() => void handleCreate()} className="rounded-2xl bg-[#ff5a3d] px-5 py-3 text-sm font-black text-white disabled:opacity-50">
                {submitting ? "Creating..." : "Create"}
              </button>
            </div>
          </div>
        </div>
      ) : null}

      {membersFor ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" role="dialog" aria-modal="true">
          <button type="button" aria-label="Close" onClick={() => setMembersFor(null)} className="absolute inset-0 h-full w-full cursor-default" />
          <div className="relative w-full max-w-lg rounded-[1.8rem] bg-white p-6 shadow-2xl">
            <div className="mb-4 flex items-start justify-between">
              <h3 className="text-lg font-black text-neutral-950">{membersFor.name} Members</h3>
              <button type="button" onClick={() => setMembersFor(null)} className="grid h-9 w-9 place-items-center rounded-full bg-neutral-100"><X className="h-4 w-4" /></button>
            </div>
            {members.length === 0 ? (
              <p className="text-xs font-bold text-neutral-400">No members yet.</p>
            ) : (
              <div className="space-y-2">
                {members.map((m) => (
                  <div key={m.user_id} className="flex items-center justify-between rounded-2xl bg-neutral-50 px-4 py-3">
                    <div className="min-w-0">
                      <p className="truncate text-sm font-bold text-neutral-800">{m.full_name || m.email || m.user_id}</p>
                      <p className="truncate text-xs text-neutral-400">{m.email}</p>
                    </div>
                    <span className="rounded-full bg-neutral-950 px-3 py-1 text-[10px] font-black capitalize text-white">{m.role}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      ) : null}
    </div>
  );
}

export default function AdminWorkspacesPage() {
  return (
    <AdminGuard>
      <AdminWorkspacesContent />
    </AdminGuard>
  );
}
