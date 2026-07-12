"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { ShieldAlert } from "lucide-react";
import { AdminGuard } from "@/components/admin/AdminGuard";
import { AdminNav } from "@/components/admin/AdminNav";
import { LoadingState } from "@/components/state/LoadingState";
import { ErrorState } from "@/components/state/ErrorState";
import { EmptyState } from "@/components/state/EmptyState";
import { adminApi, type AdminWorkspace } from "@/lib/api-client";

type LoadState = "loading" | "ready" | "error";

type AgentItem = {
  key: string;
  name: string;
  category: string;
  enabled: boolean;
  minimum_plan: string;
  allowed_roles: string[];
  risk_level: string;
  requires_security_approval: boolean;
};

type PermissionUser = {
  user_id: string;
  name: string;
  email: string;
  role: string;
  plan: string;
  assigned_agents: string[];
};

function AdminAgentAccessContent() {
  const [workspaces, setWorkspaces] = useState<AdminWorkspace[]>([]);
  const [workspaceId, setWorkspaceId] = useState("");
  const [state, setState] = useState<LoadState>("loading");
  const [errorMessage, setErrorMessage] = useState("");
  const [users, setUsers] = useState<PermissionUser[]>([]);
  const [agents, setAgents] = useState<AgentItem[]>([]);
  const [roleMatrix, setRoleMatrix] = useState<Record<string, string[]>>({});
  const [selectedUserId, setSelectedUserId] = useState("");
  const [notice, setNotice] = useState<{ type: "success" | "error" | "info"; message: string } | null>(null);
  const [saving, setSaving] = useState(false);

  const selectedUser = useMemo(() => users.find((u) => u.user_id === selectedUserId) || null, [users, selectedUserId]);
  const [pendingAssigned, setPendingAssigned] = useState<Set<string>>(new Set());

  useEffect(() => {
    void (async () => {
      const response = await adminApi.listWorkspaces();
      if (response.success && response.data.workspaces[0]) {
        setWorkspaces(response.data.workspaces);
        setWorkspaceId(response.data.workspaces[0].workspace_id);
      } else if (response.success) {
        setWorkspaces([]);
        setState("ready");
      }
    })();
  }, []);

  const load = useCallback(async (targetWorkspaceId: string) => {
    if (!targetWorkspaceId) return;
    setState("loading");
    const response = await adminApi.agentAccess(targetWorkspaceId);
    if (response.success === false) {
      setState("error");
      setErrorMessage(response.error.message || "Could not load agent access.");
      return;
    }
    setUsers(response.data.users);
    setAgents(response.data.agents);
    setRoleMatrix(response.data.role_matrix);
    setSelectedUserId(response.data.users[0]?.user_id || "");
    setPendingAssigned(new Set(response.data.users[0]?.assigned_agents || []));
    setState("ready");
  }, []);

  useEffect(() => {
    if (workspaceId) void load(workspaceId);
  }, [workspaceId, load]);

  useEffect(() => {
    if (selectedUser) setPendingAssigned(new Set(selectedUser.assigned_agents));
  }, [selectedUser]);

  function toggleAgent(agentKey: string) {
    setPendingAssigned((current) => {
      const next = new Set(current);
      if (next.has(agentKey)) next.delete(agentKey);
      else next.add(agentKey);
      return next;
    });
  }

  function applyRoleDefaults() {
    if (!selectedUser) return;
    setPendingAssigned(new Set(roleMatrix[selectedUser.role] || []));
    setNotice({ type: "info", message: `Applied ${selectedUser.role} role defaults (not saved yet).` });
  }

  function applyPlanDefaults() {
    if (!selectedUser) return;
    const allowedByPlan = agents.filter((a) => a.enabled).map((a) => a.key);
    setPendingAssigned(new Set(allowedByPlan));
    setNotice({ type: "info", message: `Applied plan defaults: all enabled agents (not saved yet).` });
  }

  async function handleSave() {
    if (!selectedUser) return;
    setSaving(true);
    const response = await adminApi.updateAgentAccess(selectedUser.user_id, workspaceId, Array.from(pendingAssigned));
    if (response.success === false) {
      setNotice({ type: "error", message: response.error.message || "Permissions could not be saved." });
      setSaving(false);
      return;
    }
    setUsers((current) => current.map((u) => (u.user_id === selectedUser.user_id ? { ...u, assigned_agents: response.data.assigned_agents } : u)));
    setNotice({ type: "success", message: "Agent access saved. SecurityAgent review + audit log recorded." });
    setSaving(false);
  }

  return (
    <div className="text-neutral-950">
      <h1 className="text-4xl font-black tracking-[-0.055em] text-neutral-950 lg:text-5xl">Admin Agent Access</h1>
      <p className="mt-2 text-sm font-medium text-neutral-500">Select any workspace and user to toggle agent access, backed by the same permission engine every workspace&apos;s own Agent Permissions page uses.</p>

      <AdminNav />

      {notice ? (
        <div className={["mb-5 rounded-2xl px-4 py-3 text-sm font-bold", notice.type === "success" ? "border border-emerald-100 bg-emerald-50 text-emerald-700" : notice.type === "info" ? "border border-blue-100 bg-blue-50 text-blue-700" : "border border-red-100 bg-red-50 text-red-700"].join(" ")}>
          {notice.message}
        </div>
      ) : null}

      <div className="mb-6 flex flex-wrap gap-3">
        <select value={workspaceId} onChange={(e) => setWorkspaceId(e.target.value)} className="rounded-full border border-neutral-200 bg-white px-4 py-2.5 text-sm font-bold outline-none focus:border-[#ff5a3d]">
          {workspaces.map((w) => (
            <option key={w.workspace_id} value={w.workspace_id}>{w.name}</option>
          ))}
        </select>
        <select value={selectedUserId} onChange={(e) => setSelectedUserId(e.target.value)} className="rounded-full border border-neutral-200 bg-white px-4 py-2.5 text-sm font-bold outline-none focus:border-[#ff5a3d]">
          {users.map((u) => (
            <option key={u.user_id} value={u.user_id}>{u.name} ({u.role})</option>
          ))}
        </select>
      </div>

      {state === "loading" ? (
        <LoadingState variant="light" title="Loading agent access..." />
      ) : state === "error" ? (
        <ErrorState variant="light" title="Agent access could not load" message={errorMessage} onRetry={() => void load(workspaceId)} />
      ) : workspaces.length === 0 ? (
        <EmptyState variant="light" icon="◈" title="No workspaces yet" message="Create a workspace first under Admin Workspaces." />
      ) : !selectedUser ? (
        <EmptyState variant="light" icon="◌" title="No members in this workspace" message="Assign a user to this workspace under Admin Users first." />
      ) : (
        <div className="grid gap-5 xl:grid-cols-[0.6fr_1.4fr]">
          <div className="space-y-4">
            <div className="rounded-[1.6rem] bg-white p-5 shadow-sm">
              <p className="text-base font-black text-neutral-950">{selectedUser.name}</p>
              <p className="text-xs font-bold text-neutral-400">{selectedUser.email}</p>
              <div className="mt-3 flex gap-2">
                <span className="rounded-full bg-neutral-100 px-3 py-1 text-[11px] font-black capitalize text-neutral-600">{selectedUser.role}</span>
                <span className="rounded-full bg-[#fff3ed] px-3 py-1 text-[11px] font-black capitalize text-[#ff5a3d]">{selectedUser.plan}</span>
              </div>
              <div className="mt-4 grid gap-2">
                <button type="button" onClick={applyRoleDefaults} className="rounded-2xl bg-neutral-950 px-4 py-3 text-sm font-black text-white">Apply Role Defaults</button>
                <button type="button" onClick={applyPlanDefaults} className="rounded-2xl border border-neutral-200 bg-white px-4 py-3 text-sm font-black text-neutral-700">Apply Plan Defaults</button>
                <button type="button" disabled={saving} onClick={() => void handleSave()} className="rounded-2xl bg-[#ff5a3d] px-4 py-3 text-sm font-black text-white disabled:opacity-50">
                  {saving ? "Saving..." : "Save Permissions"}
                </button>
              </div>
            </div>
          </div>

          <div className="rounded-[1.6rem] bg-white p-5 shadow-sm">
            <p className="mb-4 text-base font-black text-neutral-950">Agents ({agents.length})</p>
            <div className="grid gap-3 md:grid-cols-2">
              {agents.map((agent) => {
                const isAssigned = pendingAssigned.has(agent.key);
                const isRoleAllowed = agent.allowed_roles.includes(selectedUser.role);
                return (
                  <div key={agent.key} className={["rounded-2xl border p-4", isAssigned ? "border-[#ff5a3d]/40 bg-[#fff3ed]" : "border-neutral-100 bg-neutral-50"].join(" ")}>
                    <div className="mb-2 flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <p className="truncate text-sm font-black text-neutral-950">{agent.name}</p>
                        <p className="text-[10px] font-bold uppercase tracking-wide text-neutral-400">{agent.category}</p>
                      </div>
                      <button
                        type="button"
                        onClick={() => toggleAgent(agent.key)}
                        className={["relative h-7 w-12 shrink-0 rounded-full transition", isAssigned ? "bg-[#ff5a3d]" : "bg-neutral-300"].join(" ")}
                        aria-label={`Toggle ${agent.name}`}
                      >
                        <span className={["absolute top-1 h-5 w-5 rounded-full bg-white shadow transition", isAssigned ? "left-6" : "left-1"].join(" ")} />
                      </button>
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      <span className="rounded-full bg-white px-2 py-0.5 text-[10px] font-black text-neutral-500">{agent.minimum_plan}+ plan</span>
                      {agent.requires_security_approval ? (
                        <span className="flex items-center gap-1 rounded-full bg-[#fff3ed] px-2 py-0.5 text-[10px] font-black text-[#ff5a3d]">
                          <ShieldAlert className="h-2.5 w-2.5" /> SecurityAgent routed
                        </span>
                      ) : null}
                      {!isRoleAllowed ? <span className="rounded-full bg-red-50 px-2 py-0.5 text-[10px] font-black text-red-600">Role blocked</span> : null}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default function AdminAgentAccessPage() {
  return (
    <AdminGuard>
      <AdminAgentAccessContent />
    </AdminGuard>
  );
}
