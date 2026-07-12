"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { Plus, Search, ShieldOff, ShieldCheck, RotateCcw, X } from "lucide-react";
import { AdminGuard } from "@/components/admin/AdminGuard";
import { AdminNav } from "@/components/admin/AdminNav";
import { LoadingState } from "@/components/state/LoadingState";
import { ErrorState } from "@/components/state/ErrorState";
import { EmptyState } from "@/components/state/EmptyState";
import {
  adminApi,
  type AdminUser,
  type AdminWorkspace,
} from "@/lib/api-client";

type LoadState = "loading" | "ready" | "error";

const ROLE_OPTIONS = ["owner", "admin", "manager", "member", "viewer"];

function CreateUserModal({
  workspaces,
  submitting,
  onClose,
  onSubmit,
}: {
  workspaces: AdminWorkspace[];
  submitting: boolean;
  onClose: () => void;
  onSubmit: (form: { email: string; password: string; full_name: string; workspace_id?: string; role?: string }) => void;
}) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [fullName, setFullName] = useState("");
  const [workspaceId, setWorkspaceId] = useState("");
  const [role, setRole] = useState("member");

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" role="dialog" aria-modal="true">
      <button type="button" aria-label="Close" onClick={onClose} className="absolute inset-0 h-full w-full cursor-default" />
      <div className="relative w-full max-w-lg rounded-[1.8rem] bg-white p-6 shadow-2xl">
        <div className="mb-5 flex items-start justify-between">
          <h3 className="text-xl font-black text-neutral-950">Create User</h3>
          <button type="button" onClick={onClose} className="grid h-9 w-9 place-items-center rounded-full bg-neutral-100 hover:bg-neutral-950 hover:text-white">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="space-y-3">
          <input type="email" placeholder="Email" value={email} onChange={(e) => setEmail(e.target.value)} className="w-full rounded-2xl border border-neutral-200 bg-neutral-50 px-4 py-3 text-sm font-semibold outline-none focus:border-[#ff5a3d]" />
          <input type="password" placeholder="Temporary password (min 8 chars)" value={password} onChange={(e) => setPassword(e.target.value)} className="w-full rounded-2xl border border-neutral-200 bg-neutral-50 px-4 py-3 text-sm font-semibold outline-none focus:border-[#ff5a3d]" />
          <input type="text" placeholder="Full name" value={fullName} onChange={(e) => setFullName(e.target.value)} className="w-full rounded-2xl border border-neutral-200 bg-neutral-50 px-4 py-3 text-sm font-semibold outline-none focus:border-[#ff5a3d]" />
          <div className="grid grid-cols-2 gap-3">
            <select value={workspaceId} onChange={(e) => setWorkspaceId(e.target.value)} className="rounded-2xl border border-neutral-200 bg-neutral-50 px-4 py-3 text-sm font-semibold outline-none focus:border-[#ff5a3d]">
              <option value="">No workspace yet</option>
              {workspaces.map((w) => (
                <option key={w.workspace_id} value={w.workspace_id}>{w.name}</option>
              ))}
            </select>
            <select value={role} onChange={(e) => setRole(e.target.value)} disabled={!workspaceId} className="rounded-2xl border border-neutral-200 bg-neutral-50 px-4 py-3 text-sm font-semibold outline-none focus:border-[#ff5a3d] disabled:opacity-50">
              {ROLE_OPTIONS.map((r) => (
                <option key={r} value={r}>{r}</option>
              ))}
            </select>
          </div>
        </div>
        <div className="mt-6 flex justify-end gap-3">
          <button type="button" onClick={onClose} className="rounded-2xl border border-neutral-200 px-4 py-3 text-sm font-bold text-neutral-600">Cancel</button>
          <button
            type="button"
            disabled={submitting || !email.trim() || password.length < 8 || !fullName.trim()}
            onClick={() => onSubmit({ email, password, full_name: fullName, workspace_id: workspaceId || undefined, role: workspaceId ? role : undefined })}
            className="rounded-2xl bg-[#ff5a3d] px-5 py-3 text-sm font-black text-white disabled:cursor-not-allowed disabled:opacity-50"
          >
            {submitting ? "Creating..." : "Create User"}
          </button>
        </div>
      </div>
    </div>
  );
}

function AdminUsersContent() {
  const [state, setState] = useState<LoadState>("loading");
  const [errorMessage, setErrorMessage] = useState("");
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [workspaces, setWorkspaces] = useState<AdminWorkspace[]>([]);
  const [search, setSearch] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [busyUserId, setBusyUserId] = useState<string | null>(null);
  const [notice, setNotice] = useState<{ type: "success" | "error"; message: string } | null>(null);
  const [assignTarget, setAssignTarget] = useState<AdminUser | null>(null);
  const [assignWorkspaceId, setAssignWorkspaceId] = useState("");
  const [assignRole, setAssignRole] = useState("member");

  const load = useCallback(async (searchTerm?: string) => {
    setState("loading");
    const [usersResponse, workspacesResponse] = await Promise.all([
      adminApi.listUsers({ search: searchTerm || undefined, limit: 100 }),
      adminApi.listWorkspaces(),
    ]);

    if (usersResponse.success === false) {
      setState("error");
      setErrorMessage(usersResponse.error.message || "Could not load users.");
      return;
    }

    setUsers(usersResponse.data.users);
    if (workspacesResponse.success) setWorkspaces(workspacesResponse.data.workspaces);
    setState("ready");
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function handleCreate(form: { email: string; password: string; full_name: string; workspace_id?: string; role?: string }) {
    setSubmitting(true);
    const response = await adminApi.createUser(form);
    if (response.success === false) {
      setNotice({ type: "error", message: response.error.message || "User could not be created." });
      setSubmitting(false);
      return;
    }
    setNotice({ type: "success", message: `${form.email} created.` });
    setShowCreate(false);
    setSubmitting(false);
    void load(search);
  }

  async function handleToggleActive(user: AdminUser) {
    setBusyUserId(user.id);
    const response = await adminApi.updateUser(user.id, { is_active: !user.is_active });
    if (response.success === false) {
      setNotice({ type: "error", message: response.error.message || "Could not update user." });
      setBusyUserId(null);
      return;
    }
    setUsers((current) => current.map((u) => (u.id === user.id ? response.data.user : u)));
    setNotice({ type: "success", message: `${user.email} ${!user.is_active ? "enabled" : "disabled"}.` });
    setBusyUserId(null);
  }

  async function handleResetRole(user: AdminUser, workspaceId: string) {
    setBusyUserId(user.id);
    const response = await adminApi.updateUser(user.id, { workspace_id: workspaceId, reset_role: true });
    if (response.success === false) {
      setNotice({ type: "error", message: response.error.message || "Could not reset role." });
      setBusyUserId(null);
      return;
    }
    setNotice({ type: "success", message: `${user.email}'s role reset to member.` });
    setBusyUserId(null);
    void load(search);
  }

  async function handleAssign() {
    if (!assignTarget || !assignWorkspaceId) return;
    setBusyUserId(assignTarget.id);
    const response = await adminApi.updateUser(assignTarget.id, { workspace_id: assignWorkspaceId, role: assignRole });
    if (response.success === false) {
      setNotice({ type: "error", message: response.error.message || "Could not assign workspace/role." });
      setBusyUserId(null);
      return;
    }
    setNotice({ type: "success", message: `${assignTarget.email} assigned to workspace as ${assignRole}.` });
    setAssignTarget(null);
    setBusyUserId(null);
    void load(search);
  }

  const workspaceNameById = useMemo(() => {
    const map = new Map<string, string>();
    workspaces.forEach((w) => map.set(w.workspace_id, w.name));
    return map;
  }, [workspaces]);

  return (
    <div className="text-neutral-950">
      <div className="mb-6 flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <h1 className="text-4xl font-black tracking-[-0.055em] text-neutral-950 lg:text-5xl">Admin Users</h1>
          <p className="mt-2 text-sm font-medium text-neutral-500">Every user across every workspace. Passwords are never returned by the API.</p>
        </div>
        <button type="button" onClick={() => setShowCreate(true)} className="inline-flex items-center gap-2 rounded-full bg-[#ff5a3d] px-5 py-3 text-xs font-black text-white shadow-lg shadow-[#ff5a3d]/20">
          <Plus className="h-4 w-4" /> Create User
        </button>
      </div>

      <AdminNav />

      {notice ? (
        <div className={["mb-5 rounded-2xl px-4 py-3 text-sm font-bold", notice.type === "success" ? "border border-emerald-100 bg-emerald-50 text-emerald-700" : "border border-red-100 bg-red-50 text-red-700"].join(" ")}>
          {notice.message}
        </div>
      ) : null}

      <div className="mb-5 flex items-center gap-3 rounded-full border border-neutral-200 bg-white px-4 py-2.5">
        <Search className="h-4 w-4 text-neutral-400" />
        <input
          type="search"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") void load(search); }}
          placeholder="Search by email or name..."
          className="w-full text-sm font-semibold outline-none"
        />
        <button type="button" onClick={() => void load(search)} className="rounded-full bg-neutral-950 px-3 py-1.5 text-xs font-black text-white">Search</button>
      </div>

      {state === "loading" ? (
        <LoadingState variant="light" title="Loading users..." />
      ) : state === "error" ? (
        <ErrorState variant="light" title="Users could not load" message={errorMessage} onRetry={() => void load(search)} />
      ) : users.length === 0 ? (
        <EmptyState variant="light" icon="◌" title="No users found" message="Create the first user, or adjust your search." />
      ) : (
        <div className="grid gap-4 xl:grid-cols-2">
          {users.map((user) => {
            const isBusy = busyUserId === user.id;
            return (
              <article key={user.id} className="rounded-[1.5rem] border border-neutral-100 bg-neutral-50 p-4">
                <div className="mb-3 flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <h2 className="truncate text-base font-black text-neutral-950">{user.full_name || user.email}</h2>
                    <p className="truncate text-xs font-bold text-neutral-400">{user.email}</p>
                  </div>
                  <div className="flex gap-1.5">
                    {user.is_platform_admin ? (
                      <span className="rounded-full bg-[#fff3ed] px-2.5 py-1 text-[10px] font-black text-[#ff5a3d]">Platform Admin</span>
                    ) : null}
                    <span className={["rounded-full px-2.5 py-1 text-[10px] font-black", user.is_active ? "bg-emerald-50 text-emerald-700" : "bg-red-50 text-red-700"].join(" ")}>
                      {user.is_active ? "Active" : "Disabled"}
                    </span>
                  </div>
                </div>

                {user.memberships.length === 0 ? (
                  <p className="text-xs font-bold text-neutral-400">No workspace memberships yet.</p>
                ) : (
                  <div className="space-y-2">
                    {user.memberships.map((m) => (
                      <div key={m.membership_id} className="flex items-center justify-between rounded-xl bg-white px-3 py-2 text-xs">
                        <span className="font-bold text-neutral-700">{workspaceNameById.get(m.workspace_id) || m.workspace_id}</span>
                        <span className="rounded-full bg-neutral-100 px-2 py-0.5 font-black capitalize text-neutral-600">{m.role}</span>
                      </div>
                    ))}
                  </div>
                )}

                <div className="mt-4 flex flex-wrap gap-2">
                  <button
                    type="button"
                    disabled={isBusy}
                    onClick={() => void handleToggleActive(user)}
                    className={["flex items-center gap-1.5 rounded-2xl px-3 py-2 text-xs font-black disabled:opacity-50", user.is_active ? "bg-red-50 text-red-700" : "bg-emerald-50 text-emerald-700"].join(" ")}
                  >
                    {user.is_active ? <ShieldOff className="h-3.5 w-3.5" /> : <ShieldCheck className="h-3.5 w-3.5" />}
                    {user.is_active ? "Disable" : "Enable"}
                  </button>
                  <button
                    type="button"
                    onClick={() => { setAssignTarget(user); setAssignWorkspaceId(user.memberships[0]?.workspace_id || workspaces[0]?.workspace_id || ""); setAssignRole("member"); }}
                    className="rounded-2xl border border-neutral-200 bg-white px-3 py-2 text-xs font-black text-neutral-700"
                  >
                    Assign Workspace / Role
                  </button>
                  {user.memberships.length > 0 ? (
                    <button
                      type="button"
                      disabled={isBusy}
                      onClick={() => void handleResetRole(user, user.memberships[0].workspace_id)}
                      className="flex items-center gap-1.5 rounded-2xl border border-neutral-200 bg-white px-3 py-2 text-xs font-black text-neutral-700 disabled:opacity-50"
                    >
                      <RotateCcw className="h-3.5 w-3.5" /> Reset Role
                    </button>
                  ) : null}
                </div>
              </article>
            );
          })}
        </div>
      )}

      {showCreate ? (
        <CreateUserModal workspaces={workspaces} submitting={submitting} onClose={() => setShowCreate(false)} onSubmit={(form) => void handleCreate(form)} />
      ) : null}

      {assignTarget ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" role="dialog" aria-modal="true">
          <button type="button" aria-label="Close" onClick={() => setAssignTarget(null)} className="absolute inset-0 h-full w-full cursor-default" />
          <div className="relative w-full max-w-md rounded-[1.8rem] bg-white p-6 shadow-2xl">
            <h3 className="mb-4 text-lg font-black text-neutral-950">Assign {assignTarget.email}</h3>
            <div className="space-y-3">
              <select value={assignWorkspaceId} onChange={(e) => setAssignWorkspaceId(e.target.value)} className="w-full rounded-2xl border border-neutral-200 bg-neutral-50 px-4 py-3 text-sm font-semibold outline-none">
                <option value="">Select workspace</option>
                {workspaces.map((w) => (
                  <option key={w.workspace_id} value={w.workspace_id}>{w.name}</option>
                ))}
              </select>
              <select value={assignRole} onChange={(e) => setAssignRole(e.target.value)} className="w-full rounded-2xl border border-neutral-200 bg-neutral-50 px-4 py-3 text-sm font-semibold outline-none">
                {ROLE_OPTIONS.map((r) => (
                  <option key={r} value={r}>{r}</option>
                ))}
              </select>
            </div>
            <div className="mt-6 flex justify-end gap-3">
              <button type="button" onClick={() => setAssignTarget(null)} className="rounded-2xl border border-neutral-200 px-4 py-3 text-sm font-bold text-neutral-600">Cancel</button>
              <button type="button" disabled={!assignWorkspaceId} onClick={() => void handleAssign()} className="rounded-2xl bg-[#ff5a3d] px-5 py-3 text-sm font-black text-white disabled:opacity-50">Assign</button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}

export default function AdminUsersPage() {
  return (
    <AdminGuard>
      <AdminUsersContent />
    </AdminGuard>
  );
}
