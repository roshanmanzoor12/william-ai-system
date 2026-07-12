"use client";

import { useCallback, useEffect, useState } from "react";
import { Mail, Copy, Send } from "lucide-react";
import { AdminGuard } from "@/components/admin/AdminGuard";
import { AdminNav } from "@/components/admin/AdminNav";
import { LoadingState } from "@/components/state/LoadingState";
import { ErrorState } from "@/components/state/ErrorState";
import { EmptyState } from "@/components/state/EmptyState";
import { adminApi, type AdminInvite, type AdminWorkspace } from "@/lib/api-client";

type LoadState = "loading" | "ready" | "error";

const ROLE_OPTIONS = ["owner", "admin", "manager", "member", "viewer"];
const PLAN_OPTIONS = ["free", "starter", "pro", "business", "enterprise"];

function statusStyle(status: string): string {
  if (status === "pending") return "bg-blue-50 text-blue-700";
  if (status === "accepted") return "bg-emerald-50 text-emerald-700";
  if (status === "expired") return "bg-orange-50 text-orange-700";
  return "bg-neutral-100 text-neutral-600";
}

function AdminInvitesContent() {
  const [state, setState] = useState<LoadState>("loading");
  const [errorMessage, setErrorMessage] = useState("");
  const [invites, setInvites] = useState<AdminInvite[]>([]);
  const [workspaces, setWorkspaces] = useState<AdminWorkspace[]>([]);
  const [notice, setNotice] = useState<{ type: "success" | "error" | "info"; message: string } | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const [email, setEmail] = useState("");
  const [workspaceId, setWorkspaceId] = useState("");
  const [role, setRole] = useState("member");
  const [plan, setPlan] = useState("");
  const [lastLink, setLastLink] = useState<string | null>(null);

  const load = useCallback(async () => {
    setState("loading");
    const [invitesResponse, workspacesResponse] = await Promise.all([adminApi.listInvites(), adminApi.listWorkspaces()]);
    if (invitesResponse.success === false) {
      setState("error");
      setErrorMessage(invitesResponse.error.message || "Could not load invites.");
      return;
    }
    setInvites(invitesResponse.data.invites);
    if (workspacesResponse.success) {
      setWorkspaces(workspacesResponse.data.workspaces);
      if (!workspaceId && workspacesResponse.data.workspaces[0]) {
        setWorkspaceId(workspacesResponse.data.workspaces[0].workspace_id);
      }
    }
    setState("ready");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function handleInvite() {
    if (!email.trim() || !workspaceId) return;
    setSubmitting(true);
    setNotice(null);
    setLastLink(null);

    const response = await adminApi.createInvite({ email: email.trim(), workspace_id: workspaceId, role, plan: plan || undefined });
    if (response.success === false) {
      setNotice({ type: "error", message: response.error.message || "Invite could not be created." });
      setSubmitting(false);
      return;
    }

    setLastLink(response.data.invite_link);
    if (response.data.email_status === "sent") {
      setNotice({ type: "success", message: `Invite email sent to ${email.trim()}.` });
    } else {
      setNotice({
        type: "info",
        message: `external_dependency_required: no SMTP provider configured. Share the invite link below manually.`,
      });
    }
    setEmail("");
    setSubmitting(false);
    void load();
  }

  return (
    <div className="text-neutral-950">
      <h1 className="text-4xl font-black tracking-[-0.055em] text-neutral-950 lg:text-5xl">Admin Invites</h1>
      <p className="mt-2 text-sm font-medium text-neutral-500">Invite users into any workspace, with a chosen role and plan hint.</p>

      <AdminNav />

      {notice ? (
        <div
          className={[
            "mb-5 rounded-2xl px-4 py-3 text-sm font-bold",
            notice.type === "success" ? "border border-emerald-100 bg-emerald-50 text-emerald-700" : notice.type === "info" ? "border border-orange-100 bg-orange-50 text-orange-700" : "border border-red-100 bg-red-50 text-red-700",
          ].join(" ")}
        >
          {notice.message}
        </div>
      ) : null}

      {lastLink ? (
        <div className="mb-5 flex items-center gap-3 rounded-2xl border border-neutral-200 bg-white px-4 py-3">
          <span className="min-w-0 flex-1 truncate text-xs font-bold text-neutral-600">{lastLink}</span>
          <button
            type="button"
            onClick={() => navigator.clipboard.writeText(lastLink)}
            className="flex shrink-0 items-center gap-1.5 rounded-full bg-neutral-950 px-3 py-1.5 text-[11px] font-black text-white"
          >
            <Copy className="h-3 w-3" /> Copy link
          </button>
        </div>
      ) : null}

      <div className="mb-6 rounded-[1.6rem] bg-white p-5 shadow-sm">
        <div className="mb-4 flex items-center gap-2">
          <Mail className="h-4 w-4 text-neutral-400" />
          <p className="text-base font-black text-neutral-950">Invite by Email</p>
        </div>
        <div className="grid gap-3 md:grid-cols-4">
          <input type="email" placeholder="person@example.com" value={email} onChange={(e) => setEmail(e.target.value)} className="rounded-2xl border border-neutral-200 bg-neutral-50 px-4 py-3 text-sm font-semibold outline-none focus:border-[#ff5a3d] md:col-span-2" />
          <select value={workspaceId} onChange={(e) => setWorkspaceId(e.target.value)} className="rounded-2xl border border-neutral-200 bg-neutral-50 px-4 py-3 text-sm font-semibold outline-none focus:border-[#ff5a3d]">
            <option value="">Select workspace</option>
            {workspaces.map((w) => (
              <option key={w.workspace_id} value={w.workspace_id}>{w.name}</option>
            ))}
          </select>
          <select value={role} onChange={(e) => setRole(e.target.value)} className="rounded-2xl border border-neutral-200 bg-neutral-50 px-4 py-3 text-sm font-semibold outline-none focus:border-[#ff5a3d]">
            {ROLE_OPTIONS.map((r) => (
              <option key={r} value={r}>{r}</option>
            ))}
          </select>
          <select value={plan} onChange={(e) => setPlan(e.target.value)} className="rounded-2xl border border-neutral-200 bg-neutral-50 px-4 py-3 text-sm font-semibold outline-none focus:border-[#ff5a3d]">
            <option value="">No plan hint</option>
            {PLAN_OPTIONS.map((p) => (
              <option key={p} value={p}>{p}</option>
            ))}
          </select>
          <button
            type="button"
            disabled={submitting || !email.trim() || !workspaceId}
            onClick={() => void handleInvite()}
            className="flex items-center justify-center gap-2 rounded-2xl bg-[#ff5a3d] px-4 py-3 text-sm font-black text-white disabled:cursor-not-allowed disabled:opacity-50 md:col-span-4"
          >
            <Send className="h-4 w-4" /> {submitting ? "Sending..." : "Create Invite"}
          </button>
        </div>
      </div>

      {state === "loading" ? (
        <LoadingState variant="light" title="Loading invites..." />
      ) : state === "error" ? (
        <ErrorState variant="light" title="Invites could not load" message={errorMessage} onRetry={() => void load()} />
      ) : invites.length === 0 ? (
        <EmptyState variant="light" icon="✉" title="No invites yet" message="Send your first invite above." />
      ) : (
        <div className="grid gap-3 xl:grid-cols-2">
          {invites.map((invite) => (
            <div key={invite.invite_id} className="rounded-[1.5rem] border border-neutral-100 bg-neutral-50 p-4">
              <div className="mb-2 flex items-center justify-between">
                <p className="text-sm font-black text-neutral-950">{invite.invited_email}</p>
                <span className={["rounded-full px-2.5 py-1 text-[10px] font-black capitalize", statusStyle(invite.status)].join(" ")}>{invite.status}</span>
              </div>
              <p className="text-xs font-bold text-neutral-500">
                {workspaces.find((w) => w.workspace_id === invite.workspace_id)?.name || invite.workspace_id} · role: {invite.role}
              </p>
              <p className="mt-1 text-[11px] text-neutral-400">
                Invited {invite.created_at ? new Date(invite.created_at).toLocaleString() : "—"}
                {invite.expires_at ? ` · expires ${new Date(invite.expires_at).toLocaleDateString()}` : ""}
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function AdminInvitesPage() {
  return (
    <AdminGuard>
      <AdminInvitesContent />
    </AdminGuard>
  );
}
