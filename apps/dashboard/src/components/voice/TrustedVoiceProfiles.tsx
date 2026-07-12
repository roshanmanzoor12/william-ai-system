"use client";

/**
 * apps/dashboard/src/components/voice/TrustedVoiceProfiles.tsx
 *
 * Live-wired "Trusted Voice Profiles" settings section for Phase 9's real
 * voice backend (apps/api/routes/voice.py). Lists workspace voice profiles,
 * and lets owner/admin roles create, edit, disable, and revoke them. Every
 * mutation is gated client-side by role (defense in depth -- the backend
 * re-checks require_auth_role(Role.ADMIN.value) on every write regardless).
 */

import { useCallback, useEffect, useState } from "react";
import { Plus, ShieldAlert, Trash2, UserCog, X } from "lucide-react";
import { readSession, hasMinRole, type SessionData } from "@/lib/auth";
import {
  voiceApi,
  VOICE_AGENT_KEYS,
  type VoiceAgentKey,
  type VoiceProfile,
  type VoiceProfileCreatePayload,
  type VoiceProfileRole,
  type VoiceProfileStatus,
  type VoiceprintStatus,
} from "@/lib/api-client";
import { LoadingState } from "@/components/state/LoadingState";
import { ErrorState } from "@/components/state/ErrorState";
import { EmptyState } from "@/components/state/EmptyState";

type LoadState = "loading" | "ready" | "error";

const ROLE_OPTIONS: VoiceProfileRole[] = [
  "owner",
  "admin",
  "trusted_developer",
  "trusted_manager",
  "trusted_assistant",
  "guest",
];

const DEFAULT_FORM: VoiceProfileCreatePayload = {
  display_name: "",
  role: "guest",
  allowed_agents: [],
  blocked_agents: [],
  allowed_capabilities: [],
  blocked_capabilities: [],
  can_use_voice: true,
  can_use_wake_word: false,
  can_access_private_memory: false,
  can_access_finance: false,
  can_access_system_agent: false,
  can_run_code_agent: false,
  requires_approval_for_risky_actions: true,
  preferred_language: "en",
  reply_language_mode: "same_as_speaker",
};

const BOOLEAN_FIELDS: {
  key: keyof VoiceProfileCreatePayload;
  label: string;
  helper: string;
}[] = [
  { key: "can_use_voice", label: "Can use voice", helper: "Allowed to submit voice commands at all." },
  { key: "can_use_wake_word", label: "Can use wake word", helper: "Allowed to trigger wake-word listening modes." },
  { key: "can_access_private_memory", label: "Can access private memory", helper: "Allowed to reach private memory records." },
  { key: "can_access_finance", label: "Can access finance", helper: "Off by default -- matches the backend's own safe default." },
  { key: "can_access_system_agent", label: "Can access system agent", helper: "Off by default -- matches the backend's own safe default." },
  { key: "can_run_code_agent", label: "Can run code agent", helper: "Off by default -- matches the backend's own safe default." },
  { key: "requires_approval_for_risky_actions", label: "Requires approval for risky actions", helper: "Routes risky actions through Security Agent approval." },
];

function statusStyle(status: VoiceProfileStatus): string {
  if (status === "active") return "border-emerald-400/20 bg-emerald-400/10 text-emerald-300";
  if (status === "disabled") return "border-orange-400/25 bg-orange-500/10 text-orange-300";
  return "border-red-400/25 bg-red-500/10 text-red-300";
}

function voiceprintStyle(status: VoiceprintStatus): string {
  if (status === "enrolled") return "border-emerald-400/20 bg-emerald-400/10 text-emerald-300";
  if (status === "pending") return "border-blue-400/20 bg-blue-400/10 text-blue-300";
  if (status === "external_dependency_required")
    return "border-orange-400/25 bg-orange-500/10 text-orange-300";
  return "border-white/10 bg-white/[0.04] text-zinc-400";
}

function formatDate(value?: string | null): string {
  if (!value) return "Never";
  try {
    return new Intl.DateTimeFormat("en-US", {
      month: "short",
      day: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    }).format(new Date(value));
  } catch {
    return value;
  }
}

function toggleAgentInList(list: string[], key: VoiceAgentKey): string[] {
  return list.includes(key) ? list.filter((item) => item !== key) : [...list, key];
}

function ProfileFormModal({
  initial,
  title,
  submitting,
  onClose,
  onSubmit,
}: {
  initial: VoiceProfileCreatePayload;
  title: string;
  submitting: boolean;
  onClose: () => void;
  onSubmit: (payload: VoiceProfileCreatePayload) => void;
}) {
  const [form, setForm] = useState<VoiceProfileCreatePayload>(initial);

  function updateField<K extends keyof VoiceProfileCreatePayload>(
    key: K,
    value: VoiceProfileCreatePayload[K],
  ) {
    setForm((current) => ({ ...current, [key]: value }));
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-label={title}
    >
      <button
        type="button"
        aria-label="Close"
        onClick={onClose}
        className="absolute inset-0 h-full w-full cursor-default"
      />

      <div className="relative max-h-[88vh] w-full max-w-2xl overflow-y-auto rounded-[28px] border border-white/10 bg-[#0b0c10] p-6 shadow-[0_40px_120px_rgba(0,0,0,0.5)]">
        <div className="mb-5 flex items-start justify-between gap-4">
          <h3 className="text-xl font-black text-white">{title}</h3>
          <button
            type="button"
            onClick={onClose}
            className="grid h-9 w-9 place-items-center rounded-full bg-white/[0.06] text-zinc-300 transition hover:bg-orange-500 hover:text-black"
            aria-label="Close"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="space-y-4">
          <label className="block">
            <span className="mb-2 block text-xs font-bold uppercase tracking-[0.16em] text-zinc-500">
              Display name
            </span>
            <input
              type="text"
              value={form.display_name}
              maxLength={160}
              onChange={(event) => updateField("display_name", event.target.value)}
              className="w-full rounded-2xl border border-white/10 bg-[#07080b] px-4 py-3 text-sm font-semibold text-zinc-200 outline-none transition focus:border-orange-500/40 focus:ring-4 focus:ring-orange-500/10"
              placeholder="e.g. Jane Doe"
            />
          </label>

          <div className="grid gap-4 sm:grid-cols-2">
            <label className="block">
              <span className="mb-2 block text-xs font-bold uppercase tracking-[0.16em] text-zinc-500">
                Role
              </span>
              <select
                value={form.role}
                onChange={(event) =>
                  updateField("role", event.target.value as VoiceProfileRole)
                }
                className="w-full rounded-2xl border border-white/10 bg-[#07080b] px-4 py-3 text-sm font-semibold text-zinc-200 outline-none transition focus:border-orange-500/40 focus:ring-4 focus:ring-orange-500/10"
              >
                {ROLE_OPTIONS.map((role) => (
                  <option key={role} value={role}>
                    {role.replace(/_/g, " ")}
                  </option>
                ))}
              </select>
            </label>

            <label className="block">
              <span className="mb-2 block text-xs font-bold uppercase tracking-[0.16em] text-zinc-500">
                Preferred language
              </span>
              <input
                type="text"
                value={form.preferred_language}
                maxLength={16}
                onChange={(event) =>
                  updateField("preferred_language", event.target.value)
                }
                className="w-full rounded-2xl border border-white/10 bg-[#07080b] px-4 py-3 text-sm font-semibold text-zinc-200 outline-none transition focus:border-orange-500/40 focus:ring-4 focus:ring-orange-500/10"
                placeholder="en"
              />
            </label>
          </div>

          <label className="block">
            <span className="mb-2 block text-xs font-bold uppercase tracking-[0.16em] text-zinc-500">
              Reply language mode
            </span>
            <input
              type="text"
              value={form.reply_language_mode}
              onChange={(event) =>
                updateField("reply_language_mode", event.target.value)
              }
              className="w-full rounded-2xl border border-white/10 bg-[#07080b] px-4 py-3 text-sm font-semibold text-zinc-200 outline-none transition focus:border-orange-500/40 focus:ring-4 focus:ring-orange-500/10"
              placeholder="same_as_speaker"
            />
          </label>

          <div>
            <span className="mb-2 block text-xs font-bold uppercase tracking-[0.16em] text-zinc-500">
              Allowed agents
            </span>
            <div className="flex flex-wrap gap-2">
              {VOICE_AGENT_KEYS.map((key) => {
                const active = (form.allowed_agents || []).includes(key);
                return (
                  <button
                    key={`allow-${key}`}
                    type="button"
                    onClick={() =>
                      updateField(
                        "allowed_agents",
                        toggleAgentInList(form.allowed_agents || [], key),
                      )
                    }
                    className={[
                      "rounded-full border px-3 py-1.5 text-[11px] font-black capitalize transition",
                      active
                        ? "border-emerald-400/30 bg-emerald-400/10 text-emerald-300"
                        : "border-white/10 bg-white/[0.03] text-zinc-400 hover:border-emerald-400/20",
                    ].join(" ")}
                  >
                    {key}
                  </button>
                );
              })}
            </div>
            <p className="mt-2 text-[11px] text-zinc-500">
              Empty means no explicit allow-list restriction from this field.
            </p>
          </div>

          <div>
            <span className="mb-2 block text-xs font-bold uppercase tracking-[0.16em] text-zinc-500">
              Blocked agents
            </span>
            <div className="flex flex-wrap gap-2">
              {VOICE_AGENT_KEYS.map((key) => {
                const active = (form.blocked_agents || []).includes(key);
                return (
                  <button
                    key={`block-${key}`}
                    type="button"
                    onClick={() =>
                      updateField(
                        "blocked_agents",
                        toggleAgentInList(form.blocked_agents || [], key),
                      )
                    }
                    className={[
                      "rounded-full border px-3 py-1.5 text-[11px] font-black capitalize transition",
                      active
                        ? "border-red-400/30 bg-red-500/10 text-red-300"
                        : "border-white/10 bg-white/[0.03] text-zinc-400 hover:border-red-400/20",
                    ].join(" ")}
                  >
                    {key}
                  </button>
                );
              })}
            </div>
          </div>

          <div className="space-y-3">
            <span className="block text-xs font-bold uppercase tracking-[0.16em] text-zinc-500">
              Permissions
            </span>
            {BOOLEAN_FIELDS.map((field) => (
              <label
                key={field.key}
                className="flex items-start justify-between gap-4 rounded-2xl border border-white/10 bg-black/25 p-3"
              >
                <span>
                  <span className="block text-sm font-bold text-white">
                    {field.label}
                  </span>
                  <span className="mt-1 block text-xs text-zinc-500">
                    {field.helper}
                  </span>
                </span>
                <input
                  type="checkbox"
                  checked={Boolean(form[field.key])}
                  onChange={(event) =>
                    updateField(
                      field.key,
                      event.target.checked as VoiceProfileCreatePayload[typeof field.key],
                    )
                  }
                  className="mt-1 h-5 w-5 shrink-0 accent-orange-500"
                />
              </label>
            ))}
          </div>
        </div>

        <div className="mt-6 flex justify-end gap-3">
          <button
            type="button"
            onClick={onClose}
            className="rounded-2xl border border-white/10 bg-white/[0.04] px-4 py-3 text-sm font-bold text-zinc-300 transition hover:bg-white/[0.08]"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={submitting || !form.display_name.trim()}
            onClick={() => onSubmit(form)}
            className="rounded-2xl bg-orange-500 px-5 py-3 text-sm font-black text-black transition hover:bg-orange-400 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {submitting ? "Saving..." : "Save Profile"}
          </button>
        </div>
      </div>
    </div>
  );
}

export function TrustedVoiceProfiles() {
  const [session, setSession] = useState<SessionData | null>(null);
  const [state, setState] = useState<LoadState>("loading");
  const [errorMessage, setErrorMessage] = useState("");
  const [profiles, setProfiles] = useState<VoiceProfile[]>([]);
  const [notice, setNotice] = useState<{
    type: "success" | "error";
    message: string;
  } | null>(null);
  const [modalMode, setModalMode] = useState<"create" | "edit" | null>(null);
  const [editingProfile, setEditingProfile] = useState<VoiceProfile | null>(
    null,
  );
  const [submitting, setSubmitting] = useState(false);
  const [busyProfileId, setBusyProfileId] = useState<string | null>(null);

  const canManageProfiles = Boolean(
    session && hasMinRole(session.role, "admin"),
  );

  const load = useCallback(async () => {
    setState("loading");
    setErrorMessage("");

    const response = await voiceApi.listProfiles();

    if (response.success === false) {
      setState("error");
      setErrorMessage(response.error.message || "Could not load voice profiles.");
      return;
    }

    setProfiles(response.data.profiles);
    setState("ready");
  }, []);

  useEffect(() => {
    setSession(readSession());
    void load();
  }, [load]);

  async function handleCreate(payload: VoiceProfileCreatePayload) {
    setSubmitting(true);
    setNotice(null);

    const response = await voiceApi.createProfile(payload);

    if (response.success === false) {
      setNotice({
        type: "error",
        message: response.error.message || "Voice profile could not be created.",
      });
      setSubmitting(false);
      return;
    }

    setProfiles((current) => [response.data.profile, ...current]);
    setNotice({ type: "success", message: "Voice profile created." });
    setSubmitting(false);
    setModalMode(null);
  }

  async function handleUpdate(
    profileId: string,
    payload: VoiceProfileCreatePayload,
  ) {
    setSubmitting(true);
    setNotice(null);

    const response = await voiceApi.updateProfile(profileId, payload);

    if (response.success === false) {
      setNotice({
        type: "error",
        message: response.error.message || "Voice profile could not be updated.",
      });
      setSubmitting(false);
      return;
    }

    setProfiles((current) =>
      current.map((profile) =>
        profile.id === profileId ? response.data.profile : profile,
      ),
    );
    setNotice({ type: "success", message: "Voice profile updated." });
    setSubmitting(false);
    setModalMode(null);
    setEditingProfile(null);
  }

  async function handleSetStatus(
    profile: VoiceProfile,
    status: VoiceProfileStatus,
  ) {
    if (!canManageProfiles) return;

    setBusyProfileId(profile.id);
    setNotice(null);

    const response = await voiceApi.updateProfile(profile.id, { status });

    if (response.success === false) {
      setNotice({
        type: "error",
        message: response.error.message || "Voice profile status could not change.",
      });
      setBusyProfileId(null);
      return;
    }

    setProfiles((current) =>
      current.map((item) =>
        item.id === profile.id ? response.data.profile : item,
      ),
    );
    setNotice({
      type: "success",
      message: `${profile.display_name} is now ${status}.`,
    });
    setBusyProfileId(null);
  }

  async function handleRevoke(profile: VoiceProfile) {
    if (!canManageProfiles) return;

    setBusyProfileId(profile.id);
    setNotice(null);

    const response = await voiceApi.deleteProfile(profile.id, false);

    if (response.success === false) {
      setNotice({
        type: "error",
        message: response.error.message || "Voice profile could not be revoked.",
      });
      setBusyProfileId(null);
      return;
    }

    setProfiles((current) =>
      current.map((item) =>
        item.id === profile.id ? response.data.profile : item,
      ),
    );
    setNotice({ type: "success", message: `${profile.display_name} revoked.` });
    setBusyProfileId(null);
  }

  return (
    <section className="rounded-[32px] border border-white/10 bg-white/[0.035] p-5 shadow-[0_30px_100px_rgba(0,0,0,0.32)] md:p-6">
      <div className="mb-6 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <div>
          <p className="text-sm font-bold text-orange-300">Trusted Voice Profiles</p>
          <h2 className="mt-2 text-2xl font-black tracking-tight text-white">
            Who William Trusts By Voice
          </h2>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-zinc-500">
            Live workspace voice profiles from /voice/profiles -- roles,
            agent access, and voiceprint enrollment state.
          </p>
        </div>

        <button
          type="button"
          disabled={!canManageProfiles}
          onClick={() => setModalMode("create")}
          className="inline-flex items-center gap-2 rounded-2xl bg-orange-500 px-3 py-2 text-xs font-black text-black transition hover:bg-orange-400 disabled:cursor-not-allowed disabled:opacity-50"
        >
          <Plus className="h-3.5 w-3.5" />
          Add profile
        </button>
      </div>

      {!canManageProfiles ? (
        <div className="mb-5 flex items-center gap-2 rounded-2xl border border-orange-400/25 bg-orange-500/10 px-4 py-3 text-xs font-bold text-orange-200">
          <ShieldAlert className="h-4 w-4 shrink-0" />
          Only owner/admin roles can create, edit, disable, or revoke voice
          profiles. You are viewing in read-only mode.
        </div>
      ) : null}

      {notice ? (
        <div
          className={[
            "mb-5 rounded-2xl border px-4 py-3 text-sm font-bold",
            notice.type === "success"
              ? "border-emerald-400/20 bg-emerald-400/10 text-emerald-300"
              : "border-red-400/25 bg-red-500/10 text-red-300",
          ].join(" ")}
        >
          {notice.message}
        </div>
      ) : null}

      {state === "loading" ? (
        <LoadingState
          variant="dark"
          title="Loading voice profiles..."
          subtitle="Calling /voice/profiles."
        />
      ) : state === "error" ? (
        <ErrorState
          variant="dark"
          title="Voice profiles could not load"
          message={errorMessage}
          onRetry={() => void load()}
        />
      ) : profiles.length === 0 ? (
        <EmptyState
          variant="dark"
          icon="◌"
          title="No voice profiles yet"
          message="Add a trusted voice profile so William knows who is allowed to speak commands into this workspace."
        />
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">
          {profiles.map((profile) => {
            const isBusy = busyProfileId === profile.id;

            return (
              <article
                key={profile.id}
                className="rounded-[26px] border border-white/10 bg-white/[0.035] p-4 transition hover:border-orange-500/25 hover:bg-orange-500/[0.055]"
              >
                <div className="mb-3 flex items-start justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <span className="flex h-11 w-11 items-center justify-center rounded-2xl border border-orange-500/20 bg-orange-500/10 text-orange-300">
                      <UserCog className="h-5 w-5" />
                    </span>
                    <div>
                      <h3 className="text-sm font-black text-white">
                        {profile.display_name}
                      </h3>
                      <p className="mt-1 text-xs capitalize text-zinc-500">
                        {profile.role.replace(/_/g, " ")}
                      </p>
                    </div>
                  </div>

                  <span
                    className={`rounded-full border px-2.5 py-1 text-[11px] font-bold capitalize ${statusStyle(
                      profile.status,
                    )}`}
                  >
                    {profile.status}
                  </span>
                </div>

                <div className="mb-3 flex flex-wrap gap-2">
                  <span
                    className={`rounded-full border px-2.5 py-1 text-[10px] font-black capitalize ${voiceprintStyle(
                      profile.voiceprint_status,
                    )}`}
                  >
                    Voiceprint: {profile.voiceprint_status.replace(/_/g, " ")}
                  </span>
                  {profile.can_use_wake_word ? (
                    <span className="rounded-full border border-blue-400/20 bg-blue-400/10 px-2.5 py-1 text-[10px] font-black text-blue-300">
                      Wake word
                    </span>
                  ) : null}
                  {profile.requires_approval_for_risky_actions ? (
                    <span className="rounded-full border border-white/10 bg-white/[0.04] px-2.5 py-1 text-[10px] font-black text-zinc-400">
                      Approval required
                    </span>
                  ) : null}
                </div>

                <div className="grid grid-cols-2 gap-3 text-xs text-zinc-500">
                  <div>
                    <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-600">
                      Language
                    </p>
                    <p className="mt-1 font-bold text-white">
                      {profile.preferred_language || "—"}
                    </p>
                  </div>
                  <div>
                    <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-600">
                      Last used
                    </p>
                    <p className="mt-1 font-bold text-white">
                      {formatDate(profile.last_used_at)}
                    </p>
                  </div>
                </div>

                {profile.allowed_agents.length > 0 ? (
                  <div className="mt-3">
                    <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-600">
                      Allowed agents
                    </p>
                    <div className="mt-1 flex flex-wrap gap-1.5">
                      {profile.allowed_agents.map((agent) => (
                        <span
                          key={agent}
                          className="rounded-full bg-white/[0.05] px-2 py-0.5 text-[10px] font-bold text-zinc-300"
                        >
                          {agent}
                        </span>
                      ))}
                    </div>
                  </div>
                ) : null}

                <div className="mt-4 flex flex-wrap gap-2">
                  <button
                    type="button"
                    disabled={!canManageProfiles || isBusy}
                    onClick={() => {
                      setEditingProfile(profile);
                      setModalMode("edit");
                    }}
                    className="rounded-2xl border border-white/10 bg-white/[0.04] px-3 py-2 text-xs font-bold text-zinc-300 transition hover:border-orange-500/30 hover:bg-orange-500/10 hover:text-orange-300 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    Edit
                  </button>

                  {profile.status === "active" ? (
                    <button
                      type="button"
                      disabled={!canManageProfiles || isBusy}
                      onClick={() => void handleSetStatus(profile, "disabled")}
                      className="rounded-2xl border border-orange-400/20 bg-orange-500/10 px-3 py-2 text-xs font-bold text-orange-300 transition hover:bg-orange-500/20 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      {isBusy ? "Working..." : "Disable"}
                    </button>
                  ) : profile.status === "disabled" ? (
                    <button
                      type="button"
                      disabled={!canManageProfiles || isBusy}
                      onClick={() => void handleSetStatus(profile, "active")}
                      className="rounded-2xl border border-emerald-400/20 bg-emerald-400/10 px-3 py-2 text-xs font-bold text-emerald-300 transition hover:bg-emerald-400/20 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      {isBusy ? "Working..." : "Re-enable"}
                    </button>
                  ) : null}

                  {profile.status !== "revoked" ? (
                    <button
                      type="button"
                      disabled={!canManageProfiles || isBusy}
                      onClick={() => void handleRevoke(profile)}
                      className="inline-flex items-center gap-1.5 rounded-2xl border border-red-400/25 bg-red-500/10 px-3 py-2 text-xs font-bold text-red-300 transition hover:bg-red-500/20 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                      {isBusy ? "Working..." : "Revoke"}
                    </button>
                  ) : null}
                </div>
              </article>
            );
          })}
        </div>
      )}

      {modalMode === "create" ? (
        <ProfileFormModal
          title="Add Voice Profile"
          initial={DEFAULT_FORM}
          submitting={submitting}
          onClose={() => setModalMode(null)}
          onSubmit={(payload) => void handleCreate(payload)}
        />
      ) : null}

      {modalMode === "edit" && editingProfile ? (
        <ProfileFormModal
          title={`Edit ${editingProfile.display_name}`}
          initial={{
            display_name: editingProfile.display_name,
            role: editingProfile.role,
            allowed_agents: editingProfile.allowed_agents,
            blocked_agents: editingProfile.blocked_agents,
            allowed_capabilities: editingProfile.allowed_capabilities,
            blocked_capabilities: editingProfile.blocked_capabilities,
            can_use_voice: editingProfile.can_use_voice,
            can_use_wake_word: editingProfile.can_use_wake_word,
            can_access_private_memory: editingProfile.can_access_private_memory,
            can_access_finance: editingProfile.can_access_finance,
            can_access_system_agent: editingProfile.can_access_system_agent,
            can_run_code_agent: editingProfile.can_run_code_agent,
            requires_approval_for_risky_actions:
              editingProfile.requires_approval_for_risky_actions,
            preferred_language: editingProfile.preferred_language,
            reply_language_mode: editingProfile.reply_language_mode,
          }}
          submitting={submitting}
          onClose={() => {
            setModalMode(null);
            setEditingProfile(null);
          }}
          onSubmit={(payload) => void handleUpdate(editingProfile.id, payload)}
        />
      ) : null}
    </section>
  );
}
