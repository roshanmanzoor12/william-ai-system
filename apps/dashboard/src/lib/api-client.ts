/**
 * apps/dashboard/src/lib/api-client.ts
 *
 * Single shared HTTP client for every dashboard page. Replaces the ad-hoc
 * per-page `fetch()` wrappers that had drifted into three different (and
 * two actively broken) shapes:
 *   - dashboard/agents/memory/agent-permissions already sent a real
 *     `Authorization: Bearer <token>` header (correct).
 *   - analytics/workflows/crm/tasks sent spoofable `X-User-Id` /
 *     `X-Workspace-Id` headers instead -- the real backend's
 *     get_current_auth_context() (apps/api/routes/auth.py) never reads
 *     those headers at all, so every request from these pages was
 *     rejected with 401 ACCESS_TOKEN_REQUIRED.
 *   - billing/finance/creator/calls sent no auth header at all and relied
 *     on `credentials: "include"` cookies the backend doesn't issue.
 *
 * Every backend route (apps/api/main.py's response_success/response_error,
 * apps/api/routes/auth.py's api_success/raise_api_error, and every other
 * routes/*.py module) returns the same envelope:
 *   { success, message, data, error: { code, details } | null, metadata }
 * This client standardizes on that shape end to end.
 */

import axios, { AxiosError, AxiosRequestConfig, AxiosInstance } from "axios";
import {
  SessionData,
  UserRole,
  UserPlan,
  SubscriptionStatus,
  readSession,
  saveSession,
  clearSession,
} from "./auth";

export type ApiErrorBody = {
  code: string;
  details?: unknown;
};

export type ApiEnvelope<T> = {
  success: boolean;
  message: string;
  data: T;
  error: ApiErrorBody | null;
  metadata: Record<string, unknown>;
};

export type ApiResult<T> =
  | {
      success: true;
      data: T;
      message: string;
      metadata: Record<string, unknown>;
    }
  | {
      success: false;
      error: ApiErrorBody & { message: string };
      metadata: Record<string, unknown>;
    };

// NEXT_PUBLIC_API_BASE_URL already includes the API prefix, e.g.
// "http://localhost:8000/api/v1" (see .env.example at the repo root and
// under apps/dashboard/) -- every path passed to this client is relative
// to that, e.g. request("/tasks") -> {API_BASE_URL}/tasks.
export const API_BASE_URL = (
  process.env.NEXT_PUBLIC_API_BASE_URL || ""
).replace(/\/$/, "");

const http: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  headers: { "Content-Type": "application/json" },
  timeout: 30000,
});

let refreshPromise: Promise<string | null> | null = null;

function safeErrorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return "Unexpected error.";
}

http.interceptors.request.use((config) => {
  const session = readSession();

  if (session?.accessToken) {
    config.headers.Authorization = `Bearer ${session.accessToken}`;
  }

  return config;
});

async function performRefresh(session: SessionData): Promise<string | null> {
  if (!session.refreshToken) return null;

  try {
    const response = await axios.post<ApiEnvelope<RawLoginData>>(
      `${API_BASE_URL}/auth/refresh`,
      {
        refresh_token: session.refreshToken,
        workspace_id: session.workspace_id,
      },
      { headers: { "Content-Type": "application/json" } },
    );

    const body = response.data;
    if (!body.success || !body.data) return null;

    const nextSession = normalizeAuthPayload(
      body.data,
      session.subscription_status,
    );
    const rememberedInLocalStorage =
      typeof window !== "undefined" &&
      Boolean(window.localStorage.getItem("william.session"));
    saveSession(nextSession, rememberedInLocalStorage);

    return nextSession.accessToken;
  } catch {
    return null;
  }
}

http.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as
      | (AxiosRequestConfig & { _retried?: boolean })
      | undefined;
    const status = error.response?.status;
    const session = readSession();

    if (
      status === 401 &&
      originalRequest &&
      !originalRequest._retried &&
      session?.refreshToken
    ) {
      originalRequest._retried = true;

      if (!refreshPromise) {
        refreshPromise = performRefresh(session).finally(() => {
          refreshPromise = null;
        });
      }

      const newAccessToken = await refreshPromise;

      if (newAccessToken) {
        originalRequest.headers = originalRequest.headers || {};
        originalRequest.headers.Authorization = `Bearer ${newAccessToken}`;
        return http.request(originalRequest);
      }

      clearSession();
      if (typeof window !== "undefined") window.location.assign("/login");
    }

    if (status === 401 && (!session || !session.refreshToken)) {
      clearSession();
      if (
        typeof window !== "undefined" &&
        window.location.pathname !== "/login"
      ) {
        window.location.assign("/login");
      }
    }

    return Promise.reject(error);
  },
);

/**
 * Generic authenticated request. Every domain-specific helper below is a
 * thin wrapper over this. `path` is relative to API_BASE_URL, e.g. "/tasks"
 * or "/agents/health".
 */
export async function request<T>(
  path: string,
  config: AxiosRequestConfig = {},
): Promise<ApiResult<T>> {
  try {
    const response = await http.request<ApiEnvelope<T>>({
      url: path,
      ...config,
    });
    const body = response.data;

    if (body.success) {
      return {
        success: true,
        data: body.data,
        message: body.message,
        metadata: body.metadata,
      };
    }

    return {
      success: false,
      error: {
        code: body.error?.code || "UNKNOWN_ERROR",
        details: body.error?.details,
        message: body.message,
      },
      metadata: body.metadata || {},
    };
  } catch (error) {
    const axiosError = error as AxiosError<ApiEnvelope<T>>;
    const responseBody = axiosError.response?.data;

    if (
      responseBody &&
      typeof responseBody === "object" &&
      "success" in responseBody
    ) {
      return {
        success: false,
        error: {
          code: responseBody.error?.code || "HTTP_ERROR",
          details: responseBody.error?.details,
          message: responseBody.message || "Request failed.",
        },
        metadata: responseBody.metadata || {},
      };
    }

    return {
      success: false,
      error: { code: "NETWORK_ERROR", message: safeErrorMessage(error) },
      metadata: {},
    };
  }
}

export const get = <T>(path: string, config?: AxiosRequestConfig) =>
  request<T>(path, { ...config, method: "GET" });

export const post = <T>(
  path: string,
  data?: unknown,
  config?: AxiosRequestConfig,
) => request<T>(path, { ...config, method: "POST", data });

export const patch = <T>(
  path: string,
  data?: unknown,
  config?: AxiosRequestConfig,
) => request<T>(path, { ...config, method: "PATCH", data });

export const del = <T>(path: string, config?: AxiosRequestConfig) =>
  request<T>(path, { ...config, method: "DELETE" });

// =============================================================================
// Auth
// =============================================================================

type RawUserRecord = {
  user_id: string;
  email: string;
  full_name: string;
  is_active: boolean;
};

type RawWorkspaceRecord = {
  workspace_id: string;
  name: string;
  slug?: string;
  plan: string;
  subscription_status: string;
};

type RawMembershipRecord = {
  role: string;
  plan: string;
  permissions: string[];
};

type RawLoginData = {
  user: RawUserRecord;
  workspace: RawWorkspaceRecord;
  membership: RawMembershipRecord;
  tokens: {
    access_token: string;
    refresh_token: string;
    token_type: string;
    access_expires_at: number;
    refresh_expires_at: number;
  };
};

const ALLOWED_ROLES: UserRole[] = [
  "owner",
  "admin",
  "manager",
  "developer",
  "analyst",
  "agent",
  "user",
  "viewer",
];
const ALLOWED_PLANS: UserPlan[] = [
  "free",
  "starter",
  "pro",
  "business",
  "enterprise",
];
const ALLOWED_SUBSCRIPTION_STATUSES: SubscriptionStatus[] = [
  "active",
  "trialing",
  "past_due",
  "canceled",
];

/**
 * apps/api/routes/auth.py's login/register/refresh responses nest tokens
 * under `data.tokens.access_token` and put role/plan/permissions under
 * `data.membership`, not a flat `data.subscription` object. `workspace.slug`
 * is a real, unique field (database/models/workspace.py::Workspace.slug,
 * auto-derived from the workspace name) -- fall back to workspace_id only
 * for defensive safety against an old/cached response shape, not because
 * the backend lacks the field. This is the one place that translation
 * happens, so every page can keep reading the already-agreed-on flat
 * SessionData shape.
 */
function normalizeAuthPayload(
  raw: RawLoginData,
  fallbackSubscriptionStatus?: SubscriptionStatus,
): SessionData {
  const role = (ALLOWED_ROLES as string[]).includes(raw.membership.role)
    ? (raw.membership.role as UserRole)
    : "viewer";
  const plan = (ALLOWED_PLANS as string[]).includes(raw.membership.plan)
    ? (raw.membership.plan as UserPlan)
    : "free";
  const subscriptionStatus = (
    ALLOWED_SUBSCRIPTION_STATUSES as string[]
  ).includes(raw.workspace.subscription_status)
    ? (raw.workspace.subscription_status as SubscriptionStatus)
    : fallbackSubscriptionStatus || "active";

  return {
    accessToken: raw.tokens.access_token,
    refreshToken: raw.tokens.refresh_token,
    user_id: raw.user.user_id,
    workspace_id: raw.workspace.workspace_id,
    email: raw.user.email,
    name: raw.user.full_name,
    role,
    plan,
    subscription_status: subscriptionStatus,
    permissions: raw.membership.permissions || [],
    workspace_name: raw.workspace.name,
    workspace_slug: raw.workspace.slug || raw.workspace.workspace_id,
    saved_at: new Date().toISOString(),
  };
}

function mapAuthResult(
  result: ApiResult<RawLoginData>,
): ApiResult<SessionData> {
  if (result.success === false) {
    return { success: false, error: result.error, metadata: result.metadata };
  }

  return {
    success: true,
    data: normalizeAuthPayload(result.data),
    message: result.message,
    metadata: result.metadata,
  };
}

export const authApi = {
  async register(payload: {
    email: string;
    password: string;
    full_name: string;
    workspace_name?: string;
    invite_code?: string;
  }): Promise<ApiResult<SessionData>> {
    const result = await request<RawLoginData>("/auth/register", {
      method: "POST",
      data: payload,
    });
    return mapAuthResult(result);
  },

  async login(payload: {
    email: string;
    password: string;
    workspace_id?: string;
  }): Promise<ApiResult<SessionData>> {
    const result = await request<RawLoginData>("/auth/login", {
      method: "POST",
      data: payload,
    });
    return mapAuthResult(result);
  },

  async logout(
    refreshToken?: string,
    logoutAllSessions = false,
  ): Promise<ApiResult<Record<string, unknown>>> {
    return request("/auth/logout", {
      method: "POST",
      data: {
        refresh_token: refreshToken,
        logout_all_sessions: logoutAllSessions,
      },
    });
  },

  async me(): Promise<
    ApiResult<{
      user: RawUserRecord;
      workspace: RawWorkspaceRecord;
      membership: RawMembershipRecord;
    }>
  > {
    return request("/auth/me", { method: "GET" });
  },
};

// =============================================================================
// Domain helpers
//
// Kept intentionally thin: each backend router (apps/api/routes/*.py) has
// its own request/response Pydantic models with dozens of fields, and
// duplicating all of them here would drift out of sync the moment either
// side changes. Callers supply the response type via the generic and get
// the shared auth/refresh/error handling for free. Paths are relative to
// API_BASE_URL (which already includes "/api/v1"), matching the mount
// table in apps/api/main.py's OPTIONAL_ROUTERS / built-in routers.
// =============================================================================

export const dashboardApi = {
  summary: <T>() => get<T>("/dashboard/summary"),
};

export const agentsApi = {
  list: <T>() => get<T>("/agents"),
  catalog: <T>() => get<T>("/agents/catalog"),
  health: <T>() => get<T>("/agents/health"),
  get: <T>(agentName: string) =>
    get<T>(`/agents/${encodeURIComponent(agentName)}`),
  execute: <T>(payload: unknown) => post<T>("/agents/execute", payload),
  status: <T>() => get<T>("/agents/status"),
};

export const tasksApi = {
  list: <T>(params?: Record<string, string | number | boolean | undefined>) =>
    get<T>("/tasks", { params }),
  get: <T>(taskId: string) => get<T>(`/tasks/${encodeURIComponent(taskId)}`),
  create: <T>(payload: unknown) => post<T>("/tasks", payload),
  createAndRun: <T>(payload: unknown) => post<T>("/tasks/run", payload),
  run: <T>(taskId: string) =>
    post<T>(`/tasks/${encodeURIComponent(taskId)}/run`),
  cancel: <T>(taskId: string) =>
    post<T>(`/tasks/${encodeURIComponent(taskId)}/cancel`),
  events: <T>(taskId: string) =>
    get<T>(`/tasks/${encodeURIComponent(taskId)}/events`),
  audit: <T>() => get<T>("/tasks/audit"),
};

export const memoryApi = {
  save: <T>(payload: unknown) => post<T>("/memory/save", payload),
  search: <T>(payload: unknown) => post<T>("/memory/search", payload),
  list: <T>(params?: Record<string, string | number | boolean | undefined>) =>
    get<T>("/memory", { params }),
  get: <T>(memoryId: string) =>
    get<T>(`/memory/${encodeURIComponent(memoryId)}`),
  remove: <T>(memoryId: string) =>
    del<T>(`/memory/${encodeURIComponent(memoryId)}`),
};

export const securityApi = {
  createApproval: <T>(payload: unknown) =>
    post<T>("/security/approvals", payload),
  decide: <T>(payload: unknown) => post<T>("/security/decide", payload),
  listApprovals: <T>(
    params?: Record<string, string | number | boolean | undefined>,
  ) => get<T>("/security/approvals", { params }),
  getApproval: <T>(approvalId: string) =>
    get<T>(`/security/approvals/${encodeURIComponent(approvalId)}`),
  audit: <T>(params?: Record<string, string | number | boolean | undefined>) =>
    get<T>("/security/audit", { params }),
};

export const workflowsApi = {
  listTemplates: <T>() => get<T>("/workflows/templates"),
  createTemplate: <T>(payload: unknown) =>
    post<T>("/workflows/templates", payload),
  run: <T>(payload: unknown) => post<T>("/workflows/run", payload),
  listRuns: <T>(
    params?: Record<string, string | number | boolean | undefined>,
  ) => get<T>("/workflows/runs", { params }),
  getRun: <T>(runId: string) =>
    get<T>(`/workflows/runs/${encodeURIComponent(runId)}`),
  listWebhooks: <T>() => get<T>("/workflows/webhooks"),
};

export const auditApi = {
  list: <T>(params?: Record<string, string | number | boolean | undefined>) =>
    get<T>("/audit", { params }),
  get: <T>(eventId: string) => get<T>(`/audit/${encodeURIComponent(eventId)}`),
};

export const analyticsApi = {
  summary: <T>(
    params?: Record<string, string | number | boolean | undefined>,
  ) => get<T>("/analytics/summary", { params }),
};

export const billingApi = {
  plans: <T>() => get<T>("/billing/plans"),
  subscription: <T>() => get<T>("/billing/subscription"),
  createSubscription: <T>(payload: unknown) =>
    post<T>("/billing/subscription", payload),
  cancelSubscription: <T>() => post<T>("/billing/subscription/cancel"),
  usage: <T>() => get<T>("/billing/usage"),
  invoices: <T>(
    params?: Record<string, string | number | boolean | undefined>,
  ) => get<T>("/billing/invoices", { params }),
  summaryReport: <T>() => get<T>("/billing/summary"),
};

export const subscriptionsApi = {
  plan: <T>() => get<T>("/subscriptions/plan"),
  accessCheck: <T>(payload: unknown) =>
    post<T>("/subscriptions/access-check", payload),
  dashboard: <T>() => get<T>("/subscriptions/dashboard"),
};

export const filesApi = {
  upload: <T>(formData: FormData) =>
    request<T>("/files/upload", {
      method: "POST",
      data: formData,
      headers: { "Content-Type": "multipart/form-data" },
    }),
  list: <T>() => get<T>("/files"),
  download: <T>(fileId: string) =>
    get<T>(`/files/${encodeURIComponent(fileId)}/download`),
  remove: <T>(fileId: string) => del<T>(`/files/${encodeURIComponent(fileId)}`),
};

export const usersApi = {
  me: <T>() => get<T>("/users/me"),
  updateMe: <T>(payload: unknown) => patch<T>("/users/me", payload),
  list: <T>() => get<T>("/users"),
};

export const workspacesApi = {
  current: <T>() => get<T>("/workspaces/current"),
  updateCurrent: <T>(payload: unknown) =>
    patch<T>("/workspaces/current", payload),
  members: <T>() => get<T>("/workspaces/current/members"),
  inviteMember: <T>(payload: unknown) =>
    post<T>("/workspaces/current/invites", payload),
};

// =============================================================================
// Voice (Phase 9 -- apps/api/routes/voice.py, mounted at /voice/*)
//
// Shapes below mirror apps/api/routes/voice.py's Pydantic models and
// database/models/voice.py's to_dict() output exactly (read directly from
// source, not guessed). Every endpoint requires the same real
// Authorization: Bearer <token> header the rest of this client already
// attaches via the request() interceptor.
// =============================================================================

export type VoiceMode =
  | "disabled"
  | "push_to_talk"
  | "wake_word_admin"
  | "wake_word_trusted_users"
  | "continuous_conversation"
  | "standby";

export type VoiceDependencyStatusValue =
  | "available"
  | "configured"
  | "external_dependency_required";

export type VoiceDependencyStatus = {
  wake_word_engine: VoiceDependencyStatusValue;
  audio_input_worker: VoiceDependencyStatusValue;
  stt_provider: VoiceDependencyStatusValue;
  tts_provider: VoiceDependencyStatusValue;
  speaker_recognition_provider: VoiceDependencyStatusValue;
};

export type VoiceRuntimeState =
  | "disabled"
  | "push_to_talk"
  | "worker_offline"
  | "dependency_required"
  | "listening"
  | "standby";

export type VoiceSettings = {
  id: string;
  workspace_id: string;
  mode: VoiceMode;
  wake_word: string;
  requires_security_approval: boolean;
  dependency_status: VoiceDependencyStatus;
  voice_worker_connected: boolean;
  voice_worker_last_seen_at: string | null;
  last_wake_event_at: string | null;
  last_recognized_speaker_profile_id: string | null;
  last_speaker_display_name: string | null;
  last_detected_language: string | null;
  last_command_transcript: string | null;
  last_routed_agent: string | null;
  last_response_text: string | null;
  last_error_message: string | null;
  last_error_at: string | null;
  created_at: string;
  updated_at: string;
};

export type VoiceStatusData = {
  settings: VoiceSettings;
  wake_word_default: string;
  // Flattened, dashboard-shaped view of the same settings row (see
  // apps/api/routes/voice.py::get_voice_status) -- prefer these over
  // digging into `settings` when driving the Voice Control UI's states.
  mode: VoiceMode;
  enabled: boolean;
  runtime_state: VoiceRuntimeState;
  wake_word_enabled: boolean;
  wake_word_phrase: string;
  worker_connected: boolean;
  worker_last_seen_at: string | null;
  dependencies: VoiceDependencyStatus;
  missing_dependencies: string[];
  active_sessions: number;
  last_wake_event: string | null;
  last_command: string | null;
  last_detected_language: string | null;
  last_speaker_name: string | null;
  last_routed_agent: string | null;
  last_error: string | null;
  user_id: string;
  workspace_id: string;
};

export type VoiceHeartbeatData = {
  worker_connected: boolean;
  worker_last_seen_at: string | null;
};

export type VoiceConfigUpdateData = {
  settings: VoiceSettings;
  requires_approval: boolean;
  approved: boolean;
};

// The 14 real agent keys from AGENT_CATALOG (apps/api/routes/agents.py),
// used for the allowed_agents/blocked_agents multi-selects.
export const VOICE_AGENT_KEYS = [
  "voice",
  "system",
  "browser",
  "code",
  "memory",
  "security",
  "verification",
  "visual",
  "workflow",
  "hologram",
  "call",
  "business",
  "finance",
  "creator",
] as const;

export type VoiceAgentKey = (typeof VOICE_AGENT_KEYS)[number];

export type VoiceProfileRole =
  | "owner"
  | "admin"
  | "trusted_developer"
  | "trusted_manager"
  | "trusted_assistant"
  | "guest";

export type VoiceProfileStatus = "active" | "disabled" | "revoked";

export type VoiceprintStatus =
  | "enrolled"
  | "pending"
  | "external_dependency_required"
  | "disabled";

export type VoiceProfile = {
  id: string;
  workspace_id: string;
  created_by_user_id: string;
  linked_user_id: string | null;
  display_name: string;
  role: VoiceProfileRole;
  allowed_agents: string[];
  blocked_agents: string[];
  allowed_capabilities: string[];
  blocked_capabilities: string[];
  can_use_voice: boolean;
  can_use_wake_word: boolean;
  can_access_private_memory: boolean;
  can_access_finance: boolean;
  can_access_system_agent: boolean;
  can_run_code_agent: boolean;
  requires_approval_for_risky_actions: boolean;
  preferred_language: string;
  reply_language_mode: string;
  voiceprint_status: VoiceprintStatus;
  voiceprint_reference_id: string | null;
  status: VoiceProfileStatus;
  created_at: string;
  updated_at: string;
  last_used_at: string | null;
};

export type VoiceProfileListData = {
  profiles: VoiceProfile[];
  count: number;
};

export type VoiceProfileMutationData = { profile: VoiceProfile };

export type VoiceProfileCreatePayload = {
  display_name: string;
  role?: VoiceProfileRole;
  linked_user_id?: string | null;
  allowed_agents?: string[];
  blocked_agents?: string[];
  allowed_capabilities?: string[];
  blocked_capabilities?: string[];
  can_use_voice?: boolean;
  can_use_wake_word?: boolean;
  can_access_private_memory?: boolean;
  can_access_finance?: boolean;
  can_access_system_agent?: boolean;
  can_run_code_agent?: boolean;
  requires_approval_for_risky_actions?: boolean;
  preferred_language?: string;
  reply_language_mode?: string;
};

export type VoiceProfileUpdatePayload = Partial<VoiceProfileCreatePayload> & {
  status?: VoiceProfileStatus;
};

export type VoiceCommandRequestPayload = {
  transcript: string;
  detected_language?: string;
  speaker_profile_id?: string;
  session_id?: string;
  wake_word?: string;
};

export type VoicePushToTalkPayload = {
  transcript: string;
  detected_language?: string;
  session_id?: string;
};

export type VoiceSpeechOutputStatus =
  | "available"
  | "external_dependency_required";

export type VoiceCommandResponseData = {
  success: boolean;
  message: string;
  response_text: string;
  reply_language: string;
  speech_output_status: VoiceSpeechOutputStatus;
  master_result: unknown;
  request_id: string;
};

export type VoiceEnrollStartPayload = {
  profile_id?: string;
  display_name: string;
};

export type VoiceEnrollDependencyStatus = {
  configured_providers: string[];
  provider_configured: boolean;
  dev_bypass_available: boolean;
};

export type VoiceEnrollStartData = {
  profile_id: string;
  dependency_status: VoiceEnrollDependencyStatus;
};

export type VoiceEnrollCompletePayload = {
  profile_id: string;
  voice_sample_ref: string;
};

export type VoiceEnrollCompleteData = {
  profile: VoiceProfile;
  enrollment_result: Record<string, unknown>;
};

// Deliberately NOT generic (unlike the domain helpers above): every voice
// endpoint has one real, concrete response shape read directly from
// apps/api/routes/voice.py, so callers get real narrowing on
// `response.success` for free instead of having to pass a type argument.
export const voiceApi = {
  status: () => get<VoiceStatusData>("/voice/status"),

  updateConfig: (payload: { mode?: VoiceMode; wake_word?: string }) =>
    post<VoiceConfigUpdateData>("/voice/config", payload),

  listProfiles: () => get<VoiceProfileListData>("/voice/profiles"),

  createProfile: (payload: VoiceProfileCreatePayload) =>
    post<VoiceProfileMutationData>("/voice/profiles", payload),

  updateProfile: (profileId: string, payload: VoiceProfileUpdatePayload) =>
    patch<VoiceProfileMutationData>(
      `/voice/profiles/${encodeURIComponent(profileId)}`,
      payload,
    ),

  deleteProfile: (profileId: string, hardDelete = false) =>
    del<VoiceProfileMutationData>(
      `/voice/profiles/${encodeURIComponent(profileId)}?hard_delete=${
        hardDelete ? "true" : "false"
      }`,
    ),

  sendCommand: (payload: VoiceCommandRequestPayload) =>
    post<VoiceCommandResponseData>("/voice/command", payload),

  sendPushToTalkText: (payload: VoicePushToTalkPayload) =>
    post<VoiceCommandResponseData>("/voice/push-to-talk/text", payload),

  enrollStart: (payload: VoiceEnrollStartPayload) =>
    post<VoiceEnrollStartData>("/voice/enroll/start", payload),

  enrollComplete: (payload: VoiceEnrollCompletePayload) =>
    post<VoiceEnrollCompleteData>("/voice/enroll/complete", payload),

  workerHeartbeat: () => post<VoiceHeartbeatData>("/voice/worker/heartbeat", {}),
};
