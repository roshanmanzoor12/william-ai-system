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
  | { success: true; data: T; message: string; metadata: Record<string, unknown> }
  | { success: false; error: ApiErrorBody & { message: string }; metadata: Record<string, unknown> };

// NEXT_PUBLIC_API_BASE_URL already includes the API prefix, e.g.
// "http://localhost:8000/api/v1" (see .env.example at the repo root and
// under apps/dashboard/) -- every path passed to this client is relative
// to that, e.g. request("/tasks") -> {API_BASE_URL}/tasks.
export const API_BASE_URL = (process.env.NEXT_PUBLIC_API_BASE_URL || "").replace(/\/$/, "");

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
      { refresh_token: session.refreshToken, workspace_id: session.workspace_id },
      { headers: { "Content-Type": "application/json" } },
    );

    const body = response.data;
    if (!body.success || !body.data) return null;

    const nextSession = normalizeAuthPayload(body.data, session.subscription_status);
    const rememberedInLocalStorage =
      typeof window !== "undefined" && Boolean(window.localStorage.getItem("william.session"));
    saveSession(nextSession, rememberedInLocalStorage);

    return nextSession.accessToken;
  } catch {
    return null;
  }
}

http.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as (AxiosRequestConfig & { _retried?: boolean }) | undefined;
    const status = error.response?.status;
    const session = readSession();

    if (status === 401 && originalRequest && !originalRequest._retried && session?.refreshToken) {
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
      if (typeof window !== "undefined" && window.location.pathname !== "/login") {
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
    const response = await http.request<ApiEnvelope<T>>({ url: path, ...config });
    const body = response.data;

    if (body.success) {
      return { success: true, data: body.data, message: body.message, metadata: body.metadata };
    }

    return {
      success: false,
      error: { code: body.error?.code || "UNKNOWN_ERROR", details: body.error?.details, message: body.message },
      metadata: body.metadata || {},
    };
  } catch (error) {
    const axiosError = error as AxiosError<ApiEnvelope<T>>;
    const responseBody = axiosError.response?.data;

    if (responseBody && typeof responseBody === "object" && "success" in responseBody) {
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

export const post = <T>(path: string, data?: unknown, config?: AxiosRequestConfig) =>
  request<T>(path, { ...config, method: "POST", data });

export const patch = <T>(path: string, data?: unknown, config?: AxiosRequestConfig) =>
  request<T>(path, { ...config, method: "PATCH", data });

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

const ALLOWED_ROLES: UserRole[] = ["owner", "admin", "member", "viewer"];
const ALLOWED_PLANS: UserPlan[] = ["free", "starter", "pro", "enterprise"];
const ALLOWED_SUBSCRIPTION_STATUSES: SubscriptionStatus[] = [
  "active",
  "trialing",
  "past_due",
  "canceled",
];

/**
 * apps/api/routes/auth.py's login/register/refresh responses nest tokens
 * under `data.tokens.access_token` and put role/plan/permissions under
 * `data.membership`, not a flat `data.subscription` object -- there is no
 * `workspace.slug` field anywhere in the backend (WorkspaceRecord has no
 * slug concept), so workspace_id is reused for display purposes rather
 * than inventing one. This is the one place that translation happens, so
 * every page can keep reading the already-agreed-on flat SessionData shape.
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
  const subscriptionStatus = (ALLOWED_SUBSCRIPTION_STATUSES as string[]).includes(
    raw.workspace.subscription_status,
  )
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
    workspace_slug: raw.workspace.workspace_id,
    saved_at: new Date().toISOString(),
  };
}

function mapAuthResult(result: ApiResult<RawLoginData>): ApiResult<SessionData> {
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
    const result = await request<RawLoginData>("/auth/register", { method: "POST", data: payload });
    return mapAuthResult(result);
  },

  async login(payload: {
    email: string;
    password: string;
    workspace_id?: string;
  }): Promise<ApiResult<SessionData>> {
    const result = await request<RawLoginData>("/auth/login", { method: "POST", data: payload });
    return mapAuthResult(result);
  },

  async logout(refreshToken?: string, logoutAllSessions = false): Promise<ApiResult<Record<string, unknown>>> {
    return request("/auth/logout", {
      method: "POST",
      data: { refresh_token: refreshToken, logout_all_sessions: logoutAllSessions },
    });
  },

  async me(): Promise<ApiResult<{ user: RawUserRecord; workspace: RawWorkspaceRecord; membership: RawMembershipRecord }>> {
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
  get: <T>(agentName: string) => get<T>(`/agents/${encodeURIComponent(agentName)}`),
  execute: <T>(payload: unknown) => post<T>("/agents/execute", payload),
  status: <T>() => get<T>("/agents/status"),
};

export const tasksApi = {
  list: <T>(params?: Record<string, string | number | boolean | undefined>) =>
    get<T>("/tasks", { params }),
  get: <T>(taskId: string) => get<T>(`/tasks/${encodeURIComponent(taskId)}`),
  create: <T>(payload: unknown) => post<T>("/tasks", payload),
  createAndRun: <T>(payload: unknown) => post<T>("/tasks/run", payload),
  run: <T>(taskId: string) => post<T>(`/tasks/${encodeURIComponent(taskId)}/run`),
  cancel: <T>(taskId: string) => post<T>(`/tasks/${encodeURIComponent(taskId)}/cancel`),
  events: <T>(taskId: string) => get<T>(`/tasks/${encodeURIComponent(taskId)}/events`),
  audit: <T>() => get<T>("/tasks/audit"),
};

export const memoryApi = {
  save: <T>(payload: unknown) => post<T>("/memory/save", payload),
  search: <T>(payload: unknown) => post<T>("/memory/search", payload),
  list: <T>(params?: Record<string, string | number | boolean | undefined>) =>
    get<T>("/memory", { params }),
  get: <T>(memoryId: string) => get<T>(`/memory/${encodeURIComponent(memoryId)}`),
  remove: <T>(memoryId: string) => del<T>(`/memory/${encodeURIComponent(memoryId)}`),
};

export const securityApi = {
  createApproval: <T>(payload: unknown) => post<T>("/security/approvals", payload),
  decide: <T>(payload: unknown) => post<T>("/security/decide", payload),
  listApprovals: <T>(params?: Record<string, string | number | boolean | undefined>) =>
    get<T>("/security/approvals", { params }),
  getApproval: <T>(approvalId: string) => get<T>(`/security/approvals/${encodeURIComponent(approvalId)}`),
  audit: <T>(params?: Record<string, string | number | boolean | undefined>) =>
    get<T>("/security/audit", { params }),
};

export const workflowsApi = {
  listTemplates: <T>() => get<T>("/workflows/templates"),
  createTemplate: <T>(payload: unknown) => post<T>("/workflows/templates", payload),
  run: <T>(payload: unknown) => post<T>("/workflows/run", payload),
  listRuns: <T>(params?: Record<string, string | number | boolean | undefined>) =>
    get<T>("/workflows/runs", { params }),
  getRun: <T>(runId: string) => get<T>(`/workflows/runs/${encodeURIComponent(runId)}`),
  listWebhooks: <T>() => get<T>("/workflows/webhooks"),
};

export const auditApi = {
  list: <T>(params?: Record<string, string | number | boolean | undefined>) =>
    get<T>("/audit", { params }),
  get: <T>(eventId: string) => get<T>(`/audit/${encodeURIComponent(eventId)}`),
};

export const analyticsApi = {
  summary: <T>(params?: Record<string, string | number | boolean | undefined>) =>
    get<T>("/analytics/summary", { params }),
};

export const billingApi = {
  plans: <T>() => get<T>("/billing/plans"),
  subscription: <T>() => get<T>("/billing/subscription"),
  createSubscription: <T>(payload: unknown) => post<T>("/billing/subscription", payload),
  cancelSubscription: <T>() => post<T>("/billing/subscription/cancel"),
  usage: <T>() => get<T>("/billing/usage"),
  invoices: <T>(params?: Record<string, string | number | boolean | undefined>) =>
    get<T>("/billing/invoices", { params }),
  summaryReport: <T>() => get<T>("/billing/summary"),
};

export const subscriptionsApi = {
  plan: <T>() => get<T>("/subscriptions/plan"),
  accessCheck: <T>(payload: unknown) => post<T>("/subscriptions/access-check", payload),
  dashboard: <T>() => get<T>("/subscriptions/dashboard"),
};

export const filesApi = {
  upload: <T>(formData: FormData) =>
    request<T>("/files/upload", { method: "POST", data: formData, headers: { "Content-Type": "multipart/form-data" } }),
  list: <T>() => get<T>("/files"),
  download: <T>(fileId: string) => get<T>(`/files/${encodeURIComponent(fileId)}/download`),
  remove: <T>(fileId: string) => del<T>(`/files/${encodeURIComponent(fileId)}`),
};

export const usersApi = {
  me: <T>() => get<T>("/users/me"),
  updateMe: <T>(payload: unknown) => patch<T>("/users/me", payload),
  list: <T>() => get<T>("/users"),
};

export const workspacesApi = {
  current: <T>() => get<T>("/workspaces/current"),
  updateCurrent: <T>(payload: unknown) => patch<T>("/workspaces/current", payload),
  members: <T>() => get<T>("/workspaces/current/members"),
  inviteMember: <T>(payload: unknown) => post<T>("/workspaces/current/invites", payload),
};
