/**
 * apps/dashboard/src/lib/auth.ts
 *
 * Single source of truth for the William / Jarvis dashboard's client-side
 * session: what it looks like, where it lives (localStorage/sessionStorage
 * under "william.session"), and how pages decide whether a signed-in user
 * is allowed to see a given screen.
 *
 * This mirrors the SessionData shape and storage convention that already
 * existed independently in dashboard/page.tsx, agents/page.tsx,
 * memory/page.tsx, agent-permissions/page.tsx, and login/page.tsx -- those
 * pages agreed on the wire format without sharing code. Centralizing it here
 * means new pages don't have to re-derive it, and a change to the session
 * shape only has to happen once.
 */

export type UserRole = "owner" | "admin" | "member" | "viewer";
export type UserPlan = "free" | "starter" | "pro" | "enterprise";
export type SubscriptionStatus = "active" | "trialing" | "past_due" | "canceled";

export type SessionData = {
  accessToken: string;
  refreshToken?: string;
  user_id: string;
  workspace_id: string;
  email: string;
  name: string;
  role: UserRole;
  plan: UserPlan;
  subscription_status: SubscriptionStatus;
  permissions: string[];
  workspace_name: string;
  workspace_slug: string;
  saved_at: string;
};

const SESSION_KEY = "william.session";
const ACCESS_TOKEN_KEY = "william.access_token";
const REFRESH_TOKEN_KEY = "william.refresh_token";

// Baseline permissions implied by role, in case a membership's explicit
// `permissions` list (returned by the backend) doesn't already carry them.
// Matches apps/api/routes/auth.py's ROLE_RANK ordering (owner > admin >
// member > viewer).
const ROLE_PERMISSIONS: Record<UserRole, string[]> = {
  owner: [
    "dashboard:read",
    "workspace:read",
    "tasks:write",
    "agents:run",
    "security:approve",
    "audit:read",
    "memory:read",
    "billing:manage",
  ],
  admin: [
    "dashboard:read",
    "workspace:read",
    "tasks:write",
    "agents:run",
    "audit:read",
    "memory:read",
  ],
  member: ["dashboard:read", "workspace:read", "tasks:write", "agents:run", "memory:read"],
  viewer: ["dashboard:read", "workspace:read", "memory:read"],
};

const PLAN_ACCESS: Record<UserPlan, boolean> = {
  free: true,
  starter: true,
  pro: true,
  enterprise: true,
};

function isValidSession(value: unknown): value is SessionData {
  if (!value || typeof value !== "object") return false;
  const session = value as Partial<SessionData>;

  return Boolean(
    session.accessToken &&
      session.user_id &&
      session.workspace_id &&
      session.role &&
      session.plan &&
      session.subscription_status &&
      ["active", "trialing", "past_due", "canceled"].includes(session.subscription_status),
  );
}

export function readSession(): SessionData | null {
  if (typeof window === "undefined") return null;

  const raw =
    window.localStorage.getItem(SESSION_KEY) || window.sessionStorage.getItem(SESSION_KEY);

  if (!raw) return null;

  try {
    const parsed = JSON.parse(raw);
    return isValidSession(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

export function saveSession(session: SessionData, rememberMe: boolean): void {
  if (typeof window === "undefined") return;

  const selectedStorage = rememberMe ? window.localStorage : window.sessionStorage;
  const otherStorage = rememberMe ? window.sessionStorage : window.localStorage;

  otherStorage.removeItem(SESSION_KEY);
  otherStorage.removeItem(ACCESS_TOKEN_KEY);
  otherStorage.removeItem(REFRESH_TOKEN_KEY);

  selectedStorage.setItem(SESSION_KEY, JSON.stringify(session));
  selectedStorage.setItem(ACCESS_TOKEN_KEY, session.accessToken);

  if (session.refreshToken) {
    selectedStorage.setItem(REFRESH_TOKEN_KEY, session.refreshToken);
  }
}

export function clearSession(): void {
  if (typeof window === "undefined") return;

  window.localStorage.removeItem(SESSION_KEY);
  window.localStorage.removeItem(ACCESS_TOKEN_KEY);
  window.localStorage.removeItem(REFRESH_TOKEN_KEY);
  window.sessionStorage.removeItem(SESSION_KEY);
  window.sessionStorage.removeItem(ACCESS_TOKEN_KEY);
  window.sessionStorage.removeItem(REFRESH_TOKEN_KEY);
}

export function hasPermission(session: SessionData, permission: string): boolean {
  const sessionPermissions = new Set([
    ...(ROLE_PERMISSIONS[session.role] || []),
    ...(session.permissions || []),
  ]);

  return sessionPermissions.has(permission);
}

export type SessionAccessResult =
  | { allowed: true }
  | { allowed: false; code: string; message: string };

/** Client-side gate only -- every real authorization decision is re-checked
 * server-side against the verified access token. This exists purely to
 * avoid flashing a dashboard the backend would reject anyway. */
export function canUseDashboard(session: SessionData): SessionAccessResult {
  if (!session.user_id || !session.workspace_id) {
    return {
      allowed: false,
      code: "ISOLATION_CONTEXT_MISSING",
      message: "Session is missing user_id or workspace_id.",
    };
  }

  if (!PLAN_ACCESS[session.plan]) {
    return {
      allowed: false,
      code: "PLAN_ACCESS_DENIED",
      message: "Your plan cannot access the dashboard.",
    };
  }

  if (!["active", "trialing"].includes(session.subscription_status)) {
    return {
      allowed: false,
      code: "SUBSCRIPTION_INACTIVE",
      message: "Your workspace subscription is not active.",
    };
  }

  if (!hasPermission(session, "dashboard:read") && !hasPermission(session, "workspace:read")) {
    return {
      allowed: false,
      code: "PERMISSION_DENIED",
      message: "Your role cannot open this dashboard.",
    };
  }

  return { allowed: true };
}
