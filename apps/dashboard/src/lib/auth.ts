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

// Matches apps/api/routes/auth.py's real Role/Plan enums exactly (confirmed
// by reading the source, not guessed) -- five pages independently invented
// two different, both-wrong, 4-value vocabularies ("owner|admin|member|
// viewer" and "owner|admin|operator|viewer") before this file existed. The
// real backend has 8 roles and 5 plans; ROLE_RANK/PLAN_RANK below mirror the
// backend's own numeric ranking so `hasMinRole`/`hasMinPlan` comparisons
// stay correct even for roles/plans the older frontend code never accounted
// for (manager, developer, analyst, agent, user, business).
export type UserRole =
  | "owner"
  | "admin"
  | "manager"
  | "developer"
  | "analyst"
  | "agent"
  | "user"
  | "viewer";
export type UserPlan = "free" | "starter" | "pro" | "business" | "enterprise";
export type SubscriptionStatus = "active" | "trialing" | "past_due" | "canceled";

const ROLE_RANK: Record<UserRole, number> = {
  viewer: 10,
  user: 20,
  agent: 30,
  analyst: 35,
  developer: 40,
  manager: 50,
  admin: 80,
  owner: 100,
};

const PLAN_RANK: Record<UserPlan, number> = {
  free: 10,
  starter: 20,
  pro: 40,
  business: 70,
  enterprise: 100,
};

export function hasMinRole(role: UserRole, requiredRole: UserRole): boolean {
  return (ROLE_RANK[role] ?? 0) >= (ROLE_RANK[requiredRole] ?? 0);
}

export function hasMinPlan(plan: UserPlan, requiredPlan: UserPlan): boolean {
  return (PLAN_RANK[plan] ?? 0) >= (PLAN_RANK[requiredPlan] ?? 0);
}

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

// Baseline permissions implied by rank, in case a membership's explicit
// `permissions` list (returned by the backend) doesn't already carry them.
// There is no backend-side static role -> permissions table to mirror here
// (apps/api/routes/auth.py only grants a fixed permission set to a brand
// new OWNER on self-registration: workspace:read, workspace:update,
// agent:execute, session:manage, billing:read -- invited members get
// whatever list the inviter passes, per-membership, with no default), so
// this is a rank-threshold approximation covering the permission strings
// the dashboard pages actually gate on. It only affects what the UI shows;
// every sensitive action is re-authorized server-side against ROLE_RANK
// regardless of what this table says.
function permissionsForRank(rank: number): string[] {
  const permissions = ["dashboard:read", "workspace:read", "memory:read"];
  if (rank >= ROLE_RANK.user) permissions.push("tasks:write", "agents:run", "agent:execute");
  if (rank >= ROLE_RANK.manager) permissions.push("audit:read", "billing:read");
  if (rank >= ROLE_RANK.admin) permissions.push("security:approve", "workspace:update", "session:manage");
  if (rank >= ROLE_RANK.owner) permissions.push("billing:manage");
  return permissions;
}

const ROLE_PERMISSIONS: Record<UserRole, string[]> = Object.fromEntries(
  (Object.keys(ROLE_RANK) as UserRole[]).map((role) => [role, permissionsForRank(ROLE_RANK[role])]),
) as Record<UserRole, string[]>;

const PLAN_ACCESS: Record<UserPlan, boolean> = {
  free: true,
  starter: true,
  pro: true,
  business: true,
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
