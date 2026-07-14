"use client";

import React, {
  FormEvent,
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";
import { useRouter } from "next/navigation";
import { EmptyState } from "@/components/state/EmptyState";
import { ErrorState } from "@/components/state/ErrorState";
import { LoadingState } from "@/components/state/LoadingState";
import { WindowsWorkerStatusCard } from "@/components/system/WindowsWorkerStatusCard";

// Previously only 4 of the real backend's 8 roles (apps/api/routes/auth.py's
// Role enum: owner/admin/manager/developer/analyst/agent/user/viewer) and
// only 4 of the real 5 plans (missing "business") were listed here. Any
// session with role="manager" (a common, real DB-level WorkspaceMemberRole)
// or a real "business"-plan workspace fell through ROLE_PERMISSIONS/
// PLAN_AGENT_LIMITS lookups below to undefined/[], which made
// validateAccess() incorrectly treat a legitimately logged-in user as
// unauthorized and bounce them back to /login.
type UserRole =
  | "owner"
  | "admin"
  | "manager"
  | "developer"
  | "analyst"
  | "agent"
  | "member"
  | "user"
  | "viewer";
type UserPlan = "free" | "starter" | "pro" | "business" | "enterprise";
type SubscriptionStatus = "active" | "trialing" | "past_due" | "canceled";

type ApiError = {
  code: string;
  message: string;
  status_code?: number;
  details?: Record<string, unknown>;
};

type ApiResponse<T> = {
  success: boolean;
  data: T | null;
  error: ApiError | null;
};

type SessionData = {
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
  // Real, DB-driven flag (database.models.user.User.is_platform_admin,
  // already returned by /auth/login's user object and persisted into
  // william.session by apps/dashboard/src/lib/api-client.ts). Used here
  // only to label the plan card "Admin Unlimited" -- the actual bypass is
  // enforced server-side (apps.api.routes.auth.platform_admin_gets_unlimited_plan),
  // never trusted client-side for access decisions.
  is_platform_admin?: boolean;
};

type AgentStatus =
  | "active"
  | "inactive"
  | "blocked"
  | "pending"
  | "maintenance";
type AgentRiskLevel = "low" | "medium" | "high";

type AgentItem = {
  agent_id: string;
  key: string;
  name: string;
  category:
    | "core"
    | "execution"
    | "memory"
    | "security"
    | "business"
    | "finance"
    | "creative"
    | "device";
  description: string;
  status: AgentStatus;
  enabled: boolean;
  requires_security_approval: boolean;
  risk_level: AgentRiskLevel;
  version?: string;
  last_run_at?: string | null;
  last_health_check_at?: string | null;
  total_tasks?: number;
  completed_tasks?: number;
  failed_tasks?: number;
  permissions?: string[];

  // Real fields sourced from the live /agents payload (undefined for the
  // offline DEFAULT_AGENTS fallback, which has no manifest to show).
  tier?: AgentDefinitionApi["tier"];
  required_plan?: string;
  required_role?: string;
  core_agent?: boolean;
  default_enabled?: boolean;
  capabilities_summary?: AgentCapabilitySummary[];
  capability_manifest?: AgentCapabilityManifestEntry[];
  capability_manifest_meta?: AgentCapabilityManifestMeta | null;
  workspace_config?: AgentWorkspaceConfigApi | null;
  access?: AgentAccessDecisionApi | null;
  health?: AgentHealthRecordApi | null;
};

type AgentsSummary = {
  totalAgents: number;
  enabledAgents: number;
  activeAgents: number;
  pendingAgents: number;
  blockedAgents: number;
  securityProtectedAgents: number;
};

type AgentActionResponse = {
  agent_id: string;
  key: string;
  status: AgentStatus;
  enabled: boolean;
  security?: {
    routed_to_security_agent: boolean;
    approved: boolean;
    risk_level: AgentRiskLevel;
  };
  verification?: {
    verification_id?: string;
    status: "prepared" | "completed" | "pending";
  };
  audit?: {
    event_id?: string;
    action: string;
  };
};

// -----------------------------------------------------------------------------
// Live `/agents` response shapes (mirrors apps/api/routes/agents.py exactly:
// AgentCapability, AgentDefinition, WorkspaceAgentConfig, AgentAccessDecision,
// AgentHealthRecord, and the capability_manifest/capability_manifest_meta
// fields added in public_agent_definition() from agents/capability_manifest.py).
// -----------------------------------------------------------------------------

type CapabilityRiskLevel = "low" | "medium" | "high" | "critical";
type CapabilityPermissionLevel =
  | "allowed"
  | "approval_required"
  | "blocked_by_default";
type CapabilityManifestStatus =
  | "available"
  | "configured"
  | "approval_required"
  | "external_dependency_required"
  | "planned"
  | "capability_unavailable";

type AgentCapabilitySummary = {
  key: string;
  label: string;
  description: string;
  sensitive: boolean;
  required_permission: string | null;
};

type AgentCapabilityManifestEntry = {
  id: string;
  name: string;
  description: string;
  risk_level: CapabilityRiskLevel;
  permission_level: CapabilityPermissionLevel;
  status: CapabilityManifestStatus;
  required_integrations: string[];
  safe_mvp_behavior: string;
  verification_method: string;
  memory_policy: string;
  audit_required: boolean;
};

type AgentCapabilityManifestMeta = {
  count: number;
  expected_count: number;
  complete: boolean;
  status_breakdown: Record<string, number>;
};

type AgentDefinitionApi = {
  agent_name: string;
  display_name: string;
  description: string;
  tier: "core" | "standard" | "super" | "future";
  required_plan: string;
  required_role: string;
  core_agent: boolean;
  default_enabled: boolean;
  capabilities: AgentCapabilitySummary[];
  capability_manifest: AgentCapabilityManifestEntry[];
  capability_manifest_meta: AgentCapabilityManifestMeta;
};

type AgentWorkspaceConfigApi = {
  workspace_id: string;
  agent_name: string;
  enabled: boolean;
  enabled_by_user_id?: string | null;
  disabled_by_user_id?: string | null;
  allowed_user_ids: string[];
  denied_user_ids: string[];
  custom_permissions: string[];
  created_at: string;
  updated_at: string;
  metadata: Record<string, unknown>;
};

type AgentAccessDecisionApi = {
  allowed: boolean;
  reason: string;
  user_id: string;
  workspace_id: string;
  agent_name: string;
  role: string;
  plan: string;
  enabled_for_workspace: boolean;
  required_role: string;
  required_plan: string;
  missing_permissions: string[];
};

type AgentHealthRecordApi = {
  agent_name: string;
  status: string;
  available: boolean;
  loaded: boolean;
  source?: string | null;
  error?: string | null;
  checked_at: string;
  metadata: Record<string, unknown>;
};

type AgentListEntryApi = {
  agent: AgentDefinitionApi;
  workspace_config: AgentWorkspaceConfigApi | null;
  access: AgentAccessDecisionApi | null;
  health: AgentHealthRecordApi | null;
};

type AgentListResponseApi = {
  agents: AgentListEntryApi[];
  count: number;
  isolation?: { user_id: string; workspace_id: string };
};

type LoadState = "checking_session" | "loading" | "ready" | "empty" | "error";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || "";

const ROLE_PERMISSIONS: Record<UserRole, string[]> = {
  owner: [
    "dashboard:read",
    "workspace:read",
    "agents:read",
    "agents:run",
    "agents:configure",
    "security:approve",
    "audit:read",
  ],
  admin: [
    "dashboard:read",
    "workspace:read",
    "agents:read",
    "agents:run",
    "agents:configure",
    "audit:read",
  ],
  manager: [
    "dashboard:read",
    "workspace:read",
    "agents:read",
    "agents:run",
    "audit:read",
  ],
  developer: ["dashboard:read", "workspace:read", "agents:read", "agents:run"],
  analyst: ["dashboard:read", "workspace:read", "agents:read"],
  agent: ["dashboard:read", "workspace:read", "agents:read"],
  member: ["dashboard:read", "workspace:read", "agents:read", "agents:run"],
  user: ["dashboard:read", "workspace:read", "agents:read", "agents:run"],
  viewer: ["dashboard:read", "workspace:read", "agents:read"],
};

// apps/api/routes/agents.py::AGENT_CATALOG has 15 real agents -- pro/
// business/enterprise previously capped at 14, one short of the real
// catalog, which silently blocked enabling the 15th agent (hologram) from
// this page even on a plan that should allow all of them.
const PLAN_AGENT_LIMITS: Record<UserPlan, number> = {
  free: 2,
  starter: 5,
  pro: 15,
  business: 15,
  enterprise: 15,
};

const DEFAULT_AGENTS: AgentItem[] = [
  {
    agent_id: "agent_master",
    key: "master_agent",
    name: "Master Agent",
    category: "core",
    description:
      "Plans, routes, and coordinates all workspace-safe agent tasks.",
    status: "active",
    enabled: true,
    requires_security_approval: false,
    risk_level: "medium",
    version: "1.0.0",
    total_tasks: 0,
    completed_tasks: 0,
    failed_tasks: 0,
  },
  {
    agent_id: "agent_security",
    key: "security_agent",
    name: "Security Agent",
    category: "security",
    description:
      "Reviews sensitive actions before execution and creates safety decisions.",
    status: "active",
    enabled: true,
    requires_security_approval: false,
    risk_level: "high",
    version: "1.0.0",
    total_tasks: 0,
    completed_tasks: 0,
    failed_tasks: 0,
  },
  {
    agent_id: "agent_verification",
    key: "verification_agent",
    name: "Verification Agent",
    category: "core",
    description: "Prepares completion evidence and confirmation payloads.",
    status: "active",
    enabled: true,
    requires_security_approval: false,
    risk_level: "medium",
    version: "1.0.0",
    total_tasks: 0,
    completed_tasks: 0,
    failed_tasks: 0,
  },
  {
    agent_id: "agent_memory",
    key: "memory_agent",
    name: "Memory Agent",
    category: "memory",
    description:
      "Stores and recalls useful context inside strict workspace boundaries.",
    status: "active",
    enabled: true,
    requires_security_approval: true,
    risk_level: "high",
    version: "1.0.0",
    total_tasks: 0,
    completed_tasks: 0,
    failed_tasks: 0,
  },
  {
    agent_id: "agent_code",
    key: "code_agent",
    name: "Code Agent",
    category: "execution",
    description:
      "Builds, reviews, and improves project code with safe execution reports.",
    status: "inactive",
    enabled: false,
    requires_security_approval: true,
    risk_level: "high",
    version: "1.0.0",
    total_tasks: 0,
    completed_tasks: 0,
    failed_tasks: 0,
  },
  {
    agent_id: "agent_browser",
    key: "browser_agent",
    name: "Browser Agent",
    category: "execution",
    description:
      "Handles browser tasks with approval gates for sensitive actions.",
    status: "inactive",
    enabled: false,
    requires_security_approval: true,
    risk_level: "high",
    version: "1.0.0",
    total_tasks: 0,
    completed_tasks: 0,
    failed_tasks: 0,
  },
  {
    agent_id: "agent_voice",
    key: "voice_agent",
    name: "Voice Agent",
    category: "device",
    description:
      "Supports voice interaction, speech output, and command handoff.",
    status: "inactive",
    enabled: false,
    requires_security_approval: false,
    risk_level: "medium",
    version: "1.0.0",
    total_tasks: 0,
    completed_tasks: 0,
    failed_tasks: 0,
  },
  {
    agent_id: "agent_system",
    key: "system_agent",
    name: "System Agent",
    category: "device",
    description:
      "Performs safe system-level actions through strict Security Agent approval.",
    status: "blocked",
    enabled: false,
    requires_security_approval: true,
    risk_level: "high",
    version: "1.0.0",
    total_tasks: 0,
    completed_tasks: 0,
    failed_tasks: 0,
  },
  {
    agent_id: "agent_visual",
    key: "visual_agent",
    name: "Visual Agent",
    category: "creative",
    description: "Reads UI states, screenshots, layouts, and visual errors.",
    status: "inactive",
    enabled: false,
    requires_security_approval: false,
    risk_level: "medium",
    version: "1.0.0",
    total_tasks: 0,
    completed_tasks: 0,
    failed_tasks: 0,
  },
  {
    agent_id: "agent_workflow",
    key: "workflow_agent",
    name: "Workflow Agent",
    category: "business",
    description:
      "Builds repeatable automations, approvals, and workspace-safe processes.",
    status: "inactive",
    enabled: false,
    requires_security_approval: true,
    risk_level: "medium",
    version: "1.0.0",
    total_tasks: 0,
    completed_tasks: 0,
    failed_tasks: 0,
  },
  {
    agent_id: "agent_hologram",
    key: "hologram_agent",
    name: "Hologram Agent",
    category: "creative",
    description:
      "Future-facing visual/avatar/hologram interface layer for immersive responses.",
    status: "inactive",
    enabled: false,
    requires_security_approval: false,
    risk_level: "medium",
    version: "1.0.0",
    total_tasks: 0,
    completed_tasks: 0,
    failed_tasks: 0,
  },
  {
    agent_id: "agent_call",
    key: "call_agent",
    name: "Call Agent",
    category: "business",
    description:
      "Supports call workflows, call summaries, and business follow-up tasks.",
    status: "inactive",
    enabled: false,
    requires_security_approval: true,
    risk_level: "high",
    version: "1.0.0",
    total_tasks: 0,
    completed_tasks: 0,
    failed_tasks: 0,
  },
  {
    agent_id: "agent_business",
    key: "business_agent",
    name: "Business Agent",
    category: "business",
    description:
      "Creates strategies, plans, SOPs, proposals, and client-ready outputs.",
    status: "inactive",
    enabled: false,
    requires_security_approval: false,
    risk_level: "low",
    version: "1.0.0",
    total_tasks: 0,
    completed_tasks: 0,
    failed_tasks: 0,
  },
  {
    agent_id: "agent_finance",
    key: "finance_agent",
    name: "Finance Agent",
    category: "finance",
    description:
      "Handles finance reports, usage summaries, and subscription insights.",
    status: "inactive",
    enabled: false,
    requires_security_approval: true,
    risk_level: "high",
    version: "1.0.0",
    total_tasks: 0,
    completed_tasks: 0,
    failed_tasks: 0,
  },
  {
    agent_id: "agent_creator",
    key: "creator_agent",
    name: "Creator Agent",
    category: "creative",
    description:
      "Creates content, images briefs, marketing assets, and campaign ideas.",
    status: "inactive",
    enabled: false,
    requires_security_approval: false,
    risk_level: "low",
    version: "1.0.0",
    total_tasks: 0,
    completed_tasks: 0,
    failed_tasks: 0,
  },
];

function createSafeError<T = never>(
  code: string,
  message: string,
  statusCode = 400,
  details: Record<string, unknown> = {},
): ApiResponse<T> {
  return {
    success: false,
    data: null,
    error: {
      code,
      message,
      status_code: statusCode,
      details,
    },
  };
}

function readSession(): SessionData | null {
  if (typeof window === "undefined") return null;

  const raw =
    window.localStorage.getItem("william.session") ||
    window.sessionStorage.getItem("william.session");

  if (!raw) return null;

  try {
    const session = JSON.parse(raw) as SessionData;

    // Only checks the session is well-formed here -- whether the workspace
    // is actually ALLOWED to use the app (an active/trialing subscription)
    // is validateAccess()'s job below, which can then show an honest
    // "your subscription is not active" message. Rejecting past_due/
    // canceled sessions at this layer instead silently treated a real,
    // logged-in user as not-logged-in and bounced them to /login with no
    // explanation.
    if (
      !session.accessToken ||
      !session.user_id ||
      !session.workspace_id ||
      !session.role ||
      !session.plan ||
      !["active", "trialing", "past_due", "canceled"].includes(
        session.subscription_status,
      )
    ) {
      return null;
    }

    return session;
  } catch {
    return null;
  }
}

function clearSession(): void {
  if (typeof window === "undefined") return;

  window.localStorage.removeItem("william.session");
  window.localStorage.removeItem("william.access_token");
  window.localStorage.removeItem("william.refresh_token");
  window.sessionStorage.removeItem("william.session");
  window.sessionStorage.removeItem("william.access_token");
  window.sessionStorage.removeItem("william.refresh_token");
}

function hasPermission(session: SessionData, permission: string): boolean {
  const merged = new Set([
    ...(ROLE_PERMISSIONS[session.role] || []),
    ...(session.permissions || []),
  ]);

  return merged.has(permission);
}

function validateAccess(session: SessionData): ApiResponse<SessionData> {
  if (!session.user_id || !session.workspace_id) {
    return createSafeError(
      "ISOLATION_CONTEXT_MISSING",
      "Session is missing user_id or workspace_id.",
      403,
    );
  }

  if (!["active", "trialing"].includes(session.subscription_status)) {
    return createSafeError(
      "SUBSCRIPTION_INACTIVE",
      "Your workspace subscription is not active.",
      402,
      {
        status: session.subscription_status,
      },
    );
  }

  if (!hasPermission(session, "agents:read")) {
    return createSafeError(
      "AGENT_READ_DENIED",
      "Your role cannot view agent controls.",
      403,
      {
        role: session.role,
      },
    );
  }

  return {
    success: true,
    data: session,
    error: null,
  };
}

async function parseApiJson<T>(response: Response): Promise<ApiResponse<T>> {
  try {
    const json = (await response.json()) as ApiResponse<T>;

    if (
      typeof json === "object" &&
      json !== null &&
      typeof json.success === "boolean" &&
      "data" in json &&
      "error" in json
    ) {
      return json;
    }

    return createSafeError<T>(
      "INVALID_API_RESPONSE",
      "The API returned an invalid response shape.",
      response.status,
    );
  } catch {
    return createSafeError<T>(
      "INVALID_JSON_RESPONSE",
      "The API response could not be parsed.",
      response.status,
    );
  }
}

async function apiRequest<T>(
  endpoint: string,
  session: SessionData,
  options: RequestInit = {},
): Promise<ApiResponse<T>> {
  if (!API_BASE_URL) {
    return createSafeError<T>(
      "API_BASE_URL_MISSING",
      "API is not connected. Set NEXT_PUBLIC_API_BASE_URL in your environment.",
      503,
      {
        required_env: "NEXT_PUBLIC_API_BASE_URL",
      },
    );
  }

  const baseUrl = API_BASE_URL.replace(/\/$/, "");
  const url = `${baseUrl}${endpoint.startsWith("/") ? endpoint : `/${endpoint}`}`;

  try {
    const response = await fetch(url, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${session.accessToken}`,
        "X-User-ID": session.user_id,
        "X-Workspace-ID": session.workspace_id,
        "X-Client-App": "william-dashboard",
        "X-Audit-Enabled": "true",
        ...(options.headers || {}),
      },
      credentials: "include",
    });

    const body = await parseApiJson<T>(response);

    if (!response.ok) {
      if (!body.success && body.error) return body;

      return createSafeError<T>(
        "HTTP_ERROR",
        "Request failed.",
        response.status,
      );
    }

    return body;
  } catch {
    return createSafeError<T>(
      "NETWORK_ERROR",
      "Could not connect to the William API.",
      503,
    );
  }
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

function formatNumber(value?: number): string {
  return new Intl.NumberFormat("en-US").format(value || 0);
}

function getAgentIcon(category: AgentItem["category"]): string {
  const icons: Record<AgentItem["category"], string> = {
    core: "✦",
    execution: "⚡",
    memory: "◌",
    security: "▣",
    business: "◆",
    finance: "$",
    creative: "✎",
    device: "⌘",
  };

  return icons[category];
}

function getStatusStyle(status: AgentStatus): string {
  if (status === "active") return "bg-emerald-50 text-emerald-700";
  if (status === "inactive") return "bg-neutral-100 text-neutral-600";
  if (status === "pending") return "bg-yellow-50 text-yellow-700";
  if (status === "maintenance") return "bg-blue-50 text-blue-700";
  return "bg-red-50 text-red-700";
}

// The Voice Agent's generic enabled/disabled registry status ("Inactive")
// doesn't reflect whether voice is actually configured -- a workspace can
// have voice fully set up (push_to_talk or wake word) while the agent
// itself is simply not toggled on in the generic registry sense, which
// read as "broken" even though nothing was wrong. This card shows the
// real /voice/status runtime_state instead, matching the Voice Control
// Settings section's own state labels exactly.
type VoiceRuntimeStateLite =
  | "disabled"
  | "push_to_talk"
  | "worker_offline"
  | "dependency_required"
  | "listening"
  | "standby";

const VOICE_RUNTIME_LABELS: Record<VoiceRuntimeStateLite, string> = {
  disabled: "Disabled",
  push_to_talk: "Push to Talk",
  worker_offline: "Worker Offline",
  dependency_required: "Dependency Required",
  listening: "Listening",
  standby: "Standby",
};

function getVoiceRuntimeStyle(state: VoiceRuntimeStateLite): string {
  if (state === "listening") return "bg-emerald-50 text-emerald-700";
  if (state === "push_to_talk") return "bg-blue-50 text-blue-700";
  if (state === "worker_offline" || state === "dependency_required")
    return "bg-orange-50 text-orange-700";
  if (state === "standby") return "bg-purple-50 text-purple-700";
  return "bg-neutral-100 text-neutral-600";
}

function getRiskStyle(risk: AgentRiskLevel): string {
  if (risk === "low") return "bg-emerald-50 text-emerald-700";
  if (risk === "medium") return "bg-orange-50 text-orange-700";
  return "bg-red-50 text-red-700";
}

function getCapabilityStatusStyle(status: string): string {
  if (status === "available" || status === "configured")
    return "bg-emerald-50 text-emerald-700";
  if (status === "approval_required") return "bg-amber-50 text-amber-800";
  if (status === "external_dependency_required")
    return "bg-orange-50 text-orange-700";
  if (status === "planned") return "bg-blue-50 text-blue-700";
  return "bg-neutral-100 text-neutral-600";
}

function getCapabilityRiskStyle(risk: string): string {
  if (risk === "low") return "bg-emerald-50 text-emerald-700";
  if (risk === "medium") return "bg-orange-50 text-orange-700";
  if (risk === "high" || risk === "critical") return "bg-red-50 text-red-700";
  return "bg-neutral-100 text-neutral-600";
}

function getPermissionLevelStyle(level: string): string {
  if (level === "allowed") return "bg-emerald-50 text-emerald-700";
  if (level === "approval_required") return "bg-amber-50 text-amber-800";
  return "bg-red-50 text-red-700";
}

// agents.py AGENT_CATALOG has no explicit UI "category" field, so live agents
// are mapped into this page's existing category taxonomy by agent_name.
const AGENT_CATEGORY_MAP: Record<string, AgentItem["category"]> = {
  master: "core",
  security: "security",
  verification: "core",
  memory: "memory",
  code: "execution",
  browser: "execution",
  voice: "device",
  system: "device",
  visual: "creative",
  workflow: "business",
  hologram: "creative",
  call: "business",
  business: "business",
  finance: "finance",
  creator: "creative",
};

// One realistic example prompt per agent, keyed by agents.py AGENT_CATALOG's
// agent_name. Used only as a UI hint in the capability drawer — never sent
// anywhere or treated as live capability data.
const AGENT_TEST_PROMPTS: Record<string, string> = {
  master:
    "Plan and coordinate the steps needed to prepare this week's client report.",
  voice: "Read me my latest notifications.",
  system: "Check current CPU and memory usage on this device.",
  browser: "Open our pricing page and check whether it still loads correctly.",
  code: "Add input validation to the login form.",
  memory:
    "Remember that my main client is Acme Corp, then recall it next time I ask.",
  security: "Review this file-delete request before it runs.",
  verification:
    "Confirm that the last workflow run actually completed successfully.",
  visual: "Look at this dashboard screenshot and tell me what looks broken.",
  workflow:
    "Create a weekly automation that emails our sales summary every Monday.",
  hologram: "Render a greeting avatar for our new customer onboarding screen.",
  call: "Summarize my last call with the Acme Corp client.",
  business: "Draft a one-page SOP for onboarding new clients.",
  finance: "Draft an invoice for client Acme Corp.",
  creator: "Write three Instagram captions for our new product launch.",
};

const CAPABILITY_STATUS_ORDER: CapabilityManifestStatus[] = [
  "available",
  "configured",
  "approval_required",
  "external_dependency_required",
  "planned",
  "capability_unavailable",
];

const CAPABILITY_STATUS_LABELS: Record<CapabilityManifestStatus, string> = {
  available: "Available",
  configured: "Configured",
  approval_required: "Approval required",
  external_dependency_required: "Needs setup",
  planned: "Planned",
  capability_unavailable: "Unavailable",
};

type CapabilityFilter = "all" | CapabilityManifestStatus;

function deriveAgentStatus(
  enabled: boolean,
  health: AgentHealthRecordApi | null,
): AgentStatus {
  if (!enabled) return "inactive";
  if (!health) return "pending";
  if (health.status === "degraded") return "maintenance";
  if (health.status === "unavailable") return "blocked";
  if (health.status === "disabled") return "inactive";
  // System Agent (and any future agent whose real "active" signal is
  // actual task/worker activity, not just a successful module import)
  // reports "idle" when enabled and loaded but nothing has really run
  // recently -- shown as "pending" so it never reads as falsely active.
  if (health.status === "idle") return "pending";
  return "active";
}

function deriveRiskLevel(
  manifest: AgentCapabilityManifestEntry[],
): AgentRiskLevel {
  if (
    manifest.some(
      (item) => item.risk_level === "critical" || item.risk_level === "high",
    )
  ) {
    return "high";
  }
  if (manifest.some((item) => item.risk_level === "medium")) return "medium";
  if (manifest.length > 0) return "low";
  return "medium";
}

function deriveRequiresSecurityApproval(
  capabilities: AgentCapabilitySummary[],
  manifest: AgentCapabilityManifestEntry[],
): boolean {
  return (
    capabilities.some((item) => item.sensitive) ||
    manifest.some(
      (item) =>
        item.permission_level === "approval_required" ||
        item.permission_level === "blocked_by_default",
    )
  );
}

function mapApiAgentEntryToItem(entry: AgentListEntryApi): AgentItem {
  const definition = entry.agent;
  const workspaceConfig = entry.workspace_config;
  const enabled =
    workspaceConfig?.enabled ??
    entry.access?.enabled_for_workspace ??
    definition.default_enabled;
  const manifest = definition.capability_manifest || [];
  const capabilitiesSummary = definition.capabilities || [];

  return {
    agent_id: definition.agent_name,
    key: definition.agent_name,
    name: definition.display_name,
    category: AGENT_CATEGORY_MAP[definition.agent_name] || "core",
    description: definition.description,
    status: deriveAgentStatus(enabled, entry.health),
    enabled,
    requires_security_approval: deriveRequiresSecurityApproval(
      capabilitiesSummary,
      manifest,
    ),
    risk_level: deriveRiskLevel(manifest),
    last_run_at: null,
    last_health_check_at: entry.health?.checked_at ?? null,
    total_tasks: 0,
    completed_tasks: 0,
    failed_tasks: 0,
    permissions: Array.from(
      new Set([
        ...capabilitiesSummary
          .map((item) => item.required_permission)
          .filter((item): item is string => Boolean(item)),
        ...(workspaceConfig?.custom_permissions || []),
      ]),
    ),
    tier: definition.tier,
    required_plan: definition.required_plan,
    required_role: definition.required_role,
    core_agent: definition.core_agent,
    default_enabled: definition.default_enabled,
    capabilities_summary: capabilitiesSummary,
    capability_manifest: manifest,
    capability_manifest_meta: definition.capability_manifest_meta || null,
    workspace_config: workspaceConfig,
    access: entry.access,
    health: entry.health,
  };
}

function formatCapabilitySummary(agent: AgentItem): string | null {
  const meta = agent.capability_manifest_meta;
  if (!meta || meta.count === 0) return null;

  const breakdown = meta.status_breakdown || {};
  const available = (breakdown.available || 0) + (breakdown.configured || 0);
  const needsSetup = breakdown.external_dependency_required || 0;
  const needsApproval = breakdown.approval_required || 0;
  const planned = breakdown.planned || 0;
  const unavailable = breakdown.capability_unavailable || 0;

  const parts = [`${meta.count} capabilities`];
  if (available) parts.push(`${available} available`);
  if (needsSetup) parts.push(`${needsSetup} need setup`);
  if (needsApproval) parts.push(`${needsApproval} need approval`);
  if (planned) parts.push(`${planned} planned`);
  if (unavailable) parts.push(`${unavailable} unavailable`);

  return parts.join(" · ");
}

function aggregateRequiredIntegrations(
  manifest: AgentCapabilityManifestEntry[],
): string[] {
  const set = new Set<string>();
  manifest.forEach((item) => {
    (item.required_integrations || []).forEach((integration) =>
      set.add(integration),
    );
  });
  return Array.from(set).sort();
}

function getApprovalCapabilities(
  manifest: AgentCapabilityManifestEntry[],
): AgentCapabilityManifestEntry[] {
  return manifest.filter(
    (item) =>
      item.permission_level === "approval_required" ||
      item.permission_level === "blocked_by_default" ||
      item.audit_required,
  );
}

function calculateSummary(agents: AgentItem[]): AgentsSummary {
  return {
    totalAgents: agents.length,
    enabledAgents: agents.filter((agent) => agent.enabled).length,
    activeAgents: agents.filter((agent) => agent.status === "active").length,
    pendingAgents: agents.filter((agent) => agent.status === "pending").length,
    blockedAgents: agents.filter((agent) => agent.status === "blocked").length,
    securityProtectedAgents: agents.filter(
      (agent) => agent.requires_security_approval,
    ).length,
  };
}

function StatCard({
  title,
  value,
  subtitle,
  highlight,
  icon,
}: {
  title: string;
  value: string;
  subtitle: string;
  highlight?: boolean;
  icon: string;
}) {
  return (
    <div
      className={[
        "rounded-[1.55rem] p-5 shadow-sm",
        highlight
          ? "bg-[#ff5a3d] text-white shadow-xl shadow-[#ff5a3d]/25"
          : "bg-white text-neutral-950",
      ].join(" ")}
    >
      <div className="mb-6 flex items-center justify-between">
        <p
          className={[
            "text-sm font-bold",
            highlight ? "text-white/80" : "text-neutral-500",
          ].join(" ")}
        >
          {title}
        </p>
        <span
          className={[
            "grid h-9 w-9 place-items-center rounded-full text-sm",
            highlight
              ? "bg-white/15 text-white"
              : "bg-neutral-100 text-neutral-500",
          ].join(" ")}
        >
          {icon}
        </span>
      </div>
      <p className="text-4xl font-black tracking-[-0.05em]">{value}</p>
      <p
        className={[
          "mt-2 text-xs font-bold",
          highlight ? "text-white/75" : "text-emerald-600",
        ].join(" ")}
      >
        {subtitle}
      </p>
    </div>
  );
}

function AgentCapabilityDrawer({
  agent,
  onClose,
  statusFilter,
  onStatusFilterChange,
}: {
  agent: AgentItem;
  onClose: () => void;
  statusFilter: CapabilityFilter;
  onStatusFilterChange: (filter: CapabilityFilter) => void;
}) {
  const manifest = agent.capability_manifest || [];
  const meta = agent.capability_manifest_meta || null;
  const breakdown = meta?.status_breakdown || {};
  const filteredCapabilities =
    statusFilter === "all"
      ? manifest
      : manifest.filter((item) => item.status === statusFilter);
  const dependencies = aggregateRequiredIntegrations(manifest);
  const approvalCapabilities = getApprovalCapabilities(manifest);
  const testPrompt =
    AGENT_TEST_PROMPTS[agent.key] ||
    `Ask William to use the ${agent.name} for a task in your workspace.`;

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end bg-neutral-950/40 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-label={`${agent.name} capability details`}
    >
      <button
        type="button"
        aria-label="Close capability details"
        onClick={onClose}
        className="absolute inset-0 h-full w-full cursor-default"
      />

      <div className="relative flex h-full w-full max-w-2xl flex-col overflow-y-auto bg-white p-6 shadow-2xl sm:rounded-l-[2rem]">
        <div className="mb-5 flex items-start justify-between gap-4">
          <div className="min-w-0">
            <p className="text-xs font-black uppercase tracking-[0.18em] text-neutral-400">
              {agent.key}
            </p>
            <h2 className="mt-1 text-2xl font-black tracking-[-0.04em] text-neutral-950">
              {agent.name}
            </h2>
            <p className="mt-2 text-sm font-medium leading-5 text-neutral-500">
              {agent.description}
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="grid h-10 w-10 shrink-0 place-items-center rounded-full bg-neutral-100 text-lg font-black text-neutral-500 transition hover:bg-neutral-950 hover:text-white"
            aria-label="Close"
          >
            ×
          </button>
        </div>

        <div className="mb-5 flex flex-wrap gap-2">
          {agent.tier ? (
            <span className="rounded-full bg-neutral-100 px-3 py-1 text-[11px] font-black capitalize text-neutral-600">
              {agent.tier} tier
            </span>
          ) : null}
          {agent.required_plan ? (
            <span className="rounded-full bg-neutral-100 px-3 py-1 text-[11px] font-black capitalize text-neutral-600">
              {agent.required_plan}+ plan
            </span>
          ) : null}
          {agent.required_role ? (
            <span className="rounded-full bg-neutral-100 px-3 py-1 text-[11px] font-black capitalize text-neutral-600">
              {agent.required_role}+ role
            </span>
          ) : null}
          <span
            className={[
              "rounded-full px-3 py-1 text-[11px] font-black capitalize",
              getRiskStyle(agent.risk_level),
            ].join(" ")}
          >
            {agent.risk_level} risk
          </span>
        </div>

        <div className="mb-5 rounded-2xl border border-neutral-100 bg-neutral-50 p-4">
          <p className="text-xs font-black uppercase tracking-[0.16em] text-neutral-400">
            Try it in the AI console
          </p>
          <p className="mt-2 text-sm font-bold text-neutral-800">
            &ldquo;{testPrompt}&rdquo;
          </p>
        </div>

        <div className="mb-5 rounded-2xl border border-neutral-100 bg-neutral-50 p-4">
          <p className="mb-3 text-xs font-black uppercase tracking-[0.16em] text-neutral-400">
            Health
          </p>
          {agent.health ? (
            <div className="grid grid-cols-2 gap-3 text-xs font-bold text-neutral-600 sm:grid-cols-3">
              <div>
                <p className="text-[10px] uppercase tracking-[0.14em] text-neutral-400">
                  Status
                </p>
                <p className="mt-1 text-neutral-950">{agent.health.status}</p>
              </div>
              <div>
                <p className="text-[10px] uppercase tracking-[0.14em] text-neutral-400">
                  Available
                </p>
                <p className="mt-1 text-neutral-950">
                  {agent.health.available ? "Yes" : "No"}
                </p>
              </div>
              <div>
                <p className="text-[10px] uppercase tracking-[0.14em] text-neutral-400">
                  Loaded
                </p>
                <p className="mt-1 text-neutral-950">
                  {agent.health.loaded ? "Yes" : "No"}
                </p>
              </div>
              <div className="col-span-2 sm:col-span-3">
                <p className="text-[10px] uppercase tracking-[0.14em] text-neutral-400">
                  Source
                </p>
                <p className="mt-1 break-all text-neutral-950">
                  {agent.health.source || "Not resolved"}
                </p>
              </div>
              {agent.health.error ? (
                <div className="col-span-2 sm:col-span-3">
                  <p className="text-[10px] uppercase tracking-[0.14em] text-red-400">
                    Error
                  </p>
                  <p className="mt-1 break-all text-red-700">
                    {agent.health.error}
                  </p>
                </div>
              ) : null}
              <div className="col-span-2 sm:col-span-3">
                <p className="text-[10px] uppercase tracking-[0.14em] text-neutral-400">
                  Checked
                </p>
                <p className="mt-1 text-neutral-950">
                  {formatDate(agent.health.checked_at)}
                </p>
              </div>
            </div>
          ) : (
            <p className="text-xs font-bold text-neutral-400">
              No health check recorded yet for this agent. Run
              &ldquo;Check&rdquo; from the registry card to record one.
            </p>
          )}
        </div>

        <div className="mb-5 rounded-2xl border border-neutral-100 bg-neutral-50 p-4">
          <p className="mb-3 text-xs font-black uppercase tracking-[0.16em] text-neutral-400">
            Dependencies
          </p>
          {dependencies.length > 0 ? (
            <div className="flex flex-wrap gap-2">
              {dependencies.map((dependency) => (
                <span
                  key={dependency}
                  className="rounded-full bg-white px-3 py-1 text-[11px] font-black text-neutral-600"
                >
                  {dependency}
                </span>
              ))}
            </div>
          ) : (
            <p className="text-xs font-bold text-neutral-400">
              No external integrations declared for this agent&apos;s
              capabilities.
            </p>
          )}
        </div>

        <div className="mb-5 rounded-2xl border border-neutral-100 bg-neutral-50 p-4">
          <p className="mb-3 text-xs font-black uppercase tracking-[0.16em] text-neutral-400">
            Approval requirements
          </p>
          {approvalCapabilities.length > 0 ? (
            <ul className="space-y-2">
              {approvalCapabilities.map((capability) => (
                <li
                  key={capability.id}
                  className="rounded-xl bg-white p-3 text-xs font-bold text-neutral-700"
                >
                  <span className="text-neutral-950">{capability.name}</span>
                  <span className="ml-2 rounded-full bg-amber-50 px-2 py-0.5 text-[10px] font-black capitalize text-amber-800">
                    {capability.permission_level.replace(/_/g, " ")}
                  </span>
                  {capability.audit_required ? (
                    <span className="ml-2 rounded-full bg-[#fff3ed] px-2 py-0.5 text-[10px] font-black text-[#ff5a3d]">
                      Audit required
                    </span>
                  ) : null}
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-xs font-bold text-neutral-400">
              No capabilities in this manifest currently require approval or
              audit.
            </p>
          )}
        </div>

        <div className="mb-4 flex items-center justify-between">
          <p className="text-sm font-black text-neutral-950">
            Capability manifest
            {meta ? ` (${meta.count}/${meta.expected_count})` : ""}
          </p>
        </div>

        {manifest.length === 0 ? (
          <EmptyState
            variant="light"
            icon="∅"
            title="No capability manifest for this agent"
            message={
              agent.key === "master"
                ? "The Master Agent orchestrates the other agents and does not carry its own 50-item capability manifest."
                : "This agent has no capability manifest available yet. Connect the live API to load its declared capabilities."
            }
          />
        ) : (
          <>
            <div className="mb-4 flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() => onStatusFilterChange("all")}
                className={[
                  "rounded-full px-3 py-1.5 text-[11px] font-black transition",
                  statusFilter === "all"
                    ? "bg-neutral-950 text-white"
                    : "bg-neutral-100 text-neutral-600 hover:bg-neutral-200",
                ].join(" ")}
              >
                All ({manifest.length})
              </button>
              {CAPABILITY_STATUS_ORDER.map((status) => (
                <button
                  key={status}
                  type="button"
                  onClick={() => onStatusFilterChange(status)}
                  className={[
                    "rounded-full px-3 py-1.5 text-[11px] font-black transition",
                    statusFilter === status
                      ? "bg-neutral-950 text-white"
                      : "bg-neutral-100 text-neutral-600 hover:bg-neutral-200",
                  ].join(" ")}
                >
                  {CAPABILITY_STATUS_LABELS[status]} ({breakdown[status] || 0})
                </button>
              ))}
            </div>

            <div className="space-y-3">
              {filteredCapabilities.map((capability) => (
                <div
                  key={capability.id}
                  className="rounded-2xl border border-neutral-100 bg-neutral-50 p-4"
                >
                  <div className="mb-2 flex flex-wrap items-start justify-between gap-2">
                    <div className="min-w-0">
                      <p className="truncate text-[11px] font-black uppercase tracking-[0.12em] text-neutral-400">
                        {capability.id}
                      </p>
                      <p className="text-sm font-black text-neutral-950">
                        {capability.name}
                      </p>
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      <span
                        className={[
                          "rounded-full px-2.5 py-1 text-[10px] font-black capitalize",
                          getCapabilityStatusStyle(capability.status),
                        ].join(" ")}
                      >
                        {capability.status.replace(/_/g, " ")}
                      </span>
                      <span
                        className={[
                          "rounded-full px-2.5 py-1 text-[10px] font-black capitalize",
                          getCapabilityRiskStyle(capability.risk_level),
                        ].join(" ")}
                      >
                        {capability.risk_level} risk
                      </span>
                      <span
                        className={[
                          "rounded-full px-2.5 py-1 text-[10px] font-black capitalize",
                          getPermissionLevelStyle(capability.permission_level),
                        ].join(" ")}
                      >
                        {capability.permission_level.replace(/_/g, " ")}
                      </span>
                    </div>
                  </div>

                  <p className="text-xs font-medium leading-5 text-neutral-600">
                    {capability.description}
                  </p>

                  {capability.safe_mvp_behavior ? (
                    <p className="mt-2 text-xs font-medium leading-5 text-neutral-500">
                      <span className="font-black text-neutral-700">
                        Safe MVP behavior:{" "}
                      </span>
                      {capability.safe_mvp_behavior}
                    </p>
                  ) : null}

                  {capability.required_integrations.length > 0 ? (
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {capability.required_integrations.map((integration) => (
                        <span
                          key={integration}
                          className="rounded-full bg-white px-2.5 py-1 text-[10px] font-black text-neutral-500"
                        >
                          {integration}
                        </span>
                      ))}
                    </div>
                  ) : null}

                  <div className="mt-2 grid gap-1 text-[11px] font-medium text-neutral-500 sm:grid-cols-2">
                    {capability.verification_method ? (
                      <p>
                        <span className="font-black text-neutral-600">
                          Verification:{" "}
                        </span>
                        {capability.verification_method}
                      </p>
                    ) : null}
                    {capability.memory_policy ? (
                      <p>
                        <span className="font-black text-neutral-600">
                          Memory:{" "}
                        </span>
                        {capability.memory_policy}
                      </p>
                    ) : null}
                  </div>

                  <p className="mt-2 text-[11px] font-black text-neutral-400">
                    {capability.audit_required
                      ? "Audit required"
                      : "Audit optional"}
                  </p>
                </div>
              ))}

              {filteredCapabilities.length === 0 ? (
                <p className="text-xs font-bold text-neutral-400">
                  No capabilities match this filter.
                </p>
              ) : null}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

export default function Page() {
  const router = useRouter();

  const [session, setSession] = useState<SessionData | null>(null);
  const [agents, setAgents] = useState<AgentItem[]>([]);
  const [state, setState] = useState<LoadState>("checking_session");
  const [errorMessage, setErrorMessage] = useState("");
  const [search, setSearch] = useState("");
  const [categoryFilter, setCategoryFilter] = useState<
    "all" | AgentItem["category"]
  >("all");
  const [statusFilter, setStatusFilter] = useState<"all" | AgentStatus>("all");
  const [busyAgentId, setBusyAgentId] = useState<string | null>(null);
  const [notice, setNotice] = useState<{
    type: "success" | "error" | "info";
    message: string;
  } | null>(null);
  const [selectedAgentId, setSelectedAgentId] = useState<string | null>(null);
  const [capabilityStatusFilter, setCapabilityStatusFilter] =
    useState<CapabilityFilter>("all");
  const [voiceRuntimeState, setVoiceRuntimeState] =
    useState<VoiceRuntimeStateLite | null>(null);
  const [systemWorkerConnected, setSystemWorkerConnected] = useState<
    boolean | null
  >(null);

  const canConfigureAgents = useMemo(() => {
    if (!session) return false;
    return hasPermission(session, "agents:configure");
  }, [session]);

  const canApproveSecurity = useMemo(() => {
    if (!session) return false;
    return hasPermission(session, "security:approve");
  }, [session]);

  // The JWT/session's own "plan" is always the real, raw workspace plan
  // (apps/api/routes/auth.py bakes membership.plan into the token, never
  // the dev-only admin bypass). Each live /agents entry's access.plan is
  // the server's actual EFFECTIVE plan for this request
  // (apps.api.routes.agents::effective_plan_for), which is "enterprise"
  // for a platform admin in a non-production environment even when the
  // workspace's real stored plan is still "free". Prefer that live value
  // so this page doesn't show a stale "free" plan for an admin who never
  // ran scripts/grant_platform_admin.py against this exact workspace.
  const effectivePlan = useMemo<UserPlan>(() => {
    const liveAccessPlan = agents.find((agent) => agent.access?.plan)?.access
      ?.plan as UserPlan | undefined;
    return liveAccessPlan || session?.plan || "free";
  }, [agents, session]);

  const isAdminUnlimited = Boolean(
    session?.is_platform_admin && effectivePlan === "enterprise",
  );

  const maxAgentsForPlan = useMemo(() => {
    if (!session) return 0;
    return PLAN_AGENT_LIMITS[effectivePlan] || 0;
  }, [effectivePlan, session]);

  const summary = useMemo(() => calculateSummary(agents), [agents]);

  const selectedAgent = useMemo(
    () => agents.find((item) => item.agent_id === selectedAgentId) || null,
    [agents, selectedAgentId],
  );

  function openAgentDetails(agent: AgentItem) {
    setSelectedAgentId(agent.agent_id);
    setCapabilityStatusFilter("all");
  }

  const enabledPercent = useMemo(() => {
    if (!summary.totalAgents) return 0;
    return Math.round((summary.enabledAgents / summary.totalAgents) * 100);
  }, [summary.enabledAgents, summary.totalAgents]);

  const filteredAgents = useMemo(() => {
    const normalizedSearch = search.trim().toLowerCase();

    return agents.filter((agent) => {
      const matchesSearch =
        !normalizedSearch ||
        agent.name.toLowerCase().includes(normalizedSearch) ||
        agent.key.toLowerCase().includes(normalizedSearch) ||
        agent.description.toLowerCase().includes(normalizedSearch);

      const matchesCategory =
        categoryFilter === "all" || agent.category === categoryFilter;

      const matchesStatus =
        statusFilter === "all" || agent.status === statusFilter;

      return matchesSearch && matchesCategory && matchesStatus;
    });
  }, [agents, categoryFilter, search, statusFilter]);

  const loadAgents = useCallback(
    async (activeSession: SessionData) => {
      setState("loading");
      setErrorMessage("");

      const access = validateAccess(activeSession);

      if (!access.success) {
        clearSession();
        router.replace("/login");
        return;
      }

      // The real backend endpoint (apps/api/routes/agents.py::list_agents)
      // never binds/reads user_id/workspace_id query params -- it derives
      // both from the verified JWT via get_current_auth_context. Sending
      // them was harmless dead weight, not a functional requirement.
      const response = await apiRequest<AgentListResponseApi>(
        "/agents",
        activeSession,
        {
          method: "GET",
          headers: {
            "X-Action": "agents.list",
          },
        },
      );

      if (!response.success) {
        if (response.error?.code === "API_BASE_URL_MISSING") {
          setAgents(DEFAULT_AGENTS);
          setState("ready");
          setNotice({
            type: "info",
            message:
              "API is not connected yet, so the control center is showing the built-in William/Jarvis registry structure. Connect NEXT_PUBLIC_API_BASE_URL for live database data.",
          });
          return;
        }

        setState("error");
        setErrorMessage(response.error?.message || "Could not load agents.");
        return;
      }

      const liveAgents = (response.data?.agents || []).map(
        mapApiAgentEntryToItem,
      );
      setAgents(liveAgents);
      setState(liveAgents.length > 0 ? "ready" : "empty");

      if (liveAgents.some((agent) => agent.key === "voice")) {
        const voiceResponse = await apiRequest<{
          runtime_state: VoiceRuntimeStateLite;
        }>("/voice/status", activeSession, { method: "GET" });
        if (voiceResponse.success && voiceResponse.data) {
          setVoiceRuntimeState(voiceResponse.data.runtime_state);
        }
      }

      if (liveAgents.some((agent) => agent.key === "system")) {
        const systemWorkerResponse = await apiRequest<{
          worker_connected: boolean;
        }>("/system/worker/status", activeSession, { method: "GET" });
        if (systemWorkerResponse.success && systemWorkerResponse.data) {
          setSystemWorkerConnected(
            Boolean(systemWorkerResponse.data.worker_connected),
          );
        }
      }
    },
    [router],
  );

  useEffect(() => {
    const activeSession = readSession();

    if (!activeSession) {
      router.replace("/login");
      return;
    }

    setSession(activeSession);
    void loadAgents(activeSession);
  }, [loadAgents, router]);

  async function handleToggleAgent(agent: AgentItem, nextEnabled: boolean) {
    if (!session) {
      router.replace("/login");
      return;
    }

    if (!canConfigureAgents) {
      setNotice({
        type: "error",
        message: "Your role cannot enable or disable agents.",
      });
      return;
    }

    const currentEnabledCount = agents.filter((item) => item.enabled).length;

    if (nextEnabled && currentEnabledCount >= maxAgentsForPlan) {
      setNotice({
        type: "error",
        message: `Your ${isAdminUnlimited ? "Admin Unlimited" : effectivePlan} plan allows ${maxAgentsForPlan} enabled agent(s). Upgrade or disable another agent first.`,
      });
      return;
    }

    if (agent.requires_security_approval && !canApproveSecurity) {
      setNotice({
        type: "error",
        message:
          "This agent requires Security Agent approval. Your role cannot approve sensitive agent changes.",
      });
      return;
    }

    setBusyAgentId(agent.agent_id);
    setNotice(null);

    const response = await apiRequest<AgentActionResponse>(
      `/agents/${encodeURIComponent(agent.agent_id)}/${nextEnabled ? "enable" : "disable"}`,
      session,
      {
        method: "POST",
        headers: {
          "X-Action": nextEnabled ? "agents.enable" : "agents.disable",
          "X-Sensitive-Action": agent.requires_security_approval
            ? "true"
            : "false",
        },
        body: JSON.stringify({
          user_id: session.user_id,
          workspace_id: session.workspace_id,
          agent_id: agent.agent_id,
          agent_key: agent.key,
          enabled: nextEnabled,
          route: {
            master_agent: true,
            security_agent: agent.requires_security_approval,
            memory_agent: true,
            verification_agent: true,
          },
          clientContext: {
            app: "william-dashboard",
            module: "agents.control_center",
            action: nextEnabled ? "agents.enable" : "agents.disable",
            requiresAudit: true,
            requiresSecurityRoute: agent.requires_security_approval,
            memoryCompatible: true,
            verificationCompatible: true,
          },
        }),
      },
    );

    if (!response.success || !response.data) {
      if (response.error?.code === "API_BASE_URL_MISSING") {
        setAgents((current) =>
          current.map((item) =>
            item.agent_id === agent.agent_id
              ? {
                  ...item,
                  enabled: nextEnabled,
                  status: nextEnabled ? "active" : "inactive",
                }
              : item,
          ),
        );
        setNotice({
          type: "info",
          message:
            "Local UI state updated. Connect the API to persist this change in the database.",
        });
        setBusyAgentId(null);
        return;
      }

      setNotice({
        type: "error",
        message:
          response.error?.message || "Agent status could not be updated.",
      });
      setBusyAgentId(null);
      return;
    }

    setAgents((current) =>
      current.map((item) =>
        item.agent_id === agent.agent_id
          ? {
              ...item,
              enabled: response.data?.enabled ?? nextEnabled,
              status:
                response.data?.status ?? (nextEnabled ? "active" : "inactive"),
            }
          : item,
      ),
    );

    setNotice({
      type: "success",
      message: `${agent.name} ${nextEnabled ? "enabled" : "disabled"} successfully. Security, audit, memory, and verification metadata prepared.`,
    });

    setBusyAgentId(null);
  }

  async function handleHealthCheck(agent: AgentItem) {
    if (!session) {
      router.replace("/login");
      return;
    }

    if (!hasPermission(session, "agents:run")) {
      setNotice({
        type: "error",
        message: "Your role cannot run agent health checks.",
      });
      return;
    }

    setBusyAgentId(agent.agent_id);
    setNotice(null);

    const response = await apiRequest<AgentActionResponse>(
      `/agents/${encodeURIComponent(agent.agent_id)}/health-check`,
      session,
      {
        method: "POST",
        headers: {
          "X-Action": "agents.health_check",
          "X-Sensitive-Action": "false",
        },
        body: JSON.stringify({
          user_id: session.user_id,
          workspace_id: session.workspace_id,
          agent_id: agent.agent_id,
          agent_key: agent.key,
          route: {
            master_agent: true,
            security_agent: false,
            memory_agent: true,
            verification_agent: true,
          },
          clientContext: {
            app: "william-dashboard",
            module: "agents.health_check",
            action: "agents.health_check",
            requiresAudit: true,
            requiresSecurityRoute: false,
            memoryCompatible: true,
            verificationCompatible: true,
          },
        }),
      },
    );

    if (!response.success || !response.data) {
      if (response.error?.code === "API_BASE_URL_MISSING") {
        setAgents((current) =>
          current.map((item) =>
            item.agent_id === agent.agent_id
              ? {
                  ...item,
                  status: item.enabled ? "active" : "inactive",
                  last_health_check_at: new Date().toISOString(),
                }
              : item,
          ),
        );
        setNotice({
          type: "info",
          message:
            "Local health check simulated. Connect the API for real registry health status.",
        });
        setBusyAgentId(null);
        return;
      }

      setNotice({
        type: "error",
        message: response.error?.message || "Health check failed.",
      });
      setBusyAgentId(null);
      return;
    }

    setAgents((current) =>
      current.map((item) =>
        item.agent_id === agent.agent_id
          ? {
              ...item,
              status: response.data?.status ?? item.status,
              enabled: response.data?.enabled ?? item.enabled,
              last_health_check_at: new Date().toISOString(),
            }
          : item,
      ),
    );

    setNotice({
      type: "success",
      message: `${agent.name} health check completed and verification payload prepared.`,
    });

    setBusyAgentId(null);
  }

  function handleLogout() {
    clearSession();
    router.replace("/login");
  }

  if (state === "checking_session" || !session) {
    return (
      <div className="grid min-h-[420px] place-items-center text-neutral-950">
        <LoadingState
          variant="light"
          title="Checking agent access..."
          subtitle="Validating user_id and workspace_id."
        />
      </div>
    );
  }

  return (
    <div className="text-neutral-950">
      <section className="flex min-w-0 flex-1 flex-col px-0">
        <div className="mb-6 flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <h1 className="text-4xl font-black tracking-[-0.055em] text-neutral-950 lg:text-5xl">
              Agent Control Center
            </h1>
            <p className="mt-2 text-sm font-medium text-neutral-500">
              Enable, disable, monitor, and verify William/Jarvis agents without
              mixing workspace data.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div className="relative w-full max-w-md">
              <span className="absolute left-4 top-1/2 -translate-y-1/2 text-neutral-400">
                ⌕
              </span>
              <input
                type="search"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Search agents, registry keys, status..."
                className="h-12 w-full rounded-full border border-neutral-200 bg-white px-11 text-sm font-semibold outline-none transition placeholder:text-neutral-400 focus:border-[#ff5a3d] focus:ring-4 focus:ring-[#ff5a3d]/10"
              />
            </div>
            <div className="rounded-2xl bg-white px-4 py-3 shadow-sm">
              <p className="text-[11px] font-black uppercase tracking-[0.18em] text-neutral-400">
                Workspace
              </p>
              <p className="mt-1 text-sm font-black text-neutral-950">
                {session.workspace_name}
              </p>
            </div>
            <button
              type="button"
              onClick={handleLogout}
              className="rounded-2xl bg-white px-4 py-3 text-xs font-black text-neutral-500 shadow-sm transition hover:text-[#ff5a3d]"
              aria-label="Logout"
            >
              ↩ Logout
            </button>
          </div>
        </div>

        {notice ? (
          <div
            className={[
              "mb-5 rounded-2xl px-4 py-3 text-sm font-bold",
              notice.type === "success"
                ? "border border-emerald-100 bg-emerald-50 text-emerald-700"
                : notice.type === "error"
                  ? "border border-red-100 bg-red-50 text-red-700"
                  : "border border-amber-100 bg-amber-50 text-amber-800",
            ].join(" ")}
          >
            {notice.message}
          </div>
        ) : null}

        {state === "loading" ? (
          <LoadingState
            variant="light"
            title="Loading agent registry..."
            subtitle="Checking workspace-safe agent access."
          />
        ) : state === "error" ? (
          <ErrorState
            variant="light"
            title="Agents could not load"
            message={errorMessage}
            onRetry={() => {
              if (session) void loadAgents(session);
            }}
          />
        ) : (
          <div className="space-y-5">
            <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-6">
              <StatCard
                title="Total Agents"
                value={formatNumber(summary.totalAgents)}
                subtitle="Registry compatible"
                icon="▦"
                highlight
              />
              <StatCard
                title="Enabled"
                value={formatNumber(summary.enabledAgents)}
                subtitle={`${enabledPercent}% enabled`}
                icon="✓"
              />
              <StatCard
                title="Active"
                value={formatNumber(summary.activeAgents)}
                subtitle="Ready to run"
                icon="⚡"
              />
              <StatCard
                title="Pending"
                value={formatNumber(summary.pendingAgents)}
                subtitle="Waiting checks"
                icon="…"
              />
              <StatCard
                title="Blocked"
                value={formatNumber(summary.blockedAgents)}
                subtitle="Needs attention"
                icon="!"
              />
              <StatCard
                title="Protected"
                value={formatNumber(summary.securityProtectedAgents)}
                subtitle="Security routed"
                icon="▣"
              />
            </section>

            <section className="grid gap-5 xl:grid-cols-[0.75fr_1.25fr]">
              <div className="space-y-5">
                <div className="rounded-[1.6rem] bg-white p-5 shadow-sm">
                  <div className="mb-5 flex items-center justify-between">
                    <div>
                      <p className="text-base font-black text-neutral-950">
                        Agent Capacity
                      </p>
                      <p className="text-xs font-medium text-neutral-500">
                        Plan-based control limit
                      </p>
                    </div>
                    <span className="rounded-full bg-[#fff3ed] px-3 py-1 text-xs font-black uppercase tracking-[0.06em] text-[#ff5a3d]">
                      {isAdminUnlimited ? "Admin Unlimited" : effectivePlan}
                    </span>
                  </div>

                  <div className="h-3 overflow-hidden rounded-full bg-neutral-100">
                    <div
                      className="h-full rounded-full bg-[#ff5a3d]"
                      style={{
                        width: `${Math.min(
                          100,
                          Math.round(
                            (summary.enabledAgents /
                              Math.max(maxAgentsForPlan, 1)) *
                              100,
                          ),
                        )}%`,
                      }}
                    />
                  </div>

                  <div className="mt-3 flex items-center justify-between text-xs font-bold text-neutral-500">
                    <span>{summary.enabledAgents} enabled</span>
                    <span>{maxAgentsForPlan} allowed</span>
                  </div>

                  {!canConfigureAgents ? (
                    <div className="mt-5 rounded-2xl border border-amber-100 bg-amber-50 px-4 py-3 text-xs font-bold text-amber-800">
                      View-only mode: your role can inspect agents but cannot
                      change status.
                    </div>
                  ) : null}
                </div>

                <div className="rounded-[1.6rem] bg-white p-5 shadow-sm">
                  <p className="text-base font-black text-neutral-950">
                    Filters
                  </p>

                  <div className="mt-5 space-y-4">
                    <div>
                      <label className="mb-2 block text-xs font-black uppercase tracking-[0.16em] text-neutral-400">
                        Category
                      </label>
                      <select
                        value={categoryFilter}
                        onChange={(event) =>
                          setCategoryFilter(
                            event.target.value as "all" | AgentItem["category"],
                          )
                        }
                        className="h-12 w-full rounded-2xl border border-neutral-200 bg-neutral-50 px-4 text-sm font-bold outline-none focus:border-[#ff5a3d] focus:ring-4 focus:ring-[#ff5a3d]/10"
                      >
                        <option value="all">All Categories</option>
                        <option value="core">Core</option>
                        <option value="execution">Execution</option>
                        <option value="memory">Memory</option>
                        <option value="security">Security</option>
                        <option value="business">Business</option>
                        <option value="finance">Finance</option>
                        <option value="creative">Creative</option>
                        <option value="device">Device</option>
                      </select>
                    </div>

                    <div>
                      <label className="mb-2 block text-xs font-black uppercase tracking-[0.16em] text-neutral-400">
                        Status
                      </label>
                      <select
                        value={statusFilter}
                        onChange={(event) =>
                          setStatusFilter(
                            event.target.value as "all" | AgentStatus,
                          )
                        }
                        className="h-12 w-full rounded-2xl border border-neutral-200 bg-neutral-50 px-4 text-sm font-bold outline-none focus:border-[#ff5a3d] focus:ring-4 focus:ring-[#ff5a3d]/10"
                      >
                        <option value="all">All Statuses</option>
                        <option value="active">Active</option>
                        <option value="inactive">Inactive</option>
                        <option value="pending">Pending</option>
                        <option value="blocked">Blocked</option>
                        <option value="maintenance">Maintenance</option>
                      </select>
                    </div>
                  </div>
                </div>

                <div className="rounded-[1.6rem] bg-white p-5 shadow-sm">
                  <p className="text-base font-black text-neutral-950">
                    System Rules
                  </p>

                  <div className="mt-5 space-y-3">
                    {[
                      [
                        "Isolation",
                        "Every action carries user_id + workspace_id",
                      ],
                      [
                        "Security",
                        "Sensitive agent changes route for approval",
                      ],
                      ["Audit", "State-changing actions send audit headers"],
                      [
                        "Verification",
                        "Agent changes prepare confirmation payloads",
                      ],
                    ].map(([title, text]) => (
                      <div
                        key={title}
                        className="rounded-2xl border border-neutral-100 bg-neutral-50 p-4"
                      >
                        <p className="text-sm font-black text-neutral-950">
                          {title}
                        </p>
                        <p className="mt-1 text-xs font-medium text-neutral-500">
                          {text}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              <div className="rounded-[1.6rem] bg-white p-5 shadow-sm">
                <div className="mb-5 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                  <div>
                    <p className="text-lg font-black tracking-[-0.03em] text-neutral-950">
                      Agent Registry
                    </p>
                    <p className="text-sm font-medium text-neutral-500">
                      Live enable/disable/status control for all William/Jarvis
                      agents.
                    </p>
                  </div>

                  <a
                    href="/agent-permissions"
                    className="rounded-full bg-neutral-950 px-4 py-2 text-xs font-black text-white transition hover:bg-[#ff5a3d]"
                  >
                    Permissions →
                  </a>
                </div>

                {state === "empty" || filteredAgents.length === 0 ? (
                  <EmptyState
                    variant="light"
                    icon="∅"
                    title="No agents registered yet"
                    message="Connect the backend registry/plugin loader and agents will appear here with live status, enable controls, audit logs, and verification payloads."
                  />
                ) : (
                  <div className="grid gap-4 xl:grid-cols-2">
                    {filteredAgents.map((agent) => {
                      const isBusy = busyAgentId === agent.agent_id;
                      // Live /agents entries key protected core agents as
                      // "master"/"security" (apps/api/routes/agents.py's
                      // AGENT_CATALOG bare agent_name); the offline
                      // DEFAULT_AGENTS mock fallback uses the suffixed
                      // "master_agent"/"security_agent" form. Both are
                      // checked so Security Agent in particular can never
                      // be disabled from this page regardless of data
                      // source (CLAUDE.md: never disable SecurityAgent).
                      const isProtectedCoreAgent =
                        agent.key === "master" ||
                        agent.key === "master_agent" ||
                        agent.key === "security" ||
                        agent.key === "security_agent";
                      const cannotToggle =
                        !canConfigureAgents ||
                        isBusy ||
                        isProtectedCoreAgent ||
                        (agent.requires_security_approval &&
                          !canApproveSecurity);

                      return (
                        <article
                          key={agent.agent_id}
                          className="rounded-[1.5rem] border border-neutral-100 bg-neutral-50 p-4 transition hover:-translate-y-0.5 hover:bg-white hover:shadow-xl hover:shadow-black/5"
                        >
                          <div className="mb-4 flex items-start justify-between gap-4">
                            <div className="flex min-w-0 items-start gap-3">
                              <div
                                className={[
                                  "grid h-12 w-12 shrink-0 place-items-center rounded-2xl text-lg font-black",
                                  agent.enabled
                                    ? "bg-[#ff5a3d] text-white shadow-lg shadow-[#ff5a3d]/25"
                                    : "bg-white text-neutral-500",
                                ].join(" ")}
                              >
                                {getAgentIcon(agent.category)}
                              </div>

                              <div className="min-w-0">
                                <h2 className="truncate text-base font-black text-neutral-950">
                                  {agent.name}
                                </h2>
                                <p className="truncate text-xs font-bold text-neutral-400">
                                  {agent.key}
                                </p>
                              </div>
                            </div>

                            {agent.key === "voice" && voiceRuntimeState ? (
                              <span
                                className={[
                                  "rounded-full px-3 py-1 text-[11px] font-black",
                                  getVoiceRuntimeStyle(voiceRuntimeState),
                                ].join(" ")}
                              >
                                {VOICE_RUNTIME_LABELS[voiceRuntimeState]}
                              </span>
                            ) : agent.key === "system" &&
                              systemWorkerConnected !== null ? (
                              <span
                                className={[
                                  "rounded-full px-3 py-1 text-[11px] font-black",
                                  systemWorkerConnected
                                    ? "bg-emerald-50 text-emerald-700"
                                    : "bg-orange-50 text-orange-700",
                                ].join(" ")}
                              >
                                {systemWorkerConnected
                                  ? "Worker Connected"
                                  : "Worker Offline"}
                              </span>
                            ) : (
                              <span
                                className={[
                                  "rounded-full px-3 py-1 text-[11px] font-black capitalize",
                                  getStatusStyle(agent.status),
                                ].join(" ")}
                              >
                                {agent.status}
                              </span>
                            )}
                          </div>

                          <p className="min-h-10 text-sm font-medium leading-5 text-neutral-500">
                            {agent.description}
                          </p>

                          <div className="mt-4 grid grid-cols-3 gap-3">
                            <div className="rounded-2xl bg-white p-3">
                              <p className="text-[10px] font-black uppercase tracking-[0.14em] text-neutral-400">
                                Tasks
                              </p>
                              <p className="mt-1 text-sm font-black">
                                {formatNumber(agent.total_tasks)}
                              </p>
                            </div>
                            <div className="rounded-2xl bg-white p-3">
                              <p className="text-[10px] font-black uppercase tracking-[0.14em] text-neutral-400">
                                Done
                              </p>
                              <p className="mt-1 text-sm font-black text-emerald-700">
                                {formatNumber(agent.completed_tasks)}
                              </p>
                            </div>
                            <div className="rounded-2xl bg-white p-3">
                              <p className="text-[10px] font-black uppercase tracking-[0.14em] text-neutral-400">
                                Failed
                              </p>
                              <p className="mt-1 text-sm font-black text-red-700">
                                {formatNumber(agent.failed_tasks)}
                              </p>
                            </div>
                          </div>

                          {agent.key === "system" && (
                            <div className="mt-4">
                              <WindowsWorkerStatusCard variant="full" />
                            </div>
                          )}

                          <div className="mt-4 flex flex-wrap items-center gap-2">
                            <span
                              className={[
                                "rounded-full px-3 py-1 text-[11px] font-black capitalize",
                                getRiskStyle(agent.risk_level),
                              ].join(" ")}
                            >
                              {agent.risk_level} risk
                            </span>

                            {agent.requires_security_approval ? (
                              <span className="rounded-full bg-[#fff3ed] px-3 py-1 text-[11px] font-black text-[#ff5a3d]">
                                Security routed
                              </span>
                            ) : (
                              <span className="rounded-full bg-emerald-50 px-3 py-1 text-[11px] font-black text-emerald-700">
                                Standard route
                              </span>
                            )}
                          </div>

                          <button
                            type="button"
                            onClick={() => openAgentDetails(agent)}
                            className="mt-4 w-full rounded-2xl border border-neutral-200 bg-white px-4 py-3 text-left text-xs font-bold text-neutral-600 transition hover:border-[#ff5a3d] hover:text-[#ff5a3d]"
                          >
                            <span className="block text-[10px] font-black uppercase tracking-[0.14em] text-neutral-400">
                              Capabilities
                            </span>
                            <span className="mt-1 block text-neutral-800">
                              {formatCapabilitySummary(agent) ||
                                "View agent details (no capability manifest loaded)"}
                            </span>
                          </button>

                          <div className="mt-4 rounded-2xl bg-white p-3 text-xs font-medium text-neutral-500">
                            Last health check:{" "}
                            <span className="font-black text-neutral-800">
                              {formatDate(agent.last_health_check_at)}
                            </span>
                          </div>

                          <div className="mt-4 flex gap-3">
                            <button
                              type="button"
                              disabled={cannotToggle}
                              onClick={() =>
                                void handleToggleAgent(agent, !agent.enabled)
                              }
                              className={[
                                "flex-1 rounded-2xl px-4 py-3 text-xs font-black transition disabled:cursor-not-allowed disabled:opacity-50",
                                agent.enabled
                                  ? "bg-neutral-950 text-white hover:bg-red-600"
                                  : "bg-[#ff5a3d] text-white shadow-lg shadow-[#ff5a3d]/20 hover:bg-neutral-950",
                              ].join(" ")}
                            >
                              {isBusy
                                ? "Saving..."
                                : agent.enabled
                                  ? "Disable"
                                  : "Enable"}
                            </button>

                            <button
                              type="button"
                              disabled={
                                isBusy || !hasPermission(session, "agents:run")
                              }
                              onClick={() => void handleHealthCheck(agent)}
                              className="rounded-2xl border border-neutral-200 bg-white px-4 py-3 text-xs font-black text-neutral-700 transition hover:border-[#ff5a3d] hover:text-[#ff5a3d] disabled:cursor-not-allowed disabled:opacity-50"
                            >
                              Check
                            </button>
                          </div>

                          {isProtectedCoreAgent ? (
                            <p className="mt-3 text-[11px] font-bold text-neutral-400">
                              Core protected agent: direct disable is locked.
                            </p>
                          ) : null}
                        </article>
                      );
                    })}
                  </div>
                )}
              </div>
            </section>
          </div>
        )}
      </section>

      {selectedAgent ? (
        <AgentCapabilityDrawer
          agent={selectedAgent}
          onClose={() => setSelectedAgentId(null)}
          statusFilter={capabilityStatusFilter}
          onStatusFilterChange={setCapabilityStatusFilter}
        />
      ) : null}
    </div>
  );
}
