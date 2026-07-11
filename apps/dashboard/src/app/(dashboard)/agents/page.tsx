"use client";

import React, { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";

type UserRole = "owner" | "admin" | "member" | "viewer";
type UserPlan = "free" | "starter" | "pro" | "enterprise";
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
};

type AgentStatus = "active" | "inactive" | "blocked" | "pending" | "maintenance";
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
  member: ["dashboard:read", "workspace:read", "agents:read", "agents:run"],
  viewer: ["dashboard:read", "workspace:read", "agents:read"],
};

const PLAN_AGENT_LIMITS: Record<UserPlan, number> = {
  free: 2,
  starter: 5,
  pro: 14,
  enterprise: 14,
};

const DEFAULT_AGENTS: AgentItem[] = [
  {
    agent_id: "agent_master",
    key: "master_agent",
    name: "Master Agent",
    category: "core",
    description: "Plans, routes, and coordinates all workspace-safe agent tasks.",
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
    description: "Reviews sensitive actions before execution and creates safety decisions.",
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
    description: "Stores and recalls useful context inside strict workspace boundaries.",
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
    description: "Builds, reviews, and improves project code with safe execution reports.",
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
    description: "Handles browser tasks with approval gates for sensitive actions.",
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
    description: "Supports voice interaction, speech output, and command handoff.",
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
    description: "Performs safe system-level actions through strict Security Agent approval.",
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
    description: "Builds repeatable automations, approvals, and workspace-safe processes.",
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
    agent_id: "agent_call",
    key: "call_agent",
    name: "Call Agent",
    category: "business",
    description: "Supports call workflows, call summaries, and business follow-up tasks.",
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
    description: "Creates strategies, plans, SOPs, proposals, and client-ready outputs.",
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
    description: "Handles finance reports, usage summaries, and subscription insights.",
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
    description: "Creates content, images briefs, marketing assets, and campaign ideas.",
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

    if (
      !session.accessToken ||
      !session.user_id ||
      !session.workspace_id ||
      !session.role ||
      !session.plan ||
      !["active", "trialing"].includes(session.subscription_status)
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

function getRiskStyle(risk: AgentRiskLevel): string {
  if (risk === "low") return "bg-emerald-50 text-emerald-700";
  if (risk === "medium") return "bg-orange-50 text-orange-700";
  return "bg-red-50 text-red-700";
}

function calculateSummary(agents: AgentItem[]): AgentsSummary {
  return {
    totalAgents: agents.length,
    enabledAgents: agents.filter((agent) => agent.enabled).length,
    activeAgents: agents.filter((agent) => agent.status === "active").length,
    pendingAgents: agents.filter((agent) => agent.status === "pending").length,
    blockedAgents: agents.filter((agent) => agent.status === "blocked").length,
    securityProtectedAgents: agents.filter((agent) => agent.requires_security_approval).length,
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
        <p className={["text-sm font-bold", highlight ? "text-white/80" : "text-neutral-500"].join(" ")}>
          {title}
        </p>
        <span
          className={[
            "grid h-9 w-9 place-items-center rounded-full text-sm",
            highlight ? "bg-white/15 text-white" : "bg-neutral-100 text-neutral-500",
          ].join(" ")}
        >
          {icon}
        </span>
      </div>
      <p className="text-4xl font-black tracking-[-0.05em]">{value}</p>
      <p className={["mt-2 text-xs font-bold", highlight ? "text-white/75" : "text-emerald-600"].join(" ")}>
        {subtitle}
      </p>
    </div>
  );
}

function LoadingPanel() {
  return (
    <div className="grid min-h-[420px] place-items-center rounded-[2rem] bg-white shadow-sm">
      <div className="text-center">
        <div className="mx-auto h-12 w-12 animate-spin rounded-full border-4 border-neutral-200 border-t-[#ff5a3d]" />
        <p className="mt-4 text-sm font-black text-neutral-950">
          Loading agent registry...
        </p>
        <p className="mt-1 text-xs font-medium text-neutral-500">
          Checking workspace-safe agent access.
        </p>
      </div>
    </div>
  );
}

function ErrorPanel({
  message,
  onRetry,
}: {
  message: string;
  onRetry: () => void;
}) {
  return (
    <div className="grid min-h-[420px] place-items-center rounded-[2rem] border border-red-100 bg-red-50 p-8 text-center">
      <div>
        <div className="mx-auto grid h-14 w-14 place-items-center rounded-2xl bg-white text-2xl shadow-sm">
          !
        </div>
        <h2 className="mt-5 text-2xl font-black tracking-[-0.04em] text-red-900">
          Agents could not load
        </h2>
        <p className="mt-2 max-w-md text-sm font-medium text-red-700">{message}</p>
        <button
          type="button"
          onClick={onRetry}
          className="mt-6 rounded-2xl bg-red-600 px-5 py-3 text-sm font-black text-white transition hover:bg-red-700"
        >
          Retry
        </button>
      </div>
    </div>
  );
}

function EmptyPanel() {
  return (
    <div className="grid min-h-[320px] place-items-center rounded-[1.6rem] border border-dashed border-neutral-200 bg-white p-8 text-center">
      <div>
        <div className="mx-auto grid h-14 w-14 place-items-center rounded-2xl bg-neutral-100 text-xl">
          ∅
        </div>
        <h3 className="mt-4 text-xl font-black tracking-[-0.03em] text-neutral-950">
          No agents registered yet
        </h3>
        <p className="mt-2 max-w-md text-sm font-medium text-neutral-500">
          Connect the backend registry/plugin loader and agents will appear here with live status,
          enable controls, audit logs, and verification payloads.
        </p>
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
  const [categoryFilter, setCategoryFilter] = useState<"all" | AgentItem["category"]>("all");
  const [statusFilter, setStatusFilter] = useState<"all" | AgentStatus>("all");
  const [busyAgentId, setBusyAgentId] = useState<string | null>(null);
  const [notice, setNotice] = useState<{
    type: "success" | "error" | "info";
    message: string;
  } | null>(null);

  const canConfigureAgents = useMemo(() => {
    if (!session) return false;
    return hasPermission(session, "agents:configure");
  }, [session]);

  const canApproveSecurity = useMemo(() => {
    if (!session) return false;
    return hasPermission(session, "security:approve");
  }, [session]);

  const maxAgentsForPlan = useMemo(() => {
    if (!session) return 0;
    return PLAN_AGENT_LIMITS[session.plan] || 0;
  }, [session]);

  const summary = useMemo(() => calculateSummary(agents), [agents]);

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

      const matchesStatus = statusFilter === "all" || agent.status === statusFilter;

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

      const response = await apiRequest<AgentItem[]>(
        `/agents?user_id=${encodeURIComponent(activeSession.user_id)}&workspace_id=${encodeURIComponent(
          activeSession.workspace_id,
        )}`,
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

      const liveAgents = response.data || [];
      setAgents(liveAgents);
      setState(liveAgents.length > 0 ? "ready" : "empty");
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
        message: `Your ${session.plan} plan allows ${maxAgentsForPlan} enabled agent(s). Upgrade or disable another agent first.`,
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
          "X-Sensitive-Action": agent.requires_security_approval ? "true" : "false",
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
        message: response.error?.message || "Agent status could not be updated.",
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
              status: response.data?.status ?? (nextEnabled ? "active" : "inactive"),
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
        <div className="rounded-[2rem] bg-white px-8 py-7 text-center shadow-2xl shadow-black/10">
          <div className="mx-auto h-10 w-10 animate-spin rounded-full border-4 border-neutral-200 border-t-[#ff5a3d]" />
          <p className="mt-4 text-sm font-black">Checking agent access...</p>
          <p className="mt-1 text-xs font-medium text-neutral-500">
            Validating user_id and workspace_id.
          </p>
        </div>
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
                Enable, disable, monitor, and verify William/Jarvis agents without mixing workspace data.
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
            <LoadingPanel />
          ) : state === "error" ? (
            <ErrorPanel
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
                      <span className="rounded-full bg-[#fff3ed] px-3 py-1 text-xs font-black text-[#ff5a3d]">
                        {session.plan}
                      </span>
                    </div>

                    <div className="h-3 overflow-hidden rounded-full bg-neutral-100">
                      <div
                        className="h-full rounded-full bg-[#ff5a3d]"
                        style={{
                          width: `${Math.min(
                            100,
                            Math.round((summary.enabledAgents / Math.max(maxAgentsForPlan, 1)) * 100),
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
                        View-only mode: your role can inspect agents but cannot change status.
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
                            setCategoryFilter(event.target.value as "all" | AgentItem["category"])
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
                            setStatusFilter(event.target.value as "all" | AgentStatus)
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
                        ["Isolation", "Every action carries user_id + workspace_id"],
                        ["Security", "Sensitive agent changes route for approval"],
                        ["Audit", "State-changing actions send audit headers"],
                        ["Verification", "Agent changes prepare confirmation payloads"],
                      ].map(([title, text]) => (
                        <div
                          key={title}
                          className="rounded-2xl border border-neutral-100 bg-neutral-50 p-4"
                        >
                          <p className="text-sm font-black text-neutral-950">{title}</p>
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
                        Live enable/disable/status control for all William/Jarvis agents.
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
                    <EmptyPanel />
                  ) : (
                    <div className="grid gap-4 xl:grid-cols-2">
                      {filteredAgents.map((agent) => {
                        const isBusy = busyAgentId === agent.agent_id;
                        const cannotToggle =
                          !canConfigureAgents ||
                          isBusy ||
                          agent.key === "master_agent" ||
                          agent.key === "security_agent" ||
                          (agent.requires_security_approval && !canApproveSecurity);

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

                              <span
                                className={[
                                  "rounded-full px-3 py-1 text-[11px] font-black capitalize",
                                  getStatusStyle(agent.status),
                                ].join(" ")}
                              >
                                {agent.status}
                              </span>
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
                                onClick={() => void handleToggleAgent(agent, !agent.enabled)}
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
                                disabled={isBusy || !hasPermission(session, "agents:run")}
                                onClick={() => void handleHealthCheck(agent)}
                                className="rounded-2xl border border-neutral-200 bg-white px-4 py-3 text-xs font-black text-neutral-700 transition hover:border-[#ff5a3d] hover:text-[#ff5a3d] disabled:cursor-not-allowed disabled:opacity-50"
                              >
                                Check
                              </button>
                            </div>

                            {agent.key === "master_agent" || agent.key === "security_agent" ? (
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
    </div>
  );
}