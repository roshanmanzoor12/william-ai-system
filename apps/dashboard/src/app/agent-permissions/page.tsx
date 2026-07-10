"use client";

import React, { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";

type UserRole = "owner" | "admin" | "member" | "viewer";
type UserPlan = "free" | "starter" | "pro" | "enterprise";
type SubscriptionStatus = "active" | "trialing" | "past_due" | "canceled";
type LoadState = "checking_session" | "loading" | "ready" | "empty" | "error";

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

type WorkspaceUser = {
  user_id: string;
  workspace_id: string;
  name: string;
  email: string;
  role: UserRole;
  plan: UserPlan;
  status: "active" | "invited" | "suspended";
  assigned_agents: string[];
  created_at?: string;
  last_active_at?: string | null;
};

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
  enabled: boolean;
  status: "active" | "inactive" | "blocked" | "pending" | "maintenance";
  requires_security_approval: boolean;
  risk_level: "low" | "medium" | "high";
  minimum_plan: UserPlan;
  allowed_roles: UserRole[];
};

type RolePermissionMatrix = Record<UserRole, string[]>;

type PermissionPayload = {
  target_user_id: string;
  target_role: UserRole;
  target_plan: UserPlan;
  assigned_agents: string[];
  notes?: string;
};

type PermissionUpdateResponse = {
  user_id: string;
  workspace_id: string;
  assigned_agents: string[];
  audit?: {
    event_id?: string;
    action: "agent_permissions.update";
  };
  security?: {
    routed_to_security_agent: boolean;
    approved: boolean;
    risk_level: "low" | "medium" | "high";
  };
  verification?: {
    verification_id?: string;
    status: "prepared" | "completed" | "pending";
  };
};

type PageData = {
  users: WorkspaceUser[];
  agents: AgentItem[];
  role_matrix: RolePermissionMatrix;
};

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || "";

const ROLE_PERMISSIONS: Record<UserRole, string[]> = {
  owner: [
    "dashboard:read",
    "workspace:read",
    "users:read",
    "users:write",
    "agents:read",
    "agents:run",
    "agents:configure",
    "agent_permissions:read",
    "agent_permissions:write",
    "security:approve",
    "audit:read",
  ],
  admin: [
    "dashboard:read",
    "workspace:read",
    "users:read",
    "agents:read",
    "agents:run",
    "agents:configure",
    "agent_permissions:read",
    "agent_permissions:write",
    "audit:read",
  ],
  member: ["dashboard:read", "workspace:read", "agents:read", "agents:run", "agent_permissions:read"],
  viewer: ["dashboard:read", "workspace:read", "agents:read", "agent_permissions:read"],
};

const PLAN_ORDER: Record<UserPlan, number> = {
  free: 1,
  starter: 2,
  pro: 3,
  enterprise: 4,
};

const PLAN_AGENT_LIMITS: Record<UserPlan, number> = {
  free: 2,
  starter: 5,
  pro: 14,
  enterprise: 14,
};

const DEFAULT_ROLE_MATRIX: RolePermissionMatrix = {
  owner: [
    "master_agent",
    "security_agent",
    "verification_agent",
    "memory_agent",
    "code_agent",
    "browser_agent",
    "voice_agent",
    "system_agent",
    "visual_agent",
    "workflow_agent",
    "call_agent",
    "business_agent",
    "finance_agent",
    "creator_agent",
  ],
  admin: [
    "master_agent",
    "security_agent",
    "verification_agent",
    "memory_agent",
    "code_agent",
    "browser_agent",
    "visual_agent",
    "workflow_agent",
    "business_agent",
    "creator_agent",
  ],
  member: [
    "master_agent",
    "verification_agent",
    "memory_agent",
    "code_agent",
    "business_agent",
    "creator_agent",
  ],
  viewer: ["master_agent", "verification_agent", "memory_agent"],
};

const DEFAULT_AGENTS: AgentItem[] = [
  {
    agent_id: "agent_master",
    key: "master_agent",
    name: "Master Agent",
    category: "core",
    description: "Plans, routes, and coordinates every workspace-safe request.",
    enabled: true,
    status: "active",
    requires_security_approval: false,
    risk_level: "medium",
    minimum_plan: "free",
    allowed_roles: ["owner", "admin", "member", "viewer"],
  },
  {
    agent_id: "agent_security",
    key: "security_agent",
    name: "Security Agent",
    category: "security",
    description: "Approves sensitive actions and prevents unsafe execution.",
    enabled: true,
    status: "active",
    requires_security_approval: false,
    risk_level: "high",
    minimum_plan: "free",
    allowed_roles: ["owner", "admin"],
  },
  {
    agent_id: "agent_verification",
    key: "verification_agent",
    name: "Verification Agent",
    category: "core",
    description: "Prepares confirmation payloads and completion evidence.",
    enabled: true,
    status: "active",
    requires_security_approval: false,
    risk_level: "medium",
    minimum_plan: "free",
    allowed_roles: ["owner", "admin", "member", "viewer"],
  },
  {
    agent_id: "agent_memory",
    key: "memory_agent",
    name: "Memory Agent",
    category: "memory",
    description: "Stores and recalls useful context inside workspace boundaries.",
    enabled: true,
    status: "active",
    requires_security_approval: true,
    risk_level: "high",
    minimum_plan: "free",
    allowed_roles: ["owner", "admin", "member", "viewer"],
  },
  {
    agent_id: "agent_code",
    key: "code_agent",
    name: "Code Agent",
    category: "execution",
    description: "Builds, reviews, and fixes code through controlled workflows.",
    enabled: true,
    status: "active",
    requires_security_approval: true,
    risk_level: "high",
    minimum_plan: "starter",
    allowed_roles: ["owner", "admin", "member"],
  },
  {
    agent_id: "agent_browser",
    key: "browser_agent",
    name: "Browser Agent",
    category: "execution",
    description: "Handles browser operations with sensitive-action approval gates.",
    enabled: true,
    status: "active",
    requires_security_approval: true,
    risk_level: "high",
    minimum_plan: "pro",
    allowed_roles: ["owner", "admin"],
  },
  {
    agent_id: "agent_voice",
    key: "voice_agent",
    name: "Voice Agent",
    category: "device",
    description: "Supports speech commands, voice output, and voice handoff.",
    enabled: true,
    status: "active",
    requires_security_approval: false,
    risk_level: "medium",
    minimum_plan: "starter",
    allowed_roles: ["owner", "admin", "member"],
  },
  {
    agent_id: "agent_system",
    key: "system_agent",
    name: "System Agent",
    category: "device",
    description: "Runs local/system actions only after strict security approval.",
    enabled: false,
    status: "blocked",
    requires_security_approval: true,
    risk_level: "high",
    minimum_plan: "enterprise",
    allowed_roles: ["owner"],
  },
  {
    agent_id: "agent_visual",
    key: "visual_agent",
    name: "Visual Agent",
    category: "creative",
    description: "Reads layouts, screenshots, UI states, and visual issues.",
    enabled: true,
    status: "active",
    requires_security_approval: false,
    risk_level: "medium",
    minimum_plan: "starter",
    allowed_roles: ["owner", "admin", "member"],
  },
  {
    agent_id: "agent_workflow",
    key: "workflow_agent",
    name: "Workflow Agent",
    category: "business",
    description: "Creates repeatable automations, SOPs, and execution chains.",
    enabled: true,
    status: "active",
    requires_security_approval: true,
    risk_level: "medium",
    minimum_plan: "pro",
    allowed_roles: ["owner", "admin"],
  },
  {
    agent_id: "agent_call",
    key: "call_agent",
    name: "Call Agent",
    category: "business",
    description: "Supports call workflows, summaries, and follow-up actions.",
    enabled: true,
    status: "active",
    requires_security_approval: true,
    risk_level: "high",
    minimum_plan: "pro",
    allowed_roles: ["owner", "admin"],
  },
  {
    agent_id: "agent_business",
    key: "business_agent",
    name: "Business Agent",
    category: "business",
    description: "Generates strategy, proposals, SOPs, and operational plans.",
    enabled: true,
    status: "active",
    requires_security_approval: false,
    risk_level: "low",
    minimum_plan: "free",
    allowed_roles: ["owner", "admin", "member"],
  },
  {
    agent_id: "agent_finance",
    key: "finance_agent",
    name: "Finance Agent",
    category: "finance",
    description: "Handles finance summaries, usage reports, and billing insights.",
    enabled: true,
    status: "active",
    requires_security_approval: true,
    risk_level: "high",
    minimum_plan: "pro",
    allowed_roles: ["owner", "admin"],
  },
  {
    agent_id: "agent_creator",
    key: "creator_agent",
    name: "Creator Agent",
    category: "creative",
    description: "Creates content, campaign ideas, briefs, and marketing assets.",
    enabled: true,
    status: "active",
    requires_security_approval: false,
    risk_level: "low",
    minimum_plan: "free",
    allowed_roles: ["owner", "admin", "member"],
  },
];

const DEFAULT_USERS: WorkspaceUser[] = [
  {
    user_id: "user_owner",
    workspace_id: "default_workspace",
    name: "Admin",
    email: "admin@digitalpromotix.com",
    role: "owner",
    plan: "pro",
    status: "active",
    assigned_agents: DEFAULT_ROLE_MATRIX.owner,
    last_active_at: new Date().toISOString(),
  },
  {
    user_id: "user_manager",
    workspace_id: "default_workspace",
    name: "Manager",
    email: "manager@digitalpromotix.com",
    role: "admin",
    plan: "pro",
    status: "active",
    assigned_agents: DEFAULT_ROLE_MATRIX.admin,
    last_active_at: new Date().toISOString(),
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
      { status: session.subscription_status },
    );
  }

  if (!hasPermission(session, "agent_permissions:read")) {
    return createSafeError(
      "PERMISSION_READ_DENIED",
      "Your role cannot view agent permissions.",
      403,
      { role: session.role },
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
      { required_env: "NEXT_PUBLIC_API_BASE_URL" },
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

function planAllowsAgent(userPlan: UserPlan, minimumPlan: UserPlan): boolean {
  return PLAN_ORDER[userPlan] >= PLAN_ORDER[minimumPlan];
}

function roleAllowsAgent(role: UserRole, agent: AgentItem): boolean {
  return agent.allowed_roles.includes(role);
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

function getRiskStyle(risk: AgentItem["risk_level"]): string {
  if (risk === "low") return "bg-emerald-50 text-emerald-700";
  if (risk === "medium") return "bg-orange-50 text-orange-700";
  return "bg-red-50 text-red-700";
}

function getRoleStyle(role: UserRole): string {
  if (role === "owner") return "bg-[#ff5a3d] text-white";
  if (role === "admin") return "bg-neutral-950 text-white";
  if (role === "member") return "bg-emerald-50 text-emerald-700";
  return "bg-neutral-100 text-neutral-600";
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

function IconBox({
  children,
  active,
}: {
  children: React.ReactNode;
  active?: boolean;
}) {
  return (
    <div
      className={[
        "grid h-11 w-11 place-items-center rounded-2xl border text-sm font-black transition",
        active
          ? "border-black bg-black text-white shadow-xl shadow-black/15"
          : "border-neutral-200 bg-white text-neutral-500",
      ].join(" ")}
    >
      {children}
    </div>
  );
}

function StatCard({
  title,
  value,
  subtitle,
  icon,
  highlight,
}: {
  title: string;
  value: string;
  subtitle: string;
  icon: string;
  highlight?: boolean;
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
          Loading permission matrix...
        </p>
        <p className="mt-1 text-xs font-medium text-neutral-500">
          Checking users, roles, plans, and workspace-safe assignments.
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
          Permissions could not load
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
          No workspace users found
        </h3>
        <p className="mt-2 max-w-md text-sm font-medium text-neutral-500">
          Invite users into this workspace and assign agent access by role, plan, and user-level overrides.
        </p>
      </div>
    </div>
  );
}

export default function Page() {
  const router = useRouter();

  const [session, setSession] = useState<SessionData | null>(null);
  const [users, setUsers] = useState<WorkspaceUser[]>([]);
  const [agents, setAgents] = useState<AgentItem[]>([]);
  const [roleMatrix, setRoleMatrix] = useState<RolePermissionMatrix>(DEFAULT_ROLE_MATRIX);
  const [selectedUserId, setSelectedUserId] = useState<string>("");
  const [state, setState] = useState<LoadState>("checking_session");
  const [errorMessage, setErrorMessage] = useState("");
  const [search, setSearch] = useState("");
  const [notes, setNotes] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<{
    type: "success" | "error" | "info";
    message: string;
  } | null>(null);

  const selectedUser = useMemo(
    () => users.find((user) => user.user_id === selectedUserId) || null,
    [selectedUserId, users],
  );

  const canWritePermissions = useMemo(() => {
    if (!session) return false;
    return hasPermission(session, "agent_permissions:write");
  }, [session]);

  const canApproveSecurity = useMemo(() => {
    if (!session) return false;
    return hasPermission(session, "security:approve");
  }, [session]);

  const filteredAgents = useMemo(() => {
    const normalizedSearch = search.trim().toLowerCase();

    return agents.filter((agent) => {
      if (!normalizedSearch) return true;

      return (
        agent.name.toLowerCase().includes(normalizedSearch) ||
        agent.key.toLowerCase().includes(normalizedSearch) ||
        agent.description.toLowerCase().includes(normalizedSearch) ||
        agent.category.toLowerCase().includes(normalizedSearch)
      );
    });
  }, [agents, search]);

  const selectedAssignedAgents = useMemo(() => {
    if (!selectedUser) return new Set<string>();
    return new Set(selectedUser.assigned_agents);
  }, [selectedUser]);

  const selectedAllowedByRole = useMemo(() => {
    if (!selectedUser) return new Set<string>();
    return new Set(roleMatrix[selectedUser.role] || []);
  }, [roleMatrix, selectedUser]);

  const selectedPlanLimit = selectedUser ? PLAN_AGENT_LIMITS[selectedUser.plan] : 0;
  const selectedAssignedCount = selectedUser?.assigned_agents.length || 0;

  const sensitiveAssignedCount = useMemo(() => {
    if (!selectedUser) return 0;

    return agents.filter(
      (agent) =>
        selectedUser.assigned_agents.includes(agent.key) &&
        agent.requires_security_approval,
    ).length;
  }, [agents, selectedUser]);

  const loadPageData = useCallback(
    async (activeSession: SessionData) => {
      setState("loading");
      setErrorMessage("");

      const access = validateAccess(activeSession);

      if (!access.success) {
        clearSession();
        router.replace("/login");
        return;
      }

      const response = await apiRequest<PageData>(
        `/agent-permissions?user_id=${encodeURIComponent(
          activeSession.user_id,
        )}&workspace_id=${encodeURIComponent(activeSession.workspace_id)}`,
        activeSession,
        {
          method: "GET",
          headers: {
            "X-Action": "agent_permissions.read",
          },
        },
      );

      if (!response.success) {
        if (response.error?.code === "API_BASE_URL_MISSING") {
          const safeUsers = DEFAULT_USERS.map((user) => ({
            ...user,
            workspace_id: activeSession.workspace_id,
            plan: activeSession.plan,
          }));

          setUsers(safeUsers);
          setAgents(DEFAULT_AGENTS);
          setRoleMatrix(DEFAULT_ROLE_MATRIX);
          setSelectedUserId(safeUsers[0]?.user_id || "");
          setState("ready");
          setNotice({
            type: "info",
            message:
              "API is not connected yet, so this page is showing the built-in William/Jarvis permission structure. Connect NEXT_PUBLIC_API_BASE_URL for live database assignments.",
          });
          return;
        }

        setState("error");
        setErrorMessage(response.error?.message || "Could not load agent permissions.");
        return;
      }

      const data = response.data || {
        users: [],
        agents: [],
        role_matrix: DEFAULT_ROLE_MATRIX,
      };

      const safeUsers = data.users.filter(
        (user) => user.workspace_id === activeSession.workspace_id,
      );

      setUsers(safeUsers);
      setAgents(data.agents || []);
      setRoleMatrix(data.role_matrix || DEFAULT_ROLE_MATRIX);
      setSelectedUserId(safeUsers[0]?.user_id || "");
      setState(safeUsers.length > 0 ? "ready" : "empty");
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
    void loadPageData(activeSession);
  }, [loadPageData, router]);

  function toggleLocalAgent(agent: AgentItem) {
    if (!selectedUser) return;

    if (!canWritePermissions) {
      setNotice({
        type: "error",
        message: "Your role cannot change agent permissions.",
      });
      return;
    }

    if (agent.requires_security_approval && !canApproveSecurity) {
      setNotice({
        type: "error",
        message:
          "This agent requires Security Agent approval. Your role cannot approve this permission change.",
      });
      return;
    }

    if (!roleAllowsAgent(selectedUser.role, agent)) {
      setNotice({
        type: "error",
        message: `${selectedUser.role} role cannot use ${agent.name}. Change the user role or role matrix first.`,
      });
      return;
    }

    if (!planAllowsAgent(selectedUser.plan, agent.minimum_plan)) {
      setNotice({
        type: "error",
        message: `${agent.name} requires ${agent.minimum_plan} plan or higher.`,
      });
      return;
    }

    const currentlyAssigned = selectedAssignedAgents.has(agent.key);
    const nextAssigned = currentlyAssigned
      ? selectedUser.assigned_agents.filter((key) => key !== agent.key)
      : [...selectedUser.assigned_agents, agent.key];

    if (!currentlyAssigned && nextAssigned.length > PLAN_AGENT_LIMITS[selectedUser.plan]) {
      setNotice({
        type: "error",
        message: `${selectedUser.plan} plan allows ${PLAN_AGENT_LIMITS[selectedUser.plan]} assigned agent(s).`,
      });
      return;
    }

    setUsers((current) =>
      current.map((user) =>
        user.user_id === selectedUser.user_id
          ? {
              ...user,
              assigned_agents: nextAssigned,
            }
          : user,
      ),
    );

    setNotice(null);
  }

  async function handleSave(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (!session || !selectedUser) {
      router.replace("/login");
      return;
    }

    if (!canWritePermissions) {
      setNotice({
        type: "error",
        message: "Your role cannot save permission changes.",
      });
      return;
    }

    const selectedSensitiveAgents = agents.filter(
      (agent) =>
        selectedUser.assigned_agents.includes(agent.key) &&
        agent.requires_security_approval,
    );

    if (selectedSensitiveAgents.length > 0 && !canApproveSecurity) {
      setNotice({
        type: "error",
        message:
          "This change includes sensitive agents. Security Agent approval permission is required.",
      });
      return;
    }

    const invalidAgents = agents.filter((agent) => {
      if (!selectedUser.assigned_agents.includes(agent.key)) return false;
      return (
        !roleAllowsAgent(selectedUser.role, agent) ||
        !planAllowsAgent(selectedUser.plan, agent.minimum_plan)
      );
    });

    if (invalidAgents.length > 0) {
      setNotice({
        type: "error",
        message: `Fix invalid assignments first: ${invalidAgents
          .map((agent) => agent.name)
          .join(", ")}`,
      });
      return;
    }

    setBusy(true);
    setNotice(null);

    const payload: PermissionPayload = {
      target_user_id: selectedUser.user_id,
      target_role: selectedUser.role,
      target_plan: selectedUser.plan,
      assigned_agents: selectedUser.assigned_agents,
      notes: notes.trim() || undefined,
    };

    const response = await apiRequest<PermissionUpdateResponse>(
      `/agent-permissions/${encodeURIComponent(selectedUser.user_id)}`,
      session,
      {
        method: "PUT",
        headers: {
          "X-Action": "agent_permissions.update",
          "X-Sensitive-Action": selectedSensitiveAgents.length > 0 ? "true" : "false",
        },
        body: JSON.stringify({
          user_id: session.user_id,
          workspace_id: session.workspace_id,
          payload,
          route: {
            master_agent: true,
            security_agent: selectedSensitiveAgents.length > 0,
            memory_agent: true,
            verification_agent: true,
          },
          clientContext: {
            app: "william-dashboard",
            module: "agent_permissions",
            action: "agent_permissions.update",
            requiresAudit: true,
            requiresSecurityRoute: selectedSensitiveAgents.length > 0,
            memoryCompatible: true,
            verificationCompatible: true,
          },
        }),
      },
    );

    if (!response.success || !response.data) {
      if (response.error?.code === "API_BASE_URL_MISSING") {
        setNotice({
          type: "info",
          message:
            "Local permission matrix updated. Connect the API to persist changes in the database.",
        });
        setBusy(false);
        return;
      }

      setNotice({
        type: "error",
        message: response.error?.message || "Permission changes could not be saved.",
      });
      setBusy(false);
      return;
    }

    setUsers((current) =>
      current.map((user) =>
        user.user_id === selectedUser.user_id
          ? {
              ...user,
              assigned_agents: response.data?.assigned_agents || selectedUser.assigned_agents,
            }
          : user,
      ),
    );

    setNotice({
      type: "success",
      message:
        "Agent permissions saved. Security route, audit log, memory context, and verification payload are prepared.",
    });

    setBusy(false);
  }

  function applyRoleDefaults() {
    if (!selectedUser) return;

    if (!canWritePermissions) {
      setNotice({
        type: "error",
        message: "Your role cannot apply role defaults.",
      });
      return;
    }

    const roleDefaults = roleMatrix[selectedUser.role] || [];
    const allowedByPlan = roleDefaults.filter((agentKey) => {
      const agent = agents.find((item) => item.key === agentKey);
      if (!agent) return false;
      return planAllowsAgent(selectedUser.plan, agent.minimum_plan);
    });

    setUsers((current) =>
      current.map((user) =>
        user.user_id === selectedUser.user_id
          ? {
              ...user,
              assigned_agents: allowedByPlan.slice(0, PLAN_AGENT_LIMITS[selectedUser.plan]),
            }
          : user,
      ),
    );

    setNotice({
      type: "info",
      message: `Applied ${selectedUser.role} role defaults within ${selectedUser.plan} plan limit.`,
    });
  }

  function clearAssignments() {
    if (!selectedUser) return;

    if (!canWritePermissions) {
      setNotice({
        type: "error",
        message: "Your role cannot clear assignments.",
      });
      return;
    }

    const protectedAgents = ["master_agent", "verification_agent"];

    setUsers((current) =>
      current.map((user) =>
        user.user_id === selectedUser.user_id
          ? {
              ...user,
              assigned_agents: user.assigned_agents.filter((key) =>
                protectedAgents.includes(key),
              ),
            }
          : user,
      ),
    );

    setNotice({
      type: "info",
      message: "Optional assignments cleared. Protected core agents remain assigned.",
    });
  }

  function handleLogout() {
    clearSession();
    router.replace("/login");
  }

  if (state === "checking_session" || !session) {
    return (
      <main className="grid min-h-screen place-items-center bg-[#e9e9e7] px-6 text-neutral-950">
        <div className="rounded-[2rem] bg-white px-8 py-7 text-center shadow-2xl shadow-black/10">
          <div className="mx-auto h-10 w-10 animate-spin rounded-full border-4 border-neutral-200 border-t-[#ff5a3d]" />
          <p className="mt-4 text-sm font-black">Checking permissions access...</p>
          <p className="mt-1 text-xs font-medium text-neutral-500">
            Validating user_id and workspace_id.
          </p>
        </div>
      </main>
    );
  }

  return (
    <main className="min-h-screen bg-[#e9e9e7] px-4 py-6 text-neutral-950 sm:px-6 lg:px-8">
      <div className="mx-auto flex min-h-[calc(100vh-3rem)] max-w-7xl overflow-hidden rounded-[2.25rem] bg-[#f7f7f6] p-4 shadow-2xl shadow-black/10">
        <aside className="hidden w-[72px] shrink-0 flex-col items-center justify-between rounded-[1.8rem] bg-white p-4 shadow-sm lg:flex">
          <div className="space-y-8">
            <div className="grid h-12 w-12 place-items-center rounded-2xl bg-[#ff5a3d] text-lg font-black text-white shadow-xl shadow-[#ff5a3d]/25">
              W
            </div>

            <div className="space-y-3">
              <a href="/dashboard" aria-label="Dashboard">
                <IconBox>⌘</IconBox>
              </a>
              <a href="/agents" aria-label="Agents">
                <IconBox>▦</IconBox>
              </a>
              <IconBox active>☷</IconBox>
              <a href="/memory" aria-label="Memory">
                <IconBox>◌</IconBox>
              </a>
              <a href="/security" aria-label="Security">
                <IconBox>▣</IconBox>
              </a>
              <a href="/workflows" aria-label="Workflows">
                <IconBox>◎</IconBox>
              </a>
              <a href="/settings" aria-label="Settings">
                <IconBox>⚙</IconBox>
              </a>
            </div>
          </div>

          <div className="space-y-3">
            <IconBox>?</IconBox>
            <button type="button" onClick={handleLogout} aria-label="Logout">
              <IconBox>↩</IconBox>
            </button>
          </div>
        </aside>

        <section className="flex min-w-0 flex-1 flex-col px-0 lg:px-6">
          <header className="mb-6 flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
            <div className="flex flex-col gap-4 lg:flex-row lg:items-center">
              <div className="lg:hidden flex items-center gap-3 rounded-[1.5rem] bg-white p-3 shadow-sm">
                <div className="grid h-11 w-11 place-items-center rounded-2xl bg-[#ff5a3d] font-black text-white">
                  W
                </div>
                <div>
                  <p className="text-sm font-black">Agent Permissions</p>
                  <p className="text-xs font-medium text-neutral-500">
                    {session.workspace_name}
                  </p>
                </div>
              </div>

              <div className="relative w-full max-w-md">
                <span className="absolute left-4 top-1/2 -translate-y-1/2 text-neutral-400">
                  ⌕
                </span>
                <input
                  type="search"
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                  placeholder="Search agents, plans, roles, permissions..."
                  className="h-12 w-full rounded-full border border-neutral-200 bg-white px-11 text-sm font-semibold outline-none transition placeholder:text-neutral-400 focus:border-[#ff5a3d] focus:ring-4 focus:ring-[#ff5a3d]/10"
                />
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <span className="rounded-full border border-emerald-100 bg-emerald-50 px-4 py-2 text-xs font-black text-emerald-700">
                🔒 Security Guarded
              </span>
              <span className="rounded-full border border-[#ffd9cc] bg-[#fff3ed] px-4 py-2 text-xs font-black text-[#ff5a3d]">
                ⛓ Workspace Isolated
              </span>
              <div className="flex items-center gap-3 rounded-full bg-white px-3 py-2 shadow-sm">
                <div className="grid h-10 w-10 place-items-center rounded-full bg-[#ff5a3d] text-xs font-black text-white">
                  {session.name
                    .split(" ")
                    .map((part) => part[0])
                    .join("")
                    .slice(0, 2)
                    .toUpperCase() || "DP"}
                </div>
                <div>
                  <p className="max-w-[130px] truncate text-xs font-black text-neutral-950">
                    {session.name}
                  </p>
                  <p className="max-w-[130px] truncate text-[11px] font-medium text-neutral-500">
                    {session.role} · {session.plan}
                  </p>
                </div>
              </div>
            </div>
          </header>

          <div className="mb-6 flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <h1 className="text-4xl font-black tracking-[-0.055em] text-neutral-950 lg:text-5xl">
                Agent Permissions
              </h1>
              <p className="mt-2 text-sm font-medium text-neutral-500">
                Assign William/Jarvis agents by user, role, and plan with secure workspace isolation.
              </p>
            </div>

            <div className="rounded-2xl bg-white px-4 py-3 shadow-sm">
              <p className="text-[11px] font-black uppercase tracking-[0.18em] text-neutral-400">
                Workspace
              </p>
              <p className="mt-1 text-sm font-black text-neutral-950">
                {session.workspace_name}
              </p>
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
                if (session) void loadPageData(session);
              }}
            />
          ) : state === "empty" ? (
            <EmptyPanel />
          ) : (
            <form onSubmit={handleSave} className="space-y-5">
              <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
                <StatCard
                  title="Workspace Users"
                  value={String(users.length)}
                  subtitle="Same workspace only"
                  icon="◎"
                  highlight
                />
                <StatCard
                  title="Agents"
                  value={String(agents.length)}
                  subtitle="Registry compatible"
                  icon="▦"
                />
                <StatCard
                  title="Assigned"
                  value={String(selectedAssignedCount)}
                  subtitle={`${selectedPlanLimit} plan limit`}
                  icon="✓"
                />
                <StatCard
                  title="Sensitive"
                  value={String(sensitiveAssignedCount)}
                  subtitle="Security routed"
                  icon="▣"
                />
                <StatCard
                  title="Plan"
                  value={(selectedUser?.plan || session.plan).toUpperCase()}
                  subtitle="Role + plan checked"
                  icon="$"
                />
              </section>

              <section className="grid gap-5 xl:grid-cols-[0.75fr_1.25fr]">
                <div className="space-y-5">
                  <div className="rounded-[1.6rem] bg-white p-5 shadow-sm">
                    <div className="mb-5 flex items-center justify-between">
                      <div>
                        <p className="text-base font-black text-neutral-950">
                          Workspace Users
                        </p>
                        <p className="text-xs font-medium text-neutral-500">
                          Select user to assign agents.
                        </p>
                      </div>
                      <span className="rounded-full bg-neutral-100 px-3 py-1 text-xs font-black text-neutral-600">
                        {users.length}
                      </span>
                    </div>

                    <div className="space-y-3">
                      {users.map((user) => (
                        <button
                          key={user.user_id}
                          type="button"
                          onClick={() => {
                            setSelectedUserId(user.user_id);
                            setNotice(null);
                          }}
                          className={[
                            "w-full rounded-2xl border p-4 text-left transition",
                            selectedUserId === user.user_id
                              ? "border-[#ff5a3d] bg-[#fff3ed]"
                              : "border-neutral-100 bg-neutral-50 hover:bg-white",
                          ].join(" ")}
                        >
                          <div className="flex items-center justify-between gap-3">
                            <div className="min-w-0">
                              <p className="truncate text-sm font-black text-neutral-950">
                                {user.name}
                              </p>
                              <p className="truncate text-xs font-medium text-neutral-500">
                                {user.email}
                              </p>
                            </div>
                            <span
                              className={[
                                "rounded-full px-3 py-1 text-[11px] font-black capitalize",
                                getRoleStyle(user.role),
                              ].join(" ")}
                            >
                              {user.role}
                            </span>
                          </div>

                          <div className="mt-3 flex items-center justify-between text-xs font-bold text-neutral-500">
                            <span>{user.assigned_agents.length} agents</span>
                            <span>{formatDate(user.last_active_at)}</span>
                          </div>
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="rounded-[1.6rem] bg-white p-5 shadow-sm">
                    <p className="text-base font-black text-neutral-950">
                      Assignment Actions
                    </p>
                    <p className="mt-1 text-xs font-medium text-neutral-500">
                      Apply safe role defaults or clear optional permissions.
                    </p>

                    <div className="mt-5 grid gap-3">
                      <button
                        type="button"
                        disabled={!selectedUser || !canWritePermissions || busy}
                        onClick={applyRoleDefaults}
                        className="rounded-2xl bg-neutral-950 px-4 py-3 text-sm font-black text-white transition hover:bg-[#ff5a3d] disabled:cursor-not-allowed disabled:opacity-50"
                      >
                        Apply Role Defaults
                      </button>
                      <button
                        type="button"
                        disabled={!selectedUser || !canWritePermissions || busy}
                        onClick={clearAssignments}
                        className="rounded-2xl border border-neutral-200 bg-white px-4 py-3 text-sm font-black text-neutral-700 transition hover:border-red-200 hover:bg-red-50 hover:text-red-700 disabled:cursor-not-allowed disabled:opacity-50"
                      >
                        Clear Optional Assignments
                      </button>
                    </div>

                    {!canWritePermissions ? (
                      <div className="mt-5 rounded-2xl border border-amber-100 bg-amber-50 px-4 py-3 text-xs font-bold text-amber-800">
                        View-only mode: your role cannot change agent assignments.
                      </div>
                    ) : null}
                  </div>

                  <div className="rounded-[1.6rem] bg-white p-5 shadow-sm">
                    <label
                      htmlFor="notes"
                      className="block text-base font-black text-neutral-950"
                    >
                      Change Notes
                    </label>
                    <p className="mt-1 text-xs font-medium text-neutral-500">
                      Saved with audit and verification metadata.
                    </p>
                    <textarea
                      id="notes"
                      value={notes}
                      disabled={busy}
                      onChange={(event) => setNotes(event.target.value)}
                      placeholder="Example: Enabled Code Agent for project build workflow."
                      className="mt-4 min-h-28 w-full resize-none rounded-2xl border border-neutral-200 bg-neutral-50 p-4 text-sm font-semibold outline-none transition placeholder:text-neutral-400 focus:border-[#ff5a3d] focus:bg-white focus:ring-4 focus:ring-[#ff5a3d]/10 disabled:cursor-not-allowed disabled:opacity-60"
                    />
                  </div>
                </div>

                <div className="rounded-[1.6rem] bg-white p-5 shadow-sm">
                  <div className="mb-5 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                    <div>
                      <p className="text-lg font-black tracking-[-0.03em] text-neutral-950">
                        Agent Assignment Matrix
                      </p>
                      <p className="text-sm font-medium text-neutral-500">
                        {selectedUser
                          ? `Assigning agents for ${selectedUser.name} (${selectedUser.role}, ${selectedUser.plan})`
                          : "Select a user to manage agent assignments."}
                      </p>
                    </div>

                    <button
                      type="submit"
                      disabled={!selectedUser || !canWritePermissions || busy}
                      className="rounded-full bg-[#ff5a3d] px-5 py-3 text-xs font-black text-white shadow-lg shadow-[#ff5a3d]/20 transition hover:bg-neutral-950 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      {busy ? "Saving..." : "Save Permissions"}
                    </button>
                  </div>

                  {!selectedUser ? (
                    <EmptyPanel />
                  ) : (
                    <div className="grid gap-4 xl:grid-cols-2">
                      {filteredAgents.map((agent) => {
                        const isAssigned = selectedAssignedAgents.has(agent.key);
                        const isRoleAllowed = roleAllowsAgent(selectedUser.role, agent);
                        const isPlanAllowed = planAllowsAgent(
                          selectedUser.plan,
                          agent.minimum_plan,
                        );
                        const isRoleDefault = selectedAllowedByRole.has(agent.key);
                        const isLocked =
                          agent.key === "master_agent" ||
                          agent.key === "verification_agent";
                        const disabled =
                          busy ||
                          !canWritePermissions ||
                          isLocked ||
                          !isRoleAllowed ||
                          !isPlanAllowed ||
                          (agent.requires_security_approval && !canApproveSecurity);

                        return (
                          <article
                            key={agent.agent_id}
                            className={[
                              "rounded-[1.5rem] border p-4 transition",
                              isAssigned
                                ? "border-[#ff5a3d]/40 bg-[#fff3ed]"
                                : "border-neutral-100 bg-neutral-50 hover:bg-white",
                            ].join(" ")}
                          >
                            <div className="mb-4 flex items-start justify-between gap-4">
                              <div className="flex min-w-0 items-start gap-3">
                                <div
                                  className={[
                                    "grid h-12 w-12 shrink-0 place-items-center rounded-2xl text-lg font-black",
                                    isAssigned
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

                              <button
                                type="button"
                                disabled={disabled}
                                onClick={() => toggleLocalAgent(agent)}
                                className={[
                                  "relative h-8 w-14 rounded-full transition disabled:cursor-not-allowed disabled:opacity-50",
                                  isAssigned ? "bg-[#ff5a3d]" : "bg-neutral-300",
                                ].join(" ")}
                                aria-label={`Toggle ${agent.name}`}
                              >
                                <span
                                  className={[
                                    "absolute top-1 h-6 w-6 rounded-full bg-white shadow transition",
                                    isAssigned ? "left-7" : "left-1",
                                  ].join(" ")}
                                />
                              </button>
                            </div>

                            <p className="min-h-10 text-sm font-medium leading-5 text-neutral-500">
                              {agent.description}
                            </p>

                            <div className="mt-4 flex flex-wrap items-center gap-2">
                              <span
                                className={[
                                  "rounded-full px-3 py-1 text-[11px] font-black capitalize",
                                  getRiskStyle(agent.risk_level),
                                ].join(" ")}
                              >
                                {agent.risk_level} risk
                              </span>

                              <span className="rounded-full bg-neutral-100 px-3 py-1 text-[11px] font-black text-neutral-600">
                                {agent.minimum_plan}+ plan
                              </span>

                              {isRoleDefault ? (
                                <span className="rounded-full bg-emerald-50 px-3 py-1 text-[11px] font-black text-emerald-700">
                                  Role default
                                </span>
                              ) : null}

                              {agent.requires_security_approval ? (
                                <span className="rounded-full bg-[#fff3ed] px-3 py-1 text-[11px] font-black text-[#ff5a3d]">
                                  Security routed
                                </span>
                              ) : null}
                            </div>

                            {!isRoleAllowed ? (
                              <p className="mt-3 rounded-2xl bg-red-50 px-3 py-2 text-[11px] font-bold text-red-700">
                                Blocked by role: {selectedUser.role}
                              </p>
                            ) : null}

                            {!isPlanAllowed ? (
                              <p className="mt-3 rounded-2xl bg-amber-50 px-3 py-2 text-[11px] font-bold text-amber-800">
                                Requires {agent.minimum_plan} plan or higher.
                              </p>
                            ) : null}

                            {isLocked ? (
                              <p className="mt-3 rounded-2xl bg-neutral-100 px-3 py-2 text-[11px] font-bold text-neutral-600">
                                Protected core assignment cannot be removed.
                              </p>
                            ) : null}
                          </article>
                        );
                      })}
                    </div>
                  )}
                </div>
              </section>
            </form>
          )}
        </section>
      </div>
    </main>
  );
}