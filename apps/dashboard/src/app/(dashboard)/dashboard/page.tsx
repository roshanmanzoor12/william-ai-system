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
import { WilliamVoicePanel } from "@/components/voice/WilliamVoicePanel";

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

type DashboardSummary = {
  metrics: {
    totalAgents: number;
    activeAgents: number;
    completedTasks: number;
    pendingApprovals: number;
    securityChecks: number;
    memoryRecords: number;
    verificationPayloads: number;
    workspaceHealth: number;
  };
  usage: {
    tasksUsed: number;
    tasksLimit: number;
    monthlySpendCents?: number;
    monthlyLimitCents?: number;
  };
  chart: {
    labels: string[];
    taskCounts: number[];
    securityCounts: number[];
  };
};

type AgentItem = {
  agent_id: string;
  name: string;
  key: string;
  status: "active" | "inactive" | "blocked" | "pending";
  description?: string;
  last_run_at?: string | null;
};

type TaskItem = {
  task_id: string;
  order_id?: string;
  agent_name: string;
  action: string;
  status: "completed" | "pending" | "in_progress" | "failed" | "blocked";
  risk_level?: "low" | "medium" | "high";
  created_at: string;
  completed_at?: string | null;
};

type CommandResponse = {
  task_id: string;
  status: "completed" | "pending" | "in_progress" | "failed" | "blocked";
  agent_name: string;
  action: string;
  message?: string;
  verification?: {
    verification_id?: string;
    status: string;
  };
  security?: {
    approved: boolean;
    risk_level: "low" | "medium" | "high";
    routed_to_security_agent: boolean;
  };
};

type DashboardData = {
  summary: DashboardSummary;
  agents: AgentItem[];
  recentTasks: TaskItem[];
};

type LoadState = "checking_session" | "loading" | "ready" | "empty" | "error";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || "";

const EMPTY_SUMMARY: DashboardSummary = {
  metrics: {
    totalAgents: 0,
    activeAgents: 0,
    completedTasks: 0,
    pendingApprovals: 0,
    securityChecks: 0,
    memoryRecords: 0,
    verificationPayloads: 0,
    workspaceHealth: 0,
  },
  usage: {
    tasksUsed: 0,
    tasksLimit: 0,
    monthlySpendCents: 0,
    monthlyLimitCents: 0,
  },
  chart: {
    labels: [],
    taskCounts: [],
    securityCounts: [],
  },
};

const ROLE_PERMISSIONS: Record<UserRole, string[]> = {
  owner: [
    "dashboard:read",
    "workspace:read",
    "tasks:write",
    "agents:run",
    "security:approve",
    "audit:read",
    "memory:read",
  ],
  admin: [
    "dashboard:read",
    "workspace:read",
    "tasks:write",
    "agents:run",
    "audit:read",
    "memory:read",
  ],
  member: [
    "dashboard:read",
    "workspace:read",
    "tasks:write",
    "agents:run",
    "memory:read",
  ],
  viewer: ["dashboard:read", "workspace:read", "memory:read"],
};

const PLAN_ACCESS: Record<UserPlan, boolean> = {
  free: true,
  starter: true,
  pro: true,
  enterprise: true,
};

const SENSITIVE_ACTION_WORDS = [
  "delete",
  "billing",
  "payment",
  "invite",
  "export",
  "open app",
  "close app",
  "system",
  "device",
  "file remove",
  "security",
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
  const sessionPermissions = new Set([
    ...(ROLE_PERMISSIONS[session.role] || []),
    ...(session.permissions || []),
  ]);

  return sessionPermissions.has(permission);
}

function canUseDashboard(session: SessionData): ApiResponse<SessionData> {
  if (!session.user_id || !session.workspace_id) {
    return createSafeError(
      "ISOLATION_CONTEXT_MISSING",
      "Session is missing user_id or workspace_id.",
      403,
    );
  }

  if (!PLAN_ACCESS[session.plan]) {
    return createSafeError(
      "PLAN_ACCESS_DENIED",
      "Your plan cannot access the dashboard.",
      402,
      { plan: session.plan },
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

  if (
    !hasPermission(session, "dashboard:read") &&
    !hasPermission(session, "workspace:read")
  ) {
    return createSafeError(
      "PERMISSION_DENIED",
      "Your role cannot open this dashboard.",
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

function formatNumber(value: number): string {
  return new Intl.NumberFormat("en-US").format(value || 0);
}

function formatMoneyFromCents(value?: number): string {
  const amount = (value || 0) / 100;

  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: 0,
  }).format(amount);
}

function formatDate(value?: string | null): string {
  if (!value) return "—";

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

function detectSensitiveAction(command: string): boolean {
  const normalized = command.toLowerCase();
  return SENSITIVE_ACTION_WORDS.some((word) => normalized.includes(word));
}

function extractAction(command: string): string {
  const normalized = command.trim().toLowerCase();

  if (normalized.includes("memory")) return "memory.process";
  if (normalized.includes("security")) return "security.review";
  if (normalized.includes("code") || normalized.includes("file"))
    return "code.execute";
  if (normalized.includes("browser") || normalized.includes("website"))
    return "browser.operate";
  if (normalized.includes("billing") || normalized.includes("subscription"))
    return "billing.review";
  if (normalized.includes("report") || normalized.includes("analytics"))
    return "analytics.generate";

  return "master.execute";
}

function statusStyle(status: TaskItem["status"]): string {
  if (status === "completed") return "text-emerald-700 bg-emerald-50";
  if (status === "pending") return "text-orange-700 bg-orange-50";
  if (status === "in_progress") return "text-yellow-700 bg-yellow-50";
  if (status === "blocked") return "text-red-700 bg-red-50";
  return "text-neutral-700 bg-neutral-100";
}

function agentStatusStyle(status: AgentItem["status"]): string {
  if (status === "active") return "bg-emerald-50 text-emerald-700";
  if (status === "pending") return "bg-yellow-50 text-yellow-700";
  if (status === "blocked") return "bg-red-50 text-red-700";
  return "bg-neutral-100 text-neutral-500";
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

export default function Page() {
  const router = useRouter();

  const [session, setSession] = useState<SessionData | null>(null);
  const [dashboard, setDashboard] = useState<DashboardData>({
    summary: EMPTY_SUMMARY,
    agents: [],
    recentTasks: [],
  });
  const [state, setState] = useState<LoadState>("checking_session");
  const [errorMessage, setErrorMessage] = useState("");
  const [command, setCommand] = useState("");
  const [commandState, setCommandState] = useState<
    "idle" | "submitting" | "success" | "error"
  >("idle");
  const [commandMessage, setCommandMessage] = useState("");

  const canRunAgents = useMemo(() => {
    if (!session) return false;
    return (
      hasPermission(session, "agents:run") &&
      hasPermission(session, "tasks:write")
    );
  }, [session]);

  const canApproveSecurity = useMemo(() => {
    if (!session) return false;
    return hasPermission(session, "security:approve");
  }, [session]);

  const usagePercent = useMemo(() => {
    const used = dashboard.summary.usage.tasksUsed || 0;
    const limit = dashboard.summary.usage.tasksLimit || 0;
    if (!limit) return 0;
    return Math.min(100, Math.round((used / limit) * 100));
  }, [dashboard.summary.usage.tasksLimit, dashboard.summary.usage.tasksUsed]);

  const chartMax = useMemo(() => {
    const values = [
      ...dashboard.summary.chart.taskCounts,
      ...dashboard.summary.chart.securityCounts,
    ];
    return Math.max(...values, 1);
  }, [
    dashboard.summary.chart.securityCounts,
    dashboard.summary.chart.taskCounts,
  ]);

  const loadDashboard = useCallback(
    async (activeSession: SessionData) => {
      setState("loading");
      setErrorMessage("");

      const accessCheck = canUseDashboard(activeSession);

      if (!accessCheck.success) {
        clearSession();
        router.replace("/login");
        return;
      }

      const [summaryResponse, agentsResponse, tasksResponse] =
        await Promise.all([
          apiRequest<DashboardSummary>(
            `/dashboard/summary?user_id=${encodeURIComponent(
              activeSession.user_id,
            )}&workspace_id=${encodeURIComponent(activeSession.workspace_id)}`,
            activeSession,
            {
              method: "GET",
              headers: {
                "X-Action": "dashboard.summary",
              },
            },
          ),
          apiRequest<AgentItem[]>(
            `/agents?user_id=${encodeURIComponent(
              activeSession.user_id,
            )}&workspace_id=${encodeURIComponent(activeSession.workspace_id)}`,
            activeSession,
            {
              method: "GET",
              headers: {
                "X-Action": "agents.list",
              },
            },
          ),
          apiRequest<TaskItem[]>(
            `/tasks/recent?user_id=${encodeURIComponent(
              activeSession.user_id,
            )}&workspace_id=${encodeURIComponent(activeSession.workspace_id)}`,
            activeSession,
            {
              method: "GET",
              headers: {
                "X-Action": "tasks.recent",
              },
            },
          ),
        ]);

      if (!summaryResponse.success || !summaryResponse.data) {
        setState("error");
        setErrorMessage(
          summaryResponse.error?.message ||
            "Could not load dashboard summary from the API.",
        );
        return;
      }

      const agents =
        agentsResponse.success && agentsResponse.data
          ? agentsResponse.data
          : [];
      const recentTasks =
        tasksResponse.success && tasksResponse.data ? tasksResponse.data : [];

      setDashboard({
        summary: summaryResponse.data,
        agents,
        recentTasks,
      });

      const hasAnyData =
        summaryResponse.data.metrics.totalAgents > 0 ||
        summaryResponse.data.metrics.completedTasks > 0 ||
        agents.length > 0 ||
        recentTasks.length > 0;

      setState(hasAnyData ? "ready" : "empty");
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
    void loadDashboard(activeSession);
  }, [loadDashboard, router]);

  async function handleCommandSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (!session) {
      router.replace("/login");
      return;
    }

    if (!canRunAgents) {
      setCommandState("error");
      setCommandMessage("Your role cannot run agent tasks.");
      return;
    }

    const trimmedCommand = command.trim();

    if (trimmedCommand.length < 3) {
      setCommandState("error");
      setCommandMessage("Write a clear command for William first.");
      return;
    }

    const sensitive = detectSensitiveAction(trimmedCommand);

    if (sensitive && !canApproveSecurity) {
      setCommandState("error");
      setCommandMessage(
        "This looks sensitive. Your role cannot approve Security Agent actions.",
      );
      return;
    }

    setCommandState("submitting");
    setCommandMessage("");

    const action = extractAction(trimmedCommand);

    const response = await apiRequest<CommandResponse>(
      "/master/command",
      session,
      {
        method: "POST",
        headers: {
          "X-Action": action,
          "X-Sensitive-Action": sensitive ? "true" : "false",
        },
        body: JSON.stringify({
          user_id: session.user_id,
          workspace_id: session.workspace_id,
          command: trimmedCommand,
          action,
          route: {
            planner: true,
            security_agent: sensitive,
            memory_agent: true,
            verification_agent: true,
            master_agent: true,
          },
          clientContext: {
            app: "william-dashboard",
            module: "dashboard.command_console",
            requiresAudit: true,
            requiresSecurityRoute: sensitive,
            memoryCompatible: true,
            verificationCompatible: true,
          },
        }),
      },
    );

    if (!response.success || !response.data) {
      setCommandState("error");
      setCommandMessage(
        response.error?.message || "William could not execute this command.",
      );
      return;
    }

    setCommandState("success");
    setCommandMessage(
      response.data.message ||
        `Task ${response.data.task_id} routed through Master Agent successfully.`,
    );
    setCommand("");
    void loadDashboard(session);
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
          title="Checking dashboard session..."
          subtitle="Validating user_id and workspace_id."
        />
      </div>
    );
  }

  return (
    <div className="text-neutral-950">
      <section className="flex min-w-0 flex-1 flex-col px-0">
        <div className="mb-6 flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <h1 className="text-4xl font-black tracking-[-0.055em] text-neutral-950 lg:text-5xl">
              Good morning, {session.name.split(" ")[0] || "Admin"}
            </h1>
            <p className="mt-2 text-sm font-medium text-neutral-500">
              Run AI commands, monitor agent flow, track approvals, and verify
              workspace-safe actions.
            </p>
          </div>

          <div className="flex items-center gap-3">
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

        {state === "loading" ? (
          <LoadingState
            variant="light"
            title="Loading command center..."
            subtitle="Pulling workspace-safe dashboard data."
          />
        ) : state === "error" ? (
          <ErrorState
            variant="light"
            title="Dashboard could not load"
            message={errorMessage}
            onRetry={() => {
              if (session) void loadDashboard(session);
            }}
          />
        ) : (
          <div className="grid gap-5 xl:grid-cols-[1fr_1.45fr]">
            <section className="space-y-5">
              <div className="rounded-[1.6rem] bg-white p-5 shadow-sm">
                <div className="mb-5 flex items-center justify-between">
                  <div>
                    <p className="text-sm font-bold text-neutral-500">
                      Workspace Health
                    </p>
                    <p className="mt-1 text-3xl font-black tracking-[-0.05em]">
                      {dashboard.summary.metrics.workspaceHealth || 0}%
                    </p>
                  </div>
                  <span className="rounded-full bg-emerald-50 px-3 py-1 text-xs font-black text-emerald-700">
                    Active
                  </span>
                </div>

                <div className="h-3 overflow-hidden rounded-full bg-neutral-100">
                  <div
                    className="h-full rounded-full bg-[#ff5a3d]"
                    style={{
                      width: `${Math.max(
                        0,
                        Math.min(
                          100,
                          dashboard.summary.metrics.workspaceHealth || 0,
                        ),
                      )}%`,
                    }}
                  />
                </div>

                <div className="mt-5 grid grid-cols-3 gap-3">
                  <div className="rounded-2xl bg-neutral-50 p-3">
                    <p className="text-[11px] font-bold text-neutral-500">
                      Agents
                    </p>
                    <p className="mt-1 text-lg font-black">
                      {dashboard.summary.metrics.activeAgents}/
                      {dashboard.summary.metrics.totalAgents}
                    </p>
                  </div>
                  <div className="rounded-2xl bg-neutral-50 p-3">
                    <p className="text-[11px] font-bold text-neutral-500">
                      Memory
                    </p>
                    <p className="mt-1 text-lg font-black">
                      {formatNumber(dashboard.summary.metrics.memoryRecords)}
                    </p>
                  </div>
                  <div className="rounded-2xl bg-neutral-50 p-3">
                    <p className="text-[11px] font-bold text-neutral-500">
                      Verify
                    </p>
                    <p className="mt-1 text-lg font-black">
                      {formatNumber(
                        dashboard.summary.metrics.verificationPayloads,
                      )}
                    </p>
                  </div>
                </div>
              </div>

              <div className="rounded-[1.6rem] bg-white p-5 shadow-sm">
                <div className="mb-4 flex items-center justify-between">
                  <p className="text-base font-black text-neutral-950">
                    Monthly Task Limit
                  </p>
                  <p className="text-xs font-black text-neutral-500">
                    {usagePercent}%
                  </p>
                </div>

                <div className="h-3 overflow-hidden rounded-full bg-neutral-100">
                  <div
                    className="h-full rounded-full bg-[#ff5a3d]"
                    style={{ width: `${usagePercent}%` }}
                  />
                </div>

                <div className="mt-3 flex items-center justify-between text-xs font-bold text-neutral-500">
                  <span>
                    {formatNumber(dashboard.summary.usage.tasksUsed)} used
                  </span>
                  <span>
                    {formatNumber(dashboard.summary.usage.tasksLimit)} limit
                  </span>
                </div>
              </div>

              <div className="rounded-[1.6rem] bg-white p-5 shadow-sm">
                <div className="mb-5 flex items-center justify-between">
                  <p className="text-base font-black text-neutral-950">
                    Command Console
                  </p>
                  <span className="rounded-full bg-neutral-100 px-3 py-1 text-xs font-black text-neutral-600">
                    Master Agent
                  </span>
                </div>

                <form onSubmit={handleCommandSubmit} className="space-y-4">
                  <textarea
                    value={command}
                    disabled={!canRunAgents || commandState === "submitting"}
                    onChange={(event) => {
                      setCommand(event.target.value);
                      setCommandState("idle");
                      setCommandMessage("");
                    }}
                    placeholder="Tell William what to do. Example: Review recent tasks and prepare verification report."
                    className="min-h-32 w-full resize-none rounded-2xl border border-neutral-200 bg-neutral-50 p-4 text-sm font-semibold outline-none transition placeholder:text-neutral-400 focus:border-[#ff5a3d] focus:bg-white focus:ring-4 focus:ring-[#ff5a3d]/10 disabled:cursor-not-allowed disabled:opacity-60"
                  />

                  {commandMessage ? (
                    <div
                      className={[
                        "rounded-2xl px-4 py-3 text-sm font-bold",
                        commandState === "success"
                          ? "bg-emerald-50 text-emerald-700"
                          : commandState === "error"
                            ? "bg-red-50 text-red-700"
                            : "bg-neutral-50 text-neutral-600",
                      ].join(" ")}
                    >
                      {commandMessage}
                    </div>
                  ) : null}

                  <button
                    type="submit"
                    disabled={!canRunAgents || commandState === "submitting"}
                    className="flex h-13 w-full items-center justify-center gap-3 rounded-2xl bg-neutral-950 px-5 py-4 text-sm font-black text-white shadow-xl shadow-black/15 transition hover:-translate-y-0.5 hover:bg-[#ff5a3d] hover:shadow-[#ff5a3d]/25 disabled:cursor-not-allowed disabled:translate-y-0 disabled:opacity-60"
                  >
                    {commandState === "submitting" ? (
                      <>
                        <span className="h-4 w-4 animate-spin rounded-full border-2 border-white/30 border-t-white" />
                        Routing Command...
                      </>
                    ) : (
                      <>Run Through Master Flow →</>
                    )}
                  </button>
                </form>
              </div>

              <WilliamVoicePanel />
            </section>

            <section className="space-y-5">
              <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                <StatCard
                  title="Completed Tasks"
                  value={formatNumber(dashboard.summary.metrics.completedTasks)}
                  subtitle="Verification-ready"
                  icon="✓"
                  highlight
                />
                <StatCard
                  title="Pending Approvals"
                  value={formatNumber(
                    dashboard.summary.metrics.pendingApprovals,
                  )}
                  subtitle="Security queue"
                  icon="!"
                />
                <StatCard
                  title="Security Checks"
                  value={formatNumber(dashboard.summary.metrics.securityChecks)}
                  subtitle="Audit logged"
                  icon="▣"
                />
                <StatCard
                  title="Monthly Spend"
                  value={formatMoneyFromCents(
                    dashboard.summary.usage.monthlySpendCents,
                  )}
                  subtitle={`${formatMoneyFromCents(
                    dashboard.summary.usage.monthlyLimitCents,
                  )} limit`}
                  icon="$"
                />
              </div>

              <div className="rounded-[1.6rem] bg-white p-5 shadow-sm">
                <div className="mb-5 flex items-start justify-between">
                  <div>
                    <p className="text-lg font-black tracking-[-0.03em] text-neutral-950">
                      Agent Activity
                    </p>
                    <p className="text-sm font-medium text-neutral-500">
                      Tasks and Security Agent checks by period.
                    </p>
                  </div>
                  <div className="flex items-center gap-3 text-xs font-black">
                    <span className="flex items-center gap-1 text-[#ff5a3d]">
                      <span className="h-2 w-2 rounded-full bg-[#ff5a3d]" />
                      Tasks
                    </span>
                    <span className="flex items-center gap-1 text-neutral-950">
                      <span className="h-2 w-2 rounded-full bg-neutral-950" />
                      Security
                    </span>
                  </div>
                </div>

                {dashboard.summary.chart.labels.length === 0 ? (
                  <EmptyState
                    variant="light"
                    icon="∅"
                    title="No live activity yet"
                    message="Run your first command and William will create isolated tasks, audit logs, memory context, and verification payloads."
                  />
                ) : (
                  <div className="flex h-72 items-end gap-4 overflow-x-auto rounded-2xl bg-neutral-50 px-5 py-4">
                    {dashboard.summary.chart.labels.map((label, index) => {
                      const taskValue =
                        dashboard.summary.chart.taskCounts[index] || 0;
                      const securityValue =
                        dashboard.summary.chart.securityCounts[index] || 0;

                      return (
                        <div
                          key={`${label}-${index}`}
                          className="flex min-w-12 flex-1 flex-col items-center justify-end gap-2"
                        >
                          <div className="flex h-52 items-end gap-1">
                            <div
                              className="w-5 rounded-t-xl bg-[#ff5a3d]"
                              style={{
                                height: `${Math.max(
                                  6,
                                  (taskValue / chartMax) * 100,
                                )}%`,
                              }}
                              title={`Tasks: ${taskValue}`}
                            />
                            <div
                              className="w-5 rounded-t-xl bg-neutral-950"
                              style={{
                                height: `${Math.max(
                                  6,
                                  (securityValue / chartMax) * 100,
                                )}%`,
                              }}
                              title={`Security checks: ${securityValue}`}
                            />
                          </div>
                          <span className="text-[11px] font-black text-neutral-400">
                            {label}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              <div className="grid gap-5 xl:grid-cols-[0.8fr_1.2fr]">
                <div className="rounded-[1.6rem] bg-white p-5 shadow-sm">
                  <div className="mb-5 flex items-center justify-between">
                    <p className="text-base font-black text-neutral-950">
                      Agents
                    </p>
                    <a
                      href="/agents"
                      className="rounded-full bg-neutral-100 px-3 py-1 text-xs font-black text-neutral-600 transition hover:bg-[#ff5a3d] hover:text-white"
                    >
                      Manage
                    </a>
                  </div>

                  {dashboard.agents.length === 0 ? (
                    <EmptyState
                      variant="light"
                      icon="∅"
                      title="No live activity yet"
                      message="Run your first command and William will create isolated tasks, audit logs, memory context, and verification payloads."
                    />
                  ) : (
                    <div className="space-y-3">
                      {dashboard.agents.slice(0, 5).map((agent) => (
                        <div
                          key={agent.agent_id}
                          className="flex items-center justify-between rounded-2xl border border-neutral-100 bg-neutral-50 px-4 py-3"
                        >
                          <div>
                            <p className="text-sm font-black text-neutral-950">
                              {agent.name}
                            </p>
                            <p className="text-xs font-medium text-neutral-500">
                              {agent.description || agent.key}
                            </p>
                          </div>
                          <span
                            className={[
                              "rounded-full px-3 py-1 text-[11px] font-black capitalize",
                              agentStatusStyle(agent.status),
                            ].join(" ")}
                          >
                            {agent.status}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                <div className="rounded-[1.6rem] bg-white p-5 shadow-sm">
                  <div className="mb-5 flex items-center justify-between">
                    <div>
                      <p className="text-base font-black text-neutral-950">
                        Recent Activities
                      </p>
                      <p className="text-xs font-medium text-neutral-500">
                        Workspace-safe task records only.
                      </p>
                    </div>
                    <a
                      href="/tasks"
                      className="rounded-full bg-neutral-100 px-3 py-1 text-xs font-black text-neutral-600 transition hover:bg-[#ff5a3d] hover:text-white"
                    >
                      View All
                    </a>
                  </div>

                  {state === "empty" || dashboard.recentTasks.length === 0 ? (
                    <EmptyState
                      variant="light"
                      icon="∅"
                      title="No live activity yet"
                      message="Run your first command and William will create isolated tasks, audit logs, memory context, and verification payloads."
                    />
                  ) : (
                    <div className="overflow-hidden rounded-2xl border border-neutral-100">
                      <div className="grid grid-cols-[0.9fr_1.2fr_0.8fr_1fr] bg-neutral-50 px-4 py-3 text-xs font-black text-neutral-400">
                        <span>Task ID</span>
                        <span>Activity</span>
                        <span>Status</span>
                        <span>Date</span>
                      </div>

                      {dashboard.recentTasks.slice(0, 6).map((task) => (
                        <div
                          key={task.task_id}
                          className="grid grid-cols-[0.9fr_1.2fr_0.8fr_1fr] items-center border-t border-neutral-100 px-4 py-3 text-sm"
                        >
                          <span className="truncate font-bold text-neutral-700">
                            {task.order_id || task.task_id}
                          </span>
                          <span className="truncate font-semibold text-neutral-950">
                            {task.agent_name} · {task.action}
                          </span>
                          <span>
                            <span
                              className={[
                                "rounded-full px-3 py-1 text-[11px] font-black capitalize",
                                statusStyle(task.status),
                              ].join(" ")}
                            >
                              {task.status.replace("_", " ")}
                            </span>
                          </span>
                          <span className="truncate text-xs font-medium text-neutral-500">
                            {formatDate(task.created_at)}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </section>
          </div>
        )}
      </section>
    </div>
  );
}
