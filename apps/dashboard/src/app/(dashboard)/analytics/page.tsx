"use client";

/**
 * apps/dashboard/src/app/analytics/page.tsx
 *
 * William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
 * Dashboard Prompt Bible
 *
 * Purpose:
 * - Usage, task, lead, and workflow analytics dashboard.
 * - Tenant-safe frontend page using user_id and workspace_id on every analytics request.
 * - Supports future Master Agent, Security Agent, Memory Agent, Verification Agent,
 *   audit logs, billing usage, workflow metrics, and lead pipeline analytics.
 * - Includes API hooks, loading states, error states, empty states, role-based UI,
 *   plan/subscription visibility, safe errors, and audit-ready actions.
 */

import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { useRouter } from "next/navigation";
import { SessionData, hasMinPlan, hasMinRole, readSession } from "@/lib/auth";
import { EmptyState } from "@/components/state/EmptyState";
import { ErrorState } from "@/components/state/ErrorState";
import { ForbiddenState } from "@/components/state/ForbiddenState";
import { LoadingState } from "@/components/state/LoadingState";

type RangeKey = "7d" | "30d" | "90d" | "12m";

type ApiResponse<T> = {
  success: boolean;
  data?: T;
  error?: string;
  audit_event_id?: string;
};

type AnalyticsPoint = {
  label: string;
  tasks: number;
  leads: number;
  workflows: number;
  usage: number;
};

type AgentMetric = {
  agent: string;
  completed: number;
  failed: number;
  active: number;
  usage_units: number;
};

type LeadMetric = {
  source: string;
  leads: number;
  qualified: number;
  conversion_rate: number;
};

type WorkflowMetric = {
  id: string;
  name: string;
  status: "healthy" | "warning" | "blocked";
  runs: number;
  success_rate: number;
  avg_duration_seconds: number;
};

// Fields typed `number | null` have no source in the real backend --
// apps/api/routes/analytics.py's /summary endpoint only returns task
// counts (by status), a total agent-event count, and a 7-day audit-event
// count. There is no usage-metering, lead-pipeline, or workflow-analytics
// endpoint anywhere in the backend. `null` renders as an honest "Not
// available" via formatNumber/formatPercent below, instead of a
// fabricated number.
type AnalyticsData = {
  user_id: string;
  workspace_id: string;
  generated_at: string;
  usage_units: number | null;
  usage_limit: number | null;
  total_tasks: number;
  completed_tasks: number;
  failed_tasks: number;
  active_tasks: number;
  total_leads: number | null;
  qualified_leads: number | null;
  workflow_runs: number | null;
  workflow_success_rate: number | null;
  memory_writes: number | null;
  security_reviews: number | null;
  verification_ready: number | null;
  audit_events: number | null;
  series: AnalyticsPoint[];
  agents: AgentMetric[];
  leads: LeadMetric[];
  workflows: WorkflowMetric[];
};

const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL?.replace(/\/$/, "") || "";

const RANGE_LABELS: Record<RangeKey, string> = {
  "7d": "7 Days",
  "30d": "30 Days",
  "90d": "90 Days",
  "12m": "12 Months",
};

function cx(...classes: Array<string | false | null | undefined>): string {
  return classes.filter(Boolean).join(" ");
}

function safeError(error: unknown): string {
  const message =
    error instanceof Error ? error.message : String(error || "Unknown error");
  const blocked = [
    "secret",
    "token",
    "password",
    "apikey",
    "api_key",
    "database_url",
    "jwt",
    "connection string",
  ];
  const lower = message.toLowerCase();

  if (blocked.some((word) => lower.includes(word))) {
    return "A safe application error occurred. Please try again or contact the workspace admin.";
  }

  return message;
}

function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined) return "Not available";
  return new Intl.NumberFormat("en").format(value);
}

function formatPercent(value: number | null | undefined): string {
  if (value === null || value === undefined) return "Not available";
  return `${Math.round(value)}%`;
}

function formatDate(value: string): string {
  try {
    return new Intl.DateTimeFormat("en", {
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    }).format(new Date(value));
  } catch {
    return value;
  }
}

// apps/api/routes/analytics.py's real GET /analytics/summary response
// shape (confirmed by reading the source, not guessed).
type RealAnalyticsSummary = {
  workspace_id: string;
  tasks: { total: number; by_status: Record<string, number> };
  agent_events: { total: number };
  audit: { last_7_days_total: number; by_status: Record<string, number> };
  generated_at: string;
};

/**
 * Maps the real backend response onto AnalyticsData, leaving every field
 * with no real source (`number | null` in the type above) as `null` and
 * every table/chart array with no real source empty, rather than
 * fabricating plausible-looking numbers. Task counts come from
 * database/models/agent_task.py's real status values (pending, queued,
 * assigned, running, waiting_approval, paused, completed, failed,
 * cancelled, retrying).
 */
function buildAnalyticsFromReal(
  real: RealAnalyticsSummary,
  session: SessionData,
): AnalyticsData {
  const byStatus = real.tasks.by_status || {};
  const completedTasks = byStatus.completed || 0;
  const failedTasks = (byStatus.failed || 0) + (byStatus.cancelled || 0);
  const activeTasks = Math.max(
    0,
    real.tasks.total - completedTasks - failedTasks,
  );

  return {
    user_id: session.user_id,
    workspace_id: real.workspace_id,
    generated_at: real.generated_at,
    usage_units: null,
    usage_limit: null,
    total_tasks: real.tasks.total,
    completed_tasks: completedTasks,
    failed_tasks: failedTasks,
    active_tasks: activeTasks,
    total_leads: null,
    qualified_leads: null,
    workflow_runs: null,
    workflow_success_rate: null,
    memory_writes: null,
    security_reviews: null,
    verification_ready: null,
    audit_events: real.audit.last_7_days_total,
    series: [],
    agents: [],
    leads: [],
    workflows: [],
  };
}

async function dashboardFetch<T>(
  path: string,
  options: RequestInit & {
    accessToken: string;
    audit_action?: string;
  },
): Promise<ApiResponse<T>> {
  if (!API_BASE_URL) {
    return {
      success: false,
      error:
        "API is not connected. Set NEXT_PUBLIC_API_BASE_URL in your dashboard environment.",
    };
  }

  const headers = new Headers(options.headers);
  headers.set("Content-Type", "application/json");
  headers.set("Authorization", `Bearer ${options.accessToken}`);
  headers.set(
    "X-Audit-Action",
    options.audit_action || "dashboard_analytics_read",
  );

  try {
    const response = await fetch(`${API_BASE_URL}${path}`, {
      ...options,
      headers,
      credentials: "include",
    });

    const json = (await response.json().catch(() => ({}))) as ApiResponse<T>;

    if (!response.ok) {
      return {
        success: false,
        error: safeError(
          json.error || `Request failed with status ${response.status}`,
        ),
      };
    }

    return json;
  } catch (error) {
    return {
      success: false,
      error: safeError(error),
    };
  }
}

function Icon({
  name,
  size = 18,
}: {
  name:
    | "logo"
    | "search"
    | "bell"
    | "alert"
    | "grid"
    | "calendar"
    | "mail"
    | "doc"
    | "users"
    | "layers"
    | "settings"
    | "help"
    | "logout"
    | "moon"
    | "sun"
    | "chart"
    | "lead"
    | "workflow"
    | "usage"
    | "shield"
    | "memory"
    | "verify"
    | "filter"
    | "download"
    | "more"
    | "spark"
    | "arrow";
  size?: number;
}) {
  const common = {
    width: size,
    height: size,
    viewBox: "0 0 24 24",
    fill: "none",
    xmlns: "http://www.w3.org/2000/svg",
    "aria-hidden": true,
  };

  const stroke = "currentColor";

  switch (name) {
    case "logo":
      return (
        <svg
          width={size}
          height={size}
          viewBox="0 0 32 32"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
          aria-hidden
        >
          <rect
            width="32"
            height="32"
            rx="12"
            fill="url(#analyticsLogoGradient)"
          />
          <path
            d="M10 21.5V16h5.7c1.1 0 2-.9 2-2v-1.8H12V8h10v6.1c0 3.3-2.6 5.9-5.9 5.9h-1.3v1.5H10Z"
            fill="white"
          />
          <path d="M19.3 24v-5.7H24V24h-4.7Z" fill="white" />
          <defs>
            <linearGradient
              id="analyticsLogoGradient"
              x1="4"
              x2="28"
              y1="4"
              y2="28"
            >
              <stop stopColor="#ff805d" />
              <stop offset="1" stopColor="#ff3d22" />
            </linearGradient>
          </defs>
        </svg>
      );
    case "search":
      return (
        <svg {...common}>
          <path
            d="M11 19a8 8 0 1 1 5.3-2l3.4 3.3"
            stroke={stroke}
            strokeWidth="1.8"
            strokeLinecap="round"
          />
        </svg>
      );
    case "bell":
      return (
        <svg {...common}>
          <path
            d="M18 9a6 6 0 0 0-12 0c0 7-3 7-3 7h18s-3 0-3-7Z"
            stroke={stroke}
            strokeWidth="1.7"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <path
            d="M13.7 21a2 2 0 0 1-3.4 0"
            stroke={stroke}
            strokeWidth="1.7"
            strokeLinecap="round"
          />
          <circle cx="18.5" cy="5.5" r="2.5" fill="#ff5438" />
        </svg>
      );
    case "alert":
      return (
        <svg {...common}>
          <circle cx="12" cy="12" r="9" stroke={stroke} strokeWidth="1.7" />
          <path
            d="M12 7v6"
            stroke={stroke}
            strokeWidth="1.7"
            strokeLinecap="round"
          />
          <path
            d="M12 16.8h.01"
            stroke={stroke}
            strokeWidth="2.4"
            strokeLinecap="round"
          />
        </svg>
      );
    case "grid":
      return (
        <svg {...common}>
          <path
            d="M8.5 4.5h-3v3h3v-3ZM18.5 4.5h-3v3h3v-3ZM8.5 16.5h-3v3h3v-3ZM18.5 16.5h-3v3h3v-3ZM13.5 10.5h-3v3h3v-3Z"
            stroke={stroke}
            strokeWidth="1.5"
          />
        </svg>
      );
    case "calendar":
      return (
        <svg {...common}>
          <path
            d="M7 3v3M17 3v3M4 9h16M6 5h12a2 2 0 0 1 2 2v11a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2Z"
            stroke={stroke}
            strokeWidth="1.7"
            strokeLinecap="round"
          />
        </svg>
      );
    case "mail":
      return (
        <svg {...common}>
          <path d="M4 6.5h16v11H4v-11Z" stroke={stroke} strokeWidth="1.7" />
          <path
            d="m4 7 8 6 8-6"
            stroke={stroke}
            strokeWidth="1.7"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      );
    case "doc":
      return (
        <svg {...common}>
          <path
            d="M7 3.8h7l3 3V20H7V3.8Z"
            stroke={stroke}
            strokeWidth="1.7"
            strokeLinejoin="round"
          />
          <path
            d="M14 4v3h3M9.5 11h5M9.5 15h5"
            stroke={stroke}
            strokeWidth="1.5"
            strokeLinecap="round"
          />
        </svg>
      );
    case "users":
      return (
        <svg {...common}>
          <path
            d="M16 19c0-2.2-1.8-4-4-4s-4 1.8-4 4"
            stroke={stroke}
            strokeWidth="1.7"
            strokeLinecap="round"
          />
          <circle cx="12" cy="9" r="3" stroke={stroke} strokeWidth="1.7" />
          <path
            d="M20 18c0-1.8-1.1-3.3-2.7-3.8M16.8 6.3a2.5 2.5 0 0 1 0 4.4"
            stroke={stroke}
            strokeWidth="1.5"
            strokeLinecap="round"
          />
        </svg>
      );
    case "layers":
      return (
        <svg {...common}>
          <path
            d="m12 3 8 4-8 4-8-4 8-4Z"
            stroke={stroke}
            strokeWidth="1.7"
            strokeLinejoin="round"
          />
          <path
            d="m4 12 8 4 8-4M4 17l8 4 8-4"
            stroke={stroke}
            strokeWidth="1.7"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      );
    case "settings":
      return (
        <svg {...common}>
          <circle cx="12" cy="12" r="3" stroke={stroke} strokeWidth="1.7" />
          <path
            d="M19 12a7.4 7.4 0 0 0-.1-1l2-1.5-2-3.5-2.4 1a6 6 0 0 0-1.8-1L14.4 3h-4l-.4 3a6 6 0 0 0-1.8 1L5.8 6l-2 3.5 2 1.5a7.4 7.4 0 0 0 0 2l-2 1.5 2 3.5 2.4-1a6 6 0 0 0 1.8 1l.4 3h4l.4-3a6 6 0 0 0 1.8-1l2.4 1 2-3.5-2-1.5c.1-.3.1-.7.1-1Z"
            stroke={stroke}
            strokeWidth="1.2"
            strokeLinejoin="round"
          />
        </svg>
      );
    case "help":
      return (
        <svg {...common}>
          <circle cx="12" cy="12" r="9" stroke={stroke} strokeWidth="1.7" />
          <path
            d="M9.8 9.3a2.4 2.4 0 0 1 4.6 1c0 1.8-2.4 2-2.4 3.5"
            stroke={stroke}
            strokeWidth="1.7"
            strokeLinecap="round"
          />
          <path
            d="M12 17.2h.01"
            stroke={stroke}
            strokeWidth="2.4"
            strokeLinecap="round"
          />
        </svg>
      );
    case "logout":
      return (
        <svg {...common}>
          <path
            d="M10 5H6v14h4M14 8l4 4-4 4M18 12H9"
            stroke={stroke}
            strokeWidth="1.7"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      );
    case "moon":
      return (
        <svg {...common}>
          <path
            d="M19 15.2A7.5 7.5 0 0 1 8.8 5a8 8 0 1 0 10.2 10.2Z"
            stroke={stroke}
            strokeWidth="1.7"
            strokeLinejoin="round"
          />
        </svg>
      );
    case "sun":
      return (
        <svg {...common}>
          <circle cx="12" cy="12" r="4" stroke={stroke} strokeWidth="1.7" />
          <path
            d="M12 2.5v2M12 19.5v2M21.5 12h-2M4.5 12h-2M18.7 5.3l-1.4 1.4M6.7 17.3l-1.4 1.4M18.7 18.7l-1.4-1.4M6.7 6.7 5.3 5.3"
            stroke={stroke}
            strokeWidth="1.7"
            strokeLinecap="round"
          />
        </svg>
      );
    case "chart":
      return (
        <svg {...common}>
          <path
            d="M4 19V5M4 19h16"
            stroke={stroke}
            strokeWidth="1.7"
            strokeLinecap="round"
          />
          <path
            d="M8 16v-5M12 16V8M16 16v-7"
            stroke={stroke}
            strokeWidth="2"
            strokeLinecap="round"
          />
        </svg>
      );
    case "lead":
      return (
        <svg {...common}>
          <circle cx="9" cy="8" r="3" stroke={stroke} strokeWidth="1.7" />
          <path
            d="M3.8 19c.8-3 2.7-5 5.2-5s4.4 2 5.2 5"
            stroke={stroke}
            strokeWidth="1.7"
            strokeLinecap="round"
          />
          <path
            d="M16 8h5M18.5 5.5v5"
            stroke={stroke}
            strokeWidth="1.7"
            strokeLinecap="round"
          />
        </svg>
      );
    case "workflow":
      return (
        <svg {...common}>
          <path
            d="M6 6h4v4H6V6ZM14 14h4v4h-4v-4ZM14 6h4v4h-4V6ZM8 10v2a2 2 0 0 0 2 2h4M12 8h2"
            stroke={stroke}
            strokeWidth="1.7"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      );
    case "usage":
      return (
        <svg {...common}>
          <path
            d="M12 3v18M5 8h8a3 3 0 0 1 0 6H9a3 3 0 0 0 0 6h10"
            stroke={stroke}
            strokeWidth="1.7"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      );
    case "shield":
      return (
        <svg {...common}>
          <path
            d="M12 3 19 6v5.5c0 4.5-2.8 7.8-7 9.5-4.2-1.7-7-5-7-9.5V6l7-3Z"
            stroke={stroke}
            strokeWidth="1.7"
            strokeLinejoin="round"
          />
          <path
            d="m9.5 12 1.8 1.8 3.7-4"
            stroke={stroke}
            strokeWidth="1.7"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      );
    case "memory":
      return (
        <svg {...common}>
          <rect
            x="5"
            y="5"
            width="14"
            height="14"
            rx="3"
            stroke={stroke}
            strokeWidth="1.7"
          />
          <path
            d="M9 2.5v3M15 2.5v3M9 18.5v3M15 18.5v3M2.5 9h3M2.5 15h3M18.5 9h3M18.5 15h3"
            stroke={stroke}
            strokeWidth="1.5"
            strokeLinecap="round"
          />
        </svg>
      );
    case "verify":
      return (
        <svg {...common}>
          <circle cx="12" cy="12" r="9" stroke={stroke} strokeWidth="1.7" />
          <path
            d="m8.5 12.3 2.2 2.2 4.9-5.2"
            stroke={stroke}
            strokeWidth="1.9"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      );
    case "filter":
      return (
        <svg {...common}>
          <path
            d="M4 6h16M7 12h10M10 18h4"
            stroke={stroke}
            strokeWidth="1.8"
            strokeLinecap="round"
          />
        </svg>
      );
    case "download":
      return (
        <svg {...common}>
          <path
            d="M12 4v10M8 10l4 4 4-4M5 20h14"
            stroke={stroke}
            strokeWidth="1.8"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      );
    case "more":
      return (
        <svg {...common}>
          <path
            d="M6 12h.01M12 12h.01M18 12h.01"
            stroke={stroke}
            strokeWidth="3"
            strokeLinecap="round"
          />
        </svg>
      );
    case "spark":
      return (
        <svg {...common}>
          <path
            d="M12 2.5 13.7 9l6.3 3-6.3 3L12 21.5 10.3 15 4 12l6.3-3L12 2.5Z"
            stroke={stroke}
            strokeWidth="1.5"
            strokeLinejoin="round"
          />
        </svg>
      );
    case "arrow":
      return (
        <svg {...common}>
          <path
            d="M7 17 17 7M9 7h8v8"
            stroke={stroke}
            strokeWidth="1.8"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      );
    default:
      return null;
  }
}

function BigBarChart({ data }: { data: AnalyticsPoint[] }) {
  const max = Math.max(...data.map((point) => point.usage), 1);

  return (
    <div className="chartCard">
      <div className="cardTop">
        <div>
          <h3>Usage and Growth</h3>
          <p>Tasks, leads, workflows, and agent usage units</p>
        </div>
        <div className="legend">
          <span>
            <i className="orangeDot" /> Usage
          </span>
          <span>
            <i className="darkDot" /> Tasks
          </span>
        </div>
      </div>

      {data.length === 0 ? (
        <EmptyState
          variant="light"
          icon="◈"
          title="No usage trend data"
          message="Time-series usage/lead/workflow analytics are not available yet -- the backend only reports point-in-time task and audit totals today."
        />
      ) : (
        <div className="barChart" aria-label="Usage analytics chart">
          {data.map((point) => {
            const usageHeight = Math.max(
              34,
              Math.round((point.usage / max) * 146),
            );
            const taskHeight = Math.max(
              24,
              Math.round(
                (point.tasks / Math.max(...data.map((item) => item.tasks), 1)) *
                  112,
              ),
            );

            return (
              <div className="barGroup" key={point.label}>
                <div className="bars">
                  <span
                    className="bar barOrange"
                    style={{ height: usageHeight }}
                  />
                  <span
                    className="bar barDark"
                    style={{ height: taskHeight }}
                  />
                </div>
                <span className="barLabel">{point.label}</span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function DonutMeter({ value, label }: { value: number | null; label: string }) {
  if (value === null) {
    return (
      <div className="donutWrap">
        <div className="donut" style={{ ["--value" as string]: "0deg" }}>
          <div>
            <strong>N/A</strong>
            <span>{label}</span>
          </div>
        </div>
      </div>
    );
  }

  const normalized = Math.max(0, Math.min(100, value));

  return (
    <div className="donutWrap">
      <div
        className="donut"
        style={{ ["--value" as string]: `${normalized * 3.6}deg` }}
      >
        <div>
          <strong>{normalized}%</strong>
          <span>{label}</span>
        </div>
      </div>
    </div>
  );
}

function StatusBadge({ status }: { status: WorkflowMetric["status"] }) {
  return (
    <span className={cx("statusBadge", `status-${status}`)}>
      <span />
      {status}
    </span>
  );
}

export default function Page() {
  const router = useRouter();
  const [session, setSession] = useState<SessionData | null>(null);
  const [checkingSession, setCheckingSession] = useState(true);
  const [range, setRange] = useState<RangeKey>("30d");
  const [analytics, setAnalytics] = useState<AnalyticsData | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const mounted = useRef(false);

  useEffect(() => {
    const activeSession = readSession();

    if (!activeSession) {
      router.replace("/login");
      return;
    }

    setSession(activeSession);
    setCheckingSession(false);
  }, [router]);

  const canViewAdvancedAnalytics =
    Boolean(session) &&
    hasMinRole(session!.role, "manager") &&
    hasMinPlan(session!.plan, "pro");
  const canExportAnalytics =
    Boolean(session) &&
    hasMinRole(session!.role, "admin") &&
    hasMinPlan(session!.plan, "business");
  const canViewBillingUsage =
    Boolean(session) && hasMinRole(session!.role, "admin");
  const canViewSecurityAnalytics =
    Boolean(session) && hasMinRole(session!.role, "admin");

  const usagePercent = useMemo(() => {
    if (
      !analytics ||
      analytics.usage_units === null ||
      analytics.usage_limit === null
    )
      return null;
    return Math.min(
      100,
      Math.round(
        (analytics.usage_units / Math.max(analytics.usage_limit, 1)) * 100,
      ),
    );
  }, [analytics]);

  const taskCompletionRate = useMemo(() => {
    if (!analytics || analytics.total_tasks === 0) return 0;
    return Math.round(
      (analytics.completed_tasks / analytics.total_tasks) * 100,
    );
  }, [analytics]);

  const leadQualificationRate = useMemo(() => {
    if (
      !analytics ||
      analytics.total_leads === null ||
      analytics.qualified_leads === null ||
      analytics.total_leads === 0
    ) {
      return null;
    }
    return Math.round(
      (analytics.qualified_leads / analytics.total_leads) * 100,
    );
  }, [analytics]);

  const loadAnalytics = useCallback(
    async (
      nextRange: RangeKey = range,
      mode: "initial" | "refresh" = "initial",
    ) => {
      if (!session) return;

      if (mode === "initial") setIsLoading(true);
      if (mode === "refresh") setIsRefreshing(true);

      setError(null);

      // The real router is apps.api.routes.analytics at "/analytics/summary"
      // (confirmed by reading the source) -- it has no range filter, only
      // task-status counts, an agent-event total, and a fixed 7-day audit
      // count, so `nextRange` only affects the range tabs' selected state,
      // not what data comes back.
      const response = await dashboardFetch<RealAnalyticsSummary>(
        "/analytics/summary",
        {
          method: "GET",
          accessToken: session.accessToken,
          audit_action: "analytics_dashboard_read",
        },
      );

      if (response.success && response.data) {
        setAnalytics(buildAnalyticsFromReal(response.data, session));
      } else {
        setAnalytics(null);
        if (response.error) setError(response.error);
      }

      setIsLoading(false);
      setIsRefreshing(false);
    },
    [range, session],
  );

  useEffect(() => {
    if (!session || mounted.current) return;
    mounted.current = true;
    void loadAnalytics(range, "initial");
  }, [loadAnalytics, range, session]);

  const handleRetry = useCallback(() => {
    setError(null);
    void loadAnalytics(range, "initial");
  }, [loadAnalytics, range]);

  const changeRange = (nextRange: RangeKey) => {
    setRange(nextRange);
    void loadAnalytics(nextRange, "refresh");
  };

  const exportAnalytics = () => {
    if (!canExportAnalytics || !analytics || !session) {
      setError(
        "Analytics export requires admin access and Business plan or higher.",
      );
      return;
    }

    const safePayload = {
      user_id: session.user_id,
      workspace_id: session.workspace_id,
      exported_at: new Date().toISOString(),
      range,
      analytics,
      audit_action: "analytics_export_frontend",
    };

    const blob = new Blob([JSON.stringify(safePayload, null, 2)], {
      type: "application/json",
    });

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `william-analytics-${session.workspace_id}-${range}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  if (checkingSession || !session) {
    return (
      <div className="dashboardPanel">
        <LoadingState variant="light" title="Checking secure session..." />
      </div>
    );
  }

  return (
    <div className="dashboardPanel">
      <div className="heroLine">
        <div>
          <h1>Analytics, {session.name.split(" ")[0]}</h1>
          <p>
            Monitor usage, tasks, leads, workflows, security reviews, memory
            writes, and verification readiness.
          </p>
        </div>

        <div className="heroActions">
          <div className="tenantBadge">
            <span>{session.role}</span>
            <strong>{session.plan}</strong>
          </div>
          <button
            className="exportBtn"
            onClick={exportAnalytics}
            disabled={!canExportAnalytics || !analytics}
          >
            <Icon name="download" size={16} />
            Export
          </button>
        </div>
      </div>

      {error ? (
        <div className="mb-4">
          <ErrorState variant="light" message={error} onRetry={handleRetry} />
        </div>
      ) : null}

      <div className="rangeRow">
        <div className="rangeTabs" aria-label="Analytics date range">
          {(Object.keys(RANGE_LABELS) as RangeKey[]).map((item) => (
            <button
              key={item}
              className={cx(range === item && "active")}
              onClick={() => changeRange(item)}
            >
              {RANGE_LABELS[item]}
            </button>
          ))}
        </div>

        <button
          className="refreshBtn"
          onClick={() => loadAnalytics(range, "refresh")}
          disabled={isRefreshing}
        >
          <Icon name="filter" size={16} />
          {isRefreshing ? "Refreshing..." : "Refresh"}
        </button>
      </div>

      {isLoading ? (
        <section className="stateBox">
          <LoadingState
            variant="light"
            title="Loading analytics..."
            subtitle="Checking user and workspace scoped dashboard records."
          />
        </section>
      ) : !analytics ? (
        <section className="stateBox">
          <EmptyState
            variant="light"
            icon="◈"
            title="No analytics found"
            message="Once agents start running, your numbers will wake up and start flexing."
          />
        </section>
      ) : (
        <>
          <section className="overviewGrid">
            <div className="balanceCard">
              <div className="cardTop">
                <div>
                  <p>Total Usage</p>
                  <h2>{formatNumber(analytics.usage_units)}</h2>
                  <span className="greenText">
                    {usagePercent === null
                      ? "Usage metering not available yet"
                      : `↑ ${usagePercent}% of plan limit`}
                  </span>
                </div>
                <button className="currencyBtn">{RANGE_LABELS[range]}</button>
              </div>

              <div className="usageTrack">
                <span style={{ width: `${usagePercent ?? 0}%` }} />
              </div>

              <div className="usageMeta">
                <span>{formatNumber(analytics.usage_units)} used</span>
                <strong>{formatNumber(analytics.usage_limit)} limit</strong>
              </div>

              <div className="miniWallets">
                <div>
                  <Icon name="chart" />
                  <strong>{formatNumber(analytics.total_tasks)}</strong>
                  <span>Tasks</span>
                </div>
                <div>
                  <Icon name="lead" />
                  <strong>{formatNumber(analytics.total_leads)}</strong>
                  <span>Leads</span>
                </div>
                <div>
                  <Icon name="workflow" />
                  <strong>{formatNumber(analytics.workflow_runs)}</strong>
                  <span>Runs</span>
                </div>
              </div>
            </div>

            <div className="metricGrid">
              <div className="metricCard hot">
                <div className="metricIcon">
                  <Icon name="spark" />
                </div>
                <span>Completed Tasks</span>
                <strong>{formatNumber(analytics.completed_tasks)}</strong>
                <p>↑ {taskCompletionRate}% completion rate</p>
              </div>

              <div className="metricCard">
                <div className="metricIcon">
                  <Icon name="lead" />
                </div>
                <span>Qualified Leads</span>
                <strong>{formatNumber(analytics.qualified_leads)}</strong>
                <p>
                  {leadQualificationRate === null
                    ? "Not available"
                    : `${leadQualificationRate}% qualification`}
                </p>
              </div>

              <div className="metricCard">
                <div className="metricIcon">
                  <Icon name="workflow" />
                </div>
                <span>Workflow Success</span>
                <strong>
                  {formatPercent(analytics.workflow_success_rate)}
                </strong>
                <p>{formatNumber(analytics.workflow_runs)} total runs</p>
              </div>

              <div className="metricCard">
                <div className="metricIcon">
                  <Icon name="verify" />
                </div>
                <span>Verification Ready</span>
                <strong>{formatNumber(analytics.verification_ready)}</strong>
                <p>Completion payloads</p>
              </div>
            </div>

            <BigBarChart data={analytics.series} />
          </section>

          <section className="progressAndCards">
            <div className="progressCard">
              <div className="cardTop">
                <div>
                  <h3>System Health</h3>
                  <p>Live quality indicators for William/Jarvis operations</p>
                </div>
                <button className="liveToggle">Tenant Safe</button>
              </div>

              <div className="donutGrid">
                <DonutMeter value={taskCompletionRate} label="Tasks" />
                <DonutMeter
                  value={analytics.workflow_success_rate}
                  label="Workflows"
                />
                <DonutMeter value={leadQualificationRate} label="Leads" />
              </div>
            </div>

            <div className="cardsCard">
              <div className="cardTop">
                <h3>Agent Contracts</h3>
                <button className="smallSoft">Audit On</button>
              </div>

              <div className="contractCards">
                <div className="contract dark">
                  <span>Memory Agent</span>
                  <strong>
                    {formatNumber(analytics.memory_writes)} context writes
                  </strong>
                  <small>User/workspace scoped</small>
                </div>

                <div className="contract orange">
                  <span>Security Agent</span>
                  <strong>
                    {canViewSecurityAnalytics
                      ? formatNumber(analytics.security_reviews)
                      : "Locked"}
                  </strong>
                  <small>
                    {canViewSecurityAnalytics
                      ? "Sensitive reviews"
                      : "Admin only"}
                  </small>
                </div>
              </div>
            </div>
          </section>

          <section className="lowerGrid">
            <div className="tableCard">
              <div className="tableHeader">
                <div>
                  <h2>Agent Usage</h2>
                  <p>
                    Performance by agent lane. No cross-workspace data included.
                  </p>
                </div>
                <button className="filterBtn">
                  <Icon name="filter" size={16} /> Filter
                </button>
              </div>

              {!canViewAdvancedAnalytics ? (
                <div className="lockedBox">
                  <ForbiddenState
                    variant="light"
                    title="Advanced Analytics Locked"
                    message="Upgrade to Pro and use Operator role or higher."
                  />
                </div>
              ) : analytics.agents.length === 0 ? (
                <EmptyState
                  variant="light"
                  icon="◈"
                  title="No agent usage"
                  message="Per-agent usage breakdowns are not available yet -- the backend only reports a total agent-event count today, not a per-agent split."
                />
              ) : (
                <div className="tableWrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Agent</th>
                        <th>Completed</th>
                        <th>Active</th>
                        <th>Failed</th>
                        <th>Usage</th>
                        <th>Rate</th>
                        <th />
                      </tr>
                    </thead>
                    <tbody>
                      {analytics.agents.map((agent) => {
                        const total =
                          agent.completed + agent.failed + agent.active;
                        const rate = total
                          ? Math.round((agent.completed / total) * 100)
                          : 0;

                        return (
                          <tr key={agent.agent}>
                            <td>
                              <div className="activityCell">
                                <span className="agentIcon">
                                  <Icon name="spark" size={15} />
                                </span>
                                <div>
                                  <strong>{agent.agent} Agent</strong>
                                  <small>usage lane</small>
                                </div>
                              </div>
                            </td>
                            <td>{formatNumber(agent.completed)}</td>
                            <td>{formatNumber(agent.active)}</td>
                            <td>{formatNumber(agent.failed)}</td>
                            <td>{formatNumber(agent.usage_units)}</td>
                            <td>
                              <div className="rowProgress">
                                <span style={{ width: `${rate}%` }} />
                              </div>
                              <small>{rate}%</small>
                            </td>
                            <td>
                              <button
                                className="moreBtn"
                                aria-label={`More details for ${agent.agent}`}
                              >
                                <Icon name="more" size={18} />
                              </button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div className="sideCards">
              <div className="leadCard">
                <div className="cardTop">
                  <div>
                    <h3>Lead Analytics</h3>
                    <p>Source quality and qualification</p>
                  </div>
                  <Icon name="lead" />
                </div>

                <div className="leadList">
                  {analytics.leads.length === 0 ? (
                    <EmptyState
                      variant="light"
                      icon="◈"
                      title="No lead data"
                      message="Lead-pipeline analytics are not available yet -- there is no CRM backend router to source this from."
                    />
                  ) : (
                    analytics.leads.map((lead) => (
                      <div className="leadRow" key={lead.source}>
                        <div>
                          <strong>{lead.source}</strong>
                          <span>
                            {formatNumber(lead.qualified)} qualified from{" "}
                            {formatNumber(lead.leads)}
                          </span>
                        </div>
                        <b>{lead.conversion_rate}%</b>
                      </div>
                    ))
                  )}
                </div>
              </div>

              <div className="leadCard">
                <div className="cardTop">
                  <div>
                    <h3>Billing Usage</h3>
                    <p>Plan consumption and audit events</p>
                  </div>
                  <Icon name="usage" />
                </div>

                {canViewBillingUsage ? (
                  <div className="billingPanel">
                    <strong>
                      {usagePercent === null ? "N/A" : `${usagePercent}%`}
                    </strong>
                    <span>
                      {usagePercent === null
                        ? "Usage metering is not available yet"
                        : `${formatNumber(analytics.usage_units)} / ${formatNumber(analytics.usage_limit)} units`}
                    </span>
                    <div className="usageTrack small">
                      <span style={{ width: `${usagePercent ?? 0}%` }} />
                    </div>
                    <p>
                      {formatNumber(analytics.audit_events)} audit events (last
                      7 days) · generated {formatDate(analytics.generated_at)}
                    </p>
                  </div>
                ) : (
                  <div className="lockedMini">
                    <ForbiddenState
                      variant="light"
                      message="Billing analytics are admin-only."
                    />
                  </div>
                )}
              </div>
            </div>
          </section>

          <section className="workflowCard">
            <div className="tableHeader">
              <div>
                <h2>Workflow Analytics</h2>
                <p>
                  Automation runs, success rate, and blocked workflow
                  visibility.
                </p>
              </div>
              <button className="filterBtn">
                <Icon name="workflow" size={16} /> Manage
              </button>
            </div>

            <div className="workflowGrid">
              {analytics.workflows.length === 0 ? (
                <EmptyState
                  variant="light"
                  icon="◈"
                  title="No workflow analytics"
                  message="Workflow run analytics are not available yet -- apps/api/routes/workflows.py tracks individual runs, but there is no aggregate success-rate/duration reporting endpoint yet."
                />
              ) : (
                analytics.workflows.map((workflow) => (
                  <div className="workflowItem" key={workflow.id}>
                    <div className="workflowTop">
                      <div>
                        <span>{workflow.id}</span>
                        <strong>{workflow.name}</strong>
                      </div>
                      <StatusBadge status={workflow.status} />
                    </div>

                    <div className="workflowStats">
                      <div>
                        <span>Runs</span>
                        <strong>{formatNumber(workflow.runs)}</strong>
                      </div>
                      <div>
                        <span>Success</span>
                        <strong>{workflow.success_rate}%</strong>
                      </div>
                      <div>
                        <span>Avg Time</span>
                        <strong>{workflow.avg_duration_seconds}s</strong>
                      </div>
                    </div>

                    <div className="rowProgress wide">
                      <span style={{ width: `${workflow.success_rate}%` }} />
                    </div>
                  </div>
                ))
              )}
            </div>
          </section>
        </>
      )}

      <style jsx>{`
        :global(*) {
          box-sizing: border-box;
        }

        :global(body) {
          margin: 0;
          background: #e9e9e7;
          color: #1b1b18;
          font-family:
            Inter,
            ui-sans-serif,
            system-ui,
            -apple-system,
            BlinkMacSystemFont,
            "Segoe UI",
            sans-serif;
        }

        .pageShell {
          min-height: 100vh;
          padding: 34px;
          display: grid;
          grid-template-columns: 72px minmax(0, 1fr);
          background:
            radial-gradient(
              circle at 50% 10%,
              rgba(255, 255, 255, 0.8),
              transparent 28%
            ),
            #e9e9e7;
        }

        .sideRail {
          background: #fdfdfc;
          border-radius: 26px 0 0 26px;
          padding: 18px 10px;
          min-height: calc(100vh - 68px);
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 24px;
          box-shadow: 0 24px 80px rgba(25, 25, 22, 0.08);
        }

        .brandPill {
          width: 112px;
          height: 48px;
          margin-left: 58px;
          background: #ffffff;
          border-radius: 999px;
          display: flex;
          align-items: center;
          gap: 10px;
          padding: 8px 12px;
          box-shadow: 0 10px 35px rgba(25, 25, 22, 0.08);
          z-index: 2;
        }

        .brandPill strong {
          font-size: 14px;
          letter-spacing: -0.02em;
        }

        .themeSwitch,
        .railNav,
        .railBottom {
          background: #ffffff;
          border: 1px solid #f0f0ee;
          border-radius: 999px;
          padding: 8px;
          display: flex;
          flex-direction: column;
          gap: 8px;
        }

        .railNav {
          margin-top: 18px;
        }

        .railBottom {
          margin-top: auto;
        }

        .themeSwitch button,
        .railNav button,
        .railBottom button,
        .circleBtn,
        .moreBtn {
          border: 0;
          width: 36px;
          height: 36px;
          border-radius: 50%;
          display: grid;
          place-items: center;
          background: transparent;
          color: #22221f;
          cursor: pointer;
          transition: 0.2s ease;
        }

        .themeSwitch button:hover,
        .railNav button:hover,
        .railBottom button:hover,
        .circleBtn:hover,
        .moreBtn:hover {
          background: #f3f3f1;
          transform: translateY(-1px);
        }

        .railNav button.active {
          background: #22221f;
          color: white;
        }

        .dashboardPanel {
          background: transparent;
          overflow: hidden;
        }

        .topBar {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 16px;
          margin-bottom: 26px;
        }

        .navTabs {
          display: flex;
          align-items: center;
          gap: 6px;
          background: #ffffff;
          padding: 7px;
          border-radius: 999px;
          box-shadow: 0 8px 28px rgba(25, 25, 22, 0.06);
        }

        .navTabs button {
          border: 0;
          background: transparent;
          color: #575752;
          padding: 11px 18px;
          border-radius: 999px;
          cursor: pointer;
          font-weight: 600;
          font-size: 13px;
        }

        .navTabs button.active {
          background: linear-gradient(180deg, #343430, #151512);
          color: white;
          box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.15);
        }

        .topActions {
          display: flex;
          align-items: center;
          gap: 10px;
        }

        .circleBtn,
        .profilePill {
          background: #ffffff;
          box-shadow: 0 8px 28px rgba(25, 25, 22, 0.06);
        }

        .profilePill {
          min-width: 222px;
          border-radius: 999px;
          display: flex;
          align-items: center;
          gap: 10px;
          padding: 8px 12px;
        }

        .avatar {
          width: 34px;
          height: 34px;
          border-radius: 50%;
          background: linear-gradient(135deg, #f5c4a3, #2c201c);
          color: white;
          display: grid;
          place-items: center;
          font-size: 12px;
          font-weight: 800;
        }

        .profilePill strong {
          display: block;
          font-size: 12px;
        }

        .profilePill span {
          display: block;
          max-width: 150px;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
          color: #777771;
          font-size: 11px;
        }

        .heroLine {
          display: flex;
          justify-content: space-between;
          align-items: flex-start;
          gap: 16px;
          margin-bottom: 16px;
        }

        .heroLine h1 {
          margin: 0;
          font-size: clamp(30px, 4vw, 46px);
          letter-spacing: -0.065em;
          line-height: 1;
          color: #181815;
        }

        .heroLine p {
          margin: 10px 0 0;
          color: #66665f;
          font-size: 15px;
        }

        .heroActions {
          display: flex;
          align-items: center;
          gap: 10px;
        }

        .tenantBadge {
          background: #ffffff;
          border: 1px solid #eeeeeb;
          border-radius: 22px;
          padding: 12px 16px;
          min-width: 120px;
          text-transform: capitalize;
          text-align: right;
        }

        .tenantBadge span {
          color: #787870;
          font-size: 12px;
          display: block;
        }

        .tenantBadge strong {
          font-size: 16px;
        }

        .exportBtn,
        .refreshBtn,
        .filterBtn,
        .currencyBtn,
        .smallSoft,
        .liveToggle {
          border: 1px solid #eeeeeb;
          background: #ffffff;
          border-radius: 999px;
          padding: 10px 13px;
          font-weight: 800;
          color: #353531;
          cursor: pointer;
          display: inline-flex;
          align-items: center;
          gap: 7px;
          transition: 0.2s ease;
        }

        .exportBtn {
          background: #22221f;
          color: white;
          border-color: #22221f;
          height: 44px;
        }

        button:disabled {
          opacity: 0.45;
          cursor: not-allowed;
          transform: none !important;
        }

        .exportBtn:hover,
        .refreshBtn:hover,
        .filterBtn:hover {
          transform: translateY(-1px);
        }

        .errorBox {
          margin-bottom: 16px;
          background: #fff3ef;
          border: 1px solid rgba(255, 84, 56, 0.24);
          color: #8b2b1f;
          border-radius: 18px;
          padding: 12px 14px;
          display: flex;
          align-items: center;
          gap: 10px;
        }

        .errorBox button {
          margin-left: auto;
          border: 0;
          background: #ff5438;
          color: white;
          padding: 8px 12px;
          border-radius: 999px;
          cursor: pointer;
        }

        .rangeRow {
          display: flex;
          justify-content: space-between;
          align-items: center;
          gap: 12px;
          margin-bottom: 16px;
        }

        .rangeTabs {
          background: #ffffff;
          border: 1px solid #eeeeeb;
          border-radius: 999px;
          padding: 6px;
          display: flex;
          gap: 6px;
          box-shadow: 0 8px 28px rgba(25, 25, 22, 0.04);
        }

        .rangeTabs button {
          border: 0;
          background: transparent;
          color: #686862;
          padding: 9px 14px;
          border-radius: 999px;
          font-weight: 800;
          cursor: pointer;
        }

        .rangeTabs button.active {
          background: #22221f;
          color: white;
        }

        .overviewGrid {
          display: grid;
          grid-template-columns: 1.05fr 1.05fr 1.05fr;
          gap: 16px;
          margin-bottom: 16px;
        }

        .balanceCard,
        .chartCard,
        .progressCard,
        .cardsCard,
        .tableCard,
        .leadCard,
        .workflowCard,
        .stateBox {
          background: #ffffff;
          border: 1px solid #eeeeeb;
          border-radius: 22px;
          padding: 18px;
          box-shadow: 0 12px 40px rgba(25, 25, 22, 0.045);
        }

        .cardTop {
          display: flex;
          align-items: flex-start;
          justify-content: space-between;
          gap: 12px;
        }

        .cardTop h3,
        .tableHeader h2 {
          margin: 0;
          font-size: 18px;
          letter-spacing: -0.04em;
        }

        .cardTop p,
        .tableHeader p {
          margin: 5px 0 0;
          color: #74746d;
          font-size: 13px;
        }

        .balanceCard h2 {
          margin: 6px 0 4px;
          font-size: 38px;
          letter-spacing: -0.06em;
        }

        .balanceCard p,
        .metricCard span {
          margin: 0;
          color: #74746d;
          font-size: 13px;
          font-weight: 600;
        }

        .greenText {
          color: #2dbf65;
          font-size: 12px;
          font-weight: 800;
        }

        .usageTrack {
          margin-top: 22px;
          height: 14px;
          background: repeating-linear-gradient(
            -45deg,
            #f0f0ee,
            #f0f0ee 4px,
            #e6e6e3 4px,
            #e6e6e3 8px
          );
          border-radius: 999px;
          overflow: hidden;
        }

        .usageTrack.small {
          height: 10px;
          margin-top: 12px;
        }

        .usageTrack span {
          display: block;
          height: 100%;
          background: linear-gradient(90deg, #ff3f22, #ff8b58);
          border-radius: 999px;
          transition: width 0.35s ease;
        }

        .usageMeta {
          display: flex;
          justify-content: space-between;
          margin-top: 10px;
          color: #777771;
          font-size: 13px;
        }

        .usageMeta strong {
          color: #22221f;
        }

        .miniWallets {
          margin-top: 16px;
          background: #f7f7f5;
          border-radius: 18px;
          padding: 12px;
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 10px;
        }

        .miniWallets div {
          background: #ffffff;
          border-radius: 14px;
          padding: 12px;
          min-width: 0;
        }

        .miniWallets strong {
          display: block;
          margin-top: 8px;
          font-size: 17px;
        }

        .miniWallets span {
          font-size: 11px;
          color: #777771;
        }

        .metricGrid {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 12px;
        }

        .metricCard {
          background: #ffffff;
          border: 1px solid #eeeeeb;
          border-radius: 18px;
          padding: 16px;
          min-height: 132px;
          position: relative;
        }

        .metricCard.hot {
          background: linear-gradient(160deg, #ff8a55, #ff3f22);
          color: white;
          border-color: transparent;
        }

        .metricCard.hot span,
        .metricCard.hot p {
          color: rgba(255, 255, 255, 0.78);
        }

        .metricIcon {
          position: absolute;
          right: 14px;
          top: 14px;
          width: 30px;
          height: 30px;
          border-radius: 50%;
          display: grid;
          place-items: center;
          background: rgba(0, 0, 0, 0.06);
        }

        .metricCard strong {
          display: block;
          margin-top: 30px;
          font-size: 34px;
          letter-spacing: -0.07em;
        }

        .metricCard p {
          margin: 5px 0 0;
          color: #74746d;
          font-size: 12px;
          font-weight: 800;
        }

        .legend {
          display: flex;
          gap: 10px;
          font-size: 11px;
          color: #66665f;
          align-items: center;
        }

        .legend span {
          display: inline-flex;
          gap: 5px;
          align-items: center;
        }

        .orangeDot,
        .darkDot {
          width: 8px;
          height: 8px;
          border-radius: 2px;
          display: inline-block;
        }

        .orangeDot {
          background: #ff5438;
        }

        .darkDot {
          background: #22221f;
        }

        .barChart {
          height: 205px;
          margin-top: 18px;
          display: flex;
          align-items: end;
          justify-content: space-between;
          gap: 10px;
          padding: 10px 0 0;
          background-image: linear-gradient(
            to top,
            #ededeb 1px,
            transparent 1px
          );
          background-size: 100% 42px;
        }

        .barGroup {
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 8px;
          flex: 1;
        }

        .bars {
          height: 150px;
          display: flex;
          align-items: end;
          gap: 5px;
        }

        .bar {
          width: 18px;
          border-radius: 999px 999px 5px 5px;
          display: block;
        }

        .barOrange {
          background: repeating-linear-gradient(
            -45deg,
            #ff5438,
            #ff5438 4px,
            #ff765f 4px,
            #ff765f 8px
          );
        }

        .barDark {
          background: #22221f;
        }

        .barLabel {
          font-size: 11px;
          color: #777771;
        }

        .progressAndCards {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 16px;
          margin-bottom: 16px;
        }

        .donutGrid {
          margin-top: 18px;
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 12px;
        }

        .donutWrap {
          display: grid;
          place-items: center;
          background: #f7f7f5;
          border-radius: 18px;
          padding: 16px 10px;
        }

        .donut {
          width: 112px;
          height: 112px;
          border-radius: 50%;
          background: conic-gradient(#ff5438 var(--value), #ededeb 0deg);
          display: grid;
          place-items: center;
          position: relative;
        }

        .donut:after {
          content: "";
          position: absolute;
          inset: 11px;
          border-radius: 50%;
          background: white;
        }

        .donut div {
          position: relative;
          z-index: 1;
          text-align: center;
        }

        .donut strong {
          display: block;
          font-size: 24px;
          letter-spacing: -0.05em;
        }

        .donut span {
          font-size: 11px;
          color: #777771;
          font-weight: 800;
        }

        .contractCards {
          margin-top: 16px;
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 12px;
        }

        .contract {
          border-radius: 18px;
          min-height: 124px;
          padding: 18px;
          color: white;
          display: flex;
          flex-direction: column;
          justify-content: space-between;
          overflow: hidden;
          position: relative;
        }

        .contract:after {
          content: "";
          position: absolute;
          width: 110px;
          height: 110px;
          border-radius: 28px;
          background: rgba(255, 255, 255, 0.08);
          right: -28px;
          top: -24px;
          transform: rotate(18deg);
        }

        .contract.dark {
          background: linear-gradient(135deg, #1f1f1b, #090907);
        }

        .contract.orange {
          background: linear-gradient(135deg, #ff8a55, #ff3f22);
        }

        .contract span,
        .contract small {
          color: rgba(255, 255, 255, 0.75);
          font-size: 12px;
          z-index: 1;
        }

        .contract strong {
          z-index: 1;
          max-width: 180px;
          letter-spacing: -0.03em;
        }

        .lowerGrid {
          display: grid;
          grid-template-columns: minmax(0, 1.45fr) minmax(320px, 0.55fr);
          gap: 16px;
          margin-bottom: 16px;
        }

        .tableCard,
        .workflowCard {
          padding: 0;
          overflow: hidden;
        }

        .tableHeader {
          padding: 18px;
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 16px;
        }

        .tableWrap {
          overflow-x: auto;
        }

        table {
          width: 100%;
          border-collapse: collapse;
          min-width: 760px;
        }

        th,
        td {
          padding: 14px 18px;
          border-top: 1px solid #eeeeeb;
          text-align: left;
          font-size: 13px;
          vertical-align: middle;
        }

        th {
          color: #85857e;
          background: #fbfbfa;
          font-weight: 800;
        }

        td {
          color: #30302c;
        }

        tbody tr {
          transition: 0.2s ease;
        }

        tbody tr:hover {
          background: #fbfbfa;
        }

        td small {
          display: block;
          margin-top: 4px;
          color: #85857e;
          font-size: 11px;
        }

        .activityCell {
          display: flex;
          align-items: center;
          gap: 10px;
          min-width: 190px;
        }

        .activityCell strong {
          display: block;
          letter-spacing: -0.02em;
        }

        .agentIcon {
          width: 28px;
          height: 28px;
          border-radius: 8px;
          display: grid;
          place-items: center;
          color: #ffffff;
          background: linear-gradient(135deg, #ff8a55, #ff3f22);
          flex: 0 0 auto;
        }

        .rowProgress {
          width: 92px;
          height: 8px;
          background: #eeeeeb;
          border-radius: 999px;
          overflow: hidden;
        }

        .rowProgress.wide {
          width: 100%;
          margin-top: 14px;
        }

        .rowProgress span {
          height: 100%;
          display: block;
          border-radius: 999px;
          background: linear-gradient(90deg, #ff5438, #ff9b69);
        }

        .sideCards {
          display: grid;
          gap: 16px;
        }

        .leadList {
          display: grid;
          gap: 12px;
          margin-top: 16px;
        }

        .leadRow {
          background: #f7f7f5;
          border-radius: 16px;
          padding: 13px;
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 12px;
        }

        .leadRow strong {
          display: block;
          font-size: 13px;
        }

        .leadRow span {
          display: block;
          margin-top: 4px;
          color: #777771;
          font-size: 11px;
        }

        .leadRow b {
          color: #ff5438;
          font-size: 18px;
        }

        .billingPanel {
          margin-top: 16px;
          background: #f7f7f5;
          border-radius: 18px;
          padding: 16px;
        }

        .billingPanel strong {
          display: block;
          font-size: 36px;
          letter-spacing: -0.07em;
        }

        .billingPanel span {
          color: #777771;
          font-size: 13px;
          font-weight: 800;
        }

        .billingPanel p {
          margin: 12px 0 0;
          color: #777771;
          font-size: 12px;
        }

        .lockedBox,
        .lockedMini {
          min-height: 260px;
          display: grid;
          place-items: center;
          align-content: center;
          text-align: center;
          gap: 10px;
          border-top: 1px solid #eeeeeb;
          color: #777771;
        }

        .lockedBox strong {
          color: #22221f;
          font-size: 18px;
        }

        .lockedMini {
          min-height: 140px;
          background: #f7f7f5;
          border-radius: 18px;
          border: 0;
          margin-top: 16px;
          padding: 14px;
        }

        .emptyNote {
          margin: 0;
          padding: 20px 18px;
          color: #8a8a83;
          font-size: 13px;
          line-height: 1.6;
          text-align: center;
        }

        .workflowGrid {
          padding: 0 18px 18px;
          display: grid;
          grid-template-columns: repeat(5, minmax(210px, 1fr));
          gap: 12px;
          overflow-x: auto;
        }

        .workflowItem {
          background: #f7f7f5;
          border: 1px solid #eeeeeb;
          border-radius: 18px;
          padding: 14px;
          min-width: 210px;
        }

        .workflowTop {
          display: flex;
          justify-content: space-between;
          align-items: flex-start;
          gap: 12px;
        }

        .workflowTop span {
          color: #777771;
          font-size: 11px;
          font-weight: 800;
        }

        .workflowTop strong {
          display: block;
          margin-top: 4px;
          letter-spacing: -0.03em;
        }

        .workflowStats {
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 8px;
          margin-top: 16px;
        }

        .workflowStats div {
          background: white;
          border-radius: 12px;
          padding: 10px;
        }

        .workflowStats span {
          color: #85857e;
          font-size: 10px;
          font-weight: 800;
        }

        .workflowStats strong {
          display: block;
          margin-top: 3px;
          font-size: 14px;
        }

        .statusBadge {
          display: inline-flex;
          align-items: center;
          gap: 6px;
          text-transform: capitalize;
          font-size: 11px;
          font-weight: 900;
          white-space: nowrap;
        }

        .statusBadge span {
          width: 7px;
          height: 7px;
          border-radius: 50%;
          background: currentColor;
        }

        .status-healthy {
          color: #30a46c;
        }

        .status-warning {
          color: #a57900;
        }

        .status-blocked {
          color: #d93025;
        }

        .stateBox {
          min-height: 520px;
          display: grid;
          place-items: center;
          align-content: center;
          text-align: center;
          gap: 10px;
          color: #777771;
        }

        .stateBox strong {
          color: #22221f;
          font-size: 18px;
        }

        .stateBox p {
          margin: 0;
        }

        .loader {
          width: 36px;
          height: 36px;
          border-radius: 50%;
          border: 3px solid #eeeeeb;
          border-top-color: #ff5438;
          animation: spin 0.8s linear infinite;
        }

        @keyframes spin {
          to {
            transform: rotate(360deg);
          }
        }

        @media (max-width: 1220px) {
          .overviewGrid,
          .lowerGrid {
            grid-template-columns: 1fr;
          }

          .progressAndCards {
            grid-template-columns: 1fr;
          }
        }

        @media (max-width: 860px) {
          .pageShell {
            grid-template-columns: 1fr;
            padding: 12px;
          }

          .sideRail {
            min-height: auto;
            border-radius: 24px 24px 0 0;
            flex-direction: row;
            overflow-x: auto;
            justify-content: flex-start;
          }

          .brandPill {
            margin-left: 0;
            width: auto;
          }

          .themeSwitch,
          .railNav,
          .railBottom {
            flex-direction: row;
          }

          .railBottom {
            margin-top: 0;
            margin-left: auto;
          }

          .dashboardPanel {
            border-radius: 0 0 24px 24px;
            min-height: auto;
            padding: 16px;
          }

          .topBar,
          .heroLine,
          .rangeRow,
          .tableHeader {
            flex-direction: column;
            align-items: stretch;
          }

          .navTabs,
          .rangeTabs {
            overflow-x: auto;
          }

          .topActions {
            justify-content: space-between;
          }

          .profilePill {
            min-width: 0;
            flex: 1;
          }

          .heroActions {
            justify-content: space-between;
          }

          .metricGrid,
          .contractCards,
          .donutGrid {
            grid-template-columns: 1fr;
          }

          .heroLine h1 {
            font-size: 34px;
          }
        }

        @media (max-width: 560px) {
          .topActions {
            flex-wrap: wrap;
          }

          .miniWallets {
            grid-template-columns: 1fr;
          }

          .heroActions {
            flex-direction: column;
            align-items: stretch;
          }

          .tenantBadge {
            text-align: left;
          }
        }
      `}</style>
    </div>
  );
}
