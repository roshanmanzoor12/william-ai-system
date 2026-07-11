"use client";

/**
 * apps/dashboard/src/app/tasks/page.tsx
 *
 * William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
 * Dashboard Prompt Bible
 *
 * Purpose:
 * - Task history and live progress dashboard.
 * - Tenant-safe frontend page using user_id and workspace_id on every task request.
 * - Supports future Master Agent, Security Agent, Memory Agent, and Verification Agent integration.
 * - Includes loading, error, empty states, role/plan visibility, safe errors, and audit-ready actions.
 */

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { SessionData, hasMinPlan, hasMinRole, readSession } from "@/lib/auth";

// Matches apps/api/routes/tasks.py's real TaskStatus/TaskPriority enums and
// TaskRecord model exactly (confirmed by reading the source). The old
// vocabulary here ("rejected" status, "critical" priority, plus a `progress`
// percentage, `duration_ms`, and `cost_units` that have no backend field at
// all) was fabricated and never matched what the API actually returns.
type TaskStatus = "created" | "queued" | "running" | "waiting_security" | "completed" | "failed" | "cancelled";
type TaskPriority = "low" | "normal" | "high" | "urgent";

type TaskRecord = {
  task_id: string;
  user_id: string;
  workspace_id: string;
  created_by_user_id: string;
  action: string;
  message: string;
  preferred_agent: string | null;
  priority: TaskPriority;
  status: TaskStatus;
  approved_by_security: boolean;
  security_result: Record<string, unknown> | null;
  memory_result: Record<string, unknown> | null;
  verification_result: Record<string, unknown> | null;
  created_at: string;
  updated_at: string;
  started_at: string | null;
  completed_at: string | null;
};

type TaskListResponse = {
  tasks: TaskRecord[];
  pagination: { limit: number; offset: number; returned: number };
  filters: { status: string | null; agent: string | null; include_workspace_tasks: boolean };
  isolation: { user_id: string; workspace_id: string };
};

function taskTitle(task: TaskRecord): string {
  return task.message || task.action;
}

function taskAgentLabel(task: TaskRecord): string {
  return task.preferred_agent || "Unassigned";
}

/** Real duration, derived from real timestamps -- null (not a fabricated
 * number) until the task has both started and completed. */
function taskDurationMs(task: TaskRecord): number | null {
  if (!task.started_at || !task.completed_at) return null;
  return new Date(task.completed_at).getTime() - new Date(task.started_at).getTime();
}

function taskIsSensitive(task: TaskRecord): boolean {
  return task.status === "waiting_security" || task.security_result !== null;
}

function taskSecurityReviewStatus(task: TaskRecord): "not_required" | "pending" | "approved" | "rejected" {
  if (task.status === "waiting_security") return "pending";
  if (task.security_result !== null) return task.approved_by_security ? "approved" : "rejected";
  return "not_required";
}

type ApiResponse<T> = {
  success: boolean;
  data?: T;
  error?: string;
  audit_event_id?: string;
};

type TaskStats = {
  total: number;
  completed: number;
  running: number;
  failed: number;
  securityPending: number;
};

const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL?.replace(/\/$/, "") || "";

const STATUS_LABELS: Record<TaskStatus, string> = {
  created: "Created",
  queued: "Queued",
  running: "Running",
  waiting_security: "Security Review",
  completed: "Completed",
  failed: "Failed",
  cancelled: "Cancelled",
};

const PRIORITY_LABELS: Record<TaskPriority, string> = {
  low: "Low",
  normal: "Normal",
  high: "High",
  urgent: "Urgent",
};

// Purely a coarse visual stage indicator for the progress bar's width --
// not a real completion percentage (the backend has no such field on
// TaskRecord; per-run progress only exists as individual TaskProgressEvent
// rows this page doesn't fetch). Never rendered as a number to the user.
const STATUS_STAGE_WIDTH: Record<TaskStatus, number> = {
  created: 5,
  queued: 15,
  running: 55,
  waiting_security: 60,
  completed: 100,
  failed: 100,
  cancelled: 100,
};

function nowIso(): string {
  return new Date().toISOString();
}

function safeError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error || "Unknown error");
  const blocked = ["secret", "token", "password", "apikey", "api_key", "database_url", "jwt"];
  const lower = message.toLowerCase();

  if (blocked.some((word) => lower.includes(word))) {
    return "A safe application error occurred. Please try again or contact workspace admin.";
  }

  return message;
}

function formatDateTime(value: string): string {
  try {
    return new Intl.DateTimeFormat("en", {
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

function formatDuration(ms: number | null): string {
  if (ms === null) return "Not available";
  if (ms < 1000) return `${ms}ms`;
  const seconds = Math.round(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const rest = seconds % 60;
  return `${minutes}m ${rest}s`;
}

function cx(...classes: Array<string | false | null | undefined>): string {
  return classes.filter(Boolean).join(" ");
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
      error: "API is not connected. Set NEXT_PUBLIC_API_BASE_URL in your dashboard environment.",
    };
  }

  const headers = new Headers(options.headers);
  headers.set("Content-Type", "application/json");
  headers.set("Authorization", `Bearer ${options.accessToken}`);
  headers.set("X-Audit-Action", options.audit_action || "dashboard_task_read");

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
        error: safeError(json.error || `Request failed with status ${response.status}`),
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
    | "play"
    | "shield"
    | "check"
    | "clock"
    | "x"
    | "filter"
    | "more"
    | "bolt"
    | "memory"
    | "chart"
    | "spark";
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
        <svg {...common} viewBox="0 0 32 32">
          <rect width="32" height="32" rx="12" fill="url(#logoGradient)" />
          <path d="M10 21.5V16h5.7c1.1 0 2-.9 2-2v-1.8H12V8h10v6.1c0 3.3-2.6 5.9-5.9 5.9h-1.3v1.5H10Z" fill="white" />
          <path d="M19.3 24v-5.7H24V24h-4.7Z" fill="white" />
          <defs>
            <linearGradient id="logoGradient" x1="4" x2="28" y1="4" y2="28">
              <stop stopColor="#ff805d" />
              <stop offset="1" stopColor="#ff3d22" />
            </linearGradient>
          </defs>
        </svg>
      );
    case "search":
      return (
        <svg {...common}>
          <path d="M11 19a8 8 0 1 1 5.3-2l3.4 3.3" stroke={stroke} strokeWidth="1.8" strokeLinecap="round" />
        </svg>
      );
    case "bell":
      return (
        <svg {...common}>
          <path d="M18 9a6 6 0 0 0-12 0c0 7-3 7-3 7h18s-3 0-3-7Z" stroke={stroke} strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
          <path d="M13.7 21a2 2 0 0 1-3.4 0" stroke={stroke} strokeWidth="1.7" strokeLinecap="round" />
          <circle cx="18.5" cy="5.5" r="2.5" fill="#ff5438" />
        </svg>
      );
    case "alert":
      return (
        <svg {...common}>
          <circle cx="12" cy="12" r="9" stroke={stroke} strokeWidth="1.7" />
          <path d="M12 7v6" stroke={stroke} strokeWidth="1.7" strokeLinecap="round" />
          <path d="M12 16.8h.01" stroke={stroke} strokeWidth="2.4" strokeLinecap="round" />
        </svg>
      );
    case "grid":
      return (
        <svg {...common}>
          <path d="M8.5 4.5h-3v3h3v-3ZM18.5 4.5h-3v3h3v-3ZM8.5 16.5h-3v3h3v-3ZM18.5 16.5h-3v3h3v-3ZM13.5 10.5h-3v3h3v-3Z" stroke={stroke} strokeWidth="1.5" />
        </svg>
      );
    case "calendar":
      return (
        <svg {...common}>
          <path d="M7 3v3M17 3v3M4 9h16M6 5h12a2 2 0 0 1 2 2v11a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2Z" stroke={stroke} strokeWidth="1.7" strokeLinecap="round" />
        </svg>
      );
    case "mail":
      return (
        <svg {...common}>
          <path d="M4 6.5h16v11H4v-11Z" stroke={stroke} strokeWidth="1.7" />
          <path d="m4 7 8 6 8-6" stroke={stroke} strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      );
    case "doc":
      return (
        <svg {...common}>
          <path d="M7 3.8h7l3 3V20H7V3.8Z" stroke={stroke} strokeWidth="1.7" strokeLinejoin="round" />
          <path d="M14 4v3h3M9.5 11h5M9.5 15h5" stroke={stroke} strokeWidth="1.5" strokeLinecap="round" />
        </svg>
      );
    case "users":
      return (
        <svg {...common}>
          <path d="M16 19c0-2.2-1.8-4-4-4s-4 1.8-4 4" stroke={stroke} strokeWidth="1.7" strokeLinecap="round" />
          <circle cx="12" cy="9" r="3" stroke={stroke} strokeWidth="1.7" />
          <path d="M20 18c0-1.8-1.1-3.3-2.7-3.8M16.8 6.3a2.5 2.5 0 0 1 0 4.4" stroke={stroke} strokeWidth="1.5" strokeLinecap="round" />
        </svg>
      );
    case "layers":
      return (
        <svg {...common}>
          <path d="m12 3 8 4-8 4-8-4 8-4Z" stroke={stroke} strokeWidth="1.7" strokeLinejoin="round" />
          <path d="m4 12 8 4 8-4M4 17l8 4 8-4" stroke={stroke} strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      );
    case "settings":
      return (
        <svg {...common}>
          <circle cx="12" cy="12" r="3" stroke={stroke} strokeWidth="1.7" />
          <path d="M19 12a7.4 7.4 0 0 0-.1-1l2-1.5-2-3.5-2.4 1a6 6 0 0 0-1.8-1L14.4 3h-4l-.4 3a6 6 0 0 0-1.8 1L5.8 6l-2 3.5 2 1.5a7.4 7.4 0 0 0 0 2l-2 1.5 2 3.5 2.4-1a6 6 0 0 0 1.8 1l.4 3h4l.4-3a6 6 0 0 0 1.8-1l2.4 1 2-3.5-2-1.5c.1-.3.1-.7.1-1Z" stroke={stroke} strokeWidth="1.2" strokeLinejoin="round" />
        </svg>
      );
    case "help":
      return (
        <svg {...common}>
          <circle cx="12" cy="12" r="9" stroke={stroke} strokeWidth="1.7" />
          <path d="M9.8 9.3a2.4 2.4 0 0 1 4.6 1c0 1.8-2.4 2-2.4 3.5" stroke={stroke} strokeWidth="1.7" strokeLinecap="round" />
          <path d="M12 17.2h.01" stroke={stroke} strokeWidth="2.4" strokeLinecap="round" />
        </svg>
      );
    case "logout":
      return (
        <svg {...common}>
          <path d="M10 5H6v14h4M14 8l4 4-4 4M18 12H9" stroke={stroke} strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      );
    case "moon":
      return (
        <svg {...common}>
          <path d="M19 15.2A7.5 7.5 0 0 1 8.8 5a8 8 0 1 0 10.2 10.2Z" stroke={stroke} strokeWidth="1.7" strokeLinejoin="round" />
        </svg>
      );
    case "sun":
      return (
        <svg {...common}>
          <circle cx="12" cy="12" r="4" stroke={stroke} strokeWidth="1.7" />
          <path d="M12 2.5v2M12 19.5v2M21.5 12h-2M4.5 12h-2M18.7 5.3l-1.4 1.4M6.7 17.3l-1.4 1.4M18.7 18.7l-1.4-1.4M6.7 6.7 5.3 5.3" stroke={stroke} strokeWidth="1.7" strokeLinecap="round" />
        </svg>
      );
    case "play":
      return (
        <svg {...common}>
          <path d="M8 5.5v13l11-6.5-11-6.5Z" stroke={stroke} strokeWidth="1.7" strokeLinejoin="round" />
        </svg>
      );
    case "shield":
      return (
        <svg {...common}>
          <path d="M12 3 19 6v5.5c0 4.5-2.8 7.8-7 9.5-4.2-1.7-7-5-7-9.5V6l7-3Z" stroke={stroke} strokeWidth="1.7" strokeLinejoin="round" />
          <path d="m9.5 12 1.8 1.8 3.7-4" stroke={stroke} strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      );
    case "check":
      return (
        <svg {...common}>
          <path d="m5 12 4 4L19 6" stroke={stroke} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      );
    case "clock":
      return (
        <svg {...common}>
          <circle cx="12" cy="12" r="9" stroke={stroke} strokeWidth="1.7" />
          <path d="M12 7v5l3 2" stroke={stroke} strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      );
    case "x":
      return (
        <svg {...common}>
          <path d="m7 7 10 10M17 7 7 17" stroke={stroke} strokeWidth="2" strokeLinecap="round" />
        </svg>
      );
    case "filter":
      return (
        <svg {...common}>
          <path d="M4 6h16M7 12h10M10 18h4" stroke={stroke} strokeWidth="1.8" strokeLinecap="round" />
        </svg>
      );
    case "more":
      return (
        <svg {...common}>
          <path d="M6 12h.01M12 12h.01M18 12h.01" stroke={stroke} strokeWidth="3" strokeLinecap="round" />
        </svg>
      );
    case "bolt":
      return (
        <svg {...common}>
          <path d="M13 2 5 13h6l-1 9 8-12h-6l1-8Z" stroke={stroke} strokeWidth="1.7" strokeLinejoin="round" />
        </svg>
      );
    case "memory":
      return (
        <svg {...common}>
          <rect x="5" y="5" width="14" height="14" rx="3" stroke={stroke} strokeWidth="1.7" />
          <path d="M9 2.5v3M15 2.5v3M9 18.5v3M15 18.5v3M2.5 9h3M2.5 15h3M18.5 9h3M18.5 15h3" stroke={stroke} strokeWidth="1.5" strokeLinecap="round" />
        </svg>
      );
    case "chart":
      return (
        <svg {...common}>
          <path d="M4 19V5M4 19h16" stroke={stroke} strokeWidth="1.7" strokeLinecap="round" />
          <path d="M8 16v-5M12 16V8M16 16v-7" stroke={stroke} strokeWidth="2" strokeLinecap="round" />
        </svg>
      );
    case "spark":
      return (
        <svg {...common}>
          <path d="M12 2.5 13.7 9l6.3 3-6.3 3L12 21.5 10.3 15 4 12l6.3-3L12 2.5Z" stroke={stroke} strokeWidth="1.5" strokeLinejoin="round" />
        </svg>
      );
    default:
      return null;
  }
}

function MiniBarChart({ tasks }: { tasks: TaskRecord[] }) {
  const bars = useMemo(() => {
    const labels = ["Master", "Security", "Memory", "Workflow", "Verify", "Code"];
    const counts = labels.map((label) => {
      const total = tasks.filter((task) => taskAgentLabel(task).toLowerCase().includes(label.toLowerCase())).length;
      const completed = tasks.filter(
        (task) => taskAgentLabel(task).toLowerCase().includes(label.toLowerCase()) && task.status === "completed",
      ).length;

      return {
        label,
        total: Math.max(total, 1),
        completed,
        failed: tasks.filter(
          (task) => taskAgentLabel(task).toLowerCase().includes(label.toLowerCase()) && task.status === "failed",
        ).length,
      };
    });

    return counts;
  }, [tasks]);

  return (
    <div className="chartCard">
      <div className="cardTop">
        <div>
          <h3>Agent Task Flow</h3>
          <p>Live completion ratio by agent lane</p>
        </div>
        <div className="legend">
          <span><i className="orangeDot" /> Completed</span>
          <span><i className="darkDot" /> Active</span>
        </div>
      </div>

      <div className="barChart" aria-label="Agent task flow chart">
        {bars.map((bar) => {
          const completedHeight = Math.max(24, Math.min(112, 36 + bar.completed * 20));
          const activeHeight = Math.max(18, Math.min(90, 26 + (bar.total - bar.completed + bar.failed) * 18));

          return (
            <div className="barGroup" key={bar.label}>
              <div className="bars">
                <span className="bar barOrange" style={{ height: completedHeight }} />
                <span className="bar barDark" style={{ height: activeHeight }} />
              </div>
              <span className="barLabel">{bar.label}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function StatusPill({ status }: { status: TaskStatus }) {
  return (
    <span className={cx("statusPill", `status-${status}`)}>
      <span />
      {STATUS_LABELS[status]}
    </span>
  );
}

function PriorityPill({ priority }: { priority: TaskPriority }) {
  return <span className={cx("priorityPill", `priority-${priority}`)}>{PRIORITY_LABELS[priority]}</span>;
}

export default function Page() {
  const router = useRouter();
  const [session, setSession] = useState<SessionData | null>(null);
  const [checkingSession, setCheckingSession] = useState(true);
  const [tasks, setTasks] = useState<TaskRecord[]>([]);
  const [selectedStatus, setSelectedStatus] = useState<TaskStatus | "all">("all");
  const [search, setSearch] = useState("");
  const [isLoading, setIsLoading] = useState(true);
  const [isCreatingTask, setIsCreatingTask] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [liveEnabled, setLiveEnabled] = useState(true);
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

  const canCreateTask = Boolean(session) && hasMinRole(session!.role, "manager") && hasMinPlan(session!.plan, "pro");
  const canApproveSecurity = Boolean(session) && hasMinRole(session!.role, "admin");
  const canExport = Boolean(session) && hasMinRole(session!.role, "admin") && hasMinPlan(session!.plan, "business");

  const stats: TaskStats = useMemo(() => {
    const total = tasks.length;
    const completed = tasks.filter((task) => task.status === "completed").length;
    const running = tasks.filter((task) => task.status === "running").length;
    const failed = tasks.filter((task) => task.status === "failed" || task.status === "cancelled").length;
    const securityPending = tasks.filter((task) => task.status === "waiting_security").length;

    return { total, completed, running, failed, securityPending };
  }, [tasks]);

  const filteredTasks = useMemo(() => {
    const q = search.trim().toLowerCase();

    return tasks.filter((task) => {
      const statusMatch = selectedStatus === "all" || task.status === selectedStatus;
      const searchMatch =
        !q ||
        task.task_id.toLowerCase().includes(q) ||
        taskTitle(task).toLowerCase().includes(q) ||
        taskAgentLabel(task).toLowerCase().includes(q);

      return statusMatch && searchMatch;
    });
  }, [tasks, selectedStatus, search]);

  const liveTask = useMemo(() => {
    return tasks.find((task) => task.status === "running") || tasks.find((task) => task.status === "waiting_security") || tasks[0];
  }, [tasks]);

  const loadTasks = useCallback(
    async (mode: "initial" | "poll" = "initial") => {
      if (!session) return;

      if (mode === "initial") setIsLoading(true);
      setError(null);

      const response = await dashboardFetch<TaskListResponse>("/tasks", {
        method: "GET",
        accessToken: session.accessToken,
        audit_action: "task_history_read",
      });

      if (response.success && response.data) {
        setTasks(response.data.tasks);
      } else if (mode === "initial") {
        setTasks([]);
        if (response.error) setError(response.error);
      }

      if (mode === "initial") setIsLoading(false);
    },
    [session],
  );

  useEffect(() => {
    if (!session || mounted.current) return;
    mounted.current = true;
    void loadTasks("initial");
  }, [loadTasks, session]);

  // "Live" polls the real /tasks endpoint on an interval instead of
  // fabricating progress ticks client-side -- there is no progress field
  // anywhere in the backend's TaskRecord to simulate in the first place.
  useEffect(() => {
    if (!liveEnabled || !session) return;

    const timer = window.setInterval(() => {
      void loadTasks("poll");
    }, 5000);

    return () => window.clearInterval(timer);
  }, [liveEnabled, session, loadTasks]);

  const createTask = async () => {
    if (!session) return;

    if (!canCreateTask) {
      setError("Your current role or plan cannot create agent tasks.");
      return;
    }

    setIsCreatingTask(true);
    setError(null);

    const payload = {
      action: "general_request",
      message: `Task created from the dashboard by ${session.name}.`,
      priority: "normal",
      auto_run: true,
      approved_by_security: false,
      metadata: { source: "dashboard_run_task_button" },
    };

    const response = await dashboardFetch<{ task: TaskRecord }>("/tasks/run", {
      method: "POST",
      accessToken: session.accessToken,
      audit_action: "task_create",
      body: JSON.stringify(payload),
    });

    if (response.success && response.data) {
      setTasks((current) => [response.data!.task, ...current]);
    } else {
      // A sensitive task's run step can fail server-side with 403
      // SECURITY_APPROVAL_REQUIRED even though the task itself was created
      // (it lands in "waiting_security") -- refresh from the real list
      // either way instead of guessing at what happened.
      if (response.error) setError(response.error);
      void loadTasks("poll");
    }

    setIsCreatingTask(false);
  };

  const approveSecurityTask = async (task: TaskRecord) => {
    if (!session) return;

    if (!canApproveSecurity) {
      setError("Only admins or owners can approve sensitive Security Agent tasks.");
      return;
    }

    setError(null);

    // The real backend has no dedicated "approve" endpoint -- a
    // waiting_security task is unblocked by re-running it with
    // approved_by_security: true (apps/api/routes/tasks.py's
    // TaskRunRequest, handled by POST /tasks/{task_id}/run).
    const response = await dashboardFetch<{ task: TaskRecord }>(`/tasks/${encodeURIComponent(task.task_id)}/run`, {
      method: "POST",
      accessToken: session.accessToken,
      audit_action: "security_task_approve",
      body: JSON.stringify({
        approved_by_security: true,
        runtime_input: {},
        metadata: { source: "dashboard_security_approval" },
      }),
    });

    if (response.success && response.data) {
      setTasks((current) => current.map((item) => (item.task_id === task.task_id ? response.data!.task : item)));
    } else if (response.error) {
      setError(response.error);
    }
  };

  const exportTasks = () => {
    if (!session) return;

    if (!canExport) {
      setError("Task export requires admin access and Business plan or higher.");
      return;
    }

    const isolatedTasks = tasks.filter(
      (task) => task.user_id === session.user_id && task.workspace_id === session.workspace_id,
    );

    const blob = new Blob([JSON.stringify({ user_id: session.user_id, workspace_id: session.workspace_id, tasks: isolatedTasks }, null, 2)], {
      type: "application/json",
    });

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `william-tasks-${session.workspace_id}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  if (checkingSession || !session) {
    return (
      <div className="dashboardPanel">
        <p>Checking secure session...</p>
      </div>
    );
  }

  return (
    <div className="dashboardPanel">
        <div className="heroLine">
          <div>
            <h1>Good morning, {session.name.split(" ")[0]}</h1>
            <p>Track agent tasks, live progress, security reviews, memory context, and verification status.</p>
          </div>

          <div className="tenantBadge">
            <span>{session.role}</span>
            <strong>{session.plan}</strong>
          </div>
        </div>

        {error ? (
          <div className="errorBox" role="alert">
            <Icon name="alert" />
            <span>{error}</span>
            <button onClick={() => setError(null)}>Dismiss</button>
          </div>
        ) : null}

        <section className="overviewGrid">
          <div className="balanceCard">
            <div className="cardTop">
              <div>
                <p>Total Tasks</p>
                <h2>{stats.total}</h2>
                <span className="greenText">↑ {stats.completed} completed</span>
              </div>
              <button className="currencyBtn">Live</button>
            </div>

            <div className="actionRow">
              <button className="primaryBtn" onClick={createTask} disabled={!canCreateTask || isCreatingTask}>
                <Icon name="play" size={16} />
                {isCreatingTask ? "Creating..." : "Run Task"}
              </button>
              <button className="softBtn" onClick={exportTasks} disabled={!canExport}>
                Export
              </button>
            </div>

            <div className="miniWallets">
              <div>
                <Icon name="bolt" />
                <strong>{stats.running}</strong>
                <span>Running</span>
              </div>
              <div>
                <Icon name="shield" />
                <strong>{stats.securityPending}</strong>
                <span>Security</span>
              </div>
              <div>
                <Icon name="check" />
                <strong>{stats.completed}</strong>
                <span>Completed</span>
              </div>
            </div>
          </div>

          <div className="metricGrid">
            <div className="metricCard hot">
              <div className="metricIcon"><Icon name="spark" /></div>
              <span>Total Completed</span>
              <strong>{stats.completed}</strong>
              <p>↑ Verification ready</p>
            </div>
            <div className="metricCard">
              <div className="metricIcon"><Icon name="clock" /></div>
              <span>Active Progress</span>
              <strong>{stats.running}</strong>
              <p>Live this session</p>
            </div>
            <div className="metricCard">
              <div className="metricIcon"><Icon name="memory" /></div>
              <span>Memory Ready</span>
              <strong>{tasks.filter((task) => task.memory_result !== null).length}</strong>
              <p>Context safe</p>
            </div>
            <div className="metricCard">
              <div className="metricIcon"><Icon name="chart" /></div>
              <span>Failed / Cancelled</span>
              <strong>{stats.failed}</strong>
              <p>Needs review</p>
            </div>
          </div>

          <MiniBarChart tasks={tasks} />
        </section>

        <section className="progressAndCards">
          <div className="progressCard">
            <div className="cardTop">
              <div>
                <h3>Most Active Task</h3>
                <p>{liveTask ? taskTitle(liveTask) : "No active task yet"}</p>
              </div>
              <button className={cx("liveToggle", liveEnabled && "on")} onClick={() => setLiveEnabled((value) => !value)}>
                {liveEnabled ? "Live On" : "Paused"}
              </button>
            </div>

            <div className="progressTrack">
              <span style={{ width: `${liveTask ? STATUS_STAGE_WIDTH[liveTask.status] : 0}%` }} />
            </div>

            <div className="progressMeta">
              <span>{liveTask ? formatDateTime(liveTask.updated_at) : "No recent activity"}</span>
              <strong>{liveTask ? STATUS_LABELS[liveTask.status] : "Empty"}</strong>
            </div>
          </div>

          <div className="cardsCard">
            <div className="cardTop">
              <h3>Agent Contracts</h3>
              <button className="smallSoft">+ Add rule</button>
            </div>

            <div className="contractCards">
              <div className="contract dark">
                <span>Security</span>
                <strong>Required for sensitive actions</strong>
                <small>Approval gate active</small>
              </div>
              <div className="contract orange">
                <span>Verification</span>
                <strong>Completion payload ready</strong>
                <small>Confirmation layer</small>
              </div>
            </div>
          </div>
        </section>

        <section className="tableCard">
          <div className="tableHeader">
            <div>
              <h2>Task History</h2>
              <p>All rows are scoped to current user and workspace only.</p>
            </div>

            <div className="tableTools">
              <label className="searchBox">
                <Icon name="search" size={16} />
                <input
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                  placeholder="Search task, agent..."
                />
              </label>

              <select value={selectedStatus} onChange={(event) => setSelectedStatus(event.target.value as TaskStatus | "all")}>
                <option value="all">All Status</option>
                <option value="created">Created</option>
                <option value="queued">Queued</option>
                <option value="running">Running</option>
                <option value="waiting_security">Security Review</option>
                <option value="completed">Completed</option>
                <option value="failed">Failed</option>
                <option value="cancelled">Cancelled</option>
              </select>

              <button className="filterBtn"><Icon name="filter" size={16} /> Filter</button>
            </div>
          </div>

          {isLoading ? (
            <div className="stateBox">
              <div className="loader" />
              <strong>Loading task history...</strong>
              <p>Checking workspace-safe records.</p>
            </div>
          ) : filteredTasks.length === 0 ? (
            <div className="stateBox">
              <Icon name="doc" size={34} />
              <strong>No tasks found</strong>
              <p>Create a task or clear your filters. Clean slate, very main-character energy.</p>
            </div>
          ) : (
            <div className="tableWrap">
              <table>
                <thead>
                  <tr>
                    <th><input type="checkbox" aria-label="Select all tasks" /></th>
                    <th>Task ID</th>
                    <th>Activity</th>
                    <th>Agent</th>
                    <th>Duration</th>
                    <th>Status</th>
                    <th>Priority</th>
                    <th>Updated</th>
                    <th />
                  </tr>
                </thead>

                <tbody>
                  {filteredTasks.map((task) => (
                    <tr key={task.task_id}>
                      <td><input type="checkbox" aria-label={`Select ${task.task_id}`} /></td>
                      <td><strong className="mono">{task.task_id}</strong></td>
                      <td>
                        <div className="activityCell">
                          <span className={cx("agentIcon", taskIsSensitive(task) && "sensitive")}>
                            {taskIsSensitive(task) ? <Icon name="shield" size={15} /> : <Icon name="bolt" size={15} />}
                          </span>
                          <div>
                            <strong>{taskTitle(task)}</strong>
                            <small>
                              {task.memory_result !== null ? "Memory-ready" : "Memory pending"} ·{" "}
                              {task.verification_result !== null ? "Verified" : "Verification pending"}
                            </small>
                          </div>
                        </div>
                      </td>
                      <td>{taskAgentLabel(task)}</td>
                      <td>{formatDuration(taskDurationMs(task))}</td>
                      <td><StatusPill status={task.status} /></td>
                      <td><PriorityPill priority={task.priority} /></td>
                      <td>
                        <span>{formatDateTime(task.updated_at)}</span>
                      </td>
                      <td>
                        {task.status === "waiting_security" ? (
                          <button className="approveBtn" onClick={() => approveSecurityTask(task)} disabled={!canApproveSecurity}>
                            Approve
                          </button>
                        ) : (
                          <button className="moreBtn" aria-label={`More actions for ${task.task_id}`}>
                            <Icon name="more" size={18} />
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

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
          gap: 0;
          background:
            radial-gradient(circle at 50% 10%, rgba(255, 255, 255, 0.8), transparent 28%),
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
          box-shadow: inset 0 1px 0 rgba(255,255,255,0.15);
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
          margin-bottom: 22px;
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
        .tableCard {
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
          font-weight: 700;
        }

        .currencyBtn,
        .smallSoft,
        .liveToggle,
        .filterBtn,
        .tableTools select {
          border: 1px solid #eeeeeb;
          background: #ffffff;
          border-radius: 999px;
          padding: 9px 12px;
          font-weight: 700;
          color: #353531;
          cursor: pointer;
        }

        .actionRow {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 10px;
          margin: 22px 0 16px;
        }

        .primaryBtn,
        .softBtn,
        .approveBtn {
          border: 0;
          height: 44px;
          border-radius: 999px;
          font-weight: 800;
          cursor: pointer;
          display: inline-flex;
          align-items: center;
          justify-content: center;
          gap: 8px;
          transition: 0.2s ease;
        }

        .primaryBtn {
          background: linear-gradient(180deg, #31312d, #161613);
          color: white;
        }

        .softBtn {
          background: #f4f4f2;
          color: #22221f;
        }

        .primaryBtn:hover,
        .softBtn:hover,
        .approveBtn:hover {
          transform: translateY(-1px);
        }

        button:disabled {
          opacity: 0.45;
          cursor: not-allowed;
          transform: none !important;
        }

        .miniWallets {
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
          color: rgba(255,255,255,0.78);
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
          background: rgba(0,0,0,0.06);
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
          font-weight: 700;
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
          background-image: linear-gradient(to top, #ededeb 1px, transparent 1px);
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

        .progressTrack {
          margin-top: 22px;
          height: 14px;
          background:
            repeating-linear-gradient(
              -45deg,
              #f0f0ee,
              #f0f0ee 4px,
              #e6e6e3 4px,
              #e6e6e3 8px
            );
          border-radius: 999px;
          overflow: hidden;
        }

        .progressTrack span {
          display: block;
          height: 100%;
          background: linear-gradient(90deg, #ff3f22, #ff8b58);
          border-radius: 999px;
          transition: width 0.4s ease;
        }

        .progressMeta {
          display: flex;
          justify-content: space-between;
          margin-top: 10px;
          color: #777771;
          font-size: 13px;
        }

        .progressMeta strong {
          color: #22221f;
        }

        .liveToggle.on {
          background: #22221f;
          color: white;
          border-color: #22221f;
        }

        .contractCards {
          margin-top: 16px;
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 12px;
        }

        .contract {
          border-radius: 18px;
          min-height: 112px;
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
          background: rgba(255,255,255,0.08);
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
          color: rgba(255,255,255,0.75);
          font-size: 12px;
          z-index: 1;
        }

        .contract strong {
          z-index: 1;
          max-width: 160px;
          letter-spacing: -0.03em;
        }

        .tableCard {
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

        .tableTools {
          display: flex;
          align-items: center;
          gap: 8px;
          flex-wrap: wrap;
          justify-content: flex-end;
        }

        .searchBox {
          width: min(260px, 100%);
          height: 42px;
          border: 1px solid #eeeeeb;
          background: white;
          border-radius: 14px;
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 0 12px;
        }

        .searchBox input {
          width: 100%;
          border: 0;
          outline: 0;
          background: transparent;
          color: #22221f;
        }

        .filterBtn {
          display: inline-flex;
          align-items: center;
          gap: 6px;
          height: 42px;
        }

        .tableTools select {
          height: 42px;
          border-radius: 14px;
          outline: 0;
        }

        .tableWrap {
          overflow-x: auto;
        }

        table {
          width: 100%;
          border-collapse: collapse;
          min-width: 980px;
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
          font-weight: 700;
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

        .mono {
          font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
          font-size: 12px;
        }

        .activityCell {
          display: flex;
          align-items: center;
          gap: 10px;
          min-width: 280px;
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
          background: linear-gradient(135deg, #54b4ff, #1677ff);
          flex: 0 0 auto;
        }

        .agentIcon.sensitive {
          background: linear-gradient(135deg, #ff8a55, #ff3f22);
        }

        .rowProgress {
          width: 92px;
          height: 8px;
          background: #eeeeeb;
          border-radius: 999px;
          overflow: hidden;
        }

        .rowProgress span {
          height: 100%;
          display: block;
          border-radius: 999px;
          background: linear-gradient(90deg, #ff5438, #ff9b69);
        }

        .statusPill {
          display: inline-flex;
          align-items: center;
          gap: 6px;
          white-space: nowrap;
          font-weight: 700;
          font-size: 12px;
        }

        .statusPill span {
          width: 7px;
          height: 7px;
          border-radius: 50%;
          background: currentColor;
        }

        .status-completed {
          color: #30a46c;
        }

        .status-running {
          color: #1677ff;
        }

        .status-waiting_security {
          color: #ff5438;
        }

        .status-failed,
        .status-rejected {
          color: #d93025;
        }

        .status-queued {
          color: #a57900;
        }

        .priorityPill {
          padding: 6px 9px;
          border-radius: 999px;
          font-size: 11px;
          font-weight: 800;
          background: #f3f3f1;
          color: #55554f;
        }

        .priority-high,
        .priority-critical {
          background: #fff1ec;
          color: #ff5438;
        }

        .priority-low {
          background: #edf8f1;
          color: #30a46c;
        }

        .approveBtn {
          height: 34px;
          padding: 0 13px;
          color: white;
          background: #22221f;
          font-size: 12px;
        }

        .stateBox {
          min-height: 280px;
          display: grid;
          place-items: center;
          align-content: center;
          text-align: center;
          gap: 10px;
          color: #777771;
          border-top: 1px solid #eeeeeb;
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

        @media (max-width: 1180px) {
          .overviewGrid {
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
          .tableHeader {
            flex-direction: column;
            align-items: stretch;
          }

          .navTabs {
            overflow-x: auto;
          }

          .topActions {
            justify-content: space-between;
          }

          .profilePill {
            min-width: 0;
            flex: 1;
          }

          .metricGrid,
          .contractCards {
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

          .actionRow,
          .miniWallets {
            grid-template-columns: 1fr;
          }

          .tableTools,
          .searchBox {
            width: 100%;
          }
        }
      `}</style>
    </div>
  );
}