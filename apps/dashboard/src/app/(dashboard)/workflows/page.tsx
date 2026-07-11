"use client";

/**
 * apps/dashboard/src/app/workflows/page.tsx
 *
 * William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
 * Dashboard Prompt Bible
 *
 * Purpose:
 * - Workflow builder and templates dashboard.
 * - Tenant-safe frontend page using user_id and workspace_id on every workflow request.
 * - Supports future Master Agent, Security Agent, Memory Agent, Verification Agent,
 *   audit logs, workflow registry, template loading, billing limits, and role checks.
 */

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { SessionData, UserPlan, hasMinPlan, hasMinRole, readSession } from "@/lib/auth";

// Matches apps/api/routes/workflows.py's real WorkflowStatus (template
// status) and WorkflowStepType enums exactly (confirmed by reading the
// source). The old WorkflowStatus/TemplateCategory/NodeType vocabulary
// ("blocked"/"completed" status, a "category" field, plan-gating on
// templates) had no backend equivalent at all -- templates only have
// name/description/status/steps/trigger_types/tags; there is no
// category, required-plan, sensitivity flag, time estimate, or usage
// count anywhere in WorkflowTemplateRecord.
type WorkflowStatus = "draft" | "active" | "paused" | "archived";
type WorkflowStepType =
  | "master_agent"
  | "agent"
  | "tool"
  | "http_request"
  | "webhook_response"
  | "memory_save"
  | "security_approval"
  | "condition"
  | "delay"
  | "notification";
type NodeType = "agent" | "security" | "memory" | "action";

type ApiResponse<T> = {
  success: boolean;
  data?: T;
  error?: string;
  audit_event_id?: string;
};

type WorkflowStep = {
  id: string;
  name: string;
  step_type: WorkflowStepType;
  agent_name: string | null;
  tool_name: string | null;
  requires_security_approval: boolean;
  risk_level: "low" | "medium" | "high" | "critical";
};

// Presentation-only node used to draw the canvas preview -- derived from
// a real WorkflowStep via stepToNode() below, never a separate data
// source. x/y are a deterministic left-to-right layout computed from the
// step's position in the list, not data returned by the backend (which
// has no visual-position concept at all).
type WorkflowNode = {
  id: string;
  type: NodeType;
  title: string;
  agent: string;
  sensitive: boolean;
  x: number;
  y: number;
};

type WorkflowTemplate = {
  id: string;
  user_id: string;
  workspace_id: string;
  name: string;
  description: string | null;
  status: WorkflowStatus;
  steps: WorkflowStep[];
  trigger_types: string[];
  tags: string[];
  created_at: string;
  updated_at: string;
};

function stepToNode(step: WorkflowStep, index: number): WorkflowNode {
  const typeMap: Record<WorkflowStepType, NodeType> = {
    master_agent: "agent",
    agent: "agent",
    tool: "action",
    http_request: "action",
    webhook_response: "action",
    memory_save: "memory",
    security_approval: "security",
    condition: "action",
    delay: "action",
    notification: "action",
  };

  return {
    id: step.id,
    type: typeMap[step.step_type],
    title: step.name,
    agent: step.agent_name || step.tool_name || step.step_type,
    sensitive: step.requires_security_approval,
    x: 8 + index * 242,
    y: 42,
  };
}

function templateIsSensitive(template: WorkflowTemplate): boolean {
  return template.steps.some((step) => step.requires_security_approval);
}

// Matches apps/api/routes/workflows.py's real WorkflowRunRecord exactly
// (confirmed by reading the source). The old WorkflowRecord conflated "a
// workflow" (a persistent thing with a cumulative run count and success
// rate) with what the backend actually models -- there is no such
// persistent "workflow" object, only templates (reusable recipes) and
// individual runs (one execution each). `runs`/`success_rate` had no
// backend source at all; a single run has neither concept.
type WorkflowRunStatus = "queued" | "running" | "waiting_approval" | "completed" | "failed" | "cancelled";

type WorkflowRun = {
  id: string;
  user_id: string;
  workspace_id: string;
  template_id: string;
  trigger_type: string;
  status: WorkflowRunStatus;
  current_step_index: number;
  approval_id: string | null;
  error: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  updated_at: string;
};

const RUN_STATUS_LABELS: Record<WorkflowRunStatus, string> = {
  queued: "Queued",
  running: "Running",
  waiting_approval: "Security Review",
  completed: "Completed",
  failed: "Failed",
  cancelled: "Cancelled",
};

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL?.replace(/\/$/, "") || "";

const STATUS_LABELS: Record<WorkflowStatus, string> = {
  draft: "Draft",
  active: "Active",
  paused: "Paused",
  archived: "Archived",
};

function cx(...classes: Array<string | false | null | undefined>): string {
  return classes.filter(Boolean).join(" ");
}

function nowIso(): string {
  return new Date().toISOString();
}

function safeError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error || "Unknown error");
  const blocked = ["secret", "token", "password", "apikey", "api_key", "database_url", "jwt", "connection string"];

  if (blocked.some((word) => message.toLowerCase().includes(word))) {
    return "A safe application error occurred. Please try again or contact the workspace admin.";
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

function formatNumber(value: number): string {
  return new Intl.NumberFormat("en").format(value);
}

// apps/api/routes/workflows.py returns {ok, message, templates|runs|
// webhooks|data, ...} -- a different envelope from every other router's
// {success, data, error} (confirmed by reading WorkflowResponse/
// WorkflowTemplateSearchResponse/WorkflowRunSearchResponse directly).
// `dataKey` names which top-level key on the real response holds the
// payload this call cares about; defaults to "data" for the single-item
// endpoints (POST /run, POST /templates, etc., which nest the record one
// level deeper under data.template / data.run).
async function dashboardFetch<T>(
  path: string,
  options: RequestInit & {
    accessToken: string;
    audit_action?: string;
    dataKey?: "templates" | "runs" | "webhooks" | "data";
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
  headers.set("X-Audit-Action", options.audit_action || "workflow_dashboard_read");

  try {
    const response = await fetch(`${API_BASE_URL}${path}`, {
      ...options,
      headers,
      credentials: "include",
    });

    const raw = (await response.json().catch(() => ({}))) as {
      ok?: boolean;
      message?: string;
      error?: { message?: string } | string;
      templates?: unknown;
      runs?: unknown;
      webhooks?: unknown;
      data?: unknown;
    };

    if (!response.ok || raw.ok === false) {
      const rawError = typeof raw.error === "string" ? raw.error : raw.error?.message;
      return {
        success: false,
        error: safeError(rawError || raw.message || `Request failed with status ${response.status}`),
      };
    }

    const key = options.dataKey || "data";
    return { success: true, data: raw[key] as T };
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
    | "workflow"
    | "template"
    | "shield"
    | "memory"
    | "verify"
    | "play"
    | "pause"
    | "plus"
    | "filter"
    | "more"
    | "spark"
    | "arrow"
    | "bolt"
    | "crm";
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
        <svg width={size} height={size} viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden>
          <rect width="32" height="32" rx="12" fill="url(#workflowLogoGradient)" />
          <path d="M10 21.5V16h5.7c1.1 0 2-.9 2-2v-1.8H12V8h10v6.1c0 3.3-2.6 5.9-5.9 5.9h-1.3v1.5H10Z" fill="white" />
          <path d="M19.3 24v-5.7H24V24h-4.7Z" fill="white" />
          <defs>
            <linearGradient id="workflowLogoGradient" x1="4" x2="28" y1="4" y2="28">
              <stop stopColor="#ff805d" />
              <stop offset="1" stopColor="#ff3d22" />
            </linearGradient>
          </defs>
        </svg>
      );
    case "search":
      return <svg {...common}><path d="M11 19a8 8 0 1 1 5.3-2l3.4 3.3" stroke={stroke} strokeWidth="1.8" strokeLinecap="round" /></svg>;
    case "bell":
      return <svg {...common}><path d="M18 9a6 6 0 0 0-12 0c0 7-3 7-3 7h18s-3 0-3-7Z" stroke={stroke} strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" /><path d="M13.7 21a2 2 0 0 1-3.4 0" stroke={stroke} strokeWidth="1.7" strokeLinecap="round" /><circle cx="18.5" cy="5.5" r="2.5" fill="#ff5438" /></svg>;
    case "alert":
      return <svg {...common}><circle cx="12" cy="12" r="9" stroke={stroke} strokeWidth="1.7" /><path d="M12 7v6" stroke={stroke} strokeWidth="1.7" strokeLinecap="round" /><path d="M12 16.8h.01" stroke={stroke} strokeWidth="2.4" strokeLinecap="round" /></svg>;
    case "grid":
      return <svg {...common}><path d="M8.5 4.5h-3v3h3v-3ZM18.5 4.5h-3v3h3v-3ZM8.5 16.5h-3v3h3v-3ZM18.5 16.5h-3v3h3v-3ZM13.5 10.5h-3v3h3v-3Z" stroke={stroke} strokeWidth="1.5" /></svg>;
    case "calendar":
      return <svg {...common}><path d="M7 3v3M17 3v3M4 9h16M6 5h12a2 2 0 0 1 2 2v11a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2Z" stroke={stroke} strokeWidth="1.7" strokeLinecap="round" /></svg>;
    case "mail":
      return <svg {...common}><path d="M4 6.5h16v11H4v-11Z" stroke={stroke} strokeWidth="1.7" /><path d="m4 7 8 6 8-6" stroke={stroke} strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" /></svg>;
    case "doc":
      return <svg {...common}><path d="M7 3.8h7l3 3V20H7V3.8Z" stroke={stroke} strokeWidth="1.7" strokeLinejoin="round" /><path d="M14 4v3h3M9.5 11h5M9.5 15h5" stroke={stroke} strokeWidth="1.5" strokeLinecap="round" /></svg>;
    case "users":
      return <svg {...common}><path d="M16 19c0-2.2-1.8-4-4-4s-4 1.8-4 4" stroke={stroke} strokeWidth="1.7" strokeLinecap="round" /><circle cx="12" cy="9" r="3" stroke={stroke} strokeWidth="1.7" /><path d="M20 18c0-1.8-1.1-3.3-2.7-3.8M16.8 6.3a2.5 2.5 0 0 1 0 4.4" stroke={stroke} strokeWidth="1.5" strokeLinecap="round" /></svg>;
    case "layers":
      return <svg {...common}><path d="m12 3 8 4-8 4-8-4 8-4Z" stroke={stroke} strokeWidth="1.7" strokeLinejoin="round" /><path d="m4 12 8 4 8-4M4 17l8 4 8-4" stroke={stroke} strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" /></svg>;
    case "settings":
      return <svg {...common}><circle cx="12" cy="12" r="3" stroke={stroke} strokeWidth="1.7" /><path d="M19 12a7.4 7.4 0 0 0-.1-1l2-1.5-2-3.5-2.4 1a6 6 0 0 0-1.8-1L14.4 3h-4l-.4 3a6 6 0 0 0-1.8 1L5.8 6l-2 3.5 2 1.5a7.4 7.4 0 0 0 0 2l-2 1.5 2 3.5 2.4-1a6 6 0 0 0 1.8 1l.4 3h4l.4-3a6 6 0 0 0 1.8-1l2.4 1 2-3.5-2-1.5c.1-.3.1-.7.1-1Z" stroke={stroke} strokeWidth="1.2" strokeLinejoin="round" /></svg>;
    case "help":
      return <svg {...common}><circle cx="12" cy="12" r="9" stroke={stroke} strokeWidth="1.7" /><path d="M9.8 9.3a2.4 2.4 0 0 1 4.6 1c0 1.8-2.4 2-2.4 3.5" stroke={stroke} strokeWidth="1.7" strokeLinecap="round" /><path d="M12 17.2h.01" stroke={stroke} strokeWidth="2.4" strokeLinecap="round" /></svg>;
    case "logout":
      return <svg {...common}><path d="M10 5H6v14h4M14 8l4 4-4 4M18 12H9" stroke={stroke} strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" /></svg>;
    case "moon":
      return <svg {...common}><path d="M19 15.2A7.5 7.5 0 0 1 8.8 5a8 8 0 1 0 10.2 10.2Z" stroke={stroke} strokeWidth="1.7" strokeLinejoin="round" /></svg>;
    case "sun":
      return <svg {...common}><circle cx="12" cy="12" r="4" stroke={stroke} strokeWidth="1.7" /><path d="M12 2.5v2M12 19.5v2M21.5 12h-2M4.5 12h-2M18.7 5.3l-1.4 1.4M6.7 17.3l-1.4 1.4M18.7 18.7l-1.4-1.4M6.7 6.7 5.3 5.3" stroke={stroke} strokeWidth="1.7" strokeLinecap="round" /></svg>;
    case "workflow":
      return <svg {...common}><path d="M6 6h4v4H6V6ZM14 14h4v4h-4v-4ZM14 6h4v4h-4V6ZM8 10v2a2 2 0 0 0 2 2h4M12 8h2" stroke={stroke} strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" /></svg>;
    case "template":
      return <svg {...common}><path d="M4 5h7v6H4V5ZM13 5h7v4h-7V5ZM13 11h7v8h-7v-8ZM4 13h7v6H4v-6Z" stroke={stroke} strokeWidth="1.7" strokeLinejoin="round" /></svg>;
    case "shield":
      return <svg {...common}><path d="M12 3 19 6v5.5c0 4.5-2.8 7.8-7 9.5-4.2-1.7-7-5-7-9.5V6l7-3Z" stroke={stroke} strokeWidth="1.7" strokeLinejoin="round" /><path d="m9.5 12 1.8 1.8 3.7-4" stroke={stroke} strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" /></svg>;
    case "memory":
      return <svg {...common}><rect x="5" y="5" width="14" height="14" rx="3" stroke={stroke} strokeWidth="1.7" /><path d="M9 2.5v3M15 2.5v3M9 18.5v3M15 18.5v3M2.5 9h3M2.5 15h3M18.5 9h3M18.5 15h3" stroke={stroke} strokeWidth="1.5" strokeLinecap="round" /></svg>;
    case "verify":
      return <svg {...common}><circle cx="12" cy="12" r="9" stroke={stroke} strokeWidth="1.7" /><path d="m8.5 12.3 2.2 2.2 4.9-5.2" stroke={stroke} strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round" /></svg>;
    case "play":
      return <svg {...common}><path d="M8 5.5v13l11-6.5-11-6.5Z" stroke={stroke} strokeWidth="1.7" strokeLinejoin="round" /></svg>;
    case "pause":
      return <svg {...common}><path d="M8 5v14M16 5v14" stroke={stroke} strokeWidth="2.2" strokeLinecap="round" /></svg>;
    case "plus":
      return <svg {...common}><path d="M12 5v14M5 12h14" stroke={stroke} strokeWidth="1.9" strokeLinecap="round" /></svg>;
    case "filter":
      return <svg {...common}><path d="M4 6h16M7 12h10M10 18h4" stroke={stroke} strokeWidth="1.8" strokeLinecap="round" /></svg>;
    case "more":
      return <svg {...common}><path d="M6 12h.01M12 12h.01M18 12h.01" stroke={stroke} strokeWidth="3" strokeLinecap="round" /></svg>;
    case "spark":
      return <svg {...common}><path d="M12 2.5 13.7 9l6.3 3-6.3 3L12 21.5 10.3 15 4 12l6.3-3L12 2.5Z" stroke={stroke} strokeWidth="1.5" strokeLinejoin="round" /></svg>;
    case "arrow":
      return <svg {...common}><path d="M7 17 17 7M9 7h8v8" stroke={stroke} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" /></svg>;
    case "bolt":
      return <svg {...common}><path d="M13 2 5 13h6l-1 9 8-12h-6l1-8Z" stroke={stroke} strokeWidth="1.7" strokeLinejoin="round" /></svg>;
    case "crm":
      return <svg {...common}><path d="M5 5h14v14H5V5Z" stroke={stroke} strokeWidth="1.7" /><path d="M8 9h8M8 13h5M8 17h8" stroke={stroke} strokeWidth="1.6" strokeLinecap="round" /></svg>;
    default:
      return null;
  }
}

function StatusPill({ status }: { status: WorkflowStatus }) {
  return (
    <span className={cx("statusPill", `status-${status}`)}>
      <span />
      {STATUS_LABELS[status]}
    </span>
  );
}

function RunStatusPill({ status }: { status: WorkflowRunStatus }) {
  return (
    <span className={cx("statusPill", `status-${status}`)}>
      <span />
      {RUN_STATUS_LABELS[status]}
    </span>
  );
}

function TemplateStatusIcon({ status }: { status: WorkflowStatus }) {
  if (status === "active") return <Icon name="spark" size={16} />;
  if (status === "paused") return <Icon name="pause" size={16} />;
  if (status === "archived") return <Icon name="doc" size={16} />;
  return <Icon name="template" size={16} />;
}

function WorkflowCanvas({ nodes }: { nodes: WorkflowNode[] }) {
  return (
    <div className="canvasWrap">
      <div className="canvasGrid">
        <svg className="connectorSvg" viewBox="0 0 940 210" preserveAspectRatio="none" aria-hidden>
          {nodes.slice(0, -1).map((node, index) => {
            const next = nodes[index + 1];
            return (
              <path
                key={`${node.id}-${next.id}`}
                d={`M ${node.x + 180} ${node.y + 42} C ${node.x + 220} ${node.y + 42}, ${next.x - 40} ${next.y + 42}, ${next.x} ${next.y + 42}`}
                stroke="#d8d8d4"
                strokeWidth="3"
                strokeLinecap="round"
                fill="none"
              />
            );
          })}
        </svg>

        {nodes.map((node) => (
          <div
            key={node.id}
            className={cx("builderNode", `node-${node.type}`, node.sensitive && "sensitive")}
            style={{ left: node.x, top: node.y }}
          >
            <div className="nodeIcon">
              {node.type === "agent" ? <Icon name="spark" size={16} /> : null}
              {node.type === "security" ? <Icon name="shield" size={16} /> : null}
              {node.type === "memory" ? <Icon name="memory" size={16} /> : null}
              {node.type === "action" ? <Icon name="workflow" size={16} /> : null}
            </div>
            <div>
              <strong>{node.title}</strong>
              <span>{node.agent}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function Page() {
  const router = useRouter();
  const [session, setSession] = useState<SessionData | null>(null);
  const [checkingSession, setCheckingSession] = useState(true);
  const [templates, setTemplates] = useState<WorkflowTemplate[]>([]);
  const [runs, setRuns] = useState<WorkflowRun[]>([]);
  const [selectedTemplateId, setSelectedTemplateId] = useState<string>("");
  const [selectedStatus, setSelectedStatus] = useState<WorkflowStatus | "all">("all");
  const [search, setSearch] = useState("");
  const [isLoading, setIsLoading] = useState(true);
  const [isCreating, setIsCreating] = useState(false);
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

  const canCreateWorkflow = Boolean(session) && hasMinRole(session!.role, "manager") && hasMinPlan(session!.plan, "pro");
  const canUseSensitiveWorkflow = Boolean(session) && hasMinRole(session!.role, "admin") && hasMinPlan(session!.plan, "business");
  const canPublishWorkflow = Boolean(session) && hasMinRole(session!.role, "admin") && hasMinPlan(session!.plan, "pro");

  const selectedTemplate = useMemo(() => {
    return templates.find((template) => template.id === selectedTemplateId) || templates[0];
  }, [selectedTemplateId, templates]);

  const stats = useMemo(() => {
    const total = runs.length;
    const running = runs.filter((run) => run.status === "running").length;
    const waitingApproval = runs.filter((run) => run.status === "waiting_approval").length;
    const completed = runs.filter((run) => run.status === "completed").length;
    const failed = runs.filter((run) => run.status === "failed" || run.status === "cancelled").length;
    const finished = completed + failed;
    const successRate = finished ? Math.round((completed / finished) * 100) : null;

    return { total, running, waitingApproval, completed, failed, successRate };
  }, [runs]);

  const filteredTemplates = useMemo(() => {
    const q = search.trim().toLowerCase();

    return templates.filter((template) => {
      const statusMatch = selectedStatus === "all" || template.status === selectedStatus;
      const searchMatch =
        !q ||
        template.name.toLowerCase().includes(q) ||
        (template.description || "").toLowerCase().includes(q);

      return statusMatch && searchMatch;
    });
  }, [templates, selectedStatus, search]);

  const loadWorkflows = useCallback(async () => {
    if (!session) return;

    setIsLoading(true);
    setError(null);

    const [templateResponse, runResponse] = await Promise.all([
      dashboardFetch<WorkflowTemplate[]>("/workflows/templates", {
        method: "GET",
        accessToken: session.accessToken,
        audit_action: "workflow_templates_read",
        dataKey: "templates",
      }),
      dashboardFetch<WorkflowRun[]>("/workflows/runs", {
        method: "GET",
        accessToken: session.accessToken,
        audit_action: "workflow_history_read",
        dataKey: "runs",
      }),
    ]);

    if (templateResponse.success && Array.isArray(templateResponse.data)) {
      setTemplates(templateResponse.data);
      setSelectedTemplateId((current) => current || templateResponse.data![0]?.id || "");
    } else {
      setTemplates([]);
      if (templateResponse.error) setError(templateResponse.error);
    }

    if (runResponse.success && Array.isArray(runResponse.data)) {
      setRuns(runResponse.data);
    } else {
      setRuns([]);
      if (runResponse.error) setError(runResponse.error);
    }

    setIsLoading(false);
  }, [session]);

  useEffect(() => {
    if (mounted.current) return;
    mounted.current = true;
    void loadWorkflows();
  }, [loadWorkflows]);

  const createWorkflowFromTemplate = async (template: WorkflowTemplate) => {
    if (!session) return;

    if (!canCreateWorkflow) {
      setError("Your current role or plan cannot run workflows.");
      return;
    }

    if (templateIsSensitive(template) && !canUseSensitiveWorkflow) {
      setError("Sensitive workflow templates require admin access and Business plan or higher.");
      return;
    }

    setIsCreating(true);
    setError(null);

    const payload = {
      template_id: template.id,
      trigger_type: "manual",
      input_data: {},
      metadata: { source: "dashboard_workflows_page" },
      dry_run: false,
    };

    // POST /workflows/run nests the created record one level deeper, under
    // data.run (see WorkflowResponse(data={"run": run.visible_dict()})).
    const response = await dashboardFetch<{ run: WorkflowRun }>("/workflows/run", {
      method: "POST",
      accessToken: session.accessToken,
      audit_action: "workflow_create",
      body: JSON.stringify(payload),
      dataKey: "data",
    });

    if (response.success && response.data) {
      setRuns((current) => [response.data!.run, ...current]);
    } else if (response.error) {
      setError(response.error);
    }

    setIsCreating(false);
  };

  const toggleTemplateStatus = async (template: WorkflowTemplate) => {
    if (!session) return;

    if (!canCreateWorkflow) {
      setError("Your current role or plan cannot change template status.");
      return;
    }

    const nextStatus: WorkflowStatus = template.status === "active" ? "paused" : "active";

    const response = await dashboardFetch<{ template: WorkflowTemplate }>(
      `/workflows/templates/${encodeURIComponent(template.id)}`,
      {
        method: "PATCH",
        accessToken: session.accessToken,
        audit_action: "workflow_template_status_change",
        body: JSON.stringify({ status: nextStatus }),
        dataKey: "data",
      },
    );

    if (response.success && response.data) {
      setTemplates((current) => current.map((item) => (item.id === template.id ? response.data!.template : item)));
    } else if (response.error) {
      setError(response.error);
    }
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
            <h1>Workflows, {session.name.split(" ")[0]}</h1>
            <p>Build agent automations, load templates, route sensitive actions, save memory context, and verify completions.</p>
          </div>

          <div className="heroActions">
            <div className="tenantBadge">
              <span>{session.role}</span>
              <strong>{session.plan}</strong>
            </div>
            <button
              className="createBtn"
              disabled={!canCreateWorkflow || !selectedTemplate || isCreating}
              onClick={() => selectedTemplate && createWorkflowFromTemplate(selectedTemplate)}
            >
              <Icon name="plus" size={16} />
              {isCreating ? "Creating..." : "Create Flow"}
            </button>
          </div>
        </div>

        {error ? (
          <div className="errorBox" role="alert">
            <Icon name="alert" />
            <span>{error}</span>
            <button onClick={() => setError(null)}>Dismiss</button>
          </div>
        ) : null}

        {isLoading ? (
          <section className="stateBox">
            <div className="loader" />
            <strong>Loading workflows...</strong>
            <p>Checking tenant-safe workflow templates and automation history.</p>
          </section>
        ) : (
          <>
            <section className="overviewGrid">
              <div className="balanceCard">
                <div className="cardTop">
                  <div>
                    <p>Total Runs</p>
                    <h2>{formatNumber(stats.total)}</h2>
                    <span className="greenText">↑ {stats.running} running now</span>
                  </div>
                  <button className="currencyBtn">Live</button>
                </div>

                <div className="actionRow">
                  <button
                    className="primaryBtn"
                    disabled={!canCreateWorkflow || !selectedTemplate || isCreating}
                    onClick={() => selectedTemplate && createWorkflowFromTemplate(selectedTemplate)}
                  >
                    <Icon name="play" size={16} />
                    Use Template
                  </button>
                  <button className="softBtn" onClick={() => loadWorkflows()}>
                    Refresh
                  </button>
                </div>

                <div className="miniWallets">
                  <div>
                    <Icon name="workflow" />
                    <strong>{formatNumber(stats.completed)}</strong>
                    <span>Completed</span>
                  </div>
                  <div>
                    <Icon name="verify" />
                    <strong>{stats.successRate === null ? "N/A" : `${stats.successRate}%`}</strong>
                    <span>Success</span>
                  </div>
                  <div>
                    <Icon name="shield" />
                    <strong>{stats.waitingApproval}</strong>
                    <span>Awaiting Approval</span>
                  </div>
                </div>
              </div>

              <div className="metricGrid">
                <div className="metricCard hot">
                  <div className="metricIcon"><Icon name="spark" /></div>
                  <span>Templates</span>
                  <strong>{templates.length}</strong>
                  <p>Ready to launch</p>
                </div>

                <div className="metricCard">
                  <div className="metricIcon"><Icon name="memory" /></div>
                  <span>Queued</span>
                  <strong>{runs.filter((run) => run.status === "queued").length}</strong>
                  <p>Waiting to start</p>
                </div>

                <div className="metricCard">
                  <div className="metricIcon"><Icon name="shield" /></div>
                  <span>Security Routed</span>
                  <strong>{runs.filter((run) => run.approval_id !== null).length}</strong>
                  <p>Approval required</p>
                </div>

                <div className="metricCard">
                  <div className="metricIcon"><Icon name="verify" /></div>
                  <span>Failed</span>
                  <strong>{stats.failed}</strong>
                  <p>Needs review</p>
                </div>
              </div>

              <div className="chartCard">
                <div className="cardTop">
                  <div>
                    <h3>Run Status</h3>
                    <p>Real run counts by status</p>
                  </div>
                  <div className="legend">
                    <span><i className="orangeDot" /> Count</span>
                  </div>
                </div>

                {runs.length === 0 ? (
                  <p className="emptyNote">No workflow runs yet -- use a template above to start one.</p>
                ) : (
                <div className="barChart">
                  {(Object.keys(RUN_STATUS_LABELS) as WorkflowRunStatus[]).map((statusKey) => {
                    const count = runs.filter((run) => run.status === statusKey).length;
                    const barHeight = Math.max(8, Math.min(145, count * 24));

                    return (
                      <div className="barGroup" key={statusKey}>
                        <div className="bars">
                          <span className="bar barOrange" style={{ height: barHeight }} />
                        </div>
                        <span className="barLabel">{RUN_STATUS_LABELS[statusKey]}</span>
                      </div>
                    );
                  })}
                </div>
                )}
              </div>
            </section>

            <section className="builderGrid">
              <div className="builderCard">
                <div className="tableHeader">
                  <div>
                    <h2>Workflow Builder</h2>
                    <p>{selectedTemplate ? selectedTemplate.description : "Select a template to preview the workflow chain."}</p>
                  </div>

                  <button
                    className="filterBtn"
                    disabled={!selectedTemplate}
                    onClick={() => selectedTemplate && createWorkflowFromTemplate(selectedTemplate)}
                  >
                    <Icon name="plus" size={16} />
                    Build
                  </button>
                </div>

                {selectedTemplate ? (
                  <WorkflowCanvas nodes={selectedTemplate.steps.map(stepToNode)} />
                ) : (
                  <div className="emptyBuilder">
                    <Icon name="workflow" size={34} />
                    <strong>No template selected</strong>
                    <p>Pick one from the template library. The robots need a blueprint, boss.</p>
                  </div>
                )}
              </div>

              <div className="contractCard">
                <div className="cardTop">
                  <h3>Automation Rules</h3>
                  <button className="smallSoft">Audit On</button>
                </div>

                <div className="contractCards">
                  <div className="contract dark">
                    <span>Security Agent</span>
                    <strong>{selectedTemplate && templateIsSensitive(selectedTemplate) ? "Required before publish" : "Not required"}</strong>
                    <small>Sensitive action gate</small>
                  </div>

                  <div className="contract orange">
                    <span>Verification Agent</span>
                    <strong>Always prepared</strong>
                    <small>Completion confirmation</small>
                  </div>
                </div>

                <div className="ruleList">
                  <div>
                    <Icon name="memory" />
                    <span>Memory Agent compatible context</span>
                  </div>
                  <div>
                    <Icon name="shield" />
                    <span>Role and plan checked before execution</span>
                  </div>
                  <div>
                    <Icon name="doc" />
                    <span>Audit event emitted for state changes</span>
                  </div>
                </div>
              </div>
            </section>

            <section className="templateSection">
              <div className="tableHeader">
                <div>
                  <h2>Workflow Templates</h2>
                  <p>Production-ready automation starters scoped to current workspace.</p>
                </div>

                <div className="tableTools">
                  <label className="searchBox">
                    <Icon name="search" size={16} />
                    <input
                      value={search}
                      onChange={(event) => setSearch(event.target.value)}
                      placeholder="Search templates..."
                    />
                  </label>

                  <select
                    value={selectedStatus}
                    onChange={(event) => setSelectedStatus(event.target.value as WorkflowStatus | "all")}
                  >
                    <option value="all">All Statuses</option>
                    <option value="draft">Draft</option>
                    <option value="active">Active</option>
                    <option value="paused">Paused</option>
                    <option value="archived">Archived</option>
                  </select>

                  <button className="filterBtn"><Icon name="filter" size={16} /> Filter</button>
                </div>
              </div>

              {filteredTemplates.length === 0 ? (
                <div className="emptyBuilder">
                  <Icon name="template" size={34} />
                  <strong>No templates found</strong>
                  <p>{templates.length === 0 ? "Create a workflow template to get started." : "Clear filters to see your existing templates."}</p>
                </div>
              ) : (
                <div className="templateGrid">
                  {filteredTemplates.map((template) => {
                    const sensitive = templateIsSensitive(template);

                    return (
                      <article
                        key={template.id}
                        className={cx("templateCard", selectedTemplate?.id === template.id && "selected")}
                        onClick={() => setSelectedTemplateId(template.id)}
                      >
                        <div className="templateTop">
                          <span className="templateIcon"><TemplateStatusIcon status={template.status} /></span>
                          <button
                            className="moreBtn"
                            aria-label={`Toggle status for ${template.name}`}
                            onClick={(event) => {
                              event.stopPropagation();
                              void toggleTemplateStatus(template);
                            }}
                            disabled={!canCreateWorkflow}
                          >
                            <Icon name="more" size={18} />
                          </button>
                        </div>

                        <h3>{template.name}</h3>
                        <p>{template.description || "No description."}</p>

                        <div className="templateMeta">
                          <span>{template.steps.length} steps</span>
                          <span>{STATUS_LABELS[template.status]}</span>
                          {sensitive ? <span>Security-reviewed</span> : null}
                        </div>

                        <button
                          className="templateBtn"
                          disabled={!canCreateWorkflow || (sensitive && !canUseSensitiveWorkflow) || isCreating}
                          onClick={(event) => {
                            event.stopPropagation();
                            createWorkflowFromTemplate(template);
                          }}
                        >
                          {sensitive && !canUseSensitiveWorkflow ? "Admin Only" : "Use Template"}
                        </button>
                      </article>
                    );
                  })}
                </div>
              )}
            </section>

            <section className="tableCard">
              <div className="tableHeader">
                <div>
                  <h2>Run History</h2>
                  <p>Live run records scoped to the current user and workspace only.</p>
                </div>
                <button className="filterBtn" onClick={() => loadWorkflows()}><Icon name="workflow" size={16} /> Refresh</button>
              </div>

              {runs.length === 0 ? (
                <div className="emptyBuilder">
                  <Icon name="doc" size={34} />
                  <strong>No runs yet</strong>
                  <p>Use a template above to start your first workflow run.</p>
                </div>
              ) : (
                <div className="tableWrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Run ID</th>
                        <th>Template</th>
                        <th>Status</th>
                        <th>Trigger</th>
                        <th>Security</th>
                        <th>Started</th>
                        <th>Completed</th>
                      </tr>
                    </thead>

                    <tbody>
                      {runs.map((run) => {
                        const template = templates.find((item) => item.id === run.template_id);
                        const sensitive = run.approval_id !== null;

                        return (
                          <tr key={run.id}>
                            <td><strong className="mono">{run.id}</strong></td>
                            <td>
                              <div className="activityCell">
                                <span className={cx("agentIcon", sensitive && "sensitive")}>
                                  {sensitive ? <Icon name="shield" size={15} /> : <Icon name="workflow" size={15} />}
                                </span>
                                <div>
                                  <strong>{template?.name || run.template_id}</strong>
                                  {run.error ? <small>{run.error}</small> : null}
                                </div>
                              </div>
                            </td>
                            <td><RunStatusPill status={run.status} /></td>
                            <td>{run.trigger_type}</td>
                            <td>{sensitive ? <Icon name="shield" size={15} /> : "—"}</td>
                            <td>{run.started_at ? formatDateTime(run.started_at) : "Not started"}</td>
                            <td>{run.completed_at ? formatDateTime(run.completed_at) : "—"}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
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

        .createBtn,
        .currencyBtn,
        .smallSoft,
        .filterBtn,
        .primaryBtn,
        .softBtn,
        .approveBtn,
        .templateBtn {
          border: 0;
          border-radius: 999px;
          font-weight: 800;
          cursor: pointer;
          display: inline-flex;
          align-items: center;
          justify-content: center;
          gap: 8px;
          transition: 0.2s ease;
          white-space: nowrap;
        }

        .createBtn,
        .primaryBtn,
        .approveBtn {
          background: linear-gradient(180deg, #31312d, #161613);
          color: white;
        }

        .createBtn {
          height: 44px;
          padding: 0 16px;
        }

        .primaryBtn,
        .softBtn {
          height: 44px;
        }

        .softBtn,
        .currencyBtn,
        .smallSoft,
        .filterBtn {
          background: #ffffff;
          color: #22221f;
          border: 1px solid #eeeeeb;
          padding: 10px 13px;
        }

        .primaryBtn:hover,
        .softBtn:hover,
        .createBtn:hover,
        .approveBtn:hover,
        .templateBtn:hover {
          transform: translateY(-1px);
        }

        button:disabled {
          opacity: 0.45;
          cursor: not-allowed;
          transform: none !important;
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
        .builderCard,
        .contractCard,
        .templateSection,
        .tableCard,
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

        .actionRow {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 10px;
          margin: 22px 0 16px;
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
          background: repeating-linear-gradient(-45deg, #ff5438, #ff5438 4px, #ff765f 4px, #ff765f 8px);
        }

        .barDark {
          background: #22221f;
        }

        .barLabel {
          font-size: 11px;
          color: #777771;
        }

        .builderGrid {
          display: grid;
          grid-template-columns: minmax(0, 1.5fr) minmax(320px, 0.5fr);
          gap: 16px;
          margin-bottom: 16px;
        }

        .builderCard,
        .contractCard,
        .templateSection,
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

        .canvasWrap {
          padding: 0 18px 18px;
          overflow-x: auto;
        }

        .canvasGrid {
          height: 210px;
          min-width: 940px;
          border-radius: 22px;
          background:
            linear-gradient(#ededeb 1px, transparent 1px),
            linear-gradient(90deg, #ededeb 1px, transparent 1px),
            #f8f8f6;
          background-size: 28px 28px;
          position: relative;
          overflow: hidden;
        }

        .connectorSvg {
          position: absolute;
          inset: 0;
          width: 100%;
          height: 100%;
        }

        .builderNode {
          position: absolute;
          width: 190px;
          min-height: 84px;
          border-radius: 18px;
          background: white;
          border: 1px solid #eeeeeb;
          box-shadow: 0 16px 36px rgba(25,25,22,0.08);
          padding: 14px;
          display: flex;
          align-items: center;
          gap: 10px;
          z-index: 2;
        }

        .builderNode.sensitive {
          border-color: rgba(255, 84, 56, 0.3);
        }

        .nodeIcon {
          width: 34px;
          height: 34px;
          border-radius: 12px;
          display: grid;
          place-items: center;
          background: linear-gradient(135deg, #ff8a55, #ff3f22);
          color: white;
          flex: 0 0 auto;
        }

        .builderNode strong {
          display: block;
          font-size: 13px;
          letter-spacing: -0.03em;
        }

        .builderNode span {
          display: block;
          margin-top: 4px;
          color: #777771;
          font-size: 11px;
          font-weight: 700;
        }

        .contractCards {
          margin: 0 18px 16px;
          display: grid;
          grid-template-columns: 1fr;
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
          max-width: 180px;
          letter-spacing: -0.03em;
        }

        .ruleList {
          margin: 0 18px 18px;
          display: grid;
          gap: 10px;
        }

        .ruleList div {
          display: flex;
          align-items: center;
          gap: 10px;
          background: #f7f7f5;
          border-radius: 14px;
          padding: 12px;
          color: #44443f;
          font-size: 12px;
          font-weight: 800;
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

        .tableTools select {
          height: 42px;
          border: 1px solid #eeeeeb;
          background: white;
          border-radius: 14px;
          padding: 0 12px;
          font-weight: 800;
          outline: 0;
        }

        .templateGrid {
          padding: 0 18px 18px;
          display: grid;
          grid-template-columns: repeat(4, minmax(220px, 1fr));
          gap: 12px;
        }

        .templateCard {
          border: 1px solid #eeeeeb;
          background: #ffffff;
          border-radius: 20px;
          padding: 16px;
          cursor: pointer;
          transition: 0.2s ease;
        }

        .templateCard:hover,
        .templateCard.selected {
          transform: translateY(-2px);
          box-shadow: 0 16px 40px rgba(25,25,22,0.08);
          border-color: rgba(255,84,56,0.35);
        }

        .templateCard.locked {
          opacity: 0.72;
        }

        .templateTop {
          display: flex;
          justify-content: space-between;
          align-items: center;
        }

        .templateIcon {
          width: 34px;
          height: 34px;
          border-radius: 12px;
          background: linear-gradient(135deg, #ff8a55, #ff3f22);
          color: white;
          display: grid;
          place-items: center;
        }

        .templateCard h3 {
          margin: 18px 0 8px;
          letter-spacing: -0.04em;
        }

        .templateCard p {
          min-height: 58px;
          margin: 0;
          color: #777771;
          font-size: 13px;
          line-height: 1.45;
        }

        .templateMeta {
          display: flex;
          gap: 6px;
          flex-wrap: wrap;
          margin: 14px 0;
        }

        .templateMeta span {
          background: #f3f3f1;
          border-radius: 999px;
          padding: 6px 9px;
          color: #55554f;
          font-size: 11px;
          font-weight: 900;
          text-transform: capitalize;
        }

        .templateBtn {
          width: 100%;
          height: 38px;
          background: #22221f;
          color: white;
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
          font-weight: 800;
        }

        td {
          color: #30302c;
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
          min-width: 260px;
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

        .statusPill {
          display: inline-flex;
          align-items: center;
          gap: 6px;
          white-space: nowrap;
          font-weight: 800;
          text-transform: capitalize;
          font-size: 12px;
        }

        .statusPill span {
          width: 7px;
          height: 7px;
          border-radius: 50%;
          background: currentColor;
        }

        .status-active,
        .status-completed {
          color: #30a46c;
        }

        .status-paused,
        .status-draft,
        .status-queued,
        .status-running,
        .status-waiting_approval {
          color: #a57900;
        }

        .status-archived,
        .status-failed,
        .status-cancelled {
          color: #d93025;
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

        .contractMini {
          display: flex;
          gap: 6px;
          color: #ff5438;
        }

        .approveBtn {
          height: 34px;
          padding: 0 13px;
          font-size: 12px;
        }

        .emptyBuilder,
        .stateBox {
          min-height: 260px;
          display: grid;
          place-items: center;
          align-content: center;
          text-align: center;
          gap: 10px;
          color: #777771;
          padding: 28px;
        }

        .stateBox {
          min-height: 520px;
        }

        .emptyBuilder strong,
        .stateBox strong {
          color: #22221f;
          font-size: 18px;
        }

        .emptyBuilder p,
        .stateBox p {
          margin: 0;
        }

        .emptyNote {
          margin: 0;
          padding: 20px 18px;
          color: #8a8a83;
          font-size: 13px;
          line-height: 1.6;
          text-align: center;
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
          .builderGrid {
            grid-template-columns: 1fr;
          }

          .templateGrid {
            grid-template-columns: repeat(2, minmax(220px, 1fr));
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

          .topActions,
          .heroActions {
            justify-content: space-between;
          }

          .profilePill {
            min-width: 0;
            flex: 1;
          }

          .metricGrid,
          .templateGrid {
            grid-template-columns: 1fr;
          }

          .heroLine h1 {
            font-size: 34px;
          }
        }

        @media (max-width: 560px) {
          .topActions,
          .heroActions {
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

          .tenantBadge,
          .createBtn {
            width: 100%;
            text-align: left;
          }
        }
      `}</style>
    </div>
  );
}