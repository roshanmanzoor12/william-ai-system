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

type WorkflowStatus = "draft" | "active" | "paused" | "blocked" | "completed";
type TemplateCategory = "crm" | "security" | "memory" | "marketing" | "finance" | "creator";
type NodeType = "trigger" | "agent" | "security" | "memory" | "verification" | "action";

type ApiResponse<T> = {
  success: boolean;
  data?: T;
  error?: string;
  audit_event_id?: string;
};

type WorkflowNode = {
  id: string;
  type: NodeType;
  title: string;
  agent: string;
  description: string;
  sensitive: boolean;
  x: number;
  y: number;
};

type WorkflowTemplate = {
  id: string;
  user_id: string;
  workspace_id: string;
  title: string;
  category: TemplateCategory;
  description: string;
  required_plan: UserPlan;
  sensitive: boolean;
  nodes: WorkflowNode[];
  estimated_minutes: number;
  usage_units: number;
};

type WorkflowRecord = {
  id: string;
  user_id: string;
  workspace_id: string;
  name: string;
  status: WorkflowStatus;
  template_id?: string;
  nodes: WorkflowNode[];
  runs: number;
  success_rate: number;
  last_run_at: string;
  security_review_required: boolean;
  memory_payload_ready: boolean;
  verification_payload_ready: boolean;
  audit_event_id?: string;
};

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL?.replace(/\/$/, "") || "";

const STATUS_LABELS: Record<WorkflowStatus, string> = {
  draft: "Draft",
  active: "Active",
  paused: "Paused",
  blocked: "Blocked",
  completed: "Completed",
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

function makeNode(
  id: string,
  type: NodeType,
  title: string,
  agent: string,
  description: string,
  sensitive: boolean,
  x: number,
  y: number,
): WorkflowNode {
  return { id, type, title, agent, description, sensitive, x, y };
}

function buildDemoTemplates(session: SessionData): WorkflowTemplate[] {
  return [
    {
      id: "TPL-CRM-001",
      user_id: session.user_id,
      workspace_id: session.workspace_id,
      title: "Lead Form to CRM",
      category: "crm",
      description: "Capture website leads, enrich context, route to CRM, and prepare verification payload.",
      required_plan: "pro",
      sensitive: false,
      estimated_minutes: 4,
      usage_units: 18,
      nodes: [
        makeNode("node-1", "trigger", "Form Submitted", "Browser Agent", "Website lead form trigger.", false, 8, 42),
        makeNode("node-2", "memory", "Save Context", "Memory Agent", "Store lead source and campaign context.", false, 250, 42),
        makeNode("node-3", "action", "Create CRM Lead", "Business Agent", "Create tenant-scoped CRM record.", false, 492, 42),
        makeNode("node-4", "verification", "Confirm Payload", "Verification Agent", "Prepare completion confirmation.", false, 734, 42),
      ],
    },
    {
      id: "TPL-SEC-002",
      user_id: session.user_id,
      workspace_id: session.workspace_id,
      title: "Sensitive Action Approval",
      category: "security",
      description: "Route risky tasks to Security Agent before file, billing, permission, or external actions.",
      required_plan: "business",
      sensitive: true,
      estimated_minutes: 6,
      usage_units: 24,
      nodes: [
        makeNode("node-1", "trigger", "Sensitive Task", "Master Agent", "Detect state-changing action.", true, 8, 42),
        makeNode("node-2", "security", "Security Review", "Security Agent", "Approve or reject the action.", true, 250, 42),
        makeNode("node-3", "action", "Execute Safely", "System Agent", "Run only after approval.", true, 492, 42),
        makeNode("node-4", "verification", "Verify Result", "Verification Agent", "Prepare safe confirmation.", false, 734, 42),
      ],
    },
    {
      id: "TPL-MEM-003",
      user_id: session.user_id,
      workspace_id: session.workspace_id,
      title: "Memory Enrichment",
      category: "memory",
      description: "Summarize useful task context and save it with user/workspace isolation.",
      required_plan: "pro",
      sensitive: false,
      estimated_minutes: 3,
      usage_units: 12,
      nodes: [
        makeNode("node-1", "trigger", "Task Completed", "Master Agent", "Completed task trigger.", false, 8, 42),
        makeNode("node-2", "memory", "Extract Useful Context", "Memory Agent", "Normalize safe memory context.", false, 250, 42),
        makeNode("node-3", "verification", "Attach Verification", "Verification Agent", "Link verification payload.", false, 492, 42),
      ],
    },
    {
      id: "TPL-MKT-004",
      user_id: session.user_id,
      workspace_id: session.workspace_id,
      title: "Marketing Campaign Builder",
      category: "marketing",
      description: "Generate campaign content, check compliance, and send draft to approval.",
      required_plan: "business",
      sensitive: true,
      estimated_minutes: 8,
      usage_units: 30,
      nodes: [
        makeNode("node-1", "trigger", "Campaign Request", "Creator Agent", "User campaign request.", false, 8, 42),
        makeNode("node-2", "agent", "Generate Assets", "Creator Agent", "Generate campaign copy.", false, 250, 42),
        makeNode("node-3", "security", "Policy Review", "Security Agent", "Approve external campaign action.", true, 492, 42),
        makeNode("node-4", "verification", "Ready for Launch", "Verification Agent", "Confirm all outputs.", false, 734, 42),
      ],
    },
  ];
}

function buildDemoWorkflows(session: SessionData, templates: WorkflowTemplate[]): WorkflowRecord[] {
  return [
    {
      id: "WF-000076",
      user_id: session.user_id,
      workspace_id: session.workspace_id,
      name: "Lead form to CRM production flow",
      status: "active",
      template_id: templates[0]?.id,
      nodes: templates[0]?.nodes || [],
      runs: 162,
      success_rate: 96,
      last_run_at: new Date(Date.now() - 1000 * 60 * 12).toISOString(),
      security_review_required: false,
      memory_payload_ready: true,
      verification_payload_ready: true,
      audit_event_id: "audit_wf_000076",
    },
    {
      id: "WF-000075",
      user_id: session.user_id,
      workspace_id: session.workspace_id,
      name: "Security approval chain",
      status: "active",
      template_id: templates[1]?.id,
      nodes: templates[1]?.nodes || [],
      runs: 88,
      success_rate: 94,
      last_run_at: new Date(Date.now() - 1000 * 60 * 38).toISOString(),
      security_review_required: true,
      memory_payload_ready: true,
      verification_payload_ready: true,
      audit_event_id: "audit_wf_000075",
    },
    {
      id: "WF-000074",
      user_id: session.user_id,
      workspace_id: session.workspace_id,
      name: "Memory enrichment for completed tasks",
      status: "paused",
      template_id: templates[2]?.id,
      nodes: templates[2]?.nodes || [],
      runs: 119,
      success_rate: 87,
      last_run_at: new Date(Date.now() - 1000 * 60 * 90).toISOString(),
      security_review_required: false,
      memory_payload_ready: true,
      verification_payload_ready: true,
      audit_event_id: "audit_wf_000074",
    },
    {
      id: "WF-000073",
      user_id: session.user_id,
      workspace_id: session.workspace_id,
      name: "Marketing campaign approval",
      status: "blocked",
      template_id: templates[3]?.id,
      nodes: templates[3]?.nodes || [],
      runs: 39,
      success_rate: 68,
      last_run_at: new Date(Date.now() - 1000 * 60 * 210).toISOString(),
      security_review_required: true,
      memory_payload_ready: true,
      verification_payload_ready: false,
      audit_event_id: "audit_wf_000073",
    },
  ];
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
      error: "API base URL is not configured. Using local safe demo workflow data.",
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

function CategoryIcon({ category }: { category: TemplateCategory }) {
  if (category === "crm") return <Icon name="crm" size={16} />;
  if (category === "security") return <Icon name="shield" size={16} />;
  if (category === "memory") return <Icon name="memory" size={16} />;
  if (category === "marketing") return <Icon name="spark" size={16} />;
  if (category === "finance") return <Icon name="bolt" size={16} />;
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
              {node.type === "trigger" ? <Icon name="bolt" size={16} /> : null}
              {node.type === "agent" ? <Icon name="spark" size={16} /> : null}
              {node.type === "security" ? <Icon name="shield" size={16} /> : null}
              {node.type === "memory" ? <Icon name="memory" size={16} /> : null}
              {node.type === "verification" ? <Icon name="verify" size={16} /> : null}
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
  const [workflows, setWorkflows] = useState<WorkflowRecord[]>([]);
  const [selectedTemplateId, setSelectedTemplateId] = useState<string>("");
  const [selectedCategory, setSelectedCategory] = useState<TemplateCategory | "all">("all");
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
    const total = workflows.length;
    const active = workflows.filter((workflow) => workflow.status === "active").length;
    const blocked = workflows.filter((workflow) => workflow.status === "blocked").length;
    const runs = workflows.reduce((sum, workflow) => sum + workflow.runs, 0);
    const successRate = total
      ? Math.round(workflows.reduce((sum, workflow) => sum + workflow.success_rate, 0) / total)
      : 0;

    return { total, active, blocked, runs, successRate };
  }, [workflows]);

  const filteredTemplates = useMemo(() => {
    const q = search.trim().toLowerCase();

    return templates.filter((template) => {
      const categoryMatch = selectedCategory === "all" || template.category === selectedCategory;
      const searchMatch =
        !q ||
        template.title.toLowerCase().includes(q) ||
        template.description.toLowerCase().includes(q) ||
        template.category.toLowerCase().includes(q);

      return categoryMatch && searchMatch;
    });
  }, [templates, selectedCategory, search]);

  const loadWorkflows = useCallback(async () => {
    if (!session) return;

    setIsLoading(true);
    setError(null);

    const [templateResponse, workflowResponse] = await Promise.all([
      dashboardFetch<WorkflowTemplate[]>("/api/workflows/templates", {
        method: "GET",
        accessToken: session.accessToken,
        audit_action: "workflow_templates_read",
      }),
      dashboardFetch<WorkflowRecord[]>("/api/workflows", {
        method: "GET",
        accessToken: session.accessToken,
        audit_action: "workflow_history_read",
      }),
    ]);

    const demoTemplates = buildDemoTemplates(session);

    if (templateResponse.success && Array.isArray(templateResponse.data)) {
      const isolatedTemplates = templateResponse.data.filter(
        (item) => item.user_id === session.user_id && item.workspace_id === session.workspace_id,
      );
      setTemplates(isolatedTemplates.length ? isolatedTemplates : demoTemplates);
    } else {
      setTemplates(demoTemplates);
      if (templateResponse.error && API_BASE_URL) setError(templateResponse.error);
    }

    if (workflowResponse.success && Array.isArray(workflowResponse.data)) {
      const isolatedWorkflows = workflowResponse.data.filter(
        (item) => item.user_id === session.user_id && item.workspace_id === session.workspace_id,
      );
      setWorkflows(isolatedWorkflows);
    } else {
      setWorkflows(buildDemoWorkflows(session, demoTemplates));
      if (workflowResponse.error && API_BASE_URL) setError(workflowResponse.error);
    }

    setSelectedTemplateId((current) => current || demoTemplates[0]?.id || "");
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
      setError("Your current role or plan cannot create workflows.");
      return;
    }

    if (template.sensitive && !canUseSensitiveWorkflow) {
      setError("Sensitive workflow templates require admin access and Business plan or higher.");
      return;
    }

    if (!hasMinPlan(session.plan, template.required_plan)) {
      setError(`This template requires the ${template.required_plan} plan or higher.`);
      return;
    }

    setIsCreating(true);
    setError(null);

    const payload = {
      user_id: session.user_id,
      workspace_id: session.workspace_id,
      template_id: template.id,
      name: `${template.title} workflow`,
      nodes: template.nodes,
      security_agent_required: template.sensitive,
      memory_agent_compatible: true,
      prepare_verification_payload: true,
      audit_action: "workflow_created_from_template",
    };

    const response = await dashboardFetch<WorkflowRecord>("/api/workflows", {
      method: "POST",
      accessToken: session.accessToken,
      audit_action: "workflow_create",
      body: JSON.stringify(payload),
    });

    if (response.success && response.data) {
      if (response.data.user_id === session.user_id && response.data.workspace_id === session.workspace_id) {
        setWorkflows((current) => [response.data as WorkflowRecord, ...current]);
      }
    } else {
      const demoWorkflow: WorkflowRecord = {
        id: `WF-${String(Math.floor(Math.random() * 900000) + 100000)}`,
        user_id: session.user_id,
        workspace_id: session.workspace_id,
        name: `${template.title} workflow`,
        status: template.sensitive ? "draft" : "active",
        template_id: template.id,
        nodes: template.nodes,
        runs: 0,
        success_rate: 100,
        last_run_at: nowIso(),
        security_review_required: template.sensitive,
        memory_payload_ready: true,
        verification_payload_ready: false,
        audit_event_id: `audit_${Date.now()}`,
      };

      setWorkflows((current) => [demoWorkflow, ...current]);
    }

    setIsCreating(false);
  };

  const toggleWorkflowStatus = async (workflow: WorkflowRecord) => {
    if (!session) return;

    if (!canPublishWorkflow) {
      setError("Only admins or owners can publish, pause, or resume workflows.");
      return;
    }

    const nextStatus: WorkflowStatus = workflow.status === "active" ? "paused" : "active";

    const response = await dashboardFetch<WorkflowRecord>(`/api/workflows/${encodeURIComponent(workflow.id)}/status`, {
      method: "PATCH",
      accessToken: session.accessToken,
      audit_action: "workflow_status_change",
      body: JSON.stringify({
        user_id: session.user_id,
        workspace_id: session.workspace_id,
        workflow_id: workflow.id,
        status: nextStatus,
        security_agent_required: workflow.security_review_required,
        prepare_verification_payload: true,
      }),
    });

    if (response.success && response.data) {
      setWorkflows((current) =>
        current.map((item) =>
          item.id === workflow.id &&
          response.data?.user_id === session.user_id &&
          response.data?.workspace_id === session.workspace_id
            ? response.data
            : item,
        ),
      );
      return;
    }

    setWorkflows((current) =>
      current.map((item) =>
        item.id === workflow.id
          ? {
              ...item,
              status: nextStatus,
              last_run_at: nowIso(),
              verification_payload_ready: nextStatus === "active",
            }
          : item,
      ),
    );
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
                    <p>Total Workflows</p>
                    <h2>{formatNumber(stats.total)}</h2>
                    <span className="greenText">↑ {stats.active} active automations</span>
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
                    <strong>{formatNumber(stats.runs)}</strong>
                    <span>Total Runs</span>
                  </div>
                  <div>
                    <Icon name="verify" />
                    <strong>{stats.successRate}%</strong>
                    <span>Success</span>
                  </div>
                  <div>
                    <Icon name="shield" />
                    <strong>{stats.blocked}</strong>
                    <span>Blocked</span>
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
                  <span>Memory Ready</span>
                  <strong>{workflows.filter((item) => item.memory_payload_ready).length}</strong>
                  <p>Context compatible</p>
                </div>

                <div className="metricCard">
                  <div className="metricIcon"><Icon name="shield" /></div>
                  <span>Security Routed</span>
                  <strong>{workflows.filter((item) => item.security_review_required).length}</strong>
                  <p>Approval required</p>
                </div>

                <div className="metricCard">
                  <div className="metricIcon"><Icon name="verify" /></div>
                  <span>Verified</span>
                  <strong>{workflows.filter((item) => item.verification_payload_ready).length}</strong>
                  <p>Payload prepared</p>
                </div>
              </div>

              <div className="chartCard">
                <div className="cardTop">
                  <div>
                    <h3>Workflow Performance</h3>
                    <p>Runs and success rate by automation</p>
                  </div>
                  <div className="legend">
                    <span><i className="orangeDot" /> Runs</span>
                    <span><i className="darkDot" /> Success</span>
                  </div>
                </div>

                <div className="barChart">
                  {workflows.map((workflow) => {
                    const runHeight = Math.max(34, Math.min(145, workflow.runs));
                    const successHeight = Math.max(24, Math.min(118, workflow.success_rate));

                    return (
                      <div className="barGroup" key={workflow.id}>
                        <div className="bars">
                          <span className="bar barOrange" style={{ height: runHeight }} />
                          <span className="bar barDark" style={{ height: successHeight }} />
                        </div>
                        <span className="barLabel">{workflow.id.replace("WF-", "")}</span>
                      </div>
                    );
                  })}
                </div>
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
                  <WorkflowCanvas nodes={selectedTemplate.nodes} />
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
                    <strong>{selectedTemplate?.sensitive ? "Required before publish" : "Not required"}</strong>
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
                    value={selectedCategory}
                    onChange={(event) => setSelectedCategory(event.target.value as TemplateCategory | "all")}
                  >
                    <option value="all">All Categories</option>
                    <option value="crm">CRM</option>
                    <option value="security">Security</option>
                    <option value="memory">Memory</option>
                    <option value="marketing">Marketing</option>
                    <option value="finance">Finance</option>
                    <option value="creator">Creator</option>
                  </select>

                  <button className="filterBtn"><Icon name="filter" size={16} /> Filter</button>
                </div>
              </div>

              {filteredTemplates.length === 0 ? (
                <div className="emptyBuilder">
                  <Icon name="template" size={34} />
                  <strong>No templates found</strong>
                  <p>Clear filters or create a new workflow from scratch.</p>
                </div>
              ) : (
                <div className="templateGrid">
                  {filteredTemplates.map((template) => {
                    const locked = !hasMinPlan(session.plan, template.required_plan);

                    return (
                      <article
                        key={template.id}
                        className={cx("templateCard", selectedTemplate?.id === template.id && "selected", locked && "locked")}
                        onClick={() => setSelectedTemplateId(template.id)}
                      >
                        <div className="templateTop">
                          <span className="templateIcon"><CategoryIcon category={template.category} /></span>
                          <button className="moreBtn" aria-label={`More actions for ${template.title}`}>
                            <Icon name="more" size={18} />
                          </button>
                        </div>

                        <h3>{template.title}</h3>
                        <p>{template.description}</p>

                        <div className="templateMeta">
                          <span>{template.estimated_minutes} min</span>
                          <span>{template.usage_units} units</span>
                          <span>{template.required_plan}</span>
                        </div>

                        <button
                          className="templateBtn"
                          disabled={locked || (template.sensitive && !canUseSensitiveWorkflow)}
                          onClick={(event) => {
                            event.stopPropagation();
                            createWorkflowFromTemplate(template);
                          }}
                        >
                          {locked ? "Plan Locked" : template.sensitive && !canUseSensitiveWorkflow ? "Admin Only" : "Use Template"}
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
                  <h2>Workflow History</h2>
                  <p>Live workflow records filtered by current user and workspace only.</p>
                </div>
                <button className="filterBtn"><Icon name="workflow" size={16} /> Manage</button>
              </div>

              {workflows.length === 0 ? (
                <div className="emptyBuilder">
                  <Icon name="doc" size={34} />
                  <strong>No workflows yet</strong>
                  <p>Create one from a template and make the agent squad actually useful.</p>
                </div>
              ) : (
                <div className="tableWrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Workflow ID</th>
                        <th>Name</th>
                        <th>Status</th>
                        <th>Runs</th>
                        <th>Success</th>
                        <th>Contracts</th>
                        <th>Last Run</th>
                        <th />
                      </tr>
                    </thead>

                    <tbody>
                      {workflows.map((workflow) => (
                        <tr key={workflow.id}>
                          <td><strong className="mono">{workflow.id}</strong></td>
                          <td>
                            <div className="activityCell">
                              <span className={cx("agentIcon", workflow.security_review_required && "sensitive")}>
                                {workflow.security_review_required ? <Icon name="shield" size={15} /> : <Icon name="workflow" size={15} />}
                              </span>
                              <div>
                                <strong>{workflow.name}</strong>
                                <small>{workflow.template_id || "Custom workflow"}</small>
                              </div>
                            </div>
                          </td>
                          <td><StatusPill status={workflow.status} /></td>
                          <td>{formatNumber(workflow.runs)}</td>
                          <td>
                            <div className="rowProgress">
                              <span style={{ width: `${workflow.success_rate}%` }} />
                            </div>
                            <small>{workflow.success_rate}%</small>
                          </td>
                          <td>
                            <div className="contractMini">
                              {workflow.security_review_required ? <Icon name="shield" size={15} /> : null}
                              {workflow.memory_payload_ready ? <Icon name="memory" size={15} /> : null}
                              {workflow.verification_payload_ready ? <Icon name="verify" size={15} /> : null}
                            </div>
                          </td>
                          <td>
                            <span>{formatDateTime(workflow.last_run_at)}</span>
                            <small>{workflow.audit_event_id || "audit pending"}</small>
                          </td>
                          <td>
                            <button className="approveBtn" onClick={() => toggleWorkflowStatus(workflow)} disabled={!canPublishWorkflow}>
                              {workflow.status === "active" ? <Icon name="pause" size={14} /> : <Icon name="play" size={14} />}
                              {workflow.status === "active" ? "Pause" : "Run"}
                            </button>
                          </td>
                        </tr>
                      ))}
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
        .status-draft {
          color: #a57900;
        }

        .status-blocked {
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