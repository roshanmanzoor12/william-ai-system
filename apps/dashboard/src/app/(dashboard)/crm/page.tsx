"use client";

/**
 * apps/dashboard/src/app/crm/page.tsx
 *
 * William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
 * Dashboard Prompt Bible
 *
 * Purpose:
 * - CRM dashboard for leads, clients, and sales pipeline.
 * - Tenant-safe frontend page using user_id and workspace_id on every request.
 * - Supports future Master Agent, Business Agent, Memory Agent, Security Agent,
 *   Verification Agent, audit logging, workflow automation, and billing limits.
 */

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { SessionData, hasMinPlan, hasMinRole, readSession } from "@/lib/auth";

type LeadStatus = "new" | "qualified" | "proposal" | "won" | "lost";
type LeadSource = "Website" | "Google Ads" | "Call Agent" | "Workflow" | "Referral";
type ClientHealth = "excellent" | "good" | "watch" | "risk";

type ApiResponse<T> = {
  success: boolean;
  data?: T;
  error?: string;
  audit_event_id?: string;
};

type LeadRecord = {
  id: string;
  user_id: string;
  workspace_id: string;
  name: string;
  company: string;
  email: string;
  phone: string;
  source: LeadSource;
  status: LeadStatus;
  value: number;
  score: number;
  assigned_agent: string;
  sensitive: boolean;
  memory_payload_ready: boolean;
  verification_payload_ready: boolean;
  security_review_required: boolean;
  created_at: string;
  updated_at: string;
  audit_event_id?: string;
};

type ClientRecord = {
  id: string;
  user_id: string;
  workspace_id: string;
  name: string;
  company: string;
  plan: string;
  revenue: number;
  health: ClientHealth;
  active_workflows: number;
  open_tasks: number;
  last_contact_at: string;
};

type PipelineStage = {
  id: LeadStatus;
  title: string;
  value: number;
  count: number;
};

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL?.replace(/\/$/, "") || "";

const STATUS_LABELS: Record<LeadStatus, string> = {
  new: "New",
  qualified: "Qualified",
  proposal: "Proposal",
  won: "Won",
  lost: "Lost",
};

const HEALTH_LABELS: Record<ClientHealth, string> = {
  excellent: "Excellent",
  good: "Good",
  watch: "Watch",
  risk: "Risk",
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
    return "A safe application error occurred. Please try again or contact workspace admin.";
  }

  return message;
}

function formatMoney(value: number): string {
  return new Intl.NumberFormat("en", {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: 0,
  }).format(value);
}

function formatNumber(value: number): string {
  return new Intl.NumberFormat("en").format(value);
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
      error: "API base URL is not configured. Using local safe demo CRM data.",
    };
  }

  const headers = new Headers(options.headers);
  headers.set("Content-Type", "application/json");
  headers.set("Authorization", `Bearer ${options.accessToken}`);
  headers.set("X-Audit-Action", options.audit_action || "crm_dashboard_read");

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
    | "crm"
    | "lead"
    | "client"
    | "pipeline"
    | "money"
    | "shield"
    | "memory"
    | "verify"
    | "plus"
    | "filter"
    | "more"
    | "spark"
    | "phone"
    | "mail2";
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
          <rect width="32" height="32" rx="12" fill="url(#crmLogoGradient)" />
          <path d="M10 21.5V16h5.7c1.1 0 2-.9 2-2v-1.8H12V8h10v6.1c0 3.3-2.6 5.9-5.9 5.9h-1.3v1.5H10Z" fill="white" />
          <path d="M19.3 24v-5.7H24V24h-4.7Z" fill="white" />
          <defs>
            <linearGradient id="crmLogoGradient" x1="4" x2="28" y1="4" y2="28">
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
    case "mail2":
      return <svg {...common}><path d="M4 6.5h16v11H4v-11Z" stroke={stroke} strokeWidth="1.7" /><path d="m4 7 8 6 8-6" stroke={stroke} strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" /></svg>;
    case "doc":
      return <svg {...common}><path d="M7 3.8h7l3 3V20H7V3.8Z" stroke={stroke} strokeWidth="1.7" strokeLinejoin="round" /><path d="M14 4v3h3M9.5 11h5M9.5 15h5" stroke={stroke} strokeWidth="1.5" strokeLinecap="round" /></svg>;
    case "users":
    case "client":
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
    case "crm":
      return <svg {...common}><path d="M5 5h14v14H5V5Z" stroke={stroke} strokeWidth="1.7" /><path d="M8 9h8M8 13h5M8 17h8" stroke={stroke} strokeWidth="1.6" strokeLinecap="round" /></svg>;
    case "lead":
      return <svg {...common}><circle cx="9" cy="8" r="3" stroke={stroke} strokeWidth="1.7" /><path d="M3.8 19c.8-3 2.7-5 5.2-5s4.4 2 5.2 5" stroke={stroke} strokeWidth="1.7" strokeLinecap="round" /><path d="M16 8h5M18.5 5.5v5" stroke={stroke} strokeWidth="1.7" strokeLinecap="round" /></svg>;
    case "pipeline":
      return <svg {...common}><path d="M4 7h5v5H4V7ZM15 4h5v5h-5V4ZM15 15h5v5h-5v-5ZM9 9.5h3a3 3 0 0 0 3-3M9 9.5h3a3 3 0 0 1 3 3v5" stroke={stroke} strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" /></svg>;
    case "money":
      return <svg {...common}><path d="M4 7h16v10H4V7Z" stroke={stroke} strokeWidth="1.7" /><circle cx="12" cy="12" r="2.5" stroke={stroke} strokeWidth="1.7" /><path d="M7 10v4M17 10v4" stroke={stroke} strokeWidth="1.7" strokeLinecap="round" /></svg>;
    case "shield":
      return <svg {...common}><path d="M12 3 19 6v5.5c0 4.5-2.8 7.8-7 9.5-4.2-1.7-7-5-7-9.5V6l7-3Z" stroke={stroke} strokeWidth="1.7" strokeLinejoin="round" /><path d="m9.5 12 1.8 1.8 3.7-4" stroke={stroke} strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" /></svg>;
    case "memory":
      return <svg {...common}><rect x="5" y="5" width="14" height="14" rx="3" stroke={stroke} strokeWidth="1.7" /><path d="M9 2.5v3M15 2.5v3M9 18.5v3M15 18.5v3M2.5 9h3M2.5 15h3M18.5 9h3M18.5 15h3" stroke={stroke} strokeWidth="1.5" strokeLinecap="round" /></svg>;
    case "verify":
      return <svg {...common}><circle cx="12" cy="12" r="9" stroke={stroke} strokeWidth="1.7" /><path d="m8.5 12.3 2.2 2.2 4.9-5.2" stroke={stroke} strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round" /></svg>;
    case "plus":
      return <svg {...common}><path d="M12 5v14M5 12h14" stroke={stroke} strokeWidth="1.9" strokeLinecap="round" /></svg>;
    case "filter":
      return <svg {...common}><path d="M4 6h16M7 12h10M10 18h4" stroke={stroke} strokeWidth="1.8" strokeLinecap="round" /></svg>;
    case "more":
      return <svg {...common}><path d="M6 12h.01M12 12h.01M18 12h.01" stroke={stroke} strokeWidth="3" strokeLinecap="round" /></svg>;
    case "spark":
      return <svg {...common}><path d="M12 2.5 13.7 9l6.3 3-6.3 3L12 21.5 10.3 15 4 12l6.3-3L12 2.5Z" stroke={stroke} strokeWidth="1.5" strokeLinejoin="round" /></svg>;
    case "phone":
      return <svg {...common}><path d="M8 5 6 7c-.8.8-.8 2 0 3.5 1.6 3 4.5 5.9 7.5 7.5 1.5.8 2.7.8 3.5 0l2-2-3.2-3.2-1.8 1.2c-1.4-.8-2.7-2.1-3.5-3.5l1.2-1.8L8 5Z" stroke={stroke} strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" /></svg>;
    default:
      return null;
  }
}

function StatusPill({ status }: { status: LeadStatus }) {
  return (
    <span className={cx("statusPill", `status-${status}`)}>
      <span />
      {STATUS_LABELS[status]}
    </span>
  );
}

function HealthPill({ health }: { health: ClientHealth }) {
  return (
    <span className={cx("healthPill", `health-${health}`)}>
      <span />
      {HEALTH_LABELS[health]}
    </span>
  );
}

export default function Page() {
  const router = useRouter();
  const [session, setSession] = useState<SessionData | null>(null);
  const [checkingSession, setCheckingSession] = useState(true);
  const [leads, setLeads] = useState<LeadRecord[]>([]);
  const [clients, setClients] = useState<ClientRecord[]>([]);
  const [selectedStatus, setSelectedStatus] = useState<LeadStatus | "all">("all");
  const [search, setSearch] = useState("");
  const [isLoading, setIsLoading] = useState(true);
  const [isCreatingLead, setIsCreatingLead] = useState(false);
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

  const canCreateLead = Boolean(session) && hasMinRole(session!.role, "manager") && hasMinPlan(session!.plan, "pro");
  const canExportCrm = Boolean(session) && hasMinRole(session!.role, "admin") && hasMinPlan(session!.plan, "business");
  const canViewSensitiveLead = Boolean(session) && hasMinRole(session!.role, "admin");

  const stats = useMemo(() => {
    const totalLeads = leads.length;
    const pipelineValue = leads.reduce((sum, lead) => sum + lead.value, 0);
    const wonValue = leads.filter((lead) => lead.status === "won").reduce((sum, lead) => sum + lead.value, 0);
    const qualified = leads.filter((lead) => lead.status === "qualified" || lead.status === "proposal").length;
    const avgScore = totalLeads ? Math.round(leads.reduce((sum, lead) => sum + lead.score, 0) / totalLeads) : 0;
    const clientRevenue = clients.reduce((sum, client) => sum + client.revenue, 0);

    return { totalLeads, pipelineValue, wonValue, qualified, avgScore, clientRevenue };
  }, [leads, clients]);

  const pipelineStages: PipelineStage[] = useMemo(() => {
    return (["new", "qualified", "proposal", "won", "lost"] as LeadStatus[]).map((status) => {
      const stageLeads = leads.filter((lead) => lead.status === status);

      return {
        id: status,
        title: STATUS_LABELS[status],
        value: stageLeads.reduce((sum, lead) => sum + lead.value, 0),
        count: stageLeads.length,
      };
    });
  }, [leads]);

  const filteredLeads = useMemo(() => {
    const q = search.trim().toLowerCase();

    return leads.filter((lead) => {
      const statusMatch = selectedStatus === "all" || lead.status === selectedStatus;
      const searchMatch =
        !q ||
        lead.id.toLowerCase().includes(q) ||
        lead.name.toLowerCase().includes(q) ||
        lead.company.toLowerCase().includes(q) ||
        lead.source.toLowerCase().includes(q) ||
        lead.assigned_agent.toLowerCase().includes(q);

      return statusMatch && searchMatch;
    });
  }, [leads, selectedStatus, search]);

  const loadCrm = useCallback(async () => {
    if (!session) return;

    setIsLoading(true);
    setError(null);

    // There is no CRM router anywhere in apps/api/routes/ -- no
    // "/crm/leads", "/crm/clients", or any lead/client concept exists in
    // the backend at all (confirmed by listing the routes directory).
    // These calls will always 404 today; leads/clients stay empty rather
    // than falling back to fabricated demo rows. If a real CRM backend is
    // added later at these same paths, this starts working automatically.
    const [leadResponse, clientResponse] = await Promise.all([
      dashboardFetch<LeadRecord[]>("/crm/leads", {
        method: "GET",
        accessToken: session.accessToken,
        audit_action: "crm_leads_read",
      }),
      dashboardFetch<ClientRecord[]>("/crm/clients", {
        method: "GET",
        accessToken: session.accessToken,
        audit_action: "crm_clients_read",
      }),
    ]);

    if (leadResponse.success && Array.isArray(leadResponse.data)) {
      setLeads(leadResponse.data);
    } else {
      setLeads([]);
    }

    if (clientResponse.success && Array.isArray(clientResponse.data)) {
      setClients(clientResponse.data);
    } else {
      setClients([]);
    }

    if (!leadResponse.success || !clientResponse.success) {
      setError("CRM is not connected to a backend yet -- no CRM API exists in this deployment.");
    }

    setIsLoading(false);
  }, [session]);

  useEffect(() => {
    if (mounted.current) return;
    mounted.current = true;
    void loadCrm();
  }, [loadCrm]);

  const createLead = async () => {
    if (!session) return;

    if (!canCreateLead) {
      setError("Your current role or plan cannot create CRM leads.");
      return;
    }

    setIsCreatingLead(true);
    setError(null);

    const payload = {
      name: "New AI Qualified Lead",
      company: "Digital Promotix Prospect",
      source: "Workflow",
      status: "new",
    };

    // No CRM router exists in the backend (see loadCrm's note above) --
    // this will always fail today. Left wired to the real path rather
    // than faking a created lead, so it starts working the moment a real
    // CRM backend is added, instead of silently lying in the meantime.
    const response = await dashboardFetch<LeadRecord>("/crm/leads", {
      method: "POST",
      accessToken: session.accessToken,
      audit_action: "crm_lead_create",
      body: JSON.stringify(payload),
    });

    if (response.success && response.data) {
      setLeads((current) => [response.data as LeadRecord, ...current]);
    } else {
      setError("CRM is not connected to a backend yet -- no CRM API exists in this deployment.");
    }

    setIsCreatingLead(false);
  };

  const exportCrm = () => {
    if (!session) return;

    if (!canExportCrm) {
      setError("CRM export requires admin access and Business plan or higher.");
      return;
    }

    const safePayload = {
      user_id: session.user_id,
      workspace_id: session.workspace_id,
      exported_at: new Date().toISOString(),
      leads,
      clients,
      audit_action: "crm_export_frontend",
    };

    const blob = new Blob([JSON.stringify(safePayload, null, 2)], {
      type: "application/json",
    });

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `william-crm-${session.workspace_id}.json`;
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
            <h1>CRM, {session.name.split(" ")[0]}</h1>
            <p>Manage leads, clients, pipeline value, memory context, security reviews, and verification-ready sales actions.</p>
          </div>

          <div className="heroActions">
            <div className="tenantBadge">
              <span>{session.role}</span>
              <strong>{session.plan}</strong>
            </div>
            <button className="createBtn" onClick={createLead} disabled={!canCreateLead || isCreatingLead}>
              <Icon name="plus" size={16} />
              {isCreatingLead ? "Creating..." : "Add Lead"}
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
            <strong>Loading CRM...</strong>
            <p>Checking tenant-safe leads, clients, and pipeline records.</p>
          </section>
        ) : (
          <>
            <section className="overviewGrid">
              <div className="balanceCard">
                <div className="cardTop">
                  <div>
                    <p>Pipeline Value</p>
                    <h2>{formatMoney(stats.pipelineValue)}</h2>
                    <span className="greenText">↑ {formatMoney(stats.wonValue)} won value</span>
                  </div>
                  <button className="currencyBtn">USD</button>
                </div>

                <div className="actionRow">
                  <button className="primaryBtn" onClick={createLead} disabled={!canCreateLead || isCreatingLead}>
                    <Icon name="plus" size={16} />
                    Add Lead
                  </button>
                  <button className="softBtn" onClick={exportCrm} disabled={!canExportCrm}>
                    Export
                  </button>
                </div>

                <div className="miniWallets">
                  <div>
                    <Icon name="lead" />
                    <strong>{formatNumber(stats.totalLeads)}</strong>
                    <span>Total Leads</span>
                  </div>
                  <div>
                    <Icon name="pipeline" />
                    <strong>{formatNumber(stats.qualified)}</strong>
                    <span>Qualified</span>
                  </div>
                  <div>
                    <Icon name="spark" />
                    <strong>{stats.avgScore}</strong>
                    <span>Avg Score</span>
                  </div>
                </div>
              </div>

              <div className="metricGrid">
                <div className="metricCard hot">
                  <div className="metricIcon"><Icon name="money" /></div>
                  <span>Client Revenue</span>
                  <strong>{formatMoney(stats.clientRevenue)}</strong>
                  <p>Active client base</p>
                </div>

                <div className="metricCard">
                  <div className="metricIcon"><Icon name="client" /></div>
                  <span>Clients</span>
                  <strong>{clients.length}</strong>
                  <p>Workspace scoped</p>
                </div>

                <div className="metricCard">
                  <div className="metricIcon"><Icon name="memory" /></div>
                  <span>Memory Ready</span>
                  <strong>{leads.filter((lead) => lead.memory_payload_ready).length}</strong>
                  <p>Lead context saved</p>
                </div>

                <div className="metricCard">
                  <div className="metricIcon"><Icon name="shield" /></div>
                  <span>Security Reviews</span>
                  <strong>{leads.filter((lead) => lead.security_review_required).length}</strong>
                  <p>Sensitive actions</p>
                </div>
              </div>

              <div className="chartCard">
                <div className="cardTop">
                  <div>
                    <h3>Pipeline Chart</h3>
                    <p>Lead value by current stage</p>
                  </div>
                  <div className="legend">
                    <span><i className="orangeDot" /> Value</span>
                    <span><i className="darkDot" /> Count</span>
                  </div>
                </div>

                <div className="barChart">
                  {pipelineStages.map((stage) => {
                    const maxValue = Math.max(...pipelineStages.map((item) => item.value), 1);
                    const valueHeight = Math.max(28, Math.round((stage.value / maxValue) * 140));
                    const countHeight = Math.max(22, Math.min(112, stage.count * 28));

                    return (
                      <div className="barGroup" key={stage.id}>
                        <div className="bars">
                          <span className="bar barOrange" style={{ height: valueHeight }} />
                          <span className="bar barDark" style={{ height: countHeight }} />
                        </div>
                        <span className="barLabel">{stage.title}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            </section>

            <section className="pipelineSection">
              <div className="tableHeader">
                <div>
                  <h2>Sales Pipeline</h2>
                  <p>Every card is filtered by current user and workspace only.</p>
                </div>
                <button className="filterBtn"><Icon name="pipeline" size={16} /> Manage</button>
              </div>

              <div className="pipelineGrid">
                {pipelineStages.map((stage) => (
                  <div className="pipelineColumn" key={stage.id}>
                    <div className="pipelineTop">
                      <strong>{stage.title}</strong>
                      <span>{stage.count}</span>
                    </div>
                    <p>{formatMoney(stage.value)}</p>

                    <div className="pipelineCards">
                      {leads
                        .filter((lead) => lead.status === stage.id)
                        .slice(0, 3)
                        .map((lead) => (
                          <article className="pipelineLead" key={lead.id}>
                            <div className="leadTop">
                              <span className={cx("agentIcon", lead.sensitive && "sensitive")}>
                                {lead.sensitive ? <Icon name="shield" size={15} /> : <Icon name="lead" size={15} />}
                              </span>
                              <button className="moreBtn" aria-label={`More actions for ${lead.id}`}>
                                <Icon name="more" size={18} />
                              </button>
                            </div>
                            <strong>{lead.name}</strong>
                            <small>{lead.company}</small>
                            <div className="pipelineMeta">
                              <span>{formatMoney(lead.value)}</span>
                              <b>{lead.score}</b>
                            </div>
                          </article>
                        ))}
                    </div>
                  </div>
                ))}
              </div>
            </section>

            <section className="clientsAndRules">
              <div className="clientsCard">
                <div className="cardTop">
                  <div>
                    <h3>Client Accounts</h3>
                    <p>Revenue, health, workflows, and open tasks</p>
                  </div>
                  <button className="smallSoft">+ Add client</button>
                </div>

                {clients.length === 0 ? (
                  <p className="emptyNote">No CRM backend is connected in this deployment yet.</p>
                ) : (
                <div className="clientGrid">
                  {clients.map((client) => (
                    <article className="clientCard" key={client.id}>
                      <div className="clientHeader">
                        <div className="clientAvatar">{client.name.slice(0, 2).toUpperCase()}</div>
                        <HealthPill health={client.health} />
                      </div>
                      <h3>{client.company}</h3>
                      <p>{client.plan}</p>

                      <div className="clientStats">
                        <div>
                          <span>Revenue</span>
                          <strong>{formatMoney(client.revenue)}</strong>
                        </div>
                        <div>
                          <span>Workflows</span>
                          <strong>{client.active_workflows}</strong>
                        </div>
                        <div>
                          <span>Tasks</span>
                          <strong>{client.open_tasks}</strong>
                        </div>
                      </div>

                      <small>Last contact {formatDateTime(client.last_contact_at)}</small>
                    </article>
                  ))}
                </div>
                )}
              </div>

              <div className="contractCard">
                <div className="cardTop">
                  <h3>CRM Contracts</h3>
                  <button className="smallSoft">Audit On</button>
                </div>

                <div className="contractCards">
                  <div className="contract dark">
                    <span>Memory Agent</span>
                    <strong>Lead context saved per workspace</strong>
                    <small>No cross-client leakage</small>
                  </div>

                  <div className="contract orange">
                    <span>Security Agent</span>
                    <strong>{canViewSensitiveLead ? "Sensitive contact actions routed" : "Admin-only visibility"}</strong>
                    <small>Safe approval gate</small>
                  </div>
                </div>
              </div>
            </section>

            <section className="tableCard">
              <div className="tableHeader">
                <div>
                  <h2>Lead History</h2>
                  <p>Leads, clients, pipeline movements, and agent-prepared CRM context.</p>
                </div>

                <div className="tableTools">
                  <label className="searchBox">
                    <Icon name="search" size={16} />
                    <input
                      value={search}
                      onChange={(event) => setSearch(event.target.value)}
                      placeholder="Search lead, company..."
                    />
                  </label>

                  <select value={selectedStatus} onChange={(event) => setSelectedStatus(event.target.value as LeadStatus | "all")}>
                    <option value="all">All Status</option>
                    <option value="new">New</option>
                    <option value="qualified">Qualified</option>
                    <option value="proposal">Proposal</option>
                    <option value="won">Won</option>
                    <option value="lost">Lost</option>
                  </select>

                  <button className="filterBtn"><Icon name="filter" size={16} /> Filter</button>
                </div>
              </div>

              {filteredLeads.length === 0 ? (
                <div className="emptyBox">
                  <Icon name="lead" size={34} />
                  <strong>{leads.length === 0 ? "CRM not connected" : "No leads match your filters"}</strong>
                  <p>
                    {leads.length === 0
                      ? "There is no CRM backend in this deployment yet -- leads and clients aren't available."
                      : "Clear filters to see your existing leads."}
                  </p>
                </div>
              ) : (
                <div className="tableWrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Lead ID</th>
                        <th>Lead</th>
                        <th>Source</th>
                        <th>Value</th>
                        <th>Score</th>
                        <th>Status</th>
                        <th>Contracts</th>
                        <th>Updated</th>
                        <th />
                      </tr>
                    </thead>

                    <tbody>
                      {filteredLeads.map((lead) => (
                        <tr key={lead.id}>
                          <td><strong className="mono">{lead.id}</strong></td>
                          <td>
                            <div className="activityCell">
                              <span className={cx("agentIcon", lead.sensitive && "sensitive")}>
                                {lead.sensitive ? <Icon name="shield" size={15} /> : <Icon name="lead" size={15} />}
                              </span>
                              <div>
                                <strong>{lead.name}</strong>
                                <small>{lead.company} · {lead.assigned_agent}</small>
                              </div>
                            </div>
                          </td>
                          <td>{lead.source}</td>
                          <td>{formatMoney(lead.value)}</td>
                          <td>
                            <div className="rowProgress">
                              <span style={{ width: `${lead.score}%` }} />
                            </div>
                            <small>{lead.score}/100</small>
                          </td>
                          <td><StatusPill status={lead.status} /></td>
                          <td>
                            <div className="contractMini">
                              {lead.security_review_required ? <Icon name="shield" size={15} /> : null}
                              {lead.memory_payload_ready ? <Icon name="memory" size={15} /> : null}
                              {lead.verification_payload_ready ? <Icon name="verify" size={15} /> : null}
                            </div>
                          </td>
                          <td>
                            <span>{formatDateTime(lead.updated_at)}</span>
                            <small>{lead.audit_event_id || "audit pending"}</small>
                          </td>
                          <td>
                            <div className="rowActions">
                              <button className="roundMini" aria-label={`Call ${lead.name}`}><Icon name="phone" size={15} /></button>
                              <button className="roundMini" aria-label={`Email ${lead.name}`}><Icon name="mail2" size={15} /></button>
                              <button className="moreBtn" aria-label={`More actions for ${lead.id}`}><Icon name="more" size={18} /></button>
                            </div>
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
        .moreBtn,
        .roundMini {
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
        .moreBtn:hover,
        .roundMini:hover {
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
        .softBtn {
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
        .primaryBtn {
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
        .filterBtn:hover {
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
        .pipelineSection,
        .clientsCard,
        .contractCard,
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

        .pipelineSection,
        .tableCard {
          padding: 0;
          overflow: hidden;
          margin-bottom: 16px;
        }

        .tableHeader {
          padding: 18px;
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 16px;
        }

        .pipelineGrid {
          padding: 0 18px 18px;
          display: grid;
          grid-template-columns: repeat(5, minmax(190px, 1fr));
          gap: 12px;
          overflow-x: auto;
        }

        .pipelineColumn {
          background: #f7f7f5;
          border: 1px solid #eeeeeb;
          border-radius: 18px;
          padding: 12px;
          min-width: 190px;
        }

        .pipelineTop {
          display: flex;
          align-items: center;
          justify-content: space-between;
        }

        .pipelineTop strong {
          letter-spacing: -0.03em;
        }

        .pipelineTop span {
          background: white;
          border-radius: 999px;
          padding: 5px 9px;
          color: #777771;
          font-size: 11px;
          font-weight: 900;
        }

        .pipelineColumn > p {
          color: #ff5438;
          font-weight: 900;
          margin: 8px 0 12px;
        }

        .pipelineCards {
          display: grid;
          gap: 10px;
        }

        .pipelineLead {
          background: white;
          border-radius: 16px;
          padding: 12px;
          border: 1px solid #eeeeeb;
        }

        .leadTop {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 12px;
        }

        .pipelineLead strong {
          display: block;
          font-size: 13px;
        }

        .pipelineLead small {
          display: block;
          margin-top: 4px;
          color: #777771;
          font-size: 11px;
        }

        .pipelineMeta {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-top: 12px;
        }

        .pipelineMeta span {
          color: #22221f;
          font-weight: 900;
          font-size: 12px;
        }

        .pipelineMeta b {
          color: #ff5438;
          background: #fff1ec;
          border-radius: 999px;
          padding: 5px 8px;
          font-size: 11px;
        }

        .clientsAndRules {
          display: grid;
          grid-template-columns: minmax(0, 1.4fr) minmax(320px, 0.6fr);
          gap: 16px;
          margin-bottom: 16px;
        }

        .clientGrid {
          margin-top: 16px;
          display: grid;
          grid-template-columns: repeat(3, minmax(210px, 1fr));
          gap: 12px;
        }

        .clientCard {
          background: #f7f7f5;
          border: 1px solid #eeeeeb;
          border-radius: 18px;
          padding: 14px;
        }

        .clientHeader {
          display: flex;
          justify-content: space-between;
          align-items: center;
        }

        .clientAvatar {
          width: 38px;
          height: 38px;
          border-radius: 14px;
          display: grid;
          place-items: center;
          background: linear-gradient(135deg, #ff8a55, #ff3f22);
          color: white;
          font-weight: 900;
          font-size: 12px;
        }

        .clientCard h3 {
          margin: 16px 0 4px;
          letter-spacing: -0.04em;
        }

        .clientCard p {
          margin: 0;
          color: #777771;
          font-size: 12px;
          font-weight: 800;
        }

        .clientStats {
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 8px;
          margin: 14px 0;
        }

        .clientStats div {
          background: white;
          border-radius: 12px;
          padding: 10px;
        }

        .clientStats span {
          display: block;
          color: #85857e;
          font-size: 10px;
          font-weight: 900;
        }

        .clientStats strong {
          display: block;
          margin-top: 4px;
          font-size: 13px;
        }

        .clientCard > small {
          color: #777771;
          font-size: 11px;
        }

        .contractCards {
          margin-top: 16px;
          display: grid;
          grid-template-columns: 1fr;
          gap: 12px;
        }

        .contract {
          border-radius: 18px;
          min-height: 120px;
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
          max-width: 190px;
          letter-spacing: -0.03em;
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

        .tableWrap {
          overflow-x: auto;
        }

        table {
          width: 100%;
          border-collapse: collapse;
          min-width: 1050px;
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

        .statusPill,
        .healthPill {
          display: inline-flex;
          align-items: center;
          gap: 6px;
          white-space: nowrap;
          font-weight: 800;
          text-transform: capitalize;
          font-size: 12px;
        }

        .statusPill span,
        .healthPill span {
          width: 7px;
          height: 7px;
          border-radius: 50%;
          background: currentColor;
        }

        .status-new {
          color: #1677ff;
        }

        .status-qualified,
        .status-proposal {
          color: #a57900;
        }

        .status-won,
        .health-excellent,
        .health-good {
          color: #30a46c;
        }

        .status-lost,
        .health-risk {
          color: #d93025;
        }

        .health-watch {
          color: #a57900;
        }

        .contractMini {
          display: flex;
          gap: 6px;
          color: #ff5438;
        }

        .rowActions {
          display: flex;
          align-items: center;
          gap: 4px;
        }

        .roundMini {
          width: 30px;
          height: 30px;
          background: #f7f7f5;
        }

        .emptyBox,
        .stateBox {
          min-height: 280px;
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

        .emptyBox strong,
        .stateBox strong {
          color: #22221f;
          font-size: 18px;
        }

        .emptyBox p,
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
          .clientsAndRules {
            grid-template-columns: 1fr;
          }

          .clientGrid {
            grid-template-columns: repeat(2, minmax(210px, 1fr));
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
          .clientGrid {
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