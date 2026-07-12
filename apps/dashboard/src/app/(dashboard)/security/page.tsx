import type React from "react";
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  ArrowRight,
  BadgeCheck,
  Ban,
  BellRing,
  Bot,
  CheckCircle2,
  CircleDot,
  Clock3,
  Database,
  DoorClosed,
  Download,
  Eye,
  FileCheck2,
  FileClock,
  Fingerprint,
  Globe2,
  History,
  KeyRound,
  Layers3,
  Lock,
  MessageSquareWarning,
  Network,
  PauseCircle,
  Play,
  RefreshCcw,
  Route,
  Search,
  ShieldAlert,
  ShieldCheck,
  ShieldEllipsis,
  ShieldX,
  Siren,
  SlidersHorizontal,
  TerminalSquare,
  TimerReset,
  Trash2,
  Unlock,
  UserCheck,
  WalletCards,
  Zap,
} from "lucide-react";

type RiskLevel = "low" | "medium" | "high" | "critical";
type ApprovalStatus = "pending" | "approved" | "denied" | "expired";
type AuditStatus = "allowed" | "blocked" | "approval_required" | "reviewed";
type SecurityMode = "guarded" | "strict" | "lockdown";

type MetricCard = {
  label: string;
  value: string;
  description: string;
  icon: React.ComponentType<{ className?: string }>;
};

type ApprovalRequest = {
  id: string;
  title: string;
  description: string;
  agent: string;
  actionType: string;
  risk: RiskLevel;
  status: ApprovalStatus;
  requestedAt: string;
  scope: string;
  reason: string;
};

type AuditLog = {
  id: string;
  event: string;
  description: string;
  agent: string;
  status: AuditStatus;
  risk: RiskLevel;
  timestamp: string;
  workspaceScope: string;
};

type RiskEvent = {
  title: string;
  description: string;
  risk: RiskLevel;
  icon: React.ComponentType<{ className?: string }>;
};

type PolicyRule = {
  title: string;
  description: string;
  mode: SecurityMode;
  icon: React.ComponentType<{ className?: string }>;
};

const metrics: MetricCard[] = [
  {
    label: "Security Mode",
    value: "Guarded",
    description:
      "Sensitive actions are routed through approval and risk checks.",
    icon: ShieldCheck,
  },
  {
    label: "Pending Approvals",
    value: "7",
    description:
      "Protected actions waiting for owner or Security Agent review.",
    icon: Fingerprint,
  },
  {
    label: "Blocked Events",
    value: "13",
    description: "Unsafe actions stopped before execution.",
    icon: Ban,
  },
  {
    label: "Audit Coverage",
    value: "100%",
    description:
      "Every sensitive request is designed to generate an audit event.",
    icon: FileClock,
  },
];

const approvalRequests: ApprovalRequest[] = [
  {
    id: "APP-1041",
    title: "Run Protected Terminal Command",
    description:
      "Code Agent requested a terminal operation that may modify project files and must be approved before execution.",
    agent: "Code Agent",
    actionType: "terminal_command",
    risk: "high",
    status: "pending",
    requestedAt: "Today · 09:46",
    scope: "owner + workspace_id",
    reason:
      "Terminal commands can alter files, install packages, or expose sensitive logs.",
  },
  {
    id: "APP-1042",
    title: "Access Private Memory Export",
    description:
      "Memory Agent requested export access for private project memory and client-related notes.",
    agent: "Memory Agent",
    actionType: "memory_export",
    risk: "critical",
    status: "pending",
    requestedAt: "Today · 09:51",
    scope: "private_user + workspace_id",
    reason: "Memory exports may contain private user, client, or project data.",
  },
  {
    id: "APP-1043",
    title: "Prepare Invoice Draft",
    description:
      "Finance Agent requested permission to prepare an invoice draft for workspace billing records.",
    agent: "Finance Agent",
    actionType: "finance_draft",
    risk: "high",
    status: "approved",
    requestedAt: "Yesterday · 17:22",
    scope: "finance role required",
    reason:
      "Finance drafts are allowed, but payments or transfers must never be auto-submitted.",
  },
  {
    id: "APP-1044",
    title: "Submit External Browser Form",
    description:
      "Browser Agent attempted to prepare a form submission on an external website.",
    agent: "Browser Agent",
    actionType: "external_form_submit",
    risk: "critical",
    status: "denied",
    requestedAt: "Yesterday · 14:10",
    scope: "workspace browser session",
    reason:
      "External form submission requires explicit confirmation and fraud checks.",
  },
];

const auditLogs: AuditLog[] = [
  {
    id: "AUD-9001",
    event: "Security approval required",
    description:
      "System Agent attempted a protected local automation task. Execution paused safely.",
    agent: "System Agent",
    status: "approval_required",
    risk: "critical",
    timestamp: "Today · 10:02",
    workspaceScope: "user_id + workspace_id",
  },
  {
    id: "AUD-9002",
    event: "Memory privacy check passed",
    description:
      "Memory Agent prepared a private user memory payload with correct workspace isolation metadata.",
    agent: "Memory Agent",
    status: "reviewed",
    risk: "medium",
    timestamp: "Today · 09:58",
    workspaceScope: "private_user",
  },
  {
    id: "AUD-9003",
    event: "Browser action blocked",
    description:
      "External page form action was blocked because permission state was missing.",
    agent: "Browser Agent",
    status: "blocked",
    risk: "critical",
    timestamp: "Yesterday · 22:14",
    workspaceScope: "workspace browser logs",
  },
  {
    id: "AUD-9004",
    event: "Verification payload created",
    description:
      "Verification Agent payload prepared for dashboard page generation task.",
    agent: "Verification Agent",
    status: "allowed",
    risk: "low",
    timestamp: "Yesterday · 21:40",
    workspaceScope: "current project",
  },
];

const riskEvents: RiskEvent[] = [
  {
    title: "Financial Protection",
    description:
      "Finance Agent can prepare invoices and reports, but must never submit payments or transfers automatically.",
    risk: "critical",
    icon: WalletCards,
  },
  {
    title: "System Command Guard",
    description:
      "OS commands, file deletion, installs, device controls, and automation need explicit approval.",
    risk: "critical",
    icon: TerminalSquare,
  },
  {
    title: "Browser Fraud Shield",
    description:
      "Logins, form submissions, downloads, scraping, and external actions require policy checks.",
    risk: "high",
    icon: Globe2,
  },
  {
    title: "Private Memory Control",
    description:
      "Sensitive user, team, project, and client memory cannot be exported or shared without review.",
    risk: "high",
    icon: Database,
  },
];

const policyRules: PolicyRule[] = [
  {
    title: "Guarded Mode",
    description:
      "Default production mode. Allows safe reads and drafts while pausing risky actions for approval.",
    mode: "guarded",
    icon: ShieldCheck,
  },
  {
    title: "Strict Mode",
    description:
      "Requires approval for most external actions, private data access, browser submissions, and automations.",
    mode: "strict",
    icon: ShieldAlert,
  },
  {
    title: "Emergency Lockdown",
    description:
      "Stops agents, freezes risky workflows, blocks automation, and requires owner re-authentication.",
    mode: "lockdown",
    icon: Siren,
  },
];

function getRiskStyles(risk: RiskLevel): string {
  switch (risk) {
    case "low":
      return "border-emerald-400/20 bg-emerald-400/10 text-emerald-300";
    case "medium":
      return "border-blue-400/20 bg-blue-400/10 text-blue-300";
    case "high":
      return "border-orange-400/25 bg-orange-500/10 text-orange-300";
    case "critical":
      return "border-red-400/25 bg-red-500/10 text-red-300";
    default:
      return "border-white/10 bg-white/[0.04] text-zinc-400";
  }
}

function getApprovalStyles(status: ApprovalStatus): string {
  switch (status) {
    case "pending":
      return "border-yellow-400/25 bg-yellow-400/10 text-yellow-300";
    case "approved":
      return "border-emerald-400/20 bg-emerald-400/10 text-emerald-300";
    case "denied":
      return "border-red-400/25 bg-red-500/10 text-red-300";
    case "expired":
      return "border-zinc-500/20 bg-zinc-500/10 text-zinc-400";
    default:
      return "border-white/10 bg-white/[0.04] text-zinc-400";
  }
}

function getAuditStyles(status: AuditStatus): string {
  switch (status) {
    case "allowed":
      return "border-emerald-400/20 bg-emerald-400/10 text-emerald-300";
    case "blocked":
      return "border-red-400/25 bg-red-500/10 text-red-300";
    case "approval_required":
      return "border-yellow-400/25 bg-yellow-400/10 text-yellow-300";
    case "reviewed":
      return "border-blue-400/20 bg-blue-400/10 text-blue-300";
    default:
      return "border-white/10 bg-white/[0.04] text-zinc-400";
  }
}

function getModeStyles(mode: SecurityMode): string {
  switch (mode) {
    case "guarded":
      return "border-emerald-400/20 bg-emerald-400/10 text-emerald-300";
    case "strict":
      return "border-orange-400/25 bg-orange-500/10 text-orange-300";
    case "lockdown":
      return "border-red-400/25 bg-red-500/10 text-red-300";
    default:
      return "border-white/10 bg-white/[0.04] text-zinc-400";
  }
}

function formatStatus(status: string): string {
  return status.replaceAll("_", " ");
}

function MetricCardItem({ label, value, description, icon: Icon }: MetricCard) {
  return (
    <div className="rounded-[28px] border border-white/10 bg-white/[0.035] p-5 shadow-[0_24px_80px_rgba(0,0,0,0.28)] transition hover:border-orange-500/25 hover:bg-orange-500/[0.055]">
      <div className="mb-5 flex items-center justify-between gap-4">
        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-zinc-500">
          {label}
        </p>
        <span className="flex h-11 w-11 items-center justify-center rounded-2xl border border-orange-500/20 bg-orange-500/10 text-orange-300">
          <Icon className="h-5 w-5" />
        </span>
      </div>

      <p className="text-2xl font-black tracking-tight text-white">{value}</p>
      <p className="mt-2 text-sm leading-6 text-zinc-500">{description}</p>
    </div>
  );
}

function RiskBadge({ risk }: { risk: RiskLevel }) {
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2.5 py-1 text-[11px] font-bold capitalize ${getRiskStyles(
        risk,
      )}`}
    >
      {risk} risk
    </span>
  );
}

function ApprovalBadge({ status }: { status: ApprovalStatus }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-bold capitalize ${getApprovalStyles(
        status,
      )}`}
    >
      <span className="h-2 w-2 rounded-full bg-current shadow-[0_0_14px_currentColor]" />
      {formatStatus(status)}
    </span>
  );
}

function AuditBadge({ status }: { status: AuditStatus }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-bold capitalize ${getAuditStyles(
        status,
      )}`}
    >
      <span className="h-2 w-2 rounded-full bg-current shadow-[0_0_14px_currentColor]" />
      {formatStatus(status)}
    </span>
  );
}

function ApprovalCard({ approval }: { approval: ApprovalRequest }) {
  const isPending = approval.status === "pending";

  return (
    <article className="rounded-[30px] border border-white/10 bg-white/[0.035] p-5 shadow-[0_28px_90px_rgba(0,0,0,0.3)] transition hover:border-orange-500/25 hover:bg-orange-500/[0.055]">
      <div className="mb-5 flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
        <div>
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <ApprovalBadge status={approval.status} />
            <RiskBadge risk={approval.risk} />
            <span className="rounded-full border border-white/10 bg-white/[0.04] px-2.5 py-1 text-[11px] font-bold text-zinc-400">
              {approval.id}
            </span>
          </div>

          <h3 className="text-lg font-black text-white">{approval.title}</h3>
          <p className="mt-2 text-sm leading-7 text-zinc-500">
            {approval.description}
          </p>
        </div>

        <div className="flex flex-wrap gap-2">
          {isPending ? (
            <>
              <button
                type="button"
                className="inline-flex items-center gap-2 rounded-2xl border border-emerald-400/20 bg-emerald-400/10 px-3 py-2 text-xs font-bold text-emerald-300 transition hover:bg-emerald-400/15"
              >
                <CheckCircle2 className="h-3.5 w-3.5" />
                Approve
              </button>

              <button
                type="button"
                className="inline-flex items-center gap-2 rounded-2xl border border-red-400/20 bg-red-500/10 px-3 py-2 text-xs font-bold text-red-300 transition hover:bg-red-500/15"
              >
                <ShieldX className="h-3.5 w-3.5" />
                Deny
              </button>
            </>
          ) : null}

          <button
            type="button"
            className="inline-flex items-center gap-2 rounded-2xl border border-white/10 bg-white/[0.04] px-3 py-2 text-xs font-bold text-zinc-300 transition hover:border-orange-500/30 hover:bg-orange-500/10 hover:text-orange-300"
          >
            <Eye className="h-3.5 w-3.5" />
            Review
          </button>
        </div>
      </div>

      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <div className="rounded-2xl border border-white/10 bg-black/25 p-3">
          <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-zinc-500">
            Agent
          </p>
          <p className="mt-2 text-sm font-bold text-white">{approval.agent}</p>
        </div>

        <div className="rounded-2xl border border-white/10 bg-black/25 p-3">
          <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-zinc-500">
            Action
          </p>
          <p className="mt-2 font-mono text-xs font-bold text-orange-200">
            {approval.actionType}
          </p>
        </div>

        <div className="rounded-2xl border border-white/10 bg-black/25 p-3">
          <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-zinc-500">
            Requested
          </p>
          <p className="mt-2 text-sm font-bold text-white">
            {approval.requestedAt}
          </p>
        </div>

        <div className="rounded-2xl border border-white/10 bg-black/25 p-3">
          <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-zinc-500">
            Scope
          </p>
          <p className="mt-2 text-sm font-bold text-white">{approval.scope}</p>
        </div>
      </div>

      <div className="mt-5 rounded-2xl border border-orange-400/15 bg-orange-500/[0.07] p-4">
        <div className="mb-2 flex items-center gap-2">
          <ShieldAlert className="h-4 w-4 text-orange-300" />
          <p className="text-xs font-black uppercase tracking-[0.16em] text-orange-300">
            Security Reason
          </p>
        </div>
        <p className="text-sm leading-6 text-zinc-400">{approval.reason}</p>
      </div>
    </article>
  );
}

function AuditLogCard({ log }: { log: AuditLog }) {
  return (
    <article className="rounded-[26px] border border-white/10 bg-white/[0.035] p-4 transition hover:border-orange-500/25 hover:bg-orange-500/[0.055]">
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <AuditBadge status={log.status} />
        <RiskBadge risk={log.risk} />
        <span className="rounded-full border border-white/10 bg-white/[0.04] px-2.5 py-1 text-[11px] font-bold text-zinc-400">
          {log.id}
        </span>
      </div>

      <h3 className="text-base font-black text-white">{log.event}</h3>
      <p className="mt-2 text-sm leading-6 text-zinc-500">{log.description}</p>

      <div className="mt-4 grid gap-3 md:grid-cols-3">
        <div className="rounded-2xl border border-white/10 bg-black/25 p-3">
          <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-zinc-500">
            Agent
          </p>
          <p className="mt-2 text-sm font-bold text-white">{log.agent}</p>
        </div>

        <div className="rounded-2xl border border-white/10 bg-black/25 p-3">
          <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-zinc-500">
            Time
          </p>
          <p className="mt-2 text-sm font-bold text-white">{log.timestamp}</p>
        </div>

        <div className="rounded-2xl border border-white/10 bg-black/25 p-3">
          <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-zinc-500">
            Scope
          </p>
          <p className="mt-2 text-sm font-bold text-white">
            {log.workspaceScope}
          </p>
        </div>
      </div>
    </article>
  );
}

function RiskEventCard({ event }: { event: RiskEvent }) {
  const Icon = event.icon;

  return (
    <div className="rounded-[26px] border border-white/10 bg-white/[0.035] p-5 transition hover:border-orange-500/25 hover:bg-orange-500/[0.055]">
      <div className="mb-4 flex items-start justify-between gap-4">
        <span className="flex h-12 w-12 items-center justify-center rounded-2xl border border-orange-500/20 bg-orange-500/10 text-orange-300">
          <Icon className="h-6 w-6" />
        </span>
        <RiskBadge risk={event.risk} />
      </div>
      <p className="text-sm font-bold text-white">{event.title}</p>
      <p className="mt-2 text-sm leading-6 text-zinc-500">
        {event.description}
      </p>
    </div>
  );
}

function PolicyRuleCard({ rule }: { rule: PolicyRule }) {
  const Icon = rule.icon;

  return (
    <div className="rounded-2xl border border-white/10 bg-white/[0.035] p-4">
      <div className="mb-3 flex items-start justify-between gap-3">
        <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl bg-orange-500/10 text-orange-300">
          <Icon className="h-5 w-5" />
        </span>
        <span
          className={`rounded-full border px-2.5 py-1 text-[11px] font-bold capitalize ${getModeStyles(
            rule.mode,
          )}`}
        >
          {rule.mode}
        </span>
      </div>

      <p className="text-sm font-bold text-white">{rule.title}</p>
      <p className="mt-2 text-sm leading-6 text-zinc-500">{rule.description}</p>
    </div>
  );
}

export default function SecurityPage() {
  const pendingCount = approvalRequests.filter(
    (approval) => approval.status === "pending",
  ).length;

  const criticalApprovals = approvalRequests.filter(
    (approval) => approval.risk === "critical",
  ).length;

  const blockedLogs = auditLogs.filter(
    (log) => log.status === "blocked",
  ).length;

  return (
    <div className="space-y-6">
      <section className="relative overflow-hidden rounded-[34px] border border-white/10 bg-[radial-gradient(circle_at_18%_10%,rgba(249,115,22,0.3),transparent_34%),linear-gradient(135deg,rgba(255,255,255,0.08),rgba(255,255,255,0.025))] p-6 shadow-[0_40px_120px_rgba(0,0,0,0.42)] md:p-8 lg:p-10">
        <div className="absolute right-10 top-0 h-72 w-72 rounded-full bg-orange-500/20 blur-3xl" />
        <div className="absolute bottom-0 left-1/3 h-56 w-56 rounded-full bg-red-900/25 blur-3xl" />

        <div className="relative grid gap-8 xl:grid-cols-[1.1fr_0.9fr] xl:items-center">
          <div>
            <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-orange-400/25 bg-orange-500/10 px-4 py-2 text-xs font-bold uppercase tracking-[0.18em] text-orange-300">
              <ShieldCheck className="h-4 w-4" />
              Security Center
            </div>

            <h1 className="max-w-5xl text-4xl font-black tracking-tight text-white md:text-5xl lg:text-6xl">
              Approve, Block, Audit, And Lock Down William’s Sensitive Actions.
            </h1>

            <p className="mt-5 max-w-3xl text-base leading-8 text-zinc-400 md:text-lg">
              Review approval requests, risk events, audit logs, protected
              actions, emergency lockdown controls, and workspace-safe security
              decisions before anything risky touches the system.
            </p>

            <div className="mt-7 flex flex-wrap gap-3">
              <span className="inline-flex items-center gap-2 rounded-2xl border border-yellow-400/25 bg-yellow-400/10 px-4 py-2 text-sm font-bold text-yellow-300">
                <Fingerprint className="h-4 w-4" />
                {pendingCount} Pending Approvals
              </span>

              <span className="inline-flex items-center gap-2 rounded-2xl border border-red-400/25 bg-red-500/10 px-4 py-2 text-sm font-bold text-red-300">
                <AlertTriangle className="h-4 w-4" />
                {criticalApprovals} Critical Requests
              </span>

              <span className="inline-flex items-center gap-2 rounded-2xl border border-orange-400/25 bg-orange-500/10 px-4 py-2 text-sm font-bold text-orange-300">
                <Ban className="h-4 w-4" />
                {blockedLogs} Blocked Event
              </span>
            </div>
          </div>

          <div className="rounded-[30px] border border-red-400/20 bg-red-500/[0.08] p-5 shadow-[0_30px_100px_rgba(0,0,0,0.42)] backdrop-blur-xl">
            <div className="mb-5 flex items-center justify-between">
              <div>
                <p className="text-sm font-bold text-white">Emergency Lock</p>
                <p className="mt-1 text-xs text-zinc-400">
                  Freeze risky agents and automation
                </p>
              </div>

              <span className="flex h-12 w-12 items-center justify-center rounded-2xl bg-red-500 text-white shadow-[0_0_40px_rgba(248,113,113,0.35)]">
                <Siren className="h-6 w-6" />
              </span>
            </div>

            <p className="text-sm leading-7 text-zinc-400">
              Emergency lock should stop all risky workflows, block protected
              actions, pause automation, and require owner re-authentication
              before agents resume.
            </p>

            <div className="mt-5 grid gap-3 sm:grid-cols-2">
              <button
                type="button"
                className="inline-flex items-center justify-center gap-2 rounded-2xl border border-red-400/25 bg-red-500/15 px-4 py-3 text-sm font-black text-red-200 transition hover:bg-red-500/25"
              >
                <PauseCircle className="h-4 w-4" />
                Activate Lock
              </button>

              <button
                type="button"
                className="inline-flex items-center justify-center gap-2 rounded-2xl border border-white/10 bg-white/[0.04] px-4 py-3 text-sm font-black text-zinc-300 transition hover:border-emerald-400/30 hover:bg-emerald-400/10 hover:text-emerald-300"
              >
                <Unlock className="h-4 w-4" />
                Unlock Review
              </button>
            </div>

            <div className="mt-5 rounded-2xl border border-red-400/20 bg-black/25 p-4">
              <div className="flex items-center gap-3">
                <span className="h-2.5 w-2.5 rounded-full bg-red-400 shadow-[0_0_18px_rgba(248,113,113,0.9)]" />
                <p className="text-sm font-bold text-red-300">
                  Lockdown available, not active
                </p>
              </div>
              <p className="mt-2 text-sm leading-6 text-zinc-500">
                This UI is safe and does not trigger real lockdown until backend
                Security Agent routes exist.
              </p>
            </div>
          </div>
        </div>
      </section>

      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {metrics.map((metric) => (
          <MetricCardItem key={metric.label} {...metric} />
        ))}
      </section>

      <section className="grid gap-6 xl:grid-cols-[0.78fr_1.22fr]">
        <aside className="space-y-6">
          <div className="rounded-[32px] border border-white/10 bg-white/[0.035] p-5 shadow-[0_30px_100px_rgba(0,0,0,0.32)] md:p-6">
            <div className="mb-6 flex items-center justify-between">
              <div>
                <p className="text-sm font-bold text-orange-300">
                  Security Filters
                </p>
                <h2 className="mt-2 text-2xl font-black text-white">
                  Control View
                </h2>
              </div>
              <Search className="h-5 w-5 text-orange-300" />
            </div>

            <div className="rounded-2xl border border-white/10 bg-black/25 p-3">
              <div className="flex items-center gap-3">
                <Search className="h-4 w-4 text-zinc-500" />
                <input
                  aria-label="Search security events"
                  className="w-full bg-transparent text-sm text-zinc-200 outline-none placeholder:text-zinc-600"
                  placeholder="Search approvals, audit logs, risk events..."
                  type="text"
                />
              </div>
            </div>

            <div className="mt-5 space-y-3">
              {[
                "All Security Events",
                "Pending Approvals",
                "Critical Risk",
                "Blocked",
                "Allowed",
                "Reviewed",
              ].map((filter, index) => (
                <button
                  key={filter}
                  type="button"
                  className={`flex w-full items-center justify-between rounded-2xl border px-4 py-3 text-sm font-bold transition ${
                    index === 0
                      ? "border-orange-500/25 bg-orange-500/10 text-orange-300"
                      : "border-white/10 bg-white/[0.035] text-zinc-400 hover:border-orange-500/25 hover:bg-orange-500/10 hover:text-orange-300"
                  }`}
                >
                  {filter}
                  <CircleDot className="h-3.5 w-3.5" />
                </button>
              ))}
            </div>
          </div>

          <div className="rounded-[32px] border border-white/10 bg-black/30 p-5 md:p-6">
            <div className="mb-5 flex items-center justify-between">
              <div>
                <p className="text-sm font-bold text-orange-300">
                  Policy Modes
                </p>
                <h2 className="mt-2 text-xl font-black text-white">
                  Guard Rules
                </h2>
              </div>
              <SlidersHorizontal className="h-5 w-5 text-orange-300" />
            </div>

            <div className="space-y-3">
              {policyRules.map((rule) => (
                <PolicyRuleCard key={rule.title} rule={rule} />
              ))}
            </div>
          </div>

          <div className="rounded-[32px] border border-orange-500/15 bg-orange-500/[0.07] p-5 md:p-6">
            <div className="mb-4 flex items-center gap-3">
              <Zap className="h-5 w-5 text-orange-300" />
              <p className="text-sm font-black uppercase tracking-[0.16em] text-orange-300">
                Next Backend Hook
              </p>
            </div>
            <p className="text-sm leading-7 text-zinc-400">
              Later, connect this page to Security Agent routes for permission
              checks, approval decisions, audit logging, risk scoring, fraud
              detection, and emergency lock.
            </p>
          </div>
        </aside>

        <main className="space-y-6">
          <div className="flex flex-col gap-3 rounded-[30px] border border-white/10 bg-white/[0.035] p-5 md:flex-row md:items-center md:justify-between">
            <div>
              <p className="text-sm font-bold text-orange-300">
                Approval Queue
              </p>
              <h2 className="mt-2 text-2xl font-black tracking-tight text-white">
                Sensitive Actions Waiting For Review
              </h2>
            </div>

            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                className="inline-flex items-center gap-2 rounded-2xl border border-white/10 bg-white/[0.04] px-3 py-2 text-xs font-bold text-zinc-300 transition hover:border-orange-500/30 hover:bg-orange-500/10 hover:text-orange-300"
              >
                <Download className="h-3.5 w-3.5" />
                Export Audit
              </button>

              <button
                type="button"
                className="inline-flex items-center gap-2 rounded-2xl bg-orange-500 px-3 py-2 text-xs font-black text-black transition hover:bg-orange-400"
              >
                <RefreshCcw className="h-3.5 w-3.5" />
                Refresh
              </button>
            </div>
          </div>

          <div className="grid gap-5">
            {approvalRequests.map((approval) => (
              <ApprovalCard key={approval.id} approval={approval} />
            ))}
          </div>

          <div className="grid gap-5 xl:grid-cols-2">
            <section className="rounded-[32px] border border-white/10 bg-white/[0.035] p-5 shadow-[0_30px_100px_rgba(0,0,0,0.32)] md:p-6">
              <div className="mb-5 flex items-center justify-between">
                <div>
                  <p className="text-sm font-bold text-orange-300">
                    Risk Events
                  </p>
                  <h2 className="mt-2 text-xl font-black text-white">
                    Protected Areas
                  </h2>
                </div>
                <AlertOctagon className="h-5 w-5 text-orange-300" />
              </div>

              <div className="grid gap-4">
                {riskEvents.map((event) => (
                  <RiskEventCard key={event.title} event={event} />
                ))}
              </div>
            </section>

            <section className="rounded-[32px] border border-white/10 bg-white/[0.035] p-5 shadow-[0_30px_100px_rgba(0,0,0,0.32)] md:p-6">
              <div className="mb-5 flex items-center justify-between">
                <div>
                  <p className="text-sm font-bold text-orange-300">
                    Audit Logs
                  </p>
                  <h2 className="mt-2 text-xl font-black text-white">
                    Recent Events
                  </h2>
                </div>
                <History className="h-5 w-5 text-orange-300" />
              </div>

              <div className="space-y-4">
                {auditLogs.map((log) => (
                  <AuditLogCard key={log.id} log={log} />
                ))}
              </div>
            </section>
          </div>
        </main>
      </section>

      <section className="rounded-[32px] border border-white/10 bg-black/30 p-5 md:p-6">
        <div className="grid gap-5 lg:grid-cols-4">
          <div className="rounded-[26px] border border-white/10 bg-white/[0.035] p-5">
            <UserCheck className="mb-4 h-6 w-6 text-orange-300" />
            <p className="text-sm font-bold text-white">Permission Checker</p>
            <p className="mt-2 text-sm leading-6 text-zinc-500">
              Checks allowed, approval-required, biometric-required, or blocked
              actions before execution.
            </p>
          </div>

          <div className="rounded-[26px] border border-white/10 bg-white/[0.035] p-5">
            <ShieldEllipsis className="mb-4 h-6 w-6 text-orange-300" />
            <p className="text-sm font-bold text-white">Risk Engine</p>
            <p className="mt-2 text-sm leading-6 text-zinc-500">
              Scores financial, destructive, private, device, browser, terminal,
              and account actions.
            </p>
          </div>

          <div className="rounded-[26px] border border-white/10 bg-white/[0.035] p-5">
            <BellRing className="mb-4 h-6 w-6 text-orange-300" />
            <p className="text-sm font-bold text-white">Approval Manager</p>
            <p className="mt-2 text-sm leading-6 text-zinc-500">
              Creates confirmation prompts and records approval or denial
              decisions for audit history.
            </p>
          </div>

          <div className="rounded-[26px] border border-white/10 bg-white/[0.035] p-5">
            <DoorClosed className="mb-4 h-6 w-6 text-orange-300" />
            <p className="text-sm font-bold text-white">Emergency Lock</p>
            <p className="mt-2 text-sm leading-6 text-zinc-500">
              Future kill switch can freeze risky agents, workflows, and
              automation until owner verification.
            </p>
          </div>
        </div>
      </section>

      <section className="rounded-[32px] border border-red-400/15 bg-red-500/[0.06] p-5 md:p-6">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <div className="mb-3 flex items-center gap-2">
              <MessageSquareWarning className="h-5 w-5 text-red-300" />
              <p className="text-sm font-black uppercase tracking-[0.16em] text-red-300">
                Safety Reminder
              </p>
            </div>
            <p className="max-w-4xl text-sm leading-7 text-zinc-400">
              This frontend page does not approve, deny, lock, unlock, or
              execute real actions yet. Real decisions must be connected later
              through protected backend routes, owner confirmation, audit
              storage, and Security Agent policy checks.
            </p>
          </div>

          <button
            type="button"
            className="inline-flex items-center justify-center gap-2 rounded-2xl border border-red-400/25 bg-red-500/10 px-4 py-3 text-sm font-bold text-red-300 transition hover:bg-red-500/15"
          >
            <Siren className="h-4 w-4" />
            Emergency Review
          </button>
        </div>
      </section>
    </div>
  );
}
