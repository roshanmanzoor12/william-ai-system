import type React from "react";
import {
  AlertTriangle,
  ArrowRight,
  BadgeCheck,
  Bell,
  Bot,
  Brain,
  BriefcaseBusiness,
  CheckCircle2,
  CircleDot,
  Code2,
  CreditCard,
  Database,
  Eye,
  FileCheck2,
  Fingerprint,
  Globe2,
  Headphones,
  KeyRound,
  Layers3,
  Lock,
  Mail,
  Network,
  Palette,
  PlugZap,
  RefreshCcw,
  Save,
  Settings,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  TerminalSquare,
  ToggleRight,
  UserCog,
  Users,
  WalletCards,
  Workflow,
  Zap,
} from "lucide-react";
import { VoiceControlSettings } from "@/components/voice/VoiceControlSettings";
import { TrustedVoiceProfiles } from "@/components/voice/TrustedVoiceProfiles";

type RoleLevel = "owner" | "admin" | "manager" | "member" | "viewer";
type PermissionStatus =
  | "enabled"
  | "approval_required"
  | "limited"
  | "disabled";
type IntegrationStatus = "connected" | "available" | "restricted";

type MetricCard = {
  label: string;
  value: string;
  description: string;
  icon: React.ComponentType<{ className?: string }>;
};

type TeamMember = {
  name: string;
  email: string;
  role: RoleLevel;
  status: string;
  access: string;
};

type AgentPermission = {
  agent: string;
  description: string;
  status: PermissionStatus;
  icon: React.ComponentType<{ className?: string }>;
};

type Integration = {
  name: string;
  description: string;
  status: IntegrationStatus;
  icon: React.ComponentType<{ className?: string }>;
};

type SettingsRule = {
  title: string;
  description: string;
  icon: React.ComponentType<{ className?: string }>;
};

const metrics: MetricCard[] = [
  {
    label: "Workspace",
    value: "Digital Promotix",
    description: "Primary workspace for William/Jarvis dashboard operations.",
    icon: BriefcaseBusiness,
  },
  {
    label: "Team Seats",
    value: "5",
    description: "Role-based access preview for team and workspace members.",
    icon: Users,
  },
  {
    label: "Agent Rules",
    value: "14",
    description: "Agent permission controls prepared for all William agents.",
    icon: Bot,
  },
  {
    label: "Integrations",
    value: "8",
    description:
      "External app connections can be linked through backend routes.",
    icon: PlugZap,
  },
];

const teamMembers: TeamMember[] = [
  {
    name: "Workspace Owner",
    email: "owner@digitalpromotix.com",
    role: "owner",
    status: "Active",
    access: "Full access",
  },
  {
    name: "Admin User",
    email: "admin@digitalpromotix.com",
    role: "admin",
    status: "Active",
    access: "Security + billing",
  },
  {
    name: "Marketing Manager",
    email: "marketing@digitalpromotix.com",
    role: "manager",
    status: "Active",
    access: "Campaign + CRM",
  },
  {
    name: "Team Member",
    email: "member@digitalpromotix.com",
    role: "member",
    status: "Invited",
    access: "Limited workspace",
  },
];

const agentPermissions: AgentPermission[] = [
  {
    agent: "Master Agent",
    description:
      "Planning, routing, response building, and multi-agent coordination.",
    status: "enabled",
    icon: Bot,
  },
  {
    agent: "Security Agent",
    description:
      "Risk scoring, approvals, audit logs, emergency lock, and privacy checks.",
    status: "enabled",
    icon: Fingerprint,
  },
  {
    agent: "Memory Agent",
    description:
      "Private, project, client, team, and workspace memory controls.",
    status: "approval_required",
    icon: Brain,
  },
  {
    agent: "Code Agent",
    description:
      "Project files, code edits, dependencies, builds, tests, and terminal runs.",
    status: "approval_required",
    icon: Code2,
  },
  {
    agent: "System Agent",
    description:
      "Apps, files, OS commands, device controls, and local automation.",
    status: "approval_required",
    icon: TerminalSquare,
  },
  {
    agent: "Browser Agent",
    description:
      "Search, scraping, page analysis, forms, downloads, and screenshots.",
    status: "limited",
    icon: Globe2,
  },
  {
    agent: "Finance Agent",
    description:
      "Invoices, budgets, receipts, reports, and finance drafts only.",
    status: "approval_required",
    icon: WalletCards,
  },
  {
    agent: "Hologram Agent",
    description:
      "AR overlays, gestures, spatial mapping, and device bridge features.",
    status: "disabled",
    icon: Eye,
  },
];

const integrations: Integration[] = [
  {
    name: "FastAPI Backend",
    description:
      "Connect dashboard pages to backend routes and agent execution APIs.",
    status: "available",
    icon: Network,
  },
  {
    name: "Database",
    description:
      "Store users, workspaces, tasks, memory, billing, and audit logs.",
    status: "available",
    icon: Database,
  },
  {
    name: "WebSocket Events",
    description:
      "Stream task progress, approvals, verification reports, and agent events.",
    status: "available",
    icon: Zap,
  },
  {
    name: "Email",
    description:
      "Send approved alerts, reports, invitations, and workspace notifications.",
    status: "restricted",
    icon: Mail,
  },
  {
    name: "Billing Provider",
    description:
      "Manage subscriptions, invoices, payment methods, and usage limits.",
    status: "restricted",
    icon: CreditCard,
  },
  {
    name: "Verification Reports",
    description:
      "Attach proof, screenshots, logs, confidence, and completion summaries.",
    status: "connected",
    icon: FileCheck2,
  },
];

const settingsRules: SettingsRule[] = [
  {
    title: "Workspace Isolation",
    description:
      "Every setting must stay scoped to workspace_id so one workspace cannot affect another.",
    icon: Network,
  },
  {
    title: "Role-Based Access",
    description:
      "Owner, admin, manager, member, and viewer roles should control page and agent access.",
    icon: UserCog,
  },
  {
    title: "Approval Before Risk",
    description:
      "Dangerous actions such as payments, terminal commands, messages, calls, and deletes need approval.",
    icon: ShieldCheck,
  },
  {
    title: "No Hardcoded Secrets",
    description:
      "API keys, tokens, credentials, and billing secrets must stay in protected environment variables.",
    icon: Lock,
  },
];

function getRoleStyles(role: RoleLevel): string {
  switch (role) {
    case "owner":
      return "border-orange-400/25 bg-orange-500/10 text-[#ff5a3d]";
    case "admin":
      return "border-emerald-200 bg-emerald-50 text-emerald-700";
    case "manager":
      return "border-blue-200 bg-blue-50 text-blue-700";
    case "member":
      return "border-purple-200 bg-purple-50 text-purple-700";
    case "viewer":
      return "border-zinc-500/20 bg-zinc-500/10 text-neutral-500";
    default:
      return "border-neutral-100 bg-neutral-50 text-neutral-500";
  }
}

function getPermissionStyles(status: PermissionStatus): string {
  switch (status) {
    case "enabled":
      return "border-emerald-200 bg-emerald-50 text-emerald-700";
    case "approval_required":
      return "border-yellow-200 bg-yellow-50 text-yellow-700";
    case "limited":
      return "border-orange-400/25 bg-orange-500/10 text-[#ff5a3d]";
    case "disabled":
      return "border-red-200 bg-red-50 text-red-700";
    default:
      return "border-neutral-100 bg-neutral-50 text-neutral-500";
  }
}

function getIntegrationStyles(status: IntegrationStatus): string {
  switch (status) {
    case "connected":
      return "border-emerald-200 bg-emerald-50 text-emerald-700";
    case "available":
      return "border-blue-200 bg-blue-50 text-blue-700";
    case "restricted":
      return "border-orange-400/25 bg-orange-500/10 text-[#ff5a3d]";
    default:
      return "border-neutral-100 bg-neutral-50 text-neutral-500";
  }
}

function formatStatus(value: string): string {
  return value.replaceAll("_", " ");
}

function MetricCardItem({ label, value, description, icon: Icon }: MetricCard) {
  return (
    <div className="rounded-[28px] border border-neutral-100 bg-white p-5 shadow-sm transition hover:border-orange-500/25 hover:bg-orange-500/[0.055]">
      <div className="mb-5 flex items-center justify-between gap-4">
        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-neutral-400">
          {label}
        </p>
        <span className="flex h-11 w-11 items-center justify-center rounded-2xl border border-orange-500/20 bg-orange-500/10 text-[#ff5a3d]">
          <Icon className="h-5 w-5" />
        </span>
      </div>

      <p className="text-2xl font-black tracking-tight text-neutral-950">{value}</p>
      <p className="mt-2 text-sm leading-6 text-neutral-400">{description}</p>
    </div>
  );
}

function TeamMemberCard({ member }: { member: TeamMember }) {
  return (
    <article className="rounded-[26px] border border-neutral-100 bg-white p-4 transition hover:border-orange-500/25 hover:bg-orange-500/[0.055]">
      <div className="mb-4 flex items-start justify-between gap-4">
        <div className="flex items-center gap-3">
          <span className="flex h-11 w-11 items-center justify-center rounded-2xl border border-orange-500/20 bg-orange-500/10 text-[#ff5a3d]">
            <Users className="h-5 w-5" />
          </span>
          <div>
            <h3 className="text-sm font-black text-neutral-950">{member.name}</h3>
            <p className="mt-1 text-xs text-neutral-400">{member.email}</p>
          </div>
        </div>

        <span
          className={`rounded-full border px-2.5 py-1 text-[11px] font-bold capitalize ${getRoleStyles(
            member.role,
          )}`}
        >
          {member.role}
        </span>
      </div>

      <div className="grid gap-3 sm:grid-cols-2">
        <div className="rounded-2xl border border-neutral-100 bg-neutral-50 p-3">
          <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-neutral-400">
            Status
          </p>
          <p className="mt-2 text-sm font-bold text-neutral-950">{member.status}</p>
        </div>

        <div className="rounded-2xl border border-neutral-100 bg-neutral-50 p-3">
          <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-neutral-400">
            Access
          </p>
          <p className="mt-2 text-sm font-bold text-neutral-950">{member.access}</p>
        </div>
      </div>
    </article>
  );
}

function AgentPermissionCard({ permission }: { permission: AgentPermission }) {
  const Icon = permission.icon;
  const isDisabled = permission.status === "disabled";

  return (
    <article className="rounded-[26px] border border-neutral-100 bg-white p-4 transition hover:border-orange-500/25 hover:bg-orange-500/[0.055]">
      <div className="mb-4 flex items-start justify-between gap-4">
        <span className="flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl border border-orange-500/20 bg-orange-500/10 text-[#ff5a3d]">
          <Icon className="h-5 w-5" />
        </span>

        <button
          type="button"
          aria-label={`${permission.agent} permission state`}
          className={`flex h-10 w-10 items-center justify-center rounded-2xl border transition ${
            isDisabled
              ? "border-red-200 bg-red-50 text-red-700"
              : "border-emerald-200 bg-emerald-50 text-emerald-700 hover:border-orange-500/30 hover:bg-orange-500/10 hover:text-[#ff5a3d]"
          }`}
        >
          <ToggleRight className="h-5 w-5" />
        </button>
      </div>

      <h3 className="text-sm font-black text-neutral-950">{permission.agent}</h3>
      <p className="mt-2 min-h-[72px] text-sm leading-6 text-neutral-400">
        {permission.description}
      </p>

      <span
        className={`mt-4 inline-flex rounded-full border px-2.5 py-1 text-[11px] font-bold capitalize ${getPermissionStyles(
          permission.status,
        )}`}
      >
        {formatStatus(permission.status)}
      </span>
    </article>
  );
}

function IntegrationCard({ integration }: { integration: Integration }) {
  const Icon = integration.icon;

  return (
    <article className="rounded-[26px] border border-neutral-100 bg-white p-4 transition hover:border-orange-500/25 hover:bg-orange-500/[0.055]">
      <div className="mb-4 flex items-start justify-between gap-4">
        <span className="flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl border border-orange-500/20 bg-orange-500/10 text-[#ff5a3d]">
          <Icon className="h-5 w-5" />
        </span>

        <span
          className={`rounded-full border px-2.5 py-1 text-[11px] font-bold capitalize ${getIntegrationStyles(
            integration.status,
          )}`}
        >
          {integration.status}
        </span>
      </div>

      <h3 className="text-sm font-black text-neutral-950">{integration.name}</h3>
      <p className="mt-2 min-h-[72px] text-sm leading-6 text-neutral-400">
        {integration.description}
      </p>

      <button
        type="button"
        className="mt-4 inline-flex items-center gap-2 rounded-2xl border border-neutral-100 bg-neutral-50 px-3 py-2 text-xs font-bold text-neutral-600 transition hover:border-orange-500/30 hover:bg-orange-500/10 hover:text-[#ff5a3d]"
      >
        Configure
        <ArrowRight className="h-3.5 w-3.5" />
      </button>
    </article>
  );
}

function SettingsRuleCard({ rule }: { rule: SettingsRule }) {
  const Icon = rule.icon;

  return (
    <div className="flex items-start gap-3 rounded-2xl border border-neutral-100 bg-white p-4">
      <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl bg-orange-500/10 text-[#ff5a3d]">
        <Icon className="h-5 w-5" />
      </span>

      <div>
        <p className="text-sm font-bold text-neutral-950">{rule.title}</p>
        <p className="mt-1 text-sm leading-6 text-neutral-400">
          {rule.description}
        </p>
      </div>
    </div>
  );
}

export default function SettingsPage() {
  const approvalRequiredAgents = agentPermissions.filter(
    (permission) => permission.status === "approval_required",
  ).length;

  const connectedIntegrations = integrations.filter(
    (integration) => integration.status === "connected",
  ).length;

  const activeMembers = teamMembers.filter(
    (member) => member.status === "Active",
  ).length;

  return (
    <div className="space-y-6">
      <section className="relative overflow-hidden rounded-[34px] border border-neutral-100 bg-[radial-gradient(circle_at_18%_10%,rgba(255,90,61,0.10),transparent_34%),linear-gradient(135deg,rgba(0,0,0,0.015),rgba(0,0,0,0.0))] p-6 shadow-sm md:p-8 lg:p-10">
        <div className="absolute right-10 top-0 h-72 w-72 rounded-full bg-orange-500/20 blur-3xl" />
        <div className="absolute bottom-0 left-1/3 h-56 w-56 rounded-full bg-orange-900/25 blur-3xl" />

        <div className="relative grid gap-8 xl:grid-cols-[1.1fr_0.9fr] xl:items-center">
          <div>
            <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-orange-400/25 bg-orange-500/10 px-4 py-2 text-xs font-bold uppercase tracking-[0.18em] text-[#ff5a3d]">
              <Settings className="h-4 w-4" />
              Workspace Settings
            </div>

            <h1 className="max-w-5xl text-4xl font-black tracking-tight text-neutral-950 md:text-5xl lg:text-6xl">
              Configure Workspace, Team, Roles, Agents, And Integrations.
            </h1>

            <p className="mt-5 max-w-3xl text-base leading-8 text-neutral-500 md:text-lg">
              Manage workspace identity, team roles, agent permissions,
              integration access, privacy behavior, notification preferences,
              and SaaS-safe security rules for William/Jarvis.
            </p>

            <div className="mt-7 flex flex-wrap gap-3">
              <span className="inline-flex items-center gap-2 rounded-2xl border border-emerald-200 bg-emerald-50 px-4 py-2 text-sm font-bold text-emerald-700">
                <BadgeCheck className="h-4 w-4" />
                {activeMembers} Active Members
              </span>

              <span className="inline-flex items-center gap-2 rounded-2xl border border-yellow-200 bg-yellow-50 px-4 py-2 text-sm font-bold text-yellow-700">
                <ShieldCheck className="h-4 w-4" />
                {approvalRequiredAgents} Approval-Gated Agents
              </span>

              <span className="inline-flex items-center gap-2 rounded-2xl border border-blue-200 bg-blue-50 px-4 py-2 text-sm font-bold text-blue-700">
                <PlugZap className="h-4 w-4" />
                {connectedIntegrations} Connected Integration
              </span>
            </div>
          </div>

          <div className="rounded-[30px] border border-neutral-100 bg-neutral-50 p-5 shadow-sm backdrop-blur-xl">
            <div className="mb-5 flex items-center justify-between">
              <div>
                <p className="text-sm font-bold text-neutral-950">
                  Workspace Identity
                </p>
                <p className="mt-1 text-xs text-neutral-400">
                  Current workspace preview
                </p>
              </div>

              <span className="flex h-12 w-12 items-center justify-center rounded-2xl bg-orange-500 text-black shadow-[0_0_40px_rgba(249,115,22,0.35)]">
                <BriefcaseBusiness className="h-6 w-6" />
              </span>
            </div>

            <div className="space-y-4">
              <label className="block">
                <span className="mb-2 block text-xs font-bold uppercase tracking-[0.16em] text-neutral-400">
                  Workspace Name
                </span>
                <input
                  className="w-full rounded-2xl border border-neutral-100 bg-neutral-50 px-4 py-3 text-sm font-semibold text-neutral-700 outline-none transition placeholder:text-neutral-400 focus:border-orange-500/40 focus:ring-4 focus:ring-orange-500/10"
                  defaultValue="Digital Promotix"
                  type="text"
                />
              </label>

              <label className="block">
                <span className="mb-2 block text-xs font-bold uppercase tracking-[0.16em] text-neutral-400">
                  Workspace Slug
                </span>
                <input
                  className="w-full rounded-2xl border border-neutral-100 bg-neutral-50 px-4 py-3 text-sm font-semibold text-neutral-700 outline-none transition placeholder:text-neutral-400 focus:border-orange-500/40 focus:ring-4 focus:ring-orange-500/10"
                  defaultValue="digital-promotix"
                  type="text"
                />
              </label>

              <label className="block">
                <span className="mb-2 block text-xs font-bold uppercase tracking-[0.16em] text-neutral-400">
                  Default Reply Style
                </span>
                <select className="w-full rounded-2xl border border-neutral-100 bg-neutral-50 px-4 py-3 text-sm font-semibold text-neutral-700 outline-none transition focus:border-orange-500/40 focus:ring-4 focus:ring-orange-500/10">
                  <option>Professional and direct</option>
                  <option>Friendly and detailed</option>
                  <option>Short and technical</option>
                  <option>Executive summary first</option>
                </select>
              </label>

              <button
                type="button"
                className="inline-flex w-full items-center justify-center gap-2 rounded-2xl bg-orange-500 px-4 py-3 text-sm font-black text-black transition hover:bg-orange-400"
              >
                <Save className="h-4 w-4" />
                Save Workspace Settings
              </button>
            </div>

            <div className="mt-5 rounded-2xl border border-emerald-200 bg-emerald-50 p-4">
              <div className="flex items-center gap-3">
                <span className="h-2.5 w-2.5 rounded-full bg-emerald-400 shadow-[0_0_18px_rgba(52,211,153,0.9)]" />
                <p className="text-sm font-bold text-emerald-700">
                  Workspace isolation active
                </p>
              </div>
              <p className="mt-2 text-sm leading-6 text-neutral-500">
                Settings are designed to stay scoped by workspace_id, role, and
                current user permissions.
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
          <div className="rounded-[32px] border border-neutral-100 bg-white p-5 shadow-sm md:p-6">
            <div className="mb-6 flex items-center justify-between">
              <div>
                <p className="text-sm font-bold text-[#ff5a3d]">
                  Settings Menu
                </p>
                <h2 className="mt-2 text-2xl font-black text-neutral-950">
                  Control Areas
                </h2>
              </div>
              <SlidersHorizontal className="h-5 w-5 text-[#ff5a3d]" />
            </div>

            <div className="space-y-3">
              {[
                "Workspace",
                "Team Members",
                "Roles",
                "Agent Permissions",
                "Integrations",
                "Privacy",
                "Notifications",
                "Security",
              ].map((item, index) => (
                <button
                  key={item}
                  type="button"
                  className={`flex w-full items-center justify-between rounded-2xl border px-4 py-3 text-sm font-bold transition ${
                    index === 0
                      ? "border-orange-500/25 bg-orange-500/10 text-[#ff5a3d]"
                      : "border-neutral-100 bg-white text-neutral-500 hover:border-orange-500/25 hover:bg-orange-500/10 hover:text-[#ff5a3d]"
                  }`}
                >
                  {item}
                  <CircleDot className="h-3.5 w-3.5" />
                </button>
              ))}
            </div>
          </div>

          <div className="rounded-[32px] border border-neutral-100 bg-neutral-50 p-5 md:p-6">
            <div className="mb-5 flex items-center justify-between">
              <div>
                <p className="text-sm font-bold text-[#ff5a3d]">
                  Settings Rules
                </p>
                <h2 className="mt-2 text-xl font-black text-neutral-950">
                  SaaS Safety
                </h2>
              </div>
              <ShieldCheck className="h-5 w-5 text-[#ff5a3d]" />
            </div>

            <div className="space-y-3">
              {settingsRules.map((rule) => (
                <SettingsRuleCard key={rule.title} rule={rule} />
              ))}
            </div>
          </div>

          <div className="rounded-[32px] border border-orange-500/15 bg-orange-500/[0.07] p-5 md:p-6">
            <div className="mb-4 flex items-center gap-3">
              <Zap className="h-5 w-5 text-[#ff5a3d]" />
              <p className="text-sm font-black uppercase tracking-[0.16em] text-[#ff5a3d]">
                Next Backend Hook
              </p>
            </div>
            <p className="text-sm leading-7 text-neutral-500">
              Later, connect this page to auth routes, workspace models, team
              roles, agent permissions, integration secrets, audit logs, and
              subscription access control.
            </p>
          </div>
        </aside>

        <main className="space-y-6">
          <section className="rounded-[32px] border border-neutral-100 bg-white p-5 shadow-sm md:p-6">
            <div className="mb-6 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
              <div>
                <p className="text-sm font-bold text-[#ff5a3d]">Team</p>
                <h2 className="mt-2 text-2xl font-black tracking-tight text-neutral-950">
                  Members, Roles, And Access
                </h2>
              </div>

              <button
                type="button"
                className="inline-flex items-center gap-2 rounded-2xl bg-orange-500 px-3 py-2 text-xs font-black text-black transition hover:bg-orange-400"
              >
                <Users className="h-3.5 w-3.5" />
                Invite Member
              </button>
            </div>

            <div className="grid gap-4 xl:grid-cols-2">
              {teamMembers.map((member) => (
                <TeamMemberCard key={member.email} member={member} />
              ))}
            </div>
          </section>

          <section className="rounded-[32px] border border-neutral-100 bg-white p-5 shadow-sm md:p-6">
            <div className="mb-6 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
              <div>
                <p className="text-sm font-bold text-[#ff5a3d]">
                  Agent Permissions
                </p>
                <h2 className="mt-2 text-2xl font-black tracking-tight text-neutral-950">
                  Control What Agents Can Do
                </h2>
              </div>

              <span className="inline-flex items-center gap-2 rounded-full border border-yellow-200 bg-yellow-50 px-3 py-2 text-xs font-bold text-yellow-700">
                <KeyRound className="h-3.5 w-3.5" />
                Approval Rules Active
              </span>
            </div>

            <div className="grid gap-4 lg:grid-cols-2">
              {agentPermissions.map((permission) => (
                <AgentPermissionCard
                  key={permission.agent}
                  permission={permission}
                />
              ))}
            </div>
          </section>

          <VoiceControlSettings />

          <TrustedVoiceProfiles />

          <section className="rounded-[32px] border border-neutral-100 bg-white p-5 shadow-sm md:p-6">
            <div className="mb-6 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
              <div>
                <p className="text-sm font-bold text-[#ff5a3d]">
                  Integrations
                </p>
                <h2 className="mt-2 text-2xl font-black tracking-tight text-neutral-950">
                  Connect Backend, Apps, And Services
                </h2>
              </div>

              <button
                type="button"
                className="inline-flex items-center gap-2 rounded-2xl border border-neutral-100 bg-neutral-50 px-3 py-2 text-xs font-bold text-neutral-600 transition hover:border-orange-500/30 hover:bg-orange-500/10 hover:text-[#ff5a3d]"
              >
                <RefreshCcw className="h-3.5 w-3.5" />
                Refresh
              </button>
            </div>

            <div className="grid gap-4 lg:grid-cols-2">
              {integrations.map((integration) => (
                <IntegrationCard
                  key={integration.name}
                  integration={integration}
                />
              ))}
            </div>
          </section>

          <section className="rounded-[32px] border border-neutral-100 bg-neutral-50 p-5 md:p-6">
            <div className="grid gap-5 lg:grid-cols-3">
              <div className="rounded-[26px] border border-neutral-100 bg-white p-5">
                <Bell className="mb-4 h-6 w-6 text-[#ff5a3d]" />
                <p className="text-sm font-bold text-neutral-950">Notifications</p>
                <p className="mt-2 text-sm leading-6 text-neutral-400">
                  Configure task alerts, security approvals, billing updates,
                  and verification reports.
                </p>
              </div>

              <div className="rounded-[26px] border border-neutral-100 bg-white p-5">
                <Palette className="mb-4 h-6 w-6 text-[#ff5a3d]" />
                <p className="text-sm font-bold text-neutral-950">
                  Brand Preferences
                </p>
                <p className="mt-2 text-sm leading-6 text-neutral-400">
                  Store workspace theme, tone, content style, and dashboard
                  appearance preferences.
                </p>
              </div>

              <div className="rounded-[26px] border border-neutral-100 bg-white p-5">
                <Layers3 className="mb-4 h-6 w-6 text-[#ff5a3d]" />
                <p className="text-sm font-bold text-neutral-950">Module Settings</p>
                <p className="mt-2 text-sm leading-6 text-neutral-400">
                  Future settings can enable or restrict modules per plan, role,
                  and workspace policy.
                </p>
              </div>
            </div>
          </section>
        </main>
      </section>

      <section className="rounded-[32px] border border-red-400/15 bg-red-500/[0.06] p-5 md:p-6">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <div className="mb-3 flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-red-700" />
              <p className="text-sm font-black uppercase tracking-[0.16em] text-red-700">
                Settings Safety Reminder
              </p>
            </div>
            <p className="max-w-4xl text-sm leading-7 text-neutral-500">
              This frontend page does not actually save workspace, team, agent,
              billing, integration, or security settings yet. Real changes must
              be connected later through protected backend routes, role checks,
              audit logs, and Security Agent approval where needed.
            </p>
          </div>

          <button
            type="button"
            className="inline-flex items-center justify-center gap-2 rounded-2xl border border-red-200 bg-red-50 px-4 py-3 text-sm font-bold text-red-700 transition hover:bg-red-500/15"
          >
            <Lock className="h-4 w-4" />
            Review Protected Settings
          </button>
        </div>
      </section>
    </div>
  );
}
