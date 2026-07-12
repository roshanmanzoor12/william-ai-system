"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  Activity,
  BarChart3,
  Bell,
  Bot,
  Brain,
  BriefcaseBusiness,
  CalendarDays,
  ChevronRight,
  CreditCard,
  FileClock,
  Fingerprint,
  Gauge,
  Headphones,
  Home,
  KeyRound,
  Layers3,
  Lock,
  MemoryStick,
  MessageSquareText,
  Network,
  Orbit,
  RadioTower,
  Search,
  Settings,
  ShieldCheck,
  ShieldEllipsis,
  Sparkles,
  Sun,
  Users,
  WalletCards,
  Workflow,
  Zap,
} from "lucide-react";
import { OfflineBanner } from "@/components/state/OfflineBanner";
import { readSession, type SessionData } from "@/lib/auth";

type DashboardLayoutProps = {
  children: React.ReactNode;
};

type NavItem = {
  label: string;
  href: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: string;
};

const primaryNavItems: NavItem[] = [
  { label: "AI Console", href: "/", icon: Home },
  { label: "Dashboard", href: "/dashboard", icon: Gauge },
  { label: "Agents", href: "/agents", icon: Bot },
  { label: "Tasks", href: "/tasks", icon: FileClock },
  { label: "Memory", href: "/memory", icon: Brain },
  { label: "Security", href: "/security", icon: ShieldCheck, badge: "Live" },
  { label: "Workflows", href: "/workflows", icon: Workflow },
  { label: "Analytics", href: "/analytics", icon: BarChart3 },
];

const businessNavItems: NavItem[] = [
  { label: "CRM", href: "/crm", icon: Users },
  { label: "Calls", href: "/calls", icon: Headphones },
  { label: "Creator", href: "/creator", icon: Sparkles },
  { label: "Finance", href: "/finance", icon: WalletCards },
  { label: "Billing", href: "/billing", icon: CreditCard },
  { label: "Permissions", href: "/agent-permissions", icon: KeyRound },
  { label: "Settings", href: "/settings", icon: Settings },
];

// Platform-admin only -- shown solely when session.is_platform_admin is
// true (a real, DB-driven flag read at login, see lib/auth.ts). This is a
// UI convenience only: every /api/v1/admin/* route re-checks the same flag
// server-side regardless of whether this link is visible.
const adminNavItems: NavItem[] = [
  { label: "Admin Control Center", href: "/admin", icon: ShieldEllipsis },
];

const agentStatusCards = [
  { label: "Master Agent", value: "Routing", icon: Orbit },
  { label: "Security Agent", value: "Guarded", icon: Fingerprint },
  { label: "Memory Agent", value: "Isolated", icon: MemoryStick },
];

function SidebarNavGroup({
  title,
  items,
}: {
  title: string;
  items: NavItem[];
}) {
  return (
    <div className="space-y-2">
      <p className="px-3 text-[10px] font-bold uppercase tracking-[0.22em] text-zinc-400">
        {title}
      </p>

      <nav className="space-y-1">
        {items.map((item) => {
          const Icon = item.icon;

          return (
            <Link
              key={item.href}
              href={item.href}
              className="group flex items-center justify-between rounded-2xl border border-transparent px-3 py-2.5 text-sm text-zinc-500 transition duration-200 hover:border-orange-200 hover:bg-orange-50 hover:text-zinc-950"
            >
              <span className="flex items-center gap-3">
                <span className="flex h-9 w-9 items-center justify-center rounded-xl border border-zinc-100 bg-white text-zinc-400 shadow-sm transition duration-200 group-hover:border-orange-200 group-hover:bg-orange-100 group-hover:text-orange-600">
                  <Icon className="h-4 w-4" />
                </span>

                <span className="font-semibold">{item.label}</span>
              </span>

              {item.badge ? (
                <span className="rounded-full border border-orange-200 bg-orange-50 px-2 py-0.5 text-[10px] font-black uppercase tracking-wide text-orange-600">
                  {item.badge}
                </span>
              ) : (
                <ChevronRight className="h-3.5 w-3.5 text-zinc-300 transition duration-200 group-hover:text-orange-500" />
              )}
            </Link>
          );
        })}
      </nav>
    </div>
  );
}

function SystemMetric({
  label,
  value,
  icon: Icon,
}: {
  label: string;
  value: string;
  icon: React.ComponentType<{ className?: string }>;
}) {
  return (
    <div className="william-card-soft p-3">
      <div className="mb-2 flex items-center justify-between gap-3">
        <span className="text-[11px] font-semibold text-zinc-500">{label}</span>
        <span className="flex h-8 w-8 items-center justify-center rounded-xl border border-orange-100 bg-orange-50 text-orange-600">
          <Icon className="h-4 w-4" />
        </span>
      </div>
      <p className="text-sm font-bold text-zinc-950">{value}</p>
    </div>
  );
}

export default function DashboardLayout({ children }: DashboardLayoutProps) {
  const [session, setSession] = useState<SessionData | null>(null);

  useEffect(() => {
    setSession(readSession());
  }, []);

  return (
    <div className="william-app-shell">
      <OfflineBanner />
      <div className="william-dashboard-frame">
        <div className="flex min-h-[calc(100vh-48px)]">
          <aside className="hidden w-[292px] shrink-0 border-r border-zinc-100 bg-white/70 px-5 py-5 backdrop-blur-2xl xl:block">
            <div className="mb-7 rounded-[28px] border border-white bg-white p-4 shadow-[0_18px_55px_rgba(15,23,42,0.06)]">
              <Link href="/" className="flex items-center gap-3">
                <div className="relative flex h-12 w-12 items-center justify-center rounded-2xl bg-gradient-to-br from-orange-400 to-orange-600 text-white shadow-[0_18px_36px_rgba(255,107,53,0.28)]">
                  <Zap className="h-6 w-6" />
                  <span className="absolute -right-1 -top-1 h-3.5 w-3.5 rounded-full border-2 border-white bg-emerald-500" />
                </div>

                <div>
                  <p className="text-base font-black tracking-tight text-zinc-950">
                    William / Jarvis
                  </p>
                  <p className="text-xs font-medium text-zinc-500">
                    Digital Promotix AI SaaS
                  </p>
                </div>
              </Link>

              <div className="mt-5 rounded-2xl border border-orange-100 bg-orange-50 p-3">
                <div className="mb-2 flex items-center justify-between">
                  <span className="text-[11px] font-black uppercase tracking-[0.16em] text-orange-600">
                    Workspace
                  </span>
                  <span className="rounded-full bg-emerald-50 px-2 py-0.5 text-[10px] font-black text-emerald-700">
                    Active
                  </span>
                </div>
                <p className="text-sm font-bold text-zinc-950">
                  Default Workspace
                </p>
                <p className="mt-1 text-xs text-zinc-500">
                  SaaS isolated context ready
                </p>
              </div>
            </div>

            <div className="custom-scrollbar flex max-h-[calc(100vh-220px)] flex-col gap-7 overflow-y-auto pr-1">
              <SidebarNavGroup title="Command Center" items={primaryNavItems} />
              <SidebarNavGroup
                title="Business Stack"
                items={businessNavItems}
              />
              {session?.is_platform_admin ? (
                <SidebarNavGroup title="Platform" items={adminNavItems} />
              ) : null}

              <div className="rounded-[26px] border border-zinc-100 bg-white p-4 shadow-[0_18px_55px_rgba(15,23,42,0.05)]">
                <div className="mb-4 flex items-center justify-between">
                  <p className="text-xs font-black uppercase tracking-[0.18em] text-zinc-400">
                    Agent Pulse
                  </p>
                  <Activity className="h-4 w-4 text-orange-500" />
                </div>

                <div className="space-y-3">
                  {agentStatusCards.map((card) => {
                    const Icon = card.icon;

                    return (
                      <div
                        key={card.label}
                        className="flex items-center justify-between rounded-2xl border border-zinc-100 bg-zinc-50 px-3 py-3"
                      >
                        <div className="flex items-center gap-3">
                          <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-orange-50 text-orange-600">
                            <Icon className="h-4 w-4" />
                          </span>
                          <div>
                            <p className="text-xs font-bold text-zinc-900">
                              {card.label}
                            </p>
                            <p className="text-[11px] text-zinc-500">
                              {card.value}
                            </p>
                          </div>
                        </div>
                        <span className="william-status-dot" />
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          </aside>

          <main className="flex min-w-0 flex-1 flex-col">
            <header className="sticky top-0 z-30 border-b border-zinc-100 bg-white/76 px-4 py-4 backdrop-blur-2xl sm:px-6 lg:px-8">
              <div className="mx-auto flex max-w-[1600px] items-center justify-between gap-4">
                <div className="flex min-w-0 items-center gap-4">
                  <Link
                    href="/"
                    className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl border border-orange-100 bg-orange-50 text-orange-600 xl:hidden"
                    aria-label="William dashboard home"
                  >
                    <Zap className="h-5 w-5" />
                  </Link>

                  <div className="hidden min-w-0 rounded-2xl border border-zinc-100 bg-white px-4 py-2 shadow-sm md:block">
                    <div className="flex items-center gap-3">
                      <Search className="h-4 w-4 text-zinc-400" />
                      <span className="text-sm text-zinc-400">
                        Search agents, tasks, approvals, memories...
                      </span>
                    </div>
                  </div>

                  <div className="min-w-0 md:hidden">
                    <p className="truncate text-sm font-black text-zinc-950">
                      William / Jarvis
                    </p>
                    <p className="truncate text-xs text-zinc-500">
                      Multi-agent dashboard
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2 sm:gap-3">
                  <div className="hidden items-center gap-2 rounded-2xl border border-emerald-100 bg-emerald-50 px-3 py-2 text-xs font-bold text-emerald-700 lg:flex">
                    <Lock className="h-3.5 w-3.5" />
                    Security Guarded
                  </div>

                  <div className="hidden items-center gap-2 rounded-2xl border border-orange-100 bg-orange-50 px-3 py-2 text-xs font-bold text-orange-600 lg:flex">
                    <Network className="h-3.5 w-3.5" />
                    Workspace Isolated
                  </div>

                  <button
                    type="button"
                    className="flex h-11 w-11 items-center justify-center rounded-2xl border border-zinc-100 bg-white text-zinc-500 shadow-sm transition hover:border-orange-200 hover:bg-orange-50 hover:text-orange-600"
                    aria-label="Calendar"
                  >
                    <CalendarDays className="h-4 w-4" />
                  </button>

                  <button
                    type="button"
                    className="relative flex h-11 w-11 items-center justify-center rounded-2xl border border-zinc-100 bg-white text-zinc-500 shadow-sm transition hover:border-orange-200 hover:bg-orange-50 hover:text-orange-600"
                    aria-label="Notifications"
                  >
                    <Bell className="h-4 w-4" />
                    <span className="absolute right-2.5 top-2.5 h-2 w-2 rounded-full bg-orange-500 shadow-[0_0_12px_rgba(255,107,53,0.9)]" />
                  </button>

                  <button
                    type="button"
                    className="hidden h-11 w-11 items-center justify-center rounded-2xl border border-zinc-100 bg-white text-zinc-500 shadow-sm transition hover:border-orange-200 hover:bg-orange-50 hover:text-orange-600 sm:flex"
                    aria-label="Theme"
                  >
                    <Sun className="h-4 w-4" />
                  </button>

                  <Link
                    href="/settings"
                    className="flex items-center gap-3 rounded-2xl border border-zinc-100 bg-white py-1.5 pl-1.5 pr-3 shadow-sm transition hover:border-orange-200 hover:bg-orange-50"
                  >
                    <span className="flex h-8 w-8 items-center justify-center rounded-xl bg-gradient-to-br from-orange-400 to-orange-600 text-xs font-black text-white">
                      DP
                    </span>
                    <span className="hidden text-left sm:block">
                      <span className="block text-xs font-black text-zinc-950">
                        Admin
                      </span>
                      <span className="block text-[11px] text-zinc-500">
                        Owner Role
                      </span>
                    </span>
                  </Link>
                </div>
              </div>
            </header>

            <section className="border-b border-zinc-100 bg-white/40 px-4 py-4 sm:px-6 lg:px-8">
              <div className="mx-auto grid max-w-[1600px] grid-cols-1 gap-3 md:grid-cols-3">
                <SystemMetric
                  label="Security Agent"
                  value="Risk checks enabled"
                  icon={ShieldCheck}
                />
                <SystemMetric
                  label="Master Routing"
                  value="Registry compatible"
                  icon={Layers3}
                />
                <SystemMetric
                  label="Memory Layer"
                  value="Workspace isolated"
                  icon={MessageSquareText}
                />
              </div>
            </section>

            <div className="flex-1 px-4 py-6 sm:px-6 lg:px-8">
              <div className="mx-auto max-w-[1600px]">
                <div className="rounded-[32px] border border-white bg-white/70 p-3 shadow-[0_30px_90px_rgba(15,23,42,0.08)] backdrop-blur-xl sm:p-4 lg:p-5">
                  <div className="rounded-[26px] border border-zinc-100 bg-[#fafafa] p-4 shadow-inner sm:p-6 lg:p-8">
                    {children}
                  </div>
                </div>
              </div>
            </div>

            <footer className="border-t border-zinc-100 bg-white/55 px-4 py-4 sm:px-6 lg:px-8">
              <div className="mx-auto flex max-w-[1600px] flex-col gap-3 text-xs text-zinc-500 md:flex-row md:items-center md:justify-between">
                <div className="flex flex-wrap items-center gap-3">
                  <span className="inline-flex items-center gap-2">
                    <span className="h-2 w-2 rounded-full bg-emerald-500" />
                    SaaS isolation active
                  </span>
                  <span className="hidden h-1 w-1 rounded-full bg-zinc-300 md:inline-flex" />
                  <span>Security Agent approval flow ready</span>
                  <span className="hidden h-1 w-1 rounded-full bg-zinc-300 md:inline-flex" />
                  <span>Verification payload compatible</span>
                </div>

                <div className="flex items-center gap-2">
                  <RadioTower className="h-3.5 w-3.5 text-orange-500" />
                  <span>William / Jarvis Dashboard v1.0</span>
                </div>
              </div>
            </footer>
          </main>
        </div>
      </div>
    </div>
  );
}
