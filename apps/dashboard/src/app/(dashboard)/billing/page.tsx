"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { SessionData, UserPlan, UserRole, readSession } from "@/lib/auth";
import { EmptyState } from "@/components/state/EmptyState";
import { ErrorState } from "@/components/state/ErrorState";
import { ForbiddenState } from "@/components/state/ForbiddenState";
import { LoadingState } from "@/components/state/LoadingState";

type ApiMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

type RoleName = UserRole;

type SubscriptionPlan = UserPlan;

// Matches apps/api/routes/billing.py's real enums/dataclasses exactly
// (confirmed by reading the source). The old BillingStatus ("canceled",
// "incomplete", "restricted") didn't match the backend's real
// SubscriptionStatus at all ("cancelled" spelled differently, "inactive"
// instead of "incomplete"/"restricted").
type BillingStatus =
  | "active"
  | "trialing"
  | "past_due"
  | "cancelled"
  | "inactive";
type BillingInterval = "monthly" | "yearly";
type InvoiceStatus = "draft" | "open" | "paid" | "void" | "uncollectible";
type UsageMetricKey =
  | "tasks"
  | "agent_runs"
  | "memory_records"
  | "workflow_runs"
  | "webhooks"
  | "files"
  | "storage_mb"
  | "api_calls"
  | "team_members";

type BillingRisk = "low" | "medium" | "high" | "critical";

// apps/api/routes/security.py's real POST /security/decide outcome values.
type SecurityDecisionOutcome = "approved" | "denied" | "requires_approval";

type ConsoleUser = {
  user_id: string;
  workspace_id: string;
  name: string;
  email: string;
  role: RoleName;
  plan: SubscriptionPlan;
  permissions: string[];
  plan_features: string[];
};

// Real PlanRecord from GET /billing/plans -- price_cents/currency/interval
// replace the old fabricated price_label string; features is a flat list
// of included feature keys (the backend has no "excluded feature" concept
// to show a struck-out comparison against).
type PlanRecord = {
  id: string;
  name: string;
  plan: SubscriptionPlan;
  price_cents: number;
  currency: string;
  interval: BillingInterval;
  features: string[];
  limits: Record<string, number>;
  recommended: boolean;
  active: boolean;
};

// Real UsageRecord from GET /billing/usage -- no "label"/"unit" display
// strings exist on the backend (those were invented); `metric` is the
// real enum key, formatted for display via formatMetricLabel() below.
type UsageRecord = {
  id: string;
  user_id: string;
  workspace_id: string;
  metric: UsageMetricKey;
  used: number;
  limit: number;
  period_start: string;
  period_end: string | null;
  updated_at: string;
};

type SubscriptionRecord = {
  id: string;
  user_id: string;
  workspace_id: string;
  plan: SubscriptionPlan;
  status: BillingStatus;
  interval: BillingInterval;
  currency: string;
  current_period_start: string;
  current_period_end: string | null;
  cancel_at_period_end: boolean;
  provider: string;
  created_at: string;
  updated_at: string;
  cancelled_at: string | null;
};

type InvoiceRecord = {
  id: string;
  user_id: string;
  workspace_id: string;
  subscription_id: string | null;
  invoice_number: string;
  status: InvoiceStatus;
  currency: string;
  subtotal_cents: number;
  tax_cents: number;
  total_cents: number;
  hosted_invoice_url: string | null;
  invoice_pdf_url: string | null;
  due_at: string | null;
  paid_at: string | null;
  created_at: string;
};

// The real POST /security/decide response's `data.decision` shape.
type SecurityDecision = {
  outcome: SecurityDecisionOutcome;
  risk_level: BillingRisk;
  decision_mode: string;
  reason: string;
  action: string;
  category: string;
  requires_approval: boolean;
  approval_id?: string;
};

// The `verification` field every apps/api/routes/billing.py mutation
// response already includes -- prepared server-side, not fabricated
// client-side like the old VerificationPayload/MemoryPayload/
// AuditEventPayload types were.
type VerificationResult = Record<string, unknown>;

type ApiClientOptions = {
  method?: ApiMethod;
  body?: unknown;
  headers?: Record<string, string>;
};

const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL?.replace(/\/$/, "") || "";

const DEFAULT_USER: ConsoleUser = {
  user_id: "local_user_demo",
  workspace_id: "local_workspace_demo",
  name: "Digital Promotix Owner",
  email: "owner@example.test",
  role: "owner",
  plan: "enterprise",
  permissions: [
    "dashboard:billing:read",
    "dashboard:billing:write",
    "billing:usage:read",
    "billing:plan:change",
    "billing:subscription:cancel",
    "billing:portal:open",
    "agent:security_agent:access",
    "agent:verification_agent:access",
    "agent:memory_agent:access",
    "security:review:sensitive_action",
    "audit:write",
    "memory:write",
    "verification:prepare",
  ],
  plan_features: [
    "billing_dashboard",
    "usage_metering",
    "subscription_management",
    "security_agent_review",
    "verification_payloads",
    "memory_context",
    "audit_logs",
    "multi_agent_orchestration",
    "workflow_automation",
    "call_agent",
    "creator_agent",
    "finance_agent",
  ],
};

const USAGE_METRIC_LABELS: Record<UsageMetricKey, string> = {
  tasks: "Agent Tasks",
  agent_runs: "Agent Runs",
  memory_records: "Memory Records",
  workflow_runs: "Workflow Runs",
  webhooks: "Webhooks",
  files: "Files",
  storage_mb: "Storage (MB)",
  api_calls: "API Calls",
  team_members: "Team Members",
};

function hasPermission(user: ConsoleUser, permission: string): boolean {
  return user.permissions.includes(permission);
}

function hasPlanFeature(user: ConsoleUser, feature: string): boolean {
  return user.plan_features.includes(feature);
}

function sanitizeError(error: unknown): string {
  if (error instanceof Error && error.message) {
    if (
      /token|secret|password|key|authorization|credential|card|payment/i.test(
        error.message,
      )
    ) {
      return "Request failed safely. Sensitive billing details were hidden.";
    }

    return error.message;
  }

  return "Request failed safely. Please try again.";
}

function formatLabel(value: string): string {
  return value
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function getPlanRank(plan: SubscriptionPlan): number {
  const ranks: Record<SubscriptionPlan, number> = {
    free: 0,
    starter: 1,
    pro: 2,
    business: 3,
    enterprise: 4,
  };

  return ranks[plan];
}

type BillingActionType =
  | "upgrade_plan"
  | "downgrade_plan"
  | "cancel_subscription"
  | "reactivate_subscription"
  | "open_billing_portal";

function detectBillingRisk(
  actionType: BillingActionType,
  currentPlan: SubscriptionPlan,
  targetPlan?: SubscriptionPlan,
): BillingRisk {
  if (actionType === "cancel_subscription") return "critical";
  if (actionType === "downgrade_plan") return "high";

  if (actionType === "upgrade_plan" && targetPlan) {
    return getPlanRank(targetPlan) > getPlanRank(currentPlan)
      ? "high"
      : "medium";
  }

  if (actionType === "open_billing_portal") return "medium";
  return "low";
}

function getStatusBadgeClass(status: BillingStatus): string {
  switch (status) {
    case "active":
      return "border-emerald-400/40 bg-emerald-400/10 text-emerald-100";
    case "trialing":
      return "border-cyan-400/40 bg-cyan-400/10 text-cyan-100";
    case "past_due":
      return "border-orange-400/40 bg-orange-400/10 text-orange-100";
    case "cancelled":
    case "inactive":
      return "border-red-400/40 bg-red-400/10 text-red-100";
    default:
      return "border-slate-400/30 bg-slate-400/10 text-slate-200";
  }
}

function getDecisionBadgeClass(outcome: SecurityDecisionOutcome): string {
  switch (outcome) {
    case "approved":
      return "border-emerald-400/40 bg-emerald-400/10 text-emerald-100";
    case "requires_approval":
      return "border-orange-400/40 bg-orange-400/10 text-orange-100";
    case "denied":
      return "border-red-400/40 bg-red-400/10 text-red-100";
    default:
      return "border-slate-400/30 bg-slate-400/10 text-slate-200";
  }
}

function getUsagePercent(record: UsageRecord): number {
  if (record.limit <= 0) return 0;
  return Math.min(100, Math.round((record.used / record.limit) * 100));
}

function formatLimit(limit: number): string {
  return limit.toLocaleString();
}

function formatPriceCents(cents: number, currency: string): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: currency.toUpperCase(),
    maximumFractionDigits: 0,
  }).format(cents / 100);
}

async function apiRequest<T>(
  path: string,
  options: ApiClientOptions = {},
): Promise<T> {
  const activeSession = readSession();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...options.headers,
  };

  if (activeSession?.accessToken) {
    headers.Authorization = `Bearer ${activeSession.accessToken}`;
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    method: options.method || "GET",
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
    credentials: "include",
  });

  const contentType = response.headers.get("content-type") || "";
  const payload = contentType.includes("application/json")
    ? await response.json()
    : {
        success: false,
        error: { message: "Server returned a non-JSON response." },
      };

  if (!response.ok) {
    throw new Error(
      payload?.error?.message || payload?.message || "API request failed.",
    );
  }

  return payload as T;
}

/**
 * There is no backend concept of ConsoleUser's `permissions`/
 * `plan_features` capability-flag lists (apps/api/routes/auth.py only
 * grants a fixed set of coarse permission strings to a brand new OWNER --
 * see the "no backend-side static role -> permissions table" note in
 * src/lib/auth.ts). Rather than fabricate a fake-looking granular matrix
 * per role, every real session gets the same full capability lists this
 * page already ships in DEFAULT_USER -- the actual security boundary is
 * apps/api/routes/billing.py's server-side role/plan checks on each
 * endpoint, not these client-side display flags.
 */
function sessionToConsoleUser(session: SessionData): ConsoleUser {
  return {
    user_id: session.user_id,
    workspace_id: session.workspace_id,
    name: session.name,
    email: session.email,
    role: session.role,
    plan: session.plan,
    permissions: DEFAULT_USER.permissions,
    plan_features: DEFAULT_USER.plan_features,
  };
}

function loadSession(): ConsoleUser {
  const activeSession = readSession();

  if (!activeSession) {
    throw new Error("No signed-in session was found.");
  }

  return sessionToConsoleUser(activeSession);
}

// The real envelope every apps/api/routes/billing.py and security.py
// endpoint returns: {ok, message, data, verification, request_id}.
type BackendEnvelope<T> = {
  ok: boolean;
  message: string;
  data: T;
  verification?: Record<string, unknown>;
  request_id?: string;
};

async function loadPlans(): Promise<PlanRecord[]> {
  const response = await apiRequest<
    BackendEnvelope<unknown> & { plans: PlanRecord[] }
  >("/billing/plans");
  if (!response.ok)
    throw new Error(response.message || "Unable to load plans.");
  return response.plans;
}

async function loadSubscription(): Promise<SubscriptionRecord> {
  const response = await apiRequest<
    BackendEnvelope<{
      subscription: SubscriptionRecord;
      limits: Record<string, number>;
    }>
  >("/billing/subscription");

  if (!response.ok) {
    throw new Error(response.message || "Unable to load subscription.");
  }

  return response.data.subscription;
}

async function loadUsage(): Promise<UsageRecord[]> {
  const response =
    await apiRequest<BackendEnvelope<{ plan: string; usage: UsageRecord[] }>>(
      "/billing/usage",
    );
  if (!response.ok)
    throw new Error(response.message || "Unable to load usage.");
  return response.data.usage;
}

/**
 * Real Security Agent gate (POST /security/decide, apps/api/routes/
 * security.py) -- evaluated before any state-changing billing mutation.
 * Replaces the old submitSecurityReview()'s fabricated always-approve
 * fallback and made-up "/api/security/review" endpoint.
 */
async function decideRiskyAction(
  action: string,
  risk: BillingRisk,
  payload: Record<string, unknown>,
): Promise<{
  decision: SecurityDecision;
  verification: Record<string, unknown>;
}> {
  const response = await apiRequest<
    BackendEnvelope<{ decision: SecurityDecision }>
  >("/security/decide", {
    method: "POST",
    body: {
      action,
      category: "billing",
      payload,
      requested_risk_level: risk,
      require_human_for_high_risk: true,
    },
  });

  if (!response.ok)
    throw new Error(response.message || "Security review failed.");
  return {
    decision: response.data.decision,
    verification: response.verification || {},
  };
}

async function updateSubscriptionPlan(plan: SubscriptionPlan): Promise<{
  subscription: SubscriptionRecord;
  verification: Record<string, unknown>;
}> {
  const response = await apiRequest<
    BackendEnvelope<{ subscription: SubscriptionRecord }>
  >("/billing/subscription", {
    method: "PATCH",
    body: { plan },
  });
  if (!response.ok)
    throw new Error(
      response.message || "Unable to update the subscription plan.",
    );
  return {
    subscription: response.data.subscription,
    verification: response.verification || {},
  };
}

async function cancelSubscriptionReal(): Promise<{
  subscription: SubscriptionRecord;
  verification: Record<string, unknown>;
}> {
  const response = await apiRequest<
    BackendEnvelope<{ subscription: SubscriptionRecord }>
  >("/billing/subscription/cancel?cancel_at_period_end=true", {
    method: "POST",
  });
  if (!response.ok)
    throw new Error(response.message || "Unable to cancel the subscription.");
  return {
    subscription: response.data.subscription,
    verification: response.verification || {},
  };
}

async function reactivateSubscriptionReal(): Promise<{
  subscription: SubscriptionRecord;
  verification: Record<string, unknown>;
}> {
  const response = await apiRequest<
    BackendEnvelope<{ subscription: SubscriptionRecord }>
  >("/billing/subscription/reactivate", { method: "POST" });
  if (!response.ok)
    throw new Error(
      response.message || "Unable to reactivate the subscription.",
    );
  return {
    subscription: response.data.subscription,
    verification: response.verification || {},
  };
}

function StatCard(props: {
  label: string;
  value: string | number;
  hint: string;
}) {
  return (
    <div className="rounded-3xl border border-white/10 bg-white/[0.05] p-5 shadow-xl shadow-black/20">
      <p className="text-xs uppercase tracking-[0.25em] text-slate-500">
        {props.label}
      </p>
      <p className="mt-3 text-3xl font-black text-white">{props.value}</p>
      <p className="mt-2 text-xs text-slate-400">{props.hint}</p>
    </div>
  );
}

export default function Page() {
  const router = useRouter();
  const [user, setUser] = useState<ConsoleUser>(DEFAULT_USER);
  const [subscription, setSubscription] = useState<SubscriptionRecord | null>(
    null,
  );
  const [plans, setPlans] = useState<PlanRecord[]>([]);
  const [usage, setUsage] = useState<UsageRecord[]>([]);
  const [selectedPlan, setSelectedPlan] = useState<SubscriptionPlan>("pro");
  const [isBooting, setIsBooting] = useState(true);
  const [isActionRunning, setIsActionRunning] = useState(false);
  const [safeError, setSafeError] = useState<string | null>(null);
  const [lastSecurityDecision, setLastSecurityDecision] =
    useState<SecurityDecision | null>(null);
  const [lastVerification, setLastVerification] =
    useState<VerificationResult | null>(null);

  const canReadBilling = useMemo(() => {
    return (
      hasPermission(user, "dashboard:billing:read") &&
      hasPermission(user, "billing:usage:read") &&
      hasPlanFeature(user, "billing_dashboard")
    );
  }, [user]);

  const canManageBilling = useMemo(() => {
    return (
      hasPermission(user, "dashboard:billing:write") &&
      hasPermission(user, "billing:plan:change") &&
      hasPlanFeature(user, "subscription_management") &&
      ["owner", "admin"].includes(user.role)
    );
  }, [user]);

  const canCancelSubscription = useMemo(() => {
    return (
      hasPermission(user, "billing:subscription:cancel") &&
      hasPlanFeature(user, "subscription_management") &&
      user.role === "owner"
    );
  }, [user]);

  const currentPlanCard = useMemo(() => {
    return plans.find((plan) => plan.plan === subscription?.plan) || null;
  }, [plans, subscription?.plan]);

  const selectedPlanCard = useMemo(() => {
    return plans.find((plan) => plan.plan === selectedPlan) || null;
  }, [plans, selectedPlan]);

  const usageHealth = useMemo(() => {
    if (usage.length === 0) return null;
    const totalPercent = usage.reduce(
      (sum, record) => sum + getUsagePercent(record),
      0,
    );
    return Math.round(totalPercent / usage.length);
  }, [usage]);

  const refreshBillingData = useCallback(async () => {
    const [loadedSubscription, loadedPlans, loadedUsage] = await Promise.all([
      loadSubscription(),
      loadPlans(),
      loadUsage(),
    ]);
    setSubscription(loadedSubscription);
    setPlans(loadedPlans);
    setUsage(loadedUsage);
    setSelectedPlan(loadedSubscription.plan);
  }, []);

  useEffect(() => {
    let isMounted = true;

    async function boot() {
      setIsBooting(true);
      setSafeError(null);

      let sessionUser: ConsoleUser;

      try {
        sessionUser = loadSession();
      } catch {
        if (isMounted) router.replace("/login");
        return;
      }

      if (!isMounted) return;
      setUser(sessionUser);

      try {
        await refreshBillingData();
      } catch (error) {
        // A real session exists but the billing API call itself failed
        // (network issue, backend down) -- show a safe error instead of
        // silently swapping in fake demo data, and without forcing a
        // logout the user's session doesn't actually warrant.
        if (isMounted) setSafeError(sanitizeError(error));
      } finally {
        if (isMounted) setIsBooting(false);
      }
    }

    boot();

    return () => {
      isMounted = false;
    };
  }, [refreshBillingData, router]);

  const handleRetry = useCallback(() => {
    setSafeError(null);
    setIsBooting(true);
    refreshBillingData()
      .catch((error) => setSafeError(sanitizeError(error)))
      .finally(() => setIsBooting(false));
  }, [refreshBillingData]);

  const runBillingAction = useCallback(
    async (actionType: BillingActionType, targetPlan?: SubscriptionPlan) => {
      if (!subscription || isActionRunning) return;

      setSafeError(null);

      if (!canReadBilling) {
        setSafeError("Your role or subscription plan cannot access billing.");
        return;
      }

      if (
        subscription.user_id !== user.user_id ||
        subscription.workspace_id !== user.workspace_id
      ) {
        setSafeError(
          "Cross-user or cross-workspace billing access was blocked safely.",
        );
        return;
      }

      if (
        ["upgrade_plan", "downgrade_plan", "open_billing_portal"].includes(
          actionType,
        ) &&
        !canManageBilling
      ) {
        setSafeError("Your role or plan cannot manage billing actions.");
        return;
      }

      if (actionType === "cancel_subscription" && !canCancelSubscription) {
        setSafeError("Only workspace owners can cancel subscriptions.");
        return;
      }

      // No payment-provider billing-portal integration exists anywhere in
      // apps/api/routes/billing.py -- rather than fabricate a portal URL,
      // this is honestly unavailable until a real provider is wired up.
      if (actionType === "open_billing_portal") {
        setSafeError(
          "The billing portal is not connected to a payment provider yet.",
        );
        return;
      }

      const risk = detectBillingRisk(actionType, subscription.plan, targetPlan);

      setIsActionRunning(true);

      try {
        // Real Security Agent gate (POST /security/decide) before any
        // state-changing subscription mutation.
        const { decision, verification: decisionVerification } =
          await decideRiskyAction(`billing.${actionType}`, risk, {
            subscription_id: subscription.id,
            current_plan: subscription.plan,
            target_plan: targetPlan || subscription.plan,
          });

        setLastSecurityDecision(decision);
        setLastVerification(decisionVerification);

        if (decision.outcome === "denied") {
          setSafeError(`Security Agent denied this action: ${decision.reason}`);
          return;
        }

        if (decision.outcome === "requires_approval") {
          setSafeError(
            `This action requires approval before it runs (approval ${decision.approval_id || "pending"}). ${decision.reason}`,
          );
          return;
        }

        let result: {
          subscription: SubscriptionRecord;
          verification: Record<string, unknown>;
        };

        if (actionType === "upgrade_plan" || actionType === "downgrade_plan") {
          if (!targetPlan) return;
          result = await updateSubscriptionPlan(targetPlan);
          setUser((current) => ({
            ...current,
            plan: result.subscription.plan,
          }));
        } else if (actionType === "cancel_subscription") {
          result = await cancelSubscriptionReal();
        } else {
          result = await reactivateSubscriptionReal();
        }

        setSubscription(result.subscription);
        setSelectedPlan(result.subscription.plan);
        setLastVerification(result.verification);

        // Usage isn't affected by plan/status mutations in the real
        // backend, but refetch it anyway so limits shown match the new
        // plan immediately instead of waiting for the next full reload.
        try {
          setUsage(await loadUsage());
        } catch {
          // Non-fatal -- the subscription mutation itself already succeeded.
        }
      } catch (error) {
        setSafeError(sanitizeError(error));
      } finally {
        setIsActionRunning(false);
      }
    },
    [
      canCancelSubscription,
      canManageBilling,
      canReadBilling,
      isActionRunning,
      subscription,
      user,
    ],
  );

  if (isBooting) {
    return (
      <div className="rounded-[28px] bg-slate-950 px-4 py-6 text-white sm:px-6 lg:px-8">
        <section className="mx-auto flex min-h-[70vh] max-w-7xl items-center justify-center">
          <LoadingState variant="dark" title="Loading billing..." />
        </section>
      </div>
    );
  }

  return (
    <div className="rounded-[28px] bg-[radial-gradient(circle_at_top_left,rgba(34,211,238,0.16),transparent_34%),radial-gradient(circle_at_top_right,rgba(168,85,247,0.18),transparent_30%),#020617] px-4 py-6 text-white sm:px-6 lg:px-8">
      <section className="mx-auto max-w-7xl">
        <div className="mb-6 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-cyan-400/30 bg-cyan-400/10 px-4 py-2 text-sm text-cyan-100">
              <span className="h-2 w-2 rounded-full bg-cyan-300 shadow-[0_0_16px_rgba(103,232,249,0.9)]" />
              Billing / Plans / Subscription Usage
            </div>
            <h1 className="text-3xl font-black tracking-tight sm:text-4xl lg:text-5xl">
              Subscription Control Center
            </h1>
            <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-300 sm:text-base">
              Manage William/Jarvis plans, usage, billing permissions, and
              subscription actions with workspace isolation, Security Agent
              review, audit hooks, Memory Agent context, and Verification Agent
              payloads. No mystery billing goblin energy.
            </p>
          </div>

          <div className="rounded-3xl border border-white/10 bg-white/[0.05] p-4 shadow-xl shadow-black/20">
            <p className="text-xs uppercase tracking-[0.25em] text-slate-400">
              Workspace Scope
            </p>
            <p className="mt-2 text-sm font-semibold text-white">{user.name}</p>
            <p className="mt-1 text-xs text-slate-400">{user.email}</p>
            <div className="mt-3 flex flex-wrap gap-2 text-xs">
              <span className="rounded-full border border-white/10 bg-white/10 px-3 py-1">
                {user.role}
              </span>
              <span className="rounded-full border border-white/10 bg-white/10 px-3 py-1">
                {user.plan}
              </span>
              <span className="rounded-full border border-white/10 bg-white/10 px-3 py-1">
                {user.workspace_id}
              </span>
            </div>
          </div>
        </div>

        {safeError ? (
          <div className="mb-6">
            <ErrorState
              variant="dark"
              message={safeError}
              onRetry={handleRetry}
            />
          </div>
        ) : null}

        {!canReadBilling ? (
          <div className="mb-6">
            <ForbiddenState
              variant="dark"
              message="Your current role or subscription plan cannot access billing."
            />
          </div>
        ) : null}

        <div className="mb-6 grid gap-4 md:grid-cols-4">
          <StatCard
            label="Current Plan"
            value={subscription ? formatLabel(subscription.plan) : "N/A"}
            hint="Workspace subscription"
          />
          <StatCard
            label="Status"
            value={subscription ? formatLabel(subscription.status) : "N/A"}
            hint="Billing health"
          />
          <StatCard
            label="Usage Load"
            value={usageHealth === null ? "N/A" : `${usageHealth}%`}
            hint="Average metered usage"
          />
          <StatCard
            label="Current Period Ends"
            value={
              subscription?.current_period_end
                ? new Date(subscription.current_period_end).toLocaleDateString()
                : "N/A"
            }
            hint="Next billing cycle"
          />
        </div>

        <div className="grid gap-6 lg:grid-cols-[410px_1fr]">
          <aside className="space-y-6">
            <section className="rounded-3xl border border-white/10 bg-white/[0.05] p-4 shadow-2xl shadow-black/20">
              <h2 className="text-lg font-bold">Subscription Snapshot</h2>
              <p className="mt-1 text-xs text-slate-400">
                Scoped to current workspace only.
              </p>

              {subscription ? (
                <div className="mt-4 space-y-3">
                  <InfoTile
                    label="Subscription ID"
                    value={subscription.id}
                    mono
                  />
                  <InfoTile label="Provider" value={subscription.provider} />
                  <InfoTile
                    label="Billing Interval"
                    value={formatLabel(subscription.interval)}
                  />
                  <InfoTile
                    label="Updated"
                    value={new Date(subscription.updated_at).toLocaleString()}
                  />

                  <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
                    <div className="mb-3 flex items-center justify-between">
                      <p className="text-xs uppercase tracking-[0.2em] text-slate-500">
                        Status
                      </p>
                      <span
                        className={[
                          "rounded-full border px-3 py-1 text-xs",
                          getStatusBadgeClass(subscription.status),
                        ].join(" ")}
                      >
                        {formatLabel(subscription.status)}
                      </span>
                    </div>
                    <p className="text-sm leading-6 text-slate-300">
                      Plan changes, cancellation, and portal actions are treated
                      as sensitive billing events and routed through Security
                      Agent.
                    </p>
                  </div>
                </div>
              ) : (
                <div className="mt-4 rounded-3xl border border-white/10 bg-slate-950/40 p-6 text-center">
                  <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-2xl border border-cyan-400/30 bg-cyan-400/10">
                    $
                  </div>
                  <h3 className="font-bold">No subscription found</h3>
                  <p className="mt-2 text-xs leading-5 text-slate-400">
                    Billing data will appear here once your workspace
                    subscription is created.
                  </p>
                </div>
              )}
            </section>

            <section className="rounded-3xl border border-white/10 bg-white/[0.05] p-4 shadow-2xl shadow-black/20">
              <h2 className="text-lg font-bold">Access Control</h2>
              <p className="mt-1 text-xs text-slate-400">
                Role and subscription gates.
              </p>

              <div className="mt-4 space-y-3">
                <AccessRow label="Read Billing" enabled={canReadBilling} />
                <AccessRow label="Manage Plan" enabled={canManageBilling} />
                <AccessRow
                  label="Cancel Subscription"
                  enabled={canCancelSubscription}
                />
                <AccessRow
                  label="Security Review"
                  enabled={hasPermission(
                    user,
                    "security:review:sensitive_action",
                  )}
                />
                <AccessRow
                  label="Audit Logging"
                  enabled={hasPermission(user, "audit:write")}
                />
                <AccessRow
                  label="Memory Context"
                  enabled={hasPermission(user, "memory:write")}
                />
                <AccessRow
                  label="Verification Payload"
                  enabled={hasPermission(user, "verification:prepare")}
                />
              </div>
            </section>
          </aside>

          <section className="min-h-[820px] rounded-3xl border border-white/10 bg-white/[0.05] shadow-2xl shadow-black/30">
            <div className="border-b border-white/10 p-5">
              <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
                <div>
                  <h2 className="text-2xl font-black">Plans & Usage</h2>
                  <p className="mt-2 max-w-2xl text-sm text-slate-400">
                    Upgrade, downgrade, refresh usage, or open billing workflows
                    safely.
                  </p>
                </div>

                {lastSecurityDecision ? (
                  <div
                    className={[
                      "rounded-2xl border p-3 text-sm xl:max-w-md",
                      getDecisionBadgeClass(lastSecurityDecision.outcome),
                    ].join(" ")}
                  >
                    <div className="font-semibold">
                      Last Security Decision:{" "}
                      {formatLabel(lastSecurityDecision.outcome)}
                    </div>
                    <p className="mt-1 opacity-80">
                      {lastSecurityDecision.reason}
                    </p>
                  </div>
                ) : null}
              </div>
            </div>

            <div className="space-y-6 p-5">
              <section className="grid gap-4 xl:grid-cols-4">
                {plans.length === 0 ? (
                  <div className="xl:col-span-4">
                    <EmptyState
                      variant="dark"
                      icon="◈"
                      title="No plans available"
                      message="No plans returned by the billing API."
                    />
                  </div>
                ) : (
                  plans.map((plan) => {
                    const isCurrent = subscription?.plan === plan.plan;
                    const isSelected = selectedPlan === plan.plan;

                    return (
                      <button
                        key={plan.id}
                        type="button"
                        onClick={() => setSelectedPlan(plan.plan)}
                        className={[
                          "rounded-3xl border p-5 text-left transition",
                          isSelected
                            ? "border-cyan-400/50 bg-cyan-400/10 shadow-lg shadow-cyan-950/40"
                            : plan.recommended
                              ? "border-purple-400/30 bg-purple-400/10 hover:bg-purple-400/15"
                              : "border-white/10 bg-slate-950/40 hover:border-white/20 hover:bg-white/[0.07]",
                        ].join(" ")}
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div>
                            <h3 className="text-xl font-black text-white">
                              {plan.name}
                            </h3>
                            <p className="mt-1 text-2xl font-black text-cyan-100">
                              {plan.price_cents === 0
                                ? "Free"
                                : `${formatPriceCents(plan.price_cents, plan.currency)}/${plan.interval === "yearly" ? "yr" : "mo"}`}
                            </p>
                          </div>
                          {isCurrent ? (
                            <span className="rounded-full border border-emerald-400/30 bg-emerald-400/10 px-2 py-1 text-[10px] text-emerald-100">
                              Current
                            </span>
                          ) : null}
                        </div>

                        <div className="mt-4 space-y-2 text-xs text-slate-300">
                          <p>Tasks: {formatLimit(plan.limits.tasks ?? 0)}</p>
                          <p>
                            Agent Runs:{" "}
                            {formatLimit(plan.limits.agent_runs ?? 0)}
                          </p>
                          <p>
                            Memory Records:{" "}
                            {formatLimit(plan.limits.memory_records ?? 0)}
                          </p>
                          <p>
                            Team Members:{" "}
                            {formatLimit(plan.limits.team_members ?? 0)}
                          </p>
                        </div>

                        <div className="mt-4 space-y-2">
                          {plan.features.slice(0, 4).map((feature) => (
                            <div
                              key={feature}
                              className="flex items-center gap-2 text-xs text-slate-300"
                            >
                              <span className="h-2 w-2 rounded-full bg-emerald-400" />
                              {formatLabel(feature)}
                            </div>
                          ))}
                        </div>
                      </button>
                    );
                  })
                )}
              </section>

              <section className="rounded-3xl border border-white/10 bg-slate-950/40 p-5">
                <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
                  <div>
                    <h3 className="text-lg font-bold">
                      Selected Plan: {selectedPlanCard?.name || selectedPlan}
                    </h3>
                    <p className="mt-1 text-sm text-slate-400">
                      Current plan is{" "}
                      {currentPlanCard?.name || subscription?.plan || "N/A"}.
                      Sensitive changes are routed through the real Security
                      Agent decision endpoint before they run.
                    </p>
                  </div>

                  <div className="flex flex-wrap gap-3">
                    <button
                      type="button"
                      disabled={
                        isActionRunning ||
                        !canManageBilling ||
                        !subscription ||
                        selectedPlan === subscription.plan
                      }
                      onClick={() =>
                        runBillingAction(
                          getPlanRank(selectedPlan) >
                            getPlanRank(subscription?.plan || "free")
                            ? "upgrade_plan"
                            : "downgrade_plan",
                          selectedPlan,
                        )
                      }
                      className="rounded-2xl bg-cyan-400 px-5 py-3 text-sm font-black text-slate-950 shadow-lg shadow-cyan-950/40 transition hover:bg-cyan-300 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400 disabled:shadow-none"
                    >
                      {isActionRunning ? "Processing..." : "Apply Plan Change"}
                    </button>

                    <button
                      type="button"
                      disabled={isActionRunning || !canManageBilling}
                      onClick={() => runBillingAction("open_billing_portal")}
                      className="rounded-2xl border border-white/10 bg-white/10 px-5 py-3 text-sm font-bold text-white transition hover:bg-white/15 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      Billing Portal
                    </button>

                    {subscription?.cancel_at_period_end ? (
                      <button
                        type="button"
                        disabled={isActionRunning || !canCancelSubscription}
                        onClick={() =>
                          runBillingAction("reactivate_subscription")
                        }
                        className="rounded-2xl border border-emerald-400/30 bg-emerald-400/10 px-5 py-3 text-sm font-bold text-emerald-100 transition hover:bg-emerald-400/20 disabled:cursor-not-allowed disabled:opacity-50"
                      >
                        Reactivate
                      </button>
                    ) : (
                      <button
                        type="button"
                        disabled={isActionRunning || !canCancelSubscription}
                        onClick={() => runBillingAction("cancel_subscription")}
                        className="rounded-2xl border border-red-400/30 bg-red-400/10 px-5 py-3 text-sm font-bold text-red-100 transition hover:bg-red-400/20 disabled:cursor-not-allowed disabled:opacity-50"
                      >
                        Cancel
                      </button>
                    )}
                  </div>
                </div>
              </section>

              <section className="rounded-3xl border border-white/10 bg-slate-950/40 p-5">
                <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
                  <div>
                    <h3 className="text-lg font-bold">Usage Metering</h3>
                    <p className="mt-1 text-sm text-slate-400">
                      All usage is scoped by user_id and workspace_id. No
                      cross-workspace soup.
                    </p>
                  </div>

                  <button
                    type="button"
                    disabled={isActionRunning || !canReadBilling}
                    onClick={async () => {
                      setSafeError(null);
                      try {
                        setUsage(await loadUsage());
                      } catch (error) {
                        setSafeError(sanitizeError(error));
                      }
                    }}
                    className="rounded-2xl border border-cyan-400/30 bg-cyan-400/10 px-5 py-3 text-sm font-bold text-cyan-100 transition hover:bg-cyan-400/20 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    Refresh Usage
                  </button>
                </div>

                {usage.length === 0 ? (
                  <div className="mt-5">
                    <EmptyState
                      variant="dark"
                      icon="◈"
                      title="No usage data"
                      message="No usage data returned by the billing API yet."
                    />
                  </div>
                ) : (
                  <div className="mt-5 grid gap-4 md:grid-cols-2">
                    {usage.map((record) => {
                      const percent = getUsagePercent(record);

                      return (
                        <div
                          key={record.id}
                          className="rounded-3xl border border-white/10 bg-black/20 p-5"
                        >
                          <div className="flex items-start justify-between gap-3">
                            <div>
                              <h4 className="font-bold text-white">
                                {USAGE_METRIC_LABELS[record.metric]}
                              </h4>
                              <p className="mt-1 text-xs text-slate-400">
                                {record.used.toLocaleString()} used
                              </p>
                            </div>
                            <span className="rounded-full border border-white/10 bg-white/10 px-3 py-1 text-xs text-slate-300">
                              {percent}%
                            </span>
                          </div>

                          <div className="mt-4 h-3 overflow-hidden rounded-full bg-white/10">
                            <div
                              className="h-full rounded-full bg-cyan-400 shadow-[0_0_18px_rgba(34,211,238,0.7)]"
                              style={{ width: `${percent}%` }}
                            />
                          </div>

                          <p className="mt-3 text-xs text-slate-500">
                            Limit: {formatLimit(record.limit)}
                          </p>
                        </div>
                      );
                    })}
                  </div>
                )}
              </section>

              {lastVerification ? (
                <section className="rounded-3xl border border-white/10 bg-slate-950/40 p-5">
                  <h3 className="text-lg font-bold">Agent Payloads</h3>

                  <details className="mt-4 rounded-2xl border border-emerald-400/20 bg-emerald-400/5 p-3 text-xs text-emerald-100">
                    <summary className="cursor-pointer font-semibold">
                      Verification Agent Payload Ready
                    </summary>
                    <pre className="mt-3 overflow-auto whitespace-pre-wrap text-[11px] leading-5">
                      {JSON.stringify(lastVerification, null, 2)}
                    </pre>
                  </details>
                </section>
              ) : null}
            </div>
          </section>
        </div>
      </section>
    </div>
  );
}

function InfoTile(props: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
      <p className="text-xs uppercase tracking-[0.2em] text-slate-500">
        {props.label}
      </p>
      <p
        className={[
          "mt-2 text-sm font-semibold text-slate-200",
          props.mono ? "break-all font-mono text-xs" : "",
        ].join(" ")}
      >
        {props.value}
      </p>
    </div>
  );
}

function AccessRow(props: { label: string; enabled: boolean }) {
  return (
    <div className="flex items-center justify-between rounded-2xl border border-white/10 bg-black/20 px-4 py-3 text-sm">
      <span className="text-slate-300">{props.label}</span>
      <span
        className={[
          "rounded-full border px-3 py-1 text-xs",
          props.enabled
            ? "border-emerald-400/30 bg-emerald-400/10 text-emerald-100"
            : "border-orange-400/30 bg-orange-400/10 text-orange-100",
        ].join(" ")}
      >
        {props.enabled ? "Allowed" : "Restricted"}
      </span>
    </div>
  );
}
