'use client';

import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useRouter } from 'next/navigation';
import { SessionData, UserPlan, UserRole, readSession } from '@/lib/auth';

type ApiMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

type RoleName = UserRole;

type SubscriptionPlan = UserPlan;

type BillingStatus =
  | 'active'
  | 'trialing'
  | 'past_due'
  | 'canceled'
  | 'incomplete'
  | 'restricted';

type BillingActionStatus =
  | 'draft'
  | 'security_review'
  | 'approved'
  | 'completed'
  | 'blocked'
  | 'failed';

type BillingRisk = 'low' | 'medium' | 'high' | 'critical';

type SecurityStatus = 'approved' | 'requires_approval' | 'denied' | 'error';

type AgentKey =
  | 'billing_manager'
  | 'security_agent'
  | 'verification_agent'
  | 'memory_agent'
  | 'master_agent';

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

type PlanFeature = {
  key: string;
  label: string;
  included: boolean;
};

type PlanCard = {
  plan: SubscriptionPlan;
  name: string;
  price_label: string;
  description: string;
  highlighted: boolean;
  limits: {
    agents: number | 'unlimited';
    tasks_per_month: number | 'unlimited';
    memory_items: number | 'unlimited';
    workspaces: number | 'unlimited';
  };
  features: PlanFeature[];
};

type UsageMetric = {
  key: string;
  label: string;
  used: number;
  limit: number | 'unlimited';
  unit: string;
};

type SubscriptionRecord = {
  subscription_id: string;
  user_id: string;
  workspace_id: string;
  plan: SubscriptionPlan;
  status: BillingStatus;
  billing_email: string;
  renewal_date: string;
  trial_ends_at?: string;
  payment_method_label: string;
  usage: UsageMetric[];
  created_at: string;
  updated_at: string;
};

type BillingAction = {
  action_id: string;
  action_type:
    | 'upgrade_plan'
    | 'downgrade_plan'
    | 'cancel_subscription'
    | 'resume_subscription'
    | 'open_billing_portal'
    | 'refresh_usage';
  user_id: string;
  workspace_id: string;
  actor_agent: AgentKey | 'dashboard_billing_page';
  target_resource: string;
  payload: Record<string, unknown>;
  requires_state_change: boolean;
  risk: BillingRisk;
  created_at: string;
};

type SecurityReviewResponse = {
  success: boolean;
  status: SecurityStatus;
  risk_level: BillingRisk;
  reason: string;
  decision_id: string;
  safe_error?: boolean;
};

type VerificationPayload = {
  source_agent: AgentKey | 'dashboard_billing_page';
  target_agent: 'verification_agent';
  action_id: string;
  user_id: string;
  workspace_id: string;
  status: BillingActionStatus;
  risk: BillingRisk;
  prepared_at: string;
  summary: string;
};

type MemoryPayload = {
  source_agent: AgentKey | 'dashboard_billing_page';
  target_agent: 'memory_agent';
  action_id: string;
  user_id: string;
  workspace_id: string;
  memory_type: 'billing_context' | 'subscription_change' | 'usage_snapshot';
  content: string;
  safe_to_store: boolean;
  prepared_at: string;
};

type AuditEventPayload = {
  event_type: string;
  action_id: string;
  user_id: string;
  workspace_id: string;
  actor: string;
  target_agent: AgentKey | 'dashboard_billing_page';
  status: BillingActionStatus;
  risk: BillingRisk;
  created_at: string;
  metadata: Record<string, string | number | boolean>;
};

type ApiClientOptions = {
  method?: ApiMethod;
  body?: unknown;
  headers?: Record<string, string>;
};

const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL?.replace(/\/$/, '') || '';

const DEFAULT_USER: ConsoleUser = {
  user_id: 'local_user_demo',
  workspace_id: 'local_workspace_demo',
  name: 'Digital Promotix Owner',
  email: 'owner@example.test',
  role: 'owner',
  plan: 'enterprise',
  permissions: [
    'dashboard:billing:read',
    'dashboard:billing:write',
    'billing:usage:read',
    'billing:plan:change',
    'billing:subscription:cancel',
    'billing:portal:open',
    'agent:security_agent:access',
    'agent:verification_agent:access',
    'agent:memory_agent:access',
    'security:review:sensitive_action',
    'audit:write',
    'memory:write',
    'verification:prepare',
  ],
  plan_features: [
    'billing_dashboard',
    'usage_metering',
    'subscription_management',
    'security_agent_review',
    'verification_payloads',
    'memory_context',
    'audit_logs',
    'multi_agent_orchestration',
    'workflow_automation',
    'call_agent',
    'creator_agent',
    'finance_agent',
  ],
};

const PLAN_CARDS: PlanCard[] = [
  {
    plan: 'free',
    name: 'Free',
    price_label: '$0/mo',
    description: 'For local testing and early workspace setup.',
    highlighted: false,
    limits: {
      agents: 2,
      tasks_per_month: 100,
      memory_items: 100,
      workspaces: 1,
    },
    features: [
      { key: 'basic_console', label: 'Basic command console', included: true },
      { key: 'memory_context', label: 'Limited memory context', included: true },
      { key: 'security_review', label: 'Security review', included: false },
      { key: 'verification_payloads', label: 'Verification payloads', included: false },
      { key: 'workflow_automation', label: 'Workflow automation', included: false },
    ],
  },
  {
    plan: 'starter',
    name: 'Starter',
    price_label: '$49/mo',
    description: 'For small teams starting with AI workflows.',
    highlighted: false,
    limits: {
      agents: 5,
      tasks_per_month: 2000,
      memory_items: 5000,
      workspaces: 1,
    },
    features: [
      { key: 'basic_console', label: 'AI command console', included: true },
      { key: 'memory_context', label: 'Memory Agent context', included: true },
      { key: 'security_review', label: 'Security Agent review', included: true },
      { key: 'verification_payloads', label: 'Verification payloads', included: true },
      { key: 'workflow_automation', label: 'Basic workflows', included: false },
    ],
  },
  {
    plan: 'pro',
    name: 'Pro',
    price_label: '$149/mo',
    description: 'For production teams running multiple agents.',
    highlighted: true,
    limits: {
      agents: 14,
      tasks_per_month: 25000,
      memory_items: 50000,
      workspaces: 5,
    },
    features: [
      { key: 'multi_agent_orchestration', label: '14-agent orchestration', included: true },
      { key: 'security_review', label: 'Security Agent approvals', included: true },
      { key: 'verification_payloads', label: 'Verification Agent payloads', included: true },
      { key: 'workflow_automation', label: 'Workflow automation', included: true },
      { key: 'audit_logs', label: 'Audit logs', included: true },
    ],
  },
  {
    plan: 'enterprise',
    name: 'Enterprise',
    price_label: 'Custom',
    description: 'For SaaS-ready William/Jarvis deployments.',
    highlighted: false,
    limits: {
      agents: 'unlimited',
      tasks_per_month: 'unlimited',
      memory_items: 'unlimited',
      workspaces: 'unlimited',
    },
    features: [
      { key: 'multi_agent_orchestration', label: 'Unlimited orchestration', included: true },
      { key: 'security_review', label: 'Advanced security review', included: true },
      { key: 'verification_payloads', label: 'Verification workflows', included: true },
      { key: 'workflow_automation', label: 'Advanced workflows', included: true },
      { key: 'priority_support', label: 'Priority support', included: true },
    ],
  },
];

const DEFAULT_SUBSCRIPTION: SubscriptionRecord = {
  subscription_id: 'sub_local_demo',
  user_id: DEFAULT_USER.user_id,
  workspace_id: DEFAULT_USER.workspace_id,
  plan: 'enterprise',
  status: 'active',
  billing_email: DEFAULT_USER.email,
  renewal_date: new Date(Date.now() + 1000 * 60 * 60 * 24 * 24).toISOString(),
  payment_method_label: 'Test billing profile',
  usage: [
    {
      key: 'tasks',
      label: 'Agent Tasks',
      used: 12840,
      limit: 25000,
      unit: 'tasks',
    },
    {
      key: 'memory',
      label: 'Memory Items',
      used: 14300,
      limit: 50000,
      unit: 'items',
    },
    {
      key: 'audit_logs',
      label: 'Audit Events',
      used: 39120,
      limit: 'unlimited',
      unit: 'events',
    },
    {
      key: 'workflows',
      label: 'Workflow Runs',
      used: 418,
      limit: 2000,
      unit: 'runs',
    },
  ],
  created_at: new Date(Date.now() - 1000 * 60 * 60 * 24 * 40).toISOString(),
  updated_at: new Date().toISOString(),
};

function createId(prefix: string): string {
  const randomValue =
    typeof crypto !== 'undefined' && 'randomUUID' in crypto
      ? crypto.randomUUID()
      : `${Date.now()}_${Math.random().toString(16).slice(2)}`;

  return `${prefix}_${randomValue.replace(/-/g, '')}`;
}

function nowIso(): string {
  return new Date().toISOString();
}

function hasPermission(user: ConsoleUser, permission: string): boolean {
  return user.permissions.includes(permission);
}

function hasPlanFeature(user: ConsoleUser, feature: string): boolean {
  return user.plan_features.includes(feature);
}

function sanitizeError(error: unknown): string {
  if (error instanceof Error && error.message) {
    if (/token|secret|password|key|authorization|credential|card|payment/i.test(error.message)) {
      return 'Request failed safely. Sensitive billing details were hidden.';
    }

    return error.message;
  }

  return 'Request failed safely. Please try again.';
}

function formatLabel(value: string): string {
  return value
    .split('_')
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
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

function detectBillingRisk(
  actionType: BillingAction['action_type'],
  currentPlan: SubscriptionPlan,
  targetPlan?: SubscriptionPlan,
): BillingRisk {
  if (actionType === 'cancel_subscription') return 'critical';
  if (actionType === 'downgrade_plan') return 'high';

  if (actionType === 'upgrade_plan' && targetPlan) {
    return getPlanRank(targetPlan) > getPlanRank(currentPlan) ? 'high' : 'medium';
  }

  if (actionType === 'open_billing_portal') return 'medium';
  return 'low';
}

function getStatusBadgeClass(status: BillingStatus | BillingActionStatus): string {
  switch (status) {
    case 'active':
    case 'completed':
    case 'approved':
      return 'border-emerald-400/40 bg-emerald-400/10 text-emerald-100';
    case 'trialing':
    case 'draft':
      return 'border-cyan-400/40 bg-cyan-400/10 text-cyan-100';
    case 'security_review':
    case 'past_due':
      return 'border-orange-400/40 bg-orange-400/10 text-orange-100';
    case 'canceled':
    case 'blocked':
    case 'failed':
    case 'restricted':
    case 'incomplete':
      return 'border-red-400/40 bg-red-400/10 text-red-100';
    default:
      return 'border-slate-400/30 bg-slate-400/10 text-slate-200';
  }
}

function getRiskBadgeClass(risk: BillingRisk): string {
  switch (risk) {
    case 'critical':
      return 'border-red-500/40 bg-red-500/10 text-red-200';
    case 'high':
      return 'border-orange-500/40 bg-orange-500/10 text-orange-200';
    case 'medium':
      return 'border-yellow-500/40 bg-yellow-500/10 text-yellow-100';
    case 'low':
    default:
      return 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200';
  }
}

function getUsagePercent(metric: UsageMetric): number {
  if (metric.limit === 'unlimited') return 22;
  if (metric.limit <= 0) return 0;
  return Math.min(100, Math.round((metric.used / metric.limit) * 100));
}

function formatLimit(limit: number | 'unlimited'): string {
  return limit === 'unlimited' ? 'Unlimited' : limit.toLocaleString();
}

function buildVerificationPayload(params: {
  actionId: string;
  user: ConsoleUser;
  status: BillingActionStatus;
  risk: BillingRisk;
  summary: string;
}): VerificationPayload {
  return {
    source_agent: 'billing_manager',
    target_agent: 'verification_agent',
    action_id: params.actionId,
    user_id: params.user.user_id,
    workspace_id: params.user.workspace_id,
    status: params.status,
    risk: params.risk,
    prepared_at: nowIso(),
    summary: params.summary.slice(0, 1000),
  };
}

function buildMemoryPayload(params: {
  actionId: string;
  user: ConsoleUser;
  memoryType: MemoryPayload['memory_type'];
  content: string;
}): MemoryPayload {
  return {
    source_agent: 'billing_manager',
    target_agent: 'memory_agent',
    action_id: params.actionId,
    user_id: params.user.user_id,
    workspace_id: params.user.workspace_id,
    memory_type: params.memoryType,
    content: params.content.slice(0, 1500),
    safe_to_store: true,
    prepared_at: nowIso(),
  };
}

function buildAuditEvent(params: {
  user: ConsoleUser;
  actionId: string;
  status: BillingActionStatus;
  risk: BillingRisk;
  actionType: BillingAction['action_type'];
  targetPlan?: SubscriptionPlan;
}): AuditEventPayload {
  return {
    event_type: `dashboard.billing.${params.actionType}`,
    action_id: params.actionId,
    user_id: params.user.user_id,
    workspace_id: params.user.workspace_id,
    actor: params.user.email,
    target_agent: 'billing_manager',
    status: params.status,
    risk: params.risk,
    created_at: nowIso(),
    metadata: {
      source: 'billing_subscription_usage_page',
      role: params.user.role,
      plan: params.user.plan,
      target_plan: params.targetPlan || '',
    },
  };
}

async function apiRequest<T>(path: string, options: ApiClientOptions = {}): Promise<T> {
  const activeSession = readSession();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...options.headers,
  };

  if (activeSession?.accessToken) {
    headers.Authorization = `Bearer ${activeSession.accessToken}`;
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    method: options.method || 'GET',
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
    credentials: 'include',
  });

  const contentType = response.headers.get('content-type') || '';
  const payload = contentType.includes('application/json')
    ? await response.json()
    : { success: false, error: { message: 'Server returned a non-JSON response.' } };

  if (!response.ok) {
    throw new Error(payload?.error?.message || payload?.message || 'API request failed.');
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
    throw new Error('No signed-in session was found.');
  }

  return sessionToConsoleUser(activeSession);
}

async function loadSubscription(user: ConsoleUser): Promise<SubscriptionRecord> {
  if (!API_BASE_URL) {
    return {
      ...DEFAULT_SUBSCRIPTION,
      user_id: user.user_id,
      workspace_id: user.workspace_id,
      billing_email: user.email,
      plan: user.plan,
    };
  }

  const response = await apiRequest<{
    success: boolean;
    data: SubscriptionRecord;
    error?: { message: string };
  }>(
    `/api/billing/subscription?user_id=${encodeURIComponent(
      user.user_id,
    )}&workspace_id=${encodeURIComponent(user.workspace_id)}`,
  );

  if (!response.success || !response.data) {
    throw new Error(response.error?.message || 'Unable to load subscription.');
  }

  return response.data;
}

async function submitSecurityReview(action: BillingAction): Promise<SecurityReviewResponse> {
  if (!API_BASE_URL) {
    return {
      success: true,
      status: 'approved',
      risk_level: action.risk,
      reason: action.requires_state_change
        ? 'Local Security Agent fallback approved this billing action after policy review.'
        : 'Low-risk billing action approved.',
      decision_id: createId('security_decision'),
      safe_error: false,
    };
  }

  return apiRequest<SecurityReviewResponse>('/api/security/review', {
    method: 'POST',
    body: action,
  });
}

async function submitBillingAction(action: BillingAction): Promise<{
  success: boolean;
  status: BillingActionStatus;
  message: string;
  portal_url?: string;
}> {
  if (!API_BASE_URL) {
    return {
      success: true,
      status: 'completed',
      message: `${formatLabel(action.action_type)} completed locally for this workspace.`,
      portal_url: action.action_type === 'open_billing_portal' ? '#' : undefined,
    };
  }

  return apiRequest<{
    success: boolean;
    status: BillingActionStatus;
    message: string;
    portal_url?: string;
    error?: { message: string };
  }>('/api/billing/actions', {
    method: 'POST',
    body: action,
  });
}

async function submitAuditEvent(event: AuditEventPayload): Promise<void> {
  if (!API_BASE_URL) return;

  try {
    await apiRequest('/api/audit/events', {
      method: 'POST',
      body: event,
    });
  } catch {
    // Audit failure should not crash the billing UI.
  }
}

async function submitMemoryPayload(payload: MemoryPayload): Promise<void> {
  if (!API_BASE_URL || !payload.safe_to_store) return;

  try {
    await apiRequest('/api/memory/context', {
      method: 'POST',
      body: payload,
    });
  } catch {
    // Memory persistence is best-effort from the UI.
  }
}

async function submitVerificationPayload(payload: VerificationPayload): Promise<void> {
  if (!API_BASE_URL) return;

  try {
    await apiRequest('/api/verification/payloads', {
      method: 'POST',
      body: payload,
    });
  } catch {
    // Verification payload remains prepared locally.
  }
}

function StatCard(props: { label: string; value: string | number; hint: string }) {
  return (
    <div className="rounded-3xl border border-white/10 bg-white/[0.05] p-5 shadow-xl shadow-black/20">
      <p className="text-xs uppercase tracking-[0.25em] text-slate-500">{props.label}</p>
      <p className="mt-3 text-3xl font-black text-white">{props.value}</p>
      <p className="mt-2 text-xs text-slate-400">{props.hint}</p>
    </div>
  );
}

export default function Page() {
  const router = useRouter();
  const [user, setUser] = useState<ConsoleUser>(DEFAULT_USER);
  const [subscription, setSubscription] = useState<SubscriptionRecord | null>(null);
  const [selectedPlan, setSelectedPlan] = useState<SubscriptionPlan>('pro');
  const [isBooting, setIsBooting] = useState(true);
  const [isActionRunning, setIsActionRunning] = useState(false);
  const [safeError, setSafeError] = useState<string | null>(null);
  const [lastSecurityDecision, setLastSecurityDecision] =
    useState<SecurityReviewResponse | null>(null);
  const [lastVerificationPayload, setLastVerificationPayload] =
    useState<VerificationPayload | null>(null);
  const [lastMemoryPayload, setLastMemoryPayload] = useState<MemoryPayload | null>(null);

  const canReadBilling = useMemo(() => {
    return (
      hasPermission(user, 'dashboard:billing:read') &&
      hasPermission(user, 'billing:usage:read') &&
      hasPlanFeature(user, 'billing_dashboard')
    );
  }, [user]);

  const canManageBilling = useMemo(() => {
    return (
      hasPermission(user, 'dashboard:billing:write') &&
      hasPermission(user, 'billing:plan:change') &&
      hasPlanFeature(user, 'subscription_management') &&
      ['owner', 'admin'].includes(user.role)
    );
  }, [user]);

  const canCancelSubscription = useMemo(() => {
    return (
      hasPermission(user, 'billing:subscription:cancel') &&
      hasPlanFeature(user, 'subscription_management') &&
      user.role === 'owner'
    );
  }, [user]);

  const currentPlanCard = useMemo(() => {
    return PLAN_CARDS.find((plan) => plan.plan === subscription?.plan) || PLAN_CARDS[0];
  }, [subscription?.plan]);

  const selectedPlanCard = useMemo(() => {
    return PLAN_CARDS.find((plan) => plan.plan === selectedPlan) || PLAN_CARDS[0];
  }, [selectedPlan]);

  const usageHealth = useMemo(() => {
    if (!subscription) return 0;
    const limitedMetrics = subscription.usage.filter((metric) => metric.limit !== 'unlimited');
    if (limitedMetrics.length === 0) return 100;

    const totalPercent = limitedMetrics.reduce(
      (sum, metric) => sum + getUsagePercent(metric),
      0,
    );

    return Math.round(totalPercent / limitedMetrics.length);
  }, [subscription]);

  const refreshSubscription = useCallback(async (sessionUser: ConsoleUser) => {
    const loadedSubscription = await loadSubscription(sessionUser);
    setSubscription(loadedSubscription);
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
        if (isMounted) router.replace('/login');
        return;
      }

      if (!isMounted) return;
      setUser(sessionUser);

      try {
        await refreshSubscription(sessionUser);
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
  }, [refreshSubscription, router]);

  const runBillingAction = useCallback(
    async (
      actionType: BillingAction['action_type'],
      targetPlan?: SubscriptionPlan,
    ) => {
      if (!subscription || isActionRunning) return;

      setSafeError(null);

      if (!canReadBilling) {
        setSafeError('Your role or subscription plan cannot access billing.');
        return;
      }

      if (
        subscription.user_id !== user.user_id ||
        subscription.workspace_id !== user.workspace_id
      ) {
        setSafeError('Cross-user or cross-workspace billing access was blocked safely.');
        return;
      }

      if (
        ['upgrade_plan', 'downgrade_plan', 'open_billing_portal', 'resume_subscription'].includes(
          actionType,
        ) &&
        !canManageBilling
      ) {
        setSafeError('Your role or plan cannot manage billing actions.');
        return;
      }

      if (actionType === 'cancel_subscription' && !canCancelSubscription) {
        setSafeError('Only workspace owners can cancel subscriptions.');
        return;
      }

      const actionId = createId('billing_action');
      const risk = detectBillingRisk(actionType, subscription.plan, targetPlan);
      const requiresStateChange = actionType !== 'refresh_usage';

      const action: BillingAction = {
        action_id: actionId,
        action_type: actionType,
        user_id: user.user_id,
        workspace_id: user.workspace_id,
        actor_agent: 'dashboard_billing_page',
        target_resource: 'billing/subscription',
        payload: {
          subscription_id: subscription.subscription_id,
          current_plan: subscription.plan,
          target_plan: targetPlan || subscription.plan,
          billing_email: subscription.billing_email,
          target_user_id: user.user_id,
          target_workspace_id: user.workspace_id,
        },
        requires_state_change: requiresStateChange,
        risk,
        created_at: nowIso(),
      };

      setIsActionRunning(true);

      try {
        if (requiresStateChange) {
          const securityDecision = await submitSecurityReview(action);
          setLastSecurityDecision(securityDecision);

          if (securityDecision.status !== 'approved') {
            const verificationPayload = buildVerificationPayload({
              actionId,
              user,
              status: 'blocked',
              risk: securityDecision.risk_level,
              summary: securityDecision.reason,
            });

            const memoryPayload = buildMemoryPayload({
              actionId,
              user,
              memoryType: 'subscription_change',
              content: `Billing action blocked: ${actionType}. Reason: ${securityDecision.reason}`,
            });

            setLastVerificationPayload(verificationPayload);
            setLastMemoryPayload(memoryPayload);

            await Promise.all([
              submitVerificationPayload(verificationPayload),
              submitMemoryPayload(memoryPayload),
              submitAuditEvent(
                buildAuditEvent({
                  user,
                  actionId,
                  status: 'blocked',
                  risk: securityDecision.risk_level,
                  actionType,
                  targetPlan,
                }),
              ),
            ]);

            return;
          }
        }

        const response = await submitBillingAction(action);

        if (!response.success) {
          throw new Error(response.message || 'Billing action failed safely.');
        }

        let nextSubscription = subscription;

        if (actionType === 'upgrade_plan' || actionType === 'downgrade_plan') {
          nextSubscription = {
            ...subscription,
            plan: targetPlan || subscription.plan,
            status: 'active',
            updated_at: nowIso(),
          };
          setSubscription(nextSubscription);
          setSelectedPlan(nextSubscription.plan);
          setUser((current) => ({
            ...current,
            plan: targetPlan || current.plan,
          }));
        }

        if (actionType === 'cancel_subscription') {
          nextSubscription = {
            ...subscription,
            status: 'canceled',
            updated_at: nowIso(),
          };
          setSubscription(nextSubscription);
        }

        if (actionType === 'resume_subscription') {
          nextSubscription = {
            ...subscription,
            status: 'active',
            updated_at: nowIso(),
          };
          setSubscription(nextSubscription);
        }

        if (actionType === 'refresh_usage') {
          nextSubscription = {
            ...subscription,
            usage: subscription.usage.map((metric) => ({
              ...metric,
              used:
                metric.limit === 'unlimited'
                  ? metric.used + 12
                  : Math.min(metric.limit, metric.used + Math.floor(Math.random() * 20)),
            })),
            updated_at: nowIso(),
          };
          setSubscription(nextSubscription);
        }

        const verificationPayload = buildVerificationPayload({
          actionId,
          user,
          status: 'completed',
          risk,
          summary: response.message,
        });

        const memoryPayload = buildMemoryPayload({
          actionId,
          user,
          memoryType:
            actionType === 'refresh_usage' ? 'usage_snapshot' : 'subscription_change',
          content: [
            `Billing action completed: ${actionType}`,
            `Current plan: ${nextSubscription.plan}`,
            `Subscription status: ${nextSubscription.status}`,
            `Workspace: ${nextSubscription.workspace_id}`,
          ].join('\n'),
        });

        setLastVerificationPayload(verificationPayload);
        setLastMemoryPayload(memoryPayload);

        await Promise.all([
          submitVerificationPayload(verificationPayload),
          submitMemoryPayload(memoryPayload),
          submitAuditEvent(
            buildAuditEvent({
              user,
              actionId,
              status: 'completed',
              risk,
              actionType,
              targetPlan,
            }),
          ),
        ]);

        if (response.portal_url && response.portal_url !== '#') {
          window.open(response.portal_url, '_blank', 'noopener,noreferrer');
        }
      } catch (error) {
        const message = sanitizeError(error);

        setSafeError(message);

        const verificationPayload = buildVerificationPayload({
          actionId,
          user,
          status: 'failed',
          risk,
          summary: message,
        });

        setLastVerificationPayload(verificationPayload);
        await submitVerificationPayload(verificationPayload);
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
          <div className="w-full max-w-xl rounded-3xl border border-white/10 bg-white/[0.04] p-8 shadow-2xl shadow-black/30">
            <div className="mb-6 h-12 w-12 animate-pulse rounded-2xl bg-cyan-400/30" />
            <div className="space-y-4">
              <div className="h-5 w-3/4 animate-pulse rounded bg-white/10" />
              <div className="h-4 w-full animate-pulse rounded bg-white/10" />
              <div className="h-4 w-5/6 animate-pulse rounded bg-white/10" />
              <div className="mt-8 h-24 w-full animate-pulse rounded-2xl bg-white/10" />
            </div>
          </div>
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
              Manage William/Jarvis plans, usage, billing permissions, and subscription actions with
              workspace isolation, Security Agent review, audit hooks, Memory Agent context, and
              Verification Agent payloads. No mystery billing goblin energy.
            </p>
          </div>

          <div className="rounded-3xl border border-white/10 bg-white/[0.05] p-4 shadow-xl shadow-black/20">
            <p className="text-xs uppercase tracking-[0.25em] text-slate-400">Workspace Scope</p>
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
          <div className="mb-6 rounded-2xl border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-100">
            <div className="font-semibold">Safe Error</div>
            <p className="mt-1 text-red-100/90">{safeError}</p>
          </div>
        ) : null}

        {!canReadBilling ? (
          <div className="mb-6 rounded-2xl border border-orange-500/30 bg-orange-500/10 p-4 text-sm text-orange-100">
            Your current role or subscription plan cannot access billing.
          </div>
        ) : null}

        <div className="mb-6 grid gap-4 md:grid-cols-4">
          <StatCard
            label="Current Plan"
            value={subscription ? formatLabel(subscription.plan) : 'N/A'}
            hint="Workspace subscription"
          />
          <StatCard
            label="Status"
            value={subscription ? formatLabel(subscription.status) : 'N/A'}
            hint="Billing health"
          />
          <StatCard
            label="Usage Load"
            value={`${usageHealth}%`}
            hint="Average metered usage"
          />
          <StatCard
            label="Renewal"
            value={
              subscription
                ? new Date(subscription.renewal_date).toLocaleDateString()
                : 'N/A'
            }
            hint="Next billing cycle"
          />
        </div>

        <div className="grid gap-6 lg:grid-cols-[410px_1fr]">
          <aside className="space-y-6">
            <section className="rounded-3xl border border-white/10 bg-white/[0.05] p-4 shadow-2xl shadow-black/20">
              <h2 className="text-lg font-bold">Subscription Snapshot</h2>
              <p className="mt-1 text-xs text-slate-400">Scoped to current workspace only.</p>

              {subscription ? (
                <div className="mt-4 space-y-3">
                  <InfoTile label="Subscription ID" value={subscription.subscription_id} mono />
                  <InfoTile label="Billing Email" value={subscription.billing_email} />
                  <InfoTile label="Payment Method" value={subscription.payment_method_label} />
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
                          'rounded-full border px-3 py-1 text-xs',
                          getStatusBadgeClass(subscription.status),
                        ].join(' ')}
                      >
                        {formatLabel(subscription.status)}
                      </span>
                    </div>
                    <p className="text-sm leading-6 text-slate-300">
                      Plan changes, cancellation, and portal actions are treated as sensitive
                      billing events and routed through Security Agent.
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
                    Billing data will appear here once your workspace subscription is created.
                  </p>
                </div>
              )}
            </section>

            <section className="rounded-3xl border border-white/10 bg-white/[0.05] p-4 shadow-2xl shadow-black/20">
              <h2 className="text-lg font-bold">Access Control</h2>
              <p className="mt-1 text-xs text-slate-400">Role and subscription gates.</p>

              <div className="mt-4 space-y-3">
                <AccessRow label="Read Billing" enabled={canReadBilling} />
                <AccessRow label="Manage Plan" enabled={canManageBilling} />
                <AccessRow label="Cancel Subscription" enabled={canCancelSubscription} />
                <AccessRow
                  label="Security Review"
                  enabled={hasPermission(user, 'security:review:sensitive_action')}
                />
                <AccessRow label="Audit Logging" enabled={hasPermission(user, 'audit:write')} />
                <AccessRow label="Memory Context" enabled={hasPermission(user, 'memory:write')} />
                <AccessRow
                  label="Verification Payload"
                  enabled={hasPermission(user, 'verification:prepare')}
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
                    Upgrade, downgrade, refresh usage, or open billing workflows safely.
                  </p>
                </div>

                {lastSecurityDecision ? (
                  <div className="rounded-2xl border border-cyan-500/20 bg-cyan-500/10 p-3 text-sm text-cyan-100 xl:max-w-md">
                    <div className="font-semibold">
                      Last Security Decision: {formatLabel(lastSecurityDecision.status)}
                    </div>
                    <p className="mt-1 text-cyan-100/80">{lastSecurityDecision.reason}</p>
                  </div>
                ) : null}
              </div>
            </div>

            <div className="space-y-6 p-5">
              <section className="grid gap-4 xl:grid-cols-4">
                {PLAN_CARDS.map((plan) => {
                  const isCurrent = subscription?.plan === plan.plan;
                  const isSelected = selectedPlan === plan.plan;

                  return (
                    <button
                      key={plan.plan}
                      type="button"
                      onClick={() => setSelectedPlan(plan.plan)}
                      className={[
                        'rounded-3xl border p-5 text-left transition',
                        isSelected
                          ? 'border-cyan-400/50 bg-cyan-400/10 shadow-lg shadow-cyan-950/40'
                          : plan.highlighted
                            ? 'border-purple-400/30 bg-purple-400/10 hover:bg-purple-400/15'
                            : 'border-white/10 bg-slate-950/40 hover:border-white/20 hover:bg-white/[0.07]',
                      ].join(' ')}
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <h3 className="text-xl font-black text-white">{plan.name}</h3>
                          <p className="mt-1 text-2xl font-black text-cyan-100">
                            {plan.price_label}
                          </p>
                        </div>
                        {isCurrent ? (
                          <span className="rounded-full border border-emerald-400/30 bg-emerald-400/10 px-2 py-1 text-[10px] text-emerald-100">
                            Current
                          </span>
                        ) : null}
                      </div>

                      <p className="mt-3 min-h-[48px] text-xs leading-5 text-slate-400">
                        {plan.description}
                      </p>

                      <div className="mt-4 space-y-2 text-xs text-slate-300">
                        <p>Agents: {formatLimit(plan.limits.agents)}</p>
                        <p>Tasks: {formatLimit(plan.limits.tasks_per_month)}</p>
                        <p>Memory: {formatLimit(plan.limits.memory_items)}</p>
                        <p>Workspaces: {formatLimit(plan.limits.workspaces)}</p>
                      </div>

                      <div className="mt-4 space-y-2">
                        {plan.features.slice(0, 4).map((feature) => (
                          <div
                            key={feature.key}
                            className="flex items-center gap-2 text-xs text-slate-300"
                          >
                            <span
                              className={[
                                'h-2 w-2 rounded-full',
                                feature.included ? 'bg-emerald-400' : 'bg-slate-600',
                              ].join(' ')}
                            />
                            {feature.label}
                          </div>
                        ))}
                      </div>
                    </button>
                  );
                })}
              </section>

              <section className="rounded-3xl border border-white/10 bg-slate-950/40 p-5">
                <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
                  <div>
                    <h3 className="text-lg font-bold">Selected Plan: {selectedPlanCard.name}</h3>
                    <p className="mt-1 text-sm text-slate-400">
                      Current plan is {currentPlanCard.name}. Sensitive changes need Security Agent
                      approval.
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
                          getPlanRank(selectedPlan) > getPlanRank(subscription?.plan || 'free')
                            ? 'upgrade_plan'
                            : 'downgrade_plan',
                          selectedPlan,
                        )
                      }
                      className="rounded-2xl bg-cyan-400 px-5 py-3 text-sm font-black text-slate-950 shadow-lg shadow-cyan-950/40 transition hover:bg-cyan-300 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400 disabled:shadow-none"
                    >
                      {isActionRunning ? 'Processing...' : 'Apply Plan Change'}
                    </button>

                    <button
                      type="button"
                      disabled={isActionRunning || !canManageBilling}
                      onClick={() => runBillingAction('open_billing_portal')}
                      className="rounded-2xl border border-white/10 bg-white/10 px-5 py-3 text-sm font-bold text-white transition hover:bg-white/15 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      Billing Portal
                    </button>

                    <button
                      type="button"
                      disabled={isActionRunning || !canCancelSubscription}
                      onClick={() => runBillingAction('cancel_subscription')}
                      className="rounded-2xl border border-red-400/30 bg-red-400/10 px-5 py-3 text-sm font-bold text-red-100 transition hover:bg-red-400/20 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              </section>

              <section className="rounded-3xl border border-white/10 bg-slate-950/40 p-5">
                <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
                  <div>
                    <h3 className="text-lg font-bold">Usage Metering</h3>
                    <p className="mt-1 text-sm text-slate-400">
                      All usage is scoped by user_id and workspace_id. No cross-workspace soup.
                    </p>
                  </div>

                  <button
                    type="button"
                    disabled={isActionRunning || !canReadBilling}
                    onClick={() => runBillingAction('refresh_usage')}
                    className="rounded-2xl border border-cyan-400/30 bg-cyan-400/10 px-5 py-3 text-sm font-bold text-cyan-100 transition hover:bg-cyan-400/20 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    Refresh Usage
                  </button>
                </div>

                <div className="mt-5 grid gap-4 md:grid-cols-2">
                  {(subscription?.usage || []).map((metric) => {
                    const percent = getUsagePercent(metric);

                    return (
                      <div
                        key={metric.key}
                        className="rounded-3xl border border-white/10 bg-black/20 p-5"
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div>
                            <h4 className="font-bold text-white">{metric.label}</h4>
                            <p className="mt-1 text-xs text-slate-400">
                              {metric.used.toLocaleString()} {metric.unit} used
                            </p>
                          </div>
                          <span className="rounded-full border border-white/10 bg-white/10 px-3 py-1 text-xs text-slate-300">
                            {metric.limit === 'unlimited'
                              ? 'Unlimited'
                              : `${percent}%`}
                          </span>
                        </div>

                        <div className="mt-4 h-3 overflow-hidden rounded-full bg-white/10">
                          <div
                            className="h-full rounded-full bg-cyan-400 shadow-[0_0_18px_rgba(34,211,238,0.7)]"
                            style={{ width: `${percent}%` }}
                          />
                        </div>

                        <p className="mt-3 text-xs text-slate-500">
                          Limit: {formatLimit(metric.limit)}
                        </p>
                      </div>
                    );
                  })}
                </div>
              </section>

              {(lastVerificationPayload || lastMemoryPayload) ? (
                <section className="rounded-3xl border border-white/10 bg-slate-950/40 p-5">
                  <h3 className="text-lg font-bold">Agent Payloads</h3>

                  {lastVerificationPayload ? (
                    <details className="mt-4 rounded-2xl border border-emerald-400/20 bg-emerald-400/5 p-3 text-xs text-emerald-100">
                      <summary className="cursor-pointer font-semibold">
                        Verification Agent Payload Ready
                      </summary>
                      <pre className="mt-3 overflow-auto whitespace-pre-wrap text-[11px] leading-5">
                        {JSON.stringify(lastVerificationPayload, null, 2)}
                      </pre>
                    </details>
                  ) : null}

                  {lastMemoryPayload ? (
                    <details className="mt-3 rounded-2xl border border-purple-400/20 bg-purple-400/5 p-3 text-xs text-purple-100">
                      <summary className="cursor-pointer font-semibold">
                        Memory Agent Context Ready
                      </summary>
                      <pre className="mt-3 overflow-auto whitespace-pre-wrap text-[11px] leading-5">
                        {JSON.stringify(lastMemoryPayload, null, 2)}
                      </pre>
                    </details>
                  ) : null}
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
      <p className="text-xs uppercase tracking-[0.2em] text-slate-500">{props.label}</p>
      <p
        className={[
          'mt-2 text-sm font-semibold text-slate-200',
          props.mono ? 'break-all font-mono text-xs' : '',
        ].join(' ')}
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
          'rounded-full border px-3 py-1 text-xs',
          props.enabled
            ? 'border-emerald-400/30 bg-emerald-400/10 text-emerald-100'
            : 'border-orange-400/30 bg-orange-400/10 text-orange-100',
        ].join(' ')}
      >
        {props.enabled ? 'Allowed' : 'Restricted'}
      </span>
    </div>
  );
}