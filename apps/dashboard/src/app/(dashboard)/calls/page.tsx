"use client";

import React, {
  FormEvent,
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";
import { useRouter } from "next/navigation";
import { SessionData, UserPlan, UserRole, readSession } from "@/lib/auth";
import { EmptyState } from "@/components/state/EmptyState";
import { ErrorState } from "@/components/state/ErrorState";
import { ForbiddenState } from "@/components/state/ForbiddenState";
import { LoadingState } from "@/components/state/LoadingState";

type ApiMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

type RoleName = UserRole;

type SubscriptionPlan = UserPlan;

type CallStatus =
  | "queued"
  | "ringing"
  | "in_progress"
  | "missed"
  | "completed"
  | "follow_up"
  | "blocked"
  | "failed";

type LeadIntent =
  | "new_lead"
  | "support"
  | "billing"
  | "sales"
  | "appointment"
  | "unknown";

type CallRisk = "low" | "medium" | "high" | "critical";

type SecurityDecisionOutcome = "approved" | "denied" | "requires_approval";

type AgentKey =
  | "master_agent"
  | "security_agent"
  | "verification_agent"
  | "memory_agent"
  | "workflow_agent"
  | "call_agent"
  | "crm_agent";

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

type CallRecord = {
  call_id: string;
  user_id: string;
  workspace_id: string;
  caller_name: string;
  caller_phone: string;
  caller_email?: string;
  company?: string;
  status: CallStatus;
  intent: LeadIntent;
  priority: "normal" | "high" | "urgent";
  source: string;
  summary: string;
  notes: string;
  assigned_agent: AgentKey;
  started_at: string;
  ended_at?: string;
  duration_seconds?: number;
  risk: CallRisk;
  verification?: VerificationResult;
};

type ReceptionistAction = {
  action_id: string;
  call_id: string;
  action_type:
    | "answer_call"
    | "create_lead"
    | "schedule_follow_up"
    | "send_callback_sms"
    | "transfer_call"
    | "save_call_memory"
    | "prepare_verification";
  user_id: string;
  workspace_id: string;
  actor_agent: AgentKey | "dashboard_receptionist";
  target_resource: string;
  payload: Record<string, unknown>;
  requires_state_change: boolean;
  risk: CallRisk;
  created_at: string;
};

// The real POST /security/decide response's `data.decision` shape
// (apps/api/routes/security.py), same contract billing.tsx/creator.tsx use.
type SecurityDecision = {
  outcome: SecurityDecisionOutcome;
  risk_level: CallRisk;
  decision_mode: string;
  reason: string;
  action: string;
  category: string;
  requires_approval: boolean;
  approval_id?: string;
};

// The `verification` field a real backend mutation response would include,
// prepared server-side -- not fabricated client-side like the old
// VerificationPayload/MemoryPayload/AuditEventPayload types were.
type VerificationResult = Record<string, unknown>;

type CallStats = {
  calls_today: number;
  active_calls: number;
  missed_calls: number;
  follow_ups: number;
};

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
  name: "Digital Promotix Operator",
  email: "operator@example.test",
  role: "owner",
  plan: "enterprise",
  permissions: [
    "dashboard:calls:read",
    "dashboard:calls:write",
    "agent:call_agent:access",
    "agent:security_agent:access",
    "agent:verification_agent:access",
    "agent:memory_agent:access",
    "agent:workflow_agent:access",
    "call:answer",
    "call:create_lead",
    "call:schedule_follow_up",
    "call:send_callback",
    "security:review:sensitive_action",
    "audit:write",
    "memory:write",
    "verification:prepare",
  ],
  plan_features: [
    "call_agent",
    "ai_receptionist",
    "call_lead_capture",
    "call_follow_ups",
    "security_agent_review",
    "verification_payloads",
    "memory_context",
    "audit_logs",
  ],
};

// The old LOCAL_CALLS array (three fully-written fake caller records with
// invented names/phone numbers/summaries) has been removed -- no real calls
// backend exists yet (no apps/api/routes/calls.py), so the call queue now
// stays honestly empty until a real Call Agent API is wired up, instead of
// presenting fabricated callers as if they were live data.

const SCRIPT_SECTIONS = [
  {
    title: "Opening",
    text: "Hi, thanks for calling. This is William, the AI receptionist for Digital Promotix. How can I help you today?",
  },
  {
    title: "Lead Qualification",
    text: "May I confirm your name, phone number, email, company, and what service you are interested in?",
  },
  {
    title: "Intent Capture",
    text: "Are you looking for pricing, support, a callback, a demo, or help starting a new project?",
  },
  {
    title: "Close",
    text: "Perfect. I’ve captured your details and will prepare the next step. You’ll receive a follow-up shortly.",
  },
];

function createId(prefix: string): string {
  const randomValue =
    typeof crypto !== "undefined" && "randomUUID" in crypto
      ? crypto.randomUUID()
      : `${Date.now()}_${Math.random().toString(16).slice(2)}`;

  return `${prefix}_${randomValue.replace(/-/g, "")}`;
}

function nowIso(): string {
  return new Date().toISOString();
}

function hasPermission(user: ConsoleUser, permission: string): boolean {
  return user.permissions.includes(permission);
}

function hasAllPermissions(user: ConsoleUser, permissions: string[]): boolean {
  return permissions.every((permission) => hasPermission(user, permission));
}

function hasPlanFeature(user: ConsoleUser, feature: string): boolean {
  return user.plan_features.includes(feature);
}

function sanitizeError(error: unknown): string {
  if (error instanceof Error && error.message) {
    if (
      /token|secret|password|key|authorization|credential/i.test(error.message)
    ) {
      return "Request failed safely. Sensitive error details were hidden.";
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

function getStatusBadgeClass(status: CallStatus): string {
  switch (status) {
    case "ringing":
      return "border-cyan-400/40 bg-cyan-400/10 text-cyan-100";
    case "in_progress":
      return "border-blue-400/40 bg-blue-400/10 text-blue-100";
    case "completed":
      return "border-emerald-400/40 bg-emerald-400/10 text-emerald-100";
    case "follow_up":
      return "border-purple-400/40 bg-purple-400/10 text-purple-100";
    case "missed":
      return "border-orange-400/40 bg-orange-400/10 text-orange-100";
    case "blocked":
    case "failed":
      return "border-red-400/40 bg-red-400/10 text-red-100";
    case "queued":
    default:
      return "border-slate-400/30 bg-slate-400/10 text-slate-200";
  }
}

function getRiskBadgeClass(risk: CallRisk): string {
  switch (risk) {
    case "critical":
      return "border-red-500/40 bg-red-500/10 text-red-200";
    case "high":
      return "border-orange-500/40 bg-orange-500/10 text-orange-200";
    case "medium":
      return "border-yellow-500/40 bg-yellow-500/10 text-yellow-100";
    case "low":
    default:
      return "border-emerald-500/40 bg-emerald-500/10 text-emerald-200";
  }
}

function getPriorityClass(priority: CallRecord["priority"]): string {
  switch (priority) {
    case "urgent":
      return "border-red-400/30 bg-red-400/10 text-red-100";
    case "high":
      return "border-orange-400/30 bg-orange-400/10 text-orange-100";
    case "normal":
    default:
      return "border-slate-400/30 bg-slate-400/10 text-slate-200";
  }
}

function detectRiskFromAction(
  actionType: ReceptionistAction["action_type"],
): CallRisk {
  if (actionType === "send_callback_sms" || actionType === "create_lead")
    return "high";
  if (actionType === "schedule_follow_up" || actionType === "transfer_call")
    return "medium";
  return "low";
}

function isSensitiveAction(
  actionType: ReceptionistAction["action_type"],
): boolean {
  return [
    "create_lead",
    "send_callback_sms",
    "transfer_call",
    "schedule_follow_up",
  ].includes(actionType);
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
 * the server-side role/plan checks on each endpoint, not these
 * client-side display flags.
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

// There is no apps/api/routes/calls.py in this deployment -- this is left
// pointed at the real, currently 404-ing /calls path (not a fabricated
// "/api/calls" guess) so it starts working automatically once a real Call
// Agent backend exists, matching the crm/page.tsx and creator/page.tsx
// pattern for pages with no backend yet.
async function loadCalls(): Promise<CallRecord[]> {
  const response = await apiRequest<{
    success: boolean;
    data: CallRecord[];
    error?: { message: string };
  }>("/calls");

  if (!response.success) {
    throw new Error(response.error?.message || "Unable to load calls.");
  }

  return response.data || [];
}

/**
 * Real Security Agent gate (POST /security/decide, apps/api/routes/
 * security.py) -- evaluated before any state-changing receptionist action.
 * Replaces the old submitSecurityReview()'s fabricated always-approve
 * fallback and made-up "/api/security/review" endpoint.
 */
async function decideRiskyAction(
  action: ReceptionistAction,
): Promise<{ decision: SecurityDecision; verification: VerificationResult }> {
  const response = await apiRequest<{
    ok: boolean;
    message: string;
    data: { decision: SecurityDecision };
    verification?: VerificationResult;
  }>("/security/decide", {
    method: "POST",
    body: {
      action: action.action_type,
      category: "calls",
      payload: action.payload,
      requested_risk_level: action.risk,
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

async function submitCallAction(action: ReceptionistAction): Promise<{
  success: boolean;
  status: CallStatus;
  message: string;
}> {
  return apiRequest<{
    success: boolean;
    status: CallStatus;
    message: string;
    error?: { message: string };
  }>("/calls/actions", {
    method: "POST",
    body: action,
  });
}

function StatCard(props: { label: string; value: number; hint: string }) {
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
  const [calls, setCalls] = useState<CallRecord[]>([]);
  const [selectedCallId, setSelectedCallId] = useState<string>("");
  const [isBooting, setIsBooting] = useState(true);
  const [isActionRunning, setIsActionRunning] = useState(false);
  const [safeError, setSafeError] = useState<string | null>(null);
  const [operatorNote, setOperatorNote] = useState("");
  const [callbackTime, setCallbackTime] = useState("");
  const [lastSecurityDecision, setLastSecurityDecision] =
    useState<SecurityDecision | null>(null);
  const [lastVerification, setLastVerification] =
    useState<VerificationResult | null>(null);

  const canReadCalls = useMemo(() => {
    return (
      hasPermission(user, "dashboard:calls:read") &&
      hasPermission(user, "agent:call_agent:access") &&
      hasPlanFeature(user, "call_agent")
    );
  }, [user]);

  const canWriteCalls = useMemo(() => {
    return (
      hasPermission(user, "dashboard:calls:write") &&
      hasPermission(user, "call:answer") &&
      hasPlanFeature(user, "ai_receptionist")
    );
  }, [user]);

  const canCreateLead = useMemo(() => {
    return (
      hasPermission(user, "call:create_lead") &&
      hasPlanFeature(user, "call_lead_capture")
    );
  }, [user]);

  const canFollowUp = useMemo(() => {
    return (
      hasPermission(user, "call:schedule_follow_up") &&
      hasPlanFeature(user, "call_follow_ups")
    );
  }, [user]);

  const selectedCall = useMemo(() => {
    return (
      calls.find((call) => call.call_id === selectedCallId) || calls[0] || null
    );
  }, [calls, selectedCallId]);

  const stats = useMemo<CallStats>(() => {
    return {
      calls_today: calls.length,
      active_calls: calls.filter(
        (call) => call.status === "ringing" || call.status === "in_progress",
      ).length,
      missed_calls: calls.filter((call) => call.status === "missed").length,
      follow_ups: calls.filter((call) => call.status === "follow_up").length,
    };
  }, [calls]);

  const scopedCalls = useMemo(() => {
    return calls.filter(
      (call) =>
        call.user_id === user.user_id &&
        call.workspace_id === user.workspace_id,
    );
  }, [calls, user.user_id, user.workspace_id]);

  const refreshCalls = useCallback(async () => {
    const loadedCalls = await loadCalls();
    setCalls(loadedCalls);

    if (loadedCalls.length > 0) {
      setSelectedCallId((current) => current || loadedCalls[0].call_id);
    }
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
        await refreshCalls();
      } catch {
        // A real session exists but there is no real calls backend to call
        // yet (no apps/api/routes/calls.py) -- show a safe, honest message
        // instead of silently swapping in fake demo callers, and without
        // forcing a logout the user's session doesn't actually warrant.
        if (isMounted) {
          setSafeError(
            "Call Agent is not connected to a backend yet -- no calls API exists in this deployment.",
          );
        }
      } finally {
        if (isMounted) setIsBooting(false);
      }
    }

    boot();

    return () => {
      isMounted = false;
    };
  }, [refreshCalls, router]);

  const handleRetry = useCallback(() => {
    setSafeError(null);
    setIsBooting(true);
    refreshCalls()
      .catch((error) => setSafeError(sanitizeError(error)))
      .finally(() => setIsBooting(false));
  }, [refreshCalls]);

  const updateCall = useCallback(
    (callId: string, patch: Partial<CallRecord>) => {
      setCalls((current) =>
        current.map((call) =>
          call.call_id === callId ? { ...call, ...patch } : call,
        ),
      );
    },
    [],
  );

  const runReceptionistAction = useCallback(
    async (actionType: ReceptionistAction["action_type"]) => {
      if (!selectedCall || isActionRunning) return;

      setSafeError(null);

      if (!canReadCalls || !canWriteCalls) {
        setSafeError(
          "Your role or subscription plan cannot operate the Call Agent panel.",
        );
        return;
      }

      if (actionType === "create_lead" && !canCreateLead) {
        setSafeError("Your role or plan does not allow call-to-lead creation.");
        return;
      }

      if (actionType === "schedule_follow_up" && !canFollowUp) {
        setSafeError(
          "Your role or plan does not allow call follow-up scheduling.",
        );
        return;
      }

      if (
        selectedCall.user_id !== user.user_id ||
        selectedCall.workspace_id !== user.workspace_id
      ) {
        setSafeError(
          "Cross-user or cross-workspace call access was blocked safely.",
        );
        return;
      }

      const actionId = createId("call_action");
      const risk = detectRiskFromAction(actionType);

      const action: ReceptionistAction = {
        action_id: actionId,
        call_id: selectedCall.call_id,
        action_type: actionType,
        user_id: user.user_id,
        workspace_id: user.workspace_id,
        actor_agent: "dashboard_receptionist",
        target_resource: "calls/receptionist_panel",
        payload: {
          call_id: selectedCall.call_id,
          caller_name: selectedCall.caller_name,
          caller_phone: selectedCall.caller_phone,
          caller_email: selectedCall.caller_email || "",
          company: selectedCall.company || "",
          intent: selectedCall.intent,
          operator_note: operatorNote,
          callback_time: callbackTime,
          target_user_id: user.user_id,
          target_workspace_id: user.workspace_id,
        },
        requires_state_change: isSensitiveAction(actionType),
        risk,
        created_at: nowIso(),
      };

      setIsActionRunning(true);

      try {
        let verification: VerificationResult | null = null;

        if (action.requires_state_change) {
          const decisionResult = await decideRiskyAction(action);
          setLastSecurityDecision(decisionResult.decision);
          setLastVerification(decisionResult.verification);
          verification = decisionResult.verification;

          if (decisionResult.decision.outcome !== "approved") {
            updateCall(selectedCall.call_id, {
              status: "blocked",
              risk: decisionResult.decision.risk_level,
              notes:
                `${selectedCall.notes}\nSecurity Agent: ${decisionResult.decision.reason}`.trim(),
            });
            setSafeError(
              `Security Agent ${decisionResult.decision.outcome === "denied" ? "denied" : "requires approval for"} this action: ${decisionResult.decision.reason}`,
            );
            return;
          }
        }

        const response = await submitCallAction(action);

        if (!response.success) {
          throw new Error(response.message || "Call action failed safely.");
        }

        const nextStatus = response.status;
        const actionSummary = [
          response.message,
          operatorNote ? `Operator note: ${operatorNote}` : "",
          callbackTime ? `Callback time: ${callbackTime}` : "",
        ]
          .filter(Boolean)
          .join("\n");

        updateCall(selectedCall.call_id, {
          status: nextStatus,
          notes: `${selectedCall.notes}\n${actionSummary}`.trim(),
          risk,
          verification: verification || selectedCall.verification,
          ended_at:
            nextStatus === "completed" || nextStatus === "follow_up"
              ? nowIso()
              : selectedCall.ended_at,
        });

        setOperatorNote("");
        setCallbackTime("");
      } catch (error) {
        const message = sanitizeError(error);
        setSafeError(message);

        updateCall(selectedCall.call_id, {
          status: "failed",
          notes: `${selectedCall.notes}\nSafe Error: ${message}`.trim(),
        });
      } finally {
        setIsActionRunning(false);
      }
    },
    [
      callbackTime,
      canCreateLead,
      canFollowUp,
      canReadCalls,
      canWriteCalls,
      isActionRunning,
      operatorNote,
      selectedCall,
      updateCall,
      user,
    ],
  );

  const handleCreateManualCall = useCallback(
    (event: FormEvent<HTMLFormElement>) => {
      event.preventDefault();

      if (!canWriteCalls) {
        setSafeError("Your role or plan does not allow manual call creation.");
        return;
      }

      const formData = new FormData(event.currentTarget);
      const callerName = String(formData.get("caller_name") || "").trim();
      const callerPhone = String(formData.get("caller_phone") || "").trim();
      const callerEmail = String(formData.get("caller_email") || "").trim();
      const intent = String(formData.get("intent") || "unknown") as LeadIntent;

      if (!callerName || !callerPhone) {
        setSafeError("Caller name and phone are required.");
        return;
      }

      const call: CallRecord = {
        call_id: createId("call"),
        user_id: user.user_id,
        workspace_id: user.workspace_id,
        caller_name: callerName,
        caller_phone: callerPhone,
        caller_email: callerEmail || undefined,
        company: String(formData.get("company") || "").trim(),
        status: "queued",
        intent,
        priority: "normal",
        source: "Manual Receptionist Entry",
        summary: "Manual call record created from receptionist panel.",
        notes: "",
        assigned_agent: "call_agent",
        started_at: nowIso(),
        risk: "low",
      };

      setCalls((current) => [call, ...current]);
      setSelectedCallId(call.call_id);
      event.currentTarget.reset();
      setSafeError(null);
    },
    [canWriteCalls, user.user_id, user.workspace_id],
  );

  if (isBooting) {
    return (
      <div className="rounded-[28px] bg-slate-950 px-4 py-6 text-white sm:px-6 lg:px-8">
        <section className="mx-auto flex min-h-[70vh] max-w-7xl items-center justify-center">
          <LoadingState variant="dark" title="Loading Call Agent panel..." />
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
              Call Agent / AI Receptionist
            </div>
            <h1 className="text-3xl font-black tracking-tight sm:text-4xl lg:text-5xl">
              Receptionist Command Panel
            </h1>
            <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-300 sm:text-base">
              Manage inbound calls, qualify leads, prepare callbacks, route
              sensitive actions through Security Agent, store useful Memory
              Agent context, and prepare Verification Agent payloads. Clean,
              scoped, and not held together with digital duct tape.
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

        {!canReadCalls ? (
          <div className="mb-6">
            <ForbiddenState
              variant="dark"
              message="Your current role or subscription plan cannot access the Call Agent panel."
            />
          </div>
        ) : null}

        <div className="mb-6 grid gap-4 md:grid-cols-4">
          <StatCard
            label="Calls Today"
            value={stats.calls_today}
            hint="Scoped to this workspace"
          />
          <StatCard
            label="Active Calls"
            value={stats.active_calls}
            hint="Ringing or in progress"
          />
          <StatCard
            label="Missed Calls"
            value={stats.missed_calls}
            hint="Needs fast follow-up"
          />
          <StatCard
            label="Follow-Ups"
            value={stats.follow_ups}
            hint="Callback queue"
          />
        </div>

        <div className="grid gap-6 lg:grid-cols-[390px_1fr]">
          <aside className="space-y-6">
            <section className="rounded-3xl border border-white/10 bg-white/[0.05] p-4 shadow-2xl shadow-black/20">
              <div className="mb-4 flex items-center justify-between">
                <div>
                  <h2 className="text-lg font-bold">Call Queue</h2>
                  <p className="text-xs text-slate-400">
                    User/workspace scoped records
                  </p>
                </div>
                <span className="rounded-full bg-white/10 px-3 py-1 text-xs text-slate-300">
                  {scopedCalls.length} calls
                </span>
              </div>

              <div className="max-h-[570px] space-y-3 overflow-auto pr-1">
                {scopedCalls.length === 0 ? (
                  <EmptyState
                    variant="dark"
                    icon="☎"
                    title="No calls yet"
                    message="New inbound calls and manual receptionist entries will appear here."
                  />
                ) : (
                  scopedCalls.map((call) => {
                    const isSelected = selectedCall?.call_id === call.call_id;

                    return (
                      <button
                        key={call.call_id}
                        type="button"
                        onClick={() => setSelectedCallId(call.call_id)}
                        className={[
                          "w-full rounded-2xl border p-4 text-left transition",
                          isSelected
                            ? "border-cyan-400/50 bg-cyan-400/10 shadow-lg shadow-cyan-950/40"
                            : "border-white/10 bg-slate-950/40 hover:border-white/20 hover:bg-white/[0.07]",
                        ].join(" ")}
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div>
                            <h3 className="font-semibold text-white">
                              {call.caller_name}
                            </h3>
                            <p className="mt-1 text-xs text-slate-400">
                              {call.caller_phone}
                            </p>
                          </div>
                          <span
                            className={[
                              "rounded-full border px-2 py-1 text-[10px]",
                              getPriorityClass(call.priority),
                            ].join(" ")}
                          >
                            {formatLabel(call.priority)}
                          </span>
                        </div>

                        <p className="mt-3 line-clamp-2 text-xs leading-5 text-slate-400">
                          {call.summary}
                        </p>

                        <div className="mt-3 flex flex-wrap gap-2">
                          <span
                            className={[
                              "rounded-full border px-2 py-1 text-[10px]",
                              getStatusBadgeClass(call.status),
                            ].join(" ")}
                          >
                            {formatLabel(call.status)}
                          </span>
                          <span
                            className={[
                              "rounded-full border px-2 py-1 text-[10px]",
                              getRiskBadgeClass(call.risk),
                            ].join(" ")}
                          >
                            {formatLabel(call.risk)}
                          </span>
                        </div>
                      </button>
                    );
                  })
                )}
              </div>
            </section>

            <section className="rounded-3xl border border-white/10 bg-white/[0.05] p-4 shadow-2xl shadow-black/20">
              <h2 className="text-lg font-bold">Manual Call Entry</h2>
              <p className="mt-1 text-xs text-slate-400">
                For calls captured outside the dialer.
              </p>

              <form
                onSubmit={handleCreateManualCall}
                className="mt-4 space-y-3"
              >
                <input
                  name="caller_name"
                  placeholder="Caller name"
                  className="w-full rounded-2xl border border-white/10 bg-slate-950/60 px-4 py-3 text-sm text-white outline-none placeholder:text-slate-500 focus:border-cyan-400/40"
                />
                <input
                  name="caller_phone"
                  placeholder="Phone number"
                  className="w-full rounded-2xl border border-white/10 bg-slate-950/60 px-4 py-3 text-sm text-white outline-none placeholder:text-slate-500 focus:border-cyan-400/40"
                />
                <input
                  name="caller_email"
                  placeholder="Email optional"
                  className="w-full rounded-2xl border border-white/10 bg-slate-950/60 px-4 py-3 text-sm text-white outline-none placeholder:text-slate-500 focus:border-cyan-400/40"
                />
                <input
                  name="company"
                  placeholder="Company optional"
                  className="w-full rounded-2xl border border-white/10 bg-slate-950/60 px-4 py-3 text-sm text-white outline-none placeholder:text-slate-500 focus:border-cyan-400/40"
                />
                <select
                  name="intent"
                  className="w-full rounded-2xl border border-white/10 bg-slate-950/60 px-4 py-3 text-sm text-white outline-none focus:border-cyan-400/40"
                  defaultValue="new_lead"
                >
                  <option value="new_lead">New Lead</option>
                  <option value="sales">Sales</option>
                  <option value="support">Support</option>
                  <option value="billing">Billing</option>
                  <option value="appointment">Appointment</option>
                  <option value="unknown">Unknown</option>
                </select>

                <button
                  type="submit"
                  disabled={!canWriteCalls}
                  className="w-full rounded-2xl bg-cyan-400 px-5 py-3 text-sm font-black text-slate-950 shadow-lg shadow-cyan-950/40 transition hover:bg-cyan-300 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400 disabled:shadow-none"
                >
                  Add Call
                </button>
              </form>
            </section>
          </aside>

          <section className="min-h-[780px] rounded-3xl border border-white/10 bg-white/[0.05] shadow-2xl shadow-black/30">
            {selectedCall ? (
              <>
                <div className="border-b border-white/10 p-5">
                  <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
                    <div>
                      <div className="flex flex-wrap items-center gap-3">
                        <h2 className="text-2xl font-black">
                          {selectedCall.caller_name}
                        </h2>
                        <span
                          className={[
                            "rounded-full border px-3 py-1 text-xs",
                            getStatusBadgeClass(selectedCall.status),
                          ].join(" ")}
                        >
                          {formatLabel(selectedCall.status)}
                        </span>
                        <span
                          className={[
                            "rounded-full border px-3 py-1 text-xs",
                            getRiskBadgeClass(selectedCall.risk),
                          ].join(" ")}
                        >
                          Risk: {formatLabel(selectedCall.risk)}
                        </span>
                      </div>

                      <p className="mt-2 text-sm text-slate-300">
                        {selectedCall.caller_phone}
                      </p>
                      <p className="mt-1 text-xs text-slate-500">
                        {selectedCall.caller_email || "No email captured"} •{" "}
                        {selectedCall.company || "No company captured"}
                      </p>
                    </div>

                    <div className="rounded-2xl border border-white/10 bg-slate-950/50 p-4 text-xs text-slate-400">
                      <p>
                        <span className="text-slate-500">call_id:</span>{" "}
                        <span className="font-mono text-slate-300">
                          {selectedCall.call_id}
                        </span>
                      </p>
                      <p className="mt-2">
                        <span className="text-slate-500">user_id:</span>{" "}
                        <span className="font-mono text-slate-300">
                          {selectedCall.user_id}
                        </span>
                      </p>
                      <p className="mt-2">
                        <span className="text-slate-500">workspace_id:</span>{" "}
                        <span className="font-mono text-slate-300">
                          {selectedCall.workspace_id}
                        </span>
                      </p>
                    </div>
                  </div>

                  {lastSecurityDecision ? (
                    <div className="mt-4 rounded-2xl border border-cyan-500/20 bg-cyan-500/10 p-3 text-sm text-cyan-100">
                      <div className="font-semibold">
                        Last Security Decision:{" "}
                        {formatLabel(lastSecurityDecision.outcome)}
                      </div>
                      <p className="mt-1 text-cyan-100/80">
                        {lastSecurityDecision.reason}
                      </p>
                    </div>
                  ) : null}
                </div>

                <div className="grid gap-6 p-5 xl:grid-cols-[1fr_360px]">
                  <div className="space-y-6">
                    <section className="rounded-3xl border border-white/10 bg-slate-950/40 p-5">
                      <h3 className="text-lg font-bold">Call Intelligence</h3>
                      <div className="mt-4 grid gap-3 md:grid-cols-2">
                        <InfoTile
                          label="Intent"
                          value={formatLabel(selectedCall.intent)}
                        />
                        <InfoTile label="Source" value={selectedCall.source} />
                        <InfoTile
                          label="Started"
                          value={new Date(
                            selectedCall.started_at,
                          ).toLocaleString()}
                        />
                        <InfoTile
                          label="Duration"
                          value={
                            selectedCall.duration_seconds
                              ? `${Math.round(selectedCall.duration_seconds / 60)} min`
                              : "Live / pending"
                          }
                        />
                      </div>

                      <div className="mt-4 rounded-2xl border border-white/10 bg-black/20 p-4">
                        <p className="text-xs uppercase tracking-[0.2em] text-slate-500">
                          Summary
                        </p>
                        <p className="mt-2 text-sm leading-6 text-slate-200">
                          {selectedCall.summary}
                        </p>
                      </div>

                      <div className="mt-4 rounded-2xl border border-white/10 bg-black/20 p-4">
                        <p className="text-xs uppercase tracking-[0.2em] text-slate-500">
                          Notes
                        </p>
                        <p className="mt-2 whitespace-pre-wrap text-sm leading-6 text-slate-200">
                          {selectedCall.notes ||
                            "No notes yet. Add one below after the call action."}
                        </p>
                      </div>
                    </section>

                    <section className="rounded-3xl border border-white/10 bg-slate-950/40 p-5">
                      <h3 className="text-lg font-bold">
                        Receptionist Action Center
                      </h3>
                      <p className="mt-1 text-sm text-slate-400">
                        Sensitive actions route through Security Agent before
                        execution.
                      </p>

                      <div className="mt-4 grid gap-3 md:grid-cols-2">
                        <button
                          type="button"
                          disabled={isActionRunning || !canWriteCalls}
                          onClick={() => runReceptionistAction("answer_call")}
                          className="rounded-2xl border border-cyan-400/30 bg-cyan-400/10 px-4 py-4 text-left transition hover:bg-cyan-400/20 disabled:cursor-not-allowed disabled:opacity-50"
                        >
                          <div className="font-bold text-cyan-100">
                            Answer / Start Call
                          </div>
                          <p className="mt-1 text-xs leading-5 text-cyan-100/70">
                            Mark this call as in progress and attach
                            receptionist context.
                          </p>
                        </button>

                        <button
                          type="button"
                          disabled={isActionRunning || !canCreateLead}
                          onClick={() => runReceptionistAction("create_lead")}
                          className="rounded-2xl border border-emerald-400/30 bg-emerald-400/10 px-4 py-4 text-left transition hover:bg-emerald-400/20 disabled:cursor-not-allowed disabled:opacity-50"
                        >
                          <div className="font-bold text-emerald-100">
                            Create CRM Lead
                          </div>
                          <p className="mt-1 text-xs leading-5 text-emerald-100/70">
                            High-risk state change. Security Agent approval
                            required.
                          </p>
                        </button>

                        <button
                          type="button"
                          disabled={isActionRunning || !canFollowUp}
                          onClick={() =>
                            runReceptionistAction("schedule_follow_up")
                          }
                          className="rounded-2xl border border-purple-400/30 bg-purple-400/10 px-4 py-4 text-left transition hover:bg-purple-400/20 disabled:cursor-not-allowed disabled:opacity-50"
                        >
                          <div className="font-bold text-purple-100">
                            Schedule Follow-Up
                          </div>
                          <p className="mt-1 text-xs leading-5 text-purple-100/70">
                            Prepare callback task for the Workflow Agent.
                          </p>
                        </button>

                        <button
                          type="button"
                          disabled={
                            isActionRunning ||
                            !hasPermission(user, "call:send_callback")
                          }
                          onClick={() =>
                            runReceptionistAction("send_callback_sms")
                          }
                          className="rounded-2xl border border-orange-400/30 bg-orange-400/10 px-4 py-4 text-left transition hover:bg-orange-400/20 disabled:cursor-not-allowed disabled:opacity-50"
                        >
                          <div className="font-bold text-orange-100">
                            Send Callback SMS
                          </div>
                          <p className="mt-1 text-xs leading-5 text-orange-100/70">
                            Sensitive outbound communication. Security review
                            required.
                          </p>
                        </button>
                      </div>

                      <div className="mt-5 grid gap-4 md:grid-cols-2">
                        <label className="block">
                          <span className="text-xs uppercase tracking-[0.2em] text-slate-500">
                            Operator Note
                          </span>
                          <textarea
                            value={operatorNote}
                            onChange={(event) =>
                              setOperatorNote(event.target.value)
                            }
                            rows={5}
                            placeholder="Add call notes, lead qualification, objections, next step..."
                            className="mt-2 w-full resize-none rounded-2xl border border-white/10 bg-slate-950/70 px-4 py-3 text-sm text-white outline-none placeholder:text-slate-500 focus:border-cyan-400/40"
                          />
                        </label>

                        <label className="block">
                          <span className="text-xs uppercase tracking-[0.2em] text-slate-500">
                            Callback Time
                          </span>
                          <input
                            type="datetime-local"
                            value={callbackTime}
                            onChange={(event) =>
                              setCallbackTime(event.target.value)
                            }
                            className="mt-2 w-full rounded-2xl border border-white/10 bg-slate-950/70 px-4 py-3 text-sm text-white outline-none focus:border-cyan-400/40"
                          />
                          <p className="mt-3 text-xs leading-5 text-slate-400">
                            Used when scheduling follow-up or preparing callback
                            workflow.
                          </p>
                        </label>
                      </div>
                    </section>

                    {selectedCall.verification ? (
                      <section className="rounded-3xl border border-white/10 bg-slate-950/40 p-5">
                        <h3 className="text-lg font-bold">Agent Payloads</h3>

                        <details className="mt-4 rounded-2xl border border-emerald-400/20 bg-emerald-400/5 p-3 text-xs text-emerald-100">
                          <summary className="cursor-pointer font-semibold">
                            Verification Agent Payload Ready
                          </summary>
                          <pre className="mt-3 overflow-auto whitespace-pre-wrap text-[11px] leading-5">
                            {JSON.stringify(selectedCall.verification, null, 2)}
                          </pre>
                        </details>
                      </section>
                    ) : null}
                  </div>

                  <aside className="space-y-6">
                    <section className="rounded-3xl border border-white/10 bg-slate-950/40 p-5">
                      <h3 className="text-lg font-bold">Live Script</h3>
                      <p className="mt-1 text-xs text-slate-400">
                        Receptionist flow for consistent call handling.
                      </p>

                      <div className="mt-4 space-y-3">
                        {SCRIPT_SECTIONS.map((section) => (
                          <div
                            key={section.title}
                            className="rounded-2xl border border-white/10 bg-black/20 p-4"
                          >
                            <p className="text-xs uppercase tracking-[0.2em] text-cyan-300">
                              {section.title}
                            </p>
                            <p className="mt-2 text-sm leading-6 text-slate-300">
                              {section.text}
                            </p>
                          </div>
                        ))}
                      </div>
                    </section>

                    <section className="rounded-3xl border border-white/10 bg-slate-950/40 p-5">
                      <h3 className="text-lg font-bold">Access Control</h3>
                      <div className="mt-4 space-y-3 text-sm">
                        <AccessRow label="Read Calls" enabled={canReadCalls} />
                        <AccessRow
                          label="Operate Receptionist"
                          enabled={canWriteCalls}
                        />
                        <AccessRow
                          label="Create CRM Lead"
                          enabled={canCreateLead}
                        />
                        <AccessRow
                          label="Schedule Follow-Up"
                          enabled={canFollowUp}
                        />
                        <AccessRow
                          label="Security Review"
                          enabled={hasPermission(
                            user,
                            "security:review:sensitive_action",
                          )}
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
                </div>
              </>
            ) : (
              <div className="flex min-h-[720px] items-center justify-center p-8">
                <EmptyState
                  variant="dark"
                  icon="☎"
                  title="No call selected"
                  message="Select a call from the queue or create a manual call record. Every call action remains scoped to the current user_id and workspace_id."
                />
              </div>
            )}
          </section>
        </div>
      </section>
    </div>
  );
}

function InfoTile(props: { label: string; value: string }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
      <p className="text-xs uppercase tracking-[0.2em] text-slate-500">
        {props.label}
      </p>
      <p className="mt-2 text-sm font-semibold text-slate-200">{props.value}</p>
    </div>
  );
}

function AccessRow(props: { label: string; enabled: boolean }) {
  return (
    <div className="flex items-center justify-between rounded-2xl border border-white/10 bg-black/20 px-4 py-3">
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
