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

type CreatorStatus =
  | "draft"
  | "queued"
  | "generating"
  | "security_review"
  | "ready"
  | "published"
  | "blocked"
  | "failed";

type ContentType =
  | "social_post"
  | "ad_copy"
  | "blog_outline"
  | "email_campaign"
  | "landing_section"
  | "video_script"
  | "seo_brief";

type ContentPlatform =
  | "linkedin"
  | "facebook"
  | "instagram"
  | "google_ads"
  | "website"
  | "email"
  | "youtube"
  | "multi_channel";

type ContentTone =
  | "professional"
  | "friendly"
  | "premium"
  | "bold"
  | "educational"
  | "conversion_focused";

type ContentRisk = "low" | "medium" | "high" | "critical";

type AgentKey =
  | "master_agent"
  | "security_agent"
  | "verification_agent"
  | "memory_agent"
  | "workflow_agent"
  | "creator_agent"
  | "business_agent"
  | "visual_agent";

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

type ContentAsset = {
  asset_id: string;
  user_id: string;
  workspace_id: string;
  title: string;
  content_type: ContentType;
  platform: ContentPlatform;
  tone: ContentTone;
  status: CreatorStatus;
  risk: ContentRisk;
  campaign: string;
  audience: string;
  goal: string;
  prompt: string;
  draft: string;
  created_at: string;
  updated_at: string;
  created_by_agent: AgentKey;
  verification?: VerificationResult;
};

type CreatorAction = {
  action_id: string;
  asset_id: string;
  action_type:
    | "generate_content"
    | "rewrite_content"
    | "save_content_memory"
    | "prepare_publish"
    | "publish_content"
    | "prepare_verification";
  user_id: string;
  workspace_id: string;
  actor_agent: AgentKey | "dashboard_creator_studio";
  target_resource: string;
  payload: Record<string, unknown>;
  requires_state_change: boolean;
  risk: ContentRisk;
  created_at: string;
};

// apps/api/routes/security.py's real POST /security/decide outcome values
// and response shape (confirmed by reading the source) -- replaces the old
// fabricated SecurityReviewResponse whose local fallback always approved
// every action regardless of risk.
type SecurityDecisionOutcome = "approved" | "denied" | "requires_approval";

type SecurityDecision = {
  outcome: SecurityDecisionOutcome;
  risk_level: ContentRisk;
  decision_mode: string;
  reason: string;
  action: string;
  category: string;
  requires_approval: boolean;
  approval_id?: string;
};

// The `verification` field the real /security/decide response includes,
// prepared server-side -- not fabricated client-side like the old
// VerificationPayload/MemoryPayload/AuditEventPayload types were.
type VerificationResult = Record<string, unknown>;

type CreatorStats = {
  drafts: number;
  ready_assets: number;
  published: number;
  blocked: number;
};

type ApiClientOptions = {
  method?: ApiMethod;
  body?: unknown;
  headers?: Record<string, string>;
};

type ContentFormState = {
  title: string;
  campaign: string;
  audience: string;
  goal: string;
  content_type: ContentType;
  platform: ContentPlatform;
  tone: ContentTone;
  prompt: string;
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
    "dashboard:creator:read",
    "dashboard:creator:write",
    "agent:creator_agent:access",
    "agent:security_agent:access",
    "agent:verification_agent:access",
    "agent:memory_agent:access",
    "agent:workflow_agent:access",
    "creator:generate",
    "creator:edit",
    "creator:publish",
    "security:review:sensitive_action",
    "audit:write",
    "memory:write",
    "verification:prepare",
  ],
  plan_features: [
    "creator_agent",
    "content_studio",
    "content_generation",
    "content_publish_workflows",
    "security_agent_review",
    "verification_payloads",
    "memory_context",
    "audit_logs",
  ],
};

const EMPTY_FORM: ContentFormState = {
  title: "",
  campaign: "",
  audience: "",
  goal: "Generate qualified leads",
  content_type: "social_post",
  platform: "linkedin",
  tone: "conversion_focused",
  prompt: "",
};

// There is no /creator/assets or /creator/actions router anywhere in
// apps/api/routes/ (confirmed by listing the directory) -- the Creator
// Agent exists as an agent-registry entry (apps/api/routes/agents.py)
// invokable through the generic task system, but nothing persists a
// queryable "content asset" list or returns generated draft text to the
// dashboard. The old LOCAL_ASSETS array (three fully-written fake social/
// ad/landing-page drafts) and submitCreatorAction()'s local fallback
// (echoing the user's own prompt back as if it were "Creator Agent
// output") are removed rather than kept as a fabricated stand-in.

const CONTENT_TEMPLATES = [
  {
    title: "Lead-Gen Social Post",
    type: "social_post" as ContentType,
    platform: "linkedin" as ContentPlatform,
    prompt:
      "Write a conversion-focused LinkedIn post that explains the offer, creates urgency, and ends with a soft CTA.",
  },
  {
    title: "Google Ads Copy",
    type: "ad_copy" as ContentType,
    platform: "google_ads" as ContentPlatform,
    prompt:
      "Create Google Ads headlines and descriptions focused on calls, trust, and clear service benefits.",
  },
  {
    title: "SEO Blog Outline",
    type: "blog_outline" as ContentType,
    platform: "website" as ContentPlatform,
    prompt:
      "Create an SEO blog outline with search intent, H2 structure, FAQs, and conversion CTA.",
  },
  {
    title: "Email Campaign",
    type: "email_campaign" as ContentType,
    platform: "email" as ContentPlatform,
    prompt:
      "Write a short email campaign with subject line, preview text, body, and CTA.",
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

function getStatusBadgeClass(status: CreatorStatus): string {
  switch (status) {
    case "generating":
      return "border-blue-400/40 bg-blue-400/10 text-blue-100";
    case "security_review":
      return "border-orange-400/40 bg-orange-400/10 text-orange-100";
    case "ready":
      return "border-cyan-400/40 bg-cyan-400/10 text-cyan-100";
    case "published":
      return "border-emerald-400/40 bg-emerald-400/10 text-emerald-100";
    case "blocked":
    case "failed":
      return "border-red-400/40 bg-red-400/10 text-red-100";
    case "queued":
      return "border-purple-400/40 bg-purple-400/10 text-purple-100";
    case "draft":
    default:
      return "border-slate-400/30 bg-slate-400/10 text-slate-200";
  }
}

function getRiskBadgeClass(risk: ContentRisk): string {
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

function detectRisk(params: {
  contentType: ContentType;
  platform: ContentPlatform;
  prompt: string;
  actionType?: CreatorAction["action_type"];
}): ContentRisk {
  const normalized = params.prompt.toLowerCase();

  const criticalTerms = [
    "guaranteed income",
    "fake review",
    "impersonate",
    "medical cure",
    "secret key",
    "password",
    "private token",
    "bypass policy",
  ];

  const highTerms = [
    "publish",
    "send email",
    "financial advice",
    "legal advice",
    "health claim",
    "competitor name",
    "customer data",
    "personal data",
    "political",
  ];

  if (criticalTerms.some((term) => normalized.includes(term)))
    return "critical";

  if (
    params.actionType === "publish_content" ||
    params.platform === "email" ||
    params.platform === "google_ads" ||
    highTerms.some((term) => normalized.includes(term))
  ) {
    return "high";
  }

  if (
    params.contentType === "ad_copy" ||
    params.contentType === "email_campaign" ||
    params.contentType === "landing_section"
  ) {
    return "medium";
  }

  return "low";
}

function isSensitiveAction(
  actionType: CreatorAction["action_type"],
  risk: ContentRisk,
): boolean {
  return (
    actionType === "publish_content" ||
    actionType === "prepare_publish" ||
    risk === "high" ||
    risk === "critical"
  );
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

// apps/api/routes/ has no creator.py -- no /creator/assets or
// /creator/actions endpoint exists anywhere in this deployment (confirmed
// by listing the routes directory). The Creator Agent is only reachable
// as an agent-registry entry via the generic task system, which doesn't
// persist a queryable content-asset list or return draft text to the
// dashboard. Left pointed at the real (currently 404ing) paths rather
// than a fabricated local fallback, so this starts working automatically
// once a real creator backend exists.
async function loadAssets(): Promise<ContentAsset[]> {
  const response = await apiRequest<{
    success: boolean;
    data: ContentAsset[];
    error?: { message: string };
  }>("/creator/assets");

  if (!response.success) {
    throw new Error(
      response.error?.message || "Unable to load creator assets.",
    );
  }

  return response.data || [];
}

/**
 * Real Security Agent gate (POST /security/decide, apps/api/routes/
 * security.py) -- evaluated before any state-changing creator action.
 * Replaces the old submitSecurityReview()'s fabricated always-approve
 * fallback and made-up "/api/security/review" endpoint.
 */
async function decideRiskyAction(
  action: CreatorAction,
): Promise<{ decision: SecurityDecision; verification: VerificationResult }> {
  const response = await apiRequest<{
    ok: boolean;
    message: string;
    data: { decision: SecurityDecision };
    verification?: VerificationResult;
  }>("/security/decide", {
    method: "POST",
    body: {
      action: `creator.${action.action_type}`,
      category: "general",
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

async function submitCreatorAction(action: CreatorAction): Promise<{
  success: boolean;
  status: CreatorStatus;
  message: string;
  draft?: string;
}> {
  return apiRequest<{
    success: boolean;
    status: CreatorStatus;
    message: string;
    draft?: string;
    error?: { message: string };
  }>("/creator/actions", {
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
  const [assets, setAssets] = useState<ContentAsset[]>([]);
  const [selectedAssetId, setSelectedAssetId] = useState<string>("");
  const [form, setForm] = useState<ContentFormState>(EMPTY_FORM);
  const [isBooting, setIsBooting] = useState(true);
  const [isActionRunning, setIsActionRunning] = useState(false);
  const [safeError, setSafeError] = useState<string | null>(null);
  const [lastSecurityDecision, setLastSecurityDecision] =
    useState<SecurityDecision | null>(null);
  const [lastVerification, setLastVerification] =
    useState<VerificationResult | null>(null);

  const canReadCreator = useMemo(() => {
    return (
      hasPermission(user, "dashboard:creator:read") &&
      hasPermission(user, "agent:creator_agent:access") &&
      hasPlanFeature(user, "creator_agent") &&
      hasPlanFeature(user, "content_studio")
    );
  }, [user]);

  const canWriteCreator = useMemo(() => {
    return (
      hasPermission(user, "dashboard:creator:write") &&
      hasPermission(user, "creator:generate") &&
      hasPlanFeature(user, "content_generation")
    );
  }, [user]);

  const canPublish = useMemo(() => {
    return (
      hasPermission(user, "creator:publish") &&
      hasPlanFeature(user, "content_publish_workflows")
    );
  }, [user]);

  const scopedAssets = useMemo(() => {
    return assets.filter(
      (asset) =>
        asset.user_id === user.user_id &&
        asset.workspace_id === user.workspace_id,
    );
  }, [assets, user.user_id, user.workspace_id]);

  const selectedAsset = useMemo(() => {
    return (
      scopedAssets.find((asset) => asset.asset_id === selectedAssetId) ||
      scopedAssets[0] ||
      null
    );
  }, [scopedAssets, selectedAssetId]);

  const stats = useMemo<CreatorStats>(() => {
    return {
      drafts: scopedAssets.filter((asset) => asset.status === "draft").length,
      ready_assets: scopedAssets.filter((asset) => asset.status === "ready")
        .length,
      published: scopedAssets.filter((asset) => asset.status === "published")
        .length,
      blocked: scopedAssets.filter((asset) => asset.status === "blocked")
        .length,
    };
  }, [scopedAssets]);

  const refreshAssets = useCallback(async () => {
    const loadedAssets = await loadAssets();
    setAssets(loadedAssets);

    if (loadedAssets.length > 0) {
      setSelectedAssetId((current) => current || loadedAssets[0].asset_id);
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
        await refreshAssets();
      } catch {
        // No /creator/assets endpoint exists in this deployment yet (see
        // loadAssets()'s note) -- this will always land here today. Show
        // an honest "not connected" message instead of silently swapping
        // in fabricated demo assets, and without forcing a logout the
        // user's session doesn't actually warrant.
        setSafeError(
          "Content Studio is not connected to a backend yet -- no creator API exists in this deployment.",
        );
      } finally {
        if (isMounted) setIsBooting(false);
      }
    }

    boot();

    return () => {
      isMounted = false;
    };
  }, [refreshAssets, router]);

  const handleRetry = useCallback(() => {
    setSafeError(null);
    setIsBooting(true);
    refreshAssets()
      .catch((error) => setSafeError(sanitizeError(error)))
      .finally(() => setIsBooting(false));
  }, [refreshAssets]);

  const updateAsset = useCallback(
    (assetId: string, patch: Partial<ContentAsset>) => {
      setAssets((current) =>
        current.map((asset) =>
          asset.asset_id === assetId
            ? {
                ...asset,
                ...patch,
                updated_at: nowIso(),
              }
            : asset,
        ),
      );
    },
    [],
  );

  const handleFormChange = useCallback(
    <Key extends keyof ContentFormState>(
      key: Key,
      value: ContentFormState[Key],
    ) => {
      setForm((current) => ({ ...current, [key]: value }));
    },
    [],
  );

  const handleTemplateClick = useCallback(
    (template: (typeof CONTENT_TEMPLATES)[number]) => {
      setForm((current) => ({
        ...current,
        title: template.title,
        content_type: template.type,
        platform: template.platform,
        prompt: template.prompt,
      }));
    },
    [],
  );

  const createAssetFromForm = useCallback(
    async (event: FormEvent<HTMLFormElement>) => {
      event.preventDefault();

      setSafeError(null);

      if (!canReadCreator || !canWriteCreator) {
        setSafeError(
          "Your role or subscription plan cannot generate creator assets.",
        );
        return;
      }

      if (!user.user_id || !user.workspace_id) {
        setSafeError(
          "Missing user or workspace scope. Creator action was blocked safely.",
        );
        return;
      }

      const title = form.title.trim();
      const prompt = form.prompt.trim();

      if (!title || !prompt) {
        setSafeError("Title and prompt are required to generate content.");
        return;
      }

      const risk = detectRisk({
        contentType: form.content_type,
        platform: form.platform,
        prompt,
        actionType: "generate_content",
      });

      const assetId = createId("asset");
      const actionId = createId("creator_action");

      const initialAsset: ContentAsset = {
        asset_id: assetId,
        user_id: user.user_id,
        workspace_id: user.workspace_id,
        title,
        content_type: form.content_type,
        platform: form.platform,
        tone: form.tone,
        status:
          risk === "high" || risk === "critical"
            ? "security_review"
            : "generating",
        risk,
        campaign: form.campaign.trim() || "Untitled Campaign",
        audience: form.audience.trim() || "Target audience",
        goal: form.goal.trim() || "Generate qualified leads",
        prompt,
        draft: "",
        created_at: nowIso(),
        updated_at: nowIso(),
        created_by_agent: "creator_agent",
      };

      const action: CreatorAction = {
        action_id: actionId,
        asset_id: assetId,
        action_type: "generate_content",
        user_id: user.user_id,
        workspace_id: user.workspace_id,
        actor_agent: "dashboard_creator_studio",
        target_resource: "creator/assets",
        payload: {
          ...form,
          title,
          prompt,
          target_user_id: user.user_id,
          target_workspace_id: user.workspace_id,
        },
        requires_state_change: isSensitiveAction("generate_content", risk),
        risk,
        created_at: nowIso(),
      };

      setIsActionRunning(true);
      setAssets((current) => [initialAsset, ...current]);
      setSelectedAssetId(assetId);

      try {
        if (action.requires_state_change) {
          const { decision, verification } = await decideRiskyAction(action);
          setLastSecurityDecision(decision);
          setLastVerification(verification);

          if (decision.outcome !== "approved") {
            updateAsset(assetId, {
              status:
                decision.outcome === "denied" ? "blocked" : "security_review",
              risk: decision.risk_level,
            });
            setSafeError(
              `Security Agent ${decision.outcome === "denied" ? "denied" : "requires approval for"} this action: ${decision.reason}`,
            );
            return;
          }
        }

        // No /creator/actions endpoint exists yet (see submitCreatorAction's
        // note) -- this call is expected to fail today. It is never
        // replaced with a fabricated draft; the asset is marked failed and
        // the real error is surfaced instead.
        const response = await submitCreatorAction(action);

        if (!response.success) {
          throw new Error(response.message || "Creator action failed safely.");
        }

        const draft = response.draft || "";
        const readyStatus: CreatorStatus =
          response.status === "published" ? "published" : "ready";

        updateAsset(assetId, {
          draft,
          status: readyStatus,
          updated_at: nowIso(),
        });

        setForm(EMPTY_FORM);
      } catch (error) {
        const message = sanitizeError(error);

        setSafeError(message);
        updateAsset(assetId, {
          status: "failed",
        });
      } finally {
        setIsActionRunning(false);
      }
    },
    [canReadCreator, canWriteCreator, form, updateAsset, user],
  );

  const runAssetAction = useCallback(
    async (actionType: CreatorAction["action_type"]) => {
      if (!selectedAsset || isActionRunning) return;

      setSafeError(null);

      if (!canReadCreator || !canWriteCreator) {
        setSafeError(
          "Your role or subscription plan cannot operate Creator Studio.",
        );
        return;
      }

      if (actionType === "publish_content" && !canPublish) {
        setSafeError("Your role or subscription plan cannot publish content.");
        return;
      }

      if (
        selectedAsset.user_id !== user.user_id ||
        selectedAsset.workspace_id !== user.workspace_id
      ) {
        setSafeError(
          "Cross-user or cross-workspace content access was blocked safely.",
        );
        return;
      }

      const actionId = createId("creator_action");
      const risk = detectRisk({
        contentType: selectedAsset.content_type,
        platform: selectedAsset.platform,
        prompt: `${selectedAsset.prompt}\n${selectedAsset.draft}`,
        actionType,
      });

      const action: CreatorAction = {
        action_id: actionId,
        asset_id: selectedAsset.asset_id,
        action_type: actionType,
        user_id: user.user_id,
        workspace_id: user.workspace_id,
        actor_agent: "dashboard_creator_studio",
        target_resource: "creator/assets",
        payload: {
          asset_id: selectedAsset.asset_id,
          title: selectedAsset.title,
          platform: selectedAsset.platform,
          content_type: selectedAsset.content_type,
          draft: selectedAsset.draft,
          target_user_id: user.user_id,
          target_workspace_id: user.workspace_id,
        },
        requires_state_change: isSensitiveAction(actionType, risk),
        risk,
        created_at: nowIso(),
      };

      setIsActionRunning(true);

      try {
        if (action.requires_state_change) {
          updateAsset(selectedAsset.asset_id, {
            status: "security_review",
            risk,
          });

          const { decision, verification } = await decideRiskyAction(action);
          setLastSecurityDecision(decision);
          setLastVerification(verification);

          if (decision.outcome !== "approved") {
            updateAsset(selectedAsset.asset_id, {
              status:
                decision.outcome === "denied" ? "blocked" : "security_review",
              risk: decision.risk_level,
            });
            setSafeError(
              `Security Agent ${decision.outcome === "denied" ? "denied" : "requires approval for"} this action: ${decision.reason}`,
            );
            return;
          }
        }

        const response = await submitCreatorAction(action);

        if (!response.success) {
          throw new Error(response.message || "Creator action failed safely.");
        }

        const nextStatus: CreatorStatus =
          actionType === "publish_content"
            ? "published"
            : actionType === "prepare_publish"
              ? "ready"
              : "ready";

        updateAsset(selectedAsset.asset_id, {
          status: nextStatus,
          risk,
        });
      } catch (error) {
        const message = sanitizeError(error);

        setSafeError(message);
        updateAsset(selectedAsset.asset_id, {
          status: "failed",
        });
      } finally {
        setIsActionRunning(false);
      }
    },
    [
      canPublish,
      canReadCreator,
      canWriteCreator,
      isActionRunning,
      selectedAsset,
      updateAsset,
      user,
    ],
  );

  if (isBooting) {
    return (
      <div className="rounded-[28px] bg-slate-950 px-4 py-6 text-white sm:px-6 lg:px-8">
        <section className="mx-auto flex min-h-[70vh] max-w-7xl items-center justify-center">
          <LoadingState variant="dark" title="Loading Creator Studio..." />
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
              Creator Agent / Content Studio
            </div>
            <h1 className="text-3xl font-black tracking-tight sm:text-4xl lg:text-5xl">
              AI Content Studio
            </h1>
            <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-300 sm:text-base">
              Generate campaign assets, social posts, ad copy, SEO briefs,
              scripts, and publish-ready content with scoped user/workspace
              controls, Security Agent approval, Memory Agent context, audit
              hooks, and Verification Agent payloads. Content machine, but with
              brakes.
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

        {!canReadCreator ? (
          <div className="mb-6">
            <ForbiddenState
              variant="dark"
              message="Your current role or subscription plan cannot access Creator Studio."
            />
          </div>
        ) : null}

        <div className="mb-6 grid gap-4 md:grid-cols-4">
          <StatCard
            label="Drafts"
            value={stats.drafts}
            hint="Editable content assets"
          />
          <StatCard
            label="Ready"
            value={stats.ready_assets}
            hint="Prepared for review"
          />
          <StatCard
            label="Published"
            value={stats.published}
            hint="Approved outputs"
          />
          <StatCard
            label="Blocked"
            value={stats.blocked}
            hint="Security protected"
          />
        </div>

        <div className="grid gap-6 lg:grid-cols-[410px_1fr]">
          <aside className="space-y-6">
            <section className="rounded-3xl border border-white/10 bg-white/[0.05] p-4 shadow-2xl shadow-black/20">
              <div className="mb-4 flex items-center justify-between">
                <div>
                  <h2 className="text-lg font-bold">Content Library</h2>
                  <p className="text-xs text-slate-400">
                    User/workspace scoped assets
                  </p>
                </div>
                <span className="rounded-full bg-white/10 px-3 py-1 text-xs text-slate-300">
                  {scopedAssets.length} assets
                </span>
              </div>

              <div className="max-h-[520px] space-y-3 overflow-auto pr-1">
                {scopedAssets.length === 0 ? (
                  <EmptyState
                    variant="dark"
                    icon="✍"
                    title="No content yet"
                    message="Generate your first content asset from the studio form below."
                  />
                ) : (
                  scopedAssets.map((asset) => {
                    const isSelected =
                      selectedAsset?.asset_id === asset.asset_id;

                    return (
                      <button
                        key={asset.asset_id}
                        type="button"
                        onClick={() => setSelectedAssetId(asset.asset_id)}
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
                              {asset.title}
                            </h3>
                            <p className="mt-1 text-xs text-slate-400">
                              {formatLabel(asset.content_type)} •{" "}
                              {formatLabel(asset.platform)}
                            </p>
                          </div>
                          <span
                            className={[
                              "rounded-full border px-2 py-1 text-[10px]",
                              getRiskBadgeClass(asset.risk),
                            ].join(" ")}
                          >
                            {formatLabel(asset.risk)}
                          </span>
                        </div>

                        <p className="mt-3 line-clamp-2 text-xs leading-5 text-slate-400">
                          {asset.draft || asset.prompt}
                        </p>

                        <div className="mt-3 flex flex-wrap gap-2">
                          <span
                            className={[
                              "rounded-full border px-2 py-1 text-[10px]",
                              getStatusBadgeClass(asset.status),
                            ].join(" ")}
                          >
                            {formatLabel(asset.status)}
                          </span>
                          <span className="rounded-full border border-white/10 bg-white/10 px-2 py-1 text-[10px] text-slate-300">
                            {asset.campaign}
                          </span>
                        </div>
                      </button>
                    );
                  })
                )}
              </div>
            </section>

            <section className="rounded-3xl border border-white/10 bg-white/[0.05] p-4 shadow-2xl shadow-black/20">
              <h2 className="text-lg font-bold">Quick Templates</h2>
              <p className="mt-1 text-xs text-slate-400">
                Click one, then customize.
              </p>

              <div className="mt-4 space-y-2">
                {CONTENT_TEMPLATES.map((template) => (
                  <button
                    key={template.title}
                    type="button"
                    onClick={() => handleTemplateClick(template)}
                    className="w-full rounded-2xl border border-white/10 bg-slate-950/40 px-4 py-3 text-left text-xs leading-5 text-slate-300 transition hover:border-cyan-400/30 hover:bg-cyan-400/10 hover:text-cyan-100"
                  >
                    <span className="font-semibold text-white">
                      {template.title}
                    </span>
                    <span className="mt-1 block text-slate-400">
                      {template.prompt}
                    </span>
                  </button>
                ))}
              </div>
            </section>
          </aside>

          <section className="min-h-[850px] rounded-3xl border border-white/10 bg-white/[0.05] shadow-2xl shadow-black/30">
            <div className="border-b border-white/10 p-5">
              <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
                <div>
                  <h2 className="text-2xl font-black">Create Content</h2>
                  <p className="mt-2 max-w-2xl text-sm text-slate-400">
                    Build a prompt brief for Creator Agent. High-risk publishing
                    actions route through Security Agent before execution.
                  </p>
                </div>

                {lastSecurityDecision ? (
                  <div className="rounded-2xl border border-cyan-500/20 bg-cyan-500/10 p-3 text-sm text-cyan-100 xl:max-w-md">
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
            </div>

            <div className="grid gap-6 p-5 xl:grid-cols-[1fr_390px]">
              <div className="space-y-6">
                <form
                  onSubmit={createAssetFromForm}
                  className="rounded-3xl border border-white/10 bg-slate-950/40 p-5"
                >
                  <h3 className="text-lg font-bold">Creator Brief</h3>
                  <p className="mt-1 text-sm text-slate-400">
                    The cleaner the brief, the better the output. Garbage in,
                    fancy garbage out.
                  </p>

                  <div className="mt-5 grid gap-4 md:grid-cols-2">
                    <label className="block">
                      <span className="text-xs uppercase tracking-[0.2em] text-slate-500">
                        Asset Title
                      </span>
                      <input
                        value={form.title}
                        onChange={(event) =>
                          handleFormChange("title", event.target.value)
                        }
                        placeholder="Example: AI Receptionist Launch Post"
                        className="mt-2 w-full rounded-2xl border border-white/10 bg-slate-950/70 px-4 py-3 text-sm text-white outline-none placeholder:text-slate-500 focus:border-cyan-400/40"
                      />
                    </label>

                    <label className="block">
                      <span className="text-xs uppercase tracking-[0.2em] text-slate-500">
                        Campaign
                      </span>
                      <input
                        value={form.campaign}
                        onChange={(event) =>
                          handleFormChange("campaign", event.target.value)
                        }
                        placeholder="Example: William SaaS Launch"
                        className="mt-2 w-full rounded-2xl border border-white/10 bg-slate-950/70 px-4 py-3 text-sm text-white outline-none placeholder:text-slate-500 focus:border-cyan-400/40"
                      />
                    </label>

                    <label className="block">
                      <span className="text-xs uppercase tracking-[0.2em] text-slate-500">
                        Audience
                      </span>
                      <input
                        value={form.audience}
                        onChange={(event) =>
                          handleFormChange("audience", event.target.value)
                        }
                        placeholder="Example: local service businesses"
                        className="mt-2 w-full rounded-2xl border border-white/10 bg-slate-950/70 px-4 py-3 text-sm text-white outline-none placeholder:text-slate-500 focus:border-cyan-400/40"
                      />
                    </label>

                    <label className="block">
                      <span className="text-xs uppercase tracking-[0.2em] text-slate-500">
                        Goal
                      </span>
                      <input
                        value={form.goal}
                        onChange={(event) =>
                          handleFormChange("goal", event.target.value)
                        }
                        placeholder="Example: book more calls"
                        className="mt-2 w-full rounded-2xl border border-white/10 bg-slate-950/70 px-4 py-3 text-sm text-white outline-none placeholder:text-slate-500 focus:border-cyan-400/40"
                      />
                    </label>

                    <label className="block">
                      <span className="text-xs uppercase tracking-[0.2em] text-slate-500">
                        Content Type
                      </span>
                      <select
                        value={form.content_type}
                        onChange={(event) =>
                          handleFormChange(
                            "content_type",
                            event.target.value as ContentType,
                          )
                        }
                        className="mt-2 w-full rounded-2xl border border-white/10 bg-slate-950/70 px-4 py-3 text-sm text-white outline-none focus:border-cyan-400/40"
                      >
                        <option value="social_post">Social Post</option>
                        <option value="ad_copy">Ad Copy</option>
                        <option value="blog_outline">Blog Outline</option>
                        <option value="email_campaign">Email Campaign</option>
                        <option value="landing_section">Landing Section</option>
                        <option value="video_script">Video Script</option>
                        <option value="seo_brief">SEO Brief</option>
                      </select>
                    </label>

                    <label className="block">
                      <span className="text-xs uppercase tracking-[0.2em] text-slate-500">
                        Platform
                      </span>
                      <select
                        value={form.platform}
                        onChange={(event) =>
                          handleFormChange(
                            "platform",
                            event.target.value as ContentPlatform,
                          )
                        }
                        className="mt-2 w-full rounded-2xl border border-white/10 bg-slate-950/70 px-4 py-3 text-sm text-white outline-none focus:border-cyan-400/40"
                      >
                        <option value="linkedin">LinkedIn</option>
                        <option value="facebook">Facebook</option>
                        <option value="instagram">Instagram</option>
                        <option value="google_ads">Google Ads</option>
                        <option value="website">Website</option>
                        <option value="email">Email</option>
                        <option value="youtube">YouTube</option>
                        <option value="multi_channel">Multi Channel</option>
                      </select>
                    </label>

                    <label className="block md:col-span-2">
                      <span className="text-xs uppercase tracking-[0.2em] text-slate-500">
                        Tone
                      </span>
                      <select
                        value={form.tone}
                        onChange={(event) =>
                          handleFormChange(
                            "tone",
                            event.target.value as ContentTone,
                          )
                        }
                        className="mt-2 w-full rounded-2xl border border-white/10 bg-slate-950/70 px-4 py-3 text-sm text-white outline-none focus:border-cyan-400/40"
                      >
                        <option value="professional">Professional</option>
                        <option value="friendly">Friendly</option>
                        <option value="premium">Premium</option>
                        <option value="bold">Bold</option>
                        <option value="educational">Educational</option>
                        <option value="conversion_focused">
                          Conversion Focused
                        </option>
                      </select>
                    </label>

                    <label className="block md:col-span-2">
                      <span className="text-xs uppercase tracking-[0.2em] text-slate-500">
                        Prompt / Instructions
                      </span>
                      <textarea
                        value={form.prompt}
                        onChange={(event) =>
                          handleFormChange("prompt", event.target.value)
                        }
                        rows={7}
                        placeholder="Tell Creator Agent exactly what to create, what to avoid, what audience to target, and what CTA to use."
                        className="mt-2 w-full resize-none rounded-2xl border border-white/10 bg-slate-950/70 px-4 py-3 text-sm leading-6 text-white outline-none placeholder:text-slate-500 focus:border-cyan-400/40"
                      />
                    </label>
                  </div>

                  <div className="mt-5 flex flex-col gap-3 border-t border-white/10 pt-4 sm:flex-row sm:items-center sm:justify-between">
                    <div className="flex flex-wrap gap-2 text-xs">
                      <span className="rounded-full border border-white/10 bg-white/10 px-3 py-1 text-slate-300">
                        user_id: {user.user_id}
                      </span>
                      <span className="rounded-full border border-white/10 bg-white/10 px-3 py-1 text-slate-300">
                        workspace_id: {user.workspace_id}
                      </span>
                    </div>

                    <button
                      type="submit"
                      disabled={isActionRunning || !canWriteCreator}
                      className="rounded-2xl bg-cyan-400 px-5 py-3 text-sm font-black text-slate-950 shadow-lg shadow-cyan-950/40 transition hover:bg-cyan-300 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400 disabled:shadow-none"
                    >
                      {isActionRunning ? "Creating..." : "Generate Content"}
                    </button>
                  </div>
                </form>

                <section className="rounded-3xl border border-white/10 bg-slate-950/40 p-5">
                  <h3 className="text-lg font-bold">Selected Asset</h3>

                  {selectedAsset ? (
                    <div className="mt-4">
                      <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                        <div>
                          <h4 className="text-xl font-black text-white">
                            {selectedAsset.title}
                          </h4>
                          <p className="mt-1 text-xs text-slate-400">
                            {formatLabel(selectedAsset.content_type)} •{" "}
                            {formatLabel(selectedAsset.platform)} •{" "}
                            {formatLabel(selectedAsset.tone)}
                          </p>
                        </div>

                        <div className="flex flex-wrap gap-2">
                          <span
                            className={[
                              "rounded-full border px-3 py-1 text-xs",
                              getStatusBadgeClass(selectedAsset.status),
                            ].join(" ")}
                          >
                            {formatLabel(selectedAsset.status)}
                          </span>
                          <span
                            className={[
                              "rounded-full border px-3 py-1 text-xs",
                              getRiskBadgeClass(selectedAsset.risk),
                            ].join(" ")}
                          >
                            {formatLabel(selectedAsset.risk)}
                          </span>
                        </div>
                      </div>

                      <div className="mt-4 grid gap-3 md:grid-cols-3">
                        <InfoTile
                          label="Campaign"
                          value={selectedAsset.campaign}
                        />
                        <InfoTile
                          label="Audience"
                          value={selectedAsset.audience}
                        />
                        <InfoTile label="Goal" value={selectedAsset.goal} />
                      </div>

                      <div className="mt-4 rounded-2xl border border-white/10 bg-black/20 p-4">
                        <p className="text-xs uppercase tracking-[0.2em] text-slate-500">
                          Draft Output
                        </p>
                        <pre className="mt-3 whitespace-pre-wrap text-sm leading-6 text-slate-200">
                          {selectedAsset.draft || "No draft generated yet."}
                        </pre>
                      </div>

                      <div className="mt-5 grid gap-3 md:grid-cols-3">
                        <button
                          type="button"
                          disabled={isActionRunning || !canWriteCreator}
                          onClick={() => runAssetAction("save_content_memory")}
                          className="rounded-2xl border border-purple-400/30 bg-purple-400/10 px-4 py-4 text-left transition hover:bg-purple-400/20 disabled:cursor-not-allowed disabled:opacity-50"
                        >
                          <div className="font-bold text-purple-100">
                            Save Memory
                          </div>
                          <p className="mt-1 text-xs leading-5 text-purple-100/70">
                            Store useful campaign context safely.
                          </p>
                        </button>

                        <button
                          type="button"
                          disabled={isActionRunning || !canWriteCreator}
                          onClick={() => runAssetAction("prepare_publish")}
                          className="rounded-2xl border border-orange-400/30 bg-orange-400/10 px-4 py-4 text-left transition hover:bg-orange-400/20 disabled:cursor-not-allowed disabled:opacity-50"
                        >
                          <div className="font-bold text-orange-100">
                            Prepare Publish
                          </div>
                          <p className="mt-1 text-xs leading-5 text-orange-100/70">
                            Security review for publish-ready action.
                          </p>
                        </button>

                        <button
                          type="button"
                          disabled={isActionRunning || !canPublish}
                          onClick={() => runAssetAction("publish_content")}
                          className="rounded-2xl border border-emerald-400/30 bg-emerald-400/10 px-4 py-4 text-left transition hover:bg-emerald-400/20 disabled:cursor-not-allowed disabled:opacity-50"
                        >
                          <div className="font-bold text-emerald-100">
                            Publish
                          </div>
                          <p className="mt-1 text-xs leading-5 text-emerald-100/70">
                            Sensitive state-changing action.
                          </p>
                        </button>
                      </div>

                      {selectedAsset.verification ? (
                        <div className="mt-5">
                          <details className="rounded-2xl border border-emerald-400/20 bg-emerald-400/5 p-3 text-xs text-emerald-100">
                            <summary className="cursor-pointer font-semibold">
                              Verification Agent Payload Ready
                            </summary>
                            <pre className="mt-3 overflow-auto whitespace-pre-wrap text-[11px] leading-5">
                              {JSON.stringify(
                                selectedAsset.verification,
                                null,
                                2,
                              )}
                            </pre>
                          </details>
                        </div>
                      ) : null}
                    </div>
                  ) : (
                    <div className="mt-4 flex min-h-[280px] items-center justify-center">
                      <EmptyState
                        variant="dark"
                        icon="✍"
                        title="No asset selected"
                        message="Generate content from the brief form or select an asset from the library. Every asset stays scoped to the current user and workspace."
                      />
                    </div>
                  )}
                </section>
              </div>

              <aside className="space-y-6">
                <section className="rounded-3xl border border-white/10 bg-slate-950/40 p-5">
                  <h3 className="text-lg font-bold">Studio Guardrails</h3>
                  <p className="mt-1 text-xs text-slate-400">
                    Real SaaS behavior: permissions, plan gates, approvals,
                    logs.
                  </p>

                  <div className="mt-4 space-y-3">
                    <AccessRow
                      label="Read Creator Studio"
                      enabled={canReadCreator}
                    />
                    <AccessRow
                      label="Generate Content"
                      enabled={canWriteCreator}
                    />
                    <AccessRow label="Publish Content" enabled={canPublish} />
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

                <section className="rounded-3xl border border-white/10 bg-slate-950/40 p-5">
                  <h3 className="text-lg font-bold">Creator Agent Flow</h3>
                  <div className="mt-4 space-y-3">
                    <FlowStep
                      index="01"
                      title="Brief"
                      text="User submits scoped content brief with user_id and workspace_id."
                    />
                    <FlowStep
                      index="02"
                      title="Risk Check"
                      text="Creator action is classified as low, medium, high, or critical."
                    />
                    <FlowStep
                      index="03"
                      title="Security"
                      text="Sensitive publishing or high-risk content routes to Security Agent."
                    />
                    <FlowStep
                      index="04"
                      title="Memory"
                      text="Useful campaign context is prepared for Memory Agent."
                    />
                    <FlowStep
                      index="05"
                      title="Verification"
                      text="Completed actions prepare Verification Agent payloads."
                    />
                  </div>
                </section>
              </aside>
            </div>
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

function FlowStep(props: { index: string; title: string; text: string }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
      <div className="flex items-center gap-3">
        <span className="flex h-9 w-9 items-center justify-center rounded-2xl border border-cyan-400/30 bg-cyan-400/10 text-xs font-black text-cyan-100">
          {props.index}
        </span>
        <h4 className="font-bold text-white">{props.title}</h4>
      </div>
      <p className="mt-3 text-xs leading-5 text-slate-400">{props.text}</p>
    </div>
  );
}
