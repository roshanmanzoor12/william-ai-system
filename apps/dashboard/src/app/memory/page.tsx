"use client";

import React, { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";

type UserRole = "owner" | "admin" | "member" | "viewer";
type UserPlan = "free" | "starter" | "pro" | "enterprise";
type SubscriptionStatus = "active" | "trialing" | "past_due" | "canceled";
type LoadState = "checking_session" | "loading" | "ready" | "empty" | "error";
type MemoryType = "task" | "agent" | "workspace" | "user" | "security" | "verification" | "workflow";
type MemorySensitivity = "standard" | "sensitive" | "restricted";

type ApiError = {
  code: string;
  message: string;
  status_code?: number;
  details?: Record<string, unknown>;
};

type ApiResponse<T> = {
  success: boolean;
  data: T | null;
  error: ApiError | null;
};

type SessionData = {
  accessToken: string;
  refreshToken?: string;
  user_id: string;
  workspace_id: string;
  email: string;
  name: string;
  role: UserRole;
  plan: UserPlan;
  subscription_status: SubscriptionStatus;
  permissions: string[];
  workspace_name: string;
  workspace_slug: string;
  saved_at: string;
};

type MemoryRecord = {
  memory_id: string;
  user_id: string;
  workspace_id: string;
  title: string;
  summary: string;
  key: string;
  type: MemoryType;
  sensitivity: MemorySensitivity;
  source_agent: string;
  tags: string[];
  created_at: string;
  updated_at?: string | null;
  last_used_at?: string | null;
};

type MemorySummary = {
  totalRecords: number;
  standardRecords: number;
  sensitiveRecords: number;
  restrictedRecords: number;
  exportedRecords: number;
  deletedThisMonth: number;
  storageUsedMb: number;
  storageLimitMb: number;
  chart: {
    labels: string[];
    standard: number[];
    sensitive: number[];
  };
};

type MemoryPageData = {
  summary: MemorySummary;
  records: MemoryRecord[];
};

type MemoryActionResponse = {
  memory_id?: string;
  exported_file_url?: string;
  deleted_count?: number;
  audit?: {
    event_id?: string;
    action: "memory.delete" | "memory.export";
  };
  security?: {
    routed_to_security_agent: boolean;
    approved: boolean;
    risk_level: "low" | "medium" | "high";
  };
  verification?: {
    verification_id?: string;
    status: "prepared" | "completed" | "pending";
  };
};

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || "";

const ROLE_PERMISSIONS: Record<UserRole, string[]> = {
  owner: [
    "dashboard:read",
    "workspace:read",
    "memory:read",
    "memory:write",
    "memory:delete",
    "memory:export",
    "security:approve",
    "audit:read",
  ],
  admin: [
    "dashboard:read",
    "workspace:read",
    "memory:read",
    "memory:write",
    "memory:delete",
    "memory:export",
    "audit:read",
  ],
  member: ["dashboard:read", "workspace:read", "memory:read", "memory:write"],
  viewer: ["dashboard:read", "workspace:read", "memory:read"],
};

const PLAN_MEMORY_LIMIT_MB: Record<UserPlan, number> = {
  free: 128,
  starter: 1024,
  pro: 10240,
  enterprise: 102400,
};

const DEFAULT_SUMMARY: MemorySummary = {
  totalRecords: 0,
  standardRecords: 0,
  sensitiveRecords: 0,
  restrictedRecords: 0,
  exportedRecords: 0,
  deletedThisMonth: 0,
  storageUsedMb: 0,
  storageLimitMb: 0,
  chart: {
    labels: [],
    standard: [],
    sensitive: [],
  },
};

const LOCAL_DEMO_MEMORIES: MemoryRecord[] = [
  {
    memory_id: "memory_master_flow",
    user_id: "local_user",
    workspace_id: "local_workspace",
    title: "Master Agent Flow Rule",
    summary:
      "Every command must include user_id and workspace_id before planner, security, execution, and verification.",
    key: "master.flow.required_context",
    type: "agent",
    sensitivity: "standard",
    source_agent: "master_agent",
    tags: ["routing", "workspace", "verification"],
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    last_used_at: new Date().toISOString(),
  },
  {
    memory_id: "memory_security_sensitive_actions",
    user_id: "local_user",
    workspace_id: "local_workspace",
    title: "Sensitive Action Policy",
    summary:
      "Delete, export, billing, system, browser submit, and device actions require Security Agent approval.",
    key: "security.sensitive_actions.policy",
    type: "security",
    sensitivity: "sensitive",
    source_agent: "security_agent",
    tags: ["security", "approval", "audit"],
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    last_used_at: new Date().toISOString(),
  },
  {
    memory_id: "memory_verification_payload",
    user_id: "local_user",
    workspace_id: "local_workspace",
    title: "Verification Payload Format",
    summary:
      "Completed tasks should create a verification payload with task id, agent name, action, status, and evidence.",
    key: "verification.payload.format",
    type: "verification",
    sensitivity: "standard",
    source_agent: "verification_agent",
    tags: ["verification", "completion", "evidence"],
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    last_used_at: null,
  },
];

function createSafeError<T = never>(
  code: string,
  message: string,
  statusCode = 400,
  details: Record<string, unknown> = {},
): ApiResponse<T> {
  return {
    success: false,
    data: null,
    error: {
      code,
      message,
      status_code: statusCode,
      details,
    },
  };
}

function readSession(): SessionData | null {
  if (typeof window === "undefined") return null;

  const raw =
    window.localStorage.getItem("william.session") ||
    window.sessionStorage.getItem("william.session");

  if (!raw) return null;

  try {
    const session = JSON.parse(raw) as SessionData;

    if (
      !session.accessToken ||
      !session.user_id ||
      !session.workspace_id ||
      !session.role ||
      !session.plan ||
      !["active", "trialing"].includes(session.subscription_status)
    ) {
      return null;
    }

    return session;
  } catch {
    return null;
  }
}

function clearSession(): void {
  if (typeof window === "undefined") return;

  window.localStorage.removeItem("william.session");
  window.localStorage.removeItem("william.access_token");
  window.localStorage.removeItem("william.refresh_token");
  window.sessionStorage.removeItem("william.session");
  window.sessionStorage.removeItem("william.access_token");
  window.sessionStorage.removeItem("william.refresh_token");
}

function hasPermission(session: SessionData, permission: string): boolean {
  const merged = new Set([
    ...(ROLE_PERMISSIONS[session.role] || []),
    ...(session.permissions || []),
  ]);

  return merged.has(permission);
}

function validateAccess(session: SessionData): ApiResponse<SessionData> {
  if (!session.user_id || !session.workspace_id) {
    return createSafeError(
      "ISOLATION_CONTEXT_MISSING",
      "Session is missing user_id or workspace_id.",
      403,
    );
  }

  if (!["active", "trialing"].includes(session.subscription_status)) {
    return createSafeError(
      "SUBSCRIPTION_INACTIVE",
      "Your workspace subscription is not active.",
      402,
      { status: session.subscription_status },
    );
  }

  if (!hasPermission(session, "memory:read")) {
    return createSafeError(
      "MEMORY_READ_DENIED",
      "Your role cannot view workspace memory.",
      403,
      { role: session.role },
    );
  }

  return {
    success: true,
    data: session,
    error: null,
  };
}

async function parseApiJson<T>(response: Response): Promise<ApiResponse<T>> {
  try {
    const json = (await response.json()) as ApiResponse<T>;

    if (
      typeof json === "object" &&
      json !== null &&
      typeof json.success === "boolean" &&
      "data" in json &&
      "error" in json
    ) {
      return json;
    }

    return createSafeError<T>(
      "INVALID_API_RESPONSE",
      "The API returned an invalid response shape.",
      response.status,
    );
  } catch {
    return createSafeError<T>(
      "INVALID_JSON_RESPONSE",
      "The API response could not be parsed.",
      response.status,
    );
  }
}

async function apiRequest<T>(
  endpoint: string,
  session: SessionData,
  options: RequestInit = {},
): Promise<ApiResponse<T>> {
  if (!API_BASE_URL) {
    return createSafeError<T>(
      "API_BASE_URL_MISSING",
      "API is not connected. Set NEXT_PUBLIC_API_BASE_URL in your environment.",
      503,
      { required_env: "NEXT_PUBLIC_API_BASE_URL" },
    );
  }

  const baseUrl = API_BASE_URL.replace(/\/$/, "");
  const url = `${baseUrl}${endpoint.startsWith("/") ? endpoint : `/${endpoint}`}`;

  try {
    const response = await fetch(url, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${session.accessToken}`,
        "X-User-ID": session.user_id,
        "X-Workspace-ID": session.workspace_id,
        "X-Client-App": "william-dashboard",
        "X-Audit-Enabled": "true",
        ...(options.headers || {}),
      },
      credentials: "include",
    });

    const body = await parseApiJson<T>(response);

    if (!response.ok) {
      if (!body.success && body.error) return body;

      return createSafeError<T>("HTTP_ERROR", "Request failed.", response.status);
    }

    return body;
  } catch {
    return createSafeError<T>(
      "NETWORK_ERROR",
      "Could not connect to the William API.",
      503,
    );
  }
}

function buildLocalSummary(records: MemoryRecord[], session: SessionData): MemorySummary {
  const storageLimitMb = PLAN_MEMORY_LIMIT_MB[session.plan];

  return {
    totalRecords: records.length,
    standardRecords: records.filter((record) => record.sensitivity === "standard").length,
    sensitiveRecords: records.filter((record) => record.sensitivity === "sensitive").length,
    restrictedRecords: records.filter((record) => record.sensitivity === "restricted").length,
    exportedRecords: 0,
    deletedThisMonth: 0,
    storageUsedMb: Math.max(1, Math.round(records.length * 0.7)),
    storageLimitMb,
    chart: {
      labels: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
      standard: [4, 6, 5, 8, 7, 9, 6],
      sensitive: [1, 2, 1, 3, 2, 2, 1],
    },
  };
}

function formatNumber(value?: number): string {
  return new Intl.NumberFormat("en-US").format(value || 0);
}

function formatDate(value?: string | null): string {
  if (!value) return "Never";

  try {
    return new Intl.DateTimeFormat("en-US", {
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

function getTypeIcon(type: MemoryType): string {
  const icons: Record<MemoryType, string> = {
    task: "☷",
    agent: "✦",
    workspace: "▦",
    user: "◎",
    security: "▣",
    verification: "✓",
    workflow: "⌘",
  };

  return icons[type];
}

function getSensitivityStyle(sensitivity: MemorySensitivity): string {
  if (sensitivity === "standard") return "bg-emerald-50 text-emerald-700";
  if (sensitivity === "sensitive") return "bg-orange-50 text-orange-700";
  return "bg-red-50 text-red-700";
}

function IconBox({
  children,
  active,
}: {
  children: React.ReactNode;
  active?: boolean;
}) {
  return (
    <div
      className={[
        "grid h-11 w-11 place-items-center rounded-2xl border text-sm font-black transition",
        active
          ? "border-black bg-black text-white shadow-xl shadow-black/15"
          : "border-neutral-200 bg-white text-neutral-500",
      ].join(" ")}
    >
      {children}
    </div>
  );
}

function StatCard({
  title,
  value,
  subtitle,
  icon,
  highlight,
}: {
  title: string;
  value: string;
  subtitle: string;
  icon: string;
  highlight?: boolean;
}) {
  return (
    <div
      className={[
        "rounded-[1.55rem] p-5 shadow-sm",
        highlight
          ? "bg-[#ff5a3d] text-white shadow-xl shadow-[#ff5a3d]/25"
          : "bg-white text-neutral-950",
      ].join(" ")}
    >
      <div className="mb-6 flex items-center justify-between">
        <p
          className={[
            "text-sm font-bold",
            highlight ? "text-white/80" : "text-neutral-500",
          ].join(" ")}
        >
          {title}
        </p>
        <span
          className={[
            "grid h-9 w-9 place-items-center rounded-full text-sm",
            highlight ? "bg-white/15 text-white" : "bg-neutral-100 text-neutral-500",
          ].join(" ")}
        >
          {icon}
        </span>
      </div>
      <p className="text-4xl font-black tracking-[-0.05em]">{value}</p>
      <p
        className={[
          "mt-2 text-xs font-bold",
          highlight ? "text-white/75" : "text-emerald-600",
        ].join(" ")}
      >
        {subtitle}
      </p>
    </div>
  );
}

function LoadingPanel() {
  return (
    <div className="grid min-h-[420px] place-items-center rounded-[2rem] bg-white shadow-sm">
      <div className="text-center">
        <div className="mx-auto h-12 w-12 animate-spin rounded-full border-4 border-neutral-200 border-t-[#ff5a3d]" />
        <p className="mt-4 text-sm font-black text-neutral-950">Loading memory layer...</p>
        <p className="mt-1 text-xs font-medium text-neutral-500">
          Reading isolated workspace memory records.
        </p>
      </div>
    </div>
  );
}

function ErrorPanel({
  message,
  onRetry,
}: {
  message: string;
  onRetry: () => void;
}) {
  return (
    <div className="grid min-h-[420px] place-items-center rounded-[2rem] border border-red-100 bg-red-50 p-8 text-center">
      <div>
        <div className="mx-auto grid h-14 w-14 place-items-center rounded-2xl bg-white text-2xl shadow-sm">
          !
        </div>
        <h2 className="mt-5 text-2xl font-black tracking-[-0.04em] text-red-900">
          Memory could not load
        </h2>
        <p className="mt-2 max-w-md text-sm font-medium text-red-700">{message}</p>
        <button
          type="button"
          onClick={onRetry}
          className="mt-6 rounded-2xl bg-red-600 px-5 py-3 text-sm font-black text-white transition hover:bg-red-700"
        >
          Retry
        </button>
      </div>
    </div>
  );
}

function EmptyPanel() {
  return (
    <div className="grid min-h-[320px] place-items-center rounded-[1.6rem] border border-dashed border-neutral-200 bg-white p-8 text-center">
      <div>
        <div className="mx-auto grid h-14 w-14 place-items-center rounded-2xl bg-neutral-100 text-xl">
          ∅
        </div>
        <h3 className="mt-4 text-xl font-black tracking-[-0.03em] text-neutral-950">
          No memory records found
        </h3>
        <p className="mt-2 max-w-md text-sm font-medium text-neutral-500">
          Once agents complete useful work, Memory Agent will store isolated workspace context here.
        </p>
      </div>
    </div>
  );
}

export default function Page() {
  const router = useRouter();

  const [session, setSession] = useState<SessionData | null>(null);
  const [summary, setSummary] = useState<MemorySummary>(DEFAULT_SUMMARY);
  const [records, setRecords] = useState<MemoryRecord[]>([]);
  const [selectedMemoryIds, setSelectedMemoryIds] = useState<string[]>([]);
  const [state, setState] = useState<LoadState>("checking_session");
  const [errorMessage, setErrorMessage] = useState("");
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState<"all" | MemoryType>("all");
  const [sensitivityFilter, setSensitivityFilter] = useState<"all" | MemorySensitivity>("all");
  const [busyAction, setBusyAction] = useState<"delete" | "export" | null>(null);
  const [notice, setNotice] = useState<{
    type: "success" | "error" | "info";
    message: string;
  } | null>(null);

  const canDeleteMemory = useMemo(() => {
    if (!session) return false;
    return hasPermission(session, "memory:delete");
  }, [session]);

  const canExportMemory = useMemo(() => {
    if (!session) return false;
    return hasPermission(session, "memory:export");
  }, [session]);

  const canApproveSecurity = useMemo(() => {
    if (!session) return false;
    return hasPermission(session, "security:approve");
  }, [session]);

  const filteredRecords = useMemo(() => {
    const normalizedSearch = search.trim().toLowerCase();

    return records.filter((record) => {
      const sameWorkspace =
        !session ||
        (record.user_id === session.user_id && record.workspace_id === session.workspace_id);

      const matchesSearch =
        !normalizedSearch ||
        record.title.toLowerCase().includes(normalizedSearch) ||
        record.summary.toLowerCase().includes(normalizedSearch) ||
        record.key.toLowerCase().includes(normalizedSearch) ||
        record.source_agent.toLowerCase().includes(normalizedSearch) ||
        record.tags.some((tag) => tag.toLowerCase().includes(normalizedSearch));

      const matchesType = typeFilter === "all" || record.type === typeFilter;
      const matchesSensitivity =
        sensitivityFilter === "all" || record.sensitivity === sensitivityFilter;

      return sameWorkspace && matchesSearch && matchesType && matchesSensitivity;
    });
  }, [records, search, session, sensitivityFilter, typeFilter]);

  const selectedRecords = useMemo(() => {
    const selected = new Set(selectedMemoryIds);
    return records.filter((record) => selected.has(record.memory_id));
  }, [records, selectedMemoryIds]);

  const selectedHasSensitive = selectedRecords.some(
    (record) => record.sensitivity === "sensitive" || record.sensitivity === "restricted",
  );

  const storagePercent = useMemo(() => {
    if (!summary.storageLimitMb) return 0;
    return Math.min(100, Math.round((summary.storageUsedMb / summary.storageLimitMb) * 100));
  }, [summary.storageLimitMb, summary.storageUsedMb]);

  const chartMax = useMemo(() => {
    return Math.max(...summary.chart.standard, ...summary.chart.sensitive, 1);
  }, [summary.chart.sensitive, summary.chart.standard]);

  const loadMemory = useCallback(
    async (activeSession: SessionData) => {
      setState("loading");
      setErrorMessage("");

      const access = validateAccess(activeSession);

      if (!access.success) {
        clearSession();
        router.replace("/login");
        return;
      }

      const response = await apiRequest<MemoryPageData>(
        `/memory?user_id=${encodeURIComponent(activeSession.user_id)}&workspace_id=${encodeURIComponent(
          activeSession.workspace_id,
        )}`,
        activeSession,
        {
          method: "GET",
          headers: {
            "X-Action": "memory.read",
          },
        },
      );

      if (!response.success) {
        if (response.error?.code === "API_BASE_URL_MISSING") {
          const localRecords = LOCAL_DEMO_MEMORIES.map((record) => ({
            ...record,
            user_id: activeSession.user_id,
            workspace_id: activeSession.workspace_id,
          }));

          setRecords(localRecords);
          setSummary(buildLocalSummary(localRecords, activeSession));
          setState("ready");
          setNotice({
            type: "info",
            message:
              "API is not connected yet, so this page is showing local Memory Agent structure. Connect NEXT_PUBLIC_API_BASE_URL for live database memory records.",
          });
          return;
        }

        setState("error");
        setErrorMessage(response.error?.message || "Could not load memory records.");
        return;
      }

      const data = response.data || {
        summary: DEFAULT_SUMMARY,
        records: [],
      };

      const safeRecords = data.records.filter(
        (record) =>
          record.user_id === activeSession.user_id &&
          record.workspace_id === activeSession.workspace_id,
      );

      setSummary({
        ...data.summary,
        storageLimitMb:
          data.summary.storageLimitMb || PLAN_MEMORY_LIMIT_MB[activeSession.plan],
      });
      setRecords(safeRecords);
      setSelectedMemoryIds([]);
      setState(safeRecords.length > 0 ? "ready" : "empty");
    },
    [router],
  );

  useEffect(() => {
    const activeSession = readSession();

    if (!activeSession) {
      router.replace("/login");
      return;
    }

    setSession(activeSession);
    void loadMemory(activeSession);
  }, [loadMemory, router]);

  function toggleSelected(memoryId: string) {
    setSelectedMemoryIds((current) =>
      current.includes(memoryId)
        ? current.filter((id) => id !== memoryId)
        : [...current, memoryId],
    );
  }

  function toggleSelectAllVisible() {
    const visibleIds = filteredRecords.map((record) => record.memory_id);
    const allVisibleSelected = visibleIds.every((id) => selectedMemoryIds.includes(id));

    if (allVisibleSelected) {
      setSelectedMemoryIds((current) => current.filter((id) => !visibleIds.includes(id)));
      return;
    }

    setSelectedMemoryIds((current) => Array.from(new Set([...current, ...visibleIds])));
  }

  async function handleDeleteSelected() {
    if (!session) {
      router.replace("/login");
      return;
    }

    if (!canDeleteMemory) {
      setNotice({
        type: "error",
        message: "Your role cannot delete memory records.",
      });
      return;
    }

    if (selectedMemoryIds.length === 0) {
      setNotice({
        type: "error",
        message: "Select at least one memory record to delete.",
      });
      return;
    }

    if (selectedHasSensitive && !canApproveSecurity) {
      setNotice({
        type: "error",
        message:
          "Deleting sensitive/restricted memory requires Security Agent approval permission.",
      });
      return;
    }

    setBusyAction("delete");
    setNotice(null);

    const response = await apiRequest<MemoryActionResponse>("/memory/delete", session, {
      method: "POST",
      headers: {
        "X-Action": "memory.delete",
        "X-Sensitive-Action": selectedHasSensitive ? "true" : "false",
      },
      body: JSON.stringify({
        user_id: session.user_id,
        workspace_id: session.workspace_id,
        memory_ids: selectedMemoryIds,
        route: {
          master_agent: true,
          security_agent: selectedHasSensitive,
          memory_agent: true,
          verification_agent: true,
        },
        clientContext: {
          app: "william-dashboard",
          module: "memory.manager",
          action: "memory.delete",
          requiresAudit: true,
          requiresSecurityRoute: selectedHasSensitive,
          memoryCompatible: true,
          verificationCompatible: true,
        },
      }),
    });

    if (!response.success || !response.data) {
      if (response.error?.code === "API_BASE_URL_MISSING") {
        setRecords((current) =>
          current.filter((record) => !selectedMemoryIds.includes(record.memory_id)),
        );
        setSelectedMemoryIds([]);
        setNotice({
          type: "info",
          message:
            "Local memory records removed from UI. Connect the API to delete from the database.",
        });
        setBusyAction(null);
        return;
      }

      setNotice({
        type: "error",
        message: response.error?.message || "Memory records could not be deleted.",
      });
      setBusyAction(null);
      return;
    }

    setRecords((current) =>
      current.filter((record) => !selectedMemoryIds.includes(record.memory_id)),
    );
    setSelectedMemoryIds([]);
    setNotice({
      type: "success",
      message:
        "Memory records deleted. Security route, audit log, and verification payload were prepared.",
    });
    setBusyAction(null);
  }

  async function handleExportSelected() {
    if (!session) {
      router.replace("/login");
      return;
    }

    if (!canExportMemory) {
      setNotice({
        type: "error",
        message: "Your role cannot export memory records.",
      });
      return;
    }

    const exportIds =
      selectedMemoryIds.length > 0
        ? selectedMemoryIds
        : filteredRecords.map((record) => record.memory_id);

    if (exportIds.length === 0) {
      setNotice({
        type: "error",
        message: "No memory records available to export.",
      });
      return;
    }

    const exportRecords = records.filter((record) => exportIds.includes(record.memory_id));
    const exportHasSensitive = exportRecords.some(
      (record) => record.sensitivity === "sensitive" || record.sensitivity === "restricted",
    );

    if (exportHasSensitive && !canApproveSecurity) {
      setNotice({
        type: "error",
        message:
          "Exporting sensitive/restricted memory requires Security Agent approval permission.",
      });
      return;
    }

    setBusyAction("export");
    setNotice(null);

    const response = await apiRequest<MemoryActionResponse>("/memory/export", session, {
      method: "POST",
      headers: {
        "X-Action": "memory.export",
        "X-Sensitive-Action": exportHasSensitive ? "true" : "false",
      },
      body: JSON.stringify({
        user_id: session.user_id,
        workspace_id: session.workspace_id,
        memory_ids: exportIds,
        format: "json",
        route: {
          master_agent: true,
          security_agent: exportHasSensitive,
          memory_agent: true,
          verification_agent: true,
        },
        clientContext: {
          app: "william-dashboard",
          module: "memory.manager",
          action: "memory.export",
          requiresAudit: true,
          requiresSecurityRoute: exportHasSensitive,
          memoryCompatible: true,
          verificationCompatible: true,
        },
      }),
    });

    if (!response.success || !response.data) {
      if (response.error?.code === "API_BASE_URL_MISSING") {
        const blob = new Blob(
          [
            JSON.stringify(
              {
                user_id: session.user_id,
                workspace_id: session.workspace_id,
                exported_at: new Date().toISOString(),
                records: exportRecords,
              },
              null,
              2,
            ),
          ],
          { type: "application/json" },
        );

        const url = URL.createObjectURL(blob);
        const anchor = document.createElement("a");
        anchor.href = url;
        anchor.download = `william-memory-${session.workspace_slug}.json`;
        anchor.click();
        URL.revokeObjectURL(url);

        setNotice({
          type: "info",
          message:
            "Local JSON export created. Connect the API for database-backed export with audit and verification.",
        });
        setBusyAction(null);
        return;
      }

      setNotice({
        type: "error",
        message: response.error?.message || "Memory export could not be prepared.",
      });
      setBusyAction(null);
      return;
    }

    if (response.data.exported_file_url) {
      window.open(response.data.exported_file_url, "_blank", "noopener,noreferrer");
    }

    setNotice({
      type: "success",
      message:
        "Memory export prepared. Security route, audit log, and verification payload are ready.",
    });
    setBusyAction(null);
  }

  function handleLogout() {
    clearSession();
    router.replace("/login");
  }

  if (state === "checking_session" || !session) {
    return (
      <main className="grid min-h-screen place-items-center bg-[#e9e9e7] px-6 text-neutral-950">
        <div className="rounded-[2rem] bg-white px-8 py-7 text-center shadow-2xl shadow-black/10">
          <div className="mx-auto h-10 w-10 animate-spin rounded-full border-4 border-neutral-200 border-t-[#ff5a3d]" />
          <p className="mt-4 text-sm font-black">Checking memory access...</p>
          <p className="mt-1 text-xs font-medium text-neutral-500">
            Validating user_id and workspace_id.
          </p>
        </div>
      </main>
    );
  }

  return (
    <main className="min-h-screen bg-[#e9e9e7] px-4 py-6 text-neutral-950 sm:px-6 lg:px-8">
      <div className="mx-auto flex min-h-[calc(100vh-3rem)] max-w-7xl overflow-hidden rounded-[2.25rem] bg-[#f7f7f6] p-4 shadow-2xl shadow-black/10">
        <aside className="hidden w-[72px] shrink-0 flex-col items-center justify-between rounded-[1.8rem] bg-white p-4 shadow-sm lg:flex">
          <div className="space-y-8">
            <div className="grid h-12 w-12 place-items-center rounded-2xl bg-[#ff5a3d] text-lg font-black text-white shadow-xl shadow-[#ff5a3d]/25">
              W
            </div>

            <div className="space-y-3">
              <a href="/dashboard" aria-label="Dashboard">
                <IconBox>⌘</IconBox>
              </a>
              <a href="/agents" aria-label="Agents">
                <IconBox>▦</IconBox>
              </a>
              <a href="/agent-permissions" aria-label="Agent permissions">
                <IconBox>☷</IconBox>
              </a>
              <IconBox active>◌</IconBox>
              <a href="/security" aria-label="Security">
                <IconBox>▣</IconBox>
              </a>
              <a href="/workflows" aria-label="Workflows">
                <IconBox>◎</IconBox>
              </a>
              <a href="/settings" aria-label="Settings">
                <IconBox>⚙</IconBox>
              </a>
            </div>
          </div>

          <div className="space-y-3">
            <IconBox>?</IconBox>
            <button type="button" onClick={handleLogout} aria-label="Logout">
              <IconBox>↩</IconBox>
            </button>
          </div>
        </aside>

        <section className="flex min-w-0 flex-1 flex-col px-0 lg:px-6">
          <header className="mb-6 flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
            <div className="flex flex-col gap-4 lg:flex-row lg:items-center">
              <div className="lg:hidden flex items-center gap-3 rounded-[1.5rem] bg-white p-3 shadow-sm">
                <div className="grid h-11 w-11 place-items-center rounded-2xl bg-[#ff5a3d] font-black text-white">
                  W
                </div>
                <div>
                  <p className="text-sm font-black">Memory Manager</p>
                  <p className="text-xs font-medium text-neutral-500">
                    {session.workspace_name}
                  </p>
                </div>
              </div>

              <div className="relative w-full max-w-md">
                <span className="absolute left-4 top-1/2 -translate-y-1/2 text-neutral-400">
                  ⌕
                </span>
                <input
                  type="search"
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                  placeholder="Search memory, agents, tags, keys..."
                  className="h-12 w-full rounded-full border border-neutral-200 bg-white px-11 text-sm font-semibold outline-none transition placeholder:text-neutral-400 focus:border-[#ff5a3d] focus:ring-4 focus:ring-[#ff5a3d]/10"
                />
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <span className="rounded-full border border-emerald-100 bg-emerald-50 px-4 py-2 text-xs font-black text-emerald-700">
                🔒 Security Guarded
              </span>
              <span className="rounded-full border border-[#ffd9cc] bg-[#fff3ed] px-4 py-2 text-xs font-black text-[#ff5a3d]">
                ⛓ Workspace Isolated
              </span>
              <div className="flex items-center gap-3 rounded-full bg-white px-3 py-2 shadow-sm">
                <div className="grid h-10 w-10 place-items-center rounded-full bg-[#ff5a3d] text-xs font-black text-white">
                  {session.name
                    .split(" ")
                    .map((part) => part[0])
                    .join("")
                    .slice(0, 2)
                    .toUpperCase() || "DP"}
                </div>
                <div>
                  <p className="max-w-[130px] truncate text-xs font-black text-neutral-950">
                    {session.name}
                  </p>
                  <p className="max-w-[130px] truncate text-[11px] font-medium text-neutral-500">
                    {session.role} · {session.plan}
                  </p>
                </div>
              </div>
            </div>
          </header>

          <div className="mb-6 flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <h1 className="text-4xl font-black tracking-[-0.055em] text-neutral-950 lg:text-5xl">
                Memory Manager
              </h1>
              <p className="mt-2 text-sm font-medium text-neutral-500">
                Search, export, and delete workspace-safe memory records without leaking user context.
              </p>
            </div>

            <div className="rounded-2xl bg-white px-4 py-3 shadow-sm">
              <p className="text-[11px] font-black uppercase tracking-[0.18em] text-neutral-400">
                Workspace
              </p>
              <p className="mt-1 text-sm font-black text-neutral-950">
                {session.workspace_name}
              </p>
            </div>
          </div>

          {notice ? (
            <div
              className={[
                "mb-5 rounded-2xl px-4 py-3 text-sm font-bold",
                notice.type === "success"
                  ? "border border-emerald-100 bg-emerald-50 text-emerald-700"
                  : notice.type === "error"
                    ? "border border-red-100 bg-red-50 text-red-700"
                    : "border border-amber-100 bg-amber-50 text-amber-800",
              ].join(" ")}
            >
              {notice.message}
            </div>
          ) : null}

          {state === "loading" ? (
            <LoadingPanel />
          ) : state === "error" ? (
            <ErrorPanel
              message={errorMessage}
              onRetry={() => {
                if (session) void loadMemory(session);
              }}
            />
          ) : (
            <div className="space-y-5">
              <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-6">
                <StatCard
                  title="Total Memory"
                  value={formatNumber(summary.totalRecords)}
                  subtitle="Workspace-scoped"
                  icon="◌"
                  highlight
                />
                <StatCard
                  title="Standard"
                  value={formatNumber(summary.standardRecords)}
                  subtitle="Low risk"
                  icon="✓"
                />
                <StatCard
                  title="Sensitive"
                  value={formatNumber(summary.sensitiveRecords)}
                  subtitle="Security routed"
                  icon="▣"
                />
                <StatCard
                  title="Restricted"
                  value={formatNumber(summary.restrictedRecords)}
                  subtitle="Approval required"
                  icon="!"
                />
                <StatCard
                  title="Exports"
                  value={formatNumber(summary.exportedRecords)}
                  subtitle="Audit tracked"
                  icon="↥"
                />
                <StatCard
                  title="Deleted"
                  value={formatNumber(summary.deletedThisMonth)}
                  subtitle="This month"
                  icon="×"
                />
              </section>

              <section className="grid gap-5 xl:grid-cols-[0.75fr_1.25fr]">
                <div className="space-y-5">
                  <div className="rounded-[1.6rem] bg-white p-5 shadow-sm">
                    <div className="mb-5 flex items-center justify-between">
                      <div>
                        <p className="text-base font-black text-neutral-950">Storage Usage</p>
                        <p className="text-xs font-medium text-neutral-500">
                          Plan-based memory capacity.
                        </p>
                      </div>
                      <span className="rounded-full bg-[#fff3ed] px-3 py-1 text-xs font-black text-[#ff5a3d]">
                        {session.plan}
                      </span>
                    </div>

                    <div className="h-3 overflow-hidden rounded-full bg-neutral-100">
                      <div
                        className="h-full rounded-full bg-[#ff5a3d]"
                        style={{ width: `${storagePercent}%` }}
                      />
                    </div>

                    <div className="mt-3 flex items-center justify-between text-xs font-bold text-neutral-500">
                      <span>{summary.storageUsedMb} MB used</span>
                      <span>{summary.storageLimitMb} MB limit</span>
                    </div>
                  </div>

                  <div className="rounded-[1.6rem] bg-white p-5 shadow-sm">
                    <div className="mb-5">
                      <p className="text-base font-black text-neutral-950">
                        Memory Activity
                      </p>
                      <p className="text-xs font-medium text-neutral-500">
                        Standard vs sensitive records.
                      </p>
                    </div>

                    {summary.chart.labels.length === 0 ? (
                      <EmptyPanel />
                    ) : (
                      <div className="flex h-56 items-end gap-4 rounded-2xl bg-neutral-50 px-5 py-4">
                        {summary.chart.labels.map((label, index) => {
                          const standard = summary.chart.standard[index] || 0;
                          const sensitive = summary.chart.sensitive[index] || 0;

                          return (
                            <div
                              key={`${label}-${index}`}
                              className="flex flex-1 flex-col items-center justify-end gap-2"
                            >
                              <div className="flex h-40 items-end gap-1">
                                <div
                                  className="w-5 rounded-t-xl bg-[#ff5a3d]"
                                  style={{
                                    height: `${Math.max(8, (standard / chartMax) * 100)}%`,
                                  }}
                                  title={`Standard: ${standard}`}
                                />
                                <div
                                  className="w-5 rounded-t-xl bg-neutral-950"
                                  style={{
                                    height: `${Math.max(8, (sensitive / chartMax) * 100)}%`,
                                  }}
                                  title={`Sensitive: ${sensitive}`}
                                />
                              </div>
                              <span className="text-[11px] font-black text-neutral-400">
                                {label}
                              </span>
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>

                  <div className="rounded-[1.6rem] bg-white p-5 shadow-sm">
                    <p className="text-base font-black text-neutral-950">Filters</p>

                    <div className="mt-5 space-y-4">
                      <div>
                        <label className="mb-2 block text-xs font-black uppercase tracking-[0.16em] text-neutral-400">
                          Type
                        </label>
                        <select
                          value={typeFilter}
                          onChange={(event) =>
                            setTypeFilter(event.target.value as "all" | MemoryType)
                          }
                          className="h-12 w-full rounded-2xl border border-neutral-200 bg-neutral-50 px-4 text-sm font-bold outline-none focus:border-[#ff5a3d] focus:ring-4 focus:ring-[#ff5a3d]/10"
                        >
                          <option value="all">All Types</option>
                          <option value="task">Task</option>
                          <option value="agent">Agent</option>
                          <option value="workspace">Workspace</option>
                          <option value="user">User</option>
                          <option value="security">Security</option>
                          <option value="verification">Verification</option>
                          <option value="workflow">Workflow</option>
                        </select>
                      </div>

                      <div>
                        <label className="mb-2 block text-xs font-black uppercase tracking-[0.16em] text-neutral-400">
                          Sensitivity
                        </label>
                        <select
                          value={sensitivityFilter}
                          onChange={(event) =>
                            setSensitivityFilter(
                              event.target.value as "all" | MemorySensitivity,
                            )
                          }
                          className="h-12 w-full rounded-2xl border border-neutral-200 bg-neutral-50 px-4 text-sm font-bold outline-none focus:border-[#ff5a3d] focus:ring-4 focus:ring-[#ff5a3d]/10"
                        >
                          <option value="all">All Sensitivity</option>
                          <option value="standard">Standard</option>
                          <option value="sensitive">Sensitive</option>
                          <option value="restricted">Restricted</option>
                        </select>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="rounded-[1.6rem] bg-white p-5 shadow-sm">
                  <div className="mb-5 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                    <div>
                      <p className="text-lg font-black tracking-[-0.03em] text-neutral-950">
                        Memory Records
                      </p>
                      <p className="text-sm font-medium text-neutral-500">
                        {selectedMemoryIds.length} selected · {filteredRecords.length} visible
                      </p>
                    </div>

                    <div className="flex flex-wrap gap-3">
                      <button
                        type="button"
                        onClick={toggleSelectAllVisible}
                        disabled={filteredRecords.length === 0 || busyAction !== null}
                        className="rounded-full border border-neutral-200 bg-white px-4 py-2 text-xs font-black text-neutral-700 transition hover:border-[#ff5a3d] hover:text-[#ff5a3d] disabled:cursor-not-allowed disabled:opacity-50"
                      >
                        Select Visible
                      </button>
                      <button
                        type="button"
                        onClick={() => void handleExportSelected()}
                        disabled={!canExportMemory || busyAction !== null}
                        className="rounded-full bg-neutral-950 px-4 py-2 text-xs font-black text-white transition hover:bg-[#ff5a3d] disabled:cursor-not-allowed disabled:opacity-50"
                      >
                        {busyAction === "export" ? "Exporting..." : "Export"}
                      </button>
                      <button
                        type="button"
                        onClick={() => void handleDeleteSelected()}
                        disabled={!canDeleteMemory || selectedMemoryIds.length === 0 || busyAction !== null}
                        className="rounded-full bg-red-600 px-4 py-2 text-xs font-black text-white transition hover:bg-red-700 disabled:cursor-not-allowed disabled:opacity-50"
                      >
                        {busyAction === "delete" ? "Deleting..." : "Delete"}
                      </button>
                    </div>
                  </div>

                  {state === "empty" || filteredRecords.length === 0 ? (
                    <EmptyPanel />
                  ) : (
                    <div className="space-y-4">
                      {filteredRecords.map((record) => {
                        const isSelected = selectedMemoryIds.includes(record.memory_id);

                        return (
                          <article
                            key={record.memory_id}
                            className={[
                              "rounded-[1.5rem] border p-4 transition",
                              isSelected
                                ? "border-[#ff5a3d]/40 bg-[#fff3ed]"
                                : "border-neutral-100 bg-neutral-50 hover:bg-white",
                            ].join(" ")}
                          >
                            <div className="mb-4 flex items-start justify-between gap-4">
                              <div className="flex min-w-0 items-start gap-3">
                                <button
                                  type="button"
                                  onClick={() => toggleSelected(record.memory_id)}
                                  className={[
                                    "mt-1 grid h-6 w-6 shrink-0 place-items-center rounded-lg border text-xs font-black transition",
                                    isSelected
                                      ? "border-[#ff5a3d] bg-[#ff5a3d] text-white"
                                      : "border-neutral-300 bg-white text-transparent",
                                  ].join(" ")}
                                  aria-label={`Select ${record.title}`}
                                >
                                  ✓
                                </button>

                                <div
                                  className={[
                                    "grid h-12 w-12 shrink-0 place-items-center rounded-2xl text-lg font-black",
                                    isSelected
                                      ? "bg-[#ff5a3d] text-white shadow-lg shadow-[#ff5a3d]/25"
                                      : "bg-white text-neutral-500",
                                  ].join(" ")}
                                >
                                  {getTypeIcon(record.type)}
                                </div>

                                <div className="min-w-0">
                                  <h2 className="truncate text-base font-black text-neutral-950">
                                    {record.title}
                                  </h2>
                                  <p className="truncate text-xs font-bold text-neutral-400">
                                    {record.key}
                                  </p>
                                </div>
                              </div>

                              <span
                                className={[
                                  "rounded-full px-3 py-1 text-[11px] font-black capitalize",
                                  getSensitivityStyle(record.sensitivity),
                                ].join(" ")}
                              >
                                {record.sensitivity}
                              </span>
                            </div>

                            <p className="text-sm font-medium leading-6 text-neutral-500">
                              {record.summary}
                            </p>

                            <div className="mt-4 flex flex-wrap gap-2">
                              <span className="rounded-full bg-white px-3 py-1 text-[11px] font-black text-neutral-600">
                                {record.source_agent}
                              </span>
                              <span className="rounded-full bg-white px-3 py-1 text-[11px] font-black text-neutral-600 capitalize">
                                {record.type}
                              </span>
                              {record.tags.map((tag) => (
                                <span
                                  key={`${record.memory_id}-${tag}`}
                                  className="rounded-full bg-white px-3 py-1 text-[11px] font-black text-neutral-500"
                                >
                                  #{tag}
                                </span>
                              ))}
                            </div>

                            <div className="mt-4 grid gap-3 rounded-2xl bg-white p-3 text-xs font-medium text-neutral-500 sm:grid-cols-3">
                              <span>
                                Created:{" "}
                                <strong className="text-neutral-800">
                                  {formatDate(record.created_at)}
                                </strong>
                              </span>
                              <span>
                                Updated:{" "}
                                <strong className="text-neutral-800">
                                  {formatDate(record.updated_at)}
                                </strong>
                              </span>
                              <span>
                                Last used:{" "}
                                <strong className="text-neutral-800">
                                  {formatDate(record.last_used_at)}
                                </strong>
                              </span>
                            </div>
                          </article>
                        );
                      })}
                    </div>
                  )}
                </div>
              </section>
            </div>
          )}
        </section>
      </div>
    </main>
  );
}