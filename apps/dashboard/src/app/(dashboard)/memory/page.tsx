"use client";

/**
 * apps/dashboard/src/app/(dashboard)/memory/page.tsx
 *
 * William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
 * Memory Manager dashboard page.
 *
 * Wired to the real apps/api/routes/memory.py backend (GET/DELETE /memory,
 * POST /memory/export, GET /memory/health/status) via the shared
 * src/lib/auth.ts session module and Bearer-token auth. Previously this page
 * read sessions straight out of localStorage/sessionStorage with its own
 * local SessionData type (from before the shared lib/auth.ts module
 * existed), and fell back to three fabricated LOCAL_DEMO_MEMORIES records
 * plus a hardcoded fake 7-day activity chart whenever the API call failed.
 * Both are gone -- the real backend's MemoryRecord shape (memory_type:
 * short/long/project/client, sensitivity: public/internal/confidential/
 * restricted) is different from the old invented vocabulary
 * (type: task/agent/security/... , sensitivity: standard/sensitive/
 * restricted), so the types below match the real Pydantic/dataclass models
 * in apps/api/routes/memory.py exactly, not the old guesses.
 */

import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import {
  SessionData,
  UserRole,
  clearSession,
  hasMinRole,
  hasPermission,
  readSession,
} from "@/lib/auth";
import { EmptyState } from "@/components/state/EmptyState";
import { ErrorState } from "@/components/state/ErrorState";
import { ForbiddenState } from "@/components/state/ForbiddenState";
import { LoadingState } from "@/components/state/LoadingState";

type LoadState =
  | "checking_session"
  | "loading"
  | "ready"
  | "empty"
  | "error"
  | "forbidden";

type MemoryType = "short" | "long" | "project" | "client";
type MemorySensitivity = "public" | "internal" | "confidential" | "restricted";
type MemorySource = "user" | "master_agent" | "memory_agent" | "system" | "api";

// Matches apps/api/routes/memory.py's MemoryRecord.visible_dict() exactly.
type MemoryRecord = {
  id: string;
  user_id: string;
  workspace_id: string;
  memory_type: MemoryType;
  content: string;
  title: string | null;
  tags: string[];
  source: MemorySource;
  sensitivity: MemorySensitivity;
  project_id: string | null;
  client_id: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
  deleted_at: string | null;
  created_by: string | null;
  updated_by: string | null;
};

// The real GET /memory/health/status response's `data` shape.
type MemoryHealth = {
  active_memory_count: number;
  total_scoped_memory_count: number;
  memory_limit: number;
};

type BackendEnvelope<T> = {
  ok: boolean;
  message: string;
  data: T;
  verification?: Record<string, unknown>;
  request_id?: string;
};

type MemorySearchEnvelope = {
  ok: boolean;
  message: string;
  records: MemoryRecord[];
  total: number;
  limit: number;
  offset: number;
  request_id?: string;
};

type ApiClientOptions = {
  method?: "GET" | "POST" | "PATCH" | "DELETE";
  body?: unknown;
};

const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL?.replace(/\/$/, "") || "";

function canWriteMemory(role: UserRole): boolean {
  return hasMinRole(role, "user");
}

function canDeleteMemory(role: UserRole): boolean {
  return hasMinRole(role, "manager");
}

function canExportMemory(role: UserRole): boolean {
  return hasMinRole(role, "manager");
}

function canViewRestricted(role: UserRole): boolean {
  return hasMinRole(role, "admin");
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

async function apiRequest<T>(
  path: string,
  options: ApiClientOptions = {},
): Promise<T> {
  const activeSession = readSession();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
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
    : { ok: false, error: { message: "Server returned a non-JSON response." } };

  if (!response.ok) {
    throw new Error(
      payload?.error?.message || payload?.message || "API request failed.",
    );
  }

  return payload as T;
}

async function loadMemoryRecords(filters: {
  query: string;
  memoryType: "all" | MemoryType;
}): Promise<{ records: MemoryRecord[]; total: number }> {
  const params = new URLSearchParams();
  if (filters.query.trim()) params.set("query", filters.query.trim());
  if (filters.memoryType !== "all")
    params.set("memory_type", filters.memoryType);
  params.set("limit", "100");

  const response = await apiRequest<MemorySearchEnvelope>(
    `/memory?${params.toString()}`,
  );
  if (!response.ok)
    throw new Error(response.message || "Unable to load memory records.");
  return { records: response.records, total: response.total };
}

async function loadMemoryHealth(): Promise<MemoryHealth> {
  const response = await apiRequest<BackendEnvelope<MemoryHealth>>(
    "/memory/health/status",
  );
  if (!response.ok)
    throw new Error(response.message || "Unable to load memory status.");
  return response.data;
}

async function deleteMemoryRecords(
  memoryIds: string[],
): Promise<{ deleted_ids: string[]; deleted_count: number }> {
  const response = await apiRequest<
    BackendEnvelope<{
      deleted_ids: string[];
      deleted_count: number;
      hard_delete: boolean;
    }>
  >("/memory", {
    method: "DELETE",
    body: { memory_ids: memoryIds },
  });

  if (!response.ok)
    throw new Error(response.message || "Memory records could not be deleted.");
  return response.data;
}

// The real POST /memory/export only filters by memory_types/tags/project_id/
// client_id -- there is no memory_ids field, so "export selected records"
// isn't something the real backend supports. This exports every record
// matching the current type filter instead of fabricating an ID-based
// filter the API doesn't have.
async function exportMemoryRecords(
  memoryType: "all" | MemoryType,
): Promise<{ records: MemoryRecord[]; count: number }> {
  const response = await apiRequest<{
    ok: boolean;
    message: string;
    count: number;
    records: MemoryRecord[];
  }>("/memory/export", {
    method: "POST",
    body: {
      memory_types: memoryType === "all" ? [] : [memoryType],
      export_format: "json",
    },
  });

  if (!response.ok)
    throw new Error(response.message || "Memory export could not be prepared.");
  return { records: response.records, count: response.count };
}

function formatNumber(value?: number | null): string {
  if (value === null || value === undefined) return "Not available";
  return new Intl.NumberFormat("en-US").format(value);
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

function formatLabel(value: string): string {
  return value
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function getTypeIcon(type: MemoryType): string {
  const icons: Record<MemoryType, string> = {
    short: "☷",
    long: "▦",
    project: "◎",
    client: "✦",
  };
  return icons[type];
}

function getSensitivityStyle(sensitivity: MemorySensitivity): string {
  if (sensitivity === "public") return "bg-emerald-50 text-emerald-700";
  if (sensitivity === "internal") return "bg-blue-50 text-blue-700";
  if (sensitivity === "confidential") return "bg-orange-50 text-orange-700";
  return "bg-red-50 text-red-700";
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
            highlight
              ? "bg-white/15 text-white"
              : "bg-neutral-100 text-neutral-500",
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

function DistributionCard({
  title,
  subtitle,
  entries,
}: {
  title: string;
  subtitle: string;
  entries: { label: string; count: number }[];
}) {
  const max = Math.max(...entries.map((entry) => entry.count), 1);

  return (
    <div className="rounded-[1.6rem] bg-white p-5 shadow-sm">
      <div className="mb-5">
        <p className="text-base font-black text-neutral-950">{title}</p>
        <p className="text-xs font-medium text-neutral-500">{subtitle}</p>
      </div>

      {entries.every((entry) => entry.count === 0) ? (
        <EmptyState
          variant="light"
          title="No memory records found"
          message="Once agents complete useful work, Memory Agent will store isolated workspace context here."
        />
      ) : (
        <div className="space-y-3">
          {entries.map((entry) => (
            <div key={entry.label}>
              <div className="mb-1 flex items-center justify-between text-xs font-bold text-neutral-500">
                <span>{entry.label}</span>
                <span>{entry.count}</span>
              </div>
              <div className="h-2.5 overflow-hidden rounded-full bg-neutral-100">
                <div
                  className="h-full rounded-full bg-[#ff5a3d]"
                  style={{
                    width: `${Math.max(4, (entry.count / max) * 100)}%`,
                  }}
                />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function Page() {
  const router = useRouter();

  const [session, setSession] = useState<SessionData | null>(null);
  const [health, setHealth] = useState<MemoryHealth | null>(null);
  const [records, setRecords] = useState<MemoryRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [selectedMemoryIds, setSelectedMemoryIds] = useState<string[]>([]);
  const [state, setState] = useState<LoadState>("checking_session");
  const [errorMessage, setErrorMessage] = useState("");
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState<"all" | MemoryType>("all");
  const [sensitivityFilter, setSensitivityFilter] = useState<
    "all" | MemorySensitivity
  >("all");
  const [busyAction, setBusyAction] = useState<"delete" | "export" | null>(
    null,
  );
  const [notice, setNotice] = useState<{
    type: "success" | "error" | "info";
    message: string;
  } | null>(null);

  const canDelete = useMemo(
    () => (session ? canDeleteMemory(session.role) : false),
    [session],
  );
  const canExport = useMemo(
    () => (session ? canExportMemory(session.role) : false),
    [session],
  );
  const canViewRestrictedRecords = useMemo(
    () => (session ? canViewRestricted(session.role) : false),
    [session],
  );

  const filteredRecords = useMemo(() => {
    const normalizedSearch = search.trim().toLowerCase();

    return records.filter((record) => {
      const matchesSensitivity =
        sensitivityFilter === "all" || record.sensitivity === sensitivityFilter;
      const matchesSearch =
        !normalizedSearch ||
        (record.title || "").toLowerCase().includes(normalizedSearch) ||
        record.content.toLowerCase().includes(normalizedSearch) ||
        record.tags.some((tag) => tag.toLowerCase().includes(normalizedSearch));
      const visibleRestricted =
        record.sensitivity !== "restricted" || canViewRestrictedRecords;

      return matchesSensitivity && matchesSearch && visibleRestricted;
    });
  }, [records, search, sensitivityFilter, canViewRestrictedRecords]);

  const sensitivityBreakdown = useMemo(() => {
    const buckets: Record<MemorySensitivity, number> = {
      public: 0,
      internal: 0,
      confidential: 0,
      restricted: 0,
    };
    records.forEach((record) => {
      buckets[record.sensitivity] += 1;
    });
    return buckets;
  }, [records]);

  const typeBreakdown = useMemo(() => {
    const buckets: Record<MemoryType, number> = {
      short: 0,
      long: 0,
      project: 0,
      client: 0,
    };
    records.forEach((record) => {
      buckets[record.memory_type] += 1;
    });
    return buckets;
  }, [records]);

  const recordLimitPercent = useMemo(() => {
    if (!health || !health.memory_limit) return 0;
    return Math.min(
      100,
      Math.round((health.active_memory_count / health.memory_limit) * 100),
    );
  }, [health]);

  const loadMemory = useCallback(
    async (
      activeSession: SessionData,
      currentQuery: string,
      currentType: "all" | MemoryType,
    ) => {
      setState("loading");
      setErrorMessage("");

      try {
        const [{ records: loadedRecords, total: loadedTotal }, loadedHealth] =
          await Promise.all([
            loadMemoryRecords({ query: currentQuery, memoryType: currentType }),
            loadMemoryHealth(),
          ]);

        setRecords(loadedRecords);
        setTotal(loadedTotal);
        setHealth(loadedHealth);
        setSelectedMemoryIds([]);
        setState(loadedRecords.length > 0 ? "ready" : "empty");
      } catch (error) {
        setState("error");
        setErrorMessage(sanitizeError(error));
      }
    },
    [],
  );

  useEffect(() => {
    const activeSession = readSession();

    if (!activeSession) {
      router.replace("/login");
      return;
    }

    if (!hasPermission(activeSession, "memory:read")) {
      setSession(activeSession);
      setState("forbidden");
      return;
    }

    setSession(activeSession);
    void loadMemory(activeSession, search, typeFilter);
    // Only re-run on mount -- search/typeFilter changes are applied via the
    // explicit "Apply Filters" action below, not on every keystroke.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [loadMemory, router]);

  function applyFilters() {
    if (session) void loadMemory(session, search, typeFilter);
  }

  function toggleSelected(memoryId: string) {
    setSelectedMemoryIds((current) =>
      current.includes(memoryId)
        ? current.filter((id) => id !== memoryId)
        : [...current, memoryId],
    );
  }

  function toggleSelectAllVisible() {
    const visibleIds = filteredRecords.map((record) => record.id);
    const allVisibleSelected = visibleIds.every((id) =>
      selectedMemoryIds.includes(id),
    );

    if (allVisibleSelected) {
      setSelectedMemoryIds((current) =>
        current.filter((id) => !visibleIds.includes(id)),
      );
      return;
    }

    setSelectedMemoryIds((current) =>
      Array.from(new Set([...current, ...visibleIds])),
    );
  }

  async function handleDeleteSelected() {
    if (!session) {
      router.replace("/login");
      return;
    }

    if (!canDelete) {
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

    setBusyAction("delete");
    setNotice(null);

    try {
      const result = await deleteMemoryRecords(selectedMemoryIds);
      setRecords((current) =>
        current.filter((record) => !result.deleted_ids.includes(record.id)),
      );
      setTotal((current) => Math.max(0, current - result.deleted_count));
      setSelectedMemoryIds([]);
      setNotice({
        type: "success",
        message: `${result.deleted_count} memory record(s) deleted. Security route, audit log, and verification payload were prepared server-side.`,
      });
    } catch (error) {
      setNotice({ type: "error", message: sanitizeError(error) });
    } finally {
      setBusyAction(null);
    }
  }

  async function handleExport() {
    if (!session) {
      router.replace("/login");
      return;
    }

    if (!canExport) {
      setNotice({
        type: "error",
        message: "Your role cannot export memory records.",
      });
      return;
    }

    setBusyAction("export");
    setNotice(null);

    try {
      const result = await exportMemoryRecords(typeFilter);

      const blob = new Blob(
        [
          JSON.stringify(
            {
              workspace_id: session.workspace_id,
              exported_at: new Date().toISOString(),
              count: result.count,
              records: result.records,
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
        type: "success",
        message: `Exported ${result.count} memory record(s). Security route, audit log, and verification payload were prepared server-side.`,
      });
    } catch (error) {
      setNotice({ type: "error", message: sanitizeError(error) });
    } finally {
      setBusyAction(null);
    }
  }

  function handleLogout() {
    clearSession();
    router.replace("/login");
  }

  if (state === "checking_session" || !session) {
    return (
      <div className="grid min-h-[420px] place-items-center text-neutral-950">
        <LoadingState
          variant="light"
          title="Checking memory access..."
          subtitle="Validating user_id and workspace_id."
        />
      </div>
    );
  }

  if (state === "forbidden") {
    return (
      <div className="text-neutral-950">
        <ForbiddenState
          variant="light"
          message="Your role cannot view workspace memory."
        />
      </div>
    );
  }

  return (
    <div className="text-neutral-950">
      <section className="flex min-w-0 flex-1 flex-col px-0">
        <div className="mb-6 flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <h1 className="text-4xl font-black tracking-[-0.055em] text-neutral-950 lg:text-5xl">
              Memory Manager
            </h1>
            <p className="mt-2 text-sm font-medium text-neutral-500">
              Search, export, and delete workspace-safe memory records without
              leaking user context.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div className="relative w-full max-w-md">
              <span className="absolute left-4 top-1/2 -translate-y-1/2 text-neutral-400">
                ⌕
              </span>
              <input
                type="search"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter") applyFilters();
                }}
                placeholder="Search memory content, titles, tags..."
                className="h-12 w-full rounded-full border border-neutral-200 bg-white px-11 text-sm font-semibold outline-none transition placeholder:text-neutral-400 focus:border-[#ff5a3d] focus:ring-4 focus:ring-[#ff5a3d]/10"
              />
            </div>
            <div className="rounded-2xl bg-white px-4 py-3 shadow-sm">
              <p className="text-[11px] font-black uppercase tracking-[0.18em] text-neutral-400">
                Workspace
              </p>
              <p className="mt-1 text-sm font-black text-neutral-950">
                {session.workspace_name}
              </p>
            </div>
            <button
              type="button"
              onClick={handleLogout}
              className="rounded-2xl bg-white px-4 py-3 text-xs font-black text-neutral-500 shadow-sm transition hover:text-[#ff5a3d]"
              aria-label="Logout"
            >
              ↩ Logout
            </button>
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
          <LoadingState
            variant="light"
            title="Loading memory layer..."
            subtitle="Reading isolated workspace memory records."
          />
        ) : state === "error" ? (
          <ErrorState
            variant="light"
            title="Memory could not load"
            message={errorMessage}
            onRetry={() => {
              if (session) void loadMemory(session, search, typeFilter);
            }}
          />
        ) : (
          <div className="space-y-5">
            <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              <StatCard
                title="Total Memory"
                value={formatNumber(total)}
                subtitle="Workspace-scoped"
                icon="◌"
                highlight
              />
              <StatCard
                title="Public / Internal"
                value={formatNumber(
                  sensitivityBreakdown.public + sensitivityBreakdown.internal,
                )}
                subtitle="Standard visibility"
                icon="✓"
              />
              <StatCard
                title="Confidential"
                value={formatNumber(sensitivityBreakdown.confidential)}
                subtitle="Security routed"
                icon="▣"
              />
              <StatCard
                title="Restricted"
                value={formatNumber(sensitivityBreakdown.restricted)}
                subtitle="Owner/Admin only"
                icon="!"
              />
            </section>

            <section className="grid gap-5 xl:grid-cols-[0.75fr_1.25fr]">
              <div className="space-y-5">
                <div className="rounded-[1.6rem] bg-white p-5 shadow-sm">
                  <div className="mb-5 flex items-center justify-between">
                    <div>
                      <p className="text-base font-black text-neutral-950">
                        Plan Capacity
                      </p>
                      <p className="text-xs font-medium text-neutral-500">
                        Active records against your plan&apos;s record limit.
                      </p>
                    </div>
                    <span className="rounded-full bg-[#fff3ed] px-3 py-1 text-xs font-black text-[#ff5a3d]">
                      {session.plan}
                    </span>
                  </div>

                  <div className="h-3 overflow-hidden rounded-full bg-neutral-100">
                    <div
                      className="h-full rounded-full bg-[#ff5a3d]"
                      style={{ width: `${recordLimitPercent}%` }}
                    />
                  </div>

                  <div className="mt-3 flex items-center justify-between text-xs font-bold text-neutral-500">
                    <span>
                      {formatNumber(health?.active_memory_count)} records used
                    </span>
                    <span>
                      {formatNumber(health?.memory_limit)} record limit
                    </span>
                  </div>
                </div>

                <DistributionCard
                  title="Memory by Type"
                  subtitle="short / long / project / client"
                  entries={(Object.keys(typeBreakdown) as MemoryType[]).map(
                    (type) => ({
                      label: formatLabel(type),
                      count: typeBreakdown[type],
                    }),
                  )}
                />

                <div className="rounded-[1.6rem] bg-white p-5 shadow-sm">
                  <p className="text-base font-black text-neutral-950">
                    Filters
                  </p>

                  <div className="mt-5 space-y-4">
                    <div>
                      <label className="mb-2 block text-xs font-black uppercase tracking-[0.16em] text-neutral-400">
                        Type
                      </label>
                      <select
                        value={typeFilter}
                        onChange={(event) =>
                          setTypeFilter(
                            event.target.value as "all" | MemoryType,
                          )
                        }
                        className="h-12 w-full rounded-2xl border border-neutral-200 bg-neutral-50 px-4 text-sm font-bold outline-none focus:border-[#ff5a3d] focus:ring-4 focus:ring-[#ff5a3d]/10"
                      >
                        <option value="all">All Types</option>
                        <option value="short">Short</option>
                        <option value="long">Long</option>
                        <option value="project">Project</option>
                        <option value="client">Client</option>
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
                        <option value="public">Public</option>
                        <option value="internal">Internal</option>
                        <option value="confidential">Confidential</option>
                        <option value="restricted">Restricted</option>
                      </select>
                    </div>

                    <button
                      type="button"
                      onClick={applyFilters}
                      className="h-12 w-full rounded-2xl bg-neutral-950 text-sm font-black text-white transition hover:bg-[#ff5a3d]"
                    >
                      Apply Filters
                    </button>
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
                      {selectedMemoryIds.length} selected ·{" "}
                      {filteredRecords.length} visible
                    </p>
                  </div>

                  <div className="flex flex-wrap gap-3">
                    <button
                      type="button"
                      onClick={toggleSelectAllVisible}
                      disabled={
                        filteredRecords.length === 0 || busyAction !== null
                      }
                      className="rounded-full border border-neutral-200 bg-white px-4 py-2 text-xs font-black text-neutral-700 transition hover:border-[#ff5a3d] hover:text-[#ff5a3d] disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      Select Visible
                    </button>
                    <button
                      type="button"
                      onClick={() => void handleExport()}
                      disabled={!canExport || busyAction !== null}
                      className="rounded-full bg-neutral-950 px-4 py-2 text-xs font-black text-white transition hover:bg-[#ff5a3d] disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      {busyAction === "export"
                        ? "Exporting..."
                        : "Export (current filter)"}
                    </button>
                    <button
                      type="button"
                      onClick={() => void handleDeleteSelected()}
                      disabled={
                        !canDelete ||
                        selectedMemoryIds.length === 0 ||
                        busyAction !== null
                      }
                      className="rounded-full bg-red-600 px-4 py-2 text-xs font-black text-white transition hover:bg-red-700 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      {busyAction === "delete"
                        ? "Deleting..."
                        : "Delete Selected"}
                    </button>
                  </div>
                </div>

                {state === "empty" || filteredRecords.length === 0 ? (
                  <EmptyState
                    variant="light"
                    title="No memory records found"
                    message="Once agents complete useful work, Memory Agent will store isolated workspace context here."
                  />
                ) : (
                  <div className="space-y-4">
                    {filteredRecords.map((record) => {
                      const isSelected = selectedMemoryIds.includes(record.id);

                      return (
                        <article
                          key={record.id}
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
                                onClick={() => toggleSelected(record.id)}
                                className={[
                                  "mt-1 grid h-6 w-6 shrink-0 place-items-center rounded-lg border text-xs font-black transition",
                                  isSelected
                                    ? "border-[#ff5a3d] bg-[#ff5a3d] text-white"
                                    : "border-neutral-300 bg-white text-transparent",
                                ].join(" ")}
                                aria-label={`Select ${record.title || record.id}`}
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
                                {getTypeIcon(record.memory_type)}
                              </div>

                              <div className="min-w-0">
                                <h2 className="truncate text-base font-black text-neutral-950">
                                  {record.title || "Untitled memory"}
                                </h2>
                                <p className="truncate text-xs font-bold text-neutral-400">
                                  {record.id}
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

                          <p className="line-clamp-3 text-sm font-medium leading-6 text-neutral-500">
                            {record.content}
                          </p>

                          <div className="mt-4 flex flex-wrap gap-2">
                            <span className="rounded-full bg-white px-3 py-1 text-[11px] font-black text-neutral-600">
                              {formatLabel(record.source)}
                            </span>
                            <span className="rounded-full bg-white px-3 py-1 text-[11px] font-black capitalize text-neutral-600">
                              {record.memory_type}
                            </span>
                            {record.tags.map((tag) => (
                              <span
                                key={`${record.id}-${tag}`}
                                className="rounded-full bg-white px-3 py-1 text-[11px] font-black text-neutral-500"
                              >
                                #{tag}
                              </span>
                            ))}
                          </div>

                          <div className="mt-4 grid gap-3 rounded-2xl bg-white p-3 text-xs font-medium text-neutral-500 sm:grid-cols-2">
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
  );
}
