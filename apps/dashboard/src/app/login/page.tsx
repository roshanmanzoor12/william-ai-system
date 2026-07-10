"use client";

import React, { FormEvent, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";

type UserRole = "owner" | "admin" | "member" | "viewer";
type UserPlan = "free" | "starter" | "pro" | "enterprise";
type SubscriptionStatus = "active" | "trialing" | "past_due" | "canceled";

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

type LoginPayload = {
  email: string;
  password: string;
  workspaceSlug?: string;
  rememberMe: boolean;
  clientContext: {
    app: "william-dashboard";
    module: "auth.login";
    action: "auth.login";
    userAgent: string;
    requiresAudit: true;
    requiresSecurityRoute: false;
    memoryCompatible: true;
    verificationCompatible: true;
  };
};

type LoginData = {
  accessToken: string;
  refreshToken?: string;
  user: {
    user_id: string;
    email: string;
    name: string;
    role: UserRole;
  };
  workspace: {
    workspace_id: string;
    name: string;
    slug: string;
  };
  subscription: {
    plan: UserPlan;
    status: SubscriptionStatus;
  };
  permissions: string[];
  audit?: {
    event_id?: string;
    action: "auth.login";
    routed_to_security_agent: boolean;
    memory_ready: boolean;
    verification_ready: boolean;
  };
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

type FormErrors = {
  email?: string;
  password?: string;
  workspaceSlug?: string;
  general?: string;
};

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || "";

const ALLOWED_ROLES: Record<UserRole, boolean> = {
  owner: true,
  admin: true,
  member: true,
  viewer: true,
};

const ALLOWED_PLANS: Record<UserPlan, boolean> = {
  free: true,
  starter: true,
  pro: true,
  enterprise: true,
};

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

function isValidEmail(value: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim());
}

function normalizeWorkspaceSlug(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
}

function validateLoginForm(
  email: string,
  password: string,
  workspaceSlug: string,
): FormErrors {
  const errors: FormErrors = {};

  if (!email.trim()) {
    errors.email = "Email address is required.";
  } else if (!isValidEmail(email)) {
    errors.email = "Enter a valid email address.";
  }

  if (!password) {
    errors.password = "Password is required.";
  } else if (password.length < 8) {
    errors.password = "Password must be at least 8 characters.";
  }

  if (workspaceSlug.trim()) {
    const normalized = normalizeWorkspaceSlug(workspaceSlug);
    if (normalized.length < 2) {
      errors.workspaceSlug = "Workspace slug must be at least 2 characters.";
    }
  }

  return errors;
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
      "The server returned an invalid response shape.",
      response.status,
    );
  } catch {
    return createSafeError<T>(
      "INVALID_JSON_RESPONSE",
      "The server response could not be parsed.",
      response.status,
    );
  }
}

async function loginRequest(payload: LoginPayload): Promise<ApiResponse<LoginData>> {
  if (!API_BASE_URL) {
    return createSafeError<LoginData>(
      "API_BASE_URL_MISSING",
      "API is not connected. Set NEXT_PUBLIC_API_BASE_URL in your dashboard environment.",
      503,
      {
        required_env: "NEXT_PUBLIC_API_BASE_URL",
      },
    );
  }

  try {
    const baseUrl = API_BASE_URL.replace(/\/$/, "");
    const response = await fetch(`${baseUrl}/auth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Client-App": "william-dashboard",
        "X-Action": "auth.login",
      },
      credentials: "include",
      body: JSON.stringify(payload),
    });

    const body = await parseApiJson<LoginData>(response);

    if (!response.ok) {
      if (!body.success && body.error) {
        return body;
      }

      return createSafeError<LoginData>(
        "LOGIN_HTTP_ERROR",
        "Login failed. Please check your credentials and try again.",
        response.status,
      );
    }

    return body;
  } catch {
    return createSafeError<LoginData>(
      "NETWORK_ERROR",
      "Could not connect to the William API. Make sure your backend server is running.",
      503,
    );
  }
}

function validateLoginData(data: LoginData): ApiResponse<LoginData> {
  if (!data.accessToken) {
    return createSafeError<LoginData>(
      "ACCESS_TOKEN_MISSING",
      "Login succeeded, but no access token was returned.",
      403,
    );
  }

  if (!data.user?.user_id || !data.workspace?.workspace_id) {
    return createSafeError<LoginData>(
      "ISOLATION_CONTEXT_MISSING",
      "Login succeeded, but user/workspace isolation context is missing.",
      403,
    );
  }

  if (!ALLOWED_ROLES[data.user.role]) {
    return createSafeError<LoginData>(
      "ROLE_ACCESS_DENIED",
      "Your role does not have dashboard access.",
      403,
      {
        role: data.user.role,
      },
    );
  }

  if (!ALLOWED_PLANS[data.subscription.plan]) {
    return createSafeError<LoginData>(
      "PLAN_ACCESS_DENIED",
      "Your plan does not have dashboard access.",
      402,
      {
        plan: data.subscription.plan,
      },
    );
  }

  if (!["active", "trialing"].includes(data.subscription.status)) {
    return createSafeError<LoginData>(
      "SUBSCRIPTION_INACTIVE",
      "Your workspace subscription is not active.",
      402,
      {
        status: data.subscription.status,
      },
    );
  }

  if (
    !data.permissions.includes("dashboard:read") &&
    !data.permissions.includes("workspace:read")
  ) {
    return createSafeError<LoginData>(
      "PERMISSION_DENIED",
      "Your account does not have permission to open this workspace dashboard.",
      403,
    );
  }

  return {
    success: true,
    data,
    error: null,
  };
}

function saveSession(data: LoginData, rememberMe: boolean): void {
  const session: SessionData = {
    accessToken: data.accessToken,
    refreshToken: data.refreshToken,
    user_id: data.user.user_id,
    workspace_id: data.workspace.workspace_id,
    email: data.user.email,
    name: data.user.name,
    role: data.user.role,
    plan: data.subscription.plan,
    subscription_status: data.subscription.status,
    permissions: data.permissions,
    workspace_name: data.workspace.name,
    workspace_slug: data.workspace.slug,
    saved_at: new Date().toISOString(),
  };

  const selectedStorage = rememberMe ? window.localStorage : window.sessionStorage;
  const otherStorage = rememberMe ? window.sessionStorage : window.localStorage;

  otherStorage.removeItem("william.session");
  otherStorage.removeItem("william.access_token");
  otherStorage.removeItem("william.refresh_token");

  selectedStorage.setItem("william.session", JSON.stringify(session));
  selectedStorage.setItem("william.access_token", data.accessToken);

  if (data.refreshToken) {
    selectedStorage.setItem("william.refresh_token", data.refreshToken);
  }
}

function readExistingSession(): SessionData | null {
  if (typeof window === "undefined") return null;

  const raw =
    window.localStorage.getItem("william.session") ||
    window.sessionStorage.getItem("william.session");

  if (!raw) return null;

  try {
    const session = JSON.parse(raw) as SessionData;

    if (
      session?.accessToken &&
      session?.user_id &&
      session?.workspace_id &&
      session?.subscription_status &&
      ["active", "trialing"].includes(session.subscription_status)
    ) {
      return session;
    }

    return null;
  } catch {
    return null;
  }
}

function clearExistingSession(): void {
  if (typeof window === "undefined") return;

  window.localStorage.removeItem("william.session");
  window.localStorage.removeItem("william.access_token");
  window.localStorage.removeItem("william.refresh_token");
  window.sessionStorage.removeItem("william.session");
  window.sessionStorage.removeItem("william.access_token");
  window.sessionStorage.removeItem("william.refresh_token");
}

function FieldError({ message }: { message?: string }) {
  if (!message) return null;

  return (
    <p className="mt-2 text-xs font-semibold text-red-600" role="alert">
      {message}
    </p>
  );
}

function StatusPill({
  label,
  tone,
}: {
  label: string;
  tone: "dark" | "green" | "orange" | "light";
}) {
  const styles = {
    dark: "bg-black text-white",
    green: "bg-emerald-50 text-emerald-700 border border-emerald-100",
    orange: "bg-[#fff3ed] text-[#ff5a3d] border border-[#ffd9cc]",
    light: "bg-white text-neutral-700 border border-neutral-200",
  };

  return (
    <span
      className={[
        "inline-flex items-center rounded-full px-4 py-2 text-xs font-bold",
        styles[tone],
      ].join(" ")}
    >
      {label}
    </span>
  );
}

export default function Page() {
  const router = useRouter();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [workspaceSlug, setWorkspaceSlug] = useState("");
  const [rememberMe, setRememberMe] = useState(true);
  const [showPassword, setShowPassword] = useState(false);
  const [errors, setErrors] = useState<FormErrors>({});
  const [isLoading, setIsLoading] = useState(false);
  const [isCheckingSession, setIsCheckingSession] = useState(true);

  const normalizedWorkspaceSlug = useMemo(
    () => normalizeWorkspaceSlug(workspaceSlug),
    [workspaceSlug],
  );

  useEffect(() => {
    const session = readExistingSession();

    if (session) {
      router.replace("/dashboard");
      return;
    }

    setIsCheckingSession(false);
  }, [router]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    const validationErrors = validateLoginForm(email, password, workspaceSlug);
    setErrors(validationErrors);

    if (Object.keys(validationErrors).length > 0) {
      return;
    }

    setIsLoading(true);

    const payload: LoginPayload = {
      email: email.trim().toLowerCase(),
      password,
      workspaceSlug: normalizedWorkspaceSlug || undefined,
      rememberMe,
      clientContext: {
        app: "william-dashboard",
        module: "auth.login",
        action: "auth.login",
        userAgent:
          typeof window !== "undefined" ? window.navigator.userAgent : "server",
        requiresAudit: true,
        requiresSecurityRoute: false,
        memoryCompatible: true,
        verificationCompatible: true,
      },
    };

    const response = await loginRequest(payload);

    if (!response.success || !response.data) {
      setErrors({
        general:
          response.error?.message ||
          "Login failed. Check your email, password, and workspace.",
      });
      setIsLoading(false);
      return;
    }

    const accessCheck = validateLoginData(response.data);

    if (!accessCheck.success || !accessCheck.data) {
      setErrors({
        general:
          accessCheck.error?.message ||
          "Your account cannot access this dashboard.",
      });
      clearExistingSession();
      setIsLoading(false);
      return;
    }

    saveSession(accessCheck.data, rememberMe);
    router.replace("/dashboard");
  }

  if (isCheckingSession) {
    return (
      <main className="grid min-h-screen place-items-center bg-[#e9e9e7] px-6 text-neutral-950">
        <div className="rounded-[2rem] bg-white px-8 py-7 text-center shadow-2xl shadow-black/10">
          <div className="mx-auto h-10 w-10 animate-spin rounded-full border-4 border-neutral-200 border-t-[#ff5a3d]" />
          <p className="mt-4 text-sm font-bold">Checking secure session...</p>
          <p className="mt-1 text-xs text-neutral-500">
            Verifying user and workspace isolation.
          </p>
        </div>
      </main>
    );
  }

  return (
    <main className="min-h-screen bg-[#e9e9e7] px-4 py-6 text-neutral-950 sm:px-6 lg:px-8">
      <section className="mx-auto flex min-h-[calc(100vh-3rem)] max-w-7xl items-center justify-center">
        <div className="grid w-full overflow-hidden rounded-[2.25rem] bg-[#f7f7f6] p-4 shadow-2xl shadow-black/10 lg:grid-cols-[0.95fr_1.05fr] lg:p-5">
          <div className="relative flex min-h-[720px] flex-col justify-between rounded-[1.8rem] bg-white p-7 shadow-sm sm:p-10">
            <div>
              <header className="mb-10 flex items-center justify-between gap-4">
                <div className="flex items-center gap-4">
                  <div className="relative grid h-14 w-14 place-items-center rounded-2xl bg-[#ff5a3d] text-xl font-black text-white shadow-xl shadow-[#ff5a3d]/25">
                    W
                    <span className="absolute -right-1 -top-1 h-4 w-4 rounded-full border-2 border-white bg-emerald-400" />
                  </div>
                  <div>
                    <p className="text-xl font-black tracking-[-0.04em] text-neutral-950">
                      William
                    </p>
                    <p className="text-sm font-medium text-neutral-500">
                      Jarvis Multi-Agent SaaS
                    </p>
                  </div>
                </div>

                <StatusPill label="Secure Login" tone="light" />
              </header>

              <div className="mb-8">
                <p className="text-sm font-black text-[#ff5a3d]">
                  Digital Promotix
                </p>
                <h1 className="mt-4 max-w-xl text-5xl font-black leading-[0.95] tracking-[-0.065em] text-neutral-950 sm:text-6xl">
                  Good morning, commander.
                </h1>
                <p className="mt-5 max-w-md text-base leading-7 text-neutral-500">
                  Sign in to control agents, tasks, memory, security approvals,
                  workspace analytics, and verification reports from one clean
                  command center.
                </p>
              </div>

              {errors.general ? (
                <div
                  className="mb-5 rounded-2xl border border-red-200 bg-red-50 px-4 py-3 text-sm font-semibold text-red-700"
                  role="alert"
                >
                  {errors.general}
                </div>
              ) : null}

              {!API_BASE_URL ? (
                <div className="mb-5 rounded-2xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm font-semibold text-amber-800">
                  Backend API is not connected. Add{" "}
                  <code className="rounded bg-white px-1.5 py-0.5 text-xs">
                    NEXT_PUBLIC_API_BASE_URL
                  </code>{" "}
                  in your dashboard environment.
                </div>
              ) : null}

              <form className="space-y-5" onSubmit={handleSubmit} noValidate>
                <div>
                  <label
                    htmlFor="email"
                    className="mb-2 block text-sm font-bold text-neutral-800"
                  >
                    Email Address
                  </label>
                  <input
                    id="email"
                    type="email"
                    autoComplete="email"
                    value={email}
                    disabled={isLoading}
                    onChange={(event) => {
                      setEmail(event.target.value);
                      setErrors((current) => ({
                        ...current,
                        email: undefined,
                        general: undefined,
                      }));
                    }}
                    placeholder="admin@digitalpromotix.com"
                    className="h-14 w-full rounded-2xl border border-neutral-200 bg-neutral-50 px-4 text-sm font-semibold text-neutral-950 outline-none transition placeholder:text-neutral-400 focus:border-[#ff5a3d] focus:bg-white focus:ring-4 focus:ring-[#ff5a3d]/10 disabled:cursor-not-allowed disabled:opacity-60"
                  />
                  <FieldError message={errors.email} />
                </div>

                <div>
                  <label
                    htmlFor="workspaceSlug"
                    className="mb-2 block text-sm font-bold text-neutral-800"
                  >
                    Workspace Slug{" "}
                    <span className="font-medium text-neutral-400">
                      optional
                    </span>
                  </label>
                  <input
                    id="workspaceSlug"
                    type="text"
                    autoComplete="organization"
                    value={workspaceSlug}
                    disabled={isLoading}
                    onChange={(event) => {
                      setWorkspaceSlug(event.target.value);
                      setErrors((current) => ({
                        ...current,
                        workspaceSlug: undefined,
                        general: undefined,
                      }));
                    }}
                    placeholder="digital-promotix"
                    className="h-14 w-full rounded-2xl border border-neutral-200 bg-neutral-50 px-4 text-sm font-semibold text-neutral-950 outline-none transition placeholder:text-neutral-400 focus:border-[#ff5a3d] focus:bg-white focus:ring-4 focus:ring-[#ff5a3d]/10 disabled:cursor-not-allowed disabled:opacity-60"
                  />
                  {normalizedWorkspaceSlug ? (
                    <p className="mt-2 text-xs font-medium text-neutral-500">
                      Workspace check:{" "}
                      <span className="font-bold text-neutral-800">
                        {normalizedWorkspaceSlug}
                      </span>
                    </p>
                  ) : null}
                  <FieldError message={errors.workspaceSlug} />
                </div>

                <div>
                  <label
                    htmlFor="password"
                    className="mb-2 block text-sm font-bold text-neutral-800"
                  >
                    Password
                  </label>
                  <div className="relative">
                    <input
                      id="password"
                      type={showPassword ? "text" : "password"}
                      autoComplete="current-password"
                      value={password}
                      disabled={isLoading}
                      onChange={(event) => {
                        setPassword(event.target.value);
                        setErrors((current) => ({
                          ...current,
                          password: undefined,
                          general: undefined,
                        }));
                      }}
                      placeholder="Minimum 8 characters"
                      className="h-14 w-full rounded-2xl border border-neutral-200 bg-neutral-50 px-4 pr-24 text-sm font-semibold text-neutral-950 outline-none transition placeholder:text-neutral-400 focus:border-[#ff5a3d] focus:bg-white focus:ring-4 focus:ring-[#ff5a3d]/10 disabled:cursor-not-allowed disabled:opacity-60"
                    />

                    <button
                      type="button"
                      disabled={isLoading}
                      onClick={() => setShowPassword((current) => !current)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 rounded-xl px-3 py-2 text-xs font-black text-neutral-500 transition hover:bg-white hover:text-neutral-950 disabled:cursor-not-allowed disabled:opacity-60"
                    >
                      {showPassword ? "Hide" : "Show"}
                    </button>
                  </div>
                  <FieldError message={errors.password} />
                </div>

                <div className="flex items-center justify-between gap-4">
                  <label className="flex cursor-pointer items-center gap-3 text-sm font-semibold text-neutral-600">
                    <input
                      type="checkbox"
                      checked={rememberMe}
                      disabled={isLoading}
                      onChange={(event) => setRememberMe(event.target.checked)}
                      className="h-4 w-4 rounded border-neutral-300 accent-[#ff5a3d]"
                    />
                    Keep me signed in
                  </label>

                  <a
                    href="/forgot-password"
                    className="text-sm font-black text-neutral-950 underline-offset-4 transition hover:text-[#ff5a3d] hover:underline"
                  >
                    Forgot password?
                  </a>
                </div>

                <button
                  type="submit"
                  disabled={isLoading}
                  className="group flex h-14 w-full items-center justify-center gap-3 rounded-2xl bg-neutral-950 px-5 text-sm font-black text-white shadow-xl shadow-black/15 transition hover:-translate-y-0.5 hover:bg-[#ff5a3d] hover:shadow-[#ff5a3d]/25 disabled:cursor-not-allowed disabled:translate-y-0 disabled:opacity-70"
                >
                  {isLoading ? (
                    <>
                      <span className="h-4 w-4 animate-spin rounded-full border-2 border-white/30 border-t-white" />
                      Verifying Workspace...
                    </>
                  ) : (
                    <>
                      Sign In To Dashboard
                      <span className="transition group-hover:translate-x-1">
                        →
                      </span>
                    </>
                  )}
                </button>
              </form>
            </div>

            <footer className="mt-10 grid grid-cols-1 gap-3 sm:grid-cols-3">
              <div className="rounded-2xl border border-neutral-100 bg-neutral-50 p-4">
                <p className="text-xs font-black text-neutral-950">Security</p>
                <p className="mt-1 text-[11px] font-medium text-neutral-500">
                  Audit-ready login
                </p>
              </div>
              <div className="rounded-2xl border border-neutral-100 bg-neutral-50 p-4">
                <p className="text-xs font-black text-neutral-950">Isolation</p>
                <p className="mt-1 text-[11px] font-medium text-neutral-500">
                  user_id + workspace_id
                </p>
              </div>
              <div className="rounded-2xl border border-neutral-100 bg-neutral-50 p-4">
                <p className="text-xs font-black text-neutral-950">Verify</p>
                <p className="mt-1 text-[11px] font-medium text-neutral-500">
                  Session payload safe
                </p>
              </div>
            </footer>
          </div>

          <div className="relative hidden min-h-[720px] overflow-hidden rounded-[1.8rem] border border-white bg-[#f4f4f3] p-7 lg:block">
            <div className="absolute -right-24 -top-24 h-80 w-80 rounded-full bg-[#ff5a3d]/20 blur-3xl" />
            <div className="absolute -bottom-24 -left-24 h-80 w-80 rounded-full bg-black/10 blur-3xl" />

            <div className="relative flex h-full flex-col">
              <header className="mb-8 flex items-center justify-between rounded-[1.5rem] bg-white/85 p-2 shadow-sm backdrop-blur">
                <nav className="flex items-center gap-2 text-sm font-bold text-neutral-500">
                  <span className="rounded-full bg-black px-5 py-3 text-white">
                    Overview
                  </span>
                  <span className="px-4 py-3">Activity</span>
                  <span className="px-4 py-3">Manage</span>
                  <span className="px-4 py-3">Agents</span>
                </nav>

                <div className="flex items-center gap-2">
                  <div className="grid h-10 w-10 place-items-center rounded-full bg-white shadow-sm">
                    ⌕
                  </div>
                  <div className="grid h-10 w-10 place-items-center rounded-full bg-white shadow-sm">
                    !
                  </div>
                </div>
              </header>

              <section className="mb-6">
                <p className="text-sm font-black text-[#ff5a3d]">
                  William / Jarvis SaaS Console
                </p>
                <h2 className="mt-3 max-w-2xl text-5xl font-black leading-[0.95] tracking-[-0.06em] text-neutral-950">
                  Secure multi-agent control.
                </h2>
                <p className="mt-4 max-w-xl text-sm leading-6 text-neutral-500">
                  Route requests through planner, Security Agent, Memory Agent,
                  and Verification Agent without mixing users, workspaces, logs,
                  tasks, files, memory, or analytics.
                </p>
              </section>

              <section className="grid grid-cols-3 gap-4">
                <div className="rounded-[1.5rem] bg-white p-5 shadow-sm">
                  <div className="mb-6 flex items-center justify-between">
                    <p className="text-sm font-bold text-neutral-500">Agents</p>
                    <span className="rounded-full bg-neutral-100 px-3 py-1 text-[11px] font-black text-neutral-600">
                      Live
                    </span>
                  </div>
                  <p className="text-4xl font-black tracking-[-0.05em] text-neutral-950">
                    14
                  </p>
                  <p className="mt-2 text-xs font-bold text-emerald-600">
                    Master orchestration ready
                  </p>
                </div>

                <div className="rounded-[1.5rem] bg-[#ff5a3d] p-5 text-white shadow-xl shadow-[#ff5a3d]/25">
                  <div className="mb-6 flex items-center justify-between">
                    <p className="text-sm font-bold text-white/80">Security</p>
                    <span className="rounded-full bg-white/20 px-3 py-1 text-[11px] font-black">
                      Guarded
                    </span>
                  </div>
                  <p className="text-4xl font-black tracking-[-0.05em]">100%</p>
                  <p className="mt-2 text-xs font-bold text-white/80">
                    Sensitive actions routed
                  </p>
                </div>

                <div className="rounded-[1.5rem] bg-white p-5 shadow-sm">
                  <div className="mb-6 flex items-center justify-between">
                    <p className="text-sm font-bold text-neutral-500">Memory</p>
                    <span className="rounded-full bg-neutral-100 px-3 py-1 text-[11px] font-black text-neutral-600">
                      Safe
                    </span>
                  </div>
                  <p className="text-4xl font-black tracking-[-0.05em] text-neutral-950">
                    ISO
                  </p>
                  <p className="mt-2 text-xs font-bold text-emerald-600">
                    Workspace isolated
                  </p>
                </div>
              </section>

              <section className="mt-4 grid flex-1 grid-cols-5 gap-4">
                <div className="col-span-3 rounded-[1.5rem] bg-white p-5 shadow-sm">
                  <div className="mb-5 flex items-center justify-between">
                    <div>
                      <p className="text-base font-black text-neutral-950">
                        Master Flow
                      </p>
                      <p className="text-xs font-medium text-neutral-500">
                        Request → Planner → Security → Agent → Verification
                      </p>
                    </div>
                    <StatusPill label="Ready" tone="green" />
                  </div>

                  <div className="space-y-3">
                    {[
                      ["01", "Request Intake", "user_id + workspace_id required"],
                      ["02", "Security Agent", "Sensitive action approval"],
                      ["03", "Verification Agent", "Completed payload prepared"],
                    ].map(([number, title, subtitle]) => (
                      <div
                        key={number}
                        className="flex items-center justify-between rounded-2xl border border-neutral-100 bg-neutral-50 px-4 py-3"
                      >
                        <div className="flex items-center gap-3">
                          <div className="grid h-9 w-9 place-items-center rounded-xl bg-white text-xs font-black text-[#ff5a3d]">
                            {number}
                          </div>
                          <div>
                            <p className="text-sm font-black text-neutral-950">
                              {title}
                            </p>
                            <p className="text-xs font-medium text-neutral-500">
                              {subtitle}
                            </p>
                          </div>
                        </div>
                        <span className="h-2.5 w-2.5 rounded-full bg-emerald-500" />
                      </div>
                    ))}
                  </div>
                </div>

                <div className="col-span-2 rounded-[1.5rem] bg-white p-5 shadow-sm">
                  <p className="text-base font-black text-neutral-950">
                    Agent Health
                  </p>
                  <p className="mt-1 text-xs font-medium text-neutral-500">
                    Registry compatible
                  </p>

                  <div className="mt-6 flex h-44 items-end gap-3">
                    {[68, 88, 54, 96, 78, 84].map((height, index) => (
                      <div
                        key={index}
                        className="flex flex-1 flex-col items-center gap-2"
                      >
                        <div
                          className="w-full rounded-t-xl bg-[#ff5a3d]"
                          style={{ height: `${height}%` }}
                        />
                        <span className="text-[10px] font-bold text-neutral-400">
                          A{index + 1}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </section>

              <section className="mt-4 rounded-[1.5rem] bg-white p-5 shadow-sm">
                <div className="mb-4 flex items-center justify-between">
                  <p className="text-base font-black text-neutral-950">
                    Protected System Rules
                  </p>
                  <StatusPill label="No Demo Data" tone="orange" />
                </div>

                <div className="grid grid-cols-[1.1fr_1.4fr_.8fr] gap-2 rounded-2xl border border-neutral-100 bg-neutral-50 px-4 py-3 text-xs font-black text-neutral-500">
                  <span>Layer</span>
                  <span>Rule</span>
                  <span className="text-right">Status</span>
                </div>

                {[
                  ["Workspace", "Never mix users or workspace data", "Active"],
                  ["Security", "Sensitive actions route for approval", "Active"],
                  ["Verification", "Completed actions prepare evidence", "Ready"],
                ].map(([layer, rule, status]) => (
                  <div
                    key={layer}
                    className="mt-2 grid grid-cols-[1.1fr_1.4fr_.8fr] rounded-2xl border border-neutral-100 px-4 py-3 text-sm"
                  >
                    <span className="font-black text-neutral-950">{layer}</span>
                    <span className="font-medium text-neutral-500">{rule}</span>
                    <span className="text-right font-black text-emerald-600">
                      {status}
                    </span>
                  </div>
                ))}
              </section>
            </div>
          </div>
        </div>
      </section>
    </main>
  );
}