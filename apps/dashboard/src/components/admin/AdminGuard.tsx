"use client";

/**
 * apps/dashboard/src/components/admin/AdminGuard.tsx
 *
 * Shared client-side gate for every /admin/* page. This is a UI
 * convenience only -- it never substitutes for the real check: every
 * apps/api/routes/admin.py endpoint re-verifies AuthContext.is_platform_admin
 * server-side (require_platform_admin) regardless of what this component
 * decides to render. A non-admin who bypasses this guard still gets a real
 * 403 from every admin API call.
 */

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { ShieldAlert } from "lucide-react";
import { readSession, type SessionData } from "@/lib/auth";
import { LoadingState } from "@/components/state/LoadingState";

type GuardState = "checking" | "allowed" | "denied" | "signed_out";

export function AdminGuard({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const [state, setState] = useState<GuardState>("checking");
  const [session, setSession] = useState<SessionData | null>(null);

  useEffect(() => {
    const activeSession = readSession();

    if (!activeSession) {
      router.replace("/login");
      return;
    }

    setSession(activeSession);
    setState(activeSession.is_platform_admin ? "allowed" : "denied");
  }, [router]);

  if (state === "checking") {
    return (
      <div className="grid min-h-[420px] place-items-center text-neutral-950">
        <LoadingState variant="light" title="Checking admin access..." subtitle="Validating platform-admin status." />
      </div>
    );
  }

  if (state === "denied") {
    return (
      <div className="grid min-h-[420px] place-items-center text-neutral-950">
        <div className="max-w-md rounded-[1.6rem] border border-red-100 bg-red-50 p-6 text-center">
          <ShieldAlert className="mx-auto mb-3 h-8 w-8 text-red-500" />
          <p className="text-base font-black text-red-700">Platform admin access required</p>
          <p className="mt-2 text-sm font-medium text-red-600">
            {session?.email || "This account"} is not a platform admin. Contact an existing platform admin, or
            run <code className="rounded bg-red-100 px-1.5 py-0.5">scripts/grant_platform_admin.py</code> in local dev.
          </p>
        </div>
      </div>
    );
  }

  return <>{children}</>;
}
