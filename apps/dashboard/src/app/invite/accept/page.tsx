"use client";

/**
 * apps/dashboard/src/app/invite/accept/page.tsx
 *
 * Standalone (not inside the (dashboard) shell) accept-invite landing
 * page -- this is the exact path apps/api/routes/admin.py::create_invite
 * builds invite links to: `${WILLIAM_DASHBOARD_URL}/invite/accept?token=...`.
 *
 * POST /api/v1/admin/invites/{token}/accept requires a real, already-
 * authenticated session whose JWT email matches the invited email -- it is
 * intentionally NOT gated on platform-admin (anyone can accept their own
 * invite). If the visitor isn't logged in yet, this page tells them to
 * register/log in with the invited email first, then return to this same
 * URL.
 */

import { useEffect, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { CheckCircle2, XCircle, LogIn } from "lucide-react";
import { readSession } from "@/lib/auth";
import { adminApi } from "@/lib/api-client";

type PageState = "checking" | "needs_login" | "accepting" | "accepted" | "error";

export default function InviteAcceptPage() {
  const searchParams = useSearchParams();
  const token = searchParams.get("token") || "";
  const [state, setState] = useState<PageState>("checking");
  const [message, setMessage] = useState("");

  useEffect(() => {
    if (!token) {
      setState("error");
      setMessage("This invite link is missing its token.");
      return;
    }

    const session = readSession();
    if (!session) {
      setState("needs_login");
      return;
    }

    void (async () => {
      setState("accepting");
      const response = await adminApi.acceptInvite(token);
      if (response.success === false) {
        setState("error");
        setMessage(response.error.message || "This invite could not be accepted.");
        return;
      }
      setState("accepted");
    })();
  }, [token]);

  return (
    <div className="grid min-h-screen place-items-center bg-neutral-50 px-4 text-neutral-950">
      <div className="w-full max-w-md rounded-[1.8rem] bg-white p-8 text-center shadow-xl">
        {state === "checking" || state === "accepting" ? (
          <>
            <div className="mx-auto mb-4 h-10 w-10 animate-pulse rounded-full bg-orange-100" />
            <p className="text-base font-black">Checking your invite...</p>
          </>
        ) : state === "needs_login" ? (
          <>
            <LogIn className="mx-auto mb-4 h-9 w-9 text-orange-500" />
            <p className="text-lg font-black">Log in to accept this invite</p>
            <p className="mt-2 text-sm font-medium text-neutral-500">
              Log in (or register) using the exact email address this invite was sent to, then come back to this same link.
            </p>
            <Link
              href={`/login?redirect=${encodeURIComponent(`/invite/accept?token=${token}`)}`}
              className="mt-6 inline-flex items-center justify-center rounded-2xl bg-[#ff5a3d] px-5 py-3 text-sm font-black text-white"
            >
              Go to login
            </Link>
          </>
        ) : state === "accepted" ? (
          <>
            <CheckCircle2 className="mx-auto mb-4 h-9 w-9 text-emerald-500" />
            <p className="text-lg font-black">Invite accepted</p>
            <p className="mt-2 text-sm font-medium text-neutral-500">You now have access to this workspace.</p>
            <Link href="/dashboard" className="mt-6 inline-flex items-center justify-center rounded-2xl bg-neutral-950 px-5 py-3 text-sm font-black text-white">
              Go to dashboard
            </Link>
          </>
        ) : (
          <>
            <XCircle className="mx-auto mb-4 h-9 w-9 text-red-500" />
            <p className="text-lg font-black">Invite could not be accepted</p>
            <p className="mt-2 text-sm font-medium text-red-600">{message}</p>
          </>
        )}
      </div>
    </div>
  );
}
