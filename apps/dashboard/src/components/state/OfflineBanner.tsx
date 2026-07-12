"use client";

/**
 * apps/dashboard/src/components/state/OfflineBanner.tsx
 *
 * Global, navigator.onLine-based banner mounted once in the dashboard
 * layout (apps/dashboard/src/app/(dashboard)/layout.tsx) rather than
 * per-page -- it needs to appear regardless of which page is active.
 */

import { useEffect, useState } from "react";

export function OfflineBanner() {
  const [isOffline, setIsOffline] = useState(false);

  useEffect(() => {
    setIsOffline(typeof navigator !== "undefined" && !navigator.onLine);

    function handleOffline() {
      setIsOffline(true);
    }

    function handleOnline() {
      setIsOffline(false);
    }

    window.addEventListener("offline", handleOffline);
    window.addEventListener("online", handleOnline);

    return () => {
      window.removeEventListener("offline", handleOffline);
      window.removeEventListener("online", handleOnline);
    };
  }, []);

  if (!isOffline) return null;

  return (
    <div
      role="status"
      className="sticky top-0 z-50 flex items-center justify-center gap-2 bg-amber-500 px-4 py-2 text-center text-xs font-black text-amber-950"
    >
      You are offline. Actions that need the William API will fail until your
      connection is restored.
    </div>
  );
}
