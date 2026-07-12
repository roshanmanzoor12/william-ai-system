"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const TABS = [
  { label: "Overview", href: "/admin" },
  { label: "Users", href: "/admin/users" },
  { label: "Invites", href: "/admin/invites" },
  { label: "Workspaces", href: "/admin/workspaces" },
  { label: "Plans", href: "/admin/plans" },
  { label: "Agent Access", href: "/admin/agent-access" },
  { label: "Audit", href: "/admin/audit" },
];

export function AdminNav() {
  const pathname = usePathname();

  return (
    <div className="mb-6 flex flex-wrap gap-2">
      {TABS.map((tab) => {
        const active = pathname === tab.href;
        return (
          <Link
            key={tab.href}
            href={tab.href}
            className={[
              "rounded-full px-4 py-2 text-xs font-black transition",
              active
                ? "bg-neutral-950 text-white"
                : "bg-white text-neutral-600 shadow-sm hover:text-[#ff5a3d]",
            ].join(" ")}
          >
            {tab.label}
          </Link>
        );
      })}
    </div>
  );
}
