/**
 * apps/dashboard/src/components/state/LoadingState.tsx
 *
 * Shared loading panel. `variant` picks which of the two visual languages
 * already in use across the dashboard to render in: "dark" (the cyan/slate
 * theme used by billing/finance/creator/calls/analytics/tasks/workflows/
 * crm) or "light" (the neutral/#ff5a3d theme used by memory/agents/
 * agent-permissions/dashboard). This renders only the inner panel -- pages
 * keep their own outer full-page background wrapper for the initial boot
 * screen, so visual output is unchanged from what each page already had.
 */

type LoadingStateProps = {
  variant: "dark" | "light";
  title?: string;
  subtitle?: string;
};

export function LoadingState({
  variant,
  title = "Loading...",
  subtitle,
}: LoadingStateProps) {
  if (variant === "dark") {
    return (
      <div className="w-full max-w-xl rounded-3xl border border-white/10 bg-white/[0.04] p-8 shadow-2xl shadow-black/30">
        <div className="mb-6 h-12 w-12 animate-pulse rounded-2xl bg-cyan-400/30" />
        <div className="space-y-4">
          <div className="h-5 w-3/4 animate-pulse rounded bg-white/10" />
          <div className="h-4 w-full animate-pulse rounded bg-white/10" />
          <div className="h-4 w-5/6 animate-pulse rounded bg-white/10" />
          <div className="mt-8 h-24 w-full animate-pulse rounded-2xl bg-white/10" />
        </div>
        {title ? (
          <p className="mt-4 text-sm font-semibold text-white/70">{title}</p>
        ) : null}
        {subtitle ? (
          <p className="mt-1 text-xs text-white/40">{subtitle}</p>
        ) : null}
      </div>
    );
  }

  return (
    <div className="grid min-h-[420px] w-full place-items-center rounded-[2rem] bg-white shadow-sm">
      <div className="text-center">
        <div className="mx-auto h-12 w-12 animate-spin rounded-full border-4 border-neutral-200 border-t-[#ff5a3d]" />
        <p className="mt-4 text-sm font-black text-neutral-950">{title}</p>
        {subtitle ? (
          <p className="mt-1 text-xs font-medium text-neutral-500">
            {subtitle}
          </p>
        ) : null}
      </div>
    </div>
  );
}
