/**
 * apps/dashboard/src/components/state/EmptyState.tsx
 *
 * Shared "no records yet" panel, matching the two visual languages already
 * in use (see LoadingState.tsx for the same variant split).
 */

type EmptyStateProps = {
  variant: "dark" | "light";
  icon?: string;
  title: string;
  message: string;
};

export function EmptyState({
  variant,
  icon = "∅",
  title,
  message,
}: EmptyStateProps) {
  if (variant === "dark") {
    return (
      <div className="rounded-3xl border border-white/10 bg-slate-950/40 p-6 text-center">
        <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-2xl border border-cyan-400/30 bg-cyan-400/10 text-lg">
          {icon}
        </div>
        <h3 className="font-bold text-white">{title}</h3>
        <p className="mt-2 text-xs leading-5 text-slate-400">{message}</p>
      </div>
    );
  }

  return (
    <div className="grid min-h-[320px] place-items-center rounded-[1.6rem] border border-dashed border-neutral-200 bg-white p-8 text-center">
      <div>
        <div className="mx-auto grid h-14 w-14 place-items-center rounded-2xl bg-neutral-100 text-xl">
          {icon}
        </div>
        <h3 className="mt-4 text-xl font-black tracking-[-0.03em] text-neutral-950">
          {title}
        </h3>
        <p className="mt-2 max-w-md text-sm font-medium text-neutral-500">
          {message}
        </p>
      </div>
    </div>
  );
}
