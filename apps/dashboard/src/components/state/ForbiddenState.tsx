/**
 * apps/dashboard/src/components/state/ForbiddenState.tsx
 *
 * Shared role/plan-denied panel. Every real authorization decision is
 * re-checked server-side regardless of what this shows -- this exists so a
 * denied page reads as an intentional, explained state instead of a blank
 * or broken-looking screen.
 */

type ForbiddenStateProps = {
  variant: "dark" | "light";
  title?: string;
  message: string;
};

export function ForbiddenState({
  variant,
  title = "Access Restricted",
  message,
}: ForbiddenStateProps) {
  if (variant === "dark") {
    return (
      <div className="rounded-3xl border border-orange-500/30 bg-orange-500/10 p-6 text-center">
        <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-2xl border border-orange-400/30 bg-orange-400/10 text-lg text-orange-100">
          🔒
        </div>
        <h3 className="font-bold text-orange-100">{title}</h3>
        <p className="mt-2 text-xs leading-5 text-orange-100/80">{message}</p>
      </div>
    );
  }

  return (
    <div className="grid min-h-[320px] place-items-center rounded-[1.6rem] border border-amber-100 bg-amber-50 p-8 text-center">
      <div>
        <div className="mx-auto grid h-14 w-14 place-items-center rounded-2xl bg-white text-2xl shadow-sm">
          🔒
        </div>
        <h3 className="mt-4 text-xl font-black tracking-[-0.03em] text-amber-900">
          {title}
        </h3>
        <p className="mt-2 max-w-md text-sm font-medium text-amber-700">
          {message}
        </p>
      </div>
    </div>
  );
}
