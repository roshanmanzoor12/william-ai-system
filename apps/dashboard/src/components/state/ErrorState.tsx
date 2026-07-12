/**
 * apps/dashboard/src/components/state/ErrorState.tsx
 *
 * Shared error panel with a retry button, matching the two visual languages
 * already in use (see LoadingState.tsx for the same variant split). The
 * dark variant mirrors the inline "Safe Error" banner every dark-theme page
 * already had, but adds the retry action those banners were missing.
 */

type ErrorStateProps = {
  variant: "dark" | "light";
  title?: string;
  message: string;
  onRetry?: () => void;
};

export function ErrorState({
  variant,
  title,
  message,
  onRetry,
}: ErrorStateProps) {
  if (variant === "dark") {
    return (
      <div className="rounded-2xl border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-100">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="font-semibold">{title || "Safe Error"}</div>
            <p className="mt-1 text-red-100/90">{message}</p>
          </div>
          {onRetry ? (
            <button
              type="button"
              onClick={onRetry}
              className="shrink-0 rounded-xl border border-red-400/40 bg-red-500/20 px-4 py-2 text-xs font-black text-red-50 transition hover:bg-red-500/30"
            >
              Retry
            </button>
          ) : null}
        </div>
      </div>
    );
  }

  return (
    <div className="grid min-h-[420px] place-items-center rounded-[2rem] border border-red-100 bg-red-50 p-8 text-center">
      <div>
        <div className="mx-auto grid h-14 w-14 place-items-center rounded-2xl bg-white text-2xl shadow-sm">
          !
        </div>
        <h2 className="mt-5 text-2xl font-black tracking-[-0.04em] text-red-900">
          {title || "Could not load"}
        </h2>
        <p className="mt-2 max-w-md text-sm font-medium text-red-700">
          {message}
        </p>
        {onRetry ? (
          <button
            type="button"
            onClick={onRetry}
            className="mt-6 rounded-2xl bg-red-600 px-5 py-3 text-sm font-black text-white transition hover:bg-red-700"
          >
            Retry
          </button>
        ) : null}
      </div>
    </div>
  );
}
