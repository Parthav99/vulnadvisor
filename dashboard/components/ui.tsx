import type { ReactNode } from "react";

export function Card({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={`card ${className ?? ""}`}>{children}</div>;
}

export function Badge({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={`pill ${className ?? ""}`}>{children}</span>;
}

export function PageHeader({ title, subtitle }: { title: ReactNode; subtitle?: ReactNode }) {
  return (
    <header className="mb-5">
      <h1 className="text-xl font-semibold">{title}</h1>
      {subtitle ? <p className="muted mt-1 text-sm">{subtitle}</p> : null}
    </header>
  );
}

export function Stat({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="card">
      <div className="muted text-xs uppercase tracking-wide">{label}</div>
      <div className="mt-1 text-2xl font-semibold">{value}</div>
    </div>
  );
}

export function EmptyState({ children }: { children: ReactNode }) {
  return <div className="card muted text-center text-sm">{children}</div>;
}

/** A pulsing placeholder block; compose these in loading.tsx skeletons (never spinners). */
export function Skeleton({ className }: { className?: string }) {
  return <div aria-hidden className={`animate-pulse rounded-md bg-[#21262d] ${className ?? ""}`} />;
}

/** Branded full-page notice used by not-found / error screens. */
export function FullPageNotice({
  title,
  children,
  action,
}: {
  title: string;
  children: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="mx-auto max-w-md py-16 text-center">
      <p aria-hidden className="mb-3 text-3xl text-[#3fb950]">
        ◆
      </p>
      <h1 className="text-xl font-semibold">{title}</h1>
      <div className="muted mt-2 text-sm">{children}</div>
      {action ? <div className="mt-6">{action}</div> : null}
    </div>
  );
}
