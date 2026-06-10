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
