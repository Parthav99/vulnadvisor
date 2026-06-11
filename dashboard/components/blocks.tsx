import type { ReactNode } from "react";
import { Card, CardContent } from "@/components/ui/card";

// App-specific composition blocks built on the shadcn primitives. Generic
// primitives (Card, Badge, Button, Skeleton, …) live in components/ui/.

export function PageHeader({ title, subtitle }: { title: ReactNode; subtitle?: ReactNode }) {
  return (
    <header className="mb-5">
      <h1 className="font-heading text-xl font-semibold">{title}</h1>
      {subtitle ? <p className="mt-1 text-sm text-muted-foreground">{subtitle}</p> : null}
    </header>
  );
}

export function Stat({ label, value }: { label: string; value: ReactNode }) {
  return (
    <Card size="sm">
      <CardContent>
        <div className="text-xs tracking-wide text-muted-foreground uppercase">{label}</div>
        <div className="mt-1 text-2xl font-semibold">{value}</div>
      </CardContent>
    </Card>
  );
}

export function EmptyState({ children }: { children: ReactNode }) {
  return (
    <Card>
      <CardContent className="text-center text-sm text-muted-foreground">{children}</CardContent>
    </Card>
  );
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
      <p aria-hidden className="mb-3 text-3xl text-safe">
        ◆
      </p>
      <h1 className="font-heading text-xl font-semibold">{title}</h1>
      <div className="mt-2 text-sm text-muted-foreground">{children}</div>
      {action ? <div className="mt-6">{action}</div> : null}
    </div>
  );
}
