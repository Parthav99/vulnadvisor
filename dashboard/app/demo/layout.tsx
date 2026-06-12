// File: dashboard/app/demo/layout.tsx
// The /demo segment (Task 14.3): public, read-only, clearly watermarked. Every page under
// it renders from lib/demo-data only — no auth, no API calls, no mutation surface. The
// watermark banner wraps all demo pages so sample data can never pass as a real org.
import Link from "next/link";
import { Eye } from "lucide-react";
import { Button } from "@/components/ui/button";
import { DemoTourButton } from "./demo-tour-button";

export const metadata = { title: "Demo org" };

export default function DemoLayout({ children }: { children: React.ReactNode }) {
  return (
    <div>
      <div
        role="note"
        aria-label="Demo mode"
        className="mb-5 flex flex-wrap items-center gap-3 rounded-xl border border-dashed border-warn/60 bg-card px-4 py-3"
      >
        <Eye aria-hidden className="size-4 shrink-0 text-warn" />
        <p className="min-w-0 flex-1 text-sm">
          <span className="font-semibold text-warn">Demo organization</span>
          <span className="text-muted-foreground">
            {" "}
            — sample data, read-only. This is the real product UI on a seeded org.
          </span>
        </p>
        <div className="flex items-center gap-2">
          <DemoTourButton />
          <Button asChild variant="outline" size="sm">
            <Link href="/">Sign in for your repos</Link>
          </Button>
        </div>
      </div>
      {children}
    </div>
  );
}
