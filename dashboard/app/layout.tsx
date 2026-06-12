import type { Metadata } from "next";
import { Suspense } from "react";
import { GeistSans } from "geist/font/sans";
import { GeistMono } from "geist/font/mono";
import "./globals.css";
import { AppShell } from "@/components/shell/app-shell";
import {
  ShellPalette,
  ShellSidebar,
  ShellSidebarFallback,
  ShellTour,
} from "@/components/shell/shell-slots";
import { cn } from "@/lib/utils";

const DESCRIPTION =
  "Reachability-first vulnerability triage for Python — see which findings are actually reachable from your code, with the evidence.";

export const metadata: Metadata = {
  title: {
    default: "VulnAdvisor — reachability-first triage",
    template: "%s · VulnAdvisor",
  },
  description: DESCRIPTION,
  applicationName: "VulnAdvisor",
  openGraph: {
    siteName: "VulnAdvisor",
    title: "VulnAdvisor — reachability-first triage",
    description: DESCRIPTION,
    type: "website",
  },
};

// Deliberately synchronous: the shell's data-dependent parts stream in through
// Suspense slots, so a page's notFound()/error status is never pre-empted by an
// early flush waiting on shell data.
export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={cn("dark h-full antialiased", GeistSans.variable, GeistMono.variable)}
    >
      <body className="min-h-full">
        <AppShell
          sidebar={
            <Suspense fallback={<ShellSidebarFallback />}>
              <ShellSidebar />
            </Suspense>
          }
          palette={
            <Suspense fallback={null}>
              <ShellPalette />
            </Suspense>
          }
          tour={
            <Suspense fallback={null}>
              <ShellTour />
            </Suspense>
          }
        >
          {children}
        </AppShell>
      </body>
    </html>
  );
}
