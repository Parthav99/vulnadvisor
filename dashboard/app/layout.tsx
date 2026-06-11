import type { Metadata } from "next";
import "./globals.css";
import { Nav } from "@/components/nav";

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

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="h-full antialiased">
      <body className="flex min-h-full flex-col">
        <Nav />
        <main className="mx-auto w-full max-w-5xl flex-1 px-4 py-6">{children}</main>
      </body>
    </html>
  );
}
