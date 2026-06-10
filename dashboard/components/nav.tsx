import Link from "next/link";

export function Nav() {
  return (
    <header className="border-b border-[#30363d] bg-[#161b22]">
      <div className="mx-auto flex w-full max-w-5xl items-center justify-between px-4 py-3">
        <Link href="/" className="flex items-center gap-2 font-semibold">
          <span aria-hidden className="text-[#3fb950]">
            ◆
          </span>
          VulnAdvisor
        </Link>
        <span className="muted text-xs">reachability-first triage</span>
      </div>
    </header>
  );
}
