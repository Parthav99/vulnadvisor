// File: dashboard/components/copilot/byom-config.tsx
// BYOM key-configuration modal (Task 15.1c): paste a personal model key once, stored ONLY in
// this browser's localStorage, sent per copilot request via the 15.1b headers. Never sent to
// or stored on our servers (the test-connection request transits it over TLS, nothing more).
"use client";

import { useEffect, useId, useState } from "react";

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  byomHeaders,
  clearByomConfig,
  loadByomConfig,
  maskKey,
  saveByomConfig,
  type ByomConfig,
} from "@/lib/byom";
import {
  COPILOT_PROVIDERS,
  type CopilotProvider,
  defaultModelFor,
  isValidModelId,
  isValidUserKey,
} from "@/lib/copilot";

const PROVIDER_LABELS: Record<CopilotProvider, string> = {
  openrouter: "OpenRouter",
  openai: "OpenAI",
  anthropic: "Anthropic",
};

type TestState =
  | { kind: "idle" }
  | { kind: "running" }
  | { kind: "ok" }
  | { kind: "failed"; message: string };

/** One trivial request through /api/copilot proves key + provider + org access end to end. */
async function testConnection(orgSlug: string, config: ByomConfig): Promise<TestState> {
  try {
    const res = await fetch("/api/copilot", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...byomHeaders(config) },
      body: JSON.stringify({
        orgSlug,
        messages: [
          {
            id: "byom-test",
            role: "user",
            parts: [{ type: "text", text: "Reply with the single word: ok" }],
          },
        ],
      }),
    });
    if (!res.ok) {
      const body = (await res.json().catch(() => null)) as { error?: string } | null;
      return { kind: "failed", message: body?.error ?? `request failed (${res.status})` };
    }
    // The stream reports provider failures (bad key, no quota) as error events.
    const text = await res.text();
    if (text.includes('"type":"error"')) {
      return { kind: "failed", message: "the provider rejected the key (or it has no quota)" };
    }
    return { kind: "ok" };
  } catch {
    return { kind: "failed", message: "network error" };
  }
}

export function ByomConfigDialog({ orgSlug }: { orgSlug: string }) {
  const fieldId = useId();
  const [open, setOpen] = useState(false);
  const [stored, setStored] = useState<ByomConfig | null>(null);
  const [provider, setProvider] = useState<CopilotProvider>("openrouter");
  const [apiKey, setApiKey] = useState("");
  const [model, setModel] = useState("");
  const [test, setTest] = useState<TestState>({ kind: "idle" });

  // localStorage exists only client-side; hydrate after mount.
  useEffect(() => {
    const config = loadByomConfig(window.localStorage);
    setStored(config);
    if (config) {
      setProvider(config.provider);
      setApiKey(config.apiKey);
      setModel(config.model ?? "");
    }
  }, [open]);

  const keyOk = isValidUserKey(apiKey.trim());
  const modelOk = model.trim() === "" || isValidModelId(model.trim());

  function currentConfig(): ByomConfig {
    const trimmedModel = model.trim();
    return {
      provider,
      apiKey: apiKey.trim(),
      ...(trimmedModel !== "" ? { model: trimmedModel } : {}),
    };
  }

  function save() {
    saveByomConfig(window.localStorage, currentConfig());
    setStored(currentConfig());
    setTest({ kind: "idle" });
    setOpen(false);
  }

  function clear() {
    clearByomConfig(window.localStorage);
    setStored(null);
    setApiKey("");
    setModel("");
    setTest({ kind: "idle" });
  }

  async function runTest() {
    setTest({ kind: "running" });
    setTest(await testConnection(orgSlug, currentConfig()));
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm" data-tour="byom-config">
          {stored ? `Personal key ${maskKey(stored.apiKey)}` : "Use your own AI key"}
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Bring your own model</DialogTitle>
          <DialogDescription>
            Your key is stored only in this browser and sent directly with each copilot
            request — never saved on VulnAdvisor servers. A free OpenRouter key works.
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-4">
          <fieldset>
            <legend className="mb-1.5 text-sm font-medium">Provider</legend>
            <div className="flex gap-2" role="radiogroup" aria-label="AI provider">
              {COPILOT_PROVIDERS.map((p) => (
                <Button
                  key={p}
                  type="button"
                  role="radio"
                  aria-checked={provider === p}
                  variant={provider === p ? "default" : "outline"}
                  size="sm"
                  onClick={() => setProvider(p)}
                >
                  {PROVIDER_LABELS[p]}
                </Button>
              ))}
            </div>
          </fieldset>

          <div className="grid gap-1.5">
            <label className="text-sm font-medium" htmlFor={`${fieldId}-key`}>
              API key
            </label>
            <Input
              id={`${fieldId}-key`}
              type="password"
              autoComplete="off"
              placeholder={provider === "openrouter" ? "sk-or-…" : "sk-…"}
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              aria-invalid={apiKey !== "" && !keyOk}
            />
            {apiKey !== "" && !keyOk ? (
              <p className="text-xs text-risk">That doesn&apos;t look like an API key.</p>
            ) : null}
          </div>

          <div className="grid gap-1.5">
            <label className="text-sm font-medium" htmlFor={`${fieldId}-model`}>
              Model <span className="font-normal text-muted-foreground">(optional)</span>
            </label>
            <Input
              id={`${fieldId}-model`}
              placeholder={defaultModelFor(provider)}
              value={model}
              onChange={(e) => setModel(e.target.value)}
              aria-invalid={!modelOk}
            />
            {!modelOk ? <p className="text-xs text-risk">Invalid model id.</p> : null}
          </div>

          <div aria-live="polite" className="min-h-5 text-sm">
            {test.kind === "running" ? (
              <span className="text-muted-foreground">Testing the connection…</span>
            ) : test.kind === "ok" ? (
              <span className="text-safe">Connection works — the copilot will use this key.</span>
            ) : test.kind === "failed" ? (
              <span className="text-risk">Test failed: {test.message}</span>
            ) : null}
          </div>
        </div>

        <DialogFooter className="gap-2 sm:justify-between">
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={clear}
            disabled={stored === null && apiKey === ""}
          >
            Clear key
          </Button>
          <div className="flex gap-2">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={runTest}
              disabled={!keyOk || !modelOk || test.kind === "running"}
            >
              Test connection
            </Button>
            <Button type="button" size="sm" onClick={save} disabled={!keyOk || !modelOk}>
              Save in this browser
            </Button>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
