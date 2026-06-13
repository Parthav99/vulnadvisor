// File: dashboard/components/copilot/copilot-panel.tsx
// The triage copilot UI (Task 15.2): a floating "How can I help?" launcher opening a
// slide-over chat that streams answers from /api/copilot, grounded in the caller's own scan
// data. The conversation lives only in React state — never persisted, never sent anywhere but
// the request itself (privacy: we don't store chats). A BYOM personal key (15.1c), if present
// in this browser, is attached per request via the 15.1b headers.
"use client";

import { useEffect, useRef, useState } from "react";
import { usePathname } from "next/navigation";
import Link from "next/link";
import { useChat } from "@ai-sdk/react";
import { DefaultChatTransport } from "ai";
import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { MessageCircleQuestion, Send, Square, Trash2 } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";
import { byomHeaders, loadByomConfig } from "@/lib/byom";
import {
  isInternalHref,
  orgSlugFromPathname,
  pageContextLabel,
  SUGGESTED_PROMPTS,
} from "@/lib/copilot-ui";
import { cn } from "@/lib/utils";

/** Markdown link renderer: in-app links route client-side and close the panel; rest open safely. */
function MarkdownLink({
  href,
  children,
  onNavigate,
}: {
  href?: string;
  children?: React.ReactNode;
  onNavigate: () => void;
}) {
  if (href && isInternalHref(href)) {
    return (
      <Link href={href} className="link" onClick={onNavigate}>
        {children}
      </Link>
    );
  }
  return (
    <a href={href} className="link" target="_blank" rel="noreferrer">
      {children}
    </a>
  );
}

export function CopilotPanel() {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);
  const [input, setInput] = useState("");
  const scrollRef = useRef<HTMLDivElement>(null);

  // The org for this conversation, derived from the route; the launcher only shows under /orgs.
  const orgSlug = orgSlugFromPathname(pathname);
  const pageLabel = pageContextLabel(pathname);

  const { messages, sendMessage, status, error, stop, setMessages } = useChat({
    transport: new DefaultChatTransport({
      api: "/api/copilot",
      // Built per send so a key saved mid-session (and the current page) are always fresh.
      prepareSendMessagesRequest: ({ messages: msgs }) => {
        const byom = typeof window !== "undefined" ? loadByomConfig(window.localStorage) : null;
        return {
          body: { orgSlug, page: pageLabel, messages: msgs },
          headers: byom ? byomHeaders(byom) : undefined,
        };
      },
    }),
  });

  const busy = status === "submitted" || status === "streaming";

  // Keep the latest message in view as tokens stream in.
  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight });
  }, [messages, busy]);

  if (orgSlug === null) return null; // no org context → no copilot launcher

  function submit(text: string) {
    const trimmed = text.trim();
    if (trimmed === "" || busy) return;
    setInput("");
    void sendMessage({ text: trimmed });
  }

  return (
    <Sheet open={open} onOpenChange={setOpen}>
      <SheetTrigger asChild>
        <Button
          size="lg"
          className="fixed right-5 bottom-5 z-30 gap-2 rounded-full shadow-lg"
          data-tour="copilot-launcher"
        >
          <MessageCircleQuestion aria-hidden />
          How can I help?
        </Button>
      </SheetTrigger>
      <SheetContent
        className="gap-0 p-0"
        aria-describedby={undefined}
        onOpenAutoFocus={(e) => {
          // Focus the input, not the close button, when the panel opens.
          e.preventDefault();
          (e.currentTarget as HTMLElement).querySelector<HTMLInputElement>("#copilot-input")?.focus();
        }}
      >
        <SheetHeader>
          <SheetTitle>Triage copilot</SheetTitle>
          <SheetDescription>
            Grounded in your own scan data. Answers explain priority — they never change it.
          </SheetDescription>
          {pageLabel ? (
            <span className="mt-1 inline-flex w-fit items-center rounded-full bg-secondary px-2 py-0.5 text-xs text-muted-foreground">
              Context: {pageLabel}
            </span>
          ) : null}
        </SheetHeader>

        <div
          ref={scrollRef}
          className="flex-1 space-y-4 overflow-y-auto px-4 py-4"
          role="log"
          aria-live="polite"
          aria-label="Conversation"
        >
          {messages.length === 0 ? (
            <div className="space-y-3">
              <p className="text-sm text-muted-foreground">
                Ask about your findings, scans, and posture. Try:
              </p>
              <div className="flex flex-col items-start gap-2">
                {SUGGESTED_PROMPTS.map((prompt) => (
                  <Button
                    key={prompt}
                    variant="outline"
                    size="sm"
                    onClick={() => submit(prompt)}
                  >
                    {prompt}
                  </Button>
                ))}
              </div>
            </div>
          ) : (
            messages.map((message) => {
              const text = message.parts
                .filter((p): p is { type: "text"; text: string } => p.type === "text")
                .map((p) => p.text)
                .join("");
              const isUser = message.role === "user";
              const toolOnly = text === "" && !isUser;
              return (
                <div
                  key={message.id}
                  className={cn("flex", isUser ? "justify-end" : "justify-start")}
                >
                  <div
                    className={cn(
                      "max-w-[85%] rounded-lg px-3 py-2 text-sm",
                      isUser ? "bg-primary text-primary-foreground" : "bg-secondary",
                    )}
                  >
                    {isUser ? (
                      text
                    ) : toolOnly ? (
                      <span className="text-muted-foreground">Looking through your scans…</span>
                    ) : (
                      <div className="prose-copilot space-y-2">
                        <Markdown
                          remarkPlugins={[remarkGfm]}
                          components={{
                            a: (props) => (
                              <MarkdownLink {...props} onNavigate={() => setOpen(false)} />
                            ),
                          }}
                        >
                          {text}
                        </Markdown>
                      </div>
                    )}
                  </div>
                </div>
              );
            })
          )}

          {error ? (
            <div className="rounded-lg border border-risk/40 bg-risk/10 px-3 py-2 text-sm text-risk">
              Something went wrong. If you haven&apos;t set up a model key, add one in{" "}
              <Link className="link" href={`/orgs/${orgSlug}/settings`} onClick={() => setOpen(false)}>
                settings
              </Link>
              .
            </div>
          ) : null}
        </div>

        <form
          className="flex items-end gap-2 border-t p-3"
          onSubmit={(e) => {
            e.preventDefault();
            submit(input);
          }}
        >
          <label htmlFor="copilot-input" className="sr-only">
            Ask the triage copilot
          </label>
          <input
            id="copilot-input"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask about your findings…"
            autoComplete="off"
            className="flex-1 rounded-md border bg-background px-3 py-2 text-sm focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
          />
          {messages.length > 0 ? (
            <Button
              type="button"
              variant="ghost"
              size="icon"
              aria-label="Clear conversation"
              onClick={() => setMessages([])}
              disabled={busy}
            >
              <Trash2 aria-hidden />
            </Button>
          ) : null}
          {busy ? (
            <Button type="button" size="icon" variant="outline" aria-label="Stop" onClick={() => stop()}>
              <Square aria-hidden />
            </Button>
          ) : (
            <Button type="submit" size="icon" aria-label="Send" disabled={input.trim() === ""}>
              <Send aria-hidden />
            </Button>
          )}
        </form>
      </SheetContent>
    </Sheet>
  );
}
