// File: dashboard/app/api/copilot/route.ts
// Triage copilot backend (Task 15.1): a streaming route handler that lets Claude answer
// questions over the caller's own scan data.
//
// Security shape:
// - Every tool call is a GET against the existing read/analytics API carrying the caller's
//   own session cookie — tenant isolation is inherited, there is no service account.
// - The Anthropic key comes from the platform's grant endpoint (org BYO key, decrypted only
//   behind the COPILOT_SERVICE_TOKEN) with the dashboard's ANTHROPIC_API_KEY as the platform
//   fallback; the grant also consumes one slot of the org's daily cap (429 when spent).
// - Tool results are wrapped as delimited untrusted data (lib/copilot.ts) because advisory
//   summaries are attacker-influenceable text; the red-team suite covers this.

import { createAnthropic } from "@ai-sdk/anthropic";
import {
  convertToModelMessages,
  jsonSchema,
  stepCountIs,
  streamText,
  tool,
  validateUIMessages,
  type ToolSet,
  type UIMessage,
} from "ai";

import {
  COPILOT_SYSTEM_PROMPT,
  DEFAULT_COPILOT_MODEL,
  isValidOrgSlug,
  MAX_MESSAGES,
  MAX_STEPS,
  TOOL_SPECS,
  wrapToolResult,
} from "@/lib/copilot";

// Streaming responses on the Vercel free tier; tool loops can take a while.
export const maxDuration = 60;

const API_BASE = process.env.API_URL ?? "http://localhost:8000";
const MAX_BODY_CHARS = 100_000;

interface CopilotGrant {
  key_source: "org" | "platform";
  api_key: string | null;
  remaining_today: number;
}

function jsonError(status: number, message: string): Response {
  return Response.json({ error: message }, { status });
}

/** Forward the browser's own credentials to the platform — never a service identity. */
function callerHeaders(req: Request): Record<string, string> {
  const headers: Record<string, string> = { Accept: "application/json" };
  const cookie = req.headers.get("cookie");
  if (cookie) headers["Cookie"] = cookie;
  // Optional API key for local/dev rendering without an interactive login (mirrors lib/api).
  const token = process.env.DASHBOARD_API_TOKEN;
  if (token) headers["Authorization"] = `Bearer ${token}`;
  return headers;
}

async function obtainGrant(
  req: Request,
  orgSlug: string,
): Promise<{ grant: CopilotGrant } | { failure: Response }> {
  const serviceToken = process.env.COPILOT_SERVICE_TOKEN;
  if (!serviceToken) {
    return { failure: jsonError(503, "Copilot is not configured on this deployment.") };
  }
  const res = await fetch(
    `${API_BASE}/v1/orgs/${encodeURIComponent(orgSlug)}/copilot/grant`,
    {
      method: "POST",
      headers: { ...callerHeaders(req), "X-Copilot-Service": serviceToken },
      cache: "no-store",
    },
  );
  if (res.ok) {
    return { grant: (await res.json()) as CopilotGrant };
  }
  switch (res.status) {
    case 401:
      return { failure: jsonError(401, "Sign in to use the copilot.") };
    case 404:
      return { failure: jsonError(404, "Organization not found.") };
    case 429:
      return {
        failure: jsonError(429, "This organization has reached today's copilot limit."),
      };
    case 403: // our service token is wrong — a deployment problem, not the user's
    case 503:
      return { failure: jsonError(503, "Copilot is not configured on this deployment.") };
    default:
      return { failure: jsonError(502, "The platform API is unavailable.") };
  }
}

/** Org-scoped, session-authenticated, read-only tools built from the shared specs. */
function buildTools(req: Request, orgSlug: string): ToolSet {
  const tools: ToolSet = {};
  for (const spec of TOOL_SPECS) {
    tools[spec.name] = tool({
      description: spec.description,
      inputSchema: jsonSchema(spec.inputSchema),
      execute: async (input: unknown) => {
        let path: string;
        try {
          path = spec.path(orgSlug, (input ?? {}) as Record<string, unknown>);
        } catch (err) {
          return wrapToolResult({
            error: err instanceof Error ? err.message : "invalid tool input",
          });
        }
        const res = await fetch(`${API_BASE}${path}`, {
          headers: callerHeaders(req),
          cache: "no-store",
        });
        if (!res.ok) {
          return wrapToolResult({
            error: "request failed",
            status: res.status,
            hint:
              res.status === 404
                ? "not found, or not accessible to this user's organization"
                : undefined,
          });
        }
        return wrapToolResult(await res.json());
      },
    });
  }
  return tools;
}

export async function POST(req: Request): Promise<Response> {
  let body: { orgSlug?: unknown; messages?: unknown; page?: unknown };
  try {
    const raw = await req.text();
    if (raw.length > MAX_BODY_CHARS) return jsonError(413, "Conversation too large.");
    body = JSON.parse(raw) as typeof body;
  } catch {
    return jsonError(400, "Invalid JSON body.");
  }

  if (!isValidOrgSlug(body.orgSlug)) return jsonError(400, "Invalid org.");
  const orgSlug = body.orgSlug;

  let messages: UIMessage[];
  try {
    messages = await validateUIMessages({ messages: body.messages });
  } catch {
    return jsonError(400, "Invalid messages.");
  }
  // Only user/assistant turns from the client — a client-supplied "system" message must
  // never reach the model with system authority.
  messages = messages
    .filter((m) => m.role === "user" || m.role === "assistant")
    .slice(-MAX_MESSAGES);
  if (messages.length === 0) return jsonError(400, "No messages.");

  const grantResult = await obtainGrant(req, orgSlug);
  if ("failure" in grantResult) return grantResult.failure;

  const apiKey = grantResult.grant.api_key ?? process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return jsonError(
      503,
      "No Anthropic key available — add your organization's key in Settings.",
    );
  }

  // The page context is user-controlled display state: include it as data, single line, capped.
  const page =
    typeof body.page === "string" && body.page.length > 0
      ? body.page.replace(/\s+/g, " ").slice(0, 200)
      : null;
  const system = page
    ? `${COPILOT_SYSTEM_PROMPT}\n\n## Context\nThe user is currently viewing: ${page}`
    : COPILOT_SYSTEM_PROMPT;

  const anthropic = createAnthropic({ apiKey });
  const result = streamText({
    model: anthropic(process.env.COPILOT_MODEL ?? DEFAULT_COPILOT_MODEL),
    system,
    messages: await convertToModelMessages(messages),
    tools: buildTools(req, orgSlug),
    stopWhen: stepCountIs(MAX_STEPS),
  });
  return result.toUIMessageStreamResponse();
}
