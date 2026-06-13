// File: dashboard/app/api/copilot/route.ts
// Triage copilot backend (Task 15.1): a streaming route handler that lets Claude answer
// questions over the caller's own scan data.
//
// Security shape:
// - Every tool call is a GET against the existing read/analytics API carrying the caller's
//   own session cookie — tenant isolation is inherited, there is no service account.
// - Key precedence (15.1b BYOM): a personal key from the X-Copilot-User-Key header (used
//   once, never stored/logged, no cap — the user pays their own provider) → the org BYO key
//   via the platform's grant endpoint (decrypted only behind COPILOT_SERVICE_TOKEN, daily
//   cap enforced) → the deployment fallback key (ANTHROPIC_API_KEY / OPENAI_API_KEY).
// - Tool results are wrapped as delimited untrusted data (lib/copilot.ts) because advisory
//   summaries are attacker-influenceable text; the red-team suite covers this.

import { createAnthropic } from "@ai-sdk/anthropic";
import { createOpenAI } from "@ai-sdk/openai";
import {
  type LanguageModel,
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
  type CopilotProvider,
  defaultModelFor,
  isValidModelId,
  isValidOrgSlug,
  isValidProvider,
  isValidUserKey,
  MAX_MESSAGES,
  MAX_STEPS,
  OPENROUTER_BASE_URL,
  providerForKey,
  TOOL_SPECS,
  wrapToolResult,
} from "@/lib/copilot";

/** Build the language model for a key/provider/model triple. */
function buildModel(apiKey: string, provider: CopilotProvider, modelId: string): LanguageModel {
  switch (provider) {
    case "anthropic":
      return createAnthropic({ apiKey })(modelId);
    case "openrouter":
      // OpenAI-compatible chat-completions endpoint (OpenRouter has no Responses API).
      return createOpenAI({ apiKey, baseURL: OPENROUTER_BASE_URL }).chat(modelId);
    case "openai":
      return createOpenAI({ apiKey })(modelId);
  }
}

/**
 * The BYOM personal key (Task 15.1b), read from headers and used for this request only —
 * never stored, never logged. Returns null when absent; a Response when malformed.
 */
function personalKey(
  req: Request,
): { apiKey: string; provider: CopilotProvider; modelId: string } | Response | null {
  const apiKey = req.headers.get("x-copilot-user-key");
  if (apiKey === null) return null;
  if (!isValidUserKey(apiKey)) return jsonError(400, "Invalid API key format.");
  const providerHeader = req.headers.get("x-copilot-provider");
  if (providerHeader !== null && !isValidProvider(providerHeader)) {
    return jsonError(400, "Unknown provider.");
  }
  const provider = providerHeader ?? providerForKey(apiKey);
  const modelHeader = req.headers.get("x-copilot-model");
  if (modelHeader !== null && !isValidModelId(modelHeader)) {
    return jsonError(400, "Invalid model id.");
  }
  return { apiKey, provider, modelId: modelHeader ?? defaultModelFor(provider) };
}

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

  // Key-source precedence: BYOM personal key (no grant, no cap — the user pays their own
  // provider) → org BYO key / platform fallback via the grant endpoint (cap enforced).
  const personal = personalKey(req);
  if (personal instanceof Response) return personal;

  let model: LanguageModel;
  if (personal !== null) {
    // Still the caller's own tenancy: verify membership before any model call.
    const orgCheck = await fetch(`${API_BASE}/v1/orgs/${encodeURIComponent(orgSlug)}`, {
      headers: callerHeaders(req),
      cache: "no-store",
    });
    if (orgCheck.status === 401) return jsonError(401, "Sign in to use the copilot.");
    if (orgCheck.status === 404) return jsonError(404, "Organization not found.");
    if (!orgCheck.ok) return jsonError(502, "The platform API is unavailable.");
    model = buildModel(personal.apiKey, personal.provider, personal.modelId);
  } else {
    const grantResult = await obtainGrant(req, orgSlug);
    if ("failure" in grantResult) return grantResult.failure;
    const apiKey =
      grantResult.grant.api_key ??
      process.env.ANTHROPIC_API_KEY ??
      process.env.OPENAI_API_KEY;
    if (!apiKey) {
      return jsonError(
        503,
        "No model API key available — add a personal key in the copilot settings, or your organization's key in Settings.",
      );
    }
    const provider = providerForKey(apiKey);
    model = buildModel(apiKey, provider, process.env.COPILOT_MODEL ?? defaultModelFor(provider));
  }

  // The page context is user-controlled display state: include it as data, single line, capped.
  const page =
    typeof body.page === "string" && body.page.length > 0
      ? body.page.replace(/\s+/g, " ").slice(0, 200)
      : null;
  const system = page
    ? `${COPILOT_SYSTEM_PROMPT}\n\n## Context\nThe user is currently viewing: ${page}`
    : COPILOT_SYSTEM_PROMPT;

  const result = streamText({
    model,
    system,
    messages: await convertToModelMessages(messages),
    tools: buildTools(req, orgSlug),
    stopWhen: stepCountIs(MAX_STEPS),
  });
  return result.toUIMessageStreamResponse();
}
