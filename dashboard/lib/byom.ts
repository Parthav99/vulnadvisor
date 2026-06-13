// File: dashboard/lib/byom.ts
// BYOM personal-key configuration (Task 15.1c). Pure + storage-injectable — no React, no
// window access at module level — so the (de)serialization, validation, header mapping, and
// masking are unit-testable (lib/byom.test.ts). The key is persisted ONLY in the user's
// browser (localStorage) and sent per request via the 15.1b headers; it never reaches a
// platform table.

import {
  type CopilotProvider,
  isValidModelId,
  isValidProvider,
  isValidUserKey,
} from "./copilot.ts";

export const BYOM_STORAGE_KEY = "va_byom";

export interface ByomConfig {
  provider: CopilotProvider;
  apiKey: string;
  /** Optional model override; the provider default applies when absent. */
  model?: string;
}

/** Defensive parse of a stored value: anything malformed degrades to null, never throws. */
export function parseByomConfig(raw: unknown): ByomConfig | null {
  if (typeof raw !== "string" || raw.length === 0) return null;
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof data !== "object" || data === null) return null;
  const { provider, apiKey, model } = data as Record<string, unknown>;
  if (!isValidProvider(provider) || !isValidUserKey(apiKey)) return null;
  if (model !== undefined && !isValidModelId(model)) return null;
  return { provider, apiKey, ...(model !== undefined ? { model } : {}) };
}

/** Serialize for storage; throws on an invalid config (callers validate via the form). */
export function serializeByomConfig(config: ByomConfig): string {
  if (!isValidProvider(config.provider)) throw new Error("invalid provider");
  if (!isValidUserKey(config.apiKey)) throw new Error("invalid API key");
  if (config.model !== undefined && !isValidModelId(config.model)) {
    throw new Error("invalid model id");
  }
  return JSON.stringify({
    provider: config.provider,
    apiKey: config.apiKey,
    ...(config.model !== undefined ? { model: config.model } : {}),
  });
}

type StorageLike = Pick<Storage, "getItem" | "setItem" | "removeItem">;

export function loadByomConfig(storage: StorageLike): ByomConfig | null {
  try {
    return parseByomConfig(storage.getItem(BYOM_STORAGE_KEY));
  } catch {
    return null; // storage access can throw (privacy modes); no key is a safe default
  }
}

export function saveByomConfig(storage: StorageLike, config: ByomConfig): void {
  storage.setItem(BYOM_STORAGE_KEY, serializeByomConfig(config));
  emitByomChange();
}

export function clearByomConfig(storage: StorageLike): void {
  storage.removeItem(BYOM_STORAGE_KEY);
  emitByomChange();
}

// --- reactive snapshot (for useSyncExternalStore) ----------------------------------------------
// localStorage isn't a React store, so the UI subscribes to it via these. Same-tab writes go
// through save/clear above (which notify); cross-tab writes arrive via the `storage` event. The
// snapshot is the raw string (a stable primitive, so React's getSnapshot cache check is happy).

const byomListeners = new Set<() => void>();

function emitByomChange(): void {
  for (const listener of byomListeners) listener();
}

export function subscribeByomStorage(callback: () => void): () => void {
  byomListeners.add(callback);
  if (typeof window !== "undefined") window.addEventListener("storage", callback);
  return () => {
    byomListeners.delete(callback);
    if (typeof window !== "undefined") window.removeEventListener("storage", callback);
  };
}

/** The raw stored string (client) or null (SSR / absent / blocked). */
export function byomRawSnapshot(): string | null {
  if (typeof window === "undefined") return null;
  try {
    return window.localStorage.getItem(BYOM_STORAGE_KEY);
  } catch {
    return null;
  }
}

/** The Task 15.1b request headers for a stored config. */
export function byomHeaders(config: ByomConfig): Record<string, string> {
  return {
    "X-Copilot-User-Key": config.apiKey,
    "X-Copilot-Provider": config.provider,
    ...(config.model !== undefined ? { "X-Copilot-Model": config.model } : {}),
  };
}

/** Display form: vendor prefix + last 4, everything else hidden. */
export function maskKey(apiKey: string): string {
  const prefix = apiKey.startsWith("sk-ant-")
    ? "sk-ant-"
    : apiKey.startsWith("sk-or-")
      ? "sk-or-"
      : apiKey.startsWith("sk-")
        ? "sk-"
        : "";
  return `${prefix}…${apiKey.slice(-4)}`;
}
