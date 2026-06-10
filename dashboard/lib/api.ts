import { cookies } from "next/headers";

// Server-side base URL for the platform API (the dashboard fetches it during SSR).
const API_BASE = process.env.API_URL ?? "http://localhost:8000";
// Browser-reachable base URL, used for links the user navigates to (OAuth login, App install).
export const PUBLIC_API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function authHeaders(): Promise<Record<string, string>> {
  const headers: Record<string, string> = { Accept: "application/json" };
  // Forward the browser's session cookie to the API (same host in dev; set a cookie domain in prod).
  const store = await cookies();
  const cookieHeader = store
    .getAll()
    .map((c) => `${c.name}=${c.value}`)
    .join("; ");
  if (cookieHeader) headers["Cookie"] = cookieHeader;
  // Optional API key for local/dev rendering without an interactive login.
  const token = process.env.DASHBOARD_API_TOKEN;
  if (token) headers["Authorization"] = `Bearer ${token}`;
  return headers;
}

export async function apiGet<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: await authHeaders(),
    cache: "no-store",
    // Send credentials (the session cookie) on cross-origin requests to the API.
    credentials: "include",
  });
  if (!res.ok) {
    throw new ApiError(res.status, `GET ${path} -> ${res.status}`);
  }
  return (await res.json()) as T;
}

/** Like {@link apiGet} but returns null on 401 (unauthenticated) or 404 (not found / no access). */
export async function apiGetOrNull<T>(path: string): Promise<T | null> {
  try {
    return await apiGet<T>(path);
  } catch (err) {
    if (err instanceof ApiError && (err.status === 401 || err.status === 404)) {
      return null;
    }
    throw err;
  }
}

// Auth / install links are full-page browser navigations. They go through the same-origin
// /api proxy (see next.config.ts) so the OAuth callback's Set-Cookie lands on the dashboard's
// own domain — without that, the session cookie would be scoped to the backend domain and
// invisible to this app's server-side rendering.
export function loginUrl(): string {
  return `/api/v1/auth/github/login`;
}

export function installUrl(): string {
  return `/api/v1/github/install`;
}
