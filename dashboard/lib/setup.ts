// File: dashboard/lib/setup.ts
// Pure helpers for the one-click setup flow (Task E). Kept free of React/window so the popup
// return-detection logic is unit-testable (lib/setup.test.ts).

// The incremental-authorization OAuth flow (Task 17.4 Part 3), reached through the same-origin
// /api proxy so the session cookie rides along. `setup=1` requests the repo/workflow scopes the
// platform needs to open the setup PR and write the VULNADVISOR_API_KEY secret.
export const SETUP_OAUTH_PATH = "/api/v1/auth/github/login?setup=1";

/**
 * Has the OAuth consent popup returned to our own origin — i.e. the user finished granting and the
 * backend callback redirected back to the dashboard?
 *
 * The popup's journey is: our origin (the `/api` login route) → github.com (cross-origin, where
 * reading `location` throws, so callers treat that as "keep waiting") → back to our origin at the
 * dashboard root. We only count it as returned when it is same-origin AND no longer on an
 * `/auth/github` route AND not the initial `about:blank` — so neither the start URL nor the
 * transient blank document (which inherits the opener's origin in some browsers) fires prematurely.
 */
export function oauthPopupReturned(
  popupOrigin: string,
  popupHref: string,
  selfOrigin: string,
): boolean {
  if (popupOrigin !== selfOrigin) return false;
  if (popupHref === "" || popupHref === "about:blank") return false;
  return !popupHref.includes("/auth/github");
}
