// Tests for the one-click setup helpers (Task E): the OAuth popup return detection — it must not
// fire on the start URL, the transient about:blank, or while the popup is on github.com, only once
// the user has returned to the dashboard.
// Run: npm test  (node --test; Node >= 23.6 strips TS types natively).
import assert from "node:assert/strict";
import { test } from "node:test";

import { oauthPopupReturned, SETUP_OAUTH_PATH } from "./setup.ts";

const SELF = "https://dash.example";

test("SETUP_OAUTH_PATH requests the elevated setup scopes via the same-origin proxy", () => {
  assert.ok(SETUP_OAUTH_PATH.startsWith("/api/"));
  assert.match(SETUP_OAUTH_PATH, /setup=1/);
});

test("returns true only once the popup is back on the dashboard", () => {
  assert.equal(oauthPopupReturned(SELF, `${SELF}/`, SELF), true);
  assert.equal(oauthPopupReturned(SELF, `${SELF}/setup`, SELF), true);
});

test("does not fire on the start login URL or the callback (still on /auth/github)", () => {
  assert.equal(
    oauthPopupReturned(SELF, `${SELF}/api/v1/auth/github/login?setup=1`, SELF),
    false,
  );
  assert.equal(
    oauthPopupReturned(SELF, `${SELF}/api/v1/auth/github/callback?code=x`, SELF),
    false,
  );
});

test("does not fire on the transient about:blank document (even if it inherits our origin)", () => {
  assert.equal(oauthPopupReturned(SELF, "about:blank", SELF), false);
  assert.equal(oauthPopupReturned(SELF, "", SELF), false);
});

test("does not fire while the popup is cross-origin (a different origin than ours)", () => {
  assert.equal(oauthPopupReturned("https://github.com", "https://github.com/login", SELF), false);
  // about:blank's origin is reported as the string "null" in some browsers — also not ours.
  assert.equal(oauthPopupReturned("null", "about:blank", SELF), false);
});
