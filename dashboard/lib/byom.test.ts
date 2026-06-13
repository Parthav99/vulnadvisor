// Tests for the BYOM config layer (Task 15.1c gate): localStorage-only persistence shape,
// defensive parsing, the 15.1b header mapping, and key masking.
// Run: npm test  (node --test; Node >= 23.6 strips TS types natively).
import assert from "node:assert/strict";
import { test } from "node:test";

import {
  BYOM_STORAGE_KEY,
  byomHeaders,
  clearByomConfig,
  loadByomConfig,
  maskKey,
  parseByomConfig,
  saveByomConfig,
  serializeByomConfig,
} from "./byom.ts";

const CONFIG = {
  provider: "openrouter" as const,
  apiKey: "sk-or-v1-0123456789abcdef",
  model: "deepseek/deepseek-chat-v3.1:free",
};

function fakeStorage(): Storage {
  const map = new Map<string, string>();
  return {
    getItem: (k: string) => map.get(k) ?? null,
    setItem: (k: string, v: string) => void map.set(k, v),
    removeItem: (k: string) => void map.delete(k),
    clear: () => map.clear(),
    key: () => null,
    get length() {
      return map.size;
    },
  };
}

test("save/load roundtrip via storage, clear removes", () => {
  const storage = fakeStorage();
  saveByomConfig(storage, CONFIG);
  assert.deepEqual(loadByomConfig(storage), CONFIG);
  assert.ok(storage.getItem(BYOM_STORAGE_KEY)!.includes(CONFIG.apiKey)); // browser-only home
  clearByomConfig(storage);
  assert.equal(loadByomConfig(storage), null);
});

test("model is optional", () => {
  const { model: _model, ...noModel } = CONFIG;
  assert.deepEqual(parseByomConfig(serializeByomConfig(noModel)), noModel);
});

test("malformed stored values degrade to null, never throw", () => {
  for (const raw of [
    null,
    "",
    "not json",
    "42",
    '{"provider":"ollama","apiKey":"sk-or-v1-0123456789"}', // unsupported provider
    '{"provider":"openai"}', // missing key
    '{"provider":"openai","apiKey":"has space in key"}',
    `{"provider":"openai","apiKey":"sk-ok-0123456789","model":"bad model"}`,
  ]) {
    assert.equal(parseByomConfig(raw), null, String(raw));
  }
});

test("serialize refuses invalid configs", () => {
  assert.throws(() => serializeByomConfig({ ...CONFIG, apiKey: "nope" }), /API key/);
  assert.throws(() => serializeByomConfig({ ...CONFIG, model: "a b" }), /model/);
});

test("headers carry exactly the 15.1b contract", () => {
  assert.deepEqual(byomHeaders(CONFIG), {
    "X-Copilot-User-Key": CONFIG.apiKey,
    "X-Copilot-Provider": "openrouter",
    "X-Copilot-Model": CONFIG.model,
  });
  const { model: _model, ...noModel } = CONFIG;
  assert.equal("X-Copilot-Model" in byomHeaders(noModel), false);
});

test("loadByomConfig survives a throwing storage (private mode)", () => {
  const throwing = {
    getItem: () => {
      throw new Error("denied");
    },
    setItem: () => {},
    removeItem: () => {},
  };
  assert.equal(loadByomConfig(throwing), null);
});

test("masking shows vendor prefix and last 4 only", () => {
  assert.equal(maskKey("sk-or-v1-0123456789abcdef"), "sk-or-…cdef");
  assert.equal(maskKey("sk-ant-api03-xyzw"), "sk-ant-…xyzw");
  assert.equal(maskKey("sk-proj-abcd1234"), "sk-…1234");
  assert.ok(!maskKey(CONFIG.apiKey).includes("0123456789"));
});
