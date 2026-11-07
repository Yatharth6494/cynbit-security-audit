import test from "node:test";
import assert from "node:assert/strict";
import { SlidingWindowLimiter } from "../src/hardening/rate-limit.mjs";
import { startTestServer, postJson } from "./helpers.mjs";

test("sliding window limiter allows up to max and resets after the window", () => {
  let now = 1000;
  const limiter = new SlidingWindowLimiter({ windowMs: 1000, max: 2, now: () => now });
  assert.equal(limiter.check("k").allowed, true);
  assert.equal(limiter.check("k").allowed, true);
  const blocked = limiter.check("k");
  assert.equal(blocked.allowed, false);
  assert.ok(blocked.retryAfterSeconds >= 1);
  now = 2500;
  assert.equal(limiter.check("k").allowed, true);
});

test("contact endpoint returns 429 with Retry-After", async () => {
  const server = await startTestServer({ rateLimits: { contact: 2 } });
  try {
    const payload = {
      fullName: "Alex",
      email: "alex@example.com",
      message: "Hello"
    };
    assert.equal((await postJson(server.url, "/api/contact", payload)).status, 200);
    assert.equal((await postJson(server.url, "/api/contact", payload)).status, 200);
    const blocked = await postJson(server.url, "/api/contact", payload);
    assert.equal(blocked.status, 429);
    assert.ok(blocked.headers.get("retry-after"));
    assert.equal(blocked.headers.get("ratelimit-limit"), "2");
  } finally {
    await server.close();
  }
});

test("oversized JSON bodies are rejected", async () => {
  const server = await startTestServer();
  try {
    const response = await postJson(server.url, "/api/contact", {
      fullName: "Alex",
      email: "alex@example.com",
      message: "x".repeat(20000)
    });
    assert.equal(response.status, 413);
  } finally {
    await server.close();
  }
});
