import test from "node:test";
import assert from "node:assert/strict";
import { startTestServer } from "./helpers.mjs";

test("hardened HTML responses include a nonce-based CSP and strict headers", async () => {
  const server = await startTestServer();
  try {
    const response = await fetch(`${server.url}/`);
    assert.equal(response.status, 200);
    const csp = response.headers.get("content-security-policy");
    assert.match(csp, /default-src 'self'/);
    assert.match(csp, /object-src 'none'/);
    assert.match(csp, /frame-ancestors 'none'/);
    assert.match(csp, /script-src 'self' 'nonce-[^']+' 'strict-dynamic'/);
    assert.equal(response.headers.get("x-content-type-options"), "nosniff");
    assert.equal(response.headers.get("x-frame-options"), "DENY");
    assert.equal(response.headers.get("referrer-policy"), "no-referrer");
    assert.match(response.headers.get("permissions-policy"), /camera=\(\)/);
    assert.equal(response.headers.get("cross-origin-opener-policy"), "same-origin");
    assert.equal(response.headers.get("cross-origin-resource-policy"), "same-origin");
    const hsts = response.headers.get("strict-transport-security");
    assert.match(hsts, /max-age=63072000/);
    assert.match(hsts, /includeSubDomains/);
    assert.match(hsts, /preload/);
    assert.equal(response.headers.get("x-powered-by"), null);
    assert.equal(response.headers.get("access-control-allow-origin"), null);
    const nonce = csp.match(/'nonce-([^']+)'/)[1];
    const body = await response.text();
    assert.ok(body.includes(`nonce="${nonce}"`));
  } finally {
    await server.close();
  }
});

test("JSON responses deny framing and do not allow wildcard CORS", async () => {
  const server = await startTestServer();
  try {
    const response = await fetch(`${server.url}/healthz`);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("access-control-allow-origin"), null);
    assert.match(response.headers.get("content-security-policy"), /default-src 'none'/);
    assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  } finally {
    await server.close();
  }
});
