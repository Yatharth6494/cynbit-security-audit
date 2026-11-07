import test from "node:test";
import assert from "node:assert/strict";
import {
  analyzeHeaders,
  analyzeRobots,
  parseCsp,
  parseHsts,
  scoreFindings
} from "../src/scanner/checks.mjs";
import { renderMarkdown } from "../src/scanner/render.mjs";

const GOOD_HEADERS = {
  "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
  "content-security-policy":
    "default-src 'self'; object-src 'none'; frame-ancestors 'none'; script-src 'self' 'nonce-abc' 'strict-dynamic'; base-uri 'self'",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "camera=(), microphone=()",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin"
};

test("parseHsts extracts max-age and flags", () => {
  const parsed = parseHsts("max-age=63072000; includeSubDomains; preload");
  assert.equal(parsed.present, true);
  assert.equal(parsed.maxAge, 63072000);
  assert.equal(parsed.includeSubDomains, true);
  assert.equal(parsed.preload, true);
});

test("parseCsp builds a directive map", () => {
  const csp = parseCsp(GOOD_HEADERS["content-security-policy"]);
  assert.equal(csp.present, true);
  assert.deepEqual(csp.directives["object-src"], ["'none'"]);
  assert.deepEqual(csp.directives["frame-ancestors"], ["'none'"]);
});

test("a hardened header set produces no high severity findings", () => {
  const result = analyzeHeaders(new Headers(GOOD_HEADERS), { setCookies: [] });
  const high = result.findings.filter((finding) => ["critical", "high"].includes(finding.severity));
  assert.equal(high.length, 0);
});

test("missing headers are detected", () => {
  const result = analyzeHeaders(new Headers(), { setCookies: [] });
  const ids = result.findings.map((finding) => finding.id);
  assert.ok(ids.includes("HSTS-001"));
  assert.ok(ids.includes("CSP-001"));
  assert.ok(ids.includes("XFO-001"));
  assert.ok(ids.includes("REF-001"));
});

test("wildcard CORS is flagged", () => {
  const result = analyzeHeaders(new Headers({ ...GOOD_HEADERS, "access-control-allow-origin": "*" }), {
    setCookies: []
  });
  assert.ok(result.findings.some((finding) => finding.id === "CORS-002"));
});

test("insecure cookies are flagged", () => {
  const result = analyzeHeaders(new Headers(GOOD_HEADERS), {
    setCookies: ["session=abc; Path=/"]
  });
  const ids = result.findings.map((finding) => finding.id);
  assert.ok(ids.includes("COOKIE-001"));
  assert.ok(ids.includes("COOKIE-002"));
});

test("robots.txt sensitive path disclosure is flagged", () => {
  const result = analyzeRobots("User-agent: *\nDisallow: /api/\nDisallow: /admin/\nAllow: /");
  assert.ok(result.findings.some((finding) => finding.id === "ROBOTS-001"));
  assert.deepEqual(result.sensitivePaths.sort(), ["/admin/", "/api/"]);
});

test("scoring grades a clean report as A", () => {
  const score = scoreFindings([]);
  assert.equal(score.score, 100);
  assert.equal(score.grade, "A");
});

test("markdown renderer includes evidence and scope", () => {
  const result = {
    target: "https://example.test/",
    finalUrl: "https://example.test/",
    scannedAt: new Date().toISOString(),
    findings: [
      {
        id: "CSP-001",
        title: "Content-Security-Policy is not set",
        severity: "high",
        category: "Browser hardening",
        evidence: "No CSP header",
        impact: "Script injection is easier",
        recommendation: "Add a nonce-based CSP"
      }
    ],
    checks: [{ name: "CSP", status: "fail", detail: "missing" }],
    tls: { protocol: "TLSv1.3", cipher: "TLS_AES_128_GCM_SHA256", cert: { subject: "CN=example.test" } },
    httpRedirect: { status: 308, location: "https://example.test/" },
    performance: { scriptCount: 1, styleCount: 1, assets: [] },
    files: []
  };
  const markdown = renderMarkdown(result);
  assert.match(markdown, /CSP-001/);
  assert.match(markdown, /Scope and limitations/);
});
