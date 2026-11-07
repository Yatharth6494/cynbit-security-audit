import { randomBytes } from "node:crypto";

export function createNonce() {
  return randomBytes(16).toString("base64");
}

export function buildCsp(nonce, options = {}) {
  const reportUri = options.reportUri || "/api/csp-report";
  if (!nonce) {
    return [
      "default-src 'none'",
      "base-uri 'none'",
      "form-action 'none'",
      "frame-ancestors 'none'"
    ].join("; ");
  }
  return [
    "default-src 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    "img-src 'self' data:",
    "font-src 'self'",
    `style-src 'self' 'nonce-${nonce}'`,
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`,
    "connect-src 'self'",
    "upgrade-insecure-requests",
    `report-uri ${reportUri}`
  ].join("; ");
}

export function securityHeaders(options = {}) {
  const { nonce, html = false, hsts = true } = options;
  const headers = {
    "Content-Security-Policy": buildCsp(html ? nonce : null),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": html ? "no-referrer" : "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "X-DNS-Prefetch-Control": "off",
    "X-Permitted-Cross-Domain-Policies": "none",
    "Origin-Agent-Cluster": "?1"
  };
  if (hsts) {
    headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload";
  }
  return headers;
}

export function applySecurityHeaders(response, options = {}) {
  for (const [name, value] of Object.entries(securityHeaders(options))) {
    response.setHeader(name, value);
  }
}

export function sessionCookie(name, value, options = {}) {
  const secure = options.secure ?? true;
  const maxAge = options.maxAge ?? 7200;
  const sameSite = options.sameSite ?? "Lax";
  const parts = [`${name}=${value}`, "Path=/", "HttpOnly", `SameSite=${sameSite}`, `Max-Age=${maxAge}`];
  if (secure) parts.push("Secure");
  return parts.join("; ");
}

export function clearSessionCookie(name) {
  return `${name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`;
}
