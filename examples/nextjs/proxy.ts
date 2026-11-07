import { NextRequest, NextResponse } from "next/server";
import { rateLimit, clientIp } from "./lib/rate-limit";

function createNonce() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function csp(nonce: string) {
  return [
    "default-src 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    "img-src 'self' data: https://images.unsplash.com https://www.google-analytics.com",
    "font-src 'self'",
    `style-src 'self' 'unsafe-inline'`,
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic' https://www.googletagmanager.com https://sdk.cashfree.com`,
    "connect-src 'self' https://www.google-analytics.com https://region1.google-analytics.com https://sdk.cashfree.com https://api.cashfree.com https://sandbox.cashfree.com",
    "frame-src https://sdk.cashfree.com https://api.cashfree.com https://sandbox.cashfree.com",
    "upgrade-insecure-requests",
    "report-uri /api/csp-report"
  ].join("; ");
}

function withHeaders(response: NextResponse, headers: Record<string, string>) {
  for (const [name, value] of Object.entries(headers)) response.headers.set(name, value);
  return response;
}

function baseHeaders(nonce: string, pathname: string) {
  return {
    "Content-Security-Policy": csp(nonce),
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": pathname.startsWith("/set-password")
      ? "no-referrer"
      : "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin"
  };
}

export async function proxy(request: NextRequest) {
  const nonce = createNonce();
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);

  const pathname = request.nextUrl.pathname;
  const mutating = request.method !== "GET" && request.method !== "HEAD";
  const sensitive = pathname.startsWith("/api/") || pathname.startsWith("/intern-portal/login");

  if (mutating || pathname.startsWith("/api/payments/")) {
    const ip = clientIp(request);
    const isWebhook = pathname === "/api/payments/cashfree/webhook";
    const limit = await rateLimit(
      `${isWebhook ? "webhook" : sensitive ? "sensitive" : "mutation"}:${ip}`,
      isWebhook ? 240 : sensitive ? 10 : 60,
      60
    );
    if (!limit.allowed) {
      const blocked = NextResponse.json(
        { error: { code: "rate_limited" } },
        {
          status: 429,
          headers: {
            "Retry-After": String(limit.retryAfterSeconds),
            "RateLimit-Limit": String(limit.limit),
            "RateLimit-Remaining": String(limit.remaining)
          }
        }
      );
      return withHeaders(blocked, baseHeaders(nonce, pathname));
    }
  }

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  return withHeaders(response, baseHeaders(nonce, pathname));
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|logo.svg).*)"]
};
