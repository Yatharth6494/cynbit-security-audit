import http from "node:http";
import { randomUUID } from "node:crypto";
import { createStore } from "./store.mjs";
import { createLogger } from "./logger.mjs";
import { SlidingWindowLimiter, clientIp, rateLimitHeaders } from "./rate-limit.mjs";
import {
  applySecurityHeaders,
  createNonce,
  sessionCookie,
  clearSessionCookie
} from "./security.mjs";
import {
  validateContact,
  validateNewsletter,
  validateDiary,
  validateCheckout,
  validateSetPassword,
  validateLogin
} from "./validation.mjs";
import {
  hashPassword,
  verifyPassword,
  newToken,
  hashToken,
  signSession,
  verifySession,
  verifyWebhookSignature
} from "./crypto.mjs";

export const PRODUCTS = {
  bitelevate: {
    id: "bitelevate",
    name: "BitElevate 60-Day Sprint",
    amount: 399900,
    currency: "INR"
  }
};

const SESSION_COOKIE = "cynbit_session";
const JSON_LIMIT = 16 * 1024;
const WEBHOOK_LIMIT = 64 * 1024;
const SETUP_TOKEN_TTL_MS = 24 * 60 * 60 * 1000;

let dummyHash = null;

function dummyPasswordHash() {
  if (!dummyHash) dummyHash = hashPassword("not-a-real-password-123");
  return dummyHash;
}

function getCookie(request, name) {
  const header = request.headers.cookie || "";
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    const key = part.slice(0, index).trim();
    if (key === name) return part.slice(index + 1).trim();
  }
  return null;
}

function originAllowed(request, allowedHosts) {
  const origin = request.headers.origin;
  if (!origin) return true;
  try {
    const parsed = new URL(origin);
    return parsed.host === request.headers.host || allowedHosts.has(parsed.hostname);
  } catch {
    return false;
  }
}

function readBody(request, limit) {
  return new Promise((resolve, reject) => {
    const declared = Number(request.headers["content-length"] || 0);
    if (declared > limit) {
      request.resume();
      reject(Object.assign(new Error("payload_too_large"), { status: 413 }));
      return;
    }
    let size = 0;
    const chunks = [];
    request.on("data", (chunk) => {
      size += chunk.length;
      if (size > limit) {
        request.pause();
        reject(Object.assign(new Error("payload_too_large"), { status: 413 }));
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => resolve(Buffer.concat(chunks)));
    request.on("error", reject);
  });
}

async function readJson(request, limit) {
  const raw = await readBody(request, limit);
  try {
    return JSON.parse(raw.toString("utf8") || "{}");
  } catch {
    throw Object.assign(new Error("invalid_json"), { status: 400 });
  }
}

function isJson(request) {
  return /^application\/json\b/i.test(String(request.headers["content-type"] || ""));
}

function defaultMailer(logger) {
  return {
    async send(message) {
      logger.info("mail.queued", {
        to: message.to,
        subject: message.subject,
        setupUrl: message.setupUrl
      });
    }
  };
}

function renderHome(nonce) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cynbit hardening reference</title>
<style nonce="${nonce}">
:root { color-scheme: dark; }
body { margin: 0; font-family: ui-sans-serif, system-ui, sans-serif; background: #0b0c10; color: #e8eaf0; }
main { max-width: 760px; margin: 0 auto; padding: 48px 24px; }
h1 { font-size: 28px; letter-spacing: -0.02em; }
p, li { color: #aab0c0; line-height: 1.6; }
code { background: #16181f; padding: 2px 6px; border-radius: 6px; color: #9ef0c0; }
pre { background: #16181f; padding: 16px; border-radius: 12px; overflow: auto; }
.status { display: inline-block; padding: 4px 10px; border-radius: 999px; background: #13301f; color: #7cf0a8; font-size: 12px; font-weight: 700; }
</style>
</head>
<body>
<main>
<span class="status">HARDENED REFERENCE</span>
<h1>Cynbit security hardening kit</h1>
<p>This server demonstrates the controls recommended in the audit: nonce-based CSP, strict security headers, server-side validation, rate limiting, HMAC webhook verification, server-side pricing, idempotency, and one-time credential setup.</p>
<ul>
<li><code>GET /healthz</code> liveness and store counters</li>
<li><code>POST /api/contact</code> validated inquiry</li>
<li><code>POST /api/payments/checkout</code> server-priced order</li>
<li><code>POST /api/payments/webhook</code> signed, idempotent fulfilment</li>
<li><code>POST /api/portal/set-password</code> single-use setup token</li>
<li><code>POST /api/portal/login</code> HttpOnly session cookie</li>
<li><code>GET /api/portal/me</code> session check</li>
</ul>
<pre id="stats">loading health…</pre>
<p>Run <code>npm test</code> for the security test suite and <code>npm run demo</code> for the end-to-end payment flow.</p>
</main>
<script nonce="${nonce}">
fetch("/healthz", { headers: { accept: "application/json" } })
  .then((response) => response.json())
  .then((data) => { document.getElementById("stats").textContent = JSON.stringify(data, null, 2); })
  .catch(() => { document.getElementById("stats").textContent = "health check failed"; });
</script>
</body>
</html>`;
}

export function createHardeningServer(options = {}) {
  const logger =
    options.logger ||
    createLogger({ sink: options.logSink, service: options.service || "cynbit-hardening" });
  const store = options.store || createStore();
  const mailer = options.mailer || defaultMailer(logger);
  const secret = options.secret || process.env.APP_SECRET || "dev-app-secret-change-me";
  const webhookSecret =
    options.webhookSecret || process.env.CASHFREE_WEBHOOK_SECRET || "dev-webhook-secret-change-me";
  const secureCookies = options.secureCookies ?? false;
  const publicOrigin = options.publicOrigin || null;
  const allowedHosts = new Set(options.allowedHosts || ["localhost", "127.0.0.1", "::1"]);
  const rateLimits = options.rateLimits || {};

  const limiters = {
    mutation: new SlidingWindowLimiter({ max: rateLimits.mutation ?? 60 }),
    contact: new SlidingWindowLimiter({ max: rateLimits.contact ?? 5 }),
    checkout: new SlidingWindowLimiter({ max: rateLimits.checkout ?? 5 }),
    auth: new SlidingWindowLimiter({ max: rateLimits.auth ?? 10 }),
    webhook: new SlidingWindowLimiter({ max: rateLimits.webhook ?? 240 })
  };

  const server = http.createServer(async (request, response) => {
    const started = Date.now();
    const requestId = randomUUID();
    const ip = clientIp(request);
    const url = new URL(request.url || "/", `http://${request.headers.host || "localhost"}`);
    const nonce = createNonce();
    const htmlRoute = request.method === "GET" && (url.pathname === "/" || url.pathname === "/demo");

    if (htmlRoute) applySecurityHeaders(response, { nonce, html: true });
    else applySecurityHeaders(response, { nonce: null, html: false });
    response.setHeader("X-Request-Id", requestId);

    response.on("finish", () => {
      logger.info("request.completed", {
        requestId,
        method: request.method,
        path: url.pathname,
        status: response.statusCode,
        ip,
        durationMs: Date.now() - started
      });
    });

    const sendJson = (status, body, extraHeaders = {}) => {
      response.writeHead(status, {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
        ...extraHeaders
      });
      response.end(JSON.stringify(body));
    };
    const sendError = (status, code, extraHeaders = {}) =>
      sendJson(status, { error: { code, requestId } }, extraHeaders);
    const applyLimit = (policy, key) => {
      const result = limiters[policy].check(key);
      for (const [name, value] of Object.entries(rateLimitHeaders(result))) {
        response.setHeader(name, value);
      }
      return result;
    };

    try {
      if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/demo")) {
        response.writeHead(200, {
          "Content-Type": "text/html; charset=utf-8",
          "Cache-Control": "no-store"
        });
        response.end(renderHome(nonce));
        return;
      }

      if (request.method === "GET" && url.pathname === "/healthz") {
        sendJson(200, { status: "ok", uptime: process.uptime(), stats: store.stats() });
        return;
      }

      if (request.method === "GET" && url.pathname === "/api/portal/me") {
        const token = getCookie(request, SESSION_COOKIE);
        const session = verifySession(token, secret);
        if (!session) return sendError(401, "unauthenticated");
        const user = store.getUser(session.sub);
        if (!user) return sendError(401, "unauthenticated");
        return sendJson(200, {
          email: user.email,
          fullName: user.fullName,
          status: user.status
        });
      }

      if (request.method === "POST" && url.pathname === "/api/contact") {
        if (!originAllowed(request, allowedHosts)) return sendError(403, "origin_not_allowed");
        if (!isJson(request)) return sendError(415, "unsupported_media_type");
        const limit = applyLimit("contact", `${ip}:contact`);
        if (!limit.allowed) return sendError(429, "rate_limited");
        const body = await readJson(request, JSON_LIMIT);
        const parsed = validateContact(body);
        if (!parsed.ok) {
          if (parsed.bot) return sendJson(200, { ok: true });
          return sendJson(400, {
            error: { code: "validation_failed", fields: parsed.errors, requestId }
          });
        }
        store.addInquiry(parsed.value);
        await mailer.send({
          to: "opportunities@cynbit.in",
          replyTo: parsed.value.email,
          subject: "New project inquiry",
          text: `${parsed.value.fullName} (${parsed.value.company || "individual"}) requested contact.`
        });
        return sendJson(200, { ok: true });
      }

      if (request.method === "POST" && url.pathname === "/api/newsletter") {
        if (!originAllowed(request, allowedHosts)) return sendError(403, "origin_not_allowed");
        if (!isJson(request)) return sendError(415, "unsupported_media_type");
        const limit = applyLimit("mutation", `${ip}:newsletter`);
        if (!limit.allowed) return sendError(429, "rate_limited");
        const body = await readJson(request, JSON_LIMIT);
        const parsed = validateNewsletter(body);
        if (!parsed.ok) {
          if (parsed.bot) return sendJson(200, { ok: true });
          return sendJson(400, {
            error: { code: "validation_failed", fields: parsed.errors, requestId }
          });
        }
        store.addSubscriber(parsed.value.email);
        return sendJson(200, { ok: true });
      }

      if (request.method === "POST" && url.pathname === "/api/diary") {
        if (!originAllowed(request, allowedHosts)) return sendError(403, "origin_not_allowed");
        if (!isJson(request)) return sendError(415, "unsupported_media_type");
        const limit = applyLimit("mutation", `${ip}:diary`);
        if (!limit.allowed) return sendError(429, "rate_limited");
        const body = await readJson(request, JSON_LIMIT);
        const parsed = validateDiary(body);
        if (!parsed.ok) {
          if (parsed.bot) return sendJson(200, { ok: true });
          return sendJson(400, {
            error: { code: "validation_failed", fields: parsed.errors, requestId }
          });
        }
        store.addDiary(parsed.value);
        return sendJson(202, { ok: true, status: "PENDING_REVIEW" });
      }

      if (request.method === "POST" && url.pathname === "/api/payments/checkout") {
        if (!originAllowed(request, allowedHosts)) return sendError(403, "origin_not_allowed");
        if (!isJson(request)) return sendError(415, "unsupported_media_type");
        const limit = applyLimit("checkout", `${ip}:checkout`);
        if (!limit.allowed) return sendError(429, "rate_limited");
        const body = await readJson(request, JSON_LIMIT);
        const parsed = validateCheckout(body);
        if (!parsed.ok) {
          if (parsed.bot) return sendJson(200, { ok: true });
          return sendJson(400, {
            error: { code: "validation_failed", fields: parsed.errors, requestId }
          });
        }
        const product = PRODUCTS.bitelevate;
        const orderId = `ord_${randomUUID().replace(/-/g, "")}`;
        store.createOrder({
          id: orderId,
          email: parsed.value.email,
          fullName: parsed.value.fullName,
          productId: product.id,
          amount: product.amount,
          currency: product.currency,
          application: parsed.value
        });
        logger.info("checkout.created", {
          requestId,
          orderId,
          amount: product.amount,
          currency: product.currency
        });
        return sendJson(201, {
          orderId,
          product: product.name,
          amount: product.amount,
          currency: product.currency
        });
      }

      if (request.method === "POST" && url.pathname === "/api/payments/webhook") {
        const limit = applyLimit("webhook", `${ip}:webhook`);
        if (!limit.allowed) return sendError(429, "rate_limited");
        const raw = (await readBody(request, WEBHOOK_LIMIT)).toString("utf8");
        const timestamp = request.headers["x-webhook-timestamp"];
        const signature = request.headers["x-webhook-signature"];
        const verification = verifyWebhookSignature(webhookSecret, timestamp, raw, signature);
        if (!verification.ok) {
          logger.warn("webhook.rejected", { requestId, reason: verification.reason });
          return sendError(401, "invalid_signature");
        }
        let event;
        try {
          event = JSON.parse(raw);
        } catch {
          return sendError(400, "invalid_json");
        }
        const eventId = String(event.eventId || event.id || "");
        const orderId = String(event.orderId || event.order_id || "");
        const amount = Number(event.amount);
        const currency = String(event.currency || "");
        const status = String(event.status || "").toUpperCase();
        if (!eventId || !orderId || !Number.isFinite(amount) || !currency) {
          return sendError(400, "invalid_event");
        }
        if (store.hasWebhookEvent(eventId)) {
          return sendJson(200, { received: true, duplicate: true });
        }
        const order = store.getOrder(orderId);
        if (!order) return sendError(404, "order_not_found");
        if (amount !== order.amount || currency !== order.currency) {
          logger.warn("webhook.amount_mismatch", {
            requestId,
            orderId,
            expected: order.amount,
            received: amount
          });
          return sendError(400, "amount_mismatch");
        }
        if (status !== "PAID") {
          return sendError(400, "payment_not_completed");
        }
        if (order.status === "FULFILLED") {
          return sendJson(200, { received: true, duplicate: true });
        }
        let user = store.getUser(order.email);
        if (!user) {
          user = store.createUser({ email: order.email, fullName: order.fullName });
        }
        const setupToken = newToken();
        store.createSetupToken(hashToken(setupToken), order.email, Date.now() + SETUP_TOKEN_TTL_MS);
        const origin = publicOrigin || `http://${request.headers.host}`;
        const setupUrl = `${origin}/set-password?token=${setupToken}`;
        await mailer.send({
          to: order.email,
          subject: "Your BitElevate portal setup link",
          text: "Use the single-use link to set your portal password. It expires in 24 hours.",
          setupUrl
        });
        store.addWebhookEvent(eventId);
        store.markFulfilled(orderId);
        logger.info("payment.fulfilled", {
          requestId,
          orderId,
          email: order.email,
          amount: order.amount
        });
        return sendJson(200, { received: true });
      }

      if (request.method === "POST" && url.pathname === "/api/portal/set-password") {
        if (!originAllowed(request, allowedHosts)) return sendError(403, "origin_not_allowed");
        if (!isJson(request)) return sendError(415, "unsupported_media_type");
        const limit = applyLimit("auth", `${ip}:set-password`);
        if (!limit.allowed) return sendError(429, "rate_limited");
        const body = await readJson(request, JSON_LIMIT);
        const parsed = validateSetPassword(body);
        if (!parsed.ok) {
          return sendJson(400, {
            error: { code: "validation_failed", fields: parsed.errors, requestId }
          });
        }
        const record = store.consumeSetupToken(hashToken(parsed.value.token));
        if (!record) return sendError(400, "invalid_or_expired_token");
        const user = store.getUser(record.email);
        if (!user) return sendError(400, "invalid_or_expired_token");
        store.setPassword(user.email, hashPassword(parsed.value.password));
        logger.info("auth.password_set", { requestId, email: user.email });
        return sendJson(200, { ok: true });
      }

      if (request.method === "POST" && url.pathname === "/api/portal/login") {
        if (!originAllowed(request, allowedHosts)) return sendError(403, "origin_not_allowed");
        if (!isJson(request)) return sendError(415, "unsupported_media_type");
        const body = await readJson(request, JSON_LIMIT);
        const parsed = validateLogin(body);
        if (!parsed.ok) {
          return sendJson(400, {
            error: { code: "validation_failed", fields: parsed.errors, requestId }
          });
        }
        const limit = applyLimit("auth", `${ip}:${parsed.value.email}`);
        if (!limit.allowed) return sendError(429, "rate_limited");
        const user = store.getUser(parsed.value.email);
        const valid =
          user && user.passwordHash
            ? verifyPassword(parsed.value.password, user.passwordHash)
            : verifyPassword(parsed.value.password, dummyPasswordHash());
        if (!user || !user.passwordHash || !valid) {
          logger.warn("auth.login_failed", { requestId, email: parsed.value.email });
          return sendError(401, "invalid_credentials");
        }
        const expiresAt = Math.floor(Date.now() / 1000) + 7200;
        const token = signSession({ sub: user.email, exp: expiresAt }, secret);
        logger.info("auth.login_success", { requestId, email: user.email });
        return sendJson(
          200,
          { ok: true, user: { email: user.email, fullName: user.fullName } },
          { "Set-Cookie": sessionCookie(SESSION_COOKIE, token, { secure: secureCookies, maxAge: 7200 }) }
        );
      }

      if (request.method === "POST" && url.pathname === "/api/portal/logout") {
        return sendJson(200, { ok: true }, { "Set-Cookie": clearSessionCookie(SESSION_COOKIE) });
      }

      if (request.method === "POST" && url.pathname === "/api/csp-report") {
        request.resume();
        response.writeHead(204);
        response.end();
        return;
      }

      if (request.method === "OPTIONS") {
        response.setHeader("Allow", "GET, POST, OPTIONS");
        response.writeHead(204);
        response.end();
        return;
      }

      return sendError(404, "not_found");
    } catch (error) {
      request.resume();
      if (error.status && error.status < 500) return sendError(error.status, error.message);
      logger.error("request.failed", {
        requestId,
        path: url.pathname,
        error: error.message
      });
      return sendError(500, "internal_error");
    }
  });

  const start = (port = 0, host = "127.0.0.1") =>
    new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(port, host, () => {
        const address = server.address();
        resolve({ port: address.port, url: `http://${host}:${address.port}` });
      });
    });

  const stop = () =>
    new Promise((resolve, reject) => {
      if (!server.listening) return resolve();
      server.close((error) => (error ? reject(error) : resolve()));
    });

  return { server, start, stop, store, config: { secureCookies, publicOrigin, webhookSecret } };
}
