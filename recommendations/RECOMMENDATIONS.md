# Technical Recommendations

This document turns the audit findings into an engineering plan. It covers target architecture, benchmarks, production hardening, and the order of work. The working prototype under `src/hardening/` implements the core patterns; the drop-in Next.js files under `examples/nextjs/` show how to apply them to Cynbit's actual stack.

## 1. Principles

1. **Treat every Server Action as a public API.** The client bundle publishes action references. Validate, authorize, rate limit, and log every mutation on the server.
2. **Never trust the browser for money or identity.** Prices, product IDs, payment status, account state, and authorization decisions come from the server.
3. **Prefer short-lived, single-use secrets over reusable passwords.** Setup links, reset links, and payment claims should expire quickly and be consumed once.
4. **Contain blast radius.** CSP, least privilege, segmented keys, and per-route rate limits limit the damage from any single bug.
5. **Make abuse expensive and observable.** Rate limits, bot challenges, idempotency, quotas, and alerts are product features, not afterthoughts.
6. **Collect less, keep less, log less.** Data minimization and PII redaction reduce both breach impact and compliance burden.

## 2. Target architecture

```
Browser
  │  HTTPS, HSTS, CSP, SameSite cookies
  ▼
Vercel Edge / Firewall / WAF
  │  bot rules, geo/rate controls, request IDs
  ▼
Next.js App Router (www + bitelevate)
  ├─ marketing routes (static / ISR)
  ├─ Server Actions (validated, authorized, rate limited)
  ├─ Route Handlers (webhooks, health, CSP reports)
  └─ intern portal (session auth, RBAC)
        │
        ├─ PostgreSQL (Prisma)          orders, users, diaries, audit events
        ├─ Redis / Upstash              rate limits, idempotency, sessions
        ├─ Resend                       transactional email
        ├─ Cashfree                     hosted checkout + signed webhooks
        ├─ Object storage               uploads, exports (private, signed URLs)
        └─ Observability                structured logs, metrics, traces, alerts
```

Recommended separations:

- **Marketing site** and **portal** can remain separate deployments, but share one security baseline and one identity model.
- **Payment webhook** runs as a dedicated route handler with raw-body access, signature verification, and a database transaction. It must not depend on a user session.
- **Email sending** goes through an outbox table processed by a worker, not inline in the request path. This prevents lost emails and duplicate sends during retries.
- **Rate-limit state** lives in Redis, not process memory, so limits hold across serverless instances.

## 3. Benchmarks and targets

| Area | Target | Why |
| --- | --- | --- |
| Security headers | SecurityHeaders grade A; Mozilla Observatory A+ | Baseline browser hardening |
| CSP | Enforced, nonce + strict-dynamic, no `unsafe-inline`/`unsafe-eval`, zero unexplained reports | Script injection containment |
| HSTS | `max-age=63072000; includeSubDomains; preload` | No downgrade path |
| TLS | TLS 1.2+ only, TLS 1.3 preferred, valid chain, automated renewal, 21-day expiry alert | Transport integrity |
| Email auth | DMARC `p=reject`, aligned SPF and DKIM for every sender, aggregate reports monitored | Anti-spoofing |
| CAA/DNSSEC | CAA at apex and subdomains, DNSSEC enabled | Certificate and DNS integrity |
| Auth | Argon2id, 12+ char policy, breached-password block, MFA for staff/admin, session rotation | Account protection |
| Sessions | `HttpOnly`, `Secure`, `SameSite=Lax` or `Strict`, short TTL, server-side revocation | Session theft containment |
| Authorization | Deny by default; object-level checks on every portal resource; RBAC for staff | Prevent IDOR and privilege escalation |
| Payments | Server-side catalog, signed webhook, timestamp tolerance, idempotency, reconciliation job | Prevent bypass and double fulfilment |
| Rate limits | Contact/checkout 5/min/IP; login 10/min/IP+account; reset 3/hour/email; shared store | Abuse and cost control |
| Validation | 100% of Server Actions use a schema; reject unknown fields; body caps 16–64 KB | Input safety and DoS control |
| Data | Inventory complete, retention defined, PII redacted from logs, encryption at rest | DPDP/GDPR readiness |
| Availability | 99.9% monthly, error budget tracked | Product reliability |
| Recovery | RPO ≤ 15 min for orders, RTO ≤ 4 hours | Payment and account integrity |
| Performance | LCP < 2.5 s, INP < 200 ms, CLS < 0.1, TTFB < 800 ms on mobile | Core Web Vitals |
| Dependencies | No high/critical advisories; patch critical within 7 days, high within 30 | Supply chain |
| Incident response | Acknowledge security reports within 2 business days; contain critical within 24 hours | Trust and compliance |

Map the program to **OWASP ASVS Level 2** for the portal and payment flows. Use the **OWASP API Security Top 10 2023** for Server Actions and route handlers.

## 4. Security architecture patterns

### 4.1 Server Actions as an API boundary

Every action should follow the same pipeline:

1. Enforce `Content-Type` and method.
2. Check `Origin`/`Host` for browser-initiated requests. Configure `serverActions.allowedOrigins` explicitly.
3. Enforce a body-size limit.
4. Rate limit by IP, route, and account.
5. Validate with a schema. Reject unknown fields. Normalize strings. Enforce length caps.
6. Verify a bot token (Turnstile) for anonymous forms.
7. Authorize the authenticated user and the target object.
8. Execute inside a transaction when state changes span tables.
9. Write an audit event without PII.
10. Return a generic result. Do not leak stack traces or internal identifiers.

### 4.2 Payment state machine

Use explicit states and unique constraints:

```
CREATED ──signed webhook PAYMENT_PAID──▶ PAID ──provision──▶ FULFILLED
    │                                      │
    └──expire──▶ EXPIRED                   └──refund──▶ REFUNDED
```

Rules:

- The order ID, amount, currency, product, and buyer identity are created server-side.
- The webhook handler verifies the provider signature over the raw body and a timestamp within tolerance.
- A unique index on `(provider, provider_event_id)` makes replays no-ops.
- Fulfilment runs in one transaction: create or find user, create setup token hash, mark order fulfilled, enqueue outbox email.
- A reconciliation job compares provider settlement reports with local orders daily.
- Refunds and chargebacks transition state and revoke access through a documented runbook.

### 4.3 Credential delivery

Replace plaintext temporary passwords with:

- A 256-bit random setup token.
- Store only `sha256(token)` with `expires_at` and `used_at`.
- Email a link with a short expiry (15–30 minutes).
- Set the link page to `Referrer-Policy: no-referrer`, no analytics, and no third-party scripts.
- On use, set the password hash, mark the token used, revoke other sessions, and audit the event.
- Never log the token, password, or full setup URL.

For staff and administrators, require MFA and separate the admin plane from the customer portal.

### 4.4 Session model

- Prefer server-side sessions or short-lived signed tokens in `HttpOnly` cookies.
- Do not store access tokens in `localStorage` or `sessionStorage`.
- Rotate the session ID on login and privilege change.
- Provide "sign out all devices" and a session list in the portal.
- Set idle and absolute timeouts. For sensitive actions, re-authenticate.

### 4.5 Multi-tenant and object-level authorization

If the portal ever serves multiple organizations or cohorts:

- Scope every query by tenant/cohort ID derived from the session, never from a request parameter.
- Add tests that attempt cross-tenant reads and writes.
- Keep staff roles separate from student/intern roles. Audit role changes.

### 4.6 Data flow and privacy

- Build a field-level data map and classify each field.
- Collect only what the product needs. Phone and university should have a documented purpose.
- Keep UGC (diaries) in a separate table from identity data. Publish a redacted projection.
- Use an outbox for email and a retention job for deletions.
- Log identifiers, not payloads. Use a shared redaction function for every logger.
- Encrypt sensitive fields with a KMS-backed key. Rotate keys on a schedule.

### 4.7 Edge and WAF

- Enable Vercel Firewall/WAF rules for known bad bots, path probing, and volumetric bursts.
- Add a challenge for suspicious traffic before it reaches Server Actions.
- Keep a request ID from edge to logs and error responses.
- Do not rely on robots.txt or path obscurity. Enforce auth at the edge and in the app.

## 5. Production hardening checklist

### DNS, email, certificates

- [ ] Microsoft 365 DKIM enabled; `selector1`/`selector2` published.
- [ ] SPF includes every sender and ends with `-all`.
- [ ] DMARC `p=reject` with `rua`/`ruf`, strict alignment, and monitored reports.
- [ ] CAA at apex and all subdomains.
- [ ] DNSSEC enabled.
- [ ] MTA-STS and TLS-RPT published.
- [ ] Certificate renewal automated; expiry alerts at 21 and 7 days.
- [ ] Registry lock on the domain; registrar account protected with MFA.

### Edge and headers

- [ ] HSTS `includeSubDomains; preload` after subdomain audit.
- [ ] CSP enforced with nonce + strict-dynamic.
- [ ] `X-Content-Type-Options: nosniff`.
- [ ] `frame-ancestors 'none'` and `X-Frame-Options: DENY`.
- [ ] `Referrer-Policy: strict-origin-when-cross-origin`, `no-referrer` on sensitive routes.
- [ ] `Permissions-Policy` denies unused features.
- [ ] COOP and CORP set.
- [ ] `X-Powered-By` removed.
- [ ] CORS allowlist only; no wildcard on documents.
- [ ] WAF and bot rules enabled.
- [ ] Request IDs and structured access logs.

### Application

- [ ] Every Server Action has a schema and authorization check.
- [ ] Body-size caps and content-type checks.
- [ ] Shared rate limiter with Redis.
- [ ] Turnstile or equivalent on anonymous forms.
- [ ] Idempotency keys for payment and email side effects.
- [ ] Generic error responses; detailed errors only in logs.
- [ ] No secrets in `NEXT_PUBLIC_*`.
- [ ] `poweredByHeader: false`, strict TypeScript, lint and typecheck in CI.

### Authentication and authorization

- [ ] Argon2id password hashing.
- [ ] Breached-password check and password policy.
- [ ] MFA for staff and admin.
- [ ] Session rotation, revocation, idle timeout.
- [ ] HttpOnly/Secure/SameSite cookies.
- [ ] Generic login and reset responses.
- [ ] Rate limits on login, reset, and setup.
- [ ] Object-level authorization tests.
- [ ] Audit log for auth and privilege events.

### Payments

- [ ] Server-side product catalog and price.
- [ ] Signed webhook with raw-body verification and timestamp tolerance.
- [ ] Unique event ID and idempotent fulfilment.
- [ ] Transactional account provisioning.
- [ ] Outbox email delivery.
- [ ] Daily reconciliation with provider settlement.
- [ ] Refund and chargeback runbook.
- [ ] No credential returned to the browser.

### Data and privacy

- [ ] Data inventory and record of processing.
- [ ] Retention policy and automated deletion.
- [ ] Consent management; analytics gated.
- [ ] PII redaction in logs and error tracking.
- [ ] Encryption at rest and key rotation.
- [ ] Least-privilege database roles and audit queries.
- [ ] DPAs with every processor.
- [ ] Grievance officer and breach runbook.
- [ ] DPIA for the portal and payment flow.

### Supply chain and CI/CD

- [ ] Lockfile committed; install with `npm ci`.
- [ ] Dependency scanning (`npm audit`, Dependabot/Renovate).
- [ ] SAST and secret scanning.
- [ ] SBOM generated per release.
- [ ] Signed builds and protected branches.
- [ ] Preview deployments require auth and are `noindex`.
- [ ] Separate secrets per environment; rotation schedule.
- [ ] Least-privilege CI tokens.

### Observability and response

- [ ] Centralized logs with retention and access control.
- [ ] Metrics for 4xx/5xx, latency, rate-limit hits, webhook failures, and email failures.
- [ ] Alerts for payment anomalies, credential events, and spikes.
- [ ] Sentry or equivalent with PII scrubbing.
- [ ] Uptime and synthetic checks for login, checkout, and webhook.
- [ ] Backups tested; restore drill documented.
- [ ] Incident response plan with roles, contacts, and communication templates.
- [ ] `security.txt` and a monitored security mailbox.
- [ ] Vulnerability disclosure policy and safe harbor.

## 6. Concrete configurations

### 6.1 Headers (Next.js)

```js
const securityHeaders = [
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=(), usb=()" },
  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
  { key: "Cross-Origin-Resource-Policy", value: "same-origin" }
];

export default {
  poweredByHeader: false,
  async headers() {
    return [{ source: "/(.*)", headers: securityHeaders }];
  }
};
```

CSP belongs in `proxy.ts` (or `middleware.ts` on Next.js 15) because it needs a per-request nonce. See `examples/nextjs/proxy.ts`.

### 6.2 DMARC progression

```dns
_dmarc.cynbit.in.  TXT  "v=DMARC1; p=none; rua=mailto:dmarc@cynbit.in; ruf=mailto:dmarc@cynbit.in; fo=1; adkim=s; aspf=s; pct=100"
```

After 2–4 weeks of clean reports:

```dns
_dmarc.cynbit.in.  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@cynbit.in; fo=1; adkim=s; aspf=s; pct=100"
```

Then:

```dns
_dmarc.cynbit.in.  TXT  "v=DMARC1; p=reject; rua=mailto:dmarc@cynbit.in; ruf=mailto:dmarc@cynbit.in; fo=1; adkim=s; aspf=s; pct=100"
```

### 6.3 Server Action pipeline (pseudocode)

```js
export async function submitInquiry(formData) {
  assertSameOrigin();
  assertContentType("application/json");
  const ip = clientIp();
  const limit = await rateLimit(`contact:${ip}`, 5, 60);
  if (!limit.allowed) return { success: false, error: "Too many requests." };
  const parsed = contactSchema.safeParse(Object.fromEntries(formData));
  if (!parsed.success) return { success: false, error: "Check your input." };
  if (formData.get("website")) return { success: true };
  await verifyTurnstile(formData.get("cf-turnstile-response"), ip);
  await enqueueEmail("contact", parsed.data);
  return { success: true };
}
```

### 6.4 Payment webhook (pseudocode)

```js
const raw = await request.text();
const timestamp = request.headers.get("x-webhook-timestamp");
const signature = request.headers.get("x-webhook-signature");
if (!verifySignature(raw, timestamp, signature, process.env.CASHFREE_CLIENT_SECRET)) {
  return new Response("invalid signature", { status: 401 });
}
const event = schema.parse(JSON.parse(raw));
await db.$transaction(async (tx) => {
  const order = await tx.order.findUnique({ where: { id: event.orderId } });
  if (!order) throw new NotFound();
  if (order.amount !== event.amount || order.currency !== event.currency) throw new AmountMismatch();
  await tx.webhookEvent.create({ data: { providerEventId: event.id } });
  if (order.status === "FULFILLED") return;
  const user = await upsertUser(tx, order);
  const setup = createSetupToken();
  await tx.setupToken.create({ data: { userId: user.id, tokenHash: setup.hash, expiresAt: setup.expiresAt } });
  await tx.outbox.create({ data: { type: "SETUP_EMAIL", userId: user.id, tokenId: setup.id } });
  await tx.order.update({ where: { id: order.id }, data: { status: "FULFILLED" } });
});
return Response.json({ received: true });
```

### 6.5 Rate limiting with a shared store

Use Upstash Redis or Vercel KV:

```
INCR   rl:{route}:{ip}
EXPIRE rl:{route}:{ip} 60 NX
```

If the counter exceeds the limit, return `429` with `Retry-After`. For login, key on `ip + normalizedEmail`. For password reset, key on `email` and cap at 3/hour. For webhooks, rate limit by provider IP and keep signature verification mandatory.

## 7. How the prototype maps to the findings

| Finding | Prototype control | Test |
| --- | --- | --- |
| H-1 plaintext credentials | One-time setup token, hashed password, no password in responses, server-priced order | `test/payments.test.mjs` |
| H-1 payment bypass | HMAC webhook, timestamp tolerance, amount/currency check, idempotency | `test/payments.test.mjs` |
| H-2 email spoofing | Guidance and DNS snippets; not executable in code | Audit evidence and checklist |
| H-3 missing CSP | Nonce-based CSP with strict-dynamic, no analytics | `test/headers.test.mjs` |
| M-1 headers | Full baseline header set, HSTS flags, no x-powered-by | `test/headers.test.mjs` |
| M-2 CORS | No wildcard ACAO on any response | `test/headers.test.mjs` |
| M-3 abuse | Per-route sliding-window limits, 429 + Retry-After, body caps, honeypot | `test/rate-limit.test.mjs` |
| M-3 validation | Server-side schemas, normalization, length caps | `test/validation.test.mjs` |
| M-4 privacy | PII redaction in logs, no payload logging, no password/token logging | `test/validation.test.mjs` |
| M-4 auth | HttpOnly/SameSite session cookie, generic errors, hashed passwords | `test/payments.test.mjs` |
| L-2 disclosure | Guidance for security.txt | Checklist |

## 8. Rollout sequence

1. **Instrument first.** Add request IDs, structured logs, CSP report-only, DMARC `rua`, and rate-limit metrics. You cannot verify fixes without telemetry.
2. **Stop the bleeding.** Fix H-1 and add rate limits plus Turnstile. These are the highest-impact changes.
3. **Harden the browser.** Ship headers and CSP report-only. Remove analytics from auth and payment routes.
4. **Harden email.** Enable DKIM, align SPF, move DMARC to quarantine.
5. **Harden data.** Publish retention and deletion, add consent, redact logs, encrypt sensitive fields.
6. **Prove it.** Add the tests from this repository to CI and commission an independent penetration test of the portal and payment flow.
7. **Operate it.** Add alerts, a disclosure program, a reconciliation job, and quarterly access reviews.

## 9. Effort and impact

| Workstream | Effort | Impact | Priority |
| --- | --- | --- | --- |
| Payment/credential redesign | Medium–High | Very high | P0 |
| Email authentication | Low | High | P0 |
| Security headers + CSP | Low–Medium | High | P1 |
| Rate limits + Turnstile | Medium | High | P1 |
| Privacy/consent/retention | Medium–High | Medium–High | P1 |
| WAF + monitoring | Medium | Medium | P2 |
| DNSSEC/CAA/MTA-STS | Low | Medium | P2 |
| ASVS Level 2 review and pen test | High | High | P2 |
| Performance budget and font self-hosting | Low–Medium | Medium | P3 |
| Bug bounty/disclosure program | Medium | Medium | P3 |
