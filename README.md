# Cynbit Security Audit and Hardening Kit

A passive, read-only security assessment of Cynbit's public web properties, plus a working reference implementation of the controls the assessment recommends.

- **Target:** `https://www.cynbit.in`, `https://cynbit.in`, `https://bitelevate.cynbit.in`
- **Assessment date:** 2026-11-07
- **Method:** public HTML, JavaScript, headers, DNS, TLS, robots.txt, and sitemap inspection only
- **Constraints:** no authentication, form submissions, payment initiation, fuzzing, exploitation, or private-system access
- **Overall risk:** High

## Why this repository exists

The site has a strong transport baseline: TLS 1.3, modern ciphers, HTTP-to-HTTPS redirects, HSTS, immutable asset caching, and no public source maps. The risk sits in the application and operational layers:

1. The public BitElevate flow expects a plaintext `bitElevateCredentials` object containing `email` and `password`, renders it as a temporary password, and copies it to the clipboard.
2. DMARC is `p=none` with no reporting addresses, Microsoft 365 DKIM selectors are absent, and apex SPF does not align with Microsoft 365 inbound mail.
3. No Content-Security-Policy exists while Google Tag Manager, Google Fonts, Cashfree, and other third parties execute on the same origin.

This repository documents the evidence, provides a prioritized remediation plan, and implements a working alternative for the payment and credential flow.

## What is inside

| Path | Contents |
| --- | --- |
| `audit/AUDIT_REPORT.md` | Full findings, evidence, impact, recommendations, and limitations |
| `audit/evidence/` | Captured headers, DNS/email records, TLS details, public surface map, scanner outputs |
| `recommendations/RECOMMENDATIONS.md` | Target architecture, benchmarks, hardening checklist, rollout sequence |
| `src/scanner/` | Zero-dependency passive posture scanner used to generate the evidence reports |
| `src/hardening/` | Working Node.js reference server for headers, validation, rate limits, payments, auth, and logging |
| `examples/nextjs/` | Drop-in Next.js, Prisma, Cashfree, and outbox reference files for the real stack |
| `test/` | 25 security regression tests using the built-in `node:test` runner |
| `scripts/demo.mjs` | End-to-end payment, credential setup, and login demonstration |
| `docs/SUBMISSION.md` | Paste-ready submission entries |

## Quick start

Requires Node.js 18.17 or newer. No runtime dependencies are needed for the audit, scanner, prototype, tests, or demo.

```bash
npm test
npm run demo
```

Run the scanner against a public target:

```bash
node src/scanner/index.mjs https://www.cynbit.in --out audit/evidence
```

The scanner writes `scan-report.md`, `scan-report.json`, and `scan-summary.txt`. It performs a single read-only `GET` plus DNS and TLS inspection. It does not submit forms, authenticate, fuzz, or attempt exploitation.

## Audit results at a glance

| ID | Severity | Finding |
| --- | --- | --- |
| H-1 | High / potential Critical | Payment return path expects a plaintext temporary password in the browser; payment binding must be proven server-side |
| H-2 | High | DMARC `p=none`, no reporting, no Microsoft 365 DKIM visible, SPF not aligned with inbound mail |
| H-3 | High | No CSP on the marketing site or portal while third-party scripts execute |
| M-1 | Medium | Missing baseline headers; HSTS lacks `includeSubDomains`/`preload`; `X-Powered-By` leaks |
| M-2 | Medium | Wildcard `Access-Control-Allow-Origin: *` on document routes |
| M-3 | Medium | No visible bot/rate-limit controls on public mutations |
| M-4 | Medium | Privacy and DPDP practices need retention, consent, and data-flow documentation |
| L-1 | Low | `robots.txt` advertises `/api/`, `/admin/`, and `/portal/` |
| L-2 | Low | No `security.txt` or vulnerability disclosure policy |
| L-3 | Low | No CAA, DNSSEC, MTA-STS, or TLS-RPT |
| L-4 | Low | Sitemap canonical and `lastmod` inconsistencies |
| L-5 | Info | Framework fingerprinting from `X-Powered-By` and asset paths |

Automated posture scores from the scanner:

- `www.cynbit.in`: **35/100 (F)**, 11 findings
- `bitelevate.cynbit.in`: **38/100 (F)**, 10 findings

The automated score measures header and DNS hygiene, not exploitability. It should be read alongside the manual report.

## Working hardening reference

`src/hardening/server.mjs` demonstrates:

- Nonce-based CSP with `strict-dynamic`
- Strict baseline headers, including HSTS `includeSubDomains; preload`
- No wildcard CORS
- Per-route sliding-window rate limits with `429` and `Retry-After`
- Content-type and body-size enforcement
- Server-side schema validation and normalization
- Honeypot handling
- Server-side product catalog and pricing
- HMAC-signed webhook with a timestamp tolerance
- Idempotent fulfilment protected by a unique event ID
- One-time, expiring setup tokens; no password in any response
- Argon2-class password hashing in the Next.js reference and scrypt in the zero-dependency demo
- `HttpOnly`, `SameSite=Lax` session cookies
- Generic authentication errors and PII-redacted logs

Run `npm run demo` to see the full flow. The test suite proves the negative cases: bad signature, amount tampering, stale replay, token reuse, weak password, oversized body, and rate-limit enforcement.

## Applying it to production

The Next.js 16 / Prisma 7 reference under `examples/nextjs/` maps the prototype to the observed stack. It requires Node.js 20.19+, 22.12+, or 24+ and its dependencies are audited clean at the time of writing:

- `proxy.ts` for nonce-based CSP and rate limits (`middleware.ts` on Next.js 15)
- `lib/validation.ts` for strict Server Action schemas
- `lib/passwords.ts` for Argon2id and setup tokens
- `app/actions/checkout.ts` for server-priced orders
- `app/api/payments/cashfree/webhook/route.ts` for signed, idempotent fulfilment
- `app/api/cron/outbox/route.ts` for crash-safe email delivery
- `prisma/schema.prisma` for orders, users, setup tokens, webhook events, outbox, and audit events

See `examples/nextjs/README.md` for wiring notes and known differences between the reference and a live deployment.

## Remediation order

1. Remove plaintext credentials and client-trusted payment verification. Provision only from a signed webhook; use one-time setup links.
2. Enable Microsoft 365 DKIM, align SPF, add DMARC reporting, then move to `quarantine` and `reject`.
3. Ship CSP in report-only mode, remove analytics from auth and payment routes, then enforce.
4. Add baseline headers, remove wildcard CORS, and fix HSTS flags.
5. Add validation, rate limits, Turnstile, and body caps to every public mutation.
6. Publish retention and consent practices, redact logs, and encrypt sensitive fields.
7. Add monitoring, a disclosure policy, reconciliation, and an independent penetration test.

The full sequence, benchmarks, and checklists are in `recommendations/RECOMMENDATIONS.md`.

## Scope and limitations

- Only public, unauthenticated surfaces were reviewed.
- No server code, database, logs, cloud configuration, or private portal area was accessed.
- No form was submitted and no payment was initiated.
- Findings marked "verify internally" require access to server code or configuration.
- The scanner is a hygiene tool, not a substitute for manual review or a penetration test.
- PageSpeed Insights quota was exhausted during the assessment; performance observations come from direct request measurements.

## Responsible use

This work is intended for Cynbit's own assessment and remediation. Do not use the scanner or techniques in this repository against systems you do not own or have written permission to test. See `SECURITY.md` for disclosure guidance.

## License

MIT. See `LICENSE`.
