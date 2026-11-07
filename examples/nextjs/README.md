# Next.js hardening reference

These files are drop-in reference implementations for the actual Cynbit stack. They are not a standalone app: copy the files into the existing Next.js App Router projects and wire the imports, database, and environment variables.

Prerequisites: Node.js 20.19+, 22.12+, or 24+ and Next.js 16. The reference uses Next.js 16 `proxy.ts`, Prisma 7, React 19, and the Next.js App Router.

## What is included

| File | Purpose |
| --- | --- |
| `next.config.mjs` | Baseline headers, server action origin allowlist, body cap, no `x-powered-by` |
| `proxy.ts` | Per-request CSP nonce, strict headers, rate limiting (named `middleware.ts` on Next.js 15) |
| `lib/rate-limit.ts` | Redis-backed sliding window with in-memory fallback |
| `lib/validation.ts` | Strict schemas for every public form and auth action |
| `lib/passwords.ts` | Argon2id hashing and single-use setup tokens |
| `lib/auth.ts` | Signed `HttpOnly` session cookie and session reader |
| `lib/cashfree.ts` | Server-side order creation and webhook signature verification |
| `lib/crypto.ts` | AES-256-GCM protection for tokens waiting in the outbox |
| `lib/prisma.ts` | Prisma 7 singleton using the `pg` driver adapter |
| `app/actions/forms.ts` | Contact, newsletter, and diary Server Actions |
| `app/actions/checkout.ts` | Server-priced checkout; no client-controlled amount |
| `app/actions/auth.ts` | Login, set-password, and logout |
| `app/api/payments/cashfree/webhook/route.ts` | Signed, idempotent fulfilment |
| `app/api/cron/outbox/route.ts` | Crash-safe setup email delivery |
| `app/api/csp-report/route.ts` | Bounded CSP report sink |
| `app/set-password/page.tsx` | Fragment-based setup page that clears the token from history |
| `lib/privacy.ts` | Email masking and PII redaction helper for logs |
| `prisma/schema.prisma` | Orders, users, setup tokens, webhook events, outbox, audit events |
| `prisma.config.ts` | Prisma 7 CLI datasource and migration configuration |

## Wiring steps

1. Copy `lib/`, `proxy.ts`, and the relevant `app/` routes into the portal project. On Next.js 15, rename `proxy.ts` to `middleware.ts` and the exported function to `middleware`.
2. Copy `.env.example` values into your secret manager. Never commit real values.
3. Install dependencies, add the Prisma models, run `npx prisma generate`, then run `npx prisma migrate dev`. Prisma 7 reads `DATABASE_URL` from `prisma.config.ts` and connects through `@prisma/adapter-pg`.
4. Replace `from` and destination addresses in the email helpers.
5. Remove the old `verifyBitelevatePayment` client provisioning path. Provision only from the webhook.
6. Point the Cashfree webhook URL at `/api/payments/cashfree/webhook`. Cashfree signs with the PG client secret, so keep that secret available to the handler and rotate it only after in-flight events drain.
7. Schedule `/api/cron/outbox` every minute with a bearer `CRON_SECRET`.
8. Put the set-password page at `/set-password`. It reads `location.hash`, clears the fragment, and POSTs the token to `setPassword`.
9. Run `npm run typecheck` and the repository root `npm test`. Add ESLint with the Next.js 16 ESLint CLI configuration if the portal already uses linting.

## Important implementation notes

- **Prisma 7.** The generated client lives in `generated/prisma` and is ignored by git. Run `npx prisma generate` after every schema change. Prisma 7 requires a driver adapter; the reference uses `@prisma/adapter-pg` with `pg`.
- **CSP nonce.** Next.js consumes the `x-nonce` request header for its own scripts. If a third-party script is needed, pass the nonce explicitly or load it through a consent-gated server container.
- **Inline styles.** The reference allows `'unsafe-inline'` for `style-src` because Next.js injects inline styles. Scripts remain nonce-bound with `'strict-dynamic'`. Replace style allowances with hashes or nonces when the app stops using inline style injection.
- **Cashfree payloads.** The webhook schema matches the common `data.order` and `data.payment` shape. Confirm the exact payload version in the Cashfree dashboard and extend the schema rather than trusting unvalidated fields.
- **Cashfree signature.** The signature is `base64(HMAC-SHA256(timestamp + rawBody))` with no separator, keyed by the PG client secret. The timestamp header is in milliseconds; the reference accepts seconds as well for older integrations. Always verify over the raw request body, before JSON parsing.
- **Amounts.** Cashfree sends `order_amount` in major units. The database stores paise in `amountMinor`; the handler multiplies by 100 and rounds. Verify this against live events before relying on it.
- **Idempotency.** `WebhookEvent` has a unique constraint on `(provider, providerEventId)`. The event ID prefers Cashfree's `x-idempotency-key` and otherwise combines event type, payment ID, and payment status. Duplicate deliveries return `200` and do not resend email or create users.
- **Outbox encryption.** The setup token is encrypted with `APP_SECRET` while it waits for delivery. The worker decrypts it only to build the email. Rotate `APP_SECRET` with a key-versioning strategy before changing it in production.
- **Setup links.** The email uses `/set-password#token=...`. The fragment is not sent in the `Referer` header. The page must clear the fragment after reading it and must not load analytics.
- **Rate limiting.** The in-memory fallback is only for local development and single-instance previews. Production must set Upstash/Vercel KV variables so limits hold across serverless instances.
- **Fail-open behavior.** The Redis helper falls back to memory on network failure to preserve availability. For login and payment endpoints, consider failing closed and alerting instead.
- **Sessions.** The reference uses a short-lived signed `HttpOnly` cookie. The `Session` table is included for deployments that need immediate revocation or a device list; store only token hashes and check them in `getSession` before authorizing sensitive actions.
- **Account status.** New accounts stay `PENDING_SETUP` until the setup token is consumed. Login requires `ACTIVE`.
- **Audit data.** Audit events store identifiers and actions, not form payloads. Keep it that way.
