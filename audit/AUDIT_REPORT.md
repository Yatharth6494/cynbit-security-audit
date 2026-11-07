# Cynbit Public Surface Security Audit

- Assessment date: 2026-11-07
- Scope: `www.cynbit.in`, `cynbit.in`, `bitelevate.cynbit.in`, and public DNS/email records
- Method: passive, read-only inspection of publicly served HTML, JavaScript, CSS, headers, DNS, TLS, robots.txt, and sitemap
- Constraints: no authentication, no form submissions, no payment initiation, no fuzzing, no exploitation, no private-area access
- Overall risk: **High**

## 1. Executive summary

Cynbit runs a modern Next.js App Router marketing site and a separate BitElevate intern portal on Vercel. The transport layer is solid: TLS 1.3 is negotiated, TLS 1.0/1.1 are rejected, HTTP redirects to HTTPS, and static assets are immutable-cached with Brotli. Source maps are not publicly readable.

The two highest-risk areas are not infrastructure flaws. They are application design and operational controls:

1. **The public payment flow appears to return a plaintext temporary password to the browser.** Public client code expects a `bitElevateCredentials` object containing `email` and `password`, renders it as "Temporary Login Password", and offers to copy it to the clipboard. Payment return parameters (`order_id`, `token`) are read from the URL. Without internal verification, this is a potential account-takeover and payment-bypass path. Even with correct server checks, plaintext credential delivery through the DOM and clipboard is avoidable risk.
2. **Email anti-spoofing is not enforced.** DMARC is `p=none` with no reporting addresses. The apex SPF authorizes GoDaddy but not Microsoft 365, while inbound mail is Microsoft 365. No Microsoft 365 DKIM selectors were observed. Cynbit sends credentials and payment confirmations by email, which raises the impact of brand impersonation.

The third high-risk finding is the complete absence of a Content-Security-Policy, while Google Tag Manager, Google Fonts, Cashfree's SDK, and other third parties execute on the same origin. The portal login page also loads Google Tag Manager. CSP is the main containment control if any script or dependency is compromised.

The site also lacks baseline browser hardening headers, emits a wildcard `Access-Control-Allow-Origin: *` on document responses, advertises `/api/`, `/admin/`, and `/portal/` in robots.txt, has no vulnerability disclosure policy, and has data-handling documentation that does not yet meet the practical requirements of India's DPDP Act 2023.

### Top actions, in order

1. Remove plaintext password delivery. Provision accounts with a single-use, expiring setup link. Verify payment by signed webhook, not by a client-callable return URL alone. Keep price and product identifiers server-side. Make fulfilment idempotent.
2. Enforce DMARC. Publish Microsoft 365 DKIM, align SPF to every authorized sender, add `rua` reporting, move from `p=none` to `quarantine` and then `reject`.
3. Ship a nonce-based CSP in report-only mode, then enforce it. Remove Google Tag Manager from authenticated and payment pages, or gate it behind consent and a server-side container.
4. Add baseline headers: `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `frame-ancestors 'none'`, COOP, CORP, and HSTS `includeSubDomains; preload`.
5. Add abuse controls to every public mutation: server-side schema validation, per-IP and per-account rate limits, Turnstile, body-size caps, and idempotency. Remove wildcard CORS from document routes.

## 2. Attack surface and stack

| Layer | Observation |
| --- | --- |
| Edge | Vercel, HTTP/2, Brotli, edge cache (`x-vercel-cache: HIT`) |
| Framework | Next.js App Router with React Server Components and Server Actions (`/_next/static/`, `x-nextjs-prerender`) |
| Marketing hosts | `www.cynbit.in`, apex `cynbit.in` (307 to www) |
| Portal host | `bitelevate.cynbit.in` (307 from `/intern-portal/login`) |
| DNS | GoDaddy nameservers; `www` CNAME to Vercel; apex A to Vercel |
| Email inbound | Microsoft 365 (`cynbit-in.mail.protection.outlook.com`) |
| Email outbound | Resend DKIM on apex; Resend envelope domain `send.cynbit.in` on Amazon SES |
| Payments | Cashfree JS SDK v3, production mode selected by server response |
| Analytics | Google Tag Manager / GA4 `G-LK6CQWCWX0` on marketing and portal login |
| Fonts | Google Fonts Material Symbols (external, render-blocking CSS) |
| Storage/orchestration named in privacy policy | Resend for email, Prisma for database |

### Public mutation surface

Visible in public client bundles:

- `submitInquiry` (contact form)
- `subscribeToNewsletter`
- `submitDiaryEntry`
- `createBitelevateCashfreeOrder`
- `verifyBitelevatePayment`
- `loginIntern`
- `requestPasswordReset`

Server Action reference IDs are public by design and are intentionally omitted here. Treat every Server Action as a public API endpoint: it can be invoked directly, so it must validate input, authorize the caller, and enforce rate limits without relying on the UI.

### Data collected

| Surface | Personal data | Sensitivity |
| --- | --- | --- |
| Contact | name, email, company, industry, message | Business contact data |
| BitElevate | name, university, email, phone, track, duration, referral, ambitions, payment metadata | Education + contact + payment-adjacent |
| Diaries | name, role, email, title, story | PII + user-generated content intended for publication |
| Newsletter | email | Marketing contact data |
| Portal | email, password, session | Authentication data |

## 3. Findings

Severity reflects impact and likelihood from the public evidence. Items marked **verify internally** require access to server code, configuration, or logs that were out of scope.

### 3.1 High

#### H-1. Payment flow returns plaintext credentials to the browser

**Severity:** High, potentially Critical if order binding is missing  
**Category:** Authentication, payments, data handling  
**Status:** Verified in public client code; server-side binding must be verified internally

**Evidence.** The public BitElevate bundle contains Server Actions named `createBitelevateCashfreeOrder` and `verifyBitelevatePayment`. On return from Cashfree, the page reads `order_id` and `token` from `window.location.search`, calls verification, and expects `bitElevateCredentials` containing `email` and `password`. The success UI renders the password as "Temporary Login Password" and writes it, together with the login URL and user ID, to the clipboard through `navigator.clipboard.writeText`.

**Impact.**

- Any script that runs on the page, including a compromised third-party dependency, a browser extension, or an injected payload, can read the password from the DOM or intercept the clipboard write.
- Passwords can persist in clipboard managers, screen recordings, shared screens, and browser session restore.
- A token in the query string can leak through the `Referer` header to Google Tag Manager, Google Fonts, Cashfree, or any other third party loaded on the return page. The site has no `Referrer-Policy`.
- If `verifyBitelevatePayment` does not bind the token to the order, to the paid amount, and to a single use, an attacker could call it with another order identifier or replay a captured return URL. This is a payment-bypass and account-takeover risk. It could not be tested without unauthorized actions.
- If fulfilment is not idempotent, refreshes and webhook retries can create duplicate accounts or credentials.

**Recommendation.**

1. Provision accounts only from a signature-verified Cashfree webhook. Do not treat the browser return as proof of payment.
2. Derive product, amount, and currency from a server-side catalog. Never accept amount or product identifiers from the client.
3. Store an order state machine (`CREATED → PAID → FULFILLED`) with a unique constraint on the payment event ID. Make fulfilment idempotent and transaction-safe.
4. Generate a 256-bit single-use setup token, store only its SHA-256 hash with a 15–30 minute expiry, and email a link to `/set-password?token=…`. Never return a password in an HTTP response.
5. Hash passwords with Argon2id (or scrypt with strong parameters). Use a password policy of at least 12 characters and block known-breached passwords.
6. Put the setup token in a URL fragment or exchange it server-side, set `Referrer-Policy: no-referrer` on the page, and avoid loading analytics on the setup route.
7. Add login rate limiting, generic error messages (already observed), session rotation, and an audit trail for credential events.

**Verification.**

- Confirm the webhook handler verifies the Cashfree signature over `x-webhook-timestamp + rawBody` using the PG client secret; Cashfree timestamps are in milliseconds.
- Confirm the order lookup uses a server-side order ID and amount, not client input.
- Confirm a replayed event does not create a second account or send a second email.
- Confirm no response body, log line, or analytics event contains a password or setup token.
- Confirm the portal session cookie is `HttpOnly`, `Secure`, `SameSite=Lax` or `Strict`, and rotated on login.

**Prototype.** The working implementation in `src/hardening/server.mjs` demonstrates the recommended flow: server-priced order, HMAC-signed webhook with timestamp tolerance, replay protection, one-time setup token, hashed passwords, and no password in any response. Tests in `test/payments.test.mjs` prove the negative cases (bad signature, amount tampering, replay, token reuse).

#### H-2. Email anti-spoofing is not enforced

**Severity:** High  
**Category:** Email security, brand protection  
**Status:** Verified from public DNS

**Evidence.**

- `_dmarc.cynbit.in` returns `v=DMARC1; p=none;` with no `rua` or `ruf`.
- Apex SPF is `v=spf1 include:secureserver.net -all`.
- Apex MX is Microsoft 365 (`cynbit-in.mail.protection.outlook.com`).
- `selector1._domainkey.cynbit.in` and `selector2._domainkey.cynbit.in` CNAMEs were not observed.
- Resend DKIM exists at `resend._domainkey.cynbit.in`, and `send.cynbit.in` has its own SPF and Amazon SES MX records. Those are good controls for Resend.
- No MTA-STS or TLS-RPT records were observed. No apex CAA record was observed. DNSSEC is not enabled.

**Impact.** Anyone can send mail that claims to be from `@cynbit.in` and DMARC will not instruct receivers to quarantine or reject it. Because Cynbit emails credentials, enrollment confirmations, and payment messages, spoofed mail can be used for phishing, invoice fraud, and credential theft. If Microsoft 365 sends any mail from the apex domain without DKIM, it will also fail SPF alignment.

**Recommendation.**

1. Enable Microsoft 365 DKIM for the domain and publish the `selector1` and `selector2` CNAMEs.
2. Make SPF list every authorized sender. If Microsoft 365 sends outbound mail, add `include:spf.protection.outlook.com`. Keep Resend on the dedicated `send.cynbit.in` envelope domain. End with `-all`.
3. Add DMARC reporting: `v=DMARC1; p=quarantine; rua=mailto:dmarc@cynbit.in; ruf=mailto:dmarc@cynbit.in; fo=1; adkim=s; aspf=s; pct=100`. Move to `p=reject` after 2–4 weeks of clean reports.
4. Publish CAA at the apex for the certificate authorities actually used, for example `letsencrypt.org` and `pki.goog`.
5. Enable DNSSEC at the registrar and publish MTA-STS and TLS-RPT.
6. Monitor DMARC aggregate reports and alert on new sending sources.

**Verification.** Use a DMARC validator and send test mail from every sender (Microsoft 365, Resend, any CRM). Confirm alignment and authentication pass, then confirm an unauthorized sender is rejected at `p=reject`.

#### H-3. No Content-Security-Policy on pages that execute third-party scripts and handle credentials

**Severity:** High  
**Category:** Browser hardening, supply chain  
**Status:** Verified

**Evidence.** No `Content-Security-Policy` header was returned on `www.cynbit.in` or `bitelevate.cynbit.in`. The marketing pages load Google Tag Manager, Google Fonts, and Unsplash images. The portal login page also loads Google Tag Manager. Cashfree's SDK is injected on demand on the BitElevate page. The payment success view contains plaintext credentials (H-1).

**Impact.** CSP is the last line of defense against script injection and third-party compromise. Without it, any XSS, malicious dependency, or compromised tag can read the DOM, exfiltrate session data, alter payment state, or capture the temporary password. The absence of CSP also means there is no reporting channel for injection attempts.

**Recommendation.**

1. Deploy a nonce-based CSP in `Content-Security-Policy-Report-Only` first. Use `script-src 'self' 'nonce-…' 'strict-dynamic'`, `object-src 'none'`, `base-uri 'self'`, `frame-ancestors 'none'`, and `form-action 'self'`.
2. Self-host fonts with `next/font` and remove the Google Fonts stylesheet.
3. Remove Google Tag Manager from portal, checkout, and credential pages. If analytics is required, use a server-side container or a consent-gated, first-party proxy.
4. Prefer `next/script` with explicit integrity where the vendor supports it. Cashfree's SDK should be allowlisted by origin and loaded only on the checkout route.
5. Add a CSP report endpoint, monitor violations, then enforce.
6. Add Trusted Types in report-only mode after CSP is stable.

**Verification.** Confirm zero CSP violations for critical user journeys over 7 days, then enforce. Confirm the policy blocks an injected inline script in a staging test.

### 3.2 Medium

#### M-1. Baseline security headers and HSTS coverage are incomplete

**Severity:** Medium  
**Category:** Browser hardening, transport  
**Status:** Verified

**Evidence.** Document responses lack `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `X-Frame-Options`/`frame-ancestors`, COOP, and CORP. HSTS is `max-age=63072000` without `includeSubDomains` or `preload`. `X-Powered-By: Next.js` appears on some routes (`/contact`, `/careers`) but not the homepage, indicating inconsistent header configuration.

**Impact.** Clickjacking, MIME sniffing, referrer leakage of tokens, feature abuse, and avoidable framework fingerprinting. HSTS without subdomain coverage leaves the portal host independently downgradable.

**Recommendation.** Apply headers globally in `next.config.mjs` or `proxy.ts`/`middleware.ts` (see `examples/nextjs/next.config.mjs`). Set `poweredByHeader: false`. Only add `includeSubDomains; preload` after confirming every subdomain is HTTPS-only.

#### M-2. Wildcard CORS on document responses

**Severity:** Medium  
**Category:** API and browser boundary  
**Status:** Verified

**Evidence.** `Access-Control-Allow-Origin: *` was returned on the homepage, `/services`, `/products`, `/bitelevate`, the 404 page, and `bitelevate.cynbit.in/login`. It was not present on `/contact` or `/careers`, so the configuration is inconsistent.

**Impact.** CORS is unnecessary on same-origin document routes. If the same wildcard policy is applied to JSON endpoints or Server Actions, any origin can read responses. On an authentication page it also signals that the origin boundary is not intentionally designed.

**Recommendation.** Remove CORS headers from document routes. For APIs, use an explicit allowlist, set `Vary: Origin`, and never combine `*` with credentials. Server Actions should remain same-origin.

#### M-3. Public mutations lack visible abuse controls

**Severity:** Medium  
**Category:** API abuse, availability, cost  
**Status:** No CAPTCHA widget or token field observed in public forms; application-level rate limits could not be confirmed externally

**Evidence.** The public forms expose five Server Actions plus two portal authentication actions. No Turnstile/reCAPTCHA widget or token field appears in the bundles. No `RateLimit-*` or `Retry-After` headers were observed. Vercel may provide edge WAF controls, but those were not confirmed.

**Impact.** Automated submissions can pollute the CRM, send unlimited email through Resend, spam the diary moderation queue, create unpaid Cashfree orders, attempt credential stuffing, and trigger password-reset email bombing. Unbounded server actions also create cost and availability risk.

**Recommendation.**

1. Add Cloudflare Turnstile or equivalent to public forms and verify the token server-side.
2. Rate limit by IP, route, and account: for example 5/minute for contact and checkout, 10/minute for login, 3/hour per email for password reset, and a global per-IP burst cap.
3. Use a shared store (Upstash Redis, Vercel KV, or Postgres) so limits work across serverless instances.
4. Add honeypot fields, body-size limits, content-type enforcement, and idempotency keys.
5. Add a moderation queue and abuse alerts for diary submissions and newsletters.
6. Add a WAF rule set for known bad bots and volumetric bursts.

#### M-4. Data-handling and privacy documentation do not yet match the data collected

**Severity:** Medium  
**Category:** Privacy, compliance  
**Status:** Verified from public policy text and client behavior

**Evidence.** The privacy policy states that Cynbit collects name, email, and professional context, uses Resend for email and Prisma for database management, and stores "blog comments or diary entries". The BitElevate flow collects university, phone, ambitions, and payment-adjacent data. The diary flow collects name, role, email, title, and story for publication. The cookie policy describes essential, analytics, and functional cookies, but Google Tag Manager is loaded on marketing and login pages without an observed consent gate. The policy does not state retention periods, legal basis, a grievance officer, cross-border transfer details, subprocessor list, or a breach notification process.

**Impact.** India's Digital Personal Data Protection Act 2023 requires notice, consent, purpose limitation, data minimization, storage limitation, grievance redressal, and breach notification. GDPR/ePrivacy obligations may also apply to EU visitors. Publishing user-generated diaries can expose PII if redaction and moderation are incomplete. Over-retention increases breach impact.

**Recommendation.**

1. Build a data inventory and record of processing: field, purpose, legal basis, storage location, subprocessor, retention, deletion trigger.
2. Add a consent management platform. Load analytics only after consent. Do not load GTM on login, checkout, or credential setup routes.
3. Publish retention periods and a deletion process. Add self-service or email-based erasure with verified identity.
4. Appoint and publish a grievance officer and a security contact. Add a breach response runbook with 72-hour assessment.
5. Minimize data: do not collect phone or university unless required; redact PII from public diaries; separate moderation data from published content.
6. Encrypt sensitive fields at rest with a KMS-backed envelope key; restrict database access with least privilege and audit queries.
7. Sign DPAs with Vercel, Resend, Cashfree, Google, and any other processor; document international transfers.
8. Redact PII, passwords, tokens, and payment data from logs and error trackers.

### 3.3 Low and informational

#### L-1. robots.txt advertises sensitive paths

`robots.txt` disallows `/api/`, `/admin/`, and `/portal/`. robots.txt is public and is not access control. Listing private paths helps attackers prioritize. Remove these entries and enforce authentication and authorization at the edge and in the application. Return consistent 404s for unauthorized resources where appropriate.

#### L-2. No vulnerability disclosure policy

`/.well-known/security.txt` returns 404. Publish `security.txt` with `Contact`, `Expires`, `Preferred-Languages`, and a link to a disclosure policy. Provide a monitored security mailbox and a safe-harbor statement.

#### L-3. Certificate, CAA, and DNS hygiene

Each hostname uses a separate single-name Let's Encrypt certificate. `www` inherits CAA from the Vercel CNAME target, but the apex has no CAA record. DNSSEC is not enabled, and MTA-STS/TLS-RPT are absent. Add apex CAA, enable DNSSEC, automate renewal with expiry alerts, and consider a wildcard or multi-SAN certificate for operational simplicity.

#### L-4. Framework and stack fingerprinting

`X-Powered-By: Next.js` is inconsistent across routes. Remove it and avoid unnecessary server banners. This is low risk on its own but reduces attacker reconnaissance when combined with dependency versions.

#### L-5. Sitemap and canonical inconsistency

The sitemap lists apex URLs (`https://cynbit.in/...`) while the apex 307-redirects to `www`. `og:url` also uses the apex. Static pages report a `lastmod` equal to the scan time, which suggests the value is generated per request rather than reflecting real content changes. This is not a security issue, but it wastes crawl budget and creates canonical ambiguity. Pick one canonical host, use it consistently, and emit stable `lastmod` values.

#### I-1. Positive controls observed

- TLS 1.3 negotiated; TLS 1.0 and 1.1 rejected.
- HTTP redirects to HTTPS with 308.
- HSTS is present with a two-year max-age.
- Public `.js.map` requests return 403.
- Static assets use `Cache-Control: public, max-age=31536000, immutable` and Brotli.
- Vercel edge caching is active.
- No `Set-Cookie` was observed on public pages, so there were no public session cookies to inspect.
- Login errors are generic ("Invalid email or password"), reducing user enumeration.
- Password reset uses a generic success message.
- Cashfree hosted checkout keeps card data out of Cynbit's origin, reducing PCI scope.
- Resend DKIM and the dedicated `send.cynbit.in` envelope domain are correctly separated from the corporate apex.

## 4. Data-handling review

| Question | Observation | Risk |
| --- | --- | --- |
| What is collected? | Contact data, education/phone data, diary UGC, newsletter email, portal credentials | Medium |
| Where is it stored? | Privacy policy names Prisma; infrastructure is Vercel | Unknown residency and encryption |
| How long is it retained? | Not stated | Over-retention |
| Who can access it? | Not observable externally | Needs role-based access review |
| Is it encrypted? | TLS in transit; at-rest encryption not stated | Verify KMS/disk encryption |
| Are logs scrubbed? | Not observable | Password/token leakage risk in logs |
| Are processors documented? | Resend and Prisma named; Cashfree, Vercel, Google not named in the policy excerpt | Incomplete transparency |
| Is consent captured? | Newsletter links the privacy policy; analytics loads unconditionally | Consent gap |
| Can users delete data? | Policy offers email contact | Process and SLA not stated |
| Is UGC moderated? | Diary copy says stories are reviewed before publishing | Moderation and PII redaction must be enforced |

## 5. Performance review

Observed from public responses on 2026-11-07:

- Homepage HTML: approximately 100.6 KB uncompressed, 15.6 KB over the wire with Brotli.
- Homepage references 16 JavaScript chunks; the sampled main chunk is approximately 173 KB raw and 46 KB over the wire.
- Static assets are served with one-year immutable caching and Brotli; Vercel edge cache is active.
- Google Fonts CSS is an external render-blocking stylesheet. Material Symbols adds a third-party connection.
- Google Tag Manager loads globally, including on the portal login page.
- TTFB from the assessment location was approximately 240 ms for the homepage and contact page.
- The PageSpeed Insights API quota was exhausted during the assessment, so no Lighthouse score is reported. The recommendations below are based on direct asset and header measurements.

Recommendations:

1. Self-host fonts with `next/font`, subset them, and use `font-display: swap`.
2. Remove GTM from authenticated and payment routes; defer or consent-gate it elsewhere.
3. Split large client components and dynamic-import below-the-fold sections.
4. Run a bundle analyzer and set a performance budget. Track LCP, INP, CLS, and TTFB in RUM.
5. Preconnect only to origins that are actually required on the critical path.
6. Keep the immutable static cache policy and add early hints only after measuring benefit.

## 6. Prioritized remediation roadmap

### 0–7 days

1. Verify and fix H-1: webhook-only fulfilment, server-side price, signed events, idempotency, one-time setup links, no plaintext password.
2. Add baseline security headers and HSTS flags. Add `security.txt`.
3. Remove wildcard CORS from document routes.
4. Add rate limits and Turnstile to contact, newsletter, diary, checkout, login, and password reset.
5. Publish DMARC `rua`, enable Microsoft 365 DKIM, and align SPF.
6. Remove `/api/`, `/admin/`, and `/portal/` from robots.txt.
7. Add `Referrer-Policy: no-referrer` on payment return and credential setup routes.

### 30 days

1. Enforce the nonce-based CSP after a clean report-only period.
2. Move DMARC to `p=quarantine`, then `p=reject`.
3. Add consent management and remove analytics from authentication and payment routes.
4. Publish retention, deletion, grievance, and subprocessor details. Sign DPAs.
5. Add structured logging with PII redaction, centralized alerting, and audit trails for auth and payment events.
6. Add dependency scanning, SAST, secret scanning, and lockfile enforcement in CI.
7. Add WAF/bot rules and alerting for abuse patterns.
8. Add apex CAA, DNSSEC, MTA-STS, and TLS-RPT.

### 90 days

1. Commission an independent penetration test covering the portal, payment flow, and authorization boundaries.
2. Map controls to OWASP ASVS Level 2 and close gaps.
3. Run a DPDP/GDPR readiness review and a data-protection impact assessment for the portal.
4. Test backups, restore, and disaster recovery. Define RTO/RPO.
5. Establish a vulnerability disclosure program and a security.txt contact with an SLA.
6. Add tabletop exercises for payment fraud, credential compromise, and email impersonation.
7. Track security and performance SLOs: header grade A, DMARC reject, no high/critical dependency findings, LCP < 2.5 s, INP < 200 ms, CLS < 0.1.

## 7. Verification plan for the fixes

| Control | How to verify |
| --- | --- |
| Security headers | `curl -D - https://www.cynbit.in/` and `https://bitelevate.cynbit.in/login`; expect CSP, nosniff, frame-ancestors, Referrer-Policy, Permissions-Policy, COOP, CORP, HSTS with includeSubDomains |
| CORS | Confirm no `Access-Control-Allow-Origin` on document routes; API allowlist only |
| CSP | Report-only for 7 days with zero unexplained violations, then enforce; attempt a staging inline-script injection |
| Payment | Signed webhook test, amount tamper test, replay test, duplicate fulfilment test, no password in response or logs |
| Credentials | Setup token single-use and expiring; password stored only as Argon2id/scrypt hash; session cookie HttpOnly/Secure/SameSite |
| Rate limits | Automated test returns 429 with Retry-After; limits shared across instances |
| Email | DMARC validator shows pass for every sender and reject for unauthorized senders; aggregate reports arrive |
| Privacy | Data inventory complete; consent recorded; deletion request exercised end to end; logs contain no PII or secrets |
| Performance | Lighthouse mobile and RUM budgets; bundle size and third-party requests tracked per release |

## 8. Limitations

- This assessment is passive and external. It cannot confirm server-side validation, authorization, webhook verification, password hashing, database access controls, WAF rules, or logging hygiene.
- No form was submitted, no order was created, no login was attempted, and no private area was accessed.
- Public client code reveals intent and data shape, not the server implementation. H-1 must be validated by the Cynbit engineering team before it is treated as a confirmed vulnerability.
- The PageSpeed Insights quota was exhausted, so performance conclusions are based on direct measurements rather than Lighthouse.
- DNS and TLS results reflect the assessment date. Certificate and DNS state can change.

## 9. References

- OWASP Top 10: https://owasp.org/Top10/
- OWASP API Security Top 10 2023: https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- OWASP Application Security Verification Standard: https://owasp.org/www-project-application-security-verification-standard/
- OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/
- RFC 7489 (DMARC): https://datatracker.ietf.org/doc/html/rfc7489
- RFC 7208 (SPF): https://datatracker.ietf.org/doc/html/rfc7208
- RFC 9116 (security.txt): https://www.rfc-editor.org/rfc/rfc9116.html
- Next.js Content Security Policy: https://nextjs.org/docs/app/building-your-application/configuring/content-security-policy
- Vercel security headers: https://vercel.com/docs/security/security-headers
- web.dev Core Web Vitals: https://web.dev/articles/vitals
- Digital Personal Data Protection Act, 2023 (India), official gazette text
- Cashfree Payments webhook signature documentation (vendor documentation)
- SecurityHeaders: https://securityheaders.com/
- Mozilla Observatory: https://developer.mozilla.org/en-US/observatory

## 10. Evidence index

- `audit/evidence/headers-www.txt` — response headers for www, contact, 404, robots.txt, security.txt
- `audit/evidence/headers-bitelevate.txt` — portal login and root headers
- `audit/evidence/dns-email.txt` — DNS, SPF, DMARC, DKIM, CAA, MTA-STS, DNSSEC
- `audit/evidence/tls.txt` — certificate and protocol details
- `audit/evidence/public-surface.md` — routes, forms, server actions, data fields, request log
- `audit/evidence/scan-report.md` — automated passive posture scan for www
- `audit/evidence/bitelevate/scan-report.md` — automated passive posture scan for the portal
- `src/hardening/` — working hardening reference implementation
- `examples/nextjs/` — drop-in Next.js, Prisma, Cashfree, and outbox reference files
- `recommendations/RECOMMENDATIONS.md` — target architecture, benchmarks, and rollout plan
- `test/` — 25 automated tests covering headers, validation, rate limits, payments, replay, and auth
