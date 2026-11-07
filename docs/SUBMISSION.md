# Submission Entries

Public repository: https://github.com/Yatharth6494/cynbit-security-audit

## Entry 1: Primary link

```text
Cynbit public-surface security assessment and hardening kit
https://github.com/Yatharth6494/cynbit-security-audit

A passive, read-only review of www.cynbit.in, cynbit.in, and bitelevate.cynbit.in, with captured evidence, a prioritized audit report, a zero-dependency posture scanner, and a working hardening reference for payments, credentials, headers, validation, and rate limiting.

Contents:
- Full audit report with severity, evidence, impact, and remediation
- Raw evidence for headers, DNS/email, TLS, public surface, and scanner output
- Technical recommendations with target architecture, benchmarks, and rollout plan
- Working Node.js reference server plus drop-in Next.js/Prisma/Cashfree files
- 25 passing security regression tests and an end-to-end demo

Start here: README.md
Audit: audit/AUDIT_REPORT.md
Recommendations: recommendations/RECOMMENDATIONS.md
Verification: npm test && npm run demo
```

## Entry 2: Execution Notes & Campaign Rationale

```text
Execution Notes & Campaign Rationale

I treated the assessment as a passive, read-only review. I inspected only publicly served content: HTML, JavaScript bundles, response headers, DNS records, TLS configuration, robots.txt, sitemap.xml, and the portal login redirect. I did not authenticate, submit forms, initiate payments, fuzz, exploit, or access private systems. Every observation in the report is reproducible from the captured evidence.

I prioritized impact over volume. The highest-risk issue is not infrastructure: the public BitElevate flow expects a plaintext temporary password in the browser and reads order_id and token from the return URL. I documented the exposure without testing another user's order, then built a safer flow: server-side pricing, a signed Cashfree webhook, a unique payment-event constraint for idempotency, a one-time setup token, Argon2id hashing in the Next.js reference, and no password in any response. The test suite proves bad signatures, amount tampering, stale replays, token reuse, and weak passwords are rejected.

The second theme is containment. Email is used for credentials and payment messages, but DMARC is p=none with no reporting and Microsoft 365 DKIM is not visible. I recommended a staged DKIM/SPF/DMARC rollout rather than an immediate reject that could break legitimate mail. The site also has no CSP while third parties execute on the same origin, so I added a nonce-based policy and removed analytics from sensitive routes in the reference design.

The third theme is making abuse expensive and observable. Public Server Actions are APIs. The prototype applies origin checks, content-type checks, body caps, schema validation, shared rate limiting, Turnstile, generic errors, and PII-redacted logging. The Next.js reference maps these controls to the actual stack and uses an encrypted outbox so a webhook retry cannot lose or duplicate credential emails.

I kept the work within ethical and legal limits. Where server-side behavior could not be proven from outside, I marked it "verify internally" instead of attempting unauthorized access. The result is a conservative risk assessment, a reproducible evidence trail, and a working implementation that Cynbit can adopt incrementally.
```
