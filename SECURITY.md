# Security Policy

## Reporting a vulnerability

If you believe you have found a vulnerability in a Cynbit system, report it privately.

- Preferred: `security@cynbit.in` (provision this mailbox before publishing the policy)
- Interim: `opportunities@cynbit.in` with the subject line `Security disclosure`
- Include: affected host or component, reproduction steps, impact, and any proof-of-concept
- Do not include: real customer data, passwords, payment credentials, or full personal records

Do not open a public issue, post details on social media, or test against production accounts, payments, or other users' data.

## Scope

In scope:

- `www.cynbit.in`
- `cynbit.in`
- `bitelevate.cynbit.in`
- Public APIs and Server Actions reachable without authentication

Out of scope:

- Denial-of-service or volumetric testing
- Social engineering of staff or customers
- Physical security
- Third-party services not controlled by Cynbit
- Automated scanning that degrades service
- Accessing, modifying, or exfiltrating data that is not yours

## Safe harbor

Cynbit will not pursue legal action for good-faith research that:

1. Stays within the scope above.
2. Avoids privacy violations, data destruction, and service disruption.
3. Uses the minimum access necessary to demonstrate the issue.
4. Reports promptly and keeps the details private until remediation is agreed.
5. Does not extort, demand payment, or publish before a fix is available.

This safe harbor does not authorize testing against systems or data outside the stated scope.

## What to expect

- Acknowledgement within 2 business days
- Initial triage within 5 business days
- A remediation plan and timeline for confirmed issues
- Credit if desired, once the issue is resolved
- Coordination on disclosure, normally within 90 days

## Hardening baseline

This repository documents the recommended baseline:

- TLS 1.2+ with HSTS `includeSubDomains; preload`
- Nonce-based CSP with no `unsafe-inline` or `unsafe-eval` for scripts
- DMARC `p=reject` with reporting and aligned SPF/DKIM
- Argon2id password hashing, MFA for staff, and `HttpOnly` sessions
- Server-side validation, authorization, and rate limits on every mutation
- Signed, idempotent payment webhooks and server-side pricing
- One-time setup links instead of plaintext credentials
- PII-redacted logs, retention limits, and a documented data inventory
- A monitored disclosure mailbox and `/.well-known/security.txt`
