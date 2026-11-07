# Passive Security Posture Report

- Target: https://www.cynbit.in/
- Final URL: https://www.cynbit.in/
- Scanned at: 2026-11-07T14:20:37.146Z
- Score: **35/100** (grade **F**)
- Findings: 11 (critical 0, high 1, medium 3, low 7, info 0)

## Checks

| Check | Status | Detail |
| --- | --- | --- |
| HSTS | warn | missing includeSubDomains |
| CSP | fail | missing |
| Frame protection | fail | missing |
| nosniff | fail | missing |
| Referrer-Policy | fail | missing |
| Permissions-Policy | fail | missing |
| CORS | warn | wildcard |
| Server banner | info | Vercel |
| Source maps | pass | HTTP 403 |
| security.txt | fail | HTTP 404 |
| robots.txt | warn | /api/, /admin/, /portal/ |
| TLS version | pass | TLSv1.3 |
| TLS certificate | pass | 46 days remaining |
| HTTP to HTTPS | pass | 308 -> https://www.cynbit.in/ |
| Static cache | pass | public,max-age=31536000,immutable |
| Static cache | pass | public,max-age=31536000,immutable |
| Static cache | pass | public,max-age=31536000,immutable |

## Findings

### CSP-001 - Content-Security-Policy is not set

- Severity: **HIGH**
- Category: Browser hardening
- Evidence: `No Content-Security-Policy response header on HTML documents.`
- Impact: Any injected or compromised third-party script can execute freely, read the DOM, and exfiltrate credentials or payment state.
- Recommendation: Deploy a nonce-based CSP with strict-dynamic, object-src 'none', base-uri 'self', and frame-ancestors 'none'. Roll out in report-only mode first.

### CORS-002 - Wildcard Access-Control-Allow-Origin

- Severity: **MEDIUM**
- Category: API
- Evidence: `Access-Control-Allow-Origin: * on a document response.`
- Impact: Cross-origin scripts can read the response. If the same policy is applied to JSON or server actions, it becomes a data exposure.
- Recommendation: Remove CORS headers from document routes and use an explicit origin allowlist for APIs.

### REF-001 - Referrer-Policy is missing

- Severity: **MEDIUM**
- Category: Browser hardening
- Evidence: `No Referrer-Policy response header.`
- Impact: Sensitive URL parameters, including payment or reset tokens, can leak to third parties via the Referer header.
- Recommendation: Send Referrer-Policy: strict-origin-when-cross-origin, and no-referrer on token-bearing return and reset pages.

### XFO-001 - No clickjacking protection

- Severity: **MEDIUM**
- Category: Browser hardening
- Evidence: `Neither X-Frame-Options nor CSP frame-ancestors is present.`
- Impact: Attackers can overlay the site in a frame to capture clicks or credentials.
- Recommendation: Set frame-ancestors 'none' and X-Frame-Options: DENY.

### COOP-001 - Cross-Origin-Opener-Policy is missing

- Severity: **LOW**
- Category: Browser hardening
- Evidence: `No Cross-Origin-Opener-Policy response header.`
- Impact: Cross-window attacks and Spectre-style isolation gaps are more likely.
- Recommendation: Send Cross-Origin-Opener-Policy: same-origin on documents.

### CORP-001 - Cross-Origin-Resource-Policy is missing

- Severity: **LOW**
- Category: Browser hardening
- Evidence: `No Cross-Origin-Resource-Policy response header.`
- Impact: Other sites can embed resources in ways that enable side-channel or data-leak attacks.
- Recommendation: Send Cross-Origin-Resource-Policy: same-origin (or same-site where needed).

### DISC-001 - No vulnerability disclosure policy

- Severity: **LOW**
- Category: Governance
- Evidence: `/.well-known/security.txt returned HTTP 404.`
- Impact: Researchers have no safe, documented way to report vulnerabilities, increasing the chance of public disclosure or extortion.
- Recommendation: Publish /.well-known/security.txt with Contact, Expires, Preferred-Languages, and a disclosure policy.

### HSTS-002 - HSTS does not cover subdomains

- Severity: **LOW**
- Category: Transport
- Evidence: `Strict-Transport-Security: max-age=63072000`
- Impact: Subdomains such as the intern portal can be downgraded or stripped independently.
- Recommendation: Add includeSubDomains and preload after auditing all subdomains.

### MIME-001 - X-Content-Type-Options is missing

- Severity: **LOW**
- Category: Browser hardening
- Evidence: `No X-Content-Type-Options: nosniff header.`
- Impact: Browsers may MIME-sniff responses and execute content as a different type.
- Recommendation: Send X-Content-Type-Options: nosniff on every response.

### PERM-001 - Permissions-Policy is missing

- Severity: **LOW**
- Category: Browser hardening
- Evidence: `No Permissions-Policy response header.`
- Impact: Powerful browser features remain available to embedded or injected code.
- Recommendation: Disable features the site does not use, for example camera=(), microphone=(), geolocation=(), payment=(), usb=().

### ROBOTS-001 - robots.txt advertises sensitive application paths

- Severity: **LOW**
- Category: Information disclosure
- Evidence: `Disallow entries: /api/, /admin/, /portal/`
- Impact: robots.txt is public and is not an access control. Listing private paths helps attackers prioritize targets.
- Recommendation: Remove private path names from robots.txt and enforce authentication and authorization at the edge and in the application.

## Transport

- TLS protocol: TLSv1.3
- Cipher: TLS_AES_128_GCM_SHA256
- Certificate: CN=www.cynbit.in
- Issuer: CN=YR2, O=Let's Encrypt
- Valid to: Dec 24 04:47:43 2026 GMT
- HTTP redirect: 308 -> https://www.cynbit.in/

## Performance observations

- TTFB: 482 ms
- Total document fetch: 499 ms
- HTML bytes: 100660
- Content-Length: n/a
- Script tags: 16
- Stylesheets: 2
- Compression: br
- Edge cache: HIT
- Assets sampled: 3

## Files probed

| Path | Status |
| --- | --- |
| /robots.txt | 200 |
| /.well-known/security.txt | 404 |
| /sitemap.xml | 200 |
| /.well-known/change-password | 404 |

## Scope and limitations

This is a read-only assessment of publicly served content. It does not authenticate, submit forms, fuzz inputs, attempt exploitation, or access private areas. Absence of a header or control is observable; presence of server-side validation or edge controls may not be.
