# Public surface inventory

Assessment date: 2026-11-07
Scope: publicly reachable Cynbit web properties only. No authentication, form submission, fuzzing, exploitation, or private-area access was performed.

## Hosts

| Host | Behaviour | Observed stack |
| --- | --- | --- |
| `https://www.cynbit.in` | 200, marketing site | Next.js App Router, Vercel edge, Let's Encrypt |
| `https://cynbit.in` | 307 to `https://www.cynbit.in/` | Vercel, separate single-name certificate |
| `https://bitelevate.cynbit.in` | 200, intern portal login | Next.js App Router, Vercel edge, Let's Encrypt |
| `http://www.cynbit.in` | 308 to HTTPS | Vercel |
| `http://cynbit.in` | 308 to HTTPS | Vercel |

## DNS and email

| Record | Value |
| --- | --- |
| Nameservers | `ns33.domaincontrol.com`, `ns34.domaincontrol.com` |
| `www` | CNAME `e12d688042344235.vercel-dns-017.com` |
| Apex MX | `0 cynbit-in.mail.protection.outlook.com` (Microsoft 365) |
| Apex SPF | `v=spf1 include:secureserver.net -all` |
| DMARC | `v=DMARC1; p=none;` (no rua/ruf) |
| Resend DKIM | `resend._domainkey.cynbit.in` TXT present |
| Resend envelope domain | `send.cynbit.in` MX to Amazon SES; SPF via `_spfm.send.cynbit.in` |
| Microsoft 365 DKIM | `selector1` and `selector2` CNAMEs not observed |
| CAA apex | none |
| CAA at `www` CNAME target | `globalsign.com`, `letsencrypt.org`, `pki.goog`, `sectigo.com` |
| MTA-STS / TLS-RPT | not observed |
| DNSSEC | not enabled |

## Public forms and mutations

The client bundles expose Next.js Server Action names. Action reference IDs are intentionally omitted from this report.

| Surface | Fields | Server action |
| --- | --- | --- |
| `/contact` | fullName, email, company, industry, message | `submitInquiry` |
| `/bitelevate` | fullName, university, email, phone, track, duration, referralName, ambitions | `createBitelevateCashfreeOrder`, `verifyBitelevatePayment` |
| `/diaries` | fullName, role, email, title, story | `submitDiaryEntry` |
| `/blog/[slug]` | email | `subscribeToNewsletter` |
| `bitelevate.cynbit.in/login` | email, password | `loginIntern`, `requestPasswordReset` |

## Payment and credential flow observed in public client code

1. The public BitElevate form submits application data to `createBitelevateCashfreeOrder`.
2. The server returns an order identifier, a token, a Cashfree payment session, and an environment flag.
3. The browser opens Cashfree Checkout in production mode.
4. On return, the page reads `order_id` and `token` from `window.location.search` and calls `verifyBitelevatePayment`.
5. On success, the client expects an object named `bitElevateCredentials` containing `email` and `password`.
6. The UI renders the value as "Temporary Login Password" and offers "Copy Password" / "Copy All Login Details" to the clipboard.

No payment was initiated and no credentials were requested or used.

## Third parties visible on public pages

- Google Tag Manager / Google Analytics 4 (`G-LK6CQWCWX0`), loaded on marketing pages and on the portal login page.
- Google Fonts (`fonts.googleapis.com` Material Symbols).
- Cashfree JS SDK v3 (`sdk.cashfree.com`), loaded on demand for checkout.
- Unsplash-hosted images (observed in client code).
- Social links to LinkedIn, Instagram, Facebook, X.

## Read-only requests made

- `GET /`, `/contact`, `/careers`, `/diaries`, `/bitelevate`, `/blog/best-crm-automation-strategies`, `/privacy`, `/cookies`
- `GET /robots.txt`, `/sitemap.xml`, `/.well-known/security.txt`, `/.well-known/change-password`
- `GET` of public `/_next/static/*.js` and `.css` assets referenced by those pages
- `GET` of `.js.map` paths adjacent to public bundles (403)
- `GET /nonexistent-audit-probe` to observe the 404 response
- `GET https://bitelevate.cynbit.in/login` (public login page, redirect target of `/intern-portal/login`)
- DNS queries, TLS handshakes, and HTTP HEAD/GET header checks
- Two `OPTIONS`-equivalent observations were not used; no API mutations were sent

## Not tested

- No login attempt, password reset, or account access.
- No submission of contact, newsletter, diary, or BitElevate forms.
- No payment order creation or webhook invocation.
- No `/admin/`, `/portal/`, `/api/`, or authenticated portal access.
- No rate-limit exhaustion, fuzzing, directory brute force, or exploitation.
- No source-code access, repository access, cloud console access, or private system access.
