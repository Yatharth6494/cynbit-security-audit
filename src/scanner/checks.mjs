export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

const DEDUCTIONS = { critical: 40, high: 20, medium: 8, low: 3, info: 0 };

export function getHeader(headers, name) {
  if (!headers) return undefined;
  if (typeof headers.get === "function") return headers.get(name) ?? undefined;
  const key = Object.keys(headers).find((k) => k.toLowerCase() === name.toLowerCase());
  return key ? headers[key] : undefined;
}

export function parseHsts(value) {
  if (!value) return { present: false, maxAge: null, includeSubDomains: false, preload: false };
  const parts = value.split(";").map((p) => p.trim()).filter(Boolean);
  const maxAgePart = parts.find((p) => /^max-age=/i.test(p));
  const maxAge = maxAgePart ? Number(maxAgePart.split("=")[1]) : null;
  return {
    present: true,
    maxAge: Number.isFinite(maxAge) ? maxAge : null,
    includeSubDomains: parts.some((p) => /^includeSubDomains$/i.test(p)),
    preload: parts.some((p) => /^preload$/i.test(p))
  };
}

export function parseCsp(value) {
  if (!value) return { present: false, directives: {} };
  const directives = {};
  for (const part of value.split(";")) {
    const pieces = part.trim().split(/\s+/).filter(Boolean);
    if (!pieces.length) continue;
    const [name, ...values] = pieces;
    directives[name.toLowerCase()] = values;
  }
  return { present: true, directives };
}

export function parseCookies(setCookies = []) {
  return setCookies.map((raw) => {
    const [pair, ...attributes] = String(raw).split(";").map((p) => p.trim());
    const [name] = pair.split("=");
    const lower = attributes.map((a) => a.toLowerCase());
    const sameSiteAttr = attributes.find((a) => /^samesite=/i.test(a));
    return {
      name,
      secure: lower.includes("secure"),
      httpOnly: lower.includes("httponly"),
      sameSite: sameSiteAttr ? sameSiteAttr.split("=")[1] : null,
      raw
    };
  });
}

export function analyzeHeaders(headers, options = {}) {
  const { setCookies = [], isDocument = true } = options;
  const findings = [];
  const checks = [];

  const push = (finding) => findings.push(finding);
  const check = (name, status, detail) => checks.push({ name, status, detail });

  const hsts = parseHsts(getHeader(headers, "strict-transport-security"));
  if (!hsts.present) {
    push({
      id: "HSTS-001",
      title: "Strict-Transport-Security header is missing",
      severity: "medium",
      category: "Transport",
      evidence: "No Strict-Transport-Security response header.",
      impact: "First-visit and downgrade attacks can intercept traffic before the browser learns to use HTTPS.",
      recommendation: "Send HSTS with max-age=63072000; includeSubDomains; preload after confirming every subdomain is HTTPS-only."
    });
    check("HSTS", "fail", "missing");
  } else if (!hsts.includeSubDomains) {
    push({
      id: "HSTS-002",
      title: "HSTS does not cover subdomains",
      severity: "low",
      category: "Transport",
      evidence: `Strict-Transport-Security: ${getHeader(headers, "strict-transport-security")}`,
      impact: "Subdomains such as the intern portal can be downgraded or stripped independently.",
      recommendation: "Add includeSubDomains and preload after auditing all subdomains."
    });
    check("HSTS", "warn", "missing includeSubDomains");
  } else {
    check("HSTS", "pass", `max-age=${hsts.maxAge}`);
  }

  const csp = parseCsp(getHeader(headers, "content-security-policy"));
  if (isDocument && !csp.present) {
    push({
      id: "CSP-001",
      title: "Content-Security-Policy is not set",
      severity: "high",
      category: "Browser hardening",
      evidence: "No Content-Security-Policy response header on HTML documents.",
      impact: "Any injected or compromised third-party script can execute freely, read the DOM, and exfiltrate credentials or payment state.",
      recommendation: "Deploy a nonce-based CSP with strict-dynamic, object-src 'none', base-uri 'self', and frame-ancestors 'none'. Roll out in report-only mode first."
    });
    check("CSP", "fail", "missing");
  } else if (csp.present) {
    const directives = csp.directives;
    if (!directives["object-src"]) {
      push({
        id: "CSP-002",
        title: "CSP does not restrict object-src",
        severity: "low",
        category: "Browser hardening",
        evidence: "Content-Security-Policy has no object-src directive.",
        impact: "Legacy plugin content can be embedded from unintended origins.",
        recommendation: "Add object-src 'none'."
      });
    }
    if (!directives["frame-ancestors"]) {
      push({
        id: "CSP-003",
        title: "CSP does not restrict framing",
        severity: "medium",
        category: "Browser hardening",
        evidence: "Content-Security-Policy has no frame-ancestors directive.",
        impact: "The page can be framed for clickjacking unless X-Frame-Options is also present.",
        recommendation: "Add frame-ancestors 'none' (or the explicit allowed origins)."
      });
    }
    const scriptSrc = (directives["script-src"] || []).join(" ");
    if (scriptSrc.includes("'unsafe-inline'")) {
      push({
        id: "CSP-004",
        title: "CSP allows unsafe inline scripts",
        severity: "medium",
        category: "Browser hardening",
        evidence: "script-src contains 'unsafe-inline'.",
        impact: "Inline injection still executes, weakening the main benefit of CSP.",
        recommendation: "Use per-request nonces or hashes plus strict-dynamic instead of unsafe-inline."
      });
    }
    if (scriptSrc.includes("'unsafe-eval'")) {
      push({
        id: "CSP-005",
        title: "CSP allows eval",
        severity: "low",
        category: "Browser hardening",
        evidence: "script-src contains 'unsafe-eval'.",
        impact: "String-to-code execution remains available to injected scripts.",
        recommendation: "Remove unsafe-eval and refactor code that depends on it."
      });
    }
    check("CSP", "pass", "present");
  }

  const frameAncestors = csp.directives?.["frame-ancestors"]?.join(" ");
  const xfo = getHeader(headers, "x-frame-options");
  if (isDocument && !xfo && !frameAncestors) {
    push({
      id: "XFO-001",
      title: "No clickjacking protection",
      severity: "medium",
      category: "Browser hardening",
      evidence: "Neither X-Frame-Options nor CSP frame-ancestors is present.",
      impact: "Attackers can overlay the site in a frame to capture clicks or credentials.",
      recommendation: "Set frame-ancestors 'none' and X-Frame-Options: DENY."
    });
    check("Frame protection", "fail", "missing");
  } else {
    check("Frame protection", "pass", frameAncestors || xfo);
  }

  const nosniff = getHeader(headers, "x-content-type-options");
  if (String(nosniff).toLowerCase() !== "nosniff") {
    push({
      id: "MIME-001",
      title: "X-Content-Type-Options is missing",
      severity: "low",
      category: "Browser hardening",
      evidence: "No X-Content-Type-Options: nosniff header.",
      impact: "Browsers may MIME-sniff responses and execute content as a different type.",
      recommendation: "Send X-Content-Type-Options: nosniff on every response."
    });
    check("nosniff", "fail", "missing");
  } else {
    check("nosniff", "pass", "present");
  }

  const referrer = getHeader(headers, "referrer-policy");
  if (!referrer) {
    push({
      id: "REF-001",
      title: "Referrer-Policy is missing",
      severity: "medium",
      category: "Browser hardening",
      evidence: "No Referrer-Policy response header.",
      impact: "Sensitive URL parameters, including payment or reset tokens, can leak to third parties via the Referer header.",
      recommendation: "Send Referrer-Policy: strict-origin-when-cross-origin, and no-referrer on token-bearing return and reset pages."
    });
    check("Referrer-Policy", "fail", "missing");
  } else if (/unsafe-url|no-referrer-when-downgrade/i.test(referrer)) {
    push({
      id: "REF-002",
      title: "Referrer-Policy is permissive",
      severity: "low",
      category: "Browser hardening",
      evidence: `Referrer-Policy: ${referrer}`,
      impact: "Full URLs can leak to third-party origins.",
      recommendation: "Use strict-origin-when-cross-origin or no-referrer for sensitive flows."
    });
    check("Referrer-Policy", "warn", referrer);
  } else {
    check("Referrer-Policy", "pass", referrer);
  }

  const permissions = getHeader(headers, "permissions-policy");
  if (!permissions) {
    push({
      id: "PERM-001",
      title: "Permissions-Policy is missing",
      severity: "low",
      category: "Browser hardening",
      evidence: "No Permissions-Policy response header.",
      impact: "Powerful browser features remain available to embedded or injected code.",
      recommendation: "Disable features the site does not use, for example camera=(), microphone=(), geolocation=(), payment=(), usb=()."
    });
    check("Permissions-Policy", "fail", "missing");
  } else {
    check("Permissions-Policy", "pass", "present");
  }

  const coop = getHeader(headers, "cross-origin-opener-policy");
  if (isDocument && !coop) {
    push({
      id: "COOP-001",
      title: "Cross-Origin-Opener-Policy is missing",
      severity: "low",
      category: "Browser hardening",
      evidence: "No Cross-Origin-Opener-Policy response header.",
      impact: "Cross-window attacks and Spectre-style isolation gaps are more likely.",
      recommendation: "Send Cross-Origin-Opener-Policy: same-origin on documents."
    });
  } else if (coop) {
    check("COOP", "pass", coop);
  }

  const corp = getHeader(headers, "cross-origin-resource-policy");
  if (!corp) {
    push({
      id: "CORP-001",
      title: "Cross-Origin-Resource-Policy is missing",
      severity: "low",
      category: "Browser hardening",
      evidence: "No Cross-Origin-Resource-Policy response header.",
      impact: "Other sites can embed resources in ways that enable side-channel or data-leak attacks.",
      recommendation: "Send Cross-Origin-Resource-Policy: same-origin (or same-site where needed)."
    });
  } else {
    check("CORP", "pass", corp);
  }

  const acao = getHeader(headers, "access-control-allow-origin");
  const acac = getHeader(headers, "access-control-allow-credentials");
  if (acao === "*" && String(acac).toLowerCase() === "true") {
    push({
      id: "CORS-001",
      title: "Wildcard CORS with credentials",
      severity: "critical",
      category: "API",
      evidence: "Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true.",
      impact: "Any origin can read authenticated responses, which is a direct account data exposure.",
      recommendation: "Never combine wildcard origins with credentials. Use an explicit allowlist and Vary: Origin."
    });
    check("CORS", "fail", "wildcard with credentials");
  } else if (acao === "*") {
    push({
      id: "CORS-002",
      title: "Wildcard Access-Control-Allow-Origin",
      severity: "medium",
      category: "API",
      evidence: "Access-Control-Allow-Origin: * on a document response.",
      impact: "Cross-origin scripts can read the response. If the same policy is applied to JSON or server actions, it becomes a data exposure.",
      recommendation: "Remove CORS headers from document routes and use an explicit origin allowlist for APIs."
    });
    check("CORS", "warn", "wildcard");
  } else if (acao) {
    check("CORS", "pass", acao);
  }

  const poweredBy = getHeader(headers, "x-powered-by");
  if (poweredBy) {
    push({
      id: "INFO-001",
      title: "Framework version disclosure",
      severity: "low",
      category: "Information disclosure",
      evidence: `X-Powered-By: ${poweredBy}`,
      impact: "Reduces the effort needed to fingerprint the stack and target known issues.",
      recommendation: "Set poweredByHeader: false in Next.js and remove unnecessary server banners."
    });
    check("X-Powered-By", "warn", poweredBy);
  }

  const cookies = parseCookies(setCookies);
  for (const cookie of cookies) {
    if (!cookie.secure) {
      push({
        id: "COOKIE-001",
        title: `Cookie ${cookie.name} is missing Secure`,
        severity: "medium",
        category: "Session",
        evidence: cookie.raw,
        impact: "The cookie can be sent over plaintext HTTP if a downgrade or mixed-content path exists.",
        recommendation: "Set Secure on all session and CSRF cookies."
      });
    }
    if (!cookie.httpOnly) {
      push({
        id: "COOKIE-002",
        title: `Cookie ${cookie.name} is missing HttpOnly`,
        severity: "medium",
        category: "Session",
        evidence: cookie.raw,
        impact: "Client-side scripts, including any injected script, can read the cookie.",
        recommendation: "Set HttpOnly on session cookies. Keep tokens out of localStorage."
      });
    }
    if (!cookie.sameSite) {
      push({
        id: "COOKIE-003",
        title: `Cookie ${cookie.name} is missing SameSite`,
        severity: "low",
        category: "Session",
        evidence: cookie.raw,
        impact: "Defaults vary by browser and may permit cross-site sending.",
        recommendation: "Set SameSite=Lax or Strict on session cookies."
      });
    }
  }
  if (cookies.length) {
    check("Cookies", cookies.every((c) => c.secure && c.httpOnly) ? "pass" : "warn", `${cookies.length} cookie(s)`);
  }

  const server = getHeader(headers, "server");
  if (server) check("Server banner", "info", server);

  return { findings, checks, hsts, csp, cookies, observations: { server, acao, poweredBy, referrer } };
}

export function analyzeRobots(text) {
  const findings = [];
  const checks = [];
  if (!text) {
    checks.push({ name: "robots.txt", status: "info", detail: "not present" });
    return { findings, checks, sensitivePaths: [] };
  }
  const sensitive = ["/api/", "/admin/", "/portal/", "/dashboard", "/internal", "/private", "/.git"];
  const disallowed = [];
  for (const line of text.split(/\r?\n/)) {
    const match = line.match(/^\s*Disallow:\s*(\S+)/i);
    if (!match) continue;
    const path = match[1];
    if (sensitive.some((s) => path.toLowerCase().startsWith(s))) disallowed.push(path);
  }
  const unique = [...new Set(disallowed)];
  if (unique.length) {
    findings.push({
      id: "ROBOTS-001",
      title: "robots.txt advertises sensitive application paths",
      severity: "low",
      category: "Information disclosure",
      evidence: `Disallow entries: ${unique.join(", ")}`,
      impact: "robots.txt is public and is not an access control. Listing private paths helps attackers prioritize targets.",
      recommendation: "Remove private path names from robots.txt and enforce authentication and authorization at the edge and in the application."
    });
  }
  checks.push({ name: "robots.txt", status: unique.length ? "warn" : "pass", detail: unique.join(", ") || "present" });
  return { findings, checks, sensitivePaths: unique };
}

export function analyzeSecurityTxt(status) {
  if (status === 200) {
    return {
      findings: [],
      checks: [{ name: "security.txt", status: "pass", detail: "present" }]
    };
  }
  return {
    findings: [
      {
        id: "DISC-001",
        title: "No vulnerability disclosure policy",
        severity: "low",
        category: "Governance",
        evidence: `/.well-known/security.txt returned HTTP ${status}.`,
        impact: "Researchers have no safe, documented way to report vulnerabilities, increasing the chance of public disclosure or extortion.",
        recommendation: "Publish /.well-known/security.txt with Contact, Expires, Preferred-Languages, and a disclosure policy."
      }
    ],
    checks: [{ name: "security.txt", status: "fail", detail: `HTTP ${status}` }]
  };
}

export function analyzeSourceMap(status) {
  if (status === 200) {
    return {
      findings: [
        {
          id: "SRCMAP-001",
          title: "Publicly accessible JavaScript source map",
          severity: "medium",
          category: "Information disclosure",
          evidence: "A .js.map asset returned HTTP 200.",
          impact: "Source maps expose original source, internal module structure, comments, and sometimes endpoints or secrets.",
          recommendation: "Disable production source maps, or restrict them to authenticated internal users."
        }
      ],
      checks: [{ name: "Source maps", status: "fail", detail: "publicly readable" }]
    };
  }
  return {
    findings: [],
    checks: [{ name: "Source maps", status: "pass", detail: `HTTP ${status}` }]
  };
}

export function analyzeTls(info, hostname) {
  const findings = [];
  const checks = [];
  if (!info || info.error) {
    findings.push({
      id: "TLS-000",
      title: "TLS handshake could not be verified",
      severity: "medium",
      category: "Transport",
      evidence: info?.error ? String(info.error.message || info.error) : "No TLS information.",
      impact: "Encryption and certificate validity cannot be confirmed.",
      recommendation: "Verify the endpoint serves a valid certificate chain over TLS 1.2 or newer."
    });
    return { findings, checks };
  }
  if (!["TLSv1.2", "TLSv1.3"].includes(info.protocol)) {
    findings.push({
      id: "TLS-001",
      title: "Obsolete TLS protocol enabled",
      severity: "high",
      category: "Transport",
      evidence: `Negotiated protocol: ${info.protocol}`,
      impact: "TLS 1.0 and 1.1 have known weaknesses and are not permitted by modern compliance baselines.",
      recommendation: "Allow only TLS 1.2 and TLS 1.3, with strong cipher suites."
    });
    checks.push({ name: "TLS version", status: "fail", detail: info.protocol });
  } else {
    checks.push({ name: "TLS version", status: "pass", detail: info.protocol });
  }
  if (info.cert) {
    const host = String(hostname).toLowerCase();
    const names = (info.cert.subjectAltName || "")
      .split(",")
      .map((s) => s.trim().replace(/^DNS:/i, "").toLowerCase())
      .filter(Boolean);
    const covered = names.some((name) => {
      if (name === host) return true;
      if (name.startsWith("*.")) return host.endsWith(name.slice(1)) && host.split(".").length === name.split(".").length;
      return false;
    });
    if (names.length && !covered) {
      findings.push({
        id: "TLS-002",
        title: "Certificate does not cover the scanned hostname",
        severity: "high",
        category: "Transport",
        evidence: `${hostname} not present in SAN list: ${names.join(", ")}`,
        impact: "Browsers will reject the connection or users will be trained to bypass warnings.",
        recommendation: "Issue a certificate whose SAN covers every public hostname, and automate renewal."
      });
    }
    const expires = info.cert.validTo ? new Date(info.cert.validTo) : null;
    if (expires) {
      const days = Math.floor((expires.getTime() - Date.now()) / 86400000);
      if (days < 14) {
        findings.push({
          id: "TLS-003",
          title: "TLS certificate expires soon",
          severity: "medium",
          category: "Transport",
          evidence: `Certificate expires ${info.cert.validTo} (${days} days).`,
          impact: "Expiry causes a full outage for browsers and API clients.",
          recommendation: "Automate renewal and add expiry monitoring with at least 21 days of alerting."
        });
      } else if (days < 30) {
        findings.push({
          id: "TLS-004",
          title: "TLS certificate expiry is within 30 days",
          severity: "low",
          category: "Transport",
          evidence: `Certificate expires ${info.cert.validTo} (${days} days).`,
          impact: "Renewal failures become outages.",
          recommendation: "Automate renewal and alert on expiry."
        });
      }
      checks.push({ name: "TLS certificate", status: days >= 14 ? "pass" : "warn", detail: `${days} days remaining` });
    }
  }
  return { findings, checks };
}

export function analyzeHttpRedirect(result) {
  if (!result) {
    return { findings: [], checks: [{ name: "HTTP to HTTPS", status: "info", detail: "not checked" }] };
  }
  if (!result.error && [301, 302, 307, 308].includes(result.status) && String(result.location || "").startsWith("https://")) {
    return {
      findings: [],
      checks: [{ name: "HTTP to HTTPS", status: "pass", detail: `${result.status} -> ${result.location}` }]
    };
  }
  return {
    findings: [
      {
        id: "HTTP-001",
        title: "Plaintext HTTP is not permanently redirected to HTTPS",
        severity: "high",
        category: "Transport",
        evidence: result.error ? String(result.error.message || result.error) : `HTTP ${result.status}, Location: ${result.location || "none"}`,
        impact: "Users and integrations can be downgraded to plaintext, enabling interception and cookie theft.",
        recommendation: "Redirect HTTP to HTTPS with 301 or 308 and enable HSTS."
      }
    ],
    checks: [{ name: "HTTP to HTTPS", status: "fail", detail: result.error ? "error" : `HTTP ${result.status}` }]
  };
}

export function analyzeCacheControl(headers, url) {
  const value = String(getHeader(headers, "cache-control") || "");
  const isStatic = /\/_next\/static\//.test(url);
  if (!isStatic) return { findings: [], checks: [] };
  if (/immutable/i.test(value) && /max-age=(\d+)/i.test(value)) {
    const maxAge = Number(value.match(/max-age=(\d+)/i)[1]);
    if (maxAge >= 31536000) {
      return { findings: [], checks: [{ name: "Static cache", status: "pass", detail: value }] };
    }
  }
  return {
    findings: [
      {
        id: "CACHE-001",
        title: "Static assets are not immutable-cached",
        severity: "low",
        category: "Performance",
        evidence: `Cache-Control: ${value || "missing"} on ${url}`,
        impact: "Repeat visits revalidate assets and waste bandwidth.",
        recommendation: "Serve content-hashed assets with Cache-Control: public, max-age=31536000, immutable."
      }
    ],
    checks: [{ name: "Static cache", status: "warn", detail: value || "missing" }]
  };
}

export function scoreFindings(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let deduction = 0;
  for (const finding of findings) {
    counts[finding.severity] = (counts[finding.severity] || 0) + 1;
    deduction += DEDUCTIONS[finding.severity] || 0;
  }
  const score = Math.max(0, 100 - Math.min(100, deduction));
  const grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F";
  return { score, grade, counts };
}

export function sortFindings(findings) {
  return [...findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || a.id.localeCompare(b.id)
  );
}

export function summarize(findings) {
  const { score, grade, counts } = scoreFindings(findings);
  const total = findings.length;
  return { score, grade, counts, total };
}
