import { sortFindings, summarize } from "./checks.mjs";

const LABELS = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  info: "INFO"
};

export function renderText(result) {
  const summary = summarize(result.findings);
  const lines = [];
  lines.push(`Passive posture report for ${result.target}`);
  lines.push(`Scanned: ${result.scannedAt}`);
  lines.push(`Score: ${summary.score}/100 (grade ${summary.grade}) | findings: ${summary.total}`);
  lines.push("");
  for (const finding of sortFindings(result.findings)) {
    lines.push(`[${LABELS[finding.severity]}] ${finding.id} ${finding.title}`);
    lines.push(`  ${finding.evidence.replace(/\s+/g, " ").slice(0, 220)}`);
  }
  if (!result.findings.length) lines.push("No issues detected by the passive checks.");
  return lines.join("\n");
}

export function renderMarkdown(result) {
  const summary = summarize(result.findings);
  const lines = [];
  lines.push(`# Passive Security Posture Report`);
  lines.push("");
  lines.push(`- Target: ${result.target}`);
  lines.push(`- Final URL: ${result.finalUrl}`);
  lines.push(`- Scanned at: ${result.scannedAt}`);
  lines.push(`- Score: **${summary.score}/100** (grade **${summary.grade}**)`);
  lines.push(
    `- Findings: ${summary.total} (critical ${summary.counts.critical}, high ${summary.counts.high}, medium ${summary.counts.medium}, low ${summary.counts.low}, info ${summary.counts.info})`
  );
  lines.push("");
  lines.push(`## Checks`);
  lines.push("");
  lines.push(`| Check | Status | Detail |`);
  lines.push(`| --- | --- | --- |`);
  for (const check of result.checks) {
    lines.push(`| ${escapeCell(check.name)} | ${check.status} | ${escapeCell(check.detail || "")} |`);
  }
  lines.push("");
  lines.push(`## Findings`);
  lines.push("");
  if (!result.findings.length) {
    lines.push("No issues detected by the passive checks.");
  }
  for (const finding of sortFindings(result.findings)) {
    lines.push(`### ${finding.id} - ${finding.title}`);
    lines.push("");
    lines.push(`- Severity: **${LABELS[finding.severity]}**`);
    lines.push(`- Category: ${finding.category}`);
    lines.push(`- Evidence: \`${String(finding.evidence).replace(/\n/g, " ").slice(0, 500)}\``);
    lines.push(`- Impact: ${finding.impact}`);
    lines.push(`- Recommendation: ${finding.recommendation}`);
    lines.push("");
  }
  lines.push(`## Transport`);
  lines.push("");
  lines.push(`- TLS protocol: ${result.tls?.protocol || "unknown"}`);
  lines.push(`- Cipher: ${result.tls?.cipher || "unknown"}`);
  lines.push(`- Certificate: ${result.tls?.cert?.subject || "unknown"}`);
  lines.push(`- Issuer: ${result.tls?.cert?.issuer || "unknown"}`);
  lines.push(`- Valid to: ${result.tls?.cert?.validTo || "unknown"}`);
  lines.push(`- HTTP redirect: ${result.httpRedirect ? `${result.httpRedirect.status} -> ${result.httpRedirect.location || "none"}` : "not checked"}`);
  lines.push("");
  lines.push(`## Performance observations`);
  lines.push("");
  lines.push(`- TTFB: ${result.performance?.ttfbMs ?? "n/a"} ms`);
  lines.push(`- Total document fetch: ${result.performance?.totalMs ?? "n/a"} ms`);
  lines.push(`- HTML bytes: ${result.performance?.documentBytes ?? "n/a"}`);
  lines.push(`- Content-Length: ${result.performance?.contentLength ?? "n/a"}`);
  lines.push(`- Script tags: ${result.performance?.scriptCount ?? "n/a"}`);
  lines.push(`- Stylesheets: ${result.performance?.styleCount ?? "n/a"}`);
  lines.push(`- Compression: ${result.performance?.contentEncoding || "none observed"}`);
  lines.push(`- Edge cache: ${result.performance?.edgeCache || "not observed"}`);
  lines.push(`- Assets sampled: ${result.performance?.assets?.length ?? 0}`);
  lines.push("");
  lines.push(`## Files probed`);
  lines.push("");
  lines.push(`| Path | Status |`);
  lines.push(`| --- | --- |`);
  for (const file of result.files) {
    lines.push(`| ${escapeCell(file.path)} | ${file.status ?? file.error ?? "unknown"} |`);
  }
  lines.push("");
  lines.push(`## Scope and limitations`);
  lines.push("");
  lines.push(
    `This is a read-only assessment of publicly served content. It does not authenticate, submit forms, fuzz inputs, attempt exploitation, or access private areas. Absence of a header or control is observable; presence of server-side validation or edge controls may not be.`
  );
  lines.push("");
  return lines.join("\n");
}

export function renderJson(result) {
  return JSON.stringify(result, null, 2);
}

function escapeCell(value) {
  return String(value).replace(/\|/g, "\\|").replace(/\n/g, " ");
}
