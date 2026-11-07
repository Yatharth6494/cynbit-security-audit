#!/usr/bin/env node
import http from "node:http";
import tls from "node:tls";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import {
  analyzeCacheControl,
  analyzeHeaders,
  analyzeHttpRedirect,
  analyzeRobots,
  analyzeSecurityTxt,
  analyzeSourceMap,
  analyzeTls,
  summarize,
  SEVERITY_ORDER
} from "./checks.mjs";
import { renderJson, renderMarkdown, renderText } from "./render.mjs";

const USER_AGENT =
  "CynbitAuditScanner/1.0 (passive; read-only; +https://github.com/)";
const DEFAULT_TIMEOUT = 20000;

export async function runScan(target, options = {}) {
  const url = new URL(/^https?:\/\//i.test(target) ? target : `https://${target}`);
  if (url.protocol !== "https:") url.protocol = "https:";
  const hostname = url.hostname;
  const requestLog = [];

  const started = Date.now();
  const response = await fetchWithTimeout(url.href, { redirect: "follow" }, options.timeout);
  const ttfbMs = Date.now() - started;
  const headers = response.headers;
  const setCookies = typeof headers.getSetCookie === "function" ? headers.getSetCookie() : [];
  const html = await response.text();
  const totalMs = Date.now() - started;
  requestLog.push({ method: "GET", url: url.href, status: response.status });

  const headerAnalysis = analyzeHeaders(headers, { setCookies, isDocument: true });
  const findings = [...headerAnalysis.findings];
  const checks = [...headerAnalysis.checks];

  const scripts = extractAssets(html, "script", "src");
  const styles = extractAssets(html, "link", "href").filter((href) => /\.css(\?|$)/i.test(href));
  const scriptCandidates = scripts
    .filter((src) => !/polyfills|webpack/i.test(src))
    .slice(0, 4);

  if (scriptCandidates.length) {
    const absolute = new URL(scriptCandidates[0], url).href;
    const mapStatus = await probeStatus(`${absolute}.map`, options.timeout);
    const mapAnalysis = analyzeSourceMap(mapStatus);
    findings.push(...mapAnalysis.findings);
    checks.push(...mapAnalysis.checks);
    requestLog.push({ method: "GET", url: `${absolute}.map`, status: mapStatus });
  }

  const fileTargets = ["/robots.txt", "/.well-known/security.txt", "/sitemap.xml", "/.well-known/change-password"];
  const files = [];
  let robotsText = "";
  for (const filePath of fileTargets) {
    const fileUrl = new URL(filePath, url).href;
    try {
      const res = await fetchWithTimeout(fileUrl, { redirect: "follow" }, options.timeout);
      const text = filePath === "/robots.txt" ? await res.text() : "";
      files.push({ path: filePath, status: res.status, url: fileUrl });
      requestLog.push({ method: "GET", url: fileUrl, status: res.status });
      if (filePath === "/robots.txt" && res.status === 200) robotsText = text;
      if (filePath === "/.well-known/security.txt") {
        const securityTxt = analyzeSecurityTxt(res.status);
        findings.push(...securityTxt.findings);
        checks.push(...securityTxt.checks);
      }
    } catch (error) {
      files.push({ path: filePath, error: error.message });
    }
  }

  const robots = analyzeRobots(robotsText);
  findings.push(...robots.findings);
  checks.push(...robots.checks);

  const [tlsInfo, httpRedirect] = await Promise.all([
    inspectTls(hostname, options.timeout),
    inspectHttpRedirect(hostname, options.timeout)
  ]);
  const tlsAnalysis = analyzeTls(tlsInfo, hostname);
  findings.push(...tlsAnalysis.findings);
  checks.push(...tlsAnalysis.checks);
  const redirectAnalysis = analyzeHttpRedirect(httpRedirect);
  findings.push(...redirectAnalysis.findings);
  checks.push(...redirectAnalysis.checks);

  const assets = [];
  for (const asset of [...scriptCandidates.slice(0, 2), ...styles.slice(0, 1)]) {
    const absolute = new URL(asset, url).href;
    try {
      const res = await fetchWithTimeout(
        absolute,
        { method: "GET", headers: { "accept-encoding": "br, gzip" } },
        options.timeout
      );
      if (res.body) await res.body.cancel();
      const cacheAnalysis = analyzeCacheControl(res.headers, absolute);
      findings.push(...cacheAnalysis.findings);
      checks.push(...cacheAnalysis.checks);
      assets.push({
        url: absolute,
        status: res.status,
        contentLength: res.headers.get("content-length"),
        contentEncoding: res.headers.get("content-encoding"),
        cacheControl: res.headers.get("cache-control"),
        edgeCache: res.headers.get("x-vercel-cache")
      });
      requestLog.push({ method: "GET", url: absolute, status: res.status });
    } catch (error) {
      assets.push({ url: absolute, error: error.message });
    }
  }

  const result = {
    target: url.href,
    finalUrl: response.url,
    scannedAt: new Date().toISOString(),
    status: response.status,
    summary: summarize(findings),
    checks,
    findings,
    files,
    tls: {
      protocol: tlsInfo?.protocol,
      cipher: tlsInfo?.cipher,
      cert: tlsInfo?.cert,
      error: tlsInfo?.error ? String(tlsInfo.error.message || tlsInfo.error) : undefined
    },
    httpRedirect,
    performance: {
      ttfbMs,
      totalMs,
      documentBytes: Buffer.byteLength(html),
      contentLength: headers.get("content-length"),
      contentEncoding: headers.get("content-encoding"),
      edgeCache: headers.get("x-vercel-cache"),
      scriptCount: scripts.length,
      styleCount: styles.length,
      assets
    },
    observations: headerAnalysis.observations,
    requestLog
  };
  return result;
}

function extractAssets(html, tag, attribute) {
  const regex = new RegExp(`<${tag}[^>]+${attribute}="([^"]+)"`, "gi");
  const values = [];
  let match;
  while ((match = regex.exec(html))) values.push(match[1]);
  return [...new Set(values)];
}

async function fetchWithTimeout(url, init = {}, timeout = DEFAULT_TIMEOUT) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    return await fetch(url, {
      ...init,
      signal: controller.signal,
      headers: { "user-agent": USER_AGENT, ...(init.headers || {}) }
    });
  } finally {
    clearTimeout(timer);
  }
}

async function probeStatus(url, timeout) {
  try {
    const res = await fetchWithTimeout(url, { method: "GET" }, timeout);
    if (res.body) await res.body.cancel();
    return res.status;
  } catch {
    return 0;
  }
}

function inspectTls(host, timeout) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (value) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };
    const socket = tls.connect(
      { host, port: 443, servername: host, rejectUnauthorized: true, timeout },
      () => {
        try {
          const peer = socket.getPeerCertificate();
          const cert = peer && Object.keys(peer).length
            ? {
                subject: formatName(peer.subject),
                issuer: formatName(peer.issuer),
                validFrom: peer.valid_from,
                validTo: peer.valid_to,
                subjectAltName: peer.subjectaltname
              }
            : null;
          done({ protocol: socket.getProtocol(), cipher: socket.getCipher()?.name, cert });
        } catch (error) {
          done({ error });
        } finally {
          socket.end();
        }
      }
    );
    socket.on("error", (error) => done({ error }));
    socket.on("timeout", () => {
      socket.destroy();
      done({ error: new Error("TLS timeout") });
    });
  });
}

function formatName(name) {
  if (!name) return undefined;
  if (typeof name === "string") return name;
  const cn = name.CN ? `CN=${name.CN}` : "";
  const org = name.O ? `O=${name.O}` : "";
  return [cn, org].filter(Boolean).join(", ") || JSON.stringify(name);
}

function inspectHttpRedirect(host, timeout) {
  return new Promise((resolve) => {
    const request = http.request(
      {
        host,
        port: 80,
        path: "/",
        method: "GET",
        timeout,
        headers: { "user-agent": USER_AGENT }
      },
      (response) => {
        response.resume();
        resolve({ status: response.statusCode, location: response.headers.location });
      }
    );
    request.on("error", (error) => resolve({ error }));
    request.on("timeout", () => {
      request.destroy();
      resolve({ error: new Error("HTTP timeout") });
    });
    request.end();
  });
}

async function main() {
  const args = process.argv.slice(2);
  const target = args.find((arg) => !arg.startsWith("--"));
  if (!target) {
    console.error("Usage: node src/scanner/index.mjs <url> [--json] [--out <dir>] [--fail-on <severity>]");
    process.exit(2);
  }
  const json = args.includes("--json");
  const outIndex = args.indexOf("--out");
  const outDir = outIndex >= 0 ? args[outIndex + 1] : null;
  const failIndex = args.indexOf("--fail-on");
  const failOn = failIndex >= 0 ? args[failIndex + 1] : null;

  const result = await runScan(target);
  const markdown = renderMarkdown(result);

  if (json) {
    console.log(renderJson(result));
  } else {
    console.log(renderText(result));
  }

  if (outDir) {
    await mkdir(outDir, { recursive: true });
    await writeFile(path.join(outDir, "scan-report.md"), markdown);
    await writeFile(path.join(outDir, "scan-report.json"), renderJson(result));
    await writeFile(path.join(outDir, "scan-summary.txt"), renderText(result));
    console.error(`Wrote ${path.join(outDir, "scan-report.md")}`);
  }

  if (failOn) {
    const threshold = SEVERITY_ORDER.indexOf(failOn);
    if (threshold < 0) {
      console.error(`Unknown severity for --fail-on: ${failOn}`);
      process.exit(2);
    }
    const failing = result.findings.some((finding) => SEVERITY_ORDER.indexOf(finding.severity) <= threshold);
    process.exit(failing ? 1 : 0);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}
