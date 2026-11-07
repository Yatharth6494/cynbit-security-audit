import { createHardeningServer } from "../src/hardening/server.mjs";

const BASE_LIMITS = { mutation: 200, contact: 200, checkout: 200, auth: 200, webhook: 200 };

export async function startTestServer(options = {}) {
  const sent = [];
  const logs = [];
  const mailer = {
    async send(message) {
      sent.push(message);
    }
  };
  const app = createHardeningServer({
    secret: "test-app-secret",
    webhookSecret: "test-webhook-secret",
    secureCookies: false,
    mailer,
    logSink: (line) => logs.push(JSON.parse(line)),
    rateLimits: { ...BASE_LIMITS, ...(options.rateLimits || {}) },
    ...options
  });
  const { url } = await app.start();
  return {
    app,
    url,
    sent,
    logs,
    async close() {
      await app.stop();
    }
  };
}

export async function postJson(url, path, body, headers = {}) {
  return fetch(`${url}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: typeof body === "string" ? body : JSON.stringify(body)
  });
}

export const validCheckout = {
  fullName: "Aarav Sharma",
  email: "aarav@example.com",
  phone: "+91 98765 43210",
  university: "SKIT Jaipur",
  track: "Full Stack",
  duration: "60 Days",
  referralName: "",
  ambitions: "Build production systems and learn secure backend engineering."
};
