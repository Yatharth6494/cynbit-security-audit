import { createHardeningServer } from "../src/hardening/server.mjs";
import { signWebhook } from "../src/hardening/crypto.mjs";

const WEBHOOK_SECRET = "demo-webhook-secret";
const sent = [];

const app = createHardeningServer({
  secret: "demo-app-secret",
  webhookSecret: WEBHOOK_SECRET,
  secureCookies: false,
  mailer: {
    async send(message) {
      sent.push(message);
    }
  },
  logSink: (line) => {
    const event = JSON.parse(line);
    if (event.event === "payment.fulfilled" || event.event === "auth.password_set") {
      console.log(`[log] ${event.event}`);
    }
  }
});

const { url } = await app.start();

async function postJson(path, body, headers = {}) {
  return fetch(`${url}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body)
  });
}

function line(label, value) {
  console.log(`${label.padEnd(24)} ${value}`);
}

try {
  console.log("Cynbit hardened payment and credential flow\n");

  const checkout = await postJson("/api/payments/checkout", {
    fullName: "Aarav Sharma",
    email: "aarav@example.com",
    phone: "+91 98765 43210",
    university: "SKIT Jaipur",
    track: "Full Stack",
    duration: "60 Days",
    referralName: "",
    ambitions: "Build production systems and learn secure backend engineering."
  });

  if (checkout.status !== 201) throw new Error(`checkout failed: ${checkout.status}`);
  const order = await checkout.json();
  line("order id", order.orderId);
  line("server price", `${order.amount} ${order.currency}`);
  line("password in response", String(JSON.stringify(order).includes("password")));

  const timestamp = Math.floor(Date.now() / 1000);
  const raw = JSON.stringify({
    eventId: "evt_demo_001",
    orderId: order.orderId,
    amount: order.amount,
    currency: order.currency,
    status: "PAID"
  });
  const signature = signWebhook(WEBHOOK_SECRET, timestamp, raw);

  const webhook = await fetch(`${url}/api/payments/webhook`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-webhook-timestamp": String(timestamp),
      "x-webhook-signature": signature
    },
    body: raw
  });
  if (webhook.status !== 200) throw new Error(`webhook failed: ${webhook.status}`);
  line("webhook", `${webhook.status} signed and accepted`);

  const replay = await fetch(`${url}/api/payments/webhook`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-webhook-timestamp": String(timestamp),
      "x-webhook-signature": signature
    },
    body: raw
  });
  const replayBody = await replay.json();
  line("replay", `${replay.status} duplicate=${replayBody.duplicate === true}`);
  line("emails sent", String(sent.length));

  const setupUrl = new URL(sent[0].setupUrl);
  const token = setupUrl.searchParams.get("token");
  line("setup token", `${token.slice(0, 8)}… (single use, 24h)`);

  const weak = await postJson("/api/portal/set-password", { token, password: "short" });
  line("weak password", `${weak.status} rejected`);

  const setPassword = await postJson("/api/portal/set-password", {
    token,
    password: "CorrectHorse9Battery"
  });
  line("set password", `${setPassword.status} accepted`);

  const reuse = await postJson("/api/portal/set-password", {
    token,
    password: "CorrectHorse9Battery"
  });
  line("token reuse", `${reuse.status} rejected`);

  const login = await postJson("/api/portal/login", {
    email: "aarav@example.com",
    password: "CorrectHorse9Battery"
  });
  if (login.status !== 200) throw new Error(`login failed: ${login.status}`);
  const cookie = login.headers.get("set-cookie");
  line("session cookie", cookie.split(";").slice(1).join(";").trim());

  const me = await fetch(`${url}/api/portal/me`, {
    headers: { cookie: cookie.split(";")[0] }
  });
  const profile = await me.json();
  line("authenticated as", profile.email);
  line("password hash leaked", String(JSON.stringify(profile).includes("passwordHash")));

  console.log("\nFlow complete. No password was returned to the browser.");
} catch (error) {
  console.error(`\nDemo failed: ${error.message}`);
  process.exitCode = 1;
} finally {
  await app.stop();
}
