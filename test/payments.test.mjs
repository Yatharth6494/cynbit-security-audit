import test from "node:test";
import assert from "node:assert/strict";
import { startTestServer, postJson, validCheckout } from "./helpers.mjs";
import { signWebhook } from "../src/hardening/crypto.mjs";

const WEBHOOK_SECRET = "test-webhook-secret";

function signedWebhook(body, options = {}) {
  const raw = JSON.stringify(body);
  const timestamp = options.timestamp ?? Math.floor(Date.now() / 1000);
  const signature = options.signature ?? signWebhook(WEBHOOK_SECRET, timestamp, raw);
  return { raw, headers: { "x-webhook-timestamp": String(timestamp), "x-webhook-signature": signature } };
}

async function createOrder(server) {
  const response = await postJson(server.url, "/api/payments/checkout", validCheckout);
  assert.equal(response.status, 201);
  return response.json();
}

test("payment flow provisions access without exposing a password", async () => {
  const server = await startTestServer();
  try {
    const order = await createOrder(server);
    assert.equal(order.amount, 399900);
    assert.equal(order.currency, "INR");
    assert.ok(order.orderId);
    assert.equal(JSON.stringify(order).includes("password"), false);
    assert.equal(JSON.stringify(order).includes("token"), false);

    const event = signedWebhook({
      eventId: "evt_001",
      orderId: order.orderId,
      amount: order.amount,
      currency: order.currency,
      status: "PAID"
    });
    const webhook = await fetch(`${server.url}/api/payments/webhook`, {
      method: "POST",
      headers: { "content-type": "application/json", ...event.headers },
      body: event.raw
    });
    assert.equal(webhook.status, 200);
    const webhookBody = await webhook.text();
    assert.equal(webhookBody.includes("password"), false);
    assert.equal(webhookBody.includes("token="), false);
    assert.equal(server.sent.length, 1);
    assert.ok(server.sent[0].setupUrl.includes("/set-password?token="));

    const replay = await fetch(`${server.url}/api/payments/webhook`, {
      method: "POST",
      headers: { "content-type": "application/json", ...event.headers },
      body: event.raw
    });
    assert.equal(replay.status, 200);
    assert.equal((await replay.json()).duplicate, true);
    assert.equal(server.sent.length, 1);

    const token = new URL(server.sent[0].setupUrl).searchParams.get("token");
    const weak = await postJson(server.url, "/api/portal/set-password", {
      token,
      password: "short"
    });
    assert.equal(weak.status, 400);

    const setPassword = await postJson(server.url, "/api/portal/set-password", {
      token,
      password: "CorrectHorse9Battery"
    });
    assert.equal(setPassword.status, 200);

    const reuse = await postJson(server.url, "/api/portal/set-password", {
      token,
      password: "CorrectHorse9Battery"
    });
    assert.equal(reuse.status, 400);

    const wrongLogin = await postJson(server.url, "/api/portal/login", {
      email: validCheckout.email,
      password: "WrongPassword9"
    });
    assert.equal(wrongLogin.status, 401);

    const login = await postJson(server.url, "/api/portal/login", {
      email: validCheckout.email,
      password: "CorrectHorse9Battery"
    });
    assert.equal(login.status, 200);
    const cookie = login.headers.get("set-cookie");
    assert.match(cookie, /HttpOnly/);
    assert.match(cookie, /SameSite=Lax/);
    assert.match(cookie, /Path=\//);

    const me = await fetch(`${server.url}/api/portal/me`, {
      headers: { cookie: cookie.split(";")[0] }
    });
    assert.equal(me.status, 200);
    const profile = await me.json();
    assert.equal(profile.email, validCheckout.email);
    assert.equal(profile.passwordHash, undefined);
  } finally {
    await server.close();
  }
});

test("webhook rejects a bad signature", async () => {
  const server = await startTestServer();
  try {
    const order = await createOrder(server);
    const event = signedWebhook(
      {
        eventId: "evt_bad",
        orderId: order.orderId,
        amount: order.amount,
        currency: order.currency,
        status: "PAID"
      },
      { signature: "0".repeat(64) }
    );
    const response = await fetch(`${server.url}/api/payments/webhook`, {
      method: "POST",
      headers: { "content-type": "application/json", ...event.headers },
      body: event.raw
    });
    assert.equal(response.status, 401);
    assert.equal(server.sent.length, 0);
  } finally {
    await server.close();
  }
});

test("webhook rejects amount tampering and does not provision", async () => {
  const server = await startTestServer();
  try {
    const order = await createOrder(server);
    const event = signedWebhook({
      eventId: "evt_tamper",
      orderId: order.orderId,
      amount: 1,
      currency: order.currency,
      status: "PAID"
    });
    const response = await fetch(`${server.url}/api/payments/webhook`, {
      method: "POST",
      headers: { "content-type": "application/json", ...event.headers },
      body: event.raw
    });
    assert.equal(response.status, 400);
    assert.equal((await response.json()).error.code, "amount_mismatch");
    assert.equal(server.sent.length, 0);
    assert.equal(server.app.store.getOrder(order.orderId).status, "CREATED");
  } finally {
    await server.close();
  }
});

test("webhook rejects replay outside the timestamp tolerance", async () => {
  const server = await startTestServer();
  try {
    const order = await createOrder(server);
    const event = signedWebhook(
      {
        eventId: "evt_old",
        orderId: order.orderId,
        amount: order.amount,
        currency: order.currency,
        status: "PAID"
      },
      { timestamp: Math.floor(Date.now() / 1000) - 3600 }
    );
    const response = await fetch(`${server.url}/api/payments/webhook`, {
      method: "POST",
      headers: { "content-type": "application/json", ...event.headers },
      body: event.raw
    });
    assert.equal(response.status, 401);
    assert.equal(server.sent.length, 0);
  } finally {
    await server.close();
  }
});
