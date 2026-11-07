import { createHmac, timingSafeEqual } from "node:crypto";

const API_VERSION = "2023-08-01";

function required(name: string) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not configured`);
  return value;
}

type CreateOrderInput = {
  orderId: string;
  amountMinor: number;
  currency: string;
  customerId: string;
  customerName: string;
  customerEmail: string;
  customerPhone: string;
};

export async function createCashfreeOrder(input: CreateOrderInput) {
  const response = await fetch("https://api.cashfree.com/pg/orders", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-version": API_VERSION,
      "x-client-id": required("CASHFREE_CLIENT_ID"),
      "x-client-secret": required("CASHFREE_CLIENT_SECRET")
    },
    body: JSON.stringify({
      order_id: input.orderId,
      order_amount: Number((input.amountMinor / 100).toFixed(2)),
      order_currency: input.currency,
      customer_details: {
        customer_id: input.customerId,
        customer_name: input.customerName,
        customer_email: input.customerEmail,
        customer_phone: input.customerPhone
      }
    }),
    cache: "no-store"
  });

  if (!response.ok) {
    throw new Error(`Cashfree order creation failed with status ${response.status}`);
  }

  return (await response.json()) as {
    payment_session_id: string;
    order_id: string;
  };
}

export function verifyCashfreeSignature(
  rawBody: string,
  timestamp: string | null,
  signature: string | null
) {
  if (!timestamp || !signature) return false;
  const rawTimestamp = Number(timestamp);
  if (!Number.isFinite(rawTimestamp)) return false;
  const timestampMs = rawTimestamp > 1e12 ? rawTimestamp : rawTimestamp * 1000;
  const age = Math.abs(Date.now() - timestampMs);
  if (age > 300_000) return false;

  const expected = createHmac("sha256", required("CASHFREE_CLIENT_SECRET"))
    .update(`${timestamp}${rawBody}`)
    .digest("base64");

  const supplied = Buffer.from(signature, "base64");
  const computed = Buffer.from(expected, "base64");
  return supplied.length === computed.length && timingSafeEqual(supplied, computed);
}
