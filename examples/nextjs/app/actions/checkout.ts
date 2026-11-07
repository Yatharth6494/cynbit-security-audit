"use server";

import { randomUUID } from "node:crypto";
import { headers } from "next/headers";
import { createCashfreeOrder } from "@/lib/cashfree";
import { prisma } from "@/lib/prisma";
import { rateLimit } from "@/lib/rate-limit";
import { checkoutSchema } from "@/lib/validation";

const CATALOG = {
  "bitelevate-60": {
    productId: "bitelevate-60",
    name: "BitElevate 60-Day Sprint",
    amountMinor: 399900,
    currency: "INR"
  }
} as const;

export async function createBitelevateOrder(formData: FormData) {
  const headerStore = await headers();
  const forwarded = headerStore.get("x-forwarded-for");
  const ip = forwarded?.split(",")[0].trim() || headerStore.get("x-real-ip") || "unknown";

  const limit = await rateLimit(`checkout:${ip}`, 5, 60);
  if (!limit.allowed) return { ok: false, error: "Too many checkout attempts. Try again shortly." };

  const parsed = checkoutSchema.safeParse(Object.fromEntries(formData));
  if (!parsed.success) return { ok: false, error: "Check your details and try again." };
  if (parsed.data.website) return { ok: false, error: "Unable to start checkout." };

  const product = CATALOG["bitelevate-60"];
  const providerOrderId = `ord_${randomUUID().replace(/-/g, "").slice(0, 24)}`;

  const order = await prisma.order.create({
    data: {
      providerOrderId,
      provider: "cashfree",
      amountMinor: product.amountMinor,
      currency: product.currency,
      status: "CREATED",
      email: parsed.data.email,
      fullName: parsed.data.fullName,
      phone: parsed.data.phone,
      university: parsed.data.university,
      track: parsed.data.track,
      duration: parsed.data.duration,
      referralName: parsed.data.referralName,
      ambitions: parsed.data.ambitions
    }
  });

  let payment: Awaited<ReturnType<typeof createCashfreeOrder>>;
  try {
    payment = await createCashfreeOrder({
      orderId: providerOrderId,
      amountMinor: product.amountMinor,
      currency: product.currency,
      customerId: order.id,
      customerName: parsed.data.fullName,
      customerEmail: parsed.data.email,
      customerPhone: parsed.data.phone
    });
  } catch {
    await prisma.order.update({
      where: { id: order.id },
      data: { status: "FAILED" }
    });
    return { ok: false, error: "Unable to start checkout. Try again shortly." };
  }

  await prisma.order.update({
    where: { id: order.id },
    data: { paymentSessionId: payment.payment_session_id }
  });

  return {
    ok: true,
    orderId: providerOrderId,
    paymentSessionId: payment.payment_session_id,
    product: product.name,
    amount: product.amountMinor,
    currency: product.currency
  };
}
