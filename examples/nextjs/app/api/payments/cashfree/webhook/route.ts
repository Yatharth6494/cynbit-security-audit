import { z } from "zod";
import { verifyCashfreeSignature } from "@/lib/cashfree";
import { encryptSecret } from "@/lib/crypto";
import { createSetupToken } from "@/lib/passwords";
import { prisma } from "@/lib/prisma";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const webhookSchema = z.object({
  type: z.string().optional(),
  data: z.object({
    order: z.object({
      order_id: z.string().min(1).max(64),
      order_amount: z.union([z.number(), z.string()]),
      order_currency: z.string().length(3)
    }),
    payment: z.object({
      payment_status: z.string().min(1),
      cf_payment_id: z.union([z.string(), z.number()]).optional(),
      payment_id: z.string().optional()
    })
  })
});

function eventIdFor(payload: z.infer<typeof webhookSchema>) {
  const payment = payload.data.payment;
  const id =
    payment.cf_payment_id ??
    payment.payment_id ??
    `${payload.data.order.order_id}:${payment.payment_status}`;
  return `${payload.type ?? "payment"}:${id}:${payment.payment_status.toUpperCase()}`;
}

export async function POST(request: Request) {
  const raw = await request.text();
  const timestamp = request.headers.get("x-webhook-timestamp");
  const signature = request.headers.get("x-webhook-signature");

  if (!verifyCashfreeSignature(raw, timestamp, signature)) {
    return Response.json({ error: "invalid_signature" }, { status: 401 });
  }

  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch {
    return Response.json({ error: "invalid_json" }, { status: 400 });
  }

  const parsed = webhookSchema.safeParse(json);
  if (!parsed.success) {
    return Response.json({ error: "invalid_event" }, { status: 400 });
  }

  const eventId = request.headers.get("x-idempotency-key") || eventIdFor(parsed.data);
  const providerOrderId = parsed.data.data.order.order_id;
  const amountMinor = Math.round(Number(parsed.data.data.order.order_amount) * 100);
  const currency = parsed.data.data.order.order_currency.toUpperCase();
  const paymentStatus = parsed.data.data.payment.payment_status.toUpperCase();

  if (!Number.isFinite(amountMinor) || amountMinor <= 0) {
    return Response.json({ error: "invalid_amount" }, { status: 400 });
  }

  const order = await prisma.order.findUnique({ where: { providerOrderId } });
  if (!order) return Response.json({ error: "order_not_found" }, { status: 404 });

  if (order.amountMinor !== amountMinor || order.currency !== currency) {
    return Response.json({ error: "amount_mismatch" }, { status: 400 });
  }

  if (paymentStatus !== "SUCCESS") {
    await prisma.webhookEvent
      .create({ data: { provider: "cashfree", providerEventId: eventId, payload: parsed.data } })
      .catch((error: { code?: string }) => {
        if (error.code !== "P2002") throw error;
      });
    return Response.json({ received: true });
  }

  const setup = createSetupToken();
  let duplicate = false;

  try {
    await prisma.$transaction(async (tx) => {
      await tx.webhookEvent.create({
        data: { provider: "cashfree", providerEventId: eventId, payload: parsed.data }
      });

      if (order.status === "FULFILLED") {
        duplicate = true;
        return;
      }

      const user = await tx.user.upsert({
        where: { email: order.email },
        update: { fullName: order.fullName },
        create: {
          email: order.email,
          fullName: order.fullName,
          status: "PENDING_SETUP"
        }
      });

      const setupToken = await tx.setupToken.create({
        data: {
          userId: user.id,
          tokenHash: setup.hash,
          expiresAt: new Date(Date.now() + 30 * 60 * 1000)
        }
      });

      await tx.outbox.create({
        data: {
          type: "SETUP_EMAIL",
          payload: {
            email: user.email,
            fullName: user.fullName,
            setupTokenId: setupToken.id,
            tokenCiphertext: encryptSecret(setup.token)
          }
        }
      });

      await tx.order.update({
        where: { id: order.id },
        data: { status: "FULFILLED", userId: user.id }
      });
    });
  } catch (error) {
    if ((error as { code?: string }).code === "P2002") duplicate = true;
    else throw error;
  }

  return Response.json({ received: true, duplicate });
}
