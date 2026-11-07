import { Resend } from "resend";
import { decryptSecret } from "@/lib/crypto";
import { prisma } from "@/lib/prisma";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type SetupEmailPayload = {
  email: string;
  fullName: string;
  setupTokenId: string;
  tokenCiphertext: string;
};

function authorized(request: Request) {
  const secret = process.env.CRON_SECRET;
  return Boolean(secret) && request.headers.get("authorization") === `Bearer ${secret}`;
}

export async function GET(request: Request) {
  if (!authorized(request)) return Response.json({ error: "unauthorized" }, { status: 401 });

  const appUrl = process.env.APP_URL;
  const apiKey = process.env.RESEND_API_KEY;
  if (!appUrl || !apiKey) {
    return Response.json({ error: "misconfigured" }, { status: 500 });
  }

  const rows = await prisma.outbox.findMany({
    where: { status: "PENDING", attempts: { lt: 5 } },
    orderBy: { createdAt: "asc" },
    take: 20
  });

  const resend = new Resend(apiKey);
  let sent = 0;
  let failed = 0;

  for (const row of rows) {
    try {
      if (row.type !== "SETUP_EMAIL") throw new Error("unsupported outbox type");

      const payload = row.payload as unknown as SetupEmailPayload;
      const token = decryptSecret(payload.tokenCiphertext);
      const setupUrl = `${appUrl.replace(/\/$/, "")}/set-password#token=${encodeURIComponent(token)}`;

      const result = await resend.emails.send({
        from: "Cynbit <noreply@cynbit.in>",
        to: payload.email,
        subject: "Set up your BitElevate portal access",
        text: [
          `Hi ${payload.fullName},`,
          "",
          "Your payment is confirmed. Use the single-use link below to set your portal password.",
          "The link expires in 30 minutes.",
          "",
          setupUrl,
          "",
          "If you did not request this, contact opportunities@cynbit.in."
        ].join("\n")
      });

      if (result.error) throw new Error("email delivery failed");

      await prisma.outbox.update({
        where: { id: row.id },
        data: {
          status: "SENT",
          sentAt: new Date(),
          attempts: { increment: 1 },
          payload: { email: payload.email, delivered: true }
        }
      });
      await prisma.setupToken.update({
        where: { id: payload.setupTokenId },
        data: { emailSentAt: new Date() }
      });
      sent += 1;
    } catch (error) {
      failed += 1;
      const attempts = row.attempts + 1;
      await prisma.outbox.update({
        where: { id: row.id },
        data: {
          attempts,
          status: attempts >= 5 ? "FAILED" : "PENDING",
          lastError: error instanceof Error ? error.message.slice(0, 300) : "unknown"
        }
      });
    }
  }

  return Response.json({ processed: rows.length, sent, failed });
}
