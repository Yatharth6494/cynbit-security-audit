"use server";

import { headers } from "next/headers";
import { clearSessionCookie, setSessionCookie, signSession } from "@/lib/auth";
import { prisma } from "@/lib/prisma";
import { hashPassword, hashToken, verifyPasswordWithDummy } from "@/lib/passwords";
import { rateLimit } from "@/lib/rate-limit";
import { loginSchema, setPasswordSchema } from "@/lib/validation";

async function requestIp() {
  const headerStore = await headers();
  const forwarded = headerStore.get("x-forwarded-for");
  return forwarded?.split(",")[0].trim() || headerStore.get("x-real-ip") || "unknown";
}

export async function loginIntern(formData: FormData) {
  const ip = await requestIp();
  const parsed = loginSchema.safeParse(Object.fromEntries(formData));
  if (!parsed.success) return { ok: false, error: "Invalid email or password." };

  const limit = await rateLimit(`login:${ip}:${parsed.data.email}`, 10, 60);
  if (!limit.allowed) return { ok: false, error: "Too many attempts. Try again shortly." };

  const user = await prisma.user.findUnique({ where: { email: parsed.data.email } });
  const valid = await verifyPasswordWithDummy(
    user?.status === "ACTIVE" ? user.passwordHash : null,
    parsed.data.password
  );

  if (!user || !valid) {
    return { ok: false, error: "Invalid email or password." };
  }

  const token = signSession({ sub: user.id, role: "INTERN" });
  await setSessionCookie(token);

  await prisma.auditEvent.create({
    data: { actorId: user.id, action: "auth.login", target: user.id, ip }
  });

  return { ok: true };
}

export async function setPassword(formData: FormData) {
  const ip = await requestIp();
  const parsed = setPasswordSchema.safeParse(Object.fromEntries(formData));
  if (!parsed.success) return { ok: false, error: "Use a password with 12+ characters, letters, and numbers." };

  const limit = await rateLimit(`set-password:${ip}`, 10, 60);
  if (!limit.allowed) return { ok: false, error: "Too many attempts. Try again shortly." };

  const record = await prisma.setupToken.findUnique({
    where: { tokenHash: hashToken(parsed.data.token) },
    include: { user: true }
  });

  if (!record || record.usedAt || record.expiresAt.getTime() <= Date.now()) {
    return { ok: false, error: "This setup link is invalid or expired." };
  }

  const passwordHash = await hashPassword(parsed.data.password);

  await prisma.$transaction([
    prisma.user.update({
      where: { id: record.userId },
      data: { passwordHash, status: "ACTIVE" }
    }),
    prisma.setupToken.update({
      where: { id: record.id },
      data: { usedAt: new Date() }
    }),
    prisma.session.updateMany({
      where: { userId: record.userId, revokedAt: null },
      data: { revokedAt: new Date() }
    }),
    prisma.auditEvent.create({
      data: {
        actorId: record.userId,
        action: "auth.password_set",
        target: record.userId,
        ip
      }
    })
  ]);

  return { ok: true };
}

export async function logout() {
  await clearSessionCookie();
  return { ok: true };
}
