"use server";

import { headers } from "next/headers";
import { Resend } from "resend";
import { prisma } from "@/lib/prisma";
import { rateLimit } from "@/lib/rate-limit";
import { contactSchema, diarySchema, newsletterSchema } from "@/lib/validation";

async function requestContext() {
  const headerStore = await headers();
  const forwarded = headerStore.get("x-forwarded-for");
  const ip = forwarded?.split(",")[0].trim() || headerStore.get("x-real-ip") || "unknown";
  return { ip, userAgent: headerStore.get("user-agent") || "" };
}

async function verifyTurnstile(token: string | undefined, ip: string) {
  const secret = process.env.TURNSTILE_SECRET_KEY;
  if (!secret) return process.env.NODE_ENV !== "production";
  if (!token) return false;

  const body = new URLSearchParams({ secret, response: token, remoteip: ip });
  const response = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST",
    body,
    cache: "no-store"
  });
  if (!response.ok) return false;
  const result = (await response.json()) as { success?: boolean };
  return result.success === true;
}

async function sendMail(input: {
  subject: string;
  replyTo?: string;
  text: string;
}) {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) throw new Error("RESEND_API_KEY is not configured");
  const resend = new Resend(apiKey);
  const result = await resend.emails.send({
    from: "Cynbit <noreply@cynbit.in>",
    to: "opportunities@cynbit.in",
    replyTo: input.replyTo,
    subject: input.subject,
    text: input.text
  });
  if (result.error) throw new Error("email delivery failed");
}

export async function submitInquiry(formData: FormData) {
  const { ip } = await requestContext();
  const limit = await rateLimit(`contact:${ip}`, 5, 60);
  if (!limit.allowed) return { ok: false, error: "Too many requests. Try again shortly." };

  const parsed = contactSchema.safeParse(Object.fromEntries(formData));
  if (!parsed.success) return { ok: false, error: "Check the form fields and try again." };
  if (parsed.data.website) return { ok: true };

  const turnstile = formData.get("cf-turnstile-response");
  if (!(await verifyTurnstile(typeof turnstile === "string" ? turnstile : undefined, ip))) {
    return { ok: false, error: "Verification failed. Reload and try again." };
  }

  await prisma.contactInquiry.create({
    data: {
      fullName: parsed.data.fullName,
      email: parsed.data.email,
      company: parsed.data.company,
      industry: parsed.data.industry,
      message: parsed.data.message
    }
  });

  try {
    await sendMail({
      subject: "New project inquiry",
      replyTo: parsed.data.email,
      text: `${parsed.data.fullName} submitted a project inquiry.`
    });
  } catch {
    return { ok: true };
  }

  return { ok: true };
}

export async function subscribeToNewsletter(formData: FormData) {
  const { ip } = await requestContext();
  const limit = await rateLimit(`newsletter:${ip}`, 5, 60);
  if (!limit.allowed) return { ok: false, error: "Too many requests. Try again shortly." };

  const parsed = newsletterSchema.safeParse(Object.fromEntries(formData));
  if (!parsed.success) return { ok: false, error: "Enter a valid email address." };
  if (parsed.data.website) return { ok: true };

  await prisma.newsletterSubscriber.upsert({
    where: { email: parsed.data.email },
    update: {},
    create: { email: parsed.data.email }
  });

  return { ok: true };
}

export async function submitDiaryEntry(formData: FormData) {
  const { ip } = await requestContext();
  const limit = await rateLimit(`diary:${ip}`, 3, 3600);
  if (!limit.allowed) return { ok: false, error: "Too many submissions. Try again later." };

  const parsed = diarySchema.safeParse(Object.fromEntries(formData));
  if (!parsed.success) return { ok: false, error: "Check the form fields and try again." };
  if (parsed.data.website) return { ok: true };

  await prisma.diaryEntry.create({
    data: {
      fullName: parsed.data.fullName,
      role: parsed.data.role,
      email: parsed.data.email,
      title: parsed.data.title,
      story: parsed.data.story
    }
  });

  return { ok: true, status: "PENDING_REVIEW" };
}
