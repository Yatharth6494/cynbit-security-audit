import { z } from "zod";

const email = z.string().trim().toLowerCase().email().max(254);

const phone = z
  .string()
  .trim()
  .max(24)
  .refine((value) => {
    const digits = value.replace(/\D/g, "");
    return digits.length >= 10 && digits.length <= 15;
  }, "Enter a valid phone number");

const honeypot = z.string().max(200).optional().default("");

export const contactSchema = z
  .object({
    fullName: z.string().trim().min(1).max(120),
    email,
    company: z.string().trim().max(120).optional().default(""),
    industry: z.string().trim().max(120).optional().default(""),
    message: z.string().trim().min(1).max(5000),
    website: honeypot
  })
  .strict();

export const newsletterSchema = z
  .object({
    email,
    website: honeypot
  })
  .strict();

export const diarySchema = z
  .object({
    fullName: z.string().trim().min(1).max(120),
    role: z.string().trim().min(1).max(160),
    email,
    title: z.string().trim().min(1).max(160),
    story: z.string().trim().min(1).max(5000),
    website: honeypot
  })
  .strict();

export const checkoutSchema = z
  .object({
    fullName: z.string().trim().min(1).max(120),
    email,
    phone,
    university: z.string().trim().min(1).max(160),
    track: z.string().trim().min(1).max(80),
    duration: z.string().trim().min(1).max(80),
    referralName: z.string().trim().max(160).optional().default(""),
    ambitions: z.string().trim().min(1).max(2000),
    website: honeypot
  })
  .strict();

export const setPasswordSchema = z
  .object({
    token: z.string().min(20).max(200),
    password: z
      .string()
      .min(12)
      .max(128)
      .regex(/[A-Za-z]/, "Use at least one letter")
      .regex(/\d/, "Use at least one number")
  })
  .strict();

export const loginSchema = z
  .object({
    email,
    password: z.string().min(1).max(128)
  })
  .strict();
