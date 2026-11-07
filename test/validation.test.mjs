import test from "node:test";
import assert from "node:assert/strict";
import {
  validateContact,
  validateCheckout,
  validateSetPassword
} from "../src/hardening/validation.mjs";
import { redact, maskEmail } from "../src/hardening/logger.mjs";

test("valid contact input is normalized", () => {
  const result = validateContact({
    fullName: "  Alex Rivera ",
    email: "ALEX@Example.com",
    company: "Fintech",
    industry: "Payments",
    message: "Hello there"
  });
  assert.equal(result.ok, true);
  assert.equal(result.value.fullName, "Alex Rivera");
  assert.equal(result.value.email, "alex@example.com");
});

test("invalid email is rejected", () => {
  const result = validateContact({ fullName: "Alex", email: "not-an-email", message: "Hi" });
  assert.equal(result.ok, false);
  assert.ok(result.errors.email);
});

test("honeypot submissions are marked as bots", () => {
  const result = validateContact({
    fullName: "Alex",
    email: "alex@example.com",
    message: "Hi",
    website: "https://spam.example"
  });
  assert.equal(result.ok, false);
  assert.equal(result.bot, true);
});

test("checkout validates phone and required fields", () => {
  const good = validateCheckout({
    fullName: "Aarav",
    email: "aarav@example.com",
    phone: "+91 98765 43210",
    university: "SKIT",
    track: "Full Stack",
    duration: "60 Days",
    ambitions: "Learn"
  });
  assert.equal(good.ok, true);
  const bad = validateCheckout({ ...good.value, phone: "123" });
  assert.equal(bad.ok, false);
  assert.ok(bad.errors.phone);
});

test("password policy requires length and mixed classes", () => {
  const short = validateSetPassword({ token: "a".repeat(32), password: "short" });
  assert.equal(short.ok, false);
  const weak = validateSetPassword({ token: "a".repeat(32), password: "onlyletterslong" });
  assert.equal(weak.ok, false);
  const strong = validateSetPassword({ token: "a".repeat(32), password: "CorrectHorse9Battery" });
  assert.equal(strong.ok, true);
});

test("logs redact credentials and mask PII", () => {
  const redacted = redact({
    password: "super-secret",
    token: "abc123",
    setupUrl: "https://example.test/set-password?token=abc",
    email: "alex@example.com",
    phone: "+919876543210",
    note: "contact alex@example.com"
  });
  assert.equal(redacted.password, "[redacted]");
  assert.equal(redacted.token, "[redacted]");
  assert.equal(redacted.setupUrl, "[redacted]");
  assert.equal(redacted.phone, "***10");
  assert.equal(redacted.email, "a***@example.com");
  assert.equal(redacted.note, "contact a***@example.com");
  assert.equal(maskEmail("opportunities@cynbit.in"), "o***@cynbit.in");
});
