import {
  createHash,
  createHmac,
  randomBytes,
  scryptSync,
  timingSafeEqual
} from "node:crypto";

const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 64, maxmem: 64 * 1024 * 1024 };

export function hashPassword(password) {
  const salt = randomBytes(16);
  const derived = scryptSync(password, salt, SCRYPT.keylen, {
    N: SCRYPT.N,
    r: SCRYPT.r,
    p: SCRYPT.p,
    maxmem: SCRYPT.maxmem
  });
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString("base64url")}$${derived.toString("base64url")}`;
}

export function verifyPassword(password, stored) {
  if (typeof password !== "string" || typeof stored !== "string") return false;
  const parts = stored.split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") return false;
  const [, n, r, p, salt, hash] = parts;
  try {
    const expected = Buffer.from(hash, "base64url");
    const derived = scryptSync(password, Buffer.from(salt, "base64url"), expected.length, {
      N: Number(n),
      r: Number(r),
      p: Number(p),
      maxmem: SCRYPT.maxmem
    });
    return expected.length === derived.length && timingSafeEqual(expected, derived);
  } catch {
    return false;
  }
}

export function newToken(bytes = 32) {
  return randomBytes(bytes).toString("base64url");
}

export function hashToken(token) {
  return createHash("sha256").update(String(token)).digest("hex");
}

export function hmacHex(secret, data) {
  return createHmac("sha256", secret).update(data).digest("hex");
}

export function signWebhook(secret, timestamp, rawBody) {
  return hmacHex(secret, `${timestamp}.${rawBody}`);
}

export function verifyWebhookSignature(secret, timestamp, rawBody, signature, options = {}) {
  const tolerance = options.toleranceSeconds ?? 300;
  const now = options.now ?? Date.now();
  const ts = Number(timestamp);
  if (!Number.isFinite(ts)) return { ok: false, reason: "invalid_timestamp" };
  const age = Math.abs(now / 1000 - ts);
  if (age > tolerance) return { ok: false, reason: "timestamp_out_of_tolerance" };
  if (typeof signature !== "string" || !/^[a-f0-9]{64}$/i.test(signature)) {
    return { ok: false, reason: "malformed_signature" };
  }
  const expected = signWebhook(secret, timestamp, rawBody);
  const supplied = Buffer.from(signature, "hex");
  const computed = Buffer.from(expected, "hex");
  if (supplied.length !== computed.length || !timingSafeEqual(supplied, computed)) {
    return { ok: false, reason: "signature_mismatch" };
  }
  return { ok: true };
}

export function signSession(payload, secret) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = hmacHex(secret, body);
  return `${body}.${signature}`;
}

export function verifySession(token, secret, options = {}) {
  if (typeof token !== "string") return null;
  const [body, signature] = token.split(".");
  if (!body || !signature) return null;
  const expected = hmacHex(secret, body);
  const supplied = Buffer.from(signature, "hex");
  const computed = Buffer.from(expected, "hex");
  if (supplied.length !== computed.length || !timingSafeEqual(supplied, computed)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    const now = options.now ?? Date.now();
    if (typeof payload.exp !== "number" || payload.exp * 1000 <= now) return null;
    return payload;
  } catch {
    return null;
  }
}

export function safeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && timingSafeEqual(left, right);
}
