import { createHmac, timingSafeEqual } from "node:crypto";
import { cookies } from "next/headers";

const SESSION_COOKIE = "cynbit_session";
const SESSION_TTL_SECONDS = 7200;

type SessionPayload = {
  sub: string;
  role: string;
  exp: number;
};

function secret() {
  const value = process.env.APP_SECRET;
  if (!value || value.length < 32) {
    throw new Error("APP_SECRET must be at least 32 characters");
  }
  return value;
}

export function signSession(payload: Omit<SessionPayload, "exp">, ttlSeconds = SESSION_TTL_SECONDS) {
  const body = Buffer.from(
    JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + ttlSeconds })
  ).toString("base64url");
  const signature = createHmac("sha256", secret()).update(body).digest("hex");
  return `${body}.${signature}`;
}

export function verifySessionToken(token: string | undefined | null): SessionPayload | null {
  if (!token) return null;
  const [body, signature] = token.split(".");
  if (!body || !signature) return null;

  const expected = createHmac("sha256", secret()).update(body).digest("hex");
  const supplied = Buffer.from(signature, "hex");
  const computed = Buffer.from(expected, "hex");
  if (supplied.length !== computed.length || !timingSafeEqual(supplied, computed)) {
    return null;
  }

  try {
    const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as SessionPayload;
    if (typeof payload.exp !== "number" || payload.exp * 1000 <= Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

export async function getSession() {
  const store = await cookies();
  return verifySessionToken(store.get(SESSION_COOKIE)?.value);
}

export async function setSessionCookie(token: string) {
  const store = await cookies();
  store.set(SESSION_COOKIE, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: SESSION_TTL_SECONDS
  });
}

export async function clearSessionCookie() {
  const store = await cookies();
  store.set(SESSION_COOKIE, "", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: 0
  });
}
