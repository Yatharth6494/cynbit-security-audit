import argon2 from "argon2";
import { createHash, randomBytes } from "node:crypto";

let dummyHash: string | null = null;

export async function hashPassword(password: string) {
  return argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 19456,
    timeCost: 2,
    parallelism: 1
  });
}

export async function verifyPassword(hash: string, password: string) {
  try {
    return await argon2.verify(hash, password);
  } catch {
    return false;
  }
}

export async function verifyPasswordWithDummy(
  hash: string | null | undefined,
  password: string
) {
  if (hash) return verifyPassword(hash, password);
  if (!dummyHash) dummyHash = await hashPassword("dummy-password-not-used-123");
  await verifyPassword(dummyHash, password);
  return false;
}

export function createSetupToken() {
  const token = randomBytes(32).toString("base64url");
  return { token, hash: hashToken(token) };
}

export function hashToken(token: string) {
  return createHash("sha256").update(token).digest("hex");
}
