type LimitResult = {
  allowed: boolean;
  limit: number;
  remaining: number;
  retryAfterSeconds: number;
};

const memory = new Map<string, number[]>();

function memoryLimit(key: string, limit: number, windowSeconds: number): LimitResult {
  const now = Date.now();
  const windowMs = windowSeconds * 1000;
  const hits = (memory.get(key) || []).filter((ts) => ts > now - windowMs);
  const allowed = hits.length < limit;
  if (allowed) hits.push(now);
  memory.set(key, hits);
  const resetMs = hits.length ? hits[0] + windowMs - now : windowMs;
  return {
    allowed,
    limit,
    remaining: Math.max(0, limit - hits.length),
    retryAfterSeconds: Math.max(1, Math.ceil(resetMs / 1000))
  };
}

export async function rateLimit(key: string, limit: number, windowSeconds: number): Promise<LimitResult> {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) return memoryLimit(key, limit, windowSeconds);

  try {
    const response = await fetch(`${url}/pipeline`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json"
      },
      body: JSON.stringify([
        ["INCR", key],
        ["EXPIRE", key, windowSeconds, "NX"]
      ]),
      cache: "no-store"
    });
    if (!response.ok) return memoryLimit(key, limit, windowSeconds);
    const data = (await response.json()) as Array<{ result?: number }>;
    const count = Number(data?.[0]?.result ?? 0);
    const allowed = count <= limit;
    return {
      allowed,
      limit,
      remaining: Math.max(0, limit - count),
      retryAfterSeconds: allowed ? 0 : windowSeconds
    };
  } catch {
    return memoryLimit(key, limit, windowSeconds);
  }
}

export function clientIp(request: { headers: Headers }): string {
  const forwarded = request.headers.get("x-forwarded-for");
  if (forwarded) return forwarded.split(",")[0].trim();
  return request.headers.get("x-real-ip") || "unknown";
}
