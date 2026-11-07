export class SlidingWindowLimiter {
  constructor(options = {}) {
    this.windowMs = options.windowMs ?? 60000;
    this.max = options.max ?? 60;
    this.now = options.now ?? (() => Date.now());
    this.buckets = new Map();
  }

  check(key) {
    const now = this.now();
    const windowStart = now - this.windowMs;
    const hits = (this.buckets.get(key) || []).filter((ts) => ts > windowStart);
    const allowed = hits.length < this.max;
    if (allowed) hits.push(now);
    this.buckets.set(key, hits);
    const oldest = hits[0] ?? now;
    const resetMs = Math.max(0, oldest + this.windowMs - now);
    return {
      allowed,
      limit: this.max,
      remaining: Math.max(0, this.max - hits.length),
      resetMs,
      retryAfterSeconds: Math.max(1, Math.ceil(resetMs / 1000))
    };
  }

  reset(key) {
    if (key) this.buckets.delete(key);
    else this.buckets.clear();
  }

  prune() {
    const cutoff = this.now() - this.windowMs;
    for (const [key, hits] of this.buckets) {
      const kept = hits.filter((ts) => ts > cutoff);
      if (kept.length) this.buckets.set(key, kept);
      else this.buckets.delete(key);
    }
  }
}

export function clientIp(request, options = {}) {
  const trustProxy = options.trustProxy ?? true;
  if (trustProxy) {
    const forwarded = request.headers["x-forwarded-for"];
    if (typeof forwarded === "string" && forwarded.length) {
      return forwarded.split(",")[0].trim();
    }
    const realIp = request.headers["x-real-ip"];
    if (typeof realIp === "string" && realIp.length) return realIp;
  }
  return request.socket?.remoteAddress || "unknown";
}

export function rateLimitHeaders(result) {
  return {
    "RateLimit-Limit": String(result.limit),
    "RateLimit-Remaining": String(result.remaining),
    "RateLimit-Reset": String(Math.ceil(result.resetMs / 1000)),
    ...(result.allowed ? {} : { "Retry-After": String(result.retryAfterSeconds) })
  };
}
