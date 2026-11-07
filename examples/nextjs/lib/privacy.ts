const SENSITIVE_KEY = /(password|token|secret|signature|authorization|cookie|setupurl|credential)/i;
const EMAIL_PATTERN = /([a-z0-9._%+-])[a-z0-9._%+-]*(@[a-z0-9.-]+\.[a-z]{2,})/gi;

export function maskEmail(value: string) {
  return value.replace(EMAIL_PATTERN, (_, first, domain) => `${first}***${domain}`);
}

export function redact(value: unknown, key = ""): unknown {
  if (SENSITIVE_KEY.test(key)) return "[redacted]";
  if (value === null || value === undefined) return value;
  if (typeof value === "string") return maskEmail(value);
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (Array.isArray(value)) return value.map((item) => redact(item, key));
  if (typeof value === "object") {
    const output: Record<string, unknown> = {};
    for (const [childKey, childValue] of Object.entries(value)) {
      output[childKey] = redact(childValue, childKey);
    }
    return output;
  }
  return value;
}
