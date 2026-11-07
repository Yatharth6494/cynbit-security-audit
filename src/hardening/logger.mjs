const SENSITIVE_KEY = /(password|passwd|token|secret|signature|authorization|cookie|setupurl|reseturl|credential|apikey|api_key)/i;
const EMAIL_KEY = /(email|recipient|^to$)/i;
const PHONE_KEY = /(phone|mobile|whatsapp)/i;
const EMAIL_PATTERN = /([a-z0-9._%+-])[a-z0-9._%+-]*(@[a-z0-9.-]+\.[a-z]{2,})/gi;

export function maskEmail(value) {
  if (typeof value !== "string") return value;
  return value.replace(EMAIL_PATTERN, (_, first, domain) => `${first}***${domain}`);
}

export function maskPhone(value) {
  if (typeof value !== "string") return value;
  const digits = value.replace(/\D/g, "");
  if (digits.length < 4) return "[redacted]";
  return `***${digits.slice(-2)}`;
}

export function redact(value, key = "") {
  if (SENSITIVE_KEY.test(key)) return "[redacted]";
  if (value === null || value === undefined) return value;
  if (typeof value === "string") {
    if (EMAIL_KEY.test(key)) return maskEmail(value);
    if (PHONE_KEY.test(key)) return maskPhone(value);
    return maskEmail(value);
  }
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (Array.isArray(value)) return value.map((item) => redact(item, key));
  if (typeof value === "object") {
    const output = {};
    for (const [childKey, childValue] of Object.entries(value)) {
      output[childKey] = redact(childValue, childKey);
    }
    return output;
  }
  return value;
}

export function createLogger(options = {}) {
  const sink = options.sink || ((line) => process.stdout.write(`${line}\n`));
  const service = options.service || "cynbit-hardening";
  const write = (level, event, fields = {}) => {
    const payload = {
      ts: new Date().toISOString(),
      level,
      service,
      event,
      ...redact(fields)
    };
    sink(JSON.stringify(payload));
  };
  return {
    info: (event, fields) => write("info", event, fields),
    warn: (event, fields) => write("warn", event, fields),
    error: (event, fields) => write("error", event, fields)
  };
}
