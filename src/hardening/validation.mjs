const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const CONTROL_PATTERN = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g;

function text(value) {
  if (typeof value !== "string") return "";
  return value.replace(/\r\n/g, "\n").replace(CONTROL_PATTERN, "").trim();
}

function fail(errors) {
  return { ok: false, errors };
}

function email(value) {
  const normalized = text(value).toLowerCase();
  if (!normalized || normalized.length > 254 || !EMAIL_PATTERN.test(normalized)) return null;
  return normalized;
}

function bounded(value, { min = 0, max = 500, optional = false } = {}) {
  const normalized = text(value);
  if (!normalized && optional) return { value: "" };
  if (normalized.length < min) return { error: `Must be at least ${min} characters.` };
  if (normalized.length > max) return { error: `Must be at most ${max} characters.` };
  return { value: normalized };
}

function phone(value) {
  const normalized = text(value);
  const digits = normalized.replace(/\D/g, "");
  if (digits.length < 10 || digits.length > 15) return null;
  if (!/^\+?[\d\s().-]+$/.test(normalized)) return null;
  return normalized;
}

function botCheck(input) {
  const honeypot = text(input.website ?? input.hp ?? "");
  return honeypot.length > 0;
}

export function validateContact(input = {}) {
  const errors = {};
  if (botCheck(input)) return { ok: false, bot: true, errors: { form: "Rejected." } };
  const fullName = bounded(input.fullName, { min: 1, max: 120 });
  if (fullName.error) errors.fullName = fullName.error;
  const emailValue = email(input.email);
  if (!emailValue) errors.email = "Enter a valid email address.";
  const company = bounded(input.company, { max: 120, optional: true });
  if (company.error) errors.company = company.error;
  const industry = bounded(input.industry, { max: 120, optional: true });
  if (industry.error) errors.industry = industry.error;
  const message = bounded(input.message, { min: 1, max: 5000 });
  if (message.error) errors.message = message.error;
  if (Object.keys(errors).length) return fail(errors);
  return {
    ok: true,
    value: {
      fullName: fullName.value,
      email: emailValue,
      company: company.value,
      industry: industry.value,
      message: message.value
    }
  };
}

export function validateNewsletter(input = {}) {
  if (botCheck(input)) return { ok: false, bot: true, errors: { form: "Rejected." } };
  const emailValue = email(input.email);
  if (!emailValue) return fail({ email: "Enter a valid email address." });
  return { ok: true, value: { email: emailValue } };
}

export function validateDiary(input = {}) {
  const errors = {};
  if (botCheck(input)) return { ok: false, bot: true, errors: { form: "Rejected." } };
  const fullName = bounded(input.fullName, { min: 1, max: 120 });
  if (fullName.error) errors.fullName = fullName.error;
  const role = bounded(input.role, { min: 1, max: 160 });
  if (role.error) errors.role = role.error;
  const emailValue = email(input.email);
  if (!emailValue) errors.email = "Enter a valid email address.";
  const title = bounded(input.title, { min: 1, max: 160 });
  if (title.error) errors.title = title.error;
  const story = bounded(input.story, { min: 1, max: 5000 });
  if (story.error) errors.story = story.error;
  if (Object.keys(errors).length) return fail(errors);
  return {
    ok: true,
    value: {
      fullName: fullName.value,
      role: role.value,
      email: emailValue,
      title: title.value,
      story: story.value
    }
  };
}

export function validateCheckout(input = {}) {
  const errors = {};
  if (botCheck(input)) return { ok: false, bot: true, errors: { form: "Rejected." } };
  const fullName = bounded(input.fullName, { min: 1, max: 120 });
  if (fullName.error) errors.fullName = fullName.error;
  const emailValue = email(input.email);
  if (!emailValue) errors.email = "Enter a valid email address.";
  const phoneValue = phone(input.phone);
  if (!phoneValue) errors.phone = "Enter a valid phone number.";
  const university = bounded(input.university, { min: 1, max: 160 });
  if (university.error) errors.university = university.error;
  const track = bounded(input.track, { min: 1, max: 80 });
  if (track.error) errors.track = track.error;
  const duration = bounded(input.duration, { min: 1, max: 80 });
  if (duration.error) errors.duration = duration.error;
  const referralName = bounded(input.referralName, { max: 160, optional: true });
  if (referralName.error) errors.referralName = referralName.error;
  const ambitions = bounded(input.ambitions, { min: 1, max: 2000 });
  if (ambitions.error) errors.ambitions = ambitions.error;
  if (Object.keys(errors).length) return fail(errors);
  return {
    ok: true,
    value: {
      fullName: fullName.value,
      email: emailValue,
      phone: phoneValue,
      university: university.value,
      track: track.value,
      duration: duration.value,
      referralName: referralName.value,
      ambitions: ambitions.value
    }
  };
}

export function validateSetPassword(input = {}) {
  const errors = {};
  const token = text(input.token);
  if (token.length < 20 || token.length > 200) errors.token = "Invalid or expired link.";
  const password = typeof input.password === "string" ? input.password : "";
  if (password.length < 12) errors.password = "Use at least 12 characters.";
  if (password.length > 128) errors.password = "Use at most 128 characters.";
  if (!/[A-Za-z]/.test(password) || !/\d/.test(password)) {
    errors.password = "Use at least one letter and one number.";
  }
  if (Object.keys(errors).length) return fail(errors);
  return { ok: true, value: { token, password } };
}

export function validateLogin(input = {}) {
  const errors = {};
  const emailValue = email(input.email);
  if (!emailValue) errors.email = "Enter a valid email address.";
  const password = typeof input.password === "string" ? input.password : "";
  if (!password || password.length > 128) errors.password = "Enter your password.";
  if (Object.keys(errors).length) return fail(errors);
  return { ok: true, value: { email: emailValue, password } };
}
