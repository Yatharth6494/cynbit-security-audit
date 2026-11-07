"use client";

import { useEffect, useState } from "react";
import { setPassword } from "../actions/auth";

export default function SetPasswordPage() {
  const [token, setToken] = useState("");
  const [message, setMessage] = useState("");

  useEffect(() => {
    const params = new URLSearchParams(window.location.hash.slice(1));
    const value = params.get("token") || "";
    setToken(value);
    if (value) window.history.replaceState(null, "", window.location.pathname);
  }, []);

  async function handleSubmit(formData: FormData) {
    const password = String(formData.get("password") || "");
    const confirm = String(formData.get("confirm") || "");

    if (password !== confirm) {
      setMessage("Passwords do not match.");
      return;
    }

    formData.set("token", token);
    const result = await setPassword(formData);
    setMessage(
      result.ok ? "Password set. You can sign in now." : result.error || "Unable to set password."
    );
  }

  return (
    <main>
      <h1>Set your portal password</h1>
      <p>This single-use link expires 30 minutes after your payment is confirmed.</p>
      {!token ? <p role="alert">This setup link is missing or invalid.</p> : null}
      <form action={handleSubmit}>
        <input type="hidden" name="token" value={token} />
        <label>
          New password
          <input
            name="password"
            type="password"
            minLength={12}
            maxLength={128}
            autoComplete="new-password"
            required
          />
        </label>
        <label>
          Confirm password
          <input
            name="confirm"
            type="password"
            minLength={12}
            maxLength={128}
            autoComplete="new-password"
            required
          />
        </label>
        <button type="submit" disabled={!token}>
          Set password
        </button>
      </form>
      {message ? <p role="status">{message}</p> : null}
    </main>
  );
}
