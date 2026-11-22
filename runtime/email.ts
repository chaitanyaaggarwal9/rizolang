/**
 * Rizo Lang runtime: email (confirming addresses and resetting passwords).
 *
 * Emails are plain text, built from fixed sentences plus a link: nothing
 * from a request is ever put into a subject or body, so emails can't be used
 * to send someone else's words.
 *
 * Links carry their one-time token after "#", so the token never reaches a
 * server log or a Referer header, and email scanners that open links can't
 * use it up: the page sends it to the server with a POST.
 *
 * Only SHA-256 hashes of tokens are stored. Each token works once.
 */
import { createHash, randomBytes } from "node:crypto";

export interface Email {
  readonly to: string;
  readonly subject: string;
  readonly text: string;
}

/** Sends one email. Throws when it could not be sent. */
export type Mailer = (email: Email) => Promise<void>;

export const UNVERIFIED = '"_rizo_unverified"';
export const EMAIL_TOKENS = '"_rizo_email_tokens"';

/** How long links work. */
export const VERIFY_SECONDS = 24 * 60 * 60;
export const RESET_SECONDS = 60 * 60;

export type TokenPurpose = "verify" | "reset" | "email";

/** How long a link to confirm a new login email works. */
export const CHANGE_SECONDS = 60 * 60;

export const EMAIL_SQL = {
  isUnverified: `SELECT 1 FROM ${UNVERIFIED} WHERE "user_id" = $1`,
  markVerified: `DELETE FROM ${UNVERIFIED} WHERE "user_id" = $1`,
  createToken: `INSERT INTO ${EMAIL_TOKENS} ("id", "user_id", "purpose", "expires_at") VALUES ($1, $2, $3, now() + make_interval(secs => $4))`,
  /** Use a token: it must exist, be unexpired and be for this purpose. It is deleted either way. */
  useToken: `DELETE FROM ${EMAIL_TOKENS} WHERE "id" = $1 AND "purpose" = $2 AND "expires_at" > now() RETURNING "user_id"`,
  /** Older links stop working when a new one is sent, and after a password reset. */
  deleteTokens: `DELETE FROM ${EMAIL_TOKENS} WHERE "user_id" = $1 AND "purpose" = $2`,
  /** A link to confirm a new login email ($4), which takes effect only when the link is opened. */
  createEmailChange: `INSERT INTO ${EMAIL_TOKENS} ("id", "user_id", "purpose", "expires_at", "new_email") VALUES ($1, $2, 'email', now() + make_interval(secs => $3), $4)`,
  useEmailChange: `DELETE FROM ${EMAIL_TOKENS} WHERE "id" = $1 AND "purpose" = 'email' AND "expires_at" > now() RETURNING "user_id", "new_email"`,
  sweepTokens: `DELETE FROM ${EMAIL_TOKENS} WHERE "expires_at" <= now()`,
} as const;

/** A new link token (sent by email) and its hash (stored). */
export function newEmailToken(): { token: string; hash: string } {
  const token = randomBytes(32).toString("base64url");
  return { token, hash: emailTokenHash(token) };
}

export function emailTokenHash(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

/** A token as the browser sends it back, or undefined if it can't be one. */
export function readEmailToken(value: unknown): string | undefined {
  return typeof value === "string" && /^[A-Za-z0-9_-]{43}$/.test(value) ? value : undefined;
}

/** The emails the app sends. `site` is the host name of RIZO_PUBLIC_URL. */
export const MESSAGES = {
  verify: (publicUrl: string, token: string): { subject: string; text: string } => ({
    subject: `Confirm your email for ${host(publicUrl)}`,
    text: [
      `Confirm your email address to finish creating your account on ${host(publicUrl)}:`,
      "",
      `${publicUrl}/verify-email#token=${token}`,
      "",
      "The link works once, for 24 hours.",
      "If you didn't create an account, you can ignore this email.",
    ].join("\n"),
  }),
  alreadyRegistered: (publicUrl: string): { subject: string; text: string } => ({
    subject: `You already have an account on ${host(publicUrl)}`,
    text: [
      `Someone tried to create an account on ${host(publicUrl)} with this email address, but it already has one.`,
      "",
      `If it was you, log in: ${publicUrl}/login`,
      `Forgot your password? Reset it: ${publicUrl}/reset-password`,
      "",
      "If it wasn't you, you can ignore this email. Nothing has changed.",
    ].join("\n"),
  }),
  changeEmail: (publicUrl: string, token: string): { subject: string; text: string } => ({
    subject: `Confirm your new email for ${host(publicUrl)}`,
    text: [
      `Confirm that you want to log in to ${host(publicUrl)} with this email address from now on:`,
      "",
      `${publicUrl}/confirm-email#token=${token}`,
      "",
      "The link works once, for 1 hour. Until you open it, nothing changes.",
      "If you didn't ask for this, you can ignore this email.",
    ].join("\n"),
  }),
  emailChanged: (publicUrl: string): { subject: string; text: string } => ({
    subject: `Your email for ${host(publicUrl)} was changed`,
    text: [
      `The email address you use to log in to ${host(publicUrl)} was just changed, and this address no longer works for logging in.`,
      "",
      "If you made this change, there is nothing to do.",
      "If you didn't, someone may know your password: reply to this email or contact the site's owner right away.",
    ].join("\n"),
  }),
  reset: (publicUrl: string, token: string): { subject: string; text: string } => ({
    subject: `Reset your password for ${host(publicUrl)}`,
    text: [
      `Choose a new password for your account on ${host(publicUrl)}:`,
      "",
      `${publicUrl}/reset-password#token=${token}`,
      "",
      "The link works once, for 1 hour. Using it logs you out everywhere.",
      "If you didn't ask for this, you can ignore this email. Your password has not changed.",
    ].join("\n"),
  }),
} as const;

function host(publicUrl: string): string {
  return new URL(publicUrl).host;
}

/** Sends email through Resend's HTTPS API (https://resend.com). */
export function resendMailer(apiKey: string, from: string, send: typeof fetch = fetch): Mailer {
  return async (email) => {
    const r = await send("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({ from, to: [email.to], subject: email.subject, text: email.text }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!r.ok) throw new Error(`Resend answered ${r.status}`);
  };
}

/** For local development only: prints emails instead of sending them. */
export function consoleMailer(write: (text: string) => void): Mailer {
  return async (email) => {
    write(`--- email to ${email.to}\nSubject: ${email.subject}\n\n${email.text}\n---\n`);
  };
}

export interface EmailConfig {
  readonly mailer: Mailer;
  /** Where links in emails point, without a trailing slash, e.g. "https://blog.example". */
  readonly publicUrl: string;
  /** True when emails are printed instead of sent. */
  readonly dev: boolean;
}

/**
 * Email settings from environment variables. Throws an Error whose message
 * says what is wrong and how to fix it.
 */
export function emailConfig(env: Readonly<Record<string, string | undefined>>, write: (text: string) => void): EmailConfig {
  const publicUrl = checkPublicUrl(env["RIZO_PUBLIC_URL"]);
  if (env["RIZO_EMAIL_DEV"] === "1") return { mailer: consoleMailer(write), publicUrl, dev: true };
  const apiKey = env["RIZO_EMAIL_API_KEY"] ?? "";
  const from = env["RIZO_EMAIL_FROM"] ?? "";
  if (apiKey === "" || from === "") {
    throw new Error(
      "RIZO_EMAIL_API_KEY and RIZO_EMAIL_FROM must be set: accounts need email to confirm addresses and reset passwords.\n" +
        "  fix: Set RIZO_EMAIL_API_KEY to a Resend API key and RIZO_EMAIL_FROM to an address on your verified domain, " +
        "e.g. RIZO_EMAIL_FROM=\"Blog <hello@blog.example>\". For local development only, set RIZO_EMAIL_DEV=1 to print emails instead.",
    );
  }
  if (/[\r\n]/.test(from) || !/@[^@\s>]+\.[^@\s>]+>?$/.test(from)) {
    throw new Error("RIZO_EMAIL_FROM is not a valid sender.\n  fix: Use an address like hello@blog.example or \"Blog <hello@blog.example>\".");
  }
  return { mailer: resendMailer(apiKey, from), publicUrl, dev: false };
}

/** The app's public address: https, or http only for localhost. No path, query or fragment. */
export function checkPublicUrl(raw: string | undefined): string {
  const fix = "  fix: Set RIZO_PUBLIC_URL to the address people use to open the app, e.g. RIZO_PUBLIC_URL=https://blog.example";
  if (raw === undefined || raw === "") throw new Error(`RIZO_PUBLIC_URL is not set: links in emails need the app's address.\n${fix}`);
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`RIZO_PUBLIC_URL is not a valid address.\n${fix}`);
  }
  const local = url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && local)) {
    throw new Error(`RIZO_PUBLIC_URL must start with https:// (http:// is allowed only for localhost).\n${fix}`);
  }
  if ((url.pathname !== "/" && url.pathname !== "") || url.search !== "" || url.hash !== "" || url.username !== "" || url.password !== "") {
    throw new Error(`RIZO_PUBLIC_URL must be just the address, with no path, query or login.\n${fix}`);
  }
  return url.origin;
}
