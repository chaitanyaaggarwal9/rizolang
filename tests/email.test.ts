import { describe, expect, it } from "vitest";
import { MESSAGES, checkPublicUrl, emailConfig, emailTokenHash, newEmailToken, readEmailToken, resendMailer } from "../runtime/email.ts";

describe("email settings", () => {
  const ok = { RIZO_PUBLIC_URL: "https://blog.example", RIZO_EMAIL_API_KEY: "re_test", RIZO_EMAIL_FROM: "Blog <hello@blog.example>" };

  it("accepts a Resend key, a sender and an https address", () => {
    expect(emailConfig(ok, () => undefined)).toMatchObject({ publicUrl: "https://blog.example", dev: false });
  });

  it("prints emails instead of sending them only when RIZO_EMAIL_DEV=1", async () => {
    const printed: string[] = [];
    const config = emailConfig({ RIZO_PUBLIC_URL: "http://localhost:3000", RIZO_EMAIL_DEV: "1" }, (t) => printed.push(t));
    expect(config.dev).toBe(true);
    await config.mailer({ to: "a@b.co", subject: "Hi", text: "Body" });
    expect(printed.join("")).toContain("Subject: Hi");
  });

  it.each([
    ["no key", { ...ok, RIZO_EMAIL_API_KEY: "" }, "RIZO_EMAIL_API_KEY"],
    ["no sender", { ...ok, RIZO_EMAIL_FROM: undefined }, "RIZO_EMAIL_FROM"],
    ["a sender with a line break", { ...ok, RIZO_EMAIL_FROM: "a@b.co\r\nBcc: x@evil.example" }, "not a valid sender"],
    ["no public address", { ...ok, RIZO_PUBLIC_URL: undefined }, "RIZO_PUBLIC_URL is not set"],
  ])("refuses to start with %s, and says how to fix it", (_label, env, message) => {
    expect(() => emailConfig(env, () => undefined)).toThrow(message);
    expect(() => emailConfig(env, () => undefined)).toThrow("fix:");
  });

  it.each([
    ["http://blog.example", "https://"],
    ["https://blog.example/app", "no path"],
    ["https://blog.example/?x=1", "no path"],
    ["https://user:pass@blog.example", "no path"],
    ["javascript:alert(1)", "https://"],
    ["not a url", "not a valid address"],
  ])("refuses the public address %s", (url, message) => {
    expect(() => checkPublicUrl(url)).toThrow(message);
  });

  it("allows http only for localhost, and drops a trailing slash", () => {
    expect(checkPublicUrl("http://localhost:3000/")).toBe("http://localhost:3000");
    expect(checkPublicUrl("https://Blog.Example/")).toBe("https://blog.example");
  });
});

describe("sending through Resend", () => {
  it("posts one plain-text email over HTTPS with the API key", async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    const fake = (async (url: string, init: RequestInit) => {
      calls.push({ url, init });
      return new Response("{}", { status: 200 });
    }) as unknown as typeof fetch;
    await resendMailer("re_key", "hello@blog.example", fake)({ to: "a@b.co", subject: "S", text: "T" });
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe("https://api.resend.com/emails");
    expect(calls[0]?.init.headers).toMatchObject({ Authorization: "Bearer re_key" });
    expect(JSON.parse(String(calls[0]?.init.body))).toEqual({ from: "hello@blog.example", to: ["a@b.co"], subject: "S", text: "T" });
  });

  it("throws when Resend refuses, without the key in the message", async () => {
    const fake = (async () => new Response("{}", { status: 401 })) as unknown as typeof fetch;
    await expect(resendMailer("re_secret", "hello@blog.example", fake)({ to: "a@b.co", subject: "S", text: "T" })).rejects.toThrow(/^Resend answered 401$/);
  });
});

describe("emailed links", () => {
  it("use 256-bit tokens, stored only as hashes", () => {
    const { token, hash } = newEmailToken();
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(hash).toBe(emailTokenHash(token));
    expect(hash).not.toContain(token);
    expect(newEmailToken().token).not.toBe(token);
  });

  it("accept only well-formed tokens", () => {
    expect(readEmailToken("A".repeat(43))).toBe("A".repeat(43));
    for (const bad of ["A".repeat(42), "A".repeat(44), `${"A".repeat(42)}=`, 5, null, "' OR 1=1 --"]) expect(readEmailToken(bad)).toBeUndefined();
  });

  it("put the token after #, so it never reaches a server log", () => {
    const token = "B".repeat(43);
    expect(MESSAGES.verify("https://blog.example", token).text).toContain(`https://blog.example/verify-email#token=${token}`);
    expect(MESSAGES.reset("https://blog.example", token).text).toContain(`https://blog.example/reset-password#token=${token}`);
    expect(MESSAGES.alreadyRegistered("https://blog.example").text).not.toContain("token");
  });
});
