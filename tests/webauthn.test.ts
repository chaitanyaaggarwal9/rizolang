import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { CborError, decodeCbor } from "../runtime/cbor.ts";
import { PasskeyError, coseToKey, verifyAssertion, verifyRegistration } from "../runtime/webauthn.ts";
import { SoftAuthenticator, encodeCbor } from "./authenticator.js";

const SITE = { rpId: "blog.example", origin: "https://blog.example" };
const challenge = (n = 1) => Buffer.alloc(32, n).toString("base64url");

describe("CBOR", () => {
  it("decodes what WebAuthn uses", () => {
    const bytes = encodeCbor(new Map<string | number, never>([["a", 1 as never], [-2, Buffer.from([1, 2]) as never], [3, [true, "x"] as never]]));
    expect(decodeCbor(bytes).value).toEqual(new Map<string | number, unknown>([["a", 1], [-2, new Uint8Array([1, 2])], [3, [true, "x"]]]));
  });

  it.each([
    ["indefinite length", Buffer.from([0x5f])],
    ["tag", Buffer.from([0xc0, 0x01])],
    ["float", Buffer.from([0xfa, 0, 0, 0, 0])],
    ["truncated", Buffer.from([0x58, 10, 1])],
    ["duplicate key", Buffer.from([0xa2, 0x01, 0x01, 0x01, 0x02])],
    ["huge array", Buffer.from([0x9a, 0xff, 0xff, 0xff, 0xff])],
    ["deep nesting", Buffer.from(Array(20).fill(0x81).concat([0x00]))],
  ])("refuses %s", (_label, bytes) => {
    expect(() => decodeCbor(bytes)).toThrow(CborError);
  });
});

describe("passkey registration", () => {
  const expected = { challenge: challenge(), ...SITE };

  it("accepts a valid new passkey and keeps its public key", () => {
    const authenticator = new SoftAuthenticator();
    const created = authenticator.register({ challenge: expected.challenge, ...SITE, userId: "u1" });
    const r = verifyRegistration(created.response, expected);
    expect(r).toMatchObject({ credentialId: created.id, algorithm: -7, signCount: 0 });
    expect(r.publicKey.length).toBeGreaterThan(80);
  });

  it.each([
    ["a different challenge", { challenge: challenge(2) }, {}, "challenge"],
    ["another site's origin", {}, { origin: "https://evil.example" }, "different site"],
    ["another site's rp id", {}, { rpId: "evil.example" }, "different site"],
    ["no user verification", {}, { noUserVerification: true }, "not verified"],
    ["the wrong ceremony", {}, { type: "webauthn.get" }, "different step"],
    ["an embedded frame", {}, { crossOrigin: true }, "embedded"],
  ])("refuses %s", (_label, override: { challenge?: string }, extra, message) => {
    const created = new SoftAuthenticator().register({ challenge: override.challenge ?? expected.challenge, ...SITE, userId: "u1" }, extra);
    expect(() => verifyRegistration(created.response, expected)).toThrow(message);
  });

  it("refuses garbage instead of crashing", () => {
    for (const bad of [{}, { clientDataJSON: "!!", attestationObject: "" }, { clientDataJSON: 5, attestationObject: [] }]) {
      expect(() => verifyRegistration(bad as never, expected)).toThrow(PasskeyError);
    }
  });
});

describe("passkey login", () => {
  const setup = () => {
    const authenticator = new SoftAuthenticator();
    const reg = verifyRegistration(authenticator.register({ challenge: challenge(), ...SITE, userId: "u1" }).response, { challenge: challenge(), ...SITE });
    return { authenticator, stored: { publicKey: reg.publicKey, algorithm: reg.algorithm, signCount: reg.signCount } };
  };

  it("accepts a valid signature and returns the new counter", () => {
    const { authenticator, stored } = setup();
    const expected = { challenge: challenge(3), ...SITE };
    expect(verifyAssertion(authenticator.login({ challenge: expected.challenge, ...SITE }).response, stored, expected)).toBe(1);
  });

  it("refuses a signature from a different key", () => {
    const { stored } = setup();
    const impostor = new SoftAuthenticator();
    const expected = { challenge: challenge(3), ...SITE };
    expect(() => verifyAssertion(impostor.login({ challenge: expected.challenge, ...SITE }).response, stored, expected)).toThrow("signature");
  });

  it("refuses a tampered message", () => {
    const { authenticator, stored } = setup();
    const expected = { challenge: challenge(3), ...SITE };
    const r = authenticator.login({ challenge: expected.challenge, ...SITE }).response;
    const data = Buffer.from(r.authenticatorData, "base64url");
    data[36] = (data[36] ?? 0) ^ 1; // change the counter after signing
    expect(() => verifyAssertion({ ...r, authenticatorData: data.toString("base64url") }, stored, expected)).toThrow("signature");
  });

  it("refuses a counter that went backwards (a cloned key)", () => {
    const { authenticator, stored } = setup();
    const expected = { challenge: challenge(3), ...SITE };
    const r = authenticator.login({ challenge: expected.challenge, ...SITE }).response;
    expect(() => verifyAssertion(r, { ...stored, signCount: 5 }, expected)).toThrow("copied");
  });

  it.each([
    ["another site", { origin: "https://evil.example" }, "different site"],
    ["another rp id", { rpId: "evil.example" }, "different site"],
    ["no user verification", { noUserVerification: true }, "not verified"],
  ])("refuses %s", (_label, extra, message) => {
    const { authenticator, stored } = setup();
    const expected = { challenge: challenge(3), ...SITE };
    expect(() => verifyAssertion(authenticator.login({ challenge: expected.challenge, ...SITE }, extra).response, stored, expected)).toThrow(message);
  });
});

describe("COSE keys", () => {
  it("accepts RS256 keys", () => {
    const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const jwk = publicKey.export({ format: "jwk" });
    const cose = new Map<number, unknown>([[1, 3], [3, -257], [-1, Buffer.from(jwk.n ?? "", "base64url")], [-2, Buffer.from(jwk.e ?? "", "base64url")]]);
    expect(coseToKey(cose as never).algorithm).toBe(-257);
  });

  it("refuses unsupported algorithms and curves", () => {
    expect(() => coseToKey(new Map([[1, 1], [3, -8]]) as never)).toThrow("not supported");
    expect(() => coseToKey(new Map([[1, 2], [3, -7], [-1, 2]]) as never)).toThrow("P-256");
  });
});
