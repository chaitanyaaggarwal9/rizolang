/**
 * Rizo Lang runtime: passkey (WebAuthn) verification with node:crypto.
 *
 * Registration and login each check, following the WebAuthn specification:
 * - the browser data is for this ceremony (type), this one-time challenge
 *   and this site (origin), and not from a cross-origin frame;
 * - the authenticator data is for this site (rpIdHash) and the user was
 *   present and verified (fingerprint, face or PIN);
 * - at login, the signature is valid for the stored public key, and the
 *   signature counter has not gone backwards (a sign of a cloned key).
 *
 * Attestation statements are not checked ("none" attestation): any
 * authenticator may be registered, as is usual for passkeys.
 */
import { type KeyObject, createHash, createPublicKey, timingSafeEqual, verify } from "node:crypto";
import { type CborKey, type CborValue, decodeCbor } from "./cbor.ts";

export class PasskeyError extends Error {}

/** Algorithms accepted for passkeys: ES256 and RS256 (COSE identifiers). */
export const SUPPORTED_ALGORITHMS = [-7, -257] as const;

export interface Expected {
  /** The challenge this server issued for this ceremony (base64url). */
  readonly challenge: string;
  /** The site's origin, e.g. "https://example.com". */
  readonly origin: string;
  /** The relying party id: the site's hostname, e.g. "example.com". */
  readonly rpId: string;
}

export interface RegisteredPasskey {
  readonly credentialId: string;
  /** The public key, as base64url SPKI DER. */
  readonly publicKey: string;
  readonly algorithm: number;
  readonly signCount: number;
}

const FLAG_USER_PRESENT = 0x01;
const FLAG_USER_VERIFIED = 0x04;
const FLAG_ATTESTED_DATA = 0x40;

export function fromBase64url(text: unknown, what: string, maxBytes: number): Buffer {
  if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text) || text.length > Math.ceil((maxBytes * 4) / 3)) {
    throw new PasskeyError(`${what} is not valid.`);
  }
  return Buffer.from(text, "base64url");
}

const sha256 = (data: Uint8Array): Buffer => createHash("sha256").update(data).digest();

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}

function checkClientData(clientDataJSON: Buffer, type: "webauthn.create" | "webauthn.get", expected: Expected): void {
  let data: { type?: unknown; challenge?: unknown; origin?: unknown; crossOrigin?: unknown };
  try {
    data = JSON.parse(clientDataJSON.toString("utf8"));
  } catch {
    throw new PasskeyError("The browser data is not valid.");
  }
  if (data.type !== type) throw new PasskeyError("The browser data is for a different step.");
  if (typeof data.challenge !== "string" || !sameBytes(Buffer.from(data.challenge), Buffer.from(expected.challenge))) {
    throw new PasskeyError("The challenge does not match.");
  }
  if (data.origin !== expected.origin) throw new PasskeyError("The passkey was used on a different site.");
  if (data.crossOrigin === true) throw new PasskeyError("Passkeys can't be used from embedded frames.");
}

interface AuthData {
  readonly rpIdHash: Buffer;
  readonly flags: number;
  readonly signCount: number;
  readonly credentialId?: Buffer;
  readonly coseKey?: Map<CborKey, CborValue>;
}

export function parseAuthData(data: Buffer): AuthData {
  if (data.length < 37) throw new PasskeyError("The authenticator data is too short.");
  const flags = data[32] ?? 0;
  const parsed = { rpIdHash: data.subarray(0, 32), flags, signCount: data.readUInt32BE(33) };
  if ((flags & FLAG_ATTESTED_DATA) === 0) return parsed;
  if (data.length < 55) throw new PasskeyError("The authenticator data is too short.");
  const idLength = data.readUInt16BE(53);
  if (idLength < 16 || idLength > 1023 || data.length < 55 + idLength) throw new PasskeyError("The credential id is not valid.");
  const credentialId = data.subarray(55, 55 + idLength);
  const key = decodeCbor(data.subarray(55 + idLength)).value;
  if (!(key instanceof Map)) throw new PasskeyError("The public key is not valid.");
  return { ...parsed, credentialId, coseKey: key };
}

function checkAuthData(auth: AuthData, expected: Expected): void {
  if (!sameBytes(auth.rpIdHash, sha256(Buffer.from(expected.rpId)))) throw new PasskeyError("The passkey belongs to a different site.");
  if ((auth.flags & FLAG_USER_PRESENT) === 0) throw new PasskeyError("The user was not present.");
  if ((auth.flags & FLAG_USER_VERIFIED) === 0) throw new PasskeyError("The user was not verified (fingerprint, face or PIN).");
}

/** Convert a COSE public key to a node:crypto key. Only ES256 (P-256) and RS256. */
export function coseToKey(cose: Map<CborKey, CborValue>): { key: KeyObject; algorithm: number } {
  const kty = cose.get(1);
  const alg = cose.get(3);
  const bytes = (label: number): string => {
    const v = cose.get(label);
    if (!(v instanceof Uint8Array)) throw new PasskeyError("The public key is not valid.");
    return Buffer.from(v).toString("base64url");
  };
  if (kty === 2 && alg === -7) {
    if (cose.get(-1) !== 1) throw new PasskeyError("Only the P-256 curve is supported.");
    return { key: createPublicKey({ key: { kty: "EC", crv: "P-256", x: bytes(-2), y: bytes(-3) }, format: "jwk" }), algorithm: -7 };
  }
  if (kty === 3 && alg === -257) {
    return { key: createPublicKey({ key: { kty: "RSA", n: bytes(-1), e: bytes(-2) }, format: "jwk" }), algorithm: -257 };
  }
  throw new PasskeyError("This kind of passkey is not supported (use ES256 or RS256).");
}

/** Verify a new passkey. */
export function verifyRegistration(
  response: { clientDataJSON: unknown; attestationObject: unknown },
  expected: Expected,
): RegisteredPasskey {
  const clientDataJSON = fromBase64url(response.clientDataJSON, "clientDataJSON", 4096);
  checkClientData(clientDataJSON, "webauthn.create", expected);
  const attestation = decodeCbor(fromBase64url(response.attestationObject, "attestationObject", 16_384)).value;
  if (!(attestation instanceof Map)) throw new PasskeyError("The attestation is not valid.");
  const authBytes = attestation.get("authData");
  if (!(authBytes instanceof Uint8Array)) throw new PasskeyError("The attestation is not valid.");
  const auth = parseAuthData(Buffer.from(authBytes));
  checkAuthData(auth, expected);
  if (auth.credentialId === undefined || auth.coseKey === undefined) throw new PasskeyError("The attestation has no public key.");
  const { key, algorithm } = coseToKey(auth.coseKey);
  return {
    credentialId: auth.credentialId.toString("base64url"),
    publicKey: key.export({ type: "spki", format: "der" }).toString("base64url"),
    algorithm,
    signCount: auth.signCount,
  };
}

/** Verify a login with a stored passkey. Returns the new signature counter. */
export function verifyAssertion(
  response: { clientDataJSON: unknown; authenticatorData: unknown; signature: unknown },
  stored: { publicKey: string; algorithm: number; signCount: number },
  expected: Expected,
): number {
  const clientDataJSON = fromBase64url(response.clientDataJSON, "clientDataJSON", 4096);
  checkClientData(clientDataJSON, "webauthn.get", expected);
  const authBytes = fromBase64url(response.authenticatorData, "authenticatorData", 2048);
  const auth = parseAuthData(authBytes);
  checkAuthData(auth, expected);
  const signature = fromBase64url(response.signature, "signature", 1024);
  const key = createPublicKey({ key: Buffer.from(stored.publicKey, "base64url"), format: "der", type: "spki" });
  if (!(SUPPORTED_ALGORITHMS as readonly number[]).includes(stored.algorithm)) throw new PasskeyError("Unsupported passkey.");
  const signed = Buffer.concat([authBytes, sha256(clientDataJSON)]);
  if (!verify("sha256", signed, key, signature)) throw new PasskeyError("The passkey's signature is not valid.");
  // Counters only ever go up. A counter of 0 means the authenticator doesn't keep one.
  if (auth.signCount !== 0 || stored.signCount !== 0) {
    if (auth.signCount <= stored.signCount) throw new PasskeyError("This passkey may have been copied. Remove it and add it again.");
  }
  return auth.signCount;
}
