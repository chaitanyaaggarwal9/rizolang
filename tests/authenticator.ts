/**
 * A software passkey authenticator for tests: it creates a real P-256 key
 * pair and produces the same WebAuthn messages a phone or security key would.
 */
import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from "node:crypto";

type Cbor = number | string | boolean | Uint8Array | Cbor[] | Map<number | string, Cbor>;

/** A minimal CBOR encoder (only what WebAuthn needs). */
export function encodeCbor(value: Cbor): Buffer {
  const head = (major: number, n: number): Buffer => {
    if (n < 24) return Buffer.from([(major << 5) | n]);
    if (n < 256) return Buffer.from([(major << 5) | 24, n]);
    if (n < 65536) return Buffer.from([(major << 5) | 25, n >> 8, n & 0xff]);
    const b = Buffer.alloc(5);
    b[0] = (major << 5) | 26;
    b.writeUInt32BE(n, 1);
    return b;
  };
  if (typeof value === "boolean") return Buffer.from([value ? 0xf5 : 0xf4]);
  if (typeof value === "number") return value >= 0 ? head(0, value) : head(1, -1 - value);
  if (typeof value === "string") {
    const bytes = Buffer.from(value, "utf8");
    return Buffer.concat([head(3, bytes.length), bytes]);
  }
  if (value instanceof Uint8Array) return Buffer.concat([head(2, value.length), Buffer.from(value)]);
  if (Array.isArray(value)) return Buffer.concat([head(4, value.length), ...value.map(encodeCbor)]);
  return Buffer.concat([head(5, value.size), ...[...value].flatMap(([k, v]) => [encodeCbor(k), encodeCbor(v)])]);
}

const sha256 = (data: Uint8Array | string): Buffer => createHash("sha256").update(data).digest();
const b64url = (data: Uint8Array | string): string => Buffer.from(data).toString("base64url");

export interface Options {
  /** Leave out the "user verified" flag. */
  readonly noUserVerification?: boolean;
  /** Sign for a different site. */
  readonly rpId?: string;
  readonly origin?: string;
  readonly type?: string;
  readonly crossOrigin?: boolean;
}

export class SoftAuthenticator {
  readonly credentialId = randomBytes(32);
  readonly #key: KeyObject;
  readonly #cose: Buffer;
  signCount = 0;
  /** The user handle the passkey was created for (base64url). */
  userHandle = "";

  constructor() {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    this.#key = privateKey;
    const jwk = publicKey.export({ format: "jwk" });
    this.#cose = encodeCbor(new Map<number, Cbor>([
      [1, 2], [3, -7], [-1, 1],
      [-2, Buffer.from(jwk.x ?? "", "base64url")],
      [-3, Buffer.from(jwk.y ?? "", "base64url")],
    ]));
  }

  #authData(rpId: string, attested: boolean, options: Options): Buffer {
    const flags = 0x01 | (options.noUserVerification ? 0 : 0x04) | (attested ? 0x40 : 0);
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(this.signCount);
    const parts = [sha256(options.rpId ?? rpId), Buffer.from([flags]), counter];
    if (attested) {
      const idLength = Buffer.alloc(2);
      idLength.writeUInt16BE(this.credentialId.length);
      parts.push(Buffer.alloc(16), idLength, this.credentialId, this.#cose);
    }
    return Buffer.concat(parts);
  }

  #clientData(type: string, challenge: string, origin: string, options: Options): Buffer {
    return Buffer.from(JSON.stringify({ type: options.type ?? type, challenge, origin: options.origin ?? origin, crossOrigin: options.crossOrigin ?? false }));
  }

  /** What `navigator.credentials.create()` returns, encoded as the client runtime sends it. */
  register(options: { challenge: string; rpId: string; origin: string; userId: string }, extra: Options = {}) {
    this.userHandle = options.userId;
    const authData = this.#authData(options.rpId, true, extra);
    return {
      id: b64url(this.credentialId),
      response: {
        clientDataJSON: b64url(this.#clientData("webauthn.create", options.challenge, options.origin, extra)),
        attestationObject: b64url(encodeCbor(new Map<string, Cbor>([["fmt", "none"], ["attStmt", new Map()], ["authData", authData]]))),
      },
    };
  }

  /** What `navigator.credentials.get()` returns. Each call bumps the counter, like real authenticators. */
  login(options: { challenge: string; rpId: string; origin: string }, extra: Options = {}) {
    this.signCount++;
    const authData = this.#authData(options.rpId, false, extra);
    const clientData = this.#clientData("webauthn.get", options.challenge, options.origin, extra);
    const signature = sign("sha256", Buffer.concat([authData, sha256(clientData)]), this.#key);
    return {
      id: b64url(this.credentialId),
      response: {
        clientDataJSON: b64url(clientData),
        authenticatorData: b64url(authData),
        signature: b64url(signature),
        userHandle: this.userHandle,
      },
    };
  }
}
