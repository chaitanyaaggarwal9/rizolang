/**
 * Rizo Lang runtime: encrypted fields (AES-256-GCM).
 *
 * Values of `encrypted` fields are encrypted here, before they become SQL
 * parameters, and decrypted after they are read, so the database (and its
 * backups) only ever hold ciphertext.
 *
 * Stored format: `rz1.<key id>.<iv>.<ciphertext + tag>` (base64url parts).
 * - Each value gets a random 12-byte IV.
 * - The associated data binds the value to its table and column (and key id),
 *   so a ciphertext copied into another column fails to decrypt.
 * - Keys come from RIZO_ENCRYPTION_KEYS as `id:base64key` pairs. The first one
 *   encrypts; every listed key can decrypt, which is how keys are rotated.
 *
 * Error messages never contain values or keys.
 */
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

export class EncryptionError extends Error {
  override name = "EncryptionError";
}

export interface Keys {
  /** Id of the key new values are encrypted with. */
  readonly current: string;
  readonly keys: ReadonlyMap<string, Buffer>;
}

const VERSION = "rz1";
const KEY_ID = /^[a-z0-9]{1,16}$/;

const FIX =
  "  fix: Set RIZO_ENCRYPTION_KEYS to `<id>:<key>`, where id is 1-16 lowercase letters or digits and key is 32 random bytes in base64, " +
  "e.g. RIZO_ENCRYPTION_KEYS=k1:$(openssl rand -base64 32). To rotate, put a new key first and keep the old ones after it.";

/** Read RIZO_ENCRYPTION_KEYS. Throws an Error that says what is wrong and how to fix it. */
export function parseKeys(raw: string | undefined): Keys {
  if (raw === undefined || raw.trim() === "") {
    throw new Error(`RIZO_ENCRYPTION_KEYS is not set, but this app has encrypted fields.\n${FIX}`);
  }
  const keys = new Map<string, Buffer>();
  let current: string | undefined;
  for (const entry of raw.split(",").map((s) => s.trim()).filter(Boolean)) {
    const colon = entry.indexOf(":");
    const id = entry.slice(0, colon);
    const text = entry.slice(colon + 1);
    if (colon < 0 || !KEY_ID.test(id)) throw new Error(`RIZO_ENCRYPTION_KEYS has an entry without a valid key id.\n${FIX}`);
    if (keys.has(id)) throw new Error(`RIZO_ENCRYPTION_KEYS lists key "${id}" twice.\n${FIX}`);
    const key = /^[A-Za-z0-9+/]{43}=$/.test(text) || /^[A-Za-z0-9_-]{43}$/.test(text) ? Buffer.from(text, text.endsWith("=") ? "base64" : "base64url") : undefined;
    if (key === undefined || key.length !== 32) throw new Error(`Key "${id}" in RIZO_ENCRYPTION_KEYS is not 32 bytes of base64.\n${FIX}`);
    keys.set(id, key);
    current ??= id;
  }
  if (current === undefined) throw new Error(`RIZO_ENCRYPTION_KEYS has no keys.\n${FIX}`);
  return { current, keys };
}

const additionalData = (keyId: string, aad: string): Buffer => Buffer.from(`${VERSION}.${keyId}.${aad}`);

/** Encrypt a validated value for the column named by `aad` ("table.column"). */
export function encryptValue(keys: Keys, aad: string, value: unknown): string {
  const key = keys.keys.get(keys.current);
  if (key === undefined) throw new EncryptionError("The current encryption key is missing.");
  const plain = Buffer.from(JSON.stringify(value instanceof Date ? value.toISOString() : value), "utf8");
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(additionalData(keys.current, aad));
  const data = Buffer.concat([cipher.update(plain), cipher.final(), cipher.getAuthTag()]);
  return `${VERSION}.${keys.current}.${iv.toString("base64url")}.${data.toString("base64url")}`;
}

/** The key id a stored value was encrypted with, or undefined if it isn't an encrypted value. */
export function keyIdOf(stored: string): string | undefined {
  const parts = stored.split(".");
  return parts.length === 4 && parts[0] === VERSION && KEY_ID.test(parts[1] ?? "") ? parts[1] : undefined;
}

/** Decrypt a stored value of the column named by `aad`. */
export function decryptValue(keys: Keys, aad: string, stored: unknown): unknown {
  if (typeof stored !== "string") throw new EncryptionError(`A value in ${aad} is not encrypted.`);
  const keyId = keyIdOf(stored);
  const [, , ivText = "", dataText = ""] = stored.split(".");
  if (keyId === undefined) throw new EncryptionError(`A value in ${aad} is not encrypted.`);
  const key = keys.keys.get(keyId);
  if (key === undefined) throw new EncryptionError(`A value in ${aad} uses key "${keyId}", which is not in RIZO_ENCRYPTION_KEYS.`);
  const iv = Buffer.from(ivText, "base64url");
  const data = Buffer.from(dataText, "base64url");
  if (iv.length !== 12 || data.length < 16) throw new EncryptionError(`A value in ${aad} is damaged.`);
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAAD(additionalData(keyId, aad));
    decipher.setAuthTag(data.subarray(data.length - 16));
    const plain = Buffer.concat([decipher.update(data.subarray(0, data.length - 16)), decipher.final()]);
    return JSON.parse(plain.toString("utf8"));
  } catch {
    throw new EncryptionError(`A value in ${aad} could not be decrypted: it was changed, or belongs to another column.`);
  }
}
