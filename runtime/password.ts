/**
 * Rizo Lang runtime: password hashing with scrypt (built into Node.js).
 *
 * Parameters follow the OWASP Password Storage Cheat Sheet (N=2^15, r=8, p=3,
 * about 32 MiB of memory per hash). Stored format:
 *   scrypt$<log2 N>$<r>$<p>$<salt base64url>$<hash base64url>
 */
import { randomBytes, scrypt, timingSafeEqual } from "node:crypto";

const LOG_N = 15;
const R = 8;
const P = 3;
const KEY_LENGTH = 64;
const SALT_BYTES = 16;

function derive(password: string, salt: Buffer, logN: number, r: number, p: number): Promise<Buffer> {
  const N = 2 ** logN;
  return new Promise((resolve, reject) => {
    // maxmem must exceed 128 * N * r bytes.
    scrypt(password.normalize("NFC"), salt, KEY_LENGTH, { N, r, p, maxmem: 256 * N * r }, (err, key) => {
      if (err) reject(err);
      else resolve(key);
    });
  });
}

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(SALT_BYTES);
  const key = await derive(password, salt, LOG_N, R, P);
  return `scrypt$${LOG_N}$${R}$${P}$${salt.toString("base64url")}$${key.toString("base64url")}`;
}

/** Constant-time check. Returns false (never throws) for malformed hashes. */
export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") return false;
  const logN = Number(parts[1]);
  const r = Number(parts[2]);
  const p = Number(parts[3]);
  // Bound the parameters so a tampered hash cannot make verification hang or exhaust memory.
  if (!Number.isInteger(logN) || logN < 14 || logN > 20) return false;
  if (!Number.isInteger(r) || r < 1 || r > 16 || !Number.isInteger(p) || p < 1 || p > 16) return false;
  const salt = Buffer.from(parts[4] ?? "", "base64url");
  const expected = Buffer.from(parts[5] ?? "", "base64url");
  if (salt.length < SALT_BYTES || expected.length !== KEY_LENGTH) return false;
  const actual = await derive(password, salt, logN, r, p);
  return timingSafeEqual(actual, expected);
}

let dummy: Promise<string> | undefined;
/**
 * A hash of a random password, used when a login names an unknown account,
 * so that response time does not reveal whether the account exists.
 */
export function dummyHash(): Promise<string> {
  dummy ??= hashPassword(randomBytes(32).toString("base64url"));
  return dummy;
}
