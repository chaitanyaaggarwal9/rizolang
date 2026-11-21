/**
 * Rizo Lang runtime: a small, strict CBOR decoder for WebAuthn.
 *
 * Passkey data (attestation objects and public keys) is encoded in CBOR.
 * This decoder supports only what WebAuthn uses: unsigned and negative
 * integers, byte and text strings, arrays, maps and the simple values
 * false/true/null. Indefinite lengths, tags and floats are refused, and
 * sizes and nesting are bounded, so hostile input can't exhaust memory.
 */

export type CborValue = number | bigint | Uint8Array | string | boolean | null | CborValue[] | Map<CborKey, CborValue>;
export type CborKey = number | string;

export class CborError extends Error {}

const MAX_DEPTH = 8;
const MAX_ITEMS = 1024;

export interface Decoded {
  readonly value: CborValue;
  /** Bytes consumed (the value may be followed by more data). */
  readonly length: number;
}

/** Decode one CBOR value from the start of `bytes`. */
export function decodeCbor(bytes: Uint8Array): Decoded {
  let pos = 0;
  const need = (n: number): void => {
    if (pos + n > bytes.length) throw new CborError("unexpected end of data");
  };
  const byte = (): number => {
    need(1);
    return bytes[pos++] ?? 0;
  };
  const uint = (info: number): number | bigint => {
    if (info < 24) return info;
    const size = info === 24 ? 1 : info === 25 ? 2 : info === 26 ? 4 : info === 27 ? 8 : 0;
    if (size === 0) throw new CborError("indefinite lengths are not supported");
    need(size);
    let n = 0n;
    for (let i = 0; i < size; i++) n = (n << 8n) | BigInt(bytes[pos++] ?? 0);
    return n <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(n) : n;
  };
  const count = (info: number, limit: number): number => {
    const n = uint(info);
    if (typeof n !== "number" || n > limit) throw new CborError("length too large");
    return n;
  };

  const item = (depth: number): CborValue => {
    if (depth > MAX_DEPTH) throw new CborError("nested too deeply");
    const head = byte();
    const major = head >> 5;
    const info = head & 0x1f;
    switch (major) {
      case 0:
        return uint(info);
      case 1: {
        const n = uint(info);
        return typeof n === "number" ? -1 - n : -1n - n;
      }
      case 2: {
        const n = count(info, bytes.length);
        need(n);
        const out = new Uint8Array(bytes.subarray(pos, pos + n)); // a plain copy, whatever the input type
        pos += n;
        return out;
      }
      case 3: {
        const n = count(info, bytes.length);
        need(n);
        const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(pos, pos + n));
        pos += n;
        return text;
      }
      case 4: {
        const n = count(info, MAX_ITEMS);
        const out: CborValue[] = [];
        for (let i = 0; i < n; i++) out.push(item(depth + 1));
        return out;
      }
      case 5: {
        const n = count(info, MAX_ITEMS);
        const out = new Map<CborKey, CborValue>();
        for (let i = 0; i < n; i++) {
          const key = item(depth + 1);
          if (typeof key !== "number" && typeof key !== "string") throw new CborError("map keys must be integers or text");
          if (out.has(key)) throw new CborError("duplicate map key");
          out.set(key, item(depth + 1));
        }
        return out;
      }
      case 7:
        if (info === 20) return false;
        if (info === 21) return true;
        if (info === 22) return null;
        throw new CborError("unsupported simple value or float");
      default:
        throw new CborError("tags are not supported");
    }
  };

  const value = item(0);
  return { value, length: pos };
}
