import { describe, expect, it } from "vitest";
import { EncryptionError, decryptValue, encryptValue, keyIdOf, parseKeys } from "../runtime/encryption.ts";
import { reencrypt } from "../runtime/reencrypt.ts";
import type { App } from "../runtime/types.ts";
import { buildApp } from "../src/emit/routes.js";
import { parseSnapshot, planMigration, snapshotText } from "../src/migrations.js";
import { buildSchema } from "../src/schema.js";
import { compileErrors, compileOk, firstError } from "./helpers.js";

const KEY_A = Buffer.alloc(32, 1).toString("base64");
const KEY_B = Buffer.alloc(32, 2).toString("base64");

const NOTES = (fields: string, list = "db.Note.list()") => `model Note {
  title: Text
${fields}
}
api GET /api/notes -> list Note.public {
  public
  return ${list}
}
`;

describe("the encrypted modifier", () => {
  it("is allowed on Text, Email, Number and Date, with other modifiers", () => {
    const r = compileOk(NOTES("  secret: Text encrypted max 200\n  contact: Email optional encrypted\n  amount: Number encrypted min 0\n  due: Date optional private encrypted"));
    const note = r.models[0];
    expect(note?.fields.filter((f) => f.encrypted).map((f) => f.name)).toEqual(["secret", "contact", "amount", "due"]);
  });

  it.each([
    ["Bool", "  done: Bool encrypted", "RZ0302", "encrypting it hides little"],
    ["Password", "  pin: Password encrypted", "RZ0302", "hashed"],
    ["ID", "  ref: ID encrypted", "RZ0302", "find records"],
  ])("is refused on %s", (_type, field, code, message) => {
    const e = firstError(NOTES(field));
    expect(e.code).toBe(code);
    expect(e.message + e.fix).toContain(message);
  });

  it("is refused on links", () => {
    expect(firstError(`model A {\n  b: B encrypted\n}\nmodel B {\n  x: Text\n}`).code).toBe("RZ0302");
  });

  it.each([
    ["unique", NOTES("  secret: Text unique encrypted"), "cannot be unique"],
    ["a list filter", NOTES("  secret: Text encrypted", "db.Note.list(secret = 1)"), "Cannot filter by encrypted"],
    ["an order", NOTES("  secret: Text encrypted", "db.Note.list(order secret)"), "Cannot order by encrypted"],
  ])("can't be used with %s (RZ0340), and the fix says why", (_label, source, message) => {
    const e = compileErrors(source).find((d) => d.code === "RZ0340");
    expect(e?.message).toContain(message);
    expect(e?.fix).toMatch(/encrypt/);
  });

  it("can't be the login field (which must be unique)", () => {
    const e = firstError("auth User by email\nmodel User {\n  email: Email unique encrypted\n  password: Password\n}\n");
    expect(e.code).toBe("RZ0340");
  });
});

describe("encrypted columns", () => {
  const schema = (src: string) => {
    const r = compileOk(src);
    return buildSchema(r.models, r.auth, true, r.apis);
  };

  it("are TEXT without database checks, and marked in the snapshot", () => {
    const table = schema(NOTES("  amount: Number encrypted min 0 max 10")).tables.find((t) => t.name === "notes");
    const col = table?.columns.find((c) => c.name === "amount");
    expect(col).toMatchObject({ type: "TEXT", check: null, unique: null, notNull: true, encrypted: true });
    expect(parseSnapshot(snapshotText(schema(NOTES("  amount: Number encrypted"))))).not.toHaveProperty("error");
  });

  it("treat adding or removing encrypted as replacing the column (data loss)", () => {
    const plain = schema(NOTES("  secret: Text"));
    const encrypted = schema(NOTES("  secret: Text encrypted"));
    for (const [from, to, word] of [[plain, encrypted, "becomes encrypted"], [encrypted, plain, "stops being encrypted"]] as const) {
      const p = planMigration(from, to);
      expect(p.dataLoss.join(" ")).toContain(word);
      expect(p.statements).toContain('ALTER TABLE "notes" DROP COLUMN "secret";');
    }
  });

  it("rejects a snapshot with a malformed encrypted flag", () => {
    const text = snapshotText(schema(NOTES("  secret: Text encrypted"))).replace('"encrypted": true', '"encrypted": "yes"');
    expect(parseSnapshot(text)).toHaveProperty("error");
  });

  it("are listed in the route data, bound to their table and column", () => {
    const r = compileOk(NOTES("  secret: Text encrypted"));
    const app = buildApp(r.apis, r.auth);
    expect(app.routes[0]?.encrypted).toEqual([{ key: "secret", aad: "notes.secret" }]);
    expect(app.encrypted?.[0]?.select).toBe(
      'SELECT "id", "secret" AS "value" FROM "notes" WHERE "secret" IS NOT NULL AND "secret" NOT LIKE $1 AND "id" > $2::uuid ORDER BY "id" LIMIT 500',
    );
    expect(buildApp(compileOk(NOTES("  plain: Text")).apis, undefined)).not.toHaveProperty("encrypted");
  });

  it("generate reencrypt.ts only for apps that have them", () => {
    expect(compileOk(NOTES("  secret: Text encrypted")).output.server?.reencrypt).toContain("runReencrypt(app)");
    expect(compileOk(NOTES("  plain: Text")).output.server?.reencrypt).toBeUndefined();
  });
});

describe("keys", () => {
  it("reads id:key pairs, and the first one encrypts", () => {
    const keys = parseKeys(`k2:${KEY_B}, k1:${KEY_A}`);
    expect(keys.current).toBe("k2");
    expect([...keys.keys.keys()]).toEqual(["k2", "k1"]);
    expect(parseKeys(`k1:${Buffer.alloc(32, 1).toString("base64url")}`).keys.get("k1")).toEqual(Buffer.alloc(32, 1));
  });

  it.each([
    ["missing", undefined, "is not set"],
    ["empty", " ", "is not set"],
    ["without an id", KEY_A, "valid key id"],
    ["with a bad id", `K-1:${KEY_A}`, "valid key id"],
    ["too short", `k1:${Buffer.alloc(16).toString("base64")}`, "not 32 bytes"],
    ["not base64", `k1:${"!".repeat(44)}`, "not 32 bytes"],
    ["listed twice", `k1:${KEY_A},k1:${KEY_B}`, "twice"],
  ])("refuses keys that are %s, and says how to fix it", (_label, raw, message) => {
    expect(() => parseKeys(raw)).toThrow(message);
    expect(() => parseKeys(raw)).toThrow("fix:");
  });

  it("never puts a key in an error message", () => {
    try {
      parseKeys(`k1:${KEY_A},k1:${KEY_A}`);
    } catch (e) {
      expect(String(e)).not.toContain(KEY_A);
    }
  });
});

describe("encryption", () => {
  const keys = parseKeys(`k1:${KEY_A}`);

  it("round-trips text, numbers and dates", () => {
    for (const value of ["hello", "", "ünïcødé 🔐", 42, -7, 0]) {
      expect(decryptValue(keys, "t.c", encryptValue(keys, "t.c", value))).toEqual(value);
    }
    const when = new Date("2026-01-31T12:00:00Z");
    expect(decryptValue(keys, "t.c", encryptValue(keys, "t.c", when))).toBe(when.toISOString());
  });

  it("uses a fresh IV, so equal values look different", () => {
    const a = encryptValue(keys, "t.c", "same");
    const b = encryptValue(keys, "t.c", "same");
    expect(a).not.toBe(b);
    expect(a).toMatch(/^rz1\.k1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]+$/);
    expect(a).not.toContain("same");
    expect(keyIdOf(a)).toBe("k1");
  });

  it("refuses a value copied into another column", () => {
    const stored = encryptValue(keys, "users.phone", "+1 555 0100");
    expect(() => decryptValue(keys, "users.notes", stored)).toThrow(EncryptionError);
  });

  it("refuses tampered values, without revealing them", () => {
    const stored = encryptValue(keys, "t.c", "secret value");
    const parts = stored.split(".");
    const data = Buffer.from(parts[3] ?? "", "base64url");
    data[0] = (data[0] ?? 0) ^ 1;
    const tampered = [...parts.slice(0, 3), data.toString("base64url")].join(".");
    expect(() => decryptValue(keys, "t.c", tampered)).toThrow("could not be decrypted");
    for (const bad of ["plain text", "rz1.k1.x.y", 5, null, `rz1.k9.${parts[2]}.${parts[3]}`]) {
      expect(() => decryptValue(keys, "t.c", bad)).toThrow(EncryptionError);
    }
  });

  it("says which key is missing", () => {
    const stored = encryptValue(parseKeys(`old:${KEY_B}`), "t.c", "x");
    expect(() => decryptValue(keys, "t.c", stored)).toThrow('uses key "old", which is not in RIZO_ENCRYPTION_KEYS');
  });
});

describe("rotating keys", () => {
  it("re-encrypts old values with the current key, and skips ones that are already current", async () => {
    const oldKeys = parseKeys(`k1:${KEY_A}`);
    const rows = new Map<string, string>([
      ["00000000-0000-0000-0000-000000000001", encryptValue(oldKeys, "notes.secret", "one")],
      ["00000000-0000-0000-0000-000000000002", encryptValue(oldKeys, "notes.secret", "two")],
      ["00000000-0000-0000-0000-000000000003", "not encrypted"],
    ]);
    const app = { routes: [], auth: null, pages: [], encrypted: [{ aad: "notes.secret", select: "select", update: "update" }] } as App;
    const db = {
      query: async (sql: string, values: unknown[]) => {
        if (sql === "select") {
          const [pattern, after] = values as [string, string];
          const prefix = pattern.slice(0, -1);
          const found = [...rows].filter(([id, v]) => id > after && !v.startsWith(prefix)).map(([id, value]) => ({ id, value }));
          return { rows: found, rowCount: found.length };
        }
        const [id, value, previous] = values as [string, string, string];
        if (rows.get(id) !== previous) return { rows: [], rowCount: 0 };
        rows.set(id, value);
        return { rows: [], rowCount: 1 };
      },
    };
    const both = parseKeys(`k2:${KEY_B},k1:${KEY_A}`);
    expect(await reencrypt(app, db, both)).toEqual({ updated: 2, failed: 1 });
    const newOnly = parseKeys(`k2:${KEY_B}`);
    expect(decryptValue(newOnly, "notes.secret", rows.get("00000000-0000-0000-0000-000000000001"))).toBe("one");
    expect(await reencrypt(app, db, both)).toEqual({ updated: 0, failed: 1 });
  });
});
