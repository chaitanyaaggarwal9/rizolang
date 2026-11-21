/**
 * Security tests. These prove the guarantees in docs/SPEC.md:
 *   1. A Password field never appears in a public type.
 *   2. Invalid syntax produces a clear error with the exact line and column.
 *   3. Unknown field types are rejected and no output is produced.
 *   4. Names cannot inject SQL.
 *   5. Passkeys work only on their own site and are never copied (SPEC §7.11).
 *   7. Encrypted fields reach the database only as ciphertext bound to their column (SPEC §7.13).
 *   6. Signup never reveals which emails have accounts, and emailed links are one-time and hashed (SPEC §7.12).
 */
import { createPublicKey, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { PASSKEY_SQL, challengeHash, newChallenge } from "../runtime/passkeys.ts";
import { EMAIL_SQL, MESSAGES, newEmailToken } from "../runtime/email.ts";
import { EncryptionError, decryptValue, encryptValue, parseKeys } from "../runtime/encryption.ts";
import { IDLE_SECONDS, MAX_SECONDS, SQL as SESSION_SQL } from "../runtime/session.ts";
import { MAX_TOKEN_DAYS, TOKEN_SQL } from "../runtime/tokens.ts";
import { PasskeyError, verifyAssertion, verifyRegistration } from "../runtime/webauthn.ts";
import { SoftAuthenticator } from "./authenticator.js";
import { compile } from "../src/compiler.js";
import { FIELD_TYPE_NAMES, FIELD_TYPES } from "../src/types.js";
import { buildApp } from "../src/emit/routes.js";
import { compileOk, firstError, interfaceBody, propertyNames } from "./helpers.js";

/** Small deterministic PRNG so failures are reproducible. */
function rng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 2 ** 32;
  };
}

function randomSchema(seed: number): { source: string; passwordFields: Map<string, string[]> } {
  const rand = rng(seed);
  const pick = <T>(xs: readonly T[]): T => xs[Math.floor(rand() * xs.length)] as T;
  const words = ["password", "secret", "pin", "name", "email", "token", "pass", "hash", "key", "note", "login", "code"];
  const passwordFields = new Map<string, string[]>();
  const blocks: string[] = [];
  const modelCount = 1 + Math.floor(rand() * 4);
  for (let m = 0; m < modelCount; m++) {
    const modelName = `Model${m}`;
    const fields: string[] = [];
    const secrets: string[] = [];
    const fieldCount = 1 + Math.floor(rand() * 8);
    for (let f = 0; f < fieldCount; f++) {
      const name = `${pick(words)}${f}`;
      // Bias toward Password so most models contain at least one.
      const type = rand() < 0.35 ? "Password" : pick(FIELD_TYPE_NAMES);
      const optional = rand() < 0.3 ? " optional" : "";
      if (type === "Password") secrets.push(name);
      fields.push(`  ${name}: ${type}${optional}`);
    }
    passwordFields.set(modelName, secrets);
    blocks.push(`model ${modelName} {\n${fields.join("\n")}\n}`);
  }
  return { source: blocks.join("\n\n"), passwordFields };
}

describe("security: Password never appears in a public type", () => {
  it("is excluded from the public type of a simple model", () => {
    const { output } = compileOk("model User {\n  email: Email\n  password: Password\n}");
    const pub = interfaceBody(output.typescript, "UserPublic");
    expect(propertyNames(pub)).toEqual(["id", "email"]);
    expect(pub).not.toMatch(/password/i);
    expect(pub).not.toContain("PasswordHash");
  });

  it("is excluded whatever the field is called and however many there are", () => {
    const { output } = compileOk(
      "model Account {\n  login: Text\n  secret: Password\n  recoveryPin: Password optional\n  token: Password min 20\n}",
    );
    const pub = interfaceBody(output.typescript, "AccountPublic");
    expect(propertyNames(pub)).toEqual(["id", "login"]);
    expect(pub).not.toContain("PasswordHash");
  });

  it("holds for 500 randomly generated schemas", () => {
    for (let seed = 1; seed <= 500; seed++) {
      const { source, passwordFields } = randomSchema(seed);
      const result = compile(source, "random.rz");
      if (!result.ok) throw new Error(`seed ${seed} failed to compile:\n${source}`);
      for (const [model, secrets] of passwordFields) {
        const pub = interfaceBody(result.output.typescript, `${model}Public`);
        const props = propertyNames(pub);
        for (const s of secrets) {
          expect(props, `seed ${seed}: ${model}Public must not contain ${s}`).not.toContain(s);
        }
        expect(pub).not.toContain("PasswordHash");
        // Every non-secret field is still present.
        const stored = propertyNames(interfaceBody(result.output.typescript, model));
        expect(props).toEqual(stored.filter((p) => !secrets.includes(p)));
      }
    }
  });

  it("is never stored as plain text: the column is always <name>_hash", () => {
    const { output } = compileOk("model User {\n  password: Password\n}");
    expect(output.sql).toContain('"password_hash" TEXT NOT NULL');
    expect(output.sql).not.toMatch(/"password" /);
  });

  it.each(["password: Text", "pwd: Text", "adminPassword: Text optional", "passphrase: Number"])(
    "rejects a password-like field with the wrong type: %s",
    (line) => {
      const d = firstError(`model User {\n  ${line}\n}`);
      expect(d.code).toBe("RZ0315");
      expect(d.fix).toContain(": Password`");
    },
  );

  it("does not flag fields that merely mention passwords", () => {
    compileOk("model User {\n  passwordHint: Text\n  passwordChangedAt: Date optional\n}");
  });

  it("only Password is marked secret in the type table", () => {
    const secret = FIELD_TYPE_NAMES.filter((t) => FIELD_TYPES[t].secret);
    expect(secret).toEqual(["Password"]);
  });
});

describe("security: invalid syntax gives a clear error with line and column", () => {
  it.each([
    ["missing colon", "model User {\n  email Email\n}", "RZ0205", 2, 9],
    ["comma", "model User {\n  email: Email,\n}", "RZ0212", 2, 15],
    ["snake_case name", "model User {\n  first_name: Text\n}", "RZ0101", 2, 8],
    ["unknown modifier", "model User {\n  email: Email uniq\n}", "RZ0207", 2, 16],
    ["missing brace", "model User\n  email: Email\n}", "RZ0203", 2, 3],
    ["two fields on one line", "model User {\n  a: Text b: Text\n}", "RZ0207", 2, 11],
    ["unclosed model", "model User {\n  email: Email\n", "RZ0210", 1, 12],
    ["tab indentation", "model User {\n\temail Email\n}", "RZ0205", 2, 8],
  ])("%s", (_label, source, code, line, col) => {
    const d = firstError(source);
    expect(d.code).toBe(code);
    expect(d.span.line).toBe(line);
    expect(d.span.col).toBe(col);
    expect(d.file).toBe("test.rz");
  });
});

describe("security: unknown field types are rejected", () => {
  it.each([
    ["String", "Text"],
    ["Int", "Number"],
    ["Boolean", "Bool"],
    ["DateTime", "Date"],
    ["UUID", "ID"],
    ["text", "Text"],
    ["Emial", "Email"],
    ["Passwrd", "Password"],
  ])("rejects %s and suggests %s", (bad, good) => {
    const d = firstError(`model User {\n  field: ${bad}\n}`);
    expect(d.code).toBe("RZ0301");
    expect(d.span).toEqual({ line: 2, col: 10, length: bad.length });
    expect(d.message).toContain(`"${bad}"`);
    expect(d.fix).toContain(`"${good}"`);
  });

  it("lists the valid types when there is no close match", () => {
    const d = firstError("model User {\n  field: Banana\n}");
    expect(d.fix).toBe("Use one of: Text, Number, Bool, Email, Password, Date, ID, or a model name (User).");
  });

  it("produces no output at all when any type is unknown", () => {
    const r = compile("model User {\n  ok: Text\n  bad: Json\n}", "t.rz");
    expect(r.ok).toBe(false);
    expect("output" in r).toBe(false);
  });
});

describe("security: names cannot inject SQL", () => {
  it.each([
    'model User {\n  name"; DROP TABLE users; --: Text\n}',
    "model User {\n  name': Text\n}",
    "model Us-er {\n  name: Text\n}",
    "model User {\n  na me: Text\n}",
  ])("rejects %j", (source) => {
    expect(compile(source, "t.rz").ok).toBe(false);
  });

  it("every emitted identifier contains only safe characters", () => {
    const { output } = compileOk("model User {\n  firstName: Text\n  password: Password\n}");
    const quoted = [...output.sql.matchAll(/"([^"]*)"/g)].map((m) => m[1]);
    for (const id of quoted) expect(id).toMatch(/^[a-z0-9_]+$/);
  });

  it("sanitizes the source file name echoed into generated comments", () => {
    const r = compile("model A {\n  x: Text\n}", "evil\nDROP TABLE x;.rz");
    if (!r.ok) throw new Error("expected success");
    expect(r.output.sql).not.toContain("\nDROP");
    expect(r.output.typescript).not.toContain("\nDROP");
  });
});

describe("security: generated endpoints", () => {
  const source = `auth User by email
model User {
  email: Email unique private
  password: Password
  name: Text
}
model Post {
  author: User
  title: Text
  secretNote: Text private
  published: Bool
}
api GET /posts -> list Post.public {
  public
  return db.Post.list(published = true, order title)
}
api GET /posts/:id -> Post.public {
  requires login
  requires owner author
  return db.Post.find(id)
}
api POST /posts -> Post.public {
  requires login
  return db.Post.create(body, author = me)
}
api PATCH /posts/:id -> Post.public {
  requires login
  requires owner author
  return db.Post.update(id, body)
}
api DELETE /posts/:id {
  requires login
  requires owner author
  return db.Post.delete(id)
}
api GET /users/:id -> User.public {
  public
  return db.User.find(id)
}
`;
  const result = compileOk(source);
  const app = buildApp(result.apis, result.auth);
  const allSql = [...app.routes.map((r) => r.sql), app.auth?.signup.sql ?? "", app.auth?.meSql ?? ""];

  it("never puts literal values into SQL: every value is a $n parameter", () => {
    for (const r of app.routes) {
      expect(r.sql).not.toContain("'");
      const placeholders = new Set([...r.sql.matchAll(/\$(\d+)/g)].map((m) => Number(m[1])));
      expect(placeholders.size).toBe(r.values.length);
      expect(Math.max(0, ...placeholders)).toBe(r.values.length);
    }
    expect(app.routes[0]?.values).toEqual([
      { from: "const", value: true },
      { from: "cursorSet" },
      { from: "cursorValue" },
      { from: "cursorId" },
      { from: "pageLimit" },
    ]);
    expect(app.routes[0]?.sql).toBe(
      'SELECT "id", "author_id" AS "author", "title", "published", "title"::text AS "_cursor" FROM "posts" ' +
      'WHERE "published" = $1 AND ($2 IS NOT TRUE OR ("title", "id") > ($3::text, $4::uuid)) ORDER BY "title" ASC, "id" ASC LIMIT $5',
    );
  });

  it("never selects password or private columns for responses", () => {
    for (const sql of allSql) {
      const returned = sql.split(/RETURNING|FROM/)[sql.startsWith("SELECT") ? 0 : 1] ?? "";
      expect(returned).not.toContain("password_hash");
      expect(returned).not.toContain('"email"');
      expect(returned).not.toContain("secret_note");
    }
    for (const r of app.routes) {
      expect(r.publicKeys).not.toContain("password");
      expect(r.publicKeys).not.toContain("email");
      expect(r.publicKeys).not.toContain("secretNote");
    }
  });

  it("turns requires owner into a WHERE condition on the logged-in user", () => {
    for (const r of app.routes.filter((x) => x.pattern === "/posts/:id")) {
      expect(r.sql).toMatch(/WHERE "id" = \$\d+ AND "author_id" = \$\d+/);
      expect(r.values).toContainEqual({ from: "me" });
      expect(r.access).toBe("login");
    }
  });

  it("never accepts the owner link from the request body", () => {
    for (const r of app.routes) expect((r.body ?? []).map((f) => f.key)).not.toContain("author");
    const create = app.routes.find((r) => r.method === "POST");
    expect(create?.values).toContainEqual({ from: "me" });
    expect(interfaceBody(result.output.typescript, "PostInput")).not.toContain("author");
  });

  it("logs in with a parameterized lookup and never selects the hash for responses", () => {
    expect(app.auth?.loginSql).toBe('SELECT "id", "password_hash" AS "hash" FROM "users" WHERE "email" = $1');
    expect(app.auth?.publicKeys).toEqual(["id", "name"]);
  });

  it("checks owner-or-role inside the query, with the role as a parameter", () => {
    const r = compileOk(source.replace("auth User by email", "auth User by email roles admin").replace(
      "api DELETE /posts/:id {\n  requires login\n  requires owner author\n",
      "api DELETE /posts/:id {\n  requires login\n  requires owner author or role admin\n",
    ));
    const del = buildApp(r.apis, r.auth).routes.find((x) => x.method === "DELETE");
    expect(del?.sql).toBe('DELETE FROM "posts" WHERE "id" = $1 AND ("author_id" = $2 OR $3)');
    expect(del?.values).toEqual([{ from: "path", name: "id" }, { from: "me" }, { from: "hasRole", roles: ["admin"] }]);
    const auth = buildApp(r.apis, r.auth).auth;
    expect(auth?.signup.body.map((f) => f.key)).not.toContain("role");
    expect(auth?.publicKeys).not.toContain("role");
  });

  it("never lets a profile update change the login email, password, role or owner links", () => {
    const profile = app.auth?.account.profile;
    expect(profile?.body.map((f) => f.key)).toEqual(["name"]);
    expect(profile?.sql).toBe('UPDATE "users" SET "name" = CASE WHEN $2 THEN $3 ELSE "name" END WHERE "id" = $1 RETURNING "id", "name"');
    expect(profile?.values[0]).toEqual({ from: "me" });
    expect(app.auth?.account.password).toMatchObject({ key: "newPassword", kind: "Password", min: 8, max: 128 });
  });

  it("keeps private fields out of public types", () => {
    expect(propertyNames(interfaceBody(result.output.typescript, "UserPublic"))).toEqual(["id", "name"]);
    expect(propertyNames(interfaceBody(result.output.typescript, "PostPublic"))).not.toContain("secretNote");
  });
});

describe("security: passkeys", () => {
  const SITE = { rpId: "blog.example", origin: "https://blog.example" };
  const fresh = () => Buffer.from(randomBytes(32)).toString("base64url");

  it("never puts a private login field into the passkey prompt", () => {
    const r = compileOk("auth User by email\nmodel User {\n  email: Email unique private\n  password: Password\n}\n");
    expect(buildApp(r.apis, r.auth).auth?.nameSql).toBe("");
    const visible = compileOk("auth User by email\nmodel User {\n  email: Email unique\n  password: Password\n}\n");
    expect(buildApp(visible.apis, visible.auth).auth?.nameSql).toBe('SELECT "email" AS "name" FROM "users" WHERE "id" = $1');
  });

  it("works only on the site that created it, for its own challenge, with the user verified", () => {
    const authenticator = new SoftAuthenticator();
    const challenge = fresh();
    const reg = verifyRegistration(authenticator.register({ challenge, ...SITE, userId: "u" }).response, { challenge, ...SITE });
    const stored = { publicKey: reg.publicKey, algorithm: reg.algorithm, signCount: reg.signCount };
    const c = fresh();
    for (const extra of [{ origin: "https://evil.example" }, { rpId: "evil.example" }, { noUserVerification: true }]) {
      expect(() => verifyAssertion(authenticator.login({ challenge: c, ...SITE }, extra).response, stored, { challenge: c, ...SITE })).toThrow(PasskeyError);
    }
    expect(() => verifyAssertion(authenticator.login({ challenge: fresh(), ...SITE }).response, stored, { challenge: c, ...SITE })).toThrow(PasskeyError);
    expect(verifyAssertion(authenticator.login({ challenge: c, ...SITE }).response, stored, { challenge: c, ...SITE })).toBeGreaterThan(0);
  });

  it("stores only a public key and refuses a copied passkey", () => {
    const authenticator = new SoftAuthenticator();
    const challenge = fresh();
    const reg = verifyRegistration(authenticator.register({ challenge, ...SITE, userId: "u" }).response, { challenge, ...SITE });
    expect(createPublicKey({ key: Buffer.from(reg.publicKey, "base64url"), format: "der", type: "spki" }).type).toBe("public");
    const c = fresh();
    const login = authenticator.login({ challenge: c, ...SITE }).response;
    expect(() => verifyAssertion(login, { ...reg, signCount: 10 }, { challenge: c, ...SITE })).toThrow("copied");
  });

  it("stores challenges only as hashes, and uses each one once", () => {
    const { challenge, hash } = newChallenge();
    expect(hash).not.toContain(challenge);
    expect(hash).toBe(challengeHash(challenge));
    expect(PASSKEY_SQL.useChallenge).toMatch(/^DELETE .* RETURNING "id"$/);
  });
});

describe("security: email confirmation and reset", () => {
  const r = compileOk("auth User by email\nmodel User {\n  email: Email unique\n  password: Password\n  name: Text\n}\n");
  const auth = buildApp(r.apis, r.auth).auth;

  it("creates the account and its unconfirmed mark in one statement, with parameters only", () => {
    expect(auth?.signup.sql).toBe(
      'WITH "created" AS (INSERT INTO "users" ("email", "password_hash", "name") VALUES ($1, $2, $3) RETURNING "id", "email", "name"), ' +
        '"pending" AS (INSERT INTO "_rizo_unverified" ("user_id") SELECT "id" FROM "created") SELECT "id", "email", "name" FROM "created"',
    );
  });

  it("handles camelCase fields on the account model (regression: the compiler crashed on them)", () => {
    const r = compileOk("auth User by email\nmodel User {\n  email: Email unique\n  password: Password\n  displayName: Text\n  birthDate: Date optional private\n}\n");
    expect(buildApp(r.apis, r.auth).auth?.signup.sql).toBe(
      'WITH "created" AS (INSERT INTO "users" ("email", "password_hash", "display_name", "birth_date") VALUES ($1, $2, $3, $4) RETURNING "id", "email", "display_name" AS "displayName"), ' +
        '"pending" AS (INSERT INTO "_rizo_unverified" ("user_id") SELECT "id" FROM "created") SELECT "id", "email", "displayName" FROM "created"',
    );
  });

  it("uses each emailed link once, only for its purpose, and only before it expires", () => {
    expect(EMAIL_SQL.useToken).toBe('DELETE FROM "_rizo_email_tokens" WHERE "id" = $1 AND "purpose" = $2 AND "expires_at" > now() RETURNING "user_id"');
  });

  it("never puts request data into an email: only fixed sentences and the link", () => {
    const token = newEmailToken().token;
    for (const m of [MESSAGES.verify("https://a.example", token), MESSAGES.reset("https://a.example", token), MESSAGES.alreadyRegistered("https://a.example")]) {
      const withoutLink = m.text.replace(/https:\/\/a\.example\/[a-z-]+(#token=[A-Za-z0-9_-]{43})?/g, "");
      expect(withoutLink).not.toMatch(/[<>]/);
      expect(m.subject).toMatch(/^[A-Za-z ]+ a\.example$/);
    }
  });
});

describe("security: encrypted fields", () => {
  const source = `model Note {
  title: Text
  secret: Text encrypted
}
api POST /api/notes -> Note.public {
  public
  return db.Note.create(body)
}
api PATCH /api/notes/:id -> Note.public {
  public
  return db.Note.update(id, body)
}
`;
  const app = buildApp(compileOk(source).apis, undefined);

  it("marks every endpoint that writes or returns the field, so the runtime encrypts and decrypts it", () => {
    for (const route of app.routes) expect(route.encrypted).toEqual([{ key: "secret", aad: "notes.secret" }]);
  });

  it("only ever passes the value to SQL as a parameter, in a column without database checks", () => {
    for (const route of app.routes) expect(route.sql).not.toMatch(/secret"\s*(=|LIKE|<|>)\s*'/);
    const r = compileOk(source);
    expect(r.output.sql).not.toMatch(/"secret"[^\n]*CHECK/);
  });

  it("ties each value to its column, so it can't be moved to another one", () => {
    const keys = parseKeys(`k1:${Buffer.alloc(32, 7).toString("base64")}`);
    const value = encryptValue(keys, "notes.secret", "hidden");
    expect(value).not.toContain("hidden");
    expect(decryptValue(keys, "notes.secret", value)).toBe("hidden");
    expect(() => decryptValue(keys, "users.phone", value)).toThrow(EncryptionError);
  });
});

describe("security: sessions", () => {
  it("only accepts sessions within both the idle and the maximum lifetime", () => {
    expect(SESSION_SQL.lookup).toContain('"expires_at" > now() AND "ends_at" > now()');
    expect(SESSION_SQL.touch).toContain('LEAST(now() + make_interval(secs => $2), "ends_at")');
    expect(IDLE_SECONDS).toBe(7 * 24 * 3600);
    expect(MAX_SECONDS).toBe(30 * 24 * 3600);
  });

  it("lists and logs out only your own devices, and never shows token hashes", () => {
    expect(SESSION_SQL.list).toMatch(/^SELECT "id", "device", "created_at" AS "createdAt", "last_seen_at" AS "lastSeenAt", "token_hash" = \$2 AS "current" FROM .* WHERE "user_id" = \$1 /);
    expect(SESSION_SQL.deleteById).toContain('WHERE "id" = $1 AND "user_id" = $2');
  });
});

describe("security: API tokens", () => {
  it("stores only hashes, looks up only unexpired tokens, and revokes only your own", () => {
    expect(TOKEN_SQL.create).toMatch(/^INSERT INTO "_rizo_tokens" \("token_hash", "user_id", "name", "endpoints", "expires_at"\) VALUES \(\$1, \$2, \$3, \$4, now\(\) \+ make_interval\(days => \$5\)\)/);
    expect(TOKEN_SQL.lookup).toContain('WHERE "token_hash" = $1 AND "expires_at" > now()');
    expect(TOKEN_SQL.list).not.toContain("token_hash");
    expect(TOKEN_SQL.remove).toContain('WHERE "id" = $1 AND "user_id" = $2');
    expect(MAX_TOKEN_DAYS).toBe(90);
  });
});
