/**
 * Security tests. These prove the guarantees in docs/SPEC.md:
 *   1. A Password field never appears in a public type.
 *   2. Invalid syntax produces a clear error with the exact line and column.
 *   3. Unknown field types are rejected and no output is produced.
 *   4. Names cannot inject SQL.
 *   5. Passkeys work only on their own site and are never copied (SPEC §7.11).
 *   8. People can export their data, and deleting an account keeps no personal data (SPEC §7.15).
 *   7. Encrypted fields reach the database only as ciphertext bound to their column (SPEC §7.13).
 *   6. Signup never reveals which emails have accounts, and emailed links are one-time and hashed (SPEC §7.12).
 *   9. Uploaded files are recognised by content, attached only by their uploader and kept only while used (SPEC §7.16).
 */
import { createPublicKey, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { PASSKEY_SQL, challengeHash, newChallenge } from "../runtime/passkeys.ts";
import { EMAIL_SQL, MESSAGES, newEmailToken } from "../runtime/email.ts";
import { PAGE_CSP } from "../runtime/pages.ts";
import { createRequestHandler, poolConfig } from "../runtime/server.ts";
import { EncryptionError, decryptValue, encryptValue, parseKeys } from "../runtime/encryption.ts";
import { IDLE_SECONDS, MAX_SECONDS, SQL as SESSION_SQL } from "../runtime/session.ts";
import { MAX_TOKEN_DAYS, TOKEN_SQL } from "../runtime/tokens.ts";
import { ghostValue } from "../runtime/privacy.ts";
import { FILE_SQL, detectFile, removeLocation } from "../runtime/files.ts";
import { validateValue } from "../runtime/validate.ts";
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
      // File fields need an auth line, which these random files don't have.
      const type = rand() < 0.35 ? "Password" : pick(FIELD_TYPE_NAMES.filter((t) => t !== "File"));
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
    expect(d.fix).toBe("Use one of: Text, Number, Bool, Email, Password, Date, ID, File, or a model name (User).");
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

describe("security: built-in admin pages", () => {
  const source = `auth User by email roles admin
model User {
  email: Email unique private
  password: Password
  name: Text
  phone: Text optional encrypted
}
model Post {
  author: User
  title: Text
  secretNote: Text private
}`;
  const r = compileOk(source);
  const app = buildApp(r.apis, r.auth, r.pages, r.models);

  it("never selects or returns password or private fields (SPEC §7.1), and searches neither them nor encrypted ones", () => {
    expect(app.admin).toHaveLength(2);
    for (const m of app.admin ?? []) {
      const selected = m.listSql.split(" FROM ")[0] ?? "";
      expect(selected).not.toMatch(/password_hash|"email"|secret_note/);
      expect(m.publicKeys).not.toContain("password");
      expect(m.publicKeys).not.toContain("email");
      expect(m.publicKeys).not.toContain("secretNote");
      expect(m.listSql).not.toMatch(/lower\("(email|secret_note|phone|password_hash)"\)/);
      // Values are only parameters: the search text, the cursor and the page size.
      expect(m.listSql.match(/\$\d/g)?.every((p) => ["$1", "$2", "$3"].includes(p))).toBe(true);
      // Accounts: the statement itself refuses admins, so a role change can't race the check.
      if (m.account) expect(m.deleteSql).toMatch(/DELETE FROM "users" WHERE "id" = \$1 AND "role" IS DISTINCT FROM 'admin'$/);
      else expect(m.deleteSql).toMatch(/^DELETE FROM "[a-z_]+" WHERE "id" = \$1$/);
    }
  });

  it("are admins only, and are served under /auth, which API tokens can never use (SPEC §7.14)", () => {
    const withPages = compileOk(`${source}\napi GET /api/posts -> list Post.public {\n  public\n  return db.Post.list()\n}\npage / {\n  public\n  show GET /api/posts\n}`);
    const pages = buildApp(withPages.apis, withPages.auth, withPages.pages, withPages.models).pages.filter((p) => p.pattern.startsWith("/admin"));
    expect(pages.length).toBe(3);
    for (const p of pages) expect(p).toMatchObject({ access: "login", roles: ["admin"] });
  });
});

describe("security: uploaded files (SPEC §7.16)", () => {
  const source = `auth User by email
model User {
  email: Email unique
  password: Password
}
model Post {
  author: User
  photo: File image max 2mb
  notes: File pdf optional private
}
api POST /api/posts -> Post.public {
  requires login
  return db.Post.create(body, author = me)
}
api GET /api/posts -> list Post.public {
  public
  return db.Post.list()
}`;
  const r = compileOk(source);
  const app = buildApp(r.apis, r.auth, r.pages, r.models);

  it("removes the location (GPS) from photos before they are stored", () => {
    // A big-endian EXIF block with only a GPS directory holding a latitude of 1234/100.
    const t = Buffer.alloc(80);
    t.write("MM", 0, "latin1"); t.writeUInt16BE(42, 2); t.writeUInt32BE(8, 4);
    t.writeUInt16BE(1, 8); t.writeUInt16BE(0x8825, 10); t.writeUInt16BE(4, 12); t.writeUInt32BE(1, 14); t.writeUInt32BE(26, 18);
    t.writeUInt16BE(1, 26); t.writeUInt16BE(2, 28); t.writeUInt16BE(5, 30); t.writeUInt32BE(1, 32); t.writeUInt32BE(44, 36);
    t.writeUInt32BE(1234, 44); t.writeUInt32BE(100, 48);
    const exif = Buffer.concat([Buffer.from("Exif\0\0", "latin1"), t]);
    const jpeg = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe1, 0, exif.length + 2]), exif, Buffer.from([0xff, 0xd9])]);
    const lat = Buffer.from([0, 0, 0x04, 0xd2]);
    expect(jpeg.includes(lat)).toBe(true);
    expect(removeLocation(jpeg, "jpg").includes(lat)).toBe(false);
  });

  it("recognises files by content only, so scripts (SVG, HTML) can never be stored", () => {
    for (const text of ["<svg onload=alert(1)>", "<!doctype html>", "<script>", "GIF8", "%PDF"]) expect(detectFile(Buffer.from(text, "latin1"))).toBeUndefined();
  });

  it("takes files only from logged-in users, never in a public endpoint's body", () => {
    expect(firstError(source.replace("requires login\n  return db.Post.create(body, author = me)", "public\n  return db.Post.create(body)").replace("  author: User\n", "")).code).toBe("RZ0346");
    expect(app.files?.uploads.map((u) => u.endpoints)).toEqual([["POST /api/posts"], ["POST /api/posts"]]);
  });

  it("never returns a private File field, and checks every attached file against its uploader", () => {
    const list = app.routes.find((x) => x.method === "GET");
    expect(list?.publicKeys).not.toContain("notes");
    expect(list?.sql).not.toContain('"notes"');
    expect(app.routes.find((x) => x.method === "POST")?.files?.map((f) => f.key)).toEqual(["photo", "notes"]);
  });

  it("keeps a file only while a record uses it, and builds every file query from parameters", () => {
    expect(r.output.sql).toContain('REFERENCES "_rizo_files" ("id") ON DELETE RESTRICT');
    expect(app.files?.sweepSql).toMatch(/^DELETE FROM "_rizo_files" WHERE "id" IN \(SELECT .* "f"."created_at" < now\(\) - interval '1 day'.* LIMIT 100\) RETURNING "id", "type"$/);
    for (const sql of Object.values(FILE_SQL)) expect(sql).not.toMatch(/'[^']*'/);
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

describe("security: data export and account deletion", () => {
  const source = `auth User by email
model User {
  email: Email unique private
  password: Password
  handle: Text unique min 3 max 12
  displayName: Text max 5
  phone: Text optional private encrypted
  age: Number min 13 max 120
}
model Post {
  author: User
  editor: User optional
  title: Text
}
model Like {
  user: User
  post: Post
}
`;
  const r = compileOk(source);
  const auth = buildApp(r.apis, r.auth, [], r.models).auth;

  it("exports the account's own data, private and encrypted fields included, but never the password hash", () => {
    expect(auth?.export.account.sql).toBe('SELECT "id", "email", "handle", "display_name" AS "displayName", "phone", "age" FROM "users" WHERE "id" = $1');
    expect(auth?.export.account.encrypted).toEqual([{ key: "phone", aad: "users.phone" }]);
    expect(auth?.export.records.map((x) => [x.model, x.sql])).toEqual([
      ["Post", 'SELECT "id", "author_id" AS "author", "editor_id" AS "editor", "title" FROM "posts" WHERE "author_id" = $1 OR "editor_id" = $1 ORDER BY "id" LIMIT 10001'],
      ["Like", 'SELECT "id", "user_id" AS "user", "post_id" AS "post" FROM "likes" WHERE "user_id" = $1 ORDER BY "id" LIMIT 10001'],
    ]);
  });

  it("moves records that need an owner to \"Deleted user\" in the same statement as the delete", () => {
    expect(auth?.account.deleteSql).toBe(
      'WITH "moved1" AS (UPDATE "posts" SET "author_id" = $2 WHERE "author_id" = $1), "moved2" AS (UPDATE "likes" SET "user_id" = $2 WHERE "user_id" = $1) DELETE FROM "users" WHERE "id" = $1',
    );
  });

  it("fills the \"Deleted user\" account only with valid placeholders, never personal data, and no password", () => {
    const ghost = auth?.account.ghost;
    expect(ghost?.sql).toBe('INSERT INTO "users" ("email", "password_hash", "handle", "display_name", "age") VALUES ($1, $2, $3, $4, $5) RETURNING "id"');
    const limits: Record<string, { kind: "Text" | "Email" | "Number"; min?: number; max?: number }> = {
      email: { kind: "Email", max: 254 }, handle: { kind: "Text", min: 3, max: 12 }, displayName: { kind: "Text", max: 5 }, age: { kind: "Number", min: 13, max: 120 },
    };
    for (let i = 0; i < 50; i++) {
      for (const f of ghost?.fields ?? []) {
        const value = ghostValue(f.value);
        if (f.key === "password") {
          expect(value).toBe("!");
          continue;
        }
        const spec = limits[f.key];
        if (spec === undefined) throw new Error(f.key);
        expect(validateValue({ key: f.key, ...spec }, value), `${f.key}=${String(value)}`).toEqual({ value });
      }
    }
    expect(String(ghostValue({ kind: "email", max: 254 }))).toMatch(/@deleted\.invalid$/);
  });

  it("falls back to refusing deletion when no placeholder account can be made", () => {
    const team = compileOk("auth User by email\nmodel Team {\n  name: Text\n}\nmodel User {\n  email: Email unique\n  password: Password\n  team: Team\n}\nmodel Post {\n  author: User\n}\n");
    const a = buildApp(team.apis, team.auth, [], team.models).auth;
    expect(a?.account.ghost).toBeNull();
    expect(a?.account.deleteSql).toBe('DELETE FROM "users" WHERE "id" = $1');
  });
});

describe("security: list filters from query parameters", () => {
  it("never puts a searched value into SQL, and searches without LIKE wildcards", () => {
    const r = compileOk("model Note {\n  title: Text\n  n: Number\n}\napi GET /api/notes -> list Note.public {\n  public\n  return db.Note.list(title contains ?q, n >= ?min)\n}\n");
    const route = buildApp(r.apis, r.auth).routes[0];
    expect(route?.sql).toContain('strpos(lower("title"), lower($1::text)) > 0');
    expect(route?.sql).not.toMatch(/LIKE|'%/i);
    expect(route?.values.slice(0, 2)).toEqual([{ from: "query", name: "q" }, { from: "query", name: "min" }]);
  });
});

describe("security: linked records (with)", () => {
  it("never selects a linked record's private or Password fields, and copies only its public keys", () => {
    const r = compileOk("auth User by email\nmodel User {\n  email: Email unique private\n  password: Password\n  name: Text\n}\nmodel Post {\n  author: User\n  title: Text\n}\napi GET /api/posts -> list Post.public with author {\n  public\n  return db.Post.list()\n}\n");
    const route = buildApp(r.apis, r.auth).routes[0];
    expect(route?.sql).not.toMatch(/"email"|password/);
    expect(route?.expanded).toEqual([{ key: "author", publicKeys: ["id", "name"] }]);
  });
});

describe("security: guarantees 7 to 10", () => {
  it("7: rejects cross-site writes before anything runs", async () => {
    const r = compileOk("model Note {\n  title: Text\n}\napi POST /api/notes -> Note.public {\n  public\n  return db.Note.create(body)\n}\n");
    const queries: string[] = [];
    const handler = createRequestHandler(buildApp(r.apis, r.auth), { db: { query: async (sql: string) => (queries.push(sql), { rows: [], rowCount: 0 }) }, log: () => undefined });
    const server = (await import("node:http")).createServer((req, res) => void handler(req, res));
    await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
    const port = (server.address() as { port: number }).port;
    for (const headers of [{ Origin: "https://evil.example" }, { "Sec-Fetch-Site": "cross-site" }]) {
      const res = await fetch(`http://127.0.0.1:${port}/api/notes`, { method: "POST", headers: { ...headers, "Content-Type": "application/json" }, body: JSON.stringify({ title: "x" }) });
      expect(res.status).toBe(403);
    }
    await new Promise((done) => server.close(done));
    expect(queries.filter((q) => q.startsWith("INSERT INTO \"notes\""))).toEqual([]);
  });

  it("8: cancels any query after the statement timeout (5 seconds by default)", () => {
    expect(poolConfig({ DATABASE_URL: "postgres://x" }).statement_timeout).toBe(5000);
    expect(() => poolConfig({ RIZO_DB_STATEMENT_TIMEOUT_MS: "0" })).toThrow();
  });

  it("9: writes no output when a file has an error", () => {
    const result = compile("model User {\n  name: String\n}\n", "bad.rz");
    expect(result.ok).toBe(false);
    expect(result).not.toHaveProperty("output");
  });

  it("10: serves pages with a CSP that allows only the site's own script, styles and images", () => {
    expect(PAGE_CSP).toBe("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
  });

  it("cancels pending emailed links when the email or password changes", () => {
    expect(EMAIL_SQL.deleteAllTokens).toBe('DELETE FROM "_rizo_email_tokens" WHERE "user_id" = $1');
  });
});
