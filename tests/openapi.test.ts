import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { compileOk } from "./helpers.js";

interface Doc {
  openapi: string;
  info: { title: string; description: string };
  paths: Record<string, Record<string, Op>>;
  components: { schemas: Record<string, Schema>; securitySchemes: Record<string, unknown> };
}
interface Op {
  operationId: string;
  parameters?: { name: string; in: string; required: boolean; schema: Schema }[];
  requestBody?: { content: { "application/json": { schema: Schema } } };
  responses: Record<string, { content?: { "application/json": { schema: Schema } } }>;
  security: Record<string, string[]>[];
  "x-rizo-access": string;
  "x-rizo-roles"?: string[];
  "x-rizo-owner"?: { field: string; orRoles?: string[] };
  "x-rizo-rate-limit": { requests: number; perSeconds: number };
}
interface Schema {
  type?: string | string[];
  $ref?: string;
  required?: string[];
  properties?: Record<string, Schema>;
  items?: Schema;
  additionalProperties?: boolean;
  [key: string]: unknown;
}

const blog = (): Doc => {
  const r = compileOk(readFileSync(new URL("../examples/blog.rz", import.meta.url), "utf8"));
  return JSON.parse(r.output.server?.openapi ?? "{}") as Doc;
};
const ops = (d: Doc): [string, string, Op][] =>
  Object.entries(d.paths).flatMap(([path, methods]) => Object.entries(methods).map(([m, op]): [string, string, Op] => [path, m, op]));

describe("openapi.json", () => {
  const doc = blog();

  it("is OpenAPI 3.1 with every endpoint", () => {
    expect(doc.openapi).toBe("3.1.0");
    expect(doc.info.title).toBe("test");
    expect((doc as unknown as { servers: { url: string }[] }).servers).toEqual([{ url: "/", description: "The server that serves this document." }]);
    expect(ops(doc).map(([p, m]) => `${m.toUpperCase()} ${p}`)).toEqual(expect.arrayContaining([
      "GET /api/posts", "GET /api/posts/{id}", "POST /api/posts", "PATCH /api/posts/{id}", "DELETE /api/posts/{id}",
    ]));
  });

  it("is well-formed: unique operation ids, declared path parameters, and references that resolve", () => {
    const ids = ops(doc).map(([, , op]) => op.operationId);
    expect(new Set(ids).size).toBe(ids.length);
    for (const [path, , op] of ops(doc)) {
      const inPath = [...path.matchAll(/\{([^}]+)\}/g)].map((m) => m[1]);
      expect(op.parameters?.filter((p) => p.in === "path").map((p) => p.name) ?? []).toEqual(inPath);
      for (const p of op.parameters ?? []) if (p.in === "path") expect(p.required).toBe(true);
      for (const s of op.security) for (const name of Object.keys(s)) expect(doc.components.securitySchemes).toHaveProperty(name);
    }
    const refs = [...JSON.stringify(doc).matchAll(/"\$ref":"#\/components\/schemas\/([^"]+)"/g)].map((m) => m[1] ?? "");
    expect(refs.length).toBeGreaterThan(10);
    for (const name of refs) expect(doc.components.schemas).toHaveProperty(name);
  });

  it("never describes Password or private fields in responses", () => {
    const user = doc.components.schemas["UserPublic"];
    expect(Object.keys(user?.properties ?? {}).sort()).toEqual(["avatar", "bio", "id", "name"]);
    expect(user?.additionalProperties).toBe(false);
    const names = Object.values(doc.components.schemas).flatMap((schema) => Object.keys(schema.properties ?? {}));
    expect(names.filter((n) => /password|email/i.test(n))).toEqual([]);
  });

  it("describes request bodies exactly as the server validates them", () => {
    const create = doc.paths["/api/posts"]?.["post"]?.requestBody?.content["application/json"].schema;
    expect(create?.additionalProperties).toBe(false);
    expect(create?.required).toEqual(["title", "body", "published"]);
    expect(create?.properties?.["title"]).toEqual({ type: "string", minLength: 1, maxLength: 200 });
    expect(create?.properties).not.toHaveProperty("author");
    const update = doc.paths["/api/posts/{id}"]?.["patch"]?.requestBody?.content["application/json"].schema;
    expect(update?.required).toBeUndefined();
  });

  it("states who may call each endpoint, how, and how often", () => {
    const list = doc.paths["/api/posts"]?.["get"];
    expect(list?.["x-rizo-access"]).toBe("public");
    expect(list?.security).toEqual([]);
    expect(list?.parameters?.map((p) => p.name)).toEqual(["limit", "after"]);
    const del = doc.paths["/api/posts/{id}"]?.["delete"];
    expect(del?.["x-rizo-access"]).toBe("login");
    expect(del?.security).toEqual([{ session: [] }, { token: [] }]);
    expect(del?.["x-rizo-owner"]).toEqual({ field: "author", orRoles: ["admin"] });
    expect(del?.responses).toHaveProperty("204");
    expect(doc.paths["/api/admin/posts"]?.["get"]?.["x-rizo-roles"]).toEqual(["admin", "editor"]);
    for (const [, , op] of ops(doc)) {
      expect(op["x-rizo-rate-limit"].requests).toBeGreaterThan(0);
      expect(op.responses).toHaveProperty("429");
    }
  });

  it("marks optional fields as nullable and links as ids", () => {
    const post = doc.components.schemas["PostPublic"]?.properties;
    expect(post?.["views"]?.type).toEqual(["integer", "null"]);
    expect(post?.["author"]).toMatchObject({ type: "string", format: "uuid", description: "The id of a User." });
    expect(post?.["publishedAt"] ?? post?.["createdAt"] ?? { format: "date-time" }).toMatchObject({ format: "date-time" });
  });

  it("is generated for every app with a server, and is the same on every build", () => {
    const src = "model Note {\n  title: Text\n}\napi GET /api/notes -> list Note.public {\n  public\n  return db.Note.list()\n}\n";
    expect(compileOk(src).output.server?.openapi).toBe(compileOk(src).output.server?.openapi);
    expect(JSON.parse(compileOk(src).output.server?.openapi ?? "{}").paths).toHaveProperty("/api/notes");
  });
});
