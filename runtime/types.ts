/**
 * Rizo Lang runtime: shared types.
 *
 * The compiler generates `routes.ts` as plain data of type `App`. All SQL is
 * written by the compiler at build time; the runtime never builds SQL from
 * text. It only supplies values for $1, $2, ... parameters.
 */

export type FieldKind = "Text" | "Number" | "Bool" | "Email" | "Password" | "Date" | "ID";

/** How to validate one JSON body field. */
export interface FieldSpec {
  /** JSON key, e.g. "firstName". */
  readonly key: string;
  readonly kind: FieldKind;
  /** The key must be present. */
  readonly required: boolean;
  /** The value may be null. */
  readonly nullable: boolean;
  /** Length in characters (Text, Email, Password) or value (Number). */
  readonly min?: number;
  readonly max?: number;
}

/** Where the value for one SQL parameter comes from. */
export type ValueSource =
  | { readonly from: "path"; readonly name: string }
  | { readonly from: "me" }
  /** A validated body field. Password values are hashed before use. */
  | { readonly from: "body"; readonly key: string }
  /** true when the body contains `key` (used for partial updates). */
  | { readonly from: "provided"; readonly key: string }
  | { readonly from: "const"; readonly value: number | boolean };

export type PathPart =
  | { readonly static: string }
  | { readonly param: string; readonly kind: "ID" | "Number" | "Bool" | "Text" | "Email" };

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

export interface Route {
  readonly method: HttpMethod;
  /** Original path, used in logs (never the concrete URL, which may contain values). */
  readonly pattern: string;
  readonly path: readonly PathPart[];
  readonly access: "public" | "login";
  /** Accepted body fields, or null if the request must not have a body. */
  readonly body: readonly FieldSpec[] | null;
  readonly sql: string;
  readonly values: readonly ValueSource[];
  /** one: 200 with an object (404 if no row); list: 200 with an array; created: 201; none: 204 (404 if no row). */
  readonly result: "one" | "list" | "created" | "none";
  /** The only keys ever copied into a response. */
  readonly publicKeys: readonly string[];
  /** Model name, used in error messages such as "Post not found". */
  readonly model: string;
}

export interface AuthSpec {
  /** Name of the auth model, e.g. "User". */
  readonly model: string;
  readonly signup: { readonly body: readonly FieldSpec[]; readonly sql: string; readonly values: readonly ValueSource[] };
  /** JSON keys of the login fields, e.g. "email" and "password". */
  readonly loginKey: string;
  readonly passwordKey: string;
  /** `SELECT id, <hash column> AS hash FROM <users> WHERE <login column> = $1` */
  readonly loginSql: string;
  /** `SELECT <public columns> FROM <users> WHERE id = $1` */
  readonly meSql: string;
  readonly publicKeys: readonly string[];
}

export interface App {
  readonly routes: readonly Route[];
  readonly auth: AuthSpec | null;
}
