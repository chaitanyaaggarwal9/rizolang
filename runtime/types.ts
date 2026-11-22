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

/** A field stored encrypted: its JSON key, and the "table.column" its ciphertext is bound to. */
export interface EncryptedField {
  readonly key: string;
  readonly aad: string;
}

/** An encrypted column, with the SQL `reencrypt.ts` uses to move values to the current key. */
export interface EncryptedColumn {
  readonly aad: string;
  /** `SELECT id, <column> AS value ... WHERE <column> NOT LIKE $1 AND id > $2 ORDER BY id LIMIT 500` */
  readonly select: string;
  /** `UPDATE ... SET <column> = $2 WHERE id = $1 AND <column> = $3` */
  readonly update: string;
}

/** Where the value for one SQL parameter comes from. */
export type ValueSource =
  | { readonly from: "path"; readonly name: string }
  | { readonly from: "me" }
  /** A validated body field. Password values are hashed before use. */
  | { readonly from: "body"; readonly key: string }
  /** true when the body contains `key` (used for partial updates). */
  | { readonly from: "provided"; readonly key: string }
  | { readonly from: "const"; readonly value: number | boolean }
  /** Pagination: true when the request has a cursor (`?after=`). */
  | { readonly from: "cursorSet" }
  /** Pagination: the sort column value from the cursor, as text. */
  | { readonly from: "cursorValue" }
  /** Pagination: the id from the cursor. */
  | { readonly from: "cursorId" }
  /** Pagination: the page size plus one (the extra row shows whether there is a next page). */
  | { readonly from: "pageLimit" }
  /** true when the logged-in user has one of these roles (`requires owner author or role admin`). */
  | { readonly from: "hasRole"; readonly roles: readonly string[] };

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
  /** The caller must have one of these roles; empty for no role check. */
  readonly roles: readonly string[];
  /** Accepted body fields, or null if the request must not have a body. */
  readonly body: readonly FieldSpec[] | null;
  readonly sql: string;
  readonly values: readonly ValueSource[];
  /** one: 200 with an object (404 if no row); list: 200 with an array; created: 201; none: 204 (404 if no row). */
  readonly result: "one" | "list" | "created" | "none";
  /** Requests allowed per window, per account (logged in) or IP address (logged out). */
  readonly rateLimit: { readonly max: number; readonly windowSeconds: number };
  /** For list endpoints: the largest page size, and the type of the sort column (null when sorted by id). */
  readonly page: { readonly max: number; readonly order: FieldKind | null } | null;
  /** The only keys ever copied into a response. */
  readonly publicKeys: readonly string[];
  /** Model name, used in error messages such as "Post not found". */
  readonly model: string;
  /** Fields encrypted before they are written and decrypted after they are read. Absent means none. */
  readonly encrypted?: readonly EncryptedField[];
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
  /** Declared roles; empty when the app does not use roles. */
  readonly roles: readonly string[];
  /** `SELECT "role" FROM <users> WHERE id = $1` (empty string without roles) */
  readonly roleSql: string;
  /** `UPDATE <users> SET "role" = $2 WHERE id = $1 RETURNING id, "role"` (empty string without roles) */
  readonly setRoleSql: string;
  /** Grants admin to existing accounts whose login email is in $1 (empty string without roles). */
  readonly grantAdminSql: string;
  /**
   * `SELECT <login column> AS name FROM <users> WHERE id = $1`, shown in the
   * device's passkey picker; empty when the login field is private.
   */
  readonly nameSql: string;
  /** What `GET /auth/me/export` reads. */
  readonly export: ExportSpec;
  /** Encrypted fields of the auth model. Absent means none. */
  readonly encrypted?: readonly EncryptedField[];
  /** Account management. */
  readonly account: {
    /** Limits for a new password (the Password field's min and max). */
    readonly password: FieldSpec;
    /** `SELECT <hash column> AS hash FROM <users> WHERE id = $1` */
    readonly hashSql: string;
    /** `UPDATE <users> SET <hash column> = $2 WHERE id = $1` */
    readonly setPasswordSql: string;
    /**
     * Deletes the account ($1). When `ghost` is set, it first gives the
     * account's records to the "Deleted user" account ($2), in the same statement.
     */
    readonly deleteSql: string;
    /** How to create the shared "Deleted user" account, or null when no records need one. */
    readonly ghost: GhostSpec | null;
    /** Updating your own profile, or null when there is nothing a user may change. */
    readonly profile: { readonly body: readonly FieldSpec[]; readonly sql: string; readonly values: readonly ValueSource[] } | null;
  };
}

/** A placeholder value for a field of the "Deleted user" account. Never personal data. */
export type GhostValue =
  | { readonly kind: "fixed"; readonly value: string | number | boolean }
  /** Text: "deleted-" plus random hex, cut to `max` (for unique fields). */
  | { readonly kind: "unique"; readonly max: number }
  /** An address under the reserved .invalid domain, which can never receive email. */
  | { readonly kind: "email"; readonly max: number }
  | { readonly kind: "uuid" }
  /** A random whole number in range (for unique fields). */
  | { readonly kind: "number"; readonly min: number; readonly max: number }
  /** A random date (for unique fields). */
  | { readonly kind: "date" }
  /** Not a password hash, so nobody can ever log in as this account. */
  | { readonly kind: "noPassword" };

export interface GhostSpec {
  /** `INSERT INTO <users> (...) VALUES ($1, ...) RETURNING "id"` */
  readonly sql: string;
  /** One entry per $n, in order. `key` is the JSON key (used to encrypt encrypted fields). */
  readonly fields: readonly { readonly key: string; readonly value: GhostValue }[];
  /** `DELETE FROM <users> WHERE id = $1`: removes a spare one made by a process that lost a race. */
  readonly removeSql: string;
}

/** Everything stored about one account, for `GET /auth/me/export`. */
export interface ExportSpec {
  /** Every stored field of the account except the password hash (private and encrypted fields included: it is the user's own data). */
  readonly account: { readonly sql: string; readonly encrypted?: readonly EncryptedField[] };
  /** Records of other models that link to the account ($1), at most 10,000 per model. */
  readonly records: readonly { readonly model: string; readonly sql: string; readonly encrypted?: readonly EncryptedField[] }[];
}

/** One field of a shown record, as the browser displays it. */
export interface FieldViewSpec {
  readonly key: string;
  readonly label: string;
  readonly type: FieldKind;
}

/** One input of a form: a body field plus how to show it. */
export interface FormFieldSpec extends FieldSpec {
  readonly label: string;
  /** Long text gets a multi-line box. */
  readonly multiline: boolean;
}

/** What a page shows, in order. Plain data: pages never contain markup or code. */
export type PageItemSpec =
  | { readonly kind: "text"; readonly text: string }
  /** `path` may contain :params of the page, filled in by the browser. */
  | { readonly kind: "link"; readonly label: string; readonly path: string }
  | {
      readonly kind: "show";
      /** Endpoint path pattern, e.g. "/api/posts/:id"; :params come from the page's own parameters. */
      readonly endpoint: string;
      readonly mode: "list" | "one";
      readonly model: string;
      readonly fields: readonly FieldViewSpec[];
      /** For lists: link each record to this page, filling `param` with the record's id. */
      readonly detail: { readonly path: string; readonly param: string } | null;
    }
  | {
      readonly kind: "form";
      readonly method: "POST" | "PUT" | "PATCH";
      /** Endpoint path pattern; :params come from the page. */
      readonly endpoint: string;
      readonly fields: readonly FormFieldSpec[];
      readonly submit: string;
      /** GET endpoint to prefill an edit form from, or null. */
      readonly prefill: string | null;
      /** Page to open afterwards (:id may come from the saved record), or null for "?next= or home". */
      readonly then: string | null;
      /** Built-in forms only: show this message after sending, instead of opening a page. */
      readonly done?: string;
    }
  | { readonly kind: "button"; readonly label: string; readonly method: "DELETE"; readonly endpoint: string; readonly then: string }
  /** "Log in with a passkey" (built-in login page). */
  | { readonly kind: "passkeyLogin" }
  /** List, add and remove your passkeys (built-in account page). */
  | { readonly kind: "passkeys" }
  /** The devices you are logged in on, each with "Log out" (built-in account page). */
  | { readonly kind: "sessions" }
  /** Create, list and revoke API tokens (built-in account page). */
  | { readonly kind: "tokens" }
  /** Download your data, and delete your account (built-in account page). */
  | { readonly kind: "yourData" }
  /** The privacy notice, read from GET /auth/privacy (built-in /privacy page). */
  | { readonly kind: "privacy" }
  /** Confirms the email when the page was opened from the emailed link (built-in /verify-email). */
  | { readonly kind: "verifyEmail" }
  /** Asks for a new password when the page was opened from the emailed link (built-in /reset-password). */
  | { readonly kind: "newPassword"; readonly field: FormFieldSpec };

export interface PageRoute {
  /** Original path, used in logs. */
  readonly pattern: string;
  readonly path: readonly PathPart[];
  readonly access: "public" | "login";
  readonly roles: readonly string[];
  readonly title: string;
  readonly items: readonly PageItemSpec[];
}

/** What the privacy notice (`GET /auth/privacy`, the /privacy page) says the app stores. */
export interface PrivacySpec {
  /** Region codes from `privacy for`, e.g. "EU" or "US-CA". */
  readonly regions: readonly string[];
  readonly models: readonly {
    readonly name: string;
    /** True for the auth model (people's accounts). */
    readonly account: boolean;
    readonly fields: readonly {
      readonly label: string;
      /** The field type, or "link to <Model>". */
      readonly kind: string;
      /** How the value is kept and shown. */
      readonly stored: "public" | "private" | "encrypted" | "hashed";
    }[];
    /** From `keep`, or null when records are kept until deleted. */
    readonly keep: { readonly amount: number; readonly unit: string } | null;
  }[];
}

/** A model whose records are deleted some time after they were created (`keep 2 years`). */
export interface RetentionSpec {
  readonly model: string;
  /** Deletes up to 1,000 expired records ($1 is the amount of time), skipping any that other records still need. */
  readonly sql: string;
  readonly amount: number;
}

export interface App {
  readonly routes: readonly Route[];
  readonly auth: AuthSpec | null;
  readonly pages: readonly PageRoute[];
  /** Models with `keep`. Absent means none. */
  readonly retention?: readonly RetentionSpec[];
  /** From `privacy for`: the regions, and what the app stores. Absent without that line. */
  readonly privacy?: PrivacySpec;
  /** Every encrypted column the app writes. Absent means none. */
  readonly encrypted?: readonly EncryptedColumn[];
}
