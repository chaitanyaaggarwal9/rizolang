import type { Span } from "./diagnostics.js";

/** Syntax tree produced by the parser. Names and types are not validated yet. */

export interface Program {
  readonly models: readonly ModelDecl[];
  readonly auths: readonly AuthDecl[];
  readonly apis: readonly ApiDecl[];
  readonly pages: readonly PageDecl[];
  readonly privacy: readonly PrivacyDecl[];
}

/** `privacy for EU, UK, IN, US-CA, BR` */
export interface PrivacyDecl {
  readonly span: Span;
  readonly regions: readonly { readonly name: string; readonly span: Span }[];
}

/** `keep 2 years` inside a model: records are deleted this long after they were created. */
export interface KeepDecl {
  readonly span: Span;
  readonly amount: number;
  readonly amountSpan: Span;
  readonly unit: string;
  readonly unitSpan: Span;
}

export interface ModelDecl {
  readonly name: string;
  readonly nameSpan: Span;
  readonly fields: readonly FieldDecl[];
  readonly keep: readonly KeepDecl[];
}

export interface FieldDecl {
  readonly name: string;
  readonly nameSpan: Span;
  /** A field type (Text, Email, ...) or the name of another model (a link). */
  readonly typeName: string;
  readonly typeSpan: Span;
  readonly modifiers: readonly Modifier[];
}

export type Modifier =
  | { readonly kind: "unique" | "optional" | "private" | "encrypted"; readonly span: Span }
  | { readonly kind: "min" | "max"; readonly value: number; readonly span: Span; readonly valueSpan: Span };

export type ModifierKind = Modifier["kind"];

export const MODIFIER_NAMES: readonly ModifierKind[] = ["unique", "optional", "private", "encrypted", "min", "max"];

/** A role name as written, e.g. `admin`. */
export interface RoleRef {
  readonly name: string;
  readonly span: Span;
}

/** `auth User by email` or `auth User by email roles admin, editor` */
export interface AuthDecl {
  readonly span: Span;
  readonly model: string;
  readonly modelSpan: Span;
  readonly field: string;
  readonly fieldSpan: Span;
  readonly roles: readonly RoleRef[];
}

export const HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"] as const;
export type HttpMethod = (typeof HTTP_METHODS)[number];

/** `api GET /posts/:id -> Post.public { ... }` */
export interface ApiDecl {
  readonly span: Span;
  readonly method: HttpMethod;
  readonly methodSpan: Span;
  readonly path: string;
  readonly pathSpan: Span;
  /** Undefined when the endpoint returns nothing (`api DELETE /posts/:id { ... }`). */
  readonly returns: ReturnType | undefined;
  readonly statements: readonly Statement[];
  /** Span of the closing brace, for errors about missing statements. */
  readonly endSpan: Span;
}

export interface ReturnType {
  readonly list: boolean;
  readonly model: string;
  readonly modelSpan: Span;
  /** The word after the dot; must be "public". */
  readonly view: string;
  readonly viewSpan: Span;
  readonly span: Span;
}

export type Statement =
  | { readonly kind: "public"; readonly span: Span }
  | { readonly kind: "requiresLogin"; readonly span: Span }
  /** `requires owner author` or `requires owner author or role admin` */
  | { readonly kind: "requiresOwner"; readonly span: Span; readonly field: string; readonly fieldSpan: Span; readonly orRoles: readonly RoleRef[] }
  /** `requires role admin` or `requires role admin, editor` (any of) */
  | { readonly kind: "requiresRole"; readonly span: Span; readonly roles: readonly RoleRef[] }
  /** `limit 20 per minute` */
  | { readonly kind: "limit"; readonly span: Span; readonly count: number; readonly countSpan: Span; readonly unit: string; readonly unitSpan: Span }
  | { readonly kind: "return"; readonly span: Span; readonly query: Query };

export const QUERY_ACTIONS = ["find", "list", "create", "update", "delete"] as const;
export type QueryAction = (typeof QUERY_ACTIONS)[number];

/** `db.Post.list(author = me, order title desc, limit 20)` */
export interface Query {
  readonly span: Span;
  readonly model: string;
  readonly modelSpan: Span;
  readonly action: string;
  readonly actionSpan: Span;
  readonly args: readonly QueryArg[];
}

export type QueryArg =
  /** A bare name: a path parameter (`id`) or `body`. */
  | { readonly kind: "name"; readonly name: string; readonly span: Span }
  /** `field = value`, or in a list `field > value`, `field contains ?q` and so on */
  | { readonly kind: "assign"; readonly field: string; readonly fieldSpan: Span; readonly op: CompareOp; readonly opSpan: Span; readonly value: Value; readonly span: Span }
  /** `order field` or `order field desc` */
  | { readonly kind: "order"; readonly field: string; readonly fieldSpan: Span; readonly descending: boolean; readonly span: Span }
  /** `limit 20` */
  | { readonly kind: "limit"; readonly value: number; readonly valueSpan: Span; readonly span: Span };

/** How a list filter compares a field with a value. */
export type CompareOp = "=" | "!=" | "<" | "<=" | ">" | ">=" | "contains";

export type Value =
  | { readonly kind: "name"; readonly name: string; readonly span: Span }
  /** `?q`: an optional query parameter of a list endpoint (`/api/posts?q=...`). */
  | { readonly kind: "query"; readonly name: string; readonly span: Span }
  | { readonly kind: "int"; readonly value: number; readonly span: Span }
  | { readonly kind: "bool"; readonly value: boolean; readonly span: Span };

/** Quoted text as written in a page, e.g. `"Latest posts"`. */
export interface TextRef {
  readonly text: string;
  readonly span: Span;
}

/** `page /posts { ... }` */
export interface PageDecl {
  readonly span: Span;
  readonly path: string;
  readonly pathSpan: Span;
  readonly statements: readonly PageStatement[];
  readonly endSpan: Span;
}

export type PageStatement =
  | { readonly kind: "public"; readonly span: Span }
  | { readonly kind: "requiresLogin"; readonly span: Span }
  | { readonly kind: "requiresRole"; readonly span: Span; readonly roles: readonly RoleRef[] }
  /** `title "Latest posts"` */
  | { readonly kind: "title"; readonly span: Span; readonly text: TextRef }
  /** `text "Welcome!"` */
  | { readonly kind: "text"; readonly span: Span; readonly text: TextRef }
  /** `link "Write a post" /posts/new` */
  | { readonly kind: "link"; readonly span: Span; readonly label: TextRef; readonly path: string; readonly pathSpan: Span }
  /** `show GET /api/posts` */
  | { readonly kind: "show"; readonly span: Span; readonly method: string; readonly methodSpan: Span; readonly path: string; readonly pathSpan: Span }
  /** `form POST /api/posts` */
  | { readonly kind: "form"; readonly span: Span; readonly method: string; readonly methodSpan: Span; readonly path: string; readonly pathSpan: Span }
  /** `button "Delete" DELETE /api/posts/:id` */
  | { readonly kind: "button"; readonly span: Span; readonly label: TextRef; readonly method: string; readonly methodSpan: Span; readonly path: string; readonly pathSpan: Span }
  /** `then go /posts/:id` */
  | { readonly kind: "thenGo"; readonly span: Span; readonly path: string; readonly pathSpan: Span };
