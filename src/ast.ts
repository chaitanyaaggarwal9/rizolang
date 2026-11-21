import type { Span } from "./diagnostics.js";

/** Syntax tree produced by the parser. Names and types are not validated yet. */

export interface Program {
  readonly models: readonly ModelDecl[];
  readonly auths: readonly AuthDecl[];
  readonly apis: readonly ApiDecl[];
}

export interface ModelDecl {
  readonly name: string;
  readonly nameSpan: Span;
  readonly fields: readonly FieldDecl[];
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
  | { readonly kind: "unique" | "optional" | "private"; readonly span: Span }
  | { readonly kind: "min" | "max"; readonly value: number; readonly span: Span; readonly valueSpan: Span };

export type ModifierKind = Modifier["kind"];

export const MODIFIER_NAMES: readonly ModifierKind[] = ["unique", "optional", "private", "min", "max"];

/** `auth User by email` */
export interface AuthDecl {
  readonly span: Span;
  readonly model: string;
  readonly modelSpan: Span;
  readonly field: string;
  readonly fieldSpan: Span;
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
  | { readonly kind: "requiresOwner"; readonly span: Span; readonly field: string; readonly fieldSpan: Span }
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
  /** `field = value` */
  | { readonly kind: "assign"; readonly field: string; readonly fieldSpan: Span; readonly value: Value; readonly span: Span }
  /** `order field` or `order field desc` */
  | { readonly kind: "order"; readonly field: string; readonly fieldSpan: Span; readonly descending: boolean; readonly span: Span }
  /** `limit 20` */
  | { readonly kind: "limit"; readonly value: number; readonly valueSpan: Span; readonly span: Span };

export type Value =
  | { readonly kind: "name"; readonly name: string; readonly span: Span }
  | { readonly kind: "int"; readonly value: number; readonly span: Span }
  | { readonly kind: "bool"; readonly value: boolean; readonly span: Span };
