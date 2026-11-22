/**
 * Rizo Lang runtime: serving pages.
 *
 * A page is a small HTML document that loads the client runtime
 * (/_rizo/client.js). The page's settings travel in an inert JSON data block,
 * which the browser never executes. Everything that is not markup we wrote is
 * escaped, and a strict Content-Security-Policy allows only our own script and
 * stylesheet.
 */
import { readFileSync } from "node:fs";
import type { PageRoute, SiteSpec } from "./types.ts";

/** Pages may load only our own script and stylesheet, and talk only to this server. */
export const PAGE_CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self'",
  "connect-src 'self'",
  "form-action 'self'",
  "base-uri 'none'",
  "frame-ancestors 'none'",
].join("; ");

export const PAGE_HEADERS: Readonly<Record<string, string>> = {
  "Content-Type": "text/html; charset=utf-8",
  "Content-Security-Policy": PAGE_CSP,
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Cross-Origin-Opener-Policy": "same-origin",
};

/** The only files served under /_rizo/. Nothing from the URL is used as a file path. */
const ASSETS: Readonly<Record<string, { file: string; type: string }>> = {
  "/_rizo/client.js": { file: "./client/rizo-client.js", type: "text/javascript; charset=utf-8" },
  "/_rizo/styles.css": { file: "./client/styles.css", type: "text/css; charset=utf-8" },
  // The logo from the site line, copied here by the build (absent otherwise).
  "/_rizo/logo.png": { file: "./client/logo.png", type: "image/png" },
  "/_rizo/logo.jpg": { file: "./client/logo.jpg", type: "image/jpeg" },
  "/_rizo/logo.webp": { file: "./client/logo.webp", type: "image/webp" },
};

const assetCache = new Map<string, Buffer>();

/** Returns the asset for a /_rizo/ path, or undefined. */
export function asset(pathname: string): { body: Buffer; type: string } | undefined {
  const a = Object.hasOwn(ASSETS, pathname) ? ASSETS[pathname] : undefined;
  if (a === undefined) return undefined;
  let body = assetCache.get(pathname);
  if (body === undefined) {
    try {
      body = readFileSync(new URL(a.file, import.meta.url));
    } catch {
      return undefined;
    }
    assetCache.set(pathname, body);
  }
  return { body, type: a.type };
}

export function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** JSON that is safe inside a <script type="application/json"> block. */
export function jsonForHtml(value: unknown): string {
  return JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

/** The palette colors (a class on <body>, so no inline style is needed under the CSP). */
const COLORS = new Set(["blue", "teal", "green", "purple", "pink", "red", "orange", "gray"]);

function shell(title: string, body: string, site?: SiteSpec): string {
  const color = site !== undefined && COLORS.has(site.color) ? ` class="rizo-color-${site.color}"` : "";
  const fullTitle = site !== undefined && site.name !== title ? `${title} · ${site.name}` : title;
  return [
    "<!doctype html>",
    '<html lang="en">',
    "<head>",
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    `<title>${escapeHtml(fullTitle)}</title>`,
    '<link rel="stylesheet" href="/_rizo/styles.css">',
    "</head>",
    `<body${color}>${body}</body>`,
    "</html>",
    "",
  ].join("\n");
}

/** A page: the client runtime renders it from the JSON data block. */
export function renderPage(page: PageRoute, params: Readonly<Record<string, string>>, loggedIn: boolean, hasAuth: boolean, hasPrivacy = false, site?: SiteSpec, admin = false): string {
  const data = { title: page.title, items: page.items, params, loggedIn, auth: hasAuth, privacy: hasPrivacy, ...(admin ? { admin: true } : {}), ...(site !== undefined ? { site: { name: site.name, ...(site.logo !== undefined ? { logo: site.logo } : {}) } } : {}) };
  return shell(
    page.title,
    [
      '<main id="app"><noscript>This page needs JavaScript.</noscript></main>',
      `<script type="application/json" id="rizo-page">${jsonForHtml(data)}</script>`,
      '<script type="module" src="/_rizo/client.js"></script>',
    ].join("\n"),
    site,
  );
}

/** A plain page for errors such as "not found" or "log in first". No script. */
export function renderMessage(title: string, message: string, site?: SiteSpec): string {
  return shell(title, `<main id="app" class="rizo-message"><h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p><p><a href="/">Go to the home page</a></p></main>`, site);
}
