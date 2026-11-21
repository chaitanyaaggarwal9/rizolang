/**
 * Rizo Lang runtime: fixed-window rate limiting for login and signup.
 *
 * Counts are kept in memory, per process. When running several server
 * processes behind a load balancer, each process limits independently.
 */

interface Window {
  count: number;
  resetAt: number;
}

/** Entries kept before expired windows are swept, to bound memory use. */
const SWEEP_AT = 10_000;

export class RateLimiter {
  readonly #limit: number;
  readonly #windowMs: number;
  readonly #now: () => number;
  readonly #windows = new Map<string, Window>();

  constructor(limit: number, windowMs: number, now: () => number = Date.now) {
    this.#limit = limit;
    this.#windowMs = windowMs;
    this.#now = now;
  }

  /** Seconds until `key` may try again, or 0 if it is not limited. */
  retryAfter(key: string): number {
    const w = this.#windows.get(key);
    const now = this.#now();
    if (w === undefined || w.resetAt <= now) return 0;
    return w.count >= this.#limit ? Math.ceil((w.resetAt - now) / 1000) : 0;
  }

  /** Record one attempt for `key`. */
  hit(key: string): void {
    const now = this.#now();
    if (this.#windows.size >= SWEEP_AT) {
      for (const [k, w] of this.#windows) if (w.resetAt <= now) this.#windows.delete(k);
    }
    const w = this.#windows.get(key);
    if (w === undefined || w.resetAt <= now) {
      this.#windows.set(key, { count: 1, resetAt: now + this.#windowMs });
    } else {
      w.count++;
    }
  }

  reset(key: string): void {
    this.#windows.delete(key);
  }
}
