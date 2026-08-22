/**
 * Where rate-limit counters live.
 *
 * WHY THIS EXISTS
 *
 * `RateLimitRule` hard-constructed an `InMemoryRateLimiter` — a `Map`, with no
 * seam to replace it. On any deployment with more than one process the limit was
 * effectively `max × instances`, and on Vercel or Lambda it also reset on every
 * cold start. A `rateLimit({ max: 100, window: 60 })` across eight replicas is a
 * 800/min limit that an autoscaler can raise for you.
 *
 * That was inconsistent with the rest of the SDK: the detection stores and the
 * captcha's challenge and token stores were already behind swappable interfaces
 * with in-memory defaults. The one piece of state that actually has to be shared
 * was the only one that could not be.
 *
 * SYNC AND ASYNC
 *
 * `Rule.evaluate()` is synchronous, and making it async would turn every rule
 * evaluation into a promise for the sake of the one rule that might need it. So
 * a store declares which it is:
 *
 * - A **sync** store is consumed inline during `evaluate()`. This is the default
 *   in-memory path, unchanged and allocation-free.
 * - An **async** store is consumed in `prepare()`, which `protect()` awaits
 *   before evaluation — the same pre-fetch the SDK already does for IP
 *   enrichment and Web Bot Auth verdicts.
 *
 * A rule whose async store was never prepared reports `NOT_RUN` rather than
 * silently allowing. A rate limiter that quietly stops limiting is worse than
 * one that says it is not running.
 */

/** What one consumption of the limit produced. */
export interface RateLimitOutcome {
  /** Whether this request is within the limit. */
  allowed: boolean;
  /** Requests counted in the current window, including this one. */
  current: number;
  /** When the window resets, as a Unix ms timestamp. */
  resetAt: number;
}

export interface RateLimitConsume {
  key: string;
  max: number;
  windowMs: number;
  algorithm: 'fixed' | 'sliding';
}

/**
 * A counter store.
 *
 * `sync: true` means `consume()` returns an outcome directly and may be called
 * during rule evaluation. `sync: false` means it returns a promise and will be
 * consumed during the async pre-fetch instead.
 */
export interface RateLimitStore {
  readonly sync: boolean;
  consume(input: RateLimitConsume): RateLimitOutcome | Promise<RateLimitOutcome>;
  destroy?(): void | Promise<void>;
}

/** A store whose `consume` is callable inline. */
export interface SyncRateLimitStore extends RateLimitStore {
  readonly sync: true;
  consume(input: RateLimitConsume): RateLimitOutcome;
}

import { InMemoryRateLimiter } from './rate-limiter';

/**
 * The default: counters in this process's memory.
 *
 * Correct for a single process, and the reason the SDK works with no
 * infrastructure at all. Wrong the moment you run two — see
 * {@link upstashRateLimitStore} for the shared alternative.
 */
export class MemoryRateLimitStore implements SyncRateLimitStore {
  readonly sync = true as const;
  private limiter = new InMemoryRateLimiter();

  consume({ key, max, windowMs, algorithm }: RateLimitConsume): RateLimitOutcome {
    return algorithm === 'sliding'
      ? this.limiter.checkSlidingWindow(key, max, windowMs)
      : this.limiter.checkFixedWindow(key, max, windowMs);
  }

  destroy(): void {
    this.limiter.destroy();
  }
}
