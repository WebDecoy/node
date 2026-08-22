/**
 * Rate-limit counters in Upstash Redis.
 *
 * WHY UPSTASH, AND WHY NO DEPENDENCY
 *
 * Upstash speaks Redis over HTTP, which is the only shape that works everywhere
 * this SDK runs: Vercel Edge, Cloudflare Workers and Deno have no `node:net`, so
 * an ordinary Redis client cannot open a socket there. The core package already
 * passes an edge-compatibility gate, and a store that only worked on Node would
 * be unavailable in exactly the serverless deployments that need shared counters
 * most.
 *
 * It talks to the REST API with `fetch` rather than pulling in `@upstash/redis`.
 * Two commands in a pipeline is not worth a dependency, a version to track, or a
 * transitive `node:` import finding its way into an edge bundle.
 *
 * ```ts
 * rateLimit({
 *   max: 100,
 *   window: 60,
 *   store: upstashRateLimitStore({
 *     url: process.env.UPSTASH_REDIS_REST_URL!,
 *     token: process.env.UPSTASH_REDIS_REST_TOKEN!,
 *   }),
 * })
 * ```
 */

import type { RateLimitStore, RateLimitConsume, RateLimitOutcome } from './rate-limit-store';
import { randomHex } from '../webcrypto';

export interface UpstashStoreOptions {
  /** REST endpoint, e.g. `https://eu1-xxx.upstash.io`. */
  url: string;
  /** REST token. */
  token: string;
  /** Prefix for every key written. @default 'wd:rl:' */
  prefix?: string;
  /** Request timeout in milliseconds. @default 1000 */
  timeout?: number;
  /**
   * What to do when Redis is unreachable.
   *
   * `'open'` (default) allows the request: a rate limiter that takes the site
   * down when its datastore has a bad minute has done more damage than the
   * traffic it was shaping. `'closed'` denies, for a limit that is protecting
   * something more expensive than availability.
   *
   * Either way the outcome is reported, so the decision says which happened
   * rather than looking like a normal evaluation.
   */
  onError?: 'open' | 'closed';
}

interface PipelineResult {
  result?: unknown;
  error?: string;
}

export class UpstashRateLimitStore implements RateLimitStore {
  readonly sync = false as const;
  private readonly url: string;
  private readonly token: string;
  private readonly prefix: string;
  private readonly timeout: number;
  private readonly failOpen: boolean;

  constructor(options: UpstashStoreOptions) {
    if (!options.url) throw new Error('upstashRateLimitStore: `url` is required');
    if (!options.token) throw new Error('upstashRateLimitStore: `token` is required');
    this.url = options.url.replace(/\/+$/, '');
    this.token = options.token;
    this.prefix = options.prefix ?? 'wd:rl:';
    this.timeout = options.timeout ?? 1000;
    this.failOpen = (options.onError ?? 'open') === 'open';
  }

  async consume(input: RateLimitConsume): Promise<RateLimitOutcome> {
    try {
      return input.algorithm === 'sliding'
        ? await this.sliding(input)
        : await this.fixed(input);
    } catch {
      const now = Date.now();
      return {
        allowed: this.failOpen,
        current: 0,
        resetAt: now + input.windowMs,
      };
    }
  }

  /**
   * Fixed window: one counter per key per window.
   *
   * The window id is in the key rather than tracked separately, so expiry is the
   * only cleanup needed and two processes incrementing concurrently cannot
   * disagree about which window they are in.
   */
  private async fixed({ key, max, windowMs }: RateLimitConsume): Promise<RateLimitOutcome> {
    const now = Date.now();
    const windowStart = Math.floor(now / windowMs) * windowMs;
    const redisKey = `${this.prefix}f:${key}:${windowStart}`;
    const ttlSeconds = Math.ceil(windowMs / 1000);

    // EXPIRE with NX only sets the TTL on the first increment, so a long-running
    // window is not extended by later requests into a sliding one by accident.
    const [incr] = await this.pipeline([
      ['INCR', redisKey],
      ['EXPIRE', redisKey, String(ttlSeconds), 'NX'],
    ]);

    const current = toCount(incr);
    return { allowed: current <= max, current, resetAt: windowStart + windowMs };
  }

  /**
   * Sliding window: a sorted set of request timestamps, trimmed on every read.
   *
   * The member is timestamp plus random bytes because two requests in the same
   * millisecond would otherwise be one ZADD that overwrites rather than two that
   * count — undercounting exactly when the limit matters.
   */
  private async sliding({ key, max, windowMs }: RateLimitConsume): Promise<RateLimitOutcome> {
    const now = Date.now();
    const redisKey = `${this.prefix}s:${key}`;
    const cutoff = now - windowMs;
    const ttlSeconds = Math.ceil(windowMs / 1000) + 1;

    const results = await this.pipeline([
      ['ZREMRANGEBYSCORE', redisKey, '0', String(cutoff)],
      ['ZADD', redisKey, String(now), `${now}-${randomHex(4)}`],
      ['ZCARD', redisKey],
      ['EXPIRE', redisKey, String(ttlSeconds)],
    ]);

    const current = toCount(results[2]);
    return { allowed: current <= max, current, resetAt: now + windowMs };
  }

  private async pipeline(commands: string[][]): Promise<unknown[]> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);
    try {
      const response = await fetch(`${this.url}/pipeline`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${this.token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(commands),
        signal: controller.signal,
      });
      if (!response.ok) {
        throw new Error(`Upstash responded ${response.status}`);
      }
      const body = (await response.json()) as PipelineResult[];
      if (!Array.isArray(body)) throw new Error('Upstash returned a non-pipeline body');
      for (const entry of body) {
        if (entry?.error) throw new Error(`Upstash command failed: ${entry.error}`);
      }
      return body.map((entry) => entry?.result);
    } finally {
      clearTimeout(timer);
    }
  }
}

function toCount(value: unknown): number {
  const n = typeof value === 'string' ? Number(value) : value;
  return typeof n === 'number' && Number.isFinite(n) ? n : 0;
}

/** Rate-limit counters shared through Upstash Redis. See {@link UpstashStoreOptions}. */
export function upstashRateLimitStore(options: UpstashStoreOptions): RateLimitStore {
  return new UpstashRateLimitStore(options);
}
