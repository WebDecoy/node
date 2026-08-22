/**
 * Reusing a decision we already paid for.
 *
 * WHY THIS IS NARROW
 *
 * Only decisions that cost a network round trip are cached, and only when they
 * came back DENY or CHALLENGE. Two deliberate exclusions:
 *
 * - **Rule decisions are never cached.** A rate limiter has to see every
 *   request to advance its window, and a cached tripwire DENY would stop the
 *   violation being reported. Rules are evaluated in-process and cost
 *   microseconds, so there is nothing to save.
 * - **ALLOW is never cached.** Caching an allow is how a client that has since
 *   started misbehaving keeps sailing through, and the request it saves is the
 *   cheap one — a low-risk request already returns without calling out.
 *
 * So this exists for one case: a client we have decided against, hammering the
 * origin, where each request would otherwise re-ask the service the question it
 * just answered.
 */

import type { Decision } from './decision';

export interface DecisionCacheOptions {
  /**
   * How long a denial may be reused, in milliseconds.
   * @default 60_000
   */
  ttl?: number;
  /**
   * Maximum entries held. When full, the oldest insertions are dropped.
   * A bound rather than a target: this must not become a way for a caller
   * cycling keys to grow the process's memory without limit.
   * @default 10_000
   */
  max?: number;
}

interface Entry {
  decision: Decision;
  expiresAt: number;
}

export class DecisionCache {
  private readonly ttl: number;
  private readonly max: number;
  // Insertion-ordered, which is what makes the eviction below oldest-first.
  private entries = new Map<string, Entry>();

  constructor(options: DecisionCacheOptions = {}) {
    this.ttl = options.ttl ?? 60_000;
    this.max = options.max ?? 10_000;
  }

  /** A cached decision for this key, or undefined. Expired entries are dropped. */
  get(key: string): Decision | undefined {
    const entry = this.entries.get(key);
    if (!entry) return undefined;
    if (entry.expiresAt <= Date.now()) {
      this.entries.delete(key);
      return undefined;
    }
    return entry.decision;
  }

  /**
   * Remember a decision, if it is one of the kinds worth remembering.
   * Returns whether it was stored, so a caller can assert on the policy rather
   * than infer it.
   */
  set(key: string, decision: Decision): boolean {
    if (decision.conclusion !== 'DENY' && decision.conclusion !== 'CHALLENGE') return false;
    if (this.ttl <= 0) return false;

    // Refresh insertion order on overwrite so a repeatedly-denied key is not
    // evicted ahead of a key nothing has touched since.
    this.entries.delete(key);
    this.entries.set(key, { decision, expiresAt: Date.now() + this.ttl });

    while (this.entries.size > this.max) {
      const oldest = this.entries.keys().next();
      if (oldest.done) break;
      this.entries.delete(oldest.value);
    }
    return true;
  }

  clear(): void {
    this.entries.clear();
  }

  get size(): number {
    return this.entries.size;
  }

  /** How long entries live, in milliseconds. Reported on the decision. */
  get lifetime(): number {
    return this.ttl;
  }
}
