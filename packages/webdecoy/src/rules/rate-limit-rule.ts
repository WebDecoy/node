/**
 * Rate Limit Rule
 * Implements the Rule interface using InMemoryRateLimiter
 */

import { Rule, RuleContext, RuleResult, RateLimitConfig } from './types';
import { MemoryRateLimitStore } from './rate-limit-store';
import type { RateLimitStore, RateLimitOutcome, RateLimitConsume } from './rate-limit-store';

export class RateLimitRule implements Rule {
  readonly name: string;
  private store: RateLimitStore;
  private config: Required<
    Pick<RateLimitConfig, 'max' | 'window' | 'algorithm' | 'action' | 'dryRun'>
  > &
    Pick<RateLimitConfig, 'keyBy'>;

  constructor(config: RateLimitConfig) {
    this.name = `rate-limit:${config.max}/${config.window}s`;
    this.store = config.store ?? new MemoryRateLimitStore();
    this.config = {
      max: config.max,
      window: config.window,
      algorithm: config.algorithm ?? 'fixed',
      keyBy: config.keyBy,
      action: config.action ?? 'THROTTLE',
      dryRun: config.dryRun ?? false,
    };
  }

  /**
   * Which bucket this request counts against.
   *
   * Precedence: this rule's own keyBy, then the SDK-wide characteristics, then
   * the IP. `context.key` is always populated, so the last fallback only matters
   * for a context built by hand.
   */
  private keyFor(context: RuleContext): string {
    return this.config.keyBy ? this.config.keyBy(context) : (context.key ?? context.ip);
  }

  private consumption(context: RuleContext): RateLimitConsume {
    return {
      key: this.keyFor(context),
      max: this.config.max,
      windowMs: this.config.window * 1000,
      algorithm: this.config.algorithm,
    };
  }

  /** Consume from a networked store before evaluation. No-op for a sync store. */
  async prepare(context: RuleContext): Promise<void> {
    if (this.store.sync) return;
    const outcome = await this.store.consume(this.consumption(context));
    context.prepared ??= {};
    context.prepared[this.name] = outcome;
  }

  evaluate(context: RuleContext): RuleResult {
    let result: RateLimitOutcome;

    if (this.store.sync) {
      result = this.store.consume(this.consumption(context)) as RateLimitOutcome;
    } else {
      const prepared = context.prepared?.[this.name] as RateLimitOutcome | undefined;
      if (!prepared) {
        // A networked store that was never consumed. Saying so beats allowing
        // silently: a rate limiter that has quietly stopped limiting looks
        // identical to one that is working.
        return {
          action: 'ALLOW',
          rule: this.name,
          state: 'NOT_RUN',
          reason:
            'Rate limit uses an async store and was not prepared — call protect() or evaluateRulesAsync()',
        };
      }
      result = prepared;
    }

    if (!result.allowed) {
      const retryAfter = Math.ceil((result.resetAt - Date.now()) / 1000);

      return {
        action: this.config.dryRun ? 'ALLOW' : this.config.action,
        rule: this.name,
        reason: `Rate limit exceeded: ${result.current}/${this.config.max} requests in ${this.config.window}s window`,
        metadata: {
          current: result.current,
          max: this.config.max,
          window: this.config.window,
          retryAfter: Math.max(retryAfter, 1),
          dryRun: this.config.dryRun,
        },
      };
    }

    return {
      action: 'ALLOW',
      rule: this.name,
      metadata: {
        current: result.current,
        max: this.config.max,
        remaining: this.config.max - result.current,
      },
    };
  }

  destroy(): void {
    void this.store.destroy?.();
  }
}
