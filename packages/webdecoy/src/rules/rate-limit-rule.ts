/**
 * Rate Limit Rule
 * Implements the Rule interface using InMemoryRateLimiter
 */

import { InMemoryRateLimiter } from './rate-limiter';
import { Rule, RuleContext, RuleResult, RateLimitConfig } from './types';

export class RateLimitRule implements Rule {
  readonly name: string;
  private limiter: InMemoryRateLimiter;
  private config: Required<
    Pick<RateLimitConfig, 'max' | 'window' | 'algorithm' | 'action' | 'dryRun'>
  > &
    Pick<RateLimitConfig, 'keyBy'>;

  constructor(config: RateLimitConfig) {
    this.name = `rate-limit:${config.max}/${config.window}s`;
    this.limiter = new InMemoryRateLimiter();
    this.config = {
      max: config.max,
      window: config.window,
      algorithm: config.algorithm ?? 'fixed',
      keyBy: config.keyBy,
      action: config.action ?? 'THROTTLE',
      dryRun: config.dryRun ?? false,
    };
  }

  evaluate(context: RuleContext): RuleResult {
    const key = this.config.keyBy ? this.config.keyBy(context) : context.ip;
    const windowMs = this.config.window * 1000;

    const result =
      this.config.algorithm === 'sliding'
        ? this.limiter.checkSlidingWindow(key, this.config.max, windowMs)
        : this.limiter.checkFixedWindow(key, this.config.max, windowMs);

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
    this.limiter.destroy();
  }
}
