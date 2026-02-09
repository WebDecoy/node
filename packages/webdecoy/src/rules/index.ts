/**
 * Rules Engine - Barrel exports
 */

export { RuleEngine } from './rule-engine';
export { RateLimitRule } from './rate-limit-rule';
export { FilterRule } from './filter-rule';
export { InMemoryRateLimiter } from './rate-limiter';

export type {
  Rule,
  RuleContext,
  RuleResult,
  RuleEngineResult,
  RateLimitConfig,
  FilterConfig,
  ViolationEvent,
  IPEnrichmentData,
} from './types';

import { RateLimitRule } from './rate-limit-rule';
import { FilterRule } from './filter-rule';
import type { RateLimitConfig, FilterConfig, Rule } from './types';

/**
 * Factory function to create a rate limit rule
 *
 * @example
 * ```typescript
 * import { rateLimit } from '@webdecoy/node';
 *
 * const sdk = new WebDecoy({
 *   rules: [
 *     rateLimit({ max: 100, window: 60 }),
 *   ],
 * });
 * ```
 */
export function rateLimit(config: RateLimitConfig): Rule {
  return new RateLimitRule(config);
}

/**
 * Factory function to create a filter rule
 *
 * @example
 * ```typescript
 * import { filter } from '@webdecoy/node';
 *
 * const sdk = new WebDecoy({
 *   apiKey: process.env.WEBDECOY_API_KEY,
 *   rules: [
 *     filter({ expression: 'ip.vpn or ip.tor', action: 'DENY' }),
 *     filter({ expression: 'ip.country in ["CN", "RU"]', action: 'DENY' }),
 *   ],
 * });
 * ```
 */
export function filter(config: FilterConfig): Rule {
  return new FilterRule(config);
}
