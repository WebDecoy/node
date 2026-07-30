/**
 * Rules Engine - Barrel exports
 */

export { RuleEngine } from './rule-engine';
export { RateLimitRule } from './rate-limit-rule';
export { FilterRule } from './filter-rule';
export { TripwireRule, DEFAULT_TRIPWIRE_PATHS } from './tripwire-rule';
export { WebBotAuthRule, webBotAuth } from './web-bot-auth-rule';
export { honeytoken } from './honeytoken';
export { InMemoryRateLimiter } from './rate-limiter';

export type {
  Rule,
  RuleContext,
  RuleResult,
  RuleEngineResult,
  RateLimitConfig,
  FilterConfig,
  TripwireConfig,
  ViolationEvent,
  IPEnrichmentData,
} from './types';
export type { WebBotAuthConfig } from './web-bot-auth-rule';
export type { HoneytokenOptions, Honeytoken } from './honeytoken';

import { RateLimitRule } from './rate-limit-rule';
import { FilterRule } from './filter-rule';
import { TripwireRule } from './tripwire-rule';
import type { RateLimitConfig, FilterConfig, TripwireConfig, Rule } from './types';

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

/**
 * Factory function to create a tripwire (honeypot-path) rule.
 *
 * Deterministic, zero-false-positive: any request for a hidden honeypot path is
 * automated by construction. Detects intent (going where a human can't), which
 * stealth fingerprint-spoofing (e.g. botasaurus) cannot evade.
 *
 * @example
 * ```typescript
 * import { WebDecoy, tripwire, honeytoken } from '@webdecoy/node';
 *
 * const hp = honeytoken();
 * const sdk = new WebDecoy({
 *   rules: [
 *     tripwire({ paths: [hp.path] }),   // + built-in scanner-bait paths
 *   ],
 * });
 * // inject hp.linkHtml into your pages
 * ```
 */
export function tripwire(config: TripwireConfig = {}): Rule {
  return new TripwireRule(config);
}
export {
  siteHoneytoken,
  injectHoneytokenLink,
  isInjectableHtml,
  HONEYTOKEN_BASE_PATH,
} from './honeytoken-site';
export type {
  SiteHoneytoken,
  SiteHoneytokenOptions,
  HoneytokenLinkProps,
} from './honeytoken-site';
