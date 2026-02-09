/**
 * Web Decoy SDK for Node.js
 *
 * Advanced bot detection with TLS fingerprinting and rules engine
 *
 * @example
 * ```typescript
 * import { WebDecoy, rateLimit } from '@webdecoy/node';
 *
 * // Works without API key (rate limiting only)
 * const webdecoy = new WebDecoy({
 *   rules: [
 *     rateLimit({ max: 100, window: 60 }),
 *   ],
 * });
 *
 * // Full power with API key
 * const webdecoy = new WebDecoy({
 *   apiKey: process.env.WEBDECOY_API_KEY,
 *   rules: [
 *     rateLimit({ max: 100, window: 60 }),
 *   ],
 * });
 * ```
 */

export { WebDecoy } from './sdk';

export type {
  WebDecoyConfig,
  TLSInfo,
  RequestMetadata,
  LocalAnalysis,
  SDKDetectionRequest,
  SDKDetectionResponse,
  ProtectResult,
  ProtectOptions,
} from './types';

// Rules engine exports
export { rateLimit, filter, RuleEngine, RateLimitRule, FilterRule } from './rules';

export type {
  Rule,
  RuleContext,
  RuleResult,
  RuleEngineResult,
  RateLimitConfig,
  FilterConfig,
  ViolationEvent,
  IPEnrichmentData,
} from './rules';
