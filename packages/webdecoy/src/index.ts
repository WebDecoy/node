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

// In-process detection engine (ported from FCaptcha)
export {
  DetectionEngine,
  calculateCategoryScores,
  calculateFinalScore,
  recommend,
  DEFAULT_WEIGHTS,
  isDatacenterIP,
  parseUserAgent,
  isMobileUA,
  InMemoryFingerprintStore,
  InMemoryRateLimiter,
} from './detection';

export type {
  DetectionEngineOptions,
  Detection,
  CategoryScores,
  Recommendation,
  Signals,
  BehavioralSignals,
  TemporalSignals,
  EnvironmentalSignals,
  FormAnalysisSignals,
  TextareaKeyboardStats,
  PoWOutcome,
  DetectionContext,
  Verdict,
  FingerprintStore,
  RateLimiter,
} from './detection';

// Self-hosted captcha: proof-of-work + detection + session tokens
export {
  Captcha,
  PoWManager,
  InMemoryChallengeStore,
  TokenManager,
  InMemoryTokenStore,
  resolveSecret,
  createCaptchaEndpoints,
} from './captcha';

export type {
  CaptchaOptions,
  PoWManagerOptions,
  ChallengeStore,
  TokenManagerOptions,
  TokenStore,
  ChallengeData,
  StoredChallenge,
  PoWSolution,
  PoWVerification,
  TokenVerification,
  VerifyInput,
  VerifyResult,
  ScoreResult,
  CaptchaEndpoints,
  CaptchaEndpointsOptions,
  CaptchaRequest,
  CaptchaHttpResponse,
} from './captcha';
