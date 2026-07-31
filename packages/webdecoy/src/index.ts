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

// The edge validator's verdict, as the origin sees it (#481). Exported as a
// value, not only a type: readEdgeVerdict() is how an application that is not
// using protect() — a route handler, a server component — reads the tag without
// string-matching a header.
export { readEdgeVerdict, EDGE_CLASS_HEADER, EDGE_CLEARANCE_HEADER } from './edge';
export type { EdgeClass, EdgeVerdict } from './edge';

// Declared-agent classification (#500). Exported as values for the same reason
// as readEdgeVerdict: code outside protect() — a route handler deciding whether
// to serve a paywall, a robots.txt generator — needs the same answer without
// standing up a rule engine.
export { matchUserAgent, classifyUserAgent, BOT_REGISTRY, BOT_CATEGORIES } from './bots';
export type { BotVerdict, BotAgent, BotCategory } from './bots';

// Rules engine exports
export {
  rateLimit,
  filter,
  tripwire,
  bots,
  webBotAuth,
  honeytoken,
  RuleEngine,
  RateLimitRule,
  FilterRule,
  TripwireRule,
  BotRule,
  WebBotAuthRule,
  DEFAULT_TRIPWIRE_PATHS,
  siteHoneytoken,
  injectHoneytokenLink,
  isInjectableHtml,
  HONEYTOKEN_BASE_PATH,
} from './rules';

export type {
  Rule,
  RuleContext,
  RuleResult,
  RuleEngineResult,
  RateLimitConfig,
  FilterConfig,
  TripwireConfig,
  BotRuleConfig,
  WebBotAuthConfig,
  HoneytokenOptions,
  Honeytoken,
  SiteHoneytoken,
  SiteHoneytokenOptions,
  HoneytokenLinkProps,
  ViolationEvent,
  IPEnrichmentData,
} from './rules';

// Local Web Bot Auth verification (RFC 9421, tag "web-bot-auth")
export {
  AgentVerifier,
  createAgentVerifier,
  DirectoryCache,
  DEFAULT_SIGNED_AGENT_DIRECTORIES,
} from './agent';

export type {
  AgentStatus,
  AgentCategory,
  AgentVerdict,
  AgentRequestInput,
  AgentVerifierOptions,
  SignedAgentDirectory,
} from './agent';

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
