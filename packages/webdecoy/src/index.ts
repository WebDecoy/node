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

// The decision `protect()` returns. Exported as a value because the class
// carries the narrowing helpers (`isDenied()`, `deniedBy()`) that keep an
// adapter's blocked path from being typed `any`.
export { Decision, newDecisionId } from './decision';
export type { Conclusion, RuleState, RuleOutcome, DecisionInit } from './decision';

// What counts as the same caller. Exported so an application can derive the
// same key the SDK does — two answers to "who is this" is one too many.
export { deriveKey, DEFAULT_CHARACTERISTICS } from './characteristics';
export type { Characteristic } from './characteristics';

export { DecisionCache } from './decision-cache';
export type { DecisionCacheOptions } from './decision-cache';

// The reserved test trigger: `curl -A "WebDecoy-Test/1.0" <site>`
// always produces a labeled test detection through the real pipeline.
export {
  isTestTriggerUserAgent,
  TEST_TRIGGER_UA_PREFIX,
  TEST_TRIGGER_USER_AGENT,
} from './test-trigger';

// Resolving the client IP behind a proxy. Exported as values because the
// adapters are not the only place that needs the answer: an application that
// builds its own RequestMetadata, or rate-limits something of its own, has to
// derive the address the same way or the two disagree about who the caller is.
export { resolveClientIp, normalizeIp, ipInCidr } from './client-ip';
export type { TrustedProxies, ResolveClientIpOptions, HeaderSource } from './client-ip';

// The edge validator's verdict, as the origin sees it. Exported as a
// value, not only a type: readEdgeVerdict() is how an application that is not
// using protect() — a route handler, a server component — reads the tag without
// string-matching a header.
export { readEdgeVerdict, EDGE_CLASS_HEADER, EDGE_CLEARANCE_HEADER } from './edge';
export type { EdgeClass, EdgeVerdict } from './edge';

// Declared-agent classification. Exported as values for the same reason
// as readEdgeVerdict: code outside protect() — a route handler deciding whether
// to serve a paywall, a robots.txt generator — needs the same answer without
// standing up a rule engine.
export { matchUserAgent, classifyUserAgent, BOT_REGISTRY, BOT_CATEGORIES } from './bots';
export type { BotVerdict, BotAgent, BotCategory } from './bots';

// A guard over WHATWG Request/Response — the one adapter that covers every
// runtime with a fetch handler. `@webdecoy/hono` is a thin wrapper over it; Bun,
// Deno, Astro and Nitro need no package at all.
export { consoleLogger, silentLogger, fromPino } from './logger';
export type { Logger, LogFields } from './logger';

// Browser signals, joined to the requests that follow them. See client-signals.ts
// for why this is not a threat judgement about a client that sends none.
export {
  clientSignals,
  ClientSignalRule,
  MemoryClientSignalStore,
  readClientSession,
  CLIENT_SESSION_COOKIE,
  CLIENT_SESSION_HEADER,
} from './client-signals';
export type {
  ClientVerdict,
  ClientSignalStore,
  ClientSignalConfig,
  MemoryClientSignalStoreOptions,
} from './client-signals';

export { createFetchGuard } from './fetch-guard';
export type { FetchGuard, FetchGuardOptions, GuardOutcome } from './fetch-guard';

// Rules engine exports
export {
  rateLimit,
  filter,
  tripwire,
  bots,
  botPolicy,
  BotPolicy,
  attackSignatures,
  AttackSignatureRule,
  ATTACK_SIGNATURE_IDS,
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
  MemoryRateLimitStore,
  upstashRateLimitStore,
  UpstashRateLimitStore,
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
  BotPolicyOptions,
  RobotsTxtOptions,
  AttackSignatureConfig,
  WebBotAuthConfig,
  HoneytokenOptions,
  Honeytoken,
  SiteHoneytoken,
  SiteHoneytokenOptions,
  HoneytokenLinkProps,
  ViolationEvent,
  IPEnrichmentData,
  RateLimitStore,
  SyncRateLimitStore,
  RateLimitOutcome,
  RateLimitConsume,
  UpstashStoreOptions,
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
