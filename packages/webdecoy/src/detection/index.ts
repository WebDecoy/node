/**
 * In-process detection engine ported from FCaptcha.
 *
 * Scores client-collected signals against ~40 behavioral, environmental, and
 * fingerprint heuristics to produce a bot-likelihood verdict — without a remote
 * call. Richer IP reputation (VPN/proxy/Tor, abuse score, geo) is still served
 * by api.webdecoy.com via the SDK's IP-enrichment client.
 */

export { DetectionEngine } from './engine';
export type { DetectionEngineOptions } from './engine';

export {
  calculateCategoryScores,
  calculateFinalScore,
  recommend,
} from './scoring';

export { DEFAULT_WEIGHTS, AUTOMATION_UA_PATTERNS } from './weights';
export { isDatacenterIP, DATACENTER_CIDRS } from './ip';
export { parseUserAgent, isMobileUA, BOT_UA_PATTERNS } from './ua';
export {
  InMemoryFingerprintStore,
  InMemoryRateLimiter,
  type FingerprintStore,
  type RateLimiter,
} from './stores';

export * from './detectors';

export type {
  Detection,
  ScrollJumpObservation,
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
} from './types';
