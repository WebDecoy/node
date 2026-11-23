/**
 * Detection engine.
 *
 * Runs the full FCaptcha detector suite in-process and produces a {@link Verdict}.
 * Mirrors the reference server's `runVerification` orchestration. The actual
 * proof-of-work crypto and token issuance land in Phase 2 — for now the caller
 * supplies a {@link PoWOutcome} and the engine emits the matching detections.
 */

import type { Detection, DetectionContext, Signals, Verdict } from './types';
import { DEFAULT_WEIGHTS } from './weights';
import { isDatacenterIP } from './ip';
import {
  InMemoryFingerprintStore,
  InMemoryRateLimiter,
  type FingerprintStore,
  type RateLimiter,
} from './stores';
import { calculateCategoryScores, calculateFinalScore, recommend } from './scoring';
import {
  detectVisionAI,
  detectHeadless,
  detectAutomation,
  detectCDP,
  detectBehavioral,
  detectTouchAuthenticity,
  detectSensorEntropy,
  detectTouchKinematics,
  detectFingerprint,
  detectRateAbuse,
  analyzeHeaders,
  checkBrowserConsistency,
  checkJA3Fingerprint,
  checkJA4Fingerprint,
  readJA4FromHeaders,
  analyzeFormInteraction,
  analyzeAdvancedSignals,
} from './detectors';

export interface DetectionEngineOptions {
  /** Override the per-category weights (defaults to {@link DEFAULT_WEIGHTS}). */
  weights?: Record<string, number>;
  /**
   * When true (default), a request with no PoW outcome emits a hard-fail "No PoW
   * solution provided" detection — matching the reference server. Set false to
   * score raw signals without requiring proof-of-work.
   */
  requirePoW?: boolean;
  /** Fingerprint-correlation store (defaults to an in-memory store). */
  fingerprintStore?: FingerprintStore;
  /** Rate limiter for rate-abuse detection (defaults to in-memory). */
  rateLimiter?: RateLimiter;
}

export class DetectionEngine {
  private readonly weights: Record<string, number>;
  private readonly requirePoW: boolean;
  private readonly fingerprintStore: FingerprintStore;
  private readonly rateLimiter: RateLimiter;

  constructor(options: DetectionEngineOptions = {}) {
    this.weights = options.weights ?? DEFAULT_WEIGHTS;
    this.requirePoW = options.requirePoW ?? true;
    this.fingerprintStore = options.fingerprintStore ?? new InMemoryFingerprintStore();
    this.rateLimiter = options.rateLimiter ?? new InMemoryRateLimiter();
  }

  /** Score `signals` for the given request context and return a verdict. */
  score(signals: Signals, context: DetectionContext): Verdict {
    const { ip, siteKey, userAgent } = context;
    const headers = context.headers ?? {};
    const detections: Detection[] = [];

    // Orchestrator-supplied detections (e.g. signals-tampering check).
    if (context.extraDetections) detections.push(...context.extraDetections);

    // --- Proof-of-work outcome -------------------------------------------------
    const pow = context.pow;
    if (pow && pow.provided) {
      if (pow.valid === false) {
        detections.push({
          category: 'bot',
          score: 0.7,
          confidence: 0.8,
          reason: `PoW verification failed: ${pow.reason ?? 'unknown'}`,
        });
      }
      // Challenge nonce binding: signals must be bound to the solved challenge.
      if (pow.valid && pow.nonce) {
        const clientNonce = signals.meta?.challengeNonce;
        if (!clientNonce || clientNonce !== pow.nonce) {
          detections.push({
            category: 'bot',
            score: 0.9,
            confidence: 0.9,
            reason: 'Challenge nonce mismatch (signals not bound to challenge)',
          });
        }
      }
      // Server-side timing (un-spoofable): solved suspiciously fast.
      if (pow.valid && pow.serverElapsed !== undefined && pow.serverElapsed < 1500) {
        detections.push({
          category: 'bot',
          score: 0.8,
          confidence: 0.85,
          reason: `Challenge solved too fast (${pow.serverElapsed}ms server-side)`,
        });
      }
    } else if (this.requirePoW) {
      detections.push({
        category: 'bot',
        score: 0.9,
        confidence: 0.95,
        reason: 'No PoW solution provided',
      });
    }

    // --- Behavioral / environmental detectors ---------------------------------
    const widgetInteraction = context.widgetInteraction !== false;
    detections.push(
      ...detectVisionAI(signals, widgetInteraction),
      ...detectHeadless(signals, userAgent),
      ...detectAutomation(signals),
      ...detectCDP(signals),
      ...detectBehavioral(signals, widgetInteraction),
      ...detectTouchAuthenticity(signals, userAgent),
      ...detectSensorEntropy(signals, userAgent),
      ...detectTouchKinematics(signals),
      ...detectFingerprint(signals, ip, siteKey, this.fingerprintStore),
      ...detectRateAbuse(ip, siteKey, this.rateLimiter),
    );

    // --- IP reputation (datacenter; richer reputation is remote) --------------
    if (isDatacenterIP(ip)) {
      detections.push({
        category: 'datacenter',
        score: 0.6,
        confidence: 0.8,
        reason: 'Request from known datacenter IP range',
      });
    }

    // --- Header & browser-consistency checks ----------------------------------
    detections.push(...analyzeHeaders(headers));
    detections.push(...checkBrowserConsistency(userAgent, signals));

    // --- TLS fingerprints ------------------------------------------------------
    if (context.ja3Hash) {
      detections.push(...checkJA3Fingerprint(context.ja3Hash));
    }
    if (context.trustedJA4Headers && context.trustedJA4Headers.length > 0) {
      const ja4 = readJA4FromHeaders(headers, context.trustedJA4Headers);
      if (ja4) detections.push(...checkJA4Fingerprint(ja4));
    }

    // --- Form interaction + advanced fingerprints -----------------------------
    if (signals.formAnalysis) {
      detections.push(...analyzeFormInteraction(signals.formAnalysis, signals.behavioral));
    }
    detections.push(...analyzeAdvancedSignals(signals));

    // --- Aggregate -------------------------------------------------------------
    const categoryScores = calculateCategoryScores(detections, this.weights);
    const score = calculateFinalScore(categoryScores, this.weights);

    return {
      success: score < 0.5,
      score,
      recommendation: recommend(score),
      categoryScores,
      detections,
      timestamp: Math.floor(Date.now() / 1000),
    };
  }
}
