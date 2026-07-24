/**
 * Self-hosted captcha service.
 *
 * Composes the in-process {@link DetectionEngine} with proof-of-work and token
 * issuance to reproduce the FCaptcha server's `runVerification` flow end-to-end:
 * issue challenge → verify PoW → score signals → issue session token. Runs
 * entirely in-process; only IP enrichment remains a remote call elsewhere in
 * the SDK.
 */

import { sha256Hex } from '../webcrypto';
import { DetectionEngine } from '../detection/engine';
import type { Detection, PoWOutcome, Signals } from '../detection/types';
import {
  InMemoryFingerprintStore,
  InMemoryRateLimiter,
  type FingerprintStore,
  type RateLimiter,
} from '../detection/stores';
import { resolveSecret } from './secret';
import { PoWManager, type ChallengeStore } from './pow';
import { TokenManager, type TokenStore } from './token';
import type {
  ChallengeData,
  ScoreResult,
  TokenVerification,
  VerifyInput,
  VerifyResult,
} from './types';

export interface CaptchaOptions {
  /** HMAC secret for signing challenges and tokens. Required in production. */
  secret?: string;
  /** Override per-category detection weights. */
  weights?: Record<string, number>;
  /** Trusted reverse-proxy header names carrying a JA4 fingerprint. */
  trustedJA4Headers?: string[];
  /** Pluggable stores (default to in-memory; swap for Redis in production). */
  challengeStore?: ChallengeStore;
  tokenStore?: TokenStore;
  fingerprintStore?: FingerprintStore;
  rateLimiter?: RateLimiter;
}

export class Captcha {
  private readonly engine: DetectionEngine;
  private readonly pow: PoWManager;
  private readonly tokens: TokenManager;
  private readonly trustedJA4Headers: string[];

  constructor(options: CaptchaOptions = {}) {
    const secret = resolveSecret(options.secret);
    // Share one rate limiter + fingerprint store across detection and PoW
    // scaling, matching the reference server's single-instance stores.
    const rateLimiter = options.rateLimiter ?? new InMemoryRateLimiter();
    const fingerprintStore = options.fingerprintStore ?? new InMemoryFingerprintStore();

    this.engine = new DetectionEngine({
      weights: options.weights,
      requirePoW: true,
      fingerprintStore,
      rateLimiter,
    });
    this.pow = new PoWManager({ secret, store: options.challengeStore, rateLimiter });
    this.tokens = new TokenManager({ secret, store: options.tokenStore });
    this.trustedJA4Headers = options.trustedJA4Headers ?? [];
  }

  /** Issue a PoW challenge for the client to solve (difficulty auto-scaled). */
  async issueChallenge(siteKey: string, ip: string, difficulty?: number): Promise<ChallengeData> {
    return this.pow.generate(siteKey, ip, difficulty);
  }

  /**
   * Verify a submission: checks the signals commitment, verifies PoW, scores the
   * signals, and issues a session token on success. Mirrors `runVerification`.
   */
  async verify(input: VerifyInput): Promise<VerifyResult> {
    const { siteKey, ip, userAgent } = input;
    const headers = input.headers ?? {};
    let signals: Signals = input.signals ?? {};
    const extraDetections: Detection[] = [];

    // 1. Signals commitment: the solution may bind a hash of the raw signals.
    const clientSignalsHash = input.powSolution?.signalsHash ?? null;
    if (input.signalsJson && clientSignalsHash) {
      const computed = await sha256Hex(input.signalsJson);
      if (computed !== clientSignalsHash) {
        extraDetections.push({
          category: 'bot',
          score: 0.95,
          confidence: 0.95,
          reason: 'Signals tampered after PoW (signalsHash mismatch)',
        });
      }
      try {
        signals = JSON.parse(input.signalsJson);
      } catch {
        // Keep the parsed signals if the raw JSON is unusable.
      }
    }

    // 2. Inject client-reported PoW timing for the vision-AI timing heuristic.
    if (input.powTiming) {
      signals = { ...signals, temporal: { ...(signals.temporal ?? {}), pow: input.powTiming } };
    }

    // 3. Verify proof of work → outcome consumed by the engine.
    let pow: PoWOutcome;
    if (input.powSolution && input.powSolution.challengeId) {
      const result = await this.pow.verify(input.powSolution, siteKey, clientSignalsHash);
      pow = {
        provided: true,
        valid: result.valid,
        reason: result.reason,
        serverElapsed: result.serverElapsed,
        nonce: result.nonce,
      };
    } else {
      pow = { provided: false };
    }

    // 4. Score.
    const verdict = this.engine.score(signals, {
      ip,
      siteKey,
      userAgent,
      headers,
      ja3Hash: input.ja3Hash ?? null,
      trustedJA4Headers: this.trustedJA4Headers,
      pow,
      extraDetections,
    });

    // 5. Issue a token on success.
    const token = verdict.success ? await this.tokens.issue(ip, siteKey, verdict.score) : null;

    return { ...verdict, token };
  }

  /** Invisible-mode scoring — same pipeline, returns a compact result + action. */
  async score(input: VerifyInput & { action?: string }): Promise<ScoreResult> {
    const result = await this.verify(input);
    return {
      success: result.success,
      score: result.score,
      token: result.token,
      action: input.action ?? '',
      recommendation: result.recommendation,
    };
  }

  /** Verify a previously issued token (single-use, optionally IP-bound). */
  async verifyToken(token: string, ip: string | null = null): Promise<TokenVerification> {
    return this.tokens.verify(token, ip);
  }
}
