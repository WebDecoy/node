/** Types for the self-hosted captcha service (PoW + scoring + tokens). */

import type { Recommendation, Signals, Verdict } from '../detection/types';

/** Signed challenge returned to the client to solve. */
export interface ChallengeData {
  /** Challenge id (hex). */
  id: string;
  siteKey: string;
  /** Generation time, ms epoch. */
  timestamp: number;
  /** Expiry time, ms epoch. */
  expiresAt: number;
  /** Leading-zero difficulty the solution hash must satisfy. */
  difficulty: number;
  /** Random nonce bound to the challenge (echoed back in signals). */
  nonce: string;
  /** Hash prefix the client iterates over: `${id}:${timestamp}:${difficulty}`. */
  prefix: string;
  /** HMAC signature over the challenge. */
  sig: string;
}

/** Stored challenge record (server-side only — never sent to the client). */
export interface StoredChallenge extends ChallengeData {
  ip: string;
  createdAt: number;
}

/** A client's proof-of-work solution. */
export interface PoWSolution {
  challengeId: string;
  nonce: number | string;
  hash: string;
  /** Optional commitment binding the solution to the submitted signals. */
  signalsHash?: string;
}

/** Result of verifying a PoW solution. */
export interface PoWVerification {
  valid: boolean;
  reason?: string;
  difficulty?: number;
  /** Server-measured solve time in ms (un-spoofable). */
  serverElapsed?: number;
  /** The challenge's bound nonce. */
  nonce?: string;
}

/** Result of verifying an issued token. */
export interface TokenVerification {
  valid: boolean;
  reason?: string;
  site_key?: string;
  timestamp?: number;
  score?: number;
  ip_hash?: string;
}

/** Input to {@link Captcha.verify} / {@link Captcha.score}. */
export interface VerifyInput {
  siteKey: string;
  ip: string;
  userAgent: string;
  /** Lower-cased request headers. */
  headers?: Record<string, string>;
  /** Parsed client signals. */
  signals?: Signals;
  /** Client PoW solution. */
  powSolution?: PoWSolution | null;
  /** Raw signals JSON used for the commitment check (overrides `signals`). */
  signalsJson?: string | null;
  /** Client-reported PoW timing, injected into `signals.temporal.pow`. */
  powTiming?: { duration?: number; iterations?: number } | null;
  /** Client-supplied JA3 hash (spoofable). */
  ja3Hash?: string | null;
}

/** A verdict plus an issued token (present only on success). */
export interface VerifyResult extends Verdict {
  /** True when the proof verified and the score passed. */
  success: boolean;
  /** base64url session token, or null when the request did not pass. */
  token: string | null;
}

/** Invisible-mode (`score`) result. */
export interface ScoreResult {
  /** True when the proof verified and the score passed. */
  success: boolean;
  score: number;
  token: string | null;
  action: string;
  recommendation: Recommendation;
}
