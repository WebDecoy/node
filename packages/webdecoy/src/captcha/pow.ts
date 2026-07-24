/**
 * Proof-of-work challenge issuance and verification.
 *
 * Ported from FCaptcha server.js `powChallengeStore`. HMAC-signed challenges,
 * SHA-256 leading-zero difficulty, one-time-use replay protection, 5-minute
 * expiry, optional signals-commitment binding, and un-spoofable server-side
 * timing. The challenge store is pluggable so Phase-later work can back it with
 * Redis for serverless / multi-instance deployments.
 */

import { sha256Hex, hmacSha256Hex, randomHex } from '../webcrypto';
import { isDatacenterIP } from '../detection/ip';
import type { RateLimiter } from '../detection/stores';
import { InMemoryRateLimiter } from '../detection/stores';
import type { ChallengeData, PoWSolution, PoWVerification, StoredChallenge } from './types';

const EXPIRATION_MS = 5 * 60 * 1000; // 5 minutes

/** Persistence for in-flight challenges and consumed solutions. */
export interface ChallengeStore {
  put(challenge: StoredChallenge): void;
  get(id: string): StoredChallenge | undefined;
  delete(id: string): void;
  /** Returns false if the solution key was already consumed (replay). */
  markSolutionUsed(solutionKey: string): boolean;
}

export class InMemoryChallengeStore implements ChallengeStore {
  private challenges = new Map<string, StoredChallenge>();
  private usedSolutions = new Set<string>();

  put(challenge: StoredChallenge): void {
    this.challenges.set(challenge.id, challenge);
    if (Math.random() < 0.1) this.cleanup();
  }

  get(id: string): StoredChallenge | undefined {
    return this.challenges.get(id);
  }

  delete(id: string): void {
    this.challenges.delete(id);
  }

  markSolutionUsed(solutionKey: string): boolean {
    if (this.usedSolutions.has(solutionKey)) return false;
    this.usedSolutions.add(solutionKey);
    return true;
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [id, challenge] of this.challenges) {
      if (now > challenge.expiresAt) this.challenges.delete(id);
    }
    if (this.usedSolutions.size > 10000) this.usedSolutions.clear();
  }
}

export interface PoWManagerOptions {
  secret: string;
  store?: ChallengeStore;
  /** Shared rate limiter used for difficulty scaling. */
  rateLimiter?: RateLimiter;
}

export class PoWManager {
  private readonly secret: string;
  private readonly store: ChallengeStore;
  private readonly rateLimiter: RateLimiter;

  constructor(options: PoWManagerOptions) {
    this.secret = options.secret;
    this.store = options.store ?? new InMemoryChallengeStore();
    this.rateLimiter = options.rateLimiter ?? new InMemoryRateLimiter();
  }

  /** Difficulty scaled by IP reputation and request rate (4..6). */
  scaleDifficulty(siteKey: string, ip: string): number {
    let difficulty = 4;
    if (isDatacenterIP(ip)) difficulty = 5;

    const [exceeded, count] = this.rateLimiter.check(`pow:${siteKey}:${ip}`, 60, 20);
    if (count > 10) difficulty = Math.min(6, difficulty + 1);
    if (exceeded) difficulty = 6;

    return difficulty;
  }

  /** Generate and store a signed challenge. */
  async generate(siteKey: string, ip: string, difficulty?: number): Promise<ChallengeData> {
    const resolvedDifficulty = difficulty ?? this.scaleDifficulty(siteKey, ip);
    const challengeId = randomHex(16);
    const nonce = randomHex(16);
    const timestamp = Date.now();
    const expiresAt = timestamp + EXPIRATION_MS;

    const challengeData: ChallengeData = {
      id: challengeId,
      siteKey,
      timestamp,
      expiresAt,
      difficulty: resolvedDifficulty,
      nonce,
      prefix: `${challengeId}:${timestamp}:${resolvedDifficulty}`,
      sig: '',
    };

    // Sign over the challenge (excluding the not-yet-set sig field — it's '').
    const { sig: _omit, ...toSign } = challengeData;
    void _omit;
    challengeData.sig = await hmacSha256Hex(this.secret, JSON.stringify(toSign));

    this.store.put({ ...challengeData, ip, createdAt: timestamp });
    return challengeData;
  }

  /** Verify a submitted solution. `signalsHash` binds it to the signals. */
  async verify(
    solution: PoWSolution,
    siteKey: string,
    signalsHash: string | null = null,
  ): Promise<PoWVerification> {
    const challenge = this.store.get(solution.challengeId);
    if (!challenge) return { valid: false, reason: 'challenge_not_found' };

    if (Date.now() > challenge.expiresAt) {
      this.store.delete(solution.challengeId);
      return { valid: false, reason: 'challenge_expired' };
    }

    if (challenge.siteKey !== siteKey) {
      return { valid: false, reason: 'site_key_mismatch' };
    }

    const solutionKey = `${solution.challengeId}:${solution.nonce}`;
    // Peek for replay before consuming, so an invalid hash doesn't burn the key.
    const input = signalsHash
      ? `${challenge.prefix}:${signalsHash}:${solution.nonce}`
      : `${challenge.prefix}:${solution.nonce}`;
    const expectedHash = await sha256Hex(input);

    if (solution.hash !== expectedHash) {
      return { valid: false, reason: 'invalid_hash' };
    }

    const target = '0'.repeat(challenge.difficulty);
    if (!solution.hash.startsWith(target)) {
      return { valid: false, reason: 'insufficient_difficulty' };
    }

    // Consume the solution (one-time use) only once it's known valid.
    if (!this.store.markSolutionUsed(solutionKey)) {
      return { valid: false, reason: 'solution_already_used' };
    }
    this.store.delete(solution.challengeId);

    return {
      valid: true,
      difficulty: challenge.difficulty,
      serverElapsed: Date.now() - challenge.createdAt,
      nonce: challenge.nonce,
    };
  }
}
