/**
 * Tests for the Phase 2 captcha layer: PoW manager, token manager, and the
 * end-to-end Captcha service (challenge → solve → verify → token).
 *
 * The solver + expected-hash helpers use node:crypto (sync, fast in a loop);
 * tests always run in Node. The code under test uses Web Crypto only.
 */

import { createHash } from 'crypto';
import { PoWManager } from './pow';
import { TokenManager } from './token';
import { Captcha } from './service';
import { resolveSecret, INSECURE_DEFAULT_SECRET } from './secret';
import type { ChallengeData, PoWSolution } from './types';

const SECRET = 'test-secret-0123456789abcdef';
const UA_CHROME_MAC =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36';
const GOOD_HEADERS = {
  'user-agent': UA_CHROME_MAC,
  accept: 'text/html',
  'accept-language': 'en-US,en;q=0.9',
  'accept-encoding': 'gzip, deflate, br',
};
const HUMAN_BEHAVIOR = {
  totalPoints: 80,
  trajectoryLength: 350,
  velocityVariance: 0.8,
  microTremorScore: 0.6,
  directionChanges: 15,
  mouseEventRate: 60,
  interactionDuration: 1500,
  approachPoints: 12,
  overshootCorrections: 3,
  eventDeltaVariance: 25,
};
const CHROME_MAC_ENV = {
  automationFlags: { chrome: true, platform: 'MacIntel', plugins: 5 },
  navigator: { platform: 'MacIntel', maxTouchPoints: 0 },
};

/** Brute-force a PoW solution (test difficulties are small). */
function solve(challenge: ChallengeData, signalsHash?: string): PoWSolution {
  const target = '0'.repeat(challenge.difficulty);
  for (let n = 0; ; n++) {
    const input = signalsHash
      ? `${challenge.prefix}:${signalsHash}:${n}`
      : `${challenge.prefix}:${n}`;
    const hash = createHash('sha256').update(input).digest('hex');
    if (hash.startsWith(target)) {
      return { challengeId: challenge.id, nonce: n, hash, signalsHash };
    }
  }
}

describe('secret resolution', () => {
  const original = process.env.NODE_ENV;
  afterEach(() => {
    process.env.NODE_ENV = original;
  });

  it('falls back to the dev default outside production', () => {
    process.env.NODE_ENV = 'test';
    expect(resolveSecret()).toBe(INSECURE_DEFAULT_SECRET);
  });

  it('throws on a missing secret in production', () => {
    process.env.NODE_ENV = 'production';
    expect(() => resolveSecret()).toThrow(/required in production/);
  });

  it('throws on the default secret in production', () => {
    process.env.NODE_ENV = 'production';
    expect(() => resolveSecret(INSECURE_DEFAULT_SECRET)).toThrow(/default development secret/);
  });

  it('accepts a strong secret in production', () => {
    process.env.NODE_ENV = 'production';
    expect(resolveSecret(SECRET)).toBe(SECRET);
  });
});

describe('PoWManager', () => {
  it('generates a signed challenge with a bound nonce', async () => {
    const pow = new PoWManager({ secret: SECRET });
    const c = await pow.generate('site', '1.2.3.4', 2);
    expect(c.difficulty).toBe(2);
    expect(c.sig).toHaveLength(64);
    expect(c.nonce).toHaveLength(32);
    expect(c.prefix).toBe(`${c.id}:${c.timestamp}:2`);
  });

  it('verifies a correct solution and reports server timing + nonce', async () => {
    const pow = new PoWManager({ secret: SECRET });
    const c = await pow.generate('site', '1.2.3.4', 2);
    const result = await pow.verify(solve(c), 'site');
    expect(result.valid).toBe(true);
    expect(result.nonce).toBe(c.nonce);
    expect(typeof result.serverElapsed).toBe('number');
  });

  it('rejects replay of a used solution', async () => {
    const pow = new PoWManager({ secret: SECRET });
    const c = await pow.generate('site', '1.2.3.4', 2);
    const sol = solve(c);
    expect((await pow.verify(sol, 'site')).valid).toBe(true);
    // Challenge is consumed; second attempt no longer finds it.
    expect((await pow.verify(sol, 'site')).reason).toBe('challenge_not_found');
  });

  it('rejects an unknown challenge', async () => {
    const pow = new PoWManager({ secret: SECRET });
    expect((await pow.verify({ challengeId: 'nope', nonce: 0, hash: 'x' }, 'site')).reason).toBe(
      'challenge_not_found',
    );
  });

  it('rejects a site-key mismatch', async () => {
    const pow = new PoWManager({ secret: SECRET });
    const c = await pow.generate('site', '1.2.3.4', 2);
    expect((await pow.verify(solve(c), 'other')).reason).toBe('site_key_mismatch');
  });

  it('rejects an incorrect hash', async () => {
    const pow = new PoWManager({ secret: SECRET });
    const c = await pow.generate('site', '1.2.3.4', 2);
    expect(
      (await pow.verify({ challengeId: c.id, nonce: 0, hash: 'deadbeef' }, 'site')).reason,
    ).toBe('invalid_hash');
  });

  it('rejects insufficient difficulty', async () => {
    const pow = new PoWManager({ secret: SECRET });
    const c = await pow.generate('site', '1.2.3.4', 5);
    // The correct hash for nonce 0 almost never has 5 leading zeros.
    const input = `${c.prefix}:0`;
    const hash = createHash('sha256').update(input).digest('hex');
    expect((await pow.verify({ challengeId: c.id, nonce: 0, hash }, 'site')).reason).toBe(
      'insufficient_difficulty',
    );
  });

  it('binds the solution to a signals hash', async () => {
    const pow = new PoWManager({ secret: SECRET });
    const c = await pow.generate('site', '1.2.3.4', 2);
    const signalsHash = createHash('sha256').update('{"a":1}').digest('hex');
    const sol = solve(c, signalsHash);
    // Verifying without the same signalsHash fails the hash check.
    expect((await pow.verify({ ...sol, signalsHash: undefined }, 'site')).reason).toBe(
      'invalid_hash',
    );
    expect((await pow.verify(sol, 'site', signalsHash)).valid).toBe(true);
  });

  it('scales difficulty up for datacenter IPs', () => {
    const pow = new PoWManager({ secret: SECRET });
    expect(pow.scaleDifficulty('site', '52.1.2.3')).toBeGreaterThanOrEqual(5);
    expect(pow.scaleDifficulty('site', '73.15.22.100')).toBe(4);
  });
});

describe('TokenManager', () => {
  it('issues and verifies a token', async () => {
    const tm = new TokenManager({ secret: SECRET });
    const token = await tm.issue('1.2.3.4', 'site', 0.12);
    const v = await tm.verify(token);
    expect(v.valid).toBe(true);
    expect(v.site_key).toBe('site');
    expect(v.score).toBe(0.12);
  });

  it('enforces single use (replay protection)', async () => {
    const tm = new TokenManager({ secret: SECRET });
    const token = await tm.issue('1.2.3.4', 'site', 0.1);
    expect((await tm.verify(token)).valid).toBe(true);
    expect((await tm.verify(token)).reason).toBe('token_already_used');
  });

  it('binds the token to the client IP', async () => {
    const tm = new TokenManager({ secret: SECRET });
    const token = await tm.issue('1.2.3.4', 'site', 0.1);
    expect((await tm.verify(token, '9.9.9.9')).reason).toBe('ip_mismatch');
  });

  it('rejects a tampered signature', async () => {
    const tm = new TokenManager({ secret: SECRET });
    const other = new TokenManager({ secret: 'different-secret' });
    const token = await other.issue('1.2.3.4', 'site', 0.1);
    expect((await tm.verify(token)).reason).toBe('invalid_signature');
  });

  it('rejects an expired token', async () => {
    const tm = new TokenManager({ secret: SECRET });
    const token = await tm.issue('1.2.3.4', 'site', 0.1);
    const realNow = Date.now();
    const spy = jest.spyOn(Date, 'now').mockReturnValue(realNow + 301_000);
    try {
      expect((await tm.verify(token)).reason).toBe('expired');
    } finally {
      spy.mockRestore();
    }
  });

  it('rejects garbage', async () => {
    const tm = new TokenManager({ secret: SECRET });
    expect((await tm.verify('not-a-token')).valid).toBe(false);
  });
});

describe('Captcha end-to-end', () => {
  it('passes a clean human with a valid PoW and issues a usable token', async () => {
    const captcha = new Captcha({ secret: SECRET });
    const ip = '73.15.22.100';

    // t0: issue challenge.
    const realNow = Date.now();
    const spy = jest.spyOn(Date, 'now').mockReturnValue(realNow);
    let token: string | null;
    try {
      const challenge = await captcha.issueChallenge('site', ip, 2);
      const solution = solve(challenge);

      // Advance time so server-side elapsed exceeds the too-fast threshold.
      spy.mockReturnValue(realNow + 3000);

      const result = await captcha.verify({
        siteKey: 'site',
        ip,
        userAgent: UA_CHROME_MAC,
        headers: GOOD_HEADERS,
        signals: {
          behavioral: HUMAN_BEHAVIOR,
          environmental: CHROME_MAC_ENV,
          meta: { challengeNonce: challenge.nonce },
        },
        powSolution: solution,
      });

      expect(result.success).toBe(true);
      expect(result.recommendation).toBe('allow');
      expect(result.token).toBeTruthy();
      token = result.token;
    } finally {
      spy.mockRestore();
    }

    // The issued token verifies once, then is consumed.
    expect((await captcha.verifyToken(token!, ip)).valid).toBe(true);
    expect((await captcha.verifyToken(token!, ip)).reason).toBe('token_already_used');
  });

  it('fails a clear bot (headless + CDP + datacenter, no PoW) and issues no token', async () => {
    const captcha = new Captcha({ secret: SECRET });
    const result = await captcha.verify({
      siteKey: 'site',
      ip: '52.1.2.3', // datacenter
      userAgent: 'Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/120.0.0.0',
      headers: { 'user-agent': 'HeadlessChrome' },
      signals: {
        environmental: {
          webdriver: true,
          cdp: { detected: true, signals: ['chromedriver_cdc'] },
        },
      },
    });
    expect(result.success).toBe(false);
    expect(result.token).toBeNull();
    expect(result.detections.some((d) => d.reason.includes('No PoW solution'))).toBe(true);
  });

  it('does not block on "no PoW" alone — pushes to challenge, not block', async () => {
    // A single maxed category cannot cross the 0.5 success threshold; missing
    // PoW on an otherwise-clean request yields a "challenge" recommendation.
    const captcha = new Captcha({ secret: SECRET });
    const result = await captcha.verify({
      siteKey: 'site',
      ip: '52.1.2.3',
      userAgent: 'curl/8.0',
      headers: { 'user-agent': 'curl/8.0' },
      signals: {},
    });
    expect(result.recommendation).not.toBe('allow');
    expect(result.detections.some((d) => d.reason.includes('No PoW solution'))).toBe(true);
  });

  it('detects signals tampering via the commitment hash', async () => {
    const captcha = new Captcha({ secret: SECRET });
    const ip = '73.15.22.100';
    const challenge = await captcha.issueChallenge('site', ip, 2);
    const realJson = JSON.stringify({ behavioral: HUMAN_BEHAVIOR });
    const wrongHash = createHash('sha256').update('something-else').digest('hex');
    const solution = solve(challenge, wrongHash);

    const result = await captcha.verify({
      siteKey: 'site',
      ip,
      userAgent: UA_CHROME_MAC,
      headers: GOOD_HEADERS,
      signalsJson: realJson,
      powSolution: solution,
    });

    expect(result.detections.some((d) => d.reason.includes('Signals tampered'))).toBe(true);
  });

  it('returns an action in invisible (score) mode', async () => {
    const captcha = new Captcha({ secret: SECRET });
    const out = await captcha.score({
      siteKey: 'site',
      ip: '73.15.22.100',
      userAgent: UA_CHROME_MAC,
      headers: GOOD_HEADERS,
      action: 'login',
      signals: { behavioral: HUMAN_BEHAVIOR, environmental: CHROME_MAC_ENV },
    });
    expect(out.action).toBe('login');
    expect(typeof out.score).toBe('number');
  });
});
