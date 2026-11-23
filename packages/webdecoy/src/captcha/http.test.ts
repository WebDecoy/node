/**
 * End-to-end test for the captcha HTTP handler: challenge → solve → verify →
 * token, exercised through the same normalized request/response surface the
 * framework adapters use.
 */

import { createHash } from 'crypto';
import { clientSignals, MemoryClientSignalStore } from '../client-signals';
import { createTestHarness, expectRuleState, request } from '../testing';
import { createCaptchaEndpoints, type CaptchaRequest } from './http';
import type { ChallengeData, PoWSolution } from './types';

const UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36';
const HEADERS = {
  'user-agent': UA,
  accept: 'text/html',
  'accept-language': 'en-US,en;q=0.9',
  'accept-encoding': 'gzip, deflate, br',
};
const HUMAN = {
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
const ENV = {
  automationFlags: { chrome: true, platform: 'MacIntel', plugins: 5 },
  navigator: { platform: 'MacIntel', maxTouchPoints: 0 },
};

function solve(challenge: ChallengeData, signalsHash?: string): PoWSolution {
  const target = '0'.repeat(challenge.difficulty);
  const prefix = signalsHash ? `${challenge.prefix}:${signalsHash}` : challenge.prefix;
  for (let n = 0; ; n++) {
    const hash = createHash('sha256').update(`${prefix}:${n}`).digest('hex');
    if (hash.startsWith(target)) return { challengeId: challenge.id, nonce: n, hash, signalsHash };
  }
}

function req(partial: Partial<CaptchaRequest> & Pick<CaptchaRequest, 'method' | 'pathname'>): CaptchaRequest {
  return { query: {}, headers: { 'user-agent': UA }, ip: '73.15.22.100', ...partial };
}

describe('captcha HTTP endpoints', () => {
  it('returns null for non-captcha paths (middleware falls through)', async () => {
    const { handle } = createCaptchaEndpoints({ secret: 's' });
    expect(await handle(req({ method: 'GET', pathname: '/api/data' }))).toBeNull();
  });

  it('issues a challenge on GET /__webdecoy/challenge', async () => {
    const { handle } = createCaptchaEndpoints({ secret: 's' });
    const res = await handle(req({ method: 'GET', pathname: '/__webdecoy/challenge', query: { siteKey: 'site' } }));
    expect(res?.status).toBe(200);
    const c = res!.body as ChallengeData;
    expect(c.id).toBeTruthy();
    expect(c.sig).toHaveLength(64);
    expect(c.prefix).toContain(c.id);
  });

  it('runs the full challenge → verify → token flow', async () => {
    const endpoints = createCaptchaEndpoints({ secret: 's' });
    const ip = '73.15.22.100';

    const realNow = Date.now();
    const spy = jest.spyOn(Date, 'now').mockReturnValue(realNow);
    let token: string;
    try {
      const cRes = await endpoints.handle(
        req({ method: 'GET', pathname: '/__webdecoy/challenge', query: { siteKey: 'site' }, ip }),
      );
      const challenge = cRes!.body as ChallengeData;
      const solution = solve(challenge);

      spy.mockReturnValue(realNow + 3000); // exceed the too-fast threshold

      const vRes = await endpoints.handle(
        req({
          method: 'POST',
          pathname: '/__webdecoy/verify',
          ip,
          headers: HEADERS,
          body: {
            siteKey: 'site',
            signals: { behavioral: HUMAN, environmental: ENV, meta: { challengeNonce: challenge.nonce } },
            powSolution: solution,
          },
        }),
      );

      expect(vRes?.status).toBe(200);
      const verdict = vRes!.body as { success: boolean; token: string | null; recommendation: string };
      expect(verdict.success).toBe(true);
      expect(verdict.recommendation).toBe('allow');
      expect(verdict.token).toBeTruthy();
      token = verdict.token!;
    } finally {
      spy.mockRestore();
    }

    const tRes = await endpoints.handle(
      req({ method: 'POST', pathname: '/__webdecoy/token/verify', ip, body: { token } }),
    );
    expect((tRes!.body as { valid: boolean }).valid).toBe(true);
  });

  it.each(['verify', 'score'])('applies route-specific interaction checks on /%s', async (route) => {
    const signalStore = new MemoryClientSignalStore();
    const { captcha, handle } = createCaptchaEndpoints({ secret: 's', signalStore });
    const ip = '73.15.22.100';
    const now = Date.now();
    const clock = jest.spyOn(Date, 'now').mockReturnValue(now);
    try {
      const challenge = await captcha.issueChallenge('site', ip, 2);
      clock.mockReturnValue(now + 90_000);
      const res = await handle(
        req({
          method: 'POST',
          pathname: '/__webdecoy/' + route,
          ip,
          headers: HEADERS,
          body: {
            siteKey: 'site',
            action: 'login',
            sessionId: 'scroll-session',
            powSolution: solve(challenge),
            signals: {
              behavioral: {
                ...HUMAN,
                interactionDuration: 90_000,
                scrollMorphology: { samples: 3, maxStep: 680 },
              },
              environmental: ENV,
              meta: { challengeNonce: challenge.nonce, invisible: true },
            },
          },
        }),
      );

      expect(res?.status).toBe(200);
      expect(res?.body).toMatchObject({
        success: true,
        token: expect.any(String),
        observations: [{
          id: 'large-scroll-step-v1',
          mode: 'observe',
          status: 'detected',
          samples: 3,
          maxStep: 680,
        }],
      });
      if (route === 'verify') {
        expect(res?.body).toMatchObject({
          detections: expect.arrayContaining([
            expect.objectContaining({ reason: 'Unusually long interaction time' }),
          ]),
        });
      } else {
        expect(res?.body).toMatchObject({ action: 'login', score: 0 });
        expect(signalStore.get('scroll-session')).toEqual({
          sessionId: 'scroll-session',
          score: 0,
          recommendation: 'allow',
          at: now + 90_000,
        });
      }
    } finally {
      clock.mockRestore();
    }
  });

  it('connects a verified invisible score to the next request with a scoped receipt', async () => {
    const host = 'captcha.example.test';
    const ip = '203.0.113.9';
    const signalStore = new MemoryClientSignalStore({ ttl: 3_600_000 });
    const { captcha, handle } = createCaptchaEndpoints({ secret: 'test-secret', signalStore });
    const rule = clientSignals({ store: signalStore, siteKey: 'site' });
    const dryRun = clientSignals({ store: signalStore, siteKey: 'site', minScore: 0, dryRun: true });
    const sdk = createTestHarness({ rules: [rule] });
    const dryRunSdk = createTestHarness({ rules: [dryRun] });
    const now = Date.now();
    const clock = jest.spyOn(Date, 'now').mockReturnValue(now);

    try {
      const challenge = await captcha.issueChallenge('site', ip, 2);
      const signalsJson = JSON.stringify({
        behavioral: HUMAN,
        environmental: ENV,
        meta: { sessionId: 'browser-session', challengeNonce: challenge.nonce },
      });
      const signalsHash = createHash('sha256').update(signalsJson).digest('hex');
      clock.mockReturnValue(now + 3000);
      const res = await handle(req({
        method: 'POST',
        pathname: '/__webdecoy/score',
        ip,
        headers: { ...HEADERS, host, origin: 'https://' + host },
        body: { siteKey: 'site', action: 'login', signalsJson, powSolution: solve(challenge, signalsHash) },
      }));

      expect(res?.body).toMatchObject({ success: true, action: 'login', sessionId: null });
      expect(res?.headers['cache-control']).toBe('private, no-store');
      const cookie = res?.headers['set-cookie'] ?? '';
      expect(cookie).toMatch(/^__Host-wd_cs=[a-f0-9]{48}; Path=\/; Max-Age=900; Secure; HttpOnly; SameSite=Lax$/);
      const receipt = cookie.split(';')[0];
      const followup = request({ ip, headers: { host, cookie: receipt } });

      expectRuleState(await sdk.protect(followup), 'client-signals', 'RUN');
      const monitored = await dryRunSdk.protect(followup);
      expectRuleState(monitored, 'client-signals', 'DRY_RUN');
      expect(JSON.stringify(monitored)).not.toContain(receipt.split('=')[1]);

      const otherHost = request({ ip, headers: { host: 'other.example.test', cookie: receipt } });
      expectRuleState(await sdk.protect(otherHost), 'client-signals', 'NOT_RUN');
      expectRuleState(await sdk.protect(request({ ip, headers: { host } })), 'client-signals', 'NOT_RUN');

      const wrongSite = createTestHarness({ rules: [clientSignals({ store: signalStore, siteKey: 'other' })] });
      expectRuleState(await wrongSite.protect(followup), 'client-signals', 'NOT_RUN');

      clock.mockReturnValue(now + 903_000);
      expect(signalStore.size).toBe(1);
      expectRuleState(await sdk.protect(followup), 'client-signals', 'NOT_RUN');
    } finally {
      clock.mockRestore();
    }
  });

  it('omits the receipt when there is no verified browser proof', async () => {
    const signalStore = new MemoryClientSignalStore();
    const { handle } = createCaptchaEndpoints({ secret: 'test-secret', signalStore });
    const res = await handle(req({
      method: 'POST',
      pathname: '/__webdecoy/score',
      headers: { ...HEADERS, host: 'captcha.example.test', origin: 'https://captcha.example.test' },
      body: { siteKey: 'site', signals: { behavioral: HUMAN, environmental: ENV } },
    }));
    expect(res?.headers).not.toHaveProperty('set-cookie');
    expect(signalStore.size).toBe(0);
  });

  it('400s a token verify with no token', async () => {
    const { handle } = createCaptchaEndpoints({ secret: 's' });
    const res = await handle(req({ method: 'POST', pathname: '/__webdecoy/token/verify', body: {} }));
    expect(res?.status).toBe(400);
  });

  it('honors a custom basePath', async () => {
    const { handle } = createCaptchaEndpoints({ secret: 's', basePath: '/_cap' });
    const res = await handle(req({ method: 'GET', pathname: '/_cap/challenge' }));
    expect(res?.status).toBe(200);
    expect(await handle(req({ method: 'GET', pathname: '/__webdecoy/challenge' }))).toBeNull();
  });
});
