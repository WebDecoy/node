/**
 * End-to-end test for the captcha HTTP handler: challenge → solve → verify →
 * token, exercised through the same normalized request/response surface the
 * framework adapters use.
 */

import { createHash } from 'crypto';
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

function solve(challenge: ChallengeData): PoWSolution {
  const target = '0'.repeat(challenge.difficulty);
  for (let n = 0; ; n++) {
    const hash = createHash('sha256').update(`${challenge.prefix}:${n}`).digest('hex');
    if (hash.startsWith(target)) return { challengeId: challenge.id, nonce: n, hash };
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

  it('scores in invisible mode on POST /__webdecoy/score', async () => {
    const { handle } = createCaptchaEndpoints({ secret: 's' });
    const res = await handle(
      req({
        method: 'POST',
        pathname: '/__webdecoy/score',
        headers: HEADERS,
        body: { siteKey: 'site', action: 'login', signals: { behavioral: HUMAN, environmental: ENV } },
      }),
    );
    expect(res?.status).toBe(200);
    expect((res!.body as { action: string }).action).toBe('login');
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
