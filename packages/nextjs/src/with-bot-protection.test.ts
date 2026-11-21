import { WebDecoy } from '@webdecoy/node';
import { withBotProtection } from './middleware';

/**
 * withBotProtection ignored `mode` and refused any request protect() did not
 * allow, while every other adapter (and withWebDecoy beside it) monitors by
 * default. A Pages API route wrapped with no mode was blocking on install.
 */

function pagesReq() {
  return {
    method: 'GET',
    url: '/api/protected?x=1',
    headers: { 'user-agent': 'python-requests/2.31.0' },
    socket: { remoteAddress: '203.0.113.7' },
  } as any;
}

function pagesRes() {
  const res: any = { statusCode: 200, body: undefined, headers: {} as Record<string, string> };
  res.status = (code: number) => {
    res.statusCode = code;
    return res;
  };
  res.json = (body: unknown) => {
    res.body = body;
    return res;
  };
  res.setHeader = (name: string, value: string) => {
    res.headers[name] = value;
  };
  return res;
}

const refused = { allowed: false, detection: { detection_id: 'det_1' } } as any;

describe('withBotProtection honours mode', () => {
  let protect: jest.SpyInstance;

  beforeEach(() => {
    protect = jest.spyOn(WebDecoy.prototype, 'protect').mockResolvedValue(refused);
  });
  afterEach(() => protect.mockRestore());

  it('monitors by default: the handler runs and sees what enforce would have done', async () => {
    const handler = jest.fn((_req: any, res: any) => res.status(200).json({ ok: true }));
    const req = pagesReq();
    const res = pagesRes();

    await withBotProtection(handler, { skipLocalAnalysis: true } as any)(req, res);

    expect(handler).toHaveBeenCalledTimes(1);
    expect(res.statusCode).toBe(200);
    expect(req.webdecoyDecision.allowed).toBe(false);
  });

  it('refuses only when mode is enforce', async () => {
    const handler = jest.fn();
    const res = pagesRes();

    await withBotProtection(handler, { skipLocalAnalysis: true, mode: 'enforce' } as any)(pagesReq(), res);

    expect(handler).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
  });
});

describe('withBotProtection unified cloud decisions', () => {
  afterEach(() => jest.restoreAllMocks());

  it.each([
    ['monitor', 200],
    ['enforce', 403],
  ] as const)('uses the ingest decision in %s mode', async (mode, status) => {
    const fetch = jest.spyOn(globalThis, 'fetch').mockImplementation(async () =>
      new Response(JSON.stringify({
        decision_mode: 'unified_v1', unified_score: 70, decision: 'block',
        confidence: 70, threat_level: 'HIGH', bot_detected: true,
        detection_id: 'fixture', rule_enforced: false,
      })),
    );
    const handler = jest.fn((_req, res) => res.status(200).json({ ok: true }));
    const res = pagesRes();
    await withBotProtection(handler, {
      apiKey: 'sk_test_decision_fixture', decisionMode: 'unified_v1', mode,
      rules: [], countAIReferrals: false,
    })(pagesReq(), res);
    expect(res.statusCode).toBe(status);
    expect(handler).toHaveBeenCalledTimes(mode === 'monitor' ? 1 : 0);
    expect(JSON.parse(fetch.mock.calls[0][1]?.body as string).decision_mode).toBe('unified_v1');
  });
});
