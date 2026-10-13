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
