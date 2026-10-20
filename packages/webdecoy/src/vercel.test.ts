/**
 * The Vercel clearance middleware, through the bundled gate.
 *
 * The decision itself is tested where it is written, against the vectors all
 * four validators replay. What is tested here is this package's part: the
 * environment, the client IP, Vercel's continue-with-headers protocol, and
 * that a real signed token is honoured and a missing one is challenged.
 */

import { createHash } from 'crypto';
import { readFileSync } from 'fs';
import path from 'path';
import { clearanceMiddleware, toMiddlewareResponse } from './vercel';

const ENV = { siteKey: 'org-1', scannerId: 'scanner-1', sensorKey: 'wds1.test' };
const BROWSER_UA =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36';

function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function signingKey() {
  const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  const mint = async (claims: Record<string, unknown>) => {
    const payload = new TextEncoder().encode(JSON.stringify(claims));
    const sig = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, pair.privateKey, payload));
    return `${b64url(payload)}.${b64url(sig)}`;
  };
  return { publicKey: Buffer.from(raw).toString('base64'), mint };
}

function configWith(keys: { kid: string; public_key: string }[], mode = 'enforce') {
  return {
    mode,
    allow: { search_engines: true, ai_crawlers: true, monitoring: true },
    keys,
    active_credentials: [],
    denied_fps: [],
    generated_at: 0,
    routes: ['/docs/*'],
  };
}

let hosts = 0;
const site = () => `https://site${++hosts}.example`;
const realFetch = global.fetch;

function stubConfig(config: unknown): jest.Mock {
  const fn = jest.fn(async (input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    if (url.includes('/api/v1/clearance/config')) return new Response(JSON.stringify(config), { status: 200 });
    return new Response('{}', { status: 200 });
  });
  global.fetch = fn as unknown as typeof fetch;
  return fn;
}

// Verdict telemetry schedules its flush for the end of a time bucket and keeps
// it alive with waitUntil, which on Vercel outlives the response. Timers that
// advance on their own let every test run in real time; clearing them at the
// end stops a pending flush from holding jest open.
beforeAll(() => {
  jest.useFakeTimers({ advanceTimers: true });
});

afterAll(() => {
  jest.clearAllTimers();
  jest.useRealTimers();
});

afterEach(() => {
  global.fetch = realFetch;
});

/** The request headers Vercel would hand the page, decoded from the middleware's instructions. */
function forwarded(res: Response): Headers {
  expect(res.headers.get('x-middleware-next')).toBe('1');
  const out = new Headers();
  for (const name of (res.headers.get('x-middleware-override-headers') ?? '').split(',').filter(Boolean)) {
    out.set(name, res.headers.get(`x-middleware-request-${name}`) ?? '');
  }
  return out;
}

describe('@webdecoy/node/vercel', () => {
  it('challenges a browser with no token on a protected path in enforce mode', async () => {
    stubConfig(configWith([]));
    const res = await clearanceMiddleware(ENV)(
      new Request(`${site()}/docs/start`, { headers: { accept: 'text/html', 'user-agent': BROWSER_UA } })
    );
    expect(res?.status).toBe(403);
    expect(res?.headers.get('x-middleware-next')).toBeNull();
    expect(await res?.text()).toContain('wd_clearance');
  });

  it('serves the page to a browser holding a valid signed token, and says so', async () => {
    const key = await signingKey();
    stubConfig(configWith([{ kid: 'k1', public_key: key.publicKey }]));
    const token = await key.mint({ kid: 'k1', tenant: 'org-1', fp: 'wdfp1-abc', exp: Math.floor(Date.now() / 1000) + 600 });
    const res = await clearanceMiddleware(ENV)(
      new Request(`${site()}/docs/start`, {
        headers: { accept: 'text/html', 'user-agent': BROWSER_UA, cookie: `wd_clearance=${token}; other=1` },
      })
    );
    expect(res).toBeDefined();
    const headers = forwarded(res!);
    expect(headers.get('x-wd-clearance')).toBe('valid');
    expect(headers.get('cookie')).toContain('other=1');
    expect(headers.get('user-agent')).toBe(BROWSER_UA);
  });

  it('challenges a token signed for another site', async () => {
    const key = await signingKey();
    stubConfig(configWith([{ kid: 'k1', public_key: key.publicKey }]));
    const token = await key.mint({ kid: 'k1', tenant: 'org-2', fp: 'wdfp1-abc', exp: Math.floor(Date.now() / 1000) + 600 });
    const res = await clearanceMiddleware(ENV)(
      new Request(`${site()}/docs/start`, { headers: { accept: 'application/json', cookie: `wd_clearance=${token}` } })
    );
    expect(res?.status).toBe(403);
    expect(await res?.json()).toMatchObject({ challenge: { reason: 'invalid' } });
  });

  it('lets everything through in monitor mode, labelled', async () => {
    stubConfig(configWith([], 'monitor'));
    const res = await clearanceMiddleware(ENV)(
      new Request(`${site()}/docs/start`, { headers: { accept: 'text/html', 'user-agent': BROWSER_UA } })
    );
    expect(forwarded(res!).get('x-wd-clearance')).toBe('missing');
  });

  it('strips a forged verdict before the page can read it', async () => {
    stubConfig(configWith([]));
    const res = await clearanceMiddleware(ENV)(
      new Request(`${site()}/pricing`, { headers: { 'x-wd-clearance': 'valid', 'x-wd-class': 'verified' } })
    );
    const headers = forwarded(res!);
    expect(headers.get('x-wd-clearance')).toBe('unscoped');
    expect(headers.has('x-wd-class')).toBe(false);
  });

  it('is a pass-through, not an unproven gate, without its configuration', async () => {
    const fetchMock = stubConfig(configWith([]));
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    const res = await clearanceMiddleware({ siteKey: '', scannerId: '', sensorKey: '' })(
      new Request(`${site()}/docs/start`, { headers: { accept: 'text/html', 'x-wd-clearance': 'valid' } })
    );
    expect(res?.status).not.toBe(403);
    expect(forwarded(res!).has('x-wd-clearance')).toBe(false);
    expect(fetchMock).not.toHaveBeenCalled();
    warn.mockRestore();
  });

  it('reads its identity from WEBDECOY_* when no options are given', async () => {
    stubConfig(configWith([]));
    process.env.WEBDECOY_SITE_KEY = 'org-1';
    process.env.WEBDECOY_SCANNER_ID = 'scanner-1';
    process.env.WEBDECOY_SENSOR_KEY = 'wds1.test';
    try {
      const res = await clearanceMiddleware()(
        new Request(`${site()}/docs/start`, { headers: { accept: 'text/html', 'user-agent': BROWSER_UA } })
      );
      expect(res?.status).toBe(403);
    } finally {
      delete process.env.WEBDECOY_SITE_KEY;
      delete process.env.WEBDECOY_SCANNER_ID;
      delete process.env.WEBDECOY_SENSOR_KEY;
    }
  });

  it('fails open when WebDecoy is unreachable', async () => {
    global.fetch = jest.fn(async () => {
      throw new Error('down');
    }) as unknown as typeof fetch;
    const res = await clearanceMiddleware(ENV)(
      new Request(`${site()}/docs/start`, { headers: { accept: 'text/html', 'user-agent': BROWSER_UA } })
    );
    expect(res?.status ?? 200).not.toBe(403);
  });

  it('continues untouched when the gate has no headers to set', () => {
    expect(toMiddlewareResponse({ action: 'continue', headers: null, verdict: null })).toBeUndefined();
  });
});

describe('the generated gate', () => {
  it('is exactly what the validator source built, not a hand edit', () => {
    const file = readFileSync(path.join(__dirname, 'clearance', 'gate.generated.js'), 'utf8');
    const stamp = /\/\/ Build (vercel-[0-9a-f]{12})\./.exec(file)?.[1];
    expect(stamp).toBeDefined();
    const body = file.split('\n').slice(2).join('\n');
    const original = body.split(stamp!).join('__WD_VERCEL_BUILD__');
    const hash = 'vercel-' + createHash('sha256').update(original).digest('hex').slice(0, 12);
    expect(hash).toBe(stamp);
  });
});
