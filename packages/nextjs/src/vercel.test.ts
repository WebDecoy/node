import { NextRequest } from 'next/server';
import middleware, { createVercelMiddleware } from './vercel';
import { getEdgeVerdict } from './edge-verdict';

/**
 * @webdecoy/nextjs/vercel: detection and the clearance gate from the
 * environment. The combination is @webdecoy/node's and tested there; what is
 * tested here is what the Next.js application and the visitor receive.
 */

const ENV_NAMES = ['WEBDECOY_API_KEY', 'WEBDECOY_SITE_KEY', 'WEBDECOY_SCANNER_ID', 'WEBDECOY_SENSOR_KEY'];
const ENV = {
  WEBDECOY_API_KEY: 'sk_test_next',
  WEBDECOY_SITE_KEY: 'org-1',
  WEBDECOY_SCANNER_ID: 'scanner-1',
  WEBDECOY_SENSOR_KEY: 'wds1.test',
};

const CONFIG = {
  mode: 'monitor',
  allow: { search_engines: true, ai_crawlers: true, monitoring: true },
  keys: [],
  active_credentials: [],
  denied_fps: [],
  generated_at: 0,
  routes: ['/docs/*'],
};

const realFetch = global.fetch;
let hosts = 0;
const site = () => `https://nextvercel${++hosts}.example`;
let calls: string[] = [];

beforeEach(() => {
  calls = [];
  global.fetch = jest.fn(async (input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    calls.push(url);
    if (url.includes('/api/v1/clearance/config')) return new Response(JSON.stringify(CONFIG), { status: 200 });
    if (url.includes('/api/v1/sdk/detect')) {
      return new Response(
        JSON.stringify({ decision: 'block', confidence: 100, threat_level: 'HIGH', bot_detected: true, detection_id: 'det-n' }),
        { status: 200 }
      );
    }
    return new Response('{}', { status: 200 });
  }) as unknown as typeof fetch;
});

beforeAll(() => {
  jest.useFakeTimers({ advanceTimers: true });
});

afterAll(() => {
  jest.clearAllTimers();
  jest.useRealTimers();
});

afterEach(() => {
  global.fetch = realFetch;
  for (const name of ENV_NAMES) delete process.env[name];
});

function forwarded(res: Response): Headers {
  expect(res.headers.get('x-middleware-next')).toBe('1');
  const out = new Headers();
  for (const name of (res.headers.get('x-middleware-override-headers') ?? '').split(',').filter(Boolean)) {
    out.set(name, res.headers.get(`x-middleware-request-${name}`) ?? '');
  }
  return out;
}

describe('@webdecoy/nextjs/vercel', () => {
  it('the default export reports WebDecoy-Test/1.0 from env and labels the would-block verdict', async () => {
    Object.assign(process.env, ENV);
    const res = await middleware(
      new NextRequest(`${site()}/docs/start`, { headers: { accept: 'text/html', 'user-agent': 'WebDecoy-Test/1.0' } })
    );
    expect(calls.filter((u) => u.includes('/api/v1/sdk/detect'))).toHaveLength(1);
    const headers = forwarded(res);
    expect(headers.get('x-webdecoy-would-block')).toBe('true');
    expect(headers.get('x-webdecoy-detection-id')).toBe('det-n');
    // The gate ran on the same request: a protected path with no token, monitor mode.
    expect(getEdgeVerdict(headers).clearance).toBe('missing');
    // Neither verdict is sent back to the visitor.
    expect(res.headers.get('x-wd-clearance')).toBeNull();
    expect(res.headers.get('x-webdecoy-would-block')).toBeNull();
  });

  it('fails open and never throws with no environment at all', async () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    const res = await middleware(
      new NextRequest(`${site()}/docs/start`, { headers: { 'user-agent': 'WebDecoy-Test/1.0' } })
    );
    expect(res.status).not.toBe(403);
    expect(calls).toHaveLength(0);
    warn.mockRestore();
  });

  it('without WEBDECOY_API_KEY runs the gate alone and reports nothing', async () => {
    Object.assign(process.env, { ...ENV, WEBDECOY_API_KEY: '' });
    const res = await middleware(new NextRequest(`${site()}/docs/start`, { headers: { accept: 'text/html' } }));
    expect(calls.some((u) => u.includes('/api/v1/sdk/detect'))).toBe(false);
    expect(forwarded(res).get('x-wd-clearance')).toBe('missing');
  });

  it('createVercelMiddleware takes options instead of the environment', async () => {
    const res = await createVercelMiddleware({
      apiKey: ENV.WEBDECOY_API_KEY,
      siteKey: 'org-1',
      scannerId: 'scanner-1',
      sensorKey: 'wds1.test',
      mode: 'enforce',
    })(new NextRequest(`${site()}/`, { headers: { 'user-agent': 'WebDecoy-Test/1.0' } }));
    expect(res.status).toBe(403);
  });

  it('fails open when WebDecoy is unreachable', async () => {
    Object.assign(process.env, ENV);
    global.fetch = jest.fn(async () => {
      throw new TypeError('fetch failed');
    }) as unknown as typeof fetch;
    const error = jest.spyOn(console, 'error').mockImplementation(() => undefined);
    const res = await middleware(
      new NextRequest(`${site()}/docs/start`, { headers: { 'user-agent': 'python-requests/2.31' } })
    );
    expect(res.status).not.toBe(403);
    error.mockRestore();
  });
});
