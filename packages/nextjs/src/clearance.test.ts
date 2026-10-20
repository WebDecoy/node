import { NextRequest } from 'next/server';
import { withClearance } from './clearance';
import { getEdgeVerdict } from './edge-verdict';

/**
 * withClearance: the gate's decision is @webdecoy/node's and tested there.
 * What is tested here is what the application and the visitor receive.
 */

const ENV = { siteKey: 'org-1', scannerId: 'scanner-1', sensorKey: 'wds1.test' };
const BROWSER_UA =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36';

const CONFIG = {
  mode: 'enforce',
  allow: { search_engines: true, ai_crawlers: true, monitoring: true },
  keys: [],
  active_credentials: [],
  denied_fps: [],
  generated_at: 0,
  routes: ['/docs/*'],
};

const realFetch = global.fetch;
let hosts = 0;
const site = () => `https://next${++hosts}.example`;

beforeEach(() => {
  global.fetch = jest.fn(async (input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    return url.includes('/api/v1/clearance/config')
      ? new Response(JSON.stringify(CONFIG), { status: 200 })
      : new Response('{}', { status: 200 });
  }) as unknown as typeof fetch;
});

// The gate's verdict telemetry schedules a delayed flush; let timers advance
// on their own, and clear what is left so it cannot hold jest open.
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

describe('withClearance', () => {
  it('challenges a protected page without a token, before the page renders', async () => {
    const res = await withClearance(ENV)(
      new NextRequest(`${site()}/docs/guide`, { headers: { accept: 'text/html', 'user-agent': BROWSER_UA } })
    );
    expect(res.status).toBe(403);
    expect(res.headers.get('x-middleware-next')).toBeNull();
    expect(await res.text()).toContain('wd_clearance');
  });

  it('hands the page the verdict, readable with getEdgeVerdict', async () => {
    const res = await withClearance(ENV)(
      new NextRequest(`${site()}/pricing`, {
        headers: { 'user-agent': BROWSER_UA, 'x-wd-clearance': 'valid' },
      })
    );
    expect(res.headers.get('x-middleware-next')).toBe('1');
    const forwarded = new Headers();
    for (const name of (res.headers.get('x-middleware-override-headers') ?? '').split(',')) {
      forwarded.set(name, res.headers.get(`x-middleware-request-${name}`) ?? '');
    }
    // The client's forged "valid" is gone; the gate's own verdict is there.
    expect(getEdgeVerdict(forwarded).clearance).toBe('unscoped');
    expect(forwarded.get('user-agent')).toBe(BROWSER_UA);
    // And the verdict is not sent back to the visitor.
    expect(res.headers.get('x-wd-clearance')).toBeNull();
  });

  it('fails open when WebDecoy cannot be reached', async () => {
    global.fetch = jest.fn(async () => {
      throw new Error('down');
    }) as unknown as typeof fetch;
    const res = await withClearance(ENV)(
      new NextRequest(`${site()}/docs/guide`, { headers: { accept: 'text/html', 'user-agent': BROWSER_UA } })
    );
    expect(res.status).toBe(200);
    expect(res.headers.get('x-middleware-next')).toBe('1');
  });
});
