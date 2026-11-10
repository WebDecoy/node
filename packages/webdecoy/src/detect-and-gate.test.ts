/**
 * Detection and the clearance gate in one Vercel middleware.
 *
 * The gate's decision and detection's scoring are tested where they are
 * written. What is tested here is the combination: the default export reports
 * with an API key and is the plain gate without one, a refusal still carries
 * the match key that ties it to the detection of the same request, and nothing
 * throws whatever the environment holds.
 */

import { createHash } from 'crypto';
import middleware, { createVercelMiddleware, clearanceMiddleware } from './vercel';
import { createDetectAndGate } from './detect-and-gate';
import { TEST_TRIGGER_USER_AGENT } from './test-trigger';

const GATE = { siteKey: 'org-1', scannerId: 'scanner-1', sensorKey: 'wds1.test' };
const API_KEY = 'sk_test_combined';
const BROWSER_UA =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36';
const BROWSER_HEADERS = {
  accept: 'text/html',
  'accept-language': 'en-US',
  'accept-encoding': 'gzip',
  'sec-ch-ua': '"Chromium";v="141"',
  'user-agent': BROWSER_UA,
};

const CONFIG = (mode: 'monitor' | 'enforce') => ({
  mode,
  allow: { search_engines: true, ai_crawlers: true, monitoring: true },
  keys: [],
  active_credentials: [],
  denied_fps: [],
  generated_at: 0,
  routes: ['/docs/*'],
});

interface Call {
  url: string;
  body: any;
}

let hosts = 0;
const site = () => `https://combined${++hosts}.example`;
const realFetch = global.fetch;
const ENV_NAMES = ['WEBDECOY_API_KEY', 'WEBDECOY_SITE_KEY', 'WEBDECOY_SCANNER_ID', 'WEBDECOY_SENSOR_KEY'];

/** Stub WebDecoy: clearance config, the detect endpoint and telemetry, recording every call. */
function stubWebDecoy(mode: 'monitor' | 'enforce' = 'monitor', detection: Record<string, unknown> = {}): Call[] {
  const calls: Call[] = [];
  global.fetch = jest.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    let body: any;
    try {
      body = init?.body ? JSON.parse(String(init.body)) : undefined;
    } catch {
      body = undefined;
    }
    calls.push({ url, body });
    if (url.includes('/api/v1/clearance/config')) return new Response(JSON.stringify(CONFIG(mode)), { status: 200 });
    if (url.includes('/api/v1/sdk/detect')) {
      return new Response(
        JSON.stringify({
          decision: 'block',
          confidence: 100,
          threat_level: 'HIGH',
          bot_detected: true,
          detection_id: 'det-1',
          rule_enforced: false,
          ...detection,
        }),
        { status: 200 }
      );
    }
    return new Response('{}', { status: 200 });
  }) as unknown as typeof fetch;
  return calls;
}

const detectCalls = (calls: Call[]) => calls.filter((c) => c.url.includes('/api/v1/sdk/detect'));

/** The request headers Vercel would hand the page, decoded from the middleware's instructions. */
function forwarded(res: Response | undefined): Headers {
  expect(res?.headers.get('x-middleware-next')).toBe('1');
  const out = new Headers();
  for (const name of (res!.headers.get('x-middleware-override-headers') ?? '').split(',').filter(Boolean)) {
    out.set(name, res!.headers.get(`x-middleware-request-${name}`) ?? '');
  }
  return out;
}

function setEnv(values: Record<string, string>) {
  for (const [k, v] of Object.entries(values)) process.env[k] = v;
}

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

describe('@webdecoy/node/vercel default export', () => {
  it('reports the test trigger as a test detection when WEBDECOY_API_KEY is set, and still serves it in monitor mode', async () => {
    const calls = stubWebDecoy('monitor');
    setEnv({
      WEBDECOY_API_KEY: API_KEY,
      WEBDECOY_SITE_KEY: GATE.siteKey,
      WEBDECOY_SCANNER_ID: GATE.scannerId,
      WEBDECOY_SENSOR_KEY: GATE.sensorKey,
    });

    const res = await middleware(new Request(`${site()}/`, { headers: { 'user-agent': TEST_TRIGGER_USER_AGENT } }));

    const reports = detectCalls(calls);
    expect(reports).toHaveLength(1);
    expect(reports[0].body.request_metadata.user_agent).toBe(TEST_TRIGGER_USER_AGENT);
    expect(reports[0].body.local_analysis.flags).toContain('test_trigger');

    // Monitor: served, with the verdict on the request for the application.
    const headers = forwarded(res);
    expect(headers.get('x-webdecoy-would-block')).toBe('true');
    expect(headers.get('x-webdecoy-detection-id')).toBe('det-1');
    // The gate ran too: its verdict is there.
    expect(headers.get('x-wd-clearance')).toBe('unscoped');
  });

  it('reports the test trigger with only WEBDECOY_API_KEY set, gate off', async () => {
    const calls = stubWebDecoy();
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    setEnv({ WEBDECOY_API_KEY: API_KEY });

    const res = await middleware(new Request(`${site()}/`, { headers: { 'user-agent': TEST_TRIGGER_USER_AGENT } }));

    expect(detectCalls(calls)).toHaveLength(1);
    expect(calls.some((c) => c.url.includes('/api/v1/clearance/'))).toBe(false);
    expect(forwarded(res).get('x-webdecoy-would-block')).toBe('true');
    warn.mockRestore();
  });

  it('reports an agent the bot registry names even when it sends browser headers', async () => {
    const calls = stubWebDecoy();
    const ua = `${BROWSER_UA} ChatGPT-User/1.0`;
    const res = await createVercelMiddleware({ ...GATE, apiKey: API_KEY })(
      new Request(`${site()}/blog`, { headers: { ...BROWSER_HEADERS, 'user-agent': ua } })
    );
    expect(detectCalls(calls)).toHaveLength(1);
    expect(detectCalls(calls)[0].body.request_metadata.user_agent).toBe(ua);
    expect(res?.status ?? 200).not.toBe(403);
  });

  it('does not report a plain browser', async () => {
    const calls = stubWebDecoy();
    const res = await createVercelMiddleware({ ...GATE, apiKey: API_KEY })(
      new Request(`${site()}/blog`, { headers: BROWSER_HEADERS })
    );
    expect(detectCalls(calls)).toHaveLength(0);
    expect(forwarded(res).get('x-webdecoy-would-block')).toBe('false');
  });

  it('strips inbound copies of the detection headers', async () => {
    stubWebDecoy();
    const res = await createVercelMiddleware({ ...GATE, apiKey: API_KEY })(
      new Request(`${site()}/blog`, {
        headers: { ...BROWSER_HEADERS, 'x-webdecoy-would-block': 'false', 'x-webdecoy-detection-id': 'forged' },
      })
    );
    const headers = forwarded(res);
    expect(headers.get('x-webdecoy-detection-id')).not.toBe('forged');
    expect(headers.get('x-webdecoy-would-block')).toBe('false');
  });

  it('without WEBDECOY_API_KEY is exactly the clearance gate: same response, nothing reported', async () => {
    const calls = stubWebDecoy('enforce');
    const host = site();
    const make = () =>
      new Request(`${host}/docs/start`, { headers: { accept: 'text/html', 'user-agent': TEST_TRIGGER_USER_AGENT } });

    const combined = await createVercelMiddleware(GATE)(make());
    const gateOnly = await clearanceMiddleware(GATE)(make());

    expect(detectCalls(calls)).toHaveLength(0);
    expect(combined?.status).toBe(gateOnly?.status);
    expect(combined?.status).toBe(403);
    expect(await combined?.text()).toBe(await gateOnly?.text());
  });

  it('without any environment fails open and never throws', async () => {
    const calls = stubWebDecoy();
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    const res = await middleware(
      new Request(`${site()}/docs/start`, { headers: { 'user-agent': TEST_TRIGGER_USER_AGENT } })
    );
    expect(res?.status ?? 200).not.toBe(403);
    expect(calls).toHaveLength(0);
    warn.mockRestore();
  });

  it('fails open when WebDecoy is unreachable, with the key set', async () => {
    global.fetch = jest.fn(async () => {
      throw new TypeError('fetch failed');
    }) as unknown as typeof fetch;
    const error = jest.spyOn(console, 'error').mockImplementation(() => undefined);
    const res = await createVercelMiddleware({ ...GATE, apiKey: API_KEY })(
      new Request(`${site()}/docs/start`, { headers: { accept: 'text/html', 'user-agent': 'python-requests/2.31' } })
    );
    expect(res?.status ?? 200).not.toBe(403);
    error.mockRestore();
  });

  it('fails open on a malformed API key, running the gate alone', async () => {
    const calls = stubWebDecoy('enforce');
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    const res = await createVercelMiddleware({ ...GATE, apiKey: 'not-a-key' })(
      new Request(`${site()}/blog`, { headers: { 'user-agent': TEST_TRIGGER_USER_AGENT } })
    );
    expect(detectCalls(calls)).toHaveLength(0);
    expect(forwarded(res).get('x-wd-clearance')).toBe('unscoped');
    warn.mockRestore();
  });

  it('enforce mode answers the test trigger with 403', async () => {
    stubWebDecoy();
    const res = await createVercelMiddleware({ ...GATE, apiKey: API_KEY, mode: 'enforce' })(
      new Request(`${site()}/`, { headers: { 'user-agent': TEST_TRIGGER_USER_AGENT } })
    );
    expect(res?.status).toBe(403);
  });
});

describe('would-block labeling', () => {
  it('a monitor-mode refusal reports the match key of the same client and path the detection reported', async () => {
    const calls = stubWebDecoy('monitor');
    const pending: Promise<unknown>[] = [];
    const host = site();
    const res = await createVercelMiddleware({ ...GATE, apiKey: API_KEY })(
      new Request(`${host}/docs/start?x=1`, {
        headers: { accept: 'text/html', 'user-agent': 'python-requests/2.31', 'x-forwarded-for': '198.51.100.23' },
      }),
      { waitUntil: (p) => pending.push(p) }
    );

    // Monitor: served, labelled missing, reported as would-block by detection.
    const headers = forwarded(res);
    expect(headers.get('x-wd-clearance')).toBe('missing');

    const report = detectCalls(calls)[0].body.request_metadata;
    expect(report.ip).toBe('198.51.100.23');
    expect(report.path).toBe('/docs/start');

    // The gate flushes its verdict telemetry at the end of its time bucket.
    jest.advanceTimersByTime(120_000);
    await Promise.all(pending);

    const telemetry = calls.filter((c) => c.url.includes('/api/v1/clearance/telemetry'));
    const refusals = telemetry.flatMap((c) => c.body?.refusals ?? []);
    const expected = createHash('sha256')
      .update(`${GATE.siteKey}|${report.ip}|${report.path}`)
      .digest('hex')
      .slice(0, 24);
    expect(refusals.map((r: { k: string }) => r.k)).toContain(expected);
  });
});

describe('createDetectAndGate', () => {
  it('returns the detection decision alongside the outcome', async () => {
    stubWebDecoy();
    const { outcome, decision } = await createDetectAndGate({ ...GATE, apiKey: API_KEY })(
      new Request(`${site()}/`, { headers: { 'user-agent': TEST_TRIGGER_USER_AGENT } })
    );
    expect(outcome.action).toBe('continue');
    expect(decision?.allowed).toBe(false);
  });

  it('returns no decision without a key', async () => {
    stubWebDecoy();
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    const { decision } = await createDetectAndGate({})(new Request(`${site()}/`));
    expect(decision).toBeNull();
    warn.mockRestore();
  });
});
