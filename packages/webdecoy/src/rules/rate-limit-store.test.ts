import { WebDecoy } from '../sdk';
import { rateLimit } from './index';
import { MemoryRateLimitStore, type RateLimitStore } from './rate-limit-store';
import { UpstashRateLimitStore } from './upstash-store';
import type { RequestMetadata } from '../types';

const req = (over: Partial<RequestMetadata> = {}): RequestMetadata => ({
  method: 'GET',
  path: '/',
  ip: '203.0.113.9',
  headers: {},
  timestamp: Date.now(),
  ...over,
});

/**
 * A shared async store, standing in for Redis. Two SDK instances pointed at one
 * of these is the whole point of the feature: the limit has to be one limit.
 */
function sharedStore(): RateLimitStore & { calls: number } {
  const counts = new Map<string, number>();
  return {
    sync: false,
    calls: 0,
    async consume({ key, max, windowMs }) {
      this.calls++;
      await Promise.resolve();
      const current = (counts.get(key) ?? 0) + 1;
      counts.set(key, current);
      return { allowed: current <= max, current, resetAt: Date.now() + windowMs };
    },
  };
}

describe('the default in-memory store', () => {
  it('still limits synchronously, unchanged', async () => {
    const wd = new WebDecoy({ rules: [rateLimit({ max: 2, window: 60, action: 'DENY' })] });
    const statuses = [
      (await wd.protect(req())).allowed,
      (await wd.protect(req())).allowed,
      (await wd.protect(req())).allowed,
    ];
    expect(statuses).toEqual([true, true, false]);
  });

  it('is what you get when no store is configured', () => {
    const store = new MemoryRateLimitStore();
    expect(store.sync).toBe(true);
    const first = store.consume({ key: 'k', max: 1, windowMs: 1000, algorithm: 'fixed' });
    const second = store.consume({ key: 'k', max: 1, windowMs: 1000, algorithm: 'fixed' });
    expect(first.allowed).toBe(true);
    expect(second.allowed).toBe(false);
  });
});

describe('a shared async store', () => {
  it('enforces one limit across two SDK instances', async () => {
    // This is the bug: before, each replica had its own Map, so `max: 2` across
    // two processes was a limit of four.
    const store = sharedStore();
    const a = new WebDecoy({ rules: [rateLimit({ max: 2, window: 60, action: 'DENY', store })] });
    const b = new WebDecoy({ rules: [rateLimit({ max: 2, window: 60, action: 'DENY', store })] });

    expect((await a.protect(req())).allowed).toBe(true);
    expect((await b.protect(req())).allowed).toBe(true);
    expect((await a.protect(req())).allowed).toBe(false);
    expect((await b.protect(req())).allowed).toBe(false);
  });

  it('consumes exactly once per request', async () => {
    // prepare() consumes and evaluate() reads what it left. A second consume in
    // evaluate would double-count every request and halve the effective limit.
    const store = sharedStore();
    const wd = new WebDecoy({ rules: [rateLimit({ max: 10, window: 60, store })] });
    await wd.protect(req());
    await wd.protect(req());
    expect(store.calls).toBe(2);
  });

  it('honours characteristics through the shared store', async () => {
    const store = sharedStore();
    const wd = new WebDecoy({
      characteristics: [(c) => c.headers['x-api-key']],
      rules: [rateLimit({ max: 1, window: 60, action: 'DENY', store })],
    });
    expect((await wd.protect(req({ headers: { 'x-api-key': 'a' } }))).allowed).toBe(true);
    expect((await wd.protect(req({ headers: { 'x-api-key': 'b' } }))).allowed).toBe(true);
    expect((await wd.protect(req({ headers: { 'x-api-key': 'a' } }))).allowed).toBe(false);
  });

  it('reports NOT_RUN rather than allowing silently when never prepared', () => {
    // The synchronous entry point cannot consume a networked store. Allowing
    // quietly would look identical to a limiter that is working.
    const wd = new WebDecoy({ rules: [rateLimit({ max: 1, window: 60, store: sharedStore() })] });
    const result = wd.evaluateRules({
      method: 'GET',
      path: '/',
      ip: '203.0.113.9',
      headers: {},
      timestamp: Date.now(),
    });
    expect(result?.results[0].state).toBe('NOT_RUN');
    expect(result?.action).toBe('ALLOW');
  });
});

describe('the Upstash store', () => {
  const options = { url: 'https://example.upstash.io', token: 'tok' };
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
    jest.restoreAllMocks();
  });

  function mockPipeline(results: unknown[], ok = true) {
    const spy = jest.fn(async (_url: string, _init: RequestInit) => ({
      ok,
      status: ok ? 200 : 500,
      json: async () => results.map((result) => ({ result })),
    }));
    globalThis.fetch = spy as unknown as typeof fetch;
    return spy;
  }

  it('rejects construction without credentials', () => {
    expect(() => new UpstashRateLimitStore({ url: '', token: 't' })).toThrow(/url/);
    expect(() => new UpstashRateLimitStore({ url: 'u', token: '' })).toThrow(/token/);
  });

  it('increments a window-scoped key and sets its TTL only once', async () => {
    const spy = mockPipeline([1, 1]);
    const store = new UpstashRateLimitStore(options);
    const out = await store.consume({ key: 'k', max: 5, windowMs: 60_000, algorithm: 'fixed' });

    expect(out).toMatchObject({ allowed: true, current: 1 });
    const body = JSON.parse(spy.mock.calls[0][1].body as string);
    expect(body[0][0]).toBe('INCR');
    // The window id is in the key, so expiry is the only cleanup needed and two
    // processes cannot disagree about which window they are in.
    expect(body[0][1]).toMatch(/^wd:rl:f:k:\d+$/);
    // NX, or a long window gets extended into a sliding one by later requests.
    expect(body[1]).toEqual(['EXPIRE', body[0][1], '60', 'NX']);
  });

  it('denies once the count passes max', async () => {
    mockPipeline([6, 0]);
    const store = new UpstashRateLimitStore(options);
    const out = await store.consume({ key: 'k', max: 5, windowMs: 60_000, algorithm: 'fixed' });
    expect(out.allowed).toBe(false);
    expect(out.current).toBe(6);
  });

  it('gives each sliding-window request a distinct member', async () => {
    const spy = mockPipeline([0, 1, 1, 1]);
    const store = new UpstashRateLimitStore(options);
    await store.consume({ key: 'k', max: 5, windowMs: 1000, algorithm: 'sliding' });
    await store.consume({ key: 'k', max: 5, windowMs: 1000, algorithm: 'sliding' });

    const member = (call: number) =>
      JSON.parse(spy.mock.calls[call][1].body as string)[1][3];
    // Two requests in the same millisecond must be two entries. One ZADD that
    // overwrites the other undercounts exactly when the limit matters.
    expect(member(0)).not.toBe(member(1));
  });

  it('fails open by default when Redis is unreachable', async () => {
    globalThis.fetch = (async () => {
      throw new Error('ECONNREFUSED');
    }) as unknown as typeof fetch;
    const store = new UpstashRateLimitStore(options);
    const out = await store.consume({ key: 'k', max: 1, windowMs: 1000, algorithm: 'fixed' });
    expect(out.allowed).toBe(true);
  });

  it('fails closed when asked to', async () => {
    globalThis.fetch = (async () => {
      throw new Error('ECONNREFUSED');
    }) as unknown as typeof fetch;
    const store = new UpstashRateLimitStore({ ...options, onError: 'closed' });
    const out = await store.consume({ key: 'k', max: 1, windowMs: 1000, algorithm: 'fixed' });
    expect(out.allowed).toBe(false);
  });

  it('treats a command-level error as a failure, not a zero count', async () => {
    globalThis.fetch = (async () => ({
      ok: true,
      status: 200,
      json: async () => [{ error: 'WRONGTYPE' }],
    })) as unknown as typeof fetch;
    const store = new UpstashRateLimitStore({ ...options, onError: 'closed' });
    const out = await store.consume({ key: 'k', max: 1, windowMs: 1000, algorithm: 'fixed' });
    expect(out.allowed).toBe(false);
  });

  it('trims a trailing slash off the url', async () => {
    const spy = mockPipeline([1, 1]);
    const store = new UpstashRateLimitStore({ ...options, url: 'https://example.upstash.io/' });
    await store.consume({ key: 'k', max: 5, windowMs: 1000, algorithm: 'fixed' });
    expect(spy.mock.calls[0][0]).toBe('https://example.upstash.io/pipeline');
  });
});
