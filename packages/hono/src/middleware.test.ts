import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { Hono } from 'hono';
import { tripwire, rateLimit } from '@webdecoy/node';
import { webdecoy } from './index';

/**
 * The Hono adapter, exercised through a real app.
 *
 * Hono runs on Workers, Bun and Deno, so these use `app.request()` — the same
 * fetch-shaped entry point those runtimes call — rather than standing up a
 * server.
 */
function appWith(options: Parameters<typeof webdecoy>[0] = {}) {
  const app = new Hono();
  app.use('*', webdecoy({ mode: 'enforce', rules: [tripwire()], ...options }));
  app.get('/', (c) => c.text('ok'));
  app.get('/health', (c) => c.text('healthy'));
  app.get('/page', (c) => c.html('<html><body><h1>hi</h1></body></html>'));
  app.get('/api', (c) => c.json({ ok: true }));
  return app;
}

describe('the Hono middleware', () => {
  it('serves an ordinary request', async () => {
    const res = await appWith().request('/');
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('ok');
  });

  it('blocks a tripwire hit with 403', async () => {
    const res = await appWith().request('/.env');
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ error: 'Forbidden' });
  });

  it('answers a rate-limit denial with 429 and Retry-After', async () => {
    const app = appWith({ rules: [rateLimit({ max: 1, window: 60 })] });
    expect((await app.request('/')).status).toBe(200);
    const limited = await app.request('/');
    expect(limited.status).toBe(429);
    expect(limited.headers.get('retry-after')).toBeTruthy();
  });

  it('skips the paths it was told to skip', async () => {
    const res = await appWith({ skipPaths: ['/health'] }).request('/health');
    expect(res.status).toBe(200);
  });

  it('serves the request in monitor mode, which is the default', async () => {
    const app = new Hono();
    app.use('*', webdecoy({ rules: [tripwire()] }));
    app.get('/.env', (c) => c.text('served'));

    const res = await app.request('/.env');
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('served');
  });

  it('exposes the decision on the context even when it allows', async () => {
    // In monitor mode this is the only place the verdict surfaces, and monitor
    // is the default.
    const app = new Hono();
    app.use('*', webdecoy({ rules: [tripwire()] }));
    app.get('/.env', (c) => c.json({ denied: c.get('webdecoy')?.deniedBy('tripwire') ?? null }));

    expect(await (await app.request('/.env')).json()).toEqual({ denied: true });
  });

  it('lets onBlocked shape the response', async () => {
    const app = appWith({
      onBlocked: (c, decision) => c.text(`nope: ${decision.reason ?? ''}`, 418),
    });
    const res = await app.request('/.env');
    expect(res.status).toBe(418);
    expect(await res.text()).toMatch(/^nope:/);
  });

  it('sees the query string, so attack signatures can match on it', async () => {
    const { attackSignatures } = await import('@webdecoy/node');
    const app = appWith({ rules: [attackSignatures()] });
    expect((await app.request('/?x=${jndi:ldap://evil/a}')).status).toBe(403);
    expect((await app.request('/?q=coffee%20or%20tea')).status).toBe(200);
  });
});

describe('honeytoken injection through Hono', () => {
  const withKey = { apiKey: 'sk_live_hono_test', skipLocalAnalysis: true, mode: 'monitor' as const };
  const realFetch = global.fetch;

  /**
   * The stable trap derives through async WebCrypto. Cold-start requests are
   * deliberately allowed before it is ready, so wait for the observable
   * contract instead of assuming a loaded CI runner finishes HMAC in 50 ms.
   */
  async function requestUntilInjected(app: ReturnType<typeof appWith>) {
    let lastBody = '';

    for (let attempts = 1; attempts <= 200; attempts++) {
      const response = await app.request('/page');
      const contentLength = response.headers.get('content-length');
      lastBody = await response.text();
      if (lastBody.includes('href="/__wd/')) {
        return { body: lastBody, contentLength, attempts };
      }
      await new Promise((resolve) => setTimeout(resolve, 10));
    }

    throw new Error(`honeytoken was not armed within 2 seconds; last body: ${lastBody}`);
  }

  beforeEach(() => {
    // These are response-decoration tests, not ingest integration tests. A
    // dummy API key must never turn them into live requests or make their
    // runtime depend on the production service.
    global.fetch = jest.fn(async () =>
      new Response(
        JSON.stringify({
          decision: 'allow',
          confidence: 0,
          threat_level: 'MINIMAL',
          bot_detected: false,
          detection_id: 'hono-test',
          rule_enforced: false,
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      ),
    ) as unknown as typeof fetch;
  });

  afterEach(() => {
    global.fetch = realFetch;
  });

  it('injects into an HTML response', async () => {
    const app = appWith(withKey);
    const { body, attempts } = await requestUntilInjected(app);
    expect(body).toMatch(/<a [^>]*href="\/__wd\//);
    expect(body).toContain('<h1>hi</h1>');
    expect(global.fetch).toHaveBeenCalledTimes(attempts);
  });

  it('leaves JSON completely alone', async () => {
    const app = appWith(withKey);
    const { attempts } = await requestUntilInjected(app);
    expect(await (await app.request('/api')).json()).toEqual({ ok: true });
    expect(global.fetch).toHaveBeenCalledTimes(attempts + 1);
  });

  it('does nothing without an apiKey, since the token derives from it', async () => {
    const app = appWith({ mode: 'monitor' });
    expect(await (await app.request('/page')).text()).toBe(
      '<html><body><h1>hi</h1></body></html>',
    );
  });

  it('does not commit a stale Content-Length', async () => {
    const app = appWith(withKey);
    const { body, contentLength, attempts } = await requestUntilInjected(app);
    // Either recomputed or absent. A stale one truncates the body at the client.
    if (contentLength !== null) {
      expect(Number(contentLength)).toBe(new TextEncoder().encode(body).length);
    }
    expect(global.fetch).toHaveBeenCalledTimes(attempts);
  });
});

describe('violation delivery on Workers', () => {
  // Workers can freeze the isolate once the response is returned, so the
  // report has to be handed to the execution context, not left to a timer.
  it('hands the report to executionCtx.waitUntil', async () => {
    const received: { path?: string; eventId?: string }[] = [];
    const server = createServer(async (request, response) => {
      let body = '';
      for await (const chunk of request) body += chunk;
      if (request.url === '/api/v1/sdk/violations/batch') received.push(...JSON.parse(body).events);
      response.writeHead(201).end('{}');
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const apiUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const tasks: Promise<unknown>[] = [];
    const ctx = { waitUntil: (task: Promise<unknown>) => { tasks.push(task); }, passThroughOnException() {}, props: {} };

    try {
      const app = appWith({
        apiKey: 'sk_test_hono_delivery', apiUrl, countAIReferrals: false, honeytoken: false,
        rules: [tripwire({ includeDefaults: false, paths: ['/trap'] })],
      });
      const res = await app.fetch(new Request('https://worker.example/trap'), {}, ctx);
      expect(res.status).toBe(403);
      expect(tasks).toHaveLength(1);
      await Promise.all(tasks);
      expect(received).toEqual([expect.objectContaining({ path: '/trap', eventId: expect.any(String) })]);
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
