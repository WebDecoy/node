import Fastify, { FastifyInstance } from 'fastify';
import { Readable } from 'node:stream';
import { webdecoyPlugin } from './plugin';

/**
 * Honeytoken injection through a real Fastify app.
 *
 * Express needed these tests because it wraps res.write/res.end and can corrupt
 * a response. Fastify's onSend is a supported extension point, so the risk is
 * narrower — but the failure modes that matter are the same: an anchor landing
 * in a JSON body, a payload type we should not touch, and the silent
 * no-injection case that makes a defence look installed while detecting nothing.
 */
async function appWith(opts: Record<string, unknown> = {}): Promise<FastifyInstance> {
  const app = Fastify({ logger: false });
  await app.register(webdecoyPlugin, {
    apiKey: 'sk_live_test_secret',
    skipLocalAnalysis: true,
    ...opts,
  });

  app.get('/', (_req, reply) => {
    reply.type('text/html').send('<html><body><h1>hi</h1></body></html>');
  });
  app.get('/api', (_req, reply) => {
    reply.send({ ok: true, nested: { a: 1 } });
  });
  app.get('/text', (_req, reply) => {
    reply.type('text/plain').send('plain body');
  });
  app.get('/stream', (_req, reply) => {
    reply.type('text/html').send(Readable.from(['<html><body>streamed</body></html>']));
  });

  await app.ready();
  return app;
}

describe('honeytoken injection', () => {
  it('injects the hidden link into an HTML page', async () => {
    const app = await appWith();
    const res = await app.inject({ method: 'GET', url: '/' });
    await app.close();

    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('<h1>hi</h1>');
    expect(res.body).toMatch(/<a href="\/__wd\/[0-9a-f]{12}"/);
    // Before </body>, not appended after the document — an anchor outside the
    // body can be relocated by the parser in ways that make it visible.
    expect(res.body.indexOf('__wd')).toBeLessThan(res.body.indexOf('</body>'));
  });

  it('hides the link from users and from robots-honouring crawlers', async () => {
    const app = await appWith();
    const res = await app.inject({ method: 'GET', url: '/' });
    await app.close();

    // Catching Googlebot with this would file the customer's own search traffic
    // as an attack, and reaching it with a screen reader is an accessibility bug.
    expect(res.body).toContain('rel="nofollow noindex"');
    expect(res.body).toContain('aria-hidden="true"');
    expect(res.body).toContain('tabindex="-1"');
  });

  it('never touches a JSON body', async () => {
    const app = await appWith();
    const res = await app.inject({ method: 'GET', url: '/api' });
    await app.close();

    expect(res.body).not.toContain('__wd');
    expect(JSON.parse(res.body)).toEqual({ ok: true, nested: { a: 1 } });
  });

  it('never touches a plain-text body', async () => {
    const app = await appWith();
    const res = await app.inject({ method: 'GET', url: '/text' });
    await app.close();

    expect(res.body).toBe('plain body');
  });

  it('keeps Content-Length consistent with the rewritten body', async () => {
    // A stale length truncates the page at the client — the page renders with
    // the end missing, which looks like an app bug, not a WebDecoy bug.
    const app = await appWith();
    const res = await app.inject({ method: 'GET', url: '/' });
    await app.close();

    // Asserted unconditionally: Fastify recomputes the length from what onSend
    // returns, and a guarded `if (declared)` would pass silently on the day that
    // stops being true — which is the day bodies start truncating.
    const declared = res.headers['content-length'];
    expect(declared).toBeDefined();
    expect(Number(declared)).toBe(Buffer.byteLength(res.body, 'utf8'));
    expect(res.body).toContain('__wd');
  });

  it('arms the tripwire it advertises', async () => {
    // The link and the trap must agree. A link with no armed path behind it is
    // bait that catches nothing, which is the whole defect in #482.
    const app = await appWith({ mode: 'enforce' });
    const page = await app.inject({ method: 'GET', url: '/' });
    const path = /href="(\/__wd\/[0-9a-f]{12})"/.exec(page.body)?.[1];
    expect(path).toBeDefined();

    const trap = await app.inject({ method: 'GET', url: path as string });
    await app.close();

    expect(trap.statusCode).toBe(403);
    expect(JSON.parse(trap.body).rule).toBe('tripwire');
  });

  it('leaves a streamed reply intact rather than buffering it', async () => {
    // Buffering a stream to inject a link would trade the customer's streaming
    // behaviour for a hidden anchor. The response must still be correct.
    const app = await appWith();
    const res = await app.inject({ method: 'GET', url: '/stream' });
    await app.close();

    expect(res.statusCode).toBe(200);
    expect(res.body).toBe('<html><body>streamed</body></html>');
    expect(res.body).not.toContain('__wd');
  });

  it('says so when it skips a streamed reply', async () => {
    // Silence here is the failure this issue is about: installed, and quietly
    // detecting nothing. The developer has to be able to find out.
    const warnings: string[] = [];
    const app = Fastify({ logger: false });
    app.log.warn = ((msg: unknown) => {
      warnings.push(String(msg));
      return app.log;
    }) as never;

    await app.register(webdecoyPlugin, { apiKey: 'sk_live_test_secret', skipLocalAnalysis: true });
    app.get('/stream', (_req, reply) => {
      reply.type('text/html').send(Readable.from(['<html><body>s</body></html>']));
    });
    await app.ready();

    await app.inject({ method: 'GET', url: '/stream' });
    await app.inject({ method: 'GET', url: '/stream' });
    await app.close();

    expect(warnings.some((w) => w.includes('honeytoken link was not injected'))).toBe(true);
    // Once per process, not once per request — a log line per request is noise
    // that gets filtered, which is the same as not warning at all.
    expect(warnings.filter((w) => w.includes('honeytoken link was not injected')).length).toBe(1);
  });

  it('can be turned off', async () => {
    const app = await appWith({ honeytoken: false });
    const res = await app.inject({ method: 'GET', url: '/' });
    await app.close();

    expect(res.body).not.toContain('__wd');
    expect(res.body).toBe('<html><body><h1>hi</h1></body></html>');
  });

  it('does nothing without an API key, since the token is derived from it', async () => {
    const app = Fastify({ logger: false });
    await app.register(webdecoyPlugin, { skipLocalAnalysis: true } as never);
    app.get('/', (_req, reply) => {
      reply.type('text/html').send('<html><body>hi</body></html>');
    });
    await app.ready();

    const res = await app.inject({ method: 'GET', url: '/' });
    await app.close();

    expect(res.body).not.toContain('__wd');
  });

  it('derives the same path on every boot, so replicas agree', async () => {
    // Two processes serving the same site must advertise and arm the same path.
    // A random per-process token would mean a crawler follows a link that only
    // the other replica had armed.
    const a = await appWith();
    const b = await appWith();
    const pathA = /href="(\/__wd\/[0-9a-f]{12})"/.exec(
      (await a.inject({ method: 'GET', url: '/' })).body,
    )?.[1];
    const pathB = /href="(\/__wd\/[0-9a-f]{12})"/.exec(
      (await b.inject({ method: 'GET', url: '/' })).body,
    )?.[1];
    await a.close();
    await b.close();

    expect(pathA).toBeDefined();
    expect(pathA).toBe(pathB);
  });
});
