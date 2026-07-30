import express from 'express';
import http from 'node:http';
import { AddressInfo } from 'node:net';
import { webdecoy } from './middleware';

/**
 * Honeytoken injection through a real Express app (#482).
 *
 * The unit tests cover the injection function. These cover the part that can
 * corrupt a customer's response: intercepting res.write/res.end. Each case here
 * is a way this could go wrong in production, and a corrupted response is a far
 * worse failure than a missed detection.
 */
function serve(app: express.Express): Promise<{ url: string; close: () => void }> {
  return new Promise((resolve) => {
    const server = http.createServer(app);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as AddressInfo;
      resolve({ url: `http://127.0.0.1:${port}`, close: () => server.close() });
    });
  });
}

async function get(url: string): Promise<{ status: number; body: string; length?: string }> {
  const res = await fetch(url);
  return {
    status: res.status,
    body: await res.text(),
    length: res.headers.get('content-length') ?? undefined,
  };
}

/** Give the async HMAC derivation a tick to settle before asserting on it. */
const settle = () => new Promise((r) => setTimeout(r, 50));

function appWith(opts: Record<string, unknown> = {}) {
  const app = express();
  app.use(webdecoy({ apiKey: 'sk_live_test_secret', skipLocalAnalysis: true, ...opts }));
  app.get('/', (_req, res) => res.type('html').send('<html><body><h1>hi</h1></body></html>'));
  app.get('/api', (_req, res) => res.json({ ok: true, nested: { a: 1 } }));
  app.get('/text', (_req, res) => res.type('text').send('plain body'));
  return app;
}

describe('honeytoken injection', () => {
  it('injects the hidden link into an HTML page', async () => {
    const { url, close } = await serve(appWith());
    await settle();
    const res = await get(`${url}/`);
    close();

    expect(res.status).toBe(200);
    expect(res.body).toContain('<h1>hi</h1>');
    expect(res.body).toMatch(/<a href="\/__wd\/[0-9a-f]{12}"/);
    // Before </body>, not appended after the document.
    expect(res.body.indexOf('/__wd/')).toBeLessThan(res.body.indexOf('</body>'));
  });

  it('leaves JSON completely alone', async () => {
    const { url, close } = await serve(appWith());
    await settle();
    const res = await get(`${url}/api`);
    close();

    // Corrupting an API response is worse than missing a detection.
    expect(() => JSON.parse(res.body)).not.toThrow();
    expect(JSON.parse(res.body)).toEqual({ ok: true, nested: { a: 1 } });
    expect(res.body).not.toContain('__wd');
  });

  it('leaves plain text alone', async () => {
    const { url, close } = await serve(appWith());
    await settle();
    const res = await get(`${url}/text`);
    close();
    expect(res.body).toBe('plain body');
  });

  it('corrects Content-Length, or the client truncates the body', async () => {
    const { url, close } = await serve(appWith());
    await settle();
    const res = await get(`${url}/`);
    close();

    // A stale length would cut the document short — the injected link makes the
    // body longer than what express computed.
    expect(res.length).toBe(String(Buffer.byteLength(res.body, 'utf8')));
    expect(res.body).toContain('</html>');
  });

  it('honeytoken: false opts out entirely', async () => {
    const { url, close } = await serve(appWith({ honeytoken: false }));
    await settle();
    const res = await get(`${url}/`);
    close();
    expect(res.body).not.toContain('__wd');
    expect(res.body).toBe('<html><body><h1>hi</h1></body></html>');
  });

  it('does nothing without an apiKey, since the token is derived from it', async () => {
    const app = express();
    app.use(webdecoy({ skipLocalAnalysis: true }));
    app.get('/', (_req, res) => res.type('html').send('<html><body>x</body></html>'));
    const { url, close } = await serve(app);
    await settle();
    const res = await get(`${url}/`);
    close();
    expect(res.body).not.toContain('__wd');
  });

  it('serves the same path on every request, so the tripwire matches', async () => {
    const { url, close } = await serve(appWith());
    await settle();
    const a = await get(`${url}/`);
    const b = await get(`${url}/`);
    close();

    const pathOf = (b2: string) => b2.match(/\/__wd\/[0-9a-f]{12}/)?.[0];
    expect(pathOf(a.body)).toBeDefined();
    expect(pathOf(a.body)).toBe(pathOf(b.body));
  });
});

/**
 * The acceptance criterion: a fresh Express app produces a WORKING trap with no
 * code beyond enabling honeytokens.
 *
 * Injecting the link is only half of it. If the path it advertises is not armed
 * as a tripwire, the bait leads nowhere and a crawler that follows it trips
 * nothing — which is precisely the state the SDK was already in, with the
 * developer expected to wire both halves by hand.
 */
describe('the injected link is actually armed', () => {
  it('following the bait trips the tripwire', async () => {
    const app = express();
    app.use(webdecoy({ apiKey: 'sk_live_test_secret', skipLocalAnalysis: true }));
    app.get('/', (_req, res) => res.type('html').send('<html><body>x</body></html>'));
    // Monitor mode serves everything, so the verdict is read off the request
    // rather than inferred from a status code.
    app.use((req, res) =>
      res.json({ wouldBlock: (req as any).webdecoyWouldBlock === true }),
    );

    const { url, close } = await serve(app);
    await settle();

    const page = await get(`${url}/`);
    const baitPath = page.body.match(/\/__wd\/[0-9a-f]{12}/)?.[0];
    expect(baitPath).toBeDefined();

    // A crawler follows the hidden link.
    const trap = await get(`${url}${baitPath}`);
    // An ordinary page, for contrast.
    const normal = await get(`${url}/some-real-page`);
    close();

    expect(JSON.parse(trap.body).wouldBlock).toBe(true);
    expect(JSON.parse(normal.body).wouldBlock).toBe(false);
  });
});
