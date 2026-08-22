import express from 'express';
import http from 'node:http';
import { AddressInfo } from 'node:net';
import { rateLimit } from '@webdecoy/node';
import { webdecoy } from './middleware';

/**
 * Which address the middleware keys a request on, through a real Express app.
 *
 * The resolver has its own unit tests. These cover the thing that was actually
 * broken: the middleware used to read the leftmost `X-Forwarded-For` value, so
 * a caller could hand itself a fresh rate-limit bucket per request by changing
 * one header. A rate limit is the cheapest way to observe the key the
 * middleware chose, so that is what these assert on.
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

/** An app that allows one request per key, then denies. */
function appWith(opts: Record<string, unknown> = {}) {
  const app = express();
  app.use(
    webdecoy({
      mode: 'enforce',
      rules: [rateLimit({ max: 1, window: 60, action: 'DENY' })],
      ...opts,
    }),
  );
  app.get('/', (_req, res) => res.json({ ok: true }));
  return app;
}

async function statusesFor(url: string, forwardedFor: string[]): Promise<number[]> {
  const out: number[] = [];
  for (const value of forwardedFor) {
    const res = await fetch(url, { headers: { 'x-forwarded-for': value } });
    out.push(res.status);
  }
  return out;
}

describe('client IP resolution in the Express middleware', () => {
  it('does not let a forged X-Forwarded-For buy a fresh rate-limit bucket', async () => {
    const { url, close } = await serve(appWith());
    try {
      // Three requests from one machine, each claiming a different origin. All
      // three must key on the real peer, so only the first is allowed.
      const statuses = await statusesFor(url, ['1.2.3.4', '5.6.7.8', '9.10.11.12']);
      expect(statuses).toEqual([200, 403, 403]);
    } finally {
      close();
    }
  });

  it('still separates genuinely different clients when hops are declared', async () => {
    const { url, close } = await serve(appWith({ trustProxy: 1 }));
    try {
      // With one declared hop the rightmost entry is the client, and these are
      // three different ones, so none of them limits another.
      const statuses = await statusesFor(url, ['203.0.113.1', '203.0.113.2', '203.0.113.3']);
      expect(statuses).toEqual([200, 200, 200]);
    } finally {
      close();
    }
  });

  it('with hops declared, padding the chain still cannot dodge the limit', async () => {
    const { url, close } = await serve(appWith({ trustProxy: 1 }));
    try {
      // One client behind the proxy, trying to look like three. The proxy's
      // entry is the rightmost one and it does not change.
      const statuses = await statusesFor(url, [
        '203.0.113.9',
        '1.2.3.4, 203.0.113.9',
        '5.6.7.8, 9.10.11.12, 203.0.113.9',
      ]);
      expect(statuses).toEqual([200, 403, 403]);
    } finally {
      close();
    }
  });

  it('honours an explicit getIP over trustProxy', async () => {
    let seen = 0;
    const { url, close } = await serve(
      appWith({
        trustProxy: 1,
        getIP: () => `198.51.100.${++seen}`,
      }),
    );
    try {
      const statuses = await statusesFor(url, ['1.2.3.4', '1.2.3.4']);
      expect(statuses).toEqual([200, 200]);
      expect(seen).toBe(2);
    } finally {
      close();
    }
  });

  it('defers to the app’s own trust proxy setting when trustProxy is unset', async () => {
    const app = appWith();
    // Express resolves req.ip from the chain once the app opts in, and the
    // middleware follows it rather than making the operator say it twice.
    app.set('trust proxy', 1);
    const { url, close } = await serve(app);
    try {
      const statuses = await statusesFor(url, ['203.0.113.1', '203.0.113.2']);
      expect(statuses).toEqual([200, 200]);
    } finally {
      close();
    }
  });
});
