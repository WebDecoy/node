import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createServer as createHttpServer } from 'node:http';
import { test } from 'node:test';
import { createServer } from './server.mjs';

async function startOrigin(t) {
  const decisions = [];
  const app = await createServer({ onDecision: (record) => decisions.push(record) });
  t.after(() => app.close());
  const url = await app.listen({ host: '127.0.0.1', port: 0 });
  return { decisions, url };
}

test('the built Astro page renders after the Fastify decision', async (t) => {
  const { decisions, url } = await startOrigin(t);
  const response = await fetch(url);
  assert.equal(response.status, 200);
  assert.match(await response.text(), /Astro rendered this page on demand/);
  assert.deepEqual(decisions, [
    { method: 'GET', route: '/', conclusion: 'ALLOW', tripwire: false },
  ]);
});

test('a local tripwire records DENY while the app sends its ordinary 404', async (t) => {
  const { decisions, url } = await startOrigin(t);
  const response = await fetch(new URL('/lab/check/', url));
  assert.equal(response.status, 404);
  assert.deepEqual(await response.json(), { error: 'Not found' });
  assert.deepEqual(decisions, [
    { method: 'GET', route: '/lab/check/', conclusion: 'DENY', tripwire: true },
  ]);
});

test('a prerendered response served before the origin creates no origin decision', async (t) => {
  const { decisions, url } = await startOrigin(t);
  const snapshot = await readFile(new URL('./dist/client/snapshot/index.html', import.meta.url));
  const upstream = createHttpServer(async (request, response) => {
    if (request.url === '/snapshot/') {
      response.writeHead(200, { 'Content-Type': 'text/html' }).end(snapshot);
      return;
    }
    try {
      const origin = await fetch(url);
      const html = await origin.text();
      response.writeHead(origin.status, { 'Content-Type': origin.headers.get('Content-Type') });
      response.end(html);
    } catch {
      response.writeHead(502).end('Origin unavailable');
    }
  });
  t.after(() => new Promise((resolve, reject) => {
    upstream.close((error) => error ? reject(error) : resolve());
  }));
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  const upstreamUrl = `http://127.0.0.1:${upstream.address().port}`;

  const cached = await fetch(new URL('/snapshot/', upstreamUrl));
  assert.equal(cached.status, 200);
  assert.match(await cached.text(), /Astro generated this page at build time/);
  assert.deepEqual(decisions, []);

  const forwarded = await fetch(upstreamUrl);
  assert.equal(forwarded.status, 200);
  assert.match(await forwarded.text(), /Astro rendered this page on demand/);
  assert.equal(decisions.length, 1);
});
