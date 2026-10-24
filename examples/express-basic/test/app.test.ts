import assert from 'node:assert/strict';
import { once } from 'node:events';
import type { AddressInfo } from 'node:net';
import { test } from 'node:test';
import { createApp } from '../src/app';

async function serve(mode: 'monitor' | 'enforce' = 'monitor') {
  const server = createApp(mode).listen(0, '127.0.0.1');
  await once(server, 'listening');
  return { server, base: `http://127.0.0.1:${(server.address() as AddressInfo).port}` };
}

test('ordinary traffic is allowed in both modes', async () => {
  for (const mode of ['monitor', 'enforce'] as const) {
    const { server, base } = await serve(mode);
    try {
      const response = await fetch(base);
      assert.equal(response.status, 200);
      assert.deepEqual((await response.json()).decision, { conclusion: 'ALLOW', tripwire: false });
    } finally { server.close(); }
  }
});

test('monitor mode records the tripwire and preserves the route response', async () => {
  const { server, base } = await serve();
  try {
    const response = await fetch(`${base}/demo-decoy`);
    assert.equal(response.status, 404);
    const body = await response.json();
    assert.equal(body.message, 'Controlled decoy route');
    assert.deepEqual(body.decision, { conclusion: 'DENY', tripwire: true });
  } finally { server.close(); }
});

test('explicit enforcement stops the decoy request before its route runs', async () => {
  const { server, base } = await serve('enforce');
  try {
    const response = await fetch(`${base}/demo-decoy`);
    assert.equal(response.status, 403);
    assert.notEqual((await response.json()).message, 'Controlled decoy route');
  } finally { server.close(); }
});

test('health bypasses detection and JSON submissions still work', async () => {
  const { server, base } = await serve();
  try {
    assert.deepEqual(await (await fetch(`${base}/health`)).json(), { status: 'ok' });
    const response = await fetch(`${base}/api/submit`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ data: 'ordinary submission' }),
    });
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.received, 'ordinary submission');
    assert.equal(body.decision.tripwire, false);
  } finally { server.close(); }
});
