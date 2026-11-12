import assert from 'node:assert/strict';
import { once } from 'node:events';
import { test } from 'node:test';
import { createApp } from './app.mjs';

test('real middleware preserves monitoring responses and blocks only the enforced decoy', async () => {
  const server = createApp().listen(0, '127.0.0.1');
  await once(server, 'listening');
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    for (const mode of ['monitor', 'enforce']) {
      const normal = await fetch(`${base}/${mode}/`);
      assert.equal(normal.status, 200);
      assert.deepEqual((await normal.json()).decision, { conclusion: 'ALLOW', tripwire: false });
    }
    const monitored = await fetch(`${base}/monitor/demo-decoy`);
    assert.equal(monitored.status, 404);
    assert.deepEqual((await monitored.json()).decision, { conclusion: 'DENY', tripwire: true });
    const blocked = await fetch(`${base}/enforce/demo-decoy`);
    assert.equal(blocked.status, 403);
    assert.equal((await blocked.json()).rule, 'tripwire');
    const home = await fetch(base);
    assert.equal(home.status, 200);
    assert.match(await home.text(), /Enable enforcement for this demo/);
    assert.equal((await fetch(`${base}/playground.js`)).status, 200);
  } finally {
    await new Promise((resolve, reject) => server.close(e => e ? reject(e) : resolve()));
  }
});
