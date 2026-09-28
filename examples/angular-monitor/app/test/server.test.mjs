import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
const port = 14300;
const events = [];
let output = '';
let pending = '';
const child = spawn(process.execPath, ['dist/webdecoy-angular/server/server.mjs'], {
  cwd: new URL('../', import.meta.url),
  env: { ...process.env, PORT: String(port), WEBDECOY_API_KEY: '' },
  stdio: ['ignore', 'pipe', 'pipe']
});
child.stdout.on('data', chunk => {
  output += chunk.toString();
  pending += chunk.toString();
  const lines = pending.split('\n');
  pending = lines.pop();
  for (const line of lines) {
    try { const event = JSON.parse(line); if (event.event === 'webdecoy-decision') events.push(event); } catch {}
  }
});
child.stderr.on('data', chunk => { output += chunk.toString(); });
after(() => child.kill('SIGTERM'));
const origin = `http://127.0.0.1:${port}`;
let ready = false;
for (let i=0;i<100;i++) {
  try { ready = (await fetch(origin+'/health')).ok; } catch {}
  if (ready) break;
  await delay(100);
}
assert.ok(ready, output);
async function receipt(predicate) {
  for (let i=0;i<50;i++) { const event=events.find(predicate); if(event) return event; await delay(20); }
  assert.fail('Missing receipt: '+output);
}
test('server renders Angular HTML before JavaScript', async () => {
  const response = await fetch(origin);
  assert.equal(response.status,200);
  assert.match(await response.text(), /See what reaches your server/);
});
test('catalog still works', async () => {
  const response=await fetch(origin+'/api/products');
  assert.equal(response.status,200);
  assert.equal((await response.json()).products.length,2);
  assert.equal((await receipt(e=>e.route==='catalog')).dashboardConfigured,false);
});
test('tripwire produces DENY while monitor preserves application 404', async () => {
  assert.equal((await fetch(origin+'/.env')).status,404);
  const event=await receipt(e=>e.tripwire);
  assert.equal(event.conclusion,'DENY');
  assert.equal(event.wouldBlock,true);
});
test('reserved trigger is labelled and keyless reporting is explicit', async () => {
  assert.equal((await fetch(origin+'/api/products',{headers:{'User-Agent':'WebDecoy-Test/1.0'}})).status,200);
  const event=await receipt(e=>e.testTrigger);
  assert.equal(event.dashboardConfigured,false);
  assert.equal(event.reportingError,true);
});
test('rate limit records a denial without blocking the catalog', async () => {
  for(let i=0;i<62;i++) assert.equal((await fetch(origin+'/api/products')).status,200);
  const event=await receipt(e=>e.rules.some(r=>r.rule.startsWith('rate-limit')&&r.conclusion==='DENY'));
  assert.equal(event.wouldBlock,true);
});
